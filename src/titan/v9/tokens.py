"""Cryptographically bound, two-phase commit authorizations for TITAN V9.

The token issuer and the commit verifier are intended to live on opposite sides
of the action boundary.  A PREPARE token is not executable.  The issuer may
promote it exactly once to a COMMIT token, and the environment may consume that
COMMIT token exactly once.

HMAC is deliberately used here because it is available in the Python standard
library.  Production deployments must keep the shared key inside trusted
issuer/verifier processes and persist the replay ledger transactionally.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping, Sequence, Tuple
import hashlib
import hmac
import json
import math
import secrets
import threading
import time


TOKEN_SCHEMA_VERSION = "titan-v9-token/1"
MIN_SECRET_BYTES = 32
ALLOW_DISPOSITIONS = frozenset({"ALLOW", "ALLOW_WITH_LOGGING"})
_HEX = frozenset("0123456789abcdef")


class TokenValidationError(ValueError):
    """A token is malformed, unauthentic, stale, mismatched, or replayed."""


class TokenPhase(str, Enum):
    PREPARE = "PREPARE"
    COMMIT = "COMMIT"


def _system_clock_ms() -> int:
    return time.time_ns() // 1_000_000


def sha256_hex(value: bytes) -> str:
    """Return the full lowercase SHA-256 digest of *value*."""
    if not isinstance(value, bytes):
        raise TypeError("sha256_hex requires bytes")
    return hashlib.sha256(value).hexdigest()


def _normalize_json(value: Any) -> Any:
    """Normalize a JSON value without lossy ``default=str`` coercions."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not canonical JSON")
        return value
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            out[key] = _normalize_json(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    raise TypeError("value is not canonical-JSON compatible: %s" % type(value).__name__)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible value in one deterministic representation."""
    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise ValueError("%s must be a full lowercase SHA-256 hex digest" % name)


def _canonical_object_hashes(
    object_hashes: Mapping[str, str],
) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(object_hashes, Mapping) or not object_hashes:
        raise ValueError("at least one object hash is required")
    normalized = []
    for object_id, digest in object_hashes.items():
        if not isinstance(object_id, str) or not object_id:
            raise ValueError("object identifiers must be non-empty strings")
        _validate_digest("object hash for %s" % object_id, digest)
        normalized.append((object_id, digest))
    normalized.sort(key=lambda item: item[0])
    return tuple(normalized)


@dataclass(frozen=True)
class ActionContext:
    """The exact execution context to which an authorization is bound."""

    action_hash: str
    object_hashes: Tuple[Tuple[str, str], ...]
    actor: str
    environment: str
    authorization_hash: str
    evidence_hash: str
    scorer_version: str
    policy_version: str

    def __post_init__(self) -> None:
        _validate_digest("action_hash", self.action_hash)
        _validate_digest("authorization_hash", self.authorization_hash)
        _validate_digest("evidence_hash", self.evidence_hash)
        if not self.object_hashes:
            raise ValueError("at least one object hash is required")
        if tuple(sorted(self.object_hashes, key=lambda item: item[0])) != self.object_hashes:
            raise ValueError("object_hashes must be sorted canonically")
        seen = set()
        for object_id, digest in self.object_hashes:
            if not object_id or object_id in seen:
                raise ValueError("object identifiers must be unique and non-empty")
            seen.add(object_id)
            _validate_digest("object hash for %s" % object_id, digest)
        for name in ("actor", "environment", "scorer_version", "policy_version"):
            if not getattr(self, name):
                raise ValueError("%s is required" % name)

    @classmethod
    def create(
        cls,
        *,
        action_hash: str,
        object_hashes: Mapping[str, str],
        actor: str,
        environment: str,
        authorization_hash: str,
        evidence_hash: str,
        scorer_version: str,
        policy_version: str,
    ) -> "ActionContext":
        return cls(
            action_hash=action_hash,
            object_hashes=_canonical_object_hashes(object_hashes),
            actor=actor,
            environment=environment,
            authorization_hash=authorization_hash,
            evidence_hash=evidence_hash,
            scorer_version=scorer_version,
            policy_version=policy_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_hash": self.action_hash,
            "object_hashes": [
                {"object_id": object_id, "sha256": digest}
                for object_id, digest in self.object_hashes
            ],
            "actor": self.actor,
            "environment": self.environment,
            "authorization_hash": self.authorization_hash,
            "evidence_hash": self.evidence_hash,
            "scorer_version": self.scorer_version,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class AuthorizationToken:
    """Immutable signed claims carried across the action boundary."""

    schema_version: str
    key_id: str
    token_id: str
    nonce: str
    phase: str
    disposition: str
    issued_at_ms: int
    expires_at_ms: int
    action_hash: str
    object_hashes: Tuple[Tuple[str, str], ...]
    actor: str
    environment: str
    authorization_hash: str
    evidence_hash: str
    scorer_version: str
    policy_version: str
    prepare_token_hash: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != TOKEN_SCHEMA_VERSION:
            raise ValueError("unsupported token schema")
        if not self.key_id or not self.token_id or not self.nonce:
            raise ValueError("key_id, token_id, and nonce are required")
        if self.phase not in (TokenPhase.PREPARE.value, TokenPhase.COMMIT.value):
            raise ValueError("invalid token phase")
        if self.disposition not in ALLOW_DISPOSITIONS:
            raise ValueError("authorization tokens may carry only allow dispositions")
        if self.issued_at_ms < 0 or self.expires_at_ms <= self.issued_at_ms:
            raise ValueError("invalid token lifetime")
        # Reuse ActionContext's strict validation.
        self.context()
        if self.phase == TokenPhase.PREPARE.value and self.prepare_token_hash:
            raise ValueError("PREPARE token cannot have a prepare_token_hash")
        if self.phase == TokenPhase.COMMIT.value:
            _validate_digest("prepare_token_hash", self.prepare_token_hash)
        if self.signature:
            _validate_digest("signature", self.signature)

    def context(self) -> ActionContext:
        return ActionContext(
            action_hash=self.action_hash,
            object_hashes=self.object_hashes,
            actor=self.actor,
            environment=self.environment,
            authorization_hash=self.authorization_hash,
            evidence_hash=self.evidence_hash,
            scorer_version=self.scorer_version,
            policy_version=self.policy_version,
        )

    def claims_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "key_id": self.key_id,
            "token_id": self.token_id,
            "nonce": self.nonce,
            "phase": self.phase,
            "disposition": self.disposition,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            **self.context().to_dict(),
            "prepare_token_hash": self.prepare_token_hash,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self.claims_dict())

    def serialized_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.claims_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationToken":
        try:
            raw_objects = value["object_hashes"]
            if not isinstance(raw_objects, Sequence):
                raise TypeError("object_hashes must be a sequence")
            objects = {}
            for item in raw_objects:
                if not isinstance(item, Mapping):
                    raise TypeError("object hash entries must be objects")
                object_id = item["object_id"]
                if object_id in objects:
                    raise ValueError("duplicate object identifier")
                objects[object_id] = item["sha256"]
            return cls(
                schema_version=value["schema_version"],
                key_id=value["key_id"],
                token_id=value["token_id"],
                nonce=value["nonce"],
                phase=value["phase"],
                disposition=value["disposition"],
                issued_at_ms=int(value["issued_at_ms"]),
                expires_at_ms=int(value["expires_at_ms"]),
                action_hash=value["action_hash"],
                object_hashes=_canonical_object_hashes(objects),
                actor=value["actor"],
                environment=value["environment"],
                authorization_hash=value["authorization_hash"],
                evidence_hash=value["evidence_hash"],
                scorer_version=value["scorer_version"],
                policy_version=value["policy_version"],
                prepare_token_hash=value.get("prepare_token_hash", ""),
                signature=value["signature"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenValidationError("malformed authorization token") from exc


def _validated_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes):
        raise TypeError("token secret must be bytes")
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError("token secret must contain at least 32 random bytes")
    return secret


def _signature(secret: bytes, token: AuthorizationToken) -> str:
    return hmac.new(secret, token.signing_bytes(), hashlib.sha256).hexdigest()


def _verify_common(
    *,
    secret: bytes,
    key_id: str,
    token: AuthorizationToken,
    expected_context: ActionContext,
    expected_phase: TokenPhase,
    now_ms: int,
) -> None:
    if token.key_id != key_id:
        raise TokenValidationError("unexpected token key")
    expected_signature = _signature(secret, replace(token, signature=""))
    if not hmac.compare_digest(expected_signature, token.signature):
        raise TokenValidationError("invalid token signature")
    if token.phase != expected_phase.value:
        raise TokenValidationError("unexpected token phase")
    if token.context() != expected_context:
        raise TokenValidationError("token context does not exactly match execution context")
    if now_ms < token.issued_at_ms:
        raise TokenValidationError("token is not yet valid")
    if now_ms >= token.expires_at_ms:
        raise TokenValidationError("token has expired")


class TwoPhaseTokenAuthority:
    """Trusted PREPARE/COMMIT issuer with atomic promotion protection."""

    def __init__(
        self,
        *,
        secret: bytes,
        key_id: str,
        clock_ms: Callable[[], int] = _system_clock_ms,
    ):
        self._secret = _validated_secret(secret)
        if not key_id:
            raise ValueError("key_id is required")
        self._key_id = key_id
        self._clock_ms = clock_ms
        self._promoted_nonces: set[str] = set()
        self._promotion_lock = threading.Lock()

    def configuration_state(self) -> dict[str, str]:
        """Return the non-secret signing configuration used by the governor."""

        return {
            "schema": "titan-v9-token-authority-config/1",
            "key_id": self._key_id,
            # This is a fingerprint of a required high-entropy secret, never
            # the secret itself. It makes accidental key swaps fail closed.
            "signing_key_fingerprint": sha256_hex(self._secret),
        }

    def _sign(self, token: AuthorizationToken) -> AuthorizationToken:
        unsigned = replace(token, signature="")
        return replace(unsigned, signature=_signature(self._secret, unsigned))

    def prepare(
        self,
        *,
        context: ActionContext,
        disposition: str,
        ttl_ms: int,
        not_before_ms: int | None = None,
        not_after_ms: int | None = None,
    ) -> AuthorizationToken:
        if disposition not in ALLOW_DISPOSITIONS:
            raise ValueError("only allow dispositions can produce execution authorization")
        if not isinstance(ttl_ms, int) or ttl_ms <= 0:
            raise ValueError("ttl_ms must be a positive integer")
        for name, boundary in (
            ("not_before_ms", not_before_ms),
            ("not_after_ms", not_after_ms),
        ):
            if boundary is not None and (
                isinstance(boundary, bool)
                or not isinstance(boundary, int)
                or boundary < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer")
        now_ms = self._clock_ms()
        if not_before_ms is not None and now_ms < not_before_ms:
            raise TokenValidationError(
                "clock precedes the authorization evidence validity window"
            )
        expires_at_ms = now_ms + ttl_ms
        if not_after_ms is not None:
            expires_at_ms = min(expires_at_ms, not_after_ms)
        if expires_at_ms <= now_ms:
            raise TokenValidationError(
                "authorization evidence expired before PREPARE issuance"
            )
        token = AuthorizationToken(
            schema_version=TOKEN_SCHEMA_VERSION,
            key_id=self._key_id,
            token_id=secrets.token_hex(16),
            nonce=secrets.token_hex(32),
            phase=TokenPhase.PREPARE.value,
            disposition=disposition,
            issued_at_ms=now_ms,
            expires_at_ms=expires_at_ms,
            action_hash=context.action_hash,
            object_hashes=context.object_hashes,
            actor=context.actor,
            environment=context.environment,
            authorization_hash=context.authorization_hash,
            evidence_hash=context.evidence_hash,
            scorer_version=context.scorer_version,
            policy_version=context.policy_version,
            prepare_token_hash="",
            signature="",
        )
        return self._sign(token)

    def promote(
        self,
        prepare_token: AuthorizationToken,
        *,
        expected_context: ActionContext,
    ) -> AuthorizationToken:
        now_ms = self._clock_ms()
        _verify_common(
            secret=self._secret,
            key_id=self._key_id,
            token=prepare_token,
            expected_context=expected_context,
            expected_phase=TokenPhase.PREPARE,
            now_ms=now_ms,
        )
        with self._promotion_lock:
            if prepare_token.nonce in self._promoted_nonces:
                raise TokenValidationError("PREPARE token has already been promoted")
            self._promoted_nonces.add(prepare_token.nonce)
            commit = AuthorizationToken(
                schema_version=TOKEN_SCHEMA_VERSION,
                key_id=self._key_id,
                token_id=secrets.token_hex(16),
                nonce=prepare_token.nonce,
                phase=TokenPhase.COMMIT.value,
                disposition=prepare_token.disposition,
                issued_at_ms=now_ms,
                expires_at_ms=prepare_token.expires_at_ms,
                action_hash=prepare_token.action_hash,
                object_hashes=prepare_token.object_hashes,
                actor=prepare_token.actor,
                environment=prepare_token.environment,
                authorization_hash=prepare_token.authorization_hash,
                evidence_hash=prepare_token.evidence_hash,
                scorer_version=prepare_token.scorer_version,
                policy_version=prepare_token.policy_version,
                prepare_token_hash=sha256_hex(prepare_token.serialized_bytes()),
                signature="",
            )
            return self._sign(commit)


class ReplayGuard:
    """Atomic in-memory one-time nonce ledger.

    Production must back this interface with durable transactional storage so a
    verifier restart cannot reopen consumed authorizations.
    """

    def __init__(self) -> None:
        self._consumed: set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def consume(self, key_id: str, nonce: str) -> None:
        key = (key_id, nonce)
        with self._lock:
            if key in self._consumed:
                raise TokenValidationError("authorization token replayed")
            self._consumed.add(key)

    def was_consumed(self, key_id: str, nonce: str) -> bool:
        with self._lock:
            return (key_id, nonce) in self._consumed


class CommitTokenVerifier:
    """Trusted environment-side verifier and atomic replay gate."""

    def __init__(
        self,
        *,
        secret: bytes,
        key_id: str,
        replay_guard: ReplayGuard,
        clock_ms: Callable[[], int] = _system_clock_ms,
    ):
        self._secret = _validated_secret(secret)
        if not key_id:
            raise ValueError("key_id is required")
        if not isinstance(replay_guard, ReplayGuard):
            raise TypeError("an explicit ReplayGuard is required")
        self._key_id = key_id
        self._replay_guard = replay_guard
        self._clock_ms = clock_ms

    def verify_and_consume(
        self,
        token: AuthorizationToken,
        *,
        expected_context: ActionContext,
    ) -> None:
        """Authorize exactly one commit or raise ``TokenValidationError``."""
        _verify_common(
            secret=self._secret,
            key_id=self._key_id,
            token=token,
            expected_context=expected_context,
            expected_phase=TokenPhase.COMMIT,
            now_ms=self._clock_ms(),
        )
        self._replay_guard.consume(token.key_id, token.nonce)
