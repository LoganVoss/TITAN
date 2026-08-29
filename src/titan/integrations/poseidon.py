"""TITAN-owned, shadow-only attachment for signed POSEIDON observations.

This module deliberately does not import the POSEIDON package.  It implements
the stable serialized boundary, verifies both embedded Ed25519 artifacts, and
re-attests an accepted observation as native TITAN evidence bound to one exact
action proposal.  The emitted evidence kind is intentionally not consumed by
TITAN readiness or authorization logic.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple, Union

from ..v9.action import ActionProposal, ObservableTrajectory, action_prefix
from ..v9.evidence_trust import EvidenceAttestation, EvidenceAttestationAuthority
from ..v9.tokens import canonical_json_bytes

POSEIDON_ABI = "poseidon.observation/v1"
POSEIDON_TRACE_SCHEMA = "poseidon://trace/v1"
POSEIDON_BRIDGE_SCHEMA = "poseidon://integration/titan-observation/v1"
POSEIDON_BRIDGE_MESSAGE = "poseidon.observable_attestation"
POSEIDON_PACKAGE_CONTEXT = b"POSEIDON:ObservablePackage:v1\x00"
POSEIDON_ATTESTATION_CONTEXT = b"POSEIDON:ObservableAttestation:v1\x00"
POSEIDON_REQUIRED_GATES = frozenset(
    {
        "contract_validity",
        "nuisance_invariance",
        "protected_sensitivity",
        "replay_stability",
        "bounded_complexity",
        "environment_transfer",
        "prospective_locked_holdout",
    }
)

TITAN_PROJECTION_SCHEMA = "titan-poseidon-prefix-projection/1"
TITAN_BINDING_SCHEMA = "titan-poseidon-consumer-binding/1"
TITAN_REQUEST_SCHEMA = "titan-poseidon-observation-request/1"
TITAN_RECEIPT_SCHEMA = "titan-poseidon-binding-receipt/1"
TITAN_POSEIDON_BINDER_ID = "titan-poseidon-shadow-binder-v1"
POSEIDON_SHADOW_EVIDENCE_KIND = "poseidon_observation"

_FORBIDDEN_OBSERVATION_KEYS = frozenset(
    {
        "allow",
        "authorize",
        "authorization",
        "block",
        "decision",
        "deny",
        "disposition",
        "escrow",
        "permit",
    }
)
_FORBIDDEN_OBSERVATION_VALUES = frozenset(
    {"allow", "authorize", "block", "commit", "deny", "escrow", "permit", "prepare"}
)


class PoseidonAttachmentError(ValueError):
    """A signed artifact, local binding, or trust configuration was rejected."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise PoseidonAttachmentError(code, message)


def _strict_json_loads(value: Union[str, bytes], *, maximum_bytes: int) -> Any:
    if isinstance(value, bytes):
        raw = value
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            _reject("invalid_json", "bridge input must be UTF-8 JSON")
    elif isinstance(value, str):
        text = value
        raw = value.encode("utf-8")
    else:
        _reject("invalid_json", "bridge input must be serialized JSON")
    if len(raw) > maximum_bytes:
        _reject("artifact_too_large", "bridge input exceeds the configured size limit")

    def unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _reject(
                    "duplicate_json_key", "bridge input contains a duplicate JSON key"
                )
            result[key] = item
        return result

    def invalid_constant(_: str) -> None:
        _reject("non_finite_json", "bridge input contains a non-finite number")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except PoseidonAttachmentError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError):
        _reject("invalid_json", "bridge input is malformed JSON")
    _validate_json_tree(parsed, depth=0, counter=[0])
    return parsed


def _validate_json_tree(value: Any, *, depth: int, counter: list) -> None:
    counter[0] += 1
    if counter[0] > 100_000 or depth > 64:
        _reject("json_complexity", "bridge input exceeds structural limits")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _reject("non_finite_json", "bridge input contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _reject("invalid_json", "JSON object keys must be strings")
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    _reject("invalid_json", "bridge input contains a non-JSON value")


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _reject("invalid_schema", "%s must be one JSON object" % name)
    return value


def _fields(
    value: Mapping[str, Any],
    *,
    required: Sequence[str],
    optional: Sequence[str] = (),
    name: str,
) -> None:
    keys = set(value)
    required_set = set(required)
    optional_set = set(optional)
    if keys != required_set | (keys & optional_set):
        missing = sorted(required_set - keys)
        unknown = sorted(keys - required_set - optional_set)
        _reject(
            "invalid_schema",
            "%s has missing %r or unknown %r fields" % (name, missing, unknown),
        )


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject("invalid_schema", "%s must be a non-empty string" % name)
    return value


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject("invalid_observation", "%s must be numeric" % name)
    result = float(value)
    if not math.isfinite(result):
        _reject("invalid_observation", "%s must be finite" % name)
    return result


def _sha256_prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _raw_fingerprint(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bare_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _valid_prefixed_digest(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
    ):
        return False
    return all(char in "0123456789abcdef" for char in value[7:])


def _decode_base64url(value: str, name: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        padded = encoded + b"=" * (-len(encoded) % 4)
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        _reject("invalid_key_material", "%s is not strict base64url" % name)
    raise AssertionError("unreachable")


def _public_key_bytes(value: Union[str, bytes], name: str) -> bytes:
    raw = _decode_base64url(value, name) if isinstance(value, str) else value
    if not isinstance(raw, bytes) or len(raw) != 32:
        _reject(
            "invalid_key_material", "%s must contain one raw Ed25519 public key" % name
        )
    return bytes(raw)


def _verify_ed25519(public_key: bytes, message: bytes, signature: Any) -> None:
    if not isinstance(signature, str):
        _reject("invalid_signature", "signature must be base64url text")
    raw_signature = _decode_base64url(signature, "signature")
    if len(raw_signature) != 64:
        _reject("invalid_signature", "Ed25519 signature must contain 64 bytes")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        _reject(
            "missing_dependency",
            "install titan-safety[poseidon] to verify POSEIDON Ed25519 artifacts",
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw_signature, message)
    except (InvalidSignature, ValueError):
        _reject("invalid_signature", "POSEIDON Ed25519 signature verification failed")


def _parse_timestamp_ms(value: Any, name: str) -> int:
    text = _text(value, name)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except (OverflowError, OSError, ValueError):
        _reject("invalid_time", "%s must be an ISO-8601 timestamp" % name)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject("invalid_time", "%s must be timezone-aware" % name)
    canonical = (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    if text != canonical:
        _reject("invalid_time", "%s is not a canonical POSEIDON timestamp" % name)
    return int(parsed.timestamp() * 1_000)


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _event_time(timestamp: float) -> datetime:
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        _reject("invalid_prefix", "TITAN event timestamps must be numeric")
    numeric = float(timestamp)
    if not math.isfinite(numeric):
        _reject("invalid_prefix", "TITAN event timestamps must be finite")
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=numeric)
    except OverflowError:
        _reject(
            "invalid_prefix", "TITAN event timestamp is outside the projection range"
        )
    raise AssertionError("unreachable")


def _resource(payload: Mapping[str, Any]) -> Optional[str]:
    for key in ("path", "target", "object", "dataset", "shard", "eval_name", "name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _validate_observation_only(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in _FORBIDDEN_OBSERVATION_KEYS:
                _reject(
                    "policy_smuggling",
                    "POSEIDON observation contains disposition vocabulary",
                )
            _validate_observation_only(item)
    elif isinstance(value, list):
        for item in value:
            _validate_observation_only(item)
    elif isinstance(value, str) and value.casefold() in _FORBIDDEN_OBSERVATION_VALUES:
        _reject(
            "policy_smuggling", "POSEIDON observation contains disposition vocabulary"
        )


@dataclass(frozen=True)
class PoseidonRuntimeBinding:
    key_id: str
    public_key: Union[str, bytes]
    runtime_id: str
    independence_domain: str

    def __post_init__(self) -> None:
        _text(self.key_id, "runtime key_id")
        _text(self.runtime_id, "runtime_id")
        _text(self.independence_domain, "independence_domain")
        object.__setattr__(
            self,
            "public_key",
            _public_key_bytes(self.public_key, "runtime public key"),
        )

    @property
    def fingerprint(self) -> str:
        return _raw_fingerprint(self.public_key)


@dataclass(frozen=True)
class PoseidonTrustPolicy:
    release_public_keys: Mapping[str, Union[str, bytes]]
    runtime_bindings: Tuple[PoseidonRuntimeBinding, ...]
    revoked_package_digests: Tuple[str, ...] = ()
    revoked_attestation_digests: Tuple[str, ...] = ()
    revoked_key_ids: Tuple[str, ...] = ()
    maximum_bridge_bytes: int = 2 * 1024 * 1024
    maximum_attestation_ttl_ms: int = 5 * 60 * 1_000

    def __post_init__(self) -> None:
        releases: Dict[str, bytes] = {}
        for key_id, value in dict(self.release_public_keys).items():
            _text(key_id, "release key_id")
            releases[key_id] = _public_key_bytes(value, "release public key")
        if not releases:
            raise ValueError("at least one POSEIDON release key is required")
        bindings = tuple(self.runtime_bindings)
        if not bindings:
            raise ValueError("at least one POSEIDON runtime binding is required")
        runtime_ids = [item.key_id for item in bindings]
        if len(runtime_ids) != len(set(runtime_ids)):
            raise ValueError("POSEIDON runtime key IDs must be unique")
        all_material = list(releases.values()) + [item.public_key for item in bindings]
        if len(all_material) != len(set(all_material)):
            raise ValueError(
                "POSEIDON release and runtime keys must use distinct material"
            )
        if (
            isinstance(self.maximum_bridge_bytes, bool)
            or not isinstance(self.maximum_bridge_bytes, int)
            or isinstance(self.maximum_attestation_ttl_ms, bool)
            or not isinstance(self.maximum_attestation_ttl_ms, int)
            or self.maximum_bridge_bytes <= 0
            or self.maximum_attestation_ttl_ms <= 0
        ):
            raise ValueError("POSEIDON size and TTL limits must be positive")
        for digest in (
            *self.revoked_package_digests,
            *self.revoked_attestation_digests,
        ):
            if not _valid_prefixed_digest(digest):
                raise ValueError(
                    "revocation entries must use sha256:<64 lowercase hex>"
                )
        object.__setattr__(self, "release_public_keys", MappingProxyType(releases))
        object.__setattr__(self, "runtime_bindings", bindings)
        object.__setattr__(
            self, "revoked_package_digests", tuple(self.revoked_package_digests)
        )
        object.__setattr__(
            self, "revoked_attestation_digests", tuple(self.revoked_attestation_digests)
        )
        object.__setattr__(self, "revoked_key_ids", tuple(self.revoked_key_ids))
        if any(
            not isinstance(key_id, str) or not key_id for key_id in self.revoked_key_ids
        ):
            raise ValueError("revoked key IDs must be non-empty strings")

    @property
    def runtime_by_key(self) -> Mapping[str, PoseidonRuntimeBinding]:
        return MappingProxyType({item.key_id: item for item in self.runtime_bindings})

    def configuration_state(self) -> Mapping[str, Any]:
        return {
            "schema": "titan-poseidon-trust-policy/1",
            "release_keys": {
                key_id: _raw_fingerprint(self.release_public_keys[key_id])
                for key_id in sorted(self.release_public_keys)
            },
            "runtime_bindings": [
                {
                    "key_id": item.key_id,
                    "key_fingerprint": item.fingerprint,
                    "runtime_id": item.runtime_id,
                    "independence_domain": item.independence_domain,
                }
                for item in sorted(self.runtime_bindings, key=lambda item: item.key_id)
            ],
            "revoked_package_digests": sorted(self.revoked_package_digests),
            "revoked_attestation_digests": sorted(self.revoked_attestation_digests),
            "revoked_key_ids": sorted(self.revoked_key_ids),
            "maximum_bridge_bytes": self.maximum_bridge_bytes,
            "maximum_attestation_ttl_ms": self.maximum_attestation_ttl_ms,
        }


@dataclass(frozen=True)
class PoseidonShadowMapping:
    mapping_id: str
    mapping_version: str
    package_digest: str
    package_id: str
    package_version: str
    observable_id: str
    observable_version: str
    trace_domain: str
    source_id: str
    value_minimum: float = 0.0
    value_maximum: float = 1.0
    risk_at_minimum: float = 0.0
    risk_at_maximum: float = 1.0
    minimum_coverage: float = 1.0
    maximum_uncertainty: float = 1.0
    output_type: str = "float"
    native_ttl_ms: int = 5_000

    def __post_init__(self) -> None:
        for name in (
            "mapping_id",
            "mapping_version",
            "package_id",
            "package_version",
            "observable_id",
            "observable_version",
            "trace_domain",
            "source_id",
        ):
            _text(getattr(self, name), name)
        if not _valid_prefixed_digest(self.package_digest):
            raise ValueError("package_digest must use sha256:<64 lowercase hex>")
        values = (
            self.value_minimum,
            self.value_maximum,
            self.risk_at_minimum,
            self.risk_at_maximum,
            self.minimum_coverage,
            self.maximum_uncertainty,
        )
        if any(
            isinstance(value, bool) or not math.isfinite(float(value))
            for value in values
        ):
            raise ValueError("POSEIDON mapping numbers must be finite")
        if self.value_maximum <= self.value_minimum:
            raise ValueError("value_maximum must exceed value_minimum")
        for name in ("risk_at_minimum", "risk_at_maximum", "minimum_coverage"):
            if not 0.0 <= float(getattr(self, name)) <= 1.0:
                raise ValueError("%s must be in [0,1]" % name)
        if not 0.0 <= float(self.maximum_uncertainty) <= 1.0:
            raise ValueError("maximum_uncertainty must be in [0,1]")
        if self.output_type not in ("float", "integer"):
            raise ValueError("shadow mappings accept only numeric POSEIDON outputs")
        if not isinstance(self.native_ttl_ms, int) or self.native_ttl_ms <= 0:
            raise ValueError("native_ttl_ms must be a positive integer")

    def configuration_state(self) -> Mapping[str, Any]:
        return {
            "schema": "titan-poseidon-shadow-mapping/1",
            "mapping_id": self.mapping_id,
            "mapping_version": self.mapping_version,
            "mode": "shadow_only",
            "native_evidence_kind": POSEIDON_SHADOW_EVIDENCE_KIND,
            "package_digest": self.package_digest,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "observable_id": self.observable_id,
            "observable_version": self.observable_version,
            "trace_domain": self.trace_domain,
            "source_id": self.source_id,
            "value_minimum": self.value_minimum,
            "value_maximum": self.value_maximum,
            "risk_at_minimum": self.risk_at_minimum,
            "risk_at_maximum": self.risk_at_maximum,
            "minimum_coverage": self.minimum_coverage,
            "maximum_uncertainty": self.maximum_uncertainty,
            "output_type": self.output_type,
            "native_ttl_ms": self.native_ttl_ms,
        }

    @property
    def digest(self) -> str:
        return _sha256_prefixed(self.configuration_state())

    def shadow_risk(self, value: float) -> float:
        position = (value - self.value_minimum) / (
            self.value_maximum - self.value_minimum
        )
        return self.risk_at_minimum + position * (
            self.risk_at_maximum - self.risk_at_minimum
        )


@dataclass(frozen=True)
class PoseidonObservationRequest:
    schema: str
    request_id: str
    mapping_id: str
    mapping_version: str
    mapping_digest: str
    action_hash: str
    state_snapshot_id: str
    actor: str
    environment: str
    trace_json: str
    trace_digest: str
    nonce: str
    context_json: str
    issued_at_ms: int
    expires_at_ms: int

    @property
    def trace(self) -> Mapping[str, Any]:
        return json.loads(self.trace_json)

    @property
    def runtime_context(self) -> Mapping[str, Any]:
        return json.loads(self.context_json)

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "mapping_id": self.mapping_id,
            "mapping_version": self.mapping_version,
            "mapping_digest": self.mapping_digest,
            "action_hash": self.action_hash,
            "state_snapshot_id": self.state_snapshot_id,
            "actor": self.actor,
            "environment": self.environment,
            "trace": self.trace,
            "trace_digest": self.trace_digest,
            "nonce": self.nonce,
            "runtime_context": self.runtime_context,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }

    @property
    def digest(self) -> str:
        return _sha256_prefixed(self.to_dict())


@dataclass(frozen=True)
class PoseidonBindingReceipt:
    schema: str
    status: str
    reason_code: str
    request_id: str
    action_hash: str
    mapping_digest: str
    native_attestation_id: Optional[str] = None
    poseidon_attestation_digest: Optional[str] = None

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "schema": self.schema,
            "status": self.status,
            "reason_code": self.reason_code,
            "request_id": self.request_id,
            "action_hash": self.action_hash,
            "mapping_digest": self.mapping_digest,
            "native_attestation_id": self.native_attestation_id,
            "poseidon_attestation_digest": self.poseidon_attestation_digest,
        }


@dataclass(frozen=True)
class PoseidonBindingResult:
    evidence: Optional[EvidenceAttestation]
    receipt: PoseidonBindingReceipt

    @property
    def accepted(self) -> bool:
        return self.evidence is not None and self.receipt.status == "accepted"


@dataclass(frozen=True)
class _VerifiedPoseidon:
    package_digest: str
    package_expires_at_ms: int
    attestation_digest: str
    attestation_expires_at_ms: int
    runtime_binding: PoseidonRuntimeBinding
    observation: Mapping[str, Any]
    risk: float


class PoseidonAttachment:
    """Prepare exact prefix requests and bind verified responses as shadow evidence."""

    def __init__(
        self,
        *,
        trust_policy: PoseidonTrustPolicy,
        mapping: PoseidonShadowMapping,
        native_authority: EvidenceAttestationAuthority,
        clock_ms: Optional[Callable[[], int]] = None,
        nonce_factory: Optional[Callable[[], str]] = None,
        request_ttl_ms: int = 5_000,
        maximum_pending_requests: int = 1_024,
    ) -> None:
        if native_authority.key_id in set(trust_policy.release_public_keys) | {
            item.key_id for item in trust_policy.runtime_bindings
        }:
            raise ValueError("the TITAN binder key ID must be role-separated")
        if request_ttl_ms <= 0 or maximum_pending_requests <= 0:
            raise ValueError("request TTL and pending-request limit must be positive")
        self.trust_policy = trust_policy
        self.mapping = mapping
        self.native_authority = native_authority
        self.clock_ms = clock_ms or native_authority.clock_ms
        self.nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(24))
        self.request_ttl_ms = int(request_ttl_ms)
        self.maximum_pending_requests = int(maximum_pending_requests)
        self._pending: Dict[str, Tuple[str, int]] = {}
        self._consumed: Dict[str, int] = {}
        self._lock = threading.Lock()

    def configuration_state(self) -> Mapping[str, Any]:
        state = {
            "schema": "titan-poseidon-shadow-attachment/1",
            "binder_id": TITAN_POSEIDON_BINDER_ID,
            "mode": "shadow_only",
            "mapping": self.mapping.configuration_state(),
            "trust": self.trust_policy.configuration_state(),
            "native_key_id": self.native_authority.key_id,
            "request_ttl_ms": self.request_ttl_ms,
            "maximum_pending_requests": self.maximum_pending_requests,
            "projection_schema": TITAN_PROJECTION_SCHEMA,
        }
        return {**state, "configuration_digest": _sha256_prefixed(state)}

    def prepare(
        self,
        trajectory: ObservableTrajectory,
        proposal: ActionProposal,
    ) -> PoseidonObservationRequest:
        prefix = action_prefix(trajectory, proposal)
        if prefix.observable_hash() != proposal.state_snapshot_id:
            _reject(
                "state_mismatch", "proposal state is not the exact observable prefix"
            )
        trace = self._project_prefix(prefix, proposal)
        trace_digest = _sha256_prefixed(trace)
        now = self.clock_ms()
        nonce = _text(self.nonce_factory(), "challenge nonce")
        request_seed = {
            "schema": TITAN_REQUEST_SCHEMA,
            "mapping_digest": self.mapping.digest,
            "action_hash": proposal.action_hash(),
            "state_snapshot_id": proposal.state_snapshot_id,
            "actor": proposal.actor,
            "environment": proposal.environment,
            "trace_digest": trace_digest,
            "nonce": nonce,
            "issued_at_ms": now,
        }
        request_id = _bare_digest(request_seed)
        expires = now + self.request_ttl_ms
        consumer_binding = {
            "schema": TITAN_BINDING_SCHEMA,
            "request_id": request_id,
            "mapping_id": self.mapping.mapping_id,
            "mapping_version": self.mapping.mapping_version,
            "mapping_digest": self.mapping.digest,
            "action_hash": proposal.action_hash(),
            "state_snapshot_id": proposal.state_snapshot_id,
            "actor": proposal.actor,
            "environment": proposal.environment,
            "trace_digest": trace_digest,
            "nonce": nonce,
            "issued_at_ms": now,
            "expires_at_ms": expires,
        }
        request = PoseidonObservationRequest(
            schema=TITAN_REQUEST_SCHEMA,
            request_id=request_id,
            mapping_id=self.mapping.mapping_id,
            mapping_version=self.mapping.mapping_version,
            mapping_digest=self.mapping.digest,
            action_hash=proposal.action_hash(),
            state_snapshot_id=proposal.state_snapshot_id,
            actor=proposal.actor,
            environment=proposal.environment,
            trace_json=canonical_json_bytes(trace).decode("utf-8"),
            trace_digest=trace_digest,
            nonce=nonce,
            context_json=canonical_json_bytes(
                {"consumer_binding": consumer_binding}
            ).decode("utf-8"),
            issued_at_ms=now,
            expires_at_ms=expires,
        )
        with self._lock:
            expired = [
                key for key, (_, expiry) in self._pending.items() if expiry <= now
            ]
            for key in expired:
                self._pending.pop(key, None)
            consumed_expired = [
                key for key, expiry in self._consumed.items() if expiry <= now
            ]
            for key in consumed_expired:
                self._consumed.pop(key, None)
            if len(self._pending) >= self.maximum_pending_requests:
                _reject(
                    "request_limit", "too many pending POSEIDON observation requests"
                )
            if (
                request.request_id in self._pending
                or request.request_id in self._consumed
            ):
                _reject("nonce_reuse", "challenge nonce was already used")
            self._pending[request.request_id] = (request.digest, request.expires_at_ms)
        return request

    def bind(
        self,
        request: PoseidonObservationRequest,
        proposal: ActionProposal,
        bridge_input: Union[str, bytes],
    ) -> PoseidonBindingResult:
        try:
            evidence, attestation_digest = self._bind_strict(
                request, proposal, bridge_input
            )
        except PoseidonAttachmentError as exc:
            return PoseidonBindingResult(
                evidence=None,
                receipt=PoseidonBindingReceipt(
                    schema=TITAN_RECEIPT_SCHEMA,
                    status="rejected",
                    reason_code=exc.code,
                    request_id=getattr(request, "request_id", ""),
                    action_hash=proposal.action_hash(),
                    mapping_digest=self.mapping.digest,
                ),
            )
        return PoseidonBindingResult(
            evidence=evidence,
            receipt=PoseidonBindingReceipt(
                schema=TITAN_RECEIPT_SCHEMA,
                status="accepted",
                reason_code="verified_shadow_observation",
                request_id=request.request_id,
                action_hash=proposal.action_hash(),
                mapping_digest=self.mapping.digest,
                native_attestation_id=evidence.attestation_id,
                poseidon_attestation_digest=attestation_digest,
            ),
        )

    def _bind_strict(
        self,
        request: PoseidonObservationRequest,
        proposal: ActionProposal,
        bridge_input: Union[str, bytes],
    ) -> Tuple[EvidenceAttestation, str]:
        if not isinstance(request, PoseidonObservationRequest):
            _reject("unknown_request", "request was not issued by this attachment")
        now = self.clock_ms()
        if now < request.issued_at_ms or now >= request.expires_at_ms:
            _reject("request_expired", "POSEIDON observation request is not current")
        self._validate_request_binding(request, proposal)
        with self._lock:
            if request.request_id in self._consumed:
                _reject(
                    "replay", "POSEIDON observation request has already been consumed"
                )
            pending = self._pending.get(request.request_id)
        if pending is None or pending[0] != request.digest:
            _reject("unknown_request", "request was not issued by this attachment")

        bridge = _strict_json_loads(
            bridge_input,
            maximum_bytes=self.trust_policy.maximum_bridge_bytes,
        )
        verified = self._verify_bridge(_object(bridge, "bridge"), request, now)
        remaining = min(
            self.mapping.native_ttl_ms,
            request.expires_at_ms - now,
            verified.package_expires_at_ms - now,
            verified.attestation_expires_at_ms - now,
        )
        if remaining <= 0:
            _reject("expired", "source evidence expires before native binding")
        source_commitment = {
            "schema": "titan-poseidon-source-commitment/1",
            "package_digest": verified.package_digest,
            "poseidon_attestation_digest": verified.attestation_digest,
            "mapping_digest": self.mapping.digest,
            "request_digest": request.digest,
            "trace_digest": request.trace_digest,
            "action_hash": proposal.action_hash(),
        }
        observation = verified.observation
        claims = {
            "risk": verified.risk,
            "confidence": 0.0,
            "coverage": float(observation["coverage"]),
            "passed": None,
            "verified_components": [],
            "poseidon": {
                "artifact_semantics": "observation",
                "shadow_only": True,
                "package_id": self.mapping.package_id,
                "package_version": self.mapping.package_version,
                "package_digest": verified.package_digest,
                "observable_id": self.mapping.observable_id,
                "observable_version": self.mapping.observable_version,
                "trace_id": observation["trace_id"],
                "trace_digest": request.trace_digest,
                "runtime_id": verified.runtime_binding.runtime_id,
                "independence_domain": verified.runtime_binding.independence_domain,
                "attestation_digest": verified.attestation_digest,
                "mapping_id": self.mapping.mapping_id,
                "mapping_version": self.mapping.mapping_version,
                "mapping_digest": self.mapping.digest,
                "request_id": request.request_id,
                "value": observation["value"],
                "uncertainty": observation["uncertainty"],
            },
        }
        with self._lock:
            if request.request_id in self._consumed:
                _reject(
                    "replay", "POSEIDON observation request has already been consumed"
                )
            pending = self._pending.get(request.request_id)
            if pending is None or pending[0] != request.digest:
                _reject("unknown_request", "request is no longer pending")
            self._pending.pop(request.request_id, None)
            self._consumed[request.request_id] = request.expires_at_ms
        evidence = self.native_authority.issue(
            proposal,
            verifier_id=TITAN_POSEIDON_BINDER_ID,
            source_id=self.mapping.source_id,
            evidence_kind=POSEIDON_SHADOW_EVIDENCE_KIND,
            evidence_digest=_bare_digest(source_commitment),
            claims=claims,
            ttl_ms=remaining,
        )
        source_expiry = min(
            request.expires_at_ms,
            verified.package_expires_at_ms,
            verified.attestation_expires_at_ms,
        )
        if evidence.expires_at_ms > source_expiry:
            _reject(
                "clock_mismatch", "native evidence would outlive its source evidence"
            )
        if not request.issued_at_ms <= evidence.issued_at_ms <= now:
            _reject("clock_mismatch", "native evidence issuance is outside the request")
        return evidence, verified.attestation_digest

    def _validate_request_binding(
        self,
        request: PoseidonObservationRequest,
        proposal: ActionProposal,
    ) -> None:
        expected = {
            "mapping_id": self.mapping.mapping_id,
            "mapping_version": self.mapping.mapping_version,
            "mapping_digest": self.mapping.digest,
            "action_hash": proposal.action_hash(),
            "state_snapshot_id": proposal.state_snapshot_id,
            "actor": proposal.actor,
            "environment": proposal.environment,
        }
        for name, value in expected.items():
            if getattr(request, name) != value:
                _reject(
                    "context_mismatch", "request %s does not match TITAN context" % name
                )
        if _sha256_prefixed(request.trace) != request.trace_digest:
            _reject("trace_mismatch", "request trace digest does not verify")

    def _verify_bridge(
        self,
        bridge: Mapping[str, Any],
        request: PoseidonObservationRequest,
        now_ms: int,
    ) -> _VerifiedPoseidon:
        _fields(
            bridge,
            required=(
                "schema_uri",
                "message_type",
                "verified_at",
                "package_reference",
                "package_digest",
                "observation",
                "signed_observable_package",
                "signed_observable_attestation",
            ),
            name="POSEIDON bridge",
        )
        if bridge["schema_uri"] != POSEIDON_BRIDGE_SCHEMA:
            _reject("invalid_schema", "unsupported POSEIDON bridge schema")
        if bridge["message_type"] != POSEIDON_BRIDGE_MESSAGE:
            _reject("invalid_schema", "unsupported POSEIDON bridge message")

        package = _object(bridge["signed_observable_package"], "signed package")
        manifest, package_digest, package_expiry = self._verify_package(package, now_ms)
        if bridge["package_digest"] != package_digest:
            _reject(
                "outer_mismatch", "outer package digest does not match signed package"
            )
        expected_reference = "%s@%s" % (
            manifest["package_id"],
            manifest["package_version"],
        )
        if bridge["package_reference"] != expected_reference:
            _reject(
                "outer_mismatch",
                "outer package reference does not match signed package",
            )

        attestation = _object(
            bridge["signed_observable_attestation"],
            "signed attestation",
        )
        verified = self._verify_attestation(
            attestation,
            manifest=manifest,
            package_digest=package_digest,
            request=request,
            now_ms=now_ms,
            package_expires_at_ms=package_expiry,
        )
        if bridge["observation"] != verified.observation:
            _reject(
                "outer_mismatch", "outer observation does not match signed observation"
            )
        bridge_verified_at = _parse_timestamp_ms(bridge["verified_at"], "verified_at")
        if (
            bridge_verified_at
            < _parse_timestamp_ms(attestation["payload"]["issued_at"], "issued_at")
            or bridge_verified_at > now_ms
        ):
            _reject("outer_mismatch", "outer verification time is inconsistent")
        return verified

    def _verify_package(
        self,
        package: Mapping[str, Any],
        now_ms: int,
    ) -> Tuple[Mapping[str, Any], str, int]:
        _fields(
            package,
            required=("manifest", "key_id", "signature", "algorithm"),
            name="POSEIDON package",
        )
        if package["algorithm"] != "Ed25519":
            _reject("invalid_algorithm", "POSEIDON package must use Ed25519")
        key_id = _text(package["key_id"], "package key_id")
        if key_id in self.trust_policy.revoked_key_ids:
            _reject("revoked", "POSEIDON package key is revoked")
        public_key = self.trust_policy.release_public_keys.get(key_id)
        if public_key is None:
            _reject("untrusted_key", "POSEIDON package key is not trusted")
        manifest = _object(package["manifest"], "package manifest")
        _fields(
            manifest,
            required=(
                "package_id",
                "package_version",
                "issuer",
                "created_at",
                "expires_at",
                "observable",
                "implementation_kind",
                "implementation",
                "certification",
                "nuisance_contracts",
                "test_vectors",
                "abi_version",
                "lineage",
                "artifact_digests",
                "metadata",
            ),
            name="POSEIDON manifest",
        )
        _verify_ed25519(
            public_key,
            POSEIDON_PACKAGE_CONTEXT + canonical_json_bytes(manifest),
            package["signature"],
        )
        package_digest = _sha256_prefixed(manifest)
        if package_digest in self.trust_policy.revoked_package_digests:
            _reject("revoked", "POSEIDON package is revoked")
        if package_digest != self.mapping.package_digest:
            _reject("mapping_mismatch", "POSEIDON package digest is not pinned")
        if (
            manifest["package_id"] != self.mapping.package_id
            or manifest["package_version"] != self.mapping.package_version
        ):
            _reject("mapping_mismatch", "POSEIDON package identity is not pinned")
        if manifest.get("abi_version", POSEIDON_ABI) != POSEIDON_ABI:
            _reject("abi_mismatch", "POSEIDON package ABI is unsupported")
        created = _parse_timestamp_ms(manifest["created_at"], "package created_at")
        expires = _parse_timestamp_ms(manifest["expires_at"], "package expires_at")
        if now_ms < created:
            _reject("not_yet_valid", "POSEIDON package is not yet valid")
        if now_ms >= expires:
            _reject("expired", "POSEIDON package has expired")
        observable = _object(manifest["observable"], "observable specification")
        _fields(
            observable,
            required=(
                "observable_id",
                "version",
                "name",
                "description",
                "domains",
                "input_schema_uri",
                "output_type",
                "temporal_scope",
                "missingness",
                "required_fields",
                "nuisance_contract_ids",
                "sensitivity_targets",
                "runtime_budget_ms",
                "memory_budget_mb",
                "privacy_classification",
                "abi_version",
                "metadata",
            ),
            name="POSEIDON observable specification",
        )
        if (
            observable.get("observable_id") != self.mapping.observable_id
            or observable.get("version") != self.mapping.observable_version
        ):
            _reject("mapping_mismatch", "POSEIDON observable identity is not pinned")
        if observable.get("abi_version", POSEIDON_ABI) != POSEIDON_ABI:
            _reject("abi_mismatch", "POSEIDON observable ABI is unsupported")
        if observable.get("input_schema_uri") != POSEIDON_TRACE_SCHEMA:
            _reject("mapping_mismatch", "POSEIDON trace schema is not pinned")
        if observable.get("output_type") != self.mapping.output_type:
            _reject("mapping_mismatch", "POSEIDON output type is not pinned")
        if observable.get("temporal_scope") != "prefix":
            _reject(
                "temporal_scope", "only prefix-safe POSEIDON observables may attach"
            )
        domains = observable.get("domains")
        if not isinstance(domains, list) or self.mapping.trace_domain not in domains:
            _reject("mapping_mismatch", "POSEIDON trace domain is not pinned")
        if observable.get("missingness") not in ("abstain", "error"):
            _reject("mapping_mismatch", "POSEIDON missingness policy is unsupported")
        self._verify_certification(manifest)
        return manifest, package_digest, expires

    def _verify_certification(self, manifest: Mapping[str, Any]) -> None:
        report = _object(manifest["certification"], "certification report")
        _fields(
            report,
            required=(
                "report_id",
                "evaluated_at",
                "dataset_commitment",
                "holdout_commitment",
                "gates",
                "evaluator",
                "notes",
            ),
            name="POSEIDON certification report",
        )
        evaluated_at = _parse_timestamp_ms(
            report["evaluated_at"], "certification evaluated_at"
        )
        created_at = _parse_timestamp_ms(manifest["created_at"], "package created_at")
        if evaluated_at > created_at:
            _reject("certification", "certification postdates package creation")
        for digest_name in ("dataset_commitment", "holdout_commitment"):
            if not _valid_prefixed_digest(report[digest_name]):
                _reject("certification", "%s is not a canonical digest" % digest_name)
        gates = report.get("gates")
        if not isinstance(gates, list):
            _reject("certification", "POSEIDON certification gates are missing")
        names = []
        nuisance_gate: Optional[Mapping[str, Any]] = None
        for raw_gate in gates:
            gate = _object(raw_gate, "certification gate")
            _fields(
                gate,
                required=("name", "status", "metric", "threshold", "details"),
                name="POSEIDON certification gate",
            )
            name = gate.get("name")
            status = gate.get("status")
            if not isinstance(name, str) or status != "pass":
                _reject("certification", "every POSEIDON gate must pass")
            names.append(name)
            if name == "nuisance_invariance":
                nuisance_gate = gate
        if len(names) != len(set(names)) or frozenset(names) != POSEIDON_REQUIRED_GATES:
            _reject("certification", "POSEIDON certification gate set is incomplete")
        contracts = manifest.get("nuisance_contracts")
        if not isinstance(contracts, list):
            _reject("certification", "POSEIDON nuisance contracts are missing")
        observable = _object(manifest["observable"], "observable specification")
        domains = observable.get("domains", [])
        references = []
        for raw_contract in contracts:
            contract = _object(raw_contract, "nuisance contract")
            _fields(
                contract,
                required=(
                    "contract_id",
                    "version",
                    "domain",
                    "transformations",
                    "protected_fields",
                    "metadata",
                ),
                name="POSEIDON nuisance contract",
            )
            if contract["domain"] not in domains:
                _reject("certification", "nuisance contract domain is unsupported")
            transformations = contract["transformations"]
            if not isinstance(transformations, list) or not transformations:
                _reject("certification", "nuisance transformations are missing")
            for raw_transformation in transformations:
                transformation = _object(raw_transformation, "nuisance transformation")
                _fields(
                    transformation,
                    required=(
                        "transformation_id",
                        "operator",
                        "description",
                        "parameters",
                        "applies_to",
                    ),
                    name="POSEIDON nuisance transformation",
                )
            references.append("%s@%s" % (contract["contract_id"], contract["version"]))
        if len(references) != len(set(references)):
            _reject("certification", "nuisance contract references are duplicated")
        if set(observable.get("nuisance_contract_ids", [])) != set(references):
            _reject("certification", "observable nuisance declarations do not match")
        try:
            ordered = sorted(
                contracts,
                key=lambda item: "%s@%s" % (item["contract_id"], item["version"]),
            )
        except (KeyError, TypeError):
            _reject("certification", "POSEIDON nuisance contracts are malformed")
        expected_commitment = _sha256_prefixed(ordered)
        details = {} if nuisance_gate is None else nuisance_gate.get("details", {})
        if (
            not isinstance(details, dict)
            or details.get("nuisance_contract_commitment") != expected_commitment
        ):
            _reject("certification", "nuisance gate is not bound to signed contracts")
        vectors = manifest.get("test_vectors")
        if not isinstance(vectors, list) or not vectors:
            _reject("certification", "POSEIDON package test vectors are missing")
        for raw_vector in vectors:
            vector = _object(raw_vector, "test vector")
            _fields(
                vector,
                required=(
                    "vector_id",
                    "trace",
                    "expected_value",
                    "expected_abstained",
                    "tolerance",
                ),
                name="POSEIDON test vector",
            )
            trace = vector.get("trace")
            if not isinstance(trace, dict):
                _reject("certification", "POSEIDON test vector trace is missing")
            _fields(
                trace,
                required=(
                    "trace_id",
                    "domain",
                    "occurred_at",
                    "source",
                    "events",
                    "schema_uri",
                    "schema_version",
                    "subject",
                    "captured_at",
                    "attributes",
                ),
                name="POSEIDON test vector trace",
            )
            if trace.get("domain") not in domains:
                _reject("certification", "POSEIDON test vector domain is unsupported")
            events = trace.get("events")
            if not isinstance(events, list):
                _reject("certification", "POSEIDON test vector events are malformed")
            for raw_event in events:
                event = _object(raw_event, "test vector event")
                _fields(
                    event,
                    required=(
                        "event_id",
                        "event_type",
                        "occurred_at",
                        "payload",
                        "actor",
                        "resource",
                    ),
                    name="POSEIDON test vector event",
                )

    def _verify_attestation(
        self,
        attestation: Mapping[str, Any],
        *,
        manifest: Mapping[str, Any],
        package_digest: str,
        request: PoseidonObservationRequest,
        now_ms: int,
        package_expires_at_ms: int,
    ) -> _VerifiedPoseidon:
        _fields(
            attestation,
            required=("payload", "key_id", "signature", "algorithm"),
            name="POSEIDON attestation",
        )
        if attestation["algorithm"] != "Ed25519":
            _reject("invalid_algorithm", "POSEIDON attestation must use Ed25519")
        key_id = _text(attestation["key_id"], "attestation key_id")
        if key_id in self.trust_policy.revoked_key_ids:
            _reject("revoked", "POSEIDON runtime key is revoked")
        runtime_binding = self.trust_policy.runtime_by_key.get(key_id)
        if runtime_binding is None:
            _reject("untrusted_key", "POSEIDON runtime key is not trusted")
        payload = _object(attestation["payload"], "attestation payload")
        _fields(
            payload,
            required=(
                "package_digest",
                "package_id",
                "package_version",
                "trace_digest",
                "runtime_id",
                "independence_domain",
                "observation",
                "issued_at",
                "expires_at",
                "nonce",
                "context",
                "abi_version",
            ),
            name="POSEIDON attestation payload",
        )
        _verify_ed25519(
            runtime_binding.public_key,
            POSEIDON_ATTESTATION_CONTEXT + canonical_json_bytes(payload),
            attestation["signature"],
        )
        attestation_digest = _sha256_prefixed(payload)
        if attestation_digest in self.trust_policy.revoked_attestation_digests:
            _reject("revoked", "POSEIDON attestation is revoked")
        if (
            payload.get("runtime_id") != runtime_binding.runtime_id
            or payload.get("independence_domain") != runtime_binding.independence_domain
        ):
            _reject(
                "runtime_mismatch", "POSEIDON runtime identity is not pinned to its key"
            )
        if (
            payload.get("package_digest") != package_digest
            or payload.get("package_id") != manifest["package_id"]
            or payload.get("package_version") != manifest["package_version"]
        ):
            _reject(
                "package_splice", "POSEIDON attestation is bound to another package"
            )
        if payload.get("trace_digest") != request.trace_digest:
            _reject("trace_mismatch", "POSEIDON attestation is bound to another trace")
        if payload.get("nonce") != request.nonce:
            _reject(
                "nonce_mismatch",
                "POSEIDON attestation nonce does not match the request",
            )
        if payload.get("context", {}) != request.runtime_context:
            _reject(
                "context_mismatch", "POSEIDON attestation context does not match TITAN"
            )
        if payload.get("abi_version", POSEIDON_ABI) != POSEIDON_ABI:
            _reject("abi_mismatch", "POSEIDON attestation ABI is unsupported")
        issued = _parse_timestamp_ms(payload["issued_at"], "attestation issued_at")
        if payload.get("expires_at") is None:
            _reject("freshness", "POSEIDON attestation must expire")
        expires = _parse_timestamp_ms(payload["expires_at"], "attestation expires_at")
        if issued < request.issued_at_ms or issued > now_ms:
            _reject(
                "freshness", "POSEIDON attestation issue time is outside the request"
            )
        if expires <= issued or now_ms >= expires:
            _reject("expired", "POSEIDON attestation is expired")
        if expires - issued > self.trust_policy.maximum_attestation_ttl_ms:
            _reject("freshness", "POSEIDON attestation lifetime exceeds policy")
        if expires > package_expires_at_ms:
            _reject("freshness", "POSEIDON attestation outlives its package")

        observation = _object(payload["observation"], "POSEIDON observation")
        _fields(
            observation,
            required=(
                "observable_id",
                "observable_version",
                "trace_id",
                "observed_at",
                "value",
                "abstained",
                "coverage",
                "uncertainty",
                "metadata",
                "abi_version",
            ),
            name="POSEIDON observation",
        )
        if (
            observation.get("observable_id") != self.mapping.observable_id
            or observation.get("observable_version") != self.mapping.observable_version
        ):
            _reject("mapping_mismatch", "POSEIDON observation identity is not pinned")
        if observation.get("abi_version", POSEIDON_ABI) != POSEIDON_ABI:
            _reject("abi_mismatch", "POSEIDON observation ABI is unsupported")
        if observation.get("trace_id") != request.trace.get("trace_id"):
            _reject("trace_mismatch", "POSEIDON observation trace ID is not pinned")
        if observation.get("abstained", False) is not False:
            _reject("abstained", "an abstained observation produces no TITAN evidence")
        if observation.get("value") is None:
            _reject(
                "invalid_observation", "non-abstained observation must carry a value"
            )
        value = _number(observation["value"], "observation value")
        if self.mapping.output_type == "integer" and not isinstance(
            observation["value"], int
        ):
            _reject("invalid_observation", "integer observable emitted a non-integer")
        if not self.mapping.value_minimum <= value <= self.mapping.value_maximum:
            _reject(
                "invalid_observation", "observation value is outside the frozen mapping"
            )
        coverage = _number(observation.get("coverage", 1.0), "observation coverage")
        if not 0.0 <= coverage <= 1.0 or coverage < self.mapping.minimum_coverage:
            _reject("insufficient_coverage", "observation coverage is below policy")
        if observation.get("uncertainty") is None:
            _reject(
                "unknown_uncertainty", "shadow mapping requires bounded uncertainty"
            )
        uncertainty = _number(observation["uncertainty"], "observation uncertainty")
        if not 0.0 <= uncertainty <= self.mapping.maximum_uncertainty:
            _reject("unknown_uncertainty", "observation uncertainty exceeds policy")
        observed_at = _parse_timestamp_ms(observation["observed_at"], "observed_at")
        if observed_at < request.issued_at_ms or observed_at > issued:
            _reject("freshness", "observation time is outside the request")
        metadata = observation.get("metadata", {})
        if not isinstance(metadata, dict):
            _reject("invalid_observation", "observation metadata must be an object")
        _validate_observation_only(observation.get("value"))
        _validate_observation_only(metadata)
        _validate_observation_only(payload.get("context", {}))
        return _VerifiedPoseidon(
            package_digest=package_digest,
            package_expires_at_ms=package_expires_at_ms,
            attestation_digest=attestation_digest,
            attestation_expires_at_ms=expires,
            runtime_binding=runtime_binding,
            observation=observation,
            risk=self.mapping.shadow_risk(value),
        )

    def _project_prefix(
        self,
        prefix: ObservableTrajectory,
        proposal: ActionProposal,
    ) -> Mapping[str, Any]:
        projected_events = []
        previous: Optional[datetime] = None
        for event in prefix.events:
            occurred = _event_time(event.timestamp)
            if previous is not None and occurred < previous:
                _reject("invalid_prefix", "TITAN prefix timestamps are not ordered")
            previous = occurred
            payload = {
                **dict(event.payload),
                "titan_sequence": event.sequence,
            }
            row: Dict[str, Any] = {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "occurred_at": _format_timestamp(occurred),
                "payload": payload,
                "actor": event.actor,
                # POSEIDON canonicalizes optional dataclass fields explicitly;
                # omitting this key would change the runtime's trace digest.
                "resource": _resource(event.payload),
            }
            projected_events.append(row)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        first = _event_time(prefix.events[0].timestamp) if prefix.events else epoch
        last = _event_time(prefix.events[-1].timestamp) if prefix.events else first
        return {
            "trace_id": "titan-prefix-" + proposal.state_snapshot_id[:24],
            "domain": self.mapping.trace_domain,
            "occurred_at": _format_timestamp(first),
            "source": "titan://action-prefix/v1",
            "events": projected_events,
            "schema_uri": POSEIDON_TRACE_SCHEMA,
            "schema_version": "1.0.0",
            "subject": proposal.actor,
            "captured_at": _format_timestamp(last),
            "attributes": {
                "projection_schema": TITAN_PROJECTION_SCHEMA,
                "model_version": prefix.model_version,
                "task_family": prefix.task_family,
            },
        }


__all__ = [
    "POSEIDON_SHADOW_EVIDENCE_KIND",
    "TITAN_POSEIDON_BINDER_ID",
    "PoseidonAttachment",
    "PoseidonAttachmentError",
    "PoseidonBindingReceipt",
    "PoseidonBindingResult",
    "PoseidonObservationRequest",
    "PoseidonRuntimeBinding",
    "PoseidonShadowMapping",
    "PoseidonTrustPolicy",
]
