"""Authenticated external-verifier attestations for V9 evidence.

Agent-supplied booleans and digest-looking strings are claims, not proof.
Evidence counts as empirical only after an attestation verifier authenticates
an exact action/state-bound record from a configured evidence authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Sequence
import hashlib
import hmac
import json
import math
import secrets
import time

from .action import ActionProposal
from .tokens import canonical_json_bytes


EVIDENCE_SCHEMA = "titan-v9-evidence-attestation/1"
MIN_SECRET_BYTES = 32
EVIDENCE_COMPONENT_CAPABILITIES: dict[str, frozenset[str]] = {
    "signed_authorization": frozenset(),
    "safeguard_effect": frozenset(
        {
            "semantic_diff",
            "policy_graph_delta",
            "hidden_probes",
            "rollback_proof",
        }
    ),
    "canary_effect": frozenset(
        {
            "coverage_conservation",
            "replacement_equivalence",
            "composed_degradation",
            "rollback_proof",
        }
    ),
    "destination_scope": frozenset(
        {"destination_scope", "data_classification"}
    ),
    "rollback_proof": frozenset({"rollback_proof"}),
}


class EvidenceTrustError(ValueError):
    """An evidence attestation is malformed, untrusted, stale, or mismatched."""


def _clock_ms() -> int:
    return time.time_ns() // 1_000_000


def _digest_valid(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


@dataclass(frozen=True)
class EvidenceAttestation:
    schema: str
    key_id: str
    attestation_id: str
    verifier_id: str
    source_id: str
    evidence_kind: str
    action_hash: str
    state_snapshot_id: str
    actor: str
    environment: str
    evidence_digest: str
    claims_json: str
    issued_at_ms: int
    expires_at_ms: int
    signature: str

    def __post_init__(self) -> None:
        if self.schema != EVIDENCE_SCHEMA:
            raise ValueError("unsupported evidence attestation schema")
        for name in (
            "key_id",
            "attestation_id",
            "verifier_id",
            "source_id",
            "evidence_kind",
            "actor",
            "environment",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        for name in ("action_hash", "state_snapshot_id", "evidence_digest"):
            if not _digest_valid(getattr(self, name)):
                raise ValueError(f"{name} must be a full lowercase SHA-256 digest")
        if self.issued_at_ms < 0 or self.expires_at_ms <= self.issued_at_ms:
            raise ValueError("invalid evidence attestation lifetime")
        try:
            claims = json.loads(self.claims_json)
        except json.JSONDecodeError as exc:
            raise ValueError("claims_json is malformed") from exc
        canonical = canonical_json_bytes(claims).decode("utf-8")
        if canonical != self.claims_json or not isinstance(claims, dict):
            raise ValueError("claims_json must be one canonical JSON object")
        if self.signature and not _digest_valid(self.signature):
            raise ValueError("signature must be a full lowercase SHA-256 digest")

    @property
    def claims(self) -> dict[str, Any]:
        return json.loads(self.claims_json)

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "attestation_id": self.attestation_id,
            "verifier_id": self.verifier_id,
            "source_id": self.source_id,
            "evidence_kind": self.evidence_kind,
            "action_hash": self.action_hash,
            "state_snapshot_id": self.state_snapshot_id,
            "actor": self.actor,
            "environment": self.environment,
            "evidence_digest": self.evidence_digest,
            "claims": self.claims,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceAttestation":
        try:
            claims = value["claims"]
            if not isinstance(claims, Mapping):
                raise TypeError("claims must be an object")
            return cls(
                schema=str(value["schema"]),
                key_id=str(value["key_id"]),
                attestation_id=str(value["attestation_id"]),
                verifier_id=str(value["verifier_id"]),
                source_id=str(value["source_id"]),
                evidence_kind=str(value["evidence_kind"]),
                action_hash=str(value["action_hash"]),
                state_snapshot_id=str(value["state_snapshot_id"]),
                actor=str(value["actor"]),
                environment=str(value["environment"]),
                evidence_digest=str(value["evidence_digest"]),
                claims_json=canonical_json_bytes(dict(claims)).decode("utf-8"),
                issued_at_ms=int(value["issued_at_ms"]),
                expires_at_ms=int(value["expires_at_ms"]),
                signature=str(value["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceTrustError("malformed evidence attestation") from exc


@dataclass(frozen=True)
class VerifiedEvidence:
    attestation: EvidenceAttestation
    verified_at_ms: int
    independence_domain: str

    def __post_init__(self) -> None:
        if not self.independence_domain:
            raise ValueError("independence_domain is required")

    @property
    def evidence_kind(self) -> str:
        return self.attestation.evidence_kind

    @property
    def verifier_id(self) -> str:
        return self.attestation.verifier_id

    @property
    def source_id(self) -> str:
        return self.attestation.source_id

    @property
    def evidence_digest(self) -> str:
        return self.attestation.evidence_digest

    @property
    def claims(self) -> dict[str, Any]:
        return self.attestation.claims

    @property
    def remaining_ttl_ms(self) -> int:
        return max(0, self.attestation.expires_at_ms - self.verified_at_ms)

    @property
    def expires_at_ms(self) -> int:
        return self.attestation.expires_at_ms


class EvidenceAttestationAuthority:
    """Reference HMAC issuer for an external verifier adapter."""

    def __init__(
        self,
        *,
        secret: bytes,
        key_id: str,
        clock_ms: Callable[[], int] = _clock_ms,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < MIN_SECRET_BYTES:
            raise ValueError("evidence secret must contain at least 32 random bytes")
        if not key_id:
            raise ValueError("key_id is required")
        self._secret = secret
        self.key_id = key_id
        self.clock_ms = clock_ms

    def issue(
        self,
        proposal: ActionProposal,
        *,
        verifier_id: str,
        source_id: str,
        evidence_kind: str,
        evidence_digest: str,
        claims: Mapping[str, Any],
        ttl_ms: int = 5_000,
    ) -> EvidenceAttestation:
        if not isinstance(ttl_ms, int) or ttl_ms <= 0:
            raise ValueError("ttl_ms must be a positive integer")
        now = self.clock_ms()
        unsigned = EvidenceAttestation(
            schema=EVIDENCE_SCHEMA,
            key_id=self.key_id,
            attestation_id=secrets.token_hex(16),
            verifier_id=verifier_id,
            source_id=source_id,
            evidence_kind=evidence_kind,
            action_hash=proposal.action_hash(),
            state_snapshot_id=proposal.state_snapshot_id,
            actor=proposal.actor,
            environment=proposal.environment,
            evidence_digest=evidence_digest,
            claims_json=canonical_json_bytes(dict(claims)).decode("utf-8"),
            issued_at_ms=now,
            expires_at_ms=now + ttl_ms,
            signature="",
        )
        signature = hmac.new(
            self._secret,
            unsigned.signing_bytes(),
            hashlib.sha256,
        ).hexdigest()
        return replace(unsigned, signature=signature)


class EvidenceAttestationVerifier:
    """Authenticate exact action/state-bound verifier results."""

    def __init__(
        self,
        *,
        trusted_identities: Mapping[
            str,
            Sequence[
                tuple[str, str]
                | tuple[str, str, str, str]
            ],
        ],
        secret: bytes | None = None,
        key_id: str | None = None,
        trusted_keys: Mapping[str, bytes] | None = None,
        clock_ms: Callable[[], int] = _clock_ms,
    ) -> None:
        if (secret is None) != (key_id is None):
            raise ValueError("secret and key_id must be configured together")
        keys = dict(trusted_keys or {})
        if secret is not None and key_id is not None:
            if key_id in keys and not hmac.compare_digest(keys[key_id], secret):
                raise ValueError("conflicting evidence keys for key_id")
            keys[key_id] = secret
        if not keys:
            raise ValueError("at least one trusted evidence key is required")
        for configured_key_id, configured_secret in keys.items():
            if not configured_key_id:
                raise ValueError("evidence key IDs must be non-empty")
            if (
                not isinstance(configured_secret, bytes)
                or len(configured_secret) < MIN_SECRET_BYTES
            ):
                raise ValueError(
                    "each evidence secret must contain at least 32 random bytes"
                )
        if not trusted_identities:
            raise ValueError("at least one trusted evidence identity is required")
        normalized: dict[
            str,
            dict[tuple[str, str], tuple[str, str]],
        ] = {}
        domain_keys: dict[str, str] = {}
        key_domains: dict[str, str] = {}
        for kind, identities in trusted_identities.items():
            if not isinstance(kind, str) or not kind:
                raise ValueError("evidence kinds must be non-empty strings")
            rows: dict[tuple[str, str], tuple[str, str]] = {}
            for raw_identity in identities:
                if len(raw_identity) == 2:
                    if key_id is None:
                        raise ValueError(
                            "two-field identities require the default key_id"
                        )
                    verifier_id, source_id = raw_identity
                    identity_key_id = key_id
                    independence_domain = f"shared-key:{key_id}"
                elif len(raw_identity) == 4:
                    (
                        verifier_id,
                        source_id,
                        identity_key_id,
                        independence_domain,
                    ) = raw_identity
                else:
                    raise ValueError(
                        "trusted identities must contain verifier/source pairs "
                        "or verifier/source/key/domain quadruples"
                    )
                verifier = str(verifier_id)
                source = str(source_id)
                bound_key = str(identity_key_id)
                domain = str(independence_domain)
                if not verifier or not source or not bound_key or not domain:
                    raise ValueError(
                        "trusted evidence identity fields must be non-empty"
                    )
                if bound_key not in keys:
                    raise ValueError(
                        f"trusted evidence identity references unknown key {bound_key!r}"
                    )
                identity = (verifier, source)
                if identity in rows:
                    raise ValueError(
                        "duplicate verifier/source identity for evidence kind"
                    )
                rows[identity] = (bound_key, domain)
                prior_key = domain_keys.setdefault(domain, bound_key)
                if prior_key != bound_key:
                    raise ValueError(
                        "one independence domain cannot span multiple keys"
                    )
                prior_domain = key_domains.setdefault(bound_key, domain)
                if prior_domain != domain:
                    raise ValueError(
                        "one cryptographic key cannot claim multiple "
                        "independence domains"
                    )
            if not rows:
                raise ValueError(
                    "trusted evidence identities must not be empty"
                )
            normalized[kind] = rows
        self._keys = keys
        self.key_id = key_id
        self.trusted_identities = normalized
        self.clock_ms = clock_ms

    def configuration_state(self) -> dict[str, Any]:
        """Return canonicalizable trust policy without exposing key material.

        Key fingerprints intentionally bind a configuration artifact to the
        exact high-entropy verification keys while keeping the keys themselves
        out of logs, decisions, and serialized governor state.
        """

        return {
            "schema": "titan-v9-evidence-trust-config/1",
            "trusted_key_fingerprints": {
                key_id: hashlib.sha256(self._keys[key_id]).hexdigest()
                for key_id in sorted(self._keys)
            },
            "trusted_identities": {
                evidence_kind: [
                    {
                        "verifier_id": verifier_id,
                        "source_id": source_id,
                        "key_id": binding[0],
                        "independence_domain": binding[1],
                    }
                    for (verifier_id, source_id), binding in sorted(
                        self.trusted_identities[evidence_kind].items()
                    )
                ]
                for evidence_kind in sorted(self.trusted_identities)
            },
        }

    @staticmethod
    def _validate_claims(attestation: EvidenceAttestation) -> None:
        claims = attestation.claims
        required = ("risk", "confidence", "coverage", "passed")
        missing = [name for name in required if name not in claims]
        if missing:
            raise EvidenceTrustError(
                "evidence claims missing required fields: " + ", ".join(missing)
            )
        for name in ("risk", "confidence", "coverage"):
            value = claims[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise EvidenceTrustError(f"evidence claim {name} must be numeric")
            numeric = float(value)
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise EvidenceTrustError(f"evidence claim {name} must be in [0,1]")
        if claims["passed"] is not None and not isinstance(claims["passed"], bool):
            raise EvidenceTrustError("evidence claim passed must be boolean or null")
        components = claims.get("verified_components", [])
        if not isinstance(components, list) or any(
            not isinstance(item, str) or not item for item in components
        ):
            raise EvidenceTrustError(
                "verified_components must be a list of non-empty strings"
            )
        if len(set(components)) != len(components):
            raise EvidenceTrustError("verified_components must not contain duplicates")
        allowed_components = EVIDENCE_COMPONENT_CAPABILITIES.get(
            attestation.evidence_kind,
            frozenset(),
        )
        unauthorized = sorted(set(components) - allowed_components)
        if unauthorized:
            raise EvidenceTrustError(
                f"{attestation.evidence_kind} cannot attest components: "
                + ", ".join(unauthorized)
            )

    def verify(
        self,
        attestation: EvidenceAttestation,
        proposal: ActionProposal,
    ) -> VerifiedEvidence:
        if not isinstance(attestation, EvidenceAttestation):
            raise EvidenceTrustError("unexpected evidence attestation type")
        allowed = self.trusted_identities.get(attestation.evidence_kind)
        identity = (attestation.verifier_id, attestation.source_id)
        binding = None if allowed is None else allowed.get(identity)
        if binding is None:
            raise EvidenceTrustError(
                "evidence verifier/source identity is not authorized for this kind"
            )
        expected_key_id, independence_domain = binding
        if attestation.key_id != expected_key_id:
            raise EvidenceTrustError("unexpected evidence key for verifier identity")
        secret = self._keys.get(expected_key_id)
        if secret is None:
            raise EvidenceTrustError("unexpected evidence key")
        expected = hmac.new(
            secret,
            replace(attestation, signature="").signing_bytes(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, attestation.signature):
            raise EvidenceTrustError("invalid evidence signature")
        now = self.clock_ms()
        if now < attestation.issued_at_ms:
            raise EvidenceTrustError("evidence is not yet valid")
        if now >= attestation.expires_at_ms:
            raise EvidenceTrustError("evidence has expired")
        self._validate_claims(attestation)
        expected_fields = {
            "action_hash": proposal.action_hash(),
            "state_snapshot_id": proposal.state_snapshot_id,
            "actor": proposal.actor,
            "environment": proposal.environment,
        }
        for name, value in expected_fields.items():
            if getattr(attestation, name) != value:
                raise EvidenceTrustError(
                    f"evidence {name} does not match the action proposal"
                )
        return VerifiedEvidence(
            attestation,
            verified_at_ms=now,
            independence_domain=independence_domain,
        )


EvidenceProvider = Callable[[ActionProposal], Sequence[EvidenceAttestation]]


def verify_evidence_set(
    proposal: ActionProposal,
    *,
    provider: EvidenceProvider | None,
    verifier: EvidenceAttestationVerifier | None,
) -> tuple[VerifiedEvidence, ...]:
    if (provider is None) != (verifier is None):
        raise EvidenceTrustError(
            "evidence provider and verifier must be configured together"
        )
    if provider is None or verifier is None:
        return ()
    supplied = provider(proposal)
    if isinstance(supplied, (str, bytes)) or not isinstance(supplied, Sequence):
        raise EvidenceTrustError("evidence provider must return a sequence")
    if len(supplied) > 64:
        raise EvidenceTrustError("evidence provider exceeded the attestation limit")
    verified: list[VerifiedEvidence] = []
    seen_ids: set[str] = set()
    seen_identities: set[tuple[str, str, str]] = set()
    for attestation in supplied:
        if not isinstance(attestation, EvidenceAttestation):
            raise EvidenceTrustError("evidence provider returned an unexpected type")
        if attestation.attestation_id in seen_ids:
            raise EvidenceTrustError("duplicate evidence attestation ID")
        seen_ids.add(attestation.attestation_id)
        identity = (
            attestation.evidence_kind,
            attestation.verifier_id,
            attestation.source_id,
        )
        if identity in seen_identities:
            raise EvidenceTrustError(
                "duplicate evidence kind/verifier/source identity"
            )
        seen_identities.add(identity)
        verified.append(verifier.verify(attestation, proposal))
    return tuple(verified)
