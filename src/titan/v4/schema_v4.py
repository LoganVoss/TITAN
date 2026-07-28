"""
Step 4 — Canonical V4 event schema for direct-execution agents.

Supports authorization refs, causal parents, object identities, integrity,
and forensic outcomes (forensic partition only).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import hmac
import json
import time
import uuid


SCHEMA_VERSION = "v4.0.0"
COLLECTOR_VERSION = "titan-gateway-0.4.0"


@dataclass
class CanonicalEvent:
    event_id: str
    trajectory_id: str
    session_id: str
    actor_id: str
    agent_version: str
    environment_id: str
    event_type: str
    causal_timestamp: float
    ingest_timestamp: float
    tool_name: str = ""
    action_name: str = ""
    object_refs: list[str] = field(default_factory=list)
    authorization_refs: list[str] = field(default_factory=list)
    parent_event_ids: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    payload_hash: str = ""
    result_hash: str = ""
    schema_version: str = SCHEMA_VERSION
    collector_version: str = COLLECTOR_VERSION
    # Forensic-only fields — gateway strips from online path if mode=online
    forensic_outcome: dict[str, Any] = field(default_factory=dict)

    def compute_payload_hash(self) -> str:
        blob = json.dumps(self.payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def to_dict(self, *, include_forensic: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not include_forensic:
            d.pop("forensic_outcome", None)
        return d

    @classmethod
    def create(
        cls,
        trajectory_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        session_id: str = "",
        actor_id: str = "agent",
        agent_version: str = "unknown",
        environment_id: str = "default",
        tool_name: str = "",
        action_name: str = "",
        object_refs: list[str] | None = None,
        authorization_refs: list[str] | None = None,
        parent_event_ids: list[str] | None = None,
        causal_timestamp: float | None = None,
        forensic_outcome: dict[str, Any] | None = None,
    ) -> "CanonicalEvent":
        ts = causal_timestamp if causal_timestamp is not None else time.time()
        payload = payload or {}
        ev = cls(
            event_id=uuid.uuid4().hex,
            trajectory_id=trajectory_id,
            session_id=session_id or trajectory_id,
            actor_id=actor_id,
            agent_version=agent_version,
            environment_id=environment_id,
            event_type=event_type,
            causal_timestamp=ts,
            ingest_timestamp=time.time(),
            tool_name=tool_name,
            action_name=action_name or event_type,
            object_refs=object_refs or [],
            authorization_refs=authorization_refs or [],
            parent_event_ids=parent_event_ids or [],
            payload=payload,
            forensic_outcome=forensic_outcome or {},
        )
        ev.payload_hash = ev.compute_payload_hash()
        return ev


@dataclass
class IntegrityEnvelope:
    event: dict[str, Any]
    signature: str
    key_id: str
    signed_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sign_payload(payload: dict[str, Any], secret: bytes, key_id: str = "local-dev") -> IntegrityEnvelope:
    """HMAC-SHA256 signature. Agents never hold the signing secret."""
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    sig = hmac.new(secret, blob, hashlib.sha256).hexdigest()
    return IntegrityEnvelope(event=payload, signature=sig, key_id=key_id, signed_at=time.time())


def verify_envelope(envelope: IntegrityEnvelope, secret: bytes) -> bool:
    blob = json.dumps(envelope.event, sort_keys=True, default=str).encode()
    expected = hmac.new(secret, blob, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, envelope.signature)


# Forbidden fields for deployable / online path
FORBIDDEN_ONLINE_FIELDS = frozenset({
    "label", "attack_family", "forensic_outcome", "contaminated",
    "ground_truth", "hidden_evaluator", "final_outcome", "irreversible_index",
})
