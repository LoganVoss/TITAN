"""
Step 5 — Signed event gateway.

Agents cannot forge trusted monitor fields. Gateway validates, dedupes, signs,
tracks ordering, and appends to storage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import secrets
import time

from .schema_v4 import (
    CanonicalEvent,
    FORBIDDEN_ONLINE_FIELDS,
    IntegrityEnvelope,
    sign_payload,
    verify_envelope,
)


@dataclass
class GatewayHealth:
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    missing_parent_warnings: int = 0
    integrity_alerts: int = 0


class SignedEventGateway:
    """
    Trusted ingestion boundary.

    The signing secret never leaves the gateway process. Agents submit
    untrusted events; only signed envelopes enter the trajectory store.
    """

    def __init__(self, secret: bytes | None = None, key_id: str = "gw-v4"):
        self.secret = secret or secrets.token_bytes(32)
        self.key_id = key_id
        self._seen_ids: set[str] = set()
        self._store: list[IntegrityEnvelope] = []
        self._health = GatewayHealth()
        self._drops: list[dict[str, Any]] = []

    @property
    def health(self) -> GatewayHealth:
        return self._health

    def ingest(
        self,
        event: CanonicalEvent,
        *,
        mode: str = "online",
        known_event_ids: set[str] | None = None,
    ) -> IntegrityEnvelope | None:
        """
        Validate and sign an event. Returns envelope or None if rejected.
        mode=online strips forensic fields and rejects forbidden fields.
        """
        # Dedup
        if event.event_id in self._seen_ids:
            self._health.duplicates += 1
            self._drops.append({"reason": "duplicate", "event_id": event.event_id})
            return None

        # Schema basics
        if not event.event_type or not event.trajectory_id:
            self._health.rejected += 1
            self._drops.append({"reason": "schema", "event_id": event.event_id})
            return None

        # Forbidden online fields in payload
        if mode == "online":
            for k in list(event.payload.keys()):
                if k in FORBIDDEN_ONLINE_FIELDS:
                    self._health.rejected += 1
                    self._health.integrity_alerts += 1
                    self._drops.append({
                        "reason": "forbidden_field",
                        "field": k,
                        "event_id": event.event_id,
                    })
                    return None
            event.forensic_outcome = {}

        # Parent presence warnings
        known = known_event_ids or self._seen_ids
        for pid in event.parent_event_ids:
            if pid not in known:
                self._health.missing_parent_warnings += 1

        event.payload_hash = event.compute_payload_hash()
        event.ingest_timestamp = time.time()
        payload = event.to_dict(include_forensic=(mode != "online"))
        # Prevent agent-supplied trusted monitor fields
        payload.pop("integrity_signature", None)

        env = sign_payload(payload, self.secret, self.key_id)
        if not verify_envelope(env, self.secret):
            self._health.rejected += 1
            self._health.integrity_alerts += 1
            return None

        self._seen_ids.add(event.event_id)
        self._store.append(env)
        self._health.accepted += 1
        return env

    def verify_stored(self, envelope: IntegrityEnvelope) -> bool:
        ok = verify_envelope(envelope, self.secret)
        if not ok:
            self._health.integrity_alerts += 1
        return ok

    def append_only_log(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._store]

    def events_for_trajectory(self, trajectory_id: str) -> list[dict[str, Any]]:
        out = []
        for env in self._store:
            if env.event.get("trajectory_id") == trajectory_id:
                out.append(env.event)
        return sorted(out, key=lambda e: e.get("causal_timestamp", 0))

    def forge_attempt(self, fake_event: dict[str, Any], forged_sig: str = "deadbeef") -> bool:
        """
        Simulate agent forging. Returns True if gateway correctly rejects.
        """
        env = IntegrityEnvelope(
            event=fake_event,
            signature=forged_sig,
            key_id=self.key_id,
            signed_at=time.time(),
        )
        return not self.verify_stored(env)
