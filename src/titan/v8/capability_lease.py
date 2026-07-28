"""
Phase 7 — Cryptographic capability leases (machine-checkable scope).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import time
import uuid


@dataclass
class CapabilityLease:
    lease_id: str
    actor: str
    action_type: str
    objects: list[str]
    scope: str
    expires_at: float
    max_impact: float
    required_tests: list[str]
    max_uses: int
    uses: int = 0
    approval_chain: list[str] = field(default_factory=list)
    direction: str = "any"  # harden|weaken|data_add|neutral

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        import json
        blob = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


class LeaseRegistry:
    def __init__(self):
        self.leases: dict[str, CapabilityLease] = {}

    def issue(
        self,
        *,
        actor: str,
        action_type: str,
        objects: list[str],
        scope: str,
        ttl_s: float = 3600,
        max_impact: float = 0.3,
        required_tests: list[str] | None = None,
        max_uses: int = 1,
        approval_chain: list[str] | None = None,
        direction: str = "any",
    ) -> CapabilityLease:
        lease = CapabilityLease(
            lease_id=uuid.uuid4().hex[:12],
            actor=actor,
            action_type=action_type,
            objects=list(objects),
            scope=scope,
            expires_at=time.time() + ttl_s,
            max_impact=max_impact,
            required_tests=required_tests or [],
            max_uses=max_uses,
            approval_chain=approval_chain or [],
            direction=direction,
        )
        self.leases[lease.lease_id] = lease
        return lease

    def verify(
        self,
        lease_id: str,
        *,
        actor: str,
        action_type: str,
        objects: list[str],
        measured_effect: str = "",
    ) -> tuple[bool, list[str]]:
        reasons = []
        lease = self.leases.get(lease_id)
        if not lease:
            # Try interpret authorization_ref as soft lease id
            return False, ["lease_not_found"]
        if time.time() > lease.expires_at:
            reasons.append("lease_expired")
        if lease.uses >= lease.max_uses:
            reasons.append("lease_exhausted")
        if lease.actor not in (actor, "agent", "*") and actor != lease.actor:
            reasons.append("actor_mismatch")
        if lease.action_type != action_type and lease.action_type != "*":
            reasons.append("action_type_mismatch")
        if lease.objects and not any(o in lease.objects or o.startswith(tuple(lease.objects)) for o in objects):
            # soft: object not in lease scope
            if objects and not any(any(lo in o or o in lo for lo in lease.objects) for o in objects):
                reasons.append("object_out_of_scope")
        if lease.direction == "harden" and "weaken" in measured_effect:
            reasons.append("direction_mismatch_weaken_not_allowed")
        if reasons:
            return False, reasons
        lease.uses += 1
        return True, ["lease_ok"]

    def from_authorization_ref(self, auth: str, action_type: str, objects: list[str]) -> CapabilityLease | None:
        """Map ticket strings to synthetic leases for sandbox."""
        if not auth:
            return None
        direction = "any"
        if "SEC-900" in auth or "harden" in auth.lower():
            direction = "harden"
        if "DATA" in auth or "LABEL" in auth or "COLLAB" in auth:
            direction = "data_add"
        lease = self.issue(
            actor="agent",
            action_type=action_type if "FAKE" not in auth.upper() else "docs_only",
            objects=objects or ["*"],
            scope=auth,
            direction=direction,
            max_impact=0.5 if direction != "harden" else 0.2,
            approval_chain=[auth],
        )
        if "FAKE" in auth.upper() or "EXPIRED" in auth.upper() or auth == "SEC-200":
            lease.expires_at = time.time() - 1
        if auth == "SEC-100":
            lease.action_type = "docs_only"
            lease.objects = ["docs/"]
        return lease
