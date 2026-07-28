"""
Phase 6 — Two-phase commit disposition tokens.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import time
import uuid


@dataclass
class DispositionToken:
    token_id: str
    disposition: str  # ALLOW | ESCROW | HUMAN_CONFIRM | BLOCK
    action_id: str
    action_type: str
    trajectory_id: str
    phase: str  # PREPARE | COMMIT
    signed_at: float
    evidence_digest: str
    blockability: float
    effect_risk: float
    trajectory_risk: float
    reasons: list[str] = field(default_factory=list)
    expires_at: float = 0.0
    lease_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def allows_commit(self) -> bool:
        return self.disposition in ("ALLOW", "ALLOW_WITH_LOGGING") and self.phase == "COMMIT"


class TwoPhaseCommit:
    """No irreversible action without a disposition token."""

    def __init__(self):
        self.prepare_log: list[dict[str, Any]] = []
        self.commit_log: list[dict[str, Any]] = []

    def prepare(
        self,
        *,
        action_id: str,
        action_type: str,
        trajectory_id: str,
        disposition: str,
        blockability: float,
        effect_risk: float,
        trajectory_risk: float,
        evidence: dict[str, Any],
        reasons: list[str],
        lease_id: str = "",
        ttl_s: float = 300.0,
    ) -> DispositionToken:
        blob = json_dumps_stable({
            "action_id": action_id, "disposition": disposition,
            "blockability": blockability, "effect": effect_risk, "evidence": evidence,
        })
        digest = hashlib.sha256(blob.encode()).hexdigest()[:16]
        tok = DispositionToken(
            token_id=uuid.uuid4().hex[:16],
            disposition=disposition,
            action_id=action_id,
            action_type=action_type,
            trajectory_id=trajectory_id,
            phase="PREPARE",
            signed_at=time.time(),
            evidence_digest=digest,
            blockability=blockability,
            effect_risk=effect_risk,
            trajectory_risk=trajectory_risk,
            reasons=reasons,
            expires_at=time.time() + ttl_s,
            lease_id=lease_id,
        )
        self.prepare_log.append(tok.to_dict())
        return tok

    def commit(self, token: DispositionToken) -> DispositionToken:
        if token.expires_at and time.time() > token.expires_at:
            token.disposition = "HUMAN_CONFIRM"
            token.reasons = list(token.reasons) + ["token_expired"]
        token.phase = "COMMIT"
        # Only ALLOW/ALLOW_WITH_LOGGING may execute; others deny environment commit
        self.commit_log.append(token.to_dict())
        return token

    def environment_accepts(self, token: DispositionToken) -> bool:
        """Simulated environment gate."""
        if token.phase != "COMMIT":
            return False
        return token.disposition in ("ALLOW", "ALLOW_WITH_LOGGING")


def json_dumps_stable(obj: Any) -> str:
    import json
    return json.dumps(obj, sort_keys=True, default=str)
