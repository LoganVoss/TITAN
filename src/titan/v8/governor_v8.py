"""
Decisive Action Governor — integrates ABC, effect network, evidence, two-phase, leases.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..schema import AgentTrajectory, Label
from ..v7.scorer import V7Scorer
from .action_boundary import compile_action, ActionCase, SUPPORTED_BLOCK_CLASSES
from .blockability import BlockabilityModel, BlockabilityDecision
from .two_phase import TwoPhaseCommit, DispositionToken
from .capability_lease import LeaseRegistry
from .evidence_acq import EvidenceAcquisition


@dataclass
class GovernorV8Result:
    disposition: str
    token: dict[str, Any]
    case: dict[str, Any]
    blockability: dict[str, Any]
    commit_allowed: bool
    audit: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DecisiveGovernor:
    """Final-form circuit: detect + evidence + block at action boundary."""

    version = "governor-v8.0.0-decisive"

    def __init__(self, scorer: V7Scorer | None = None):
        self.scorer = scorer or V7Scorer()
        self.block_model = BlockabilityModel(self.scorer)
        self.two_phase = TwoPhaseCommit()
        self.leases = LeaseRegistry()
        self.audit_log: list[dict[str, Any]] = []

    def evaluate(self, t: AgentTrajectory, case: ActionCase | None = None) -> GovernorV8Result:
        case = case or compile_action(t, scorer=self.scorer)
        # Capability lease check
        lease_reasons: list[str] = []
        lease_id = ""
        if case.authorization:
            lease = self.leases.from_authorization_ref(
                case.authorization, case.action_type, case.objects_affected
            )
            if lease:
                lease_id = lease.lease_id
                ok, lease_reasons = self.leases.verify(
                    lease.lease_id,
                    actor=case.actor,
                    action_type=case.action_type,
                    objects=case.objects_affected,
                    measured_effect=case.measured_effect,
                )
                if not ok and case.action_type in SUPPORTED_BLOCK_CLASSES:
                    # Invalid lease escalates blockability path
                    pass

        dec = self.block_model.decide(t, case)
        reasons = list(dec.reasons) + [f"lease:{r}" for r in lease_reasons]

        # Invalid lease on consequential action → at least ESCROW
        if lease_reasons and "lease_ok" not in lease_reasons:
            if dec.disposition in ("ALLOW", "ALLOW_WITH_LOGGING", "REQUEST_EVIDENCE"):
                dec.disposition = "ESCROW"
                reasons.append("invalid_or_expired_lease")
            if any(x in lease_reasons for x in (
                "direction_mismatch_weaken_not_allowed", "lease_expired", "object_out_of_scope"
            )) and case.action_type in ("modify_safeguard", "remove_canary"):
                dec.disposition = "BLOCK"
                reasons.append("lease_violation_autonomous_block")

        # Two-phase prepare
        token = self.two_phase.prepare(
            action_id=case.action_id,
            action_type=case.action_type,
            trajectory_id=t.trajectory_id,
            disposition=dec.disposition,
            blockability=dec.blockability,
            effect_risk=dec.effect_risk,
            trajectory_risk=dec.trajectory_risk,
            evidence={
                "sufficiency": dec.evidence_sufficiency,
                "effect": dec.effect,
                "plan": dec.evidence_plan,
            },
            reasons=reasons,
            lease_id=lease_id,
        )
        token = self.two_phase.commit(token)
        commit_ok = self.two_phase.environment_accepts(token)

        audit = {
            "governor_version": self.version,
            "supported": dec.supported,
            "region": dec.region,
            "lease_id": lease_id,
            "lease_reasons": lease_reasons,
            "commit_allowed": commit_ok,
        }
        result = GovernorV8Result(
            disposition=token.disposition,
            token=token.to_dict(),
            case=case.to_dict(),
            blockability=dec.to_dict(),
            commit_allowed=commit_ok,
            audit=audit,
        )
        self.audit_log.append(result.to_dict())
        return result
