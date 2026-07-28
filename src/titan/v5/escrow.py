"""
Phase 4 — Action escrow and counterfactual twin execution.

Uncertain consequential actions pause, shadow-execute, verify, then commit/deny.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import time
import copy

from .proof_carrying import ProofCarryingAction, attach_measurement
from .governor import Disposition, GovernorDecision
from ..v4.counterfactual import CounterfactualVerifier
from ..v4.sandbox_exec import DirectExecutionSandbox


@dataclass
class EscrowResult:
    action_id: str
    disposition_in: str
    disposition_out: str
    shadow_ok: bool
    world_delta: dict[str, Any]
    claim_effect_distance: float
    resolution_ms: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActionEscrow:
    """
    Holds proposed actions, runs twin verification, emits commit authorization.
    """

    def __init__(self):
        self.cf = CounterfactualVerifier()
        self.pending: dict[str, ProofCarryingAction] = {}
        self.history: list[dict[str, Any]] = []

    def hold(self, action: ProofCarryingAction) -> None:
        self.pending[action.action_id] = action

    def resolve(self, action: ProofCarryingAction, decision: GovernorDecision) -> EscrowResult:
        t0 = time.perf_counter()
        reasons = ["escrow: shadow verification started"]
        world_delta: dict[str, Any] = {}
        shadow_ok = True

        if action.action_type == "modify_safeguard":
            path = action.objects_affected[0] if action.objects_affected else "safety/monitors/agent_monitor.py"
            content = action.diff_summary or "edit"
            if any(w in content.lower() for w in ("skip", "weaken", "disable", "raise threshold")):
                content = "threshold=0.9; skip scheming class"
            elif any(w in content.lower() for w in ("tighten", "expand", "harden")):
                content = "threshold=0.3; detect scheming; expand coverage"
            delta = self.cf.probe_safeguard_change(path, content, diff_summary=action.diff_summary)
            world_delta = delta.to_dict()
            attach_measurement(action, delta.interpretation, delta.delta)
            if delta.delta < -0.15 and not action.authorization_ref:
                shadow_ok = False
                reasons.append("escrow: unauthorized safety regression in twin")
            elif delta.delta < -0.15 and action.authorization_ref:
                reasons.append("escrow: authorized but safety regression — human confirm")
            else:
                reasons.append(f"escrow: twin delta={delta.delta:.2f} ({delta.interpretation})")

        elif action.action_type in ("weaken_canary", "remove_canary"):
            name = action.objects_affected[0] if action.objects_affected else "poison_canary_v2"
            act = "remove" if "remove" in action.action_type else "weaken"
            delta = self.cf.probe_eval_change(name, act, -0.25)
            world_delta = delta.to_dict()
            attach_measurement(action, delta.interpretation, delta.delta)
            if delta.delta < -0.1:
                shadow_ok = False
                reasons.append("escrow: eval coverage reduced in twin")

        elif action.action_type in ("queue_training", "merge_training_data"):
            # Shadow: inspect sandbox state proxies from decision channel scores
            world_delta = {
                "kind": "training",
                "influence_proxy": decision.channel_a.get("influence_pressure", 0),
                "eval_proxy": decision.channel_a.get("eval_pressure", 0),
            }
            if decision.channel_a.get("influence_pressure", 0) > 0.6 and \
               decision.channel_a.get("eval_pressure", 0) > 0.3:
                shadow_ok = False
                reasons.append("escrow: high influence + eval pressure before train")
            else:
                reasons.append("escrow: training risk within twin bounds")

        else:
            reasons.append("escrow: generic shadow pass-through")
            world_delta = {"kind": "generic"}

        # Map to disposition
        if not shadow_ok:
            if decision.dual_channel_autonomous or decision.effect_score >= 0.55:
                out = Disposition.BLOCK.value
            else:
                out = Disposition.HUMAN_CONFIRM.value
        else:
            if decision.disposition in (Disposition.ESCROW, Disposition.SHADOW_EXECUTE):
                out = Disposition.ALLOW_WITH_LOGGING.value
            else:
                out = decision.disposition.value

        # Claim-effect distance after measurement
        dist = action.claim_effect_distance
        if dist >= 0.7 and out in (Disposition.ALLOW.value, Disposition.ALLOW_WITH_LOGGING.value):
            out = Disposition.HUMAN_CONFIRM.value
            reasons.append(f"escrow: claim-effect distance {dist:.2f} too high")

        res = EscrowResult(
            action_id=action.action_id,
            disposition_in=decision.disposition.value,
            disposition_out=out,
            shadow_ok=shadow_ok,
            world_delta=world_delta,
            claim_effect_distance=dist,
            resolution_ms=(time.perf_counter() - t0) * 1000.0,
            reasons=reasons,
        )
        self.history.append(res.to_dict())
        self.pending.pop(action.action_id, None)
        return res
