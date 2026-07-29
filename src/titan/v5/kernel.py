"""
Immutable safety kernel — Stage 1 of the governor.

TITAN cannot modify this layer. Deterministic, extremely fast checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .proof_carrying import ProofCarryingAction


# Protected paths / action taxonomy — kernel-owned constants
PROTECTED_PATH_PREFIXES = (
    "safety/monitors/",
    "safety/policy/",
    "safety/guardrails",
    "evals/",
    "ci/grader",
)
FORBIDDEN_WITHOUT_AUTH = frozenset({
    "queue_training",
    "modify_safeguard",
    "weaken_canary",
    "remove_canary",
    "export_credential",
    "disable_monitoring",
    "deploy_protected",
    "merge_training_data",
})
ALWAYS_BLOCK = frozenset({"disable_monitoring"})
CATASTROPHIC = frozenset({
    "export_credential",
    "disable_monitoring",
})


@dataclass
class KernelVerdict:
    allowed_to_proceed: bool  # whether Stage 2 may run
    force_disposition: str | None  # if set, skip to this disposition
    reasons: list[str] = field(default_factory=list)
    deterministic_violation: bool = False
    channel_b_hint: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_to_proceed": self.allowed_to_proceed,
            "force_disposition": self.force_disposition,
            "reasons": self.reasons,
            "deterministic_violation": self.deterministic_violation,
            "channel_b_hint": self.channel_b_hint,
        }


class ImmutableSafetyKernel:
    """
    Fast deterministic policy. Outside TITAN self-improvement loop.
    """

    version = "kernel-v5.0.0"

    def evaluate(self, action: ProofCarryingAction) -> KernelVerdict:
        reasons: list[str] = []
        # Always block monitoring disable
        if action.action_type in ALWAYS_BLOCK:
            return KernelVerdict(
                allowed_to_proceed=False,
                force_disposition="BLOCK",
                reasons=["kernel: disable_monitoring is forbidden"],
                deterministic_violation=True,
            )

        # Missing authorization for forbidden actions
        needs_auth = action.action_type in FORBIDDEN_WITHOUT_AUTH
        has_auth = bool(action.authorization_ref and action.authorization_ref.strip())
        if needs_auth and not has_auth:
            reasons.append("kernel: missing authorization_ref for consequential action")
            # Irreversible high-risk without auth → temporary block path
            if action.action_type in CATASTROPHIC or action.action_type in (
                "queue_training", "modify_safeguard", "weaken_canary", "remove_canary"
            ):
                return KernelVerdict(
                    allowed_to_proceed=True,  # Stage 2 still scores, but force min disposition
                    force_disposition="HUMAN_CONFIRM",
                    reasons=reasons + ["kernel: unauth high-risk → HUMAN_CONFIRM minimum"],
                    deterministic_violation=True,
                )

        # Protected path changes without auth
        for obj in action.objects_affected:
            if any(obj.startswith(p) or p in obj for p in PROTECTED_PATH_PREFIXES):
                if not has_auth:
                    reasons.append(f"kernel: protected path {obj} without authorization")
                    return KernelVerdict(
                        allowed_to_proceed=True,
                        force_disposition="ESCROW",
                        reasons=reasons,
                        deterministic_violation=True,
                    )

        # Claimed harden but objects include canary remove
        if action.action_type in ("remove_canary", "weaken_canary"):
            if "harden" in action.expected_semantic_effect.lower() or \
               "improve" in action.claimed_safety_effect.lower():
                reasons.append("kernel: impossible claim — weaken/remove canary claimed as harden")
                return KernelVerdict(
                    allowed_to_proceed=True,
                    force_disposition="ESCROW",
                    reasons=reasons,
                    deterministic_violation=True,
                    channel_b_hint={"claim_contradiction": True},
                )

        # Empty objects for modify actions
        if action.action_type in ("modify_safeguard", "merge_training_data") and not action.objects_affected:
            reasons.append("kernel: no objects_affected specified")
            return KernelVerdict(
                allowed_to_proceed=True,
                force_disposition="REQUEST_EVIDENCE",
                reasons=reasons,
            )

        return KernelVerdict(
            allowed_to_proceed=True,
            force_disposition=None,
            reasons=reasons or ["kernel: pass"],
        )
