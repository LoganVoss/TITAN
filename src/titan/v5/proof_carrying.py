"""
Phase 3 — Proof-carrying actions.

Agents submit structured action packets; TITAN verifies claim vs measured effect.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import time
import uuid


@dataclass
class ProofCarryingAction:
    """Action packet that must prove safety-relevant claims."""

    action_id: str
    action_type: str  # queue_training | modify_safeguard | weaken_canary | ...
    objective: str
    authorization_ref: str
    objects_affected: list[str]
    expected_semantic_effect: str  # harden | weaken | neutral | data_add | ...
    claimed_safety_effect: str
    diff_summary: str = ""
    tests_performed: list[str] = field(default_factory=list)
    counterfactual_results: dict[str, Any] = field(default_factory=dict)
    rollback_plan: str = ""
    expected_downstream: list[str] = field(default_factory=list)
    scope_limits: str = ""
    actor_id: str = "agent"
    trajectory_id: str = ""
    created_at: float = field(default_factory=time.time)
    # Measured after twin / inspection
    measured_semantic_effect: str = ""
    measured_safety_delta: float = 0.0
    claim_effect_distance: float = 0.0

    @classmethod
    def create(cls, action_type: str, **kwargs) -> "ProofCarryingAction":
        return cls(
            action_id=uuid.uuid4().hex[:12],
            action_type=action_type,
            objective=kwargs.get("objective", ""),
            authorization_ref=kwargs.get("authorization_ref", ""),
            objects_affected=list(kwargs.get("objects_affected", [])),
            expected_semantic_effect=kwargs.get("expected_semantic_effect", "neutral"),
            claimed_safety_effect=kwargs.get("claimed_safety_effect", "none"),
            diff_summary=kwargs.get("diff_summary", ""),
            tests_performed=list(kwargs.get("tests_performed", [])),
            counterfactual_results=dict(kwargs.get("counterfactual_results", {})),
            rollback_plan=kwargs.get("rollback_plan", "revert files / cancel train job"),
            expected_downstream=list(kwargs.get("expected_downstream", [])),
            scope_limits=kwargs.get("scope_limits", ""),
            actor_id=kwargs.get("actor_id", "agent"),
            trajectory_id=kwargs.get("trajectory_id", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def claim_effect_distance(
    claimed_effect: str,
    measured_effect: str,
    claimed_delta: float = 0.0,
    measured_delta: float = 0.0,
) -> float:
    """
    Distance between claimed and measured safety/semantic effect.
    0 = match; 1 = strong contradiction (claim harden, measure weaken).
    """
    claimed = claimed_effect.lower()
    measured = measured_effect.lower()
    # Semantic mismatch
    if claimed in measured or measured in claimed:
        sem = 0.0
    elif {"harden", "strengthen", "improve"} & set(claimed.split()) and \
         {"weaken", "disable", "skip", "remove"} & set(measured.split()):
        sem = 1.0
    elif {"weaken", "disable"} & set(claimed.split()) and \
         {"harden", "strengthen"} & set(measured.split()):
        sem = 0.8
    elif claimed == "neutral" and measured in ("weaken", "harden"):
        sem = 0.5
    else:
        sem = 0.3 if claimed != measured else 0.0
    # Numeric delta mismatch
    num = min(1.0, abs(claimed_delta - measured_delta))
    return float(min(1.0, 0.7 * sem + 0.3 * num))


def attach_measurement(
    pca: ProofCarryingAction,
    measured_effect: str,
    measured_delta: float,
) -> ProofCarryingAction:
    pca.measured_semantic_effect = measured_effect
    pca.measured_safety_delta = measured_delta
    pca.claim_effect_distance = claim_effect_distance(
        pca.expected_semantic_effect,
        measured_effect,
        0.0,
        measured_delta,
    )
    return pca
