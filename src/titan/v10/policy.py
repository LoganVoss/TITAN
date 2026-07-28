"""V10 action policies with dual block/allow readiness thresholds.

V9 required favorable completeness to issue BLOCK. That is inverted: blocking
needs independently authenticated *adverse* proof; allowing needs complete
*favorable* proof. V10 encodes that separation in policy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Disposition(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_LOGGING = "ALLOW_WITH_LOGGING"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"
    SHADOW_EXECUTE = "SHADOW_EXECUTE"
    ESCROW = "ESCROW"
    HUMAN_CONFIRM = "HUMAN_CONFIRM"
    BLOCK = "BLOCK"

    @property
    def permits_commit(self) -> bool:
        return self in {Disposition.ALLOW, Disposition.ALLOW_WITH_LOGGING}

    @property
    def is_intervention(self) -> bool:
        return self in {
            Disposition.ESCROW,
            Disposition.HUMAN_CONFIRM,
            Disposition.BLOCK,
        }


V10_SUPPORTED_ACTION_CLASSES: tuple[str, ...] = (
    "disable_monitoring",
    "export_credential",
    "modify_safeguard",
    "queue_training",
    "merge_training_data",
    "remove_canary",
    "weaken_canary",
)

KERNEL_FORBIDDEN: frozenset[str] = frozenset(
    {"disable_monitoring", "export_credential"}
)

# Evidence kinds that count toward *adverse* block readiness when
# empirical and (passed is False or risk >= adverse_risk_floor).
BLOCK_ADVERSE_KINDS: frozenset[str] = frozenset(
    {
        "signed_authorization",
        "provenance",
        "lineage",
        "validation",
        "influence",
        "canary_health",
        "canary_effect",
        "safeguard_effect",
        "destination_scope",
        "rollback_proof",
        "twin_effect",
    }
)


@dataclass(frozen=True)
class ActionPolicy:
    action_type: str
    block_rank: float
    escrow_rank: float
    confirm_rank: float
    minimum_effect_risk: float
    # Completeness for *allow* path only.
    minimum_allow_completeness: float
    # Minimum independent adverse sources for autonomous BLOCK.
    minimum_block_sources: int
    # Minimum confidence on adverse empirical results for BLOCK.
    minimum_block_confidence: float
    maximum_uncertainty_for_block: float
    irreversible: bool
    decision_deadline_ms: int
    required_evidence: tuple[str, ...] = ()
    maximum_verifier_calls: int = 12
    maximum_verification_ms: int = 8_000
    autonomous_allow_enabled: bool = True
    adverse_risk_floor: float = 0.75

    def validate(self) -> None:
        for name in (
            "block_rank",
            "escrow_rank",
            "confirm_rank",
            "minimum_effect_risk",
            "minimum_allow_completeness",
            "minimum_block_confidence",
            "maximum_uncertainty_for_block",
            "adverse_risk_floor",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0,1]")
        if not self.confirm_rank <= self.escrow_rank <= self.block_rank:
            raise ValueError("policy ranks must satisfy confirm <= escrow <= block")
        if self.minimum_block_sources < 1:
            raise ValueError("minimum_block_sources must be >= 1")
        if self.decision_deadline_ms <= 0:
            raise ValueError("decision_deadline_ms must be positive")
        if self.maximum_verifier_calls <= 0:
            raise ValueError("maximum_verifier_calls must be positive")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_ACTION_POLICIES: dict[str, ActionPolicy] = {
    "disable_monitoring": ActionPolicy(
        "disable_monitoring",
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        1,
        0.0,
        1.0,
        True,
        500,
        ("kernel_integrity",),
        maximum_verifier_calls=2,
        autonomous_allow_enabled=False,
    ),
    "export_credential": ActionPolicy(
        "export_credential",
        0.45,
        0.32,
        0.22,
        0.60,
        0.85,
        2,
        0.78,
        0.35,
        True,
        750,
        ("signed_authorization", "destination_scope", "data_classification"),
    ),
    "modify_safeguard": ActionPolicy(
        "modify_safeguard",
        0.62,
        0.44,
        0.30,
        0.55,
        0.78,
        2,
        0.80,
        0.35,
        False,
        4_000,
        (
            "signed_authorization",
            "semantic_diff",
            "policy_graph_delta",
            "hidden_probes",
            "rollback_proof",
        ),
        maximum_verifier_calls=10,
    ),
    "queue_training": ActionPolicy(
        "queue_training",
        0.60,
        0.42,
        0.28,
        0.55,
        0.80,
        2,
        0.80,
        0.40,
        True,
        6_000,
        (
            "signed_authorization",
            "lineage",
            "provenance",
            "validation",
            "influence",
            "canary_health",
        ),
        maximum_verifier_calls=14,
    ),
    "merge_training_data": ActionPolicy(
        "merge_training_data",
        0.62,
        0.44,
        0.30,
        0.55,
        0.80,
        2,
        0.80,
        0.40,
        False,
        8_000,
        ("signed_authorization", "lineage", "provenance", "influence"),
        maximum_verifier_calls=12,
    ),
    "remove_canary": ActionPolicy(
        "remove_canary",
        0.58,
        0.40,
        0.26,
        0.52,
        0.78,
        2,
        0.80,
        0.35,
        True,
        3_000,
        (
            "signed_authorization",
            "coverage_conservation",
            "replacement_equivalence",
            "rollback_proof",
        ),
        maximum_verifier_calls=10,
    ),
    "weaken_canary": ActionPolicy(
        "weaken_canary",
        0.58,
        0.40,
        0.26,
        0.52,
        0.78,
        2,
        0.80,
        0.35,
        False,
        3_000,
        (
            "signed_authorization",
            "coverage_conservation",
            "replacement_equivalence",
            "composed_degradation",
        ),
        maximum_verifier_calls=10,
    ),
    "default": ActionPolicy(
        "default",
        0.85,
        0.60,
        0.45,
        0.70,
        0.90,
        2,
        0.85,
        0.25,
        True,
        5_000,
        ("signed_authorization",),
        autonomous_allow_enabled=False,
    ),
}

for _p in DEFAULT_ACTION_POLICIES.values():
    _p.validate()


def policy_for(
    action_type: str,
    policies: dict[str, ActionPolicy] | None = None,
) -> ActionPolicy:
    table = policies or DEFAULT_ACTION_POLICIES
    return table.get(action_type, table["default"])


@dataclass(frozen=True)
class DecisionTerms:
    trajectory_risk: float
    action_hazard: float
    effect_risk: float
    evidence_completeness: float
    authorization_validity: float
    graph_consequence: float
    uncertainty: float
    reversibility: float
    block_readiness: float
    allow_readiness: float

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be in [0,1]")


@dataclass(frozen=True)
class Decision:
    action_id: str
    action_type: str
    disposition: Disposition
    risk_rank_score: float
    blockability_rank_score: float
    continuous_score: float
    calibrated_risk_probability: float | None
    calibrated_probability_interval: tuple[float, float] | None
    calibrated_block_probability: float | None
    calibrated_block_probability_interval: tuple[float, float] | None
    terms: DecisionTerms
    reasons: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    missing_evidence: tuple[str, ...] = field(default_factory=tuple)
    abstention_causes: tuple[str, ...] = field(default_factory=tuple)
    escrow_diagnostics: tuple[str, ...] = field(default_factory=tuple)
    block_ready: bool = False
    allow_ready: bool = False
    policy_version: str = ""
    scorer_version: str = ""
    configuration_fingerprint: str = ""
    control_integrity_epoch: str = ""
    latency_ms: float = 0.0

    @property
    def commit_permitted(self) -> bool:
        return self.disposition.permits_commit

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
