"""Typed V9 policy objects for consequential-action governance.

This module is intentionally online-only.  It contains no evaluation labels and
must remain safe to import from an enforcement process.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Disposition(str, Enum):
    """The seven supported action dispositions, ordered by intervention."""

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
    def is_terminal(self) -> bool:
        return self in {
            Disposition.ALLOW,
            Disposition.ALLOW_WITH_LOGGING,
            Disposition.ESCROW,
            Disposition.HUMAN_CONFIRM,
            Disposition.BLOCK,
        }


SUPPORTED_ACTION_CLASSES: tuple[str, ...] = (
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


@dataclass(frozen=True)
class ActionPolicy:
    """Frozen policy for one action class.

    Values are rank-score operating points, not probabilities.  Probability
    estimates live in the calibration subsystem and are never substituted for
    these policy requirements.
    """

    action_type: str
    block_rank: float
    escrow_rank: float
    confirm_rank: float
    minimum_effect_risk: float
    minimum_evidence_completeness: float
    maximum_uncertainty_for_block: float
    irreversible: bool
    decision_deadline_ms: int
    required_evidence: tuple[str, ...] = ()
    maximum_verifier_calls: int = 5
    maximum_verification_ms: int = 5_000
    autonomous_allow_enabled: bool = True

    def validate(self) -> None:
        for name in (
            "block_rank",
            "escrow_rank",
            "confirm_rank",
            "minimum_effect_risk",
            "minimum_evidence_completeness",
            "maximum_uncertainty_for_block",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0,1]")
        if not self.confirm_rank <= self.escrow_rank <= self.block_rank:
            raise ValueError("policy ranks must satisfy confirm <= escrow <= block")
        if self.decision_deadline_ms <= 0:
            raise ValueError("decision_deadline_ms must be positive")
        if self.maximum_verifier_calls <= 0:
            raise ValueError("maximum_verifier_calls must be positive")
        if self.maximum_verification_ms <= 0:
            raise ValueError("maximum_verification_ms must be positive")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_ACTION_POLICIES: dict[str, ActionPolicy] = {
    "disable_monitoring": ActionPolicy(
        "disable_monitoring", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, True, 500,
        ("kernel_integrity",), autonomous_allow_enabled=False,
    ),
    "export_credential": ActionPolicy(
        "export_credential", 0.48, 0.35, 0.25, 0.65, 0.85, 0.10, True, 750,
        ("signed_authorization", "destination_scope", "data_classification"),
    ),
    "modify_safeguard": ActionPolicy(
        "modify_safeguard", 0.70, 0.50, 0.34, 0.60, 0.75, 0.18, False, 3_000,
        (
            "signed_authorization",
            "semantic_diff",
            "policy_graph_delta",
            "hidden_probes",
            "rollback_proof",
        ),
    ),
    "queue_training": ActionPolicy(
        "queue_training", 0.68, 0.48, 0.34, 0.58, 0.72, 0.20, True, 5_000,
        (
            "signed_authorization",
            "lineage",
            "provenance",
            "validation",
            "influence",
            "canary_health",
        ),
        maximum_verifier_calls=6,
    ),
    "merge_training_data": ActionPolicy(
        "merge_training_data", 0.70, 0.50, 0.35, 0.58, 0.74, 0.18, False, 8_000,
        ("signed_authorization", "lineage", "provenance", "influence"),
    ),
    "remove_canary": ActionPolicy(
        "remove_canary", 0.62, 0.44, 0.30, 0.55, 0.72, 0.18, True, 2_000,
        (
            "signed_authorization",
            "coverage_conservation",
            "replacement_equivalence",
            "rollback_proof",
        ),
    ),
    "weaken_canary": ActionPolicy(
        "weaken_canary", 0.64, 0.46, 0.31, 0.55, 0.72, 0.18, False, 2_000,
        (
            "signed_authorization",
            "coverage_conservation",
            "replacement_equivalence",
            "composed_degradation",
        ),
    ),
    "default": ActionPolicy(
        "default", 0.90, 0.66, 0.50, 0.75, 0.85, 0.10, True, 5_000,
        ("signed_authorization",), autonomous_allow_enabled=False,
    ),
}

for _policy in DEFAULT_ACTION_POLICIES.values():
    _policy.validate()


@dataclass(frozen=True)
class DecisionTerms:
    """The first-principles inputs to ``D(a,t)``."""

    trajectory_risk: float
    action_hazard: float
    effect_risk: float
    evidence_completeness: float
    authorization_validity: float
    graph_consequence: float
    uncertainty: float
    reversibility: float

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
    calibrated_risk_probability: float | None
    calibrated_probability_interval: tuple[float, float] | None
    calibrated_block_probability: float | None
    calibrated_block_probability_interval: tuple[float, float] | None
    terms: DecisionTerms
    reasons: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    missing_evidence: tuple[str, ...] = field(default_factory=tuple)
    abstention_causes: tuple[str, ...] = field(default_factory=tuple)
    policy_version: str = "titan-v9-policy-1"
    scorer_version: str = "titan-v9-rank-1"
    configuration_fingerprint: str = ""
    control_integrity_epoch: str = ""
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        self.terms.validate()
        if not 0.0 <= self.risk_rank_score <= 1.0:
            raise ValueError("risk_rank_score must be in [0,1]")
        if not 0.0 <= self.blockability_rank_score <= 1.0:
            raise ValueError("blockability_rank_score must be in [0,1]")
        if self.configuration_fingerprint and (
            len(self.configuration_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.configuration_fingerprint
            )
        ):
            raise ValueError(
                "configuration_fingerprint must be a full lowercase SHA-256 digest"
            )
        if self.calibrated_risk_probability is not None and not (
            0.0 <= self.calibrated_risk_probability <= 1.0
        ):
            raise ValueError("calibrated probability must be in [0,1]")
        if self.calibrated_block_probability is not None and not (
            0.0 <= self.calibrated_block_probability <= 1.0
        ):
            raise ValueError("calibrated block probability must be in [0,1]")
        pairs = (
            (
                "risk",
                self.calibrated_risk_probability,
                self.calibrated_probability_interval,
            ),
            (
                "block",
                self.calibrated_block_probability,
                self.calibrated_block_probability_interval,
            ),
        )
        for name, probability, interval in pairs:
            if (probability is None) != (interval is None):
                raise ValueError(
                    f"calibrated {name} probability and interval must be provided together"
                )
            if interval is not None:
                lower, upper = interval
                if not 0.0 <= lower <= upper <= 1.0:
                    raise ValueError(
                        f"calibrated {name} interval must be ordered in [0,1]"
                    )
                assert probability is not None
                if not lower <= probability <= upper:
                    raise ValueError(
                        f"calibrated {name} interval must contain its probability"
                    )

    @property
    def commit_permitted(self) -> bool:
        return self.disposition.permits_commit

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["disposition"] = self.disposition.value
        return out


def policy_for(
    action_type: str,
    policies: dict[str, ActionPolicy] | None = None,
) -> ActionPolicy:
    source = policies or DEFAULT_ACTION_POLICIES
    return source.get(action_type, source["default"])
