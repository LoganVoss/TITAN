"""Escrow / readiness diagnostics for V10.

Every ESCROW must answer: which exact missing evidence prevented BLOCK or ALLOW?
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Sequence

from .policy import ActionPolicy, Disposition


@dataclass(frozen=True)
class ReadinessReport:
    """Structured answer to why authority was or was not granted."""

    block_ready: bool
    allow_ready: bool
    hard_block_condition: bool
    independent_sources: int
    adverse_independent_sources: int
    favorable_independent_sources: int
    completeness: float
    confidence: float
    adverse_confidence: float
    uncertainty: float
    effect_risk: float
    missing_for_allow: tuple[str, ...]
    missing_for_block: tuple[str, ...]
    block_blockers: tuple[str, ...]
    allow_blockers: tuple[str, ...]
    evidence_kinds_present: tuple[str, ...]
    adverse_kinds: tuple[str, ...]
    favorable_kinds: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def escrow_messages(self) -> tuple[str, ...]:
        """Human-auditable lines explaining ESCROW."""
        lines: list[str] = []
        if self.hard_block_condition and not self.block_ready:
            lines.append(
                "hard_condition_present_but_block_evidence_incomplete"
            )
            for item in self.missing_for_block:
                lines.append(f"missing_block_evidence:{item}")
            for item in self.block_blockers:
                lines.append(f"block_blocker:{item}")
        if not self.allow_ready:
            for item in self.missing_for_allow:
                lines.append(f"missing_allow_evidence:{item}")
            for item in self.allow_blockers:
                lines.append(f"allow_blocker:{item}")
        if not lines:
            lines.append("escrow_without_enumerated_gap")
        return tuple(dict.fromkeys(lines))


def build_readiness_report(
    *,
    policy: ActionPolicy,
    hard_block_condition: bool,
    independent_sources: int,
    adverse_sources: int,
    favorable_sources: int,
    completeness: float,
    confidence: float,
    adverse_confidence: float,
    uncertainty: float,
    effect_risk: float,
    missing_required: Sequence[str],
    evidence_kinds: Sequence[str],
    adverse_kinds: Sequence[str],
    favorable_kinds: Sequence[str],
    budget_exhausted: bool,
    twin_fidelity: float,
    irreversible: bool,
    authorization_validity: float,
    block_rank: float,
) -> ReadinessReport:
    missing_for_allow = tuple(missing_required)
    block_blockers: list[str] = []
    allow_blockers: list[str] = []
    missing_for_block: list[str] = []

    if adverse_sources < policy.minimum_block_sources:
        missing_for_block.append(
            f"adverse_independent_sources>={policy.minimum_block_sources}"
        )
        block_blockers.append("insufficient_adverse_independent_sources")
    if adverse_confidence < policy.minimum_block_confidence:
        missing_for_block.append(
            f"adverse_confidence>={policy.minimum_block_confidence}"
        )
        block_blockers.append("adverse_confidence_below_floor")
    if not (
        uncertainty <= policy.maximum_uncertainty_for_block
        or adverse_sources >= 3
        or (
            adverse_sources >= policy.minimum_block_sources
            and adverse_confidence >= max(policy.minimum_block_confidence, 0.90)
        )
    ):
        block_blockers.append("uncertainty_high_with_sparse_adverse_sources")
    if budget_exhausted and adverse_sources < policy.minimum_block_sources:
        block_blockers.append("verification_budget_exhausted_before_block_proof")

    # Core V10 repair: BLOCK does not require favorable completeness.
    # High-confidence multi-source adverse proof may override prefix uncertainty
    # (uncertainty reflects missing favorable coverage, not weak adverse proof).
    uncertainty_ok = bool(
        uncertainty <= policy.maximum_uncertainty_for_block
        or adverse_sources >= 3
        or (
            adverse_sources >= policy.minimum_block_sources
            and adverse_confidence >= max(policy.minimum_block_confidence, 0.90)
        )
    )
    block_ready_hard = bool(
        hard_block_condition
        and adverse_sources >= policy.minimum_block_sources
        and adverse_confidence >= policy.minimum_block_confidence
        and uncertainty_ok
    )
    block_ready_rank = bool(
        not hard_block_condition
        and block_rank >= policy.block_rank
        and adverse_sources >= policy.minimum_block_sources
        and adverse_confidence >= policy.minimum_block_confidence
        and effect_risk >= policy.minimum_effect_risk
        and uncertainty <= policy.maximum_uncertainty_for_block
    )
    block_ready = block_ready_hard or block_ready_rank

    if missing_for_allow:
        allow_blockers.append("required_favorable_evidence_missing")
    if completeness < policy.minimum_allow_completeness:
        allow_blockers.append("allow_completeness_below_floor")
    if confidence < 0.90:
        allow_blockers.append("allow_confidence_below_floor")
    if authorization_validity < 1.0:
        allow_blockers.append("authorization_not_fully_verified")
    if favorable_sources < 2:
        allow_blockers.append("insufficient_favorable_independent_sources")
    if irreversible and twin_fidelity < 0.70:
        allow_blockers.append("irreversible_requires_high_fidelity_twin")
    if effect_risk >= policy.minimum_effect_risk:
        allow_blockers.append("effect_risk_above_allow_floor")

    allow_ready = bool(
        not hard_block_condition
        and not missing_for_allow
        and completeness >= policy.minimum_allow_completeness
        and confidence >= 0.90
        and authorization_validity >= 1.0
        and favorable_sources >= 2
        and effect_risk < policy.minimum_effect_risk
        and (not irreversible or twin_fidelity >= 0.70)
        and not budget_exhausted
    )

    return ReadinessReport(
        block_ready=block_ready,
        allow_ready=allow_ready,
        hard_block_condition=hard_block_condition,
        independent_sources=independent_sources,
        adverse_independent_sources=adverse_sources,
        favorable_independent_sources=favorable_sources,
        completeness=completeness,
        confidence=confidence,
        adverse_confidence=adverse_confidence,
        uncertainty=uncertainty,
        effect_risk=effect_risk,
        missing_for_allow=missing_for_allow,
        missing_for_block=tuple(missing_for_block),
        block_blockers=tuple(dict.fromkeys(block_blockers)),
        allow_blockers=tuple(dict.fromkeys(allow_blockers)),
        evidence_kinds_present=tuple(evidence_kinds),
        adverse_kinds=tuple(adverse_kinds),
        favorable_kinds=tuple(favorable_kinds),
    )


def disposition_from_readiness(
    readiness: ReadinessReport,
    *,
    kernel_forbidden: bool,
    supported: bool,
    risk_rank: float,
    policy: ActionPolicy,
) -> tuple[Disposition, tuple[str, ...]]:
    reasons: list[str] = []
    if kernel_forbidden:
        return Disposition.BLOCK, ("kernel_forbidden_action",)
    if not supported:
        return Disposition.HUMAN_CONFIRM, ("unsupported_action_class",)
    if readiness.block_ready:
        if readiness.hard_block_condition:
            reasons.append("independently_verified_hard_block_condition")
        else:
            reasons.append("adverse_evidence_dual_channel_block")
        return Disposition.BLOCK, tuple(reasons)
    if readiness.hard_block_condition:
        reasons.append("hard_condition_present_but_block_evidence_incomplete")
        reasons.extend(readiness.escrow_messages())
        return Disposition.ESCROW, tuple(dict.fromkeys(reasons))
    if readiness.allow_ready:
        reasons.append("complete_favorable_safety_case")
        if risk_rank < 0.12:
            return Disposition.ALLOW, tuple(reasons)
        return Disposition.ALLOW_WITH_LOGGING, tuple(reasons)
    residual = (
        risk_rank >= policy.escrow_rank
        or readiness.completeness < policy.minimum_allow_completeness
        or bool(readiness.missing_for_allow)
        or readiness.effect_risk >= policy.minimum_effect_risk
        or bool(readiness.allow_blockers)
    )
    if residual:
        reasons.append("risk_or_incomplete_evidence_requires_escrow")
        reasons.extend(readiness.escrow_messages())
        return Disposition.ESCROW, tuple(dict.fromkeys(reasons))
    if risk_rank >= policy.confirm_rank:
        return Disposition.HUMAN_CONFIRM, ("policy_judgment_required",)
    reasons.append("autonomous_allow_requirements_incomplete")
    reasons.extend(readiness.escrow_messages())
    return Disposition.REQUEST_EVIDENCE, tuple(dict.fromkeys(reasons))
