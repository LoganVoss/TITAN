"""V10 evidence acquisition: reuses V9 adapters, adds dual readiness accounting.

Favorable proof never lowers risk unless independently authenticated.
Adverse proof can raise block readiness without complete favorable coverage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Sequence

from ..v9.action import ActionProposal, ObservableTrajectory
from ..v9.evidence import EvidenceBundle as V9EvidenceBundle
from ..v9.evidence import EvidenceResult, acquire_evidence as v9_acquire_evidence
from ..v9.evidence_trust import VerifiedEvidence
from .policy import BLOCK_ADVERSE_KINDS, ActionPolicy


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


@dataclass(frozen=True)
class V10EvidenceView:
    """Augmented view of V9 evidence with block/allow source accounting."""

    bundle: V9EvidenceBundle
    adverse_results: tuple[EvidenceResult, ...]
    favorable_results: tuple[EvidenceResult, ...]
    adverse_independent_sources: int
    favorable_independent_sources: int
    adverse_confidence: float
    adverse_kinds: tuple[str, ...]
    favorable_kinds: tuple[str, ...]
    continuous_features: dict[str, float]

    @property
    def effect_risk(self) -> float:
        return self.bundle.effect_risk

    @property
    def completeness(self) -> float:
        return self.bundle.completeness

    @property
    def confidence(self) -> float:
        return self.bundle.confidence

    @property
    def hard_block_condition(self) -> bool:
        return self.bundle.hard_block_condition

    @property
    def missing_required(self) -> tuple[str, ...]:
        return self.bundle.missing_required

    @property
    def independent_sources(self) -> int:
        return self.bundle.independent_sources

    @property
    def budget_exhausted(self) -> bool:
        return self.bundle.budget_exhausted

    @property
    def verified_authorization_validity(self) -> float:
        return self.bundle.verified_authorization_validity

    @property
    def twin(self):
        return self.bundle.twin

    @property
    def results(self) -> tuple[EvidenceResult, ...]:
        return self.bundle.results

    @property
    def evidence_hash(self) -> str:
        return self.bundle.evidence_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle.to_dict(),
            "adverse_independent_sources": self.adverse_independent_sources,
            "favorable_independent_sources": self.favorable_independent_sources,
            "adverse_confidence": self.adverse_confidence,
            "adverse_kinds": list(self.adverse_kinds),
            "favorable_kinds": list(self.favorable_kinds),
            "continuous_features": dict(self.continuous_features),
        }


def _is_adverse(item: EvidenceResult, *, risk_floor: float) -> bool:
    if not item.empirical:
        return False
    if item.passed is False:
        return True
    return item.risk >= risk_floor and item.confidence >= 0.70


def _is_favorable(item: EvidenceResult) -> bool:
    return bool(
        item.empirical
        and item.passed is True
        and item.risk < 0.35
        and item.confidence >= 0.70
        and item.coverage >= 0.60
    )


def acquire_evidence_v10(
    prefix: ObservableTrajectory,
    proposal: ActionProposal,
    policy: ActionPolicy,
    *,
    trusted_evidence: Sequence[VerifiedEvidence] = (),
) -> V10EvidenceView:
    # V9 policy object is structural-compatible for acquire_evidence required fields.
    from ..v9.policy import policy_for as v9_policy_for

    v9_policy = v9_policy_for(proposal.action_type)
    # Raise verifier budget for V10 by using a replaced-like budget via local
    # acquisition: call v9 then if budget-limited, still count all trusted.
    bundle = v9_acquire_evidence(
        prefix,
        proposal,
        v9_policy,
        trusted_evidence=trusted_evidence,
    )

    # If V9 budget truncated but we have more trusted evidence, re-acquire with
    # a temporary high-budget policy clone when possible.
    if bundle.budget_exhausted and len(trusted_evidence) > v9_policy.maximum_verifier_calls:
        try:
            from dataclasses import replace

            wide = replace(
                v9_policy,
                maximum_verifier_calls=max(
                    policy.maximum_verifier_calls, len(trusted_evidence) + 4
                ),
                maximum_verification_ms=policy.maximum_verification_ms,
            )
            bundle = v9_acquire_evidence(
                prefix,
                proposal,
                wide,
                trusted_evidence=trusted_evidence,
            )
        except Exception:
            pass

    adverse = tuple(
        item
        for item in bundle.results
        if item.evidence_kind in BLOCK_ADVERSE_KINDS
        and _is_adverse(item, risk_floor=policy.adverse_risk_floor)
    )
    favorable = tuple(item for item in bundle.results if _is_favorable(item))

    adverse_domains = {item.independence_domain for item in adverse}
    favorable_domains = {item.independence_domain for item in favorable}

    if adverse:
        adverse_confidence = sum(
            item.confidence * item.coverage for item in adverse
        ) / max(1e-9, sum(item.coverage for item in adverse))
    else:
        adverse_confidence = 0.0

    continuous = {
        "effect_risk": bundle.effect_risk,
        "twin_fidelity": bundle.twin.fidelity,
        "twin_fidelity_gap": 1.0 - bundle.twin.fidelity,
        "independent_sources": float(bundle.independent_sources),
        "evidence_independence_gap": 1.0
        - min(1.0, bundle.independent_sources / 4.0),
        "authorization_validity": bundle.verified_authorization_validity,
        "authorization_scope_distance": 1.0
        - bundle.verified_authorization_validity,
        "completeness": bundle.completeness,
        "confidence": bundle.confidence,
        "adverse_source_count": float(len(adverse_domains)),
        "favorable_source_count": float(len(favorable_domains)),
        "adverse_confidence": _clip(adverse_confidence),
    }

    # Intrinsic hard condition with no adverse empirical sources still counts
    # local untrusted high-risk effect as a single weak signal domain for
    # diagnostics, but does *not* invent independence.
    return V10EvidenceView(
        bundle=bundle,
        adverse_results=adverse,
        favorable_results=favorable,
        adverse_independent_sources=len(adverse_domains),
        favorable_independent_sources=len(favorable_domains),
        adverse_confidence=_clip(adverse_confidence),
        adverse_kinds=tuple(sorted({item.evidence_kind for item in adverse})),
        favorable_kinds=tuple(sorted({item.evidence_kind for item in favorable})),
        continuous_features=continuous,
    )
