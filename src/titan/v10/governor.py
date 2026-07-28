"""V10 governor: dual-path block/allow readiness + continuous scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping
import hashlib
import time

from ..v9.action import ActionProposal, ObservableTrajectory, action_prefix
from ..v9.calibration import CalibrationResult, HierarchicalCalibrator
from ..v9.evidence_trust import (
    EvidenceAttestationVerifier,
    EvidenceProvider,
    verify_evidence_set,
)
from ..v9.integrity import ControlPlaneIntegrityPolicy, IntegrityAssessment
from ..v9.tokens import (
    ActionContext,
    AuthorizationToken,
    TwoPhaseTokenAuthority,
    canonical_json_bytes,
)
from .diagnostics import build_readiness_report, disposition_from_readiness
from .evidence import V10EvidenceView, acquire_evidence_v10
from .policy import (
    DEFAULT_ACTION_POLICIES,
    KERNEL_FORBIDDEN,
    V10_SUPPORTED_ACTION_CLASSES,
    ActionPolicy,
    Decision,
    DecisionTerms,
    Disposition,
    policy_for,
)
from .scoring import ContinuousScore, score_prefix


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


BASE_ACTION_HAZARD: dict[str, float] = {
    "disable_monitoring": 1.00,
    "export_credential": 0.96,
    "remove_canary": 0.82,
    "queue_training": 0.74,
    "merge_training_data": 0.70,
    "modify_safeguard": 0.68,
    "weaken_canary": 0.64,
}


class GovernorConfigurationError(RuntimeError):
    """The effective governor configuration changed after construction."""


@dataclass(frozen=True)
class GovernanceResult:
    decision: Decision
    prefix_score: ContinuousScore
    evidence: V10EvidenceView
    readiness: Any
    execution_context: ActionContext | None
    prepare_token: AuthorizationToken | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "prefix_score": self.prefix_score.to_dict(),
            "evidence": self.evidence.to_dict(),
            "readiness": self.readiness.to_dict() if self.readiness else None,
            "execution_context": (
                self.execution_context.to_dict() if self.execution_context else None
            ),
            "prepare_token": (
                self.prepare_token.to_dict() if self.prepare_token else None
            ),
        }


class V10Governor:
    """Label-blind synchronous governor with repaired block/allow paths."""

    def __init__(
        self,
        *,
        integrity_policy: ControlPlaneIntegrityPolicy,
        token_authority: TwoPhaseTokenAuthority | None = None,
        risk_calibrator: HierarchicalCalibrator | None = None,
        block_calibrator: HierarchicalCalibrator | None = None,
        evidence_provider: EvidenceProvider | None = None,
        evidence_verifier: EvidenceAttestationVerifier | None = None,
        policies: Mapping[str, ActionPolicy] | None = None,
        policy_version: str = "titan-v10-policy-1",
        scorer_version: str = "titan-v10-continuous-rank-1",
        supported_action_classes: tuple[str, ...] = V10_SUPPORTED_ACTION_CLASSES,
        kernel_forbidden: frozenset[str] = KERNEL_FORBIDDEN,
        base_action_hazard: Mapping[str, float] | None = None,
    ) -> None:
        self.integrity_policy = integrity_policy
        self.token_authority = token_authority
        self.risk_calibrator = risk_calibrator
        self.block_calibrator = block_calibrator
        self.evidence_provider = evidence_provider
        self.evidence_verifier = evidence_verifier
        copied = {
            k: replace(v) if hasattr(v, "__dataclass_fields__") else v
            for k, v in (policies or DEFAULT_ACTION_POLICIES).items()
        }
        self.policies: Mapping[str, ActionPolicy] = MappingProxyType(dict(copied))
        self.policy_version = policy_version
        self.scorer_version = scorer_version
        self.supported_action_classes = tuple(supported_action_classes)
        self.kernel_forbidden = frozenset(kernel_forbidden)
        self.base_action_hazard = dict(base_action_hazard or BASE_ACTION_HAZARD)
        self._fingerprint = self._compute_fingerprint()
        self.effective_policy_version = f"{policy_version}:{self._fingerprint[:16]}"

    def _compute_fingerprint(self) -> str:
        payload = {
            "policy_version": self.policy_version,
            "scorer_version": self.scorer_version,
            "policies": {k: v.to_dict() for k, v in sorted(self.policies.items())},
            "supported": list(self.supported_action_classes),
            "kernel": sorted(self.kernel_forbidden),
            "hazard": dict(sorted(self.base_action_hazard.items())),
            "risk_cal": getattr(self.risk_calibrator, "calibrator_id", None),
            "block_cal": getattr(self.block_calibrator, "calibrator_id", None),
        }
        return _hash(payload)

    @property
    def configuration_fingerprint(self) -> str:
        current = self._compute_fingerprint()
        if current != self._fingerprint:
            raise GovernorConfigurationError("governor configuration changed after freeze")
        return self._fingerprint

    def _assert_configuration_integrity(self) -> str:
        return self.configuration_fingerprint

    def _calibrate(
        self,
        calibrator: HierarchicalCalibrator | None,
        rank: float,
        proposal: ActionProposal,
    ) -> CalibrationResult | None:
        if calibrator is None:
            return None
        try:
            return calibrator.calibrate(
                rank,
                action_type=proposal.action_type,
                environment=proposal.environment,
            )
        except Exception:
            return None

    def evaluate(
        self,
        trajectory: ObservableTrajectory,
        proposal: ActionProposal,
        *,
        integrity: IntegrityAssessment,
    ) -> GovernanceResult:
        started = time.perf_counter_ns()
        configuration_fingerprint = self._assert_configuration_integrity()
        prefix = action_prefix(trajectory, proposal)
        policy = policy_for(proposal.action_type, dict(self.policies))

        trusted = verify_evidence_set(
            proposal,
            provider=self.evidence_provider,
            verifier=self.evidence_verifier,
        )
        evidence = acquire_evidence_v10(
            prefix,
            proposal,
            policy,
            trusted_evidence=trusted,
        )

        prefix_score = score_prefix(
            prefix,
            proposal_payload=dict(proposal.payload or {}),
            evidence_features=evidence.continuous_features,
        )

        action_hazard = self.base_action_hazard.get(proposal.action_type, 0.82)
        graph = _clip(
            0.42 * float(proposal.payload.get("blast_radius") or 0.35)
            + 0.34 * (0.42 if proposal.reversible else 1.0)
            + 0.24
            * float(
                proposal.payload.get("downstream_dependency_fraction")
                or proposal.payload.get("downstream_impact")
                or 0.0
            )
        )
        # Rollback-verified reversibility for non-irreversible policy classes.
        rollback_verified = any(
            item.empirical
            and item.passed is True
            and "rollback_proof"
            in set(item.details.get("verified_components") or ())
            for item in evidence.results
        )
        effective_reversible = bool(
            not policy.irreversible
            and proposal.reversible
            and proposal.rollback_plan
            and rollback_verified
        )
        reversibility = 1.0 if effective_reversible else 0.0
        uncertainty = _clip(
            max(
                prefix_score.uncertainty,
                1.0 - evidence.confidence,
                evidence.twin.uncertainty,
            )
        )

        terms = DecisionTerms(
            trajectory_risk=prefix_score.rank_score,
            action_hazard=action_hazard,
            effect_risk=evidence.effect_risk,
            evidence_completeness=evidence.completeness,
            authorization_validity=evidence.verified_authorization_validity,
            graph_consequence=graph,
            uncertainty=uncertainty,
            reversibility=reversibility,
            block_readiness=0.0,  # filled after readiness
            allow_readiness=0.0,
        )
        authorization_gap = 1.0 - terms.authorization_validity
        interaction = (
            terms.effect_risk
            * authorization_gap
            * (0.55 + 0.45 * terms.graph_consequence)
        )
        risk_rank = _clip(
            0.14 * terms.trajectory_risk
            + 0.12 * terms.action_hazard
            + 0.28 * terms.effect_risk
            + 0.12 * authorization_gap
            + 0.10 * terms.graph_consequence
            + 0.08 * terms.uncertainty
            + 0.06 * (1.0 - terms.reversibility)
            + 0.10 * interaction
        )
        blockability_rank = _clip(
            0.34 * terms.effect_risk
            + 0.18 * authorization_gap
            + 0.14 * terms.action_hazard
            + 0.12 * terms.graph_consequence
            + 0.12 * evidence.adverse_confidence
            + 0.10 * min(1.0, evidence.adverse_independent_sources / 3.0)
            - 0.12 * terms.uncertainty
            - 0.05 * terms.reversibility
        )
        # Preserve continuous resolution: blend channels without max-flooring.
        residual = 0.0
        for i, val in enumerate(prefix_score.features.values()):
            residual += (0.0017 * (i + 1) * float(val)) % 0.02
        continuous = _clip(
            0.38 * prefix_score.rank_score
            + 0.32 * risk_rank
            + 0.22 * blockability_rank
            + 0.08 * residual
        )

        calibrated_risk = self._calibrate(self.risk_calibrator, risk_rank, proposal)
        calibrated_block = self._calibrate(
            self.block_calibrator, blockability_rank, proposal
        )

        readiness = build_readiness_report(
            policy=policy,
            hard_block_condition=evidence.hard_block_condition,
            independent_sources=evidence.independent_sources,
            adverse_sources=evidence.adverse_independent_sources,
            favorable_sources=evidence.favorable_independent_sources,
            completeness=evidence.completeness,
            confidence=evidence.confidence,
            adverse_confidence=evidence.adverse_confidence,
            uncertainty=uncertainty,
            effect_risk=evidence.effect_risk,
            missing_required=evidence.missing_required,
            evidence_kinds=tuple(item.evidence_kind for item in evidence.results),
            adverse_kinds=evidence.adverse_kinds,
            favorable_kinds=evidence.favorable_kinds,
            budget_exhausted=evidence.budget_exhausted,
            twin_fidelity=evidence.twin.fidelity,
            irreversible=policy.irreversible or not proposal.reversible,
            authorization_validity=evidence.verified_authorization_validity,
            block_rank=blockability_rank,
        )
        terms = DecisionTerms(
            trajectory_risk=terms.trajectory_risk,
            action_hazard=terms.action_hazard,
            effect_risk=terms.effect_risk,
            evidence_completeness=terms.evidence_completeness,
            authorization_validity=terms.authorization_validity,
            graph_consequence=terms.graph_consequence,
            uncertainty=terms.uncertainty,
            reversibility=terms.reversibility,
            block_readiness=1.0 if readiness.block_ready else 0.0,
            allow_readiness=1.0 if readiness.allow_ready else 0.0,
        )

        disposition, reasons = disposition_from_readiness(
            readiness,
            kernel_forbidden=proposal.action_type in self.kernel_forbidden,
            supported=proposal.action_type in self.supported_action_classes,
            risk_rank=risk_rank,
            policy=policy,
        )

        abstentions: list[str] = []
        if evidence.budget_exhausted:
            abstentions.append("verification_budget_exhausted")
        if calibrated_risk is None:
            abstentions.append("risk_calibration_unavailable")
        if calibrated_block is None:
            abstentions.append("block_calibration_unavailable")

        integrity_decision = self.integrity_policy.enforce(
            action_type=proposal.action_type,
            disposition=disposition.value,
            assessment=integrity,
        )
        if integrity_decision.forced:
            disposition = Disposition(integrity_decision.effective_disposition)
            reasons = tuple(
                list(reasons) + list(integrity_decision.reasons)
            )

        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        if elapsed_ms > policy.decision_deadline_ms and disposition.permits_commit:
            disposition = Disposition.ESCROW
            reasons = tuple(list(reasons) + ["decision_deadline_exceeded_fail_closed"])
            abstentions.append("decision_latency_exceeded")

        integrity_epoch = _hash(
            {
                "observed_at_ms": integrity.signals.observed_at_ms,
                "assessed_at_ms": integrity.assessed_at_ms,
                "healthy": integrity.healthy,
                "reasons": integrity.reasons,
            }
        )
        escrow_diag = (
            readiness.escrow_messages()
            if disposition == Disposition.ESCROW
            else ()
        )

        decision = Decision(
            action_id=proposal.action_id,
            action_type=proposal.action_type,
            disposition=disposition,
            risk_rank_score=risk_rank,
            blockability_rank_score=blockability_rank,
            continuous_score=continuous,
            calibrated_risk_probability=(
                calibrated_risk.probability if calibrated_risk else None
            ),
            calibrated_probability_interval=(
                calibrated_risk.interval if calibrated_risk else None
            ),
            calibrated_block_probability=(
                calibrated_block.probability if calibrated_block else None
            ),
            calibrated_block_probability_interval=(
                calibrated_block.interval if calibrated_block else None
            ),
            terms=terms,
            reasons=tuple(dict.fromkeys(reasons)),
            evidence=tuple(item.to_dict() for item in evidence.results),
            missing_evidence=tuple(evidence.missing_required),
            abstention_causes=tuple(dict.fromkeys(abstentions)),
            escrow_diagnostics=escrow_diag,
            block_ready=readiness.block_ready,
            allow_ready=readiness.allow_ready,
            policy_version=self.effective_policy_version,
            scorer_version=self.scorer_version,
            configuration_fingerprint=configuration_fingerprint,
            control_integrity_epoch=integrity_epoch,
            latency_ms=elapsed_ms,
        )

        self._assert_configuration_integrity()
        context = _context_for(
            proposal,
            evidence,
            scorer_version=self.scorer_version,
            policy_version=self.effective_policy_version,
        )
        prepare_token: AuthorizationToken | None = None
        if decision.commit_permitted and context is None:
            decision = replace(
                decision,
                disposition=Disposition.ESCROW,
                reasons=tuple(
                    list(decision.reasons) + ["invalid_execution_context_binding"]
                ),
            )
        elif (
            decision.commit_permitted
            and context is not None
            and self.token_authority is not None
        ):
            self._assert_configuration_integrity()
            prepare_token = self.token_authority.prepare(
                context=context,
                disposition=decision.disposition.value,
                ttl_ms=policy.decision_deadline_ms,
            )

        return GovernanceResult(
            decision=decision,
            prefix_score=prefix_score,
            evidence=evidence,
            readiness=readiness,
            execution_context=context if decision.commit_permitted else None,
            prepare_token=prepare_token,
        )


def _context_for(
    proposal: ActionProposal,
    evidence: V10EvidenceView,
    *,
    scorer_version: str,
    policy_version: str,
) -> ActionContext | None:
    if len(proposal.objects) != len(proposal.object_hashes):
        return None
    object_hashes = dict(zip(proposal.objects, proposal.object_hashes))
    try:
        return ActionContext.create(
            action_hash=proposal.action_hash(),
            object_hashes=object_hashes,
            actor=proposal.actor,
            environment=proposal.environment,
            authorization_hash=_hash(asdict(proposal.authorization)),
            evidence_hash=evidence.bundle.evidence_hash,
            scorer_version=scorer_version,
            policy_version=policy_version,
        )
    except (TypeError, ValueError):
        return None
