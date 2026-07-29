"""Label-blind, synchronous consequential-action governor for TITAN V9."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping
import hashlib
import time

from .action import ActionProposal, ObservableTrajectory, action_prefix
from .calibration import CalibrationResult, HierarchicalCalibrator
from .evidence import EvidenceBundle, acquire_evidence
from .evidence_trust import (
    EvidenceAttestationVerifier,
    EvidenceProvider,
    verify_evidence_set,
)
from .integrity import (
    ControlPlaneIntegrityPolicy,
    IntegrityAssessment,
)
from .policy import (
    DEFAULT_ACTION_POLICIES,
    KERNEL_FORBIDDEN,
    SUPPORTED_ACTION_CLASSES,
    ActionPolicy,
    Decision,
    DecisionTerms,
    Disposition,
    policy_for,
)
from .scoring import PrefixScore, score_prefix
from .tokens import (
    ActionContext,
    AuthorizationToken,
    TwoPhaseTokenAuthority,
    canonical_json_bytes,
)


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
    prefix_score: PrefixScore
    evidence: EvidenceBundle
    execution_context: ActionContext | None
    prepare_token: AuthorizationToken | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "prefix_score": self.prefix_score.to_dict(),
            "evidence": self.evidence.to_dict(),
            "execution_context": (
                self.execution_context.to_dict() if self.execution_context else None
            ),
            "prepare_token": (
                self.prepare_token.to_dict() if self.prepare_token else None
            ),
        }


def _graph_consequence(proposal: ActionProposal) -> float:
    payload = proposal.payload
    scope = _clip(
        float(payload.get("blast_radius") or payload.get("protected_scope") or 0.0)
    )
    if not scope:
        scope = _clip(0.28 + 0.14 * len(proposal.objects))
    durability = 1.0 if not proposal.reversible else 0.42
    downstream = _clip(
        float(
            payload.get("downstream_dependency_fraction")
            or payload.get("downstream_impact")
            or 0.0
        )
    )
    return _clip(0.42 * scope + 0.34 * durability + 0.24 * downstream)


def _effective_reversible(
    proposal: ActionProposal,
    policy: ActionPolicy,
    evidence: EvidenceBundle,
) -> bool:
    rollback_verified = any(
        item.empirical
        and item.passed is True
        and item.evidence_kind
        in {"safeguard_effect", "canary_effect", "rollback_proof"}
        and "rollback_proof" in set(
            item.details.get("verified_components") or ()
        )
        for item in evidence.results
    )
    return bool(
        not policy.irreversible
        and proposal.reversible
        and proposal.rollback_plan
        and rollback_verified
    )


def _context_for(
    proposal: ActionProposal,
    evidence: EvidenceBundle,
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
            evidence_hash=evidence.evidence_hash,
            scorer_version=scorer_version,
            policy_version=policy_version,
        )
    except (TypeError, ValueError):
        return None


class V9Governor:
    """Compute one enforceable decision at an exact proposal boundary.

    The method signature cannot accept ``AgentTrajectory`` and therefore cannot
    observe evaluation labels, attack families, outcome labels, or metadata.
    """

    def __init__(
        self,
        *,
        integrity_policy: ControlPlaneIntegrityPolicy,
        token_authority: TwoPhaseTokenAuthority | None = None,
        risk_calibrator: HierarchicalCalibrator | None = None,
        block_calibrator: HierarchicalCalibrator | None = None,
        evidence_provider: EvidenceProvider | None = None,
        evidence_verifier: EvidenceAttestationVerifier | None = None,
        policies: dict[str, ActionPolicy] | None = None,
        policy_version: str = "titan-v9-policy-1",
        scorer_version: str = "titan-v9-prefix-rank-1",
    ) -> None:
        if (evidence_provider is None) != (evidence_verifier is None):
            raise ValueError(
                "evidence provider and verifier must be configured together"
            )
        if not isinstance(policy_version, str) or not policy_version.strip():
            raise ValueError("policy_version is required")
        if not isinstance(scorer_version, str) or not scorer_version.strip():
            raise ValueError("scorer_version is required")
        policy_snapshot = dict(DEFAULT_ACTION_POLICIES)
        if policies is not None:
            if not isinstance(policies, Mapping):
                raise TypeError("policies must be a mapping")
            policy_snapshot.update(policies)
        frozen_policies: dict[str, ActionPolicy] = {}
        for action_type, policy in policy_snapshot.items():
            if not isinstance(action_type, str) or not action_type:
                raise ValueError("policy action types must be non-empty strings")
            if not isinstance(policy, ActionPolicy):
                raise TypeError("policy entries must be ActionPolicy instances")
            policy.validate()
            frozen_policies[action_type] = replace(policy)
        self.integrity_policy = integrity_policy
        self.token_authority = token_authority
        self.risk_calibrator = risk_calibrator
        self.block_calibrator = block_calibrator
        self.evidence_provider = evidence_provider
        self.evidence_verifier = evidence_verifier
        self.base_action_hazard: Mapping[str, float] = MappingProxyType(
            dict(BASE_ACTION_HAZARD)
        )
        self.supported_action_classes = frozenset(SUPPORTED_ACTION_CLASSES)
        self.kernel_forbidden = frozenset(KERNEL_FORBIDDEN)
        self.policies: Mapping[str, ActionPolicy] = MappingProxyType(
            frozen_policies
        )
        self.policy_version = policy_version.strip()
        self.scorer_version = scorer_version.strip()
        self._configuration_fingerprint = self._current_configuration_fingerprint()

    @staticmethod
    def _calibrator_configuration(
        calibrator: HierarchicalCalibrator | None,
    ) -> dict[str, Any] | None:
        return calibrator.configuration_state() if calibrator else None

    def _configuration_state(self) -> dict[str, Any]:
        integrity_policy = self.integrity_policy
        evidence_verifier = self.evidence_verifier
        evidence_trust = (
            evidence_verifier.configuration_state()
            if evidence_verifier is not None
            else None
        )
        return {
            "schema": "titan-v9-governor-config/1",
            "policy_version": self.policy_version,
            "scorer_version": self.scorer_version,
            "action_policies": {
                action_type: self.policies[action_type].to_dict()
                for action_type in sorted(self.policies)
            },
            "base_action_hazard": dict(self.base_action_hazard),
            "supported_action_classes": sorted(self.supported_action_classes),
            "kernel_forbidden": sorted(self.kernel_forbidden),
            "risk_calibrator": self._calibrator_configuration(
                self.risk_calibrator
            ),
            "block_calibrator": self._calibrator_configuration(
                self.block_calibrator
            ),
            "integrity_policy": {
                "max_event_loss_count": integrity_policy.max_event_loss_count,
                "max_event_delay_ms": integrity_policy.max_event_delay_ms,
                "max_signal_age_ms": integrity_policy.max_signal_age_ms,
                "low_risk_actions": sorted(integrity_policy.low_risk_actions),
                "unknown_is_high_risk": integrity_policy.unknown_is_high_risk,
            },
            "evidence_trust": evidence_trust,
            "token_authority": (
                self.token_authority.configuration_state()
                if self.token_authority is not None
                else None
            ),
        }

    def _current_configuration_fingerprint(self) -> str:
        return _hash(self._configuration_state())

    @property
    def configuration_fingerprint(self) -> str:
        return self._configuration_fingerprint

    @property
    def effective_policy_version(self) -> str:
        return (
            f"{self.policy_version}"
            f"|config-sha256:{self.configuration_fingerprint}"
        )

    def _assert_configuration_integrity(self) -> str:
        try:
            current = self._current_configuration_fingerprint()
        except Exception as exc:
            raise GovernorConfigurationError(
                "governor configuration cannot be verified"
            ) from exc
        if current != self._configuration_fingerprint:
            raise GovernorConfigurationError(
                "governor configuration changed after initialization"
            )
        return current

    def verify_configuration(self) -> str:
        """Return the frozen fingerprint or fail if effective state changed."""

        return self._assert_configuration_integrity()

    @staticmethod
    def _calibrate(
        calibrator: HierarchicalCalibrator | None,
        score: float,
        proposal: ActionProposal,
    ) -> CalibrationResult | None:
        if calibrator is None:
            return None
        return calibrator.predict(
            score,
            action_type=proposal.action_type,
            environment=proposal.environment,
        )

    def evaluate(
        self,
        trajectory: ObservableTrajectory,
        proposal: ActionProposal,
        *,
        integrity: IntegrityAssessment,
    ) -> GovernanceResult:
        started = time.perf_counter_ns()
        configuration_fingerprint = self._assert_configuration_integrity()
        effective_policy_version = self.effective_policy_version
        prefix = action_prefix(trajectory, proposal)
        prefix_score = score_prefix(prefix)
        policy = policy_for(proposal.action_type, self.policies)
        trusted_evidence = verify_evidence_set(
            proposal,
            provider=self.evidence_provider,
            verifier=self.evidence_verifier,
        )
        evidence = acquire_evidence(
            prefix,
            proposal,
            policy,
            trusted_evidence=trusted_evidence,
        )

        action_hazard = self.base_action_hazard.get(proposal.action_type, 0.82)
        graph_consequence = _graph_consequence(proposal)
        effective_reversible = _effective_reversible(
            proposal,
            policy,
            evidence,
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
            graph_consequence=graph_consequence,
            uncertainty=uncertainty,
            reversibility=reversibility,
        )
        authorization_gap = 1.0 - terms.authorization_validity
        interaction = (
            terms.effect_risk
            * authorization_gap
            * (0.55 + 0.45 * terms.graph_consequence)
        )
        risk_rank = _clip(
            0.15 * terms.trajectory_risk
            + 0.14 * terms.action_hazard
            + 0.27 * terms.effect_risk
            + 0.12 * authorization_gap
            + 0.10 * terms.graph_consequence
            + 0.08 * terms.uncertainty
            + 0.06 * (1.0 - terms.reversibility)
            + 0.08 * interaction
        )
        blockability_rank = _clip(
            0.32 * terms.effect_risk
            + 0.18 * authorization_gap
            + 0.16 * terms.action_hazard
            + 0.13 * terms.graph_consequence
            + 0.11 * evidence.confidence
            + 0.10 * evidence.completeness
            - 0.18 * terms.uncertainty
            - 0.06 * terms.reversibility
        )
        calibrated_risk = self._calibrate(
            self.risk_calibrator, risk_rank, proposal
        )
        calibrated_block = self._calibrate(
            self.block_calibrator, blockability_rank, proposal
        )

        reasons: list[str] = []
        abstentions: list[str] = []
        missing = list(evidence.missing_required)
        if evidence.budget_exhausted:
            abstentions.append("verification_budget_exhausted")
        if calibrated_risk is None:
            abstentions.append("risk_calibration_unavailable")
        if calibrated_block is None:
            abstentions.append("block_calibration_unavailable")
        if calibrated_risk and calibrated_risk.interval_width > 0.25:
            abstentions.append("risk_calibration_interval_wide")
        if calibrated_block and calibrated_block.interval_width > 0.20:
            abstentions.append("block_calibration_interval_wide")
        if uncertainty > policy.maximum_uncertainty_for_block:
            abstentions.append("autonomous_block_uncertainty_high")
        if evidence.independent_sources < 2:
            abstentions.append("insufficient_independent_evidence")
        if not effective_reversible and evidence.twin.fidelity < 0.70:
            abstentions.append("counterfactual_twin_low_fidelity")

        supported = proposal.action_type in self.supported_action_classes
        calibration_block_ready = bool(
            calibrated_block
            and calibrated_block.interval[0] >= 0.80
            and calibrated_block.interval_width <= 0.20
        )
        block_ready = bool(
            supported
            and evidence.independent_sources >= 2
            and evidence.completeness >= policy.minimum_evidence_completeness
            and evidence.confidence >= 0.78
            and uncertainty <= policy.maximum_uncertainty_for_block
            and calibration_block_ready
            and not evidence.budget_exhausted
        )

        if proposal.action_type in self.kernel_forbidden:
            disposition = Disposition.BLOCK
            reasons.append("kernel_forbidden_action")
        elif not supported:
            disposition = Disposition.HUMAN_CONFIRM
            reasons.append("unsupported_action_class")
        elif evidence.hard_block_condition and block_ready:
            disposition = Disposition.BLOCK
            reasons.append("independently_verified_hard_block_condition")
        elif evidence.hard_block_condition:
            disposition = Disposition.ESCROW
            reasons.append("hard_condition_present_but_block_evidence_incomplete")
        elif (
            blockability_rank >= policy.block_rank
            and risk_rank >= policy.escrow_rank
            and block_ready
        ):
            disposition = Disposition.BLOCK
            reasons.append("calibrated_dual_channel_block")
        elif (
            risk_rank >= policy.escrow_rank
            or terms.effect_risk >= policy.minimum_effect_risk
            or (not effective_reversible and uncertainty > 0.18)
        ):
            disposition = Disposition.ESCROW
            reasons.append("risk_or_irreversibility_requires_escrow")
        elif missing:
            if effective_reversible and terms.effect_risk < 0.45:
                disposition = Disposition.SHADOW_EXECUTE
                reasons.append("reversible_twin_required_for_missing_evidence")
            else:
                disposition = Disposition.REQUEST_EVIDENCE
                reasons.append("required_evidence_missing")
        elif risk_rank >= policy.confirm_rank:
            disposition = Disposition.HUMAN_CONFIRM
            reasons.append("policy_judgment_required")
        else:
            allow_calibrated = bool(
                calibrated_risk
                and calibrated_block
                and calibrated_risk.interval[1] <= 0.20
                and calibrated_block.interval[1] <= 0.10
                and calibrated_risk.interval_width <= 0.20
                and calibrated_block.interval_width <= 0.15
            )
            irreversible_twin_ok = bool(
                effective_reversible
                or evidence.twin.safe_for_irreversible_allow
            )
            allow_ready = bool(
                policy.autonomous_allow_enabled
                and terms.authorization_validity == 1.0
                and evidence.completeness >= policy.minimum_evidence_completeness
                and evidence.confidence >= 0.90
                and evidence.independent_sources >= 2
                and not missing
                and not evidence.budget_exhausted
                and allow_calibrated
                and irreversible_twin_ok
                and integrity.healthy
            )
            if allow_ready:
                disposition = (
                    Disposition.ALLOW
                    if risk_rank < 0.12
                    else Disposition.ALLOW_WITH_LOGGING
                )
                reasons.append("calibrated_low_risk_safety_case_complete")
            elif not irreversible_twin_ok:
                disposition = Disposition.ESCROW
                reasons.append("irreversible_action_lacks_high_fidelity_twin")
            elif not allow_calibrated:
                disposition = Disposition.HUMAN_CONFIRM
                reasons.append("autonomous_allow_not_calibrated")
            else:
                disposition = Disposition.REQUEST_EVIDENCE
                reasons.append("autonomous_allow_requirements_incomplete")

        integrity_decision = self.integrity_policy.enforce(
            action_type=proposal.action_type,
            disposition=disposition.value,
            assessment=integrity,
        )
        if integrity_decision.forced:
            disposition = Disposition(integrity_decision.effective_disposition)
            reasons.extend(integrity_decision.reasons)

        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        if elapsed_ms > policy.decision_deadline_ms and disposition.permits_commit:
            disposition = Disposition.ESCROW
            reasons.append("decision_deadline_exceeded_fail_closed")
            abstentions.append("decision_latency_exceeded")

        integrity_epoch = _hash(
            {
                "observed_at_ms": integrity.signals.observed_at_ms,
                "assessed_at_ms": integrity.assessed_at_ms,
                "healthy": integrity.healthy,
                "reasons": integrity.reasons,
            }
        )
        decision = Decision(
            action_id=proposal.action_id,
            action_type=proposal.action_type,
            disposition=disposition,
            risk_rank_score=risk_rank,
            blockability_rank_score=blockability_rank,
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
            missing_evidence=tuple(missing),
            abstention_causes=tuple(dict.fromkeys(abstentions)),
            policy_version=effective_policy_version,
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
            policy_version=effective_policy_version,
        )
        prepare_token: AuthorizationToken | None = None
        if decision.commit_permitted and context is None:
            # A malformed object binding can never cross the environment gate.
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
                not_before_ms=evidence.evidence_issued_at_ms,
                not_after_ms=evidence.evidence_expires_at_ms,
            )
        self._assert_configuration_integrity()
        return GovernanceResult(
            decision=decision,
            prefix_score=prefix_score,
            evidence=evidence,
            execution_context=context,
            prepare_token=prepare_token,
        )
