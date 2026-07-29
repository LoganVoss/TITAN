"""Independent evidence adapters and exact counterfactual twins for V9.

Evidence is keyed by verifier and source so aliases cannot be counted as
independent tests.  Synthetic twin estimates are useful for triage, but are
explicitly marked non-empirical and cannot authorize irreversible actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Sequence
import hashlib
import json
import math
import time

from .action import ActionProposal, ObservableTrajectory
from .canary import verify_canary_change
from .data_integrity import DataIntegrityVerification, verify_data_action
from .evidence_trust import VerifiedEvidence
from .policy import ActionPolicy
from .safeguard import verify_safeguard_change


TWIN_VARIANTS: tuple[str, ...] = (
    "standard",
    "pessimistic",
    "delayed",
    "missing_dependency",
    "adversarial_probe",
)

REQUIREMENT_EVIDENCE_KINDS: dict[str, frozenset[str]] = {
    "signed_authorization": frozenset({"signed_authorization"}),
    "semantic_diff": frozenset({"safeguard_effect"}),
    "policy_graph_delta": frozenset({"safeguard_effect"}),
    "hidden_probes": frozenset({"safeguard_effect"}),
    "coverage_conservation": frozenset({"canary_effect"}),
    "replacement_equivalence": frozenset({"canary_effect"}),
    "composed_degradation": frozenset({"canary_effect"}),
    "rollback_proof": frozenset(
        {"safeguard_effect", "canary_effect", "rollback_proof"}
    ),
    "destination_scope": frozenset({"destination_scope"}),
    "data_classification": frozenset({"destination_scope"}),
    "provenance": frozenset({"provenance"}),
    "lineage": frozenset({"lineage"}),
    "validation": frozenset({"validation"}),
    "influence": frozenset({"influence"}),
    "canary_health": frozenset({"canary_health"}),
}


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceResult:
    verifier_id: str
    source_id: str
    independence_domain: str
    evidence_kind: str
    subject_hash: str
    risk: float
    confidence: float
    coverage: float
    passed: bool | None
    evidence_digest: str
    empirical: bool
    latency_ms: float
    details: dict[str, Any]

    def __post_init__(self) -> None:
        for name in ("risk", "confidence", "coverage"):
            if not 0.0 <= float(getattr(self, name)) <= 1.0:
                raise ValueError(f"{name} must be in [0,1]")
        if self.latency_ms < 0.0 or not math.isfinite(self.latency_ms):
            raise ValueError("latency_ms must be finite and non-negative")
        if (
            not self.verifier_id
            or not self.source_id
            or not self.independence_domain
            or not self.evidence_kind
        ):
            raise ValueError(
                "verifier, source, independence domain, and evidence kind "
                "are required"
            )
        if len(self.subject_hash) != 64:
            raise ValueError("subject_hash must be a SHA-256 digest")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TwinVariantResult:
    variant: str
    risk: float
    confidence: float
    evidence_digest: str
    empirical: bool
    details: dict[str, Any]


@dataclass(frozen=True)
class TwinEnsembleReport:
    action_hash: str
    state_snapshot_id: str
    variants: tuple[TwinVariantResult, ...]
    worst_case_risk: float
    mean_risk: float
    fidelity: float
    uncertainty: float
    exact_action_bound: bool
    exact_state_bound: bool
    empirical_variant_count: int
    safe_for_irreversible_allow: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceBundle:
    action_hash: str
    results: tuple[EvidenceResult, ...]
    twin: TwinEnsembleReport
    effect_risk: float
    verified_authorization_validity: float
    completeness: float
    confidence: float
    independent_sources: int
    missing_required: tuple[str, ...]
    hard_block_condition: bool
    budget_exhausted: bool
    evidence_issued_at_ms: int | None
    evidence_expires_at_ms: int | None
    elapsed_ms: float

    @property
    def evidence_hash(self) -> str:
        return _digest(
            {
                "action_hash": self.action_hash,
                "results": [item.to_dict() for item in self.results],
                "twin": self.twin.to_dict(),
                "effect_risk": self.effect_risk,
                "verified_authorization_validity": self.verified_authorization_validity,
                "completeness": self.completeness,
                "missing_required": self.missing_required,
                "evidence_issued_at_ms": self.evidence_issued_at_ms,
                "evidence_expires_at_ms": self.evidence_expires_at_ms,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_hash"] = self.evidence_hash
        return value


def _provided_twin(
    trusted_evidence: Sequence[VerifiedEvidence],
    variant: str,
) -> TwinVariantResult | None:
    matches = tuple(
        item
        for item in trusted_evidence
        if item.evidence_kind == f"twin:{variant}"
    )
    if not matches:
        return None
    risks = [float(item.claims["risk"]) for item in matches]
    confidences = [float(item.claims["confidence"]) for item in matches]
    coverages = [float(item.claims["coverage"]) for item in matches]
    passed = all(item.claims["passed"] is True for item in matches)
    return TwinVariantResult(
        variant=variant,
        risk=max(risks),
        confidence=min(confidences),
        evidence_digest=_digest(
            {
                "variant": variant,
                "attestations": [
                    {
                        "attestation_id": item.attestation.attestation_id,
                        "evidence_digest": item.evidence_digest,
                    }
                    for item in matches
                ],
            }
        ),
        empirical=True,
        details={
            "authenticated": True,
            "attestation_ids": [
                item.attestation.attestation_id for item in matches
            ],
            "attested_passed": passed,
            "minimum_coverage": min(coverages),
        },
    )


def run_twin_ensemble(
    prefix: ObservableTrajectory,
    proposal: ActionProposal,
    *,
    base_effect_risk: float,
    trusted_evidence: Sequence[VerifiedEvidence] = (),
) -> TwinEnsembleReport:
    """Evaluate exact action/state-bound twin results, with conservative fallbacks."""

    exact_action = True
    exact_state = (
        proposal.state_snapshot_id == prefix.observable_hash()
        and proposal.prefix_exclusive_end == len(prefix.events)
    )
    variants: list[TwinVariantResult] = []
    empirical = 0
    for variant in TWIN_VARIANTS:
        provided = _provided_twin(trusted_evidence, variant)
        if provided is not None:
            variants.append(provided)
            empirical += 1
            continue
        lift = {
            "standard": 0.00,
            "pessimistic": 0.14,
            "delayed": 0.10,
            "missing_dependency": 0.18,
            "adversarial_probe": 0.22,
        }[variant]
        risk = _clip(base_effect_risk + lift * (0.45 + 0.55 * base_effect_risk))
        variants.append(
            TwinVariantResult(
                variant=variant,
                risk=risk,
                confidence=0.22,
                evidence_digest=_digest(
                    {
                        "synthetic": True,
                        "variant": variant,
                        "action_hash": proposal.action_hash(),
                        "state_snapshot_id": proposal.state_snapshot_id,
                        "base_effect_risk": base_effect_risk,
                    }
                ),
                empirical=False,
                details={"reason": "no_independent_twin_result_supplied"},
            )
        )
    risks = [item.risk for item in variants]
    confidence = sum(item.confidence for item in variants) / len(variants)
    binding = float(exact_action and exact_state)
    fidelity = _clip(
        0.12
        + 0.48 * (empirical / len(TWIN_VARIANTS))
        + 0.20 * binding
        + 0.20 * confidence
    )
    uncertainty = _clip(
        0.55 * (1.0 - fidelity)
        + 0.25 * (max(risks) - min(risks))
        + 0.20 * (1.0 - confidence)
    )
    every_twin_passed = all(
        item.details.get("attested_passed") is True
        and float(item.details.get("minimum_coverage", 0.0)) >= 0.95
        for item in variants
    )
    return TwinEnsembleReport(
        action_hash=proposal.action_hash(),
        state_snapshot_id=proposal.state_snapshot_id,
        variants=tuple(variants),
        worst_case_risk=max(risks),
        mean_risk=sum(risks) / len(risks),
        fidelity=fidelity,
        uncertainty=uncertainty,
        exact_action_bound=exact_action,
        exact_state_bound=exact_state,
        empirical_variant_count=empirical,
        safe_for_irreversible_allow=bool(
            exact_action
            and exact_state
            and empirical == len(TWIN_VARIANTS)
            and fidelity >= 0.82
            and max(risks) <= 0.20
            and every_twin_passed
        ),
    )


def _result(
    *,
    proposal: ActionProposal,
    verifier_id: str,
    source_id: str,
    kind: str,
    risk: float,
    confidence: float,
    coverage: float,
    passed: bool | None,
    digest: str,
    empirical: bool,
    started_ns: int,
    details: dict[str, Any],
    independence_domain: str = "untrusted",
) -> EvidenceResult:
    evidence_digest = digest if len(digest) == 64 else _digest(
        {
            "verifier": verifier_id,
            "source": source_id,
            "subject": proposal.action_hash(),
            "details": details,
        }
    )
    return EvidenceResult(
        verifier_id=verifier_id,
        source_id=source_id,
        independence_domain=independence_domain,
        evidence_kind=kind,
        subject_hash=proposal.action_hash(),
        risk=_clip(risk),
        confidence=_clip(confidence),
        coverage=_clip(coverage),
        passed=passed,
        evidence_digest=evidence_digest,
        empirical=empirical,
        latency_ms=(time.perf_counter_ns() - started_ns) / 1_000_000.0,
        details=details,
    )


def _trusted_kind(
    trusted_evidence: Sequence[VerifiedEvidence],
    kind: str,
) -> tuple[VerifiedEvidence, ...]:
    return tuple(item for item in trusted_evidence if item.evidence_kind == kind)


def _attested_result(
    *,
    proposal: ActionProposal,
    attestation: VerifiedEvidence,
    kind: str,
    local_risk_floor: float,
    local_coverage_ceiling: float,
    local_passed: bool | None,
    started_ns: int,
    details: dict[str, Any],
) -> EvidenceResult:
    """Translate one authenticated verifier statement conservatively.

    The local semantic inspection can make an attested result less favorable,
    but never more favorable. This prevents a valid signature from laundering a
    verifier bug that contradicts plainly observable action semantics.
    """

    claims = attestation.claims
    attested_passed = claims["passed"]
    passed = (
        attested_passed
        if local_passed is None
        else bool(attested_passed is True and local_passed)
    )
    verified_components = tuple(claims.get("verified_components") or ())
    return _result(
        proposal=proposal,
        verifier_id=attestation.verifier_id,
        source_id=attestation.source_id,
        independence_domain=attestation.independence_domain,
        kind=kind,
        risk=max(local_risk_floor, float(claims["risk"])),
        confidence=float(claims["confidence"]),
        coverage=min(local_coverage_ceiling, float(claims["coverage"])),
        passed=passed,
        digest=attestation.evidence_digest,
        empirical=True,
        started_ns=started_ns,
        details={
            **details,
            "authenticated": True,
            "attestation_id": attestation.attestation.attestation_id,
            "attestation_issued_at_ms": attestation.attestation.issued_at_ms,
            "attestation_expires_at_ms": attestation.attestation.expires_at_ms,
            "attestation_signature": attestation.attestation.signature,
            "verified_components": verified_components,
        },
    )


def _authorization_evidence(
    proposal: ActionProposal,
    trusted_evidence: Sequence[VerifiedEvidence],
) -> list[EvidenceResult]:
    started = time.perf_counter_ns()
    auth = proposal.authorization
    local_coverage = 1.0 if auth.status != "missing" else 0.0
    details = {
        "observed_status": auth.status,
        "reference": auth.reference,
        "claimed_issuer": auth.issuer,
        "scope": auth.scope,
        "agent_supplied_digest_present": bool(auth.evidence_digest),
    }
    trusted = _trusted_kind(trusted_evidence, "signed_authorization")
    if trusted:
        return [
            _attested_result(
                proposal=proposal,
                attestation=item,
                kind="signed_authorization",
                local_risk_floor=1.0 - auth.validity,
                local_coverage_ceiling=local_coverage,
                local_passed=auth.status == "valid",
                started_ns=started,
                details=details,
            )
            for item in trusted
        ]
    return [
        _result(
            proposal=proposal,
            verifier_id="local-authorization-observation-v1",
            source_id="untrusted_event_claim",
            kind="signed_authorization",
            risk=1.0 - auth.validity,
            confidence=0.35 if auth.status != "missing" else 0.15,
            coverage=local_coverage,
            passed=auth.status == "valid",
            digest="",
            empirical=False,
            started_ns=started,
            details={**details, "authenticated": False},
        )
    ]


def _data_evidence(
    proposal: ActionProposal,
    report: DataIntegrityVerification,
    trusted_evidence: Sequence[VerifiedEvidence],
) -> list[EvidenceResult]:
    output: list[EvidenceResult] = []
    specs = (
        (
            "provenance-registry-v1",
            "provenance_registry",
            "provenance",
            report.provenance_coverage,
        ),
        (
            "lineage-registry-v1",
            "lineage_registry",
            "lineage",
            report.lineage_coverage,
        ),
        (
            "validation-runner-v1",
            "validation_runner",
            "validation",
            report.validation_coverage,
        ),
        (
            "influence-analyzer-v1",
            "influence_analyzer",
            "influence",
            report.influence_checked_fraction,
        ),
        (
            "canary-runner-v1",
            "canary_runner",
            "canary_health",
            report.canary_pass_rate,
        ),
    )
    for verifier, source_default, kind, coverage in specs:
        started = time.perf_counter_ns()
        available_digests = report.evidence_digests.get(kind, ())
        # Coverage booleans and digest-looking strings inside an agent event are
        # claims, not verifier output.  They are retained for diagnostics but
        # cannot lower risk, cap authenticated coverage, or make a check pass.
        intrinsic_risk = 0.0
        local_passed: bool | None = None
        if kind == "influence":
            maximum = report.max_influence
            concentration = report.cluster_concentration
            intrinsic_risk = _clip(
                0.52 * maximum
                + 0.28 * report.composed_influence
                + 0.20 * concentration
            )
            local_passed = bool(maximum < 0.35 and concentration < 0.45)
        if kind == "canary_health":
            delta = report.canary_sensitivity_delta
            intrinsic_risk = _clip(-delta)
            local_passed = bool(delta >= -0.02)
        details = {
            "data_integrity": report.to_dict(),
            "agent_supplied_digest_count": len(available_digests),
            "agent_claimed_coverage": coverage,
        }
        trusted = _trusted_kind(trusted_evidence, kind)
        if trusted:
            output.extend(
                _attested_result(
                    proposal=proposal,
                    attestation=item,
                    kind=kind,
                    local_risk_floor=intrinsic_risk,
                    local_coverage_ceiling=1.0,
                    local_passed=local_passed,
                    started_ns=started,
                    details=details,
                )
                for item in trusted
            )
        else:
            output.append(
                _result(
                    proposal=proposal,
                    verifier_id=f"local-{verifier}",
                    source_id=f"untrusted_claim:{source_default}",
                    kind=kind,
                    risk=1.0,
                    confidence=0.15,
                    coverage=coverage,
                    passed=None,
                    digest="",
                    empirical=False,
                    started_ns=started,
                    details={**details, "authenticated": False},
                )
            )
    return output


def _effect_evidence(
    prefix: ObservableTrajectory,
    proposal: ActionProposal,
    trusted_evidence: Sequence[VerifiedEvidence],
) -> tuple[list[EvidenceResult], float, float, bool]:
    output: list[EvidenceResult] = []
    hard = False
    effect_risk = 0.0
    fidelity = 0.0
    if proposal.action_type in {"modify_safeguard", "disable_monitoring"}:
        started = time.perf_counter_ns()
        report = verify_safeguard_change(prefix, proposal)
        structured_before = isinstance(proposal.payload.get("before"), dict) or any(
            str(key).endswith("_before") for key in proposal.payload
        )
        structured_after = isinstance(proposal.payload.get("after"), dict) or any(
            str(key).endswith("_after") for key in proposal.payload
        )
        claimed_components: list[str] = []
        if (
            structured_before
            and structured_after
            and proposal.payload.get("state_snapshot_digest")
        ):
            claimed_components.append("semantic_diff")
        if proposal.payload.get("policy_graph_digest"):
            claimed_components.append("policy_graph_delta")
        if (
            proposal.payload.get("hidden_probe_results")
            and proposal.payload.get("policy_graph_digest")
        ):
            claimed_components.append("hidden_probes")
        if (
            proposal.rollback_plan
            and proposal.payload.get("rollback_test_passed")
            and proposal.payload.get("rollback_evidence_digest")
        ):
            claimed_components.append("rollback_proof")
        effect_risk = report.effect_risk
        fidelity = report.twin_fidelity
        hard = report.hard_block_condition
        local_passed = (
            not report.intrinsic_hard_block_condition
            and report.intrinsic_effect_risk < 0.20
        )
        details = {
            **report.to_dict(),
            "claimed_components": claimed_components,
        }
        trusted = _trusted_kind(trusted_evidence, "safeguard_effect")
        if trusted:
            output.extend(
                _attested_result(
                    proposal=proposal,
                    attestation=item,
                    kind="safeguard_effect",
                    local_risk_floor=report.intrinsic_effect_risk,
                    local_coverage_ceiling=1.0,
                    local_passed=local_passed,
                    started_ns=started,
                    details=details,
                )
                for item in trusted
            )
            effect_risk = max(
                report.intrinsic_effect_risk,
                max(item.risk for item in output),
            )
            fidelity = min(
                min(item.coverage, item.confidence) for item in output
            )
            hard = bool(
                report.intrinsic_hard_block_condition
                or any(
                    item.passed is False or item.risk >= 0.80
                    for item in output
                )
            )
        else:
            output.append(
                _result(
                    proposal=proposal,
                    verifier_id="local-safeguard-effect-network-v1",
                    source_id="untrusted_action_claim",
                    kind="safeguard_effect",
                    risk=report.effect_risk,
                    confidence=min(
                        0.45, 0.20 + 0.25 * report.evidence_completeness
                    ),
                    coverage=report.evidence_completeness,
                    passed=local_passed,
                    digest="",
                    empirical=False,
                    started_ns=started,
                    details={**details, "authenticated": False},
                )
            )
    elif proposal.action_type in {"remove_canary", "weaken_canary"}:
        started = time.perf_counter_ns()
        report = verify_canary_change(prefix, proposal)
        explicit_before = "coverage_before" in proposal.payload
        explicit_after = any(
            key in proposal.payload
            for key in (
                "coverage_after",
                "coverage_delta",
                "canary_delta",
                "delta",
            )
        )
        prior_same_canary = any(
            event.payload.get("eval_name") == report.canary_id
            or event.payload.get("name") == report.canary_id
            for event in prefix.events
        )
        claimed_components = []
        if explicit_before and explicit_after:
            claimed_components.append("coverage_conservation")
        if report.replacement.agent_claimed_validation:
            claimed_components.append("replacement_equivalence")
        if explicit_before and explicit_after and prior_same_canary:
            claimed_components.append("composed_degradation")
        if (
            proposal.rollback_plan
            and proposal.payload.get("rollback_test_passed")
            and proposal.payload.get("rollback_evidence_digest")
        ):
            claimed_components.append("rollback_proof")
        effect_risk = report.effect_risk
        fidelity = report.twin_fidelity
        hard = report.hard_block_condition
        details = {
            **report.to_dict(),
            "claimed_components": claimed_components,
        }
        trusted = _trusted_kind(trusted_evidence, "canary_effect")
        if trusted:
            output.extend(
                _attested_result(
                    proposal=proposal,
                    attestation=item,
                    kind="canary_effect",
                    local_risk_floor=report.intrinsic_effect_risk,
                    local_coverage_ceiling=1.0,
                    local_passed=not report.intrinsic_hard_block_condition,
                    started_ns=started,
                    details=details,
                )
                for item in trusted
            )
            effect_risk = max(
                report.intrinsic_effect_risk,
                max(item.risk for item in output),
            )
            fidelity = min(
                min(item.coverage, item.confidence) for item in output
            )
            hard = bool(
                report.intrinsic_hard_block_condition
                or any(
                    item.passed is False or item.risk >= 0.80
                    for item in output
                )
            )
        else:
            output.append(
                _result(
                    proposal=proposal,
                    verifier_id="local-canary-coverage-graph-v1",
                    source_id="untrusted_action_claim",
                    kind="canary_effect",
                    risk=report.effect_risk,
                    confidence=min(
                        0.45, 0.20 + 0.25 * report.evidence_completeness
                    ),
                    coverage=report.evidence_completeness,
                    passed=report.coverage_conserved,
                    digest="",
                    empirical=False,
                    started_ns=started,
                    details={**details, "authenticated": False},
                )
            )
    elif proposal.action_type in {"queue_training", "merge_training_data"}:
        report = verify_data_action(prefix, proposal)
        data = _data_evidence(proposal, report, trusted_evidence)
        output.extend(data)
        required_data_kinds = {
            "provenance",
            "lineage",
            "validation",
            "influence",
            "canary_health",
        }
        trusted_data_kinds = {
            item.evidence_kind for item in data if item.empirical
        }
        complete_trusted_graph = required_data_kinds <= trusted_data_kinds
        if complete_trusted_graph:
            effect_risk = max(
                report.intrinsic_effect_risk,
                max((item.risk for item in data), default=1.0),
            )
            fidelity = min(
                (
                    min(item.coverage, item.confidence)
                    for item in data
                    if item.empirical
                ),
                default=0.0,
            )
            hard = bool(
                report.intrinsic_hard_block_condition
                or any(
                    item.empirical
                    and (item.passed is False or item.risk >= 0.80)
                    for item in data
                )
            )
        else:
            effect_risk = report.effect_risk
            fidelity = 0.0
            hard = report.hard_block_condition
    elif proposal.action_type == "export_credential":
        started = time.perf_counter_ns()
        destination_valid = bool(
            proposal.payload.get("destination_scope_valid")
            and proposal.payload.get("data_classification_verified")
        )
        effect_risk = 0.25 if destination_valid and proposal.authorization.validity == 1.0 else 0.98
        fidelity = 1.0
        hard = not destination_valid
        details = {
            "destination_valid": destination_valid,
            "agent_supplied_digest_present": bool(
                proposal.payload.get("classification_evidence_digest")
            ),
        }
        trusted = _trusted_kind(trusted_evidence, "destination_scope")
        if trusted:
            output.extend(
                _attested_result(
                    proposal=proposal,
                    attestation=item,
                    kind="destination_scope",
                    local_risk_floor=effect_risk,
                    local_coverage_ceiling=1.0,
                    local_passed=destination_valid,
                    started_ns=started,
                    details=details,
                )
                for item in trusted
            )
        else:
            output.append(
                _result(
                    proposal=proposal,
                    verifier_id="local-credential-export-policy-v1",
                    source_id="untrusted_action_claim",
                    kind="destination_scope",
                    risk=effect_risk,
                    confidence=0.35,
                    coverage=1.0,
                    passed=destination_valid,
                    digest="",
                    empirical=False,
                    started_ns=started,
                    details={**details, "authenticated": False},
                )
            )
    elif proposal.action_type == "disable_monitoring":
        effect_risk, fidelity, hard = 1.0, 1.0, True
    else:
        effect_risk, fidelity, hard = 0.75, 0.0, False
    return output, effect_risk, fidelity, hard


def _covered_requirement(requirement: str, results: Iterable[EvidenceResult]) -> bool:
    authorized_kinds = REQUIREMENT_EVIDENCE_KINDS.get(
        requirement,
        frozenset({requirement}),
    )
    for item in results:
        if not (
            item.coverage >= 0.60
            and item.confidence >= 0.60
            and item.empirical
            and item.passed is True
            and item.evidence_kind in authorized_kinds
        ):
            continue
        verified_components = set(item.details.get("verified_components") or ())
        if requirement in verified_components:
            return True
        if requirement == item.evidence_kind:
            return True
        if requirement == "data_classification" and (
            "data_classification" in verified_components
        ):
            return True
    return False


def acquire_evidence(
    prefix: ObservableTrajectory,
    proposal: ActionProposal,
    policy: ActionPolicy,
    *,
    trusted_evidence: Sequence[VerifiedEvidence] = (),
) -> EvidenceBundle:
    """Run one bounded pass through distinct evidence adapters.

    Proposal fields are always available to local heuristics, but only
    independently authenticated ``trusted_evidence`` can satisfy a required
    evidence category or contribute an independent source.
    """

    started = time.perf_counter_ns()
    candidates = _authorization_evidence(proposal, trusted_evidence)
    effects, base_effect_risk, verifier_fidelity, hard = _effect_evidence(
        prefix,
        proposal,
        trusted_evidence,
    )
    candidates.extend(effects)

    # Deduplicate aliases and duplicate backends. A source may contribute only
    # once per evidence kind for this exact action.
    deduped: list[EvidenceResult] = []
    seen: set[tuple[str, str, str, str]] = set()
    budget_exhausted = False
    for item in candidates:
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        if len(deduped) >= policy.maximum_verifier_calls or elapsed_ms > policy.maximum_verification_ms:
            budget_exhausted = True
            break
        key = (
            item.verifier_id,
            item.source_id,
            item.evidence_kind,
            item.subject_hash,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    authenticated_authorizations = [
        item
        for item in deduped
        if item.evidence_kind == "signed_authorization" and item.empirical
    ]
    if authenticated_authorizations and all(
        item.passed is True for item in authenticated_authorizations
    ):
        verified_authorization_validity = min(
            (1.0 - item.risk) * item.coverage
            for item in authenticated_authorizations
        )
    else:
        verified_authorization_validity = 0.0

    twin = run_twin_ensemble(
        prefix,
        proposal,
        base_effect_risk=max(
            base_effect_risk,
            1.0 - verified_authorization_validity,
        ),
        trusted_evidence=trusted_evidence,
    )
    required = tuple(policy.required_evidence)
    missing = tuple(
        requirement
        for requirement in required
        if not _covered_requirement(requirement, deduped)
    )
    required_fraction = (
        1.0 - len(missing) / len(required) if required else 1.0
    )
    empirical_fraction = (
        sum(item.empirical for item in deduped) / len(deduped) if deduped else 0.0
    )
    source_count = len(
        {
            item.independence_domain
            for item in deduped
            if item.empirical
        }
    )
    completeness = _clip(
        0.55 * required_fraction
        + 0.25 * empirical_fraction
        + 0.10 * min(1.0, source_count / 2.0)
        + 0.10 * max(verifier_fidelity, twin.fidelity)
    )
    empirical_results = [item for item in deduped if item.empirical]
    confidence = _clip(
        sum(item.confidence * item.coverage for item in empirical_results)
        / max(1.0, sum(item.coverage for item in empirical_results))
    )
    effect_risk = max(
        base_effect_risk,
        twin.worst_case_risk * (0.45 + 0.55 * twin.fidelity),
        max((item.risk * item.confidence for item in deduped), default=0.0),
    )
    hard = bool(
        hard
        or any(
            item.empirical and item.passed is False and item.risk >= 0.80
            for item in deduped
        )
    )
    evidence_expires_at_ms = (
        min(item.expires_at_ms for item in trusted_evidence)
        if trusted_evidence
        else None
    )
    evidence_issued_at_ms = (
        max(item.attestation.issued_at_ms for item in trusted_evidence)
        if trusted_evidence
        else None
    )
    return EvidenceBundle(
        action_hash=proposal.action_hash(),
        results=tuple(deduped),
        twin=twin,
        effect_risk=_clip(effect_risk),
        verified_authorization_validity=_clip(
            verified_authorization_validity
        ),
        completeness=completeness,
        confidence=confidence,
        independent_sources=source_count,
        missing_required=missing,
        hard_block_condition=hard,
        budget_exhausted=budget_exhausted,
        evidence_issued_at_ms=evidence_issued_at_ms,
        evidence_expires_at_ms=evidence_expires_at_ms,
        elapsed_ms=(time.perf_counter_ns() - started) / 1_000_000.0,
    )
