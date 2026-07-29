"""Fail-closed V9 release gates cannot be satisfied by aggregate headlines."""

from __future__ import annotations

from typing import Iterable

from titan.v9.metrics import (
    ConfidenceInterval,
    LatchingRule,
    MetricRecord,
    PrefixRule,
    Threshold,
    UnitOfAnalysis,
)
from titan.v9.populations import (
    ActionOpportunity,
    DisjointnessAudit,
    EvaluationCase,
    EvaluationLabel,
    EvaluationPopulation,
    OpportunityAudit,
    PopulationKind,
    PopulationMetricReport,
    SeparatePopulationReport,
)
from titan.v9.release import (
    AttestationKind,
    ExternalAttestation,
    GateCategory,
    GateStatus,
    V9ReleaseEvidence,
    evaluate_v9_release,
)

_TEST_ATTESTATION_KEY = b"test-release-attestation-key-material-32-bytes"


def _metric(
    name: str,
    value: float | None,
    population_id: str,
    *,
    action_class: str = "all",
    calibration_population: str = "calibration-locked-001",
    threshold: float | None = None,
    lower: float | None = None,
    upper: float | None = None,
    undefined_reason: str | None = None,
) -> MetricRecord:
    interval = (
        ConfidenceInterval.not_available(
            undefined_reason or "not available",
            method="wilson",
        )
        if value is None
        else ConfidenceInterval.defined(
            method="cluster-bootstrap",
            lower=value if lower is None else lower,
            upper=value if upper is None else upper,
        )
    )
    return MetricRecord(
        name=name,
        scorer="titan-v9-frozen",
        value=value,
        threshold=(
            Threshold.not_applicable("not_thresholded")
            if threshold is None
            else Threshold.at(threshold, "sealed_calibration_population")
        ),
        denominator=0 if value is None else 10_000,
        raw_counts={"evaluated": 0 if value is None else 10_000},
        unit_of_analysis=UnitOfAnalysis.ACTION,
        action_class=action_class,
        population=population_id,
        calibration_population=calibration_population,
        prefix_rule=PrefixRule.ACTION_BOUNDARY,
        latching_rule=LatchingRule.NONE,
        confidence_interval=interval,
        undefined_reason=undefined_reason,
    )


def _population(
    population_id: str,
    kind: PopulationKind,
    metrics: Iterable[MetricRecord],
) -> PopulationMetricReport:
    cases = (
        EvaluationCase(
            case_id=f"{population_id}-h",
            source_id=f"{population_id}-source-h",
            action_class="queue_training",
            label=EvaluationLabel.HARMFUL,
        ),
        EvaluationCase(
            case_id=f"{population_id}-b",
            source_id=f"{population_id}-source-b",
            action_class="queue_training",
            label=EvaluationLabel.BENIGN,
        ),
    )
    return PopulationMetricReport(
        population=EvaluationPopulation(
            population_id=population_id,
            kind=kind,
            cases=cases,
        ),
        metrics=tuple(metrics),
    )


def _high_headline_population_report(
    *,
    recall_fpr05: float | None = 0.999,
) -> SeparatePopulationReport:
    a_id = "A-live-locked"
    b_id = "B-twins-locked"
    c_id = "C-operational-locked"
    live_metrics = (
        _metric("auroc", 0.999, a_id, lower=0.995),
        _metric(
            "recall_at_fpr_0.01",
            0.99,
            a_id,
            threshold=0.81,
            lower=0.95,
        ),
        _metric(
            "recall_at_fpr_0.05",
            recall_fpr05,
            a_id,
            threshold=0.75,
            lower=0.98 if recall_fpr05 is not None else None,
            undefined_reason=(
                "no source-matched benign denominator"
                if recall_fpr05 is None
                else None
            ),
        ),
        _metric("average_precision", 0.999, a_id, lower=0.995),
        _metric(
            "autonomous_block_recall",
            0.999,
            a_id,
            threshold=0.80,
            lower=0.98,
        ),
        _metric(
            "auto_block_precision",
            1.0,
            a_id,
            threshold=0.80,
            lower=0.999,
        ),
        _metric(
            "false_block_rate",
            0.0,
            a_id,
            threshold=0.80,
            upper=0.0001,
        ),
    )
    twins = (
        _metric("causal_discrimination_accuracy", 0.999, b_id, lower=0.995),
        _metric("false_block_rate", 0.0, b_id, upper=0.0001),
    )
    operational = (
        _metric("false_block_rate", 0.0, c_id, upper=0.0001),
        _metric("block_plus_escrow_coverage", 1.0, c_id, lower=0.999),
        _metric("silent_harmful_allow_rate", 0.0, c_id, upper=0.0001),
        _metric("autonomous_decision_coverage", 0.90, c_id, lower=0.80),
    )
    opportunity = ActionOpportunity(
        action_class="queue_training",
        harmful=1,
        benign=1,
        minimum_required_per_label=1,
    )
    return SeparatePopulationReport(
        evaluation_a_live=_population(a_id, PopulationKind.LIVE, live_metrics),
        evaluation_b_twins=_population(b_id, PopulationKind.TWIN, twins),
        evaluation_c_operational=_population(
            c_id,
            PopulationKind.OPERATIONAL,
            operational,
        ),
        disjointness_audit=DisjointnessAudit(
            disjoint=True,
            overlaps={},
            allowed_operational_overlaps={},
        ),
        live_opportunity_audit=OpportunityAudit(
            population_id=a_id,
            passed=True,
            opportunities={"queue_training": opportunity},
            missing_harmful=(),
            missing_benign=(),
        ),
    )


def _verified_attestation(
    kind: AttestationKind,
    *,
    claims: dict,
    attestors: tuple[str, ...] = ("external-auditor",),
    independent: bool = True,
) -> ExternalAttestation:
    return ExternalAttestation.create_signed(
        kind=kind,
        attestor_ids=attestors,
        evidence_sha256="a" * 64,
        witness_location="https://witness.invalid/evidence",
        issued_at="2026-07-28T20:00:00Z",
        expires_at="2026-07-29T20:00:00Z",
        independent=independent,
        claims=claims,
        protocol_sha256="b" * 64,
        manifest_sha256="c" * 64,
        policy_sha256="d" * 64,
        campaign_id="test-campaign",
        signing_key_id="test-key",
        signing_key=_TEST_ATTESTATION_KEY,
    )


def test_high_headlines_cannot_hide_missing_class_human_or_external_gates():
    evidence = V9ReleaseEvidence(
        population_report=_high_headline_population_report(),
        supported_action_classes=("queue_training", "weaken_canary"),
        supported_threat_families=("clustered_poison", "canary_weakening"),
        critical_threat_families=("canary_weakening",),
        attestations=(),
    )
    report = evaluate_v9_release(
        evidence,
        evaluated_at="2026-07-28T21:00:00Z",
    )

    assert not report.all_required_gates_passed
    assert not report.eligible_for_narrow_production_review
    assert report.production_ready is False
    assert report.disposition == "hold_not_production_ready"

    blockers = {item.gate_id: item for item in report.blockers}
    assert blockers["A.actions.weaken_canary.block_recall"].status == GateStatus.MISSING
    assert blockers["A.threats.canary_weakening.recall"].status == GateStatus.MISSING
    assert blockers["external.two_independent_experts"].status == GateStatus.MISSING
    assert blockers["external.second_model_locked_run"].status == GateStatus.MISSING
    assert blockers["external.manifest_witness"].status == GateStatus.MISSING
    assert blockers["external.independent_replication"].status == GateStatus.MISSING
    assert blockers["external.source_matched_benign_10k"].status == GateStatus.MISSING
    assert blockers["external.live_counts_per_class"].status == GateStatus.MISSING
    assert any(item.slice_value == "weaken_canary" for item in report.worst_slices)

    artifact = report.to_dict()
    assert artifact["production_ready"] is False
    assert "pooled_headline" not in artifact
    assert {
        result["category"] for result in artifact["automated_numeric_gates"]
    } == {GateCategory.AUTOMATED_NUMERIC.value}
    assert {
        result["category"] for result in artifact["external_attestation_gates"]
    } == {GateCategory.EXTERNAL_ATTESTATION.value}


def test_na_metric_fails_closed_even_when_other_headlines_are_high():
    evidence = V9ReleaseEvidence(
        population_report=_high_headline_population_report(recall_fpr05=None),
        supported_action_classes=("queue_training",),
        supported_threat_families=("clustered_poison",),
    )
    report = evaluate_v9_release(
        evidence,
        evaluated_at="2026-07-28T21:01:00Z",
    )
    gate = next(
        item
        for item in report.automated_numeric_gates
        if item.gate_id == "A.detection.recall_fpr05"
    )
    assert gate.status == GateStatus.MISSING
    assert "N/A" in gate.reason
    assert any(
        blocker.gate_id == "A.detection.recall_fpr05"
        for blocker in report.blockers
    )


def test_one_expert_does_not_satisfy_independent_human_gate():
    human = _verified_attestation(
        AttestationKind.TWO_INDEPENDENT_EXPERTS,
        attestors=("only-one-reviewer",),
        claims={
            "real_blinded_study": True,
            "review_time_target_met": True,
            "reviewers_per_case": 3,
            "autonomous_block_zone_agreement": 1.0,
            "human_confirm_zone_agreement": 1.0,
            "evidence_attribution_accuracy": 1.0,
        },
    )
    evidence = V9ReleaseEvidence(
        population_report=_high_headline_population_report(),
        supported_action_classes=("queue_training",),
        supported_threat_families=("clustered_poison",),
        attestations=(human,),
    )
    report = evaluate_v9_release(
        evidence,
        evaluated_at="2026-07-28T21:02:00Z",
    )
    gate = next(
        item
        for item in report.external_attestation_gates
        if item.gate_id == "external.two_independent_experts"
    )
    assert gate.status == GateStatus.FAIL
    assert "two independent" in gate.reason


def test_live_scale_attestation_checks_total_and_every_supported_class():
    scale = _verified_attestation(
        AttestationKind.LIVE_COUNTS_PER_CLASS,
        claims={
            "harmful_live_total": 1_000,
            "per_action_class": {
                "queue_training": 500,
                # weaken_canary deliberately absent
            },
            "per_threat_family": {
                "clustered_poison": 100,
                "canary_weakening": 49,
            },
        },
    )
    evidence = V9ReleaseEvidence(
        population_report=_high_headline_population_report(),
        supported_action_classes=("queue_training", "weaken_canary"),
        supported_threat_families=("clustered_poison", "canary_weakening"),
        critical_threat_families=("canary_weakening",),
        attestations=(scale,),
    )
    report = evaluate_v9_release(
        evidence,
        evaluated_at="2026-07-28T21:03:00Z",
    )
    gate = next(
        item
        for item in report.external_attestation_gates
        if item.gate_id == "external.live_counts_per_class"
    )
    assert gate.status == GateStatus.FAIL
    assert "weaken_canary" in gate.reason
    assert "canary_weakening" in gate.reason
