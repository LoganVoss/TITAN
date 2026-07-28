from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from titan.v9.adjudication import (
    ActionGroundTruth,
    AdjudicationRecord,
    ReviewerJudgment,
    agreement_report,
)
from titan.v9.calibration import (
    CalibrationDatasetSeal,
    CalibrationSample,
    HierarchicalCalibrator,
    calibration_diagnostics,
    fit_isotonic,
)


def _judgment(
    reviewer: str,
    label: ActionGroundTruth,
    *,
    unsafe: bool,
    block: bool = False,
    escrow: bool = False,
) -> ReviewerJudgment:
    return ReviewerJudgment(
        reviewer_id=reviewer,
        label=label,
        unsafe_to_allow=unsafe,
        autonomous_block_justified=block,
        escrow_justified=escrow,
        boundary_evidence_ids=("boundary-event-4",),
        boundary_evidence_digests=("b" * 64,),
        boundary_evidence_sequences=(4,),
        rationale="Only evidence available before the action was considered.",
        reviewed_at="2026-07-28T00:00:00Z",
    )


def _sample(
    rank_score: float,
    outcome: int,
    *,
    index: int,
    action_type: str = "queue_training",
    environment: str = "repo-a",
    population: str = "calibration",
    source_id: str | None = None,
) -> CalibrationSample:
    return CalibrationSample(
        rank_score,
        outcome,
        action_type,
        environment,
        population=population,
        sample_id=f"sample-{index}",
        source_id=source_id or f"session-{index // 2}",
    )


def _seal(
    rows: list[CalibrationSample],
    *,
    dataset_id: str = "calibration-campaign-v1",
    split_id: str = "calibration-fold",
) -> CalibrationDatasetSeal:
    return CalibrationDatasetSeal.create(
        rows,
        dataset_id=dataset_id,
        split_id=split_id,
    )


def test_isotonic_coalesces_equal_probability_strata_for_intervals():
    rows = [
        _sample(i / 1_000, 0, index=i)
        for i in range(200)
    ] + [
        _sample(0.8 + i / 1_000, 1, index=200 + i)
        for i in range(20)
    ]
    model = fit_isotonic(rows)
    assert len(model.bins) == 2
    low = model.predict_bin(0.1)
    assert low.total == 200
    assert low.probability == 0.0
    assert low.interval[1] < 0.02


def test_calibrator_rejects_eval_or_locked_population_leakage():
    rows = [
        _sample(
            0.1,
            0,
            index=0,
            population="locked_eval",
        ),
        _sample(0.9, 1, index=1),
    ]
    with pytest.raises(ValueError, match="calibration-population"):
        HierarchicalCalibrator(calibrator_id="risk-v1").fit(
            rows,
            seal=_seal(rows),
        )


def test_hierarchical_calibration_falls_back_without_local_support():
    rows = [
        _sample(i / 200, 0, index=i)
        for i in range(80)
    ] + [
        _sample(0.75 + i / 200, 1, index=80 + i)
        for i in range(20)
    ]
    calibrator = HierarchicalCalibrator(
        calibrator_id="risk-v1",
        minimum_local_support=50,
        minimum_outcomes_per_class=5,
    ).fit(rows, seal=_seal(rows))
    local = calibrator.predict(0.1, action_type="queue_training", environment="repo-b")
    assert local.level == "action_class"
    assert local.dataset_id == "calibration-campaign-v1"
    assert local.split_id == "calibration-fold"
    assert local.dataset_digest == calibrator.dataset_seal.dataset_digest
    assert calibrator.source_ids == tuple(
        sorted({row.source_id for row in rows})
    )
    fallback = calibrator.predict(0.1, action_type="modify_safeguard", environment="repo-b")
    assert fallback.level == "global"


def test_diagnostics_report_ece_brier_and_reliability():
    result = calibration_diagnostics(
        [0, 0, 1, 1],
        [0.05, 0.15, 0.85, 0.95],
        bins=4,
    )
    assert result.n == 4
    assert 0.0 <= result.ece <= 1.0
    assert 0.0 <= result.brier <= 1.0
    assert result.reliability


def test_adjudication_requires_third_independent_reviewer_on_disagreement():
    allow = _judgment(
        "reviewer-a",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    block = _judgment(
        "reviewer-b",
        ActionGroundTruth.AUTONOMOUS_BLOCK_JUSTIFIED,
        unsafe=True,
        block=True,
    )
    with pytest.raises(ValueError, match="third reviewer"):
        AdjudicationRecord(
            action_id="action-1",
            action_hash="a" * 64,
            boundary_sequence=4,
            primary_reviewers=(allow, block),
            final_label=ActionGroundTruth.MUST_PAUSE,
            final_unsafe_to_allow=True,
            final_autonomous_block_justified=False,
            final_escrow_justified=True,
        )

    resolver = _judgment(
        "reviewer-c",
        ActionGroundTruth.MUST_PAUSE,
        unsafe=True,
        escrow=True,
    )
    record = AdjudicationRecord(
        action_id="action-1",
        action_hash="a" * 64,
        boundary_sequence=4,
        primary_reviewers=(allow, block),
        resolution_reviewer=resolver,
        disagreement_documentation="Reviewer A treated a missing scope proof as optional.",
        final_label=ActionGroundTruth.MUST_PAUSE,
        final_unsafe_to_allow=True,
        final_autonomous_block_justified=False,
        final_escrow_justified=True,
    )
    report = agreement_report([record])
    assert report.disagreement_action_ids == ("action-1",)
    assert not report.block_gate_passed
    assert len(record.record_hash) == 64


@pytest.mark.parametrize(
    "label,unsafe,block,escrow",
    [
        (ActionGroundTruth.SAFE_TO_ALLOW, True, False, False),
        (ActionGroundTruth.NEEDS_MORE_EVIDENCE, False, False, False),
        (ActionGroundTruth.HUMAN_POLICY_JUDGMENT, True, False, True),
        (
            ActionGroundTruth.AUTONOMOUS_BLOCK_JUSTIFIED,
            True,
            False,
            False,
        ),
        (ActionGroundTruth.KERNEL_FORBIDDEN, True, True, True),
    ],
)
def test_reviewer_label_and_boolean_outcome_must_be_canonical(
    label,
    unsafe,
    block,
    escrow,
):
    with pytest.raises(ValueError, match="requires"):
        _judgment(
            "reviewer-a",
            label,
            unsafe=unsafe,
            block=block,
            escrow=escrow,
        )


def test_final_outcome_is_derived_from_consensus_or_resolution_reviewer():
    allow_a = _judgment(
        "reviewer-a",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    allow_b = _judgment(
        "reviewer-b",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    with pytest.raises(ValueError, match="two-reviewer consensus"):
        AdjudicationRecord(
            action_id="action-consensus",
            action_hash="a" * 64,
            boundary_sequence=4,
            primary_reviewers=(allow_a, allow_b),
            final_label=ActionGroundTruth.MUST_PAUSE,
            final_unsafe_to_allow=True,
            final_autonomous_block_justified=False,
            final_escrow_justified=True,
        )

    block = _judgment(
        "reviewer-b",
        ActionGroundTruth.AUTONOMOUS_BLOCK_JUSTIFIED,
        unsafe=True,
        block=True,
    )
    resolver = _judgment(
        "reviewer-c",
        ActionGroundTruth.MUST_PAUSE,
        unsafe=True,
        escrow=True,
    )
    with pytest.raises(ValueError, match="resolution reviewer"):
        AdjudicationRecord(
            action_id="action-disagreement",
            action_hash="a" * 64,
            boundary_sequence=4,
            primary_reviewers=(allow_a, block),
            resolution_reviewer=resolver,
            disagreement_documentation="Resolver found proof incomplete.",
            final_label=ActionGroundTruth.AUTONOMOUS_BLOCK_JUSTIFIED,
            final_unsafe_to_allow=True,
            final_autonomous_block_justified=True,
            final_escrow_justified=False,
        )


def test_boundary_evidence_requires_nonempty_content_digests():
    valid = _judgment(
        "reviewer-a",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    with pytest.raises(ValueError, match="one content digest"):
        replace(valid, boundary_evidence_digests=())
    with pytest.raises(ValueError, match="SHA-256"):
        replace(valid, boundary_evidence_digests=("not-a-digest",))

    future_evidence = replace(valid, boundary_evidence_sequences=(5,))
    peer = _judgment(
        "reviewer-b",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    with pytest.raises(ValueError, match="only through the action boundary"):
        AdjudicationRecord(
            action_id="action-future-leak",
            action_hash="a" * 64,
            boundary_sequence=4,
            primary_reviewers=(future_evidence, peer),
            final_label=ActionGroundTruth.SAFE_TO_ALLOW,
            final_unsafe_to_allow=False,
            final_autonomous_block_justified=False,
            final_escrow_justified=False,
        )


def test_empty_autonomous_agreement_zone_is_na_and_fails_gate():
    allow_a = _judgment(
        "reviewer-a",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    allow_b = _judgment(
        "reviewer-b",
        ActionGroundTruth.SAFE_TO_ALLOW,
        unsafe=False,
    )
    record = AdjudicationRecord(
        action_id="action-safe",
        action_hash="a" * 64,
        boundary_sequence=4,
        primary_reviewers=(allow_a, allow_b),
        final_label=ActionGroundTruth.SAFE_TO_ALLOW,
        final_unsafe_to_allow=False,
        final_autonomous_block_justified=False,
        final_escrow_justified=False,
    )
    report = agreement_report([record])
    assert report.autonomous_zone_n == 0
    assert report.autonomous_zone_agreement is None
    assert not report.autonomous_gate_passed
    with pytest.raises(ValueError, match="action IDs must be unique"):
        agreement_report([record, record])


def test_calibration_sample_identity_seal_and_freeze_are_enforced():
    with pytest.raises(ValueError, match="sample_id"):
        CalibrationSample(
            0.1,
            0,
            "queue_training",
            "repo-a",
            sample_id=" ",
            source_id="session-a",
        )
    with pytest.raises(ValueError, match="source_id"):
        CalibrationSample(
            0.1,
            0,
            "queue_training",
            "repo-a",
            sample_id="sample-a",
            source_id=" ",
        )

    rows = [
        _sample(0.1, 0, index=0),
        _sample(0.9, 1, index=1),
    ]
    duplicate = [rows[0], replace(rows[1], sample_id=rows[0].sample_id)]
    with pytest.raises(ValueError, match="must be unique"):
        fit_isotonic(duplicate)

    seal = _seal(rows)
    tampered = [rows[0], replace(rows[1], rank_score=0.8)]
    with pytest.raises(ValueError, match="do not match dataset seal"):
        HierarchicalCalibrator(
            calibrator_id="sealed-risk-v1",
            minimum_local_support=2,
            minimum_outcomes_per_class=1,
        ).fit(tampered, seal=seal)

    calibrator = HierarchicalCalibrator(
        calibrator_id="sealed-risk-v1",
        minimum_local_support=2,
        minimum_outcomes_per_class=1,
    ).fit(rows, seal=seal)
    assert calibrator.is_frozen
    with pytest.raises(RuntimeError, match="already fit and frozen"):
        calibrator.fit(rows, seal=seal)
    with pytest.raises(AttributeError, match="frozen"):
        calibrator.calibrator_id = "silently-replaced"  # type: ignore[misc]

    concurrent = HierarchicalCalibrator(
        calibrator_id="concurrent-fit-v1",
        minimum_local_support=2,
        minimum_outcomes_per_class=1,
    )

    def attempt_fit(_):
        try:
            concurrent.fit(rows, seal=seal)
            return True
        except RuntimeError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt_fit, range(2)))
    assert sum(outcomes) == 1
    assert concurrent.is_frozen
