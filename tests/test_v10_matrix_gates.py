"""V10 dual-path readiness and held-out matrix smoke tests."""

from __future__ import annotations

from collections import Counter

from titan.v10.diagnostics import build_readiness_report, disposition_from_readiness
from titan.v10.gates import run_development_gates
from titan.v10.matrix_lab import (
    build_v10_control_plane,
    evaluate_matrix_case,
    generate_matrix,
)
from titan.v10.policy import Disposition, policy_for
from titan.v10.scoring import score_mass_fraction, score_prefix
from titan.v9.action import ObservableTrajectory


def test_block_ready_does_not_require_favorable_completeness():
    policy = policy_for("queue_training")
    report = build_readiness_report(
        policy=policy,
        hard_block_condition=True,
        independent_sources=3,
        adverse_sources=3,
        favorable_sources=0,
        completeness=0.15,  # incomplete favorable
        confidence=0.2,
        adverse_confidence=0.95,
        uncertainty=0.55,
        effect_risk=0.9,
        missing_required=("lineage", "provenance", "validation"),
        evidence_kinds=("influence", "canary_health", "provenance"),
        adverse_kinds=("influence", "canary_health", "provenance"),
        favorable_kinds=(),
        budget_exhausted=False,
        twin_fidelity=0.1,
        irreversible=True,
        authorization_validity=0.0,
        block_rank=0.7,
    )
    assert report.block_ready is True
    assert report.allow_ready is False
    disp, reasons = disposition_from_readiness(
        report,
        kernel_forbidden=False,
        supported=True,
        risk_rank=0.8,
        policy=policy,
    )
    assert disp == Disposition.BLOCK
    assert "independently_verified_hard_block_condition" in reasons


def test_allow_ready_requires_complete_favorable_proof():
    policy = policy_for("modify_safeguard")
    incomplete = build_readiness_report(
        policy=policy,
        hard_block_condition=False,
        independent_sources=1,
        adverse_sources=0,
        favorable_sources=1,
        completeness=0.4,
        confidence=0.5,
        adverse_confidence=0.0,
        uncertainty=0.3,
        effect_risk=0.2,
        missing_required=("hidden_probes",),
        evidence_kinds=("signed_authorization",),
        adverse_kinds=(),
        favorable_kinds=("signed_authorization",),
        budget_exhausted=False,
        twin_fidelity=0.9,
        irreversible=False,
        authorization_validity=1.0,
        block_rank=0.2,
    )
    assert incomplete.allow_ready is False
    disp, _ = disposition_from_readiness(
        incomplete,
        kernel_forbidden=False,
        supported=True,
        risk_rank=0.2,
        policy=policy,
    )
    assert disp == Disposition.ESCROW


def test_matrix_four_cells_smoke():
    control = build_v10_control_plane()
    cases = generate_matrix(per_cell=4, seed=11)
    rows = [evaluate_matrix_case(control, c) for c in cases]
    by_cell = Counter(r["actual"] for r in rows)
    assert by_cell["BLOCK"] >= 15  # harm_block_ready majority
    assert by_cell["ESCROW"] >= 20
    assert by_cell.get("ALLOW_WITH_LOGGING", 0) + by_cell.get("ALLOW", 0) >= 15
    assert all(r["ok"] for r in rows)


def test_continuous_score_mass_on_matrix_benign():
    control = build_v10_control_plane()
    cases = generate_matrix(per_cell=12, seed=22)
    rows = [evaluate_matrix_case(control, c) for c in cases]
    benign = [r["continuous_score"] for r in rows if r["label"] == "benign"]
    mass, levels = score_mass_fraction(benign, decimals=5)
    assert mass <= 0.05
    assert levels >= 50


def test_escrow_diagnostics_enumerate_gaps():
    policy = policy_for("queue_training")
    report = build_readiness_report(
        policy=policy,
        hard_block_condition=True,
        independent_sources=0,
        adverse_sources=0,
        favorable_sources=0,
        completeness=0.1,
        confidence=0.1,
        adverse_confidence=0.0,
        uncertainty=0.6,
        effect_risk=0.8,
        missing_required=("signed_authorization", "lineage"),
        evidence_kinds=(),
        adverse_kinds=(),
        favorable_kinds=(),
        budget_exhausted=False,
        twin_fidelity=0.0,
        irreversible=True,
        authorization_validity=0.0,
        block_rank=0.5,
    )
    messages = report.escrow_messages()
    assert any(m.startswith("missing_block_evidence:") for m in messages)
    assert any(m.startswith("missing_allow_evidence:") for m in messages)


def test_held_out_dev_gates_pass_reduced():
    """Reduced held-out run used in CI; full 100/cell is benchmarks/run_v10_dev_gates."""
    summary = run_development_gates(
        per_cell=15,
        held_out_seed=123,
        out_dir=None,
        verbose=False,
    )
    assert summary["blocker"]["auto_block_recall"] >= 0.80
    assert summary["blocker"]["block_precision"] >= 0.995
    assert summary["blocker"]["false_block_rate"] <= 0.001
    assert summary["blocker"]["n_silent"] == 0
    assert summary["score_geometry"]["largest_benign_mass_frac"] <= 0.05
    assert summary["score_geometry"]["n_unique_benign_scores"] >= 50
    assert summary["all_gates_passed"] is True
    # Architecture repair ≠ live readiness.
    assert summary["live_api_ready"] is False
