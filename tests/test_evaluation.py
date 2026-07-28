"""Disjoint splits and real metrics."""

import numpy as np

from titan.evaluation.metrics import (
    auroc,
    average_precision,
    evaluate_monitor,
    recall_at_budget,
    recall_at_fpr,
)
from titan.evaluation.splits import split_dataset
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.schema import Label


def test_four_way_split_disjoint():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=8,
        n_clean_benign=10,
        n_clean_refactor=4,
        seed=5,
    ))
    part = split_dataset(suite, seed=5)
    ids = lambda xs: {t.trajectory_id for t in xs}
    all_parts = [part.discovery, part.selection, part.calibration, part.locked]
    for i in range(len(all_parts)):
        for j in range(i + 1, len(all_parts)):
            assert ids(all_parts[i]).isdisjoint(ids(all_parts[j]))
    # Calibration is benign-only
    assert all(t.label == Label.BENIGN for t in part.calibration)


def test_recall_at_fpr_perfect_separator():
    scores = np.array([0.9, 0.8, 0.7, 0.1, 0.05, 0.0])
    labels = np.array([1.0, 1.0, 1.0, 0.0, 0.0, 0.0])
    rec, thr = recall_at_fpr(scores, labels, 0.0)
    assert rec == 1.0
    rec5, _ = recall_at_fpr(scores, labels, 0.05)
    assert rec5 == 1.0


def test_recall_at_budget():
    scores = np.array([0.9, 0.8, 0.1, 0.05])
    labels = np.array([1.0, 0.0, 1.0, 0.0])
    # Top-1 gets 1/2 of harm
    assert abs(recall_at_budget(scores, labels, 1) - 0.5) < 1e-9
    assert abs(recall_at_budget(scores, labels, 3) - 1.0) < 1e-9


def test_auroc_and_ap():
    scores = np.array([0.9, 0.8, 0.2, 0.1])
    labels = np.array([1.0, 1.0, 0.0, 0.0])
    assert auroc(scores, labels) == 1.0
    assert average_precision(scores, labels) == 1.0


def test_evaluate_monitor_no_proxy_transfer():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=6,
        n_clean_benign=8,
        n_clean_refactor=4,
        seed=9,
    ))

    def scorer(t):
        return t.max_monitor_severity()

    rep = evaluate_monitor(scorer, suite, name="existing")
    assert rep.n_harmful > 0
    assert "0.05" in rep.recall_at_fpr
    assert 0.0 <= rep.calibration_error <= 1.0
    # No invented perfect score when collisions are zero
    assert rep.auroc == rep.auroc  # not NaN for balanced suite
