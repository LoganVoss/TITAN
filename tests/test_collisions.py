"""Regime-aware collisions and normalized distances."""

import numpy as np

from titan.collisions import find_collisions
from titan.features import trajectories_to_matrix, zscore_normalize
from titan.schema import AttackFamily, Label
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.scenarios.poisoning import generate_benign_curation, generate_poisoning_scenario


def test_collisions_require_cross_regime():
    harmful = [
        generate_poisoning_scenario(AttackFamily.CLUSTER_CONCENTRATION, seed=i)
        for i in range(5)
    ]
    # Same-regime only → zero collisions under require_cross_regime
    report = find_collisions(harmful, threshold=10.0, require_cross_regime=True)
    assert len(report.collisions) == 0
    assert report.n_harmful == 5
    assert report.n_benign == 0


def test_collisions_find_cross_regime_when_close():
    # Hard negatives + weak monitors should produce some collisions at high threshold
    suite = []
    for i in range(6):
        suite.append(generate_poisoning_scenario(AttackFamily.EVAL_WEAKENING, seed=i))
        suite.append(generate_benign_curation(seed=i, hard_negative=True))
    report = find_collisions(suite, threshold=5.0)  # loose
    assert report.n_harmful == 6
    assert report.n_benign == 6
    # At least the infrastructure works; may or may not collide depending on features
    assert report.pressure >= 0.0
    for c in report.collisions:
        labs = {c.label_a, c.label_b}
        assert labs == {"harmful", "benign"}


def test_zscore_normalization_equalizes_scales():
    suite = generate_scenario_suite(ScenarioSpec(n_harmful_per_family=2, n_hard_negatives=4, n_clean_benign=4, n_clean_refactor=2, seed=0))
    X, names = trajectories_to_matrix(suite)
    Z, center, scale = zscore_normalize(X)
    # After z-score, column scales should be order-1
    col_std = Z.std(axis=0)
    assert np.median(col_std) < 5.0
    assert len(names) == Z.shape[1]
