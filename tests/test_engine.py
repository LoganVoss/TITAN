"""Discovery engine: true augmentation and collision reduction attribution."""

from titan.collisions import find_collisions
from titan.engine import run_discovery
from titan.features import BASE_MONITOR_FEATURES
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.schema import Label


def test_synthesis_augments_feature_vectors():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=10,
        n_clean_benign=8,
        n_clean_refactor=4,
        seed=7,
    ))
    discovery = [t for t in suite if t.label in (Label.HARMFUL, Label.BENIGN)][:40]
    result = run_discovery(discovery, name="test", verbose=False, max_rounds=2)

    # Discovery starts from base monitors; synthesis may grow the map
    base_dim = len(BASE_MONITOR_FEATURES)
    assert len(result.feature_fns) >= base_dim
    if result.promoted:
        for c in result.promoted:
            assert any(c.name in k or k.endswith(c.name) for k in result.feature_fns)
        assert len(result.feature_fns) > base_dim


def test_final_collisions_use_augmented_features():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=12,
        n_clean_benign=10,
        n_clean_refactor=4,
        seed=11,
    ))
    result = run_discovery(suite[:50], name="aug", verbose=False)

    # Recompute with final feature map — should match final_report
    recomputed = find_collisions(
        suite[:50],
        threshold=result.final_report.threshold,
        feature_fns=result.feature_fns,
    )
    assert len(recomputed.collisions) == result.final_collisions


def test_same_threshold_default_for_honest_reduction():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=8,
        n_clean_benign=8,
        n_clean_refactor=4,
        seed=3,
    ))
    result = run_discovery(suite[:40], name="honest", verbose=False, threshold=2.5)
    # final_threshold defaults to the locked initial threshold
    assert abs(result.initial_report.threshold - 2.5) < 1e-9
    assert abs(result.final_report.threshold - 2.5) < 1e-9


def test_discovery_finds_collisions_and_promotes():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=14,
        n_clean_benign=10,
        n_clean_refactor=4,
        seed=42,
    ))
    result = run_discovery(suite, name="full", verbose=False)
    assert result.initial_collisions > 0
    assert len(result.promoted) > 0
    # True augmentation should not increase collisions
    assert result.final_collisions <= result.initial_collisions
