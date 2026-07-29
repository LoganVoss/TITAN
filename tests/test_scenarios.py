"""Scenario generation coverage."""

from titan.scenarios.generator import (
    POISON_FAMILIES,
    SABOTAGE_FAMILIES,
    ScenarioSpec,
    generate_scenario_suite,
    suite_summary,
)
from titan.schema import Label


def test_suite_has_both_classes_and_families():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=4,
        n_clean_benign=4,
        n_clean_refactor=2,
        seed=1,
    ))
    summary = suite_summary(suite)
    assert summary["harmful"] > 0
    assert summary["benign"] > 0
    for fam in POISON_FAMILIES:
        assert summary["families"].get(fam.value, 0) >= 2
    for fam in SABOTAGE_FAMILIES:
        assert summary["families"].get(fam.value, 0) >= 2


def test_expected_count():
    spec = ScenarioSpec(n_harmful_per_family=2, n_hard_negatives=4, n_clean_benign=4, n_clean_refactor=2)
    suite = generate_scenario_suite(spec)
    assert len(suite) == spec.expected_count()
