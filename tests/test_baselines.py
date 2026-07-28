"""Baseline monitors."""

from titan.baselines import FeatureClassifierBaseline, JudgeBaseline, RuleBaseline, fit_all_baselines
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.schema import Label


def test_baselines_score_in_unit_interval():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=4,
        n_clean_benign=4,
        n_clean_refactor=2,
        seed=4,
    ))
    models = fit_all_baselines(suite)
    for t in suite[:5]:
        for name, m in models.items():
            s = m.score(t)
            assert 0.0 <= s <= 1.0 + 1e-6, f"{name} score {s}"


def test_classifier_separates_after_fit():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=6,
        n_clean_benign=8,
        n_clean_refactor=4,
        seed=8,
    ))
    clf = FeatureClassifierBaseline().fit(suite)
    harm = [clf.score(t) for t in suite if t.label == Label.HARMFUL]
    ben = [clf.score(t) for t in suite if t.label == Label.BENIGN]
    assert sum(harm) / len(harm) > sum(ben) / len(ben)
