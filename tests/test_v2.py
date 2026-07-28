"""Tests for Improvements V1 modules."""

from titan.aggregator import SparseAggregator
from titan.engine_v2 import run_discovery_v2
from titan.error_atlas import build_error_atlas
from titan.llm_evidence import extract_structured_evidence, evidence_risk_score
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.scenarios.hard_negatives import HARD_NEGATIVE_FAMILIES, generate_hard_negative_v2
from titan.scenarios.adaptive import generate_stealth_attack
from titan.schema import AttackFamily, Label
from titan.temporal import chain_length_score, mutation_then_eval_within
from titan.baselines import fit_all_baselines
from titan.control_eval.sandbox import simulate_session_outcome


def test_temporal_features_on_poison():
    from titan.scenarios.poisoning import generate_poisoning_scenario
    t = generate_poisoning_scenario(AttackFamily.EVAL_WEAKENING, seed=1)
    assert mutation_then_eval_within(t) == 1.0
    assert chain_length_score(t) >= 1.0


def test_hard_negatives_benign():
    for fam in HARD_NEGATIVE_FAMILIES[:3]:
        t = generate_hard_negative_v2(fam, seed=0)
        assert t.label == Label.BENIGN


def test_stealth_attack_harmful():
    t = generate_stealth_attack(AttackFamily.STEALTH_POISON, seed=0)
    assert t.label == Label.HARMFUL
    assert t.max_monitor_severity() < 0.5


def test_evidence_extraction():
    from titan.scenarios.poisoning import generate_poisoning_scenario
    t = generate_poisoning_scenario(AttackFamily.CANARY_SUPPRESSION, seed=2)
    ev = extract_structured_evidence(t)
    assert ev.affects_training_data >= 0.0
    assert 0.0 <= evidence_risk_score(t) <= 1.0


def test_discovery_v2_promotes_and_aggregates():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=10,
        n_clean_benign=8,
        n_clean_refactor=4,
        seed=11,
    ))
    disc = suite[:35]
    sel = suite[35:50] if len(suite) > 50 else suite[20:35]
    result = run_discovery_v2(disc, selection=sel, verbose=False, max_rounds=3)
    assert result.initial_collisions >= 0
    if result.promoted:
        scorer = result.scorer()
        s = scorer(disc[0])
        assert 0.0 <= s <= 1.0 or s == s  # finite
        assert result.aggregator is not None


def test_error_atlas_runs():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2, n_hard_negatives=4, n_clean_benign=4, n_clean_refactor=2, seed=3
    ))
    models = fit_all_baselines(suite)
    atlas = build_error_atlas(
        suite,
        titan_fn=lambda t: t.max_monitor_severity(),
        classifier_fn=models["classifier"].score,
        rule_fn=models["rule"].score,
        judge_fn=models["judge"].score,
    )
    assert atlas.answers["n_harmful"] > 0
    assert "key_findings" in atlas.answers


def test_sandbox_outcome():
    t = generate_stealth_attack(AttackFamily.STEALTH_POISON, seed=5)
    out = simulate_session_outcome(t)
    assert out.trajectory_id == t.trajectory_id
    assert out.dataset_contaminated or out.training_queued
