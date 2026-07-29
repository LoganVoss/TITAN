"""DSL compilation and determinism."""

from titan.dsl import (
    BinOp,
    FeatureRef,
    UnaryOp,
    compile_expr,
    expr_to_str,
    feature_deps,
    generate_dsl_candidates,
)
from titan.scenarios.poisoning import generate_poisoning_scenario
from titan.schema import AttackFamily


def test_compile_and_score():
    expr = BinOp("mul", FeatureRef("rare_source_fraction"), FeatureRef("mean_gradient_influence"))
    fn = compile_expr(expr)
    t = generate_poisoning_scenario(AttackFamily.RARE_SOURCE_HIGH_INFLUENCE, seed=0)
    s = fn(t)
    assert s >= 0.0
    assert "rare_source_fraction" in feature_deps(expr)
    assert "mul" in expr_to_str(expr)


def test_threshold_op():
    expr = UnaryOp("threshold_gt", FeatureRef("n_data_mutations"), 0.0)
    fn = compile_expr(expr)
    t = generate_poisoning_scenario(AttackFamily.CLUSTER_CONCENTRATION, seed=1)
    assert fn(t) == 1.0


def test_generate_pool_bounded():
    pool = generate_dsl_candidates(complexity_level=3)
    assert len(pool) > 10
    assert all(c.score_fn is not None for c in pool[:5])
    # Deterministic names
    names = [c.name for c in pool]
    assert len(names) == len(set(names))
