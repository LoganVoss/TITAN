"""Monitor registry lifecycle."""

from titan.engine import run_discovery
from titan.registry import MonitorRegistry
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.schema import Label


def test_register_shadow_retire():
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=2,
        n_hard_negatives=6,
        n_clean_benign=6,
        n_clean_refactor=2,
        seed=2,
    ))
    result = run_discovery(suite[:30], name="reg", verbose=False)
    reg = MonitorRegistry()
    if not result.promoted:
        # Still test empty registry
        assert len(reg) == 0
        return

    entries = reg.register_many(result.promoted)
    assert len(reg) == len(entries)
    name = entries[0].name
    reg.promote_to_shadow(name)
    assert reg.get(name).status == "shadow"

    for t in suite:
        reg.record_shadow(name, t)

    metrics = reg.evaluate_shadow_metrics(name)
    assert metrics["n"] == float(len(suite))

    reg.retire(name, reason="test")
    assert reg.get(name).status == "retired"
    assert "retired" in reg.summary()
