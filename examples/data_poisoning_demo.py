#!/usr/bin/env python3
"""
Data-poisoning monitor demo.

Objective (role-aligned):
  Detect multi-step attempts to introduce targeted training-data poisoning
  with high recall at a fixed human-review budget, before contaminated data
  reaches a training run.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan import MonitorRegistry, run_discovery, split_dataset, evaluate_monitor
from titan.baselines import fit_all_baselines
from titan.engine import score_trajectory
from titan.report import format_trajectory_review
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite, suite_summary
from titan.schema import AttackFamily, Label


def main() -> None:
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=4,
        n_hard_negatives=14,
        n_clean_benign=16,
        n_clean_refactor=8,
        seed=7,
    ))
    print("Suite:", suite_summary(suite))

    part = split_dataset(suite, seed=7)
    print("Partitions:", part.summary())

    # Fit baselines on discovery only
    baselines = fit_all_baselines(part.discovery)

    # TITAN discovery
    disc = run_discovery(
        part.discovery,
        name="poisoning_discovery",
        selection=part.selection,
        verbose=True,
    )

    scorers = {
        "existing_monitor": lambda t: t.max_monitor_severity(),
        "rule": baselines["rule"].score,
        "classifier": baselines["classifier"].score,
        "judge": baselines["judge"].score,
        "titan": lambda t: score_trajectory(t, disc.promoted)["alert_strength"],
    }

    print("\n══ Locked-set comparison ══")
    for name, fn in scorers.items():
        rep = evaluate_monitor(fn, part.locked, name=name, budgets=(10, 25, 50))
        print(f"  {rep.summary()}")
        print(f"    recall@budget50={rep.recall_at_budget.get('50', 0):.3f}")

    # Shadow registry pipeline
    reg = MonitorRegistry()
    reg.register_many(disc.promoted)
    for e in reg.list():
        reg.promote_to_shadow(e.name)
    for t in part.selection + part.locked:
        for e in reg.list(status="shadow"):
            reg.record_shadow(e.name, t)
    print("\n══ Registry ══")
    print(" ", reg.summary())
    for e in reg.list(status="shadow")[:3]:
        m = reg.evaluate_shadow_metrics(e.name)
        print(f"  {e.name}: shadow metrics={m}")

    # Show a few harmful poisoning reviews
    print("\n══ Sample harmful reviews ══")
    harmful = [t for t in part.locked if t.label == Label.HARMFUL][:3]
    for t in harmful:
        print(format_trajectory_review(t, disc.promoted))
        print()


if __name__ == "__main__":
    main()
