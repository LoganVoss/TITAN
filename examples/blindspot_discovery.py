#!/usr/bin/env python3
"""
Show exactly where existing monitors fail: collision detail report.

A collision = harmful + benign hard-negative with similar monitor vectors.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.collisions import find_collisions, format_collision_detail
from titan.engine import run_discovery
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.schema import Label


def main() -> None:
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=16,
        n_clean_benign=10,
        n_clean_refactor=4,
        seed=99,
    ))

    print("── Before synthesis ──")
    before = find_collisions(suite, threshold=0.95)
    print(before.summary())
    for c in before.collisions[:5]:
        print(format_collision_detail(c, suite))
        print()

    result = run_discovery(suite, name="blindspots", verbose=True, threshold=0.95)

    print("── After synthesis (same threshold) ──")
    print(result.final_report.summary())
    print(f"Resolved: {result.collisions_resolved}")
    print(f"Promoted: {[c.name for c in result.promoted]}")
    for c in result.promoted:
        print(f"  {c.name}: {c.expression}")
        print(f"    {c.rationale}")
        print(f"    scores={c.score_breakdown}")


if __name__ == "__main__":
    main()
