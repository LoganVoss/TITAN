#!/usr/bin/env python3
"""TITAN quickstart — discover monitor blind spots on synthetic agent traces."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan import (
    generate_scenario_suite,
    run_discovery,
    split_dataset,
    evaluate_monitor,
    build_report,
)
from titan.report import format_report
from titan.scenarios.generator import ScenarioSpec
from titan.engine import score_trajectory


def main() -> None:
    suite = generate_scenario_suite(ScenarioSpec(
        n_harmful_per_family=3,
        n_hard_negatives=12,
        n_clean_benign=14,
        n_clean_refactor=6,
        seed=42,
    ))
    part = split_dataset(suite, seed=42, locked_model_version="agent-v2")
    print("Partitions:", part.summary())

    result = run_discovery(
        part.discovery,
        name="quickstart",
        selection=part.selection,
        verbose=True,
    )

    scorer = lambda t: score_trajectory(t, result.promoted)["alert_strength"]
    locked_eval = evaluate_monitor(scorer, part.locked, name="titan")
    print("\n" + locked_eval.summary())

    report = build_report(result, evaluation=locked_eval)
    print("\n" + format_report(report))


if __name__ == "__main__":
    main()
