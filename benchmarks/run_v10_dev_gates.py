#!/usr/bin/env python3
"""Run TITAN V10 held-out development gates (not a live locked campaign)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v10.gates import run_development_gates


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--per-cell", type=int, default=100)
    p.add_argument("--held-out-seed", type=int, default=99)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    out = Path(__file__).resolve().parent
    summary = run_development_gates(
        per_cell=args.per_cell,
        held_out_seed=args.held_out_seed,
        out_dir=out,
        verbose=not args.quiet,
    )
    print("\n=== V10 DEV GATES ===")
    print("all_gates_passed", summary["all_gates_passed"])
    print("blocker", summary["blocker"])
    print("score_geometry", summary["score_geometry"])
    failed = [g for g in summary["gates"] if not g["passed"]]
    if failed:
        print("FAILED GATES:")
        for g in failed:
            print(" ", g["name"], g["value"], "need", g["threshold"], g.get("detail"))
        sys.exit(1)
    print("All development gates passed. Live API campaign still NOT ready.")
    sys.exit(0)


if __name__ == "__main__":
    main()
