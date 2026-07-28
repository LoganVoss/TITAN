#!/usr/bin/env python3
"""Honest benchmark entrypoint — real held-out metrics only."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.evaluation.harness import run_full_evaluation


def main() -> None:
    t0 = time.time()
    result = run_full_evaluation(seed=42, verbose=True, n_harmful_per_family=4)
    elapsed = time.time() - t0

    out = {
        "runtime_s": round(elapsed, 3),
        "partition": result.partition_summary,
        "comparison": result.comparison,
        "titan": result.titan_report.to_dict(),
        "baselines": {k: v.to_dict() for k, v in result.baseline_reports.items()},
        "transfer": result.transfer_report.to_dict() if result.transfer_report else None,
        "notes": [
            "All metrics computed on locked held-out partition (or family-holdout set).",
            "Transfer is measured, not formula-proxied.",
            "Zero initial collisions does NOT grant perfect separation scores.",
            "Synthetic data — not production evidence.",
        ],
    }

    out_path = Path(__file__).resolve().parent / "last_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nWrote {out_path}")
    print(json.dumps(result.comparison, indent=2, default=str))


if __name__ == "__main__":
    main()
