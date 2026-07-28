#!/usr/bin/env python3
"""Run full TITAN V4 campaign (Steps 1–22)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v4.control_plane import run_v4_campaign


def main() -> None:
    api_key = (
        os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or os.environ.get("TITAN_XAI_KEY")
    )
    result = run_v4_campaign(
        seed=42,
        api_key=api_key,
        verbose=True,
        out_dir=Path(__file__).resolve().parent,
    )
    print("\n=== BREAKTHROUGHS ===")
    for b in result.get("breakthroughs", []):
        print(" •", b)
    if result.get("failures"):
        print("\n=== FAILURES / GAPS ===")
        for f in result["failures"]:
            print(" •", f)
    print("\n=== MILESTONES ===")
    for k, v in sorted(result.get("milestones", {}).items()):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
