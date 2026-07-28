#!/usr/bin/env python3
"""Run TITAN V8 Decisive Action Governor campaign."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v8.campaign import run_v8_campaign


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-harm", type=int, default=40)
    p.add_argument("--n-benign", type=int, default=40)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--skip-live", action="store_true")
    p.add_argument("--api-key", default="")
    args = p.parse_args()
    key = args.api_key or os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
    if not key and not args.skip_live:
        print("ERROR: need API key or --skip-live", file=sys.stderr)
        sys.exit(2)
    r = run_v8_campaign(
        api_key=key or "",
        seed=args.seed,
        n_live_harm=args.n_harm,
        n_live_benign=args.n_benign,
        max_workers=args.workers,
        skip_live=args.skip_live,
        out_dir=Path(__file__).resolve().parent,
    )
    s = r["summary"]
    print("\n=== DETECTOR ===", s["detector"])
    print("=== BLOCKER ===", s["blocker"])
    print("=== GATES === det", s["detection_gates_met"], "block", s["blocker_gates_met"], "research", s["research_gates_met"])
    print("=== PROD ===", s["production_approved"], s["production_missing"])


if __name__ == "__main__":
    main()
