#!/usr/bin/env python3
"""Run full TITAN V5 campaign (Phases 0–16 — action governor)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v5.campaign import run_v5_campaign


def main() -> None:
    p = argparse.ArgumentParser(description="TITAN V5 action-governor campaign")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-harmful", type=int, default=100)
    p.add_argument("--n-benign", type=int, default=1000)
    p.add_argument("--llm-strategies", action="store_true",
                   help="Optional: 1 LLM call for strategy seeds (default off)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    api_key = (
        os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or os.environ.get("TITAN_XAI_KEY")
    )
    result = run_v5_campaign(
        seed=args.seed,
        api_key=api_key,
        verbose=not args.quiet,
        out_dir=Path(__file__).resolve().parent,
        n_harmful=args.n_harmful,
        n_benign=args.n_benign,
        use_llm_strategies=args.llm_strategies,
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
    s = result.get("summary", {})
    print("\n=== HEADLINE ===")
    print(f"  AUROC={s.get('external_auroc')}  R@FPR5%={s.get('external_r_fpr05')}")
    print(f"  BH@FPR5%={s.get('bh_at_fpr5')}  FBR={s.get('false_block_rate')}")
    print(f"  Reviewer agreement={s.get('reviewer_agreement_exact')}")
    print(f"  Production approved={s.get('production_approved')}  missing={s.get('production_missing')}")


if __name__ == "__main__":
    main()
