#!/usr/bin/env python3
"""Run TITAN V6 live multi-turn LLM adversary campaign."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v6.campaign import run_v6_campaign


def main() -> None:
    p = argparse.ArgumentParser(description="TITAN V6 live LLM campaign")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-locked", type=int, default=100)
    p.add_argument("--n-plumbing", type=int, default=10)
    p.add_argument("--n-pilot", type=int, default=20)
    p.add_argument("--n-benign", type=int, default=800)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--skip-pilots", action="store_true")
    p.add_argument("--api-key", type=str, default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    api_key = (
        args.api_key
        or os.environ.get("XAI_API_KEY")
        or os.environ.get("GROK_API_KEY")
        or os.environ.get("TITAN_XAI_KEY")
    )
    if not api_key:
        print("ERROR: API key required (XAI_API_KEY or --api-key)", file=sys.stderr)
        sys.exit(2)

    result = run_v6_campaign(
        api_key=api_key,
        seed=args.seed,
        verbose=not args.quiet,
        out_dir=Path(__file__).resolve().parent,
        n_locked=args.n_locked,
        n_plumbing=args.n_plumbing,
        n_pilot=args.n_pilot,
        n_benign_locked=args.n_benign,
        max_workers=args.workers,
        skip_pilots=args.skip_pilots,
    )
    print("\n=== BREAKTHROUGHS ===")
    for b in result.get("breakthroughs", []):
        print(" •", b)
    if result.get("failures"):
        print("\n=== FAILURES ===")
        for f in result["failures"]:
            print(" •", f)
    s = result.get("summary", {})
    print("\n=== HEADLINE ===")
    print(f"  Live sessions: {s.get('n_locked_sessions')} meaningful={s.get('n_meaningful_harmful')}")
    print(f"  ASR={s.get('attack_success_rate')}  AUROC={s.get('external_auroc')}")
    print(f"  R@FPR5%={s.get('external_r_fpr05')}  BH@FPR5%={s.get('bh_at_fpr5')}")
    print(f"  FBR={s.get('false_block_rate')}  ABP={s.get('auto_block_precision')}")
    print(f"  Misses@FPR5={s.get('n_misses_at_fpr5')}  tokens≈{s.get('total_tokens_est')}")
    print(f"  Production={s.get('production_approved')} missing={s.get('production_missing')}")


if __name__ == "__main__":
    main()
