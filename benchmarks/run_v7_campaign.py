#!/usr/bin/env python3
"""Run TITAN V7 protected-state campaign + new live LLM transfer."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v7.campaign import run_v7_campaign


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-locked", type=int, default=100)
    p.add_argument("--n-benign", type=int, default=1200)
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--skip-live", action="store_true")
    p.add_argument("--api-key", type=str, default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    api_key = args.api_key or os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
    if not api_key and not args.skip_live:
        print("ERROR: XAI_API_KEY required", file=sys.stderr)
        sys.exit(2)
    result = run_v7_campaign(
        api_key=api_key or "",
        seed=args.seed,
        verbose=not args.quiet,
        out_dir=Path(__file__).resolve().parent,
        n_locked_live=args.n_locked,
        n_benign=args.n_benign,
        max_workers=args.workers,
        skip_live=args.skip_live,
    )
    s = result["summary"]
    print("\n=== V7 HEADLINE ===")
    print(f"  Live n={s.get('n_live_sessions')} meaningful={s.get('n_meaningful')} ASR={s.get('attack_success_rate')}")
    print(f"  AUROC={s.get('external_auroc')}  R@5={s.get('external_r_fpr05')}  BH@5={s.get('bh_at_fpr5')}")
    print(f"  mass={s.get('score_mass_frac')}  FBR={s.get('false_block_rate')}  ABP={s.get('auto_block_precision')}")
    print(f"  Δ vs V6 frozen: AUROC {s.get('delta_auroc_vs_v6'):+.3f}  R@5 {s.get('delta_r05_vs_v6'):+.3f}  BH {s.get('delta_bh_vs_v6'):+.3f}")
    print(f"  research_gates={s.get('research_gates_met')}  production={s.get('production_approved')}")
    print(f"  zeros={s.get('live_zero_families')}")


if __name__ == "__main__":
    main()
