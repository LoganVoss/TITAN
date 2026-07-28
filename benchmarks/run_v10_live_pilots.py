#!/usr/bin/env python3
"""Run real HTTP plumbing + adversarial pilots (OpenAI + xAI).

Requires OPENAI_API_KEY and XAI_API_KEY (or GROK_API_KEY) in the environment.
Never commits keys.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v10.harness import run_adversarial_pilot, run_plumbing_pilot
from titan.v10.http_providers import build_live_providers


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY missing", file=sys.stderr)
        sys.exit(2)
    if not (
        os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
    ):
        print("XAI_API_KEY / GROK_API_KEY missing", file=sys.stderr)
        sys.exit(2)

    out = Path(__file__).resolve().parent
    providers = build_live_providers()
    print("LIVE providers", providers[0].requested_model, providers[1].requested_model)

    print("=== LIVE PLUMBING PILOT ===", flush=True)
    plumbing = run_plumbing_pilot(
        out_dir=out,
        seed=11,
        verbose=True,
        providers=providers,
    )
    # rename artifacts
    (out / "v10_live_plumbing_pilot.json").write_text(
        json.dumps(plumbing, indent=2, default=str)
    )
    print("plumbing all_passed", plumbing["gates"]["all_passed"], plumbing["gates"])

    print("=== LIVE ADVERSARIAL PILOT ===", flush=True)
    # Rebuild providers for clean rate-limit state
    providers = build_live_providers()
    adversarial = run_adversarial_pilot(
        out_dir=out,
        seed=12,
        verbose=True,
        providers=providers,
    )
    (out / "v10_live_adversarial_pilot.json").write_text(
        json.dumps(adversarial, indent=2, default=str)
    )
    print("adversarial all_passed", adversarial["gates"]["all_passed"])
    for k, v in adversarial["gates"].items():
        print(f"  {k}: {v}")

    summary = {
        "plumbing": plumbing["gates"],
        "adversarial": adversarial["gates"],
        "live_ready_for_freeze": bool(
            plumbing["gates"]["all_passed"] and adversarial["gates"]["all_passed"]
        ),
        "provider_mode": "live_http",
        "models": {
            "openai": providers[0].requested_model,
            "xai": providers[1].requested_model,
        },
    }
    (out / "v10_live_pilot_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if not summary["live_ready_for_freeze"]:
        sys.exit(4)


if __name__ == "__main__":
    main()
