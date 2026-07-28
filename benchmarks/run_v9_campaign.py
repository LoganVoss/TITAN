#!/usr/bin/env python3
"""Run TITAN V9 locked in-path campaign (sandbox adversary lab)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v9.campaign import run_v9_locked_campaign


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--n-harmful", type=int, default=300)
    p.add_argument("--n-benign", type=int, default=300)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--source-commit", default="")
    p.add_argument("--wheel-sha256", default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    root = Path(__file__).resolve().parents[1]
    # Best-effort git commit
    commit = args.source_commit
    if not commit:
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL
            ).strip()
        except Exception:
            commit = "0" * 40

    wheel_sha = args.wheel_sha256
    if not wheel_sha:
        wheels = list((root / "dist").glob("*.whl")) if (root / "dist").exists() else []
        if wheels:
            wheel_sha = _sha256_file(sorted(wheels)[-1])
        else:
            wheel_sha = "0" * 64

    dep_lock = "0" * 64
    req = root / "requirements.txt"
    if req.exists():
        dep_lock = _sha256_file(req)

    result = run_v9_locked_campaign(
        out_dir=Path(__file__).resolve().parent,
        n_harmful=args.n_harmful,
        n_benign=args.n_benign,
        seed=args.seed,
        verbose=not args.quiet,
        source_commit=commit if len(commit) >= 40 else "0" * 40,
        wheel_sha256=wheel_sha if len(wheel_sha) == 64 else "0" * 64,
        dependency_lock_sha256=dep_lock,
        sandbox_image_sha256=hashlib.sha256(b"sandbox-v9-local").hexdigest(),
        public_witness_location="local://titan-v9-protocol-freeze-pending-external-witness",
    )
    s = result["summary"]
    print("\n=== V9 HEADLINE ===")
    print("population A", s["population_A_detection"])
    print("blocker A", {k: s["blocker_population_A"][k] for k in (
        "auto_block_recall", "auto_block_precision_display", "false_block_rate",
        "n_auto_block", "silent_harmful_allow_rate", "block_plus_escrow_coverage",
    )})
    print("gates", s["gates"])
    print("missing", s["production_missing"])
    print("protocol", s["protocol_hash"])


if __name__ == "__main__":
    main()
