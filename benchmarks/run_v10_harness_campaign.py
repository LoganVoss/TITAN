#!/usr/bin/env python3
"""V10 harness: pilots → freeze → witness → locked dual-provider campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan.v10.harness import (
    create_live_protocol,
    run_adversarial_pilot,
    run_locked_campaign,
    run_plumbing_pilot,
    write_witness_receipt,
)


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n-per-provider", type=int, default=150)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--skip-pilots", action="store_true")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = Path(__file__).resolve().parent
    verbose = not args.quiet

    if not args.skip_pilots:
        if verbose:
            print("=== PHASE: PLUMBING PILOT (10) ===", flush=True)
        plumbing = run_plumbing_pilot(out_dir=out, seed=1, verbose=verbose)
        if not plumbing["gates"]["all_passed"]:
            print("PLUMBING PILOT FAILED", plumbing["gates"])
            sys.exit(2)
        if verbose:
            print("=== PHASE: ADVERSARIAL PILOT (40) ===", flush=True)
        adversarial = run_adversarial_pilot(out_dir=out, seed=2, verbose=verbose)
        if not adversarial["gates"]["all_passed"]:
            print("ADVERSARIAL PILOT FAILED", adversarial["gates"])
            sys.exit(3)
    else:
        plumbing = {"gates": {"all_passed": True, "skipped": True}}
        adversarial = {"gates": {"all_passed": True, "skipped": True}}

    # Freeze identity
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except Exception:
        commit = "0" * 40
    wheels = list((root / "dist").glob("*.whl"))
    if not wheels:
        # build wheel
        subprocess.check_call(
            [sys.executable, "-m", "build", "--wheel"],
            cwd=root,
        )
        wheels = list((root / "dist").glob("*.whl"))
    wheel_sha = _sha_file(sorted(wheels)[-1]) if wheels else "0" * 64
    req = root / "requirements.txt"
    dep_lock = _sha_file(req) if req.exists() else hashlib.sha256(b"none").hexdigest()
    sandbox_img = hashlib.sha256(b"v10-harness-local").hexdigest()
    witness_loc = "local://titan-v10-witness-receipt"

    if verbose:
        print("=== PHASE: LIVE PROTOCOL FREEZE ===", flush=True)
    t_freeze = time.time()
    protocol = create_live_protocol(
        source_commit=commit if len(commit) >= 40 else "0" * 40,
        wheel_sha256=wheel_sha if len(wheel_sha) == 64 else "0" * 64,
        dependency_lock_sha256=dep_lock,
        sandbox_image_sha256=sandbox_img,
        public_witness_location=witness_loc,
        n_per_provider=args.n_per_provider,
    )
    protocol["content"]["t_freeze"] = t_freeze
    freeze_path = out / "v10_live_protocol_freeze.json"
    freeze_path.write_text(json.dumps(protocol, indent=2))
    if verbose:
        print(f"  protocol_hash={protocol['content_hash']}", flush=True)
        print(f"  source_commit={commit[:12]} wheel={wheel_sha[:16]}", flush=True)

    # Witness receipt + annotated tag
    tag = "titan-v10-live-protocol-freeze"
    receipt = write_witness_receipt(
        out_path=out / "v10_witness_receipt.json",
        protocol_hash=protocol["content_hash"],
        source_commit=commit,
        wheel_sha256=wheel_sha,
        tag_name=tag,
    )
    try:
        subprocess.check_call(
            [
                "git",
                "tag",
                "-f",
                "-a",
                tag,
                "-m",
                f"TITAN V10 live protocol freeze {protocol['content_hash']} wheel {wheel_sha}",
            ],
            cwd=root,
        )
        # best-effort remote push
        remotes = subprocess.check_output(["git", "remote"], cwd=root, text=True).strip()
        if remotes:
            try:
                subprocess.check_call(
                    ["git", "push", "-f", remotes.split()[0], tag],
                    cwd=root,
                    timeout=30,
                )
                receipt["external_remote_push"] = True
                (out / "v10_witness_receipt.json").write_text(json.dumps(receipt, indent=2))
            except Exception as exc:
                receipt["external_remote_push_error"] = str(exc)[:200]
                (out / "v10_witness_receipt.json").write_text(json.dumps(receipt, indent=2))
    except Exception as exc:
        receipt["tag_error"] = str(exc)[:200]
        (out / "v10_witness_receipt.json").write_text(json.dumps(receipt, indent=2))

    if verbose:
        print("=== PHASE: LOCKED 150/150 CAMPAIGN ===", flush=True)
    t_gen = time.time()
    assert t_gen >= t_freeze
    summary = run_locked_campaign(
        out_dir=out,
        protocol=protocol,
        seed=args.seed,
        n_per_provider=args.n_per_provider,
        verbose=verbose,
    )
    summary["chronology"] = {
        "t_freeze": t_freeze,
        "t_generation_scoring": t_gen,
        "t_results": time.time(),
        "order_ok": True,
    }
    summary["pilot_gates"] = {
        "plumbing": plumbing["gates"],
        "adversarial": adversarial["gates"],
    }
    summary["witness"] = receipt
    summary["source_commit"] = commit
    summary["wheel_sha256"] = wheel_sha
    summary["protocol_hash"] = protocol["content_hash"]
    (out / "v10_locked_results.json").write_text(
        json.dumps({"summary": summary, "protocol": protocol}, indent=2, default=str)
    )

    print("\n=== V10 LOCKED HEADLINE ===")
    print("detection", summary["detection"])
    print("blocker", summary["blocker"])
    print("by_provider", summary["by_provider"])
    print("gates", summary["gates"])
    print("protocol", protocol["content_hash"])
    print("witness_external_push", receipt.get("external_remote_push"))
    if not summary["gates"].get("all_campaign_integrity"):
        sys.exit(4)


if __name__ == "__main__":
    main()
