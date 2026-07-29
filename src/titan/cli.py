"""Command-line interface for TITAN."""

from __future__ import annotations

import argparse
import json
import sys
import time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="titan",
        description="TITAN — monitor blind-spot discovery for AI agent safety",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help="Run end-to-end discovery + evaluation demo")
    p_demo.add_argument("--seed", type=int, default=42)
    p_demo.add_argument("--quiet", action="store_true")

    p_suite = sub.add_parser("suite", help="Generate scenario suite summary")
    p_suite.add_argument("--seed", type=int, default=42)
    p_suite.add_argument("--json", action="store_true")

    p_bench = sub.add_parser("benchmark", help="Run full benchmark harness")
    p_bench.add_argument("--seed", type=int, default=42)

    p_v9_inspect = sub.add_parser(
        "v9-inspect",
        help="Label-blind shadow inspection of action proposals in a trajectory JSON",
    )
    p_v9_inspect.add_argument("trajectory", help="Path to one AgentTrajectory JSON")

    p_v9_protocol = sub.add_parser(
        "v9-verify-protocol",
        help="Verify a canonical V9 protocol and its declared content hash",
    )
    p_v9_protocol.add_argument("protocol", help="Path to the V9 protocol JSON")

    p_v9_manifest = sub.add_parser(
        "v9-verify-manifest",
        help="Verify a sealed V9 artifact manifest against a root directory",
    )
    p_v9_manifest.add_argument("manifest", help="Path to the manifest JSON")
    p_v9_manifest.add_argument("--root", required=True, help="Sealed artifact root")

    args = parser.parse_args(argv)

    if args.cmd == "demo":
        return _cmd_demo(args)
    if args.cmd == "suite":
        return _cmd_suite(args)
    if args.cmd == "benchmark":
        return _cmd_benchmark(args)
    if args.cmd == "v9-inspect":
        return _cmd_v9_inspect(args)
    if args.cmd == "v9-verify-protocol":
        return _cmd_v9_verify_protocol(args)
    if args.cmd == "v9-verify-manifest":
        return _cmd_v9_verify_manifest(args)
    return 1


def _cmd_demo(args: argparse.Namespace) -> int:
    from .evaluation.harness import run_full_evaluation
    from .report import build_report, format_report

    result = run_full_evaluation(seed=args.seed, verbose=not args.quiet)
    report = build_report(result.discovery, evaluation=result.titan_report)
    print(format_report(report))
    return 0


def _cmd_suite(args: argparse.Namespace) -> int:
    from .scenarios.generator import ScenarioSpec, generate_scenario_suite, suite_summary

    suite = generate_scenario_suite(ScenarioSpec(seed=args.seed))
    summary = suite_summary(suite)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Generated {summary['n']} trajectories")
        print(f"  harmful={summary['harmful']} benign={summary['benign']}")
        print(f"  models={summary['model_versions']} envs={summary['environments']}")
        print("  families:")
        for k, v in sorted(summary["families"].items(), key=lambda kv: -kv[1]):
            print(f"    {k:30s} {v}")
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from .evaluation.harness import run_full_evaluation

    result = run_full_evaluation(seed=args.seed, verbose=True)
    print("\nJSON comparison:")
    print(json.dumps(result.comparison, indent=2, default=str))
    return 0


def _cmd_v9_inspect(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .schema import AgentTrajectory
    from .v9.action import ObservableTrajectory, extract_action_proposals
    from .v9.governor import V9Governor
    from .v9.integrity import ControlPlaneIntegrityPolicy, IntegritySignals

    try:
        raw = json.loads(Path(args.trajectory).read_text(encoding="utf-8"))
        trajectory = ObservableTrajectory.from_trajectory(
            AgentTrajectory.from_dict(raw)
        )
        now_ms = time.time_ns() // 1_000_000
        integrity_policy = ControlPlaneIntegrityPolicy()
        integrity = integrity_policy.assess(
            IntegritySignals(
                observed_at_ms=now_ms,
                event_loss_count=0,
                max_event_delay_ms=0,
                logger_healthy=True,
                policy_healthy=True,
                registry_healthy=True,
                verifier_healthy=True,
                token_verifier_healthy=True,
            )
        )
        governor = V9Governor(integrity_policy=integrity_policy)
        proposals = extract_action_proposals(trajectory)
        decisions = [
            governor.evaluate(trajectory, proposal, integrity=integrity)
            for proposal in proposals
        ]
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "shadow_only",
                "execution_authority": False,
                "trajectory_id": trajectory.trajectory_id,
                "observable_hash": trajectory.observable_hash(),
                "action_count": len(decisions),
                "actions": [
                    {
                        "action_id": result.decision.action_id,
                        "action_type": result.decision.action_type,
                        "proposal_sequence": proposal.proposal_sequence,
                        "disposition": result.decision.disposition.value,
                        "risk_rank_score": result.decision.risk_rank_score,
                        "blockability_rank_score": (
                            result.decision.blockability_rank_score
                        ),
                        "missing_evidence": result.decision.missing_evidence,
                        "abstention_causes": result.decision.abstention_causes,
                        "reasons": result.decision.reasons,
                        "evidence_hash": result.evidence.evidence_hash,
                    }
                    for proposal, result in zip(proposals, decisions)
                ],
            },
            indent=2,
        )
    )
    return 0


def _cmd_v9_verify_protocol(args: argparse.Namespace) -> int:
    from .v9.protocol import load_protocol

    try:
        protocol = load_protocol(args.protocol)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "ok": protocol.verify(),
                "schema": protocol.schema,
                "content_hash": protocol.content_hash,
            },
            indent=2,
        )
    )
    return 0 if protocol.verify() else 2


def _cmd_v9_verify_manifest(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .v9.manifest import SealedManifest

    try:
        artifact = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        manifest = SealedManifest.from_dict(artifact)
        verification = manifest.verify(args.root)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(verification.to_dict(), indent=2))
    return 0 if verification.ok else 2


if __name__ == "__main__":
    sys.exit(main())
