"""Human-facing reports for discovery, evaluation, and operator review."""

from __future__ import annotations

from typing import Any

from .collisions import CollisionReport, format_collision_detail
from .counterfactual import suggest_counterfactuals
from .engine import DiscoveryResult
from .evaluation.metrics import EvaluationReport
from .schema import AgentTrajectory
from .synthesis import CandidateMonitor


def build_report(
    discovery: DiscoveryResult,
    *,
    evaluation: EvaluationReport | None = None,
    trajectories: list[AgentTrajectory] | None = None,
) -> dict[str, Any]:
    """Structured decision-support report."""
    headline = _headline(discovery, evaluation)
    return {
        "headline": headline,
        "discovery": discovery.to_dict(),
        "evaluation": evaluation.to_dict() if evaluation else None,
        "promoted_monitors": [_monitor_card(c) for c in discovery.promoted],
        "top_collisions": discovery.collision_details[:5],
        "caveats": _caveats(discovery, evaluation),
        "operator_actions": _actions(discovery, evaluation),
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        "=" * 72,
        "TITAN — Monitor Blind-Spot Discovery Report",
        "=" * 72,
        report["headline"],
        "",
        "── Discovery ──",
        f"  Initial collisions : {report['discovery']['initial_collisions']}",
        f"  Final collisions   : {report['discovery']['final_collisions']}",
        f"  Resolved           : {report['discovery']['collisions_resolved']}",
        f"  Pressure reduction : {report['discovery']['pressure_reduction']:.1%}",
        f"  Promoted monitors  : {len(report['promoted_monitors'])}",
        "",
    ]
    if report["promoted_monitors"]:
        lines.append("── Promoted Candidate Monitors ──")
        for m in report["promoted_monitors"]:
            lines.append(f"  • {m['name']}")
            lines.append(f"      expr: {m.get('expression')}")
            lines.append(
                f"      sep={m['separation']:.2f} stab={m['stability']:.2f} "
                f"xfer={m['transfer']:.2f} composite={m['composite']:.3f}"
            )
            lines.append(f"      why: {m.get('rationale', '')}")
        lines.append("")

    if report.get("evaluation"):
        ev = report["evaluation"]
        lines.append("── Evaluation (held-out) ──")
        lines.append(
            f"  AUROC={ev['auroc']:.3f}  AP={ev['average_precision']:.3f}  "
            f"ECE={ev['calibration_error']:.3f}"
        )
        lines.append(f"  Recall@FPR: {ev['recall_at_fpr']}")
        lines.append(f"  Recall@budget: {ev['recall_at_budget']}")
        if ev.get("per_family_recall"):
            lines.append(f"  Per-family recall@FPR5%: {ev['per_family_recall']}")
        lines.append("")

    if report.get("top_collisions"):
        lines.append("── Top Blind Spots (collisions) ──")
        for detail in report["top_collisions"][:3]:
            for ln in detail.splitlines():
                lines.append(f"  {ln}")
            lines.append("")

    lines.append("── Caveats ──")
    for c in report["caveats"]:
        lines.append(f"  • {c}")
    lines.append("")
    lines.append("── Suggested Operator Actions ──")
    for a in report["operator_actions"]:
        lines.append(f"  → {a}")
    lines.append("=" * 72)
    return "\n".join(lines)


def _monitor_card(c: CandidateMonitor) -> dict[str, Any]:
    b = c.score_breakdown
    return {
        "name": c.name,
        "expression": c.expression,
        "rationale": c.rationale,
        "separation": b.get("separation", 0.0),
        "stability": b.get("stability", 0.0),
        "transfer": b.get("transfer", 0.0),
        "composite": b.get("composite", 0.0),
        "complexity": c.complexity,
        "feature_deps": c.provenance.feature_deps,
        "attack_families": c.provenance.attack_families_seen,
    }


def _headline(discovery: DiscoveryResult, evaluation: EvaluationReport | None) -> str:
    if discovery.initial_collisions == 0:
        base = "Base monitors already separate harmful from benign on the discovery pool."
    elif discovery.collisions_resolved > 0:
        base = (
            f"Discovered {len(discovery.promoted)} candidate monitors that reduce "
            f"cross-regime collisions from {discovery.initial_collisions} to "
            f"{discovery.final_collisions} (pressure ↓ {discovery.pressure_reduction:.0%})."
        )
    else:
        base = (
            f"Found {discovery.initial_collisions} blind spots; synthesis promoted "
            f"{len(discovery.promoted)} candidates pending held-out validation."
        )
    if evaluation:
        r = evaluation.recall_at_fpr.get("0.05")
        if r is not None:
            base += f" Held-out recall@5% FPR = {r:.1%} (AUROC {evaluation.auroc:.3f})."
    return base


def _caveats(discovery: DiscoveryResult, evaluation: EvaluationReport | None) -> list[str]:
    caveats = [
        "alert_strength is a heuristic score, not a calibrated probability.",
        "baseline_support reflects sample size of clean baseline windows, not a statistical CI.",
        "Counterfactuals are feature sensitivity analyses, not causal interventions.",
        "Synthetic scenarios are research instruments — production claims require real traces.",
    ]
    if evaluation and evaluation.notes:
        caveats.extend(evaluation.notes)
    if discovery.initial_collisions == 0:
        caveats.append("Zero discovery collisions: synthesis was not stress-tested on this pool.")
    return caveats


def _actions(discovery: DiscoveryResult, evaluation: EvaluationReport | None) -> list[str]:
    actions = [
        "Register promoted candidates in shadow mode only.",
        "Calibrate thresholds on clean deployment-like traffic before any blocking.",
        "Red-team with monitor-aware attackers and measure recall@fixed review budget.",
    ]
    if discovery.promoted:
        actions.append(
            f"Inspect provenance for: {', '.join(c.name for c in discovery.promoted[:4])}."
        )
    if evaluation and evaluation.recall_at_fpr.get("0.05", 0) < 0.5:
        actions.append("Recall@5% FPR is low — expand scenario diversity or feature families.")
    return actions


def format_trajectory_review(
    trajectory: AgentTrajectory,
    candidates: list[CandidateMonitor],
) -> str:
    """Operator review card for a single session."""
    from .engine import score_trajectory

    scores = score_trajectory(trajectory, candidates)
    lines = [
        f"Trajectory {trajectory.trajectory_id}",
        f"  label={trajectory.label.value} family={trajectory.attack_family.value}",
        f"  model={trajectory.model_version} env={trajectory.environment}",
        f"  existing monitors: {trajectory.existing_monitor_scores}",
        f"  TITAN scores: {scores}",
        f"  events={len(trajectory.events)} "
        f"mutations={len(trajectory.data_mutations())} "
        f"perm_fail={len(trajectory.permission_failures())}",
    ]
    if candidates:
        scorer = lambda t: score_trajectory(t, candidates)["alert_strength"]
        cfs = suggest_counterfactuals(trajectory, scorer, top_k=3)
        if cfs:
            lines.append("  Counterfactual sensitivities (not causal):")
            for cf in cfs:
                lines.append(
                    f"    · ↓ {cf.feature} (sens={cf.estimated_sensitivity:.3f}): {cf.plain_english}"
                )
    return "\n".join(lines)
