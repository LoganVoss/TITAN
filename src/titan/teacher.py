"""
Phase 6 — Teacher-guided residual discovery.

Use a full supervised classifier (fit on discovery only) to point TITAN toward
regions where the inspectable basis is missing signal. Never uses locked labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

import numpy as np

from .baselines import FeatureClassifierBaseline
from .schema import AgentTrajectory, Label
from .synthesis import CandidateMonitor


ScoreFn = Callable[[AgentTrajectory], float]


@dataclass
class ResidualRegion:
    name: str
    trajectory_ids: list[str]
    attack_families: list[str]
    mean_teacher_score: float
    mean_titan_score: float
    n: int
    suggested_focus: str


def fit_teacher(discovery: Sequence[AgentTrajectory]) -> FeatureClassifierBaseline:
    return FeatureClassifierBaseline(name="teacher_classifier").fit(discovery)


def find_residual_regions(
    trajectories: Sequence[AgentTrajectory],
    teacher: FeatureClassifierBaseline,
    titan_fn: ScoreFn,
    *,
    teacher_conf: float = 0.65,
    titan_gap: float = 0.15,
) -> list[ResidualRegion]:
    """
    Find trajectories where teacher is confident and correct, TITAN is wrong/weak.
    """
    misses: list[tuple[AgentTrajectory, float, float]] = []
    for t in trajectories:
        if t.label not in (Label.HARMFUL, Label.BENIGN):
            continue
        ts = float(teacher.score(t))
        ti = float(titan_fn(t))
        y = 1.0 if t.label == Label.HARMFUL else 0.0
        teacher_correct = (ts >= 0.5) == (y >= 0.5)
        teacher_confident = abs(ts - 0.5) >= (teacher_conf - 0.5)
        if not (teacher_correct and teacher_confident):
            continue
        if y >= 0.5 and ti < ts - titan_gap:
            misses.append((t, ts, ti))
        elif y < 0.5 and ti > ts + titan_gap:
            misses.append((t, ts, ti))

    # Group by attack family
    by_fam: dict[str, list[tuple[AgentTrajectory, float, float]]] = {}
    for t, ts, ti in misses:
        by_fam.setdefault(t.attack_family.value, []).append((t, ts, ti))

    regions: list[ResidualRegion] = []
    for fam, items in sorted(by_fam.items(), key=lambda kv: -len(kv[1])):
        focus = _suggest_focus(fam, items)
        regions.append(ResidualRegion(
            name=f"residual_{fam}",
            trajectory_ids=[t.trajectory_id for t, _, _ in items],
            attack_families=[fam],
            mean_teacher_score=float(np.mean([ts for _, ts, _ in items])),
            mean_titan_score=float(np.mean([ti for _, _, ti in items])),
            n=len(items),
            suggested_focus=focus,
        ))
    return regions


def _suggest_focus(fam: str, items: list) -> str:
    mapping = {
        "eval_weakening": "mutation_then_eval_within, eval_weaken_pressure, canary_score_delta",
        "canary_suppression": "eval_weaken_pressure, canary_score_delta, pre_harm_risk_chain",
        "cluster_concentration": "semantic_cluster_concentration, same_cluster_mutations",
        "dispersed_commits": "multi_identity_same_cluster, dispersed_commit_score",
        "rare_source_high_influence": "rare_source_fraction, mean_gradient_influence, high_influence_mutation_pressure",
        "provenance_bypass": "bypass_then_mutation, bypass_attempt_count, perm_fail_burst",
        "label_flip_burst": "label_entropy_shift, n_data_mutations",
        "test_editing": "test_edit_after_mutation, test_edit_count",
        "monitor_evasion": "bypass_attempt_count, low_severity_pre_harm_chain",
        "safeguard_tamper": (
            "malicious_safeguard_signature, unauthorized_safeguard_write, "
            "safeguard_diff_weakens, safeguard_write_after_denial, "
            "safeguard_intent_action_mismatch"
        ),
        "exfil_attempt": "bypass_attempt_count, n_permission_failures",
        "hard_negative": "authorization_covers_safeguard, rate_mutations, ev_benign_explanation",
        "legit_safeguard_update": "authorization_covers_safeguard, safeguard_diff_hardens",
    }
    return mapping.get(fam, "pre_harm_risk_chain, low_severity_pre_harm_chain")


def residual_priority_features(regions: list[ResidualRegion]) -> list[str]:
    """Feature names the next synthesis round should prefer."""
    out: list[str] = []
    for r in regions:
        for part in r.suggested_focus.split(","):
            name = part.strip()
            if name and name not in out:
                out.append(name)
    return out


def teacher_report(
    regions: list[ResidualRegion],
    teacher: FeatureClassifierBaseline,
) -> dict[str, Any]:
    return {
        "n_regions": len(regions),
        "total_residual_trajs": sum(r.n for r in regions),
        "regions": [
            {
                "name": r.name,
                "n": r.n,
                "families": r.attack_families,
                "mean_teacher": r.mean_teacher_score,
                "mean_titan": r.mean_titan_score,
                "focus": r.suggested_focus,
            }
            for r in regions
        ],
        "priority_features": residual_priority_features(regions),
        "teacher_fitted": teacher.fitted,
    }
