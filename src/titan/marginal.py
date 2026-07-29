"""
Phase 2 — Marginal held-out utility for candidate selection.

Scores candidates by how much they improve the *current system* on selection
metrics (AUROC, AP, recall@FPR), not only standalone separation.
"""

from __future__ import annotations

from typing import Callable, Sequence

import numpy as np

from .evaluation.metrics import auroc, average_precision, recall_at_budget, recall_at_fpr
from .schema import AgentTrajectory, Label
from .synthesis import CandidateMonitor


ScoreFn = Callable[[AgentTrajectory], float]


def _labels_scores(
    trajectories: Sequence[AgentTrajectory],
    score_fn: ScoreFn,
) -> tuple[np.ndarray, np.ndarray]:
    scores, labels = [], []
    for t in trajectories:
        if t.label not in (Label.HARMFUL, Label.BENIGN):
            continue
        try:
            scores.append(float(score_fn(t)))
        except Exception:
            scores.append(0.0)
        labels.append(1.0 if t.label == Label.HARMFUL else 0.0)
    return np.asarray(scores, dtype=float), np.asarray(labels, dtype=float)


def system_metrics(score_fn: ScoreFn, trajectories: Sequence[AgentTrajectory]) -> dict[str, float]:
    s, y = _labels_scores(trajectories, score_fn)
    if len(s) == 0 or y.sum() == 0:
        return {"auroc": 0.0, "ap": 0.0, "r_fpr05": 0.0, "r_budget25": 0.0}
    r05, _ = recall_at_fpr(s, y, 0.05)
    return {
        "auroc": float(auroc(s, y)) if not np.isnan(auroc(s, y)) else 0.0,
        "ap": float(average_precision(s, y)),
        "r_fpr05": float(r05),
        "r_budget25": float(recall_at_budget(s, y, 25)),
    }


def combine_scores(
    base_fn: ScoreFn | None,
    candidate: CandidateMonitor,
    *,
    weight: float = 1.0,
) -> ScoreFn:
    def fn(t: AgentTrajectory) -> float:
        b = float(base_fn(t)) if base_fn is not None else 0.0
        try:
            c = float(candidate.score(t))
        except Exception:
            c = 0.0
        # Soft combine — continuous features add; thresholds act as boosts
        if candidate.name.startswith("thr_"):
            return b + weight * 0.35 * c
        return b + weight * c
    return fn


def marginal_utility(
    candidate: CandidateMonitor,
    selection: Sequence[AgentTrajectory],
    base_fn: ScoreFn | None,
    *,
    complexity: int = 1,
) -> dict[str, float]:
    """Δ metrics on selection when candidate is added to base system."""
    base = system_metrics(base_fn or (lambda t: 0.0), selection)
    combined = system_metrics(combine_scores(base_fn, candidate), selection)
    delta = {
        "d_auroc": combined["auroc"] - base["auroc"],
        "d_ap": combined["ap"] - base["ap"],
        "d_r_fpr05": combined["r_fpr05"] - base["r_fpr05"],
        "d_r_budget25": combined["r_budget25"] - base["r_budget25"],
        "base_auroc": base["auroc"],
        "new_auroc": combined["auroc"],
    }
    # Marginal composite: emphasize operational metrics
    complexity_pen = 0.03 * max(0, complexity - 1)
    delta["marginal"] = (
        0.30 * delta["d_auroc"]
        + 0.25 * delta["d_ap"]
        + 0.30 * delta["d_r_fpr05"]
        + 0.15 * delta["d_r_budget25"]
        - complexity_pen
    )
    return delta


def rank_by_marginal(
    candidates: list[CandidateMonitor],
    selection: Sequence[AgentTrajectory],
    base_fn: ScoreFn | None,
    *,
    already_names: set[str] | None = None,
) -> list[tuple[CandidateMonitor, dict[str, float]]]:
    already_names = already_names or set()
    ranked = []
    for c in candidates:
        if c.name in already_names:
            continue
        util = marginal_utility(c, selection, base_fn, complexity=c.complexity)
        # Blend with discovery separation for stability
        sep = c.score_breakdown.get("separation", 0.0)
        util["blended"] = util["marginal"] + 0.05 * min(1.0, sep / 3.0)
        ranked.append((c, util))
    ranked.sort(key=lambda x: x[1]["blended"], reverse=True)
    return ranked
