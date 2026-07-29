"""
Label-aware candidate scoring: separation, stability, transfer retention.

Uses explicit Label objects — never assumes first-half / second-half layout.
"""

from __future__ import annotations

from typing import Callable, Sequence

import numpy as np

from .config import (
    MAX_SEPARATION_PAIRS,
    MAX_STABILITY_PERTURBATIONS,
    NOISE_SCALE,
)
from .schema import AgentTrajectory, Label


ScoreFn = Callable[[AgentTrajectory], float]


def _pairs(
    trajectories: Sequence[AgentTrajectory],
    labels: Sequence[Label] | None = None,
    max_pairs: int = MAX_SEPARATION_PAIRS,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return (cross_regime_pairs, within_regime_pairs)."""
    labs = list(labels) if labels is not None else [t.label for t in trajectories]
    harmful = [i for i, l in enumerate(labs) if l == Label.HARMFUL]
    benign = [i for i, l in enumerate(labs) if l == Label.BENIGN]

    cross: list[tuple[int, int]] = []
    for i in harmful:
        for j in benign:
            cross.append((i, j))
            if len(cross) >= max_pairs:
                break
        if len(cross) >= max_pairs:
            break

    within: list[tuple[int, int]] = []
    for group in (harmful, benign):
        for a_idx in range(len(group)):
            for b_idx in range(a_idx + 1, len(group)):
                within.append((group[a_idx], group[b_idx]))
                if len(within) >= max_pairs:
                    break
            if len(within) >= max_pairs:
                break
        if len(within) >= max_pairs:
            break
    return cross, within


def separation_ratio(
    score_fn: ScoreFn,
    trajectories: Sequence[AgentTrajectory],
    labels: Sequence[Label] | None = None,
    max_pairs: int = MAX_SEPARATION_PAIRS,
) -> float:
    """
    Cross-regime |score_i - score_j| mean / within-regime mean.

    Higher is better. Returns 0 if insufficient pairs.
    """
    cross, within = _pairs(trajectories, labels, max_pairs)
    if not cross:
        return 0.0

    def safe(t: AgentTrajectory) -> float:
        try:
            return float(score_fn(t))
        except Exception:
            return 0.0

    scores = [safe(t) for t in trajectories]
    cross_vals = [abs(scores[i] - scores[j]) for i, j in cross]
    within_vals = [abs(scores[i] - scores[j]) for i, j in within] if within else [1e-6]

    cross_mean = float(np.mean(cross_vals)) if cross_vals else 0.0
    within_mean = float(np.mean(within_vals)) if within_vals else 1e-6
    return cross_mean / max(within_mean, 1e-12)


def stability_score(
    score_fn: ScoreFn,
    trajectories: Sequence[AgentTrajectory],
    *,
    noise_scale: float = NOISE_SCALE,
    n_perturbations: int = MAX_STABILITY_PERTURBATIONS,
    feature_key: str | None = None,
) -> float:
    """
    Stability under small payload noise on numeric event fields.

    Returns 1 / (1 + relative variance). Values near 1 are stable.
    """
    rng = np.random.default_rng(0)
    bases: list[float] = []
    rel_vars: list[float] = []

    sample = list(trajectories[: min(12, len(trajectories))])
    for t in sample:
        try:
            base = float(score_fn(t))
        except Exception:
            continue
        bases.append(base)
        perturbed: list[float] = []
        for _ in range(n_perturbations):
            # Lightweight structural noise: jitter monitor scores
            noisy = _jitter_trajectory(t, rng, noise_scale)
            try:
                perturbed.append(float(score_fn(noisy)))
            except Exception:
                perturbed.append(base)
        if abs(base) > 1e-12:
            rel_var = float(np.var(perturbed) / (base ** 2 + 1e-12))
        else:
            rel_var = float(np.var(perturbed))
        rel_vars.append(rel_var)

    if not rel_vars:
        return 0.5
    mean_rv = float(np.mean(rel_vars))
    return float(1.0 / (1.0 + mean_rv))


def _jitter_trajectory(t: AgentTrajectory, rng: np.random.Generator, scale: float) -> AgentTrajectory:
    """Copy trajectory with small noise on monitor scores and numeric payloads."""
    from copy import deepcopy
    from .schema import AgentTrajectory as AT

    scores = {
        k: float(np.clip(v + rng.normal(0, scale), 0.0, 1.0))
        for k, v in t.existing_monitor_scores.items()
    }
    events = deepcopy(t.events)
    for e in events:
        for key in ("gradient_influence", "source_rarity", "label_entropy_delta", "canary_delta"):
            if key in e.payload and isinstance(e.payload[key], (int, float)):
                e.payload[key] = float(e.payload[key]) + float(rng.normal(0, scale * 0.5))
    return AT(
        trajectory_id=t.trajectory_id + "_jitter",
        events=events,
        label=t.label,
        attack_family=t.attack_family,
        model_version=t.model_version,
        environment=t.environment,
        task_family=t.task_family,
        existing_monitor_scores=scores,
        monitor_judgments=list(t.monitor_judgments),
        metadata=dict(t.metadata),
        created_at=t.created_at,
    )


def transfer_retention(
    score_fn: ScoreFn,
    source: Sequence[AgentTrajectory],
    target: Sequence[AgentTrajectory],
    labels_source: Sequence[Label] | None = None,
    labels_target: Sequence[Label] | None = None,
) -> float:
    """
    Real transfer: separation on target / separation on source.

    Returns 0 if source separation is zero. Caps at 1.5 to avoid explosion.
    """
    sep_src = separation_ratio(score_fn, source, labels_source)
    if sep_src < 1e-9:
        return 0.0
    sep_tgt = separation_ratio(score_fn, target, labels_target)
    return float(min(1.5, sep_tgt / sep_src))


def composite_score(
    separation: float,
    stability: float,
    transfer: float,
    simplicity: float = 1.0,
    *,
    w_sep: float = 0.40,
    w_stab: float = 0.25,
    w_trans: float = 0.25,
    w_simp: float = 0.10,
) -> float:
    """Weighted composite used for candidate ranking."""
    # Soft-saturate separation so extreme ratios don't dominate
    sep_term = float(np.tanh(separation / 3.0))
    return float(
        w_sep * sep_term
        + w_stab * stability
        + w_trans * min(1.0, transfer)
        + w_simp * simplicity
    )


def score_candidate(
    score_fn: ScoreFn,
    discovery: Sequence[AgentTrajectory],
    selection: Sequence[AgentTrajectory] | None = None,
    *,
    complexity: int = 1,
) -> dict[str, float]:
    """
    Full score breakdown on discovery (+ optional held-out selection for transfer).
    """
    sep = separation_ratio(score_fn, discovery)
    stab = stability_score(score_fn, discovery)
    if selection:
        trans = transfer_retention(score_fn, discovery, selection)
    else:
        # Without held-out data, do not invent transfer — mark as unevaluated (0.5 prior)
        trans = 0.5
    simplicity = 1.0 / (1.0 + 0.25 * max(0, complexity - 1))
    comp = composite_score(sep, stab, trans, simplicity)
    return {
        "separation": float(sep),
        "stability": float(stab),
        "transfer": float(trans),
        "simplicity": float(simplicity),
        "composite": float(comp),
    }
