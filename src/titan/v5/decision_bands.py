"""
Phase 7 — Multi-band hierarchical calibration.

Separate thresholds for review / escrow / block, optional per-action and per-env.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import numpy as np

from ..schema import AgentTrajectory, Label
from .governor import DecisionBands


ScoreFn = Callable[[AgentTrajectory], float]


@dataclass
class DecisionBandCalibrator:
    """
    Fit τ_review < τ_escrow < τ_block from benign scores + target rates.
    """

    history: list[dict[str, Any]] = field(default_factory=list)

    def fit(
        self,
        score_fn: ScoreFn,
        benign: Sequence[AgentTrajectory],
        *,
        target_review_fpr: float = 0.10,
        target_escrow_fpr: float = 0.05,
        target_block_fpr: float = 0.01,
        action_type: str = "global",
        environment: str = "global",
        max_reviews_per_1000: float = 50.0,
    ) -> DecisionBands:
        scores = np.array([
            float(score_fn(t)) for t in benign if t.label == Label.BENIGN
        ], dtype=float)
        if len(scores) == 0:
            scores = np.array([float(score_fn(t)) for t in benign], dtype=float)
        if len(scores) == 0:
            bands = DecisionBands(0.3, 0.5, 0.8, action_type=action_type)
            self.history.append({"action": "fit_empty", **bands.to_dict()})
            return bands

        def q(fpr: float) -> float:
            return float(np.percentile(scores, 100 * (1 - fpr)))

        # Budget constraint on review rate
        budget_fpr = min(target_review_fpr, max_reviews_per_1000 / 1000.0)
        tau_review = q(budget_fpr)
        tau_escrow = max(tau_review + 1e-6, q(target_escrow_fpr))
        tau_block = max(tau_escrow + 1e-6, q(target_block_fpr))

        # Discrete/cliffy score distributions collapse quantiles — enforce
        # operational gaps so bands are distinct decision regions.
        # Block must sit well into the upper tail; review near budget quantile.
        smax = float(np.max(scores)) if len(scores) else 1.0
        s_p99 = float(np.percentile(scores, 99)) if len(scores) else 0.5
        s_p995 = float(np.percentile(scores, 99.5)) if len(scores) else 0.7
        # Minimum absolute floors for consequential autonomy
        min_gap = max(0.05, 0.08 * max(smax, 0.5))
        tau_review = float(tau_review)
        tau_escrow = max(tau_escrow, tau_review + min_gap)
        # Autonomous block requires high confidence — at least p99.5 of benign
        # or review+2*gap, and never below 0.55 on a [0,1]-ish risk scale.
        tau_block = max(tau_block, tau_escrow + min_gap, s_p995, s_p99 + min_gap, 0.55)
        if tau_block > 1.0 and smax <= 1.0:
            tau_block = max(0.55, min(0.95, smax + 1e-3))
        # Final ordering
        if not (tau_review < tau_escrow < tau_block):
            tau_review = min(tau_review, 0.35)
            tau_escrow = max(tau_review + min_gap, 0.50)
            tau_block = max(tau_escrow + min_gap, 0.75)

        bands = DecisionBands(tau_review, tau_escrow, tau_block, action_type=action_type)
        self.history.append({
            "action": "fit",
            "environment": environment,
            "n_benign": len(scores),
            "target_review_fpr": budget_fpr,
            "target_escrow_fpr": target_escrow_fpr,
            "target_block_fpr": target_block_fpr,
            **bands.to_dict(),
            "empirical_block_fpr": float(np.mean(scores >= tau_block)),
            "empirical_escrow_fpr": float(np.mean(scores >= tau_escrow)),
            "empirical_review_fpr": float(np.mean(scores >= tau_review)),
        })
        return bands

    def fit_action_specific(
        self,
        score_fn: ScoreFn,
        benign: Sequence[AgentTrajectory],
        action_types: Sequence[str],
        **kwargs,
    ) -> dict[str, DecisionBands]:
        out = {}
        for at in action_types:
            # Without action-labeled benign, use global scores with action tag
            out[at] = self.fit(score_fn, benign, action_type=at, **kwargs)
        return out

    def validate_on(
        self,
        score_fn: ScoreFn,
        trajectories: Sequence[AgentTrajectory],
        bands: DecisionBands,
    ) -> dict[str, Any]:
        ben = [t for t in trajectories if t.label == Label.BENIGN]
        harm = [t for t in trajectories if t.label == Label.HARMFUL]
        bs = [float(score_fn(t)) for t in ben]
        hs = [float(score_fn(t)) for t in harm]
        def rate(scores, thr):
            return float(np.mean([s >= thr for s in scores])) if scores else 0.0
        return {
            "benign_block_fpr": rate(bs, bands.tau_block),
            "benign_escrow_fpr": rate(bs, bands.tau_escrow),
            "benign_review_fpr": rate(bs, bands.tau_review),
            "harm_block_recall": rate(hs, bands.tau_block),
            "harm_escrow_recall": rate(hs, bands.tau_escrow),
            "harm_review_recall": rate(hs, bands.tau_review),
            "n_benign": len(bs),
            "n_harmful": len(hs),
            "bands": bands.to_dict(),
        }
