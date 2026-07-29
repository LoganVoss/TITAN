"""
TITAN discovery engine — the meta-monitor loop.

When examples that matter look indistinguishable to current monitors, treat
that ambiguity as evidence that the measurement system needs improvement.

Critical fixes vs prior system:
1. Synthesized features re-enter the feature vectors (true augmentation).
2. Collisions are cross-regime only (explicit labels).
3. Distances are z-score normalized.
4. Selection/transfer data is held out from discovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .collisions import CollisionReport, find_collisions, format_collision_detail
from .config import (
    DEFAULT_COLLISION_THRESHOLD,
    FINAL_COLLISION_THRESHOLD,
    MAX_COMPLEXITY_LEVEL,
    MAX_PROMOTED_PER_RUN,
    MAX_SYNTH_ROUNDS,
)
from .features import BASE_MONITOR_FEATURES, FeatureFn
from .schema import AgentTrajectory, Label
from .synthesis import CandidateMonitor, candidates_to_feature_fns, merge_feature_fns, synthesize_candidates


@dataclass
class DiscoveryResult:
    """Full output of a blind-spot discovery run."""

    name: str
    initial_report: CollisionReport
    final_report: CollisionReport
    promoted: list[CandidateMonitor]
    feature_fns: dict[str, FeatureFn]
    rounds: list[dict[str, Any]] = field(default_factory=list)
    collision_details: list[str] = field(default_factory=list)

    @property
    def initial_collisions(self) -> int:
        return len(self.initial_report.collisions)

    @property
    def final_collisions(self) -> int:
        return len(self.final_report.collisions)

    @property
    def collisions_resolved(self) -> int:
        """Attributed to feature augmentation (same threshold family, re-measured)."""
        return max(0, self.initial_collisions - self.final_collisions)

    @property
    def pressure_reduction(self) -> float:
        p0 = self.initial_report.pressure
        p1 = self.final_report.pressure
        if p0 < 1e-12:
            return 0.0  # no initial pressure → nothing to reduce
        return max(0.0, (p0 - p1) / p0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "initial_collisions": self.initial_collisions,
            "final_collisions": self.final_collisions,
            "collisions_resolved": self.collisions_resolved,
            "pressure_initial": self.initial_report.pressure,
            "pressure_final": self.final_report.pressure,
            "pressure_reduction": self.pressure_reduction,
            "promoted": [c.to_dict() for c in self.promoted],
            "feature_names": list(self.feature_fns.keys()),
            "rounds": self.rounds,
            "collision_details": self.collision_details,
        }


def run_discovery(
    trajectories: list[AgentTrajectory],
    name: str = "discovery",
    *,
    selection: list[AgentTrajectory] | None = None,
    feature_fns: dict[str, FeatureFn] | None = None,
    threshold: float | None = None,
    final_threshold: float | None = None,
    max_rounds: int = MAX_SYNTH_ROUNDS,
    max_complexity: int = MAX_COMPLEXITY_LEVEL,
    max_promoted: int = MAX_PROMOTED_PER_RUN,
    verbose: bool = True,
) -> DiscoveryResult:
    """
    Run the bounded blind-spot discovery loop.

    Parameters
    ----------
    trajectories :
        Discovery-split trajectories with labels (harmful + benign).
    selection :
        Optional held-out set used only for transfer scoring of candidates.
        Never used to invent features.
    threshold :
        Normalized collision threshold. If None, adapt from cross-regime
        distance percentiles on the discovery pool.
    final_threshold :
        Threshold for the final collision recount AFTER augmentation.
        Defaults to the same as the (possibly adaptive) initial threshold so
        reductions are attributable to features, not a moving goalpost.
    """
    # Start from existing-monitor features only — the blind-spot surface.
    # Rich safety features enter via synthesis, not the initial vector.
    active_fns: dict[str, FeatureFn] = dict(feature_fns or BASE_MONITOR_FEATURES)
    all_promoted: list[CandidateMonitor] = []
    rounds: list[dict[str, Any]] = []

    if verbose:
        print(f"\n{'=' * 64}")
        print(f"TITAN Discovery: {name}")
        print(f"  pool={len(trajectories)}  selection={len(selection or [])}")
        thr_msg = f"{threshold:.3f}" if threshold is not None else "adaptive"
        print(f"  threshold={thr_msg}")
        print(f"{'=' * 64}")

    initial = find_collisions(
        trajectories,
        threshold=threshold,
        feature_fns=active_fns,
    )
    # Lock threshold for the whole run (honest reduction attribution)
    locked_threshold = initial.threshold
    if final_threshold is None:
        final_threshold = locked_threshold

    if verbose:
        print(f"  Initial: {initial.summary()}")
        for c in initial.collisions[:3]:
            print("  " + format_collision_detail(c, trajectories).replace("\n", "\n  "))

    details = [format_collision_detail(c, trajectories) for c in initial.collisions[:8]]

    if verbose:
        print(f"  Locked threshold={locked_threshold:.3f}")

    if initial.collisions and max_rounds > 0:
        for round_i in range(1, max_rounds + 1):
            complexity = min(round_i, max_complexity)
            current = find_collisions(
                trajectories,
                threshold=locked_threshold,
                feature_fns=active_fns,
                adaptive=False,
            )
            if not current.collisions:
                if verbose:
                    print(f"  Round {round_i}: zero collisions — stopping")
                rounds.append({"round": round_i, "collisions": 0, "promoted": []})
                break

            # Skip candidates whose base feature is already promoted
            existing_names = {c.name for c in all_promoted}
            new_cands = [
                c for c in synthesize_candidates(
                    current,
                    trajectories,
                    selection=selection,
                    complexity_level=complexity,
                    existing_features=active_fns,
                    max_promoted=max(1, max_promoted - len(all_promoted)),
                )
                if c.name not in existing_names and c.name not in active_fns
            ]

            # TRUE AUGMENTATION: fold new scorers into the feature map
            extra = candidates_to_feature_fns(new_cands)
            before_dim = len(active_fns)
            active_fns = merge_feature_fns(active_fns, extra)
            all_promoted.extend(new_cands)
            if not new_cands:
                if verbose:
                    print(f"  Round {round_i}: no new candidates — stopping")
                break

            after = find_collisions(
                trajectories,
                threshold=locked_threshold,
                feature_fns=active_fns,
                adaptive=False,
            )
            rounds.append({
                "round": round_i,
                "complexity": complexity,
                "collisions_before": len(current.collisions),
                "collisions_after": len(after.collisions),
                "features_before": before_dim,
                "features_after": len(active_fns),
                "promoted": [c.name for c in new_cands],
                "scores": {c.name: c.score_breakdown for c in new_cands},
            })
            if verbose:
                print(
                    f"  Round {round_i} (L{complexity}): "
                    f"collisions {len(current.collisions)} → {len(after.collisions)} | "
                    f"+{len(new_cands)} features → dim={len(active_fns)}"
                )
                for c in new_cands:
                    b = c.score_breakdown
                    print(
                        f"    · {c.name}: sep={b['separation']:.2f} "
                        f"stab={b['stability']:.2f} xfer={b['transfer']:.2f} "
                        f"comp={b['composite']:.3f}"
                    )

            if len(all_promoted) >= max_promoted:
                break
            if len(after.collisions) == 0:
                break
    elif verbose:
        print("  >>> ZERO INITIAL COLLISIONS — base monitors already separate regimes <<<")

    # Final recount on augmented features (same locked threshold by default)
    final = find_collisions(
        trajectories,
        threshold=final_threshold,
        feature_fns=active_fns,
        adaptive=False,
    )

    if verbose:
        print(
            f"  Final: {final.summary()} | "
            f"resolved={max(0, len(initial.collisions) - len(final.collisions))} | "
            f"promoted={len(all_promoted)}"
        )
        print(f"{'=' * 64}\n")

    return DiscoveryResult(
        name=name,
        initial_report=initial,
        final_report=final,
        promoted=all_promoted,
        feature_fns=active_fns,
        rounds=rounds,
        collision_details=details,
    )


def score_trajectory(
    trajectory: AgentTrajectory,
    candidates: list[CandidateMonitor],
    *,
    aggregation: str = "weighted",
) -> dict[str, float]:
    """
    Score one trajectory with all promoted candidates + aggregate alert strength.

    aggregation:
      - "max": max raw candidate score
      - "mean": mean raw score
      - "weighted" (default): composite-weighted sum of soft-normalized scores
        (continuous features contribute more than saturated binary thresholds)
    """
    scores = {c.name: c.score(trajectory) for c in candidates}
    vals = list(scores.values())
    if not vals:
        scores["alert_strength"] = 0.0
        return scores

    if aggregation == "mean":
        scores["alert_strength"] = float(sum(vals) / len(vals))
    elif aggregation == "max":
        scores["alert_strength"] = float(max(vals))
    else:
        # Weighted soft sum: tanh keeps large continuous features bounded
        total_w = 0.0
        acc = 0.0
        for c in candidates:
            w = float(c.score_breakdown.get("composite", 0.5))
            # Prefer continuous (non-threshold) features slightly
            if not c.name.startswith("thr_"):
                w *= 1.25
            raw = scores[c.name]
            # Soft normalize: thresholds stay ~0/1; continuous get tanh
            if c.name.startswith("thr_"):
                contrib = raw
            else:
                contrib = float(np.tanh(raw)) if abs(raw) > 0 else 0.0
                # If feature is already roughly [0,1], tanh still fine
                if 0.0 <= raw <= 1.5:
                    contrib = float(raw)
            acc += w * contrib
            total_w += w
        scores["alert_strength"] = float(acc / total_w) if total_w > 0 else 0.0
    return scores
