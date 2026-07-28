"""
Candidate synthesis from collision clusters.

Critical design constraint: synthesized features MUST re-enter the feature
vector and collision detection. Collision reduction is only reported after
true augmentation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .collisions import Collision, CollisionReport, collision_clusters
from .config import (
    MAX_CANDIDATES_PER_ROUND,
    MAX_PROMOTED_PER_RUN,
    MIN_SEPARATION_RATIO,
    MIN_STABILITY,
    MIN_TRANSFER_RETENTION,
)
from .dsl import DSLCandidate, expr_to_str, feature_deps, generate_dsl_candidates
from .features import FeatureFn
from .provenance import MonitorProvenance
from .schema import AgentTrajectory, Label
from .scoring import score_candidate


@dataclass
class CandidateMonitor:
    """A scored, inspectable candidate measurement."""

    name: str
    score_fn: Callable[[AgentTrajectory], float]
    complexity: int
    score_breakdown: dict[str, float]
    provenance: MonitorProvenance
    rationale: str = ""
    expression: str | None = None

    def score(self, t: AgentTrajectory) -> float:
        return float(self.score_fn(t))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "complexity": self.complexity,
            "score_breakdown": self.score_breakdown,
            "rationale": self.rationale,
            "expression": self.expression,
            "provenance": self.provenance.to_dict(),
        }


def _collision_context(
    collisions: list[Collision],
    trajectories: list[AgentTrajectory],
) -> dict[str, Any]:
    families: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for c in collisions[:16]:
        families.add(c.attack_family_a)
        families.add(c.attack_family_b)
        pairs.append((c.trajectory_id_a, c.trajectory_id_b))
    return {
        "families": sorted(f for f in families if f not in ("none", "hard_negative", "clean_refactor", "legitimate_data_curation")),
        "pairs": pairs,
        "n": len(collisions),
        "clusters": collision_clusters(collisions, len(trajectories)),
    }


def synthesize_candidates(
    collision_report: CollisionReport,
    trajectories: list[AgentTrajectory],
    *,
    selection: list[AgentTrajectory] | None = None,
    complexity_level: int = 1,
    existing_features: dict[str, FeatureFn] | None = None,
    max_candidates: int = MAX_CANDIDATES_PER_ROUND,
    max_promoted: int = MAX_PROMOTED_PER_RUN,
) -> list[CandidateMonitor]:
    """
    Generate, score, and filter candidate monitors from collision evidence.

    Selection set is used ONLY for transfer measurement — not for discovery
    of which features exist.
    """
    if not collision_report.collisions:
        return []

    ctx = _collision_context(collision_report.collisions, trajectories)
    pool = generate_dsl_candidates(complexity_level, collision_report.feature_names)

    # Prefer candidates that touch features with small gaps in collisions
    # (those are the blind dimensions) — score all, rank by composite.
    scored: list[CandidateMonitor] = []
    for cand in pool[: max_candidates * 3]:
        breakdown = score_candidate(
            cand.score_fn,
            trajectories,
            selection,
            complexity=cand.complexity,
        )
        # Soft filter
        if breakdown["separation"] < MIN_SEPARATION_RATIO * 0.7:
            continue
        if breakdown["stability"] < MIN_STABILITY * 0.8:
            continue

        expr_str = expr_to_str(cand.expr)
        prov = MonitorProvenance(
            name=cand.name,
            source_collision_pairs=ctx["pairs"][:8],
            attack_families_seen=ctx["families"],
            score_breakdown=breakdown,
            expression=expr_str,
            dsl_ast=cand.expr.to_dict(),
            feature_deps=feature_deps(cand.expr),
            notes=cand.rationale,
            status="candidate",
        )
        scored.append(CandidateMonitor(
            name=cand.name,
            score_fn=cand.score_fn,
            complexity=cand.complexity,
            score_breakdown=breakdown,
            provenance=prov,
            rationale=cand.rationale,
            expression=expr_str,
        ))

    # Prefer continuous features over pure thresholds when composites are close
    def rank_key(c: CandidateMonitor) -> tuple:
        b = c.score_breakdown
        is_thr = 1 if c.name.startswith("thr_") else 0
        return (b["composite"], -is_thr, b["separation"], b["transfer"])

    scored.sort(key=rank_key, reverse=True)

    def _base_feature(name: str) -> str:
        if name.startswith("thr_"):
            return name.split("_gt_")[0].replace("thr_", "")
        if name.startswith("feat_"):
            return name[len("feat_"):]
        if name.startswith("dsl_"):
            return name
        return name

    promoted: list[CandidateMonitor] = []
    seen_bases: set[str] = set()
    n_thresholds = 0
    max_thresholds = max(1, max_promoted // 3)

    for c in scored:
        if len(promoted) >= max_promoted:
            break
        b = c.score_breakdown
        base = _base_feature(c.name)
        if base in seen_bases:
            continue
        if c.name.startswith("thr_"):
            if n_thresholds >= max_thresholds:
                continue
        # Gate for promotion into the active feature set
        if b["separation"] >= MIN_SEPARATION_RATIO and b["stability"] >= MIN_STABILITY:
            if selection is None or b["transfer"] >= MIN_TRANSFER_RETENTION * 0.75:
                c.provenance.status = "candidate"
                promoted.append(c)
                seen_bases.add(base)
                if c.name.startswith("thr_"):
                    n_thresholds += 1

    # Soft-fill with continuous features that nearly clear the bar (diversity)
    if len(promoted) < max_promoted:
        for c in scored:
            if len(promoted) >= max_promoted:
                break
            base = _base_feature(c.name)
            if base in seen_bases or c.name.startswith("thr_"):
                continue
            b = c.score_breakdown
            if b["separation"] >= MIN_SEPARATION_RATIO * 0.85 and b["stability"] >= MIN_STABILITY * 0.9:
                c.provenance.status = "candidate"
                promoted.append(c)
                seen_bases.add(base)

    # Always keep at least top-1 if anything scored, for inspectability
    if not promoted and scored:
        promoted = scored[:1]

    return promoted[:max_promoted]


def candidates_to_feature_fns(
    candidates: list[CandidateMonitor],
) -> dict[str, FeatureFn]:
    """Convert promoted candidates into FeatureFn entries for vector augmentation."""
    return {c.name: c.score_fn for c in candidates}


def merge_feature_fns(
    base: dict[str, FeatureFn],
    extra: dict[str, FeatureFn],
) -> dict[str, FeatureFn]:
    """Merge without overwriting base names unless extra uses distinct names."""
    out = dict(base)
    for k, v in extra.items():
        if k not in out:
            out[k] = v
        else:
            out[f"synth_{k}"] = v
    return out
