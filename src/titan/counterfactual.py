"""
Counterfactual suggestions — honest about what they are.

These are feature-space sensitivity analyses ("which features, if reduced,
would drop alert strength most?"), NOT causal interventions on the agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .features import DEFAULT_FEATURES, extract_features
from .schema import AgentTrajectory


@dataclass
class CounterfactualSuggestion:
    feature: str
    current_value: float
    suggested_direction: str  # decrease | increase
    estimated_sensitivity: float
    plain_english: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "current_value": self.current_value,
            "suggested_direction": self.suggested_direction,
            "estimated_sensitivity": self.estimated_sensitivity,
            "plain_english": self.plain_english,
            "caveat": (
                "Sensitivity analysis on monitor features — not a causal "
                "intervention plan for the agent or environment."
            ),
        }


def suggest_counterfactuals(
    trajectory: AgentTrajectory,
    score_fn: Callable[[AgentTrajectory], float],
    *,
    top_k: int = 5,
) -> list[CounterfactualSuggestion]:
    """
    Rank features by how much a small decrease would reduce the score.

    Implementation: finite-difference on payload-backed features by cloning
    the trajectory and attenuating numeric payloads.
    """
    from copy import deepcopy

    base = float(score_fn(trajectory))
    feats = extract_features(trajectory)
    suggestions: list[CounterfactualSuggestion] = []

    # Features we can meaningfully attenuate via payload edits
    attenuable = [
        ("semantic_cluster_concentration", "Spread mutations across clusters"),
        ("mean_gradient_influence", "Reduce high-influence sample injection"),
        ("max_gradient_influence", "Cap max influence samples"),
        ("rare_source_fraction", "Prefer known/common data sources"),
        ("bypass_attempt_count", "Eliminate bypass/obfuscation attempts"),
        ("eval_removal_count", "Stop removing/weakening evaluations"),
        ("test_edit_count", "Avoid editing tests/graders"),
        ("safeguard_touch_count", "Avoid modifying safeguard code"),
        ("dispersed_commit_score", "Use fewer identities / clearer provenance"),
        ("label_entropy_shift", "Avoid bulk relabeling"),
        ("n_permission_failures", "Stop retrying denied privileged actions"),
        ("monitor_disagreement", "Align stated intent with actions"),
    ]

    for feat_name, advice in attenuable:
        cur = feats.get(feat_name, 0.0)
        if cur <= 0:
            continue
        # Build a pseudo-attenuated trajectory by scaling related payloads
        t2 = deepcopy(trajectory)
        _attenuate(t2, feat_name, factor=0.5)
        try:
            new_score = float(score_fn(t2))
        except Exception:
            continue
        delta = base - new_score
        if delta <= 0:
            continue
        suggestions.append(CounterfactualSuggestion(
            feature=feat_name,
            current_value=float(cur),
            suggested_direction="decrease",
            estimated_sensitivity=float(delta),
            plain_english=advice,
        ))

    suggestions.sort(key=lambda s: s.estimated_sensitivity, reverse=True)
    return suggestions[:top_k]


def _attenuate(t: AgentTrajectory, feat_name: str, factor: float) -> None:
    for e in t.events:
        p = e.payload
        if feat_name in ("mean_gradient_influence", "max_gradient_influence") and "gradient_influence" in p:
            p["gradient_influence"] = float(p["gradient_influence"]) * factor
        if feat_name == "rare_source_fraction" and "source_rarity" in p:
            p["source_rarity"] = float(p["source_rarity"]) * factor
        if feat_name == "label_entropy_shift" and "label_entropy_delta" in p:
            p["label_entropy_delta"] = float(p["label_entropy_delta"]) * factor
        if feat_name == "semantic_cluster_concentration" and "semantic_cluster" in p:
            # Break concentration by renaming clusters
            p["semantic_cluster"] = f"{p['semantic_cluster']}_{id(e) % 7}"
        if feat_name in ("bypass_attempt_count",) and p.get("bypass_attempt"):
            p["bypass_attempt"] = False
            p["obfuscation"] = False
        if feat_name == "eval_removal_count" and p.get("action") in ("remove", "weaken", "disable"):
            p["action"] = "refresh"
            p["canary_delta"] = 0.0
        if feat_name == "dispersed_commit_score" and "identity" in p:
            p["identity"] = "agent"
            p["n_files"] = max(int(p.get("n_files", 1)), 3)
    # Also damp monitor disagreement artificially
    if feat_name == "monitor_disagreement":
        mean = sum(t.existing_monitor_scores.values()) / max(1, len(t.existing_monitor_scores))
        t.existing_monitor_scores = {k: mean for k in t.existing_monitor_scores}
