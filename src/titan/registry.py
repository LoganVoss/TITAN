"""
Versioned monitor registry with provenance, shadow deployment, and retirement.

Promotion criteria are explicit. Monitors are never silently blocking without
human-defined thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import json
import time
from pathlib import Path

from .config import (
    PROMOTION_MAX_FPR,
    PROMOTION_MIN_RECALL_AT_FPR,
    SHADOW_MIN_SAMPLES,
)
from .provenance import MonitorProvenance
from .schema import AgentTrajectory
from .synthesis import CandidateMonitor


@dataclass
class RegistryEntry:
    name: str
    version: str
    score_fn: Callable[[AgentTrajectory], float]
    provenance: MonitorProvenance
    status: str = "candidate"  # candidate | shadow | promoted | retired
    metrics: dict[str, float] = field(default_factory=dict)
    shadow_scores: list[tuple[str, float, str]] = field(default_factory=list)
    # (trajectory_id, score, true_label)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    expression: str | None = None
    rationale: str = ""

    def score(self, t: AgentTrajectory) -> float:
        return float(self.score_fn(t))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "metrics": self.metrics,
            "provenance": self.provenance.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expression": self.expression,
            "rationale": self.rationale,
            "n_shadow_scores": len(self.shadow_scores),
        }


class MonitorRegistry:
    """In-memory + optional disk-backed registry of safety monitors."""

    def __init__(self) -> None:
        self._entries: dict[str, RegistryEntry] = {}
        self._history: list[dict[str, Any]] = []

    def __len__(self) -> int:
        return len(self._entries)

    def register_candidate(self, candidate: CandidateMonitor, version: str = "0.1.0") -> RegistryEntry:
        key = f"{candidate.name}@{version}"
        entry = RegistryEntry(
            name=candidate.name,
            version=version,
            score_fn=candidate.score_fn,
            provenance=candidate.provenance,
            status="candidate",
            metrics=dict(candidate.score_breakdown),
            expression=candidate.expression,
            rationale=candidate.rationale,
        )
        entry.provenance.status = "candidate"
        self._entries[key] = entry
        self._log("register", key, entry.status)
        return entry

    def register_many(self, candidates: list[CandidateMonitor], version: str = "0.1.0") -> list[RegistryEntry]:
        return [self.register_candidate(c, version) for c in candidates]

    def get(self, name: str, version: str | None = None) -> RegistryEntry | None:
        if version:
            return self._entries.get(f"{name}@{version}")
        # latest by updated_at
        matches = [e for e in self._entries.values() if e.name == name]
        if not matches:
            return None
        return max(matches, key=lambda e: e.updated_at)

    def list(self, status: str | None = None) -> list[RegistryEntry]:
        entries = list(self._entries.values())
        if status:
            entries = [e for e in entries if e.status == status]
        return sorted(entries, key=lambda e: e.updated_at, reverse=True)

    def promote_to_shadow(self, name: str, version: str | None = None) -> RegistryEntry:
        entry = self.get(name, version)
        if entry is None:
            raise KeyError(f"Unknown monitor {name}")
        entry.status = "shadow"
        entry.provenance.status = "shadow"
        entry.updated_at = time.time()
        self._log("shadow", f"{entry.name}@{entry.version}", "shadow")
        return entry

    def record_shadow(
        self,
        name: str,
        trajectory: AgentTrajectory,
        true_label: str | None = None,
        version: str | None = None,
    ) -> float:
        entry = self.get(name, version)
        if entry is None:
            raise KeyError(f"Unknown monitor {name}")
        s = entry.score(trajectory)
        label = true_label if true_label is not None else trajectory.label.value
        entry.shadow_scores.append((trajectory.trajectory_id, s, label))
        entry.updated_at = time.time()
        return s

    def evaluate_shadow_metrics(self, name: str, version: str | None = None) -> dict[str, float]:
        """Compute simple shadow metrics if enough labeled samples exist."""
        entry = self.get(name, version)
        if entry is None:
            raise KeyError(f"Unknown monitor {name}")
        if len(entry.shadow_scores) < SHADOW_MIN_SAMPLES:
            return {
                "n": float(len(entry.shadow_scores)),
                "ready": 0.0,
            }
        scores = [s for _, s, _ in entry.shadow_scores]
        labels = [1.0 if lab == "harmful" else 0.0 for _, _, lab in entry.shadow_scores]
        # Threshold at 90th percentile of scores as a crude operating point
        import numpy as np
        thr = float(np.percentile(scores, 90))
        preds = [1.0 if s >= thr else 0.0 for s in scores]
        tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
        fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
        fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)
        tn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 0)
        n_pos = max(1, sum(labels))
        n_neg = max(1, len(labels) - sum(labels))
        recall = tp / n_pos
        fpr = fp / n_neg
        precision = tp / max(1, tp + fp)
        metrics = {
            "n": float(len(scores)),
            "ready": 1.0,
            "threshold": thr,
            "recall": float(recall),
            "fpr": float(fpr),
            "precision": float(precision),
            "tp": float(tp),
            "fp": float(fp),
            "fn": float(fn),
            "tn": float(tn),
        }
        entry.metrics.update(metrics)
        return metrics

    def try_promote(
        self,
        name: str,
        version: str | None = None,
        *,
        min_recall: float = PROMOTION_MIN_RECALL_AT_FPR,
        max_fpr: float = PROMOTION_MAX_FPR,
    ) -> tuple[bool, str]:
        """Promote shadow → promoted if metrics clear the bar."""
        entry = self.get(name, version)
        if entry is None:
            return False, "unknown monitor"
        if entry.status != "shadow":
            return False, f"status is {entry.status}, need shadow"
        metrics = self.evaluate_shadow_metrics(name, version)
        if metrics.get("ready", 0) < 1.0:
            return False, f"insufficient shadow samples ({int(metrics.get('n', 0))}/{SHADOW_MIN_SAMPLES})"
        if metrics["recall"] < min_recall:
            return False, f"recall {metrics['recall']:.3f} < {min_recall}"
        if metrics["fpr"] > max_fpr:
            return False, f"fpr {metrics['fpr']:.3f} > {max_fpr}"
        entry.status = "promoted"
        entry.provenance.status = "promoted"
        entry.updated_at = time.time()
        self._log("promote", f"{entry.name}@{entry.version}", "promoted", metrics)
        return True, "promoted"

    def retire(self, name: str, reason: str = "", version: str | None = None) -> RegistryEntry:
        entry = self.get(name, version)
        if entry is None:
            raise KeyError(f"Unknown monitor {name}")
        entry.status = "retired"
        entry.provenance.status = "retired"
        entry.provenance.notes = (entry.provenance.notes + f" | retired: {reason}").strip(" |")
        entry.updated_at = time.time()
        self._log("retire", f"{entry.name}@{entry.version}", "retired", {"reason": reason})
        return entry

    def active_scorers(self, statuses: tuple[str, ...] = ("promoted", "shadow")) -> dict[str, Callable[[AgentTrajectory], float]]:
        return {
            f"{e.name}@{e.version}": e.score_fn
            for e in self._entries.values()
            if e.status in statuses
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        data = {
            "entries": [e.to_dict() for e in self._entries.values()],
            "history": self._history,
        }
        path.write_text(json.dumps(data, indent=2, default=str))

    def summary(self) -> str:
        by_status: dict[str, int] = {}
        for e in self._entries.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
        parts = [f"{k}={v}" for k, v in sorted(by_status.items())]
        return f"MonitorRegistry({len(self)} monitors: {', '.join(parts)})"

    def _log(self, action: str, key: str, status: str, extra: dict | None = None) -> None:
        self._history.append({
            "ts": time.time(),
            "action": action,
            "key": key,
            "status": status,
            "extra": extra or {},
        })
