"""
Step 13 — Calibration subsystem: environment-aware, budget-based, versioned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import numpy as np

from ..schema import AgentTrajectory, Label


ScoreFn = Callable[[AgentTrajectory], float]


@dataclass
class OperatingPoint:
    name: str
    threshold: float
    target_fpr: float | None = None
    max_alerts_per_1000: float | None = None
    environment: str = "global"
    agent_version: str = "global"
    version: str = "1.0"
    n_calibration: int = 0
    empirical_fpr: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "threshold": self.threshold,
            "target_fpr": self.target_fpr,
            "max_alerts_per_1000": self.max_alerts_per_1000,
            "environment": self.environment,
            "agent_version": self.agent_version,
            "version": self.version,
            "n_calibration": self.n_calibration,
            "empirical_fpr": self.empirical_fpr,
            "notes": self.notes,
        }


class CalibrationSubsystem:
    def __init__(self):
        self.points: dict[str, OperatingPoint] = {}
        self.history: list[dict[str, Any]] = []

    def fit_fpr(
        self,
        score_fn: ScoreFn,
        benign: Sequence[AgentTrajectory],
        *,
        target_fpr: float = 0.05,
        name: str = "fpr_global",
        environment: str = "global",
        agent_version: str = "global",
    ) -> OperatingPoint:
        scores = [float(score_fn(t)) for t in benign if t.label == Label.BENIGN]
        if not scores:
            scores = [float(score_fn(t)) for t in benign]
        if not scores:
            thr = 0.5
        else:
            thr = float(np.percentile(scores, 100 * (1 - target_fpr)))
        emp = sum(1 for s in scores if s >= thr) / max(1, len(scores))
        op = OperatingPoint(
            name=name,
            threshold=thr,
            target_fpr=target_fpr,
            environment=environment,
            agent_version=agent_version,
            n_calibration=len(scores),
            empirical_fpr=emp,
            notes=f"quantile FPR target={target_fpr}",
        )
        self.points[name] = op
        self.history.append({"action": "fit_fpr", **op.to_dict()})
        return op

    def fit_budget(
        self,
        score_fn: ScoreFn,
        traffic: Sequence[AgentTrajectory],
        *,
        max_alerts_per_1000: float = 50.0,
        name: str = "budget_global",
    ) -> OperatingPoint:
        scores = np.array([float(score_fn(t)) for t in traffic])
        if len(scores) == 0:
            thr = 0.5
        else:
            # Keep top (max_alerts_per_1000/1000) fraction
            keep_frac = min(1.0, max_alerts_per_1000 / 1000.0)
            thr = float(np.percentile(scores, 100 * (1 - keep_frac)))
        emp = sum(1 for s in scores if s >= thr) / max(1, len(scores))
        op = OperatingPoint(
            name=name,
            threshold=thr,
            max_alerts_per_1000=max_alerts_per_1000,
            n_calibration=len(scores),
            empirical_fpr=emp,
            notes=f"budget {max_alerts_per_1000}/1000",
        )
        self.points[name] = op
        self.history.append({"action": "fit_budget", **op.to_dict()})
        return op

    def fit_per_environment(
        self,
        score_fn: ScoreFn,
        benign: Sequence[AgentTrajectory],
        target_fpr: float = 0.05,
    ) -> dict[str, OperatingPoint]:
        by_env: dict[str, list[AgentTrajectory]] = {}
        for t in benign:
            by_env.setdefault(t.environment, []).append(t)
        out = {}
        for env, ts in by_env.items():
            op = self.fit_fpr(
                score_fn, ts, target_fpr=target_fpr,
                name=f"fpr_{env}", environment=env,
            )
            out[env] = op
        return out

    def drift_report(
        self,
        score_fn: ScoreFn,
        recent_benign: Sequence[AgentTrajectory],
        baseline: OperatingPoint,
    ) -> dict[str, Any]:
        scores = [float(score_fn(t)) for t in recent_benign]
        if not scores:
            return {"drift": False, "reason": "empty"}
        emp = sum(1 for s in scores if s >= baseline.threshold) / len(scores)
        target = baseline.target_fpr or baseline.empirical_fpr
        drift = abs(emp - target) > 0.03
        return {
            "drift": drift,
            "empirical_fpr": emp,
            "baseline_fpr": target,
            "threshold": baseline.threshold,
            "recommend": "shadow_recalibrate" if drift else "hold",
        }

    def rollback(self, name: str) -> OperatingPoint | None:
        # Find previous point with same name in history
        prev = [h for h in self.history if h.get("name") == name]
        if len(prev) < 2:
            return self.points.get(name)
        old = prev[-2]
        op = OperatingPoint(
            name=old["name"],
            threshold=old["threshold"],
            target_fpr=old.get("target_fpr"),
            max_alerts_per_1000=old.get("max_alerts_per_1000"),
            environment=old.get("environment", "global"),
            n_calibration=old.get("n_calibration", 0),
            empirical_fpr=old.get("empirical_fpr", 0),
            notes="rolled_back",
            version=str(float(old.get("version", "1.0")) + 0.1),
        )
        self.points[name] = op
        self.history.append({"action": "rollback", **op.to_dict()})
        return op
