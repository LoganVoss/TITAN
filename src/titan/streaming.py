"""
Streaming safety monitor with correct buffer-offset handling.

Alert strength is a heuristic pressure score — NOT a calibrated probability.
Baseline support reflects how much clean traffic informed the baseline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable

import numpy as np

from .config import BUFFER_KEEP_WINDOWS, DEFAULT_STEP_EVENTS, DEFAULT_WINDOW_EVENTS
from .schema import AgentEvent, AgentTrajectory, Label


ScoreFn = Callable[[AgentTrajectory], float]


@dataclass
class StreamPoint:
    """One window measurement on the event stream."""

    index: int
    window_start: int  # absolute event index (never resets)
    window_end: int    # absolute event index (exclusive)
    alert_strength: float
    baseline_support: float
    state: str  # quiet | watch | alert | critical
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StreamAlert:
    index: int
    window_end: int
    severity: str
    alert_strength: float
    baseline_support: float
    trigger: str
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StreamBaseline:
    """Baseline of alert_strength under clean (benign) traffic."""

    center: float
    scale: float
    quantiles: dict[str, float]
    n_windows: int
    window_size: int
    step: int

    @property
    def baseline_support(self) -> float:
        """How much clean data supports the baseline (0–1), not a CI width."""
        return float(min(1.0, self.n_windows / 30.0))


def _window_trajectory(
    events: list[AgentEvent],
    start: int,
    end: int,
    template: AgentTrajectory | None = None,
) -> AgentTrajectory:
    base = template
    return AgentTrajectory(
        trajectory_id=f"window_{start}_{end}",
        events=events[start:end],
        label=Label.UNKNOWN,
        model_version=base.model_version if base else "unknown",
        environment=base.environment if base else "default",
        task_family=base.task_family if base else "general",
        existing_monitor_scores=dict(base.existing_monitor_scores) if base else {},
    )


def build_stream_baseline(
    benign_trajectories: list[AgentTrajectory],
    score_fn: ScoreFn,
    *,
    window_size: int = DEFAULT_WINDOW_EVENTS,
    step: int = DEFAULT_STEP_EVENTS,
) -> StreamBaseline:
    """Fit baseline alert_strength distribution on clean trajectories only."""
    scores: list[float] = []
    for t in benign_trajectories:
        if len(t.events) < window_size:
            try:
                scores.append(float(score_fn(t)))
            except Exception:
                scores.append(0.0)
            continue
        for start in range(0, len(t.events) - window_size + 1, step):
            wt = _window_trajectory(t.events, start, start + window_size, t)
            try:
                scores.append(float(score_fn(wt)))
            except Exception:
                scores.append(0.0)

    arr = np.asarray(scores if scores else [0.0], dtype=float)
    center = float(np.median(arr))
    scale = float(np.median(np.abs(arr - center)) * 1.4826)
    scale = max(scale, 1e-6)
    quantiles = {
        "p50": float(np.percentile(arr, 50)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
    }
    return StreamBaseline(
        center=center,
        scale=scale,
        quantiles=quantiles,
        n_windows=len(arr),
        window_size=window_size,
        step=step,
    )


def _state_from_z(z: float, watch_z: float, alert_z: float) -> str:
    if z >= alert_z * 1.5:
        return "critical"
    if z >= alert_z:
        return "alert"
    if z >= watch_z:
        return "watch"
    return "quiet"


class StreamingMonitor:
    """
    Stateful streaming monitor with ABSOLUTE event indices.

    After buffer truncation, ``_last_emit_end`` stays in the global coordinate
    system so emission never stalls.
    """

    def __init__(
        self,
        baseline: StreamBaseline,
        score_fn: ScoreFn,
        *,
        watch_z: float = 1.5,
        alert_z: float = 2.5,
        evidence_fns: dict[str, ScoreFn] | None = None,
    ):
        self.baseline = baseline
        self.score_fn = score_fn
        self.watch_z = watch_z
        self.alert_z = alert_z
        self.evidence_fns = evidence_fns or {}

        self._events: list[AgentEvent] = []
        self._absolute_start = 0  # absolute index of events[0]
        self._samples_seen = 0
        self._last_emit_end = 0   # absolute event index
        self._timeline: list[StreamPoint] = []
        self._alerts: list[StreamAlert] = []

    @property
    def timeline(self) -> list[StreamPoint]:
        return list(self._timeline)

    @property
    def alerts(self) -> list[StreamAlert]:
        return list(self._alerts)

    def update(
        self,
        events: list[AgentEvent],
        *,
        template: AgentTrajectory | None = None,
    ) -> dict[str, Any]:
        """Append events and emit any new window points / alerts."""
        if not events:
            return {"new_points": [], "new_alerts": []}

        self._events.extend(events)
        self._samples_seen += len(events)

        window = self.baseline.window_size
        step = self.baseline.step
        new_points: list[StreamPoint] = []
        new_alerts: list[StreamAlert] = []

        # Absolute end of buffer
        abs_end = self._absolute_start + len(self._events)
        # First window end we might emit
        # Windows are [abs_start, abs_start+window) stepping by step
        # We need windows whose end > _last_emit_end
        if len(self._events) < window:
            return {"new_points": [], "new_alerts": [], "samples_seen": self._samples_seen}

        # Local indices for windows
        local_max_start = len(self._events) - window
        for local_start in range(0, local_max_start + 1, step):
            abs_window_start = self._absolute_start + local_start
            abs_window_end = abs_window_start + window
            if abs_window_end <= self._last_emit_end:
                continue

            wt = _window_trajectory(self._events, local_start, local_start + window, template)
            try:
                strength = float(self.score_fn(wt))
            except Exception:
                strength = 0.0
            z = (strength - self.baseline.center) / self.baseline.scale
            state = _state_from_z(z, self.watch_z, self.alert_z)
            evidence = self._evidence(wt, strength)

            point = StreamPoint(
                index=len(self._timeline) + len(new_points),
                window_start=abs_window_start,
                window_end=abs_window_end,
                alert_strength=strength,
                baseline_support=self.baseline.baseline_support,
                state=state,
                evidence=evidence,
            )
            new_points.append(point)
            self._last_emit_end = abs_window_end

            if state in ("alert", "critical", "watch"):
                sev = "high" if state == "critical" else ("medium" if state == "alert" else "low")
                alert = StreamAlert(
                    index=point.index,
                    window_end=abs_window_end,
                    severity=sev,
                    alert_strength=strength,
                    baseline_support=self.baseline.baseline_support,
                    trigger=f"z={z:.2f} state={state}",
                    evidence=evidence,
                )
                if state in ("alert", "critical"):
                    new_alerts.append(alert)

        self._timeline.extend(new_points)
        self._alerts.extend(new_alerts)

        # Truncate buffer but KEEP absolute coordinates correct
        keep = max(window * BUFFER_KEEP_WINDOWS, window + step)
        if len(self._events) > keep:
            drop = len(self._events) - keep
            self._events = self._events[drop:]
            self._absolute_start += drop
            # _last_emit_end is absolute — do NOT subtract; it stays valid

        return {
            "new_points": [p.to_dict() for p in new_points],
            "new_alerts": [a.to_dict() for a in new_alerts],
            "samples_seen": self._samples_seen,
            "absolute_start": self._absolute_start,
            "last_emit_end": self._last_emit_end,
            "buffer_len": len(self._events),
        }

    def _evidence(self, wt: AgentTrajectory, strength: float) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = [{"name": "alert_strength", "value": strength}]
        for name, fn in list(self.evidence_fns.items())[:6]:
            try:
                items.append({"name": name, "value": float(fn(wt))})
            except Exception:
                pass
        return items


def aggregate_scorer(
    candidates: list[Any],
    aggregation: str = "max",
) -> ScoreFn:
    """Build a single score_fn from CandidateMonitor / RegistryEntry list."""

    def score(t: AgentTrajectory) -> float:
        vals = []
        for c in candidates:
            try:
                vals.append(float(c.score(t)))
            except Exception:
                pass
        if not vals:
            return 0.0
        if aggregation == "mean":
            return float(sum(vals) / len(vals))
        return float(max(vals))

    return score
