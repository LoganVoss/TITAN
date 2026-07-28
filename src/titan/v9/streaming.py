"""
Durable, fail-closed streaming monitor for TITAN V9.

The monitor consumes observable ``AgentEvent`` objects and evaluates fixed
windows with an injected scorer. It never reads evaluation labels. Operational
failures are first-class safety signals: a scorer failure, invalid score,
ordering violation, integrity conflict, or ingestion rejection latches the
monitor into ``DEGRADED`` and emits a health alert.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
import hashlib
import hmac
import json
import math
import os
import threading
import time
import uuid

from ..schema import AgentEvent, AgentTrajectory
from .integrity import IntegritySignals


CHECKPOINT_SCHEMA = "titan.v9.streaming.checkpoint"
CHECKPOINT_VERSION = 2
LEGACY_CHECKPOINT_VERSION = 1
DEFAULT_CALLBACK_DEADLINE_MS = 1_000
MAX_CALLBACK_DEADLINE_MS = 60_000

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
QUIET = "QUIET"
WATCH = "WATCH"
ALERT = "ALERT"
CRITICAL = "CRITICAL"

ScoreFn = Callable[[AgentTrajectory], float]

_CALLBACK_OK = "OK"
_CALLBACK_ERROR = "ERROR"
_CALLBACK_TIMEOUT = "TIMEOUT"


class CheckpointIntegrityError(ValueError):
    """Raised when a checkpoint is malformed, incompatible, or corrupted."""


class StreamConfigurationError(ValueError):
    """Raised for an unsafe or internally inconsistent stream configuration."""


def _stable_json(value: Any) -> str:
    """Canonical JSON used for fingerprints and integrity digests."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StreamBaseline:
    """Frozen operating parameters for a streaming score."""

    center: float
    scale: float
    window_size: int
    step: int
    watch_z: float = 1.5
    alert_z: float = 2.5
    critical_z: float = 3.75

    def __post_init__(self) -> None:
        numeric = {
            "center": self.center,
            "scale": self.scale,
            "watch_z": self.watch_z,
            "alert_z": self.alert_z,
            "critical_z": self.critical_z,
        }
        for name, value in numeric.items():
            if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise StreamConfigurationError(f"{name} must be finite")
        if self.scale <= 0:
            raise StreamConfigurationError("scale must be > 0")
        if self.window_size <= 0:
            raise StreamConfigurationError("window_size must be > 0")
        if self.step <= 0:
            raise StreamConfigurationError("step must be > 0")
        if not (self.watch_z <= self.alert_z <= self.critical_z):
            raise StreamConfigurationError(
                "thresholds must satisfy watch_z <= alert_z <= critical_z"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StreamContext:
    """Action-time deployment context copied into scorer windows.

    Session-level existing-monitor scores are intentionally absent because
    they have no event boundary and may encode post-action outcomes or labels.
    """

    model_version: str = "unknown"
    environment: str = "default"
    task_family: str = "general"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "environment": self.environment,
            "task_family": self.task_family,
        }


@dataclass(frozen=True)
class StreamPoint:
    """One deterministic window decision."""

    sequence: int
    window_start: int
    window_end: int
    state: str
    score: float | None
    z_score: float | None
    evidence: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = [dict(item) for item in self.evidence]
        return value


@dataclass(frozen=True)
class StreamAlert:
    """Risk or monitor-health alert retained in a bounded audit buffer."""

    sequence: int
    kind: str  # RISK | HEALTH
    state: str
    code: str
    message: str
    at_cursor: int
    window_start: int | None = None
    window_end: int | None = None
    score: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _CallbackOutcome:
    status: str
    value: float | None = None
    error_type: str | None = None


def _default_counters() -> dict[str, int]:
    return {
        "update_calls": 0,
        "accepted_events": 0,
        "duplicate_events": 0,
        "rejected_events": 0,
        "order_violations": 0,
        "event_id_conflicts": 0,
        "invalid_events": 0,
        "scoring_failures": 0,
        "scorer_timeouts": 0,
        "nonfinite_scores": 0,
        "evidence_failures": 0,
        "evidence_timeouts": 0,
        "callback_timeouts": 0,
        "callback_circuit_rejections": 0,
        "windows_emitted": 0,
        "risk_alerts_emitted": 0,
        "health_alerts_emitted": 0,
        "timeline_evictions": 0,
        "alert_evictions": 0,
        "backpressure_rejections": 0,
        "checkpoint_restores": 0,
    }


class DurableStreamingMonitor:
    """
    Thread-safe streaming monitor with durable, integrity-checked state.

    Event indices are absolute accepted-event offsets. Exact replay of a known
    ``event_id`` is idempotent. Reuse of an ID with different content is treated
    as an integrity violation and fails closed.
    """

    def __init__(
        self,
        baseline: StreamBaseline,
        score_fn: ScoreFn,
        *,
        context: StreamContext | None = None,
        evidence_fns: Mapping[str, ScoreFn] | None = None,
        timeline_capacity: int = 1024,
        alert_capacity: int = 512,
        max_batch_events: int = 4096,
        callback_deadline_ms: int = DEFAULT_CALLBACK_DEADLINE_MS,
    ) -> None:
        if not callable(score_fn):
            raise StreamConfigurationError("score_fn must be callable")
        for name, value in {
            "timeline_capacity": timeline_capacity,
            "alert_capacity": alert_capacity,
            "max_batch_events": max_batch_events,
        }.items():
            if not isinstance(value, int) or value <= 0:
                raise StreamConfigurationError(f"{name} must be a positive integer")
        if (
            isinstance(callback_deadline_ms, bool)
            or not isinstance(callback_deadline_ms, int)
            or not 1 <= callback_deadline_ms <= MAX_CALLBACK_DEADLINE_MS
        ):
            raise StreamConfigurationError(
                "callback_deadline_ms must be an integer in "
                f"[1,{MAX_CALLBACK_DEADLINE_MS}]"
            )

        self.baseline = baseline
        self.score_fn = score_fn
        self.context = context or StreamContext()
        self.evidence_fns = dict(evidence_fns or {})
        if not all(isinstance(name, str) and callable(fn) for name, fn in self.evidence_fns.items()):
            raise StreamConfigurationError("evidence_fns must map names to callables")

        self.timeline_capacity = timeline_capacity
        self.alert_capacity = alert_capacity
        self.max_batch_events = max_batch_events
        self.callback_deadline_ms = callback_deadline_ms

        self._lock = threading.RLock()
        # Updates remain serial, but external callbacks never run while the
        # state lock is held. Health and checkpoint reads therefore remain
        # responsive even if a callback does not return.
        self._update_lock = threading.Lock()
        self._callback_lock = threading.Lock()
        self._active_callbacks = 0
        self._callback_circuit_open = False
        self._events: list[AgentEvent] = []
        self._buffer_start = 0
        self._absolute_cursor = 0
        self._next_window_start = 0
        self._last_timestamp: float | None = None
        self._event_fingerprints: dict[str, str] = {}
        self._timeline: deque[StreamPoint] = deque(maxlen=timeline_capacity)
        self._alerts: deque[StreamAlert] = deque(maxlen=alert_capacity)
        self._point_sequence = 0
        self._alert_sequence = 0
        self._degraded = False
        self._counters = _default_counters()
        self._last_batch_size = 0
        self._last_backpressure_status = "OK"

    @property
    def absolute_cursor(self) -> int:
        with self._lock:
            return self._absolute_cursor

    @property
    def health_state(self) -> str:
        with self._lock:
            return (
                DEGRADED
                if self._degraded or self._callback_circuit_open
                else HEALTHY
            )

    @property
    def timeline(self) -> list[StreamPoint]:
        with self._lock:
            return list(self._timeline)

    @property
    def alerts(self) -> list[StreamAlert]:
        with self._lock:
            return list(self._alerts)

    @property
    def health_alerts(self) -> list[StreamAlert]:
        with self._lock:
            return [alert for alert in self._alerts if alert.kind == "HEALTH"]

    def health(self) -> dict[str, Any]:
        with self._lock:
            return self._health_snapshot()

    def gateway_integrity_signals(
        self,
        base: IntegritySignals,
    ) -> IntegritySignals:
        """Merge stream health into a gateway-compatible integrity snapshot.

        The caller must supply the independently observed policy, registry,
        token-verifier, logger, and verifier signals. This adapter can only
        make that trusted snapshot less favorable: a degraded stream marks the
        logger and verifier paths unhealthy, and locally rejected events are
        added to the reported event-loss count.
        """

        if not isinstance(base, IntegritySignals):
            raise TypeError("base must be an IntegritySignals snapshot")
        with self._lock:
            degraded = self._degraded or self._callback_circuit_open
            rejected_events = self._counters["rejected_events"]
        with self._callback_lock:
            callback_in_flight = self._active_callbacks > 0
        degraded = degraded or callback_in_flight
        return IntegritySignals(
            observed_at_ms=base.observed_at_ms,
            event_loss_count=base.event_loss_count + rejected_events,
            max_event_delay_ms=base.max_event_delay_ms,
            logger_healthy=bool(base.logger_healthy and not degraded),
            policy_healthy=base.policy_healthy,
            registry_healthy=base.registry_healthy,
            verifier_healthy=bool(base.verifier_healthy and not degraded),
            token_verifier_healthy=base.token_verifier_healthy,
        )

    def update(self, events: Iterable[AgentEvent]) -> dict[str, Any]:
        """Atomically validate, deduplicate, append, and score one event batch."""
        batch = list(events)
        with self._update_lock:
            new_points: list[StreamPoint] = []
            new_alerts: list[StreamAlert] = []
            with self._lock:
                self._counters["update_calls"] += 1
                self._last_batch_size = len(batch)

                if self._callback_circuit_open:
                    self._counters["rejected_events"] += len(batch)
                    self._counters["callback_circuit_rejections"] += len(batch)
                    self._last_backpressure_status = "REJECTING"
                    self._emit_health_alert(
                        "CALLBACK_CIRCUIT_OPEN",
                        "ingestion rejected because a callback previously timed out",
                        new_alerts,
                        details={"batch_size": len(batch)},
                    )
                    return self._result(
                        new_points,
                        new_alerts,
                        accepted=0,
                        duplicates=0,
                    )

                if len(batch) > self.max_batch_events:
                    self._counters["rejected_events"] += len(batch)
                    self._counters["backpressure_rejections"] += 1
                    self._last_backpressure_status = "REJECTING"
                    self._emit_health_alert(
                        "BACKPRESSURE_REJECT",
                        "event batch exceeds configured ingestion limit",
                        new_alerts,
                        details={
                            "batch_size": len(batch),
                            "max_batch_events": self.max_batch_events,
                        },
                    )
                    return self._result(
                        new_points,
                        new_alerts,
                        accepted=0,
                        duplicates=0,
                    )

                self._last_backpressure_status = (
                    "HIGH"
                    if len(batch) >= max(1, int(self.max_batch_events * 0.8))
                    else "OK"
                )
                new_events: list[AgentEvent] = []
                pending_fingerprints: dict[str, str] = {}
                duplicates = 0

                for event in batch:
                    if not isinstance(event, AgentEvent):
                        self._counters["invalid_events"] += 1
                        self._counters["rejected_events"] += len(batch)
                        self._emit_health_alert(
                            "INVALID_EVENT",
                            "ingestion received a non-AgentEvent value",
                            new_alerts,
                        )
                        return self._result(
                            new_points,
                            new_alerts,
                            accepted=0,
                            duplicates=duplicates,
                        )
                    if not isinstance(event.event_id, str) or not event.event_id.strip():
                        self._counters["invalid_events"] += 1
                        self._counters["rejected_events"] += len(batch)
                        self._emit_health_alert(
                            "INVALID_EVENT_ID",
                            "event_id must be a non-empty string",
                            new_alerts,
                        )
                        return self._result(
                            new_points,
                            new_alerts,
                            accepted=0,
                            duplicates=duplicates,
                        )
                    try:
                        timestamp = float(event.timestamp)
                        if not math.isfinite(timestamp):
                            raise ValueError("non-finite timestamp")
                        fingerprint = _sha256(event.to_dict())
                    except (TypeError, ValueError, OverflowError):
                        self._counters["invalid_events"] += 1
                        self._counters["rejected_events"] += len(batch)
                        self._emit_health_alert(
                            "INVALID_EVENT",
                            "event timestamp and payload must be finite JSON values",
                            new_alerts,
                        )
                        return self._result(
                            new_points,
                            new_alerts,
                            accepted=0,
                            duplicates=duplicates,
                        )

                    known = self._event_fingerprints.get(event.event_id)
                    pending = pending_fingerprints.get(event.event_id)
                    if known is not None or pending is not None:
                        expected = known if known is not None else pending
                        if hmac.compare_digest(expected or "", fingerprint):
                            duplicates += 1
                            continue
                        self._counters["event_id_conflicts"] += 1
                        self._counters["rejected_events"] += len(batch)
                        self._emit_health_alert(
                            "EVENT_ID_CONFLICT",
                            "event_id was reused with different observable content",
                            new_alerts,
                            details={"event_id": event.event_id},
                        )
                        return self._result(
                            new_points,
                            new_alerts,
                            accepted=0,
                            duplicates=duplicates,
                        )

                    pending_fingerprints[event.event_id] = fingerprint
                    new_events.append(event)

                previous_timestamp = self._last_timestamp
                for event in new_events:
                    timestamp = float(event.timestamp)
                    if previous_timestamp is not None and timestamp < previous_timestamp:
                        self._counters["order_violations"] += 1
                        self._counters["rejected_events"] += len(new_events)
                        self._counters["duplicate_events"] += duplicates
                        self._emit_health_alert(
                            "EVENT_ORDER_VIOLATION",
                            "new event timestamps must be monotonically non-decreasing",
                            new_alerts,
                            details={
                                "previous_timestamp": previous_timestamp,
                                "received_timestamp": timestamp,
                            },
                        )
                        return self._result(
                            new_points,
                            new_alerts,
                            accepted=0,
                            duplicates=duplicates,
                        )
                    previous_timestamp = timestamp

                self._events.extend(new_events)
                self._event_fingerprints.update(pending_fingerprints)
                self._absolute_cursor += len(new_events)
                if new_events:
                    self._last_timestamp = float(new_events[-1].timestamp)
                self._counters["accepted_events"] += len(new_events)
                self._counters["duplicate_events"] += duplicates

            window = self.baseline.window_size
            while True:
                with self._lock:
                    if self._next_window_start + window > self._absolute_cursor:
                        break
                    local_start = self._next_window_start - self._buffer_start
                    local_end = local_start + window
                    if local_start < 0 or local_end > len(self._events):
                        self._emit_health_alert(
                            "INTERNAL_CURSOR_INVARIANT",
                            "stream cursor no longer maps to the retained event buffer",
                            new_alerts,
                        )
                        break
                    window_events = list(self._events[local_start:local_end])
                    window_start = self._next_window_start
                    window_end = self._next_window_start + window

                # External code runs outside the state lock. A separate update
                # lock preserves ingestion ordering while health/checkpoint
                # readers remain responsive.
                point = self._score_window(
                    window_events,
                    window_start,
                    window_end,
                    new_alerts,
                )
                with self._lock:
                    self._append_point(point)
                    new_points.append(point)
                    self._next_window_start += self.baseline.step
                    if self._callback_circuit_open:
                        break

            with self._lock:
                self._trim_buffer()
                return self._result(
                    new_points,
                    new_alerts,
                    accepted=len(new_events),
                    duplicates=duplicates,
                )

    def checkpoint(self) -> dict[str, Any]:
        """Return a JSON-serializable checkpoint protected by a SHA-256 digest."""
        with self._lock:
            body = {
                "schema": CHECKPOINT_SCHEMA,
                "version": CHECKPOINT_VERSION,
                "config": {
                    "baseline": self.baseline.to_dict(),
                    "context": self.context.to_dict(),
                    "timeline_capacity": self.timeline_capacity,
                    "alert_capacity": self.alert_capacity,
                    "max_batch_events": self.max_batch_events,
                    "callback_deadline_ms": self.callback_deadline_ms,
                    "evidence_names": list(self.evidence_fns),
                },
                "state": {
                    "events": [event.to_dict() for event in self._events],
                    "buffer_start": self._buffer_start,
                    "absolute_cursor": self._absolute_cursor,
                    "next_window_start": self._next_window_start,
                    "last_timestamp": self._last_timestamp,
                    "event_fingerprints": dict(self._event_fingerprints),
                    "timeline": [point.to_dict() for point in self._timeline],
                    "alerts": [alert.to_dict() for alert in self._alerts],
                    "point_sequence": self._point_sequence,
                    "alert_sequence": self._alert_sequence,
                    "degraded": self._degraded,
                    "callback_circuit_open": self._callback_circuit_open,
                    "counters": dict(self._counters),
                    "last_batch_size": self._last_batch_size,
                    "last_backpressure_status": self._last_backpressure_status,
                },
            }
            return {
                **body,
                "integrity": {
                    "algorithm": "sha256",
                    "digest": _sha256(body),
                },
            }

    def save_checkpoint(self, path: str | Path) -> None:
        """Atomically persist a mode-0600 checkpoint."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = (_stable_json(self.checkpoint()) + "\n").encode("utf-8")
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            try:
                directory_fd = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Some filesystems do not permit directory fsync.
                pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    @classmethod
    def load_checkpoint(
        cls,
        path: str | Path,
        score_fn: ScoreFn,
        *,
        evidence_fns: Mapping[str, ScoreFn] | None = None,
        max_checkpoint_bytes: int = 64 * 1024 * 1024,
    ) -> "DurableStreamingMonitor":
        source = Path(path)
        if source.stat().st_size > max_checkpoint_bytes:
            raise CheckpointIntegrityError("checkpoint exceeds configured size limit")
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CheckpointIntegrityError("checkpoint is not readable JSON") from exc
        return cls.from_checkpoint(value, score_fn, evidence_fns=evidence_fns)

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: Mapping[str, Any],
        score_fn: ScoreFn,
        *,
        evidence_fns: Mapping[str, ScoreFn] | None = None,
    ) -> "DurableStreamingMonitor":
        """Verify and restore a checkpoint without trusting serialized state."""
        if not isinstance(checkpoint, Mapping):
            raise CheckpointIntegrityError("checkpoint must be an object")
        value = dict(checkpoint)
        integrity = value.pop("integrity", None)
        if not isinstance(integrity, Mapping) or integrity.get("algorithm") != "sha256":
            raise CheckpointIntegrityError("checkpoint integrity metadata is missing")
        expected = integrity.get("digest")
        if not isinstance(expected, str):
            raise CheckpointIntegrityError("checkpoint digest is missing")
        try:
            actual = _sha256(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise CheckpointIntegrityError("checkpoint is not canonical JSON") from exc
        if not hmac.compare_digest(expected, actual):
            raise CheckpointIntegrityError("checkpoint integrity digest mismatch")
        if value.get("schema") != CHECKPOINT_SCHEMA:
            raise CheckpointIntegrityError("unsupported checkpoint schema")
        checkpoint_version = value.get("version")
        if (
            isinstance(checkpoint_version, bool)
            or not isinstance(checkpoint_version, int)
            or checkpoint_version
            not in (LEGACY_CHECKPOINT_VERSION, CHECKPOINT_VERSION)
        ):
            raise CheckpointIntegrityError("unsupported checkpoint version")

        try:
            config = value["config"]
            state = value["state"]
            raw_callback_deadline = config.get(
                "callback_deadline_ms",
                DEFAULT_CALLBACK_DEADLINE_MS,
            )
            if (
                isinstance(raw_callback_deadline, bool)
                or not isinstance(raw_callback_deadline, int)
            ):
                raise CheckpointIntegrityError(
                    "checkpoint callback deadline is malformed"
                )
            baseline = StreamBaseline(**config["baseline"])
            raw_context = dict(config["context"])
            # V1/V2 checkpoints may contain this unbounded session-level
            # channel. Discard it instead of restoring a possible post-action
            # label proxy into the online callback view.
            raw_context.pop("existing_monitor_scores", None)
            context = StreamContext(**raw_context)
            monitor = cls(
                baseline,
                score_fn,
                context=context,
                evidence_fns=evidence_fns,
                timeline_capacity=int(config["timeline_capacity"]),
                alert_capacity=int(config["alert_capacity"]),
                max_batch_events=int(config["max_batch_events"]),
                callback_deadline_ms=raw_callback_deadline,
            )
            serialized_evidence = list(config.get("evidence_names", []))
            if serialized_evidence != list(monitor.evidence_fns):
                raise CheckpointIntegrityError(
                    "checkpoint evidence functions do not match restore configuration"
                )

            events = [AgentEvent.from_dict(item) for item in state["events"]]
            buffer_start = int(state["buffer_start"])
            absolute_cursor = int(state["absolute_cursor"])
            next_window_start = int(state["next_window_start"])
            last_timestamp = state.get("last_timestamp")
            if last_timestamp is not None:
                last_timestamp = float(last_timestamp)
            fingerprints = {
                str(key): str(fingerprint)
                for key, fingerprint in dict(state["event_fingerprints"]).items()
            }
            timeline = [
                StreamPoint(
                    sequence=int(item["sequence"]),
                    window_start=int(item["window_start"]),
                    window_end=int(item["window_end"]),
                    state=str(item["state"]),
                    score=None if item.get("score") is None else float(item["score"]),
                    z_score=None if item.get("z_score") is None else float(item["z_score"]),
                    evidence=tuple(dict(part) for part in item.get("evidence", [])),
                )
                for item in state.get("timeline", [])
            ]
            alerts = [
                StreamAlert(
                    sequence=int(item["sequence"]),
                    kind=str(item["kind"]),
                    state=str(item["state"]),
                    code=str(item["code"]),
                    message=str(item["message"]),
                    at_cursor=int(item["at_cursor"]),
                    window_start=(
                        None if item.get("window_start") is None else int(item["window_start"])
                    ),
                    window_end=None if item.get("window_end") is None else int(item["window_end"]),
                    score=None if item.get("score") is None else float(item["score"]),
                    details=dict(item.get("details", {})),
                )
                for item in state.get("alerts", [])
            ]
            callback_circuit_open = state.get("callback_circuit_open", False)
            if not isinstance(callback_circuit_open, bool):
                raise CheckpointIntegrityError(
                    "checkpoint callback circuit state is malformed"
                )
        except CheckpointIntegrityError:
            raise
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise CheckpointIntegrityError("checkpoint state is malformed") from exc

        if buffer_start < 0 or absolute_cursor < buffer_start:
            raise CheckpointIntegrityError("invalid absolute cursor range")
        if buffer_start + len(events) != absolute_cursor:
            raise CheckpointIntegrityError("event buffer does not match absolute cursor")
        if next_window_start < buffer_start or next_window_start % baseline.step != 0:
            raise CheckpointIntegrityError("invalid next window cursor")
        if last_timestamp is not None and not math.isfinite(last_timestamp):
            raise CheckpointIntegrityError("invalid last timestamp")
        if len(timeline) > monitor.timeline_capacity or len(alerts) > monitor.alert_capacity:
            raise CheckpointIntegrityError("retained history exceeds configured capacity")

        previous: float | None = None
        for event in events:
            timestamp = float(event.timestamp)
            if not math.isfinite(timestamp) or (previous is not None and timestamp < previous):
                raise CheckpointIntegrityError("checkpoint events are not monotonically ordered")
            previous = timestamp
            fingerprint = fingerprints.get(event.event_id)
            if fingerprint is None or not hmac.compare_digest(fingerprint, _sha256(event.to_dict())):
                raise CheckpointIntegrityError("checkpoint event fingerprint mismatch")
        if events and last_timestamp is not None and float(events[-1].timestamp) > last_timestamp:
            raise CheckpointIntegrityError("last timestamp predates retained events")

        counters = _default_counters()
        raw_counters = dict(state.get("counters", {}))
        for name in counters:
            raw = raw_counters.get(name, counters[name])
            if not isinstance(raw, int) or raw < 0:
                raise CheckpointIntegrityError(f"invalid counter {name}")
            counters[name] = raw
        if counters["accepted_events"] != absolute_cursor:
            raise CheckpointIntegrityError("accepted-event counter does not match cursor")

        with monitor._lock:
            monitor._events = events
            monitor._buffer_start = buffer_start
            monitor._absolute_cursor = absolute_cursor
            monitor._next_window_start = next_window_start
            monitor._last_timestamp = last_timestamp
            monitor._event_fingerprints = fingerprints
            monitor._timeline = deque(timeline, maxlen=monitor.timeline_capacity)
            monitor._alerts = deque(alerts, maxlen=monitor.alert_capacity)
            monitor._point_sequence = int(state.get("point_sequence", len(timeline)))
            monitor._alert_sequence = int(state.get("alert_sequence", len(alerts)))
            monitor._degraded = bool(state.get("degraded", False))
            monitor._callback_circuit_open = callback_circuit_open
            monitor._counters = counters
            monitor._counters["checkpoint_restores"] += 1
            monitor._last_batch_size = int(state.get("last_batch_size", 0))
            monitor._last_backpressure_status = str(
                state.get("last_backpressure_status", "OK")
            )
        return monitor

    def _window_trajectory(
        self,
        events: list[AgentEvent],
        start: int,
        end: int,
    ) -> AgentTrajectory:
        # AgentTrajectory defaults to UNKNOWN evaluation regime. This module
        # deliberately does not read or copy any ground-truth label. Each
        # callback receives a deep event snapshot so a timed-out worker cannot
        # mutate retained stream state or another verifier's input.
        return AgentTrajectory(
            trajectory_id=f"v9_stream_window_{start}_{end}",
            events=[AgentEvent.from_dict(event.to_dict()) for event in events],
            model_version=self.context.model_version,
            environment=self.context.environment,
            task_family=self.context.task_family,
            existing_monitor_scores={},
        )

    def _run_callback(
        self,
        function: ScoreFn,
        trajectory: AgentTrajectory,
    ) -> _CallbackOutcome:
        """Run untrusted callback code on a daemon worker with a hard deadline.

        Python cannot safely terminate an arbitrary thread. On timeout the
        worker is abandoned as a daemon and the global callback circuit opens,
        ensuring the monitor starts at most one such runaway worker.
        """

        completed = threading.Event()
        result: dict[str, Any] = {}

        def invoke() -> None:
            try:
                result["value"] = float(function(trajectory))
            except BaseException as exc:
                # Error messages and tracebacks can contain sensitive callback
                # data; only the exception class crosses the worker boundary.
                result["error_type"] = type(exc).__name__
            finally:
                with self._callback_lock:
                    self._active_callbacks -= 1
                completed.set()

        with self._callback_lock:
            self._active_callbacks += 1
        worker = threading.Thread(
            target=invoke,
            name="titan-v9-stream-callback",
            daemon=True,
        )
        try:
            worker.start()
        except BaseException as exc:
            with self._callback_lock:
                self._active_callbacks -= 1
            return _CallbackOutcome(
                status=_CALLBACK_ERROR,
                error_type=type(exc).__name__,
            )

        if not completed.wait(self.callback_deadline_ms / 1_000.0):
            return _CallbackOutcome(status=_CALLBACK_TIMEOUT)
        if "error_type" in result:
            return _CallbackOutcome(
                status=_CALLBACK_ERROR,
                error_type=str(result["error_type"]),
            )
        return _CallbackOutcome(
            status=_CALLBACK_OK,
            value=float(result["value"]),
        )

    def _score_window(
        self,
        events: list[AgentEvent],
        start: int,
        end: int,
        new_alerts: list[StreamAlert],
    ) -> StreamPoint:
        evidence: list[dict[str, Any]] = []
        score_outcome = self._run_callback(
            self.score_fn,
            self._window_trajectory(events, start, end),
        )
        if score_outcome.status == _CALLBACK_TIMEOUT:
            with self._lock:
                self._counters["scoring_failures"] += 1
                self._counters["scorer_timeouts"] += 1
                self._counters["callback_timeouts"] += 1
                self._callback_circuit_open = True
                self._emit_health_alert(
                    "SCORER_TIMEOUT",
                    "primary stream scorer exceeded its callback deadline",
                    new_alerts,
                    window_start=start,
                    window_end=end,
                    details={"deadline_ms": self.callback_deadline_ms},
                )
                return self._new_point(
                    start,
                    end,
                    DEGRADED,
                    None,
                    None,
                    evidence,
                )
        if score_outcome.status == _CALLBACK_ERROR:
            with self._lock:
                self._counters["scoring_failures"] += 1
                self._emit_health_alert(
                    "SCORER_EXCEPTION",
                    "primary stream scorer raised an exception",
                    new_alerts,
                    window_start=start,
                    window_end=end,
                    details={"error_type": score_outcome.error_type or "Exception"},
                )
                return self._new_point(
                    start,
                    end,
                    DEGRADED,
                    None,
                    None,
                    evidence,
                )

        assert score_outcome.value is not None
        score = score_outcome.value
        if not math.isfinite(score):
            with self._lock:
                self._counters["nonfinite_scores"] += 1
                self._emit_health_alert(
                    "SCORER_NONFINITE",
                    "primary stream scorer returned a non-finite value",
                    new_alerts,
                    window_start=start,
                    window_end=end,
                )
                return self._new_point(
                    start,
                    end,
                    DEGRADED,
                    None,
                    None,
                    evidence,
                )

        evidence.append({"name": "primary_score", "value": score})
        evidence_degraded = False
        for name, function in self.evidence_fns.items():
            outcome = self._run_callback(
                function,
                self._window_trajectory(events, start, end),
            )
            if outcome.status == _CALLBACK_TIMEOUT:
                evidence_degraded = True
                with self._lock:
                    self._counters["evidence_failures"] += 1
                    self._counters["evidence_timeouts"] += 1
                    self._counters["callback_timeouts"] += 1
                    self._callback_circuit_open = True
                    self._emit_health_alert(
                        "EVIDENCE_TIMEOUT",
                        "stream evidence function exceeded its callback deadline",
                        new_alerts,
                        window_start=start,
                        window_end=end,
                        details={
                            "evidence_name": name,
                            "deadline_ms": self.callback_deadline_ms,
                        },
                    )
                break
            if outcome.status == _CALLBACK_ERROR:
                evidence_degraded = True
                with self._lock:
                    self._counters["evidence_failures"] += 1
                    self._emit_health_alert(
                        "EVIDENCE_FAILURE",
                        "stream evidence function failed",
                        new_alerts,
                        window_start=start,
                        window_end=end,
                        details={
                            "evidence_name": name,
                            "error_type": outcome.error_type or "Exception",
                        },
                    )
                continue
            assert outcome.value is not None
            if not math.isfinite(outcome.value):
                evidence_degraded = True
                with self._lock:
                    self._counters["evidence_failures"] += 1
                    self._emit_health_alert(
                        "EVIDENCE_FAILURE",
                        "stream evidence function failed",
                        new_alerts,
                        window_start=start,
                        window_end=end,
                        details={
                            "evidence_name": name,
                            "error_type": "NonFiniteValue",
                        },
                    )
                continue
            evidence.append({"name": name, "value": outcome.value})

        z_score = (score - self.baseline.center) / self.baseline.scale
        if evidence_degraded:
            state = DEGRADED
        elif z_score >= self.baseline.critical_z:
            state = CRITICAL
        elif z_score >= self.baseline.alert_z:
            state = ALERT
        elif z_score >= self.baseline.watch_z:
            state = WATCH
        else:
            state = QUIET

        with self._lock:
            point = self._new_point(start, end, state, score, z_score, evidence)
            if state in (ALERT, CRITICAL):
                self._emit_risk_alert(point, new_alerts)
            return point

    def _new_point(
        self,
        start: int,
        end: int,
        state: str,
        score: float | None,
        z_score: float | None,
        evidence: list[dict[str, Any]],
    ) -> StreamPoint:
        point = StreamPoint(
            sequence=self._point_sequence,
            window_start=start,
            window_end=end,
            state=state,
            score=score,
            z_score=z_score,
            evidence=tuple(dict(item) for item in evidence),
        )
        self._point_sequence += 1
        self._counters["windows_emitted"] += 1
        return point

    def _emit_risk_alert(
        self,
        point: StreamPoint,
        new_alerts: list[StreamAlert],
    ) -> None:
        alert = StreamAlert(
            sequence=self._alert_sequence,
            kind="RISK",
            state=point.state,
            code=f"RISK_{point.state}",
            message="stream score crossed a risk threshold",
            at_cursor=self._absolute_cursor,
            window_start=point.window_start,
            window_end=point.window_end,
            score=point.score,
        )
        self._alert_sequence += 1
        self._counters["risk_alerts_emitted"] += 1
        self._append_alert(alert)
        new_alerts.append(alert)

    def _emit_health_alert(
        self,
        code: str,
        message: str,
        new_alerts: list[StreamAlert],
        *,
        window_start: int | None = None,
        window_end: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._degraded = True
        alert = StreamAlert(
            sequence=self._alert_sequence,
            kind="HEALTH",
            state=DEGRADED,
            code=code,
            message=message,
            at_cursor=self._absolute_cursor,
            window_start=window_start,
            window_end=window_end,
            details=dict(details or {}),
        )
        self._alert_sequence += 1
        self._counters["health_alerts_emitted"] += 1
        self._append_alert(alert)
        new_alerts.append(alert)

    def _append_point(self, point: StreamPoint) -> None:
        if len(self._timeline) == self.timeline_capacity:
            self._counters["timeline_evictions"] += 1
        self._timeline.append(point)

    def _append_alert(self, alert: StreamAlert) -> None:
        if len(self._alerts) == self.alert_capacity:
            self._counters["alert_evictions"] += 1
        self._alerts.append(alert)

    def _trim_buffer(self) -> None:
        # Events before the next window start can never be used again. If the
        # step skips ahead, discard only up to the accepted-event cursor.
        safe_before = min(self._next_window_start, self._absolute_cursor)
        drop = safe_before - self._buffer_start
        if drop > 0:
            del self._events[:drop]
            self._buffer_start += drop

    def _backpressure_snapshot(self) -> dict[str, Any]:
        return {
            "status": self._last_backpressure_status,
            "last_batch_size": self._last_batch_size,
            "max_batch_events": self.max_batch_events,
            "pending_events": len(self._events),
            "timeline_retained": len(self._timeline),
            "timeline_capacity": self.timeline_capacity,
            "alerts_retained": len(self._alerts),
            "alert_capacity": self.alert_capacity,
        }

    def _health_snapshot(self) -> dict[str, Any]:
        with self._callback_lock:
            active_callbacks = self._active_callbacks
        degraded = self._degraded or self._callback_circuit_open
        return {
            "state": DEGRADED if degraded else HEALTHY,
            "fail_closed": degraded,
            "absolute_cursor": self._absolute_cursor,
            "buffer_start": self._buffer_start,
            "next_window_start": self._next_window_start,
            "last_timestamp": self._last_timestamp,
            "counters": dict(self._counters),
            "backpressure": self._backpressure_snapshot(),
            "callbacks": {
                "deadline_ms": self.callback_deadline_ms,
                "active": active_callbacks,
                "circuit_open": self._callback_circuit_open,
            },
        }

    def _result(
        self,
        points: list[StreamPoint],
        alerts: list[StreamAlert],
        *,
        accepted: int,
        duplicates: int,
    ) -> dict[str, Any]:
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "new_points": [point.to_dict() for point in points],
            "new_alerts": [alert.to_dict() for alert in alerts],
            "health": self._health_snapshot(),
        }


# Clear names for callers migrating from the V1 monitor.
StreamingMonitorV9 = DurableStreamingMonitor
