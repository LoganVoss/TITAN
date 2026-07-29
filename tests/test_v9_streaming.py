"""Safety and durability invariants for the TITAN V9 streaming boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import math
import os
import threading
import time

import pytest

from titan.schema import AgentEvent, EventType
from titan.v9.integrity import ControlPlaneIntegrityPolicy, IntegritySignals
from titan.v9.streaming import (
    ALERT,
    DEFAULT_CALLBACK_DEADLINE_MS,
    DEGRADED,
    HEALTHY,
    CheckpointIntegrityError,
    DurableStreamingMonitor,
    StreamBaseline,
    StreamConfigurationError,
    StreamContext,
)


def event(index: int, *, event_id: str | None = None, timestamp: float | None = None) -> AgentEvent:
    return AgentEvent(
        event_type=EventType.TOOL_CALL,
        timestamp=float(index if timestamp is None else timestamp),
        actor="agent",
        payload={"tool": "safe_tool", "ordinal": index},
        event_id=event_id or f"event-{index}",
    )


def baseline(*, window: int = 3, step: int = 1) -> StreamBaseline:
    return StreamBaseline(
        center=0.0,
        scale=1.0,
        window_size=window,
        step=step,
        watch_z=1.0,
        alert_z=2.0,
        critical_z=3.0,
    )


def rehash_checkpoint(checkpoint):
    body = {
        key: value
        for key, value in checkpoint.items()
        if key != "integrity"
    }
    serialized = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    checkpoint["integrity"]["digest"] = hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize("bad_score", [math.nan, math.inf, -math.inf])
def test_nonfinite_scorer_is_explicitly_degraded_and_never_quiet(bad_score):
    monitor = DurableStreamingMonitor(baseline(), lambda _: bad_score)

    result = monitor.update([event(0), event(1), event(2)])

    assert result["new_points"][0]["state"] == DEGRADED
    assert result["new_points"][0]["score"] is None
    assert result["health"]["state"] == DEGRADED
    assert result["health"]["fail_closed"] is True
    assert result["new_alerts"][0]["kind"] == "HEALTH"
    assert result["new_alerts"][0]["code"] == "SCORER_NONFINITE"


def test_scorer_exception_latches_fail_closed_health_state():
    def broken(_):
        raise RuntimeError("secret details must not escape")

    monitor = DurableStreamingMonitor(baseline(), broken)
    result = monitor.update([event(0), event(1), event(2)])

    assert result["new_points"][0]["state"] == DEGRADED
    assert result["new_alerts"][0]["code"] == "SCORER_EXCEPTION"
    assert result["new_alerts"][0]["details"] == {"error_type": "RuntimeError"}
    assert "secret details" not in str(result)
    assert monitor.health_state == DEGRADED


def test_exact_event_replay_is_idempotent():
    monitor = DurableStreamingMonitor(baseline(window=2), lambda t: float(len(t.events)))
    original = [event(0), event(1), event(2)]

    first = monitor.update(original)
    replay = monitor.update(original)

    assert first["accepted"] == 3
    assert replay["accepted"] == 0
    assert replay["duplicates"] == 3
    assert replay["new_points"] == []
    assert monitor.absolute_cursor == 3
    assert monitor.health_state == HEALTHY


def test_reused_event_id_with_changed_content_fails_closed_atomically():
    monitor = DurableStreamingMonitor(baseline(window=2), lambda _: 0.0)
    monitor.update([event(0, event_id="same")])
    conflict = event(1, event_id="same")

    result = monitor.update([conflict])

    assert result["accepted"] == 0
    assert monitor.absolute_cursor == 1
    assert result["new_alerts"][0]["code"] == "EVENT_ID_CONFLICT"
    assert result["health"]["fail_closed"] is True


def test_new_events_must_be_monotonically_ordered_but_old_replay_is_allowed():
    monitor = DurableStreamingMonitor(baseline(window=2), lambda _: 0.0)
    old = event(10, event_id="old", timestamp=10.0)
    monitor.update([old])

    replay = monitor.update([old])
    assert replay["duplicates"] == 1
    assert monitor.health_state == HEALTHY

    result = monitor.update([event(9, event_id="new-but-old", timestamp=9.0)])
    assert result["accepted"] == 0
    assert result["new_alerts"][0]["code"] == "EVENT_ORDER_VIOLATION"
    assert monitor.absolute_cursor == 1
    assert monitor.health_state == DEGRADED


def test_absolute_cursor_and_window_lattice_survive_buffer_trimming():
    monitor = DurableStreamingMonitor(
        baseline(window=4, step=2),
        lambda t: float(len(t.events)),
        timeline_capacity=100,
    )
    ends = []
    for start in range(0, 60, 3):
        result = monitor.update([event(i) for i in range(start, start + 3)])
        ends.extend(point["window_end"] for point in result["new_points"])

    assert monitor.absolute_cursor == 60
    assert ends == list(range(4, 61, 2))
    assert all(b - a == 2 for a, b in zip(ends, ends[1:]))
    assert monitor.health()["backpressure"]["pending_events"] < 4


def test_timeline_and_alert_retention_are_bounded():
    monitor = DurableStreamingMonitor(
        baseline(window=1, step=1),
        lambda _: 2.5,
        timeline_capacity=3,
        alert_capacity=2,
    )
    monitor.update([event(i) for i in range(8)])

    assert len(monitor.timeline) == 3
    assert len(monitor.alerts) == 2
    counters = monitor.health()["counters"]
    assert counters["timeline_evictions"] == 5
    assert counters["alert_evictions"] == 6
    assert all(point.state == ALERT for point in monitor.timeline)


def test_checkpoint_restore_is_integrity_checked_and_replay_idempotent(tmp_path):
    scorer = lambda t: float(len(t.events))
    monitor = DurableStreamingMonitor(baseline(window=3, step=2), scorer)
    original = [event(i) for i in range(7)]
    monitor.update(original)
    checkpoint_path = tmp_path / "stream.checkpoint.json"
    monitor.save_checkpoint(checkpoint_path)

    assert os.stat(checkpoint_path).st_mode & 0o077 == 0
    restored = DurableStreamingMonitor.load_checkpoint(checkpoint_path, scorer)
    replay = restored.update(original)
    continued = restored.update([event(7), event(8)])

    assert replay["accepted"] == 0
    assert replay["duplicates"] == len(original)
    assert continued["accepted"] == 2
    assert restored.absolute_cursor == 9
    assert restored.health()["counters"]["checkpoint_restores"] == 1
    ends = [point.window_end for point in restored.timeline]
    assert ends == [3, 5, 7, 9]

    tampered = copy.deepcopy(monitor.checkpoint())
    tampered["state"]["absolute_cursor"] += 1
    with pytest.raises(CheckpointIntegrityError, match="digest mismatch"):
        DurableStreamingMonitor.from_checkpoint(tampered, scorer)


def test_concurrent_exact_replay_accepts_once_without_corrupting_state():
    monitor = DurableStreamingMonitor(baseline(window=2), lambda _: 0.0)
    batch = [event(0), event(1), event(2)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: monitor.update(batch), range(16)))

    assert sum(result["accepted"] for result in results) == len(batch)
    assert monitor.absolute_cursor == len(batch)
    assert monitor.health_state == HEALTHY
    assert monitor.health()["counters"]["duplicate_events"] == len(batch) * 15


def test_backpressure_rejection_is_atomic_and_fail_closed():
    monitor = DurableStreamingMonitor(
        baseline(window=2),
        lambda _: 0.0,
        max_batch_events=2,
    )

    result = monitor.update([event(0), event(1), event(2)])

    assert result["accepted"] == 0
    assert monitor.absolute_cursor == 0
    assert result["health"]["backpressure"]["status"] == "REJECTING"
    assert result["new_alerts"][0]["code"] == "BACKPRESSURE_REJECT"
    assert result["health"]["fail_closed"] is True


def test_hung_scorer_has_deadline_opens_circuit_and_health_never_waits_on_it():
    entered = threading.Event()
    release = threading.Event()

    def hung(_):
        entered.set()
        release.wait()
        return 0.0

    monitor = DurableStreamingMonitor(
        baseline(window=1),
        hung,
        callback_deadline_ms=250,
    )
    healthy_base = IntegritySignals(
        observed_at_ms=1_000,
        event_loss_count=0,
        max_event_delay_ms=0,
        logger_healthy=True,
        policy_healthy=True,
        registry_healthy=True,
        verifier_healthy=True,
        token_verifier_healthy=True,
    )

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(monitor.update, [event(0)])
            assert entered.wait(timeout=1.0)

            started = time.monotonic()
            health = monitor.health()
            elapsed = time.monotonic() - started
            gateway_signals = monitor.gateway_integrity_signals(healthy_base)

            assert elapsed < 0.20
            assert health["callbacks"]["active"] == 1
            assert not gateway_signals.logger_healthy
            assert not gateway_signals.verifier_healthy

            result = pending.result(timeout=1.0)
    finally:
        release.set()

    assert result["accepted"] == 1
    assert result["new_points"][0]["state"] == DEGRADED
    assert result["new_alerts"][0]["code"] == "SCORER_TIMEOUT"
    assert result["health"]["callbacks"]["circuit_open"] is True
    assert result["health"]["counters"]["callback_timeouts"] == 1
    assert result["health"]["counters"]["scorer_timeouts"] == 1

    rejected = monitor.update([event(1)])
    assert rejected["accepted"] == 0
    assert rejected["new_alerts"][0]["code"] == "CALLBACK_CIRCUIT_OPEN"


def test_hung_evidence_callback_times_out_and_never_runs_later_callbacks():
    release = threading.Event()
    later_calls = []

    def hung(_):
        release.wait()
        return 0.0

    monitor = DurableStreamingMonitor(
        baseline(window=1),
        lambda _: 0.0,
        evidence_fns={
            "hung_verifier": hung,
            "must_not_run": lambda _: later_calls.append(True) or 0.0,
        },
        callback_deadline_ms=30,
    )
    try:
        result = monitor.update([event(0)])
    finally:
        release.set()

    assert result["new_points"][0]["state"] == DEGRADED
    assert result["new_alerts"][0]["code"] == "EVIDENCE_TIMEOUT"
    assert result["new_alerts"][0]["details"] == {
        "evidence_name": "hung_verifier",
        "deadline_ms": 30,
    }
    assert result["health"]["counters"]["evidence_timeouts"] == 1
    assert result["health"]["counters"]["callback_timeouts"] == 1
    assert later_calls == []


def test_callback_deadline_and_open_circuit_are_checkpoint_bound():
    release = threading.Event()
    monitor = DurableStreamingMonitor(
        baseline(window=1),
        lambda _: release.wait() or 0.0,
        callback_deadline_ms=25,
    )
    try:
        monitor.update([event(0)])
    finally:
        release.set()

    checkpoint = monitor.checkpoint()
    assert checkpoint["config"]["callback_deadline_ms"] == 25
    assert checkpoint["state"]["callback_circuit_open"] is True

    restored = DurableStreamingMonitor.from_checkpoint(
        checkpoint,
        lambda _: 0.0,
    )
    assert restored.callback_deadline_ms == 25
    assert restored.health_state == DEGRADED
    rejected = restored.update([event(1)])
    assert rejected["accepted"] == 0
    assert rejected["new_alerts"][0]["code"] == "CALLBACK_CIRCUIT_OPEN"

    malformed = copy.deepcopy(checkpoint)
    malformed["config"]["callback_deadline_ms"] = 0
    rehash_checkpoint(malformed)
    with pytest.raises(CheckpointIntegrityError):
        DurableStreamingMonitor.from_checkpoint(malformed, lambda _: 0.0)

    legacy = copy.deepcopy(checkpoint)
    legacy["version"] = 1
    legacy["config"].pop("callback_deadline_ms")
    legacy["state"].pop("callback_circuit_open")
    legacy["state"]["degraded"] = False
    rehash_checkpoint(legacy)
    legacy_restored = DurableStreamingMonitor.from_checkpoint(
        legacy,
        lambda _: 0.0,
    )
    assert legacy_restored.callback_deadline_ms == DEFAULT_CALLBACK_DEADLINE_MS


@pytest.mark.parametrize("deadline", [True, 0, -1, 60_001, 1.5, "100"])
def test_callback_deadline_configuration_is_strict(deadline):
    with pytest.raises(StreamConfigurationError):
        DurableStreamingMonitor(
            baseline(window=1),
            lambda _: 0.0,
            callback_deadline_ms=deadline,
        )


def test_stream_integrity_adapter_can_only_degrade_gateway_signals():
    now = 5_000
    base = IntegritySignals(
        observed_at_ms=now,
        event_loss_count=2,
        max_event_delay_ms=10,
        logger_healthy=True,
        policy_healthy=False,
        registry_healthy=True,
        verifier_healthy=True,
        token_verifier_healthy=True,
    )
    monitor = DurableStreamingMonitor(baseline(window=1), lambda _: math.nan)

    before = monitor.gateway_integrity_signals(base)
    assert before == base

    monitor.update([event(0)])
    merged = monitor.gateway_integrity_signals(base)
    assert merged.event_loss_count == base.event_loss_count
    assert not merged.logger_healthy
    assert not merged.verifier_healthy
    assert not merged.policy_healthy

    policy = ControlPlaneIntegrityPolicy(clock_ms=lambda: now)
    assert not policy.assess(merged).healthy


def test_legacy_session_monitor_scores_cannot_reach_online_callbacks():
    callback_views = []

    def observe(trajectory):
        callback_views.append(dict(trajectory.existing_monitor_scores))
        return 0.0

    seed = DurableStreamingMonitor(
        baseline(window=1),
        observe,
        context=StreamContext(
            model_version="model-a",
            environment="test",
            task_family="safety",
        ),
    ).checkpoint()

    for proxy_value in (0.0, 1.0):
        legacy = copy.deepcopy(seed)
        legacy["config"]["context"]["existing_monitor_scores"] = {
            "posthoc_label_proxy": proxy_value,
        }
        rehash_checkpoint(legacy)
        restored = DurableStreamingMonitor.from_checkpoint(legacy, observe)
        restored.update([event(int(proxy_value))])

    assert callback_views == [{}, {}]
