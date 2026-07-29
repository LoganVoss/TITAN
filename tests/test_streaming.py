"""Streaming monitor buffer offset fix."""

from titan.schema import EventType, make_event
from titan.scenarios.poisoning import generate_poisoning_scenario
from titan.schema import AttackFamily
from titan.streaming import StreamingMonitor, build_stream_baseline


def test_streaming_continues_after_buffer_truncation():
    benign = [
        generate_poisoning_scenario(AttackFamily.CLUSTER_CONCENTRATION, seed=i, harmful=False)
        for i in range(3)
    ]
    # Use benign curation instead
    from titan.scenarios.poisoning import generate_benign_curation
    benign = [generate_benign_curation(seed=i) for i in range(5)]

    def score_fn(t):
        return float(len(t.data_mutations()) + t.bypass_attempt_count() if hasattr(t, "bypass_attempt_count") else len(t.events) * 0.01)

    from titan.features import bypass_attempt_count, n_data_mutations

    def score_fn(t):
        return n_data_mutations(t) + bypass_attempt_count(t)

    baseline = build_stream_baseline(benign, score_fn, window_size=4, step=2)
    mon = StreamingMonitor(baseline, score_fn, watch_z=0.5, alert_z=1.0)

    # Feed many small chunks to force truncation
    total_points = 0
    for chunk_i in range(30):
        events = [
            make_event(EventType.DATA_MUTATION, {
                "action": "add",
                "semantic_cluster": "c",
                "n_samples": 5,
                "source_rarity": 0.5,
                "gradient_influence": 0.5 + 0.1 * (chunk_i % 3),
                "label_entropy_delta": 0.0,
            }, timestamp=float(chunk_i * 10 + j))
            for j in range(3)
        ]
        out = mon.update(events)
        total_points += len(out["new_points"])

    # Critical: after truncation we must still emit new points
    assert total_points > 5
    assert mon._last_emit_end > mon._absolute_start
    # Absolute indices never go backwards
    ends = [p.window_end for p in mon.timeline]
    assert ends == sorted(ends)
    assert ends[-1] == mon._last_emit_end


def test_alert_strength_naming():
    """Ensure we don't call it calibrated confidence."""
    from titan.streaming import StreamPoint
    p = StreamPoint(0, 0, 4, 0.5, 0.3, "quiet")
    d = p.to_dict()
    assert "alert_strength" in d
    assert "confidence" not in d
    assert "baseline_support" in d
