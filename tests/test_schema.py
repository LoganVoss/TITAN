"""Schema and trajectory helpers."""

from titan.schema import (
    AgentTrajectory,
    AttackFamily,
    EventType,
    Label,
    make_event,
)
from titan.scenarios.poisoning import generate_poisoning_scenario


def test_make_event_and_roundtrip():
    e = make_event(EventType.DATA_MUTATION, {"n_samples": 3}, actor="agent")
    assert e.event_type == EventType.DATA_MUTATION
    d = e.to_dict()
    assert d["event_type"] == "data_mutation"


def test_trajectory_accessors():
    t = generate_poisoning_scenario(AttackFamily.CLUSTER_CONCENTRATION, seed=1)
    assert t.label == Label.HARMFUL
    assert len(t.data_mutations()) >= 1
    assert 0.0 <= t.mean_monitor_severity() <= 1.0
    assert t.content_hash()
    t2 = AgentTrajectory.from_dict(t.to_dict())
    assert t2.trajectory_id == t.trajectory_id
    assert len(t2.events) == len(t.events)
