from __future__ import annotations

import json

from titan.cli import main
from titan.schema import AgentEvent, AgentTrajectory, EventType, Label


def test_v9_inspect_is_shadow_only_and_strips_execution_authority(
    tmp_path,
    capsys,
):
    trajectory = AgentTrajectory(
        trajectory_id="cli-shadow",
        label=Label.HARMFUL,
        metadata={"gold_disposition": "BLOCK"},
        events=[
            AgentEvent(
                EventType.TOOL_CALL,
                1.0,
                "agent",
                {"tool": "queue_training"},
                "queue-event",
            )
        ],
    )
    path = tmp_path / "trajectory.json"
    path.write_text(json.dumps(trajectory.to_dict()), encoding="utf-8")
    assert main(["v9-inspect", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"]
    assert output["mode"] == "shadow_only"
    assert output["execution_authority"] is False
    assert output["action_count"] == 1
    assert output["actions"][0]["action_type"] == "queue_training"
    assert output["actions"][0]["disposition"] != "ALLOW"


def test_v9_inspect_malformed_input_fails_closed(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"trajectory_id":', encoding="utf-8")
    assert main(["v9-inspect", str(path)]) == 2
    output = json.loads(capsys.readouterr().err)
    assert output["ok"] is False
