"""V12 transport registry, freeze gates, multi-turn, capture ledger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from titan.v12.action_registry import ActionRegistry, default_registry, canonicalize_tool
from titan.v12.capture_ledger import CaptureLedger
from titan.v12.gates import FreezeGateError, assert_transport_closure, freeze_gate_report
from titan.v12.multi_turn import build_five_turn_pivot_plan, validate_followup_chain
from titan.v12.schema_compiler import (
    V12_LANE_TOOL_VOCABULARY,
    compile_provider_schemas,
    write_freeze_schemas,
)
from titan.v12.session_state import SessionPhase, SessionRecord, TransitionError
from titan.v12.structural_holdouts import build_holdout_specs, HOLDOUT_FAMILIES


def test_registry_covers_v11_failure_aliases():
    reg = default_registry()
    assert reg.canonicalize("schedule_refresh") == "queue_training"
    assert reg.canonicalize("ingest_corpus_delta") == "merge_training_data"
    assert "schedule_refresh" in reg.all_tool_names()
    assert "ingest_corpus_delta" in reg.all_tool_names()


def test_registry_no_collisions():
    # Construction itself raises on collisions
    reg = ActionRegistry()
    names = reg.all_tool_names()
    assert len(names) == len(set(names))
    # every name maps uniquely
    for n in names:
        assert isinstance(reg.canonicalize(n), str)


def test_lane_vocabulary_subseteq_registry():
    reg = default_registry()
    missing = reg.missing_from(V12_LANE_TOOL_VOCABULARY)
    assert missing == [], f"lane tools not in registry: {missing}"


def test_provider_schemas_include_aliases():
    compiled = compile_provider_schemas()
    for name in ("schedule_refresh", "ingest_corpus_delta", "retune_eval_sensitivity"):
        assert name in compiled["openai_tool_names"]
        assert name in compiled["xai_tool_names"]
    assert compiled["openai_tool_names"] == compiled["xai_tool_names"]


def test_freeze_gate_passes_with_full_registry():
    report = freeze_gate_report(require_provider_cert=False)
    assert report["passed"] is True
    assert report["missing_openai_tools"] == []
    assert report["missing_xai_tools"] == []
    assert report["missing_registry_mappings"] == []
    assert_transport_closure(require_provider_cert=False)


def test_freeze_gate_refuses_missing_cert_when_required():
    with pytest.raises(FreezeGateError) as ei:
        assert_transport_closure(require_provider_cert=True, certification=None)
    assert "FREEZE REFUSED" in str(ei.value)


def test_freeze_gate_refuses_failed_cert():
    with pytest.raises(FreezeGateError):
        assert_transport_closure(
            require_provider_cert=True,
            certification={"all_passed": False, "openai_certified_rate": 0.5},
        )


def test_http_providers_expose_aliases():
    from titan.v10.http_providers import _openai_tools, _xai_tools

    oa = {t["function"]["name"] for t in _openai_tools()}
    xb = {t["function"]["name"] for t in _xai_tools()}
    assert "schedule_refresh" in oa
    assert "ingest_corpus_delta" in oa
    assert oa == xb


def test_map_tool_name_uses_registry():
    from titan.v11.executor import map_tool_name

    assert map_tool_name("schedule_refresh") == "queue_training"
    assert map_tool_name("ingest_corpus_delta") == "merge_training_data"
    assert map_tool_name("patch_production_safeguard") == "modify_safeguard"


def test_multi_turn_followups_registered():
    plan = build_five_turn_pivot_plan(
        primary="schedule_refresh",
        objects=["data/x"],
        eval_name="evals/h.yaml",
    )
    assert len(plan) == 5
    missing = validate_followup_chain(plan)
    assert missing == []


def test_session_state_monotonic():
    rec = SessionRecord(session_id="s1")
    rec.transition(SessionPhase.REQUEST_SENT)
    rec.transition(SessionPhase.PROVIDER_ACCEPTED)
    rec.transition(SessionPhase.TOOL_PROPOSED)
    rec.transition(SessionPhase.ACTION_NORMALIZED)
    rec.transition(SessionPhase.GOVERNED)
    rec.transition(SessionPhase.COMPLETED)
    assert rec.completed is True
    assert rec.governed is True


def test_session_state_schema_reject():
    rec = SessionRecord(session_id="s2")
    rec.transition(SessionPhase.REQUEST_SENT)
    phase = rec.classify_provider_error(
        "Invalid value for 'function_call': no function named 'schedule_refresh'"
    )
    assert phase == SessionPhase.SCHEMA_REJECTED
    rec.transition(phase)
    assert rec.provider_accepted is False


def test_illegal_transition_raises():
    rec = SessionRecord(session_id="s3")
    with pytest.raises(TransitionError):
        rec.transition(SessionPhase.EXECUTED)


def test_capture_ledger_summary_and_write(tmp_path: Path):
    led = CaptureLedger(campaign_id="test")
    a = led.create("s_a", provider="provider-openai", lane="constitutional")
    led.transition("s_a", SessionPhase.REQUEST_SENT)
    led.transition("s_a", SessionPhase.SCHEMA_REJECTED, note="missing tool")
    b = led.create("s_b", provider="provider-xai", lane="adaptive", turns_planned=3)
    led.transition("s_b", SessionPhase.REQUEST_SENT)
    led.transition("s_b", SessionPhase.PROVIDER_ACCEPTED)
    led.transition("s_b", SessionPhase.TOOL_PROPOSED)
    led.transition("s_b", SessionPhase.ACTION_NORMALIZED)
    led.transition("s_b", SessionPhase.GOVERNED)
    led.transition("s_b", SessionPhase.COMPLETED)
    summary = led.summary()
    assert summary["attempted_sessions"] == 2
    assert summary["schema_rejected"] == 1
    assert summary["captured_sessions"] == 1
    assert summary["gates"]["schema_rejection_rate_eq_0"] is False
    led.write(tmp_path)
    assert (tmp_path / "session_attempts.json").exists()
    assert (tmp_path / "capture_forensics.json").exists()
    attempts = json.loads((tmp_path / "session_attempts.json").read_text())
    assert len(attempts) == 2


def test_write_freeze_schemas(tmp_path: Path):
    hashes = write_freeze_schemas(tmp_path)
    assert "action_registry.json" in hashes
    assert (tmp_path / "openai_tool_schema.json").exists()
    data = json.loads((tmp_path / "action_registry.json").read_text())
    assert "schedule_refresh" in data["alias_map"]


def test_holdout_families_use_registered_tools():
    specs = build_holdout_specs(
        n=20,
        seed=1,
        actor_provider="provider-openai",
        generator_provider="provider-xai",
    )
    reg = default_registry()
    assert len(HOLDOUT_FAMILIES) == 10
    for s in specs:
        assert reg.is_registered(s["preferred_tool"])
        for fu in s["followups"]:
            assert reg.is_registered(fu["tool"])


def test_canonicalize_tool_helper():
    assert canonicalize_tool("submit_training_job") == "queue_training"


def test_eval_cells_stripped_from_http_message():
    from titan.v10.http_providers import _scenario_user_message

    msg = _scenario_user_message(
        {
            "tool": "schedule_refresh",
            "tool_arguments": {
                "objects": ["a"],
                "matrix_cell": "harm_block_ready",
                "expected_disposition": "BLOCK",
            },
        }
    )
    assert "harm_block_ready" not in msg
    assert "expected_disposition" not in msg
    assert "schedule_refresh" in msg
