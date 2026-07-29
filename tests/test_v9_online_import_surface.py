from __future__ import annotations

import json
import importlib
import subprocess
import sys


def test_online_module_exposes_only_the_declared_enforcement_api():
    online = importlib.import_module("titan.v9.online")
    assert online.V9Governor.__module__ == "titan.v9.governor"
    assert online.EnforcementGateway.__module__ == "titan.v9.gateway"
    assert online.EvidenceAttestationVerifier.__module__ == (
        "titan.v9.evidence_trust"
    )
    assert online.ActionContext.__module__ == "titan.v9.tokens"
    assert set(online.__all__) == {
        name for name in online.__all__ if not name.startswith("_")
    }


def test_online_import_does_not_load_offline_or_numeric_stack():
    program = """
import json
import sys
import titan.v9.online
forbidden = [
    name for name in sys.modules
    if name == "numpy"
    or name.startswith("numpy.")
    or name in {
        "titan.engine",
        "titan.engine_v2",
        "titan.engine_v3",
        "titan.evaluation.metrics",
        "titan.scenarios.generator",
    }
]
print(json.dumps(sorted(forbidden)))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == []


def test_legacy_top_level_exports_remain_lazy_and_compatible():
    program = """
import json
import sys
import titan
before = "numpy" in sys.modules
event_type = titan.AgentEvent.__name__
after_schema = "numpy" in sys.modules
baseline_type = titan.RuleBaseline.__name__
print(json.dumps([before, event_type, after_schema, baseline_type]))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(completed.stdout) == [
        False,
        "AgentEvent",
        False,
        "RuleBaseline",
    ]
