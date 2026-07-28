"""
TITAN — Trajectory Inspection & Targeted Anomaly Network

A meta-monitor for discovering blind spots in existing AI safety measurements.

Core loop:
  Agent trajectory → existing monitor vector → find harmful/benign collisions
  → synthesize candidate measurements → validate on held-out splits
  → shadow deploy → promote / revise / retire

Primary application: data-poisoning and research-sabotage detection for
coding / research agents (RSI safety control stack).
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "0.9.0"
__all__ = [
    "__version__",
    "AgentEvent",
    "AgentTrajectory",
    "Label",
    "AttackFamily",
    "MonitorJudgment",
    "Collision",
    "CollisionReport",
    "CandidateMonitor",
    "DiscoveryResult",
    "run_discovery",
    "find_collisions",
    "evaluate_monitor",
    "EvaluationReport",
    "Partition",
    "split_dataset",
    "generate_scenario_suite",
    "MonitorRegistry",
    "StreamingMonitor",
    "build_report",
    "RuleBaseline",
    "FeatureClassifierBaseline",
    "JudgeBaseline",
    "run_discovery_v2",
    "run_discovery_v3",
    "DiscoveryResultV2",
    "TITAN_V3_VERSION",
    "SparseAggregator",
    "ErrorAtlas",
    "build_error_atlas",
]

# Keep the offline research stack out of the online governor process unless a
# caller explicitly asks for it.  In particular, importing ``titan.v9.online``
# must not eagerly import NumPy, dataset generators, evaluators, or legacy
# engines.  The public top-level API remains backwards compatible through
# module-level lazy attribute resolution.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "AgentEvent": (".schema", "AgentEvent"),
    "AgentTrajectory": (".schema", "AgentTrajectory"),
    "AttackFamily": (".schema", "AttackFamily"),
    "Label": (".schema", "Label"),
    "MonitorJudgment": (".schema", "MonitorJudgment"),
    "Collision": (".collisions", "Collision"),
    "CollisionReport": (".collisions", "CollisionReport"),
    "find_collisions": (".collisions", "find_collisions"),
    "CandidateMonitor": (".engine", "CandidateMonitor"),
    "DiscoveryResult": (".engine", "DiscoveryResult"),
    "run_discovery": (".engine", "run_discovery"),
    "EvaluationReport": (".evaluation.metrics", "EvaluationReport"),
    "evaluate_monitor": (".evaluation.metrics", "evaluate_monitor"),
    "Partition": (".evaluation.splits", "Partition"),
    "split_dataset": (".evaluation.splits", "split_dataset"),
    "generate_scenario_suite": (
        ".scenarios.generator",
        "generate_scenario_suite",
    ),
    "MonitorRegistry": (".registry", "MonitorRegistry"),
    "StreamingMonitor": (".streaming", "StreamingMonitor"),
    "build_report": (".report", "build_report"),
    "FeatureClassifierBaseline": (
        ".baselines",
        "FeatureClassifierBaseline",
    ),
    "JudgeBaseline": (".baselines", "JudgeBaseline"),
    "RuleBaseline": (".baselines", "RuleBaseline"),
    "DiscoveryResultV2": (".engine_v2", "DiscoveryResultV2"),
    "run_discovery_v2": (".engine_v2", "run_discovery_v2"),
    "run_discovery_v3": (".engine_v3", "run_discovery_v3"),
    "TITAN_V3_VERSION": (".engine_v3", "TITAN_V3_VERSION"),
    "SparseAggregator": (".aggregator", "SparseAggregator"),
    "ErrorAtlas": (".error_atlas", "ErrorAtlas"),
    "build_error_atlas": (".error_atlas", "build_error_atlas"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
