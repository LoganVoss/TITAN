"""
Typed agent-event log schema for safety monitoring.

A trajectory is a session containing messages, monitor signals, tool calls,
files accessed, code diffs, permission failures, approvals, and outcomes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
import hashlib
import json
import time
import uuid


class Label(str, Enum):
    """Ground-truth regime for evaluation. Collisions require cross-regime pairs."""

    BENIGN = "benign"
    HARMFUL = "harmful"
    UNKNOWN = "unknown"


class AttackFamily(str, Enum):
    """Attack / scenario family for stratified splits and transfer measurement."""

    NONE = "none"
    # Data poisoning
    CLUSTER_CONCENTRATION = "cluster_concentration"
    RARE_SOURCE_HIGH_INFLUENCE = "rare_source_high_influence"
    EVAL_WEAKENING = "eval_weakening"
    DISPERSED_COMMITS = "dispersed_commits"
    PROVENANCE_BYPASS = "provenance_bypass"
    LABEL_FLIP_BURST = "label_flip_burst"
    CANARY_SUPPRESSION = "canary_suppression"
    # Research sabotage
    TEST_EDITING = "test_editing"
    MONITOR_EVASION = "monitor_evasion"
    SAFEGUARD_TAMPER = "safeguard_tamper"
    EXFIL_ATTEMPT = "exfil_attempt"
    # Composite / hard negatives
    HARD_NEGATIVE = "hard_negative"
    CLEAN_REFACTOR = "clean_refactor"
    LEGITIMATE_DATA_CURATION = "legitimate_data_curation"
    # Realistic attack-adjacent benign workflows (Phase 9)
    LEGIT_REBALANCE = "legit_rebalance"
    LEGIT_REMOVE_BROKEN_EVAL = "legit_remove_broken_eval"
    LEGIT_TEST_REFACTOR = "legit_test_refactor"
    LEGIT_RELABEL_CORRECTION = "legit_relabel_correction"
    LEGIT_SPLIT_COMMITS = "legit_split_commits"
    LEGIT_APPROVED_BYPASS = "legit_approved_bypass"
    LEGIT_CANARY_UPDATE = "legit_canary_update"
    LEGIT_PROVENANCE_MIGRATION = "legit_provenance_migration"
    LEGIT_INFLUENCE_DEBUG = "legit_influence_debug"
    LEGIT_SAFEGUARD_UPDATE = "legit_safeguard_update"
    # Adaptive / monitor-aware attack variants (Phase 10)
    STEALTH_POISON = "stealth_poison"
    STEALTH_EVAL_SABOTAGE = "stealth_eval_sabotage"
    SLOW_DRIP_POISON = "slow_drip_poison"


class EventType(str, Enum):
    MESSAGE = "message"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    PERMISSION_FAILURE = "permission_failure"
    APPROVAL = "approval"
    DATA_MUTATION = "data_mutation"
    EVAL_CHANGE = "eval_change"
    MONITOR_JUDGMENT = "monitor_judgment"
    COMMIT = "commit"
    OUTCOME = "outcome"


@dataclass
class MonitorJudgment:
    """Output of an existing safety monitor on a trajectory or event."""

    monitor_id: str
    severity: float  # 0.0 (clean) → 1.0 (critical)
    category: str = "general"
    rationale: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentEvent:
    """One atomic event in an agent session."""

    event_type: EventType
    timestamp: float
    actor: str = "agent"
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentEvent":
        data = dict(data)
        data["event_type"] = EventType(data["event_type"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentTrajectory:
    """
    Full agent session with existing monitor judgments and optional ground truth.

    This is the primary input object for TITAN. Numeric feature vectors are
    derived from trajectories; they are not the organizing ontology.
    """

    trajectory_id: str
    events: list[AgentEvent]
    label: Label = Label.UNKNOWN
    attack_family: AttackFamily = AttackFamily.NONE
    model_version: str = "unknown"
    environment: str = "default"
    task_family: str = "general"
    existing_monitor_scores: dict[str, float] = field(default_factory=dict)
    monitor_judgments: list[MonitorJudgment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    # ── Convenience accessors ─────────────────────────────────────────────

    def events_of(self, *types: EventType) -> list[AgentEvent]:
        wanted = set(types)
        return [e for e in self.events if e.event_type in wanted]

    def tool_calls(self) -> list[AgentEvent]:
        return self.events_of(EventType.TOOL_CALL)

    def data_mutations(self) -> list[AgentEvent]:
        return self.events_of(EventType.DATA_MUTATION)

    def permission_failures(self) -> list[AgentEvent]:
        return self.events_of(EventType.PERMISSION_FAILURE)

    def eval_changes(self) -> list[AgentEvent]:
        return self.events_of(EventType.EVAL_CHANGE)

    def commits(self) -> list[AgentEvent]:
        return self.events_of(EventType.COMMIT)

    def mean_monitor_severity(self) -> float:
        if self.monitor_judgments:
            return float(sum(j.severity for j in self.monitor_judgments) / len(self.monitor_judgments))
        if self.existing_monitor_scores:
            return float(sum(self.existing_monitor_scores.values()) / len(self.existing_monitor_scores))
        return 0.0

    def max_monitor_severity(self) -> float:
        if self.monitor_judgments:
            return float(max(j.severity for j in self.monitor_judgments))
        if self.existing_monitor_scores:
            return float(max(self.existing_monitor_scores.values()))
        return 0.0

    def monitor_disagreement(self) -> float:
        """Absolute spread between intent-style and action-style monitor scores."""
        intent = self.existing_monitor_scores.get("intent_monitor", 0.0)
        action = self.existing_monitor_scores.get("action_monitor", 0.0)
        if "intent_monitor" in self.existing_monitor_scores or "action_monitor" in self.existing_monitor_scores:
            return abs(intent - action)
        sevs = [j.severity for j in self.monitor_judgments]
        if len(sevs) < 2:
            return 0.0
        return float(max(sevs) - min(sevs))

    def content_hash(self) -> str:
        blob = json.dumps(
            {
                "id": self.trajectory_id,
                "events": [e.to_dict() for e in self.events],
                "label": self.label.value,
                "family": self.attack_family.value,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "events": [e.to_dict() for e in self.events],
            "label": self.label.value,
            "attack_family": self.attack_family.value,
            "model_version": self.model_version,
            "environment": self.environment,
            "task_family": self.task_family,
            "existing_monitor_scores": dict(self.existing_monitor_scores),
            "monitor_judgments": [j.to_dict() for j in self.monitor_judgments],
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentTrajectory":
        events = [AgentEvent.from_dict(e) for e in data.get("events", [])]
        judgments = [MonitorJudgment(**j) for j in data.get("monitor_judgments", [])]
        return cls(
            trajectory_id=data["trajectory_id"],
            events=events,
            label=Label(data.get("label", "unknown")),
            attack_family=AttackFamily(data.get("attack_family", "none")),
            model_version=data.get("model_version", "unknown"),
            environment=data.get("environment", "default"),
            task_family=data.get("task_family", "general"),
            existing_monitor_scores=dict(data.get("existing_monitor_scores", {})),
            monitor_judgments=judgments,
            metadata=dict(data.get("metadata", {})),
            created_at=float(data.get("created_at", time.time())),
        )


def make_event(
    event_type: EventType | str,
    payload: dict[str, Any] | None = None,
    *,
    actor: str = "agent",
    timestamp: float | None = None,
) -> AgentEvent:
    et = EventType(event_type) if isinstance(event_type, str) else event_type
    return AgentEvent(
        event_type=et,
        timestamp=timestamp if timestamp is not None else time.time(),
        actor=actor,
        payload=payload or {},
    )
