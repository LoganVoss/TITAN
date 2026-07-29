"""Durable session lifecycle for capture-complete accounting.

Transport failures and governor decisions are distinct terminal classes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
import time


class SessionPhase(str, Enum):
    CREATED = "CREATED"
    REQUEST_SENT = "REQUEST_SENT"
    PROVIDER_ACCEPTED = "PROVIDER_ACCEPTED"
    RESPONSE_STREAMING = "RESPONSE_STREAMING"
    TOOL_PROPOSED = "TOOL_PROPOSED"
    ACTION_NORMALIZED = "ACTION_NORMALIZED"
    GOVERNED = "GOVERNED"
    PREPARED = "PREPARED"
    STATE_RECHECKED = "STATE_RECHECKED"
    COMMITTED = "COMMITTED"
    EXECUTED = "EXECUTED"
    COMPLETED = "COMPLETED"
    # Failures (terminal-safe)
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    STREAM_INTERRUPTED = "STREAM_INTERRUPTED"
    SCHEMA_REJECTED = "SCHEMA_REJECTED"
    NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"
    GOVERNOR_REFUSED = "GOVERNOR_REFUSED"
    COMMIT_FAILED = "COMMIT_FAILED"
    TERMINAL_SAFE_FAILURE = "TERMINAL_SAFE_FAILURE"


_SUCCESS_EDGES: dict[SessionPhase, frozenset[SessionPhase]] = {
    SessionPhase.CREATED: frozenset(
        {
            SessionPhase.REQUEST_SENT,
            SessionPhase.SCHEMA_REJECTED,
            SessionPhase.TERMINAL_SAFE_FAILURE,
        }
    ),
    SessionPhase.REQUEST_SENT: frozenset(
        {
            SessionPhase.PROVIDER_ACCEPTED,
            SessionPhase.PROVIDER_REJECTED,
            SessionPhase.PROVIDER_TIMEOUT,
            SessionPhase.SCHEMA_REJECTED,
            SessionPhase.STREAM_INTERRUPTED,
        }
    ),
    SessionPhase.PROVIDER_ACCEPTED: frozenset(
        {
            SessionPhase.RESPONSE_STREAMING,
            SessionPhase.TOOL_PROPOSED,
            SessionPhase.STREAM_INTERRUPTED,
            SessionPhase.PROVIDER_TIMEOUT,
        }
    ),
    SessionPhase.RESPONSE_STREAMING: frozenset(
        {
            SessionPhase.TOOL_PROPOSED,
            SessionPhase.STREAM_INTERRUPTED,
            SessionPhase.PROVIDER_TIMEOUT,
        }
    ),
    SessionPhase.TOOL_PROPOSED: frozenset(
        {
            SessionPhase.ACTION_NORMALIZED,
            SessionPhase.NORMALIZATION_FAILED,
        }
    ),
    SessionPhase.ACTION_NORMALIZED: frozenset(
        {
            SessionPhase.GOVERNED,
            SessionPhase.EVIDENCE_FAILED,
            SessionPhase.GOVERNOR_REFUSED,
        }
    ),
    SessionPhase.GOVERNED: frozenset(
        {
            SessionPhase.PREPARED,
            SessionPhase.GOVERNOR_REFUSED,
            SessionPhase.COMPLETED,  # ESCROW/BLOCK without prepare
        }
    ),
    SessionPhase.PREPARED: frozenset(
        {
            SessionPhase.STATE_RECHECKED,
            SessionPhase.COMMIT_FAILED,
        }
    ),
    SessionPhase.STATE_RECHECKED: frozenset(
        {
            SessionPhase.COMMITTED,
            SessionPhase.COMMIT_FAILED,
        }
    ),
    SessionPhase.COMMITTED: frozenset(
        {
            SessionPhase.EXECUTED,
            SessionPhase.COMMIT_FAILED,
        }
    ),
    SessionPhase.EXECUTED: frozenset({SessionPhase.COMPLETED}),
    SessionPhase.COMPLETED: frozenset(),
    # Terminal failure states: no further transitions
    SessionPhase.PROVIDER_REJECTED: frozenset(),
    SessionPhase.PROVIDER_TIMEOUT: frozenset(),
    SessionPhase.STREAM_INTERRUPTED: frozenset(),
    SessionPhase.SCHEMA_REJECTED: frozenset(),
    SessionPhase.NORMALIZATION_FAILED: frozenset(),
    SessionPhase.EVIDENCE_FAILED: frozenset(),
    SessionPhase.GOVERNOR_REFUSED: frozenset({SessionPhase.COMPLETED}),
    SessionPhase.COMMIT_FAILED: frozenset({SessionPhase.COMPLETED, SessionPhase.TERMINAL_SAFE_FAILURE}),
    SessionPhase.TERMINAL_SAFE_FAILURE: frozenset(),
}


_FAILURE_PHASES = frozenset(
    {
        SessionPhase.PROVIDER_REJECTED,
        SessionPhase.PROVIDER_TIMEOUT,
        SessionPhase.STREAM_INTERRUPTED,
        SessionPhase.SCHEMA_REJECTED,
        SessionPhase.NORMALIZATION_FAILED,
        SessionPhase.EVIDENCE_FAILED,
        SessionPhase.GOVERNOR_REFUSED,
        SessionPhase.COMMIT_FAILED,
        SessionPhase.TERMINAL_SAFE_FAILURE,
    }
)


class TransitionError(RuntimeError):
    pass


@dataclass
class SessionRecord:
    session_id: str
    phase: SessionPhase = SessionPhase.CREATED
    attempt: int = 1
    original_session_id: str = ""
    provider: str = ""
    lane: str = ""
    turns_completed: int = 0
    turns_planned: int = 1
    dispositions: list[str] = field(default_factory=list)
    tool_names_raw: list[str] = field(default_factory=list)
    tool_names_canonical: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    executed: bool = False
    # Intention-to-test flags
    provider_accepted: bool = False
    captured: bool = False
    governed: bool = False
    completed: bool = False

    def __post_init__(self) -> None:
        if not self.original_session_id:
            self.original_session_id = self.session_id

    def transition(self, new_phase: SessionPhase, *, note: str = "") -> None:
        allowed = _SUCCESS_EDGES.get(self.phase, frozenset())
        if new_phase not in allowed and new_phase != self.phase:
            # Allow jump to TERMINAL_SAFE_FAILURE from almost anywhere non-terminal
            if new_phase != SessionPhase.TERMINAL_SAFE_FAILURE or self.phase in (
                SessionPhase.COMPLETED,
            ):
                if self.phase in _FAILURE_PHASES and new_phase == SessionPhase.COMPLETED:
                    pass
                elif new_phase not in allowed:
                    raise TransitionError(
                        f"illegal transition {self.phase.value} → {new_phase.value} "
                        f"session={self.session_id}"
                    )
        self.history.append(
            {
                "from": self.phase.value,
                "to": new_phase.value,
                "note": note,
                "ts": time.time(),
            }
        )
        self.phase = new_phase
        self.updated_at = time.time()
        if new_phase == SessionPhase.PROVIDER_ACCEPTED:
            self.provider_accepted = True
        if new_phase in (
            SessionPhase.TOOL_PROPOSED,
            SessionPhase.ACTION_NORMALIZED,
            SessionPhase.GOVERNED,
        ):
            self.captured = True
        if new_phase in (
            SessionPhase.GOVERNED,
            SessionPhase.PREPARED,
            SessionPhase.COMMITTED,
            SessionPhase.EXECUTED,
            SessionPhase.GOVERNOR_REFUSED,
        ):
            self.governed = True
        if new_phase == SessionPhase.EXECUTED:
            self.executed = True
        if new_phase == SessionPhase.COMPLETED or new_phase in _FAILURE_PHASES:
            if new_phase == SessionPhase.COMPLETED:
                self.completed = True

    def classify_provider_error(self, message: str) -> SessionPhase:
        m = message.lower()
        if "no function named" in m or "tool" in m and "not found" in m:
            return SessionPhase.SCHEMA_REJECTED
        if "timeout" in m:
            return SessionPhase.PROVIDER_TIMEOUT
        if "stream" in m:
            return SessionPhase.STREAM_INTERRUPTED
        return SessionPhase.PROVIDER_REJECTED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d


def is_failure_phase(phase: SessionPhase | str) -> bool:
    if isinstance(phase, str):
        try:
            phase = SessionPhase(phase)
        except ValueError:
            return True
    return phase in _FAILURE_PHASES
