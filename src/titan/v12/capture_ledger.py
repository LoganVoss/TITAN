"""Append-only capture ledger and intention-to-test reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import json
import time
from pathlib import Path

from .session_state import SessionPhase, SessionRecord, is_failure_phase


@dataclass
class CaptureLedger:
    """Tracks every attempted session for ITT reporting."""

    campaign_id: str
    records: dict[str, SessionRecord] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def create(
        self,
        session_id: str,
        *,
        provider: str,
        lane: str,
        turns_planned: int = 1,
    ) -> SessionRecord:
        rec = SessionRecord(
            session_id=session_id,
            provider=provider,
            lane=lane,
            turns_planned=turns_planned,
        )
        self.records[session_id] = rec
        self._emit(session_id, "created", phase=rec.phase.value)
        return rec

    def get(self, session_id: str) -> SessionRecord | None:
        return self.records.get(session_id)

    def _emit(self, session_id: str, kind: str, **kwargs: Any) -> None:
        self.events.append(
            {
                "ts": time.time(),
                "session_id": session_id,
                "kind": kind,
                **kwargs,
            }
        )

    def note_error(self, session_id: str, error: str) -> None:
        rec = self.records[session_id]
        rec.errors.append(error[:500])
        self._emit(session_id, "error", error=error[:500])

    def transition(self, session_id: str, phase: SessionPhase, *, note: str = "") -> None:
        rec = self.records[session_id]
        rec.transition(phase, note=note)
        self._emit(session_id, "transition", phase=phase.value, note=note)

    def summary(self) -> dict[str, Any]:
        rows = list(self.records.values())
        n = len(rows)
        attempted = n
        provider_accepted = sum(1 for r in rows if r.provider_accepted)
        captured = sum(1 for r in rows if r.captured)
        governed = sum(1 for r in rows if r.governed)
        completed = sum(1 for r in rows if r.completed or r.phase == SessionPhase.COMPLETED)
        executed = sum(1 for r in rows if r.executed)
        schema_rejected = sum(1 for r in rows if r.phase == SessionPhase.SCHEMA_REJECTED)
        provider_rejected = sum(
            1
            for r in rows
            if r.phase
            in (
                SessionPhase.PROVIDER_REJECTED,
                SessionPhase.PROVIDER_TIMEOUT,
                SessionPhase.STREAM_INTERRUPTED,
            )
        )
        failure_phases = sum(1 for r in rows if is_failure_phase(r.phase) and not r.governed)
        by_phase: dict[str, int] = {}
        for r in rows:
            by_phase[r.phase.value] = by_phase.get(r.phase.value, 0) + 1
        by_lane: dict[str, dict[str, int]] = {}
        for r in rows:
            lane = r.lane or "?"
            by_lane.setdefault(lane, {"attempted": 0, "captured": 0, "schema_rejected": 0})
            by_lane[lane]["attempted"] += 1
            if r.captured:
                by_lane[lane]["captured"] += 1
            if r.phase == SessionPhase.SCHEMA_REJECTED:
                by_lane[lane]["schema_rejected"] += 1

        capture_completeness = captured / max(1, attempted)
        return {
            "schema": "titan-v12-capture-summary/1",
            "campaign_id": self.campaign_id,
            "attempted_sessions": attempted,
            "provider_accepted_sessions": provider_accepted,
            "captured_sessions": captured,
            "governed_sessions": governed,
            "completed_sessions": completed,
            "executed_actions": executed,
            "schema_rejected": schema_rejected,
            "provider_transport_failures": provider_rejected,
            "ungoverned_failures": failure_phases,
            "capture_completeness": capture_completeness,
            "schema_rejection_rate": schema_rejected / max(1, attempted),
            "by_phase": by_phase,
            "by_lane": by_lane,
            "gates": {
                "schema_rejection_rate_eq_0": schema_rejected == 0,
                "capture_completeness_ge_099": capture_completeness >= 0.99,
                "normalization_failures_eq_0": by_phase.get("NORMALIZATION_FAILED", 0) == 0,
            },
        }

    def write(self, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        attempts = [r.to_dict() for r in self.records.values()]
        (out_dir / "session_attempts.json").write_text(
            json.dumps(attempts, indent=2, default=str)
        )
        with (out_dir / "session_events.jsonl").open("w") as f:
            for ev in self.events:
                f.write(json.dumps(ev, default=str) + "\n")
        (out_dir / "capture_forensics.json").write_text(
            json.dumps(self.summary(), indent=2, default=str)
        )
