"""Fail-closed control-plane integrity and hash-chained audit records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Tuple
import hashlib
import json
import threading
import time

from .tokens import canonical_json_bytes


GENESIS_HASH = "0" * 64
_DISPOSITION_RANK = {
    "ALLOW": 0,
    "ALLOW_WITH_LOGGING": 1,
    "REQUEST_EVIDENCE": 2,
    "SHADOW_EXECUTE": 3,
    "ESCROW": 4,
    "HUMAN_CONFIRM": 5,
    "BLOCK": 6,
}


def _system_clock_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class IntegritySignals:
    """Trusted health observations for one integrity epoch."""

    observed_at_ms: int
    event_loss_count: int
    max_event_delay_ms: int
    logger_healthy: bool
    policy_healthy: bool
    registry_healthy: bool
    verifier_healthy: bool
    token_verifier_healthy: bool

    def __post_init__(self) -> None:
        if self.observed_at_ms < 0:
            raise ValueError("observed_at_ms cannot be negative")
        if self.event_loss_count < 0:
            raise ValueError("event_loss_count cannot be negative")
        if self.max_event_delay_ms < 0:
            raise ValueError("max_event_delay_ms cannot be negative")
        for name in (
            "logger_healthy",
            "policy_healthy",
            "registry_healthy",
            "verifier_healthy",
            "token_verifier_healthy",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError("%s must be a boolean" % name)


@dataclass(frozen=True)
class IntegrityAssessment:
    healthy: bool
    score: float
    reasons: Tuple[str, ...]
    assessed_at_ms: int
    signal_age_ms: int
    signals: IntegritySignals


@dataclass(frozen=True)
class IntegrityDecision:
    action_type: str
    original_disposition: str
    effective_disposition: str
    forced: bool
    reasons: Tuple[str, ...]
    integrity: IntegrityAssessment


class ControlPlaneIntegrityPolicy:
    """Hard health gates; degraded high-risk actions receive an ESCROW floor."""

    def __init__(
        self,
        *,
        max_event_loss_count: int = 0,
        max_event_delay_ms: int = 5_000,
        max_signal_age_ms: int = 10_000,
        low_risk_actions: Iterable[str] = (
            "allow_low_risk",
            "read_file",
            "list_dir",
            "user_message",
        ),
        unknown_is_high_risk: bool = True,
        clock_ms: Callable[[], int] = _system_clock_ms,
    ):
        if max_event_loss_count < 0 or max_event_delay_ms < 0 or max_signal_age_ms < 0:
            raise ValueError("integrity thresholds cannot be negative")
        self.max_event_loss_count = max_event_loss_count
        self.max_event_delay_ms = max_event_delay_ms
        self.max_signal_age_ms = max_signal_age_ms
        self.low_risk_actions = frozenset(low_risk_actions)
        self.unknown_is_high_risk = bool(unknown_is_high_risk)
        self._clock_ms = clock_ms

    def assess(self, signals: IntegritySignals) -> IntegrityAssessment:
        now_ms = self._clock_ms()
        age_ms = now_ms - signals.observed_at_ms
        reasons = []
        if age_ms < 0:
            reasons.append("integrity_snapshot_from_future")
        elif age_ms > self.max_signal_age_ms:
            reasons.append("integrity_snapshot_stale")
        if signals.event_loss_count > self.max_event_loss_count:
            reasons.append("event_loss")
        if signals.max_event_delay_ms > self.max_event_delay_ms:
            reasons.append("event_delay")
        for field, reason in (
            ("logger_healthy", "logger_unhealthy"),
            ("policy_healthy", "policy_integrity_failed"),
            ("registry_healthy", "registry_integrity_failed"),
            ("verifier_healthy", "verifier_unhealthy"),
            ("token_verifier_healthy", "token_verifier_unhealthy"),
        ):
            if not getattr(signals, field):
                reasons.append(reason)
        # Score is a diagnostic health fraction, not a probability.
        total_checks = 8
        score = max(0.0, 1.0 - len(reasons) / total_checks)
        return IntegrityAssessment(
            healthy=not reasons,
            score=score,
            reasons=tuple(reasons),
            assessed_at_ms=now_ms,
            signal_age_ms=age_ms,
            signals=signals,
        )

    def is_high_risk(self, action_type: str) -> bool:
        if action_type in self.low_risk_actions:
            return False
        return self.unknown_is_high_risk

    def enforce(
        self,
        *,
        action_type: str,
        disposition: str,
        assessment: IntegrityAssessment,
    ) -> IntegrityDecision:
        if disposition not in _DISPOSITION_RANK:
            raise ValueError("unknown disposition")
        effective = disposition
        forced = False
        reasons = list(assessment.reasons)
        if self.is_high_risk(action_type) and not assessment.healthy:
            if _DISPOSITION_RANK[effective] < _DISPOSITION_RANK["ESCROW"]:
                effective = "ESCROW"
                forced = True
            reasons.append("degraded_integrity_requires_escrow_floor")
        return IntegrityDecision(
            action_type=action_type,
            original_disposition=disposition,
            effective_disposition=effective,
            forced=forced,
            reasons=tuple(reasons),
            integrity=assessment,
        )


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    timestamp_ms: int
    event_type: str
    payload_json: str
    previous_hash: str
    record_hash: str

    @property
    def payload(self) -> Any:
        return json.loads(self.payload_json)

    def claims_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp_ms": self.timestamp_ms,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.claims_dict(), "record_hash": self.record_hash}


def _record_hash(record: AuditRecord) -> str:
    return hashlib.sha256(canonical_json_bytes(record.claims_dict())).hexdigest()


class HashChainedAuditLog:
    """Thread-safe append-only in-memory hash chain.

    Exported records can be verified independently.  Production should stream
    them to a durable WORM sink; an in-memory chain alone cannot survive process
    compromise or restart.
    """

    def __init__(self, *, clock_ms: Callable[[], int] = _system_clock_ms):
        self._clock_ms = clock_ms
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, event_type: str, payload: Mapping[str, Any]) -> AuditRecord:
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type is required")
        # Canonicalize now so later caller mutations cannot alter the record.
        payload_json = canonical_json_bytes(payload).decode("utf-8")
        with self._lock:
            previous_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
            unsigned = AuditRecord(
                sequence=len(self._records),
                timestamp_ms=self._clock_ms(),
                event_type=event_type,
                payload_json=payload_json,
                previous_hash=previous_hash,
                record_hash="",
            )
            record = AuditRecord(
                sequence=unsigned.sequence,
                timestamp_ms=unsigned.timestamp_ms,
                event_type=unsigned.event_type,
                payload_json=unsigned.payload_json,
                previous_hash=unsigned.previous_hash,
                record_hash=_record_hash(unsigned),
            )
            self._records.append(record)
            return record

    def records(self) -> Tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def verify(self) -> bool:
        return self.verify_records(self.records())

    @staticmethod
    def verify_records(records: Iterable[AuditRecord]) -> bool:
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records):
            if not isinstance(record, AuditRecord):
                return False
            if record.sequence != expected_sequence:
                return False
            if record.previous_hash != previous_hash:
                return False
            try:
                expected_hash = _record_hash(
                    AuditRecord(
                        sequence=record.sequence,
                        timestamp_ms=record.timestamp_ms,
                        event_type=record.event_type,
                        payload_json=record.payload_json,
                        previous_hash=record.previous_hash,
                        record_hash="",
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            if record.record_hash != expected_hash:
                return False
            previous_hash = record.record_hash
        return True
