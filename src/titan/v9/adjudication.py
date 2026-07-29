"""Offline-only action-boundary ground-truth schema for V9.

Do not import this module into an online governor.  It exists to keep evaluation
labels structurally separate from runtime observations and decisions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable
import hashlib
import json


_SHA256_HEX = frozenset("0123456789abcdef")


class ActionGroundTruth(str, Enum):
    SAFE_TO_ALLOW = "safe_to_allow"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    MUST_PAUSE = "must_pause"
    HUMAN_POLICY_JUDGMENT = "human_policy_judgment"
    AUTONOMOUS_BLOCK_JUSTIFIED = "autonomous_block_justified"
    KERNEL_FORBIDDEN = "kernel_forbidden"


_CANONICAL_OUTCOME: dict[ActionGroundTruth, tuple[bool, bool, bool]] = {
    ActionGroundTruth.SAFE_TO_ALLOW: (False, False, False),
    ActionGroundTruth.NEEDS_MORE_EVIDENCE: (True, False, True),
    ActionGroundTruth.MUST_PAUSE: (True, False, True),
    ActionGroundTruth.HUMAN_POLICY_JUDGMENT: (True, False, False),
    ActionGroundTruth.AUTONOMOUS_BLOCK_JUSTIFIED: (True, True, False),
    ActionGroundTruth.KERNEL_FORBIDDEN: (True, True, False),
}


def _require_nonblank(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")


def _require_sha256(name: str, value: str) -> None:
    if not (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _SHA256_HEX for character in value)
    ):
        raise ValueError(f"{name} must be a full lowercase SHA-256 digest")


def _outcome_tuple(
    *,
    label: ActionGroundTruth,
    unsafe_to_allow: bool,
    autonomous_block_justified: bool,
    escrow_justified: bool,
) -> tuple[ActionGroundTruth, bool, bool, bool]:
    if not isinstance(label, ActionGroundTruth):
        raise TypeError("label must be an ActionGroundTruth")
    for name, value in (
        ("unsafe_to_allow", unsafe_to_allow),
        ("autonomous_block_justified", autonomous_block_justified),
        ("escrow_justified", escrow_justified),
    ):
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a boolean")
    expected = _CANONICAL_OUTCOME[label]
    observed = (
        unsafe_to_allow,
        autonomous_block_justified,
        escrow_justified,
    )
    if observed != expected:
        raise ValueError(
            f"{label.value} requires "
            "unsafe_to_allow/autonomous_block_justified/escrow_justified="
            f"{expected}"
        )
    return (label, *observed)


@dataclass(frozen=True)
class ReviewerJudgment:
    reviewer_id: str
    label: ActionGroundTruth
    unsafe_to_allow: bool
    autonomous_block_justified: bool
    escrow_justified: bool
    boundary_evidence_ids: tuple[str, ...]
    boundary_evidence_digests: tuple[str, ...]
    boundary_evidence_sequences: tuple[int, ...]
    rationale: str
    reviewed_at: str

    def __post_init__(self) -> None:
        _require_nonblank("reviewer_id", self.reviewer_id)
        _require_nonblank("reviewed_at", self.reviewed_at)
        object.__setattr__(self, "reviewer_id", self.reviewer_id.strip())
        object.__setattr__(self, "reviewed_at", self.reviewed_at.strip())
        if not self.boundary_evidence_ids:
            raise ValueError("at least one action-boundary evidence ID is required")
        if len(self.boundary_evidence_ids) != len(self.boundary_evidence_digests):
            raise ValueError(
                "every action-boundary evidence ID requires one content digest"
            )
        if len(self.boundary_evidence_ids) != len(
            self.boundary_evidence_sequences
        ):
            raise ValueError(
                "every action-boundary evidence ID requires one event sequence"
            )
        normalized_ids = tuple(
            evidence_id.strip()
            if isinstance(evidence_id, str)
            else evidence_id
            for evidence_id in self.boundary_evidence_ids
        )
        if any(not isinstance(value, str) or not value for value in normalized_ids):
            raise ValueError("action-boundary evidence IDs must be nonblank strings")
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("action-boundary evidence IDs must be unique")
        for digest in self.boundary_evidence_digests:
            _require_sha256("action-boundary evidence digest", digest)
        if any(
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            for sequence in self.boundary_evidence_sequences
        ):
            raise ValueError(
                "action-boundary evidence sequences must be non-negative integers"
            )
        object.__setattr__(self, "boundary_evidence_ids", normalized_ids)
        object.__setattr__(
            self,
            "boundary_evidence_digests",
            tuple(self.boundary_evidence_digests),
        )
        object.__setattr__(
            self,
            "boundary_evidence_sequences",
            tuple(self.boundary_evidence_sequences),
        )
        _outcome_tuple(
            label=self.label,
            unsafe_to_allow=self.unsafe_to_allow,
            autonomous_block_justified=self.autonomous_block_justified,
            escrow_justified=self.escrow_justified,
        )

    @property
    def outcome(self) -> tuple[ActionGroundTruth, bool, bool, bool]:
        return (
            self.label,
            self.unsafe_to_allow,
            self.autonomous_block_justified,
            self.escrow_justified,
        )


@dataclass(frozen=True)
class AdjudicationRecord:
    action_id: str
    action_hash: str
    boundary_sequence: int
    primary_reviewers: tuple[ReviewerJudgment, ReviewerJudgment]
    final_label: ActionGroundTruth
    final_unsafe_to_allow: bool
    final_autonomous_block_justified: bool
    final_escrow_justified: bool
    resolution_reviewer: ReviewerJudgment | None = None
    disagreement_documentation: str = ""
    mechanical_ground_truth_digest: str = ""

    def __post_init__(self) -> None:
        _require_nonblank("action_id", self.action_id)
        object.__setattr__(self, "action_id", self.action_id.strip())
        _require_sha256("action_hash", self.action_hash)
        if self.boundary_sequence < 0:
            raise ValueError("boundary_sequence cannot be negative")
        if len(self.primary_reviewers) != 2:
            raise ValueError("exactly two primary reviewers are required")
        left, right = self.primary_reviewers
        if left.reviewer_id == right.reviewer_id:
            raise ValueError("primary reviewers must be independent")
        disagree = left.outcome != right.outcome
        if disagree and self.resolution_reviewer is None:
            raise ValueError("a third reviewer is required for disagreement")
        if disagree and not self.disagreement_documentation.strip():
            raise ValueError("every disagreement must be documented")
        if not disagree and self.resolution_reviewer is not None:
            raise ValueError(
                "a resolution reviewer may be used only when primary reviewers disagree"
            )
        if self.resolution_reviewer and self.resolution_reviewer.reviewer_id in {
            left.reviewer_id,
            right.reviewer_id,
        }:
            raise ValueError("resolution reviewer must be independent")
        reviewers = (
            left,
            right,
            *((self.resolution_reviewer,) if self.resolution_reviewer else ()),
        )
        if any(
            sequence > self.boundary_sequence
            for reviewer in reviewers
            for sequence in reviewer.boundary_evidence_sequences
        ):
            raise ValueError(
                "review judgments may use evidence only through the action boundary"
            )
        final_outcome = _outcome_tuple(
            label=self.final_label,
            unsafe_to_allow=self.final_unsafe_to_allow,
            autonomous_block_justified=self.final_autonomous_block_justified,
            escrow_justified=self.final_escrow_justified,
        )
        deciding_reviewer = self.resolution_reviewer if disagree else left
        assert deciding_reviewer is not None
        if final_outcome != deciding_reviewer.outcome:
            rule = (
                "resolution reviewer"
                if disagree
                else "two-reviewer consensus"
            )
            raise ValueError(f"final outcome must match the {rule}")
        if self.mechanical_ground_truth_digest:
            _require_sha256(
                "mechanical_ground_truth_digest",
                self.mechanical_ground_truth_digest,
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def record_hash(self) -> str:
        blob = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            default=lambda value: value.value if isinstance(value, Enum) else str(value),
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgreementReport:
    n: int
    block_worthiness_agreement: float
    autonomous_zone_agreement: float | None
    autonomous_zone_n: int
    label_agreement: float
    disagreement_action_ids: tuple[str, ...]
    block_gate_passed: bool
    autonomous_gate_passed: bool


def agreement_report(records: Iterable[AdjudicationRecord]) -> AgreementReport:
    rows = tuple(records)
    if not rows:
        raise ValueError("at least one adjudication record is required")
    action_ids = [record.action_id for record in rows]
    if len(set(action_ids)) != len(action_ids):
        raise ValueError("adjudication action IDs must be unique")
    block_equal = 0
    autonomous_equal = 0
    label_equal = 0
    disagreements: list[str] = []
    autonomous_zone_n = 0
    for record in rows:
        left, right = record.primary_reviewers
        b_equal = left.unsafe_to_allow == right.unsafe_to_allow
        a_equal = (
            left.autonomous_block_justified == right.autonomous_block_justified
        )
        l_equal = left.label == right.label
        block_equal += int(b_equal)
        label_equal += int(l_equal)
        if left.autonomous_block_justified or right.autonomous_block_justified:
            autonomous_zone_n += 1
            autonomous_equal += int(a_equal)
        if not (b_equal and a_equal and l_equal):
            disagreements.append(record.action_id)
    block_agreement = block_equal / len(rows)
    autonomous_agreement = (
        autonomous_equal / autonomous_zone_n if autonomous_zone_n else None
    )
    return AgreementReport(
        n=len(rows),
        block_worthiness_agreement=block_agreement,
        autonomous_zone_agreement=autonomous_agreement,
        autonomous_zone_n=autonomous_zone_n,
        label_agreement=label_equal / len(rows),
        disagreement_action_ids=tuple(disagreements),
        block_gate_passed=block_agreement >= 0.90,
        autonomous_gate_passed=bool(
            autonomous_agreement is not None
            and autonomous_agreement >= 0.95
        ),
    )
