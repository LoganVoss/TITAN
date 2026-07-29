"""
Explicit V9 evaluation populations and source/opportunity audits.

This is offline evaluation infrastructure.  ``label`` is retained only for
estimand calculation and is never exposed as an input to online decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from .metrics import MetricRecord


class PopulationContractError(ValueError):
    """Raised when evaluation populations are mixed or under-specified."""


class PopulationKind(str, Enum):
    LIVE = "A_live"
    TWIN = "B_protected_benign_twins"
    OPERATIONAL = "C_operational_mix"


class EvaluationLabel(str, Enum):
    HARMFUL = "harmful"
    BENIGN = "benign"


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    source_id: str
    action_class: str
    label: EvaluationLabel
    session_id: str = ""
    action_id: str = ""
    action_sha256: str = ""
    adjudication_sha256: str = ""
    subtype: str = "unspecified"
    threat_family: str = "unspecified"
    source_match_key: str = ""
    model_identifier: str = ""
    harness_id: str = ""
    repository_id: str = ""
    turn_budget: int = 0
    friction_profile: str = ""
    twin_of_case_id: str | None = None
    operational_stratum: str = ""

    def __post_init__(self) -> None:
        for field_name in (
            "case_id",
            "source_id",
            "action_class",
            "subtype",
            "threat_family",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise PopulationContractError(f"{field_name} is required")
        for field_name in (
            "session_id",
            "action_id",
            "action_sha256",
            "adjudication_sha256",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise PopulationContractError(f"{field_name} must be a string")
        for field_name in ("action_sha256", "adjudication_sha256"):
            digest = getattr(self, field_name)
            if digest and (
                len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise PopulationContractError(
                    f"{field_name} must be a lowercase SHA-256 digest"
                )
        for field_name in (
            "source_match_key",
            "model_identifier",
            "harness_id",
            "repository_id",
            "friction_profile",
            "operational_stratum",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise PopulationContractError(f"{field_name} must be a string")
        if (
            isinstance(self.turn_budget, bool)
            or not isinstance(self.turn_budget, int)
            or self.turn_budget < 0
        ):
            raise PopulationContractError(
                "turn_budget must be a non-negative integer"
            )
        if self.twin_of_case_id is not None and (
            not isinstance(self.twin_of_case_id, str)
            or not self.twin_of_case_id.strip()
        ):
            raise PopulationContractError(
                "twin_of_case_id must be None or a non-empty string"
            )
        try:
            object.__setattr__(self, "label", EvaluationLabel(self.label))
        except ValueError as exc:
            raise PopulationContractError(f"invalid evaluation label: {self.label}") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "case_id": self.case_id,
            "source_id": self.source_id,
            "action_class": self.action_class,
            "label": self.label.value,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "action_sha256": self.action_sha256,
            "adjudication_sha256": self.adjudication_sha256,
            "subtype": self.subtype,
            "threat_family": self.threat_family,
            "source_match_key": self.source_match_key,
            "model_identifier": self.model_identifier,
            "harness_id": self.harness_id,
            "repository_id": self.repository_id,
            "turn_budget": self.turn_budget,
            "friction_profile": self.friction_profile,
            "twin_of_case_id": self.twin_of_case_id,
            "operational_stratum": self.operational_stratum,
        }


@dataclass(frozen=True)
class EvaluationPopulation:
    population_id: str
    kind: PopulationKind
    cases: tuple[EvaluationCase, ...]
    metadata: Mapping[str, Any] = None

    def __post_init__(self) -> None:
        if not isinstance(self.population_id, str) or not self.population_id.strip():
            raise PopulationContractError("population_id is required")
        try:
            object.__setattr__(self, "kind", PopulationKind(self.kind))
        except ValueError as exc:
            raise PopulationContractError(f"invalid population kind: {self.kind}") from exc
        cases = tuple(self.cases)
        if not cases:
            raise PopulationContractError("evaluation population cannot be empty")
        if any(not isinstance(case, EvaluationCase) for case in cases):
            raise PopulationContractError("cases must be EvaluationCase instances")
        ids = [case.case_id for case in cases]
        if len(ids) != len(set(ids)):
            raise PopulationContractError("duplicate case_id inside population")
        action_ids = [case.action_id for case in cases if case.action_id]
        if len(action_ids) != len(set(action_ids)):
            raise PopulationContractError("duplicate action_id inside population")
        object.__setattr__(self, "cases", cases)
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(sorted((self.metadata or {}).items()))),
        )

    @property
    def n_cases(self) -> int:
        return len(self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "population_id": self.population_id,
            "kind": self.kind.value,
            "n_cases": self.n_cases,
            "metadata": dict(self.metadata),
            "cases": [case.to_dict() for case in self.cases],
        }


@dataclass(frozen=True)
class DisjointnessAudit:
    disjoint: bool
    overlaps: Mapping[str, tuple[str, ...]]
    allowed_operational_overlaps: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        overlaps = {
            str(key): tuple(sorted(set(value)))
            for key, value in self.overlaps.items()
        }
        allowed = {
            str(key): tuple(sorted(set(value)))
            for key, value in self.allowed_operational_overlaps.items()
        }
        if any(not key or not values for key, values in (*overlaps.items(), *allowed.items())):
            raise PopulationContractError(
                "overlap audit keys and overlap sets must be non-empty"
            )
        if set(overlaps) & set(allowed):
            raise PopulationContractError(
                "an overlap cannot be both forbidden and operationally allowed"
            )
        if self.disjoint != (not overlaps):
            raise PopulationContractError(
                "disjointness flag must be derived from forbidden overlaps"
            )
        object.__setattr__(
            self,
            "overlaps",
            MappingProxyType(dict(sorted(overlaps.items()))),
        )
        object.__setattr__(
            self,
            "allowed_operational_overlaps",
            MappingProxyType(dict(sorted(allowed.items()))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "disjoint": self.disjoint,
            "overlaps": {key: list(value) for key, value in self.overlaps.items()},
            "allowed_operational_overlaps": {
                key: list(value)
                for key, value in self.allowed_operational_overlaps.items()
            },
        }


def audit_disjointness(
    populations: Sequence[EvaluationPopulation],
    *,
    allow_operational_composition: bool = False,
) -> DisjointnessAudit:
    """
    Audit source-level overlap, not merely case-ID overlap.

    Operational C may intentionally be a published mixture of A/B.  Such
    overlap is only accepted when explicitly declared by the caller and remains
    visible in ``allowed_operational_overlaps``.
    """
    if len(populations) < 2:
        raise PopulationContractError("at least two populations are required")
    ids = [population.population_id for population in populations]
    if len(ids) != len(set(ids)):
        raise PopulationContractError("population IDs must be unique")

    overlaps: dict[str, tuple[str, ...]] = {}
    allowed: dict[str, tuple[str, ...]] = {}
    for index, left in enumerate(populations):
        left_sources = {case.source_id for case in left.cases}
        left_cases = {case.case_id for case in left.cases}
        for right in populations[index + 1 :]:
            shared_sources = left_sources & {case.source_id for case in right.cases}
            shared_cases = left_cases & {case.case_id for case in right.cases}
            shared = tuple(
                sorted(
                    [f"source_id:{item}" for item in shared_sources]
                    + [f"case_id:{item}" for item in shared_cases]
                )
            )
            if not shared:
                continue
            key = f"{left.population_id}::{right.population_id}"
            operational_pair = PopulationKind.OPERATIONAL in (left.kind, right.kind)
            if operational_pair and allow_operational_composition:
                allowed[key] = shared
            else:
                overlaps[key] = shared
    return DisjointnessAudit(
        disjoint=not overlaps,
        overlaps=MappingProxyType(overlaps),
        allowed_operational_overlaps=MappingProxyType(allowed),
    )


@dataclass(frozen=True)
class ActionOpportunity:
    action_class: str
    harmful: int
    benign: int
    minimum_required_per_label: int

    def __post_init__(self) -> None:
        if not isinstance(self.action_class, str) or not self.action_class.strip():
            raise PopulationContractError("action opportunity class is required")
        for name in ("harmful", "benign"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PopulationContractError(
                    f"action opportunity {name} must be a non-negative integer"
                )
        if (
            isinstance(self.minimum_required_per_label, bool)
            or not isinstance(self.minimum_required_per_label, int)
            or self.minimum_required_per_label < 1
        ):
            raise PopulationContractError(
                "minimum_required_per_label must be a positive integer"
            )

    @property
    def covered(self) -> bool:
        return (
            self.harmful >= self.minimum_required_per_label
            and self.benign >= self.minimum_required_per_label
        )

    @property
    def parity_ratio(self) -> float:
        larger = max(self.harmful, self.benign)
        if larger == 0:
            return 0.0
        return min(self.harmful, self.benign) / larger

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_class": self.action_class,
            "harmful": self.harmful,
            "benign": self.benign,
            "minimum_required_per_label": self.minimum_required_per_label,
            "covered": self.covered,
            "parity_ratio": self.parity_ratio,
        }


@dataclass(frozen=True)
class OpportunityAudit:
    population_id: str
    passed: bool
    opportunities: Mapping[str, ActionOpportunity]
    missing_harmful: tuple[str, ...]
    missing_benign: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.population_id, str) or not self.population_id.strip():
            raise PopulationContractError("opportunity audit population_id is required")
        opportunities = dict(self.opportunities)
        if any(
            key != opportunity.action_class
            or not isinstance(opportunity, ActionOpportunity)
            for key, opportunity in opportunities.items()
        ):
            raise PopulationContractError(
                "opportunity keys must match ActionOpportunity.action_class"
            )
        expected_harmful = tuple(
            sorted(
                key
                for key, opportunity in opportunities.items()
                if opportunity.harmful < opportunity.minimum_required_per_label
            )
        )
        expected_benign = tuple(
            sorted(
                key
                for key, opportunity in opportunities.items()
                if opportunity.benign < opportunity.minimum_required_per_label
            )
        )
        supplied_harmful = tuple(sorted(self.missing_harmful))
        supplied_benign = tuple(sorted(self.missing_benign))
        if supplied_harmful != expected_harmful or supplied_benign != expected_benign:
            raise PopulationContractError(
                "opportunity missing-class lists must be derived from counts"
            )
        expected_pass = not expected_harmful and not expected_benign
        if self.passed != expected_pass:
            raise PopulationContractError(
                "opportunity passed flag must be derived from counts"
            )
        object.__setattr__(
            self,
            "opportunities",
            MappingProxyType(dict(sorted(opportunities.items()))),
        )
        object.__setattr__(self, "missing_harmful", supplied_harmful)
        object.__setattr__(self, "missing_benign", supplied_benign)

    def to_dict(self) -> dict[str, Any]:
        return {
            "population_id": self.population_id,
            "passed": self.passed,
            "missing_harmful": list(self.missing_harmful),
            "missing_benign": list(self.missing_benign),
            "opportunities": {
                key: value.to_dict() for key, value in self.opportunities.items()
            },
        }


def audit_action_opportunities(
    population: EvaluationPopulation,
    *,
    required_action_classes: Iterable[str],
    minimum_per_label: int = 1,
) -> OpportunityAudit:
    if isinstance(minimum_per_label, bool) or not isinstance(minimum_per_label, int):
        raise PopulationContractError("minimum_per_label must be an integer")
    if minimum_per_label < 1:
        raise PopulationContractError("minimum_per_label must be positive")
    supplied = tuple(required_action_classes)
    if (
        not supplied
        or any(not isinstance(name, str) or not name.strip() for name in supplied)
    ):
        raise PopulationContractError("required_action_classes cannot be empty")
    required = tuple(sorted(set(supplied)))

    opportunities: dict[str, ActionOpportunity] = {}
    missing_harmful: list[str] = []
    missing_benign: list[str] = []
    for action_class in required:
        harmful = sum(
            case.action_class == action_class
            and case.label == EvaluationLabel.HARMFUL
            for case in population.cases
        )
        benign = sum(
            case.action_class == action_class
            and case.label == EvaluationLabel.BENIGN
            for case in population.cases
        )
        opportunity = ActionOpportunity(
            action_class=action_class,
            harmful=int(harmful),
            benign=int(benign),
            minimum_required_per_label=minimum_per_label,
        )
        opportunities[action_class] = opportunity
        if harmful < minimum_per_label:
            missing_harmful.append(action_class)
        if benign < minimum_per_label:
            missing_benign.append(action_class)
    return OpportunityAudit(
        population_id=population.population_id,
        passed=not missing_harmful and not missing_benign,
        opportunities=MappingProxyType(opportunities),
        missing_harmful=tuple(missing_harmful),
        missing_benign=tuple(missing_benign),
    )


@dataclass(frozen=True)
class PopulationMetricReport:
    population: EvaluationPopulation
    metrics: tuple[MetricRecord, ...]

    def __post_init__(self) -> None:
        metrics = tuple(self.metrics)
        if not metrics:
            raise PopulationContractError("population report needs at least one metric")
        for metric in metrics:
            if not isinstance(metric, MetricRecord):
                raise PopulationContractError("report metrics must be MetricRecord instances")
            if metric.population not in (
                self.population.population_id,
                self.population.kind.value,
            ):
                raise PopulationContractError(
                    f"metric population {metric.population!r} does not match "
                    f"{self.population.population_id!r}"
                )
            case_ids = set(metric.evaluated_case_ids)
            population_ids = {case.case_id for case in self.population.cases}
            unknown = sorted(case_ids - population_ids)
            if unknown:
                raise PopulationContractError(
                    f"metric references cases outside its population: {unknown[:5]}"
                )
            if metric.observation_sha256 and case_ids:
                selected = sorted(
                    (
                        case.to_dict()
                        for case in self.population.cases
                        if case.case_id in case_ids
                    ),
                    key=lambda item: item["case_id"],
                )
                expected = hashlib.sha256(
                    json.dumps(
                        selected,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest()
                if metric.observation_sha256 != expected:
                    raise PopulationContractError(
                        "metric observation hash does not match evaluated cases"
                    )
        object.__setattr__(self, "metrics", metrics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "population": self.population.to_dict(),
            "metrics": [metric.to_dict() for metric in self.metrics],
        }


@dataclass(frozen=True)
class SeparatePopulationReport:
    evaluation_a_live: PopulationMetricReport
    evaluation_b_twins: PopulationMetricReport
    evaluation_c_operational: PopulationMetricReport
    disjointness_audit: DisjointnessAudit
    live_opportunity_audit: OpportunityAudit
    allow_operational_composition: bool = False

    def __post_init__(self) -> None:
        expected = (
            (self.evaluation_a_live, PopulationKind.LIVE),
            (self.evaluation_b_twins, PopulationKind.TWIN),
            (self.evaluation_c_operational, PopulationKind.OPERATIONAL),
        )
        for report, kind in expected:
            if report.population.kind != kind:
                raise PopulationContractError(
                    f"expected {kind.value}, got {report.population.kind.value}"
                )
        if self.live_opportunity_audit.population_id != (
            self.evaluation_a_live.population.population_id
        ):
            raise PopulationContractError("opportunity audit must target Evaluation A")
        if not isinstance(self.allow_operational_composition, bool):
            raise PopulationContractError(
                "allow_operational_composition must be boolean"
            )
        recomputed_disjointness = audit_disjointness(
            (
                self.evaluation_a_live.population,
                self.evaluation_b_twins.population,
                self.evaluation_c_operational.population,
            ),
            allow_operational_composition=self.allow_operational_composition,
        )
        if self.disjointness_audit != recomputed_disjointness:
            raise PopulationContractError(
                "disjointness audit does not match the supplied populations"
            )

        live_cases = self.evaluation_a_live.population.cases
        for action_class, opportunity in (
            self.live_opportunity_audit.opportunities.items()
        ):
            harmful = sum(
                case.action_class == action_class
                and case.label == EvaluationLabel.HARMFUL
                for case in live_cases
            )
            benign = sum(
                case.action_class == action_class
                and case.label == EvaluationLabel.BENIGN
                for case in live_cases
            )
            if opportunity.harmful != harmful or opportunity.benign != benign:
                raise PopulationContractError(
                    "live opportunity counts do not match Evaluation A cases"
                )

    @property
    def release_audit_passed(self) -> bool:
        return self.disjointness_audit.disjoint and self.live_opportunity_audit.passed

    def to_dict(self) -> dict[str, Any]:
        # There is intentionally no pooled/headline metric field.
        return {
            "evaluation_a_live": self.evaluation_a_live.to_dict(),
            "evaluation_b_protected_benign_twins": self.evaluation_b_twins.to_dict(),
            "evaluation_c_operational_mix": self.evaluation_c_operational.to_dict(),
            "audits": {
                "release_passed": self.release_audit_passed,
                "disjointness": self.disjointness_audit.to_dict(),
                "live_action_opportunities": self.live_opportunity_audit.to_dict(),
            },
        }
