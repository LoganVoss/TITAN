"""
TITAN V9 evidence metrics.

This module is deliberately evaluation-only.  It contains no online decision
logic and must never be given access to a governor's hidden ground-truth label.

The two central invariants are:

* every emitted metric is self-describing, including undefined metrics; and
* an FPR operating point is selected over complete score-tie groups, exactly as
  the deployed ``score >= threshold`` rule will behave.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from statistics import NormalDist
from types import MappingProxyType
from typing import Any, Mapping, Sequence


class MetricContractError(ValueError):
    """Raised when a metric cannot satisfy the V9 evidence contract."""


class ThresholdKind(str, Enum):
    VALUE = "value"
    NOT_APPLICABLE = "not_applicable"


class UnitOfAnalysis(str, Enum):
    TRAJECTORY = "trajectory"
    ACTION_PREFIX = "action_prefix"
    ACTION = "action"
    SESSION = "session"


class PrefixRule(str, Enum):
    FULL = "full"
    EXCLUSIVE_IRREVERSIBLE = "exclusive_irreversible"
    ACTION_BOUNDARY = "action_boundary"
    NOT_APPLICABLE = "not_applicable"


class LatchingRule(str, Enum):
    NONE = "none"
    FIRST_ALERT_STICKS = "first_alert_sticks"
    MULTI = "multi"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class Threshold:
    """A numeric operating threshold or an explicit, justified N/A."""

    kind: ThresholdKind
    source: str
    value: float | None = None

    def __post_init__(self) -> None:
        try:
            kind = ThresholdKind(self.kind)
        except ValueError as exc:
            raise MetricContractError(f"invalid threshold kind: {self.kind!r}") from exc
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.source, str) or not self.source.strip():
            raise MetricContractError("threshold source is required")
        if kind == ThresholdKind.VALUE:
            if self.value is None or not math.isfinite(float(self.value)):
                raise MetricContractError("numeric threshold must be finite")
            object.__setattr__(self, "value", float(self.value))
        elif self.value is not None:
            raise MetricContractError("N/A threshold cannot carry a numeric value")

    @classmethod
    def at(cls, value: float, source: str) -> "Threshold":
        return cls(kind=ThresholdKind.VALUE, value=value, source=source)

    @classmethod
    def not_applicable(cls, source: str = "not_applicable") -> "Threshold":
        return cls(kind=ThresholdKind.NOT_APPLICABLE, value=None, source=source)

    @property
    def is_applicable(self) -> bool:
        return self.kind == ThresholdKind.VALUE

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.kind.value,
            "value": self.value,
            "source": self.source,
        }


@dataclass(frozen=True)
class ConfidenceInterval:
    """A confidence interval, or an explicit explanation for no interval."""

    method: str
    level: float
    lower: float | None
    upper: float | None
    undefined_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not self.method.strip():
            raise MetricContractError("confidence-interval method is required")
        if not math.isclose(float(self.level), 0.95, rel_tol=0.0, abs_tol=1e-12):
            raise MetricContractError(
                "V9 release evidence requires a fixed 95% confidence interval"
            )
        object.__setattr__(self, "level", float(self.level))
        defined = self.lower is not None or self.upper is not None
        if defined:
            if self.lower is None or self.upper is None:
                raise MetricContractError("confidence interval needs both bounds")
            lo, hi = float(self.lower), float(self.upper)
            if not math.isfinite(lo) or not math.isfinite(hi) or lo > hi:
                raise MetricContractError("invalid confidence-interval bounds")
            if self.undefined_reason:
                raise MetricContractError("defined interval cannot have an undefined reason")
            object.__setattr__(self, "lower", lo)
            object.__setattr__(self, "upper", hi)
        elif not self.undefined_reason:
            raise MetricContractError("undefined interval requires a reason")

    @classmethod
    def defined(
        cls,
        *,
        method: str,
        lower: float,
        upper: float,
        level: float = 0.95,
    ) -> "ConfidenceInterval":
        return cls(method=method, level=level, lower=lower, upper=upper)

    @classmethod
    def not_available(
        cls,
        reason: str,
        *,
        method: str = "not_applicable",
        level: float = 0.95,
    ) -> "ConfidenceInterval":
        return cls(
            method=method,
            level=level,
            lower=None,
            upper=None,
            undefined_reason=reason,
        )

    @property
    def is_defined(self) -> bool:
        return self.lower is not None and self.upper is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "level": self.level,
            "lower": self.lower,
            "upper": self.upper,
            "undefined_reason": self.undefined_reason,
        }


def _frozen_counts(raw_counts: Mapping[str, int]) -> Mapping[str, int]:
    if not raw_counts:
        raise MetricContractError("raw_counts cannot be empty")
    clean: dict[str, int] = {}
    for key, value in raw_counts.items():
        if not isinstance(key, str) or not key.strip():
            raise MetricContractError("raw-count keys must be non-empty strings")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MetricContractError(f"raw count {key!r} must be a non-negative integer")
        clean[key] = value
    return MappingProxyType(dict(sorted(clean.items())))


def _ratio_from_counts(
    name: str,
    counts: Mapping[str, int],
) -> tuple[int, int] | None:
    """Return the auditable numerator/denominator for count-derived metrics.

    ``numerator``/``evaluated`` is the canonical generic representation.  The
    named fallbacks keep existing confusion-matrix artifacts self-checking.
    Metrics such as AUROC and average precision are not count-derived; their
    row-level score artifacts must be bound separately by the release manifest.
    """

    if "numerator" in counts and "evaluated" in counts:
        return counts["numerator"], counts["evaluated"]
    lowered = name.lower()
    if "precision" in lowered and {"tp", "fp"}.issubset(counts):
        return counts["tp"], counts["tp"] + counts["fp"]
    if "recall" in lowered and {"tp", "fn"}.issubset(counts):
        return counts["tp"], counts["tp"] + counts["fn"]
    if "false_block_rate" in lowered and {"fp", "tn"}.issubset(counts):
        return counts["fp"], counts["fp"] + counts["tn"]
    if "accuracy" in lowered and {"correct", "incorrect"}.issubset(counts):
        return counts["correct"], counts["correct"] + counts["incorrect"]
    return None


@dataclass(frozen=True)
class MetricRecord:
    """
    Complete, machine-checkable metric evidence.

    ``value=None`` is the sole representation of an undefined metric.  It must
    be accompanied by ``undefined_reason``; sentinels such as ``-1`` are
    rejected by construction.
    """

    name: str
    scorer: str
    value: float | None
    threshold: Threshold
    denominator: int
    raw_counts: Mapping[str, int]
    unit_of_analysis: UnitOfAnalysis
    action_class: str
    population: str
    calibration_population: str
    prefix_rule: PrefixRule
    latching_rule: LatchingRule
    confidence_interval: ConfidenceInterval
    undefined_reason: str | None = None
    contract_version: str = "titan-v9-metric-contract-1"
    evaluated_case_ids: tuple[str, ...] = ()
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        for field_name in (
            "name",
            "scorer",
            "action_class",
            "population",
            "calibration_population",
            "contract_version",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise MetricContractError(f"{field_name} is required")
        if isinstance(self.denominator, bool) or not isinstance(self.denominator, int):
            raise MetricContractError("denominator must be an integer")
        if self.denominator < 0:
            raise MetricContractError("denominator cannot be negative")
        object.__setattr__(self, "raw_counts", _frozen_counts(self.raw_counts))
        case_ids = tuple(self.evaluated_case_ids)
        if any(not isinstance(item, str) or not item.strip() for item in case_ids):
            raise MetricContractError("evaluated_case_ids must be non-empty strings")
        if len(case_ids) != len(set(case_ids)):
            raise MetricContractError("evaluated_case_ids contains duplicates")
        if case_ids and len(case_ids) != self.denominator:
            raise MetricContractError(
                "metric denominator must equal the number of evaluated case IDs"
            )
        object.__setattr__(self, "evaluated_case_ids", case_ids)
        if self.observation_sha256:
            digest = self.observation_sha256
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise MetricContractError(
                    "observation_sha256 must be a lowercase SHA-256 digest"
                )
        if "evaluated" in self.raw_counts:
            if self.raw_counts["evaluated"] != self.denominator:
                raise MetricContractError(
                    "raw_counts['evaluated'] must equal metric denominator"
                )
        try:
            object.__setattr__(self, "unit_of_analysis", UnitOfAnalysis(self.unit_of_analysis))
            object.__setattr__(self, "prefix_rule", PrefixRule(self.prefix_rule))
            object.__setattr__(self, "latching_rule", LatchingRule(self.latching_rule))
        except ValueError as exc:
            raise MetricContractError(str(exc)) from exc
        if not isinstance(self.threshold, Threshold):
            raise MetricContractError("threshold must be a Threshold")
        if not isinstance(self.confidence_interval, ConfidenceInterval):
            raise MetricContractError("confidence_interval must be a ConfidenceInterval")

        if self.value is None:
            if not self.undefined_reason:
                raise MetricContractError("undefined metric requires undefined_reason")
            if self.confidence_interval.is_defined:
                raise MetricContractError("undefined metric cannot have a defined interval")
        else:
            numeric = float(self.value)
            if not math.isfinite(numeric):
                raise MetricContractError("metric value must be finite or explicit N/A")
            probability_terms = (
                "auroc",
                "average_precision",
                "precision",
                "recall",
                "rate",
                "coverage",
                "agreement",
                "calibration_error",
                "brier",
            )
            if any(term in self.name.lower() for term in probability_terms):
                if not 0.0 <= numeric <= 1.0:
                    raise MetricContractError(
                        f"proportion metric {self.name!r} must be in [0, 1]; "
                        "use value=None for undefined"
                    )
            if self.undefined_reason:
                raise MetricContractError("defined metric cannot have undefined_reason")
            object.__setattr__(self, "value", numeric)
            if self.confidence_interval.is_defined:
                lo = float(self.confidence_interval.lower)
                hi = float(self.confidence_interval.upper)
                if not lo <= numeric <= hi:
                    raise MetricContractError("confidence interval must contain metric value")
                probability_terms = (
                    "auroc",
                    "average_precision",
                    "precision",
                    "recall",
                    "rate",
                    "coverage",
                    "agreement",
                    "calibration_error",
                    "brier",
                    "accuracy",
                )
                if any(term in self.name.lower() for term in probability_terms):
                    if not 0.0 <= lo <= hi <= 1.0:
                        raise MetricContractError(
                            "proportion confidence intervals must stay within [0, 1]"
                        )
            ratio = _ratio_from_counts(self.name, self.raw_counts)
            if ratio is not None:
                numerator, count_denominator = ratio
                if count_denominator != self.denominator:
                    raise MetricContractError(
                        "raw count denominator does not match metric denominator"
                    )
                if numerator > count_denominator:
                    raise MetricContractError("raw numerator exceeds denominator")
                if count_denominator == 0:
                    raise MetricContractError(
                        "defined count-derived metric needs a positive denominator"
                    )
                expected = numerator / count_denominator
                if not math.isclose(
                    numeric,
                    expected,
                    rel_tol=0.0,
                    abs_tol=1e-12,
                ):
                    raise MetricContractError(
                        "metric point estimate does not match its raw counts"
                    )

    @property
    def is_defined(self) -> bool:
        return self.value is not None

    @property
    def threshold_source(self) -> str:
        return self.threshold.source

    @property
    def has_reconciled_counts(self) -> bool:
        if self.raw_counts.get("evaluated") != self.denominator:
            return False
        ratio = _ratio_from_counts(self.name, self.raw_counts)
        if ratio is None:
            # Ranking metrics require sealed row-level observations instead.
            return bool(self.observation_sha256 and self.evaluated_case_ids)
        if self.value is None:
            return self.denominator == 0
        numerator, denominator = ratio
        return bool(
            denominator == self.denominator
            and denominator > 0
            and math.isclose(
                float(self.value),
                numerator / denominator,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        # Threshold fields are deliberately flattened for easy artifact audits.
        return {
            "contract_version": self.contract_version,
            "name": self.name,
            "scorer": self.scorer,
            "value": self.value,
            "undefined_reason": self.undefined_reason,
            "threshold": self.threshold.value,
            "threshold_status": self.threshold.kind.value,
            "threshold_source": self.threshold.source,
            "denominator": self.denominator,
            "raw_counts": dict(self.raw_counts),
            "unit_of_analysis": self.unit_of_analysis.value,
            "action_class": self.action_class,
            "population": self.population,
            "calibration_population": self.calibration_population,
            "prefix_rule": self.prefix_rule.value,
            "latching_rule": self.latching_rule.value,
            "confidence_interval": self.confidence_interval.to_dict(),
            "evaluated_case_ids": list(self.evaluated_case_ids),
            "observation_sha256": self.observation_sha256 or None,
        }


def wilson_interval(
    successes: int,
    denominator: int,
    *,
    confidence: float = 0.95,
) -> ConfidenceInterval:
    """Wilson score interval for a binomial proportion."""
    if isinstance(successes, bool) or isinstance(denominator, bool):
        raise MetricContractError("counts must be integers")
    if not isinstance(successes, int) or not isinstance(denominator, int):
        raise MetricContractError("counts must be integers")
    if denominator < 0 or successes < 0 or successes > denominator:
        raise MetricContractError("invalid binomial counts")
    if denominator == 0:
        return ConfidenceInterval.not_available(
            "zero denominator",
            method="wilson",
            level=confidence,
        )
    if not (0.0 < confidence < 1.0):
        raise MetricContractError("confidence must be in (0, 1)")
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    n = float(denominator)
    p = successes / n
    z2 = z * z
    center = (p + z2 / (2.0 * n)) / (1.0 + z2 / n)
    half = (
        z
        * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)
        / (1.0 + z2 / n)
    )
    return ConfidenceInterval.defined(
        method="wilson",
        level=confidence,
        lower=max(0.0, center - half),
        upper=min(1.0, center + half),
    )


@dataclass(frozen=True)
class RecallAtFPRResult:
    target_fpr: float
    threshold: float
    recall: float
    empirical_fpr: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    n_positive: int
    n_negative: int
    max_false_positives: int
    selected_score_groups: int

    def __post_init__(self) -> None:
        if self.empirical_fpr > self.target_fpr + 1e-15:
            raise MetricContractError("selected threshold exceeds target FPR")

    @property
    def raw_counts(self) -> dict[str, int]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_fpr": self.target_fpr,
            "threshold": self.threshold,
            "recall": self.recall,
            "empirical_fpr": self.empirical_fpr,
            "raw_counts": self.raw_counts,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "max_false_positives": self.max_false_positives,
            "selected_score_groups": self.selected_score_groups,
            "tie_policy": "whole_equal_score_groups",
            "prediction_rule": "score >= threshold",
        }


def tie_safe_recall_at_fpr(
    scores: Sequence[float],
    labels: Sequence[int | bool | float],
    target_fpr: float,
) -> RecallAtFPRResult:
    """
    Choose the highest-recall threshold whose *empirical* FPR is in budget.

    Equal scores are processed as an indivisible group.  This prevents choosing
    an impossible operating point in the middle of a score mass.
    """
    if len(scores) != len(labels):
        raise MetricContractError("scores and labels must have equal length")
    if len(scores) == 0:
        raise MetricContractError("scores cannot be empty")
    target = float(target_fpr)
    if not math.isfinite(target) or not 0.0 <= target <= 1.0:
        raise MetricContractError("target_fpr must be in [0, 1]")

    rows: list[tuple[float, int]] = []
    for score, label in zip(scores, labels):
        s = float(score)
        if not math.isfinite(s):
            raise MetricContractError("scores must be finite")
        y_float = float(label)
        if y_float not in (0.0, 1.0):
            raise MetricContractError("labels must be binary")
        rows.append((s, int(y_float)))

    n_positive = sum(y for _, y in rows)
    n_negative = len(rows) - n_positive
    if n_positive == 0:
        raise MetricContractError("recall is undefined without positive examples")
    if n_negative == 0:
        raise MetricContractError("FPR is undefined without negative examples")

    groups: dict[float, list[int]] = {}
    for score, label in rows:
        groups.setdefault(score, []).append(label)
    ordered = sorted(groups.items(), key=lambda item: item[0], reverse=True)

    # Integer budgeting avoids floating-point acceptance of an extra false
    # positive near a boundary such as 1/100 > 0.009999999.
    max_fp = int(math.floor(target * n_negative + 1e-12))
    max_score = ordered[0][0]
    no_alert_threshold = math.nextafter(max_score, math.inf)
    if not math.isfinite(no_alert_threshold):
        raise MetricContractError("cannot construct a finite no-alert threshold")

    best_threshold = no_alert_threshold
    best_tp = 0
    best_fp = 0
    best_groups = 0
    cumulative_tp = 0
    cumulative_fp = 0

    for group_index, (score, group_labels) in enumerate(ordered, start=1):
        cumulative_tp += sum(group_labels)
        cumulative_fp += len(group_labels) - sum(group_labels)
        if cumulative_fp > max_fp:
            # FPR can only increase as the threshold is lowered.
            break
        best_threshold = score
        best_tp = cumulative_tp
        best_fp = cumulative_fp
        best_groups = group_index

    fn = n_positive - best_tp
    tn = n_negative - best_fp
    empirical_fpr = best_fp / n_negative
    recall = best_tp / n_positive
    return RecallAtFPRResult(
        target_fpr=target,
        threshold=float(best_threshold),
        recall=float(recall),
        empirical_fpr=float(empirical_fpr),
        true_positives=best_tp,
        false_positives=best_fp,
        true_negatives=tn,
        false_negatives=fn,
        n_positive=n_positive,
        n_negative=n_negative,
        max_false_positives=max_fp,
        selected_score_groups=best_groups,
    )


# Explicit aliases make migration from earlier metric modules unambiguous.
recall_at_fpr = tie_safe_recall_at_fpr
recall_at_fpr_tie_safe = tie_safe_recall_at_fpr
