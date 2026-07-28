"""Externally fit isotonic calibration with hierarchical fallbacks.

Rank scores and probabilities are intentionally separate types.  Calibrators
may only be fit from records explicitly marked as calibration-population data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
import bisect
import hashlib
import json
import math
import threading


CALIBRATION_POPULATION = "calibration"
CALIBRATION_DATASET_SCHEMA = "titan-v9-calibration-dataset/1"
_SHA256_HEX = frozenset("0123456789abcdef")


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def wilson_interval(positives: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 1.0)
    p = positives / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    radius = (
        z
        * math.sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total))
        / denom
    )
    lower = 0.0 if positives == 0 else _clip(center - radius)
    upper = 1.0 if positives == total else _clip(center + radius)
    return (lower, upper)


@dataclass(frozen=True)
class CalibrationSample:
    rank_score: float
    outcome: int
    action_type: str
    environment: str
    population: str = CALIBRATION_POPULATION
    sample_id: str = ""
    source_id: str = ""

    def __post_init__(self) -> None:
        if (
            isinstance(self.rank_score, bool)
            or not isinstance(self.rank_score, (int, float))
            or not math.isfinite(float(self.rank_score))
            or not 0.0 <= float(self.rank_score) <= 1.0
        ):
            raise ValueError("rank_score must be in [0,1]")
        if isinstance(self.outcome, bool) or not isinstance(self.outcome, int):
            raise ValueError("outcome must be binary")
        if self.outcome not in (0, 1):
            raise ValueError("outcome must be binary")
        for name in (
            "action_type",
            "environment",
            "population",
            "sample_id",
            "source_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
            object.__setattr__(self, name, value.strip())
        object.__setattr__(self, "rank_score", float(self.rank_score))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validated_samples(
    samples: Sequence[CalibrationSample],
) -> tuple[CalibrationSample, ...]:
    rows = tuple(samples)
    if not rows:
        raise ValueError("calibration dataset is empty")
    if any(not isinstance(row, CalibrationSample) for row in rows):
        raise TypeError("calibration dataset contains an unexpected row type")
    sample_ids = [row.sample_id for row in rows]
    if len(set(sample_ids)) != len(sample_ids):
        duplicates = sorted(
            sample_id
            for sample_id in set(sample_ids)
            if sample_ids.count(sample_id) > 1
        )
        raise ValueError(
            "calibration sample IDs must be unique; duplicates: "
            + ",".join(duplicates[:5])
        )
    return rows


def calibration_dataset_digest(
    samples: Sequence[CalibrationSample],
    *,
    dataset_id: str,
    split_id: str,
) -> str:
    """Hash the exact calibration rows and their declared dataset/split."""

    if not isinstance(dataset_id, str) or not dataset_id.strip():
        raise ValueError("dataset_id is required")
    if not isinstance(split_id, str) or not split_id.strip():
        raise ValueError("split_id is required")
    rows = _validated_samples(samples)
    content = {
        "schema": CALIBRATION_DATASET_SCHEMA,
        "dataset_id": dataset_id.strip(),
        "split_id": split_id.strip(),
        "samples": [
            row.to_dict()
            for row in sorted(rows, key=lambda item: item.sample_id)
        ],
    }
    blob = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class CalibrationDatasetSeal:
    """Canonical identity for one immutable calibration split."""

    dataset_id: str
    split_id: str
    dataset_digest: str
    sample_count: int
    source_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("dataset_id", "split_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
            object.__setattr__(self, name, value.strip())
        if not (
            isinstance(self.dataset_digest, str)
            and len(self.dataset_digest) == 64
            and all(character in _SHA256_HEX for character in self.dataset_digest)
        ):
            raise ValueError(
                "dataset_digest must be a full lowercase SHA-256 digest"
            )
        if (
            isinstance(self.sample_count, bool)
            or not isinstance(self.sample_count, int)
            or self.sample_count <= 0
        ):
            raise ValueError("sample_count must be positive")
        if (
            not isinstance(self.source_ids, tuple)
            or not self.source_ids
            or any(
                not isinstance(source_id, str) or not source_id.strip()
                for source_id in self.source_ids
            )
        ):
            raise ValueError(
                "source_ids must be a nonempty sorted set of nonblank IDs"
            )
        normalized_sources = tuple(sorted(set(self.source_ids)))
        if (
            normalized_sources != self.source_ids
            or any(source_id != source_id.strip() for source_id in self.source_ids)
        ):
            raise ValueError(
                "source_ids must be a nonempty sorted set of nonblank IDs"
            )

    @classmethod
    def create(
        cls,
        samples: Sequence[CalibrationSample],
        *,
        dataset_id: str,
        split_id: str,
    ) -> "CalibrationDatasetSeal":
        rows = _validated_samples(samples)
        if not isinstance(dataset_id, str) or not dataset_id.strip():
            raise ValueError("dataset_id is required")
        if not isinstance(split_id, str) or not split_id.strip():
            raise ValueError("split_id is required")
        return cls(
            dataset_id=dataset_id.strip(),
            split_id=split_id.strip(),
            dataset_digest=calibration_dataset_digest(
                rows,
                dataset_id=dataset_id,
                split_id=split_id,
            ),
            sample_count=len(rows),
            source_ids=tuple(sorted({row.source_id for row in rows})),
        )

    def verify(self, samples: Sequence[CalibrationSample]) -> None:
        rows = _validated_samples(samples)
        if len(rows) != self.sample_count:
            raise ValueError("calibration sample count does not match dataset seal")
        actual_sources = tuple(sorted({row.source_id for row in rows}))
        if actual_sources != self.source_ids:
            raise ValueError("calibration source IDs do not match dataset seal")
        actual_digest = calibration_dataset_digest(
            rows,
            dataset_id=self.dataset_id,
            split_id=self.split_id,
        )
        if actual_digest != self.dataset_digest:
            raise ValueError("calibration rows do not match dataset seal")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IsotonicBin:
    minimum_score: float
    maximum_score: float
    probability: float
    positives: int
    total: int

    @property
    def interval(self) -> tuple[float, float]:
        return wilson_interval(self.positives, self.total)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IsotonicModel:
    bins: tuple[IsotonicBin, ...]
    sample_count: int
    positive_count: int

    def predict_bin(self, score: float) -> IsotonicBin:
        if not self.bins:
            raise ValueError("isotonic model is empty")
        maxima = [item.maximum_score for item in self.bins]
        index = min(len(self.bins) - 1, bisect.bisect_left(maxima, _clip(score)))
        return self.bins[index]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bins": [item.to_dict() for item in self.bins],
            "sample_count": self.sample_count,
            "positive_count": self.positive_count,
        }


@dataclass(frozen=True)
class CalibrationResult:
    probability: float
    interval: tuple[float, float]
    level: str
    support: int
    positives: int
    calibrator_id: str
    dataset_id: str
    split_id: str
    dataset_digest: str

    @property
    def interval_width(self) -> float:
        return self.interval[1] - self.interval[0]


@dataclass(frozen=True)
class CalibrationDiagnostics:
    n: int
    ece: float
    brier: float
    reliability: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fit_isotonic(samples: Sequence[CalibrationSample]) -> IsotonicModel:
    rows = _validated_samples(samples)
    grouped: list[dict[str, Any]] = []
    for sample in sorted(rows, key=lambda item: item.rank_score):
        if grouped and sample.rank_score == grouped[-1]["maximum_score"]:
            grouped[-1]["positives"] += sample.outcome
            grouped[-1]["total"] += 1
        else:
            grouped.append(
                {
                    "minimum_score": sample.rank_score,
                    "maximum_score": sample.rank_score,
                    "positives": sample.outcome,
                    "total": 1,
                }
            )

    # Pool-adjacent-violators.  Equal-score rows were grouped first, so a
    # deployment threshold can never split a score mass.
    stack: list[dict[str, Any]] = []
    for group in grouped:
        stack.append(group)
        while len(stack) >= 2:
            left = stack[-2]["positives"] / stack[-2]["total"]
            right = stack[-1]["positives"] / stack[-1]["total"]
            if left <= right:
                break
            merged = {
                "minimum_score": stack[-2]["minimum_score"],
                "maximum_score": stack[-1]["maximum_score"],
                "positives": stack[-2]["positives"] + stack[-1]["positives"],
                "total": stack[-2]["total"] + stack[-1]["total"],
            }
            stack[-2:] = [merged]
    # Adjacent PAVA blocks with the same fitted value are one reliability
    # stratum. Coalescing them gives intervals the correct support instead of
    # pretending every unique floating-point score is a one-sample bucket.
    coalesced: list[dict[str, Any]] = []
    for row in stack:
        if (
            coalesced
            and coalesced[-1]["positives"] * row["total"]
            == row["positives"] * coalesced[-1]["total"]
        ):
            coalesced[-1] = {
                "minimum_score": coalesced[-1]["minimum_score"],
                "maximum_score": row["maximum_score"],
                "positives": coalesced[-1]["positives"] + row["positives"],
                "total": coalesced[-1]["total"] + row["total"],
            }
        else:
            coalesced.append(row)
    bins = tuple(
        IsotonicBin(
            minimum_score=float(row["minimum_score"]),
            maximum_score=float(row["maximum_score"]),
            probability=row["positives"] / row["total"],
            positives=int(row["positives"]),
            total=int(row["total"]),
        )
        for row in coalesced
    )
    return IsotonicModel(
        bins=bins,
        sample_count=len(rows),
        positive_count=sum(item.outcome for item in rows),
    )


class HierarchicalCalibrator:
    """Action-class → environment → global isotonic calibration."""

    def __init__(
        self,
        *,
        calibrator_id: str,
        minimum_local_support: int = 50,
        minimum_outcomes_per_class: int = 5,
    ) -> None:
        if not isinstance(calibrator_id, str) or not calibrator_id.strip():
            raise ValueError("calibrator_id is required")
        if minimum_local_support < 2 or minimum_outcomes_per_class < 1:
            raise ValueError("invalid calibrator support requirements")
        self._frozen = False
        self.calibrator_id = calibrator_id.strip()
        self.minimum_local_support = minimum_local_support
        self.minimum_outcomes_per_class = minimum_outcomes_per_class
        self._class_models: Mapping[str, IsotonicModel] = MappingProxyType({})
        self._environment_models: Mapping[str, IsotonicModel] = MappingProxyType({})
        self._global_model: IsotonicModel | None = None
        self._dataset_seal: CalibrationDatasetSeal | None = None
        self._fit_lock = threading.Lock()

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("frozen calibrator cannot be modified")
        object.__setattr__(self, name, value)

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    @property
    def dataset_seal(self) -> CalibrationDatasetSeal:
        if self._dataset_seal is None:
            raise RuntimeError("calibrator is not fit")
        return self._dataset_seal

    @property
    def source_ids(self) -> tuple[str, ...]:
        return self.dataset_seal.source_ids

    def configuration_state(self) -> dict[str, Any]:
        """Return the complete non-secret state that determines predictions."""

        return {
            "calibrator_id": self.calibrator_id,
            "minimum_local_support": self.minimum_local_support,
            "minimum_outcomes_per_class": self.minimum_outcomes_per_class,
            "frozen": self._frozen,
            "dataset_seal": (
                self._dataset_seal.to_dict()
                if self._dataset_seal is not None
                else None
            ),
            "global_model": (
                self._global_model.to_dict()
                if self._global_model is not None
                else None
            ),
            "class_models": {
                key: self._class_models[key].to_dict()
                for key in sorted(self._class_models)
            },
            "environment_models": {
                key: self._environment_models[key].to_dict()
                for key in sorted(self._environment_models)
            },
        }

    @property
    def configuration_fingerprint(self) -> str:
        blob = json.dumps(
            self.configuration_state(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _eligible(self, rows: Sequence[CalibrationSample]) -> bool:
        positives = sum(item.outcome for item in rows)
        negatives = len(rows) - positives
        return bool(
            len(rows) >= self.minimum_local_support
            and positives >= self.minimum_outcomes_per_class
            and negatives >= self.minimum_outcomes_per_class
        )

    def fit(
        self,
        samples: Iterable[CalibrationSample],
        *,
        seal: CalibrationDatasetSeal,
    ) -> "HierarchicalCalibrator":
        with self._fit_lock:
            return self._fit_once(samples, seal=seal)

    def _fit_once(
        self,
        samples: Iterable[CalibrationSample],
        *,
        seal: CalibrationDatasetSeal,
    ) -> "HierarchicalCalibrator":
        if self._frozen or self._global_model is not None:
            raise RuntimeError("calibrator is already fit and frozen")
        if not isinstance(seal, CalibrationDatasetSeal):
            raise TypeError("an explicit CalibrationDatasetSeal is required")
        rows = _validated_samples(tuple(samples))
        seal.verify(rows)
        wrong = [
            row.sample_id or str(index)
            for index, row in enumerate(rows)
            if row.population != CALIBRATION_POPULATION
        ]
        if wrong:
            raise ValueError(
                "fit accepts only sealed calibration-population rows; found: "
                + ",".join(wrong[:5])
            )
        positives = sum(item.outcome for item in rows)
        if positives == 0 or positives == len(rows):
            raise ValueError("global calibration requires both outcomes")
        global_model = fit_isotonic(rows)
        class_models: dict[str, IsotonicModel] = {}
        environment_models: dict[str, IsotonicModel] = {}
        for action_type in sorted({item.action_type for item in rows}):
            local = tuple(item for item in rows if item.action_type == action_type)
            if self._eligible(local):
                class_models[action_type] = fit_isotonic(local)
        for environment in sorted({item.environment for item in rows}):
            local = tuple(item for item in rows if item.environment == environment)
            if self._eligible(local):
                environment_models[environment] = fit_isotonic(local)
        self._global_model = global_model
        self._class_models = MappingProxyType(class_models)
        self._environment_models = MappingProxyType(environment_models)
        self._dataset_seal = seal
        self._frozen = True
        return self

    def predict(
        self,
        rank_score: float,
        *,
        action_type: str,
        environment: str,
    ) -> CalibrationResult:
        if self._global_model is None:
            raise RuntimeError("calibrator is not fit")
        if action_type in self._class_models:
            level, model = "action_class", self._class_models[action_type]
        elif environment in self._environment_models:
            level, model = "environment", self._environment_models[environment]
        else:
            level, model = "global", self._global_model
        chosen = model.predict_bin(rank_score)
        return CalibrationResult(
            probability=chosen.probability,
            interval=chosen.interval,
            level=level,
            support=chosen.total,
            positives=chosen.positives,
            calibrator_id=self.calibrator_id,
            dataset_id=self.dataset_seal.dataset_id,
            split_id=self.dataset_seal.split_id,
            dataset_digest=self.dataset_seal.dataset_digest,
        )


def calibration_diagnostics(
    outcomes: Sequence[int],
    probabilities: Sequence[float],
    *,
    bins: int = 10,
) -> CalibrationDiagnostics:
    if len(outcomes) != len(probabilities) or not outcomes:
        raise ValueError("outcomes and probabilities must be non-empty and aligned")
    if bins <= 0:
        raise ValueError("bins must be positive")
    rows: list[dict[str, Any]] = []
    ece = 0.0
    n = len(outcomes)
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        members = [
            (int(y), _clip(float(p)))
            for y, p in zip(outcomes, probabilities)
            if (low <= p < high) or (index == bins - 1 and p == 1.0)
        ]
        if not members:
            continue
        observed = sum(y for y, _ in members) / len(members)
        predicted = sum(p for _, p in members) / len(members)
        ece += (len(members) / n) * abs(observed - predicted)
        interval = wilson_interval(sum(y for y, _ in members), len(members))
        rows.append(
            {
                "lower": low,
                "upper": high,
                "n": len(members),
                "predicted": predicted,
                "observed": observed,
                "observed_interval": interval,
            }
        )
    brier = sum((int(y) - _clip(float(p))) ** 2 for y, p in zip(outcomes, probabilities)) / n
    return CalibrationDiagnostics(
        n=n,
        ece=float(ece),
        brier=float(brier),
        reliability=tuple(rows),
    )
