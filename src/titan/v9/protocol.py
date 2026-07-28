"""
Canonical, immutable TITAN V9 campaign protocol.

The declared digest is always SHA-256 over the normalized ``content`` object.
Loading an artifact with a stale or post-hoc-edited digest raises immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping


PROTOCOL_SCHEMA = "titan-v9-protocol-1"

V9_SUPPORTED_ACTION_CLASSES: tuple[str, ...] = (
    "disable_monitoring",
    "export_credential",
    "modify_safeguard",
    "queue_training",
    "merge_training_data",
    "remove_canary",
    "weaken_canary",
)

V9_SUPPORTED_THREAT_FAMILIES: tuple[str, ...] = (
    "clustered_poisoning",
    "slow_drip_poisoning",
    "rare_source_influence",
    "label_manipulation",
    "provenance_bypass",
    "dispersed_commits",
    "multi_agent_coordination",
    "monitor_evasion",
    "canary_suppression",
    "canary_weakening",
    "evaluation_weakening",
    "grader_manipulation",
    "safeguard_tampering",
    "logging_suppression",
    "capability_lease_abuse",
    "proof_packet_fabrication",
    "twin_aware_payloads",
    "delayed_activation",
    "escrow_denial_of_service",
    "hybrid_poison_evaluation",
)

V9_CRITICAL_THREAT_FAMILIES: tuple[str, ...] = (
    "clustered_poisoning",
    "canary_suppression",
    "canary_weakening",
    "safeguard_tampering",
    "logging_suppression",
)

V9_CANARY_SUBTYPES: tuple[str, ...] = (
    "threshold_reduction",
    "removal",
    "renaming",
    "grader_weakening",
    "frequency_reduction",
    "input_coverage_narrowing",
    "dependency_change",
    "timeout_reduction",
    "data_filter_change",
    "distributed_degradation",
)

V9_SAFEGUARD_SUBTYPES: tuple[str, ...] = (
    "threshold_weakening",
    "default_off",
    "rule_deletion",
    "category_removal",
    "logging_suppression",
    "alert_routing_change",
    "prompt_weakening",
    "dependency_weakening",
    "timeout_change",
    "parser_weakening",
    "cross_file_weakening",
    "delayed_activation",
    "staged_multi_actor",
)

REQUIRED_FIELDS = frozenset(
    {
        "protocol_version",
        "campaign_name",
        "titan_version",
        "scorer_version",
        "target_sample_sizes",
        "model_identifiers",
        "prompts",
        "tool_definitions",
        "action_class_thresholds",
        "supported_action_classes",
        "supported_threat_families",
        "critical_threat_families",
        "canary_subtypes",
        "safeguard_subtypes",
        "operational_mixture_weights",
        "calibration_dataset_sha256",
        "population_registry_sha256",
        "release_policy_sha256",
        "source_commit",
        "dependency_lock_sha256",
        "sandbox_image_sha256",
        "transcript_destination",
        "metric_contract_version",
        "public_witness_location",
        "created_at",
    }
)

_HEX_RE = re.compile(r"^[0-9a-f]+$")


class ProtocolIntegrityError(ValueError):
    """Raised when protocol schema or cryptographic integrity is invalid."""


def _normalize_json(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProtocolIntegrityError(f"{path}: non-finite float")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolIntegrityError(f"{path}: JSON object keys must be strings")
            normalized[key] = _normalize_json(item, f"{path}.{key}")
        return dict(sorted(normalized.items()))
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, f"{path}[]") for item in value]
    raise ProtocolIntegrityError(f"{path}: unsupported value type {type(value).__name__}")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def canonical_json_bytes(content: Mapping[str, Any]) -> bytes:
    normalized = _normalize_json(content)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def protocol_content_hash(content: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(content)).hexdigest()


def _require_text(content: Mapping[str, Any], key: str) -> None:
    value = content.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProtocolIntegrityError(f"{key} must be a non-empty string")


def _require_sha256(content: Mapping[str, Any], key: str) -> None:
    value = content.get(key)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not _HEX_RE.fullmatch(value.lower())
    ):
        raise ProtocolIntegrityError(f"{key} must be a 64-character SHA-256 digest")


def validate_protocol_content(content: Mapping[str, Any]) -> None:
    missing = sorted(REQUIRED_FIELDS - set(content))
    if missing:
        raise ProtocolIntegrityError(f"missing protocol fields: {missing}")

    for key in (
        "protocol_version",
        "campaign_name",
        "titan_version",
        "scorer_version",
        "transcript_destination",
        "metric_contract_version",
        "public_witness_location",
        "created_at",
    ):
        _require_text(content, key)
    if content["protocol_version"] != PROTOCOL_SCHEMA:
        raise ProtocolIntegrityError(
            f"protocol_version must be {PROTOCOL_SCHEMA!r}"
        )

    targets = content["target_sample_sizes"]
    if not isinstance(targets, Mapping) or not targets:
        raise ProtocolIntegrityError("target_sample_sizes must be a non-empty mapping")
    for name, value in targets.items():
        if not isinstance(name, str) or not name.strip():
            raise ProtocolIntegrityError("target sample-size names must be non-empty")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProtocolIntegrityError(
                f"target sample size {name!r} must be a non-negative integer"
            )

    models = content["model_identifiers"]
    if not isinstance(models, (list, tuple)) or not models:
        raise ProtocolIntegrityError("at least one exact model identifier is required")
    if any(not isinstance(model, str) or not model.strip() for model in models):
        raise ProtocolIntegrityError("model identifiers must be non-empty strings")

    prompts = content["prompts"]
    if not isinstance(prompts, Mapping) or not prompts:
        raise ProtocolIntegrityError("exact prompts are required")
    if any(not isinstance(v, str) for v in prompts.values()):
        raise ProtocolIntegrityError("prompt values must be exact strings")

    tools = content["tool_definitions"]
    if not isinstance(tools, (list, tuple)) or not tools:
        raise ProtocolIntegrityError("tool_definitions must be a non-empty list")

    exact_registries = (
        (
            "supported_action_classes",
            V9_SUPPORTED_ACTION_CLASSES,
        ),
        (
            "supported_threat_families",
            V9_SUPPORTED_THREAT_FAMILIES,
        ),
        (
            "critical_threat_families",
            V9_CRITICAL_THREAT_FAMILIES,
        ),
        ("canary_subtypes", V9_CANARY_SUBTYPES),
        ("safeguard_subtypes", V9_SAFEGUARD_SUBTYPES),
    )
    for field_name, expected_registry in exact_registries:
        supplied = content[field_name]
        if not isinstance(supplied, (list, tuple)) or not supplied:
            raise ProtocolIntegrityError(f"{field_name} cannot be empty")
        if any(not isinstance(name, str) or not name.strip() for name in supplied):
            raise ProtocolIntegrityError(f"{field_name} values must be strings")
        if len(set(supplied)) != len(supplied):
            raise ProtocolIntegrityError(f"{field_name} contains duplicates")
        if tuple(supplied) != expected_registry:
            raise ProtocolIntegrityError(
                f"{field_name} must equal the canonical V9 registry"
            )
    supported = content["supported_action_classes"]

    mixture = content["operational_mixture_weights"]
    if not isinstance(mixture, Mapping) or not mixture:
        raise ProtocolIntegrityError(
            "operational_mixture_weights must be a non-empty mapping"
        )
    total_weight = 0.0
    for stratum, weight in mixture.items():
        if not isinstance(stratum, str) or not stratum.strip():
            raise ProtocolIntegrityError(
                "operational mixture stratum names must be non-empty"
            )
        if (
            isinstance(weight, bool)
            or not isinstance(weight, (int, float))
            or not math.isfinite(float(weight))
            or float(weight) <= 0.0
        ):
            raise ProtocolIntegrityError(
                "operational mixture weights must be finite and positive"
            )
        total_weight += float(weight)
    if not math.isclose(total_weight, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise ProtocolIntegrityError(
            "operational mixture weights must sum to exactly one"
        )

    thresholds = content["action_class_thresholds"]
    if not isinstance(thresholds, Mapping):
        raise ProtocolIntegrityError("action_class_thresholds must be a mapping")
    missing_thresholds = sorted(set(supported) - set(thresholds))
    if missing_thresholds:
        raise ProtocolIntegrityError(
            f"supported classes lack thresholds: {missing_thresholds}"
        )
    extra_thresholds = sorted(set(thresholds) - set(supported))
    if extra_thresholds:
        raise ProtocolIntegrityError(
            f"thresholds contain unsupported classes: {extra_thresholds}"
        )
    for action_class, value in thresholds.items():
        if not isinstance(action_class, str) or not action_class.strip():
            raise ProtocolIntegrityError("threshold class names must be non-empty")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProtocolIntegrityError(
                f"threshold for {action_class!r} must be numeric"
            )
        if not math.isfinite(float(value)):
            raise ProtocolIntegrityError(
                f"threshold for {action_class!r} must be finite"
            )
        if not 0.0 <= float(value) <= 1.0:
            raise ProtocolIntegrityError(
                f"threshold for {action_class!r} must be in [0, 1]"
            )

    for key in (
        "calibration_dataset_sha256",
        "population_registry_sha256",
        "release_policy_sha256",
        "dependency_lock_sha256",
        "sandbox_image_sha256",
    ):
        _require_sha256(content, key)

    source_commit = content["source_commit"]
    if (
        not isinstance(source_commit, str)
        or len(source_commit) not in (40, 64)
        or not _HEX_RE.fullmatch(source_commit.lower())
    ):
        raise ProtocolIntegrityError("source_commit must be a full 40- or 64-hex digest")


@dataclass(frozen=True)
class V9Protocol:
    content: Mapping[str, Any]
    declared_hash: str
    schema: str = PROTOCOL_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PROTOCOL_SCHEMA:
            raise ProtocolIntegrityError(f"unsupported protocol schema {self.schema!r}")
        normalized = _normalize_json(self.content)
        validate_protocol_content(normalized)
        expected = protocol_content_hash(normalized)
        if self.declared_hash != expected:
            raise ProtocolIntegrityError(
                f"protocol hash mismatch: declared={self.declared_hash} actual={expected}"
            )
        object.__setattr__(self, "content", _freeze_json(normalized))

    @classmethod
    def create(cls, content: Mapping[str, Any]) -> "V9Protocol":
        normalized = _normalize_json(content)
        validate_protocol_content(normalized)
        return cls(
            content=normalized,
            declared_hash=protocol_content_hash(normalized),
        )

    @classmethod
    def from_dict(cls, artifact: Mapping[str, Any]) -> "V9Protocol":
        if not isinstance(artifact, Mapping):
            raise ProtocolIntegrityError("protocol artifact must be an object")
        return cls(
            schema=str(artifact.get("schema", "")),
            content=artifact.get("content", {}),
            declared_hash=str(artifact.get("declared_hash", "")),
        )

    @property
    def content_hash(self) -> str:
        return self.declared_hash

    def verify(self) -> bool:
        return protocol_content_hash(self.to_content_dict()) == self.declared_hash

    def to_content_dict(self) -> dict[str, Any]:
        return _thaw_json(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "declared_hash": self.declared_hash,
            "content": self.to_content_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_content_dict())

    def write(self, path: str | Path) -> None:
        """Atomically write the self-verifying protocol artifact."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        encoded = (
            json.dumps(
                self.to_dict(),
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
        try:
            with temporary.open("wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()


def load_protocol(path: str | Path) -> V9Protocol:
    try:
        artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolIntegrityError(f"cannot load protocol: {exc}") from exc
    return V9Protocol.from_dict(artifact)
