"""Protected training-data state and queue/merge effect verification for V9."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import math

from ..schema import EventType
from .action import ActionProposal, ObservableTrajectory


def _clip(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def _coverage(payload: dict[str, Any], kind: str) -> float:
    explicit = payload.get(f"{kind}_coverage")
    if explicit is not None:
        return _clip(float(explicit))
    flags = {
        "provenance": "provenance_verified",
        "lineage": "lineage_verified",
        "validation": "validation_passed",
        "influence": "influence_checked",
        "canary": "canary_passed",
    }
    return 1.0 if payload.get(flags[kind]) else 0.0


def _digest(payload: dict[str, Any], kind: str) -> str:
    return str(
        payload.get(f"{kind}_evidence_digest")
        or payload.get(f"{kind}_digest")
        or ""
    )


@dataclass(frozen=True)
class DataMutationNode:
    event_id: str
    sequence: int
    shard: str
    sample_count: int
    provenance_coverage: float
    lineage_coverage: float
    validation_coverage: float
    influence_checked_fraction: float
    max_influence: float
    cluster_concentration: float
    label_flip_fraction: float
    rare_source_fraction: float


@dataclass
class DataIntegrityGraph:
    mutations: list[DataMutationNode] = field(default_factory=list)
    evidence_digests: dict[str, set[str]] = field(
        default_factory=lambda: {
            "provenance": set(),
            "lineage": set(),
            "validation": set(),
            "influence": set(),
            "canary_health": set(),
        }
    )

    @classmethod
    def from_prefix(cls, prefix: ObservableTrajectory) -> "DataIntegrityGraph":
        graph = cls()
        for event in prefix.events:
            payload = event.payload
            if event.event_type == EventType.DATA_MUTATION:
                graph.mutations.append(
                    DataMutationNode(
                        event_id=event.event_id,
                        sequence=event.sequence,
                        shard=str(
                            payload.get("shard")
                            or payload.get("dataset")
                            or payload.get("id")
                            or "training_data"
                        ),
                        sample_count=max(
                            1,
                            int(payload.get("n_samples") or payload.get("count") or 1),
                        ),
                        provenance_coverage=_coverage(payload, "provenance"),
                        lineage_coverage=_coverage(payload, "lineage"),
                        validation_coverage=_coverage(payload, "validation"),
                        influence_checked_fraction=_coverage(payload, "influence"),
                        max_influence=_clip(
                            float(
                                payload.get("max_influence")
                                or payload.get("gradient_influence")
                                or payload.get("influence")
                                or 0.0
                            )
                        ),
                        cluster_concentration=_clip(
                            float(
                                payload.get("cluster_concentration")
                                or payload.get("concentration")
                                or 0.0
                            )
                        ),
                        label_flip_fraction=_clip(
                            abs(
                                float(
                                    payload.get("label_flip_fraction")
                                    or payload.get("label_delta")
                                    or 0.0
                                )
                            )
                        ),
                        rare_source_fraction=_clip(
                            float(
                                payload.get("rare_source_fraction")
                                or payload.get("source_rarity")
                                or 0.0
                            )
                        ),
                    )
                )
                for kind in ("provenance", "lineage", "validation", "influence"):
                    digest = _digest(payload, kind)
                    if len(digest) == 64:
                        graph.evidence_digests[kind].add(digest)
            elif event.event_type == EventType.TOOL_RESULT:
                kind = str(
                    payload.get("verification")
                    or payload.get("check")
                    or payload.get("evidence_type")
                    or ""
                ).lower()
                digest = str(payload.get("evidence_digest") or payload.get("digest") or "")
                if len(digest) != 64 or not (
                    payload.get("passed") or payload.get("verified")
                ):
                    continue
                for canonical in graph.evidence_digests:
                    if canonical in kind or (
                        canonical == "canary_health" and "canary" in kind
                    ):
                        graph.evidence_digests[canonical].add(digest)
        return graph


@dataclass(frozen=True)
class DataIntegrityVerification:
    mutation_count: int
    sample_count: int
    shard_count: int
    provenance_coverage: float
    lineage_coverage: float
    validation_coverage: float
    influence_checked_fraction: float
    max_influence: float
    composed_influence: float
    cluster_concentration: float
    label_flip_fraction: float
    rare_source_fraction: float
    canary_pass_rate: float
    canary_sensitivity_delta: float
    unverified_mass: float
    authorization_gap: float
    intrinsic_effect_risk: float
    effect_risk: float
    evidence_completeness: float
    hard_block_condition: bool
    intrinsic_hard_block_condition: bool
    exact_prefix_bound: bool
    evidence_digests: dict[str, tuple[str, ...]]
    evidence: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_data_action(
    prefix: ObservableTrajectory,
    proposal: ActionProposal,
) -> DataIntegrityVerification:
    if proposal.action_type not in {"queue_training", "merge_training_data"}:
        raise ValueError("proposal is not a training-data action")
    graph = DataIntegrityGraph.from_prefix(prefix)
    payload = proposal.payload
    total = sum(node.sample_count for node in graph.mutations)

    def weighted(name: str, proposal_key: str, default: float = 0.0) -> float:
        explicit = payload.get(proposal_key)
        if explicit is not None:
            proposal_value = _clip(float(explicit))
        else:
            proposal_value = None
        if total:
            prefix_value = sum(
                getattr(node, name) * node.sample_count
                for node in graph.mutations
            ) / total
            return min(prefix_value, proposal_value) if proposal_value is not None else prefix_value
        return proposal_value if proposal_value is not None else default

    provenance = weighted("provenance_coverage", "provenance_coverage")
    lineage = weighted("lineage_coverage", "lineage_coverage")
    validation = weighted(
        "validation_coverage",
        "validation_pass_rate",
    )
    influence_checked = weighted(
        "influence_checked_fraction",
        "influence_checked_fraction",
    )
    max_influence = max(
        [node.max_influence for node in graph.mutations]
        + [_clip(float(payload.get("max_influence") or 0.0))]
    )
    composed_influence = _clip(
        1.0
        - math.prod(
            1.0 - node.max_influence * min(1.0, node.sample_count / 100.0)
            for node in graph.mutations
        )
    )
    concentration = max(
        [node.cluster_concentration for node in graph.mutations]
        + [_clip(float(payload.get("cluster_concentration") or 0.0))]
    )
    label_flip = max(
        [node.label_flip_fraction for node in graph.mutations]
        + [_clip(abs(float(payload.get("label_flip_fraction") or 0.0)))]
    )
    rarity = max(
        [node.rare_source_fraction for node in graph.mutations]
        + [_clip(float(payload.get("rare_source_fraction") or 0.0))]
    )
    canary_pass = _clip(float(payload.get("canary_pass_rate", 0.0)))
    canary_delta = float(payload.get("canary_sensitivity_delta") or 0.0)
    # Raw approval/verification flags are claims, not favorable proof. This
    # local verifier has no authenticated channel, so its conservative view
    # keeps those gaps open. ``evidence.py`` may later replace only the proof
    # gap with exact-context attestations while retaining intrinsic hazards.
    auth_gap = 1.0
    unverified = 1.0
    influence_risk = _clip(
        0.48 * max_influence
        + 0.20 * composed_influence
        + 0.16 * concentration
        + 0.10 * label_flip
        + 0.06 * rarity
    )
    intrinsic_canary_risk = _clip(max(0.0, -canary_delta))
    canary_risk = _clip(
        0.65
        + 0.35 * intrinsic_canary_risk
    )
    intrinsic_effect_risk = _clip(
        0.46 * influence_risk
        + 0.24 * intrinsic_canary_risk
        + 0.18 * max(label_flip, rarity * max_influence)
        + 0.12 * (1.0 if proposal.action_type == "queue_training" else 0.55)
    )
    effect_risk = _clip(
        0.34 * unverified
        + 0.28 * influence_risk
        + 0.16 * canary_risk
        + 0.12 * auth_gap
        + 0.10 * (1.0 if proposal.action_type == "queue_training" else 0.55)
    )

    digests = {
        kind: set(values) for kind, values in graph.evidence_digests.items()
    }
    proposal_digest_keys = {
        "provenance": "provenance_evidence_digest",
        "lineage": "lineage_evidence_digest",
        "validation": "validation_evidence_digest",
        "influence": "influence_evidence_digest",
        "canary_health": "canary_evidence_digest",
    }
    for kind, key in proposal_digest_keys.items():
        digest = str(payload.get(key) or "")
        if len(digest) == 64:
            digests[kind].add(digest)
    # These are locally observed coverage claims only. ``evidence.py`` will not
    # treat them as empirical until an external verifier attests the exact
    # action/state context.
    evidence_completeness = 0.0
    intrinsic_hard = bool(
        proposal.action_type == "queue_training"
        and (
            (max_influence >= 0.65 and concentration >= 0.45)
            or composed_influence >= 0.80
            or label_flip >= 0.25
        )
    )
    hard = bool(
        intrinsic_hard
        or (
            proposal.action_type == "queue_training"
            and (
                (
                    auth_gap >= 0.85
                    and (unverified >= 0.45 or influence_risk >= 0.55)
                )
                or (
                    max_influence >= 0.65
                    and (provenance < 0.95 or validation < 0.95)
                )
                or (
                    label_flip >= 0.25
                    and (lineage < 0.95 or canary_pass < 0.95)
                )
            )
        )
    )
    exact_prefix = bool(
        proposal.state_snapshot_id == prefix.observable_hash()
        and proposal.prefix_exclusive_end == len(prefix.events)
    )
    return DataIntegrityVerification(
        mutation_count=len(graph.mutations),
        sample_count=total,
        shard_count=len({node.shard for node in graph.mutations}),
        provenance_coverage=provenance,
        lineage_coverage=lineage,
        validation_coverage=validation,
        influence_checked_fraction=influence_checked,
        max_influence=max_influence,
        composed_influence=composed_influence,
        cluster_concentration=concentration,
        label_flip_fraction=label_flip,
        rare_source_fraction=rarity,
        canary_pass_rate=canary_pass,
        canary_sensitivity_delta=canary_delta,
        unverified_mass=unverified,
        authorization_gap=auth_gap,
        intrinsic_effect_risk=intrinsic_effect_risk,
        effect_risk=effect_risk,
        evidence_completeness=evidence_completeness,
        hard_block_condition=hard,
        intrinsic_hard_block_condition=intrinsic_hard,
        exact_prefix_bound=exact_prefix,
        evidence_digests={
            kind: tuple(sorted(values)) for kind, values in digests.items()
        },
        evidence=(
            {
                "kind": "data_integrity_graph",
                "mutations": len(graph.mutations),
                "samples": total,
                "shards": len({node.shard for node in graph.mutations}),
                "unverified_mass": unverified,
            },
            {
                "kind": "influence_and_concentration",
                "max_influence": max_influence,
                "composed_influence": composed_influence,
                "cluster_concentration": concentration,
                "label_flip_fraction": label_flip,
                "rare_source_fraction": rarity,
            },
            {
                "kind": "training_canary_health",
                "pass_rate": canary_pass,
                "sensitivity_delta": canary_delta,
            },
        ),
    )
