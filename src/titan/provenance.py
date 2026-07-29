"""Audit trail (birth certificate) for every synthesized or promoted monitor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import time


@dataclass
class MonitorProvenance:
    """Complete audit trail for one candidate / registered monitor."""

    name: str
    version: str = "0.1.0"
    source_collision_pairs: list[tuple[str, str]] = field(default_factory=list)
    attack_families_seen: list[str] = field(default_factory=list)
    score_breakdown: dict[str, float] = field(default_factory=dict)
    expression: str | None = None
    dsl_ast: dict[str, Any] | None = None
    feature_deps: list[str] = field(default_factory=list)
    failure_cases: list[dict[str, Any]] = field(default_factory=list)
    discovery_split_hash: str = ""
    selection_split_hash: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    status: str = "candidate"  # candidate | shadow | promoted | retired

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source_collision_pairs"] = [list(p) for p in self.source_collision_pairs]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MonitorProvenance":
        data = dict(data)
        if "source_collision_pairs" in data:
            data["source_collision_pairs"] = [tuple(p) for p in data["source_collision_pairs"]]
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def summary(self) -> str:
        parts = [self.name, f"status={self.status}"]
        if self.score_breakdown:
            parts.append(f"composite={self.score_breakdown.get('composite', 0):.3f}")
        if self.expression:
            parts.append(f"expr={self.expression}")
        return " | ".join(parts)
