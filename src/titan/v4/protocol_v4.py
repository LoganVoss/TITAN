"""
Step 15 — Protocol freeze with chronology for external timestamping.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json
import time
from pathlib import Path


@dataclass
class ProtocolFreeze:
    name: str
    version: str
    created_at: float
    content: dict[str, Any]
    content_hash: str
    chronology: list[dict[str, Any]] = field(default_factory=list)
    git_tag: str = ""
    witness_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def record(self, stage: str, detail: str = "") -> None:
        self.chronology.append({
            "stage": stage,
            "ts": time.time(),
            "detail": detail,
        })


def freeze_protocol(
    *,
    scorer_version: str,
    feature_registry: list[str],
    thresholds: dict[str, float],
    metrics: list[str],
    sandbox_version: str = "sandbox-v4",
    critical_floors: dict[str, float] | None = None,
    path: str | Path | None = None,
) -> ProtocolFreeze:
    content = {
        "scorer_version": scorer_version,
        "feature_registry": feature_registry,
        "thresholds": thresholds,
        "metrics": metrics,
        "sandbox_version": sandbox_version,
        "critical_floors": critical_floors or {},
        "deployable_only": True,
        "before_harm_exclusive_prefix": True,
        "evaluation": "external_direct_execution_v4",
    }
    blob = json.dumps(content, sort_keys=True, default=str)
    h = hashlib.sha256(blob.encode()).hexdigest()
    pf = ProtocolFreeze(
        name="titan-v4-external-control",
        version="0.4.0",
        created_at=time.time(),
        content=content,
        content_hash=h[:16],
        git_tag=f"titan-v4-protocol-{h[:8]}",
        witness_note=(
            "Local freeze artifact. For independent witness: publish this hash "
            "via signed git tag before locked generation."
        ),
    )
    pf.record("protocol_freeze", f"hash={pf.content_hash}")
    if path:
        Path(path).write_text(json.dumps(pf.to_dict(), indent=2))
        pf.record("protocol_written", str(path))
    return pf
