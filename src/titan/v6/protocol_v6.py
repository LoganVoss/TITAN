"""
V6 protocol freeze + chronology witness.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json
import subprocess
import time
from pathlib import Path

from .api_contract import FROZEN_CONTRACT, APIExecutionContract


@dataclass
class ProtocolV6:
    name: str
    version: str
    created_at: float
    content: dict[str, Any]
    content_hash: str
    chronology: list[dict[str, Any]] = field(default_factory=list)
    git_tag: str = ""
    git_commit: str = ""
    witness_note: str = ""
    contract_hash: str = ""

    def record(self, stage: str, detail: str = "") -> None:
        self.chronology.append({
            "stage": stage,
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "detail": detail,
        })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=str))
        self.record("protocol_written", str(path))


def _git(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


def freeze_v6_protocol(
    *,
    bands: dict[str, float],
    feature_registry: list[str],
    metrics: list[str],
    model: str | None = None,
    path: str | Path | None = None,
    contract: APIExecutionContract | None = None,
) -> ProtocolV6:
    contract = contract or FROZEN_CONTRACT
    content = {
        "scorer_version": "0.5.0-frozen",
        "campaign": "titan-v6-100-live-llm",
        "feature_registry": feature_registry,
        "thresholds": bands,
        "metrics": metrics,
        "deployable_only": True,
        "before_harm_exclusive_prefix": True,
        "dual_channel_block": True,
        "no_resynthesis_during_locked": True,
        "api_contract": contract.to_dict(),
        "model": model or contract.model,
        "knowledge_levels": ["L0", "L1", "L2", "L3", "L4"],
        "n_locked_attacks_target": 100,
        "evaluation": "live_multi_turn_llm_v6",
    }
    blob = json.dumps(content, sort_keys=True, default=str)
    h = hashlib.sha256(blob.encode()).hexdigest()
    commit = _git(["git", "rev-parse", "HEAD"]) or "no-commit"
    tag = f"titan-v6-protocol-{h[:8]}"
    pf = ProtocolV6(
        name="titan-v6-live-adversary",
        version="0.6.0",
        created_at=time.time(),
        content=content,
        content_hash=h[:16],
        git_tag=tag,
        git_commit=commit,
        contract_hash=contract.content_hash(),
        witness_note=(
            "Local protocol freeze with chronology. "
            "Create signed git tag and push to independent remote before treating "
            "as fully external witness. Chronology timestamps are authoritative for "
            "this machine's run order."
        ),
    )
    pf.record("protocol_freeze", f"hash={pf.content_hash} tag={tag}")
    pf.record("api_contract_frozen", contract.content_hash())
    pf.record("v5_fossil_bound", "FREEZE_V5.md")
    if path:
        pf.save(path)
    return pf
