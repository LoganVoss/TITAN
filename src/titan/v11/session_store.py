"""Server-side evaluation contracts — hidden from acting models and online path.

Opaque session_id → sealed offline manifest. Models never see matrix_cell,
expected disposition, or harmful/benign labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json
import secrets
from pathlib import Path


def _sha(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class OfflineEvalContract:
    """Sealed offline only — never serialized into model prompts."""

    lane: str  # constitutional | adaptive | chaos | benign
    truth_label: str  # harmful | benign | fault
    evidence_cell: str | None  # harm_block_ready | ... | None for adaptive
    expected_family: str  # block | escrow | allow | fail_closed
    action_class: str
    knowledge_level: str
    generator_provider: str | None = None
    actor_provider: str | None = None
    notes: str = ""


@dataclass
class SessionManifest:
    session_id: str
    protected_state: dict[str, Any]
    tool_surface: list[dict[str, Any]]
    operational_brief: str
    offline: OfflineEvalContract
    evidence_plan: dict[str, Any] = field(default_factory=dict)

    def public_view(self) -> dict[str, Any]:
        """What the acting model may see."""
        return {
            "session_id": self.session_id,
            "environment_brief": self.operational_brief,
            "protected_objects": list(self.protected_state.get("objects", [])),
            "available_tools": self.tool_surface,
        }

    def offline_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protected_state": self.protected_state,
            "evidence_plan": self.evidence_plan,
            "offline": asdict(self.offline),
        }


class SessionStore:
    def __init__(self) -> None:
        self._by_id: dict[str, SessionManifest] = {}

    def mint_id(self) -> str:
        return f"s_{secrets.token_hex(16)}"

    def put(self, manifest: SessionManifest) -> None:
        self._by_id[manifest.session_id] = manifest

    def get(self, session_id: str) -> SessionManifest | None:
        return self._by_id.get(session_id)

    def seal(self, path: Path) -> str:
        """Write offline sealed manifest registry; returns sha256."""
        rows = [m.offline_dict() for m in self._by_id.values()]
        payload = {"schema": "titan-v11-offline-manifest/1", "sessions": rows}
        raw = json.dumps(payload, sort_keys=True, indent=2).encode()
        path.write_bytes(raw)
        return _sha(payload)

    def load(self, path: Path) -> None:
        data = json.loads(path.read_text())
        for row in data.get("sessions", []):
            off = row["offline"]
            m = SessionManifest(
                session_id=row["session_id"],
                protected_state=row.get("protected_state") or {},
                tool_surface=[],
                operational_brief="",
                offline=OfflineEvalContract(**off),
                evidence_plan=row.get("evidence_plan") or {},
            )
            self.put(m)

    def __len__(self) -> int:
        return len(self._by_id)
