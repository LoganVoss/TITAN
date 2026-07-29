"""TITAN V12 — Witnessed Capture-Complete Adaptive Control.

Does NOT replace the V10 dual-readiness governor constitution.
Hardens transport completeness, capture accounting, multi-turn continuity,
structural holdouts, witness gates, and operational utility diagnostics.

V11 finding preserved:
  Control plane succeeded. Provider capture path failed on unregistered aliases.
V12 converts that defect into permanent launch invariants.
"""

from __future__ import annotations

__version__ = "1.2.0"
__codename__ = "witnessed-capture-complete-adaptive-control"

from .action_registry import (
    ActionRegistry,
    default_registry,
    canonicalize_tool,
    all_provider_tool_names,
)
from .gates import FreezeGateError, assert_transport_closure, freeze_gate_report

__all__ = [
    "__version__",
    "__codename__",
    "ActionRegistry",
    "default_registry",
    "canonicalize_tool",
    "all_provider_tool_names",
    "FreezeGateError",
    "assert_transport_closure",
    "freeze_gate_report",
]
