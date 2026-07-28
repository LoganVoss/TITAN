"""TITAN V10 — repaired capability governance.

V10 exists because V9 proved fail-closed intervention (ESCROW) but not effective
non-kernel autonomous blocking. V10 separates:

* ``block_ready`` — independent adverse proof sufficient to refuse authority
* ``allow_ready`` — complete favorable proof sufficient to grant authority
* continuous score geometry for ranking and mass gates

Live multi-model campaigns remain a separate, later gate. This package is the
architecture repair required *before* any locked live API freeze.
"""

from __future__ import annotations

__version__ = "1.0.0"
__codename__ = "repaired-capability-governance"

from .policy import Disposition, V10_SUPPORTED_ACTION_CLASSES
from .governor import V10Governor, GovernanceResult

__all__ = [
    "__version__",
    "__codename__",
    "Disposition",
    "V10_SUPPORTED_ACTION_CLASSES",
    "V10Governor",
    "GovernanceResult",
]
