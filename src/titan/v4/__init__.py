"""TITAN V4 — production-shaped monitorability control plane."""

from .schema_v4 import CanonicalEvent, IntegrityEnvelope, sign_payload, verify_envelope
from .gateway import SignedEventGateway
from .sandbox_exec import DirectExecutionSandbox, ToolResult
from .hazard import PrecursorHazardLayer, HazardReport
from .counterfactual import CounterfactualVerifier, SafetyDelta
from .critical_family import CriticalFamilyOptimizer
from .calibration_v4 import CalibrationSubsystem, OperatingPoint
from .protocol_v4 import freeze_protocol, ProtocolFreeze
from .control_plane import V4ControlPlane, run_v4_campaign

__all__ = [
    "CanonicalEvent",
    "IntegrityEnvelope",
    "sign_payload",
    "verify_envelope",
    "SignedEventGateway",
    "DirectExecutionSandbox",
    "ToolResult",
    "PrecursorHazardLayer",
    "HazardReport",
    "CounterfactualVerifier",
    "SafetyDelta",
    "CriticalFamilyOptimizer",
    "CalibrationSubsystem",
    "OperatingPoint",
    "freeze_protocol",
    "ProtocolFreeze",
    "V4ControlPlane",
    "run_v4_campaign",
]
