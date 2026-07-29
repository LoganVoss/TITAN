"""Narrow public API for a label-blind TITAN V10 enforcement process."""

from __future__ import annotations

# Reuse V9 online building blocks for actions/tokens/gateway; governor is V10.
from ..v9.action import (
    ActionProposal,
    ObservableEvent,
    ObservableTrajectory,
    action_prefix,
    extract_action_proposals,
)
from ..v9.gateway import (
    ActionEnvelope,
    EnforcementGateway,
    ExecutionReceipt,
    GatewayDenied,
)
from ..v9.evidence_trust import (
    EvidenceAttestation,
    EvidenceAttestationAuthority,
    EvidenceAttestationVerifier,
    EvidenceTrustError,
    VerifiedEvidence,
)
from ..v9.integrity import (
    ControlPlaneIntegrityPolicy,
    HashChainedAuditLog,
    IntegrityAssessment,
    IntegritySignals,
)
from ..v9.tokens import (
    ActionContext,
    AuthorizationToken,
    CommitTokenVerifier,
    ReplayGuard,
    TwoPhaseTokenAuthority,
)
from .governor import GovernanceResult, GovernorConfigurationError, V10Governor
from .policy import ActionPolicy, Decision, DecisionTerms, Disposition

__all__ = [
    "ActionContext",
    "ActionEnvelope",
    "ActionPolicy",
    "ActionProposal",
    "AuthorizationToken",
    "CommitTokenVerifier",
    "ControlPlaneIntegrityPolicy",
    "Decision",
    "DecisionTerms",
    "Disposition",
    "EnforcementGateway",
    "EvidenceAttestation",
    "EvidenceAttestationAuthority",
    "EvidenceAttestationVerifier",
    "EvidenceTrustError",
    "ExecutionReceipt",
    "GatewayDenied",
    "GovernanceResult",
    "GovernorConfigurationError",
    "HashChainedAuditLog",
    "IntegrityAssessment",
    "IntegritySignals",
    "ObservableEvent",
    "ObservableTrajectory",
    "ReplayGuard",
    "TwoPhaseTokenAuthority",
    "V10Governor",
    "VerifiedEvidence",
    "action_prefix",
    "extract_action_proposals",
]
