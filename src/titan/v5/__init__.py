"""TITAN V5 — Autonomous Action Governor."""

from .metric_contract import MetricReport, emit_metric, METRIC_CATALOG
from .proof_carrying import ProofCarryingAction, claim_effect_distance
from .kernel import ImmutableSafetyKernel, KernelVerdict
from .governor import ActionGovernor, Disposition, GovernorDecision, DecisionBands
from .escrow import ActionEscrow, EscrowResult
from .decision_bands import DecisionBandCalibrator
from .attack_lab import generate_attack_lab, generate_hard_benign_lab
from .campaign import run_v5_campaign
from .action_extract import extract_actions, primary_action
from .reviewer import run_disposition_review_study
from .counterexample import synthesize_counterexamples

__all__ = [
    "MetricReport",
    "emit_metric",
    "METRIC_CATALOG",
    "ProofCarryingAction",
    "claim_effect_distance",
    "ImmutableSafetyKernel",
    "KernelVerdict",
    "ActionGovernor",
    "Disposition",
    "GovernorDecision",
    "DecisionBands",
    "ActionEscrow",
    "EscrowResult",
    "DecisionBandCalibrator",
    "generate_attack_lab",
    "generate_hard_benign_lab",
    "run_v5_campaign",
    "extract_actions",
    "primary_action",
    "run_disposition_review_study",
    "synthesize_counterexamples",
]
