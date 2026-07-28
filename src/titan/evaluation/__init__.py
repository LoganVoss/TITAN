"""Evaluation: disjoint partitions, real metrics, honest harness."""

from .splits import Partition, split_dataset
from .metrics import EvaluationReport, evaluate_monitor, recall_at_fpr, recall_at_budget
from .harness import run_full_evaluation

__all__ = [
    "Partition",
    "split_dataset",
    "EvaluationReport",
    "evaluate_monitor",
    "recall_at_fpr",
    "recall_at_budget",
    "run_full_evaluation",
]
