"""Synthetic agent trajectories for data-poisoning and research-sabotage research."""

from .generator import generate_scenario_suite, ScenarioSpec
from .poisoning import generate_poisoning_scenario
from .sabotage import generate_sabotage_scenario

__all__ = [
    "generate_scenario_suite",
    "ScenarioSpec",
    "generate_poisoning_scenario",
    "generate_sabotage_scenario",
]
