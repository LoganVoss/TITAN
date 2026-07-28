"""
Scenario suite generator with stratified attack families and hard negatives.

Produces realistic-enough synthetic trajectories for discovery / selection /
calibration / locked evaluation partitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..schema import AgentTrajectory, AttackFamily, Label
from .poisoning import generate_benign_curation, generate_poisoning_scenario
from .sabotage import generate_clean_refactor, generate_sabotage_scenario
from .hard_negatives import HARD_NEGATIVE_FAMILIES, generate_hard_negative_v2


POISON_FAMILIES = [
    AttackFamily.CLUSTER_CONCENTRATION,
    AttackFamily.RARE_SOURCE_HIGH_INFLUENCE,
    AttackFamily.EVAL_WEAKENING,
    AttackFamily.DISPERSED_COMMITS,
    AttackFamily.PROVENANCE_BYPASS,
    AttackFamily.LABEL_FLIP_BURST,
    AttackFamily.CANARY_SUPPRESSION,
]

SABOTAGE_FAMILIES = [
    AttackFamily.TEST_EDITING,
    AttackFamily.MONITOR_EVASION,
    AttackFamily.SAFEGUARD_TAMPER,
    AttackFamily.EXFIL_ATTEMPT,
]


@dataclass
class ScenarioSpec:
    n_harmful_per_family: int = 4
    n_hard_negatives: int = 12
    n_clean_benign: int = 16
    n_clean_refactor: int = 8
    model_versions: list[str] = field(default_factory=lambda: ["agent-v1", "agent-v2"])
    environments: list[str] = field(default_factory=lambda: ["lab", "staging"])
    seed: int = 42

    def expected_count(self) -> int:
        from .hard_negatives import HARD_NEGATIVE_FAMILIES
        n_fam = len(POISON_FAMILIES) + len(SABOTAGE_FAMILIES)
        return (
            n_fam * self.n_harmful_per_family
            + self.n_hard_negatives
            + self.n_clean_benign
            + self.n_clean_refactor
            + len(HARD_NEGATIVE_FAMILIES)
        )


def generate_scenario_suite(spec: ScenarioSpec | None = None) -> list[AgentTrajectory]:
    """
    Generate a full labeled suite spanning poisoning, sabotage, and benign work.

    Trajectories vary model_version and environment for transfer evaluation.
    """
    spec = spec or ScenarioSpec()
    rng = np.random.default_rng(spec.seed)
    out: list[AgentTrajectory] = []
    counter = 0

    def pick_model() -> str:
        return str(rng.choice(spec.model_versions))

    def pick_env() -> str:
        return str(rng.choice(spec.environments))

    for fam in POISON_FAMILIES:
        for k in range(spec.n_harmful_per_family):
            out.append(generate_poisoning_scenario(
                fam,
                seed=spec.seed + counter,
                model_version=pick_model(),
                environment=pick_env(),
                harmful=True,
            ))
            counter += 1

    for fam in SABOTAGE_FAMILIES:
        for k in range(spec.n_harmful_per_family):
            out.append(generate_sabotage_scenario(
                fam,
                seed=spec.seed + counter,
                model_version=pick_model(),
                environment=pick_env(),
                harmful=True,
            ))
            counter += 1

    for k in range(spec.n_hard_negatives):
        out.append(generate_benign_curation(
            seed=spec.seed + counter,
            hard_negative=True,
            model_version=pick_model(),
            environment=pick_env(),
        ))
        counter += 1

    for k in range(spec.n_clean_benign):
        out.append(generate_benign_curation(
            seed=spec.seed + counter,
            hard_negative=False,
            model_version=pick_model(),
            environment=pick_env(),
        ))
        counter += 1

    for k in range(spec.n_clean_refactor):
        out.append(generate_clean_refactor(
            seed=spec.seed + counter,
            model_version=pick_model(),
            environment=pick_env(),
        ))
        counter += 1

    # Phase 9 hard negatives: one of each realistic benign workflow family
    for fam in HARD_NEGATIVE_FAMILIES:
        out.append(generate_hard_negative_v2(
            fam,
            seed=spec.seed + counter,
            model_version=pick_model(),
            environment=pick_env(),
        ))
        counter += 1

    rng.shuffle(out)
    return out


def suite_summary(trajectories: list[AgentTrajectory]) -> dict[str, Any]:
    n_h = sum(1 for t in trajectories if t.label == Label.HARMFUL)
    n_b = sum(1 for t in trajectories if t.label == Label.BENIGN)
    families: dict[str, int] = {}
    for t in trajectories:
        families[t.attack_family.value] = families.get(t.attack_family.value, 0) + 1
    return {
        "n": len(trajectories),
        "harmful": n_h,
        "benign": n_b,
        "families": families,
        "model_versions": sorted({t.model_version for t in trajectories}),
        "environments": sorted({t.environment for t in trajectories}),
    }
