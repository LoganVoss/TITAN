"""
Four disjoint partitions for credible evaluation:

1. Discovery  — seed attacks + clean traces (feature invention)
2. Selection  — different attack implementations / hard negatives
3. Calibration — clean deployment-like traffic only
4. Locked evaluation — held-out model versions, environments, attack variants
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

from ..config import DEFAULT_SPLIT_FRACTIONS
from ..schema import AgentTrajectory, AttackFamily, Label


@dataclass
class Partition:
    discovery: list[AgentTrajectory]
    selection: list[AgentTrajectory]
    calibration: list[AgentTrajectory]  # clean only
    locked: list[AgentTrajectory]
    meta: dict = field(default_factory=dict)

    def summary(self) -> str:
        def stats(xs: list[AgentTrajectory]) -> str:
            h = sum(1 for t in xs if t.label == Label.HARMFUL)
            b = sum(1 for t in xs if t.label == Label.BENIGN)
            return f"n={len(xs)} (H={h},B={b})"
        return (
            f"discovery[{stats(self.discovery)}] "
            f"selection[{stats(self.selection)}] "
            f"calibration[{stats(self.calibration)}] "
            f"locked[{stats(self.locked)}]"
        )


def _stratified_indices(
    trajectories: Sequence[AgentTrajectory],
    rng: np.random.Generator,
) -> dict[str, list[int]]:
    """Group indices by (label, attack_family) for stratified draws."""
    groups: dict[str, list[int]] = {}
    for i, t in enumerate(trajectories):
        key = f"{t.label.value}::{t.attack_family.value}"
        groups.setdefault(key, []).append(i)
    for key in groups:
        rng.shuffle(groups[key])
    return groups


def split_dataset(
    trajectories: Sequence[AgentTrajectory],
    *,
    fractions: tuple[float, float, float, float] = DEFAULT_SPLIT_FRACTIONS,
    seed: int = 0,
    locked_model_version: str | None = None,
    locked_environment: str | None = None,
) -> Partition:
    """
    Create four disjoint partitions.

    Strategy:
    - Prefer holding out a model_version and/or environment for the locked set
      when diversity allows.
    - Calibration is benign-only (for FPR / threshold calibration).
    - Remaining harmful+benign are stratified into discovery / selection / locked.
    """
    assert abs(sum(fractions) - 1.0) < 1e-6, "fractions must sum to 1"
    rng = np.random.default_rng(seed)
    n = len(trajectories)
    if n == 0:
        return Partition([], [], [], [], meta={"empty": True})

    indices = list(range(n))
    locked_idx: set[int] = set()

    # Prefer environment / model holdout for locked eval
    if locked_model_version:
        locked_idx |= {i for i, t in enumerate(trajectories) if t.model_version == locked_model_version}
    if locked_environment:
        locked_idx |= {i for i, t in enumerate(trajectories) if t.environment == locked_environment}

    # Target locked size
    n_locked_target = max(1, int(round(n * fractions[3])))
    if len(locked_idx) < n_locked_target:
        remaining = [i for i in indices if i not in locked_idx]
        rng.shuffle(remaining)
        locked_idx |= set(remaining[: n_locked_target - len(locked_idx)])
    elif len(locked_idx) > n_locked_target * 1.5:
        # Too large — subsample
        locked_list = list(locked_idx)
        rng.shuffle(locked_list)
        locked_idx = set(locked_list[:n_locked_target])

    rest = [i for i in indices if i not in locked_idx]
    rng.shuffle(rest)

    # Calibration: benign only from rest
    benign_rest = [i for i in rest if trajectories[i].label == Label.BENIGN]
    n_cal = max(1, int(round(n * fractions[2])))
    cal_idx = set(benign_rest[: min(n_cal, len(benign_rest))])
    # If not enough benign, take what we have
    rest2 = [i for i in rest if i not in cal_idx]

    # Split rest2 into discovery / selection by fraction ratio
    f_disc, f_sel = fractions[0], fractions[1]
    rel = f_disc + f_sel
    n_disc = int(round(len(rest2) * (f_disc / rel))) if rel > 0 else len(rest2) // 2

    # Stratified fill for discovery / selection
    groups = _stratified_indices([trajectories[i] for i in rest2], rng)
    # Map local group indices back — simpler: just sequential with stratification
    disc_idx: list[int] = []
    sel_idx: list[int] = []
    # Rebuild groups on rest2 global indices
    g2: dict[str, list[int]] = {}
    for i in rest2:
        t = trajectories[i]
        key = f"{t.label.value}::{t.attack_family.value}"
        g2.setdefault(key, []).append(i)
    for key, idxs in g2.items():
        rng.shuffle(idxs)
        cut = max(1, int(round(len(idxs) * (f_disc / rel)))) if rel > 0 else len(idxs) // 2
        cut = min(cut, len(idxs))
        disc_idx.extend(idxs[:cut])
        sel_idx.extend(idxs[cut:])

    # Ensure discovery has both classes if possible
    def take(idxs: list[int]) -> list[AgentTrajectory]:
        return [trajectories[i] for i in idxs]

    part = Partition(
        discovery=take(disc_idx),
        selection=take(sel_idx),
        calibration=take(list(cal_idx)),
        locked=take(list(locked_idx)),
        meta={
            "seed": seed,
            "fractions": fractions,
            "locked_model_version": locked_model_version,
            "locked_environment": locked_environment,
            "n_total": n,
        },
    )
    return part


def family_holdout_split(
    trajectories: Sequence[AgentTrajectory],
    holdout_families: Sequence[AttackFamily],
    *,
    seed: int = 0,
) -> tuple[list[AgentTrajectory], list[AgentTrajectory]]:
    """Split into train (seen families) and transfer (held-out attack families)."""
    hold = set(holdout_families)
    train = [t for t in trajectories if t.attack_family not in hold or t.label == Label.BENIGN]
    # Benign can appear in both conceptually; for transfer test put all holdout-family harm
    transfer = [t for t in trajectories if t.attack_family in hold]
    # Add some benign to transfer for FPR measurement
    benign = [t for t in trajectories if t.label == Label.BENIGN]
    rng = np.random.default_rng(seed)
    if benign:
        n_add = min(len(benign), max(4, len(transfer) // 2))
        extra = list(benign)
        rng.shuffle(extra)
        # Avoid duplicates by id
        seen = {t.trajectory_id for t in transfer}
        for t in extra:
            if t.trajectory_id not in seen and len([x for x in transfer if x.label == Label.BENIGN]) < n_add:
                transfer.append(t)
                seen.add(t.trajectory_id)
    return train, transfer
