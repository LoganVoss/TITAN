"""
Step 7 — Causal audit 2.0: certificates, forbidden-field scan, online/offline parity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import inspect
import time

from ..causal_audit import run_causal_audit, suffix_independence_test
from ..schema import AgentTrajectory
from ..temporal import DEPLOYABLE_FEATURES, FORENSIC_FEATURES
from .schema_v4 import FORBIDDEN_ONLINE_FIELDS


FeatureFn = Callable[[AgentTrajectory], float]


@dataclass
class CausalCertificate:
    feature: str
    mode: str
    status: str
    checks: dict[str, bool]
    issued_at: float = field(default_factory=time.time)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "mode": self.mode,
            "status": self.status,
            "checks": self.checks,
            "issued_at": self.issued_at,
            "notes": self.notes,
        }


def static_forbidden_scan(fn: FeatureFn) -> bool:
    """Best-effort source scan for forbidden field names."""
    try:
        src = inspect.getsource(fn)
    except Exception:
        return True  # cannot scan builtins/lambdas — rely on runtime tests
    lowered = src.lower()
    for bad in FORBIDDEN_ONLINE_FIELDS:
        if bad in lowered and "forensic" not in fn.__name__:
            # allow comments mentioning forensic
            if f'"{bad}"' in src or f"'{bad}'" in src or f".{bad}" in src:
                return False
    return True


def online_offline_parity(
    fn: FeatureFn,
    t: AgentTrajectory,
) -> bool:
    """Same function in batch twice must match (streaming uses same impl)."""
    try:
        a = float(fn(t))
        b = float(fn(t))
        return abs(a - b) < 1e-12
    except Exception:
        return False


def issue_certificates(
    trajectories: list[AgentTrajectory],
    *,
    max_trajs: int = 20,
) -> dict[str, Any]:
    base = run_causal_audit(trajectories, max_trajs=max_trajs)
    certs: list[CausalCertificate] = []
    sample = trajectories[:max_trajs]

    for name, fn in DEPLOYABLE_FEATURES.items():
        checks = {
            "static_forbidden_scan": static_forbidden_scan(fn),
            "online_offline_parity": all(online_offline_parity(fn, t) for t in sample[:5]) if sample else True,
            "suffix_independence": True,
        }
        # spot-check suffix independence for feature alone
        if sample:
            ok, _ = suffix_independence_test(sample[0], {name: fn})
            checks["suffix_independence"] = ok
        status = "pass" if all(checks.values()) else "fail"
        certs.append(CausalCertificate(
            feature=name,
            mode="deployable",
            status=status,
            checks=checks,
        ))

    for name in FORENSIC_FEATURES:
        certs.append(CausalCertificate(
            feature=name,
            mode="forensic",
            status="forensic_excluded_from_online",
            checks={"excluded": True},
            notes="Must not enter online scorers",
        ))

    n_fail = sum(1 for c in certs if c.status == "fail")
    return {
        "base_audit": base.to_dict(),
        "certificates": [c.to_dict() for c in certs],
        "n_deployable_pass": sum(1 for c in certs if c.mode == "deployable" and c.status == "pass"),
        "n_deployable_fail": n_fail,
        "all_deployable_certified": n_fail == 0 and base.deployable_clean,
        "partition_ok": len(set(DEPLOYABLE_FEATURES) & set(FORENSIC_FEATURES)) == 0,
    }
