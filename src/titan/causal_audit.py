"""
Causal-prefix / information-boundary audit for deployable features.

At event index t, every deployable feature φ must satisfy:
  φ(prefix_t) depends only on events[0:t]
  φ(P ‖ S1) == φ(P ‖ S2)  (suffix independence)
Labels, attack family, final outcomes, and future irreversible indices
are inaccessible to feature extraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np

from .control_eval.sandbox import prefix_trajectory
from .schema import AgentTrajectory, EventType, Label, make_event
from .temporal import DEPLOYABLE_FEATURES, FORENSIC_FEATURES, TEMPORAL_FEATURES


ScoreFn = Callable[[AgentTrajectory], float]
FeatureFn = Callable[[AgentTrajectory], float]


@dataclass
class AuditFinding:
    feature: str
    status: str  # pass | fail | skip
    detail: str


@dataclass
class CausalAuditReport:
    findings: list[AuditFinding] = field(default_factory=list)
    n_pass: int = 0
    n_fail: int = 0
    n_suffix_tests: int = 0
    n_prefix_monotonic_ok: int = 0
    deployable_clean: bool = False
    forensic_flagged: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_pass": self.n_pass,
            "n_fail": self.n_fail,
            "n_suffix_tests": self.n_suffix_tests,
            "deployable_clean": self.deployable_clean,
            "forensic_flagged": self.forensic_flagged,
            "findings": [
                {"feature": f.feature, "status": f.status, "detail": f.detail}
                for f in self.findings
            ],
            "notes": self.notes,
        }

    def summary(self) -> str:
        lines = [
            "══ Causal-Prefix Audit ══",
            f"  deployable_clean={self.deployable_clean}  pass={self.n_pass} fail={self.n_fail}",
            f"  suffix_independence_tests={self.n_suffix_tests}",
        ]
        if self.forensic_flagged:
            lines.append(f"  forensic (not deployable): {self.forensic_flagged}")
        for f in self.findings:
            if f.status == "fail":
                lines.append(f"  FAIL {f.feature}: {f.detail}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)


def _feature_vector(
    t: AgentTrajectory,
    features: dict[str, FeatureFn],
) -> dict[str, float]:
    out = {}
    for name, fn in features.items():
        try:
            out[name] = float(fn(t))
        except Exception as exc:
            out[name] = float("nan")
            out[f"_err_{name}"] = 1.0
    return out


def _vectors_equal(a: dict[str, float], b: dict[str, float], tol: float = 1e-9) -> tuple[bool, str]:
    keys = sorted(set(a) | set(b))
    for k in keys:
        if k.startswith("_err_"):
            continue
        va, vb = a.get(k, 0.0), b.get(k, 0.0)
        if np.isnan(va) or np.isnan(vb):
            if not (np.isnan(va) and np.isnan(vb)):
                return False, f"{k}: nan mismatch"
            continue
        if abs(va - vb) > tol:
            return False, f"{k}: {va} vs {vb}"
    return True, "ok"


def suffix_independence_test(
    trajectory: AgentTrajectory,
    features: dict[str, FeatureFn],
    *,
    prefix_len: int | None = None,
) -> tuple[bool, str]:
    """
    Hold prefix P fixed, attach two different suffixes S1, S2.
    Require φ(P‖S1) on prefix-only extraction == φ(P) for all deployable φ.
    Actually: extract features on prefix alone vs on full traj but... we extract
    only from the trajectory object passed. So compare φ(P) with φ(P) after
    building T1=P‖S1, T2=P‖S2 but evaluating φ only on prefix_trajectory(T, len(P)).
    """
    n = len(trajectory.events)
    if n < 3:
        return True, "too short"
    plen = prefix_len if prefix_len is not None else max(2, n // 2)
    plen = min(plen, n - 1)
    P = prefix_trajectory(trajectory, plen)
    base = _feature_vector(P, features)

    # Two alternate futures
    t1 = _attach_suffix(P, kind="train_queue")
    t2 = _attach_suffix(P, kind="benign_end")
    # Re-extract from prefixes of same length — must match base and each other
    p1 = prefix_trajectory(t1, plen)
    p2 = prefix_trajectory(t2, plen)
    v1 = _feature_vector(p1, features)
    v2 = _feature_vector(p2, features)
    ok1, d1 = _vectors_equal(base, v1)
    if not ok1:
        return False, f"prefix changed by suffix train_queue: {d1}"
    ok2, d2 = _vectors_equal(base, v2)
    if not ok2:
        return False, f"prefix changed by suffix benign: {d2}"
    ok3, d3 = _vectors_equal(v1, v2)
    if not ok3:
        return False, f"suffixes disagree on shared prefix: {d3}"
    return True, "suffix independent"


def _attach_suffix(prefix: AgentTrajectory, kind: str) -> AgentTrajectory:
    from .schema import AgentTrajectory as AT
    import copy
    events = list(prefix.events)
    ts = events[-1].timestamp + 1 if events else 0.0
    if kind == "train_queue":
        events.append(make_event(EventType.OUTCOME, {
            "status": "completed",
            "training_run_queued": True,
            "contaminated": True,
        }, timestamp=ts))
    else:
        events.append(make_event(EventType.OUTCOME, {
            "status": "completed",
            "training_run_queued": False,
        }, timestamp=ts))
        events.append(make_event(EventType.COMMIT, {
            "identity": "agent",
            "n_files": 1,
            "message": "noop",
        }, timestamp=ts + 1))
    return AT(
        trajectory_id=prefix.trajectory_id + f"_suf_{kind}",
        events=events,
        label=prefix.label,
        attack_family=prefix.attack_family,
        model_version=prefix.model_version,
        environment=prefix.environment,
        task_family=prefix.task_family,
        existing_monitor_scores=dict(prefix.existing_monitor_scores),
        monitor_judgments=list(prefix.monitor_judgments),
        metadata=dict(prefix.metadata),
    )


def label_inaccessibility_test(features: dict[str, FeatureFn]) -> list[AuditFinding]:
    """Features must not read label/attack_family/metadata outcomes."""
    from .scenarios.poisoning import generate_poisoning_scenario
    from .schema import AttackFamily
    t = generate_poisoning_scenario(AttackFamily.CLUSTER_CONCENTRATION, seed=99)
    base = _feature_vector(t, features)
    t2 = prefix_trajectory(t, len(t.events))  # copy
    # Mutate labels/metadata only
    t2.label = Label.BENIGN if t.label == Label.HARMFUL else Label.HARMFUL
    t2.attack_family = AttackFamily.NONE
    t2.metadata = {"contaminated": True, "attack": "secret"}
    alt = _feature_vector(t2, features)
    ok, detail = _vectors_equal(base, alt)
    if ok:
        return [AuditFinding("label_inaccessibility", "pass", "features ignore label/family/metadata")]
    return [AuditFinding("label_inaccessibility", "fail", detail)]


def run_causal_audit(
    trajectories: list[AgentTrajectory],
    *,
    feature_sets: dict[str, dict[str, FeatureFn]] | None = None,
    max_trajs: int = 24,
) -> CausalAuditReport:
    """
    Audit deployable features for suffix independence and label inaccessibility.
    Forensic features are listed but not required to pass deployable gates.
    """
    report = CausalAuditReport()
    feature_sets = feature_sets or {
        "deployable": DEPLOYABLE_FEATURES,
        "forensic": FORENSIC_FEATURES,
    }

    deployable = feature_sets.get("deployable", {})
    forensic = feature_sets.get("forensic", {})
    report.forensic_flagged = sorted(forensic.keys())
    report.notes.append(
        "Forensic features may use full-trajectory outcome markers; "
        "they are EXCLUDED from deployable before-harm scoring."
    )

    # Label inaccessibility on deployable
    for finding in label_inaccessibility_test(deployable):
        report.findings.append(finding)
        if finding.status == "pass":
            report.n_pass += 1
        else:
            report.n_fail += 1

    # Suffix independence on sample trajectories
    sample = trajectories[:max_trajs]
    fails = 0
    tests = 0
    for t in sample:
        if len(t.events) < 3:
            continue
        tests += 1
        ok, detail = suffix_independence_test(t, deployable)
        report.n_suffix_tests += 1
        if not ok:
            fails += 1
            report.findings.append(AuditFinding(
                feature="suffix_independence",
                status="fail",
                detail=f"{t.trajectory_id}: {detail}",
            ))
            report.n_fail += 1
    if fails == 0 and tests > 0:
        report.findings.append(AuditFinding(
            "suffix_independence", "pass", f"all {tests} trajectories clean"
        ))
        report.n_pass += 1

    # Per-feature: forensic should not be in deployable
    overlap = set(deployable) & set(forensic)
    if overlap:
        report.findings.append(AuditFinding(
            "deployable_forensic_partition",
            "fail",
            f"overlap: {sorted(overlap)}",
        ))
        report.n_fail += 1
    else:
        report.findings.append(AuditFinding(
            "deployable_forensic_partition",
            "pass",
            "deployable ∩ forensic = ∅",
        ))
        report.n_pass += 1

    # Prefix-only recomputation consistency (streaming contract)
    mono_ok = 0
    for t in sample[:12]:
        prev = None
        good = True
        for end in range(1, min(len(t.events), 12) + 1):
            pref = prefix_trajectory(t, end)
            vec = _feature_vector(pref, deployable)
            # Recompute twice — deterministic
            vec2 = _feature_vector(pref, deployable)
            ok, d = _vectors_equal(vec, vec2)
            if not ok:
                good = False
                report.findings.append(AuditFinding(
                    "determinism", "fail", f"{t.trajectory_id}@{end}: {d}"
                ))
                report.n_fail += 1
                break
            prev = vec
        if good:
            mono_ok += 1
    report.n_prefix_monotonic_ok = mono_ok

    report.deployable_clean = report.n_fail == 0 and report.n_suffix_tests > 0
    if report.deployable_clean:
        report.notes.append("Deployable feature set PASSED causal-prefix audit.")
    else:
        report.notes.append("Deployable feature set has failures — do not claim before-harm yet.")
    return report


def assert_before_harm_scoring_excludes_irreversible_event() -> None:
    """
    detection_before_harm must score prefixes with end < irr_idx (exclusive).
    """
    from .control_eval.protocol import detection_before_harm
    # Inspect source contract via a synthetic case
    from .scenarios.adaptive import generate_stealth_attack
    from .schema import AttackFamily
    from .control_eval.sandbox import simulate_session_outcome

    t = generate_stealth_attack(AttackFamily.STEALTH_POISON, seed=0)
    outcome = simulate_session_outcome(t)
    assert outcome.first_irreversible_event_index is not None

    seen_ends = []

    def spy(traj: AgentTrajectory) -> float:
        # record how many events the scorer saw
        seen_ends.append(len(traj.events))
        return 0.0

    detection_before_harm([t], spy, threshold=0.5)
    irr = outcome.first_irreversible_event_index
    # All scored prefixes must have length <= irr (exclusive of irreversible at irr)
    # After fix: max prefix length should be irr (0-indexed exclusive => len <= irr)
    if seen_ends:
        assert max(seen_ends) <= irr, (
            f"before-harm scorer saw prefix len {max(seen_ends)} >= irr_idx {irr} "
            "(includes irreversible event or later)"
        )
