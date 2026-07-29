#!/usr/bin/env python3
"""
Shadow-deployment pipeline sketch:

  discover → register → shadow score live stream → metrics → promote/retire
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from titan import MonitorRegistry, run_discovery, StreamingMonitor
from titan.engine import score_trajectory
from titan.scenarios.generator import ScenarioSpec, generate_scenario_suite
from titan.scenarios.poisoning import generate_benign_curation
from titan.streaming import aggregate_scorer, build_stream_baseline
from titan.schema import Label


def main() -> None:
    suite = generate_scenario_suite(ScenarioSpec(seed=21, n_harmful_per_family=3))
    disc = run_discovery(suite[:40], name="pipeline", verbose=True)

    reg = MonitorRegistry()
    reg.register_many(disc.promoted)
    for e in reg.list():
        reg.promote_to_shadow(e.name)

    # Streaming on concatenated events from a harmful then benign session
    harmful = next(t for t in suite if t.label == Label.HARMFUL)
    benign = generate_benign_curation(seed=0)

    scorer = aggregate_scorer(disc.promoted) if disc.promoted else (lambda t: t.max_monitor_severity())
    baseline = build_stream_baseline(
        [generate_benign_curation(seed=i) for i in range(8)],
        scorer,
        window_size=5,
        step=2,
    )
    stream = StreamingMonitor(baseline, scorer, watch_z=1.0, alert_z=2.0)

    print("\n── Streaming harmful session ──")
    # Feed in chunks of 2 events
    ev = harmful.events
    for i in range(0, len(ev), 2):
        out = stream.update(ev[i:i + 2], template=harmful)
        if out["new_alerts"]:
            print(f"  chunk {i}: ALERTS {out['new_alerts']}")
        elif out["new_points"]:
            last = out["new_points"][-1]
            print(f"  chunk {i}: state={last['state']} strength={last['alert_strength']:.3f}")

    print("\n── Streaming benign session ──")
    for i in range(0, len(benign.events), 2):
        out = stream.update(benign.events[i:i + 2], template=benign)
        if out["new_points"]:
            last = out["new_points"][-1]
            print(f"  chunk {i}: state={last['state']} strength={last['alert_strength']:.3f}")

    print(f"\nTotal points={len(stream.timeline)} alerts={len(stream.alerts)}")
    print("Registry:", reg.summary())
    print("Shadow-only — no blocking. Promotion requires calibrated metrics + human review.")


if __name__ == "__main__":
    main()
