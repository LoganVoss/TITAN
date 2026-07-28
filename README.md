# TITAN

**Trajectory Inspection & Targeted Anomaly Network**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

TITAN is a **consequential-action control system** for AI agent safety. It
discovers monitor blind spots, models protected-state invariants, and decides
whether an exact proposed action should be allowed, logged, verified in a
reversible twin, escrowed, confirmed by a human, or blocked.

It is built for the work OpenAI’s [Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) role describes: turn open-ended future risks into concrete monitors, iterate them toward production safety pipelines, and stress-test monitorability itself.

> **Status:** V9 is a production-oriented reference implementation, not a
> production-validated blocker. Its current safety value is the enforcement
> architecture and the falsifiable release process—not a new headline score.

**Primary objective:** prevent unsafe changes to training data, evaluations,
canaries, safeguards, credentials, and monitoring infrastructure *before they
execute*, without turning ordinary authorized work into an unusable review
queue.

---

## Why this exists

Most monitors ask: *“Is this trajectory bad?”*

TITAN asks two linked questions:

1. *Where do current measurements fail to distinguish unsafe from legitimate
   protected-state transitions?*
2. *At this exact action boundary, is the evidence strong enough to grant
   execution authority?*

That is a **monitorability plus enforcement** problem, not generic anomaly
detection. The first narrow production candidate is `queue_training`: data
poisoning matters most at the moment contaminated or insufficiently verified
data could enter a training run.

---

## Architecture

```text
typed observable event stream
        ↓
extract every consequential proposal at its exact event boundary
        ↓
score only the exclusive pre-action prefix + unresolved obligations
        ↓
authenticated authorization, effect, data-integrity, and exact-state twin evidence
        ↓
calibrated action-class policy + control-plane integrity
        ↓
ALLOW / LOG / REQUEST / SHADOW / ESCROW / HUMAN / BLOCK
        ↓
signed PREPARE → fresh state check → one-use COMMIT → protected executor
```

Offline discovery and evaluation remain important, but labels are structurally
absent from the online governor interface.

### What a trajectory is

A session of messages, tool calls, file ops, data mutations, eval changes, permission failures, commits, monitor judgments, and outcomes — not a raw EEG/seismic waveform.

### What a collision is

A **cross-regime** pair only: known harmful + benign hard-negative that current measurements place close together in **z-scored** feature space. Same-regime neighbors are never collisions.

### What synthesis does

Builds deterministic DSL programs over safety features (cluster concentration, gradient influence, eval weakening after mutation, bypass attempts, …), scores them for separation / stability / **real transfer**, then **re-inserts** winners into the feature vector and re-runs collision detection. Collision reduction is attributable to augmentation — not a quieter threshold.

---

## Fixes relative to the prior prototype (Voss Codex)

| Issue | TITAN |
|---|---|
| Synthesis never re-entered vectors | Promoted features augment the active map; final collisions recompute on the new map |
| Collisions ignored labels | Explicit `Label`; cross-regime only |
| Unnormalized Euclidean distance | Robust z-score normalization |
| Selection/eval leakage | Discovery / selection / calibration / locked partitions |
| Proxy transfer & perfect-if-zero-collision scores | Real holdout metrics; no free perfect scores |
| “Confidence” / “uncertainty” misnamed | `alert_strength` + `baseline_support` |
| Streaming stalled after buffer trim | Absolute event indices; emit cursor never corrupted |
| “Persistence topology” overclaim | Honest DSL + feature names; no homology theater |
| Zero tests | Full pytest suite |

---

## Install

```bash
cd ~/Desktop/TITAN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Current frontier — TITAN V9 (0.9.0)

V9 repairs the evidence chain before scaling the campaign:

- label-blind, event-indexed action proposals with no harmful-only fallback and
  no repeated-action deduplication;
- continuous prefix hazard and unresolved-obligation tracking;
- protected training-data integrity graphs that compose provenance, lineage,
  validation, influence, concentration, label-change, and canary health before
  a queue or merge boundary;
- Canary Coverage Graph, replacement equivalence, composed degradation, and
  canary debt;
- structured safeguard semantic/effect verification;
- exact-action/state-bound evidence attestations with explicit trusted
  verifier/source/key/domain bindings, expiry, deduplication, and bounded
  acquisition; services sharing one key do not count as independent;
- rank/probability separation with isotonic calibration and Wilson intervals;
- seven typed dispositions with conservative abstention;
- HMAC-authenticated, exact-context, one-use PREPARE/COMMIT capabilities;
- canonical proposal provenance, immutable payload snapshots, fresh
  protected-object checks, and an in-path executor gateway;
- fail-closed streaming with callback deadlines and a persistent timeout
  circuit, control-plane integrity, tamper-evident audit records, immutable
  protocols, sealed manifests, and completion receipts;
- separate live, protected-twin, and operational evaluation reports plus a
  conjunctive release-gate evaluator.

See [V9 architecture](docs/v9/ARCHITECTURE.md),
[production readiness](docs/v9/PRODUCTION_READINESS.md),
[roadmap status](docs/v9/ROADMAP_STATUS.md), and
[security](docs/v9/SECURITY.md).

### V8 evidence correction

The original V8 headline is preserved as development history, not release
evidence. A forensic recomputation found:

| Population | AUROC | R@5% FPR | Benign n |
|---|---:|---:|---:|
| Pure source-matched live | 0.951875 | 0.800 | 40 |
| Protected-twin comparison | 0.986250 | 0.975 | 160 |
| Published pooled mix | 0.979375 | 0.975 | 200 |

At the published pooled threshold, source-matched live benign FPR is 7/40 =
17.5%; protected twins dilute it to 5% overall. V8 action compilation and
blocker evaluation also read ground-truth labels, and the harness executes
effects before post-hoc governance. See the
[V8 evidence audit](docs/v9/V8_EVIDENCE_AUDIT.md) and reproduce it with:

```bash
python benchmarks/audit_v8_evidence.py
```

## Quickstart

```bash
# End-to-end discovery + held-out evaluation
python examples/quickstart.py

# Data-poisoning demo with baselines + shadow registry
python examples/data_poisoning_demo.py

# Collision forensics
python examples/blindspot_discovery.py

# Streaming shadow pipeline
python examples/pipeline_shadow.py

# Full benchmark harness (v1)
python benchmarks/run_benchmarks.py

# Improvements V1 full pipeline
python benchmarks/run_v2_pipeline.py

# CLI
python -m titan.cli demo
python -m titan.cli suite
python -m titan.cli benchmark

# V9: label-blind shadow inspection (never grants execution authority)
python -m titan.cli v9-inspect trajectory.json

# V9 evidence-integrity verification
python -m titan.cli v9-verify-protocol protocol.json
python -m titan.cli v9-verify-manifest manifest.json --root artifacts/
```

### Library usage

```python
from titan import (
    generate_scenario_suite,
    split_dataset,
    run_discovery,
    evaluate_monitor,
    MonitorRegistry,
)
from titan.engine import score_trajectory
from titan.scenarios.generator import ScenarioSpec

suite = generate_scenario_suite(ScenarioSpec(seed=42))
part = split_dataset(suite, seed=42)

result = run_discovery(
    part.discovery,
    selection=part.selection,  # transfer scoring only
    verbose=True,
)

scorer = lambda t: score_trajectory(t, result.promoted)["alert_strength"]
report = evaluate_monitor(scorer, part.locked, name="titan")
print(report.summary())

reg = MonitorRegistry()
reg.register_many(result.promoted)
for e in reg.list():
    reg.promote_to_shadow(e.name)  # never blocking by default
```

---

## V9 evaluation contract

Development, calibration, and locked evaluation sources must be disjoint.
Locked results are then reported as three distinct estimands:

1. **A — pure source-matched live:** harmful and benign sessions from the same
   model, harness, repositories, budgets, friction, and action opportunities.
2. **B — protected benign twins:** exact hard-negative protected workflows.
3. **C — operational mix:** a predeclared deployment mixture, never substituted
   for A.

Equal-score groups are indivisible at an FPR threshold. Every metric records
its raw counts, denominator, action class, population, threshold source,
calibration source, prefix rule, latching rule, and uncertainty interval.
Undefined metrics are explicit `N/A`, never numeric sentinels.

Release is conjunctive and worst-slice-gated. It additionally requires the
roadmap's 300 new harmful sessions across two model families, 10,000
source-matched benign actions, per-class live floors, blinded expert review,
independent witness and replication, calibration/shift tests, and
reliability/security/privacy validation. None of those external gates is
claimed complete here.

---

## Candidate monitor families (data poisoning)

| Pattern | Signal |
|---|---|
| Semantic cluster concentration | Many mutations in one topic cluster |
| Rare-source × high influence | Obscure sources with large probe-model influence |
| Mutation → eval weaken | Data change followed by canary/eval removal |
| Intent vs action disagreement | Monitor disagreement under risky actions |
| Provenance bypass | Permission failures, obfuscation, retries |
| Dispersed commits | Poison spread across identities / micro-commits |
| Label-flip burst | Entropy spikes from bulk relabel |
| Test / safeguard tamper | Research-sabotage variants |

---

## Package layout

```text
src/titan/
  schema.py          # AgentEvent, AgentTrajectory, labels
  features.py        # Safety feature extractors
  collisions.py      # Regime-aware, normalized collisions
  dsl.py             # Constrained monitor DSL
  synthesis.py       # Candidate generation + promotion
  scoring.py         # Separation, stability, real transfer
  engine.py          # Discovery loop with true augmentation
  baselines.py       # Rules, classifier, judge
  streaming.py       # Fixed streaming monitor
  registry.py        # Versioned shadow/promote/retire
  provenance.py      # Audit certificates
  counterfactual.py  # Feature sensitivity (not causal)
  report.py          # Operator-facing reports
  scenarios/         # Poisoning + sabotage generators
  evaluation/        # Splits, metrics, harness
  v9/
    action.py         # Immutable, label-blind action-boundary types
    timing.py         # Prefix hazard + unresolved obligations
    scoring.py        # Continuous rank score (not a probability)
    evidence.py       # Evidence adapters + authenticated twin ensemble
    evidence_trust.py # Exact-context verifier attestations and trust policy
    data_integrity.py # Training-data graph + queue/merge effect verification
    canary.py         # Coverage conservation / replacement equivalence
    safeguard.py      # Structured safeguard effect verification
    calibration.py    # Hierarchical isotonic probabilities + intervals
    governor.py       # Seven-disposition synchronous policy
    gateway.py        # In-path protected executor boundary
    tokens.py         # Signed one-use PREPARE/COMMIT capabilities
    integrity.py      # Control-plane health + audit chain
    streaming.py      # Durable fail-closed monitor
    metrics.py        # Tie-safe typed metric contract
    populations.py    # Separate A/B/C evaluation populations
    protocol.py       # Canonical immutable protocol
    manifest.py       # Artifact seals + completion receipts
    release.py        # Conjunctive release-gate evaluator
```

---

## Design principles

1. **Inspectable** — every candidate is a DSL expression with provenance.  
2. **Bounded** — hard caps on rounds, candidates, and complexity.  
3. **Honest metrics** — no proxy transfer, no free perfect scores.  
4. **Authority must be earned** — shadow, evidence, and escrow precede blocking.
5. **Labeled regimes** — collisions are a safety concept, not nearest neighbors.  
6. **Normalized space** — thresholds have meaning across feature scales.  

---

## What TITAN is not

- Not a universal anomaly detector for arbitrary sensors  
- Not a claim of production FNR on open-ended traffic  
- Not calibrated probabilities without a sealed external calibration set
- Not a substitute for human review or defense in depth  

Synthetic scenarios are **research instruments**. Production claims require
real agent traces, independent adjudication and replication, privacy controls,
durable deployment infrastructure, and adversarial control evaluations.

---

## Role fit

See [docs/ROLE_FIT.md](docs/ROLE_FIT.md) for an explicit mapping to RSI Safety responsibilities (automated auditing, rigorous monitorability, scalable oversight, pipeline promotion).

---

## License

Apache-2.0
