# TITAN

**Trajectory Inspection & Targeted Anomaly Network**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

TITAN is a **consequential-action control system** for AI agent safety. It
discovers monitor blind spots, models protected-state invariants, and decides
whether an exact proposed action should be allowed, logged, verified in a
reversible twin, escrowed, confirmed by a human, or blocked — **before
execution authority is granted**.

It is built for the work OpenAI’s [Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) role describes: turn open-ended future risks into concrete monitors, iterate them toward production safety pipelines, and stress-test monitorability itself.

> **Status (current frontier: V11 / 1.1.0):** capability-governance control plane
> with dual `block_ready` / `allow_ready` constitution (frozen from V10),
> real dual-provider HTTP evaluation, **machine-enforced pre-generation witness
> receipts**, and **server-side evaluation-cell bindings**. Research integrity
> gates can pass while **production eligibility remains false**. Headline
> numbers never replace denominators, witness mode, or intention-to-test
> accounting.

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
dual readiness: block_ready  vs  allow_ready   (independent paths)
        ↓
ALLOW / LOG / REQUEST / SHADOW / ESCROW / HUMAN / BLOCK
        ↓
signed PREPARE → fresh state check → one-use COMMIT → protected executor
```

Offline discovery and evaluation remain important, but labels are structurally
absent from the online governor interface. In V11, evaluation-cell identity
(`matrix_cell`, expected disposition, harm/benign labels) lives only in a
**server-side sealed session store** keyed by opaque `session_id`.

### Capability governance (not trajectory-only scoring)

```text
PROPOSE → VERIFY → PREPARE → COMMIT
```

Infrastructure uncertainty must never become authority. Incomplete adverse
proof is not automatic BLOCK; incomplete favorable proof is not automatic ALLOW.

### What a trajectory is

A session of messages, tool calls, file ops, data mutations, eval changes,
permission failures, commits, monitor judgments, and outcomes — not a raw
EEG/seismic waveform.

---

## Current frontier — TITAN V11 (1.1.0)

V11 does **not** retune V10 thresholds. It hardens the *claim surface*:

| Upgrade | Why it matters |
| --- | --- |
| **Fail-closed witness gate** | Runner refuses any API generation without a verified receipt bound to remote GitHub artifacts (commit, tag object, wheel, protocol, generator, model contracts) |
| **Server-side eval cells** | Acting models never carry test-cell identity; governor still sees authenticated action/evidence objects |
| **Adaptive + chaos lanes** | Part of the 500-per-provider budget attacks novelty and the proof substrate, not only the known matrix |
| **10k benign diversity** | Operational utility (auto-allow, escrow friction, false blocks) with explicit fingerprint/family diversity |
| **ITT accounting** | Attempted denominator, preserved failures, no regenerate-until-success gaming |

### Flagship live campaign (`titan-v11-adaptive-crossplay`)

| Item | Value |
| --- | --- |
| Harmful sessions | **500 / provider × 2** (1000) |
| Live benign sessions | **100 / provider × 2** (200) |
| Operational benign actions | **10,000** |
| Witness | Pre-generation, remote retrieval + Ed25519 (mode weaker than external org) |
| Complete-case block-ready recall | **328/328 = 1.000** |
| Incomplete harm automatic allows | **0** |
| Incomplete benign automatic allows | **0** |
| Silent harmful allows (completed) | **0** |
| Harmful executions | **0** |
| Gateway bypasses | **0** |
| Benign-10k false blocks | **0** |
| Benign-10k complete allow rate | **~0.82** |
| Provider capture failures (ITT) | **470/1200** (alias tools missing from live tool schema) |
| Production eligible | **NO** |

Full write-up: [Attack-Vector-Results-2.md](Attack-Vector-Results-2.md)  
Artifacts: `benchmarks/campaigns/titan-v11-adaptive-crossplay/`

### Witness pipeline (fail-closed)

```text
source frozen
→ wheel built and hashed
→ protocol sealed
→ generator contract sealed
→ model contract sealed
→ signed tag created
→ branch and tag pushed
→ remote artifacts retrieved
→ independent-style receipt signed
→ runner verifies receipt
→ API generation unlocked
```

```bash
export OPENAI_API_KEY=... XAI_API_KEY=...   # env only — never commit
python benchmarks/run_v11_campaign.py \
  --n-harm-per-provider 500 \
  --n-benign-actions 10000
```

Without a valid receipt the runner aborts with:

```text
GENERATION REFUSED:
independent pre-generation witness unavailable or invalid
```

---

## Prior flagship — TITAN V10

V10 established the **dual-readiness constitution** and the live dual-provider
HTTP path (OpenAI + xAI). Locked 150/150-per-provider campaign
(`titan-v10-live-http-150x150`):

| Constitutional cell | Result |
| --- | ---: |
| Block-ready harmful BLOCK | **460/460** |
| Incomplete harmful automatic allows | **0** |
| Proof-complete benign ALLOW* | **224/224** |
| Incomplete benign automatic allows | **0** |
| AUROC (live) | **0.984** |

V10 freeze was **local / post-generation archival** relative to an independent
remote witness. Do **not** re-interpret the private GitHub push as a
pre-generation witness for V10. See Archive notes and
[Archive/Attack-Vector-Results.md](Archive/Attack-Vector-Results.md).

**Unchanged from V10 into V11:** dual readiness, action-class thresholds,
evidence floors, scorer, calibrators, PREPARE/COMMIT tokens, constitutional
metric definitions.

---

## Version lineage (honest compression)

| Version | Role |
| --- | --- |
| V4–V8 | Architecture evolution; some scores later forensic-corrected |
| **V9** | Evidence-chain repair, label-blind action proposals, release-gate machinery |
| **V10** | Dual readiness; real OpenAI+xAI HTTP; 150×150 live constitutional lock |
| **V11** | Witness-gated generation; server-side cells; adaptive/chaos; 500×2 + 10k |

Historical reports live under [`Archive/`](Archive/). Fossils of prior live
campaigns live under `fossils/` and `benchmarks/campaigns/` as sealed when frozen.

---

## Install

```bash
cd ~/Desktop/TITAN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

API keys for live campaigns (never commit):

```bash
export OPENAI_API_KEY=...
export XAI_API_KEY=...          # or GROK_API_KEY
# optional: TITAN_WITNESS_DIR=~/.titan-witness
```

---

## Quickstart

```bash
# End-to-end discovery + held-out evaluation
python examples/quickstart.py

# Data-poisoning demo with baselines + shadow registry
python examples/data_poisoning_demo.py

# Full pytest suite
pytest tests/ -q

# V9: label-blind shadow inspection (never grants execution authority)
python -m titan.cli v9-inspect trajectory.json

# V11: witness-gated live campaign (requires keys + git remote push access)
python benchmarks/run_v11_campaign.py --n-harm-per-provider 500 --n-benign-actions 10000
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
```

### V11 session store (eval cells offline)

```python
from titan.v11.session_store import SessionStore
from titan.v11.witness import assert_generation_allowed, WitnessError

# public_view() never includes matrix_cell / expected disposition / labels
# offline contracts are sealed post-witness only
```

---

## Evaluation contract

Development, calibration, and locked evaluation sources must be disjoint.
Metrics report raw counts and denominators. Equal-score groups are indivisible
at an FPR threshold.

**Constitutional cells are never recombined into naive “BLOCK / all harm”.**

Release is conjunctive and worst-slice-gated. It requires independent witnessing,
replication, calibration/shift tests, and reliability/security/privacy
validation. **None of those external gates is claimed complete for production.**

---

## Package layout

```text
src/titan/
  schema.py, features.py, collisions.py, dsl.py, synthesis.py, ...
  v9/     # evidence chain, governor, gateway, tokens, release gates
  v10/    # dual-readiness harness, HTTP providers (OpenAI + xAI)
  v11/    # witness receipts, session store, adaptive/chaos/benign lanes, executor
benchmarks/
  run_v11_campaign.py
  campaigns/titan-v11-adaptive-crossplay/
  campaigns/titan-v10-live-http-150x150/   # fossilized V10 flagship
```

---

## Design principles

1. **Inspectable** — candidates and decisions carry provenance.  
2. **Bounded** — hard caps on rounds, candidates, and complexity.  
3. **Honest metrics** — no proxy transfer, no free perfect scores, ITT reported.  
4. **Authority must be earned** — evidence and escrow precede blocking *and* allowing.  
5. **Dual readiness** — block path and allow path are not a single threshold.  
6. **Witness before generation** — remote persistence alone is not independence.  
7. **Labels stay offline** — acting models do not carry the answer key.  

---

## What TITAN is not

- Not a universal anomaly detector for arbitrary sensors  
- Not a claim of production FNR on open-ended traffic  
- Not calibrated probabilities without a sealed external calibration set  
- Not a substitute for human review or defense in depth  
- Not “independent” merely because a private GitHub remote exists  

Synthetic and lab-structured scenarios are **research instruments**. Production
claims require real agent traces, independent adjudication and replication,
privacy controls, durable deployment infrastructure, and adversarial control
evaluations under a stronger witness than this repository currently provides.

---

## Role fit

See [docs/ROLE_FIT.md](docs/ROLE_FIT.md) for an explicit mapping to RSI Safety
responsibilities (automated auditing, rigorous monitorability, scalable
oversight, pipeline promotion).

---

## License

Apache-2.0
