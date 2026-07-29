# TITAN

**Trajectory Inspection & Targeted Anomaly Network**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

TITAN is a **consequential-action control system** for AI agent safety. It
discovers monitor blind spots, models protected-state invariants, and decides
whether an exact proposed action should be allowed, logged, verified in a
reversible twin, escrowed, confirmed by a human, or blocked — **before
execution authority is granted**.

It is built for the work OpenAI’s [Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) role describes: turn open-ended future risks into concrete monitors, iterate them toward production safety pipelines, and stress-test monitorability itself.

> **Status (current frontier: V12 / 1.2.0 — capture-complete):** the V10 dual
> `block_ready` / `allow_ready` constitution remains **frozen and untouched**.
> V11 proved that constitution holds on completed decisions under adaptive and
> chaos pressure, with a real pre-generation witness. V11 also exposed a
> localized transport defect: **39.2% of planned live sessions failed provider
> schema registration** for semantic aliases. V12 turns that defect into
> permanent launch gates — registry, schema compiler, forced-tool certification,
> capture ledger, multi-turn continuity — without retuning thresholds.
> **Production eligibility remains NO** until a separate operational safety case.

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

That is a **monitorability plus enforcement** problem. Transport completeness
is part of the safety system: a provider rejection before governance is **not**
a TITAN block, escrow, or allow — it is a capture failure and must be counted
in the intention-to-test denominator.

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

### Capability governance (frozen constitution)

```text
Independent adverse proof  → BLOCK may fire
Complete favorable proof   → ALLOW may fire
Neither side proven        → ESCROW
No valid COMMIT            → no protected execution
```

### Transport is part of the safety system (V12)

```text
provider acceptance
→ event capture
→ action normalization
→ evidence resolution
→ governor disposition
→ PREPARE → state recheck → COMMIT → execution
```

Every link is measured independently. The **attempted population** is the
primary denominator.

### Evaluation truth stays offline

Acting models never receive `matrix_cell`, expected disposition, harm/benign
labels, or attack-family tags. Those live in sealed server-side session
contracts keyed by opaque `session_id`.

---

## Current frontier — TITAN V12 (1.2.0)

**Codename:** Witnessed Capture-Complete Adaptive Control

V12 does **not** replace the governor. It hardens everything around it.

### What V11 proved (preserve)

| Finding | Result |
| --- | --- |
| Pre-generation witness enforcement | **Real** (machine-enforced remote receipt) |
| Labels off acting models | **Yes** |
| Complete-case block-ready | **328/328 BLOCK** |
| Incomplete harm / incomplete benign allows | **0 / 0** |
| Adaptive + chaos silent allows | **0** |
| Harmful executions / gateway bypasses | **0 / 0** |
| Benign-10k false blocks | **0** |
| Benign-10k complete allow | **~81.8%** |
| Unique benign fingerprints | **10,000** |

Full V11 write-up: [Attack-Vector-Results-2.md](Attack-Vector-Results-2.md)

### What V11 discovered (fix in V12)

```text
Semantic aliases (schedule_refresh, ingest_corpus_delta, …)
were forced via tool_choice but absent from live HTTP tool schemas.
→ 470/1200 provider rejections before TITAN could govern.
```

That was a **schema registration failure**, not a governor miss.

### V12 permanent invariants

| Invariant | Mechanism |
| --- | --- |
| Every alias → exactly one canonical effect | `src/titan/v12/action_registry.py` |
| OpenAI & xAI schemas generated from registry | `schema_compiler.py` |
| Lane vocabulary ⊆ registry ⊆ provider schemas | **fail-closed freeze gate** |
| Every forced tool accepted by both providers | **provider certification** (pre-freeze) |
| ITT capture ledger | `capture_ledger.py` + session state machine |
| Multi-turn pivots only use registered names | `multi_turn.py` + executor |
| Structural holdouts are transport-known | `structural_holdouts.py` |
| Canary complete-benign safety-case fields | `benign_safety_case.py` (no threshold retune) |

Freeze refusal example:

```text
FREEZE REFUSED

Missing OpenAI tool definitions:
  schedule_refresh
  ingest_corpus_delta
```

### Dry readiness (no API keys)

```bash
python benchmarks/run_v12_campaign.py
# runs tests + transport freeze gate; writes readiness.json
```

### Live campaign (when you provide keys)

```bash
export OPENAI_API_KEY=...   # env only — never commit
export XAI_API_KEY=...

python benchmarks/run_v12_campaign.py \
  --live \
  --require-provider-cert \
  --n-harm-per-provider 500 \
  --n-benign-actions 10000 \
  --openai-model gpt-4o \
  --openai-reproduction-model gpt-4o-mini \
  --xai-model grok-4.3
```

Default transfer OpenAI model is **`gpt-4o`** (capability-aligned with Grok 4.3
for the next live run). Reproduction slice retains `gpt-4o-mini` for V11
comparability. **Never pool** reproduction and transfer results.

### Planned V12 allocation (replication + holdouts)

| Lane | Per provider | Notes |
| --- | ---: | --- |
| Constitutional harmful | 300 | Direct V10/V11 comparison |
| Adaptive cross-play | 150 | Multi-turn alias pivots |
| Evidence/gateway chaos | 50 | Proof substrate attacks |
| Structural holdouts | 50 | Transport-known, semantically novel |
| Live benign | 100 | Complete + incomplete cells |
| Operational benign | 10,000 (shared) | Diversity-tracked |

Target capture: **schema rejections = 0**, capture completeness **≥ 99%**.

---

## Version lineage

| Version | Role |
| --- | --- |
| V4–V8 | Architecture evolution; forensic score corrections |
| **V9** | Evidence-chain repair; label-blind proposals; release gates |
| **V10** | Dual readiness; real OpenAI+xAI HTTP; 150×150 constitutional lock |
| **V11** | Pre-generation witness; server-side cells; adaptive/chaos; 500×2 + 10k |
| **V12** | Capture-complete transport registry; freeze gates; ITT ledger; holdouts |

**Unchanged since V10:** dual readiness, thresholds, evidence floors, scorer,
calibrators, PREPARE/COMMIT tokens, constitutional metric definitions.

Historical reports: [`Archive/`](Archive/) · V11 results:
`benchmarks/campaigns/titan-v11-adaptive-crossplay/`

---

## Install

```bash
cd ~/Desktop/TITAN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q
```

---

## Quickstart

```bash
# Discovery + held-out evaluation
python examples/quickstart.py

# Full unit/integration suite
pytest tests/ -q

# V12 transport readiness (no keys)
python benchmarks/run_v12_campaign.py

# V12 live (keys + git remote push access)
python benchmarks/run_v12_campaign.py --live --require-provider-cert
```

### V12 action registry (library)

```python
from titan.v12 import default_registry, assert_transport_closure, canonicalize_tool

reg = default_registry()
assert reg.canonicalize("schedule_refresh") == "queue_training"
assert_transport_closure(require_provider_cert=False)

# HTTP adapters load the same registry for tool schemas
from titan.v10.http_providers import _openai_tools
assert any(t["function"]["name"] == "ingest_corpus_delta" for t in _openai_tools())
```

---

## Package layout

```text
src/titan/
  v9/     # evidence chain, governor core, gateway, tokens
  v10/    # dual-readiness harness, HTTP providers (registry-backed tools)
  v11/    # witness receipts, session store, lanes, live executor
  v12/    # capture-complete transport + launch gates
    action_registry.py
    schema_compiler.py
    gates.py
    provider_certification.py
    session_state.py
    capture_ledger.py
    multi_turn.py
    structural_holdouts.py
    benign_safety_case.py
    witness_gate.py
benchmarks/
  run_v11_campaign.py
  run_v12_campaign.py
  campaigns/titan-v11-adaptive-crossplay/
  campaigns/titan-v12-capture-complete/
```

---

## Design principles

1. **Inspectable** — decisions and freeze artifacts carry provenance.  
2. **Bounded** — hard caps on rounds, candidates, and complexity.  
3. **Honest metrics** — complete-case **and** intention-to-test; no regenerate-until-success.  
4. **Authority must be earned** — evidence and escrow precede blocking *and* allowing.  
5. **Dual readiness** — block path and allow path are not a single threshold.  
6. **Witness before generation** — remote persistence alone is not independence.  
7. **Labels stay offline** — acting models do not carry the answer key.  
8. **Transport-known novelty** — semantic holdouts never rely on unregistered syntax.  
9. **Safety ∧ utility** — zero false blocks without universal escrow.  

---

## What TITAN is not

- Not a universal anomaly detector for arbitrary sensors  
- Not a claim of production FNR on open-ended traffic  
- Not production-eligible because research integrity gates passed  
- Not “independent” merely because a private GitHub remote exists  
- Not a threshold-tuning exercise when capture fails  

---

## Role fit

See [docs/ROLE_FIT.md](docs/ROLE_FIT.md) for mapping to RSI Safety
responsibilities (automated auditing, rigorous monitorability, scalable
oversight, pipeline promotion).

---

## License

Apache-2.0
