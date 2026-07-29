# TITAN

<p align="center">
  <img src="docs/assets/TITAN-GITHUB-LOGO.png" alt="TITAN logo" width="280" />
</p>

<p align="center">
  <strong>Trajectory Inspection &amp; Targeted Anomaly Network</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License" /></a>
</p>

TITAN is a **control plane for AI agent actions** — not a chat filter, and not a score that only looks back after something already ran.

When an agent tries to change something that matters (training data, evaluation canaries, safeguards, credentials, monitoring gear), TITAN answers a practical question:

> **Is there enough independent proof to allow this exact action right now — or should it be blocked, held, or sent for review?**

Nothing protected executes until that decision is made. Ordinary authorized work can still get through when the evidence is complete. Incomplete or hostile work does not quietly receive authority.

> **Status:** V12 (1.2.0) — capture-complete scaffolding. The dual-readiness safety constitution is frozen from V10. Research integrity can pass while **production eligibility remains no**.

---

## What TITAN does

1. **Watches the moment of action** — every consequential tool call is inspected at its boundary, before commit.
2. **Looks for blind spots** — finds where harmful and legitimate work look too similar under current measurements.
3. **Requires proof for authority** — adverse proof can block; favorable proof can allow; neither proven means hold (escrow), not guess.
4. **Closes the door without a valid commit** — signed one-use prepare/commit tokens; no token, no protected execution.
5. **Keeps the test answer key offline** — models under evaluation never see the labels that would coach them.

**Primary goal:** stop unsafe changes to training and safety infrastructure *before they land*, without turning every legitimate ops task into a manual review queue.

---

## Why this is different

Most safety stacks do one of two things:

| Common approach | Limitation |
| --- | --- |
| Score a finished transcript (“was this conversation bad?”) | Too late — the damage may already be done |
| Block broadly on keywords or vibes | High friction; easy to game; weak on real state changes |
| Trust the model to “be careful” | No independent evidence; no hard commit gate |

TITAN is built around a different object:

```text
who proposes what action
against which protected object
with which verified authorization and effect evidence
using only what is known before commit
```

That is closer to how real systems fail — poisoned data entering a training queue, a canary quietly weakened, a safeguard rewritten — and closer to how real systems need to be defended.

**Safety and usability are measured together.** A system that blocks all harm by refusing all legitimate work is not finished. Live campaigns track false blocks, escrow rates, and how often proof-complete ops actions are allowed automatically.

---

## How this helps recursive self-improvement (RSI) safety

As agents get better at writing code, changing data, and operating infrastructure, the hard problem is not only “detect bad text.” It is:

- **Protect the things that make the next model** — data, evals, canaries, safeguards.
- **Turn fuzzy future risk into a concrete control** — an action either earns authority or it does not.
- **Iterate monitors into pipelines** — sealed protocols, honest denominators, witness-before-generation, no silent authority on failure.
- **Stress-test the monitor itself** — adaptive attacks, evidence games, capture failures reported instead of hidden.

TITAN is scaffolding for that loop: discover where measurement fails, govern the action boundary, freeze what worked, and refuse to claim production until the full safety case is earned.

---

## Core fundamentals

Most monitors ask: *“Is this trajectory bad?”*

TITAN asks two linked questions:

1. *Where do current measurements fail to separate unsafe from legitimate protected-state changes?*
2. *At this exact action boundary, is the evidence strong enough to grant execution authority?*

### Constitution (frozen)

```text
Independent adverse proof  →  BLOCK may fire
Complete favorable proof   →  ALLOW may fire
Neither side proven        →  ESCROW (hold)
No valid COMMIT            →  no protected execution
```

### Path of an action

```text
event stream
  → extract the proposed action
  → score only the pre-action prefix
  → resolve authenticated evidence
  → decide: allow / log / escrow / human / block
  → signed PREPARE → fresh state check → one-use COMMIT → execute
```

### Non-negotiables

- **Transport is part of safety** — if the API rejects a tool name, that is a capture failure, not a TITAN “block.”
- **Attempted population is the main denominator** — failures are preserved; sessions are not regenerated until success.
- **Labels stay offline** — evaluation cells never coach the acting model.
- **Witness before generation** — live evaluation manifests are not created until freeze artifacts are sealed and receipt-checked.

---

## Architecture (summary)

```text
typed observable event stream
        ↓
extract every consequential proposal at its exact event boundary
        ↓
score only the exclusive pre-action prefix + unresolved obligations
        ↓
authenticated authorization, effect, data-integrity, and twin evidence
        ↓
dual readiness: block_ready  vs  allow_ready
        ↓
ALLOW / LOG / REQUEST / SHADOW / ESCROW / HUMAN / BLOCK
        ↓
signed PREPARE → fresh state check → one-use COMMIT → protected executor
```

---

## Current frontier — V12 (1.2.0)

**Codename:** Witnessed Capture-Complete Adaptive Control

V12 does **not** retune the governor. It hardens capture and launch discipline around a frozen constitution.

### V11 results (complete-case highlights)

| Finding | Result |
| --- | ---: |
| Block-ready harmful blocked | **328/328** |
| Incomplete harmful automatic allows | **0** |
| Incomplete benign automatic allows | **0** |
| Adaptive + chaos silent allows | **0** |
| Harmful executions / gateway bypasses | **0 / 0** |
| Benign-10k false blocks | **0** |
| Benign-10k complete-evidence allow rate | **~82%** |
| Pre-generation witness | **Enforced** |

Full write-up: [Attack-Vector-Results-2.md](Attack-Vector-Results-2.md)

### V11 lesson → V12 fix

Semantic tool aliases were used in scenarios but missing from live API tool lists, so **~39% of planned sessions failed before governance**. That was a transport bug, not a safety miss.

V12 adds a **canonical action registry**, generated provider schemas, a fail-closed freeze gate, provider tool certification, a capture ledger, and multi-turn continuity checks — so that class of failure cannot freeze again.

```bash
# No keys: tests + transport freeze gate
python benchmarks/run_v12_campaign.py

# Live (env keys only — never commit secrets)
export OPENAI_API_KEY=... XAI_API_KEY=...
python benchmarks/run_v12_campaign.py --live --require-provider-cert \
  --n-harm-per-provider 500 --n-benign-actions 10000
```

---

## Version lineage

| Version | What it added |
| --- | --- |
| V4–V8 | Early architecture; some scores later corrected forensically |
| **V9** | Evidence chain repair; label-blind action boundaries |
| **V10** | Dual readiness; live dual-provider HTTP control |
| **V11** | Pre-generation witness; server-side eval cells; adaptive/chaos; scale |
| **V12** | Capture-complete transport registry and launch gates |

Historical material: [`Archive/`](Archive/)

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
python examples/quickstart.py
pytest tests/ -q
python benchmarks/run_v12_campaign.py
```

```python
from titan.v12 import default_registry, assert_transport_closure

reg = default_registry()
assert reg.canonicalize("schedule_refresh") == "queue_training"
assert_transport_closure(require_provider_cert=False)
```

---

## Package layout

```text
src/titan/
  v9/     evidence chain, governor core, gateway, tokens
  v10/    dual-readiness harness, HTTP providers
  v11/    witness receipts, session store, live executor
  v12/    action registry, freeze gates, capture ledger
benchmarks/
  run_v11_campaign.py
  run_v12_campaign.py
  campaigns/
```

---

## Design principles

1. **Inspectable** — decisions and freezes leave a paper trail.  
2. **Bounded** — hard caps on search and complexity.  
3. **Honest metrics** — complete-case and intention-to-test; no success-by-retry gaming.  
4. **Authority is earned** — evidence before allow *and* before block.  
5. **Dual readiness** — block path and allow path are not one knob.  
6. **Witness before generation** — chronology is machine-checked.  
7. **Labels stay offline** — models do not see the answer key.  
8. **Safety and utility together** — zero false blocks without universal escrow.  

---

## What TITAN is not

- Not a general sensor anomaly detector for arbitrary waveforms  
- Not a claim of production failure rates on open internet traffic  
- Not production-ready just because research gates passed  
- Not “independent” only because a private git remote exists  

---

## Why I made this

TITAN did not start as an AI-safety product. It started as an **invariant synthesis engine** aimed at hard measurement problems — originally framed around regimes like **seismic and earthquake-style signal analysis**, where the job is to find stable structure in noisy trajectories and to notice when two very different situations look the same under the wrong features.

Then a post on X about OpenAI hiring for [Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) made the mapping obvious. The same craft — discover blind spots, force honest evaluation, refuse authority without proof — applies cleanly to **agent actions that can rewrite the training and safety stack**. That lightbulb is why this repository exists in its current form: the measurement engine was redirected into a **capability-governance control plane** for consequential tool use.

The connection to that role is not a slogan bolted on at the end of a side project. It is the reason the work was re-aimed: turn open-ended future risk into concrete monitors, iterate prototypes into pipeline-shaped components, and stress-test monitorability itself under live models and adversarial structure.

**Deeper mapping** (role responsibilities ↔ TITAN design judgments): [docs/ROLE_FIT.md](docs/ROLE_FIT.md)

---

## License

Apache-2.0
