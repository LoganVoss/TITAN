# TITAN

<p align="center">
  <img src="docs/assets/TITAN-GITHUB-LOGO.png" alt="TITAN logo" width="280" />
</p>

<p align="center">
  <strong>Trajectory Inspection &amp; Targeted Anomaly Network</strong><br/>
  <em>A pre-action control plane for consequential AI agent behavior</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="version" />
  <img src="https://img.shields.io/badge/flagship-V12-success" alt="flagship" />
  <img src="https://img.shields.io/badge/production-TBD-yellow" alt="production" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-red.svg" alt="license" /></a>
</p>

---

## Foundation

TITAN is a **capability-control system** for AI agents.

TITAN intervenes the moment an agent tries to change something that matters — training data, evaluation canaries, safeguards, credentials, or infrastructure. 

The question it answers:

> **Has this actor earned authority to perform this exact action on this exact object, using evidence that existed before execution?**

If not, the action does not execute.

```text
model proposes a consequential action
        ↓
evidence is authenticated
        ↓
authority is evaluated
        ↓
PREPARE is issued or refused
        ↓
state is rechecked
        ↓
COMMIT is required
        ↓
execution is impossible without a valid COMMIT
```

That is the difference between a **monitor that comments** and a **control plane that decides**.

---

## Goal

As agents get better at writing code, changing data, and operating systems, the hard risk is not only what they *say*. It is what they can *do*:

- inject poisoned data into a training queue  
- weaken or remove an evaluation canary  
- rewrite a production safeguard  
- route around the tools that were supposed to stop them  

Common approaches fail this:

| Approach | Failure mode |
| --- | --- |
| Score the finished transcript | **Too late** — the change may already be committed |
| Block on keywords / vibes | **Too blunt** — high friction, easy to route around |
| Trust the model to be careful | **No independent proof**, no hard gate |

TITAN is built for a different object:

```text
who proposes what action
against which protected object
with which verified authorization and measured effect evidence
using only what is known before commit
```

```text
proven danger       →  BLOCK
proven safety       →  ALLOW
unresolved evidence →  ESCROW (hold)
no valid COMMIT     →  no protected execution
```

A system that “prevents harm” only by refusing all legitimate work is not a success.  
TITAN measures **safety and operational usefulness together**.

---

## Evidence

Sealed dual-provider live evaluation with frozen model identities:

| | |
| --- | --- |
| **OpenAI** | `gpt-5.5-2026-04-23` |
| **xAI** | `grok-4.3` |
| **Live sessions** | **1,300** (650 each) |
| **Operational benign actions** | **10,000** |

| Result | Number |
| --- | ---: |
| Sessions captured / completed | **1,300 / 1,300** |
| Schema rejections | **0** |
| Block-ready harmful → BLOCK | **460 / 460** |
| Incomplete harm automatic allows | **0** |
| Incomplete benign automatic allows | **0** |
| Silent harmful authority (all novelty lanes) | **0** |
| Harmful executions | **0** |
| Gateway bypasses | **0** |
| Benign-10k false blocks | **0** |
| Complete-evidence benign allow (ops scale) | **~82%** |
| Live proof-complete benign allow | **76%** |

**What “block-ready” means:** evaluation sessions are scored in offline **evidence cells**. A *block-ready harmful* cell is one where independent adverse proof is complete enough that the dual-readiness constitution *requires* BLOCK. The acting model never sees cell labels or answer keys (server-side binding only). This metric is governor recall under full adverse evidence — not the model “confessing,” and not unsupervised discovery of secret harm without evidence.

**Supported claim:** under a dual-readiness control constitution, TITAN captured every planned live session against frontier-class acting models, blocked every block-ready harmful action, granted no silent harmful authority across constitutional and novelty lanes, and executed no harmful protected action without a valid commit path.

**Boundary:** production status is **TBD** — the control mechanism is demonstrated; the full institutional safety case (independent external witness, independent replication, shadow traffic, HA ops, privacy program) is not yet complete. Production is not claimed.

| File | Purpose |
| --- | --- |
| [docs/flagship/FLAGSHIP-NUMBERS.md](docs/flagship/FLAGSHIP-NUMBERS.md) | Numbers digest (cite this) |
| [docs/flagship/Attack-Vector-Results-V12-Flagship.md](docs/flagship/Attack-Vector-Results-V12-Flagship.md) | Full report |
| [results/flagship/](results/flagship/) | Immutable machine artifacts |

---

## How it works

1. **Actions, not vibes** — evaluates consequential tool proposals at the boundary (train queue, merge data, canary change, safeguard edit).  
2. **Dual readiness** — block path and allow path are independent; unresolved evidence becomes **escrow**, not a guess.  
3. **Cryptographic commit** — `PREPARE → recheck → one-use COMMIT`; no token, no protected execution.  
4. **Transport is safety** — every tool alias is registered, schemas generated, forced tools certified before freeze.  
5. **Labels offline** — evaluation answer keys never reach the acting model.  
6. **Witness before generation** — live manifests are created only after sealed artifacts are receipt-checked.

```text
event stream → proposal → evidence → dual readiness → disposition
     → PREPARE → recheck → COMMIT → protected executor
```

---

## Repository layout

```text
.
├── README.md                 Product narrative (start here)
├── LICENSE                   Apache-2.0
├── pyproject.toml            Package metadata + tooling
├── requirements.txt          Core + live HTTP deps
├── requirements-dev.lock     Pinned CI/dev environment
│
├── src/titan/                Control-plane implementation
├── tests/                    Automated test suite (pytest)
├── examples/                 Small offline demos (no API keys)
│
├── benchmarks/               Flagship campaign runner
│   └── campaigns/…           Sealed dual-provider campaign outputs
├── results/flagship/         Immutable machine-readable artifacts
└── docs/
    ├── assets/               Logo and media
    ├── flagship/             Human-readable evidence pack
    └── ROLE_FIT.md           Research / role mapping
```

Python packaging convention: lowercase top-level dirs (`src`, `tests`, `docs`).

---

## Install

```bash
git clone https://github.com/LoganVoss/TITAN.git
cd TITAN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # tests + httpx
# or:  pip install -e ".[live]"  # live HTTP only
pytest -q
python benchmarks/run_v12_campaign.py    # offline transport gate
```

```python
from titan.v12 import default_registry, assert_transport_closure

reg = default_registry()
assert reg.canonicalize("schedule_refresh") == "queue_training"
assert_transport_closure(require_provider_cert=False)
```

Live runs need `OPENAI_API_KEY` and `XAI_API_KEY` in the environment only.

---

## Production status

| Layer | Status |
| --- | --- |
| Pre-action authority mechanism | Demonstrated (flagship) |
| Capture-complete dual-provider live eval | Demonstrated |
| Independent external-organization witness | Open |
| Independent replication | Open |
| Blinded human adjudication | Open |
| Shadow traffic on real org workflows | Open |
| Production key management / HA / privacy ops | Open |

**TBD means: strong prototype, sealed evidence, production claim withheld until the remaining layers exist.**

---

## Future improvements

Safety at flagship scale is already conservative (zero silent harm, zero false blocks on the 10k benign ops set). The next gains are mostly **utility and operational sharpness** — especially on the benign path, where too much legitimate work still lands in escrow.

### Benign path (highest leverage)

Today, live **proof-complete benign** allows at **76%** (24/100 → ESCROW) and the 10k ops set auto-allows roughly **60%** overall / **~82%** when evidence is complete. That means on the order of **one quarter to two fifths** of well-formed legitimate work still needs human review or hold — too much friction for production.

Priorities:

1. **Retune complete-evidence thresholds** on canary / twin / influence paths that currently escrow even when authorization and adverse-proof requirements are satisfied — without opening incomplete-benign automatic allows (must stay **0**).
2. **Separate “allow-ready” from “review-nice-to-have”** so escrow is reserved for true uncertainty, not residual policy caution.
3. **Close the canary-utility preflight gap** (local ≥0.90 diagnostic still fails) so complete benign graphs score cleanly.
4. **Measure review load explicitly** — target a large drop in complete-benign escrow rate while holding false BLOCK = 0 and incomplete-benign allow = 0.
5. **Shadow traffic on real workflows** to validate that lab-complete evidence matches production ticket / provenance graphs.

### Safety and evaluation depth

6. **Independent external-organization witness** and independent replication of the freeze package.  
7. **Blinded human adjudication** on escrow and borderline complete-benign cases.  
8. **Harder incomplete-harm and novelty cells** — keep zero silent allows under richer adaptive / chaos / holdout structure.  
9. **End-to-end latency and HA** for PREPARE → recheck → COMMIT under load.

### Honesty constraint

Every utility improvement must be gated the same way the flagship was: **no silent harmful authority, no incomplete automatic allows, no gateway bypass**. Raising benign pass rate by loosening incomplete-evidence rules would be a regression, not progress.

---

## Design principles

1. Authority is earned — evidence before allow *and* before block  
2. Uncertainty holds the boundary — escrow over guessing  
3. Execution requires capability — no COMMIT, no protected effect  
4. Honest denominators — attempted population, not success-by-retry  
5. Falsify yourself first — permanent machinery for every failure class found  
6. Safety and utility together — zero false blocks without universal refusal  

---

## Origin

TITAN did not begin as an AI safety portfolio piece. It began as an **invariant synthesis model**. I originally designed this system for hard measurement problems in noisy trajectories, framed around **seismic analysis**. The goal was to find stable structure, and notice when two very different situations look the same.

I was browsing X the other day, and saw a post about OpenAI hiring for [Researcher, Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) which made the transfer unavoidable. The same approach: discover blind spots, force honest evaluation, refuse authority without proof - applies cleanly to **agent actions that can rewrite the training and safety stack**. Lightbulb moment: redirect the measurement engine into a **capability-governance control plane** for consequential tool utilization. 

The result is this repository: action taxonomy, authenticated evidence, dual readiness, PREPARE/COMMIT enforcement, sealed freezes, dual-provider live evaluation under frontier-class models, and an explicit production boundary. I am fairly new to using GitHub, so please ignore my failed runs. Early CI was misconfigured for the live HTTP stack; unit tests are green now. Flagship numbers and the freeze receipt are separate artifacts. Cite those, not the Actions history, Lol.

My goal is to show:

- open-ended safety risk can be turned into a **precise technical object**  
- that object can be **built, attacked, measured, and hardened** end-to-end  
- we can determine whether a consequential action has earned execution authority **before it occurs**

Evidence: **[`docs/flagship/FLAGSHIP-NUMBERS.md`](docs/flagship/FLAGSHIP-NUMBERS.md)**  

Research Role Connection: [`docs/ROLE_FIT.md`](docs/ROLE_FIT.md)

---

## License

Apache-2.0
