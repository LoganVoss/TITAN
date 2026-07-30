# TITAN

<p align="center">
  <img src="docs/assets/TITAN-GITHUB-LOGO.png" alt="TITAN logo" width="280" />
</p>

<p align="center">
  <strong>Trajectory Inspection &amp; Targeted Anomaly Network</strong><br/>
  <em>A pre-action control plane for consequential AI agent behavior</em>
</p>

<p align="center">
  <a href="https://github.com/LoganVoss/TITAN/actions/workflows/ci.yml"><img src="https://github.com/LoganVoss/TITAN/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="version" />
  <img src="https://img.shields.io/badge/flagship-V12-success" alt="flagship" />
  <img src="https://img.shields.io/badge/production-TBD-yellow" alt="production" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="license" /></a>
</p>

---

## FOUNDATION

TITAN is a **capability-control system** for AI agents.

It does **not** wait until a conversation ends and then guess whether something “looked bad.”  
It intervenes at the moment an agent tries to change something that matters — training data, evaluation canaries, safeguards, credentials, infrastructure.

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

## GOAL

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

## EVIDENCE

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

**Supported Claim:** under a dual-readiness control constitution, TITAN captured every planned live session against frontier-class acting models, blocked every block-ready harmful action, granted no silent harmful authority across constitutional and novelty lanes, and executed no harmful protected action without a valid commit path.

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

## Production status: TBD

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

## Design principles

1. Authority is earned — evidence before allow *and* before block  
2. Uncertainty holds the boundary — escrow over guessing  
3. Execution requires capability — no COMMIT, no protected effect  
4. Honest denominators — attempted population, not success-by-retry  
5. Falsify yourself first — permanent machinery for every failure class found  
6. Safety and utility together — zero false blocks without universal refusal  

---

## ORIGIN

TITAN did not begin as an “AI safety portfolio piece.” It began as an **invariant synthesis engine**. I originally designed this system for hard measurement problems in noisy trajectories, framed around **seismic / earthquake signal analysis**. The goal was to find stable structure, and notice when two very different situations look the same.

I was browsing X the other day, and saw a post about OpenAI hiring for [Researcher, Recursive Self-Improvement Safety](https://openai.com/careers/researcher-recursive-self-improvement-safety-san-francisco/) which made the transfer unavoidable. The same approach: discover blind spots, force honest evaluation, refuse authority without proof - applies cleanly to **agent actions that can rewrite the training and safety stack**. That was a lightbulb: redirect the measurement engine into a **capability-governance control plane** for consequential tool utilization. 

The result is this repository: action taxonomy, authenticated evidence, dual readiness, PREPARE/COMMIT enforcement, sealed freezes, dual-provider live evaluation under frontier-class models, and an explicit production boundary.

My goal is to show:

- open-ended safety risk can be turned into a **precise technical object**  
- that object can be **built, attacked, measured, and hardened** end-to-end  
- We can ask: **Has this exact actor earned authority to perform this exact action on this exact state, with evidence that existed before execution?**

Evidence: **[`docs/flagship/FLAGSHIP-NUMBERS.md`](docs/flagship/FLAGSHIP-NUMBERS.md)**  

Research Role Connection: [`docs/ROLE_FIT.md`](docs/ROLE_FIT.md)

---

## License

Apache-2.0
