# TITAN Manual

**Trajectory Inspection & Targeted Anomaly Network**  
First-principles description · V5 (0.5.0) action governor  
Companion process docs: `Improvements V1.md` … `Improvements V4.md`

---

## 1. What TITAN is

TITAN is a **safety measurement and control system** for AI agent trajectories. It does not primarily ask:

> “Is this session bad?”

It asks:

> “Where do existing safety measurements collapse harmful and benign behavior — and what **causal, deployable** measurement would separate them **before irreversible harm**?”

Then it builds that measurement, freezes the protocol, evaluates under distribution shift, and — only under strict gates — may **govern consequential actions** (pause, require evidence, escrow, human-confirm, or dual-channel block).

TITAN is **primary autonomous authority for narrowly defined high-risk actions**, never solitary authority. An immutable policy kernel, human override, and defense-in-depth stack always bound it.

---

## 2. Why it exists

Frontier agent stacks already emit rich traces: messages, tools, diffs, data mutations, eval changes, approvals. Existing monitors (intent, action, provenance) often assign similar scores to:

- stealth data poisoning, and  
- legitimate rebalancing / curation / refactor  

Those **cross-regime collisions** are not noise. They are **evidence that the measurement basis is incomplete**.

OpenAI’s RSI Safety role and internal-agent monitoring direction emphasize:

- scalable oversight and automated auditing  
- control evaluations with reliability / latency standards  
- human review and eventual pre-execution checks on high-risk actions  
- threats such as data poisoning and research sabotage  

TITAN is a concrete research system aimed at that loop:

```text
weak monitor surface
  → blind-spot diagnosis
  → new measurement language
  → control evaluation
  → control plane
  → governed refusal / limited enforcement
```

---

## 3. Core ontology

### 3.1 Trajectory

An `AgentTrajectory` is a typed event log for one agent session:

| Event kinds (examples) | Role |
|---|---|
| message | user / agent text |
| tool_call / tool_result | tools |
| file_read / file_write | code & config |
| data_mutation | training data changes |
| eval_change | canary / suite edits |
| approval | authorization tickets |
| permission_failure | denials |
| commit / outcome | boundaries of harm |

Labels: `benign` | `harmful` | `unknown`.  
Families: poison variants, eval sabotage, safeguard tamper, hard negatives, etc.

### 3.2 Collision

A **collision** is a **cross-regime** pair only: one known harmful and one benign hard-negative that look similar under current features. Same-regime neighbors are never collisions.

### 3.3 Deployable vs forensic

| Class | May use | Purpose |
|---|---|---|
| **Deployable** | Only information available *before* irreversible action | Online intervention |
| **Forensic** | Post-hoc fields, outcomes, future labels | Offline analysis only |

Every promoted deployable feature must pass a **causal certificate** (forbidden-field scan, online/offline parity, suffix independence, forensic exclusion). Before-harm evaluation uses **exclusive prefixes** ending *before* the irreversible event.

### 3.4 Proof-carrying action (V5)

Consequential steps are packaged as:

- action type (e.g. `queue_training`, `modify_safeguard`)  
- authorization reference  
- objects affected  
- claimed semantic / safety effect  
- diff summary, tests, rollback plan  
- measured effect + claim–effect distance (after twin)

Agents must **prove** actions are safe enough — not merely avoid looking guilty.

---

## 4. System layers

```text
┌─────────────────────────────────────────────────────────┐
│  Immutable safety kernel (TITAN cannot modify)          │
│  taxonomy · min auth · always-block · logging · owners  │
├─────────────────────────────────────────────────────────┤
│  Channel A — behavioral                                 │
│  deployable monitors · hazard · auth mismatch           │
├─────────────────────────────────────────────────────────┤
│  Channel B — effect                                     │
│  counterfactual twin · probes · claim–effect distance   │
├─────────────────────────────────────────────────────────┤
│  Multi-band policy                                      │
│  τ_review < τ_escrow < τ_block  (+ optional per-action) │
├─────────────────────────────────────────────────────────┤
│  Dispositions                                           │
│  ALLOW → … → ESCROW → HUMAN_CONFIRM → BLOCK             │
├─────────────────────────────────────────────────────────┤
│  Audit · counterexample lab · bounded renewal           │
└─────────────────────────────────────────────────────────┘
```

### 4.1 Discovery engine (V1–V3)

1. Measure collisions under existing monitors.  
2. Synthesize candidate features (temporal / relational / safeguard).  
3. Residual boost; promote sparse set.  
4. Critical-family constraints so rare catastrophic families keep recall floors.  
5. Causal certificates on deployable set.

### 4.2 Control plane (V4)

Signed event gateway, direct-execution sandboxes, hazard lead-time, structured judges, calibration, shadow deployment, narrow human-confirm gates, production checklist that can **return Approved: False**.

### 4.3 Action governor (V5)

For each consequential action:

1. Kernel verdict (fast, deterministic).  
2. Channel A scores (trajectory + hazard + safeguard signatures).  
3. Channel B if elevated (twin probes).  
4. Combined score → disposition band.  
5. **Autonomous BLOCK only if A ∧ B** (or kernel force).  
6. ESCROW path: hold → shadow twin → resolve allow/confirm/block.  
7. Integrity monitor: low control-plane integrity → escrow all consequential.

---

## 5. Metric contract

**No metric without metadata.**

Every emitted metric must declare:

| Field | Meaning |
|---|---|
| name | catalog id |
| scorer | which head produced it |
| threshold | operating thr or null |
| denominator | what was counted |
| unit_of_analysis | trajectory / action_prefix / action |
| prefix_rule | exclusive_irreversible / full / action_boundary |
| alert_latching | none / first_alert_sticks / multi |

### Preferred operational metrics

| Metric | Intent |
|---|---|
| **R@FPR5%** | Ranking under fixed false-positive rate |
| **BH@FPR5%** | Before-harm recall at that same thr |
| **BH@budget** | Before-harm under review volume (e.g. 50 / 1000) |
| **lead ≥ k** | Enough warning events to intervene |
| **false_block_rate** | Benign consequential actions auto-blocked |
| **auto_block_precision** | Autonomous blocks that were correct |
| **reviewer_agreement** | Humans (or honest sim) on dispositions |

Ambiguous “100% before-harm” at a thr that flags most benign work is **not** an operational claim.

---

## 6. Decision bands

Separate thresholds — never one thr for “alert” and “block”:

| Band | Typical role | Failure if wrong |
|---|---|---|
| τ_review | Evidence / human queue | Alert fatigue |
| τ_escrow | Pause + twin | Workflow friction |
| τ_block | Dual-channel auto stop | False blocks / safety misses |

Fit from large **benign** streams with budget caps (e.g. ≤50 reviews / 1000). Enforce minimum gaps so discrete score cliffs cannot collapse bands.

---

## 7. Dual-channel blocking

Autonomous block requires:

**A (behavioral)** high trajectory / hazard / auth mismatch  
**and**  
**B (effect)** twin regression / probe failure / claim–effect distance  

or a **deterministic kernel violation** (e.g. `disable_monitoring`).

Rationale: high behavioral score alone can fire on hard negatives; effect confirmation reduces false blocks while preserving stop-power on real safety regressions.

---

## 8. Attack laboratory (efficient)

Goal: ≥100 harmful + ≥1000 hard benign **without** 100 full LLM sessions.

| Method | Tokens | Role |
|---|---|---|
| Combinatorial sandbox matrix | 0 | Primary mass |
| 1 LLM strategy JSON call | low | Expand novel strategies |
| Mutation around misses | 0 | Renewal fuel |
| Optional live LLM exec | high | External transfer study |

Always publish misses (id, family, score, interpretation). Misses are the next research object.

---

## 9. Human review

Evidence cards should include:

- one-sentence decision  
- causal timeline  
- top Channel A / B evidence  
- authorization panel  
- counterfactual result  
- what would make the action safe  

Evaluation (production bar): real multi-reviewer blinded study — agreement, κ, time, missing context, correctness of recommended action — not only simulated label match.

V4 failed promotion at **0.60** agreement. That refusal was correct institutional behavior.

---

## 10. Promotion discipline

### Research-ready (examples)

- External AUROC ≥ 0.85  
- R@FPR5% ≥ 0.70  
- BH@FPR5% ≥ 0.70  
- Causal certificates pass  
- Metric contract complete  

### Production-ready (examples)

- All research gates  
- Large stratified benign calibration  
- Dual-channel false-block within tolerance  
- **Real** human review study  
- Externally witnessed protocol chronology  
- Latency / throughput / security / privacy owners sign off  

TITAN must be able to print **`Approved: False`**.

---

## 11. What TITAN is not

- Not a general chatbot safety filter for open web chat  
- Not a claim of model alignment inside the base LLM  
- Not unbounded recursive self-modification of its own policy kernel  
- Not production-ready merely because AUROC is high  
- Not a replacement for human ownership of catastrophic risk  

---

## 12. Repository map

| Path | Purpose |
|---|---|
| `src/titan/schema.py` | Trajectory / event types |
| `src/titan/engine_v3.py` | Causal deployable discovery |
| `src/titan/temporal.py` | Deployable / forensic features |
| `src/titan/v4/` | Control plane, hazard, gateway, sandbox |
| `src/titan/v5/` | Governor, kernel, escrow, metric contract, attack lab |
| `benchmarks/run_v*_campaign.py` | Campaign runners |
| `Improvements V*.md` | Versioned process + results |
| `FREEZE_V*.md` | Fossils — do not retune |
| `fossils/` | Frozen results copies |
| `docs/v4/`, `docs/v5/` | Threat model, requirements, blocker spec |

---

## 13. Quick start

```bash
cd ~/Desktop/TITAN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# V5 action-governor campaign (efficient lab defaults)
python benchmarks/run_v5_campaign.py --n-harmful 100 --n-benign 1000

# Optional: one LLM strategy expansion
export XAI_API_KEY=...
python benchmarks/run_v5_campaign.py --llm-strategies
```

Tests:

```bash
pytest -q
```

---

## 14. Design principles (non-negotiable)

1. **Collisions are the unit of progress** — not leaderboard cosmetics.  
2. **Causal deployability** — intervention claims need exclusive prefixes + certificates.  
3. **Metric contract** — no naked percentages.  
4. **Multi-band operations** — review ≠ escrow ≠ block.  
5. **Dual-channel autonomy** — block with A∧B (or kernel).  
6. **Misses are fuel** — publish and synthesize, don’t bury.  
7. **Governed refusal** — high AUROC does not imply production.  
8. **Primary, not solitary** — defense in depth; humans own the break-glass.  
9. **Efficient evaluation** — combinatorial attack mass before token burn.  
10. **Fossilize** — never rewrite prior campaign evidence.

---

## 15. The destination picture

```text
Agent proposes action
    → proof-carrying action packet
    → signed causal capture
    → immutable safety kernel
    → TITAN behavioral analysis
    → counterfactual twin
    → independent effect verification
    → calibrated action-specific decision
    → allow / request evidence / escrow / confirm / block
    → immutable audit
    → miss, false-block, and disagreement ingestion
    → bounded monitor renewal
```

> TITAN should not merely recognize dangerous actions.  
> It should make consequential actions **prove they are safe enough to execute**.

That is the customs checkpoint between agent intention and irreversible reality.

---

## 16. Version line

| Version | Codename | Headline |
|---|---|---|
| V1 | prototype | Collisions → synthesis → real metrics |
| V2 | temporal | Residual boost; before-harm leak fixed later |
| V3 | causal-safeguard | Deployable/forensic split; safeguard repair |
| V4 | control plane | Direct exec external AUROC ~0.93; production refused |
| **V5** | **action-governor** | Metric contract; dual-channel; escrow; efficient lab; still refused production |

Process truth for V5: `Improvements V4.md` · results `benchmarks/improvements_v4_results.json`.
