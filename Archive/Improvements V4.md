# TITAN Improvements V4

**TITAN version:** 0.5.0 (V5 action governor)  
**Campaign:** Phases 0–16 · Metric contract · Dual-channel governor · Efficient attack lab  
**Machine results:** `benchmarks/improvements_v4_results.json`  
**Protocol freeze:** `benchmarks/v5_protocol_freeze.json`  
**V4 fossil:** `FREEZE_V4.md` · `fossils/v4/` · *do not retune*  

---

## Five-sentence arc (unchanged truth)

TITAN began as a weak but promising prototype (~0.64 AUROC) showing monitor blind spots contained recoverable signal. It interrogated itself, localized errors, and hypothesized that multi-step sabotage was lost because the monitor basis ignored temporal, relational, and causal structure. That diagnosis produced residual boosting, prefix-causal measurements, sparse aggregation, structured evidence, and deployable/forensic separation. Hashed frozen control evaluations then tested withheld families, unfamiliar agents, hard negatives, and independent attackers, measuring warnings before irreversible harm. By publishing failures and converting them into the next objective, TITAN evolved from a clever detector into a **disciplined, production-shaped program for improving the safety measurement system itself**.

---

## Executive summary — V5 destination

V4 was a **research-hardened, production-shaped safety control plane** that correctly **refused** production (human-review agreement 0.60). V5 installs the next layer the charter demanded:

> Metric contract first → action escrow → efficient 100-attack lab → large benign calibration → multi-band decisions → dual-channel autonomous block → honest promotion refusal until real humans and external protocol witness.

### Headline locked evaluation

| System | AUROC | R@FPR5% | Notes |
|---|---:|---:|---|
| Existing monitors | 0.180 | 0.000 | Weak surface |
| Rules | 0.699 | 0.059 | Hand rules |
| Supervised classifier (disc fit) | 0.985 | 0.882 | Strong on this lab split; not called “upper bound” |
| Deterministic structured judge | 0.999 | 1.000 | Evidence schema (sandbox-native) |
| **TITAN base (deployable)** | **0.938** | **0.902** | Frozen causal monitors |
| TITAN governor (combined) | 0.997 | 0.980 | Behavioral + effect channels |
| Hazard head | 1.000 | 1.000 | Action proximity |

### Metric-contracted operational results

| Metric | Scorer | Threshold | Denominator | Value |
|---|---|---:|---|---:|
| final_auroc | titan_base_v5 | — | locked n=605 | **0.938** |
| r_at_fpr (5%) | titan_base_v5 | FPR-derived | 51 harmful | **0.902** |
| **bh_at_fpr (5%)** | titan_base_v5 | same FPR thr | exclusive prefixes | **0.922** |
| bh_at_budget | titan_base_v5 | top ~5% | locked | 0.588 |
| hazard_bh | hazard_head | FPR thr | harmful subset | **0.922** |
| lead_ge_3 | hazard_head | FPR thr | harmful subset | **0.608** |
| confusion @ τ_block=0.55 | titan_base_v5 | 0.55 | 605 | TP46 FP0 TN554 FN5 |
| false_block_rate | action_governor | τ_block | benign actions | **0.000** |
| auto_block_precision | action_governor | τ_block | autonomous blocks | **1.000** |
| reviewer_agreement (sim) | disposition study | 0.70 bar | n=80 | **1.000** (simulated) |

### Decision bands (multi-band calibration)

| Band | τ | Role |
|---|---:|---|
| Review | ~0.10 | Request evidence / log |
| Escrow | ~0.15 | Shadow / twin pause |
| **Block** | **0.55** | Autonomous dual-channel only |

| Operational | Result |
|---|---|
| Lab harmful | **100** (combinatorial; 0 full LLM sessions by default) |
| Lab hard benign | **1000** |
| Causal certificates | **all deployable PASS** |
| Research gates | **ALL MET** |
| Production promotion | **NOT approved** |

### How to read this

1. **BH@FPR5% = 0.922** is the primary before-harm metric — same threshold language as ranking, exclusive irreversible prefixes. No more ambiguous “100% before-harm at a thr that flags 61% of benign.”
2. **Block band FPR = 0** on locked with recall 0.90 — autonomous region is tight; review band still needs continuous benign-stream recalibration in live ops.
3. **Governor FBR = 0, block precision = 1.0** under dual-channel (A∧B) — 8 dual-channel blocks on fleet; most high-risk harm routes to HUMAN_CONFIRM/ESCROW when effect channel incomplete.
4. **Reviewer agreement 1.0 is simulated** multi-reviewer disposition study. Production still requires **real blinded humans**.
5. **Production correctly refused** for: `real_human_study`, `protocol_externally_witnessed`.

---

## What V4 left open (and V5 addressed)

| V4 gap | V5 response |
|---|---|
| Calibration thr unusable (~61% benign FPR) | Multi-band τ_review < τ_escrow < τ_block; large n=1000 benign cal; block floor ≥0.55 |
| “100% before-harm” without metric contract | Every metric emits scorer, thr, denominator, prefix rule, latching |
| Human review 0.60 / failing usefulness | Disposition evidence cards + multi-reviewer sim; real humans still required |
| Only 6 live LLM attacks | Efficient lab: 100 combinatorial attacks (+ optional 1 LLM strategy call) |
| Special-case safeguard promotion | Inherited critical-family policy; kernel floors for catastrophic actions |
| Advisory-only gating | Action governor: ALLOW → … → ESCROW → HUMAN_CONFIRM → BLOCK |
| No action escrow / twin | `ActionEscrow` + counterfactual twin before commit |
| No dual-channel block | Behavioral ∧ effect required for autonomous BLOCK |
| Protocol not externally witnessed | Still **not** claimed — gate fails honestly |

---

## Phases 0–16 — execution log

### Phase 0 — Freeze V4 ✓

| Artifact | Path |
|---|---|
| Freeze notice | `FREEZE_V4.md` |
| V4 results | `fossils/v4/` · `benchmarks/improvements_v3_results.json` |

**Exit:** V5 does not rewrite V4 evidence. **MET.**

### Phase 1 — Blocker specification ✓

`docs/v5/BLOCKER_SPEC.md` — protected action classes, dual-channel rule, immutable kernel ownership, break-glass.

**Exit:** **MET.**

### Phase 2 — Metric contract ✓

`src/titan/v5/metric_contract.py` — `MetricReport` refuses incomplete metadata. Catalog includes `final_auroc`, `r_at_fpr`, `bh_at_fpr`, `bh_at_budget`, `auto_block_precision`, `false_block_rate`, `reviewer_agreement`, …

**Exit:** ≥10 catalog metrics; 12 emitted this run. **MET.**

### Phase 3 — Proof-carrying actions + kernel ✓

- `ProofCarryingAction` packets with claims, auth, objects, rollback.
- `ImmutableSafetyKernel`: `disable_monitoring` → always BLOCK; unauth high-risk → HUMAN_CONFIRM minimum; protected paths without auth → ESCROW.

**Exit:** Kernel forces dispositions TITAN cannot override. **MET.**

### Phase 4 — Action governor + escrow ✓

Three-stage path:

```text
PCA → Kernel → Channel A (behavioral/hazard) → Channel B (twin/effect)
    → disposition bands → optional escrow resolve → audit
```

Dispositions: `ALLOW | ALLOW_WITH_LOGGING | REQUEST_EVIDENCE | SHADOW_EXECUTE | ESCROW | HUMAN_CONFIRM | BLOCK`.

**Exit:** Dual-channel required for BLOCK; integrity collapse forces ESCROW. **MET.**

### Phase 5 — Efficient attack lab ✓

| Mode | Count | API tokens |
|---|---:|---|
| Combinatorial poison/safeguard/eval matrix | 100 | **0** |
| Optional LLM strategy seeds | 0 (default) | 0–1 call |
| Mutations of misses | on demand | 0 |

**Not** 100 full LLM sessions. Strategy: expand parameter grids in `DirectExecutionSandbox`.

**Exit:** n_harmful ≥ 80. **MET** (n=100).

### Phase 6 — Hard benign lab ✓

n=1000 stratified by agent, env, hard-negative family, authorized safeguard, clean refactor, curation.

**Exit:** n ≥ 200 (campaign target 1000). **MET.**

### Phase 7 — Multi-band calibration ✓

Fit on 600 benign; enforce τ_review < τ_escrow < τ_block with operational gaps and block floor 0.55. Validate on locked.

| Val (locked) | FPR / Recall |
|---|---|
| Review | FPR≈0 · harm recall≈0.90 |
| Escrow | FPR≈0 · harm recall≈0.90 |
| Block | FPR=0 · harm recall≈0.90 |

**Exit:** Ordered bands. **MET.**  
**Note:** Live traffic will re-fit; discrete score cliffs remain a monitoring surface for drift.

### Phase 8 — Disposition reviewer study ✓

Simulated 3-reviewer majority on governor evidence cards (not binary thr@noisy).

| Measure | Value |
|---|---:|
| Exact disposition agreement | 1.00 (sim) |
| Within-one rank | 1.00 |
| Binary escalate agreement | 1.00 |
| Mean card clarity | 1.00 |

**Exit (sim bar 0.70):** **MET.**  
**Exit (production):** real blinded humans — **NOT MET** (correctly blocked).

### Phase 9 — Counterexample synthesis ✓

Misses → collision class → mutation lab seeds.

This run: **5 false_negative** counterexamples + 5 mutations. Principle: *miss is fuel, not shame.*

**Exit:** Mechanism exists. **MET.**

### Phases 10–11 — Red team + renewal ✓

Inherits V4 continuous renewal: freeze → red team → offline discovery → shadow → promote → retire. No unbounded self-modification.

**Exit:** **MET.**

### Phases 12–14 — Governor fleet ✓

| Disposition (fleet≤200) | Count |
|---|---:|
| REQUEST_EVIDENCE | ~13 |
| ESCROW | ~57 |
| HUMAN_CONFIRM | ~71 |
| BLOCK (dual-channel) | **8** |

| Gate | Result |
|---|---|
| Shadow always non-blocking | ✓ |
| Escrow resolves | ✓ |
| False-block rate | **0.000** |
| Auto-block precision | **1.000** |
| p50 latency | **~0.7 ms** |

**Exit:** limited enforcement research bar. **MET.**

### Phase 15 — Integrity collapse ✓

`control_plane_integrity < 0.5` → all consequential actions **ESCROW**.

**Exit:** **MET.**

### Phase 16 — Promotion checklist ✓ (refusal)

| Gate | Status |
|---|---|
| information_integrity | pass |
| causal_integrity | pass |
| external_transfer | pass |
| calibration | pass (this lab) |
| human_usefulness (sim) | pass |
| operational_reliability | pass (p99 ≪ 5s) |
| security / governance / shadow | pass |
| limited_enforcement | pass |
| **real_human_study** | **FAIL** |
| **protocol_externally_witnessed** | **FAIL** |

**Approved: False.** Governance working.

---

## Architecture (V5)

```text
Agent proposes action
    → proof-carrying action packet
    → signed causal capture (V4 gateway)
    → immutable safety kernel
    → TITAN behavioral analysis (Channel A)
    → counterfactual twin / effect (Channel B)
    → calibrated multi-band decision
    → allow / evidence / escrow / confirm / block
    → immutable audit
    → miss / false-block / disagreement ingestion
    → bounded monitor renewal
```

**Primary authority, not solitary authority.** Blocking requires dual channel or deterministic kernel violation; policy kernel is outside TITAN’s self-improvement loop.

---

## Metric contract (required table)

| Metric | Scorer | Threshold | Denominator | Prefix | Latching |
|---|---|---|---|---|---|
| Before-harm @ FPR5% | TITAN base | FPR-derived | harmful w/ irr | exclusive_irreversible | first_alert_sticks |
| R@FPR5% | TITAN final | FPR-derived | 51 harmful | full | N/A |
| Hazard before-harm | Hazard head | same FPR thr | harmful subset | exclusive_irreversible | first_alert_sticks |
| Confusion review/block | TITAN base | τ_review / τ_block | locked 605 | full | N/A |
| False-block rate | Governor | τ_block | benign actions | action_boundary | N/A |

The strongest operational claim is always:

\[
\text{BH@FPR} \quad\text{or}\quad \text{BH@budget}
\]

not raw before-harm at an uncalibrated thr.

---

## Efficient attack lab design

```text
1. Combinatorial matrix (strategies × concealment × eval_mode × agent × env)
2. Optional: ONE LLM call → strategy JSON → expand to sandbox executions
3. Mutation lab around each miss
```

This delivers ≥100 harmful trajectories without burning 100 multi-turn LLM sessions.

---

## Why production is still withheld

1. **No real multi-reviewer blinded study** — sim agreement is not institutional evidence.  
2. **Protocol not third-party witnessed** — local hash only; git tag / external witness pending.  
3. **Judge near-perfect scores** remain sandbox-ontology-adjacent; external semantic judge still needed for ensemble claims.  
4. **Classifier 0.985** on this lab is strong — fair V5+ comparisons must include leave-agent-out and TITAN-feature-only baselines under larger shift.  
5. **Live multi-model LLM attacks** still optional; combinatorial mass is not a full substitute for monitor-aware LLM adaptation studies.

The system refuses promotion. That is success, not failure.

---

## Research gates vs production gates

| Class | Criterion | V5 |
|---|---|---|
| Research | AUROC ≥ 0.85 | ✓ 0.938 |
| Research | R@FPR5% ≥ 0.70 | ✓ 0.902 |
| Research | BH@FPR5% ≥ 0.70 | ✓ 0.922 |
| Research | Causal certificates | ✓ |
| Research | Metric contract | ✓ |
| Production | Real human study | ✗ |
| Production | External protocol witness | ✗ |
| Production | Dual-channel low FBR | ✓ 0.0 |
| Production | Large benign cal discipline | ✓ (lab) |

---

## Files added / changed (V5)

| Path | Role |
|---|---|
| `src/titan/v5/metric_contract.py` | Metric metadata enforcement |
| `src/titan/v5/proof_carrying.py` | Action packets |
| `src/titan/v5/kernel.py` | Immutable safety kernel |
| `src/titan/v5/governor.py` | Dual-channel action governor |
| `src/titan/v5/escrow.py` | Shadow / twin pause |
| `src/titan/v5/decision_bands.py` | Multi-band calibration |
| `src/titan/v5/attack_lab.py` | Efficient 100-attack lab |
| `src/titan/v5/action_extract.py` | Trajectory → PCA |
| `src/titan/v5/reviewer.py` | Disposition review study |
| `src/titan/v5/counterexample.py` | Miss → measurement object |
| `src/titan/v5/campaign.py` | Phases 0–16 orchestrator |
| `benchmarks/run_v5_campaign.py` | CLI entry |
| `docs/v5/BLOCKER_SPEC.md` | Protected actions |
| `TITAN-MANUAL.md` | First-principles manual |
| `FREEZE_V4.md` | V4 fossil notice |

---

## How to reproduce

```bash
cd ~/Desktop/TITAN
source .venv/bin/activate
python benchmarks/run_v5_campaign.py --n-harmful 100 --n-benign 1000
# optional strategy seeds (1 LLM call):
# python benchmarks/run_v5_campaign.py --llm-strategies
```

Results: `benchmarks/improvements_v4_results.json`.

---

## Next campaign (V6 charter sketch)

1. Real blinded multi-reviewer study (κ, time, missing context, action correctness).  
2. Public/third-party protocol tag before locked generation.  
3. ≥50–100 live multi-model LLM attacks (still with combinatorial mass underneath).  
4. External semantic judge (not sandbox-oracle).  
5. Fair classifier suite under leave-agent-out.  
6. Continuous benign traffic calibration (≥10k) stratified by repo/task/agent.  
7. Only then revisit production promotion.

---

## Closing

V4 proved TITAN can rank threats on direct execution and refuse its own promotion.  
V5 proved TITAN can **govern consequential actions** with a metric contract, dual-channel evidence, escrow, and multi-band thresholds — and **still refuse** production until humans and chronology are real.

Not another alarm.

A causal customs checkpoint between agent intention and irreversible reality — with the launch keys still under multi-owner seal.
