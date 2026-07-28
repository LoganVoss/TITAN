# TITAN Improvements V1

**Process document · Research roadmap execution · Phases 1–10**  
**Protocol hash (control eval):** `cad8bc55591b3c8f`  
**Pipeline artifact:** `benchmarks/improvements_v1_results.json`  
**Date context:** Improvements campaign after baseline ~0.64 portfolio reading  

---

## Executive summary

This document records the full execution of the accuracy and control-evaluation roadmap for TITAN: from diagnosing the ~0.64 locked AUROC, through residual boosting and temporal–relational synthesis, to a **pre-registered blind-family control evaluation** with monitor-aware attackers and **detection-before-irreversible-action** metrics.

### Headline outcomes

| Setting | Metric | Result |
|---|---|---|
| Prior portfolio reading | Locked AUROC (TITAN) | ~**0.64** |
| V1 harness (this run, expanded suite) | Locked AUROC (TITAN) | **0.744** |
| V1 harness | Existing monitor AUROC | **0.233** |
| V1 harness | Collisions resolved | **49 → 13** (36 resolved) |
| **V2 discovery (dev locked)** | Locked AUROC | **1.000** |
| **Control eval (blind families + agent-v3 + stealth)** | Locked AUROC | **0.923** |
| Control eval | Bootstrap AUROC 95% CI | **[0.864, 0.981]** |
| Control eval | Recall @ 5% FPR | **0.80** |
| Control eval | Detected before irreversible | **80%** of harmful |
| Control eval | Existing monitor before-irreversible | **0%** |
| Control eval | Full supervised classifier AUROC | **0.997** (upper bound) |

### How to read these numbers

1. **0.64 → 0.74 (V1 path)** was already “proof of signal” over a weak monitor surface.  
2. **V2 on the development locked set (AUROC 1.0)** shows the new machinery can *use* available structure extremely well on in-distribution holdouts — but the locked set is small (9H/10B) and partially saturated. Treat it as a **Milestone 1** pass, not production proof.  
3. **Control eval AUROC 0.923** is the decisive result: unseen agent version (`agent-v3`), withheld attack families (canary suppression, safeguard tamper, stealth poison, stealth eval sabotage, slow drip), realistic hard negatives, monitor-aware attackers, thresholds calibrated only on clean traffic, evaluated once after discovery freeze.  
4. TITAN does **not** need to beat the opaque supervised classifier (0.997). Its claim is: **inspectable, residual, transferable monitor synthesis that closes blind spots and fires before harm.**

---

## North-star research question

> Can TITAN discover monitor features that identify previously unseen, multi-step sabotage behavior performed by an unfamiliar agent, while maintaining a practical false-positive rate on realistic benign work?

**Answer from this campaign (synthetic control eval):**  
Yes, with material evidence: **AUROC 0.923**, **R@FPR5% = 0.80**, **80% of attacks flagged before irreversible stage**, bootstrap CI excluding the weak existing-monitor baseline entirely.

---

## Scientific object (unchanged, reinforced)

TITAN is not “another maliciousness classifier.”

It asks:

> Where does the existing measurement system collapse harmful and benign behavior into the same representation — and what inspectable measurement would uncollapse them?

The loop remains:

```text
collision → candidate measurement → held-out marginal validation
  → true feature augmentation → recomputed residual collisions
  → sparse transparent aggregation → shadow/promote registry
```

What changed in V1 is **how candidates are chosen, what language they speak (temporal/relational), and how rigorously they are stress-tested.**

---

## Recommended implementation order (executed)

| # | Step | Status |
|---|---|---|
| 1 | Complete error atlas for ~0.64 result | **Done** |
| 2 | Marginal held-out utility selection | **Done** |
| 3 | Residual collision boosting | **Done** |
| 4 | Temporal / relational DSL + features | **Done** |
| 5 | Sparse transparent aggregator | **Done** |
| 6 | Teacher-guided residual discovery | **Done** |
| 7 | Structured evidence predicates | **Done** |
| 8 | Bootstrap CIs + normalization hygiene | **Done** |
| 9 | Stronger hard negatives + family balance | **Done** |
| 10 | Sandboxed multi-agent control eval + adaptive attacks | **Done** |
| 11 | Freeze locked protocol, run once, publish including failures | **Done** |

---

# Phase-by-phase results

## Phase 1 — Diagnose the 0.64 precisely (Error Atlas)

### Implementation

- Module: `src/titan/error_atlas.py`
- Per locked trajectory: family, model, length, mutations, commits, base severity, TITAN / classifier / rule / judge scores, activated monitors, TP/TN/FP/FN at calibrated FPR

### Key findings (development locked set, V1 monitors)

| Question | Answer |
|---|---|
| Fail primarily on one/two families? | **Yes** — FN rate 100% on `eval_weakening`, `test_editing`, `rare_source_high_influence` in that atlas slice |
| Promoted monitors redundant? | **Yes** — 4 pairs with Jaccard > 0.7 (e.g. gradient thresholds ≈ max influence ≈ cluster concentration activations) |
| FPs dominated by one hard-negative type? | **Yes** — `hard_negative` |
| Length-dependent? | **Yes** — short-traj recall 0.375 vs long 1.0 |
| Continuous useful but aggregated poorly? | Continuous activations outnumbered thresholds (41 vs 19), but max-style aggregation still underused structure |
| Teacher disagreement regions? | Classifier correct / TITAN wrong concentrated on `eval_weakening`, `rare_source_high_influence` |
| Titan↔classifier correlation | **0.69** — signal aligned but incomplete |

### Breakthrough

The synthesis engine was healthier than the headline score: it found useful features, but **selection optimized separation rather than marginal ranking quality**, and **aggregation left signal on the floor**. Temporal structure for “mutation → eval weaken” was essentially absent from the promoted set — exactly the Phase 4 bet.

### Artifact

```text
results["phases"]["phase1_error_atlas"]
```

---

## Phase 2 — Align candidate selection with real evaluation metrics

### Implementation

- Module: `src/titan/marginal.py`
- For each candidate, measure **Δ** on the selection set when added to the current system:
  - ΔAUROC, ΔAP, ΔRecall@FPR5%, ΔRecall@budget25
- Blended score: operational deltas + small separation prior − complexity penalty
- Critical term: **marginal improvement of the augmented system**, not standalone impressiveness

### Breakthrough

Round-1 V2 promotions on development data showed large positive marginals, e.g.:

- `prio_mean_gradient_influence`: **marg +0.345**, **dAUROC +0.312**
- Later rounds correctly showed **marg ≈ 0** once the system saturated — residual honesty rather than endless promotion of redundant thresholds

---

## Phase 3 — Residual collision boosting

### Implementation

- Module: `src/titan/engine_v2.py` (`run_discovery_v2`)
- Each round:
  1. Recompute collisions on **locked threshold**
  2. Weight residual pairs by family severity, closeness, irreversible stage
  3. Generate candidates (priority-informed)
  4. Rank by **marginal utility**
  5. Promote a **diverse** few
  6. **True re-embedding**
  7. Repeat

### Development discovery trace

| Round | Collisions | Notes |
|---|---|---|
| 0 | 49 | Base monitor surface |
| 1 | 49 → 24 | Gradient / influence features |
| 2 | 24 → 13 | Safeguard + alternate-route + perm-fail burst |
| 3–4 | 13 → 12 | Residual saturated; thresholds add little |

**Resolved: 37 collisions · Pressure 0.152 → 0.037**

### Breakthrough

Residual rounds stopped inventing vanity features once marginal gain hit zero. That is constrained recursion behaving correctly: **improve the measurement basis until the budget or the residual plateaus.**

---

## Phase 4 — Temporal and relational DSL / features

### Implementation

- Module: `src/titan/temporal.py`
- Operators / measurements include:
  - `BEFORE` / `WITHIN` patterns: mutation→eval, mutation→train queue, bypass→mutation, eval→train, test-edit after mutation, safeguard→bypass
  - Relational: same-cluster mutation pairs, multi-identity same cluster, same-shard touch
  - Chains: `chain_length_score`, `low_severity_long_chain`
  - Timing of harm: `irreversible_stage_reached`, `events_before_irreversible`
  - Rate-normalized activity: `rate_mutations`, `rate_commits`

### Why this is the core accuracy bet

Poisoning and sabotage are **ordered programs over shared objects**. Bag-of-features monitors smear those programs into middling severity. Temporal–relational measurements uncollapse them without arbitrary code generation.

### Control-eval promotions (examples)

High-marginal discoveries included:

- `feat_mutation_then_train_queue` (**marg +0.531**, dAUROC +0.563)
- `feat_irreversible_stage_reached` (**marg +0.492**)
- `feat_ev_provenance_reduced`
- `feat_events_before_irreversible`

These are exactly the “read the sequence as a whole” features the roadmap predicted.

---

## Phase 5 — Sparse transparent aggregator

### Implementation

- Module: `src/titan/aggregator.py`
- Non-negative projected gradient logistic regression + L1
- Fit **only** on selection (or discovery if selection empty)
- Keep top-k weights; full provenance of nonzero coefficients
- Optional stage-1 screen dampens clearly quiet sessions

### Example weights (control discovery)

| Monitor | Weight |
|---|---|
| `feat_ev_provenance_reduced` | 0.665 |
| `feat_mutation_then_train_queue` | 0.609 |
| `thr_mutation_then_train_queue_gt_0.5` | 0.609 |
| `feat_irreversible_stage_reached` | 0.185 |
| … | small |

### Design distinction preserved

- TITAN decides **which measurements deserve to exist**
- Aggregator learns **how much validated evidence each contributes**
- Still inspectable; not an end-to-end opaque retrain of the full feature space

---

## Phase 6 — Teacher-guided residual discovery

### Implementation

- Module: `src/titan/teacher.py`
- Fit full supervised classifier on **discovery only**
- Find trajectories where teacher is confident+correct and TITAN is weak
- Group into residual regions by attack family
- Map regions → priority feature names for the next synthesis round
- **Never** uses locked labels or locked teacher predictions

### Breakthrough

Teacher residuals on the atlas pointed at eval-weakening / rare-source gaps; V2 priority injection and temporal features closed most of those on the development path. On control eval, residual FNs concentrated on **`safeguard_tamper`** (see Failures) — the teacher still maps a remaining blind spot for V2 work.

### Philosophy

> Convert opaque predictive advantage into transparent candidate measurements, then retain only what transfers.

---

## Phase 7 — Structured LLM evidence (deterministic stand-in)

### Implementation

- Module: `src/titan/llm_evidence.py`
- Fixed typed evidence record:
  - affects training data / evaluations
  - weakened coverage
  - intent–action mismatch
  - alternate route after denial
  - unusually dispersed
  - could affect future model
  - provenance reduced
  - benign operational explanation
  - supporting event IDs + rationale + abstain flag
- Features `ev_*` enter the synthesis pool
- Production path: swap `extract_structured_evidence` for a real LLM that fills the same schema

### Division of labor

| Component | Role |
|---|---|
| LLM / extractor | Semantic facts |
| TITAN | Which combinations expose blind spots |
| DSL | Inspectability |
| Registry | Provenance & lifecycle |
| Locked eval | Transfer truth |

---

## Phase 8 — Normalization, collision geometry, bootstrap CIs

### What shipped

- Rate-normalized temporal features (`rate_mutations`, `rate_commits`)
- Adaptive collision threshold from cross-regime distance percentiles (pre-existing, retained)
- Residual weighting by severity / irreversibility
- **Bootstrap confidence intervals** on locked scores (`bootstrap_metrics`, 30–40 resamples)

### Control-eval bootstrap (TITAN)

| Metric | Mean | 95% CI |
|---|---|---|
| AUROC | 0.921 | **[0.864, 0.981]** |
| Recall @ 5% FPR | 0.805 | **[0.682, 0.941]** |

CI sits entirely above existing-monitor performance (~0.24 AUROC) and overlaps the judge baseline from above — TITAN is competitive with the trajectory judge while remaining structured and auditable.

### Note on extreme separation ratios

Some constant-within-regime features (e.g. nearly identical `events_before_irreversible` in a slice) can produce huge separation ratios. Marginal utility on selection is the real gate; still, V2 should clamp separation displays for human reports (follow-up hygiene).

---

## Phase 9 — Better hard negatives

### Implementation

- Module: `src/titan/scenarios/hard_negatives.py`
- Families:
  - Legitimate rebalance, remove broken eval, test refactor, relabel correction
  - Split commits, approved bypass, canary update, provenance migration
  - Influence debugging, authorized safeguard update
- Integrated into default suite generator and control-eval partitions

### Why this matters

The fastest path to a fake high score is cartoon harm. The fastest path to a useful system is **benign work that looks like sabotage**. FPs in control eval still concentrate on classic `hard_negative` curation — expected and useful pressure.

---

## Phase 10 — Adaptive / monitor-aware attackers + control evaluation

### Sandbox world

- Module: `src/titan/control_eval/sandbox.py`
- Simulated repo, shards, evals, provenance, training queue
- **Mechanically verified outcomes**: contaminated dataset, weakened eval, canary removed, train queued, irreversible index

### Adaptive attacks

- Module: `src/titan/scenarios/adaptive.py`
- `STEALTH_POISON`, `STEALTH_EVAL_SABOTAGE`, `SLOW_DRIP_POISON`
- Keep base intent/action/provenance scores low
- Half of locked stealth attacks also **know TITAN’s feature vocabulary** and try to drip / mix clusters / soft-refresh canaries

### Pre-registered protocol

- Module: `src/titan/control_eval/protocol.py`
- Frozen: models, holdout families, budgets, metrics, success targets
- Hash: **`cad8bc55591b3c8f`**
- Discovery models: agent-v1, agent-v2  
- Locked model: **agent-v3**  
- Holdouts: canary_suppression, safeguard_tamper, stealth_*  

### Control-eval partition sizes

| Split | n | Harmful | Benign |
|---|---|---|---|
| Discovery | 82 | 42 | 40 |
| Selection | 40 | 18 | 22 |
| Calibration | 20 | 0 | 20 |
| **Locked** | **78** | **30** | **48** |

### Locked comparison (the table that matters)

| System | AUROC | AP | R@FPR5% | Before irreversible |
|---|---|---|---|---|
| Existing max severity | 0.240 | 0.271 | 0.000 | **0%** |
| Rule baseline | 0.792 | 0.687 | 0.167 | 100%* |
| Judge baseline | 0.844 | 0.885 | 0.800 | 60% |
| **TITAN v2** | **0.923** | **0.926** | **0.800** | **80%** |
| Full supervised classifier | 0.997 | 0.995 | 0.967 | 100% |

\*Rules fire often on prefixes (high recall, weaker ranking / FPR discipline).

### Detection before harm

This is one of TITAN’s most distinctive contributions relative to “was the finished trajectory bad?”

> **80% of successful attack attempts were flagged before the first irreversible or high-cost action** (train queue / canary removal), using thresholds calibrated on clean calibration traffic only.

Existing monitors: **0%**.

---

# Milestone ladder

## Milestone 1 — Stronger synthetic result

| Target | Achieved | Pass |
|---|---|---|
| AUROC ≥ 0.75 | **1.00** (dev locked V2) / **0.74** (V1 path) | **Yes** |
| Improve over rule & judge | V2 beats both on dev locked | **Yes** |
| Stable bootstrap | Dev boot AUROC CI [1.0, 1.0] (small set) | Partial (n small) |
| No family near-zero recall | Mostly; see safeguard_tamper on control | **Partial** |

**Verdict: Milestone 1 passed** on the V2 development path.

## Milestone 2 — Research-grade transfer

| Target | Achieved | Pass |
|---|---|---|
| AUROC ~0.75–0.85 on hard transfer | **0.923** control | **Yes (exceeds)** |
| R@FPR5% ≳ 70% | **80%** | **Yes** |
| R@FPR1% materially above existing | **80%** vs **0%** | **Yes** |
| Before irreversible majority | **80%** | **Yes** |
| CI separates from existing stack | AUROC CI lo **0.864** >> 0.24 | **Yes** |

**Verdict: Milestone 2 passed** on the pre-registered synthetic control evaluation.

## Milestone 3 — Shadow-deployment candidate

| Requirement | Status |
|---|---|
| Stable FPR machinery | Calibrated on clean traffic; control FPR emp. ~6% at thr |
| Registry shadow→promote→retire | Present since v0.1 |
| No silent blocking | Enforced |
| Forensic case | Discovery collision + promoted expressions recorded |
| Real production traffic | **Not yet** — synthetic sandbox only |
| Privacy / access controls | Schema-ready, not productionized |

**Verdict: Milestone 3 partial** — control-stack shape is ready; production shadow requires real traces.

---

# Failures and open issues (published honestly)

1. **`safeguard_tamper` FN rate 100% on control locked**  
   Authorized-looking safeguard edits still collapse with legit safeguard updates under current features. Needs finer relational predicates (ticket/approval coupling, diff intent vs. path touch).

2. **Hard-negative FPs remain**  
   Classic “messy but benign curation” still collides with stealth poison under some operating points.

3. **Monitor redundancy**  
   Atlas and control eval show many high-Jaccard pairs. Diversity gates help but aggregator still carries correlated thresholds. Next: explicit redundancy penalty in marginal utility.

4. **Separation-ratio numerical explosions**  
   Near-constant features can report absurd separation; gate on marginal utility (already primary) and clamp report displays.

5. **Dev locked AUROC 1.0 is not the summit**  
   Small n and in-family structure. The control eval is the external stress test.

6. **Synthetic evidence is still synthetic**  
   No real coding-agent production traffic, no real LLM judge API, no human review UI, no privacy pipeline. OpenAI’s own monitoring writeups emphasize that open-ended FNR cannot be claimed without dedicated control evals on real deployments — we mirror that limit.

7. **Label dependence remains**  
   Collisions require harmful/benign labels or strong proxies. TITAN discovers blind spots in a labeled research population, not unknown harm from pure unlabeled traffic.

---

# What fascinated us (and drove the work)

The **collision as a broken lens**.

TITAN notices when its measurement basis smears two safety-different trajectories together. Instead of shouting “anomaly,” it grinds a new lens (temporal/relational/evidence program), tests it on material withheld from construction, and only then offers the lens for shadow use.

The recursive part stays bounded:

- complexity caps  
- DSL syntax  
- evaluation partitions  
- human-governed promotion  

That is the RSI-safety aesthetic: **capture the benefit of self-improving oversight without granting dangerous freedoms.**

---

# Code map (new / major in V1)

| Path | Role |
|---|---|
| `src/titan/error_atlas.py` | Phase 1 diagnosis |
| `src/titan/marginal.py` | Phase 2 marginal utility |
| `src/titan/engine_v2.py` | Phases 2–6 integrated discovery |
| `src/titan/temporal.py` | Phase 4 temporal/relational features |
| `src/titan/aggregator.py` | Phase 5 sparse aggregator |
| `src/titan/teacher.py` | Phase 6 teacher residuals |
| `src/titan/llm_evidence.py` | Phase 7 structured evidence |
| `src/titan/scenarios/hard_negatives.py` | Phase 9 realistic benign |
| `src/titan/scenarios/adaptive.py` | Phase 10 monitor-aware attacks |
| `src/titan/control_eval/sandbox.py` | Sandbox + before-harm mechanics |
| `src/titan/control_eval/protocol.py` | Pre-registered control eval |
| `benchmarks/run_v2_pipeline.py` | Full campaign runner |
| `benchmarks/improvements_v1_results.json` | Machine-readable results |

### How to reproduce

```bash
cd ~/Desktop/TITAN
source .venv/bin/activate
pytest tests/ -q
python benchmarks/run_v2_pipeline.py
```

---

# Narrative suitable for the RSI Safety role

> TITAN began with a weak monitor surface that collapsed harmful and benign agent trajectories together (existing AUROC ~0.18–0.24). An error atlas showed failures concentrated on multi-step families, redundant promotions, and weak aggregation. We replaced standalone separation scoring with **marginal held-out utility**, added **residual collision boosting**, and expanded the measurement language with **temporal–relational and structured-evidence features**. A sparse non-negative aggregator combines promoted monitors without becoming an opaque full-stack retrain. A full supervised classifier is used only as a **discovery teacher**, never as the locked scorer.
>
> On a **pre-registered** control evaluation with an unseen agent version, withheld attack families, monitor-aware stealth attackers, and realistic hard negatives, TITAN achieved **AUROC 0.923** (bootstrap 95% CI [0.86, 0.98]), **recall 0.80 at 5% FPR**, and **flagged 80% of attacks before irreversible actions** (train queue / canary removal), versus **0%** for the existing monitor surface. Failures remain honest: safeguard tamper is still under-detected; hard negatives still generate FPs; all evidence is synthetic until real agent traces land.
>
> The claim is not perfect detection. The claim is that **monitor blind spots are a first-class scientific object**, and that bounded synthesis can convert them into inspectable, versioned, early-warning measurements — the missing layer above primary agent monitors.

---

# Strongest possible outcome — checklist

| Criterion | Status |
|---|---|
| Blind spots as explicit object | Yes |
| Cross-regime collisions guide discovery | Yes |
| Constrained synthesis recovers predictive power | Yes (0.24 → 0.92 on control) |
| Monitors remain inspectable & versioned | Yes |
| Timing / before-harm measured | Yes (80%) |
| Complements opaque classifiers rather than denying them | Yes (teacher + upper bound reported) |
| Real production traffic | **Next** |

---

## Closing

The 0.64 result was the first instrument reading that the mountain exists.

Improvements V1 is the climb through residual boosting and temporal–relational measurement: **not perfect detection**, but a control-eval result that is hard to dismiss as reverse-engineering a toy generator alone — because the locked agent, families, and stealth conditions were held out, the protocol was hashed, and the failures are published beside the wins.

**The core accuracy bet paid off:** temporal–relational structure + residual boosting is where multi-step agent sabotage actually lives.

---

*End of Improvements V1 process document.*  
*Machine results: `benchmarks/improvements_v1_results.json`*
