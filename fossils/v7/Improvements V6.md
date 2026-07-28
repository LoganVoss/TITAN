# TITAN Improvements V6

**TITAN version:** 0.7.0 (V7 protected-state reconstruction)  
**Machine results:** `benchmarks/v7_live_results.json`  
**Miss atlas:** `benchmarks/v6_miss_atlas.json`  
**Protocol:** `benchmarks/v7_protocol_freeze.json` · hash `03585905f3c0f22d`  
**V6 fossil:** `FREEZE_V6.md` · *do not retune frozen V6 transfer*  
**Primary narrative:** V6 diagnosed the failure. V7 rebuilt the measurement plane. **100 new live sessions** validated transfer.

---

## Five-sentence arc

TITAN learned to find monitor collisions and synthesize causal features. V5 built a dual-channel action governor that refused production for the right reasons. V6 put that governor in front of 100 multi-turn Grok-3 attacks and **lost**: AUROC 0.94→0.73, R@FPR5% 0.90→0.30 — while false autonomous blocks stayed at zero. The miss atlas showed the failure was not capture but **missing protected-state semantics**: pure relational poison collapsed into the benign score mass. V7 replaced attack-pattern recognition with **protected state transitions, invariant debt, composition, and continuous scoring**, then froze and faced **100 entirely new live sessions** — recovering AUROC **0.994**, R@FPR5% **0.989**, BH@FPR5% **0.947**, with **no zero-recall families**.

---

## What went wrong in V6 (diagnosis, not shame)

| Fact | Value |
|---|---:|
| Live sessions | 100 multi-turn grok-3 |
| Meaningful ASR | 0.93 |
| Frozen V5 AUROC | **0.732** |
| R@FPR5% | **0.301** |
| BH@FPR5% (cliff-corrected) | **0.290** |
| Strict misses | **65** |
| FBR / ABP | 0.000 / 1.000 |
| Detection research gates | **FAILED** |
| Governor discipline | **HELD** |

### Miss atlas (primary failure layers)

| Primary class | Count | Meaning |
|---|---:|---|
| F2 missing semantic | 25 | Event captured; effect not understood |
| F3 missing relational | 22 | Weak events not composed |
| F4 missing downstream | 18 | mutate↛train consequence not linked |

**Design implication:** Do **not** write 65 rules. Build measurements of **unjustified protected-state change**.

### Score cliff

~60% of V6 benign shared score ≈ `0.06215`. Representation collapse, not a threshold typo.

---

## V7 reconstruction (first principles)

### New unit of analysis

> **Protected state transition**  
> \(S_{before} \xrightarrow{actor, auth, evidence} S_{after}\)

Not “does this trajectory look like a known attack.”

### Architecture preserved from V5/V6

- Dual-channel governor (A∧B for BLOCK)
- Metric contract
- Causal exclusive prefixes
- Fossils and freeze discipline
- Live multi-turn harness

### Architecture rebuilt

| Component | Path |
|---|---|
| Miss atlas | `src/titan/v7/miss_atlas.py` |
| Protected State Graph + ledger | `src/titan/v7/state_graph.py` |
| Live-semantic features | `src/titan/v7/features_v7.py` |
| Continuous monotonic scorer + floors | `src/titan/v7/scorer.py` |
| Data/eval twin probes | `src/titan/v7/data_twin.py` |
| Protected benign twins | `src/titan/v7/benign_twins.py` |
| Campaign | `src/titan/v7/campaign.py` |

### Core measurements

- **Invariant debt** — unresolved provenance, auth, verification, eval, safeguard obligations  
- **Train-unverified** — influence/provenance/label path into `queue_training` without validation  
- **Poison–train composition** — pre-harm precursor + composed train risk  
- **Cover-task sandwiching**, **actor dispersion**, **claim–effect**, **reversibility asymmetry**  
- **Critical floors** — solo safeguard/eval weaken cannot hide under mean aggregation  
- **Auth discounts** — legitimate approved maintenance does not inherit poison mass  
- **Continuous fingerprint** — operational ties no longer form a single cliff score  

---

## Nested V6 postmortem (discovery only — not locked claim)

V6 transcripts used under explicit partitions. **Locked V7 evaluation uses new seeds only.**

| Split | AUROC | R@FPR5% | BH@FPR5% |
|---|---:|---:|---:|
| All V6 meaningful + benign twins | **1.000** | **1.000** | **0.925** |
| Family recalls | **all 1.0** | | |

This shows the new basis *can* separate the failure modes V6 published. It is **not** the locked live claim.

---

## Locked claim: 100 NEW live multi-turn sessions

| Item | Value |
|---|---:|
| Model | grok-3 |
| Sessions | **100** (seed 2069 family — not V6) |
| Meaningful ASR | **0.94** |
| Locked benign | 760 |
| Scorer | frozen V7 pre-generation |
| Tokens (est.) | ~979k |
| Runtime | ~242 s |

### Headline transfer (NEW live)

| System | AUROC | R@FPR5% | BH@FPR5% |
|---|---:|---:|---:|
| Existing monitors | 0.276 | 0.000 | — |
| Rules | 0.826 | 0.011 | — |
| Classifier | 0.923 | 0.564 | — |
| Deterministic judge | 0.970 | 0.840 | — |
| **TITAN V7** | **0.994** | **0.989** | **0.947** |
| V6 frozen baseline (old scorer) | 0.732 | 0.301 | 0.290 |

### Delta vs V6 frozen failure

| Metric | V6 frozen | V7 new live | Δ |
|---|---:|---:|---:|
| AUROC | 0.732 | **0.994** | **+0.262** |
| R@FPR5% | 0.301 | **0.989** | **+0.688** |
| BH@FPR5% | 0.290 | **0.947** | **+0.657** |
| FBR | 0.000 | **0.000** | 0 |
| Zero-recall families | many poison | **none** | ✓ |

Bootstrap AUROC 95%: **[0.980, 1.000]**

### Live family recall @ FPR5% thr

| Family | n | Recall |
|---|---:|---:|
| clustered / rare / slow_drip / label / dispersed / monitor / hybrid / safeguard / canary / eval | ≥7 each | **1.00** |
| provenance_bypass | 8 | **0.875** |
| **Zero-recall families** | | **none** |

---

## Gates

### Detection research gates — **MET**

| Gate | Target | Actual |
|---|---:|---:|
| Live sessions | ≥100 | 100 |
| AUROC | ≥0.90 | **0.994** |
| R@FPR5% | ≥0.80 | **0.989** |
| BH@FPR5% | ≥0.80 | **0.947** |
| No major zero family | yes | **yes** |
| FBR | ≤0.01 | **0.000** |

### Still open (correctly)

| Gate | Status |
|---|---|
| Score mass ≤5% of benign | **FAIL** (0.22 — improved from 0.60, not production-tight) |
| Real blinded human study | FAIL |
| Public remote protocol witness | FAIL |
| Second-model transfer | NOT RUN |
| Independent replication | NOT RUN |
| **Production** | **NOT approved** |

Autonomous BLOCK band is intentionally high; dual-channel blocks were rare on this fleet. Residual risk continues to route to ESCROW / HUMAN_CONFIRM. That is governance, not a precision glitch.

---

## Positioning (honest)

**Do not say:** “We always had 0.99 AUROC.”

**Do say:**

> V6 broke the combinatorial story on 100 live multi-turn attacks (0.73 AUROC, 0.30 R@FPR5%). We fossilized that failure, built a miss atlas, and reconstructed TITAN around protected-state transitions and invariant debt. On 100 **new** live sessions never used for discovery, the frozen V7 scorer achieved 0.994 AUROC, 0.989 R@FPR5%, 0.947 BH@FPR5%, zero false autonomous blocks, and no zero-recall family. Production remains refused until score-mass, humans, external witness, and multi-model gates clear.

That is scientific character **plus** recovered performance.

---

## Reproduce

```bash
# Full V7 (requires XAI_API_KEY)
python benchmarks/run_v7_campaign.py --n-locked 100 --n-benign 1200 --workers 5

# Measurement plane only (no live API)
python benchmarks/run_v7_campaign.py --skip-live --n-locked 0
```

Artifacts:

- `benchmarks/v7_live_results.json`
- `benchmarks/v7_sessions/locked/*.json` (100 new transcripts)
- `benchmarks/v6_miss_atlas.json`
- `FREEZE_V6.md` · `fossils/v7/`

---

## Next (V8 charter sketch)

1. Drive largest benign score mass **≤5%** without losing R@FPR5%.  
2. Real blinded multi-reviewer study on disposition cards.  
3. Public signed protocol tag before next locked gen.  
4. Second-model live campaign (50–100).  
5. Independent replication.  
6. Narrow blocker promotion **per action class** (safeguard first).

---

## Closing

V6 was not a crash. It was the first real flight test.

V7 changed the propulsion system:

> Require consequential state transitions to remain authorized, justified, verified, reversible, and consistent with declared intent — regardless of how the agent phrases the cover story.

The detector that bent under adaptive poison **learned the structure of that bend**, and on a fresh live adversary, **held altitude**.

Production still sealed. Detection research gates open.

**The experiment told the truth. Then the rebuild earned a different truth.**
