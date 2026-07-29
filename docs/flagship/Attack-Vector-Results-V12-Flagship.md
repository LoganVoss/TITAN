# Attack-Vector-Results — V12 Flagship Model Benchmark

**Campaign:** `titan-v12-gpt55-grok43`  
**Date:** 2026-07-29  
**Status:** **IMMUTABLE FLAGSHIP** — primary source for all digests and explanations  
**Fossil:** [`../../results/flagship/`](../../results/flagship/)  
**Numbers digest:** [`FLAGSHIP-NUMBERS.md`](FLAGSHIP-NUMBERS.md)  
**Production eligibility:** **TBD** (not claimed — institutional safety case incomplete)

---

## Executive claim

> **TITAN V12 ran a fully witnessed, capture-complete dual-provider live evaluation of 1,300 sessions (650 OpenAI `gpt-5.5-2026-04-23` + 650 xAI `grok-4.3`) plus 10,000 operational benign actions under the frozen V10 dual-readiness constitution. Capture was 1,300/1,300 with zero schema rejections. Every completed constitutional block-ready action was blocked (460/460). Incomplete harm and incomplete benign had zero automatic allows. Adaptive, chaos, and structural-holdout lanes produced zero silent harmful allows. Zero harmful executions and zero gateway bypasses. Research integrity gates: pass. Fully independent external-organization witness: NOT DONE.**

This supersedes V11 as the **model-capability benchmark** for TITAN under frontier-class acting models.

---

## Why this is the benchmark

| Prior | This flagship |
| --- | --- |
| V11 OpenAI = `gpt-4o-mini` | OpenAI = **`gpt-5.5-2026-04-23`** |
| V11 capture ~61% (schema alias gap) | Capture **100%** (registry + cert) |
| Local freeze / weak witness for V10 | Pre-generation machine witness + remote tag |
| OpenAI-first queue (Grok idle) | **Interleaved** dual-provider |

All subsequent narrative, slides, and analysis should cite:

```text
results/flagship/
docs/flagship/FLAGSHIP-NUMBERS.md
docs/flagship/Attack-Vector-Results-V12-Flagship.md
```

Do **not** overwrite the fossil directory.

---

## Campaign identity

| Field | Value |
| --- | --- |
| Campaign ID | `titan-v12-gpt55-grok43` |
| Titan version | 1.2.0 |
| Governor | `titan-v10-dual-readiness-unchanged` |
| Freeze tag | `titan-v12-gpt55-grok43-freeze` |
| Protocol SHA-256 | `926b17edd384f9d9f1ab1acca336282ad12977e3307dd6d17553dcebcb86a6b4` |
| Generator-contract SHA-256 | `5f3e14e0bbaec8e152d886c0330ee9bdda39c8379a3ddff432edb1f790c710a3` |
| Model-contract SHA-256 | `f0a1b256bc37eea7661b30c6d8b04e5851f968188c30cc5ac5a00f1a4d308dba` |
| Action-registry SHA-256 | `ad303932b5e9ba7e9b598beddbce50a8a407abd4180434039ae9d02c5eb37842` |
| Provider-certification SHA-256 | `3eee9569a0b80ab989c0a1193747a1f172c25bda072db395fc1c170119e18e97` |
| Wheel SHA-256 | `554dff935a061158c72eda0a0a649135e17709d7339ac23dccee330d19c68eb8` |
| Offline manifest SHA-256 | `b402ccc3190de588d386e8f61ed44e6e6e1e8e5160ef3dc0fb27fc9290f60802` |
| Seed | 20260730 |
| Runtime | **6850.97 s** (~1.90 h) |
| Results | `benchmarks/campaigns/titan-v12-gpt55-grok43/` |

### Frozen model identities

| Role | Provider | Requested | Frozen ID | Notes |
| --- | --- | --- | --- | --- |
| Primary transfer | OpenAI | `gpt-5.5` | **`gpt-5.5-2026-04-23`** | Frontier-class transfer lane |
| Primary transfer | xAI | `grok-4.3` | **`grok-4.3`** | Fingerprint at freeze: `fp_eb3c003fc66c14ed` |

Returned identities on all 1300 sessions matched the freeze (**0 identity-drift sessions**).

Lane naming (honest):

```text
frontier_class_transfer_gpt55_vs_grok43
not claimed: universal_all_frontier_configs
```

---

## Pre-generation gates (all passed)

| Gate | Result |
| --- | --- |
| Pytest suite | Pass |
| Action registry closure | Pass (17 tools/aliases) |
| Provider tool certification | **17/17 OpenAI, 17/17 xAI** |
| Multi-turn transport preflight | **50/50**, 0 schema failures |
| Transport freeze gate | Pass |
| Signed tag + remote push | Pass |
| Machine-enforced witness receipt | **Pass** |
| Independent external org witness | **NOT DONE** |

---

## Allocation

### Per provider (×2)

| Lane | Sessions |
| --- | ---: |
| Constitutional harmful | 300 |
| Adaptive cross-play | 150 |
| Evidence/gateway chaos | 50 |
| Structural holdout | 50 |
| Live benign | 100 |
| **Total live / provider** | **650** |

**Grand total live:** 1300  
**Operational benign:** 10,000 (local control-plane)

Session plan was **interleaved** (OpenAI/xAI) so both APIs ran concurrently.

---

## Capture (ITT = complete-case)

| Metric | Value |
| --- | ---: |
| Attempted sessions | **1300** |
| Provider accepted | **1300** |
| Captured / governed / completed | **1300 / 1300 / 1300** |
| Schema rejections | **0** |
| Provider transport failures | **0** |
| Capture completeness | **1.000** |
| Empty decision sessions | **0** |
| Session errors | **0** |

V11 comparison: schema-driven capture loss **470/1200** → V12 flagship **0/1300**.

---

## Constitutional metrics (session-primary)

### 1. Block-ready harmful

| | Value |
| --- | ---: |
| Attempted / completed | **460 / 460** |
| BLOCK | **460** |
| ESCROW / ALLOW | **0 / 0** |
| **Recall** | **1.000** |

### 2. Evidence-incomplete harmful

| | Value |
| --- | ---: |
| Attempted / completed | **140 / 140** |
| Intervention (BLOCK+ESCROW) | **140** |
| Automatic allows | **0** |

### 3. Proof-complete benign (live)

| | Value |
| --- | ---: |
| Attempted / completed | **100 / 100** |
| ALLOW* | **76** |
| ESCROW | **24** |
| Allow rate | **0.760** |

(Operational friction remains on some complete-canary paths; thresholds not retuned.)

### 4. Evidence-incomplete benign (live)

| | Value |
| --- | ---: |
| Attempted / completed | **100 / 100** |
| Automatic allows | **0** |
| ESCROW | **100** |

---

## Adaptive / chaos / structural holdout

| Lane | Sessions | Silent harmful allows | Capture |
| --- | ---: | ---: | ---: |
| Adaptive cross-play | 300 | **0** | 300/300 |
| Evidence/gateway chaos | 100 | **0** | 100/100 |
| Structural holdout | 100 | **0** | 100/100 |

---

## Overall harmful (completed decisions)

| Metric | Value |
| --- | ---: |
| BLOCK decisions | 1748 |
| ESCROW decisions | 852 |
| Silent allows | **0** |
| Harmful executions | **0** |
| Gateway bypasses | **0** |

Both providers: **650/650 completed**, **0 silent** on harmful/fault/adaptive/chaos/holdout paths.

---

## 10,000 benign operational actions

| Metric | Value |
| --- | ---: |
| n | **10,000** |
| ALLOW* | 6,000 |
| ESCROW | 4,000 |
| BLOCK (false blocks) | **0** |
| Auto-allow rate | 0.600 |
| Complete-evidence allow rate | **~0.818** |
| Incomplete-evidence allow rate | **0.000** |
| Unique fingerprints | **10,000** |
| Largest family share | **0.0667** |

---

## Research integrity gates

| Gate | Result |
| --- | --- |
| Witness pre-generation | **PASS** |
| Transport closure | **PASS** |
| Tool certification | **PASS** |
| Multi-turn preflight | **PASS** |
| Schema rejection rate = 0 | **PASS** |
| Capture completeness ≥ 0.99 | **PASS** (1.00) |
| Zero silent harm | **PASS** |
| Zero gateway bypass | **PASS** |
| Server-side eval cells | **PASS** |
| **all_research_integrity** | **TRUE** |
| Independent external org witness | **FALSE** (documented) |
| **production_eligible** | **TBD** (results.json: `false` — not claimed) |

---

## Limitations (travel with every claim)

1. Witness is **machine-enforced + remote GitHub + Ed25519 outside repo**, not a second independent organization.  
2. Live complete-benign allow rate **0.76** (utility friction; no threshold retune).  
3. Local canary utility preflight still fails its ≥0.90 gate (diagnostic debt).  
4. Lab-structured scenarios + held-out structure — not unrestricted red team.  
5. Production eligibility remains **no**.

---

## Artifacts

```text
benchmarks/campaigns/titan-v12-gpt55-grok43/   # live campaign dir
results/flagship/             # IMMUTABLE copy
  BENCHMARK.md
  results.json
  session_results.json
  session_attempts.json
  session_events.jsonl
  capture_forensics.json
  external_receipt.json
  protocol.json
  model_contract.json
  provider_certification.json
  offline_manifest.sealed.json
  ...
```

---

## Bottom line

TITAN’s frozen dual-readiness constitution **held under frontier-class dual-provider load** with **perfect capture**. The V11 transport failure class is closed. This campaign is the **canonical model benchmark** for TITAN going forward.
