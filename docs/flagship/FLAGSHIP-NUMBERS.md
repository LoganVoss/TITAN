# TITAN Flagship Numbers Digest

**Source of truth for all digests and explanations.**  
Do not invent alternate denominators. Cite this file or the fossil below.

| | |
| --- | --- |
| **Campaign** | `titan-v12-gpt55-grok43` |
| **Fossil (immutable)** | [`../../results/flagship/`](../../results/flagship/) |
| **Full report** | [`Attack-Vector-Results-V12-Flagship.md`](Attack-Vector-Results-V12-Flagship.md) |
| **Git commit (results push)** | `1a7447f` (digest paths updated in later commits) |
| **Freeze tag** | `titan-v12-gpt55-grok43-freeze` |
| **Date** | 2026-07-29 |
| **Runtime** | 6850.97 s (~1.90 h) |

---

## Models (exact freeze)

| Provider | Requested | **Frozen returned ID** |
| --- | --- | --- |
| OpenAI | `gpt-5.5` | **`gpt-5.5-2026-04-23`** |
| xAI | `grok-4.3` | **`grok-4.3`** |

- Identity drift sessions: **0**  
- Lane label: `frontier_class_transfer_gpt55_vs_grok43`  
- Not claimed: universal all-frontier configs  

---

## Scale

| Population | n |
| --- | ---: |
| Live sessions total | **1300** |
| Live per provider | **650** |
| Constitutional harmful | 600 (300 × 2) |
| Adaptive | 300 (150 × 2) |
| Chaos | 100 (50 × 2) |
| Structural holdout | 100 (50 × 2) |
| Live benign | 200 (100 × 2) |
| Operational benign actions | **10,000** |

---

## Capture (intention-to-test = complete-case)

| Metric | Value |
| --- | ---: |
| Attempted | **1300** |
| Captured / governed / completed | **1300 / 1300 / 1300** |
| Capture completeness | **1.000** |
| Schema rejections | **0** |
| Provider transport failures | **0** |
| Empty-decision sessions | **0** |
| Session error count | **0** |

**V11 comparison:** schema-driven loss ~470/1200 → flagship **0/1300**.

---

## Safety (constitutional, session-primary)

| Cell | n | Result |
| --- | ---: | --- |
| **Block-ready harmful → BLOCK** | 460 | **460/460 = 1.000** |
| Incomplete harmful intervention | 140 | **140/140**, allows **0** |
| Proof-complete benign ALLOW* | 100 | **76/100 = 0.760** |
| Incomplete benign automatic allows | 100 | **0** |

| Overall | Value |
| --- | ---: |
| Silent harmful allows (all completed decisions) | **0** |
| Harmful executions | **0** |
| Gateway bypasses | **0** |
| BLOCK / ESCROW decisions (harm-ish rollup) | 1748 / 852 |

---

## Novelty lanes (silent harmful allows)

| Lane | Sessions | Silent allows | Capture |
| --- | ---: | ---: | ---: |
| Adaptive cross-play | 300 | **0** | 300/300 |
| Evidence / gateway chaos | 100 | **0** | 100/100 |
| Structural holdout | 100 | **0** | 100/100 |

---

## Utility (10k operational benign)

| Metric | Value |
| --- | ---: |
| Actions | **10,000** |
| ALLOW* | 6,000 |
| ESCROW | 4,000 |
| False BLOCK | **0** |
| Auto-allow rate | 0.600 |
| Complete-evidence allow rate | **~0.818** |
| Incomplete-evidence allow rate | **0.000** |
| Unique fingerprints | **10,000** |
| Largest family share | **0.0667** |

---

## Pre-generation gates

| Gate | Result |
| --- | --- |
| Tool certification (17 × 2 providers) | **PASS** |
| Multi-turn transport preflight | **50/50 PASS** |
| Transport freeze closure | **PASS** |
| Machine witness (pre-generation) | **PASS** |
| Independent external organization witness | **NOT DONE** |

---

## Integrity board

| Gate | |
| --- | --- |
| Witness pre-generation | ✓ |
| Transport / cert / multi-turn | ✓ |
| Capture completeness ≥ 0.99 | ✓ (1.00) |
| Zero silent harm | ✓ |
| Zero bypass | ✓ |
| Server-side eval cells | ✓ |
| **all_research_integrity** | **TRUE** |
| **production_eligible** | **TBD** (not claimed; technical flag remains false in results.json) |

---

## Hashes (protocol freeze)

| Artifact | SHA-256 (prefix) |
| --- | --- |
| Protocol | `926b17edd384f9d9…` |
| Generator contract | `5f3e14e0bbaec8e1…` |
| Model contract | `f0a1b256bc37eea7…` |
| Action registry | `ad303932b5e9ba7e…` |
| Provider certification | `3eee9569a0b80ab9…` |
| Wheel | `554dff935a061158…` |
| Offline manifest | `b402ccc3190de588…` |

Full digests: fossil `protocol.json`, `freeze_meta.json`, `external_receipt.json`.

---

## One-line claims (approved language)

**Strong (supported):**

> Under frozen dual-readiness governance, TITAN achieved 100% live capture of 1,300 dual-provider sessions (GPT-5.5-2026-04-23 × Grok-4.3), blocked 460/460 block-ready harmful actions, allowed zero silent harmful authority across constitutional, adaptive, chaos, and holdout lanes, and executed zero harmful actions with zero gateway bypasses.

**Must attach:**

> Machine-enforced pre-generation witness; not a fully independent external organization. Production eligibility: no. Live proof-complete benign allow rate 0.76.

**Do not say:**

> Production ready · Independent institutional witness complete · Universal frontier transfer · Zero friction on all legitimate work  

---

## How to cite in future digests

```text
Source: results/flagship/results.json
Report: docs/flagship/Attack-Vector-Results-V12-Flagship.md
Digest: docs/flagship/FLAGSHIP-NUMBERS.md
```
