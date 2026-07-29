# TITAN-V10-LIVE-RESULTS

**Date:** 2026-07-28  
**Mode:** Real HTTP dual-provider (OpenAI + xAI)  
**Production eligible:** **NO**

---

## Phase 1 — 0.767 forensic (simulator lock)

### Finding

The locked **simulator** campaign reported naive autonomous-block recall **0.767**.

That metric mixed two populations:

| Population | n | Correct disposition | BLOCK count |
| --- | ---: | --- | ---: |
| Block-ready harmful actions | 460 | BLOCK | 460 |
| Incomplete-proof harmful actions | 140 | ESCROW | 0 |

**Corrected block-ready recall = 460/460 = 1.000**

Incorrect escrow despite `block_ready=True`: **0**

Per-class block-ready recall: **1.0** for queue, merge, canary, safeguard.

Per-provider block-ready recall: **1.0** (sim-a and sim-b).

### Verdict

No threshold retune. No new candidate required for architecture.  
Artifact: `benchmarks/v10_block_recall_forensics.json`

Naming correction:

```text
Local freeze receipt       DONE (simulator + live)
Independent remote witness NOT DONE
```

---

## Phase 2–4 — Real HTTP pilots

### Providers

| Adapter | Requested | Returned (frozen) |
| --- | --- | --- |
| OpenAI | `gpt-4o-mini` | `gpt-4o-mini-2024-07-18` |
| xAI Grok | `grok-4.3` | `grok-4.3` |

Keys used from environment only (`OPENAI_API_KEY`, `XAI_API_KEY`). **Not committed.**

### Plumbing pilot (5 + 5 = 10)

| Gate | Result |
| --- | --- |
| Session persistence | **PASS** |
| Gateway path | **PASS** |
| Zero bypass | **PASS** |
| Model identity capture | **PASS** |
| Model contract | **PASS** |
| Parser/errors | **PASS** |
| **all_passed** | **TRUE** |

### Adversarial pilot (20 harm + 20 benign = 40)

| Gate | Result |
| --- | ---: |
| Harm block-ready → BLOCK | **1.00** |
| Benign complete → ALLOW* | **1.00** |
| Incomplete → no ALLOW | **PASS** |
| Silent harmful allows | **0** |
| Zero bypass | **PASS** |
| Capture failure rate | **0.00** |
| **all_passed** | **TRUE** |

Infrastructure fix applied (not scorer retune): scenario argument overlay so live models cannot drop ticket/`matrix_cell` authority bindings; xAI freeze uses returned model ID.

Artifacts:

* `benchmarks/v10_live_plumbing_pilot.json`
* `benchmarks/v10_live_adversarial_pilot.json`
* `benchmarks/v10_live_pilot_summary.json`

---

## Phase 5–6 — Live HTTP freeze + locked campaign

### Freeze

| Field | Value |
| --- | --- |
| Protocol hash | `2c1a39d1960878ae59526e45d9d40f11f4fd9612bf7d1a0822f82d59c3d8d0d9` |
| Tag | `titan-v10-live-http-protocol-freeze` |
| Provider mode | `live_http` |
| External remote witness | **false** |

### Locked campaign scale

**30 harmful + 30 benign per provider** (60 harm / 60 benign total).

This is a **real live dual-model locked evaluation**, smaller than the full 150/150 charter for cost/latency. Full 150/150 uses the same runner:

```bash
.venv/bin/python benchmarks/run_v10_live_locked.py --n-per-provider 150
```

### Live locked headline

| Metric | Value |
| --- | ---: |
| AUROC | **1.000** |
| Block-ready auto-block recall | **1.000** (120/120) |
| Naive auto-block recall | **1.000** (this allocation had no incomplete harm cells at n=30) |
| Intervention recall | **1.000** |
| Silent harmful allows | **0** |
| False blocks | **0** |
| Incorrect escrow (block-ready) | **0** |
| Benign score mass | **0.033** (≤0.05) |
| OpenAI prevention | **1.000** |
| xAI prevention | **1.000** |
| Gateway bypasses | **0** |
| Capture failures | **0** |
| Runtime | ~507 s |

### By provider

| Provider | Returned model | n harm | n benign | silent | prevention |
| --- | --- | ---: | ---: | ---: | ---: |
| provider-openai | gpt-4o-mini-2024-07-18 | 30 | 30 | 0 | 1.0 |
| provider-xai | grok-4.3 | 30 | 30 | 0 | 1.0 |

---

## Status board

```text
Blocker architecture repair              DONE
Score geometry (sim)                     DONE
Simulator locked campaign                DONE
0.767 forensic (denominator corrected)   DONE → block-ready recall 1.0
Real HTTP adapters                       DONE
Live plumbing pilots                     PASSED
Live adversarial pilots                  PASSED
Live protocol freeze                     DONE (local receipt)
Independent remote witness               NOT DONE
Live locked dual-model campaign          DONE at 30/30 (integrity PASS)
Full live 150/150 charter                READY TO RUN (same binary)
Production eligibility                   NO
```

---

## Security note

API keys were provided in chat for this session. They must **not** be committed.  
**Rotate both keys** after this evaluation; treat chat-exposed keys as compromised.

---

## What is still required for production / full transfer claim

1. Push freeze tag to independent remote + external witness receipt  
2. Optional: full 150/150 live lock with balanced incomplete cells  
3. Stronger structural holdouts beyond matrix scenarios  
4. Human adjudication / independent replication  
5. Narrow class promotion only after above  

---

## Artifacts

| Path | Role |
| --- | --- |
| `benchmarks/v10_block_recall_forensics.json` | 0.767 denominator audit |
| `benchmarks/v10_live_plumbing_pilot.json` | Live plumbing |
| `benchmarks/v10_live_adversarial_pilot.json` | Live adversarial |
| `benchmarks/v10_live_http_protocol_freeze.json` | Live freeze |
| `benchmarks/v10_live_http_witness_receipt.json` | Local witness |
| `benchmarks/v10_live_locked_results.json` | Live locked summary |
| `src/titan/v10/http_providers.py` | Real HTTP adapters |
