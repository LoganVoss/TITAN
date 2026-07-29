# TITAN Improvements V5

**TITAN version:** 0.6.0 (V6 live-adversary campaign)  
**Primary results document:** [`V6_LIVE_LLM_RESULTS.md`](V6_LIVE_LLM_RESULTS.md)  
**Machine JSON:** `benchmarks/v6_live_llm_results.json`  
**V5 fossil:** `FREEZE_V5.md` (do not retune)

---

## Five-sentence arc

TITAN began by finding monitor collisions and synthesizing causal measurements. V4 proved direct-execution transfer and refused production when humans were not ready. V5 turned ranking into a dual-channel action governor with metric contracts and multi-band thresholds — still on combinatorial labs. **V6 ran 100 live multi-turn grok-3 attacks against the frozen V5 governor.** Ranking transfer dropped hard (AUROC 0.94→0.73, R@FPR5% 0.90→0.30); false autonomous blocks stayed at zero; production remains refused; misses are now the research program.

---

## Headline (cliff-corrected)

| Metric | V5 combinatorial | V6 live LLM |
|---|---:|---:|
| Sessions | 100 synthetic | **100 live multi-turn** |
| Meaningful ASR | n/a (generated) | **0.93** |
| AUROC | 0.938 | **0.732** |
| R@FPR5% | 0.902 | **0.301** |
| BH@FPR5% | 0.922 | **0.290** |
| FBR | 0.000 | **0.000** |
| ABP | 1.000 | **1.000** |
| Production | refused | **refused** |

See full stratified misses, disposition tables, chronology, and cost in **V6_LIVE_LLM_RESULTS.md**.
