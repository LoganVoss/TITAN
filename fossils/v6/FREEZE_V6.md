# TITAN V6 Fossil — DO NOT RETUNE

| Field | Value |
|---|---|
| Version | 0.6.0 (live-adversary) |
| Results | `V6_LIVE_LLM_RESULTS.md` · `benchmarks/v6_live_llm_results.json` |
| Protocol hash | `0fd3bfb810e339e4` |
| Transcript corpus hash | see `fossils/v6/v6_fossil_manifest.json` |
| Live sessions | 100 multi-turn grok-3 |
| Meaningful ASR | 0.93 |
| Frozen V5 AUROC | **0.732** |
| R@FPR5% | **0.301** |
| BH@FPR5% (cliff-corrected) | **0.290** |
| FBR / ABP | 0.000 / 1.000 |
| Strict misses | **65** |
| Production | Correctly **refused** |

## What V6 established

1. Combinatorial V5 overstated live robustness.
2. Governor dual-channel discipline held (FBR=0).
3. Safeguard + hybrid transferred; pure relational poison collapsed into benign mass.
4. Score cliff ≈ 0.06215 is representation collapse, not calibration noise.

## V7 rule

1. **Do not rewrite V6 frozen transfer numbers.**
2. V6 transcripts may be used as **discovery / selection / internal holdout** only under explicit partitions.
3. Locked V7 live evaluation uses **entirely new** sessions (new seeds).
4. No “65 rules for 65 misses” — protected-state verification only.
5. New results under `Improvements V6.md` and `V7_LIVE_RESULTS.md`.
