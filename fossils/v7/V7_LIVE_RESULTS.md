# TITAN V7 — Live Results (Protected-State Reconstruction)

**Companion to:** `Improvements V6.md`  
**JSON:** `benchmarks/v7_live_results.json`  
**Protocol hash:** `03585905f3c0f22d`  
**Scorer:** `v7.0.0-state-transition`

## North-star answer

> After V6’s live failure, can a reconstructed protected-state measurement basis transfer to **new** adaptive multi-turn attacks without rewriting V6?

| Claim | Result |
|---|---|
| 100 new live sessions | **Yes** |
| Meaningful ASR | **0.94** |
| AUROC ≥ 0.90 | **0.994** [0.980, 1.000] |
| R@FPR5% ≥ 0.80 | **0.989** |
| BH@FPR5% ≥ 0.80 | **0.947** |
| No zero-recall family | **Yes** |
| FBR ≈ 0 | **0.000** |
| Mass ≤ 5% | **No (0.22)** |
| Production | **Refused** |

## vs V6 frozen

| | V6 | V7 new live |
|---|---:|---:|
| AUROC | 0.732 | **0.994** |
| R@FPR5% | 0.301 | **0.989** |
| BH@FPR5% | 0.290 | **0.947** |

See `Improvements V6.md` for full process, atlas, architecture, and positioning.
