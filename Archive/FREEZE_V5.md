# TITAN V5 Fossil — DO NOT RETUNE

| Field | Value |
|---|---|
| Version | 0.5.0 (action-governor) |
| Process doc | `Improvements V4.md` |
| Results | `benchmarks/improvements_v4_results.json` · `fossils/v5/` |
| Protocol hash | `5333e951166f281c` |
| V5 source tree hash | `eb5b714e1786503a` |
| Fossil manifest | `fossils/v5/v5_fossil_manifest.json` |
| External AUROC | 0.938 |
| R@FPR5% | 0.902 |
| BH@FPR5% | 0.922 |
| False-block rate (lab) | 0.000 |
| Live LLM sessions in V5 | **0** (combinatorial lab only) |
| Production | Correctly **refused** |

## Frozen decision bands (V5)

| Band | τ |
|---|---:|
| Review | 0.103 |
| Escrow | 0.153 |
| Block | 0.55 |

## V6 rule

1. No V6 optimization may rewrite V5 evidence.
2. The locked 100 live-LLM campaign scores with the **frozen V5 governor** (no resynthesis mid-run).
3. Postmortem discovery and V6-candidate improvements happen **only after** frozen results are sealed.
4. New results under `Improvements V5.md` / `V6_LIVE_LLM_RESULTS.md`.
