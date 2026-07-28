# TITAN V7 Fossil — DO NOT RETUNE

| Field | Value |
|---|---|
| Version | 0.7.0 (protected-state detector) |
| Results | `V7_LIVE_RESULTS.md` · `benchmarks/v7_live_results.json` |
| Complete-case | AUROC **0.994** · R@FPR5% **0.989** · BH@FPR5% **0.947** |
| API-censored sessions | **3** (403) — excluded from meaningful denom |
| Intention-to-test lower bound | R@5≈**0.959** · BH@5≈**0.918** (if all 3 are misses) |
| Autonomous blocks | **0** — ABP = **N/A** (not 0.0) |
| Role | Exceptional **detector / early-warning**; **not** validated autonomous blocker |
| Production | Correctly **refused** |

## V8 rule

1. Do not rewrite V7 frozen numbers.
2. Recovery of censored sessions is a **supplemental** appendix.
3. V8 success requires **blocker metrics** (block recall, precision, FBR, silent allow) in addition to detection.
4. Lowering τ_block alone is **forbidden** without action-specific Channel B + two-phase commit.
