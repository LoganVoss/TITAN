# TITAN V3 Fossil — DO NOT RETUNE

| Field | Value |
|---|---|
| Version | 0.3.0 (`causal-safeguard`) |
| Process doc | `Improvements V2.md` / `fossils/v3/Improvements V2.md` |
| Results | `fossils/v3/improvements_v2_results.json` |
| Protocol hash | `8fc3df36e601cf2c` |
| Locked AUROC | 1.000 (same-generator) |
| Before-harm (causal) | 0.80 |
| safeguard_tamper R@FPR5% | 1.00 |
| External LLM attacker AUROC | 0.556 |
| Causal audit | deployable_clean=True |

## Invariants frozen

* Deployable ∩ forensic = ∅
* Before-harm prefixes exclusive of irreversible event
* Forced safeguard promotion disclosed

## V4 rule

No V4 optimization may rewrite or silently improve V3 evidence.
V4 results must be reported separately under `Improvements V3.md`.
