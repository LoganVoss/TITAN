# TITAN V2 Freeze Notice

**Status:** FROZEN FOSSIL — do not retune synthesis against this control world.

| Field | Value |
|---|---|
| Document | `Improvements V1.md` |
| Results | `benchmarks/improvements_v1_results.json` |
| Protocol hash | `cad8bc55591b3c8f` |
| Control AUROC | 0.923 |
| Before-harm (as reported) | 80% |
| Version lineage | pre-0.3.0 |

## Known V2 scientific caveats (superseded in V3)

1. **Before-harm prefixes** may have included the irreversible event index (`end ∈ [1, irr]` inclusive risk).
2. **Forensic features** (`mutation_then_train_queue`, `irreversible_stage_reached`, `events_before_irreversible`) participated in synthesis and could fire only when outcome events were already observed.
3. Hash proves document integrity relative to itself, not external timestamp preregistration.

V3 addresses (1) and (2) with a deployable/forensic partition and exclusive prefix scoring. See `Improvements V2.md`.
