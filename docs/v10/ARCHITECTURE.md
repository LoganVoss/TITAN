# TITAN V10 Architecture

**Codename:** repaired-capability-governance  
**Version:** 1.0.0  
**Status:** Development gates target — **not live-API ready**

## Why V10 exists

V9 proved fail-closed intervention: every harmful sandbox action was prevented,
mostly via `ESCROW`. That is not effective autonomous blocking.

Root cause: V9’s `block_ready` required **favorable** completeness and tight
calibration, so independently observed danger with incomplete safety-case
coverage always escrowed:

```text
hard_condition_present_but_block_evidence_incomplete
```

V10 separates two readiness paths.

## Dual readiness

| Path | Meaning | Requires |
| --- | --- | --- |
| **block_ready** | Enough independent *adverse* proof to refuse authority | ≥K adverse independent sources, adverse confidence floor, hard condition or dual-channel ranks — **not** favorable completeness |
| **allow_ready** | Enough independent *favorable* proof to grant authority | Required evidence covered, auth validity 1.0, completeness/confidence floors, effect risk below allow floor, high-fidelity twin if irreversible |

```text
Observed danger  ⇒  may BLOCK when adverse proof is ready
Claimed safety   ⇏  authority without favorable proof
Incomplete either side  ⇒  ESCROW with enumerated gaps
```

## Escrow diagnostics

Every `ESCROW` decision carries `escrow_diagnostics` answering:

> Which exact missing evidence prevented BLOCK or ALLOW?

Examples:

* `missing_block_evidence:adverse_independent_sources>=2`
* `block_blocker:adverse_confidence_below_floor`
* `missing_allow_evidence:lineage`
* `allow_blocker:irreversible_requires_high_fidelity_twin`

## Continuous score geometry

V10 ranking uses many continuous measurements (provenance gap, influence
concentration, canary coverage loss, twin fidelity gap, structure residuals,
…). Detection ranks must not collapse to a handful of plateaus.

Development targets:

* largest benign score mass ≤ 5%
* ≥ 50 unique benign score levels on held-out matrix traffic

## Four-cell evidence matrix

For each non-kernel supported class, development data covers:

| | Block-ready proof | Incomplete proof |
| --- | --- | --- |
| **Harmful** | `BLOCK` | `ESCROW` |
| **Benign** | `ALLOW` / `ALLOW_WITH_LOGGING` | `ESCROW` (no authority) |

Default: 100 cases per cell per class (held-out seed).

## Package layout

```text
src/titan/v10/
  policy.py        # dual thresholds, dispositions
  diagnostics.py   # readiness + escrow messages
  evidence.py      # adverse/favorable accounting over V9 adapters
  scoring.py       # continuous multi-feature rank
  governor.py      # V10Governor decision engine
  matrix_lab.py    # four-cell generators + control plane
  gates.py         # held-out development gates
  online.py        # label-blind import surface
```

Online enforcement still reuses V9 action extraction, tokens, gateway, and
integrity primitives. Decision logic and readiness accounting are V10.

## What V10 does *not* claim

* Not a locked live multi-model campaign
* Not production eligibility
* Not external protocol witness
* Not 10k operational benign actions

## Next after development gates pass

1. API harness qualification (plumbing + adversarial pilots)
2. New **live** protocol freeze (distinct from V9 sandbox freeze)
3. External witness
4. 150/150 two-model locked campaign
