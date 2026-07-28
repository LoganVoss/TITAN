# TITAN V9 roadmap status

> Status as implemented in this repository. “Implemented” means a reference
> contract and regression tests exist; it does not mean the corresponding live
> safety-performance gate has passed.

## Primary objective

TITAN V9 is designed to prevent a consequential agent action from reaching a
protected executor unless the exact pre-action state supports the selected
disposition. The narrow first promotion candidate is a training queue: turn
the broad objective “prepare for future security threats” into the enforceable
question “does this exact training action have independently authenticated
authorization, lineage, provenance, validation, influence, canary-health, and
counterfactual evidence?”

## What V9 now establishes in code

| Roadmap area | Implemented reference contract | Remaining evidence gate |
| --- | --- | --- |
| Artifact integrity | Canonical immutable protocol, typed metric contract, sealed manifest, artifact hashes, completion receipt, conjunctive release evaluator | Externally witnessed freeze, real commit/image hashes, clean independent campaign |
| Evaluation populations | Explicit live, protected-twin, and operational populations; membership and overlap audits; no aggregate-only release | 300 fresh harmful sessions, 10,000 source-matched benign actions, two model families |
| Ground truth | Boundary-only adjudication, separate allow/pause/block labels, two reviewers plus resolver, sealed evidence references | Qualified blinded reviewers and measured agreement |
| Canary control | Coverage graph, composed degradation, replacement-equivalence semantics, canary debt, hard action-boundary conditions | Fresh subtype-complete live campaign meeting per-class floors |
| Safeguard control | Semantic before/after comparison, policy-graph effects, hidden-probe and rollback obligations | Fresh harmful safeguard campaign meeting per-class floors |
| Timing | Event-indexed exclusive prefixes, unresolved-obligation debt, near-horizon hazard, lead-time and prevention metrics | Locked before-harm and action-boundary results at target FPRs |
| Score geometry | Continuous features, deterministic secondary ordering, uncertainty, score-mass and threshold-cliff metrics | Shift-stable live score distribution meeting the ≤5% mass gate |
| Calibration | One-shot sealed calibration split, hierarchical isotonic fallback, Wilson intervals, rank/probability separation | Fresh per-class/shift calibration meeting ECE and Brier gates |
| Evidence integrity | Exact action/state attestations, expiry, identity/key/domain pinning, typed component capabilities, conservative untrusted claims | Isolated verifier services, asymmetric/KMS roots, availability and latency evidence |
| Enforcement | Canonical immutable actions, seven dispositions, two-phase exact-context tokens, fresh state checks, replay rejection, action idempotency | Durable transactional ledgers and an executor reachable only through the gateway |
| Operational integrity | Fail-closed health, bounded ingestion, duplicate/conflict detection, integrity-checked checkpoints, hash-chained audit | Durable HA ingestion, WORM audit, disaster recovery, load/fault testing |
| Release policy | Non-downgradable eligibility rules, per-class/family/subtype gates, raw counts and fixed confidence intervals | Actual locked artifacts and independent attestation satisfying every gate |

## Roadmap phase disposition

- Phases 0–10 now have code-level reference implementations and adversarial
  regression coverage.
- Phases 11–18 are empirical programs. They cannot be truthfully completed by
  adding more local code or synthetic fixtures.
- Phase 19 remains shadow/escrow deployment only.
- Phase 20 must be a separately approved, narrow production promotion for one
  action class. There is intentionally no global “production-ready” switch.

## Promotion order

1. `queue_training`
2. `merge_training_data`
3. canary operations, only after their dedicated campaign
4. safeguard modification, only after fresh harmful live validation
5. broader actions last

The governing optimization target is the roadmap’s maximin principle: improve
the weakest critical, independently validated capability rather than the best
aggregate headline.
