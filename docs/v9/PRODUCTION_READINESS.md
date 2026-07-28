# TITAN V9 production readiness

> TITAN V9 is a production-oriented reference implementation. It is **not
> production-validated**, and its current outputs must not authorize real
> consequential actions without the external controls and gates below.

## What the implementation establishes

The V9 codebase now contains enforceable design contracts for:

- Label-blind, pre-action decisions.
- Seven dispositions with conservative abstention.
- Class-specific canary and safeguard verification.
- Continuous prefix hazard, evidence acquisition, and hierarchical
  calibration.
- Short-lived evidence attestations bound to the exact action/state context and
  allowlisted verifier/source/key/domain identities; untrusted
  evidence-shaped payloads cannot satisfy release or execution requirements,
  and aliases sharing one key cannot manufacture independent-source count.
- Signed, context-bound PREPARE/COMMIT tokens with one-use verification.
- Fresh object-state and control-integrity checks at the gateway.
- Fail-closed streaming with bounded callback deadlines, a persistent timeout
  circuit, gateway-health integration, and durable integrity-checked
  checkpoints.
- Typed metric records, separated evaluation populations, blinded
  adjudication records, immutable protocols, sealed manifests, and completion
  receipts.

CI compiles and tests the package on Python 3.9–3.12. Passing CI establishes
implementation consistency only; it does not establish safety performance.

## Release gates

All gates are conjunctive. A strong aggregate score cannot compensate for a
weak critical slice.

### External locked evaluation

- At least 300 new meaningful harmful sessions across two frontier model
  families, with frozen TITAN and no model-specific retuning.
- At least 10,000 source-matched benign consequential actions using the same
  models, harnesses, repositories, turn budgets, friction, and action
  opportunities.
- Separate published results for:
  - Evaluation A: pure source-matched live harmful and benign sessions.
  - Evaluation B: protected benign twins.
  - Evaluation C: the declared operational workload mixture.
- No untested supported family or action class and no critical slice hidden by
  aggregation.
- Thresholds and calibration frozen before locked evaluation.
- Target gates from the V9 roadmap, including detection, timing, per-class
  blocking, false-block, score-resolution, calibration, and autonomous-coverage
  floors.

### Human and independent validation

- Blinded expert adjudication with at least two independent reviewers and a
  third reviewer for disagreement.
- Agreement and evidence-attribution targets met separately for autonomous
  block and human-confirm zones.
- Independently witnessed protocol freeze.
- Independent execution and replication of the sealed campaign.
- Reproduction from a clean, dependency-locked environment with a successful
  zero-traceback completion receipt.

### Enforcement infrastructure

- KMS/HSM-backed signing authority with key rotation, revocation, separation of
  issuer and verifier roles, and audited access.
- Durable transactional action-idempotency and token replay protection across
  restarts and replicas.
- Protected-object version check and executor mutation in the same datastore
  transaction. The current in-process gateway lock is insufficient.
- Durable replayable event ingestion with idempotency across failover.
- Audit records exported to access-controlled WORM storage and independently
  witnessed. The in-memory hash chain is insufficient.
- High availability, disaster recovery, rollback, safe deployment, and
  break-glass procedures tested.

### Reliability and performance

- Load tests for sustained and burst throughput, queue saturation, and bounded
  memory.
- p50, p95, and p99 decision and evidence-acquisition latency measured against
  each action deadline.
- Fault injection covering scorer/verifier failure, partial logging, duplicate
  and reordered events, stale integrity, state races, network partitions,
  checkpoint corruption, restart, and regional failover.
- Deterministic replay from the durable log and reconciliation of every
  disposition, token, executor receipt, and audit record.

### Security and privacy

- Threat model and penetration testing for token theft/forgery/replay,
  capability confusion, gateway bypass, action splitting, object swapping,
  time-of-check/time-of-use races, twin-aware attacks, and control-plane
  compromise.
- Dependency lock, SBOM, vulnerability and secret scanning, signed releases,
  sandbox image provenance, and least-privilege deployment.
- Data inventory, minimization and redaction before ingestion, encryption,
  retention/deletion policy, reviewer access controls, and external-model
  context restrictions.
- Privacy and abuse reviews on representative production-like traces.

## Legacy V8 evidence policy

V8 results remain useful for hypothesis generation and regression fixtures,
but are **non-release evidence** for V9:

- V8 selected operating thresholds using the locked evaluation population.
- V8 online/action compilation paths included ground-truth-label-adjacent and
  direct label-dependent logic.
- Some V8 blocker counters could count non-block-worthy harmful blocks or
  escrows in favorable numerators.
- V8 protocol identity and artifact chronology were not a clean V9-quality
  freeze.

Therefore V8 headline metrics must not seed V9 calibration, select V9
thresholds, satisfy a V9 release gate, or be described as independent locked
evidence. Preserve them as post-hoc development evidence.

## Promotion sequence

1. Run V9 in replay and shadow mode with no execution authority.
2. Validate evidence requests and reversible twin execution.
3. Enable escrow, still without permanent denial.
4. Promote `queue_training` only after its own external gates pass.
5. Promote `merge_training_data` independently.
6. Promote canary and safeguard classes only after their dedicated live
   campaigns pass.
7. Keep unsupported and weakly validated classes on human confirmation.

Production approval should be an explicit, signed artifact that names the
action class, policy/scorer/calibrator versions, environment, expiry, rollback
owner, and evidence bundle. There is no global “TITAN is production-ready”
shortcut.
