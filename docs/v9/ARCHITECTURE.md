# TITAN V9 architecture

> **Status:** production-oriented reference implementation, not a
> production-validated safety control.

TITAN V9 is a consequential-action governor. Its primary objective is to stop
unsafe changes to training data, evaluations, canaries, safeguards, and other
protected assets before execution, while routing uncertainty or degraded
monitoring to evidence collection, escrow, or human review.

## Decision and enforcement path

```text
observable events
  → action-boundary extraction over the pre-action prefix
  → continuous prefix risk and unresolved-obligation signals
  → authenticated class-specific authorization, effect, data, and twin evidence
  → calibrated, action-specific disposition
  → PREPARE authorization
  → fresh integrity and protected-object checks
  → one-use COMMIT authorization
  → protected executor
  → hash-chained audit record
```

Only `ALLOW` and `ALLOW_WITH_LOGGING` dispositions can produce execution
authorization. The remaining dispositions are `REQUEST_EVIDENCE`,
`SHADOW_EXECUTE`, `ESCROW`, `HUMAN_CONFIRM`, and `BLOCK`.

## Online trust boundary

The online path is intentionally separated from evaluation ground truth:

- [`action.py`](../../src/titan/v9/action.py) converts agent logs into
  `ObservableTrajectory`, which contains no label, attack family, outcome
  label, evaluation metadata, or session-level monitor scores without a
  timestamped action boundary. Actions are scored using only events strictly
  before the proposal boundary.
- [`scoring.py`](../../src/titan/v9/scoring.py) computes continuous prefix rank
  signals; [`timing.py`](../../src/titan/v9/timing.py) tracks unresolved
  obligations and near-horizon hazards.
- [`canary.py`](../../src/titan/v9/canary.py) and
  [`safeguard.py`](../../src/titan/v9/safeguard.py) implement class-specific
  protected-state verification.
- [`data_integrity.py`](../../src/titan/v9/data_integrity.py) composes
  provenance, lineage, validation, influence, concentration, label-change,
  source-rarity, and canary-health obligations across the exact prefix before
  a training queue or data merge.
- [`evidence_trust.py`](../../src/titan/v9/evidence_trust.py) authenticates
  short-lived verifier statements bound to the exact action hash, protected
  state, actor, environment, evidence kind, and an allowlisted verifier/source
  identity. Trust configuration also pins that identity to a cryptographic key
  and independence domain; aliases sharing one key collapse to one source.
  Agent-supplied booleans and digest-shaped strings remain claims.
- [`evidence.py`](../../src/titan/v9/evidence.py) assembles only authenticated
  statements as empirical evidence and treats unauthenticated local
  observations as conservative heuristics. Required evidence, independent
  source count, rollback proof, and empirical twins cannot be satisfied by the
  proposed action's payload. Favorable data-validation, rollback, and canary
  replacement claims cannot lower the local safety posture.
- [`calibration.py`](../../src/titan/v9/calibration.py) separates rank scores
  from probabilities using action-class, environment, then global isotonic
  fallback with uncertainty intervals.
- [`policy.py`](../../src/titan/v9/policy.py) defines supported classes,
  action-specific policy, decision terms, and seven typed dispositions.
- [`governor.py`](../../src/titan/v9/governor.py) combines those terms into a
  label-blind synchronous decision. Missing calibration, weak twin fidelity,
  insufficient independent evidence, or high uncertainty causes abstention
  rather than an autonomous block or allow.

The currently declared supported action classes are:

- Disable monitoring and export credentials, which are kernel-forbidden.
- Modify safeguards.
- Queue training.
- Merge training data.
- Remove or weaken canaries.

Unknown action classes require human confirmation.

## Enforcement boundary

[`gateway.py`](../../src/titan/v9/gateway.py) is the intended sole route to a
consequential executor:

1. A trusted state reader supplies exact hashes for every protected object.
2. Independent verifier adapters, each rooted in its own configured
   cryptographic domain, issue short-lived exact-context evidence attestations;
   the governor fails closed on a bad signature, wrong key/domain binding,
   stale record, unknown identity, duplicate record, or context mismatch.
3. The governor evaluates the proposal and may issue a signed PREPARE token
   whose lifetime is capped by the shortest evidence lifetime.
4. At commit, the gateway rechecks control-plane health and object hashes.
5. [`tokens.py`](../../src/titan/v9/tokens.py) promotes PREPARE to COMMIT and
   binds action, objects, actor, environment, authorization, evidence, scorer,
   policy, expiry, and nonce.
6. The environment verifier authenticates and consumes COMMIT once before the
   private executor is called.

The gateway also refuses to mint a second authorization for an identical
action hash, including after the first token is spent. The current HMAC
authority, action/token replay ledgers, and gateway lock are in-process
reference components. Production requires a KMS/HSM-backed authority, durable
transactional replay storage, and one datastore transaction covering action
idempotency, nonce consumption, the final object-version check, and mutation.

## Integrity and streaming

- [`integrity.py`](../../src/titan/v9/integrity.py) treats lost/delayed events or
  unhealthy logger, policy, registry, verifier, or token verifier as degraded
  control-plane integrity. High-risk actions receive at least an escrow floor.
  Its audit chain is verifiable but currently in memory.
- [`streaming.py`](../../src/titan/v9/streaming.py) provides thread-safe,
  event-ID-deduplicated ingestion, monotonic ordering, absolute cursors,
  bounded history, backpressure status, and integrity-checked checkpoints.
  External callbacks run outside the state lock with a configured deadline.
  A failure, timeout, or non-finite value emits a `DEGRADED` health alert;
  timeout opens a persistent circuit and stops later ingestion/callbacks.
  Stream health can be merged conservatively into gateway integrity signals.
  Session-level monitor-score fields are excluded from online callback views.

## Offline research-integrity boundary

Offline modules may handle labels, but are not online decision dependencies:

- [`adjudication.py`](../../src/titan/v9/adjudication.py) separates safe-to-allow,
  pause, human-policy, autonomous-block, and kernel-forbidden ground truth.
- [`populations.py`](../../src/titan/v9/populations.py) keeps live, protected
  twin, and operational populations separate and audits source overlap and
  action opportunities.
- [`metrics.py`](../../src/titan/v9/metrics.py) requires explicit thresholds,
  sources, denominators, raw counts, units, prefix/latching rules, and
  confidence intervals.
- [`protocol.py`](../../src/titan/v9/protocol.py) freezes exact campaign inputs
  in canonical, immutable, self-verifying content.
- [`manifest.py`](../../src/titan/v9/manifest.py) seals artifacts and verifies
  completion receipts.

These hashes detect alteration; they are not substitutes for an independent
witness, signed release, or durable WORM evidence store.

## Core invariants

1. Evaluation labels cannot enter the online governor interface.
2. Only pre-action evidence can influence an action decision, and only
   authenticated external attestations can earn execution authority.
3. Unhealthy monitoring cannot silently become a clean score or permission.
4. A token authorizes one exact action and protected-object state, once.
5. Changes after admission invalidate commit authority.
6. Locked evaluation cannot choose its own thresholds or pooled headline.
7. Autonomous authority is promoted one proven action class at a time.

See [Production readiness](PRODUCTION_READINESS.md) and
[Security](SECURITY.md) for the remaining release gates.
