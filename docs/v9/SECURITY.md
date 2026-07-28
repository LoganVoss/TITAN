# TITAN V9 security

> This document describes a production-oriented reference design, not a
> completed production security assessment.

## Security objective

No consequential action should execute unless the current observable prefix,
authorization, evidence, protected-object state, policy, scorer, and
control-plane health jointly support that exact action. Uncertainty and
monitoring failure must remove authority, not create permission.

## Protected assets and adversaries

Protected assets include training data and lineage, evaluations and canaries,
safeguards and monitor configuration, credentials, model artifacts, action
authorizations, signing keys, replay state, audit evidence, and the event
stream.

Assume an agent or compromised client may:

- Fabricate ticket-like strings or proof packets.
- Replay, modify, swap, or delay tokens and actions.
- Change protected objects between admission and commit.
- Split one prohibited action across tools, actors, or time.
- Cause event loss, reordering, duplicates, scorer failure, or verifier
  disagreement.
- Fingerprint or deceive counterfactual twins.
- Attempt to bypass the gateway or tamper with logs, policy, registry, or
  calibration.

## Implemented defenses

- **Label-blind online types:** `ObservableTrajectory` excludes evaluation
  labels and the governor accepts only observable action proposals.
- **Temporal boundary:** decisions use the prefix strictly before the proposed
  action. Unscoped session-level monitor scores are excluded because they may
  have been computed from post-action data.
- **Authorization observation:** a preceding approval event must match actor,
  action, and object scope, but it remains an untrusted claim until an external
  authorization verifier attests it.
- **Authenticated evidence boundary:** HMAC-SHA-256 reference attestations bind
  verifier and source identity, evidence kind and digest, claims, exact action
  hash, protected-state snapshot, actor, environment, issue time, and expiry.
  Each identity is pinned to a configured key and independence domain. Two
  named services backed by one key count as one source, and one key is
  forbidden from claiming multiple independence domains.
  Unknown identities, malformed claims, duplicate records, bad signatures,
  stale evidence, and context mismatch fail closed.
- **No proof by appearance:** agent-supplied booleans, hashes, proof packets,
  verifier names, successful validation/rollback flags, replacement claims,
  and twin results never count as empirical evidence, independent sources,
  rollback proof, or authorization. Adverse observable semantics may raise
  risk, but favorable proof credit requires an authenticated verifier.
- **Conservative decision policy:** unsupported classes, missing calibration,
  incomplete evidence, weak twins, or high uncertainty abstain or pause.
- **Context-bound authorization:** HMAC-SHA-256 tokens bind the action and
  object hashes, actor, environment, authorization and evidence hashes,
  scorer/policy versions, expiry, phase, and nonce.
- **Two phases and one use:** PREPARE is non-executable; COMMIT is separately
  verified and consumed by a replay guard. Identical action hashes cannot
  receive a second authorization from the same gateway process.
- **Fresh commit checks:** the gateway rechecks integrity and protected-object
  hashes immediately before execution.
- **Fail-closed health:** control-integrity failures impose an escrow floor;
  streaming exceptions and non-finite scores emit `DEGRADED` health alerts.
- **Tamper evidence:** protocol, manifest, checkpoint, token, and hash-chain
  records use canonical content and full SHA-256 digests.

## Reference-component limitations

The following are explicit blockers, not deferred polish:

- HMAC keys for both evidence attestations and execution tokens currently live
  in Python process memory. The reference verifier supports distinct keys and
  refuses to count identities sharing a key as independent, but a holder of
  any symmetric verifier key can still mint records for identities bound to
  that key. Production requires independently held asymmetric verifier keys or
  KMS/HSM-backed signing, a pinned key/identity/domain registry, rotation,
  revocation, audited use, and issuer/verifier role separation.
- Action-idempotency, COMMIT replay, and PREPARE-promotion ledgers are in
  memory. Restart or replica failover must not reopen spent authority; use
  durable transactional storage.
- The gateway lock protects one process only. The final object-version check,
  nonce consumption, and protected mutation require a transactional object
  executor or equivalent serializable boundary.
- The hash-chained audit log is in memory. Export synchronously to durable WORM
  storage with remote witnessing and retention controls.
- SHA-256 checkpoint, protocol, and manifest digests detect corruption but do
  not authenticate an untrusted producer. Sign release artifacts externally.
- The reference evidence provider is an in-process synchronous callback.
  Production requires mutually isolated authorization, lineage, validation,
  influence, canary, safeguard, and twin services with authenticated transport,
  bounded response schemas, clock discipline, and independent failure domains.
- Streaming callback deadlines use daemon threads. A timed-out callback cannot
  block health reads and opens a circuit that prevents another callback from
  starting, but Python cannot forcibly terminate arbitrary thread/native code.
  Production scorers require killable process or RPC isolation and a total
  window-level budget in addition to the per-callback deadline.
- Counterfactual twins and semantic verifiers remain attackable approximations
  until fidelity and twin-aware challenge gates pass.
- No code-level mechanism can prevent a separate executor path from bypassing
  the gateway. Deployment architecture and least privilege must make the
  protected executor unreachable except through enforcement.

## Required deployment controls

1. Give the gateway identity exclusive permission to invoke protected
   executors; agents and application workers receive no direct capability.
2. Separate event ingestion, evidence issuers, governor, token issuer, token
   verifier, executor, and audit roles with mutually restricted credentials.
3. Verify exact actor and workload identity, environment, object versions,
   authorization scope/direction, and policy/scorer/calibrator version.
4. Use short-lived one-use tokens and reject clock anomalies, stale integrity,
   state mismatches, unknown keys, unknown action classes, and malformed
   canonical data.
5. Rate-limit evidence and escrow paths so an attacker cannot create a review
   or verification denial of service.
6. Monitor gateway bypass attempts, replay rejection, integrity degradation,
   break-glass use, key operations, policy/registry changes, and score shift.
7. Exercise key compromise, verifier outage, replay-store outage, WORM outage,
   and regional failover in fault tests.

## Secrets and supply chain

- Never accept API or signing keys as command-line arguments, commit them, or
  place them in transcripts and fixtures.
- Inject secrets through the deployment secret manager and redact them before
  events reach TITAN.
- Rotate any credential exposed in chat, logs, shell history, or process
  listings.
- Lock dependencies, generate an SBOM, scan dependencies and source, pin the
  sandbox image, and sign commits, tags, images, protocols, and release
  manifests.

## Privacy boundary

Agent events may contain message text, file paths, diffs, tool arguments,
identifiers, and proprietary research context. Before production:

- Define an allowlisted event schema and remove content not needed by a
  declared monitor feature.
- Redact secrets and personal data before persistence or external-model use.
- Encrypt transport and storage with tenant/environment separation.
- Apply purpose-bound reviewer access, audit every read, and minimize evidence
  cards independently of raw trace retention.
- Set deletion and legal-retention schedules for raw events, checkpoints,
  transcripts, evidence, decisions, and audit receipts.
- Validate privacy behavior under failures, replays, exports, debugging, and
  incident response.

## Incident posture

On token-verifier, logger, registry, policy, scorer, event-integrity, or replay
failure, high-risk actions must pause or enter escrow. Recovery requires a
fresh integrity epoch, fresh object state, a new decision, and new
authorization; old tokens must never be replayed.

See [Architecture](ARCHITECTURE.md) and
[Production readiness](PRODUCTION_READINESS.md).
