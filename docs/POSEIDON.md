# POSEIDON attachment

TITAN's POSEIDON attachment is a **TITAN-owned, shadow-only evidence adapter**. It lets TITAN inspect observations synthesized by POSEIDON without transferring any part of TITAN's authorization function to POSEIDON.

POSEIDON discovers attack-sensitive, nuisance-invariant observables and distributes them as signed, versioned monitor packages. TITAN remains the control plane: its KPI is authorized-action safety, utility, and gateway integrity, and its frozen readiness and PREPARE/COMMIT rules remain unchanged.

## Attachment flow

```text
signed POSEIDON package + signed runtime attestation
                         ↓
              verify signatures and bindings
                         ↓
            project the exact pre-action prefix
                         ↓
       bind action + state + actor + environment
                         ↓
          emit native poseidon_observation evidence
                         ↓
                    shadow record only
```

The adapter verifies both signed artifacts before translating anything. It accepts only the trace prefix that existed before the proposed action, so post-action information cannot leak into pre-action evidence. The translated record is bound to:

- the exact proposed action;
- the state snapshot evaluated by TITAN;
- the actor requesting authority;
- the execution environment; and
- the verified POSEIDON package and attestation identities.

The result is emitted through TITAN's native evidence vocabulary as `poseidon_observation`. Integration uses immutable signed artifacts and attestations rather than shared mutable code or POSEIDON internals.

## Install and call the attachment

Ed25519 verification is an optional dependency so TITAN's default runtime stays
unchanged:

```bash
pip install -e ".[poseidon]"
```

The API is deliberately two-stage. TITAN first creates the exact request; the
caller gives its `trace`, `nonce`, and `runtime_context` to a POSEIDON runtime;
then TITAN binds the returned bridge document:

```python
request = attachment.prepare(trajectory, proposal)

# Evaluate request.trace in an approved POSEIDON runtime using:
#   nonce=request.nonce
#   context=request.runtime_context
bridge_json = approved_poseidon_runtime(request)

result = attachment.bind(request, proposal, bridge_json)
if result.accepted:
    shadow_audit_store.append(result.evidence)
else:
    shadow_audit_store.append(result.receipt)
```

The trust policy pins exact release keys, runtime key/identity/domain tuples,
package digest, observable identity, prefix domain, ABI, freshness limits, and
revocations. The frozen mapping has one output kind: `poseidon_observation`,
with `passed=None`, no verified readiness components, and zero TITAN confidence.
Full signed artifacts belong in the audit store; the native attestation carries
their digests and provenance.

## Authority boundary

`poseidon_observation` is **observational, not dispositive**. In the current attachment it cannot:

- satisfy allow-readiness or block-readiness;
- produce or alter ALLOW, BLOCK, or ESCROW;
- grant authority to an actor;
- mint PREPARE or COMMIT; or
- bypass state recheck, transport certification, or the protected executor.

Malformed, unverifiable, stale, mismatched, or post-action inputs fail closed as attachment inputs: they do not become trusted evidence, and their absence does not relax TITAN's existing requirements.

## Why shadow-only

Shadow mode establishes the integration contract and creates an auditable record for later evaluation while leaving TITAN's demonstrated control constitution untouched. It supports measurement of whether POSEIDON observations add prospective signal, survive nuisance and transfer gates, and remain correctly bound in real TITAN workflows.

Mapping a POSEIDON observation into decision-bearing readiness would change TITAN's safety case. That mapping is intentionally **not part of this attachment**. It is future work requiring its own threat model, sealed evaluation, failure analysis, compatibility review, and explicit approval before any readiness or disposition path may consume it.
