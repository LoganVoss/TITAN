"""Adversarial tests for TITAN's signed, shadow-only POSEIDON attachment.

The fixtures intentionally implement the POSEIDON wire format locally.  They
do not import POSEIDON, so a shared serializer or verifier cannot make both
sides agree on the same mistake.
"""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan.integrations.poseidon import (
    POSEIDON_SHADOW_EVIDENCE_KIND,
    TITAN_POSEIDON_BINDER_ID,
    PoseidonAttachment,
    PoseidonRuntimeBinding,
    PoseidonShadowMapping,
    PoseidonTrustPolicy,
)
from titan.schema import EventType
from titan.v9.action import (
    ObservableEvent,
    ObservableTrajectory,
    action_prefix,
    extract_action_proposals,
)
from titan.v9.evidence import REQUIREMENT_EVIDENCE_KINDS, acquire_evidence
from titan.v9.evidence_trust import (
    EvidenceAttestationAuthority,
    EvidenceAttestationVerifier,
)
from titan.v9.policy import policy_for as v9_policy_for
from titan.v9.tokens import canonical_json_bytes
from titan.v10.diagnostics import build_readiness_report, disposition_from_readiness
from titan.v10.policy import BLOCK_ADVERSE_KINDS
from titan.v10.policy import policy_for as v10_policy_for

NOW_MS = 1_800_000_000_000
RELEASE_KEY_ID = "poseidon-release-test-v1"
RUNTIME_KEY_ID = "poseidon-runtime-test-v1"
RUNTIME_ID = "poseidon-reference-runtime-v1"
RUNTIME_DOMAIN = "poseidon-test-independent-runtime"
BINDER_KEY_ID = "titan-poseidon-binder-test-v1"
BINDER_SECRET = b"titan-poseidon-native-binder-test-secret-v1"
SOURCE_ID = "poseidon-shadow-source"
PACKAGE_CONTEXT = b"POSEIDON:ObservablePackage:v1\x00"
ATTESTATION_CONTEXT = b"POSEIDON:ObservableAttestation:v1\x00"
POSEIDON_ABI = "poseidon.observation/v1"
TRACE_SCHEMA = "poseidon://trace/v1"
BRIDGE_SCHEMA = "poseidon://integration/titan-observation/v1"
BRIDGE_MESSAGE = "poseidon.observable_attestation"
REQUIRED_GATES = (
    "contract_validity",
    "nuisance_invariance",
    "protected_sensitivity",
    "replay_stability",
    "bounded_complexity",
    "environment_transfer",
    "prospective_locked_holdout",
)


class Clock:
    def __init__(self, value: int = NOW_MS) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _private(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _iso(timestamp_ms: int) -> str:
    return (
        datetime.fromtimestamp(timestamp_ms / 1_000, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _signed(
    payload_name: str,
    payload: Mapping[str, Any],
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
    context: bytes,
) -> dict[str, Any]:
    material = deepcopy(dict(payload))
    return {
        payload_name: material,
        "key_id": key_id,
        "algorithm": "Ed25519",
        "signature": _b64url(
            private_key.sign(context + canonical_json_bytes(material))
        ),
    }


def _trajectory_and_proposal():
    prefix_event = ObservableEvent(
        event_type=EventType.MESSAGE,
        timestamp=1_799_999_998.0,
        actor="agent",
        payload={"role": "user", "content": "queue the approved training run"},
        event_id="prefix-message",
        sequence=0,
    )
    proposal_event = ObservableEvent(
        event_type=EventType.TOOL_CALL,
        timestamp=1_799_999_999.0,
        actor="agent",
        payload={
            "tool": "queue_training",
            "objects": ["training_pipeline"],
            "purpose": "test exact shadow attachment",
        },
        event_id="proposal-tool-call",
        sequence=1,
    )
    trajectory = ObservableTrajectory(
        trajectory_id="poseidon-attachment-trajectory",
        events=(prefix_event, proposal_event),
        model_version="test-model-v1",
        environment="integration-test",
        task_family="agent-governance",
    )
    proposal = extract_action_proposals(trajectory)[0]
    return trajectory, proposal


@dataclass
class Scenario:
    clock: Clock
    release_private: Ed25519PrivateKey
    runtime_private: Ed25519PrivateKey
    package: dict[str, Any]
    package_digest: str
    mapping: PoseidonShadowMapping
    trust_policy: PoseidonTrustPolicy
    native_authority: EvidenceAttestationAuthority
    attachment: PoseidonAttachment
    trajectory: ObservableTrajectory
    proposal: Any


def _make_policy(
    scenario: Scenario,
    *,
    revoked_package_digests=(),
    revoked_attestation_digests=(),
    revoked_key_ids=(),
) -> PoseidonTrustPolicy:
    return PoseidonTrustPolicy(
        release_public_keys={RELEASE_KEY_ID: _public(scenario.release_private)},
        runtime_bindings=(
            PoseidonRuntimeBinding(
                key_id=RUNTIME_KEY_ID,
                public_key=_public(scenario.runtime_private),
                runtime_id=RUNTIME_ID,
                independence_domain=RUNTIME_DOMAIN,
            ),
        ),
        revoked_package_digests=tuple(revoked_package_digests),
        revoked_attestation_digests=tuple(revoked_attestation_digests),
        revoked_key_ids=tuple(revoked_key_ids),
        maximum_attestation_ttl_ms=5_000,
    )


def _make_attachment(
    scenario: Scenario,
    *,
    trust_policy: Optional[PoseidonTrustPolicy] = None,
    nonce: str = "exact-titan-challenge-nonce",
) -> PoseidonAttachment:
    return PoseidonAttachment(
        trust_policy=trust_policy or scenario.trust_policy,
        mapping=scenario.mapping,
        native_authority=scenario.native_authority,
        clock_ms=scenario.clock,
        nonce_factory=lambda: nonce,
        request_ttl_ms=5_000,
    )


def _scenario(*, package_expires_at_ms: int = NOW_MS + 60_000) -> Scenario:
    release_private = _private(1)
    runtime_private = _private(2)
    nuisance_contracts = [
        {
            "contract_id": "presentation-reordering",
            "version": "1.0.0",
            "domain": "ai-instruction-flow",
            "transformations": [
                {
                    "transformation_id": "equivalent-field-order",
                    "operator": "field_reorder",
                    "description": "Reorder equivalent trace presentation fields.",
                    "parameters": {},
                    "applies_to": ["events.payload"],
                }
            ],
            "protected_fields": ["events.payload.role"],
            "metadata": {"fixture": True},
        }
    ]
    nuisance_commitment = _sha256(
        sorted(
            nuisance_contracts,
            key=lambda item: "%s@%s" % (item["contract_id"], item["version"]),
        )
    )
    gates = []
    for name in REQUIRED_GATES:
        gate = {
            "name": name,
            "status": "pass",
            "metric": 1.0,
            "threshold": "fixture-threshold",
            "details": {},
        }
        if name == "nuisance_invariance":
            gate["details"] = {"nuisance_contract_commitment": nuisance_commitment}
        gates.append(gate)
    manifest = {
        "package_id": "poseidon.test-observable",
        "package_version": "1.0.0",
        "issuer": "poseidon-test-release",
        "created_at": _iso(NOW_MS - 60_000),
        "expires_at": _iso(package_expires_at_ms),
        "abi_version": POSEIDON_ABI,
        "observable": {
            "observable_id": "poseidon.test.attack-sensitive-count",
            "version": "1.0.0",
            "name": "Attack-sensitive count",
            "description": "A deterministic integration-test observation.",
            "abi_version": POSEIDON_ABI,
            "input_schema_uri": TRACE_SCHEMA,
            "output_type": "float",
            "temporal_scope": "prefix",
            "missingness": "abstain",
            "domains": ["ai-instruction-flow"],
            "required_fields": ["event_count"],
            "nuisance_contract_ids": ["presentation-reordering@1.0.0"],
            "sensitivity_targets": ["integration-test"],
            "runtime_budget_ms": 10.0,
            "memory_budget_mb": 16.0,
            "privacy_classification": "synthetic",
            "metadata": {"artifact_semantics": "observation"},
        },
        "implementation_kind": "poseidon-ir/v1",
        "implementation": {
            "observable_id": "poseidon.test.attack-sensitive-count",
            "observable_version": "1.0.0",
            "ir": {
                "operator": "read",
                "value_type": "float",
                "feature": {
                    "path": "event_count",
                    "value_type": "float",
                    "unit": "count",
                },
            },
        },
        "certification": {
            "report_id": "poseidon-test-certification",
            "evaluated_at": _iso(NOW_MS - 120_000),
            "dataset_commitment": "sha256:" + "1" * 64,
            "holdout_commitment": "sha256:" + "2" * 64,
            "gates": gates,
            "evaluator": "poseidon-test-evaluator",
            "notes": ["deterministic integration fixture"],
        },
        "nuisance_contracts": nuisance_contracts,
        "test_vectors": [
            {
                "vector_id": "poseidon-test-vector",
                "trace": {
                    "trace_id": "poseidon-test-reference",
                    "domain": "ai-instruction-flow",
                    "occurred_at": _iso(NOW_MS - 180_000),
                    "source": "fixture://titan-poseidon",
                    "events": [
                        {
                            "event_id": "poseidon-test-event",
                            "event_type": "message",
                            "occurred_at": _iso(NOW_MS - 180_000),
                            "payload": {"role": "user"},
                            "actor": "user",
                            "resource": None,
                        }
                    ],
                    "schema_uri": TRACE_SCHEMA,
                    "schema_version": "1.0.0",
                    "subject": None,
                    "captured_at": _iso(NOW_MS - 180_000),
                    "attributes": {"synthetic": True},
                },
                "expected_value": 1.0,
                "expected_abstained": False,
                "tolerance": 0.0,
            }
        ],
        "lineage": [],
        "artifact_digests": {},
        "metadata": {},
    }
    package = _signed(
        "manifest",
        manifest,
        key_id=RELEASE_KEY_ID,
        private_key=release_private,
        context=PACKAGE_CONTEXT,
    )
    package_digest = _sha256(manifest)
    mapping = PoseidonShadowMapping(
        mapping_id="titan.poseidon.attack-sensitive-count",
        mapping_version="1.0.0",
        package_digest=package_digest,
        package_id=manifest["package_id"],
        package_version=manifest["package_version"],
        observable_id=manifest["observable"]["observable_id"],
        observable_version=manifest["observable"]["version"],
        trace_domain="ai-instruction-flow",
        source_id=SOURCE_ID,
        value_minimum=0.0,
        value_maximum=1.0,
        risk_at_minimum=0.0,
        risk_at_maximum=1.0,
        minimum_coverage=0.80,
        maximum_uncertainty=0.20,
        native_ttl_ms=2_000,
    )
    clock = Clock()
    native_authority = EvidenceAttestationAuthority(
        secret=BINDER_SECRET,
        key_id=BINDER_KEY_ID,
        clock_ms=clock,
    )
    trajectory, proposal = _trajectory_and_proposal()
    trust_policy = PoseidonTrustPolicy(
        release_public_keys={RELEASE_KEY_ID: _public(release_private)},
        runtime_bindings=(
            PoseidonRuntimeBinding(
                key_id=RUNTIME_KEY_ID,
                public_key=_public(runtime_private),
                runtime_id=RUNTIME_ID,
                independence_domain=RUNTIME_DOMAIN,
            ),
        ),
        maximum_attestation_ttl_ms=5_000,
    )
    attachment = PoseidonAttachment(
        trust_policy=trust_policy,
        mapping=mapping,
        native_authority=native_authority,
        clock_ms=clock,
        nonce_factory=lambda: "exact-titan-challenge-nonce",
        request_ttl_ms=5_000,
    )
    return Scenario(
        clock=clock,
        release_private=release_private,
        runtime_private=runtime_private,
        package=package,
        package_digest=package_digest,
        mapping=mapping,
        trust_policy=trust_policy,
        native_authority=native_authority,
        attachment=attachment,
        trajectory=trajectory,
        proposal=proposal,
    )


def _bridge(
    scenario: Scenario,
    request,
    *,
    observation_updates: Optional[Mapping[str, Any]] = None,
    payload_updates: Optional[Mapping[str, Any]] = None,
    runtime_private: Optional[Ed25519PrivateKey] = None,
    runtime_key_id: str = RUNTIME_KEY_ID,
) -> str:
    observation = {
        "observable_id": scenario.mapping.observable_id,
        "observable_version": scenario.mapping.observable_version,
        "abi_version": POSEIDON_ABI,
        "trace_id": request.trace["trace_id"],
        "observed_at": _iso(scenario.clock()),
        "value": 0.80,
        "abstained": False,
        "coverage": 1.0,
        "uncertainty": 0.10,
        "metadata": {"measurement": "synthetic-test-fixture"},
    }
    if observation_updates:
        observation.update(deepcopy(dict(observation_updates)))
    payload = {
        "package_digest": scenario.package_digest,
        "package_id": scenario.mapping.package_id,
        "package_version": scenario.mapping.package_version,
        "trace_digest": request.trace_digest,
        "runtime_id": RUNTIME_ID,
        "independence_domain": RUNTIME_DOMAIN,
        "observation": observation,
        "issued_at": _iso(scenario.clock()),
        "expires_at": _iso(scenario.clock() + 1_000),
        "nonce": request.nonce,
        "context": deepcopy(request.runtime_context),
        "abi_version": POSEIDON_ABI,
    }
    if payload_updates:
        payload.update(deepcopy(dict(payload_updates)))
    attestation = _signed(
        "payload",
        payload,
        key_id=runtime_key_id,
        private_key=runtime_private or scenario.runtime_private,
        context=ATTESTATION_CONTEXT,
    )
    bridge = {
        "schema_uri": BRIDGE_SCHEMA,
        "message_type": BRIDGE_MESSAGE,
        "verified_at": _iso(scenario.clock()),
        "package_reference": "%s@%s"
        % (scenario.mapping.package_id, scenario.mapping.package_version),
        "package_digest": scenario.package_digest,
        "observation": deepcopy(observation),
        "signed_observable_package": deepcopy(scenario.package),
        "signed_observable_attestation": attestation,
    }
    return canonical_json_bytes(bridge).decode("utf-8")


def _modify_bridge(serialized: str, change: Callable[[dict[str, Any]], None]) -> str:
    value = json.loads(serialized)
    change(value)
    return canonical_json_bytes(value).decode("utf-8")


def _native_verifier(clock: Clock) -> EvidenceAttestationVerifier:
    return EvidenceAttestationVerifier(
        trusted_keys={BINDER_KEY_ID: BINDER_SECRET},
        trusted_identities={
            POSEIDON_SHADOW_EVIDENCE_KIND: (
                (
                    TITAN_POSEIDON_BINDER_ID,
                    SOURCE_ID,
                    BINDER_KEY_ID,
                    "titan-shadow-binder",
                ),
            )
        },
        clock_ms=clock,
    )


def _assert_rejected(result, code: str) -> None:
    assert result.accepted is False
    assert result.evidence is None
    assert result.receipt.status == "rejected"
    assert result.receipt.reason_code == code


def test_valid_exact_prefix_bind_is_native_verifiable_shadow_evidence():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)

    prefix = action_prefix(scenario.trajectory, scenario.proposal)
    assert [event["event_id"] for event in request.trace["events"]] == [
        "prefix-message"
    ]
    assert request.trace["captured_at"] == "2027-01-15T07:59:58.000000Z"
    binding = request.runtime_context["consumer_binding"]
    assert binding == {
        "schema": "titan-poseidon-consumer-binding/1",
        "request_id": request.request_id,
        "mapping_id": scenario.mapping.mapping_id,
        "mapping_version": scenario.mapping.mapping_version,
        "mapping_digest": scenario.mapping.digest,
        "action_hash": scenario.proposal.action_hash(),
        "state_snapshot_id": prefix.observable_hash(),
        "actor": scenario.proposal.actor,
        "environment": scenario.proposal.environment,
        "trace_digest": request.trace_digest,
        "nonce": request.nonce,
        "issued_at_ms": NOW_MS,
        "expires_at_ms": NOW_MS + 5_000,
    }

    result = scenario.attachment.bind(
        request,
        scenario.proposal,
        _bridge(scenario, request),
    )
    assert result.accepted
    assert result.receipt.reason_code == "verified_shadow_observation"
    evidence = result.evidence
    assert evidence is not None
    assert evidence.evidence_kind == POSEIDON_SHADOW_EVIDENCE_KIND
    assert evidence.action_hash == scenario.proposal.action_hash()
    assert evidence.state_snapshot_id == scenario.proposal.state_snapshot_id
    assert evidence.actor == scenario.proposal.actor
    assert evidence.environment == scenario.proposal.environment
    assert evidence.claims["risk"] == pytest.approx(0.8)
    assert evidence.claims["confidence"] == 0.0
    assert evidence.claims["passed"] is None
    assert evidence.claims["verified_components"] == []
    assert evidence.claims["poseidon"]["shadow_only"] is True
    assert evidence.claims["poseidon"]["artifact_semantics"] == "observation"
    assert evidence.expires_at_ms <= request.expires_at_ms
    verified = _native_verifier(scenario.clock).verify(evidence, scenario.proposal)
    assert verified.evidence_kind == POSEIDON_SHADOW_EVIDENCE_KIND
    assert verified.independence_domain == "titan-shadow-binder"


def test_prefix_projection_matches_poseidon_canonical_trace_digest_vector():
    """Guard the cross-repository optional-field normalization contract."""

    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    assert request.trace["events"][0]["resource"] is None
    assert request.trace_digest == (
        "sha256:2b45499d3fa5ae34f161f6eb91a6bcbe1041fa3465c31f71950cf7d266b4e111"
    )


@pytest.mark.parametrize("artifact", ("package", "attestation"))
def test_signed_artifact_tampering_fails_closed(artifact: str):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = _bridge(scenario, request)

    def tamper(value):
        if artifact == "package":
            value["signed_observable_package"]["manifest"]["issuer"] = "attacker"
        else:
            value["signed_observable_attestation"]["payload"]["observation"][
                "value"
            ] = 0.01

    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _modify_bridge(bridge, tamper),
        ),
        "invalid_signature",
    )


@pytest.mark.parametrize(
    "outer_field", ("package_digest", "package_reference", "observation")
)
def test_unsigned_outer_fields_cannot_disagree_with_signed_artifacts(outer_field: str):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = _bridge(scenario, request)

    def mismatch(value):
        if outer_field == "package_digest":
            value[outer_field] = "sha256:" + "0" * 64
        elif outer_field == "package_reference":
            value[outer_field] = "poseidon.splice@9.9.9"
        else:
            value[outer_field]["value"] = 0.01

    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _modify_bridge(bridge, mismatch),
        ),
        "outer_mismatch",
    )


@pytest.mark.parametrize(
    ("payload_updates", "expected"),
    (
        ({"nonce": "wrong-challenge"}, "nonce_mismatch"),
        ({"trace_digest": "sha256:" + "3" * 64}, "trace_mismatch"),
        (
            {"context": {"consumer_binding": {"schema": "attacker-context/v1"}}},
            "context_mismatch",
        ),
    ),
)
def test_signed_attestation_is_bound_to_nonce_trace_and_full_context(
    payload_updates, expected
):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(scenario, request, payload_updates=payload_updates),
        ),
        expected,
    )


def test_request_and_response_cannot_be_rebound_to_another_action():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    different_action = replace(scenario.proposal, claimed_purpose="a different action")
    _assert_rejected(
        scenario.attachment.bind(
            request,
            different_action,
            _bridge(scenario, request),
        ),
        "context_mismatch",
    )


def test_expired_package_is_rejected():
    scenario = _scenario(package_expires_at_ms=NOW_MS)
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(scenario, request),
        ),
        "expired",
    )


@pytest.mark.parametrize(
    ("expires_at", "expected"),
    (
        (NOW_MS, "expired"),
        (NOW_MS + 5_001, "freshness"),
    ),
)
def test_attestation_expiry_and_maximum_ttl_are_enforced(expires_at, expected):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(
                scenario,
                request,
                payload_updates={"expires_at": _iso(expires_at)},
            ),
        ),
        expected,
    )


@pytest.mark.parametrize("revocation", ("package", "attestation", "runtime_key"))
def test_package_attestation_and_key_revocations_are_enforced(revocation: str):
    scenario = _scenario()
    reference_attachment = _make_attachment(scenario, nonce="revocation-nonce")
    reference_request = reference_attachment.prepare(
        scenario.trajectory, scenario.proposal
    )
    reference_bridge = json.loads(_bridge(scenario, reference_request))
    attestation_digest = _sha256(
        reference_bridge["signed_observable_attestation"]["payload"]
    )
    policy = _make_policy(
        scenario,
        revoked_package_digests=(scenario.package_digest,)
        if revocation == "package"
        else (),
        revoked_attestation_digests=(attestation_digest,)
        if revocation == "attestation"
        else (),
        revoked_key_ids=(RUNTIME_KEY_ID,) if revocation == "runtime_key" else (),
    )
    attachment = _make_attachment(
        scenario,
        trust_policy=policy,
        nonce="revocation-nonce",
    )
    request = attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        attachment.bind(request, scenario.proposal, _bridge(scenario, request)),
        "revoked",
    )


@pytest.mark.parametrize(
    ("payload_updates", "runtime_private", "runtime_key_id", "expected"),
    (
        ({"runtime_id": "lookalike-runtime"}, None, RUNTIME_KEY_ID, "runtime_mismatch"),
        (
            {"independence_domain": "lookalike-domain"},
            None,
            RUNTIME_KEY_ID,
            "runtime_mismatch",
        ),
        ({}, _private(9), "untrusted-runtime-key", "untrusted_key"),
        ({}, _private(9), RUNTIME_KEY_ID, "invalid_signature"),
    ),
)
def test_runtime_key_id_and_independence_domain_are_pinned(
    payload_updates, runtime_private, runtime_key_id, expected
):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(
                scenario,
                request,
                payload_updates=payload_updates,
                runtime_private=runtime_private,
                runtime_key_id=runtime_key_id,
            ),
        ),
        expected,
    )


@pytest.mark.parametrize(
    ("observation_updates", "expected"),
    (
        ({"abstained": True, "value": None}, "abstained"),
        ({"coverage": 0.79}, "insufficient_coverage"),
        ({"uncertainty": 0.21}, "unknown_uncertainty"),
        ({"uncertainty": None}, "unknown_uncertainty"),
    ),
)
def test_abstention_low_coverage_and_unknown_uncertainty_emit_no_native_evidence(
    observation_updates, expected
):
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(
                scenario,
                request,
                observation_updates=observation_updates,
            ),
        ),
        expected,
    )


def test_successful_request_is_single_use():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = _bridge(scenario, request)
    assert scenario.attachment.bind(request, scenario.proposal, bridge).accepted
    _assert_rejected(
        scenario.attachment.bind(request, scenario.proposal, bridge),
        "replay",
    )


def test_duplicate_json_keys_are_rejected_before_signature_verification():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = _bridge(scenario, request)
    duplicate = bridge.replace(
        '"schema_uri":',
        '"schema_uri":"duplicate", "schema_uri":',
        1,
    )
    _assert_rejected(
        scenario.attachment.bind(request, scenario.proposal, duplicate),
        "duplicate_json_key",
    )


def test_policy_vocabulary_in_signed_observation_metadata_is_rejected():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(
                scenario,
                request,
                observation_updates={"metadata": {"decision": "block"}},
            ),
        ),
        "policy_smuggling",
    )


def test_same_package_identity_with_a_different_signed_digest_is_rejected():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = json.loads(_bridge(scenario, request))
    changed_manifest = deepcopy(bridge["signed_observable_package"]["manifest"])
    changed_manifest["issuer"] = "different-signed-release"
    bridge["signed_observable_package"] = _signed(
        "manifest",
        changed_manifest,
        key_id=RELEASE_KEY_ID,
        private_key=scenario.release_private,
        context=PACKAGE_CONTEXT,
    )
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            canonical_json_bytes(bridge).decode("utf-8"),
        ),
        "mapping_mismatch",
    )


def test_noncanonical_signed_timestamp_is_rejected():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            _bridge(
                scenario,
                request,
                payload_updates={
                    "issued_at": _iso(scenario.clock()).replace(".000000Z", "Z")
                },
            ),
        ),
        "invalid_time",
    )


def test_unknown_outer_field_is_rejected():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    bridge = json.loads(_bridge(scenario, request))
    bridge["recommended_action"] = "ignore"
    _assert_rejected(
        scenario.attachment.bind(
            request,
            scenario.proposal,
            canonical_json_bytes(bridge).decode("utf-8"),
        ),
        "invalid_schema",
    )


def test_bridge_size_limit_is_enforced_before_parsing():
    scenario = _scenario()
    reference = _make_attachment(scenario, nonce="size-limit-nonce")
    reference_request = reference.prepare(scenario.trajectory, scenario.proposal)
    bridge = _bridge(scenario, reference_request)
    strict_policy = replace(
        scenario.trust_policy,
        maximum_bridge_bytes=len(bridge.encode("utf-8")) - 1,
    )
    attachment = _make_attachment(
        scenario,
        trust_policy=strict_policy,
        nonce="size-limit-nonce",
    )
    request = attachment.prepare(scenario.trajectory, scenario.proposal)
    _assert_rejected(
        attachment.bind(request, scenario.proposal, _bridge(scenario, request)),
        "artifact_too_large",
    )


def test_prepare_rejects_reused_nonce_for_the_same_action_and_clock():
    scenario = _scenario()
    scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    with pytest.raises(ValueError, match="nonce was already used"):
        scenario.attachment.prepare(scenario.trajectory, scenario.proposal)


def test_configuration_state_commits_mapping_and_public_key_fingerprints():
    scenario = _scenario()
    state = scenario.attachment.configuration_state()
    assert state["mode"] == "shadow_only"
    assert state["mapping"]["native_evidence_kind"] == POSEIDON_SHADOW_EVIDENCE_KIND
    assert state["mapping"]["package_digest"] == scenario.package_digest
    assert state["trust"]["schema"] == "titan-poseidon-trust-policy/1"
    assert state["configuration_digest"].startswith("sha256:")
    serialized = canonical_json_bytes(state)
    assert _public(scenario.release_private) not in serialized
    assert _public(scenario.runtime_private) not in serialized


def test_release_runtime_and_titan_binder_keys_are_role_separated():
    same_private = _private(7)
    same_public = _public(same_private)
    with pytest.raises(ValueError, match="distinct material"):
        PoseidonTrustPolicy(
            release_public_keys={RELEASE_KEY_ID: same_public},
            runtime_bindings=(
                PoseidonRuntimeBinding(
                    key_id=RUNTIME_KEY_ID,
                    public_key=same_public,
                    runtime_id=RUNTIME_ID,
                    independence_domain=RUNTIME_DOMAIN,
                ),
            ),
        )

    scenario = _scenario()
    colliding_native_authority = EvidenceAttestationAuthority(
        secret=BINDER_SECRET,
        key_id=RUNTIME_KEY_ID,
        clock_ms=scenario.clock,
    )
    with pytest.raises(ValueError, match="role-separated"):
        PoseidonAttachment(
            trust_policy=scenario.trust_policy,
            mapping=scenario.mapping,
            native_authority=colliding_native_authority,
        )


def _readiness(bundle, proposal):
    policy = v10_policy_for(proposal.action_type)
    return build_readiness_report(
        policy=policy,
        hard_block_condition=bundle.hard_block_condition,
        independent_sources=bundle.independent_sources,
        adverse_sources=0,
        favorable_sources=0,
        completeness=bundle.completeness,
        confidence=bundle.confidence,
        adverse_confidence=0.0,
        uncertainty=bundle.twin.uncertainty,
        effect_risk=bundle.effect_risk,
        missing_required=bundle.missing_required,
        evidence_kinds=tuple(item.evidence_kind for item in bundle.results),
        adverse_kinds=(),
        favorable_kinds=(),
        budget_exhausted=bundle.budget_exhausted,
        twin_fidelity=bundle.twin.fidelity,
        irreversible=not proposal.reversible,
        authorization_validity=bundle.verified_authorization_validity,
        block_rank=0.0,
    )


def test_poseidon_observation_cannot_satisfy_readiness_or_change_decision_terms():
    scenario = _scenario()
    request = scenario.attachment.prepare(scenario.trajectory, scenario.proposal)
    result = scenario.attachment.bind(
        request,
        scenario.proposal,
        _bridge(scenario, request),
    )
    assert result.evidence is not None
    verified_shadow = _native_verifier(scenario.clock).verify(
        result.evidence, scenario.proposal
    )
    prefix = action_prefix(scenario.trajectory, scenario.proposal)
    policy = v9_policy_for(scenario.proposal.action_type)
    baseline = acquire_evidence(prefix, scenario.proposal, policy)
    attached = acquire_evidence(
        prefix,
        scenario.proposal,
        policy,
        trusted_evidence=(verified_shadow,),
    )

    assert POSEIDON_SHADOW_EVIDENCE_KIND not in BLOCK_ADVERSE_KINDS
    assert all(
        POSEIDON_SHADOW_EVIDENCE_KIND not in authorized
        for authorized in REQUIREMENT_EVIDENCE_KINDS.values()
    )
    decision_fields = (
        "action_hash",
        "twin",
        "effect_risk",
        "verified_authorization_validity",
        "completeness",
        "confidence",
        "independent_sources",
        "missing_required",
        "hard_block_condition",
        "budget_exhausted",
    )
    for field in decision_fields:
        assert getattr(attached, field) == getattr(baseline, field)

    # Adapter latency is diagnostic wall-clock data, not a decision input.
    def decision_results(bundle):
        return tuple(
            {key: value for key, value in item.to_dict().items() if key != "latency_ms"}
            for item in bundle.results
        )

    assert decision_results(attached) == decision_results(baseline)
    assert POSEIDON_SHADOW_EVIDENCE_KIND not in {
        item.evidence_kind for item in attached.results
    }

    baseline_readiness = _readiness(baseline, scenario.proposal)
    attached_readiness = _readiness(attached, scenario.proposal)
    assert attached_readiness == baseline_readiness
    readiness_kwargs = {
        "kernel_forbidden": False,
        "supported": True,
        "risk_rank": 0.5,
        "policy": v10_policy_for(scenario.proposal.action_type),
    }
    assert disposition_from_readiness(
        attached_readiness, **readiness_kwargs
    ) == disposition_from_readiness(baseline_readiness, **readiness_kwargs)
