"""Adversarial tests for the TITAN V9 trusted enforcement foundation."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import hashlib

import pytest

from titan.v9.integrity import (
    AuditRecord,
    ControlPlaneIntegrityPolicy,
    HashChainedAuditLog,
    IntegritySignals,
)
from titan.v9.tokens import (
    ActionContext,
    AuthorizationToken,
    CommitTokenVerifier,
    ReplayGuard,
    TokenValidationError,
    TwoPhaseTokenAuthority,
    canonical_json_bytes,
)


SECRET = bytes(range(32))


class ManualClock:
    def __init__(self, now_ms: int = 1_000_000):
        self.now_ms = now_ms

    def __call__(self) -> int:
        return self.now_ms


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def context(**overrides) -> ActionContext:
    values = {
        "action_hash": digest("queue_training:job-7"),
        "object_hashes": {
            "data/shard-7": digest("shard-v4"),
            "training/config": digest("config-v2"),
        },
        "actor": "agent-17",
        "environment": "training-prod-a",
        "authorization_hash": digest("lease-93"),
        "evidence_hash": digest("evidence-manifest-8"),
        "scorer_version": "titan-scorer-v9.1",
        "policy_version": "training-policy-v12",
    }
    values.update(overrides)
    return ActionContext.create(**values)


def issued_pair(clock=None):
    clock = clock or ManualClock()
    authority = TwoPhaseTokenAuthority(secret=SECRET, key_id="test-key", clock_ms=clock)
    expected = context()
    prepare = authority.prepare(context=expected, disposition="ALLOW", ttl_ms=5_000)
    commit = authority.promote(prepare, expected_context=expected)
    return clock, authority, expected, prepare, commit


def verifier(clock):
    return CommitTokenVerifier(
        secret=SECRET,
        key_id="test-key",
        replay_guard=ReplayGuard(),
        clock_ms=clock,
    )


def test_secret_is_required_and_must_be_strong():
    with pytest.raises(TypeError):
        TwoPhaseTokenAuthority(secret=None, key_id="k")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TwoPhaseTokenAuthority(secret=b"development-secret", key_id="k")


def test_token_is_immutable_and_serialization_is_canonical():
    clock, _, expected, _, commit = issued_pair()
    with pytest.raises(FrozenInstanceError):
        commit.actor = "attacker"  # type: ignore[misc]

    reversed_context = context(
        object_hashes={
            "training/config": digest("config-v2"),
            "data/shard-7": digest("shard-v4"),
        }
    )
    assert expected == reversed_context
    restored = AuthorizationToken.from_dict(commit.to_dict())
    assert restored == commit
    assert restored.serialized_bytes() == commit.serialized_bytes()
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_valid_commit_is_accepted_once_only():
    clock, _, expected, _, commit = issued_pair()
    gate = verifier(clock)
    gate.verify_and_consume(commit, expected_context=expected)
    with pytest.raises(TokenValidationError, match="replayed"):
        gate.verify_and_consume(commit, expected_context=expected)


def test_prepare_token_cannot_execute_and_cannot_be_promoted_twice():
    clock = ManualClock()
    authority = TwoPhaseTokenAuthority(secret=SECRET, key_id="test-key", clock_ms=clock)
    expected = context()
    prepare = authority.prepare(context=expected, disposition="ALLOW", ttl_ms=5_000)
    with pytest.raises(TokenValidationError, match="phase"):
        verifier(clock).verify_and_consume(prepare, expected_context=expected)
    authority.promote(prepare, expected_context=expected)
    with pytest.raises(TokenValidationError, match="already"):
        authority.promote(prepare, expected_context=expected)


def test_tampered_token_signature_is_rejected():
    clock, _, expected, _, commit = issued_pair()
    forged = replace(commit, actor="attacker")
    with pytest.raises(TokenValidationError, match="signature"):
        verifier(clock).verify_and_consume(forged, expected_context=expected)


def test_expired_token_is_rejected():
    clock, _, expected, _, commit = issued_pair()
    clock.now_ms = commit.expires_at_ms
    with pytest.raises(TokenValidationError, match="expired"):
        verifier(clock).verify_and_consume(commit, expected_context=expected)


def test_prepare_expiry_is_capped_by_absolute_evidence_expiry():
    clock = ManualClock()
    authority = TwoPhaseTokenAuthority(
        secret=SECRET,
        key_id="test-key",
        clock_ms=clock,
    )
    expected = context()
    prepare = authority.prepare(
        context=expected,
        disposition="ALLOW",
        ttl_ms=5_000,
        not_after_ms=clock.now_ms + 125,
    )
    assert prepare.expires_at_ms == clock.now_ms + 125

    clock.now_ms = prepare.expires_at_ms
    with pytest.raises(TokenValidationError, match="evidence expired"):
        authority.prepare(
            context=expected,
            disposition="ALLOW",
            ttl_ms=5_000,
            not_after_ms=prepare.expires_at_ms,
        )

    clock.now_ms -= 500
    with pytest.raises(TokenValidationError, match="precedes"):
        authority.prepare(
            context=expected,
            disposition="ALLOW",
            ttl_ms=5_000,
            not_before_ms=prepare.issued_at_ms,
            not_after_ms=prepare.expires_at_ms,
        )


@pytest.mark.parametrize(
    "changed",
    [
        {"action_hash": digest("different-action")},
        {"object_hashes": {"data/shard-7": digest("swapped-object")}},
        {"actor": "agent-18"},
        {"environment": "training-prod-b"},
        {"authorization_hash": digest("different-lease")},
        {"evidence_hash": digest("different-evidence")},
        {"policy_version": "training-policy-v13"},
        {"scorer_version": "titan-scorer-v9.2"},
    ],
)
def test_exact_context_rejects_action_object_actor_environment_and_version_swaps(changed):
    clock, _, expected, _, commit = issued_pair()
    unexpected = context(**changed)
    assert unexpected != expected
    with pytest.raises(TokenValidationError, match="context"):
        verifier(clock).verify_and_consume(commit, expected_context=unexpected)


def test_atomic_replay_guard_allows_exactly_one_parallel_commit():
    clock, _, expected, _, commit = issued_pair()
    gate = verifier(clock)

    def attempt(_):
        try:
            gate.verify_and_consume(commit, expected_context=expected)
            return True
        except TokenValidationError:
            return False

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(attempt, range(64)))
    assert sum(outcomes) == 1


def healthy_signals(clock):
    return IntegritySignals(
        observed_at_ms=clock.now_ms,
        event_loss_count=0,
        max_event_delay_ms=10,
        logger_healthy=True,
        policy_healthy=True,
        registry_healthy=True,
        verifier_healthy=True,
        token_verifier_healthy=True,
    )


def test_healthy_integrity_preserves_allow():
    clock = ManualClock()
    policy = ControlPlaneIntegrityPolicy(clock_ms=clock)
    assessment = policy.assess(healthy_signals(clock))
    decision = policy.enforce(
        action_type="queue_training",
        disposition="ALLOW",
        assessment=assessment,
    )
    assert assessment.healthy
    assert decision.effective_disposition == "ALLOW"
    assert not decision.forced


@pytest.mark.parametrize(
    "degradation,reason",
    [
        ({"event_loss_count": 1}, "event_loss"),
        ({"max_event_delay_ms": 5_001}, "event_delay"),
        ({"logger_healthy": False}, "logger_unhealthy"),
        ({"policy_healthy": False}, "policy_integrity_failed"),
        ({"registry_healthy": False}, "registry_integrity_failed"),
        ({"verifier_healthy": False}, "verifier_unhealthy"),
        ({"token_verifier_healthy": False}, "token_verifier_unhealthy"),
    ],
)
def test_every_integrity_degradation_forces_high_risk_allow_to_escrow(degradation, reason):
    clock = ManualClock()
    policy = ControlPlaneIntegrityPolicy(clock_ms=clock)
    base = healthy_signals(clock)
    signals = replace(base, **degradation)
    assessment = policy.assess(signals)
    decision = policy.enforce(
        action_type="queue_training",
        disposition="ALLOW_WITH_LOGGING",
        assessment=assessment,
    )
    assert not assessment.healthy
    assert reason in assessment.reasons
    assert decision.effective_disposition == "ESCROW"
    assert decision.forced


def test_stale_integrity_forces_unknown_consequential_action_to_escrow():
    clock = ManualClock()
    policy = ControlPlaneIntegrityPolicy(max_signal_age_ms=100, clock_ms=clock)
    signals = replace(healthy_signals(clock), observed_at_ms=clock.now_ms - 101)
    assessment = policy.assess(signals)
    decision = policy.enforce(
        action_type="new_unrecognized_write_capability",
        disposition="REQUEST_EVIDENCE",
        assessment=assessment,
    )
    assert "integrity_snapshot_stale" in assessment.reasons
    assert decision.effective_disposition == "ESCROW"


def test_integrity_floor_never_downgrades_a_block():
    clock = ManualClock()
    policy = ControlPlaneIntegrityPolicy(clock_ms=clock)
    assessment = policy.assess(replace(healthy_signals(clock), logger_healthy=False))
    decision = policy.enforce(
        action_type="modify_safeguard",
        disposition="BLOCK",
        assessment=assessment,
    )
    assert decision.effective_disposition == "BLOCK"
    assert not decision.forced


def test_hash_chained_audit_log_detects_payload_and_chain_tampering():
    clock = ManualClock()
    log = HashChainedAuditLog(clock_ms=clock)
    mutable_payload = {"action": "queue_training", "objects": ["shard-a"]}
    first = log.append("prepare_issued", mutable_payload)
    mutable_payload["action"] = "attacker_mutation"
    clock.now_ms += 1
    second = log.append("commit_consumed", {"nonce": "n-1", "allowed": True})

    assert first.payload["action"] == "queue_training"
    assert second.previous_hash == first.record_hash
    assert log.verify()

    tampered_first = replace(first, payload_json='{"action":"tampered"}')
    assert not HashChainedAuditLog.verify_records((tampered_first, second))
    broken_link = replace(second, previous_hash="f" * 64)
    assert not HashChainedAuditLog.verify_records((first, broken_link))


def test_audit_log_is_thread_safe_and_sequence_is_contiguous():
    log = HashChainedAuditLog()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: log.append("event", {"i": i}), range(100)))
    records = log.records()
    assert [record.sequence for record in records] == list(range(100))
    assert log.verify()
