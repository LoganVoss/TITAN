"""V10 enforcement gateway — sole path to protected executors."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
import json
import threading

from ..v9.action import ActionProposal, ObservableTrajectory, extract_action_proposals
from ..v9.integrity import HashChainedAuditLog, IntegritySignals
from ..v9.tokens import (
    ActionContext,
    CommitTokenVerifier,
    TokenValidationError,
    canonical_json_bytes,
)
from .governor import GovernanceResult, V10Governor


Executor = Callable[[ActionProposal], Any]
StateReader = Callable[[tuple[str, ...]], Mapping[str, str]]
IntegrityProvider = Callable[[], IntegritySignals]


class GatewayDenied(RuntimeError):
    """The enforcement gateway refused an action before execution."""


@dataclass(frozen=True)
class ActionEnvelope:
    proposal: ActionProposal
    governance: GovernanceResult
    admitted_object_hashes: tuple[tuple[str, str], ...]
    proposal_payload_json: str
    admission_audit_hash: str


@dataclass(frozen=True)
class ExecutionReceipt:
    action_id: str
    action_hash: str
    token_id: str
    audit_record_hash: str
    executor_result: Any


class EnforcementGateway:
    """Only supported V10 route to a consequential action executor."""

    def __init__(
        self,
        *,
        governor: V10Governor,
        commit_verifier: CommitTokenVerifier,
        state_reader: StateReader,
        integrity_provider: IntegrityProvider,
        executors: Mapping[str, Executor],
        audit_log: HashChainedAuditLog,
    ) -> None:
        if governor.token_authority is None:
            raise ValueError("gateway governor requires a two-phase token authority")
        if not executors:
            raise ValueError("at least one protected executor is required")
        self.governor = governor
        self.commit_verifier = commit_verifier
        self.state_reader = state_reader
        self.integrity_provider = integrity_provider
        self._executors = dict(executors)
        self.audit_log = audit_log
        self._commit_lock = threading.RLock()
        self._authorized_actions: dict[str, str] = {}
        self.bypass_attempts = 0
        self.executor_calls = 0

    def direct_executor_call_forbidden(self, action_type: str, proposal: ActionProposal) -> None:
        """Any call outside the gateway is a hard failure for harness tests."""
        self.bypass_attempts += 1
        self.audit_log.append(
            "EXECUTOR_BYPASS_ATTEMPT",
            {
                "action_type": action_type,
                "action_id": proposal.action_id,
            },
        )
        raise GatewayDenied("direct executor access is forbidden; use gateway only")

    def _trusted_state(self, objects: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
        observed = dict(self.state_reader(objects))
        if set(observed) != set(objects):
            raise GatewayDenied("trusted state reader did not resolve the exact object set")
        return tuple(sorted(observed.items(), key=lambda item: item[0]))

    def propose(
        self,
        trajectory: ObservableTrajectory,
        proposal: ActionProposal,
    ) -> ActionEnvelope:
        if proposal.action_type not in self._executors:
            raise GatewayDenied("no protected executor registered for action class")
        try:
            canonical = [
                item
                for item in extract_action_proposals(trajectory)
                if item.action_id == proposal.action_id
                and item.proposal_sequence == proposal.proposal_sequence
                and item.proposal_event_id == proposal.proposal_event_id
            ]
            if len(canonical) != 1 or canonical[0] != proposal:
                raise GatewayDenied(
                    "proposal is not the canonical action extracted from the event log"
                )
            admitted = self._trusted_state(proposal.objects)
            trusted_hashes = dict(admitted)
            payload_json = canonical_json_bytes(proposal.payload).decode("utf-8")
            trusted_proposal = replace(
                proposal,
                object_hashes=tuple(trusted_hashes[obj] for obj in proposal.objects),
                payload=json.loads(payload_json),
            )
            integrity = self.governor.integrity_policy.assess(self.integrity_provider())
            governance = self.governor.evaluate(
                trajectory,
                trusted_proposal,
                integrity=integrity,
            )
        except GatewayDenied:
            raise
        except Exception as exc:
            self.audit_log.append(
                "ACTION_DENIED",
                {
                    "action_id": proposal.action_id,
                    "reason": "admission_verifier_failure",
                    "error_type": type(exc).__name__,
                },
            )
            raise GatewayDenied("admission verification failed closed") from exc

        if governance.decision.commit_permitted:
            prepare = governance.prepare_token
            if prepare is None:
                raise GatewayDenied("allow decision lacks execution authorization")
            with self._commit_lock:
                action_hash = trusted_proposal.action_hash()
                if action_hash in self._authorized_actions:
                    raise GatewayDenied("action already has active or spent authorization")
                self._authorized_actions[action_hash] = prepare.token_id

        record = self.audit_log.append(
            "ACTION_ADMISSION",
            {
                "action_id": trusted_proposal.action_id,
                "action_hash": trusted_proposal.action_hash(),
                "action_type": trusted_proposal.action_type,
                "disposition": governance.decision.disposition.value,
                "risk_rank": governance.decision.risk_rank_score,
                "blockability_rank": governance.decision.blockability_rank_score,
                "evidence_hash": governance.evidence.evidence_hash,
                "object_hashes": dict(admitted),
            },
        )
        return ActionEnvelope(
            proposal=trusted_proposal,
            governance=governance,
            admitted_object_hashes=admitted,
            proposal_payload_json=payload_json,
            admission_audit_hash=record.record_hash,
        )

    def commit(self, envelope: ActionEnvelope) -> ExecutionReceipt:
        with self._commit_lock:
            decision = envelope.governance.decision
            context = envelope.governance.execution_context
            prepare = envelope.governance.prepare_token
            if not decision.commit_permitted or context is None or prepare is None:
                raise GatewayDenied(
                    f"decision {decision.disposition.value} does not permit commit"
                )
            current_configuration = self.governor.verify_configuration()
            if (
                decision.configuration_fingerprint != current_configuration
                or decision.policy_version != self.governor.effective_policy_version
                or context.policy_version != self.governor.effective_policy_version
            ):
                raise GatewayDenied("governor configuration binding does not match admission")

            current_payload_json = canonical_json_bytes(envelope.proposal.payload).decode(
                "utf-8"
            )
            if (
                current_payload_json != envelope.proposal_payload_json
                or envelope.proposal.action_hash() != context.action_hash
            ):
                raise GatewayDenied("proposal changed after admission")

            registered = self._authorized_actions.get(envelope.proposal.action_hash())
            if registered != prepare.token_id:
                raise GatewayDenied("action authorization is not registered")

            fresh_integrity = self.governor.integrity_policy.assess(
                self.integrity_provider()
            )
            if not fresh_integrity.healthy:
                raise GatewayDenied("control-plane integrity failed before commit")

            fresh_state = dict(self._trusted_state(envelope.proposal.objects))
            admitted = dict(envelope.admitted_object_hashes)
            if fresh_state != admitted:
                raise GatewayDenied("protected object versions changed between prepare and commit")

            expected = ActionContext.create(
                action_hash=context.action_hash,
                object_hashes=fresh_state,
                actor=context.actor,
                environment=context.environment,
                authorization_hash=context.authorization_hash,
                evidence_hash=context.evidence_hash,
                scorer_version=context.scorer_version,
                policy_version=context.policy_version,
            )
            authority = self.governor.token_authority
            assert authority is not None
            try:
                commit_token = authority.promote(
                    prepare,
                    expected_context=expected,
                )
                self.commit_verifier.verify_and_consume(
                    commit_token,
                    expected_context=expected,
                )
            except TokenValidationError as exc:
                raise GatewayDenied("commit authorization rejected") from exc

            executor = self._executors[envelope.proposal.action_type]
            execution_proposal = replace(
                envelope.proposal,
                payload=json.loads(envelope.proposal_payload_json),
            )
            result = executor(execution_proposal)
            self.executor_calls += 1
            self._authorized_actions.pop(envelope.proposal.action_hash(), None)
            record = self.audit_log.append(
                "ACTION_COMMITTED",
                {
                    "action_id": envelope.proposal.action_id,
                    "action_hash": envelope.proposal.action_hash(),
                    "token_id": commit_token.token_id,
                },
            )
            return ExecutionReceipt(
                action_id=envelope.proposal.action_id,
                action_hash=envelope.proposal.action_hash(),
                token_id=commit_token.token_id,
                audit_record_hash=record.record_hash,
                executor_result=result,
            )
