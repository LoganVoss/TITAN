"""Synchronous V9 enforcement gateway.

Consequential executors are private to this gateway.  A mutation can run only
after a label-blind decision, fresh integrity and object-state checks, signed
PREPARE→COMMIT promotion, and one-use environment-side verification.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
import json
import threading

from .action import (
    ActionProposal,
    ObservableTrajectory,
    extract_action_proposals,
)
from .governor import GovernanceResult, V9Governor
from .integrity import HashChainedAuditLog, IntegritySignals
from .tokens import (
    ActionContext,
    CommitTokenVerifier,
    TokenValidationError,
    canonical_json_bytes,
)


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
    """The only supported V9 route to a consequential action executor."""

    def __init__(
        self,
        *,
        governor: V9Governor,
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
        if not all(isinstance(name, str) and callable(fn) for name, fn in executors.items()):
            raise TypeError("executors must map action types to callables")
        self.governor = governor
        self.commit_verifier = commit_verifier
        self.state_reader = state_reader
        self.integrity_provider = integrity_provider
        self._executors = dict(executors)
        self.audit_log = audit_log
        self._commit_lock = threading.RLock()
        # Reference in-process action idempotency. Production must persist this
        # alongside token replay state and the executor mutation.
        self._authorized_actions: dict[str, str] = {}

    def _trusted_state(
        self,
        objects: tuple[str, ...],
    ) -> tuple[tuple[str, str], ...]:
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
        except Exception as exc:
            self.audit_log.append(
                "ACTION_DENIED",
                {
                    "action_id": proposal.action_id,
                    "action_hash": proposal.action_hash(),
                    "reason": "admission_verifier_failure",
                    "error_type": type(exc).__name__,
                },
            )
            raise GatewayDenied("admission verification failed closed") from exc
        if governance.decision.commit_permitted:
            prepare = governance.prepare_token
            if prepare is None:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": trusted_proposal.action_id,
                        "action_hash": trusted_proposal.action_hash(),
                        "reason": "missing_prepare_authorization",
                    },
                )
                raise GatewayDenied("allow decision lacks execution authorization")
            with self._commit_lock:
                action_hash = trusted_proposal.action_hash()
                if action_hash in self._authorized_actions:
                    self.audit_log.append(
                        "ACTION_DENIED",
                        {
                            "action_id": trusted_proposal.action_id,
                            "action_hash": action_hash,
                            "reason": "duplicate_action_authorization",
                        },
                    )
                    raise GatewayDenied(
                        "action already has active or spent authorization"
                    )
                self._authorized_actions[action_hash] = prepare.token_id
        record = self.audit_log.append(
            "ACTION_ADMISSION",
            {
                "action_id": trusted_proposal.action_id,
                "action_hash": trusted_proposal.action_hash(),
                "action_type": trusted_proposal.action_type,
                "actor": trusted_proposal.actor,
                "environment": trusted_proposal.environment,
                "disposition": governance.decision.disposition.value,
                "risk_rank": governance.decision.risk_rank_score,
                "blockability_rank": governance.decision.blockability_rank_score,
                "evidence_hash": governance.evidence.evidence_hash,
                "integrity_epoch": governance.decision.control_integrity_epoch,
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
        """Atomically gate one executor call.

        The in-process lock closes races among gateway clients.  Production
        deployments must place object-version checks and the executor mutation
        in the same datastore transaction, because this lock cannot serialize
        writers outside the process.
        """

        with self._commit_lock:
            decision = envelope.governance.decision
            context = envelope.governance.execution_context
            prepare = envelope.governance.prepare_token
            if not decision.commit_permitted or context is None or prepare is None:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "disposition": decision.disposition.value,
                        "reasons": decision.reasons,
                    },
                )
                raise GatewayDenied(
                    f"decision {decision.disposition.value} does not permit commit"
                )
            try:
                current_configuration = self.governor.verify_configuration()
            except Exception as exc:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": (
                            "governor_configuration_changed_before_commit"
                        ),
                        "error_type": type(exc).__name__,
                    },
                )
                raise GatewayDenied(
                    "governor configuration changed before commit"
                ) from exc
            if (
                decision.configuration_fingerprint != current_configuration
                or decision.policy_version
                != self.governor.effective_policy_version
                or context.policy_version
                != self.governor.effective_policy_version
            ):
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "governor_configuration_binding_mismatch",
                    },
                )
                raise GatewayDenied(
                    "governor configuration binding does not match admission"
                )
            try:
                current_payload_json = canonical_json_bytes(
                    envelope.proposal.payload
                ).decode("utf-8")
            except (TypeError, ValueError) as exc:
                current_payload_json = ""
                payload_error: Exception | None = exc
            else:
                payload_error = None
            if (
                payload_error is not None
                or current_payload_json != envelope.proposal_payload_json
                or envelope.proposal.action_hash() != context.action_hash
            ):
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": context.action_hash,
                        "reason": "proposal_changed_after_admission",
                    },
                )
                raise GatewayDenied("proposal changed after admission")

            registered_token_id = self._authorized_actions.get(
                envelope.proposal.action_hash()
            )
            if registered_token_id != prepare.token_id:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "unregistered_action_authorization",
                    },
                )
                raise GatewayDenied("action authorization is not registered")

            fresh_integrity = self.governor.integrity_policy.assess(
                self.integrity_provider()
            )
            if not fresh_integrity.healthy:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "control_plane_integrity_degraded_before_commit",
                        "integrity_reasons": fresh_integrity.reasons,
                    },
                )
                raise GatewayDenied("control-plane integrity degraded before commit")

            try:
                fresh_state = self._trusted_state(envelope.proposal.objects)
            except Exception as exc:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "commit_state_verifier_failure",
                        "error_type": type(exc).__name__,
                    },
                )
                raise GatewayDenied("commit state verification failed closed") from exc
            if fresh_state != envelope.admitted_object_hashes:
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "object_state_changed_after_admission",
                        "admitted_object_hashes": dict(
                            envelope.admitted_object_hashes
                        ),
                        "fresh_object_hashes": dict(fresh_state),
                    },
                )
                raise GatewayDenied("protected object state changed after admission")

            expected = ActionContext.create(
                action_hash=context.action_hash,
                object_hashes=dict(fresh_state),
                actor=context.actor,
                environment=context.environment,
                authorization_hash=context.authorization_hash,
                evidence_hash=context.evidence_hash,
                scorer_version=context.scorer_version,
                policy_version=context.policy_version,
            )
            authority = self.governor.token_authority
            assert authority is not None  # constructor invariant
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
                self.audit_log.append(
                    "ACTION_DENIED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "reason": "commit_token_rejected",
                        "error_type": type(exc).__name__,
                    },
                )
                raise GatewayDenied("commit authorization rejected") from exc

            executor = self._executors[envelope.proposal.action_type]
            execution_proposal = replace(
                envelope.proposal,
                payload=json.loads(envelope.proposal_payload_json),
            )
            try:
                result = executor(execution_proposal)
            except Exception as exc:
                # The one-use token remains consumed. A retry needs a fresh
                # state-bound decision rather than replaying authority.
                self.audit_log.append(
                    "ACTION_EXECUTION_FAILED",
                    {
                        "action_id": envelope.proposal.action_id,
                        "action_hash": envelope.proposal.action_hash(),
                        "token_id": commit_token.token_id,
                        "error_type": type(exc).__name__,
                    },
                )
                raise
            record = self.audit_log.append(
                "ACTION_COMMITTED",
                {
                    "action_id": envelope.proposal.action_id,
                    "action_hash": envelope.proposal.action_hash(),
                    "token_id": commit_token.token_id,
                    "object_hashes": dict(fresh_state),
                },
            )
            return ExecutionReceipt(
                action_id=envelope.proposal.action_id,
                action_hash=envelope.proposal.action_hash(),
                token_id=commit_token.token_id,
                audit_record_hash=record.record_hash,
                executor_result=result,
            )
