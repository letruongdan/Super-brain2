"""Operator service behind ``/v2/operator/*`` (``user:cli`` only, spec 11.3): signer list/enroll/revoke.

Supports both a single-call ``handle(...)`` for direct tests and a three-phase execution model
(``prepare_call`` on the owner thread -> ``verify_pending`` off the owner thread -> ``commit_call`` on the owner
thread) so ``ssh-keygen`` subprocess verification never blocks ``OwnerLoop``.
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable, Mapping
from typing import TypeVar

from superbrain.application import _approvals_actions
from superbrain.application._approvals_types import (
    BootstrapProposalHandler,
    DoctorOperatorHandler,
    FixOwnerRunner,
    PendingApprovalCall,
    PendingDoctorFixCall,
    PendingDoctorReportCall,
    PreparedOperatorCall,
    RestoreHandler,
    _invalid,
    _journal_json,
    _proposal_json,
    _signer_json,
    _unauthenticated,
    prepare_bootstrap_call,
    prepare_doctor_fix_call,
    prepare_doctor_report_call,
)
from superbrain.application._approvals_types import (
    _b64 as _b64,
)
from superbrain.application.review_apply import ReviewApplyService
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RiskLevel,
    SignerRecord,
    assurance_for,
    canonical_utc,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.ports.approval import ApprovalPolicyPort, SshApprovalVerifierPort, WebAuthnApprovalVerifierPort

_R = TypeVar("_R")


def _run_inline(fn: Callable[[], _R]) -> _R:
    """``FixOwnerRunner`` for the direct ``handle`` path, which already runs on the owner."""
    return fn()


__all__ = [
    "BootstrapProposalHandler",
    "DoctorOperatorHandler",
    "OperatorHandle",
    "OperatorService",
    "PendingApprovalCall",
    "PendingDoctorReportCall",
    "PreparedOperatorCall",
    "RestoreHandler",
]

_PROPOSAL_PATH_ACTIONS: dict[str, ApprovalAction] = {
    "/v2/operator/proposal/approve": ApprovalAction.APPROVE,
    "/v2/operator/proposal/reject": ApprovalAction.REJECT,
    "/v2/operator/proposal/apply": ApprovalAction.APPLY,
    "/v2/operator/proposal/rollback": ApprovalAction.ROLLBACK,
}
_PROPOSAL_MUTATING_PATHS = frozenset(_PROPOSAL_PATH_ACTIONS)
_DEFERRED_PATHS = frozenset(
    {
        "/v2/operator/credential/revoke",
        "/v2/operator/policy/set",
        "/v2/operator/workspace/link",
        "/v2/operator/backup",
        "/v2/operator/job/cancel",
    }
)
_ENROLLMENT_FIELDS = frozenset({"channel", "public_key", "credential_id"})
_TERMINAL_APPROVAL_KEYS = frozenset({"message", "channel"})
_PASSKEY_APPROVAL_KEYS = frozenset({"message", "channel", "signer_id", "response_json"})
_SSH_APPROVAL_KEYS = frozenset({"message", "channel", "signer_id", "signature"})


class OperatorService:
    """Handles the admitted ``user:cli`` operator calls against the live policy store."""

    def __init__(
        self,
        policy: ApprovalPolicyPort,
        *,
        ssh_verifier: Callable[[], SshApprovalVerifierPort | None],
        webauthn_verifier: WebAuthnApprovalVerifierPort | None = None,
        review_apply: ReviewApplyService | None = None,
        restore_handler: RestoreHandler | None = None,
        bootstrap_handler: BootstrapProposalHandler | None = None,
        live_layer2_check: Callable[[], None] | None = None,
        doctor_handler: DoctorOperatorHandler | None = None,
    ) -> None:
        self._policy = policy
        self._ssh_verifier = ssh_verifier
        self._webauthn = webauthn_verifier
        self._review_apply = review_apply
        self._restore_handler = restore_handler
        self._bootstrap_handler = bootstrap_handler
        self._live_layer2_check = live_layer2_check
        self._doctor_handler = doctor_handler

    def rebind_authorities(
        self,
        policy: ApprovalPolicyPort,
        review_apply: ReviewApplyService | None,
        *,
        live_layer2_check: Callable[[], None] | None = None,
    ) -> None:
        """Update the live policy authority and review-apply service after an online restore."""
        self._policy = policy
        self._review_apply = review_apply
        if live_layer2_check is not None:
            self._live_layer2_check = live_layer2_check

    def _refresh_live_layer2(self) -> None:
        if self._live_layer2_check is not None:
            self._live_layer2_check()

    def handle(
        self,
        path: str,
        principal: Principal,
        body: Mapping[str, JsonValue],
        *,
        token: str | None = None,
    ) -> dict[str, JsonValue]:
        prepared = self.prepare_call(path, principal, body, token=token)
        if prepared.immediate is not None:
            return prepared.immediate
        if prepared.pending_doctor is not None:
            timeout_s = prepared.pending_doctor.wait_timeout_ms / 1000.0
            self.verify_doctor(prepared.pending_doctor, timeout_s=timeout_s)
            return self.commit_doctor(prepared.pending_doctor)
        if prepared.pending_fix is not None:
            return self.execute_doctor_fix(prepared.pending_fix, should_stop=lambda: False, run_on_owner=_run_inline)
        assert prepared.pending is not None
        new_sign_count = self.verify_pending(prepared.pending)
        return self.commit_call(prepared.pending, new_sign_count=new_sign_count)

    def prepare_call(
        self,
        path: str,
        principal: Principal,
        body: Mapping[str, JsonValue],
        *,
        token: str | None = None,
    ) -> PreparedOperatorCall:
        """Phase 1 (owner thread): verify live caller credential and either answer immediately or prepare crypto."""
        self._verify_caller(principal, token)
        if path == "/v2/operator/signer/list":
            if body:
                raise _invalid()
            return PreparedOperatorCall(immediate={"signers": [_signer_json(r) for r in self._policy.active_signers()]})
        if path == "/v2/operator/signer/enroll":
            return self._prepare_enroll(principal, token, body)
        if path == "/v2/operator/signer/revoke":
            return self._prepare_revoke(principal, token, body)
        if path == "/v2/operator/proposal/list":
            if body:
                raise _invalid()
            if self._review_apply is None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            owned = [p for p in self._review_apply.list_proposals() if p.owner_id == principal.owner_id]
            return PreparedOperatorCall(immediate={"proposals": [_proposal_json(p) for p in owned]})
        if path == "/v2/operator/proposal/show":
            if set(body) != {"proposal_id"} or not isinstance(body.get("proposal_id"), str) or not body["proposal_id"]:
                raise _invalid()
            if self._review_apply is None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            prop = self._review_apply.get_proposal(str(body["proposal_id"]))
            if prop.owner_id != principal.owner_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            return PreparedOperatorCall(immediate={"proposal": _proposal_json(prop)})
        if path == "/v2/operator/proposal/continue":
            if set(body) != {"proposal_id"} or not isinstance(body.get("proposal_id"), str) or not body["proposal_id"]:
                raise _invalid()
            if self._review_apply is None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            prop = self._review_apply.get_proposal(str(body["proposal_id"]))
            if prop.owner_id != principal.owner_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if prop.active_journal_id is None:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "no active journal to continue")
            journal = self._review_apply.continue_interrupted_journal(prop.active_journal_id)
            return PreparedOperatorCall(immediate={"journal": _journal_json(journal)})
        if path in _PROPOSAL_MUTATING_PATHS:
            return self._prepare_proposal_action(path, principal, token, body)
        if path == "/v2/operator/proposal/bootstrap":
            return prepare_bootstrap_call(
                principal, body, self._review_apply, self._bootstrap_handler, policy=self._policy
            )
        if path == "/v2/operator/restore":
            return self._prepare_restore(principal, token, body)
        if path == "/v2/operator/doctor/report":
            return prepare_doctor_report_call(principal, token, body, self._doctor_handler)
        if path == "/v2/operator/doctor/fix":
            return prepare_doctor_fix_call(principal, token, body, self._doctor_handler)
        if path in _DEFERRED_PATHS:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    def verify_pending(self, pending: PendingApprovalCall, *, timeout_s: float | None = None) -> int | None:
        """Phase 2 (off owner thread): verify proof; return new ``sign_count`` if passkey."""
        if pending.channel is ApprovalChannel.TERMINAL:
            return None
        signer = pending.signer
        if signer is None:
            raise _unauthenticated()
        if pending.channel is ApprovalChannel.PASSKEY_UV:
            return self._verify_passkey(pending.message, pending.raw_approval, signer)
        verifier = self._ssh_verifier()
        if verifier is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        signature = _b64(pending.raw_approval.get("signature"), urlsafe=False)
        sig = inspect.signature(verifier.verify)
        accepts_timeout = timeout_s is not None and (
            "timeout_s" in sig.parameters
            or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        )
        if accepts_timeout:
            assurance = verifier.verify(
                pending.message,
                channel=pending.channel,
                public_key=signer.public_key,
                signature=signature,
                timeout_s=timeout_s,  # type: ignore[call-arg]
            )
        else:
            assurance = verifier.verify(
                pending.message,
                channel=pending.channel,
                public_key=signer.public_key,
                signature=signature,
            )
        if assurance is not assurance_for(pending.channel):
            raise _unauthenticated()
        return None

    def commit_call(self, pending: PendingApprovalCall, *, new_sign_count: int | None) -> dict[str, JsonValue]:
        """Phase 3 (owner thread): re-verify live caller credential and commit mutation + ``sign_count`` atomically."""
        self._verify_caller(pending.principal, pending.token)
        if pending.channel is ApprovalChannel.TERMINAL:
            self._refresh_live_layer2()
        signer_id = pending.signer.signer_id if pending.signer is not None else None
        if pending.enrollment is not None:
            record = self._policy.enroll_signer(
                pending.enrollment,
                approval=pending.message,
                approver_signer_id=signer_id,
                channel=pending.channel,
                new_sign_count=new_sign_count,
            )
            return {"signer": _signer_json(record)}
        if pending.proposal_id is not None:
            return self._commit_proposal_action(pending, signer_id=signer_id, new_sign_count=new_sign_count)
        if pending.restore_target is not None:
            assert pending.restore_backup is not None and self._restore_handler is not None
            return self._restore_handler.execute(
                pending.restore_target,
                pending.restore_backup,
                pending.message,
                signer_id=signer_id,
                channel=pending.channel,
                new_sign_count=new_sign_count,
            )
        assert pending.revoke_signer_id is not None
        record = self._policy.revoke_signer(
            pending.revoke_signer_id,
            approval=pending.message,
            approver_signer_id=signer_id,
            channel=pending.channel,
            new_sign_count=new_sign_count,
        )
        return {"signer": _signer_json(record)}

    def verify_doctor(self, pending_doctor: PendingDoctorReportCall, *, timeout_s: float) -> None:
        """Phase 2 (off owner thread): wait up to ``timeout_s`` for background ``system.doctor`` completion."""
        if self._doctor_handler is None or pending_doctor.ticket is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        self._doctor_handler.wait_report(
            pending_doctor.ticket.job_id,
            generation=pending_doctor.ticket.generation,
            timeout_s=timeout_s,
        )

    def execute_doctor_fix(
        self,
        pending_fix: PendingDoctorFixCall,
        *,
        should_stop: Callable[[], bool],
        run_on_owner: FixOwnerRunner,
    ) -> dict[str, JsonValue]:
        """Phase 2 (off owner thread): run the admitted fix until done or until ``should_stop`` (the cutoff).

        Every step the fix sends to the owner first re-verifies the caller's live credential there, so a credential
        revoked after phase 1 stops the fix before its next write.
        """
        if self._doctor_handler is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

        def _checked_on_owner(fn: Callable[[], _R]) -> _R:
            def _step() -> _R:
                self._verify_caller(pending_fix.principal, pending_fix.token)
                return fn()

            return run_on_owner(_step)

        return self._doctor_handler.execute_fix(
            pending_fix.ticket, should_stop=should_stop, run_on_owner=_checked_on_owner
        )

    def commit_doctor(self, pending_doctor: PendingDoctorReportCall) -> dict[str, JsonValue]:
        """Phase 3 (owner thread): re-verify live caller credential + generation/epoch fences before reading DTO."""
        self._verify_caller(pending_doctor.principal, pending_doctor.token)
        if self._doctor_handler is None or pending_doctor.ticket is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._doctor_handler.finish_report(
            owner_id=pending_doctor.principal.owner_id,
            job_id=pending_doctor.ticket.job_id,
            generation=pending_doctor.ticket.generation,
            writer_epoch=pending_doctor.ticket.writer_epoch,
        )

    # --- internals -----------------------------------------------------------------------------------------------

    def _prepare_restore(
        self, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        return _approvals_actions._prepare_restore(self, principal, token, body)

    def _verify_caller(self, principal: Principal, token: str | None) -> None:
        if principal.harness_id != CLI_HARNESS_ID:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        if token is not None:
            resolved = self._policy.resolve_credential(token)
            if resolved != principal or resolved.harness_id != CLI_HARNESS_ID:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

    def _prepare_enroll(
        self, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        return _approvals_actions._prepare_enroll(self, principal, token, body)

    def _prepare_revoke(
        self, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        if not set(body) <= {"signer_id", "approval"} or not isinstance(body.get("signer_id"), str):
            raise _invalid()
        target = str(body["signer_id"])
        self._refresh_live_layer2()
        if "approval" not in body:
            return PreparedOperatorCall(immediate=self._challenge(ApprovalAction.SIGNER_REVOKE, target))
        message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
        return PreparedOperatorCall(
            pending=PendingApprovalCall(
                path="/v2/operator/signer/revoke",
                principal=principal,
                token=token,
                enrollment=None,
                revoke_signer_id=target,
                message=message,
                channel=channel_used,
                signer=signer,
                raw_approval=raw_approval,
            )
        )

    def _prepare_proposal_action(
        self, path: str, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        return _approvals_actions._prepare_proposal_action(self, path, principal, token, body)

    def _commit_proposal_action(
        self, pending: PendingApprovalCall, *, signer_id: str | None, new_sign_count: int | None
    ) -> dict[str, JsonValue]:
        return _approvals_actions._commit_proposal_action(
            self, pending, signer_id=signer_id, new_sign_count=new_sign_count,
        )

    def _challenge(self, action: ApprovalAction, subject_id: str) -> dict[str, JsonValue]:
        issued = self._policy.issue_nonce(action=action, subject_id=subject_id, risk_level=RiskLevel.HIGH)
        return {
            "challenge": {
                "store_id": self._policy.store_id,
                "action": issued.action.value,
                "subject_id": issued.subject_id,
                "risk_level": issued.risk_level.value,
                "trust_generation": issued.trust_generation,
                "nonce": issued.nonce,
                "expires_at": canonical_utc(issued.expires_at),
            }
        }

    def _parse_approval(
        self, principal: Principal, raw: JsonValue
    ) -> tuple[ApprovalMessage, ApprovalChannel, SignerRecord | None, Mapping[str, JsonValue]]:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("message"), Mapping):
            raise _invalid()
        raw_channel = raw.get("channel")
        if not isinstance(raw_channel, str):
            raise _invalid()
        try:
            channel = ApprovalChannel(raw_channel)
        except ValueError as err:
            raise _invalid() from err
        expected_keys = (
            _TERMINAL_APPROVAL_KEYS
            if channel is ApprovalChannel.TERMINAL
            else _PASSKEY_APPROVAL_KEYS
            if channel is ApprovalChannel.PASSKEY_UV
            else _SSH_APPROVAL_KEYS
        )
        if set(raw) != expected_keys:
            raise _invalid()
        message_raw = raw["message"]
        assert isinstance(message_raw, Mapping)
        message = ApprovalMessage.from_dict(message_raw)
        if message.owner_id != principal.owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        if channel is ApprovalChannel.TERMINAL:
            return message, channel, None, raw
        signer_id = raw.get("signer_id")
        if not isinstance(signer_id, str):
            raise _unauthenticated()
        signer = self._policy.signer(signer_id)
        if signer is None or signer.revoked or signer.channel is not channel or signer.owner_id != message.owner_id:
            raise _unauthenticated()
        return message, channel, signer, raw

    def _verify_passkey(self, message: ApprovalMessage, raw: Mapping[str, JsonValue], signer: SignerRecord) -> int:
        if self._webauthn is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        response = raw.get("response_json")
        if not isinstance(response, str) or signer.credential_id is None:
            raise _invalid()
        result = self._webauthn.verify(
            message,
            response_json=response,
            credential_id=_b64(signer.credential_id, urlsafe=True),
            credential_public_key=_b64(signer.public_key, urlsafe=True),
            stored_sign_count=signer.sign_count,
        )
        if result.assurance is not assurance_for(ApprovalChannel.PASSKEY_UV):
            raise _unauthenticated()
        return result.new_sign_count


class OperatorHandle:
    """Late-bound slot the owner session fills with its live ``OperatorService`` (owner-thread use only)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._service: OperatorService | None = None

    def bind(self, service: OperatorService) -> None:
        with self._lock:
            self._service = service

    def unbind(self) -> None:
        with self._lock:
            self._service = None

    def service(self) -> OperatorService | None:
        with self._lock:
            return self._service
