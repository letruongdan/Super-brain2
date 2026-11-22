"""Value types, protocols, and JSON serialization helpers for ``application.approvals``."""

from __future__ import annotations

import base64
import binascii
import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from superbrain.application.review_apply import ReviewApplyService
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    SignerEnrollment,
    SignerRecord,
    strict_b64url_decode,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.core.proposals import ApplyJournal, ChangeProposal
from superbrain.ports.approval import ApprovalPolicyPort


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _unauthenticated() -> BrainError:
    return BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


def _b64(value: object, *, urlsafe: bool) -> bytes:
    if urlsafe:
        return strict_b64url_decode(value)
    if not isinstance(value, str) or not value:
        raise _invalid()
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as err:
        raise _invalid() from err


def _signer_json(record: SignerRecord) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {
        "signer_id": record.signer_id,
        "owner_id": record.owner_id,
        "channel": record.channel.value,
        "key_digest": record.key_digest,
        "tofu": record.tofu,
    }
    if record.credential_id is not None:
        out["credential_id"] = record.credential_id
    return out


def _proposal_json(prop: ChangeProposal) -> dict[str, JsonValue]:
    return {
        "proposal_id": prop.proposal_id,
        "owner_id": prop.owner_id,
        "kind": prop.kind,
        "reason": prop.reason,
        "status": prop.status.value,
        "subject_revision": prop.subject_revision,
        "risk_level": prop.risk_level.value,
        "active_journal_id": prop.active_journal_id,
        "created_at": prop.created_at,
        "updated_at": prop.updated_at,
        "targets": [
            {
                "rel_path": t.rel_path,
                "normalized_rel_path": t.normalized_rel_path,
                "managed_format": t.managed_format.value,
                "slice_id": t.slice_id,
                "base_present": t.base_present,
            }
            for t in prop.targets
        ],
    }


def _journal_json(journal: ApplyJournal) -> dict[str, JsonValue]:
    return {
        "journal_id": journal.journal_id,
        "proposal_id": journal.proposal_id,
        "direction": journal.direction.value,
        "status": journal.status.value,
        "grant_id": journal.grant_id,
        "created_at": journal.created_at,
        "updated_at": journal.updated_at,
    }


@dataclass(frozen=True)
class PendingApprovalCall:
    """Validated approval-gated operator mutation awaiting off-owner-thread crypto verification."""

    path: str
    principal: Principal
    token: str | None
    enrollment: SignerEnrollment | None
    revoke_signer_id: str | None
    message: ApprovalMessage
    channel: ApprovalChannel
    signer: SignerRecord | None
    raw_approval: Mapping[str, JsonValue]
    proposal_id: str | None = None
    restore_target: Literal["store", "policy"] | None = None
    restore_backup: Path | None = None


class RestoreHandler(Protocol):
    """Composition-supplied online restore preview/validation/execution handler."""

    def preview(self, target: Literal["store", "policy"], backup: Path) -> dict[str, JsonValue]: ...

    def validate_execute(
        self,
        target: Literal["store", "policy"],
        backup: Path,
        message: ApprovalMessage,
    ) -> None: ...

    def execute(
        self,
        target: Literal["store", "policy"],
        backup: Path,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None,
    ) -> dict[str, JsonValue]: ...


@dataclass(frozen=True)
class DoctorOperatorTicket:
    """Owner-thread snapshot capturing doctor job identity and generation/epoch fences."""

    job_id: str
    generation: int
    writer_epoch: int
    checkout_root: Path | None = None
    immediate: dict[str, JsonValue] | None = None


@dataclass(frozen=True)
class PendingDoctorReportCall:
    """Validated `/v2/operator/doctor/report` call waiting off-owner for worker completion."""

    principal: Principal
    token: str | None = None
    ticket: DoctorOperatorTicket | None = None
    wait_timeout_ms: int = 10_000


class DoctorOperatorHandler(Protocol):
    """Composition-supplied background doctor enqueue/wait/read bridge for operator routes."""

    def prepare_report(
        self,
        *,
        owner_id: str,
        checkout_root: Path | None = None,
    ) -> DoctorOperatorTicket: ...

    def wait_report(
        self,
        job_id: str,
        *,
        generation: int,
        timeout_s: float,
    ) -> None: ...

    def finish_report(
        self,
        *,
        owner_id: str,
        job_id: str,
        generation: int,
        writer_epoch: int,
    ) -> dict[str, JsonValue]: ...

    def run_fix(
        self,
        *,
        owner_id: str,
        body: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue]: ...


def prepare_doctor_fix_call(
    principal: Principal,
    body: Mapping[str, JsonValue],
    doctor_handler: DoctorOperatorHandler | None,
) -> PreparedOperatorCall:
    """Validate and execute `/v2/operator/doctor/fix` under operator owner admission."""
    if doctor_handler is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    return PreparedOperatorCall(immediate=doctor_handler.run_fix(owner_id=principal.owner_id, body=body))


def prepare_doctor_report_call(
    principal: Principal,
    token: str | None,
    body: Mapping[str, JsonValue],
    doctor_handler: DoctorOperatorHandler | None,
) -> PreparedOperatorCall:
    """Validate `/v2/operator/doctor/report` body and enqueue or reuse an owner-isolated ``DoctorRun``."""
    if not set(body) <= {"wait_timeout_ms", "checkout_root"}:
        raise _invalid()
    wait_timeout_ms = 10_000
    if "wait_timeout_ms" in body:
        raw_wait = body["wait_timeout_ms"]
        if type(raw_wait) is not int or raw_wait < 0 or raw_wait > 10_000:
            raise _invalid()
        wait_timeout_ms = raw_wait
    checkout_root: Path | None = None
    if "checkout_root" in body:
        raw_co = body["checkout_root"]
        if raw_co is not None:
            if not isinstance(raw_co, str) or not raw_co or "\x00" in raw_co:
                raise _invalid()
            parsed_co = Path(raw_co)
            if ".." in parsed_co.parts:
                raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
            if not parsed_co.is_absolute():
                raise _invalid()
            checkout_root = parsed_co
    if doctor_handler is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    ticket = doctor_handler.prepare_report(owner_id=principal.owner_id, checkout_root=checkout_root)
    if ticket.immediate is not None:
        return PreparedOperatorCall(immediate=ticket.immediate)
    return PreparedOperatorCall(
        pending_doctor=PendingDoctorReportCall(
            principal=principal,
            token=token,
            ticket=ticket,
            wait_timeout_ms=wait_timeout_ms,
        )
    )


@dataclass(frozen=True)
class PreparedOperatorCall:
    immediate: dict[str, JsonValue] | None = None
    pending: PendingApprovalCall | None = None
    pending_doctor: PendingDoctorReportCall | None = None


class BootstrapProposalHandler(Protocol):
    """Callable creating a checkout-scoped bootstrap ``ChangeProposal``."""

    def __call__(
        self,
        review_apply: ReviewApplyService,
        *,
        owner_id: str,
        harness_id: str,
        checkout_root: Path,
        harness_profile_path: Path,
        reason: str | None = None,
    ) -> ChangeProposal: ...


def prepare_bootstrap_call(
    principal: Principal,
    body: Mapping[str, JsonValue],
    review_apply: ReviewApplyService | None,
    bootstrap_handler: BootstrapProposalHandler | None,
    *,
    policy: ApprovalPolicyPort | None = None,
) -> PreparedOperatorCall:
    """Validate `/v2/operator/proposal/bootstrap` body and build a ``PENDING`` bootstrap proposal."""
    if not set(body) <= {"harness", "checkout_root", "harness_profile_path", "reason"}:
        raise _invalid()
    harness = body.get("harness")
    checkout_raw = body.get("checkout_root")
    harness_profile_raw = body.get("harness_profile_path")
    reason = body.get("reason")
    if (
        not isinstance(harness, str)
        or harness not in ("claude-code", "codex")
        or not isinstance(checkout_raw, str)
        or not checkout_raw
        or "\x00" in checkout_raw
        or not Path(checkout_raw).is_absolute()
        or not isinstance(harness_profile_raw, str)
        or not harness_profile_raw
        or "\x00" in harness_profile_raw
        or not Path(harness_profile_raw).is_absolute()
    ):
        raise _invalid()
    if ".." in Path(checkout_raw).parts or ".." in Path(harness_profile_raw).parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if reason is not None and (not isinstance(reason, str) or not reason or "\x00" in reason):
        raise _invalid()
    if review_apply is None or bootstrap_handler is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    sig = inspect.signature(bootstrap_handler)
    if policy is not None and (
        "policy" in sig.parameters
        or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    ):
        prop = bootstrap_handler(
            review_apply,
            owner_id=principal.owner_id,
            harness_id=harness,
            checkout_root=Path(checkout_raw),
            harness_profile_path=Path(harness_profile_raw),
            reason=reason,
            policy=policy,  # type: ignore[call-arg]
        )
    else:
        prop = bootstrap_handler(
            review_apply,
            owner_id=principal.owner_id,
            harness_id=harness,
            checkout_root=Path(checkout_raw),
            harness_profile_path=Path(harness_profile_raw),
            reason=reason,
        )
    return PreparedOperatorCall(immediate={"proposal": _proposal_json(prop)})


def prepare_proposal_challenge(
    policy: ApprovalPolicyPort,
    review_apply: ReviewApplyService,
    prop: ChangeProposal,
    *,
    action: ApprovalAction,
    body: Mapping[str, JsonValue],
) -> PreparedOperatorCall:
    """Issue a nonce-bound challenge + proposal snapshot for approve/reject/apply/rollback."""
    raw_scope = body.get("recovery_scope")
    if raw_scope is None:
        scope = (
            RecoveryScope.CONTINUE_OR_ROLLBACK
            if action is ApprovalAction.APPLY
            else RecoveryScope.ROLLBACK
            if action is ApprovalAction.ROLLBACK
            else RecoveryScope.NONE
        )
    else:
        if not isinstance(raw_scope, str):
            raise _invalid()
        try:
            scope = RecoveryScope(raw_scope)
        except ValueError as err:
            raise _invalid() from err
    if action is ApprovalAction.ROLLBACK:
        plan = review_apply.plan_rollback_targets(prop.proposal_id)
        subject_revision = plan.subject_revision
        resource_digests = plan.resource_digests
        target_files = plan.target_files
    else:
        subject_revision = prop.subject_revision
        resource_digests = prop.resource_digests
        target_files = prop.to_target_files()
    issued = policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    msg = ApprovalMessage(
        store_id=policy.store_id,
        owner_id=prop.owner_id,
        trust_generation=issued.trust_generation,
        action=action,
        subject_id=prop.proposal_id,
        subject_revision=subject_revision,
        resource_digests=resource_digests,
        target_files=target_files,
        risk_level=prop.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=scope,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )
    return PreparedOperatorCall(immediate={"challenge": msg.to_dict(), "proposal": _proposal_json(prop)})
