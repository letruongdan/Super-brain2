"""OperatorService restore, enroll and proposal approve/reject preparation and commit."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from superbrain.application import approvals as _m
from superbrain.application._approvals_types import (
    PendingApprovalCall,
    PreparedOperatorCall,
    _invalid,
    _journal_json,
    _proposal_json,
    prepare_proposal_challenge,
)
from superbrain.application._approvals_types import (
    _b64 as _b64,
)
from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal


def _prepare_restore(
    self: _m.OperatorService, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
) -> PreparedOperatorCall:
    if not set(body) <= {"target", "backup", "approval"}:
        raise _invalid()
    raw_target = body.get("target")
    raw_backup = body.get("backup")
    if (
        raw_target not in ("store", "policy")
        or not isinstance(raw_backup, str)
        or not raw_backup
        or "\x00" in raw_backup
    ):
        raise _invalid()
    backup_path = Path(raw_backup)
    if ".." in backup_path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not backup_path.is_absolute():
        raise _invalid()
    if self._restore_handler is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    target_kind: Literal["store", "policy"] = "store" if raw_target == "store" else "policy"
    if "approval" not in body:
        return PreparedOperatorCall(immediate=self._restore_handler.preview(target_kind, backup_path))
    message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
    if channel_used is ApprovalChannel.TERMINAL:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    if message.action is not ApprovalAction.RESTORE or message.risk_level is not RiskLevel.HIGH:
        raise _invalid()
    self._restore_handler.validate_execute(target_kind, backup_path, message)
    return PreparedOperatorCall(
        pending=PendingApprovalCall(
            path="/v2/operator/restore",
            principal=principal,
            token=token,
            enrollment=None,
            revoke_signer_id=None,
            message=message,
            channel=channel_used,
            signer=signer,
            raw_approval=raw_approval,
            restore_target=target_kind,
            restore_backup=backup_path,
        )
    )


def _prepare_enroll(
    self: _m.OperatorService, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
) -> PreparedOperatorCall:
    if not set(body) <= {"enrollment", "approval"} or "enrollment" not in body:
        raise _invalid()
    raw = body["enrollment"]
    if (
        not isinstance(raw, Mapping)
        or not set(raw) <= _m._ENROLLMENT_FIELDS
        or not {"channel", "public_key"} <= set(raw)
    ):
        raise _invalid()
    channel, key, credential = raw["channel"], raw["public_key"], raw.get("credential_id")
    if (
        not isinstance(channel, str)
        or not isinstance(key, str)
        or not (credential is None or isinstance(credential, str))
    ):
        raise _invalid()
    try:
        parsed = ApprovalChannel(channel)
    except ValueError as err:
        raise _invalid() from err
    enrollment = SignerEnrollment(
        owner_id=principal.owner_id, channel=parsed, public_key=key, credential_id=credential
    )
    self._refresh_live_layer2()
    if "approval" not in body:
        return PreparedOperatorCall(immediate=self._challenge(ApprovalAction.SIGNER_ENROLL, enrollment.subject_id))
    message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
    return PreparedOperatorCall(
        pending=PendingApprovalCall(
            path="/v2/operator/signer/enroll",
            principal=principal,
            token=token,
            enrollment=enrollment,
            revoke_signer_id=None,
            message=message,
            channel=channel_used,
            signer=signer,
            raw_approval=raw_approval,
        )
    )


def _prepare_proposal_action(
    self: _m.OperatorService, path: str, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
) -> PreparedOperatorCall:
    pid = body.get("proposal_id")
    if not isinstance(pid, str) or not pid:
        raise _invalid()
    allowed_keys = {"proposal_id", "approval"} if "approval" in body else {"proposal_id", "recovery_scope"}
    if not set(body) <= allowed_keys:
        raise _invalid()
    if self._review_apply is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    prop = self._review_apply.get_proposal(pid)
    if prop.owner_id != principal.owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    action = _m._PROPOSAL_PATH_ACTIONS[path]
    self._refresh_live_layer2()
    if "approval" not in body:
        return prepare_proposal_challenge(self._policy, self._review_apply, prop, action=action, body=body)
    message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
    if message.action is not action:
        raise _invalid()
    if message.subject_id != pid or message.subject_revision != prop.subject_revision:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    return PreparedOperatorCall(
        pending=PendingApprovalCall(
            path=path,
            principal=principal,
            token=token,
            enrollment=None,
            revoke_signer_id=None,
            message=message,
            channel=channel_used,
            signer=signer,
            raw_approval=raw_approval,
            proposal_id=pid,
        )
    )


def _commit_proposal_action(
    self: _m.OperatorService, pending: PendingApprovalCall, *, signer_id: str | None, new_sign_count: int | None
) -> dict[str, JsonValue]:
    if self._review_apply is None or pending.proposal_id is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    pid = pending.proposal_id
    if pending.path == "/v2/operator/proposal/approve":
        prop = self._review_apply.approve_proposal(
            pid,
            approval=pending.message,
            signer_id=signer_id,
            channel=pending.channel,
            new_sign_count=new_sign_count,
        )
        return {"proposal": _proposal_json(prop)}
    if pending.path == "/v2/operator/proposal/reject":
        prop = self._review_apply.reject_proposal(
            pid,
            approval=pending.message,
            signer_id=signer_id,
            channel=pending.channel,
            new_sign_count=new_sign_count,
        )
        return {"proposal": _proposal_json(prop)}
    if pending.path == "/v2/operator/proposal/apply":
        journal = self._review_apply.apply_proposal(
            pid,
            approval=pending.message,
            signer_id=signer_id,
            channel=pending.channel,
            new_sign_count=new_sign_count,
        )
        return {"journal": _journal_json(journal)}
    plan = self._review_apply.plan_rollback_targets(pid)
    journal = self._review_apply.rollback_applied_proposal(
        pid,
        approval=pending.message,
        signer_id=signer_id,
        channel=pending.channel,
        plan=plan,
        new_sign_count=new_sign_count,
    )
    return {"journal": _journal_json(journal)}
