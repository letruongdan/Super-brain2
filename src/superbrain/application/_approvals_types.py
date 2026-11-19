"""Value types, protocols, and JSON serialization helpers for ``application.approvals``."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from superbrain.core._kernel_approval import (
    ApprovalChannel,
    ApprovalMessage,
    SignerEnrollment,
    SignerRecord,
    strict_b64url_decode,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.core.proposals import ApplyJournal, ChangeProposal


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
    return {
        "signer_id": record.signer_id,
        "channel": record.channel.value,
        "key_digest": record.key_digest,
        "tofu": record.tofu,
    }


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
class PreparedOperatorCall:
    immediate: dict[str, JsonValue] | None = None
    pending: PendingApprovalCall | None = None
