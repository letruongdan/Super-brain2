"""Pure Task 4 kernel types: CallResult, StagedBlob, IdempotencyRow, PrivateRequestAuth, and RequestAuthView."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TypeAlias

from superbrain.core._kernel_auth import AuthSnapshot
from superbrain.core._kernel_base import (
    ObjectRef,
    Principal,
    is_strict_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._kernel_workspace import require_canonical_timestamp, require_uuid
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

CallResult: TypeAlias = dict[str, JsonValue]
"""Validated MCP v2 tool envelope dictionary (``{"ok": True, "data": ...}`` or ``{"ok": False, "error": ...}``)."""

IDEMPOTENCY_TTL = timedelta(days=30)
"""Fixed 30-day idempotency retention window measured from the winning commit timestamp (C4)."""

IDEMPOTENCY_CLOCK_HWM_META_KEY = "idempotency_clock_hwm_utc"
"""Operational ``meta`` key recording the highest observed wall UTC timestamp in the main store (C4)."""

IDEMPOTENCY_CLOCK_UNTRUSTED_CODE = "idempotency_clock_untrusted"
"""Degraded health code exposed when C4 detects wall-clock regression or missing/corrupt watermark state."""

REDACTED_REASON_DEFAULT = "access_restricted"
"""Generic wire reason used when a recorded ref is quarantined, tombstoned, grant-revoked, or out of scope."""


def parse_canonical_utc(value: object) -> datetime:
    """Validate and parse a canonical ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` UTC timestamp."""
    checked = require_canonical_timestamp(value)
    try:
        return datetime.strptime(checked, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err


def require_aware_utc(moment: object) -> tuple[datetime, str]:
    """Validate ``moment`` is an aware UTC ``datetime`` and return ``(microsecond_utc_dt, canonical_str)``."""
    if not isinstance(moment, datetime):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    formatted = moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    normalized = datetime.strptime(formatted, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    return normalized, formatted


@dataclass(frozen=True)
class StagedBlob:
    """Root-bound proof that a safe CAS blob was durably staged before the SQLite business transaction (C2)."""

    store_id: str
    digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_sha256_digest(self.digest)
        if not is_strict_int(self.size_bytes) or self.size_bytes < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class PrivateRequestAuth:
    """RAM-only transport authentication handoff for owner live credential recheck (C3).

    ``token`` is excluded from ``repr`` and never enters ``Call.arguments``, HMAC, ledger, or disk.
    """

    credential_id: str
    principal: Principal
    token: str = field(repr=False)

    def __post_init__(self) -> None:
        require_uuid(self.credential_id)
        if not isinstance(self.principal, Principal):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.token, str) or not self.token:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


@dataclass(frozen=True)
class RequestAuthView:
    """Immutable owner-published RAM snapshot of policy auth state and active per-store HMAC key (C3)."""

    version: int
    auth: AuthSnapshot
    active_request_key_id: str
    active_request_key_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        require_positive_int(self.version)
        if not isinstance(self.auth, AuthSnapshot):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(self.active_request_key_id, label="active_request_key_id")
        if type(self.active_request_key_bytes) is not bytes or len(self.active_request_key_bytes) != 32:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class IdempotencyRow:
    """Durable operational idempotency record in ``store4`` (IDs, digests, and typed ``ObjectRef``s only)."""

    principal_id: str
    tool: str
    key_hash: str
    request_digest_key_id: str
    request_digest: str
    result_id: str
    assignment_id: str | None
    refs: tuple[ObjectRef, ...]
    committed_at: str

    def __post_init__(self) -> None:
        require_opaque_id(self.principal_id, label="principal_id")
        if not isinstance(self.tool, str) or not self.tool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_sha256_digest(self.key_hash)
        require_opaque_id(self.request_digest_key_id, label="request_digest_key_id")
        require_sha256_digest(self.request_digest)
        require_opaque_id(self.result_id, label="result_id")
        if self.assignment_id is not None:
            require_opaque_id(self.assignment_id, label="assignment_id")
        if not isinstance(self.refs, tuple) or not all(isinstance(r, ObjectRef) for r in self.refs):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        parse_canonical_utc(self.committed_at)

    def committed_at_utc(self) -> datetime:
        return parse_canonical_utc(self.committed_at)
