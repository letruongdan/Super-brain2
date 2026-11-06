"""Typed errors: every failure that leaves an API is a BrainError with an ErrorCode."""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class ErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    IDENTITY_MISMATCH = "identity_mismatch"
    NOT_FOUND = "not_found"
    QUARANTINED = "quarantined"
    REVISION_CONFLICT = "revision_conflict"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    IN_PROGRESS = "in_progress"
    COMMIT_OUTCOME_UNKNOWN = "commit_outcome_unknown"
    STORE_BUSY = "store_busy"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    UNSUPPORTED_VERSION = "unsupported_version"
    MIGRATION_REQUIRED = "migration_required"
    WRITER_HELD = "writer_held"
    UNSAFE_PATH = "unsafe_path"
    INSECURE_PERMISSIONS = "insecure_permissions"
    INTEGRITY_FAILURE = "integrity_failure"
    STORAGE_FULL = "storage_full"
    FILESYSTEM_BUSY = "filesystem_busy"
    IO_ERROR = "io_error"
    UNAUTHENTICATED = "unauthenticated"
    DAEMON_UNAVAILABLE = "daemon_unavailable"
    POLICY_UNAVAILABLE = "policy_unavailable"


class BrainError(Exception):
    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message


_DEFAULT_WIRE_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INVALID_INPUT: "invalid input",
    ErrorCode.IDENTITY_MISMATCH: "identity mismatch",
    ErrorCode.NOT_FOUND: "not found",
    ErrorCode.QUARANTINED: "quarantined",
    ErrorCode.REVISION_CONFLICT: "revision conflict",
    ErrorCode.IDEMPOTENCY_CONFLICT: "idempotency conflict",
    ErrorCode.IN_PROGRESS: "operation in progress",
    ErrorCode.COMMIT_OUTCOME_UNKNOWN: "commit outcome unknown",
    ErrorCode.STORE_BUSY: "store busy",
    ErrorCode.DEADLINE_EXCEEDED: "deadline exceeded",
    ErrorCode.CAPABILITY_UNAVAILABLE: "capability unavailable",
    ErrorCode.UNSUPPORTED_VERSION: "unsupported version",
    ErrorCode.MIGRATION_REQUIRED: "migration required",
    ErrorCode.WRITER_HELD: "writer lock held",
    ErrorCode.UNSAFE_PATH: "unsafe path",
    ErrorCode.INSECURE_PERMISSIONS: "insecure permissions",
    ErrorCode.INTEGRITY_FAILURE: "integrity failure",
    ErrorCode.STORAGE_FULL: "storage full",
    ErrorCode.FILESYSTEM_BUSY: "filesystem busy",
    ErrorCode.IO_ERROR: "I/O error",
    ErrorCode.UNAUTHENTICATED: "unauthenticated",
    ErrorCode.DAEMON_UNAVAILABLE: "daemon unavailable",
    ErrorCode.POLICY_UNAVAILABLE: "policy unavailable",
}

SAFE_WIRE_MESSAGES_BY_CODE: Mapping[ErrorCode, str] = MappingProxyType(_DEFAULT_WIRE_MESSAGES)

_EXTRA_SAFE_WIRE_MESSAGES: frozenset[str] = frozenset(
    {
        "unsupported schema version",
        "principal identity mismatch",
        "missing required field",
        "unknown field",
        "duplicate object key",
        "payload exceeds size limit",
        "string exceeds size limit",
        "array exceeds length limit",
        "nesting depth exceeded",
        "invalid UTF-8 encoding",
        "unpaired surrogate",
        "non-finite number",
        "malformed JSON",
        "boolean not allowed for integer",
        "mixed or invalid workspace selector",
        "deep health requires idempotency_key",
        "shallow health forbids idempotency_key",
        "duplicate resource digest name",
        "forbidden client-supplied authority field",
    }
)

SAFE_WIRE_MESSAGES: frozenset[str] = frozenset(_DEFAULT_WIRE_MESSAGES.values()) | _EXTRA_SAFE_WIRE_MESSAGES


def is_safe_wire_message(message: str) -> bool:
    """Return True iff ``message`` is a static allowlisted wire error description."""
    return isinstance(message, str) and message in SAFE_WIRE_MESSAGES


def safe_wire_message(code: ErrorCode, message: str | None = None) -> str:
    """Return ``message`` when allowlisted, otherwise the static default for ``code``."""
    if message is not None and is_safe_wire_message(message):
        return message
    return _DEFAULT_WIRE_MESSAGES[code]


def brain_error_wire_message(error: BrainError) -> str:
    """Extract an allowlisted wire message from ``error``, stripping raw exception/input text."""
    return safe_wire_message(error.code, error.message)
