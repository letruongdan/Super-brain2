"""Typed errors: every failure that leaves an API is a BrainError with an ErrorCode."""

from enum import StrEnum


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


class BrainError(Exception):
    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
