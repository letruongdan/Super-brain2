"""Pure Task 5 Job / ProviderInvocation types (spec 6.4, D5): states, lease token, outcomes, accounting records.

Re-exported by ``core.kernel``; imports only ``core._kernel_base``/``core._kernel_workspace`` leaves (no cycle).
Decimal quantities are canonical decimal strings that only ever reach CAS descriptors, never the ledger or a log.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import TypeAlias

from superbrain.core._json_parse import parse_json
from superbrain.core._kernel_base import (
    ObjectRef,
    is_strict_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._kernel_workspace import require_canonical_timestamp, require_uuid
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

MAX_JOB_ATTEMPTS = 3
"""Attempt 3 that fails retryably or loses its lease goes to ``dead_letter`` (spec 6.4, J1)."""
DEAD_LETTER_RETENTION = timedelta(days=30)
"""Dead-letter metadata retention (spec 5.6); cleanup records ``job.retention_expired``."""
RECOVERY_BATCH = 100
"""At most this many rows are recovered per owner transaction (resumable batches)."""
MAX_RESULT_REFS = 1024
_RETRY_BACKOFF = {1: timedelta(seconds=1), 2: timedelta(seconds=2)}
_DECIMAL_RE = re.compile(r"(0|[1-9][0-9]{0,30})(\.[0-9]{0,17}[1-9])?")


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _integrity() -> BrainError:
    return BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


class JobState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"


class AccountingStatus(StrEnum):
    NONE = "none"
    RESERVED = "reserved"
    SETTLED = "settled"
    OUTCOME_UNKNOWN = "outcome_unknown"


TERMINAL_JOB_STATES: frozenset[JobState] = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED, JobState.DEAD_LETTER}
)


class InvocationState(StrEnum):
    """Accounting state of one ``ProviderInvocation`` (owned by the ``provider_invocations`` reducer)."""

    RESERVED = "reserved"
    SETTLED = "settled"
    OUTCOME_UNKNOWN = "outcome_unknown"


class JobErrorCode(StrEnum):
    """The only failure detail a job, its ledger or a dead letter keeps: a code, never ``str(exc)`` or payload."""

    HANDLER_FAILED = "handler_failed"
    HANDLER_UNAVAILABLE = "handler_unavailable"
    INVALID_PAYLOAD = "invalid_payload"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    LEASE_LOST = "lease_lost"


def retry_backoff(attempt: int) -> timedelta:
    """Delay before the retry that follows a retryable failure of ``attempt`` (1 s after 1, 2 s after 2; J2)."""
    delay = _RETRY_BACKOFF.get(attempt) if is_strict_int(attempt) else None
    if delay is None:
        raise _invalid()
    return delay


def require_decimal(value: object) -> str:
    """Require a canonical non-negative decimal string (no sign, exponent, leading or trailing zeros)."""
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _optional_id(value: object) -> str | None:
    return None if value is None else require_opaque_id(value)


@dataclass(frozen=True)
class JobSpec:
    """Immutable, safe job request: kind, owner/scope and payload bytes (staged in CAS by the owner side)."""

    kind: str
    owner_id: str
    payload: bytes = field(repr=False)
    repo_id: str | None = None
    checkout_id: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.kind, label="kind")
        require_opaque_id(self.owner_id, label="owner_id")
        if type(self.payload) is not bytes:
            raise _invalid()
        _optional_id(self.repo_id)
        _optional_id(self.checkout_id)
        if self.checkout_id is not None and self.repo_id is None:
            raise _invalid()


@dataclass(frozen=True)
class JobRef:
    job_id: str
    state: JobState
    attempt: int

    def __post_init__(self) -> None:
        require_uuid(self.job_id)
        if not isinstance(self.state, JobState):
            raise _invalid()
        require_positive_int(self.attempt)


@dataclass(frozen=True)
class JobLease:
    """Lease token ``{job_id, attempt, writer_epoch, lease_id}``: every transition after enqueue is fenced by it."""

    job_id: str
    attempt: int
    writer_epoch: int
    lease_id: str

    def __post_init__(self) -> None:
        require_uuid(self.job_id)
        require_positive_int(self.attempt)
        require_positive_int(self.writer_epoch)
        require_uuid(self.lease_id)


def _require_refs(refs: object) -> tuple[ObjectRef, ...]:
    if (
        not isinstance(refs, tuple)
        or len(refs) > MAX_RESULT_REFS
        or not all(isinstance(ref, ObjectRef) for ref in refs)
        or len(set(refs)) != len(refs)
    ):
        raise _invalid()
    return refs


@dataclass(frozen=True)
class JobOutcome:
    """Result of one running attempt: success with validated safe refs, or a typed (non)retryable failure."""

    succeeded: bool
    result_refs: tuple[ObjectRef, ...] = ()
    retryable: bool = False
    error_code: JobErrorCode | None = None

    def __post_init__(self) -> None:
        if type(self.succeeded) is not bool or type(self.retryable) is not bool:
            raise _invalid()
        _require_refs(self.result_refs)
        if self.succeeded:
            if self.retryable or self.error_code is not None:
                raise _invalid()
        elif not isinstance(self.error_code, JobErrorCode) or self.result_refs:
            raise _invalid()

    @classmethod
    def success(cls, result_refs: tuple[ObjectRef, ...] = ()) -> JobOutcome:
        return cls(succeeded=True, result_refs=result_refs)

    @classmethod
    def failure(cls, code: JobErrorCode, *, retryable: bool) -> JobOutcome:
        return cls(succeeded=False, retryable=retryable, error_code=code)


@dataclass(frozen=True)
class UsageReservation:
    """Maximum cost reserved for one provider invocation before work is handed to the worker."""

    max_amount: str

    def __post_init__(self) -> None:
        require_decimal(self.max_amount)


@dataclass(frozen=True)
class UsageRecord:
    """Final usage of one invocation: a decimal string, or ``None`` with ``complete=False`` (unknown, never "0")."""

    amount: str | None
    complete: bool

    def __post_init__(self) -> None:
        if type(self.complete) is not bool:
            raise _invalid()
        if self.complete:
            require_decimal(self.amount)
        elif self.amount is not None:
            raise _invalid()


def reservation_descriptor(invocation_id: str, job_id: str, reservation: UsageReservation) -> bytes:
    """Canonical-JSON CAS descriptor of ``reservation`` (held by ``invocation_id``)."""
    if not isinstance(reservation, UsageReservation):
        raise _invalid()
    body: dict[str, JsonValue] = {
        "schema": "provider-reservation-v1",
        "invocation_id": require_uuid(invocation_id),
        "job_id": require_uuid(job_id),
        "max_amount": reservation.max_amount,
    }
    return canonical_json(body)


def usage_descriptor(invocation_id: str, usage: UsageRecord) -> bytes:
    """Canonical-JSON CAS descriptor of ``usage`` (held by ``invocation_id``): identical usage, identical digest."""
    if not isinstance(usage, UsageRecord):
        raise _invalid()
    body: dict[str, JsonValue] = {
        "schema": "provider-usage-v1",
        "invocation_id": require_uuid(invocation_id),
        "amount": usage.amount,
        "complete": usage.complete,
    }
    return canonical_json(body)


def result_descriptor(job_id: str, refs: tuple[ObjectRef, ...]) -> bytes:
    """Canonical-JSON CAS descriptor of a job's validated result refs (held by ``job_id``)."""
    body: dict[str, JsonValue] = {
        "schema": "job-result-v1",
        "job_id": require_uuid(job_id),
        "refs": [ref.to_dict() for ref in _require_refs(refs)],
    }
    return canonical_json(body)


def decode_result_descriptor(job_id: str, raw: bytes) -> tuple[ObjectRef, ...]:
    """Decode a ``result_descriptor`` of ``job_id``; anything else is ``INTEGRITY_FAILURE``."""
    try:
        parsed = parse_json(raw)
        if not isinstance(parsed, dict) or set(parsed) != {"schema", "job_id", "refs"}:
            raise _integrity()
        refs = parsed["refs"]
        if parsed["schema"] != "job-result-v1" or parsed["job_id"] != job_id or not isinstance(refs, list):
            raise _integrity()
        decoded = tuple(ObjectRef.from_dict(item) for item in refs if isinstance(item, dict))
        if len(decoded) != len(refs):
            raise _integrity()
        return _require_refs(decoded)
    except BrainError as err:
        raise _integrity() from err


@dataclass(frozen=True)
class JobRecord:
    """One ``p_jobs_state`` row as read inside a transaction (metadata and digests only)."""

    job_id: str
    owner_id: str
    repo_id: str | None
    checkout_id: str | None
    kind: str
    payload_digest: str
    state: JobState
    attempt: int
    retry_at: str
    writer_epoch: int | None
    lease_id: str | None
    reason: JobErrorCode | None
    result_digest: str | None
    finished_at: str | None

    def __post_init__(self) -> None:
        require_uuid(self.job_id)
        require_opaque_id(self.owner_id)
        _optional_id(self.repo_id)
        _optional_id(self.checkout_id)
        require_opaque_id(self.kind)
        require_sha256_digest(self.payload_digest)
        if not isinstance(self.state, JobState) or (
            self.reason is not None and not isinstance(self.reason, JobErrorCode)
        ):
            raise _invalid()
        require_positive_int(self.attempt)
        require_canonical_timestamp(self.retry_at)
        if self.writer_epoch is not None:
            require_positive_int(self.writer_epoch)
        if self.lease_id is not None:
            require_uuid(self.lease_id)
        if self.result_digest is not None:
            require_sha256_digest(self.result_digest)
        if self.finished_at is not None:
            require_canonical_timestamp(self.finished_at)

    def matches(self, lease: JobLease, state: JobState) -> bool:
        """True iff this row is in ``state`` under exactly ``lease`` (J3 fence)."""
        return (self.state, self.job_id, self.attempt, self.writer_epoch, self.lease_id) == (
            state,
            lease.job_id,
            lease.attempt,
            lease.writer_epoch,
            lease.lease_id,
        )


@dataclass(frozen=True)
class InvocationRecord:
    """One ``p_provider_invocations_state`` row: links job/attempt/lease by ID, never by a live foreign key."""

    invocation_id: str
    job_id: str
    attempt: int
    writer_epoch: int
    lease_id: str
    reservation_digest: str
    state: InvocationState
    usage_digest: str | None
    usage_complete: bool | None

    def __post_init__(self) -> None:
        require_uuid(self.invocation_id)
        require_uuid(self.job_id)
        require_positive_int(self.attempt)
        require_positive_int(self.writer_epoch)
        require_uuid(self.lease_id)
        require_sha256_digest(self.reservation_digest)
        if not isinstance(self.state, InvocationState):
            raise _invalid()
        settled = self.state is InvocationState.SETTLED
        if settled != (self.usage_digest is not None) or settled != (self.usage_complete is not None):
            raise _invalid()
        if self.usage_digest is not None:
            require_sha256_digest(self.usage_digest)
        if self.usage_complete is not None and type(self.usage_complete) is not bool:
            raise _invalid()


_ACCOUNTING = {
    InvocationState.RESERVED: AccountingStatus.RESERVED,
    InvocationState.SETTLED: AccountingStatus.SETTLED,
    InvocationState.OUTCOME_UNKNOWN: AccountingStatus.OUTCOME_UNKNOWN,
}


def accounting_status_of(states: Iterable[InvocationState]) -> AccountingStatus:
    """``outcome_unknown`` if any invocation is unknown, else ``reserved`` if any is, else ``settled``/``none``."""
    seen = {_ACCOUNTING[state] for state in states}
    for status in (AccountingStatus.OUTCOME_UNKNOWN, AccountingStatus.RESERVED, AccountingStatus.SETTLED):
        if status in seen:
            return status
    return AccountingStatus.NONE


@dataclass(frozen=True)
class JobView:
    """``GetJobResult``: ``job_id, state, attempt, result_refs, accounting_status``; never a payload."""

    job_id: str
    state: JobState
    attempt: int
    result_refs: tuple[ObjectRef, ...]
    accounting_status: AccountingStatus

    def __post_init__(self) -> None:
        require_opaque_id(self.job_id, label="job_id")
        if not isinstance(self.state, JobState) or not isinstance(self.accounting_status, AccountingStatus):
            raise _invalid()
        require_positive_int(self.attempt)
        _require_refs(self.result_refs)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "attempt": self.attempt,
            "result_refs": [ref.to_dict() for ref in self.result_refs],
            "accounting_status": self.accounting_status.value,
        }


@dataclass(frozen=True)
class RecoveryCounts:
    """Rows one ``recover(epoch)`` changed; a second recovery of the same epoch returns all zeros."""

    invocations_unknown: int = 0
    jobs_requeued: int = 0
    jobs_dead_lettered: int = 0

    def __post_init__(self) -> None:
        for value in (self.invocations_unknown, self.jobs_requeued, self.jobs_dead_lettered):
            if not is_strict_int(value) or value < 0:
                raise _invalid()


@dataclass(frozen=True)
class WorkerCompleted:
    """Worker command: the attempt under ``lease`` finished with these safe result refs."""

    lease: JobLease
    result_refs: tuple[ObjectRef, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.lease, JobLease):
            raise _invalid()
        _require_refs(self.result_refs)


@dataclass(frozen=True)
class WorkerFailed:
    """Worker command: the attempt under ``lease`` failed with ``code`` (retryable or not)."""

    lease: JobLease
    retryable: bool
    code: JobErrorCode

    def __post_init__(self) -> None:
        if not isinstance(self.lease, JobLease) or type(self.retryable) is not bool:
            raise _invalid()
        if not isinstance(self.code, JobErrorCode):
            raise _invalid()


@dataclass(frozen=True)
class WorkerUsage:
    """Worker command: final usage of an invocation reserved by the owner side before hand-off."""

    invocation_id: str
    usage: UsageRecord

    def __post_init__(self) -> None:
        require_uuid(self.invocation_id)
        if not isinstance(self.usage, UsageRecord):
            raise _invalid()


WorkerCommand: TypeAlias = WorkerCompleted | WorkerFailed | WorkerUsage
