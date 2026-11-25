"""Event-sourced Job / ProviderInvocation projections and their typed transaction reads (Task 5, spec 6.4, D5).

``p_jobs_*`` (handler ``jobs``) owns job state and ``p_provider_invocations_*`` (handler ``provider_invocations``)
owns accounting state. Both are pure reducers over typed ledger entries: they read only the entry and bounded rows of
their own tables, link job/lease/attempt by ID (no foreign key to a live table) and re-check each entry's fence, so
an entry that does not match the row it moves is ``INTEGRITY_FAILURE`` and the projection never diverges from the
ledger. Rebuild therefore recreates every row exactly, never enqueues, invokes a worker or creates a record, and a
``job.retention_expired`` entry removes its dead letter for good.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from functools import partial
from typing import TYPE_CHECKING, TypeVar

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    InvocationRecord,
    InvocationState,
    JobErrorCode,
    JobRecord,
    JobState,
    is_strict_int,
    require_opaque_id,
)
from superbrain.ports.policy import PolicyView
from superbrain.storage.cas import ContentStore, held_digests, read_held_blob_or_none
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kernel_schema import KERNEL_JOB_KINDS
from superbrain.storage.kinds import KindRegistry, is_uuid
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler, Txn, utc_timestamp

if TYPE_CHECKING:
    from superbrain.storage.store import Store
    from superbrain.storage.writer import WriterLease

_T = TypeVar("_T")
_HOLDER_KIND = "event"
JOBS_TABLE = "p_jobs_state"
INVOCATIONS_TABLE = "p_provider_invocations_state"
_JOB_COLUMNS = (
    "job_id, owner_id, repo_id, checkout_id, kind, payload_digest, state, attempt, retry_at, writer_epoch,"
    " lease_id, reason, result_digest, finished_at"
)
_INVOCATION_COLUMNS = (
    "invocation_id, job_id, attempt, writer_epoch, lease_id, reservation_digest, state, usage_digest, usage_complete"
)


def _corrupt(entry: LedgerEntry | None, what: str) -> BrainError:
    where = f"ledger entry {entry.sequence}" if entry is not None else "projection row"
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"{where}: {what}")


def _meta(entry: LedgerEntry, name: str) -> object:
    if name not in entry.meta:
        raise _corrupt(entry, f"{name} is missing")
    return entry.meta[name]


def _text(entry: LedgerEntry, name: str) -> str:
    value = _meta(entry, name)
    if not isinstance(value, str) or not value:
        raise _corrupt(entry, f"{name} is not text")
    return value


def _opt_text(entry: LedgerEntry, name: str) -> str | None:
    return None if _meta(entry, name) is None else _text(entry, name)


def _int(entry: LedgerEntry, name: str) -> int:
    value = _meta(entry, name)
    if not is_strict_int(value) or not isinstance(value, int) or value < 1:
        raise _corrupt(entry, f"{name} is not a positive integer")
    return value


def _opt_int(entry: LedgerEntry, name: str) -> int | None:
    return None if _meta(entry, name) is None else _int(entry, name)


def _one_row(cursor: sqlite3.Cursor, entry: LedgerEntry) -> None:
    if cursor.rowcount != 1:
        raise _corrupt(entry, f"{entry.kind} does not match the current row")


class JobsProjection:
    """``p_jobs_*``: one row per live job; every transition is fenced by prior state, attempt, epoch and lease."""

    name = "jobs"
    handler_version = 1
    kinds = frozenset({"job.queued", "job.leased", "job.running", "job.retry", "job.terminal", "job.retention_expired"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}state (job_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, repo_id TEXT,"
            " checkout_id TEXT, kind TEXT NOT NULL, payload_digest TEXT NOT NULL, state TEXT NOT NULL,"
            " attempt INTEGER NOT NULL, retry_at TEXT NOT NULL, writer_epoch INTEGER, lease_id TEXT, reason TEXT,"
            " result_digest TEXT, finished_at TEXT, sequence INTEGER NOT NULL)"
        )
        db.execute(f"CREATE INDEX {prefix}due ON {prefix}state (state, retry_at, job_id)")
        db.execute(f"CREATE INDEX {prefix}epochs ON {prefix}state (state, writer_epoch, job_id)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        table, job_id, seq = f"{prefix}state", _text(entry, "job_id"), entry.sequence
        if entry.kind == "job.queued":
            db.execute(
                f"INSERT INTO {table} (job_id, owner_id, repo_id, checkout_id, kind, payload_digest, state, attempt,"
                " retry_at, sequence) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)",
                (
                    job_id,
                    _text(entry, "owner_id"),
                    _opt_text(entry, "repo_id"),
                    _opt_text(entry, "checkout_id"),
                    _text(entry, "kind"),
                    _text(entry, "payload_digest"),
                    _int(entry, "attempt"),
                    _text(entry, "retry_at"),
                    seq,
                ),
            )
            return
        if entry.kind == "job.retention_expired":
            _one_row(db.execute(f"DELETE FROM {table} WHERE job_id = ? AND state = 'dead_letter'", (job_id,)), entry)
            return
        attempt, epoch, lease_id = _int(entry, "attempt"), _opt_int(entry, "writer_epoch"), _opt_text(entry, "lease_id")
        if entry.kind == "job.leased":
            cursor = db.execute(
                f"UPDATE {table} SET state = 'leased', writer_epoch = ?, lease_id = ?, sequence = ?"
                " WHERE job_id = ? AND state = 'queued' AND attempt = ?",
                (epoch, lease_id, seq, job_id, attempt),
            )
        elif entry.kind == "job.running":
            cursor = db.execute(
                f"UPDATE {table} SET state = 'running', sequence = ?"
                " WHERE job_id = ? AND state = 'leased' AND attempt = ? AND writer_epoch = ? AND lease_id = ?",
                (seq, job_id, attempt, epoch, lease_id),
            )
        elif entry.kind == "job.retry":  # the absolute new attempt: replaying a retry never bumps twice
            cursor = db.execute(
                f"UPDATE {table} SET state = 'queued', attempt = ?, retry_at = ?, writer_epoch = NULL,"
                " lease_id = NULL, reason = ?, sequence = ?"
                " WHERE job_id = ? AND state = ? AND attempt = ? AND writer_epoch = ? AND lease_id = ?",
                (
                    attempt,
                    _text(entry, "retry_at"),
                    _text(entry, "reason"),
                    seq,
                    job_id,
                    _text(entry, "prior_state"),
                    attempt - 1,
                    epoch,
                    lease_id,
                ),
            )
        else:  # job.terminal
            cursor = db.execute(
                f"UPDATE {table} SET state = ?, reason = ?, result_digest = ?, finished_at = ?, sequence = ?"
                " WHERE job_id = ? AND state = ? AND attempt = ? AND writer_epoch IS ? AND lease_id IS ?",
                (
                    _text(entry, "state"),
                    _opt_text(entry, "reason"),
                    _opt_text(entry, "result_digest"),
                    _text(entry, "finished_at"),
                    seq,
                    job_id,
                    _text(entry, "prior_state"),
                    attempt,
                    epoch,
                    lease_id,
                ),
            )
        _one_row(cursor, entry)


_SETTLED_V1_KEYS = frozenset({"invocation_id", "prior_state", "usage_digest", "complete"})
_SETTLED_V2_KEYS = frozenset({"invocation_id", "prior_state", "prior_usage_digest", "usage_digest", "complete"})
_SETTLED_PRIOR_STATES = frozenset({"reserved", "outcome_unknown"})


def _apply_provider_settled(
    db: sqlite3.Connection, table: str, entry: LedgerEntry, invocation_id: str, seq: int
) -> sqlite3.Cursor:
    complete = _meta(entry, "complete")
    if type(complete) is not bool:
        raise _corrupt(entry, "complete is not a boolean")
    prior_state = _text(entry, "prior_state")
    if prior_state not in _SETTLED_PRIOR_STATES:
        raise _corrupt(entry, "invalid prior_state")
    usage_digest = _text(entry, "usage_digest")
    next_state = "settled" if complete else "outcome_unknown"
    next_complete = 1 if complete else 0
    if entry.handler_version == 1:
        if set(entry.meta) != _SETTLED_V1_KEYS:
            raise _corrupt(entry, "unexpected v1 provider.settled fields")
        return db.execute(
            f"UPDATE {table} SET state = ?, usage_digest = ?, usage_complete = ?, sequence = ?"
            " WHERE invocation_id = ? AND state = ? AND (usage_complete IS NULL OR usage_complete = 0)",
            (next_state, usage_digest, next_complete, seq, invocation_id, prior_state),
        )
    if entry.handler_version == 2:
        if set(entry.meta) != _SETTLED_V2_KEYS:
            raise _corrupt(entry, "unexpected v2 provider.settled fields")
        prior_usage = _opt_text(entry, "prior_usage_digest")
        if prior_state == "reserved" and prior_usage is not None:
            raise _corrupt(entry, "reserved invocation cannot have prior_usage_digest")
        if not complete and prior_usage is not None:
            raise _corrupt(entry, "incomplete usage cannot overwrite prior_usage_digest")
        prior_complete = None if prior_usage is None else 0
        return db.execute(
            f"UPDATE {table} SET state = ?, usage_digest = ?, usage_complete = ?, sequence = ?"
            " WHERE invocation_id = ? AND state = ? AND usage_digest IS ? AND usage_complete IS ?",
            (next_state, usage_digest, next_complete, seq, invocation_id, prior_state, prior_usage, prior_complete),
        )
    raise _corrupt(entry, f"unsupported provider.settled version {entry.handler_version}")


class ProviderInvocationProjection:
    """``p_provider_invocations_*``: accounting state per invocation, independent of the job's state."""

    name = "provider_invocations"
    handler_version = 2
    kinds = frozenset({"provider.reserved", "provider.settled", "provider.unknown"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}state (invocation_id TEXT PRIMARY KEY, job_id TEXT NOT NULL,"
            " attempt INTEGER NOT NULL, writer_epoch INTEGER NOT NULL, lease_id TEXT NOT NULL,"
            " reservation_digest TEXT NOT NULL, state TEXT NOT NULL, usage_digest TEXT, usage_complete INTEGER,"
            " sequence INTEGER NOT NULL)"
        )
        db.execute(f"CREATE INDEX {prefix}by_job ON {prefix}state (job_id, sequence)")
        db.execute(f"CREATE INDEX {prefix}epochs ON {prefix}state (state, writer_epoch, invocation_id)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        table, invocation_id, seq = f"{prefix}state", _text(entry, "invocation_id"), entry.sequence
        if entry.kind == "provider.reserved":
            db.execute(
                f"INSERT INTO {table} (invocation_id, job_id, attempt, writer_epoch, lease_id, reservation_digest,"
                " state, sequence) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?)",
                (
                    invocation_id,
                    _text(entry, "job_id"),
                    _int(entry, "attempt"),
                    _int(entry, "writer_epoch"),
                    _text(entry, "lease_id"),
                    _text(entry, "reservation_digest"),
                    seq,
                ),
            )
            return
        if entry.kind == "provider.unknown":
            cursor = db.execute(
                f"UPDATE {table} SET state = 'outcome_unknown', sequence = ?"
                " WHERE invocation_id = ? AND state = 'reserved' AND writer_epoch = ? AND writer_epoch < ?",
                (seq, invocation_id, _int(entry, "writer_epoch"), _int(entry, "recovery_epoch")),
            )
        else:  # provider.settled
            cursor = _apply_provider_settled(db, table, entry, invocation_id, seq)
        _one_row(cursor, entry)


def kernel_job_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """The Task 5 projection handlers and entry kinds a kernel store is opened with."""
    return (JobsProjection(), ProviderInvocationProjection()), KindRegistry(KERNEL_JOB_KINDS)


# --- row decoding and typed reads -------------------------------------------------------------------------------------


def _decoded(build: Callable[[], _T]) -> _T:
    try:
        return build()
    except (BrainError, ValueError, TypeError) as err:
        raise _corrupt(None, "malformed job projection row") from err


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def _opt_int_col(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise TypeError("integer column")
    return value


def _job(row: Sequence[object]) -> JobRecord:
    job_id, owner, repo, checkout, kind, payload, state, attempt, retry_at, epoch, lease, reason, result, done = row
    if type(attempt) is not int:
        raise TypeError("attempt")
    return JobRecord(
        job_id=str(job_id),
        owner_id=str(owner),
        repo_id=_opt_str(repo),
        checkout_id=_opt_str(checkout),
        kind=str(kind),
        payload_digest=str(payload),
        state=JobState(str(state)),
        attempt=attempt,
        retry_at=str(retry_at),
        writer_epoch=_opt_int_col(epoch),
        lease_id=_opt_str(lease),
        reason=None if reason is None else JobErrorCode(str(reason)),
        result_digest=_opt_str(result),
        finished_at=_opt_str(done),
    )


def _invocation(row: Sequence[object]) -> InvocationRecord:
    invocation_id, job_id, attempt, epoch, lease, reservation, state, usage, complete = row
    if type(attempt) is not int or type(epoch) is not int or complete not in (None, 0, 1):
        raise TypeError("integer column")
    return InvocationRecord(
        invocation_id=str(invocation_id),
        job_id=str(job_id),
        attempt=attempt,
        writer_epoch=epoch,
        lease_id=str(lease),
        reservation_digest=str(reservation),
        state=InvocationState(str(state)),
        usage_digest=_opt_str(usage),
        usage_complete=None if complete is None else complete == 1,
    )


def _accounting_state(row: Sequence[object]) -> InvocationState:
    raw_state, complete = row
    if type(raw_state) is not str:
        raise TypeError("state")
    state = InvocationState(raw_state)
    if state is InvocationState.RESERVED and complete is None:
        return state
    if state is InvocationState.OUTCOME_UNKNOWN and (complete is None or (type(complete) is int and complete == 0)):
        return state
    if state is InvocationState.SETTLED and type(complete) is int and complete == 1:
        return state
    raise ValueError("accounting state invariant")


def _bounded(limit: int) -> int:
    if not is_strict_int(limit) or not 1 <= limit <= 100:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return limit


def _epoch(epoch: int) -> int:
    if not is_strict_int(epoch) or epoch < 1:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return epoch


class JobKernelTxReads:
    """``KernelTx`` job/invocation reads and the dead-letter hold release, mixed into ``StoreKernelTx``."""

    _txn: Txn
    _cas: ContentStore
    _policy: PolicyView

    def _rows(self, sql: str, params: tuple[object, ...]) -> list[tuple[object, ...]]:
        try:
            return self._txn.db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the job projections", exc) from exc

    def _jobs(self, where: str, params: tuple[object, ...]) -> tuple[JobRecord, ...]:
        rows = self._rows(f"SELECT {_JOB_COLUMNS} FROM {JOBS_TABLE} WHERE {where}", params)
        return tuple(_decoded(partial(_job, row)) for row in rows)

    def _invocations(self, where: str, params: tuple[object, ...]) -> tuple[InvocationRecord, ...]:
        rows = self._rows(f"SELECT {_INVOCATION_COLUMNS} FROM {INVOCATIONS_TABLE} WHERE {where}", params)
        return tuple(_decoded(partial(_invocation, row)) for row in rows)

    def release_blob(self, digest: str, *, holder_id: str, reason: str) -> None:
        if reason != "expired" or not is_uuid(holder_id) or not isinstance(digest, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if digest in held_digests(self._txn.db, _HOLDER_KIND, holder_id):
            self._txn.release(digest, _HOLDER_KIND, holder_id, reason)

    def read_held_blob(
        self,
        digest: str,
        *,
        holder_id: str,
        holder_kind: str = "event",
        now: datetime | None = None,
    ) -> bytes | None:
        check_now = self._txn._clock.now() if now is None else now
        return read_held_blob_or_none(
            self._txn.db,
            self._cas,
            self._policy,
            digest,
            holder_kind=holder_kind,
            holder_id=holder_id,
            now=check_now,
        )

    def read_job(self, job_id: str) -> JobRecord | None:
        found = self._jobs("job_id = ?", (job_id,))
        return found[0] if found else None

    def read_invocation(self, invocation_id: str) -> InvocationRecord | None:
        found = self._invocations("invocation_id = ?", (invocation_id,))
        return found[0] if found else None

    def read_job_accounting_states(self, job_id: str) -> frozenset[InvocationState]:
        rows = self._rows(
            f"SELECT DISTINCT state, usage_complete FROM {INVOCATIONS_TABLE} WHERE job_id = ?",
            (job_id,),
        )
        return frozenset(_decoded(partial(_accounting_state, row)) for row in rows)

    def due_jobs(self, now: datetime, limit: int) -> tuple[JobRecord, ...]:
        return self._jobs(
            "state = 'queued' AND retry_at <= ? ORDER BY retry_at, job_id LIMIT ?",
            (utc_timestamp(now), _bounded(limit)),
        )

    @staticmethod
    def _checked_kinds(kinds: Sequence[str]) -> tuple[str, ...]:
        if isinstance(kinds, (str, bytes)) or not isinstance(kinds, Sequence) or not (1 <= len(kinds) <= 32):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return tuple(require_opaque_id(kind, label="kind") for kind in kinds)

    def due_jobs_by_kinds(
        self, now: datetime, kinds: Sequence[str], limit: int, *, exclude: bool = False
    ) -> tuple[JobRecord, ...]:
        bounded = _bounded(limit)
        kind_tuple = self._checked_kinds(kinds)
        op = "NOT IN" if exclude else "IN"
        placeholders = ", ".join("?" for _ in kind_tuple)
        return self._jobs(
            f"state = 'queued' AND kind {op} ({placeholders}) AND retry_at <= ? ORDER BY retry_at, job_id LIMIT ?",
            (*kind_tuple, utc_timestamp(now), bounded),
        )

    def active_jobs_by_kinds(self, kinds: Sequence[str], limit: int) -> tuple[JobRecord, ...]:
        bounded = _bounded(limit)
        kind_tuple = self._checked_kinds(kinds)
        placeholders = ", ".join("?" for _ in kind_tuple)
        return self._jobs(
            f"state IN ('queued', 'leased', 'running') AND kind IN ({placeholders}) ORDER BY sequence, job_id LIMIT ?",
            (*kind_tuple, bounded),
        )

    def claimed_jobs_by_kinds(self, kinds: Sequence[str], epoch: int, limit: int) -> tuple[JobRecord, ...]:
        kind_tuple = self._checked_kinds(kinds)
        placeholders = ", ".join("?" for _ in kind_tuple)
        return self._jobs(
            f"state IN ('leased', 'running') AND writer_epoch = ? AND kind IN ({placeholders}) ORDER BY job_id LIMIT ?",
            (_epoch(epoch), *kind_tuple, _bounded(limit)),
        )

    def stale_jobs(self, epoch: int, limit: int) -> tuple[JobRecord, ...]:
        return self._jobs(
            "state IN ('leased', 'running') AND writer_epoch < ? ORDER BY job_id LIMIT ?",
            (_epoch(epoch), _bounded(limit)),
        )

    def unsettled_invocations(self, epoch: int, limit: int) -> tuple[InvocationRecord, ...]:
        return self._invocations(
            "state = 'reserved' AND writer_epoch < ? ORDER BY invocation_id LIMIT ?", (_epoch(epoch), _bounded(limit))
        )

    def expired_dead_letters(self, cutoff: datetime, limit: int) -> tuple[JobRecord, ...]:
        return self._jobs(
            "state = 'dead_letter' AND finished_at <= ? ORDER BY finished_at, job_id LIMIT ?",
            (utc_timestamp(cutoff), _bounded(limit)),
        )


def has_legacy_incomplete_settled_projections(store: Store, lease: WriterLease) -> bool:
    """Under ``lease``, return True iff ``p_provider_invocations_state`` has any legacy ``settled/0`` row."""
    if store.closed or store.in_transaction or not lease.held or lease.root != store.root:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    try:
        with store.transaction() as txn:
            row = txn.db.execute(
                f"SELECT 1 FROM {INVOCATIONS_TABLE} WHERE state = 'settled' AND usage_complete = 0 LIMIT 1"
            ).fetchone()
    except sqlite3.Error as err:
        raise sqlite_error("reading legacy incomplete settled projections", err) from err
    return row is not None
