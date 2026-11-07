"""Low-level operational SQL for ``store4`` idempotency rows and C4 clock high-water mark."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    IDEMPOTENCY_CLOCK_HWM_META_KEY,
    IdempotencyRow,
    StoredResult,
    parse_canonical_utc,
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.storage.errors import sqlite_error

_IDEMPOTENCY_COLS = (
    "principal_id, tool, key_hash, request_digest_key_id, request_digest, "
    "result_id, assignment_id, refs_json, committed_at"
)


def decode_idempotency_row(raw_row: Sequence[object]) -> IdempotencyRow:
    """Decode and strictly validate one ``idempotency`` SQLite row; corruption raises ``INTEGRITY_FAILURE``."""
    if len(raw_row) != 9:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    (
        principal_id,
        tool,
        key_hash,
        req_key_id,
        req_digest,
        result_id,
        assignment_id,
        refs_json,
        committed_at,
    ) = raw_row
    if (
        not isinstance(principal_id, str)
        or not isinstance(tool, str)
        or not isinstance(key_hash, str)
        or not isinstance(req_key_id, str)
        or not isinstance(req_digest, str)
        or not isinstance(result_id, str)
        or (assignment_id is not None and not isinstance(assignment_id, str))
        or not isinstance(refs_json, str)
        or not isinstance(committed_at, str)
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    try:
        refs = StoredResult.decode_refs_json(refs_json)
        return IdempotencyRow(
            principal_id=principal_id,
            tool=tool,
            key_hash=key_hash,
            request_digest_key_id=req_key_id,
            request_digest=req_digest,
            result_id=result_id,
            assignment_id=assignment_id,
            refs=refs,
            committed_at=committed_at,
        )
    except BrainError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err


def read_idempotency_row(db: sqlite3.Connection, principal_id: str, tool: str, key_hash: str) -> IdempotencyRow | None:
    require_opaque_id(principal_id, label="principal_id")
    if not isinstance(tool, str) or not tool:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    require_sha256_digest(key_hash)
    try:
        raw = db.execute(
            f"SELECT {_IDEMPOTENCY_COLS} FROM idempotency WHERE principal_id = ? AND tool = ? AND key_hash = ?",
            (principal_id, tool, key_hash),
        ).fetchone()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read operational idempotency row", exc) from exc
    if raw is None:
        return None
    return decode_idempotency_row(raw)


def write_idempotency_row(db: sqlite3.Connection, row: IdempotencyRow) -> None:
    if not isinstance(row, IdempotencyRow):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    stored = StoredResult(result_id=row.result_id, assignment_id=row.assignment_id, refs=row.refs)
    refs_json = stored.encode_refs_json()
    try:
        db.execute(
            "INSERT INTO idempotency ("
            "principal_id, tool, key_hash, request_digest_key_id, request_digest, "
            "result_id, assignment_id, refs_json, committed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (principal_id, tool, key_hash) DO UPDATE SET "
            "request_digest_key_id = excluded.request_digest_key_id, "
            "request_digest = excluded.request_digest, "
            "result_id = excluded.result_id, "
            "assignment_id = excluded.assignment_id, "
            "refs_json = excluded.refs_json, "
            "committed_at = excluded.committed_at",
            (
                row.principal_id,
                row.tool,
                row.key_hash,
                row.request_digest_key_id,
                row.request_digest,
                row.result_id,
                row.assignment_id,
                refs_json,
                row.committed_at,
            ),
        )
    except sqlite3.Error as exc:
        raise sqlite_error("cannot write operational idempotency row", exc) from exc


def validate_c4_clock(
    db: sqlite3.Connection,
    now_utc: datetime,
    *,
    epoch_hwm_utc: datetime | None,
) -> str | None:
    """Validate ``now_utc`` against durable ``meta[idempotency_clock_hwm_utc]``, retained rows, and ``epoch_hwm_utc``.

    Returns the existing canonical durable watermark string (or ``None`` if absent on an empty store).
    """
    try:
        meta_row = db.execute(
            "SELECT value FROM meta WHERE key = ?",
            (IDEMPOTENCY_CLOCK_HWM_META_KEY,),
        ).fetchone()
        agg_row = db.execute("SELECT COUNT(*), MIN(committed_at), MAX(committed_at) FROM idempotency").fetchone()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot validate idempotency clock watermark", exc) from exc

    assert agg_row is not None
    row_count = int(agg_row[0]) if type(agg_row[0]) is int else -1
    if row_count < 0:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    durable_hwm_str: str | None = None
    if meta_row is not None:
        raw_val = meta_row[0]
        if not isinstance(raw_val, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        try:
            durable_hwm_utc = parse_canonical_utc(raw_val)
        except BrainError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
        durable_hwm_str = raw_val
        if now_utc < durable_hwm_utc:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    elif row_count > 0:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    if row_count > 0:
        min_comm, max_comm = agg_row[1], agg_row[2]
        if not isinstance(min_comm, str) or not isinstance(max_comm, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        try:
            _ = parse_canonical_utc(min_comm)
            max_comm_utc = parse_canonical_utc(max_comm)
        except BrainError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
        if now_utc < max_comm_utc:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    if epoch_hwm_utc is not None and now_utc < epoch_hwm_utc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    return durable_hwm_str


def advance_c4_hwm(db: sqlite3.Connection, now_str: str, *, current_hwm: str | None) -> str:
    """Persist ``max(current_hwm, now_str)`` in ``meta[idempotency_clock_hwm_utc]`` inside the active transaction."""
    target = now_str if current_hwm is None or now_str >= current_hwm else current_hwm
    try:
        db.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (IDEMPOTENCY_CLOCK_HWM_META_KEY, target),
        )
    except sqlite3.Error as exc:
        raise sqlite_error("cannot advance idempotency clock watermark", exc) from exc
    return target


def select_expired_rows(db: sqlite3.Connection, cutoff_str: str, limit: int) -> tuple[IdempotencyRow, ...]:
    try:
        rows = db.execute(
            f"SELECT {_IDEMPOTENCY_COLS} FROM idempotency "
            "WHERE committed_at <= ? "
            "ORDER BY committed_at ASC, principal_id ASC, tool ASC, key_hash ASC "
            "LIMIT ?",
            (cutoff_str, limit),
        ).fetchall()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot scan expired idempotency rows", exc) from exc
    return tuple(decode_idempotency_row(r) for r in rows)


def delete_idempotency_rows(db: sqlite3.Connection, keys: Sequence[tuple[str, str, str]]) -> int:
    if not keys:
        return 0
    try:
        cursor = db.executemany(
            "DELETE FROM idempotency WHERE principal_id = ? AND tool = ? AND key_hash = ?",
            keys,
        )
    except sqlite3.Error as exc:
        raise sqlite_error("cannot prune expired idempotency rows", exc) from exc
    return len(keys) if cursor.rowcount < 0 else cursor.rowcount
