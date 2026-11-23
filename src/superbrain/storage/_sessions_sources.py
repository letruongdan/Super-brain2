"""Read-time resolution of captured events: content is served only while its payload holder is live."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import (
    EVENT_KINDS_ENDING_SESSION,
    EVENT_KINDS_RESUMING_SESSION,
    SessionRecord,
    SessionState,
)
from superbrain.storage._sessions_sql import parse_iso_utc, recompute_task_pending
from superbrain.storage.cas import read_held_blob_or_none
from superbrain.storage.errors import sqlite_error
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


def live_event_record(
    store: Store,
    policy: PolicyStore,
    *,
    task_id: str,
    producer_stream: str,
    sequence: int,
    event_id: str,
    payload_digest: str,
    now: datetime,
) -> CaptureEventRecord | None:
    """The pinned event iff its link to ``task_id`` is verified and its payload holder is live at ``now``.

    Verified means the event carries the pinned ID and digest, the link records the same event and session, the task
    and session belong to the event's repo and checkout, and the event's principal is the one the session is bound to
    in ``policy.db`` (the binding authority) and in the session row. Anything else (including links kept from older
    builds without that evidence) yields nothing; the event itself is left as it is.

    A store or ``policy.db`` read that fails is not a decision about the event: it raises (``IO_ERROR``,
    ``STORE_BUSY`` or ``STORAGE_FULL``) so the caller keeps the batch and retries instead of skipping the event.
    """
    try:
        row = _verified_row(store, task_id, producer_stream, sequence, event_id, payload_digest)
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read continuity source event", exc) from exc
    if row is None:
        return None
    try:
        binding = policy.lookup_session_binding(str(row[6]))
    except BrainError as err:
        if err.code is not ErrorCode.INVALID_INPUT:
            raise  # the binding authority could not be read
        return None  # a stored session ref that is not a session ref never binds
    if (
        binding is None
        or binding.principal_id != str(row[8])
        or binding.repo_id not in (None, str(row[9]))
        or binding.checkout_id not in (None, str(row[10]))
    ):
        return None
    return _record_if_live(store, policy, row, producer_stream, sequence, payload_digest, now=now)


def _verified_row(
    store: Store, task_id: str, producer_stream: str, sequence: int, event_id: str, payload_digest: str
) -> tuple[object, ...] | None:
    row = store._db.execute(
        "SELECT e.event_id, e.harness_id, e.kind, e.recorded_at, e.payload_digest, e.cas_holder_id, e.session_ref, "
        "e.source_metadata_json, e.principal_id, e.repo_id, e.checkout_id FROM capture_events e "
        "JOIN session_task_events l ON l.producer_stream = e.producer_stream AND l.sequence = e.sequence "
        "AND l.event_id = e.event_id AND l.payload_digest = e.payload_digest AND l.session_ref = e.session_ref "
        "JOIN tasks t ON t.task_id = l.task_id AND t.repo_id = e.repo_id AND t.checkout_id = e.checkout_id "
        "JOIN sessions s ON s.session_ref = l.session_ref AND s.repo_id = e.repo_id AND s.checkout_id = e.checkout_id "
        "AND s.principal_id = e.principal_id "
        "WHERE e.producer_stream = ? AND e.sequence = ? AND e.event_id = ? AND e.payload_digest = ? "
        "AND l.task_id = ?",
        (producer_stream, sequence, event_id, payload_digest, task_id),
    ).fetchone()
    return None if row is None else tuple(row)


def _record_if_live(
    store: Store,
    policy: PolicyStore,
    row: tuple[object, ...],
    producer_stream: str,
    sequence: int,
    payload_digest: str,
    *,
    now: datetime,
) -> CaptureEventRecord | None:
    payload = read_held_blob_or_none(
        store._db,
        store.cas,
        policy,
        payload_digest,
        holder_kind="event",
        holder_id=str(row[5]),
        now=now,
    )
    if payload is None:
        return None
    raw_meta = row[7]
    try:
        meta = json.loads(bytes(raw_meta).decode("utf-8") if isinstance(raw_meta, bytes) else str(raw_meta or "{}"))
        return CaptureEventRecord(
            event_id=str(row[0]),
            producer_stream=producer_stream,
            sequence=sequence,
            harness_id=str(row[1]),
            kind=str(row[2]),
            recorded_at=str(row[3]),
            payload=json.loads(payload.decode("utf-8")),
            session_ref=None if row[6] is None else str(row[6]),
            source_metadata=meta,
        )
    except (UnicodeDecodeError, ValueError, TypeError, BrainError):
        # An undecodable source is treated as unavailable rather than failing the owner thread.
        return None


def resolve_refresh_sources(store: Store, policy: PolicyStore, payload: bytes, *, now: datetime) -> bytes:
    """Worker input built in memory from the job's refs; sources no longer live are left out."""
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid continuity refresh payload") from exc
    refs = decoded.get("events") if isinstance(decoded, dict) else None
    task_id = decoded.get("task_id") if isinstance(decoded, dict) else None
    if not isinstance(refs, list) or not isinstance(task_id, str):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid continuity refresh payload")
    records: list[JsonValue] = []
    for ref in refs:
        if not isinstance(ref, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid continuity refresh payload")
        stream, seq, digest = ref.get("producer_stream"), ref.get("sequence"), ref.get("payload_digest")
        event_id = ref.get("event_id")
        if (
            not isinstance(stream, str)
            or type(seq) is not int
            or not isinstance(digest, str)
            or not isinstance(event_id, str)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid continuity refresh payload")
        record = live_event_record(
            store, policy, task_id=task_id, producer_stream=stream, sequence=seq, event_id=event_id,
            payload_digest=digest, now=now,
        )
        if record is not None:
            records.append(record.to_dict())
    return canonical_json({"events": records, "task_id": task_id})


def _advance_session_in_tx(db: sqlite3.Connection, session: SessionRecord, event: CaptureEventRecord) -> None:
    """Liveness and end/resume transitions of ``session`` for one new event."""
    cur_last_dt = parse_iso_utc(session.last_event_at)
    ev_dt = parse_iso_utc(event.recorded_at)
    next_last = event.recorded_at if ev_dt >= cur_last_dt else session.last_event_at
    if event.kind in EVENT_KINDS_ENDING_SESSION:
        next_state, next_ended_at = SessionState.ENDED.value, event.recorded_at
    elif session.state is SessionState.ENDED:
        if event.kind in EVENT_KINDS_RESUMING_SESSION:
            next_state, next_ended_at = SessionState.ACTIVE.value, None
        else:
            next_state, next_ended_at = SessionState.ENDED.value, session.ended_at
    else:
        next_state, next_ended_at = SessionState.ACTIVE.value, None
    db.execute(
        "UPDATE sessions SET state = ?, last_event_at = ?, ended_at = ? WHERE session_ref = ?",
        (next_state, next_last, next_ended_at, session.session_ref),
    )


def refresh_candidates(
    db: sqlite3.Connection, limit: int, after: tuple[str, str] | None
) -> tuple[tuple[str, str], ...]:
    """Pending tasks as ``(first_pending_event_at, task_id)`` keys, in key order, strictly after ``after``."""
    if after is None:
        rows = db.execute(
            "SELECT first_pending_event_at, task_id FROM continuity_refresh_state WHERE pending_event_count > 0 "
            "ORDER BY first_pending_event_at, task_id LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT first_pending_event_at, task_id FROM continuity_refresh_state WHERE pending_event_count > 0 "
            "AND (first_pending_event_at, task_id) > (?, ?) ORDER BY first_pending_event_at, task_id LIMIT ?",
            (after[0], after[1], limit),
        ).fetchall()
    return tuple((str(r[0] or ""), str(r[1])) for r in rows)


def bound_task_for_session(db: sqlite3.Connection, session_ref: str, repo_id: str, checkout_id: str) -> str | None:
    """The task currently bound to ``session_ref`` in this checkout (the most recently updated one)."""
    row = db.execute(
        "SELECT c.task_id FROM continuity_refresh_state c JOIN tasks t ON t.task_id = c.task_id "
        "WHERE c.session_ref = ? AND c.repo_id = ? AND c.checkout_id = ? "
        "ORDER BY t.updated_at DESC, c.task_id LIMIT 1",
        (session_ref, repo_id, checkout_id),
    ).fetchone()
    return None if row is None else str(row[0])


def close_refresh_batch(db: sqlite3.Connection, task_id: str, cutoff_order: int) -> None:
    """Mark everything up to the job's pinned cutoff as considered and release the task's inflight marker."""
    row = db.execute(
        "SELECT last_summarized_rowid FROM continuity_refresh_state WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None:
        return
    next_rowid = max(int(row[0]), cutoff_order)
    count, first_at = recompute_task_pending(db, task_id, next_rowid)
    db.execute(
        "UPDATE continuity_refresh_state SET pending_event_count = ?, first_pending_event_at = ?, dirty_flag = 0, "
        "active_job_id = NULL, pending_job_id = NULL, last_summarized_rowid = ? WHERE task_id = ?",
        (count, first_at, next_rowid, task_id),
    )


def link_task_event(
    db: sqlite3.Connection,
    *,
    task_id: str,
    session: SessionRecord,
    producer_stream: str,
    event: CaptureEventRecord,
    payload_digest: str,
) -> None:
    trow = db.execute("SELECT owner_id, repo_id, checkout_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    if trow is None:
        raise BrainError(ErrorCode.NOT_FOUND, "task not found")
    if str(trow[1]) != session.repo_id or str(trow[2]) != session.checkout_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "task belongs to different workspace")
    owner_id = str(trow[0])
    wrow = db.execute(
        "SELECT last_summarized_rowid, active_job_id, pending_job_id, dirty_flag "
        "FROM continuity_refresh_state WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    if wrow is None:
        db.execute(
            "INSERT INTO continuity_refresh_state ("
            "task_id, session_ref, owner_id, repo_id, checkout_id, pending_event_count, "
            "first_pending_event_at, observed_through, dirty_flag, active_job_id, pending_job_id, "
            "active_event_cutoff_seq, last_summarized_rowid"
            ") VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, 0, NULL, NULL, 0, 0)",
            (task_id, session.session_ref, owner_id, session.repo_id, session.checkout_id),
        )
        last_rowid, active_jid, pending_jid, dirty = 0, None, None, 0
    else:
        last_rowid, active_jid, pending_jid, dirty = int(wrow[0]), wrow[1], wrow[2], int(wrow[3])

    cur = db.execute(
        "INSERT INTO session_task_events ("
        "task_id, session_ref, producer_stream, sequence, event_id, harness_id, kind, "
        "recorded_at, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (task_id, producer_stream, sequence) DO NOTHING",
        (
            task_id,
            session.session_ref,
            producer_stream,
            event.sequence,
            event.event_id,
            event.harness_id,
            event.kind,
            event.recorded_at,
            payload_digest,
        ),
    )
    inserted = cur.rowcount > 0
    pending_count, first_at = recompute_task_pending(db, task_id, last_rowid)
    next_dirty = 1 if (dirty or (inserted and (active_jid is not None or pending_jid is not None))) else 0
    db.execute(
        "UPDATE continuity_refresh_state SET session_ref = ?, pending_event_count = ?, "
        "first_pending_event_at = ?, dirty_flag = ? WHERE task_id = ?",
        (session.session_ref, pending_count, first_at, next_dirty, task_id),
    )


def legacy_sweep_rows(db: sqlite3.Connection) -> tuple[tuple[str, str], ...]:
    """``(job_id, digest)`` pairs still held for content copies left by the ``778e451`` store shape."""
    rows = db.execute("SELECT job_id, digest FROM continuity_legacy_sweep ORDER BY job_id, digest").fetchall()
    return tuple((str(r[0]), str(r[1])) for r in rows)
