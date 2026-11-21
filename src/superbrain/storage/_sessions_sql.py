"""SQLite row decoders and transaction helpers for ``storage.sessions`` (SP2-3)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime

from superbrain.core._kernel_base import require_opaque_id, require_sha256_digest
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.continuity import (
    ContinuityWorkerState,
    LongRunningCheckpoint,
    RecipientProfile,
    SessionRecord,
    SessionSegmentRecord,
    SessionState,
    TaskHandoffRecord,
    monotonic_watermark,
)
from superbrain.storage.errors import sqlite_error
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

TASK_SELECT_COLS = (
    "task_id, artifact_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
    "handoff_revision, writer_generation, agent_ref, observed_ref, task_state, task_state_source, "
    "holder_principal, holder_session_ref, agent_updated_at, observed_through"
)
SESSION_SELECT_COLS = (
    "session_ref, repo_id, checkout_id, principal_id, harness_id, "
    "state, last_event_at, active_segment_id, ended_at"
)


def parse_iso_utc(timestamp: str) -> datetime:
    """Parse canonical/flexible ISO UTC ``...Z`` string into UTC aware ``datetime``."""
    return datetime.fromisoformat(timestamp[:-1] + "+00:00").astimezone(UTC)


def require_ready(store: Store, policy: PolicyStore) -> None:
    """Require store v6 and policy v5 before session/handoff operations."""
    store._check()
    policy._check()
    if store.schema_version < 6 or policy.schema_version < 5:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def decode_session(row: tuple[object, ...]) -> SessionRecord:
    """Decode one row fetched using ``SESSION_SELECT_COLS``."""
    return SessionRecord(
        session_ref=str(row[0]),
        repo_id=str(row[1]),
        checkout_id=str(row[2]),
        principal_id=str(row[3]),
        harness_id=str(row[4]),
        state=SessionState(str(row[5])),
        last_event_at=str(row[6]),
        active_segment_id=None if row[7] is None else str(row[7]),
        ended_at=None if row[8] is None else str(row[8]),
    )


def _req_int(value: object) -> int:
    if type(value) is not int:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected integer column value")
    return value


def decode_segment(row: tuple[object, ...]) -> SessionSegmentRecord:
    """Decode one ``session_segments`` row."""
    return SessionSegmentRecord(
        segment_id=str(row[0]),
        session_ref=str(row[1]),
        segment_index=_req_int(row[2]),
        profile=RecipientProfile(
            harness_id=str(row[3]),
            provider_endpoint_digest=str(row[4]),
            model_config_digest=str(row[5]),
            account_digest=str(row[6]),
        ),
        opened_at=str(row[7]),
    )


def decode_handoff(row: tuple[object, ...]) -> TaskHandoffRecord:
    """Decode one row fetched using ``TASK_SELECT_COLS``."""
    return TaskHandoffRecord(
        task_id=str(row[0]),
        artifact_id=str(row[1]),
        repo_id=str(row[2]),
        checkout_id=str(row[3]),
        current_revision=_req_int(row[4]),
        current_revision_epoch=_req_int(row[5]),
        handoff_revision=_req_int(row[6]),
        writer_generation=_req_int(row[7]),
        agent_ref=None if row[8] is None else str(row[8]),
        observed_ref=None if row[9] is None else str(row[9]),
        task_state=str(row[10]),
        task_state_source=str(row[11]),
        holder_principal=None if row[12] is None else str(row[12]),
        holder_session_ref=None if row[13] is None else str(row[13]),
        agent_updated_at=None if row[14] is None else str(row[14]),
        observed_through=None if row[15] is None else str(row[15]),
    )


def decode_worker_state(row: tuple[object, ...]) -> ContinuityWorkerState:
    """Decode one ``continuity_refresh_state`` row."""
    return ContinuityWorkerState(
        task_id=str(row[0]),
        owner_id=str(row[1]),
        repo_id=str(row[2]),
        checkout_id=str(row[3]),
        pending_event_count=_req_int(row[4]),
        first_pending_event_at=None if row[5] is None else str(row[5]),
        observed_through=None if row[6] is None else str(row[6]),
        dirty_flag=_req_int(row[7]) != 0,
        active_job_id=None if row[8] is None else str(row[8]),
        pending_job_id=None if row[9] is None else str(row[9]),
    )


def sync_producer_watermark(db: sqlite3.Connection, producer_stream: str, sequence: int, stamp: str) -> int:
    """Advance ``producer_watermarks.high_seq`` monotonically without regressing on late events."""
    row = db.execute(
        "SELECT high_seq, contiguous_seq FROM producer_watermarks WHERE producer_stream = ?",
        (producer_stream,),
    ).fetchone()
    prev_high = 0 if row is None else int(row[0])
    contiguous = 0 if row is None else int(row[1])
    next_high = monotonic_watermark(prev_high, sequence)
    db.execute(
        "INSERT INTO producer_watermarks (producer_stream, high_seq, contiguous_seq, updated_at) "
        "VALUES (?, ?, ?, ?) ON CONFLICT (producer_stream) DO UPDATE SET "
        "high_seq = CASE WHEN excluded.high_seq > producer_watermarks.high_seq "
        "THEN excluded.high_seq ELSE producer_watermarks.high_seq END, "
        "updated_at = excluded.updated_at",
        (producer_stream, next_high, contiguous, stamp),
    )
    return next_high


def recompute_task_pending(db: sqlite3.Connection, task_id: str, last_summarized_rowid: int) -> tuple[int, str | None]:
    """Compute exact unsummarized count and earliest timestamp after ``last_summarized_rowid``."""
    row = db.execute(
        "SELECT COUNT(*), MIN(recorded_at) FROM session_task_events WHERE task_id = ? AND event_order > ?",
        (task_id, last_summarized_rowid),
    ).fetchone()
    if row is None or int(row[0]) == 0:
        return 0, None
    return int(row[0]), None if row[1] is None else str(row[1])


def persist_long_running_checkpoint(
    db: sqlite3.Connection,
    *,
    task_id: str,
    session_ref: str,
    long_running_raw: object,
    saw_long_running_event: bool,
    stamp: str,
    new_id_fn: object,
) -> None:
    """Update or clear durable ``long_running`` checkpoint row atomically in ``db``."""
    if isinstance(long_running_raw, Mapping):
        ckpt = LongRunningCheckpoint.from_dict(dict(long_running_raw))
        encoded = canonical_json(ckpt.to_dict()).decode("utf-8")
        db.execute(
            "DELETE FROM session_checkpoints WHERE task_id = ? AND checkpoint_kind = 'long_running'",
            (task_id,),
        )
        db.execute(
            "INSERT INTO session_checkpoints "
            "(checkpoint_id, session_ref, task_id, checkpoint_kind, payload_json, updated_at) "
            "VALUES (?, ?, ?, 'long_running', ?, ?)",
            (new_id_fn(), session_ref, task_id, encoded, stamp),  # type: ignore[operator]
        )
    elif saw_long_running_event:
        db.execute(
            "DELETE FROM session_checkpoints WHERE task_id = ? AND checkpoint_kind = 'long_running'",
            (task_id,),
        )


def decode_checkpoint(payload_json: str) -> LongRunningCheckpoint:
    """Validate and decode persisted ``LongRunningCheckpoint`` JSON."""
    try:
        raw = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        raise sqlite_error("corrupt long_running checkpoint JSON", sqlite3.DataError(str(exc))) from exc
    return LongRunningCheckpoint.from_dict(raw)


def validate_session_binding_args(
    *,
    principal_id: str,
    repo_id: str,
    checkout_id: str,
    harness_id: str,
    raw_session_id: str,
) -> None:
    require_opaque_id(principal_id, label="principal_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    require_opaque_id(harness_id, label="harness_id")
    if not isinstance(raw_session_id, str) or not raw_session_id:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid session identifier")


def validate_session_ref_args(session_ref: str, *, checkout_id: str, repo_id: str | None = None) -> None:
    require_sha256_digest(session_ref)
    require_opaque_id(checkout_id, label="checkout_id")
    if repo_id is not None:
        require_opaque_id(repo_id, label="repo_id")
