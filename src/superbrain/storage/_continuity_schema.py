"""Store v7: session, task-handoff and continuity tables over the SP2-2 store v6 (append-only).

Three store v6 shapes exist from development builds and all three upgrade here: ``c57fb92`` (no continuity
tables), ``778e451`` (continuity tables with ``session_task_events.event_json`` copies) and r5 (refs only). A shape
is recognized by the exact definition of every capture and continuity table and index the v7 code reads (the capture
part from the one store v6 contract, ``apply_capture_store_v6``); any other or partial shape fails inside the staged
migration transaction, before the swap and before ``READY``.
"""

from __future__ import annotations

import sqlite3

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage._capture_schema import apply_capture_store_v6

CAPTURE_TABLES: frozenset[str] = frozenset({"capture_events", "producer_watermarks", "capture_gaps"})

CONTINUITY_TABLES: frozenset[str] = frozenset(
    {
        "sessions",
        "session_segments",
        "capture_exposure",
        "tasks",
        "task_handoffs",
        "handoff_revisions",
        "continuity_refresh_state",
        "session_task_events",
        "session_checkpoints",
    }
)
_REFS_LINK_COLUMNS = (
    "event_order", "task_id", "session_ref", "producer_stream", "sequence", "event_id", "harness_id", "kind",
    "recorded_at", "payload_digest",
)


def _create_continuity_tables(db: sqlite3.Connection, *, legacy_link: bool = False) -> None:
    db.execute(
        "CREATE TABLE sessions ("
        "session_ref TEXT PRIMARY KEY, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "harness_id TEXT NOT NULL, "
        "state TEXT NOT NULL, "
        "last_event_at TEXT NOT NULL, "
        "active_segment_id TEXT, "
        "ended_at TEXT)"
    )
    db.execute("CREATE INDEX idx_sessions_scope ON sessions (repo_id, checkout_id, state)")
    db.execute(
        "CREATE TABLE session_segments ("
        "segment_id TEXT PRIMARY KEY, "
        "session_ref TEXT NOT NULL REFERENCES sessions(session_ref), "
        "segment_index INTEGER NOT NULL, "
        "harness_id TEXT NOT NULL, "
        "provider_endpoint_digest TEXT NOT NULL, "
        "model_config_digest TEXT NOT NULL, "
        "account_digest TEXT NOT NULL, "
        "opened_at TEXT NOT NULL, "
        "UNIQUE(session_ref, segment_index))"
    )
    db.execute(
        "CREATE TABLE capture_exposure ("
        "segment_id TEXT NOT NULL REFERENCES session_segments(segment_id), "
        "item_ref TEXT NOT NULL, "
        "event_id TEXT NOT NULL, "
        "item_digest TEXT NOT NULL, "
        "exposure_evidence TEXT NOT NULL, "
        "completed_model_call_id TEXT, "
        "recorded_at TEXT NOT NULL, "
        "PRIMARY KEY (segment_id, item_ref))"
    )
    db.execute(
        "CREATE TABLE tasks ("
        "task_id TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "current_revision INTEGER NOT NULL DEFAULT 0, "
        "current_revision_epoch INTEGER NOT NULL DEFAULT 0, "
        "task_state TEXT NOT NULL, "
        "task_state_source TEXT NOT NULL, "
        "holder_principal TEXT, "
        "holder_session_ref TEXT, "
        "created_at TEXT NOT NULL, "
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE task_handoffs ("
        "task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), "
        "artifact_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "current_revision INTEGER NOT NULL DEFAULT 0, "
        "current_revision_epoch INTEGER NOT NULL DEFAULT 0, "
        "handoff_revision INTEGER NOT NULL DEFAULT 0, "
        "writer_generation INTEGER NOT NULL DEFAULT 0, "
        "agent_ref TEXT, "
        "observed_ref TEXT, "
        "task_state TEXT NOT NULL DEFAULT 'in_progress', "
        "task_state_source TEXT NOT NULL DEFAULT 'inferred', "
        "holder_principal TEXT, "
        "holder_session_ref TEXT, "
        "agent_updated_at TEXT, "
        "observed_through TEXT)"
    )
    db.execute(
        "CREATE TABLE handoff_revisions ("
        "revision_seq INTEGER PRIMARY KEY AUTOINCREMENT, "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "handoff_revision INTEGER NOT NULL, "
        "source_kind TEXT NOT NULL, "
        "agent_ref TEXT, "
        "observed_ref TEXT, "
        "recorded_at TEXT NOT NULL)"
    )
    db.execute("CREATE INDEX idx_handoff_revisions_task ON handoff_revisions (task_id, handoff_revision)")
    db.execute(
        "CREATE TABLE continuity_refresh_state ("
        "task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), "
        "session_ref TEXT NOT NULL REFERENCES sessions(session_ref), "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "pending_event_count INTEGER NOT NULL DEFAULT 0, "
        "first_pending_event_at TEXT, "
        "observed_through TEXT, "
        "dirty_flag INTEGER NOT NULL DEFAULT 0, "
        "active_job_id TEXT, "
        "pending_job_id TEXT, "
        "active_event_cutoff_seq INTEGER NOT NULL DEFAULT 0, "
        "last_summarized_rowid INTEGER NOT NULL DEFAULT 0)"
    )
    _create_link_table(db, "session_task_events", legacy=legacy_link)
    db.execute(
        "CREATE TABLE session_checkpoints ("
        "checkpoint_id TEXT PRIMARY KEY, "
        "session_ref TEXT NOT NULL REFERENCES sessions(session_ref), "
        "task_id TEXT REFERENCES tasks(task_id), "
        "checkpoint_kind TEXT NOT NULL, "
        "payload_json TEXT NOT NULL, "
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE INDEX idx_session_checkpoints_lookup ON session_checkpoints (session_ref, task_id, checkpoint_kind)"
    )


def _create_link_table(db: sqlite3.Connection, name: str, *, legacy: bool = False) -> None:
    """The link table; ``legacy`` adds the ``event_json`` copy column exactly where the ``778e451`` build had it."""
    db.execute(
        f"CREATE TABLE {name} ("
        "event_order INTEGER PRIMARY KEY AUTOINCREMENT, "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "session_ref TEXT NOT NULL REFERENCES sessions(session_ref), "
        "producer_stream TEXT NOT NULL, "
        "sequence INTEGER NOT NULL, "
        "event_id TEXT NOT NULL, "
        "harness_id TEXT NOT NULL, "
        "kind TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL, "
        "payload_digest TEXT NOT NULL, "
        + ("event_json TEXT NOT NULL, " if legacy else "")
        + "UNIQUE(task_id, producer_stream, sequence))"
    )


def _create_sweep_table(db: sqlite3.Connection) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS continuity_legacy_sweep ("
        "job_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY (job_id, digest))"
    )


def _tables(db: sqlite3.Connection) -> set[str]:
    return {str(r[0]) for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}


_CHECKED_TABLES = CAPTURE_TABLES | CONTINUITY_TABLES


def _definitions(db: sqlite3.Connection) -> dict[str, str]:
    """Normalized ``CREATE`` text of every capture and continuity table and index (columns, types, keys, uniques)."""
    marks = ", ".join("?" for _ in _CHECKED_TABLES)
    rows = db.execute(
        f"SELECT type, name, sql FROM sqlite_master WHERE tbl_name IN ({marks}) AND sql IS NOT NULL",
        tuple(sorted(_CHECKED_TABLES)),
    ).fetchall()
    return {f"{r[0]}:{r[1]}": " ".join(str(r[2]).split()) for r in rows}


def _known_definitions(*, continuity: bool, legacy_link: bool = False) -> dict[str, str]:
    ref = sqlite3.connect(":memory:")
    try:
        apply_capture_store_v6(ref)
        if continuity:
            _create_continuity_tables(ref, legacy_link=legacy_link)
        return _definitions(ref)
    finally:
        ref.close()


def _drop_legacy_copies(db: sqlite3.Connection, tables: set[str]) -> None:
    """``778e451`` shape: keep events and verified links, drop every derived copy of event content."""
    cols = ", ".join(_REFS_LINK_COLUMNS)
    _create_link_table(db, "session_task_events_v7")
    db.execute(f"INSERT INTO session_task_events_v7 ({cols}) SELECT {cols} FROM session_task_events")
    db.execute("DROP TABLE session_task_events")
    db.execute("ALTER TABLE session_task_events_v7 RENAME TO session_task_events")
    # Long-running checkpoints of that build stored command/cwd copies; the next refresh rebuilds them as refs.
    db.execute(
        "DELETE FROM session_checkpoints WHERE checkpoint_kind = 'long_running' "
        "AND payload_json NOT LIKE '{\"source\":%'"
    )
    # Every linked event is considered again, so the observed part is rebuilt from refs to live sources.
    db.execute(
        "UPDATE continuity_refresh_state SET last_summarized_rowid = 0, dirty_flag = 0, active_job_id = NULL, "
        "pending_job_id = NULL, "
        "pending_event_count = (SELECT COUNT(*) FROM session_task_events e "
        "WHERE e.task_id = continuity_refresh_state.task_id), "
        "first_pending_event_at = (SELECT MIN(recorded_at) FROM session_task_events e "
        "WHERE e.task_id = continuity_refresh_state.task_id)"
    )
    _create_sweep_table(db)
    if {"p_jobs_state", "p_cas_holders_"} <= tables:
        # Job payloads (full events) and observed summaries (copied text) are held by the refresh job's holder;
        # the ledger-writing sweep on open releases them and fails any such job still waiting to run.
        db.execute(
            "INSERT OR IGNORE INTO continuity_legacy_sweep (job_id, digest) "
            "SELECT h.holder_id, h.digest FROM p_jobs_state j JOIN p_cas_holders_ h "
            "ON h.holder_kind = 'event' AND h.holder_id = j.job_id WHERE j.kind = 'continuity.refresh'"
        )


def apply_continuity_store_v7(db: sqlite3.Connection) -> None:
    found = _definitions(db)
    if found == _known_definitions(continuity=False):
        _create_continuity_tables(db)
        _create_sweep_table(db)
    elif found == _known_definitions(continuity=True):
        _create_sweep_table(db)
    elif found == _known_definitions(continuity=True, legacy_link=True):
        _drop_legacy_copies(db, _tables(db))
    else:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unrecognized store v6 continuity schema")
