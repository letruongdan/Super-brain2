"""Store v8 append-only migration: handoff revision headers, C5 extended columns, deliveries & episodes (SP2-4)."""

from __future__ import annotations

import sqlite3

from superbrain.core.errors import BrainError, ErrorCode

_SEND_ATTEMPT_BASE_COLS: frozenset[str] = frozenset(
    {"id", "logical_result_id", "principal_id", "task_id", "artifact_id", "revision", "digests_json", "state"}
)
_READ_ACK_BASE_COLS: frozenset[str] = frozenset(
    {"id", "served_receipt_id", "principal_id", "task_id", "revision", "digests_json"}
)
_TASKS_BASE_COLS: frozenset[str] = frozenset(
    {"task_id", "owner_id", "repo_id", "checkout_id", "current_revision", "current_revision_epoch", "updated_at"}
)
_TASK_HANDOFFS_BASE_COLS: frozenset[str] = frozenset(
    {
        "task_id",
        "artifact_id",
        "repo_id",
        "checkout_id",
        "current_revision",
        "current_revision_epoch",
        "handoff_revision",
        "writer_generation",
        "task_state",
        "task_state_source",
        "holder_principal",
        "holder_session_ref",
    }
)

_SEND_ATTEMPT_EXT_COLS: tuple[tuple[str, str], ...] = (
    ("level", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("revision_epoch", "INTEGER NOT NULL DEFAULT 0"),
)
_READ_ACK_EXT_COLS: tuple[tuple[str, str], ...] = (
    ("artifact_id", "TEXT NOT NULL DEFAULT ''"),
    ("revision_epoch", "INTEGER NOT NULL DEFAULT 0"),
)
_TASK_HANDOFF_V8_COLS: tuple[tuple[str, str], ...] = (
    ("holder_restore_epoch", "INTEGER NOT NULL DEFAULT 0"),
    ("goal_ref", "TEXT"),
    ("goal_holder_id", "TEXT"),
    ("agent_holder_id", "TEXT"),
    ("l0_summary_ref", "TEXT"),
    ("takeover_from_principal", "TEXT"),
    ("takeover_from_session_ref", "TEXT"),
    ("updated_at", "TEXT NOT NULL DEFAULT ''"),
)


def _cols(db: sqlite3.Connection, table: str) -> set[str]:
    return {str(r[1]) for r in db.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_missing_cols(
    db: sqlite3.Connection,
    table: str,
    specs: tuple[tuple[str, str], ...],
    *,
    existing: set[str] | None = None,
) -> None:
    cols = _cols(db, table) if existing is None else existing
    for col_name, col_ddl in specs:
        if col_name not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_ddl}")


def _verify_pair_or_absent(existing: set[str], cols: tuple[tuple[str, str], ...], label: str) -> None:
    present = {name for name, _ in cols if name in existing}
    if 0 < len(present) < len(cols):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"half-migrated {label} schema")


def _require_base_table(db: sqlite3.Connection, table: str, required: frozenset[str]) -> set[str]:
    existing = _cols(db, table)
    if not required.issubset(existing):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unexpected {table} schema before v8 migration")
    return existing


def apply_handoff_store_v8(db: sqlite3.Connection) -> None:
    """Upgrade store v7 -> v8 with SP2-4 handoff revision headers, C5 columns, and delivery/episode tables."""
    sa_cols = _require_base_table(db, "artifact_send_attempt", _SEND_ATTEMPT_BASE_COLS)
    ra_cols = _require_base_table(db, "artifact_read_ack", _READ_ACK_BASE_COLS)
    tasks_cols = _require_base_table(db, "tasks", _TASKS_BASE_COLS)
    th_cols = _require_base_table(db, "task_handoffs", _TASK_HANDOFFS_BASE_COLS)
    _verify_pair_or_absent(sa_cols, _SEND_ATTEMPT_EXT_COLS, "artifact_send_attempt")
    _verify_pair_or_absent(ra_cols, _READ_ACK_EXT_COLS, "artifact_read_ack")

    _add_missing_cols(db, "artifact_send_attempt", _SEND_ATTEMPT_EXT_COLS, existing=sa_cols)
    _add_missing_cols(db, "artifact_read_ack", _READ_ACK_EXT_COLS, existing=ra_cols)
    if db.execute("SELECT 1 FROM artifact_read_ack LIMIT 1").fetchone() is not None:
        db.execute(
            "UPDATE artifact_read_ack SET artifact_id = COALESCE("
            "(SELECT s.artifact_id FROM artifact_send_attempt AS s "
            "WHERE s.id = artifact_read_ack.served_receipt_id), '') "
            "WHERE artifact_id = ''"
        )

    _add_missing_cols(db, "tasks", (("goal_ref", "TEXT"), ("goal_holder_id", "TEXT")), existing=tasks_cols)
    _add_missing_cols(db, "task_handoffs", _TASK_HANDOFF_V8_COLS, existing=th_cols)
    has_handoffs = db.execute("SELECT 1 FROM task_handoffs LIMIT 1").fetchone() is not None
    if has_handoffs:
        db.execute(
            "UPDATE task_handoffs SET updated_at = COALESCE("
            "(SELECT t.updated_at FROM tasks AS t WHERE t.task_id = task_handoffs.task_id), '') "
            "WHERE updated_at = ''"
        )

    db.execute(
        "CREATE TABLE IF NOT EXISTS handoff_revision_headers ("
        "artifact_id TEXT NOT NULL, "
        "revision_epoch INTEGER NOT NULL, "
        "revision INTEGER NOT NULL CHECK (revision >= 1), "
        "handoff_revision INTEGER NOT NULL CHECK (handoff_revision >= 0), "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "task_state TEXT NOT NULL, "
        "task_state_source TEXT NOT NULL, "
        "holder_restore_epoch INTEGER NOT NULL, "
        "writer_generation INTEGER NOT NULL, "
        "holder_harness_id TEXT, "
        "holder_principal TEXT, "
        "holder_session_ref TEXT, "
        "session_state TEXT, "
        "agent_ref TEXT, "
        "agent_holder_id TEXT, "
        "observed_ref TEXT, "
        "agent_updated_at TEXT, "
        "observed_through TEXT, "
        "recorded_at TEXT NOT NULL, "
        "PRIMARY KEY (artifact_id, revision_epoch, revision))"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_handoff_rev_headers_task "
        "ON handoff_revision_headers (task_id, revision_epoch, revision)"
    )
    # Backfill any v7 task_handoffs that already have a positive revision.
    if has_handoffs:
        db.execute(
            "INSERT OR IGNORE INTO handoff_revision_headers ("
            "artifact_id, revision_epoch, revision, handoff_revision, task_id, task_state, task_state_source, "
            "holder_restore_epoch, writer_generation, holder_harness_id, holder_principal, holder_session_ref, "
            "session_state, agent_ref, agent_holder_id, observed_ref, agent_updated_at, observed_through, recorded_at"
            ") SELECT "
            "h.artifact_id, h.current_revision_epoch, h.current_revision, h.handoff_revision, h.task_id, "
            "h.task_state, h.task_state_source, h.holder_restore_epoch, h.writer_generation, NULL, "
            "h.holder_principal, h.holder_session_ref, NULL, h.agent_ref, NULL, h.observed_ref, h.agent_updated_at, "
            "h.observed_through, h.updated_at FROM task_handoffs AS h WHERE h.current_revision >= 1"
        )

    db.execute(
        "CREATE TABLE IF NOT EXISTS deliveries ("
        "delivery_id TEXT PRIMARY KEY, "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "session_ref TEXT, "
        "mode TEXT NOT NULL, "
        "source_snapshot_id TEXT, "
        "snapshot_status TEXT NOT NULL, "
        "assignment_id TEXT, "
        "resume_artifact_id TEXT, "
        "resume_revision_epoch INTEGER, "
        "resume_revision INTEGER, "
        "resume_receipt_id TEXT, "
        "exposure_evidence TEXT NOT NULL, "
        "degraded_codes_json TEXT NOT NULL, "
        "handoff_served_epoch INTEGER, "
        "handoff_served_rev INTEGER, "
        "handoff_served_digest TEXT, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS delivery_seen_handoffs ("
        "delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id), "
        "idx INTEGER NOT NULL, "
        "artifact_id TEXT NOT NULL, "
        "revision_epoch INTEGER NOT NULL, "
        "revision INTEGER NOT NULL, "
        "digest TEXT NOT NULL, "
        "PRIMARY KEY (delivery_id, idx))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS episodes ("
        "episode_id TEXT PRIMARY KEY, "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "session_ref TEXT NOT NULL, "
        "has_handoff_op INTEGER NOT NULL, "
        "handoff_status TEXT, "
        "handoff_artifact_id TEXT, "
        "committed_handoff_revision INTEGER, "
        "committed_revision INTEGER, "
        "committed_restore_epoch INTEGER, "
        "committed_writer_generation INTEGER, "
        "evidence_ids_json TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS episode_evidence ("
        "evidence_id TEXT PRIMARY KEY, "
        "episode_id TEXT NOT NULL REFERENCES episodes(episode_id), "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "idx INTEGER NOT NULL, "
        "digest TEXT NOT NULL, "
        "cas_holder_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS artifact_get_results ("
        "result_id TEXT PRIMARY KEY, "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "artifact_id TEXT NOT NULL, "
        "revision_epoch INTEGER NOT NULL, "
        "revision INTEGER NOT NULL, "
        "level TEXT NOT NULL, "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )


def record_v8_revision_header_in_tx(
    db: sqlite3.Connection,
    *,
    task_id: str,
    next_revision: int,
    next_handoff_revision: int,
    next_task_state: str,
    next_source: str,
    principal_id: str | None,
    session_ref: str | None,
    agent_ref: str | None,
    observed_ref: str | None,
    agent_updated_at: str | None,
    observed_through: str | None,
    recorded_at: str,
    holder_harness_id: str | None = None,
    session_state: str | None = None,
) -> None:
    """Best-effort sync of ``handoff_revision_headers`` when the store is already on ``v8+``."""
    has_tbl = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'handoff_revision_headers'"
    ).fetchone()
    if has_tbl is None:
        return
    hrow = db.execute(
        "SELECT artifact_id, current_revision_epoch, holder_restore_epoch, writer_generation, agent_holder_id "
        "FROM task_handoffs WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    if hrow is None:
        return
    db.execute(
        "INSERT OR REPLACE INTO handoff_revision_headers ("
        "artifact_id, revision_epoch, revision, handoff_revision, task_id, task_state, task_state_source, "
        "holder_restore_epoch, writer_generation, holder_harness_id, holder_principal, holder_session_ref, "
        "session_state, agent_ref, agent_holder_id, observed_ref, agent_updated_at, observed_through, recorded_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(hrow[0]),
            int(hrow[1]),
            next_revision,
            next_handoff_revision,
            task_id,
            next_task_state,
            next_source,
            int(hrow[2]),
            int(hrow[3]),
            holder_harness_id,
            principal_id,
            session_ref,
            session_state,
            agent_ref,
            None if hrow[4] is None else str(hrow[4]),
            observed_ref,
            agent_updated_at,
            observed_through,
            recorded_at,
        ),
    )


__all__ = ["apply_handoff_store_v8", "record_v8_revision_header_in_tx"]
