"""Store v8 append-only migration: handoff revision headers, C5 extended columns, deliveries & episodes (SP2-4)."""

from __future__ import annotations

import sqlite3
from functools import lru_cache

from superbrain.core.errors import BrainError, ErrorCode

_ALTERED_BASE_TABLES: tuple[str, ...] = ("artifact_send_attempt", "artifact_read_ack", "tasks", "task_handoffs")
_NEW_V8_TABLES: tuple[str, ...] = (
    "handoff_revision_headers",
    "deliveries",
    "delivery_seen_handoffs",
    "episodes",
    "episode_evidence",
    "artifact_get_results",
)
_ALL_V8_TABLES: tuple[str, ...] = _ALTERED_BASE_TABLES + _NEW_V8_TABLES

_ALTER_STMTS: dict[str, tuple[str, ...]] = {
    "artifact_send_attempt": (
        "ALTER TABLE artifact_send_attempt ADD COLUMN level TEXT NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE artifact_send_attempt ADD COLUMN revision_epoch INTEGER NOT NULL DEFAULT 0",
    ),
    "artifact_read_ack": (
        "ALTER TABLE artifact_read_ack ADD COLUMN artifact_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE artifact_read_ack ADD COLUMN revision_epoch INTEGER NOT NULL DEFAULT 0",
    ),
    "tasks": (
        "ALTER TABLE tasks ADD COLUMN goal_ref TEXT",
        "ALTER TABLE tasks ADD COLUMN goal_holder_id TEXT",
    ),
    "task_handoffs": (
        "ALTER TABLE task_handoffs ADD COLUMN holder_restore_epoch INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE task_handoffs ADD COLUMN goal_ref TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN goal_holder_id TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN agent_holder_id TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN l0_summary_ref TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN takeover_from_principal TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN takeover_from_session_ref TEXT",
        "ALTER TABLE task_handoffs ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
    ),
}

_NEW_TABLE_STMTS: dict[str, str] = {
    "handoff_revision_headers": (
        "CREATE TABLE handoff_revision_headers ("
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
    ),
    "deliveries": (
        "CREATE TABLE deliveries ("
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
    ),
    "delivery_seen_handoffs": (
        "CREATE TABLE delivery_seen_handoffs ("
        "delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id), "
        "idx INTEGER NOT NULL, "
        "artifact_id TEXT NOT NULL, "
        "revision_epoch INTEGER NOT NULL, "
        "revision INTEGER NOT NULL, "
        "digest TEXT NOT NULL, "
        "PRIMARY KEY (delivery_id, idx))"
    ),
    "episodes": (
        "CREATE TABLE episodes ("
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
    ),
    "episode_evidence": (
        "CREATE TABLE episode_evidence ("
        "evidence_id TEXT PRIMARY KEY, "
        "episode_id TEXT NOT NULL REFERENCES episodes(episode_id), "
        "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
        "idx INTEGER NOT NULL, "
        "digest TEXT NOT NULL, "
        "cas_holder_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    ),
    "artifact_get_results": (
        "CREATE TABLE artifact_get_results ("
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
    ),
}

_NEW_INDEX_STMTS: dict[str, tuple[str, ...]] = {
    "handoff_revision_headers": (
        "CREATE INDEX idx_handoff_rev_headers_task "
        "ON handoff_revision_headers (task_id, revision_epoch, revision)",
    ),
}


def _definitions_by_table(db: sqlite3.Connection, tables: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Normalized ``CREATE`` DDLs per target table/index/object name from ``sqlite_master``."""
    out: dict[str, dict[str, str]] = {t: {} for t in tables}
    table_set = set(tables)
    marks = ", ".join("?" for _ in tables)
    rows = db.execute(
        f"SELECT type, name, tbl_name, sql FROM sqlite_master "
        f"WHERE (tbl_name IN ({marks}) OR name IN ({marks})) AND sql IS NOT NULL",
        tables + tables,
    ).fetchall()
    for typ, name, tbl_name, sql in rows:
        target = str(tbl_name) if str(tbl_name) in table_set else str(name)
        out[target][f"{typ}:{name}"] = " ".join(str(sql).split())
    return out


def _seed_canonical_v7_base(ref: sqlite3.Connection) -> None:
    ref.execute(
        "CREATE TABLE artifact_send_attempt ("
        "id TEXT PRIMARY KEY, "
        "logical_result_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "task_id TEXT NOT NULL, "
        "artifact_id TEXT NOT NULL, "
        "revision INTEGER NOT NULL CHECK (revision >= 1), "
        "digests_json TEXT NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('pending', 'unknown', 'served_only')))"
    )
    ref.execute("CREATE INDEX idx_artifact_send_attempt_state ON artifact_send_attempt (state)")
    ref.execute(
        "CREATE TABLE artifact_read_ack ("
        "id TEXT PRIMARY KEY, "
        "served_receipt_id TEXT NOT NULL UNIQUE, "
        "principal_id TEXT NOT NULL, "
        "task_id TEXT NOT NULL, "
        "revision INTEGER NOT NULL CHECK (revision >= 1), "
        "digests_json TEXT NOT NULL)"
    )
    ref.execute(
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
    ref.execute(
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


@lru_cache(maxsize=1)
def _reference_ddls() -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    ref = sqlite3.connect(":memory:")
    try:
        _seed_canonical_v7_base(ref)
        v7 = _definitions_by_table(ref, _ALTERED_BASE_TABLES)
        for stmts in _ALTER_STMTS.values():
            for stmt in stmts:
                ref.execute(stmt)
        for tbl in _NEW_V8_TABLES:
            ref.execute(_NEW_TABLE_STMTS[tbl])
            for idx_stmt in _NEW_INDEX_STMTS.get(tbl, ()):
                ref.execute(idx_stmt)
        v8 = _definitions_by_table(ref, _ALL_V8_TABLES)
        return v7, v8
    finally:
        ref.close()


def apply_handoff_store_v8(db: sqlite3.Connection) -> None:
    """Upgrade store v7 -> v8 with strict DDL contract verification and C5/handoff tables."""
    v7_ddls, v8_ddls = _reference_ddls()
    found = _definitions_by_table(db, _ALL_V8_TABLES)

    needs_alter: list[str] = []
    for tbl in _ALTERED_BASE_TABLES:
        if found[tbl] == v7_ddls[tbl]:
            needs_alter.append(tbl)
        elif found[tbl] != v8_ddls[tbl]:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unrecognized {tbl} schema before v8 migration")

    needs_create: list[str] = []
    for tbl in _NEW_V8_TABLES:
        if not found[tbl]:
            needs_create.append(tbl)
        elif found[tbl] != v8_ddls[tbl]:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unrecognized {tbl} schema before v8 migration")

    for tbl in needs_alter:
        for stmt in _ALTER_STMTS[tbl]:
            db.execute(stmt)

    if db.execute("SELECT 1 FROM artifact_read_ack LIMIT 1").fetchone() is not None:
        db.execute(
            "UPDATE artifact_read_ack SET artifact_id = COALESCE("
            "(SELECT s.artifact_id FROM artifact_send_attempt AS s "
            "WHERE s.id = artifact_read_ack.served_receipt_id), '') "
            "WHERE artifact_id = ''"
        )

    has_handoffs = db.execute("SELECT 1 FROM task_handoffs LIMIT 1").fetchone() is not None
    if has_handoffs:
        db.execute(
            "UPDATE task_handoffs SET updated_at = COALESCE("
            "(SELECT t.updated_at FROM tasks AS t WHERE t.task_id = task_handoffs.task_id), '') "
            "WHERE updated_at = ''"
        )

    for tbl in needs_create:
        db.execute(_NEW_TABLE_STMTS[tbl])
        for idx_stmt in _NEW_INDEX_STMTS.get(tbl, ()):
            db.execute(idx_stmt)

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

    if _definitions_by_table(db, _ALL_V8_TABLES) != v8_ddls:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "store v8 post-migration schema mismatch")


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
