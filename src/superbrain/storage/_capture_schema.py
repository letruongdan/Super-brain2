"""Store v6 capture continuity DDL helpers (``capture_events``, ``producer_watermarks``, ``capture_gaps``)."""

from __future__ import annotations

import sqlite3


def apply_capture_store_v6(db: sqlite3.Connection) -> None:
    """Apply SP2-2 ``store v6`` capture continuity tables and indexes."""
    db.execute(
        "CREATE TABLE capture_events ("
        "producer_stream TEXT NOT NULL, "
        "sequence INTEGER NOT NULL CHECK(sequence >= 1), "
        "event_id TEXT NOT NULL, "
        "harness_id TEXT NOT NULL, "
        "kind TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL, "
        "payload_digest TEXT NOT NULL, "
        "cas_holder_id TEXT NOT NULL, "
        "source TEXT NOT NULL CHECK(source IN ('tool_observed', 'unknown')), "
        "source_verification TEXT NOT NULL "
        "CHECK(source_verification IN ('verified_host', 'unverified', 'unavailable')), "
        "repo_id TEXT NOT NULL, "
        "checkout_id TEXT NOT NULL, "
        "principal_id TEXT NOT NULL, "
        "session_ref TEXT, "
        "source_metadata_json BLOB NOT NULL, "
        "committed_at TEXT NOT NULL, "
        "PRIMARY KEY (producer_stream, sequence))"
    )
    db.execute(
        "CREATE INDEX idx_capture_events_repo_seq ON capture_events (repo_id, checkout_id, committed_at)"
    )
    db.execute(
        "CREATE TABLE producer_watermarks ("
        "producer_stream TEXT PRIMARY KEY, "
        "high_seq INTEGER NOT NULL CHECK(high_seq >= 0), "
        "contiguous_seq INTEGER NOT NULL DEFAULT 0 CHECK(contiguous_seq >= 0), "
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE capture_gaps ("
        "gap_id TEXT PRIMARY KEY, "
        "producer_stream TEXT NOT NULL, "
        "sequence INTEGER NOT NULL CHECK(sequence >= 1), "
        "gap_origin TEXT NOT NULL CHECK(gap_origin IN ('producer', 'daemon')), "
        "status TEXT NOT NULL CHECK(status IN ('open', 'closed', 'producer')), "
        "reason TEXT NOT NULL, "
        "estimated_count INTEGER NOT NULL DEFAULT 1 CHECK(estimated_count >= 1), "
        "duration_ms INTEGER, "
        "repo_id TEXT, "
        "checkout_id TEXT, "
        "recorded_at TEXT NOT NULL, "
        "closed_at TEXT, "
        "UNIQUE(producer_stream, sequence, gap_origin))"
    )
    db.execute(
        "CREATE INDEX idx_capture_gaps_status ON capture_gaps (status, producer_stream, sequence)"
    )

    # SP2-3: sessions, recipient segments, exposure classifications, task handoffs & continuity worker tables.
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
    db.execute(
        "CREATE TABLE session_task_events ("
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
        "event_json TEXT NOT NULL, "
        "UNIQUE(task_id, producer_stream, sequence))"
    )
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
