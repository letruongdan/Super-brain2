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
