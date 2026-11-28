"""Store v4 and policy v4 migrations; ``kernel_schema`` re-exports them."""

from __future__ import annotations

import sqlite3

from superbrain.storage._proposal_schema import (
    KERNEL_PROPOSAL_KINDS as KERNEL_PROPOSAL_KINDS,
)


def _store_v4(db: sqlite3.Connection) -> None:
    """Main store v4 operational tables (``schema_version=4, min_reader_version=4``) for Task 4 idempotency,
    artifact send attempts, and artifact read acknowledgments (C1, C4, C5).
    """
    db.execute(
        "CREATE TABLE idempotency ("
        "principal_id TEXT NOT NULL, "
        "tool TEXT NOT NULL, "
        "key_hash TEXT NOT NULL, "
        "request_digest_key_id TEXT NOT NULL, "
        "request_digest TEXT NOT NULL, "
        "result_id TEXT NOT NULL, "
        "assignment_id TEXT, "
        "refs_json TEXT NOT NULL, "
        "committed_at TEXT NOT NULL, "
        "PRIMARY KEY (principal_id, tool, key_hash))"
    )
    db.execute("CREATE INDEX idx_idempotency_committed_at ON idempotency (committed_at, principal_id, tool, key_hash)")
    db.execute(
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
    db.execute("CREATE INDEX idx_artifact_send_attempt_state ON artifact_send_attempt (state)")
    db.execute(
        "CREATE TABLE artifact_read_ack ("
        "id TEXT PRIMARY KEY, "
        "served_receipt_id TEXT NOT NULL UNIQUE, "
        "principal_id TEXT NOT NULL, "
        "task_id TEXT NOT NULL, "
        "revision INTEGER NOT NULL CHECK (revision >= 1), "
        "digests_json TEXT NOT NULL)"
    )


def _policy_v4(db: sqlite3.Connection) -> None:
    """Policy store v4 (``schema_version=4, min_reader_version=4``): signers, single-use approval nonces and receipts,
    harness layer-2 state, recovery grants, apply-turn intents, accounting tables and the repo privacy flags (the
    migrated rows keep ``provider_egress_enabled`` and get every new flag on, spec 14.2).
    """
    db.execute(
        "CREATE TABLE signer ("
        "id TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "channel TEXT NOT NULL CHECK (channel IN ('passkey_uv', 'ssh_sk_verified', 'ssh_sk', 'ssh_key')), "
        "key_digest TEXT NOT NULL, "
        "public_key TEXT NOT NULL, "
        "credential_id TEXT, "
        "sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0), "
        "tofu INTEGER NOT NULL CHECK (tofu IN (0, 1)), "
        "created_at TEXT NOT NULL, "
        "revoked_at TEXT, "
        "last_used_at TEXT)"
    )
    db.execute("CREATE UNIQUE INDEX idx_signer_active_key ON signer (owner_id, key_digest) WHERE revoked_at IS NULL")
    db.execute(
        "CREATE TABLE approval_nonce ("
        "nonce TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "action TEXT NOT NULL, "
        "subject_id TEXT NOT NULL, "
        "risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'high')), "
        "trust_generation INTEGER NOT NULL CHECK (trust_generation >= 1), "
        "issued_at TEXT NOT NULL, "
        "expires_at TEXT NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('pending', 'consumed', 'cancelled')), "
        "ended_at TEXT, "
        "end_reason TEXT)"
    )
    db.execute(
        "CREATE TABLE approval_receipt_meta ("
        "approval_id TEXT PRIMARY KEY, "
        "nonce TEXT NOT NULL UNIQUE REFERENCES approval_nonce(nonce), "
        "action TEXT NOT NULL, "
        "subject_id TEXT NOT NULL, "
        "risk_level TEXT NOT NULL, "
        "channel TEXT NOT NULL, "
        "assurance TEXT NOT NULL, "
        "signer_id TEXT, "
        "trust_generation INTEGER NOT NULL, "
        "recovery_scope TEXT NOT NULL, "
        "message_json BLOB NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE harness_layer2_state ("
        "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
        "harness_id TEXT NOT NULL, "
        "host_version TEXT NOT NULL, "
        "config_digest TEXT NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('unknown', 'unsupported', 'verified')), "
        "intent_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE recovery_grant ("
        "grant_id TEXT PRIMARY KEY, "
        "approval_id TEXT NOT NULL UNIQUE, "
        "journal_id TEXT NOT NULL, "
        "subject_id TEXT NOT NULL, "
        "recovery_scope TEXT NOT NULL, "
        "trust_generation INTEGER NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('active', 'ended')), "
        "end_reason TEXT, "
        "opened_intent_id TEXT NOT NULL, "
        "ended_intent_id TEXT, "
        "opened_at TEXT NOT NULL, "
        "ended_at TEXT)"
    )
    db.execute(
        "CREATE TABLE apply_turn_intent ("
        "turn_id TEXT PRIMARY KEY, "
        "journal_id TEXT NOT NULL, "
        "approval_id TEXT NOT NULL, "
        "direction TEXT NOT NULL CHECK (direction IN ('apply', 'rollback')), "
        "state TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE accounting_invocations ("
        "invocation_id TEXT PRIMARY KEY, "
        "job_id TEXT NOT NULL, "
        "owner_id TEXT NOT NULL, "
        "writer_epoch INTEGER NOT NULL, "
        "period_key TEXT NOT NULL, "
        "reserved_amount TEXT NOT NULL, "
        "settled_amount TEXT, "
        "state TEXT NOT NULL CHECK (state IN ('reserved', 'outcome_unknown', 'settled')), "
        "recorded_at TEXT NOT NULL, "
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE accounting_locks ("
        "lock_key TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "period_key TEXT NOT NULL, "
        "backup_created_at TEXT NOT NULL, "
        "locked_at TEXT NOT NULL, "
        "state TEXT NOT NULL CHECK (state IN ('locked', 'reconciled')), "
        "reconciled_at TEXT, "
        "reconciled_approval_id TEXT)"
    )
    for column in _m._REPO_FLAG_COLUMNS:
        db.execute(f"ALTER TABLE repo_policy ADD COLUMN {column} INTEGER NOT NULL DEFAULT 1 CHECK ({column} IN (0, 1))")

# Imported last: the original module re-exports the names above, so it may import this module first.
from superbrain.storage import kernel_schema as _m  # noqa: E402
