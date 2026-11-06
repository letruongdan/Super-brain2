"""Increment 2 v2 schema migrations and reserved kernel policy ledger kinds."""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime

from superbrain.core.ids import new_id
from superbrain.storage.kinds import EntryKind, FieldType
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration

POLICY_V2_TABLES: frozenset[str] = frozenset(
    {
        "principal",
        "credential",
        "repo_policy",
        "repo_grant",
        "workspace_repo_locator",
        "workspace_checkout",
        "request_digest_key",
    }
)

KERNEL_POLICY_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "policy.credential_revoke",
        1,
        {
            "intent_id": FieldType.UUID,
            "principal_id": FieldType.OPAQUE_ID,
            "credential_id": FieldType.UUID,
            "owner_id": FieldType.OPAQUE_ID,
        },
        {},
        reserved=True,
    ),
    EntryKind(
        "policy.workspace_register",
        2,
        {
            "intent_id": FieldType.UUID,
            "subject_id": FieldType.DIGEST,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "principal_id": FieldType.OPAQUE_ID,
            "machine_id": FieldType.OPAQUE_ID,
            "alias": FieldType.OPAQUE_ID,
            "locator_digest": FieldType.DIGEST,
        },
        {},
        nullable=frozenset({"locator_digest", "subject_id"}),
        reserved=True,
    ),
)


_SNAPSHOT_STATUSES = frozenset({"available", "unavailable", "deadline"})
_SELECTOR_PATHS = frozenset({"rules", "jev"})
_SELECTOR_REASONS = frozenset(
    {"provider_unavailable", "egress_ineligible", "jev_selected", "jev_failed", "jev_deadline"}
)
_SOURCE_FIELDS: dict[str, FieldType] = {
    "owner_id": FieldType.OPAQUE_ID,
    "repo_id": FieldType.OPAQUE_ID,
    "source_kind": FieldType.OPAQUE_ID,
    "source_id": FieldType.OPAQUE_ID,
    "source_revision": FieldType.INT,
    "source_digest": FieldType.DIGEST,
}

KERNEL_WORKSPACE_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "snapshot.observed",
        1,
        {
            "snapshot_id": FieldType.UUID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "kind": FieldType.ENUM,
            "dirty": FieldType.BOOL,
            "descriptor_digest": FieldType.DIGEST,
            "observed_at": FieldType.TIMESTAMP,
        },
        {"kind": frozenset({"git", "directory"})},
    ),
    EntryKind(
        "lineage.task_bound",
        1,
        {
            "task_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "delivery_id": FieldType.OPAQUE_ID,
            "assignment_id": FieldType.OPAQUE_ID,
            "source_snapshot_id": FieldType.UUID,
            "snapshot_status": FieldType.ENUM,
            "selector_path": FieldType.ENUM,
            "selector_reason": FieldType.ENUM,
        },
        {
            "snapshot_status": _SNAPSHOT_STATUSES,
            "selector_path": _SELECTOR_PATHS,
            "selector_reason": _SELECTOR_REASONS,
        },
        nullable=frozenset({"assignment_id", "source_snapshot_id"}),
    ),
    EntryKind("lineage.task_source_added", 1, {"task_id": FieldType.OPAQUE_ID, **_SOURCE_FIELDS}, {}),
    EntryKind("lineage.task_unknown_marked", 1, {"task_id": FieldType.OPAQUE_ID}, {}),
    EntryKind(
        "lineage.field_source_added",
        1,
        {"task_id": FieldType.OPAQUE_ID, "field_path_digest": FieldType.DIGEST, **_SOURCE_FIELDS},
        {},
    ),
    EntryKind(
        "lineage.field_unknown_marked",
        1,
        {"task_id": FieldType.OPAQUE_ID, "field_path_digest": FieldType.DIGEST},
        {},
    ),
)
"""Task 3 event-sourced business kinds (no DDL): reducers in ``storage.workspaces`` build ``p_*`` tables."""


def _policy_v2(db: sqlite3.Connection) -> None:
    """Policy store v2 DDL: principals, credentials, repo policies/grants, workspace registry, and request HMAC key."""
    db.execute(
        "CREATE TABLE principal ("
        "id TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "harness_id TEXT NOT NULL, "
        "machine_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL, "
        "UNIQUE(owner_id, harness_id, machine_id))"
    )
    db.execute(
        "CREATE TABLE credential ("
        "id TEXT PRIMARY KEY, "
        "principal_id TEXT NOT NULL REFERENCES principal(id), "
        "secret_digest TEXT NOT NULL, "
        "created_at TEXT NOT NULL, "
        "revoked_intent_id TEXT)"
    )
    db.execute(
        "CREATE TABLE repo_policy ("
        "repo_id TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "provider_egress_enabled INTEGER NOT NULL DEFAULT 0, "
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE repo_grant ("
        "principal_id TEXT NOT NULL REFERENCES principal(id), "
        "repo_id TEXT NOT NULL REFERENCES repo_policy(repo_id), "
        "granted_intent_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL, "
        "PRIMARY KEY(principal_id, repo_id))"
    )
    db.execute(
        "CREATE TABLE workspace_repo_locator ("
        "locator_digest TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL REFERENCES repo_policy(repo_id), "
        "scheme TEXT NOT NULL, "
        "canonical_locator TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE workspace_checkout ("
        "checkout_id TEXT PRIMARY KEY, "
        "owner_id TEXT NOT NULL, "
        "repo_id TEXT NOT NULL REFERENCES repo_policy(repo_id), "
        "machine_id TEXT NOT NULL, "
        "alias TEXT NOT NULL, "
        "checkout_path TEXT NOT NULL, "
        "path_identity TEXT NOT NULL, "
        "registered_intent_id TEXT NOT NULL, "
        "created_at TEXT NOT NULL, "
        "UNIQUE(owner_id, machine_id, alias), "
        "UNIQUE(owner_id, machine_id, path_identity))"
    )
    db.execute(
        "CREATE TABLE request_digest_key ("
        "id TEXT PRIMARY KEY, "
        "key_bytes BLOB NOT NULL CHECK(length(key_bytes) = 32), "
        "active INTEGER NOT NULL CHECK(active IN (0, 1)), "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "INSERT INTO request_digest_key (id, key_bytes, active, created_at) VALUES (?, ?, 1, ?)",
        (new_id(), os.urandom(32), utc_timestamp(datetime.now(UTC))),
    )


def _store_v2(db: sqlite3.Connection) -> None:
    """Main store v2 capability fence (``schema_version=2, min_reader_version=2``).

    Business snapshot and lineage tables belong to Task 3 projection reducers, not schema DDL.
    """
    _ = db


def _policy_v3(db: sqlite3.Connection) -> None:
    """Policy store v3 capability fence (``schema_version=3, min_reader_version=3``) for the v2
    ``policy.workspace_register`` subject-authority contract.
    """
    _ = db


def _store_v3(db: sqlite3.Connection) -> None:
    """Main store v3 capability fence (``schema_version=3, min_reader_version=3``) outside ``policy/`` for the
    coupled v2 ``policy.workspace_register`` subject-authority history contract.
    """
    _ = db


POLICY_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_policy_v2)
POLICY_V3_MIGRATION = Migration(to_version=3, min_reader_version=3, apply=_policy_v3)
STORE_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_store_v2)
STORE_V3_MIGRATION = Migration(to_version=3, min_reader_version=3, apply=_store_v3)

KERNEL_POLICY_MIGRATIONS: tuple[Migration, ...] = (
    *POLICY_MIGRATIONS,
    POLICY_V2_MIGRATION,
    POLICY_V3_MIGRATION,
)
KERNEL_STORE_MIGRATIONS: tuple[Migration, ...] = (
    *STORE_MIGRATIONS,
    STORE_V2_MIGRATION,
    STORE_V3_MIGRATION,
)
