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
        1,
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
        nullable=frozenset({"locator_digest"}),
        reserved=True,
    ),
)


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


POLICY_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_policy_v2)
STORE_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_store_v2)

KERNEL_POLICY_MIGRATIONS: tuple[Migration, ...] = (*POLICY_MIGRATIONS, POLICY_V2_MIGRATION)
KERNEL_STORE_MIGRATIONS: tuple[Migration, ...] = (*STORE_MIGRATIONS, STORE_V2_MIGRATION)
