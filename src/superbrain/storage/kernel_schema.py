"""Increment 2 v2 schema migrations and reserved kernel policy ledger kinds."""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime

from superbrain.core.ids import new_id
from superbrain.storage._continuity_schema import apply_continuity_store_v7
from superbrain.storage._kernel_schema_v4 import _policy_v4 as _policy_v4
from superbrain.storage._kernel_schema_v4 import _store_v4 as _store_v4
from superbrain.storage._proposal_schema import (
    KERNEL_PROPOSAL_KINDS as KERNEL_PROPOSAL_KINDS,
)
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
    EntryKind(
        "policy.signer_reset",
        1,
        {
            "intent_id": FieldType.UUID,
            "previous_generation": FieldType.INT,
            "new_generation": FieldType.INT,
            "signers_revoked": FieldType.INT,
            "nonces_cancelled": FieldType.INT,
            "grants_ended": FieldType.INT,
        },
        {},
        reserved=True,
    ),
    EntryKind(
        "policy.repo_policy_set",
        1,
        {
            "intent_id": FieldType.UUID,
            "repo_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "automatic_capture_enabled": FieldType.BOOL,
            "manual_submission_enabled": FieldType.BOOL,
            "indexing_enabled": FieldType.BOOL,
            "provider_egress_enabled": FieldType.BOOL,
            "post_session_review_enabled": FieldType.BOOL,
        },
        {},
        reserved=True,
    ),
    EntryKind(
        "policy.layer2_state_set",
        1,
        {
            "intent_id": FieldType.UUID,
            "harness_id": FieldType.OPAQUE_ID,
            "host_version": FieldType.OPAQUE_ID,
            "config_digest": FieldType.DIGEST,
            "state": FieldType.ENUM,
        },
        {"state": frozenset({"unknown", "unsupported", "verified"})},
        reserved=True,
    ),
    EntryKind(
        "policy.recovery_grant_opened",
        1,
        {
            "intent_id": FieldType.UUID,
            "grant_id": FieldType.UUID,
            "approval_id": FieldType.UUID,
            "journal_id": FieldType.UUID,
            "subject_digest": FieldType.DIGEST,
            "recovery_scope": FieldType.ENUM,
            "trust_generation": FieldType.INT,
        },
        {"recovery_scope": frozenset({"continue", "rollback", "continue_or_rollback"})},
        reserved=True,
    ),
    EntryKind(
        "policy.recovery_grant_ended",
        1,
        {
            "intent_id": FieldType.UUID,
            "grant_id": FieldType.UUID,
            "reason": FieldType.ENUM,
            "trust_generation": FieldType.INT,
        },
        {"reason": frozenset({"trust_reset", "journal_closed"})},
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

_TERMINAL_JOB_STATES = frozenset({"succeeded", "failed", "cancelled", "dead_letter"})
_RETRY_PRIOR_STATES = frozenset({"leased", "running"})
_TERMINAL_PRIOR_STATES = frozenset({"queued", "leased", "running"})
_JOB_ERROR_CODES = frozenset(
    {"handler_failed", "handler_unavailable", "invalid_payload", "deadline_exceeded", "lease_lost"}
)
_LEASE_FIELDS: dict[str, FieldType] = {
    "job_id": FieldType.UUID,
    "attempt": FieldType.INT,
    "writer_epoch": FieldType.INT,
    "lease_id": FieldType.UUID,
}

KERNEL_JOB_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "job.queued",
        1,
        {
            "job_id": FieldType.UUID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "kind": FieldType.OPAQUE_ID,
            "payload_digest": FieldType.DIGEST,
            "attempt": FieldType.INT,
            "retry_at": FieldType.TIMESTAMP,
        },
        {},
        nullable=frozenset({"repo_id", "checkout_id"}),
    ),
    EntryKind("job.leased", 1, dict(_LEASE_FIELDS), {}),
    EntryKind("job.running", 1, dict(_LEASE_FIELDS), {}),
    EntryKind(
        "job.retry",
        1,
        {**_LEASE_FIELDS, "prior_state": FieldType.ENUM, "retry_at": FieldType.TIMESTAMP, "reason": FieldType.ENUM},
        {"prior_state": _RETRY_PRIOR_STATES, "reason": _JOB_ERROR_CODES},
    ),
    EntryKind(
        "job.terminal",
        1,
        {
            **_LEASE_FIELDS,
            "state": FieldType.ENUM,
            "prior_state": FieldType.ENUM,
            "reason": FieldType.ENUM,
            "result_digest": FieldType.DIGEST,
            "finished_at": FieldType.TIMESTAMP,
        },
        {"state": _TERMINAL_JOB_STATES, "prior_state": _TERMINAL_PRIOR_STATES, "reason": _JOB_ERROR_CODES},
        nullable=frozenset({"writer_epoch", "lease_id", "reason", "result_digest"}),
    ),
    EntryKind("job.retention_expired", 1, {"job_id": FieldType.UUID, "expired_at": FieldType.TIMESTAMP}, {}),
    EntryKind(
        "provider.reserved",
        1,
        {"invocation_id": FieldType.UUID, **_LEASE_FIELDS, "reservation_digest": FieldType.DIGEST},
        {},
    ),
    EntryKind(
        "provider.settled",
        2,
        {
            "invocation_id": FieldType.UUID,
            "prior_state": FieldType.ENUM,
            "prior_usage_digest": FieldType.DIGEST,
            "usage_digest": FieldType.DIGEST,
            "complete": FieldType.BOOL,
        },
        {"prior_state": frozenset({"reserved", "outcome_unknown"})},
        nullable=frozenset({"prior_usage_digest"}),
    ),
    EntryKind(
        "provider.unknown",
        1,
        {"invocation_id": FieldType.UUID, "writer_epoch": FieldType.INT, "recovery_epoch": FieldType.INT},
        {},
    ),
)
"""Task 5 Job/ProviderInvocation kinds (no DDL): reducers in ``storage.jobs`` build ``p_jobs_*`` and
``p_provider_invocations_*``. States, prior states and reasons are enums; decimal quantities live only in CAS."""


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


POLICY_V4_TABLES: frozenset[str] = frozenset(
    {
        "signer",
        "approval_nonce",
        "approval_receipt_meta",
        "harness_layer2_state",
        "recovery_grant",
        "apply_turn_intent",
        "accounting_invocations",
        "accounting_locks",
    }
)
_REPO_FLAG_COLUMNS: tuple[str, ...] = (
    "automatic_capture_enabled",
    "manual_submission_enabled",
    "indexing_enabled",
    "post_session_review_enabled",
)


def _store_v5(db: sqlite3.Connection) -> None:
    """Main store v5 capability fence (``schema_version=5, min_reader_version=5``): reserved ``policy.*``
    and ``proposal.*`` ledger kinds plus ``ProposalProjectionHandler`` tables (``p_proposals_*``).
    """
    _ = db


def _store_v6(db: sqlite3.Connection) -> None:
    """Main store v6 capture continuity tables (``schema_version=6, min_reader_version=6``)."""
    from superbrain.storage._capture_schema import apply_capture_store_v6

    apply_capture_store_v6(db)


POLICY_V5_TABLES: frozenset[str] = frozenset({"session_hmac_key", "session_ref_bindings"})


def _policy_v5(db: sqlite3.Connection) -> None:
    from superbrain.storage._policy_sessions import apply_policy_v5

    apply_policy_v5(db)


def _store_v8(db: sqlite3.Connection) -> None:
    from superbrain.storage._handoff_schema import apply_handoff_store_v8

    apply_handoff_store_v8(db)


POLICY_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_policy_v2)
POLICY_V3_MIGRATION = Migration(to_version=3, min_reader_version=3, apply=_policy_v3)
POLICY_V4_MIGRATION = Migration(to_version=4, min_reader_version=4, apply=_policy_v4)
POLICY_V5_MIGRATION = Migration(to_version=5, min_reader_version=5, apply=_policy_v5)
STORE_V2_MIGRATION = Migration(to_version=2, min_reader_version=2, apply=_store_v2)
STORE_V3_MIGRATION = Migration(to_version=3, min_reader_version=3, apply=_store_v3)
STORE_V4_MIGRATION = Migration(to_version=4, min_reader_version=4, apply=_store_v4)
STORE_V5_MIGRATION = Migration(to_version=5, min_reader_version=5, apply=_store_v5)
STORE_V6_MIGRATION = Migration(to_version=6, min_reader_version=6, apply=_store_v6)
# Store v7: session and continuity tables over every known store v6 shape (_continuity_schema).
STORE_V7_MIGRATION = Migration(to_version=7, min_reader_version=7, apply=apply_continuity_store_v7)
# Store v8: SP2-4 handoff revision headers, C5 extended columns, deliveries & episodes (_handoff_schema).
STORE_V8_MIGRATION = Migration(to_version=8, min_reader_version=8, apply=_store_v8)

KERNEL_POLICY_MIGRATIONS: tuple[Migration, ...] = (
    *POLICY_MIGRATIONS,
    POLICY_V2_MIGRATION,
    POLICY_V3_MIGRATION,
    POLICY_V4_MIGRATION,
    POLICY_V5_MIGRATION,
)
KERNEL_STORE_MIGRATIONS: tuple[Migration, ...] = (
    *STORE_MIGRATIONS,
    STORE_V2_MIGRATION,
    STORE_V3_MIGRATION,
    STORE_V4_MIGRATION,
    STORE_V5_MIGRATION,
    STORE_V6_MIGRATION,
    STORE_V7_MIGRATION,
    STORE_V8_MIGRATION,
)
