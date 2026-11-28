"""Ledger projections for the workspace registry mirror, snapshots and lineage; ``workspaces`` re-exports them."""

from __future__ import annotations

import sqlite3

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    MirrorCandidate,
)
from superbrain.ports.policy import PolicyView
from superbrain.storage.ledger import LedgerEntry


class WorkspaceRegistryMirrorProjection:
    """``p_workspace_registry_*``: non-authoritative audit/candidate mirror of ``policy.workspace_register``.

    Accepts legacy v1 entries (no ``subject_id``) and v2 entries (``subject_id`` null or a digest).
    """

    name = "workspace_registry"
    handler_version = 2
    kinds = frozenset({"policy.workspace_register"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}checkouts (checkout_id TEXT PRIMARY KEY, repo_id TEXT NOT NULL,"
            " principal_id TEXT NOT NULL, machine_id TEXT NOT NULL, alias TEXT NOT NULL, locator_digest TEXT,"
            " subject_id TEXT, intent_id TEXT NOT NULL, handler_version INTEGER NOT NULL, sequence INTEGER NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}locators (locator_digest TEXT PRIMARY KEY, repo_id TEXT NOT NULL,"
            " sequence INTEGER NOT NULL)"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        keys = frozenset(entry.meta)
        if entry.handler_version == 1:
            # Real v1 history has both shapes: no ``subject_id`` (6a67b38) and a ``subject_id`` digest (007b40f).
            # ``MirrorCandidate`` below type-checks the digest; history is read as written, never rejected or rewritten.
            if keys not in (_m._REGISTER_V1_KEYS, _m._REGISTER_V2_KEYS):
                raise _m._corrupt(entry, "malformed legacy workspace_register meta")
        elif entry.handler_version == 2:
            if keys != _m._REGISTER_V2_KEYS:
                raise _m._corrupt(entry, "malformed workspace_register meta")
        else:
            raise _m._corrupt(entry, "unsupported workspace_register handler version")
        try:
            candidate = MirrorCandidate(
                checkout_id=_m._req(entry, "checkout_id"),
                repo_id=_m._req(entry, "repo_id"),
                principal_id=_m._req(entry, "principal_id"),
                machine_id=_m._req(entry, "machine_id"),
                alias=_m._req(entry, "alias"),
                locator_digest=_m._text(entry, "locator_digest", nullable=True),
                subject_id=_m._text(entry, "subject_id", nullable=True),
                intent_id=_m._req(entry, "intent_id"),
                handler_version=entry.handler_version,
            )
        except BrainError as err:
            if err.code is ErrorCode.INTEGRITY_FAILURE:
                raise
            raise _m._corrupt(entry, "invalid workspace_register field") from None
        db.execute(
            f"INSERT INTO {prefix}checkouts (checkout_id, repo_id, principal_id, machine_id, alias, locator_digest,"
            " subject_id, intent_id, handler_version, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (checkout_id) DO UPDATE SET repo_id = excluded.repo_id,"
            " principal_id = excluded.principal_id, machine_id = excluded.machine_id, alias = excluded.alias,"
            " locator_digest = excluded.locator_digest, subject_id = excluded.subject_id,"
            " intent_id = excluded.intent_id, handler_version = excluded.handler_version,"
            " sequence = excluded.sequence",
            (
                candidate.checkout_id,
                candidate.repo_id,
                candidate.principal_id,
                candidate.machine_id,
                candidate.alias,
                candidate.locator_digest,
                candidate.subject_id,
                candidate.intent_id,
                candidate.handler_version,
                entry.sequence,
            ),
        )
        if candidate.locator_digest is not None:
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}locators (locator_digest, repo_id, sequence) VALUES (?, ?, ?)",
                (candidate.locator_digest, candidate.repo_id, entry.sequence),
            )


class SnapshotProjection:
    """``p_source_snapshots_*`` from ``snapshot.observed``; rows survive quarantine/tombstone of the descriptor."""

    name = "source_snapshots"
    handler_version = 1
    kinds = frozenset({"snapshot.observed"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}snapshots (snapshot_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,"
            " repo_id TEXT NOT NULL, checkout_id TEXT NOT NULL, kind TEXT NOT NULL, dirty INTEGER NOT NULL,"
            " descriptor_digest TEXT NOT NULL, observed_at TEXT NOT NULL, sequence INTEGER NOT NULL)"
        )
        db.execute(f"CREATE INDEX {prefix}by_descriptor ON {prefix}snapshots (checkout_id, descriptor_digest)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        dirty = entry.meta.get("dirty")
        if type(dirty) is not bool:
            raise _m._corrupt(entry, "dirty is not a boolean")
        db.execute(
            f"INSERT INTO {prefix}snapshots (snapshot_id, owner_id, repo_id, checkout_id, kind, dirty,"
            " descriptor_digest, observed_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _m._req(entry, "snapshot_id"),
                _m._req(entry, "owner_id"),
                _m._req(entry, "repo_id"),
                _m._req(entry, "checkout_id"),
                _m._req(entry, "kind"),
                1 if dirty else 0,
                _m._req(entry, "descriptor_digest"),
                _m._req(entry, "observed_at"),
                entry.sequence,
            ),
        )


class TaskLineageProjection:
    """``p_task_lineage_*``: first committed task binding plus a monotonic union of sources and unknown flag."""

    name = "task_lineage"
    handler_version = 1
    kinds = frozenset({"lineage.task_bound", "lineage.task_source_added", "lineage.task_unknown_marked"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}bindings (task_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,"
            " repo_id TEXT NOT NULL, checkout_id TEXT NOT NULL, delivery_id TEXT NOT NULL, assignment_id TEXT,"
            " source_snapshot_id TEXT, snapshot_status TEXT NOT NULL, selector_path TEXT NOT NULL,"
            " selector_reason TEXT NOT NULL, sequence INTEGER NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}sources (task_id TEXT NOT NULL, owner_id TEXT NOT NULL, repo_id TEXT NOT NULL,"
            " source_kind TEXT NOT NULL, source_id TEXT NOT NULL, source_revision INTEGER NOT NULL,"
            " source_digest TEXT NOT NULL, sequence INTEGER NOT NULL,"
            f" PRIMARY KEY (task_id, {_m._SOURCE_COLUMNS}))"
        )
        db.execute(f"CREATE TABLE {prefix}unknown (task_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        task_id = _m._req(entry, "task_id")
        if entry.kind == "lineage.task_unknown_marked":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}unknown (task_id, sequence) VALUES (?, ?)", (task_id, entry.sequence)
            )
        elif entry.kind == "lineage.task_source_added":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}sources (task_id, {_m._SOURCE_COLUMNS}, sequence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (task_id, *_m._source_values(entry), entry.sequence),
            )
        else:
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}bindings (task_id, owner_id, repo_id, checkout_id, delivery_id,"
                " assignment_id, source_snapshot_id, snapshot_status, selector_path, selector_reason, sequence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id,
                    _m._req(entry, "owner_id"),
                    _m._req(entry, "repo_id"),
                    _m._req(entry, "checkout_id"),
                    _m._req(entry, "delivery_id"),
                    _m._text(entry, "assignment_id", nullable=True),
                    _m._text(entry, "source_snapshot_id", nullable=True),
                    _m._req(entry, "snapshot_status"),
                    _m._req(entry, "selector_path"),
                    _m._req(entry, "selector_reason"),
                    entry.sequence,
                ),
            )


class FieldLineageProjection:
    """``p_field_lineage_*`` keyed by ``field_path_digest``; ``unknown`` is sticky once marked."""

    name = "field_lineage"
    handler_version = 1
    kinds = frozenset({"lineage.field_source_added", "lineage.field_unknown_marked"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}sources (task_id TEXT NOT NULL, field_path_digest TEXT NOT NULL,"
            " owner_id TEXT NOT NULL, repo_id TEXT NOT NULL, source_kind TEXT NOT NULL, source_id TEXT NOT NULL,"
            " source_revision INTEGER NOT NULL, source_digest TEXT NOT NULL, sequence INTEGER NOT NULL,"
            f" PRIMARY KEY (task_id, field_path_digest, {_m._SOURCE_COLUMNS}))"
        )
        db.execute(
            f"CREATE TABLE {prefix}unknown (task_id TEXT NOT NULL, field_path_digest TEXT NOT NULL,"
            " sequence INTEGER NOT NULL, PRIMARY KEY (task_id, field_path_digest))"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        task_id, path_digest = _m._req(entry, "task_id"), _m._req(entry, "field_path_digest")
        if entry.kind == "lineage.field_unknown_marked":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}unknown (task_id, field_path_digest, sequence) VALUES (?, ?, ?)",
                (task_id, path_digest, entry.sequence),
            )
            return
        db.execute(
            f"INSERT OR IGNORE INTO {prefix}sources (task_id, field_path_digest, {_m._SOURCE_COLUMNS}, sequence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task_id, path_digest, *_m._source_values(entry), entry.sequence),
        )

# Imported last: the original module re-exports the names above, so it may import this module first.
from superbrain.storage import workspaces as _m  # noqa: E402
