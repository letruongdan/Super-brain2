"""Event-sourced workspace projections (registry mirror, source snapshots, task and field lineage) and the
``KernelTx``/``KernelStorePort`` adapters over ``Store.transaction()`` (Task 3).

Every table here is a reducer over typed ledger entries: ``Store.rebuild_projections()`` recreates it exactly from
the ledger, with no observer, filesystem, network or ID generation. Reducers ignore policy on purpose: a quarantined
or tombstoned source keeps its lineage restriction instead of disappearing from the record.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from functools import partial
from typing import TypeVar

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    FieldLineage,
    KernelRecord,
    LineageRef,
    LineageSet,
    MirrorCandidate,
    ObjectRef,
    SelectorPath,
    SelectorReason,
    SnapshotStatus,
    SourceSnapshot,
    TaskBinding,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.policy import PolicyView
from superbrain.storage.cas import ContentStore
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kernel_schema import KERNEL_WORKSPACE_KINDS
from superbrain.storage.kinds import KindRegistry, RetentionClass, is_uuid
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler, Txn
from superbrain.storage.store import Store

_T = TypeVar("_T")
_HOLDER_KIND = "event"
_REGISTER_V1_KEYS = frozenset(
    {"intent_id", "repo_id", "checkout_id", "principal_id", "machine_id", "alias", "locator_digest"}
)
_REGISTER_V2_KEYS = _REGISTER_V1_KEYS | {"subject_id"}
_SOURCE_COLUMNS = "owner_id, repo_id, source_kind, source_id, source_revision, source_digest"
_SOURCE_KEYS = ("owner_id", "repo_id", "source_kind", "source_id", "source_revision", "source_digest")

MIRROR_TABLE = "p_workspace_registry_checkouts"
SNAPSHOTS_TABLE = "p_source_snapshots_snapshots"
TASK_BINDINGS_TABLE = "p_task_lineage_bindings"
TASK_SOURCES_TABLE = "p_task_lineage_sources"
TASK_UNKNOWN_TABLE = "p_task_lineage_unknown"
FIELD_SOURCES_TABLE = "p_field_lineage_sources"
FIELD_UNKNOWN_TABLE = "p_field_lineage_unknown"


def _corrupt(entry: LedgerEntry | None, what: str) -> BrainError:
    where = f"ledger entry {entry.sequence}" if entry is not None else "projection row"
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"{where}: {what}")


def _text(entry: LedgerEntry, name: str, *, nullable: bool = False) -> str | None:
    value = entry.meta.get(name)
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value:
        raise _corrupt(entry, f"{name} is not text")
    return value


def _req(entry: LedgerEntry, name: str) -> str:
    value = _text(entry, name)
    assert value is not None
    return value


def _source_values(entry: LedgerEntry) -> tuple[object, ...]:
    revision = entry.meta.get("source_revision")
    if type(revision) is not int or revision < 1:
        raise _corrupt(entry, "source_revision is not a positive integer")
    return (*(_req(entry, key) for key in _SOURCE_KEYS[:4]), revision, _req(entry, "source_digest"))


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
            if keys not in (_REGISTER_V1_KEYS, _REGISTER_V2_KEYS) or entry.meta.get("subject_id") is not None:
                raise _corrupt(entry, "malformed legacy workspace_register meta")
        elif entry.handler_version == 2:
            if keys != _REGISTER_V2_KEYS:
                raise _corrupt(entry, "malformed workspace_register meta")
        else:
            raise _corrupt(entry, "unsupported workspace_register handler version")
        try:
            candidate = MirrorCandidate(
                checkout_id=_req(entry, "checkout_id"),
                repo_id=_req(entry, "repo_id"),
                principal_id=_req(entry, "principal_id"),
                machine_id=_req(entry, "machine_id"),
                alias=_req(entry, "alias"),
                locator_digest=_text(entry, "locator_digest", nullable=True),
                subject_id=_text(entry, "subject_id", nullable=True),
                intent_id=_req(entry, "intent_id"),
                handler_version=entry.handler_version,
            )
        except BrainError as err:
            if err.code is ErrorCode.INTEGRITY_FAILURE:
                raise
            raise _corrupt(entry, "invalid workspace_register field") from None
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
            raise _corrupt(entry, "dirty is not a boolean")
        db.execute(
            f"INSERT INTO {prefix}snapshots (snapshot_id, owner_id, repo_id, checkout_id, kind, dirty,"
            " descriptor_digest, observed_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _req(entry, "snapshot_id"),
                _req(entry, "owner_id"),
                _req(entry, "repo_id"),
                _req(entry, "checkout_id"),
                _req(entry, "kind"),
                1 if dirty else 0,
                _req(entry, "descriptor_digest"),
                _req(entry, "observed_at"),
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
            f" PRIMARY KEY (task_id, {_SOURCE_COLUMNS}))"
        )
        db.execute(f"CREATE TABLE {prefix}unknown (task_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        task_id = _req(entry, "task_id")
        if entry.kind == "lineage.task_unknown_marked":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}unknown (task_id, sequence) VALUES (?, ?)", (task_id, entry.sequence)
            )
        elif entry.kind == "lineage.task_source_added":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}sources (task_id, {_SOURCE_COLUMNS}, sequence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (task_id, *_source_values(entry), entry.sequence),
            )
        else:
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}bindings (task_id, owner_id, repo_id, checkout_id, delivery_id,"
                " assignment_id, source_snapshot_id, snapshot_status, selector_path, selector_reason, sequence)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id,
                    _req(entry, "owner_id"),
                    _req(entry, "repo_id"),
                    _req(entry, "checkout_id"),
                    _req(entry, "delivery_id"),
                    _text(entry, "assignment_id", nullable=True),
                    _text(entry, "source_snapshot_id", nullable=True),
                    _req(entry, "snapshot_status"),
                    _req(entry, "selector_path"),
                    _req(entry, "selector_reason"),
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
            f" PRIMARY KEY (task_id, field_path_digest, {_SOURCE_COLUMNS}))"
        )
        db.execute(
            f"CREATE TABLE {prefix}unknown (task_id TEXT NOT NULL, field_path_digest TEXT NOT NULL,"
            " sequence INTEGER NOT NULL, PRIMARY KEY (task_id, field_path_digest))"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        task_id, path_digest = _req(entry, "task_id"), _req(entry, "field_path_digest")
        if entry.kind == "lineage.field_unknown_marked":
            db.execute(
                f"INSERT OR IGNORE INTO {prefix}unknown (task_id, field_path_digest, sequence) VALUES (?, ?, ?)",
                (task_id, path_digest, entry.sequence),
            )
            return
        db.execute(
            f"INSERT OR IGNORE INTO {prefix}sources (task_id, field_path_digest, {_SOURCE_COLUMNS}, sequence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task_id, path_digest, *_source_values(entry), entry.sequence),
        )


def kernel_workspace_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """The Task 3 projection handlers and entry kinds a kernel store is opened with."""
    handlers: tuple[ProjectionHandler, ...] = (
        WorkspaceRegistryMirrorProjection(),
        SnapshotProjection(),
        TaskLineageProjection(),
        FieldLineageProjection(),
    )
    return handlers, KindRegistry(KERNEL_WORKSPACE_KINDS)


# --- row decoding -------------------------------------------------------------------------------------------------


def _decoded(build: Callable[[], _T]) -> _T:
    try:
        return build()
    except (BrainError, ValueError, TypeError) as err:
        raise _corrupt(None, "malformed workspace projection row") from err


def _lineage_ref(row: Sequence[object]) -> LineageRef:
    owner, repo, kind, ident, revision, digest = row
    return LineageRef(
        owner_id=str(owner),
        repo_id=str(repo),
        source=ObjectRef(kind=str(kind), id=str(ident), revision=revision, digest=str(digest)),  # type: ignore[arg-type]
    )


def _snapshot(row: Sequence[object]) -> SourceSnapshot:
    snapshot_id, owner, repo, checkout, kind, dirty, digest, observed_at = row
    if type(dirty) is not int or dirty not in (0, 1):
        raise ValueError("dirty")
    return SourceSnapshot(
        snapshot_id=str(snapshot_id),
        owner_id=str(owner),
        repo_id=str(repo),
        checkout_id=str(checkout),
        kind=str(kind),
        dirty=dirty == 1,
        descriptor_digest=str(digest),
        observed_at=str(observed_at),
    )


def _mirror_candidate(row: Sequence[object]) -> MirrorCandidate:
    checkout, repo, principal, machine, alias, locator, subject, intent, version = row
    if type(version) is not int:
        raise ValueError("handler_version")
    return MirrorCandidate(
        checkout_id=str(checkout),
        repo_id=str(repo),
        principal_id=str(principal),
        machine_id=str(machine),
        alias=str(alias),
        locator_digest=None if locator is None else str(locator),
        subject_id=None if subject is None else str(subject),
        intent_id=str(intent),
        handler_version=version,
    )


_SNAPSHOT_COLUMNS = "snapshot_id, owner_id, repo_id, checkout_id, kind, dirty, descriptor_digest, observed_at"


class StoreKernelTx:
    """``KernelTx`` over one ``Txn``: typed appends, publish-before-hold blobs and projection reads."""

    def __init__(self, txn: Txn, cas: ContentStore, policy: PolicyView) -> None:
        self._txn = txn
        self._cas = cas
        self._policy = policy

    def append_record(self, record: KernelRecord) -> None:
        if not isinstance(record, KernelRecord):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        meta: dict[str, JsonValue] = dict(record.meta)
        self._txn.append(record.kind, actor=record.actor, owner_id=None, meta=meta, refs=record.refs)

    def hold_blob(self, data: bytes, *, holder_id: str) -> str:
        if not is_uuid(holder_id):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        digest = self._cas.put(data)
        self._txn.hold(digest, _HOLDER_KIND, holder_id, RetentionClass.DURABLE, None)
        return digest

    def blob_restricted(self, digest: str) -> bool:
        return self._policy.is_quarantined(digest)

    def holder_tombstoned(self, holder_id: str) -> bool:
        return is_uuid(holder_id) and self._policy.is_tombstoned(_HOLDER_KIND, holder_id)

    def _query(self, sql: str, params: tuple[object, ...]) -> list[tuple[object, ...]]:
        try:
            return self._txn.db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the workspace projections", exc) from exc

    def find_source_snapshot(self, checkout_id: str, descriptor_digest: str) -> SourceSnapshot | None:
        rows = self._query(
            f"SELECT {_SNAPSHOT_COLUMNS} FROM {SNAPSHOTS_TABLE} WHERE checkout_id = ? AND descriptor_digest = ?"
            " ORDER BY sequence LIMIT 1",
            (checkout_id, descriptor_digest),
        )
        return _decoded(lambda: _snapshot(rows[0])) if rows else None

    def read_source_snapshot(self, snapshot_id: str) -> SourceSnapshot | None:
        rows = self._query(f"SELECT {_SNAPSHOT_COLUMNS} FROM {SNAPSHOTS_TABLE} WHERE snapshot_id = ?", (snapshot_id,))
        return _decoded(lambda: _snapshot(rows[0])) if rows else None

    def read_task_binding(self, task_id: str) -> TaskBinding | None:
        rows = self._query(
            "SELECT task_id, owner_id, repo_id, checkout_id, delivery_id, assignment_id, source_snapshot_id,"
            f" snapshot_status, selector_path, selector_reason FROM {TASK_BINDINGS_TABLE} WHERE task_id = ?",
            (task_id,),
        )
        if not rows:
            return None
        row = rows[0]

        def build() -> TaskBinding:
            return TaskBinding(
                task_id=str(row[0]),
                owner_id=str(row[1]),
                repo_id=str(row[2]),
                checkout_id=str(row[3]),
                delivery_id=str(row[4]),
                assignment_id=None if row[5] is None else str(row[5]),
                source_snapshot_id=None if row[6] is None else str(row[6]),
                snapshot_status=SnapshotStatus(str(row[7])),
                selector_path=SelectorPath(str(row[8])),
                selector_reason=SelectorReason(str(row[9])),
            )

        return _decoded(build)

    def read_task_lineage(self, task_id: str) -> tuple[LineageSet, bool]:
        rows = self._query(f"SELECT {_SOURCE_COLUMNS} FROM {TASK_SOURCES_TABLE} WHERE task_id = ?", (task_id,))
        sources = _decoded(lambda: frozenset(_lineage_ref(row) for row in rows))
        unknown = bool(self._query(f"SELECT 1 FROM {TASK_UNKNOWN_TABLE} WHERE task_id = ?", (task_id,)))
        return sources, unknown

    def read_field_lineage(self, task_id: str) -> Mapping[str, FieldLineage]:
        source_rows = self._query(
            f"SELECT field_path_digest, {_SOURCE_COLUMNS} FROM {FIELD_SOURCES_TABLE} WHERE task_id = ?", (task_id,)
        )
        unknown_rows = self._query(f"SELECT field_path_digest FROM {FIELD_UNKNOWN_TABLE} WHERE task_id = ?", (task_id,))
        grouped: dict[str, set[LineageRef]] = {}
        for row in source_rows:
            grouped.setdefault(str(row[0]), set()).add(_decoded(partial(_lineage_ref, row[1:])))
        unknown = {str(row[0]) for row in unknown_rows}
        result: dict[str, FieldLineage] = {}
        for digest in sorted(set(grouped) | unknown):
            sources = frozenset(grouped.get(digest, set()))
            result[digest] = _decoded(partial(FieldLineage, digest, sources, digest in unknown))
        return result


class KernelWorkspaceStore:
    """``KernelStorePort`` over an open ``Store``: one ``Store.transaction()`` per ``transact``."""

    def __init__(self, store: Store, policy: PolicyView) -> None:
        self._store = store
        self._policy = policy

    def transact(self, operation: Callable[[KernelTx], _T]) -> _T:
        with self._store.transaction() as txn:
            return operation(StoreKernelTx(txn, self._store.cas, self._policy))


@contextmanager
def _reading(store: Store) -> Iterator[sqlite3.Connection]:
    with store.transaction() as txn:
        yield txn.db


class StoreWorkspaceMirror:
    """``WorkspaceMirrorReadPort``: reads the non-authoritative registry mirror for audit/preview only."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def mirror_candidates(
        self, *, alias: str | None = None, checkout_id: str | None = None
    ) -> tuple[MirrorCandidate, ...]:
        clauses, params = [], []
        if alias is not None:
            clauses.append("alias = ?")
            params.append(alias)
        if checkout_id is not None:
            clauses.append("checkout_id = ?")
            params.append(checkout_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with _reading(self._store) as db:
            try:
                rows = db.execute(
                    "SELECT checkout_id, repo_id, principal_id, machine_id, alias, locator_digest, subject_id,"
                    f" intent_id, handler_version FROM {MIRROR_TABLE}{where} ORDER BY sequence, checkout_id",
                    params,
                ).fetchall()
            except sqlite3.Error as exc:
                raise sqlite_error("cannot read the workspace registry mirror", exc) from exc
        return tuple(_decoded(partial(_mirror_candidate, row)) for row in rows)


class StoreSourceRestrictions:
    """``SourceRestrictionPort``: a source is restricted when policy quarantines its digest or tombstones it, or
    when a referenced snapshot is unknown to the ledger or its descriptor is quarantined."""

    def __init__(self, store: Store, policy: PolicyView) -> None:
        self._store = store
        self._policy = policy

    def is_restricted(self, ref: LineageRef) -> bool:
        if not isinstance(ref, LineageRef):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        source = ref.source
        if self._policy.is_quarantined(source.digest):
            return True
        if is_uuid(source.id) and self._policy.is_tombstoned(_HOLDER_KIND, source.id):
            return True
        if source.kind != "source_snapshot":
            return False
        with _reading(self._store) as db:
            row = db.execute(
                f"SELECT descriptor_digest FROM {SNAPSHOTS_TABLE} WHERE snapshot_id = ?", (source.id,)
            ).fetchone()
        return row is None or self._policy.is_quarantined(str(row[0]))
