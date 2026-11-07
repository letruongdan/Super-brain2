"""The main store (spec 5.4, 5.8): one long-lived connection under the writer lease, owned by one thread.

Every public method, and the ``Txn`` from ``transaction()``, checks that the store is open, that its writer lease is
still held and that it runs on the owner thread (the thread that called ``create``/``open``)."""

import os
import sqlite3
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime
from pathlib import Path

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicySource, PolicyView
from superbrain.storage import backup
from superbrain.storage.cas import (
    ContentStore,
    RetentionClass,
    held_digests,
    remove_staging_leftovers,
)
from superbrain.storage.errors import sqlite_error
from superbrain.storage.handlers import check_handlers, check_history, with_defaults
from superbrain.storage.identity import classify_reconcile_intent
from superbrain.storage.kernel_schema import KERNEL_POLICY_KINDS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import (
    LedgerEntry,
    ProjectionHandler,
    Txn,
    apply_to_handlers,
    cas_hold_meta,
    iter_entries,
    live_prefix,
    read_entries,
    rebuild_prefix,
)
from superbrain.storage.schema import (
    STORE_MIGRATIONS,
    Migration,
    code_version,
    ensure_writable,
    initialize,
    read_schema_info,
    readmit_writable,
)
from superbrain.storage.sqlite import CREATING, connect, db_files, remove_unfinished_creates
from superbrain.storage.writer import WriterLease

_HANDLE = "store"
_POLICY_ACTOR = "system:policy"
_REPLAY_BATCH = 256


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("the store needs a held writer lease for this data root")


def _objects(db: sqlite3.Connection) -> set[tuple[str, str]]:
    return {(str(t), str(n)) for t, n in db.execute("SELECT type, name FROM sqlite_master").fetchall()}


def _tables_with_prefix(db: sqlite3.Connection, prefix: str) -> list[str]:
    return sorted(name for kind, name in _objects(db) if kind == "table" and name.startswith(prefix))


def _create_tables(db: sqlite3.Connection, handler: ProjectionHandler, prefix: str) -> None:
    """Let ``handler`` create its tables, then check that it created only tables and indexes under ``prefix``."""
    before = _objects(db)
    try:
        handler.create_tables(db, prefix)
    except sqlite3.Error as exc:
        raise sqlite_error(f"projection {handler.name} could not create its tables", exc) from exc
    stray = sorted(
        name
        for kind, name in _objects(db) - before
        if kind not in ("table", "index") or not name.startswith((prefix, f"sqlite_autoindex_{prefix}"))
    )
    if stray:
        raise AssertionError(f"projection {handler.name} created objects outside {prefix!r}: {stray}")


def _swap_in_rebuilt(db: sqlite3.Connection, handler: ProjectionHandler) -> None:
    """Replace the live tables of ``handler`` with its rebuilt ones, renaming explicit indexes to match."""
    live, rebuilt = live_prefix(handler), rebuild_prefix(handler)
    for table in _tables_with_prefix(db, live):
        db.execute(f"DROP TABLE {_quote(table)}")
    for table in _tables_with_prefix(db, rebuilt):
        db.execute(f"ALTER TABLE {_quote(table)} RENAME TO {_quote(live + table[len(rebuilt) :])}")
    # RENAME keeps index names (SQLite renames only its own autoindexes), so recreate explicit ones under ``live``.
    indexes = db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL AND substr(name, 1, ?) = ?",
        (len(rebuilt), rebuilt),
    ).fetchall()
    for name, sql in indexes:
        renamed = live + name[len(rebuilt) :]
        new_sql = str(sql).replace(name, renamed, 1)
        if new_sql == sql:
            raise AssertionError(f"cannot rename index {name!r} of projection {handler.name}")
        db.execute(f"DROP INDEX {_quote(name)}")
        db.execute(new_sql)


def _create_live_tables(db: sqlite3.Connection, handlers: Sequence[ProjectionHandler]) -> None:
    """Create every handler's live tables in a new, still empty database, in one transaction."""
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            for handler in handlers:
                _create_tables(db, handler, live_prefix(handler))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
    except sqlite3.Error as exc:
        raise sqlite_error("cannot create projection tables", exc) from exc


def _replay(
    db: sqlite3.Connection,
    handlers: Sequence[ProjectionHandler],
    policy: PolicyView,
    prefix: Callable[[ProjectionHandler], str],
) -> int:
    """Apply every ledger entry, in sequence order, to ``handlers`` under ``prefix``; returns the entry count.

    An entry written by a newer version of a handler than the one given is ``UNSUPPORTED_VERSION``.
    """
    count = after = 0
    while page := read_entries(db, after, _REPLAY_BATCH):
        for entry in page:
            for handler in handlers:
                if entry.kind in handler.kinds and entry.handler_version > handler.handler_version:
                    raise BrainError(
                        ErrorCode.UNSUPPORTED_VERSION,
                        f"entry {entry.sequence} ({entry.kind}) needs handler version {entry.handler_version}, "
                        f"projection {handler.name} is version {handler.handler_version}",
                    )
            apply_to_handlers(db, handlers, entry, policy, prefix)
        count += len(page)
        after = page[-1].sequence
    return count


class Store:
    def __init__(
        self,
        *,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        policy: PolicySource,
        handlers: Sequence[ProjectionHandler],
        kinds: KindRegistry,
        db: sqlite3.Connection,
        schema_version: int,
        store_id: str,
    ) -> None:
        self._owner = threading.get_ident()
        self._root = root
        self._lease = lease
        self._os = os_
        self._policy = policy
        self._handlers = tuple(handlers)
        self._kinds = kinds
        self._db = db
        self._schema_version = schema_version
        self._store_id = store_id
        self._closed = False
        self._txn_active = False
        self._maintenance = False
        self._history_versions: dict[str, int] = {}
        self._cas = ContentStore(
            root=root,
            os_=os_,
            policy=policy,
            db=db,
            check=self._check,
            maintenance=self.maintenance,
            transaction=self.transaction,
        )

    # --- lifecycle ---------------------------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        policy: PolicySource,
        handlers: Sequence[ProjectionHandler],
        kinds: KindRegistry,
        *,
        migrations: Sequence[Migration] = STORE_MIGRATIONS,
    ) -> "Store":
        """Create a new store database with ``store_id = policy.store_id``, then open it.

        The database, with every handler's live tables, is built at ``brain.db.creating-<id>``, closed (so its WAL
        is checkpointed away) and only then published as ``brain.db``: a failure before the publish never leaves a
        ``brain.db`` behind, and one after it (while opening) leaves a complete, valid empty store that ``open``
        accepts. Leftover ``brain.db.creating-*`` files are never live data and are removed first.

        ``HolderProjection`` and ``CORE_KINDS`` are always registered, in addition to ``handlers`` and ``kinds``.
        """
        _check_lease(root, lease)
        extra = KERNEL_POLICY_KINDS if code_version(migrations) >= 2 else ()
        handlers, kinds = with_defaults(handlers, kinds, extra_kinds=extra)
        check_handlers(handlers, kinds)
        path = root.store_db
        if any(os.path.lexists(p) for p in db_files(path)):
            raise BrainError(ErrorCode.INVALID_INPUT, f"a store database already exists at {path}")
        lease.register_handle(_HANDLE)
        try:
            remove_unfinished_creates(path)
            staging = path.with_name(f"{path.name}{CREATING}{new_id()}")
            db = connect(staging, traits=os_.traits)
            try:
                initialize(db, migrations, store_id=policy.store_id)
                _create_live_tables(db, handlers)
            finally:
                db.close()
            if any(os.path.lexists(p) for p in db_files(staging)[1:]):
                raise BrainError(ErrorCode.IO_ERROR, f"{staging}: the WAL was not checkpointed away on close")
            os_.permissions.secure_file(staging)
            os_.publisher.publish(staging, path)
            return cls._open_registered(root, lease, os_, policy, handlers, kinds, migrations)
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise

    @classmethod
    def open(
        cls,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        policy: PolicySource,
        handlers: Sequence[ProjectionHandler],
        kinds: KindRegistry,
        *,
        migrations: Sequence[Migration] = STORE_MIGRATIONS,
    ) -> "Store":
        """Open the existing store for writing; its schema must equal the code's and its id ``policy.store_id``.

        Like ``create``, it always registers ``HolderProjection`` and ``CORE_KINDS``. Leftover staging files of
        unfinished ``put``s are removed. Both end with ``reconcile_policy``, so every pending intent is applied.
        """
        _check_lease(root, lease)
        extra = KERNEL_POLICY_KINDS if code_version(migrations) >= 2 else ()
        handlers, kinds = with_defaults(handlers, kinds, extra_kinds=extra)
        check_handlers(handlers, kinds)
        lease.register_handle(_HANDLE)
        try:
            return cls._open_registered(root, lease, os_, policy, handlers, kinds, migrations)
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise

    @classmethod
    def _open_registered(
        cls,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        policy: PolicySource,
        handlers: Sequence[ProjectionHandler],
        kinds: KindRegistry,
        migrations: Sequence[Migration],
    ) -> "Store":
        """``open`` once the ``store`` handle is registered; the caller unregisters it on failure."""
        path = root.store_db
        info = read_schema_info(path)
        if info is None:
            raise BrainError(ErrorCode.NOT_FOUND, f"no store database at {path}")
        ensure_writable(info, migrations)
        if info.store_id != policy.store_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the store belongs to a different policy store")
        db = connect(path, traits=os_.traits)
        try:
            readmit_writable(db, path, info, migrations)
            store = cls(
                root=root,
                lease=lease,
                os_=os_,
                policy=policy,
                handlers=handlers,
                kinds=kinds,
                db=db,
                schema_version=info.schema_version,
                store_id=info.store_id,
            )
            store._prepare()
            store.reconcile_policy()
        except BaseException:
            db.close()
            raise
        return store

    def _prepare(self) -> None:
        """Give every handler without live tables new ones, filled from the whole ledger in the same transaction
        (a handler registered after entries of its kinds were written must not start empty), then secure the
        database files and remove staging leftovers. Handlers whose live tables exist are not replayed."""
        self._history_versions = check_history(self._db, self._handlers)
        with self._immediate() as db:
            try:
                fresh = [h for h in self._handlers if not _tables_with_prefix(db, live_prefix(h))]
                for handler in fresh:
                    _create_tables(db, handler, live_prefix(handler))
                if fresh:
                    _replay(db, fresh, self._policy, live_prefix)
            except sqlite3.Error as exc:
                raise sqlite_error("cannot create projection tables", exc) from exc
        for path in db_files(self._root.store_db):
            if path.exists():
                self._os.permissions.secure_file(path)
        remove_staging_leftovers(self._root.staging_dir)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def lease(self) -> WriterLease:
        return self._lease

    @property
    def owner_thread_id(self) -> int:
        return self._owner

    def has_policy_source(self, policy: object) -> bool:
        return self._policy is policy

    def close(self) -> None:
        self._check()
        if self._txn_active:
            raise AssertionError("cannot close the store inside a transaction")
        self._closed = True
        try:
            self._db.close()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot close the store", exc) from exc
        finally:
            self._lease.unregister_handle(_HANDLE)

    @property
    def store_id(self) -> str:
        self._check()
        return self._store_id

    @property
    def schema_version(self) -> int:
        self._check()
        return self._schema_version

    @property
    def in_transaction(self) -> bool:
        self._check()
        return self._txn_active or self._db.in_transaction

    @property
    def root(self) -> DataRoot:
        self._check()
        return self._root

    # --- writing and reading -----------------------------------------------------------------------------------

    def transaction(self) -> AbstractContextManager[Txn]:
        """One write transaction: every append and projection update in it commits together or not at all."""
        self._check()
        self._require_no_transaction()
        return self._transaction()

    @contextmanager
    def _transaction(self) -> Iterator[Txn]:
        self._check()
        self._require_no_transaction()
        self._txn_active = True
        try:
            with self._immediate(crashpoints=True) as db:
                txn = Txn(
                    db,
                    kinds=self._kinds,
                    handlers=self._handlers,
                    policy=self._policy,
                    writer_epoch=self._lease.epoch,
                    schema_version=self._schema_version,
                    clock=self._os.clock,
                    check_owner=self._check,
                    blob_intact=self._cas.blob_intact,
                    history_versions=self._history_versions,
                )
                try:
                    yield txn
                finally:
                    txn._end()
        finally:
            self._txn_active = False

    @property
    def cas(self) -> ContentStore:
        """The store's blobs."""
        self._check()
        return self._cas

    def store_content(
        self,
        data: bytes,
        holder_kind: str,
        holder_id: str,
        retention: RetentionClass,
        expires_at: datetime | None,
    ) -> str:
        """``put`` ``data``, then ``hold`` it in a transaction of its own; returns the digest.

        The holder fields are validated first, so invalid ones store nothing (no orphan blob).
        A ``NOT_FOUND`` from ``hold`` means the blob vanished between the two (GC removed it as an orphan): the
        ``put`` and ``hold`` are retried exactly once, and a second failure propagates.
        """
        self._check()
        self._require_no_transaction()
        meta = cas_hold_meta(digest_bytes(data), holder_kind, holder_id, retention, expires_at)
        self._kinds.validate("cas.hold", meta)
        digest = self._cas.put(data)
        try:
            self._hold(digest, holder_kind, holder_id, retention, expires_at)
        except BrainError as err:
            if err.code is not ErrorCode.NOT_FOUND:
                raise
            digest = self._cas.put(data)
            self._hold(digest, holder_kind, holder_id, retention, expires_at)
        return digest

    def _hold(
        self, digest: str, holder_kind: str, holder_id: str, retention: RetentionClass, expires_at: datetime | None
    ) -> None:
        with self.transaction() as txn:
            txn.hold(digest, holder_kind, holder_id, retention, expires_at)

    def entries(self, after: int = 0) -> Iterator[LedgerEntry]:
        """Every ledger entry with ``sequence > after``, in sequence order."""
        self._check()
        if type(after) is not int or after < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "after must be a non-negative integer")
        return iter_entries(self._db, after, self._check)

    def rebuild_projections(self) -> int:
        """Rebuild every projection from the ledger into ``r_`` tables, then swap them in; returns the entry count.

        It all runs in one write transaction, so a failure (such as an entry written by a newer handler, which is
        ``UNSUPPORTED_VERSION``) leaves the live tables untouched and no ``r_`` table behind.
        """
        self._check()
        self._require_no_transaction()
        with self._immediate() as db:
            try:
                for handler in self._handlers:
                    for table in _tables_with_prefix(db, rebuild_prefix(handler)):
                        db.execute(f"DROP TABLE {_quote(table)}")
                    _create_tables(db, handler, rebuild_prefix(handler))
                count = _replay(db, self._handlers, self._policy, rebuild_prefix)
                for handler in self._handlers:
                    _swap_in_rebuilt(db, handler)
            except sqlite3.Error as exc:
                raise sqlite_error("cannot rebuild projections", exc) from exc
        return count

    def snapshot_db(self, dest: Path) -> None:
        """Copy the live database, as of now, into the new self-contained file ``dest`` (``backup._snapshot_db``)."""
        self._check()
        self._require_no_transaction()
        backup._snapshot_db(self._db, dest, self._os)

    def db_integrity(self) -> str:
        """SQLite's ``integrity_check`` result: ``"ok"`` for a sound database."""
        self._check()
        try:
            rows = self._db.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot check database integrity", exc) from exc
        return "\n".join(str(row[0]) for row in rows)

    def reconcile_policy(self) -> int:
        """Apply every policy intent not yet in ``applied_intents``, in recorded order; returns how many it applied.

        Each intent gets one transaction: it is marked applied, then its effect is appended (a ``policy.tombstone``
        plus a ``cas.release`` with reason ``tombstoned`` for every blob the holder still holds, or a
        ``policy.quarantine``). The mark and the effect commit together, so a crash applies an intent fully or not at
        all, and it is applied exactly once. Nothing is ever written to the policy store.
        """
        self._check()
        self._require_no_transaction()
        try:
            done = {str(row[0]) for row in self._db.execute("SELECT intent_id FROM applied_intents").fetchall()}
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the applied intents", exc) from exc
        applied = 0
        for intent in self._policy.intents():
            if intent.intent_id in done:
                continue
            with self.transaction() as txn:
                if not txn.mark_intent_applied(intent.intent_id):
                    continue
                effect_kind, meta, tombstone_holder = classify_reconcile_intent(intent)
                txn._append_reserved(effect_kind, actor=_POLICY_ACTOR, owner_id=None, meta=meta)
                if tombstone_holder is not None:
                    holder_kind, holder_id = tombstone_holder
                    for digest in held_digests(txn.db, holder_kind, holder_id):
                        txn.release(digest, holder_kind, holder_id, reason="tombstoned")
            applied += 1
            crashpoint("intents.after_store_apply")
        return applied

    # --- maintenance -------------------------------------------------------------------------------------------

    def maintenance(self) -> AbstractContextManager[None]:
        """A flag that cannot nest: entering it while it is set is ``STORE_BUSY``."""
        self._check()
        self._require_no_maintenance()
        return self._maintenance_scope()

    @contextmanager
    def _maintenance_scope(self) -> Iterator[None]:
        self._check()
        self._require_no_maintenance()
        self._maintenance = True
        try:
            yield
        finally:
            self._maintenance = False

    def _require_no_maintenance(self) -> None:
        if self._maintenance:
            raise BrainError(ErrorCode.STORE_BUSY, "store maintenance is already running")

    # --- internals ---------------------------------------------------------------------------------------------

    def _check(self) -> None:
        if self._closed:
            raise AssertionError("store closed")
        if not self._lease.held:
            raise AssertionError("store used after its writer lease was released")
        if threading.get_ident() != self._owner:
            raise AssertionError("store used off its owner thread")

    def _require_no_transaction(self) -> None:
        if self._txn_active:
            raise AssertionError("a store transaction is already active")

    @contextmanager
    def _immediate(self, *, crashpoints: bool = False) -> Iterator[sqlite3.Connection]:
        """``BEGIN IMMEDIATE`` ... ``COMMIT``; any exception rolls back and propagates unchanged."""
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise sqlite_error("cannot begin a store transaction", exc, busy=True) from exc
        try:
            yield self._db
            if crashpoints:
                crashpoint("ledger.before_commit")
            try:
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                raise sqlite_error("cannot commit the store transaction", exc) from exc
        except BaseException:
            if self._db.in_transaction:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise sqlite_error("cannot roll back the store transaction", exc) from exc
            raise
        if crashpoints:
            crashpoint("ledger.after_commit")
