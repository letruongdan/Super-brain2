"""The main store (spec 5.4, 5.8): one long-lived connection under the writer lease, owned by one thread.

Every public method checks that the store is open and that it runs on the owner thread (the thread that called
``create``/``open``); the ``Txn`` from ``transaction()`` checks the same.
"""

import os
import re
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicySource
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import (
    LedgerEntry,
    ProjectionHandler,
    Txn,
    apply_to_handlers,
    io_error,
    iter_entries,
    live_prefix,
    read_entries,
    rebuild_prefix,
)
from superbrain.storage.schema import STORE_MIGRATIONS, Migration, ensure_writable, initialize, read_schema_info
from superbrain.storage.sqlite import connect
from superbrain.storage.writer import WriterLease

_HANDLE = "store"
_HANDLER_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_BUSY_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})
_REPLAY_BATCH = 256


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _db_files(path: Path) -> tuple[Path, ...]:
    return (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("the store needs a held writer lease for this data root")


def _check_handlers(handlers: Sequence[ProjectionHandler], kinds: KindRegistry) -> None:
    names = [handler.name for handler in handlers]
    for name in names:
        if not isinstance(name, str) or _HANDLER_NAME.fullmatch(name) is None:
            raise BrainError(ErrorCode.INVALID_INPUT, f"projection handler name {name!r} is not a valid identifier")
    if len(set(names)) != len(names):
        raise BrainError(ErrorCode.INVALID_INPUT, "projection handler names must be unique")
    for a in names:
        for b in names:
            if a != b and f"{b}_".startswith(f"{a}_"):
                raise BrainError(ErrorCode.INVALID_INPUT, f"projection handlers {a!r} and {b!r} share a table prefix")
    registered = kinds.kinds()
    for handler in handlers:
        unknown = sorted(handler.kinds - registered)
        if unknown:
            raise BrainError(ErrorCode.INVALID_INPUT, f"projection {handler.name} handles unregistered kinds {unknown}")
        for kind in sorted(handler.kinds):
            if kinds.get(kind).handler_version > handler.handler_version:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION, f"projection {handler.name} is older than entry kind {kind}"
                )


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
        raise io_error(f"projection {handler.name} could not create its tables", exc) from exc
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
        """Create a new store database with ``store_id = policy.store_id``."""
        _check_lease(root, lease)
        _check_handlers(handlers, kinds)
        path = root.store_db
        if any(os.path.lexists(p) for p in _db_files(path)):
            raise BrainError(ErrorCode.INVALID_INPUT, f"a store database already exists at {path}")
        lease.register_handle(_HANDLE)
        try:
            db = connect(path)
            try:
                initialize(db, migrations, store_id=policy.store_id)
                try:
                    row = db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
                except sqlite3.Error as exc:
                    raise io_error("cannot read the new store's meta", exc) from exc
                store = cls(
                    root=root,
                    lease=lease,
                    os_=os_,
                    policy=policy,
                    handlers=handlers,
                    kinds=kinds,
                    db=db,
                    schema_version=int(row[0]),
                    store_id=policy.store_id,
                )
                store._prepare()
                os_.publisher.sync_directory(root.store_dir)
            except BaseException:
                db.close()
                raise
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise
        return store

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
        """Open the existing store for writing; its schema must equal the code's and its id ``policy.store_id``."""
        _check_lease(root, lease)
        _check_handlers(handlers, kinds)
        lease.register_handle(_HANDLE)
        try:
            path = root.store_db
            info = read_schema_info(path)
            if info is None:
                raise BrainError(ErrorCode.NOT_FOUND, f"no store database at {path}")
            ensure_writable(info, migrations)
            if info.store_id != policy.store_id:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the store belongs to a different policy store")
            db = connect(path)
            try:
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
            except BaseException:
                db.close()
                raise
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise
        return store

    def _prepare(self) -> None:
        """Create the live tables of every handler that has none, then secure the database files."""
        with self._immediate() as db:
            try:
                for handler in self._handlers:
                    if not _tables_with_prefix(db, live_prefix(handler)):
                        _create_tables(db, handler, live_prefix(handler))
            except sqlite3.Error as exc:
                raise io_error("cannot create projection tables", exc) from exc
        for path in _db_files(self._root.store_db):
            if path.exists():
                self._os.permissions.secure_file(path)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._check()
        if self._txn_active:
            raise AssertionError("cannot close the store inside a transaction")
        self._closed = True
        try:
            self._db.close()
        except sqlite3.Error as exc:
            raise io_error("cannot close the store", exc) from exc
        finally:
            self._lease.unregister_handle(_HANDLE)

    @property
    def store_id(self) -> str:
        self._check()
        return self._store_id

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
                )
                try:
                    yield txn
                finally:
                    txn._end()
        finally:
            self._txn_active = False

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
        count = 0
        with self._immediate() as db:
            try:
                for handler in self._handlers:
                    for table in _tables_with_prefix(db, rebuild_prefix(handler)):
                        db.execute(f"DROP TABLE {_quote(table)}")
                    _create_tables(db, handler, rebuild_prefix(handler))
                after = 0
                while page := read_entries(db, after, _REPLAY_BATCH):
                    for entry in page:
                        self._require_supported(entry)
                        apply_to_handlers(db, self._handlers, entry, self._policy, rebuild_prefix)
                    count += len(page)
                    after = page[-1].sequence
                for handler in self._handlers:
                    _swap_in_rebuilt(db, handler)
            except sqlite3.Error as exc:
                raise io_error("cannot rebuild projections", exc) from exc
        return count

    def _require_supported(self, entry: LedgerEntry) -> None:
        for handler in self._handlers:
            if entry.kind in handler.kinds and entry.handler_version > handler.handler_version:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"entry {entry.sequence} ({entry.kind}) needs handler version {entry.handler_version}, "
                    f"projection {handler.name} is version {handler.handler_version}",
                )

    def db_integrity(self) -> str:
        """SQLite's ``integrity_check`` result: ``"ok"`` for a sound database."""
        self._check()
        try:
            rows = self._db.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.Error as exc:
            raise io_error("cannot check database integrity", exc) from exc
        return "\n".join(str(row[0]) for row in rows)

    def reconcile_policy(self) -> int:
        """Apply policy intents not yet in ``applied_intents``; returns how many were applied.

        Placeholder: Task 11 implements it (and ``open`` will call it then). Until then it applies nothing.
        """
        self._check()
        return 0

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
            if exc.sqlite_errorcode & 0xFF in _BUSY_CODES:
                raise BrainError(ErrorCode.STORE_BUSY, f"the store database is busy: {exc}") from exc
            raise io_error("cannot begin a store transaction", exc) from exc
        try:
            yield self._db
            if crashpoints:
                crashpoint("ledger.before_commit")
            try:
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                raise io_error("cannot commit the store transaction", exc) from exc
        except BaseException:
            if self._db.in_transaction:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise io_error("cannot roll back the store transaction", exc) from exc
            raise
        if crashpoints:
            crashpoint("ledger.after_commit")
