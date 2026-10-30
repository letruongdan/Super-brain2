"""The main store (spec 5.4, 5.8): one long-lived connection under the writer lease, owned by one thread.

Every public method checks that the store is open and that it runs on the owner thread (the thread that called
``create``/``open``); the ``Txn`` from ``transaction()`` checks the same.
"""

import functools
import os
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicySource, PolicyView
from superbrain.storage.cas import ContentStore, HolderProjection, RetentionClass, blob_is_intact
from superbrain.storage.kinds import CORE_KINDS, KindRegistry
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
_CREATING = ".creating-"
_STAGING_SUFFIX = ".tmp"


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _db_files(path: Path) -> tuple[Path, ...]:
    return (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("the store needs a held writer lease for this data root")


def _with_defaults(
    handlers: Sequence[ProjectionHandler], kinds: KindRegistry
) -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """``handlers`` plus ``HolderProjection`` and ``kinds`` plus ``CORE_KINDS``, each added only if absent.

    A caller kind named like a core kind must be that core kind; a caller handler named ``cas_holders`` that is no
    ``HolderProjection`` is left in place, so the duplicate-name check refuses it.
    """
    extra_kinds = []
    for core in CORE_KINDS:
        if core.kind not in kinds.kinds():
            extra_kinds.append(core)
        elif kinds.get(core.kind) != core:
            raise BrainError(ErrorCode.INVALID_INPUT, f"core entry kind {core.kind!r} cannot be redefined")
    merged_kinds = KindRegistry([*(kinds.get(name) for name in sorted(kinds.kinds())), *extra_kinds])
    if any(isinstance(handler, HolderProjection) for handler in handlers):
        return tuple(handlers), merged_kinds
    return (HolderProjection(), *handlers), merged_kinds


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
        raise io_error("cannot create projection tables", exc) from exc


def _remove_unfinished_creates(path: Path) -> None:
    """Delete ``<brain.db>.creating-*`` leftovers (with their ``-wal``/``-shm``) of a failed or interrupted create."""
    prefix = path.name + _CREATING
    try:
        for name in sorted(os.listdir(path.parent)):
            if name.startswith(prefix):
                os.unlink(path.parent / name)
    except OSError as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot remove an unfinished store create: {exc}") from exc


def _remove_staging_leftovers(staging: Path) -> None:
    """Delete ``*.tmp`` files in ``staging``: the staging files of unfinished ``put``s, which nothing refers to."""
    try:
        names = sorted(os.listdir(staging))
    except FileNotFoundError:
        return  # no staging directory, so no leftovers
    except OSError as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot list {staging}: {exc}") from exc
    for name in names:
        if name.endswith(_STAGING_SUFFIX):
            try:
                os.unlink(staging / name)
            except OSError as exc:
                raise BrainError(ErrorCode.IO_ERROR, f"cannot remove the staging leftover {name}: {exc}") from exc


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
        self._cas = ContentStore(root=root, os_=os_, policy=policy, db=db, check=self._check)

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
        handlers, kinds = _with_defaults(handlers, kinds)
        _check_handlers(handlers, kinds)
        path = root.store_db
        if any(os.path.lexists(p) for p in _db_files(path)):
            raise BrainError(ErrorCode.INVALID_INPUT, f"a store database already exists at {path}")
        lease.register_handle(_HANDLE)
        try:
            _remove_unfinished_creates(path)
            staging = path.with_name(f"{path.name}{_CREATING}{new_id()}")
            db = connect(staging)
            try:
                initialize(db, migrations, store_id=policy.store_id)
                _create_live_tables(db, handlers)
            finally:
                db.close()
            if any(os.path.lexists(p) for p in _db_files(staging)[1:]):
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
        unfinished ``put``s are removed.
        """
        _check_lease(root, lease)
        handlers, kinds = _with_defaults(handlers, kinds)
        _check_handlers(handlers, kinds)
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
        return store

    def _prepare(self) -> None:
        """Give every handler without live tables new ones, filled from the whole ledger in the same transaction
        (a handler registered after entries of its kinds were written must not start empty), then secure the
        database files and remove staging leftovers. Handlers whose live tables exist are not replayed."""
        with self._immediate() as db:
            try:
                fresh = [h for h in self._handlers if not _tables_with_prefix(db, live_prefix(h))]
                for handler in fresh:
                    _create_tables(db, handler, live_prefix(handler))
                if fresh:
                    _replay(db, fresh, self._policy, live_prefix)
            except sqlite3.Error as exc:
                raise io_error("cannot create projection tables", exc) from exc
        for path in _db_files(self._root.store_db):
            if path.exists():
                self._os.permissions.secure_file(path)
        _remove_staging_leftovers(self._root.staging_dir)

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
                    blob_intact=functools.partial(blob_is_intact, self._root.cas_dir),
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

        A ``NOT_FOUND`` from ``hold`` means the blob vanished between the two (GC removed it as an orphan): the
        ``put`` and ``hold`` are retried exactly once, and a second failure propagates.
        """
        self._check()
        self._require_no_transaction()
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
                raise io_error("cannot rebuild projections", exc) from exc
        return count

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
            if getattr(exc, "sqlite_errorcode", 0) & 0xFF in _BUSY_CODES:
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
