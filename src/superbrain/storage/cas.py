"""Content-addressed blobs and their holders (spec 5.4).

Every payload lives in ``store/cas/<aa>/<64 hex>``, named by the sha256 of its bytes; the ledger carries only the
digest. ``ContentStore.put`` publishes a blob durably *before* anything refers to it: staging write (durable),
a re-hash of the staged file, then, for a new shard, create + secure it and make its entry in ``cas/`` durable,
then an atomic rename into the shard (whose entry is made durable too). Only after ``put`` returns does
``Txn.hold`` record a holder, inside a write transaction that first re-checks the blob, so a crash in between
leaves an orphan, never a dangling holder.

Holders are the ``cas_holders`` projection of the reserved ``cas.hold``/``cas.release`` entries; a ``cas.hold``
for a tombstoned holder is skipped, so a replay applies tombstones recorded since.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicyView
from superbrain.storage.errors import os_error, sqlite_error
from superbrain.storage.kinds import RetentionClass as RetentionClass
from superbrain.storage.kinds import is_uuid
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import LedgerEntry, Txn, utc_timestamp

_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_SHARD_NAME = re.compile(r"[0-9a-f]{2}")
_BLOB_NAME = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1 << 20
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT; st_file_attributes exists on Windows only
HOLDERS_TABLE = "p_cas_holders_"
STAGING_SUFFIX = ".tmp"


def blob_path(cas_dir: Path, digest: str) -> Path:
    """``cas/<aa>/<64 hex>`` for ``digest``; a digest not spelled ``sha256:<64 lowercase hex>`` is ``INVALID_INPUT``."""
    match = _DIGEST.fullmatch(digest) if type(digest) is str else None
    if match is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "a digest must be 'sha256:' and 64 lowercase hex digits")
    hex_ = match.group(1)
    return cas_dir / hex_[:2] / hex_


def file_digest(path: Path) -> str | None:
    """The digest of the file at ``path``, read in chunks; ``None`` if there is no such file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(_CHUNK):
                hasher.update(chunk)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise os_error(f"cannot read blob {path}", err) from err
    return "sha256:" + hasher.hexdigest()


def is_link(st: os.stat_result) -> bool:
    """Whether the ``lstat`` result ``st`` (never followed) is a symlink or a Windows reparse point (a junction
    included, which ``DirEntry.is_dir(follow_symlinks=False)`` reports as a directory)."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def validate_path_syntax(path: Path, os_: OsAdapters) -> None:
    """Reject empty, NUL, ``..``, UNC/device, and Windows ADS paths before any ``lstat`` syscall."""
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid path")
    os_.paths.reject_unsafe_path(raw)
    if ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "path must not contain '..'")


def check_container(directory: Path, os_: OsAdapters) -> None:
    """Check an existing directory before anything in it is entered or copied (spec 5.9): neither it nor a directory
    above it may be a link or reparse point (``UNSAFE_PATH``), it must be a directory (``INTEGRITY_FAILURE``) and
    owner-only (``INSECURE_PERMISSIONS``, with the real ``PermissionGuard``). Nothing is changed or re-secured."""
    validate_path_syntax(directory, os_)
    os_.paths.reject_links(directory)
    ancestor_problems = os_.permissions.check_ancestors(directory)
    if ancestor_problems:
        detail = "; ".join(f"{p.path}: {p.reason}" for p in ancestor_problems)
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"an ancestor of {directory} is not trusted: {detail}")
    try:
        mode = os.lstat(directory).st_mode
    except OSError as err:
        raise os_error(f"cannot inspect {directory}", err) from err
    if not stat.S_ISDIR(mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{directory} is not a directory")
    problems = os_.permissions.object_problems(directory)
    if problems:
        detail = "; ".join(f"{p.path}: {p.reason}" for p in problems)
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"existing {directory} is not owner-only: {detail}")


def check_backup_tree(backup: Path, os_: OsAdapters) -> None:
    """Admit every entry of a backup before anything in it is read or copied (spec 5.7, 5.9; C04, ruling of review
    round 4): the backup directory (``check_container``), then each entry below it, without following any link. A
    link or reparse point is ``UNSAFE_PATH`` and is never entered or read; anything but a regular file or a directory
    is ``INTEGRITY_FAILURE``; each must be owner-only with ``os_.permissions`` (``INSECURE_PERMISSIONS``). Only names
    and metadata are read here; which entries a backup may hold is checked afterwards by ``verify_backup``."""
    check_container(backup, os_)
    pending = [backup]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
            for entry in entries:
                path, st = Path(entry.path), entry.stat(follow_symlinks=False)
                if is_link(st):
                    raise BrainError(ErrorCode.UNSAFE_PATH, f"the backup entry {path} is a link or reparse point")
                if stat.S_ISDIR(st.st_mode):
                    pending.append(path)
                elif not stat.S_ISREG(st.st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the backup entry {path} is not a file or directory")
                problems = os_.permissions.object_problems(path)
                if problems:
                    detail = "; ".join(f"{p.path}: {p.reason}" for p in problems)
                    message = f"the backup entry {path} is not owner-only: {detail}"
                    raise BrainError(ErrorCode.INSECURE_PERMISSIONS, message)
        except OSError as err:
            raise os_error(f"cannot inspect the backup {backup}", err) from err


def check_blob_location(blob: Path, os_: OsAdapters) -> None:
    """Check ``cas/<aa>/<64 hex>`` before it is read, reused or written through (spec 5.5, 5.9).

    Neither the blob, its shard nor any directory above them may be a link or reparse point (``UNSAFE_PATH``), so the
    path stays inside the data root ``prepare_data_root`` checked. An existing shard must be a directory and an
    existing blob a regular file (``INTEGRITY_FAILURE``), each owner-only (``INSECURE_PERMISSIONS``). Missing ones are
    fine: ``put`` creates them. Nothing is changed or re-secured, inside the root or outside it.
    """
    os_.paths.reject_links(blob)
    for path, directory in ((blob.parent, True), (blob, False)):
        try:
            mode = os.lstat(path).st_mode
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError as err:
            raise os_error(f"cannot inspect {path}", err) from err
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            expected = "a directory" if directory else "a regular file"
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the CAS entry {path} is not {expected}")
        problems = os_.permissions.object_problems(path)
        if problems:
            detail = "; ".join(f"{p.path}: {p.reason}" for p in problems)
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"existing {path} is not owner-only: {detail}")


def blob_digests(cas_dir: Path, os_: OsAdapters) -> set[str]:
    """The digests of the blob files in ``cas_dir``: ``<aa>/<64 hex>`` regular files whose name starts with their
    shard's; anything else (stray files, blob links, other names) is ignored. A shard-named link or reparse point
    (a Windows junction lists as a directory) is ``UNSAFE_PATH``, as in ``check_blob_location``: nothing outside the
    data root is listed, so nothing there is copied or collected."""
    found: set[str] = set()
    try:
        with os.scandir(cas_dir) as entries:
            named = [s for s in entries if _SHARD_NAME.fullmatch(s.name)]
        os_.paths.reject_links(cas_dir, entries=[Path(s.path) for s in named])
        shards = [s for s in named if s.is_dir(follow_symlinks=False)]
        for shard in shards:
            with os.scandir(shard.path) as blobs:
                found.update(
                    "sha256:" + blob.name
                    for blob in blobs
                    if _BLOB_NAME.fullmatch(blob.name)
                    and blob.name.startswith(shard.name)
                    and blob.is_file(follow_symlinks=False)
                )
    except OSError as err:
        raise os_error(f"cannot list the blobs in {cas_dir}", err) from err
    return found


def remove_staging_leftovers(staging: Path) -> None:
    """Delete ``*.tmp`` files in ``staging``: the staging files of unfinished ``put``s, which nothing refers to."""
    try:
        names = sorted(os.listdir(staging))
    except FileNotFoundError:
        return  # no staging directory, so no leftovers
    except OSError as exc:
        raise os_error(f"cannot list {staging}", exc) from exc
    for name in names:
        if name.endswith(STAGING_SUFFIX):
            try:
                os.unlink(staging / name)
            except OSError as exc:
                raise os_error(f"cannot remove the staging leftover {name}", exc) from exc


def held_digests(db: sqlite3.Connection, holder_kind: str, holder_id: str) -> list[str]:
    """Sorted digests that ``(holder_kind, holder_id)`` currently holds, per the holder projection."""
    try:
        rows = db.execute(
            f"SELECT digest FROM {HOLDERS_TABLE} WHERE holder_kind = ? AND holder_id = ? ORDER BY digest",
            (holder_kind, holder_id),
        ).fetchall()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read the holders", exc) from exc
    return [str(row[0]) for row in rows]


def active_held_digests(db: sqlite3.Connection, holder_kind: str, holder_id: str, *, now: datetime) -> list[str]:
    """Sorted digests held by ``(holder_kind, holder_id)`` whose hold is not expired at ``now``."""
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
    cutoff = utc_timestamp(now)
    try:
        rows = db.execute(
            f"SELECT digest FROM {HOLDERS_TABLE} WHERE holder_kind = ? AND holder_id = ?"
            " AND (retention_class = ? OR expires_at IS NULL OR expires_at > ?) ORDER BY digest",
            (holder_kind, holder_id, RetentionClass.DURABLE.value, cutoff),
        ).fetchall()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read active holders", exc) from exc
    return [str(row[0]) for row in rows]


def read_held_blob_or_none(
    db: sqlite3.Connection,
    cas: ContentStore,
    policy: PolicyView,
    digest: str,
    *,
    holder_kind: str,
    holder_id: str,
    now: datetime,
) -> bytes | None:
    """Return bytes of ``digest`` iff actively held at ``now``, non-tombstoned, unquarantined, and intact."""
    if not is_uuid(holder_id):
        return None
    if policy.is_tombstoned(holder_kind, holder_id):
        return None
    if digest not in active_held_digests(db, holder_kind, holder_id, now=now):
        return None
    if policy.is_quarantined(digest) or not cas.blob_intact(digest):
        return None
    return cas.read(digest)


def _meta_text(entry: LedgerEntry, name: str) -> str:
    value = entry.meta.get(name)
    if not isinstance(value, str):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"ledger entry {entry.sequence}: {name} is not text")
    return value


_CANONICAL_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


class HolderProjection:
    """``p_cas_holders_``: one row per (holder, digest) currently held."""

    name = "cas_holders"
    handler_version = 1
    kinds = frozenset({"cas.hold", "cas.release"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix} (digest TEXT NOT NULL, holder_kind TEXT NOT NULL, holder_id TEXT NOT NULL,"
            " retention_class TEXT NOT NULL, expires_at TEXT, PRIMARY KEY (holder_kind, holder_id, digest))"
        )
        db.execute(f"CREATE INDEX {prefix}by_digest ON {prefix} (digest)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        digest = _meta_text(entry, "digest")
        holder_kind, holder_id = _meta_text(entry, "holder_kind"), _meta_text(entry, "holder_id")
        if entry.kind == "cas.release":
            db.execute(
                f"DELETE FROM {prefix} WHERE holder_kind = ? AND holder_id = ? AND digest = ?",
                (holder_kind, holder_id, digest),
            )
            return
        if policy.is_tombstoned(holder_kind, holder_id):
            return
        expires_at = entry.meta.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"ledger entry {entry.sequence}: expires_at is not text")
        if expires_at is not None and not _CANONICAL_TIMESTAMP.fullmatch(expires_at):
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE,
                f"ledger entry {entry.sequence}: expires_at is not a canonical fixed-width timestamp",
            )
        db.execute(
            f"INSERT INTO {prefix} (digest, holder_kind, holder_id, retention_class, expires_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT (holder_kind, holder_id, digest)"
            " DO UPDATE SET retention_class = excluded.retention_class, expires_at = excluded.expires_at",
            (digest, holder_kind, holder_id, _meta_text(entry, "retention"), expires_at),
        )


@dataclass(frozen=True)
class GcReport:
    """Digests ``collect_garbage`` deleted, and orphans it kept because they are younger than the grace period."""

    deleted: tuple[str, ...]
    kept_young: tuple[str, ...]


class ContentStore:
    """The blobs of one ``Store``; obtain it as ``Store.cas``. It checks the store's owner thread, like the store."""

    def __init__(
        self,
        *,
        root: DataRoot,
        os_: OsAdapters,
        policy: PolicyView,
        db: sqlite3.Connection,
        check: Callable[[], None],
        maintenance: Callable[[], AbstractContextManager[None]],
        transaction: Callable[[], AbstractContextManager[Txn]],
    ) -> None:
        self._cas_dir = root.cas_dir
        self._staging_dir = root.staging_dir
        self._os = os_
        self._policy = policy
        self._db = db
        self._check = check
        self._maintenance = maintenance
        self._transaction = transaction
        self._durable_shards: set[str] = set()
        """Shards whose entry in ``cas/`` this store made durable: created here, or synced again on first reuse."""

    def put(self, data: bytes) -> str:
        """Publish ``data`` durably and return its digest; an existing blob is verified, never rewritten.

        The blob's location is checked first (``check_blob_location``). An existing blob whose bytes do not match is
        ``INTEGRITY_FAILURE``; a matching one has its directory entries made durable again. The staging file is
        re-hashed before publishing: a mismatch is ``INTEGRITY_FAILURE``. On any failure the staging file is removed
        and the error propagates. ``put`` adds no holder: call ``Txn.hold`` once it has returned.
        """
        self._check()
        digest = digest_bytes(data)
        final = self._checked(digest)
        found = file_digest(final)
        if found is not None:
            if found != digest:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the stored blob {digest} does not match its digest")
            # An earlier put may have renamed it into place and failed before its directory entries were durable.
            self._sync_reused_shard(final.parent)
            self._os.publisher.sync_directory(final.parent)
            return digest
        staging = self._staging_dir / f"{new_id()}{STAGING_SUFFIX}"
        publisher = self._os.publisher
        try:
            try:
                publisher.write_new(staging, data)
                crashpoint("cas.after_staging_write")
                if file_digest(staging) != digest:
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the staged bytes of {digest} do not match it")
                self._ensure_shard(final.parent)
                publisher.publish(staging, final)
            except FileExistsError as err:
                raise BrainError(ErrorCode.IO_ERROR, f"unexpected existing file while storing {digest}") from err
        except BaseException as err:
            try:
                staging.unlink(missing_ok=True)
            except OSError as cleanup:
                err.add_note(f"the staging file {staging} could not be removed: {cleanup}")
            raise
        crashpoint("cas.after_rename")
        return digest

    def read(self, digest: str) -> bytes:
        """The bytes of ``digest``: ``QUARANTINED`` first, then ``NOT_FOUND``, then ``INTEGRITY_FAILURE``."""
        self._check()
        path = blob_path(self._cas_dir, digest)
        if self._policy.is_quarantined(digest):
            raise BrainError(ErrorCode.QUARANTINED, f"blob {digest} is quarantined")
        check_blob_location(path, self._os)
        try:
            data = path.read_bytes()
        except FileNotFoundError as err:
            raise BrainError(ErrorCode.NOT_FOUND, f"no blob {digest}") from err
        except OSError as err:
            raise os_error(f"cannot read blob {digest}", err) from err
        if digest_bytes(data) != digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the stored blob {digest} does not match its digest")
        return data

    def read_held(self, digest: str, *, holder_kind: str, holder_id: str, now: datetime) -> bytes:
        """Read ``digest`` iff held cleanly by ``(holder_kind, holder_id)`` and not expired/tombstoned/quarantined."""
        self._check()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
        self._checked(digest)
        if self._policy.is_quarantined(digest):
            raise BrainError(ErrorCode.QUARANTINED, f"blob {digest} is quarantined")
        if self._policy.is_tombstoned(holder_kind, holder_id):
            raise BrainError(ErrorCode.NOT_FOUND, f"holder {holder_kind}:{holder_id} is tombstoned")
        if digest not in active_held_digests(self._db, holder_kind, holder_id, now=now):
            raise BrainError(ErrorCode.NOT_FOUND, f"blob {digest} is not actively held by {holder_kind}:{holder_id}")
        return self.read(digest)

    def exists(self, digest: str) -> bool:
        self._check()
        return self._checked(digest).is_file()

    def blob_intact(self, digest: str) -> bool:
        """The blob for ``digest`` passes ``check_blob_location``, exists and its bytes hash to ``digest``."""
        self._check()
        return file_digest(self._checked(digest)) == digest

    def holders(self, digest: str) -> list[tuple[str, str, RetentionClass]]:
        """``(holder_kind, holder_id, retention)`` of every holder of ``digest``, ordered by kind and id."""
        self._check()
        blob_path(self._cas_dir, digest)  # validates the spelling
        rows = self._query(
            f"SELECT holder_kind, holder_id, retention_class FROM {HOLDERS_TABLE} WHERE digest = ?"
            " ORDER BY holder_kind, holder_id",
            (digest,),
        )
        try:
            return [(str(kind), str(holder), RetentionClass(str(retention))) for kind, holder, retention in rows]
        except ValueError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"a holder of {digest} has an unknown retention") from err

    def due_holders(self, cutoff: str) -> list[tuple[str, str]]:
        """Sorted ``(holder_kind, holder_id)`` of the holders whose every hold is non-durable, has an expiry and
        expires at or before ``cutoff``.

        A holder with any durable, never-expiring or not yet due hold is left out: a tombstone acts on the whole
        holder. ``cutoff`` is a canonical ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` timestamp, compared as text.
        """
        self._check()
        rows = self._query(
            f"SELECT holder_kind, holder_id FROM {HOLDERS_TABLE} GROUP BY holder_kind, holder_id"
            " HAVING SUM(CASE WHEN retention_class != ? AND expires_at IS NOT NULL AND expires_at <= ?"
            " THEN 0 ELSE 1 END) = 0 ORDER BY holder_kind, holder_id",
            (RetentionClass.DURABLE.value, cutoff),
        )
        return [(str(kind), str(holder)) for kind, holder in rows]

    def orphans(self) -> list[str]:
        """Sorted digests of the blob files that no holder refers to."""
        self._check()
        on_disk = blob_digests(self._cas_dir, self._os)
        held = {str(row[0]) for row in self._query(f"SELECT DISTINCT digest FROM {HOLDERS_TABLE}", ())}
        return sorted(on_disk - held)

    def collect_garbage(self, *, now: datetime, grace: timedelta = timedelta(hours=24)) -> GcReport:
        """Delete the blobs no holder refers to whose file is older than ``now - grace``; runs in maintenance.

        While maintenance is already active (a backup, say) this is ``STORE_BUSY``. Each deletion has a write
        transaction of its own that re-checks for a holder, removes the file and makes its directory durable
        before committing. ``Txn.hold`` re-checks the blob in a write transaction too, and SQLite serialises the
        two, so a holder never points at a deleted blob. Shard directories are kept; GC adds no ledger entry.
        """
        self._check()
        if now.tzinfo is None or now.utcoffset() is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
        cutoff = (now - grace).timestamp()
        with self._maintenance():
            deleted: list[str] = []
            young: list[str] = []
            for digest in self.orphans():
                path = blob_path(self._cas_dir, digest)
                try:
                    modified = path.stat().st_mtime
                except FileNotFoundError:
                    continue
                except OSError as err:
                    raise os_error(f"cannot stat blob {digest}", err) from err
                if modified >= cutoff:
                    young.append(digest)
                elif self._delete_if_unheld(digest, path):
                    deleted.append(digest)
            return GcReport(deleted=tuple(sorted(deleted)), kept_young=tuple(sorted(young)))

    def _delete_if_unheld(self, digest: str, path: Path) -> bool:
        """In one write transaction: no holder -> unlink the blob and sync its directory. True if it deleted."""
        with self._transaction():
            if self._query(f"SELECT 1 FROM {HOLDERS_TABLE} WHERE digest = ? LIMIT 1", (digest,)):
                return False
            check_blob_location(path, self._os)
            try:
                path.unlink()
            except FileNotFoundError:
                return False
            except OSError as err:  # no retry on a sharing violation: a write transaction is open
                raise os_error(f"cannot delete blob {digest}", err, sharing_busy=True) from err
            self._os.publisher.sync_directory(path.parent)
            return True

    def _query(self, sql: str, params: tuple[str, ...]) -> list[tuple[object, ...]]:
        try:
            return self._db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the blob holders", exc) from exc

    def _checked(self, digest: str) -> Path:
        path = blob_path(self._cas_dir, digest)
        check_blob_location(path, self._os)
        return path

    def _ensure_shard(self, shard: Path) -> None:
        """Create a missing shard, secure it, and make its entry in ``cas/`` durable; an existing one (already
        checked by ``check_blob_location``) is kept and goes through ``_sync_reused_shard``."""
        try:
            shard.mkdir(mode=0o700)
        except FileExistsError:
            self._sync_reused_shard(shard)
            return
        except OSError as err:
            raise os_error(f"cannot create the blob shard {shard}", err) from err
        self._os.permissions.secure_directory(shard)
        self._os.publisher.sync_directory(self._cas_dir)
        self._durable_shards.add(shard.name)

    def _sync_reused_shard(self, shard: Path) -> None:
        """Sync ``cas/`` the first time this store reuses ``shard``: the put that created it (here or in an earlier
        process) may have failed or died before its entry in ``cas/`` was durable (spec 5.4 step 5 before the ref).
        A failed sync propagates and the next reuse tries again; an OS that cannot sync a directory at all is the
        publisher's degraded tier, not an error."""
        if shard.name not in self._durable_shards:
            self._os.publisher.sync_directory(self._cas_dir)
            self._durable_shards.add(shard.name)
