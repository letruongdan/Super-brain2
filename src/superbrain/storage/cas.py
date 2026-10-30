"""Content-addressed blobs and their holders (spec 5.4).

Every payload lives in ``store/cas/<aa>/<64 hex>``, named by the sha256 of its bytes; the ledger carries only the
digest. ``ContentStore.put`` publishes a blob durably *before* anything refers to it: staging write (durable),
then, for a new shard, create + secure it and make its entry in ``cas/`` durable, then an atomic rename into the
shard (whose entry is made durable too). Only after ``put`` returns does ``Txn.hold`` record a holder, inside a
write transaction that first re-checks the blob, so a crash in between leaves an orphan, never a dangling holder.

Holders are the ``cas_holders`` projection of the reserved ``cas.hold``/``cas.release`` entries; a ``cas.hold``
for a tombstoned holder is skipped, so a replay applies tombstones recorded since.
"""

import errno
import hashlib
import os
import re
import sqlite3
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicyView
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import LedgerEntry, io_error

_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_SHARD_NAME = re.compile(r"[0-9a-f]{2}")
_BLOB_NAME = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1 << 20
_ERROR_DISK_FULL = 112  # Windows ERROR_DISK_FULL
HOLDERS_TABLE = "p_cas_holders_"


class RetentionClass(StrEnum):
    EVENT_PAYLOAD = "event_payload"
    EVIDENCE = "evidence"
    DURABLE = "durable"


def _os_error(what: str, err: OSError) -> BrainError:
    if err.errno == errno.ENOSPC or getattr(err, "winerror", None) == _ERROR_DISK_FULL:
        return BrainError(ErrorCode.STORAGE_FULL, f"no space left: {what}")
    return BrainError(ErrorCode.IO_ERROR, f"{what}: {err}")


def blob_path(cas_dir: Path, digest: str) -> Path:
    """``cas/<aa>/<64 hex>`` for ``digest``; a digest not spelled ``sha256:<64 lowercase hex>`` is ``INVALID_INPUT``."""
    match = _DIGEST.fullmatch(digest) if type(digest) is str else None
    if match is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "a digest must be 'sha256:' and 64 lowercase hex digits")
    hex_ = match.group(1)
    return cas_dir / hex_[:2] / hex_


def _file_digest(path: Path) -> str | None:
    """The digest of the file at ``path``, read in chunks; ``None`` if there is no such file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(_CHUNK):
                hasher.update(chunk)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise _os_error(f"cannot read blob {path}", err) from err
    return "sha256:" + hasher.hexdigest()


def blob_is_intact(cas_dir: Path, digest: str) -> bool:
    """The blob for ``digest`` exists and its bytes hash to ``digest``."""
    return _file_digest(blob_path(cas_dir, digest)) == digest


def _meta_text(entry: LedgerEntry, name: str) -> str:
    value = entry.meta.get(name)
    if not isinstance(value, str):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"ledger entry {entry.sequence}: {name} is not text")
    return value


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
        db.execute(
            f"INSERT INTO {prefix} (digest, holder_kind, holder_id, retention_class, expires_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT (holder_kind, holder_id, digest)"
            " DO UPDATE SET retention_class = excluded.retention_class, expires_at = excluded.expires_at",
            (digest, holder_kind, holder_id, _meta_text(entry, "retention"), expires_at),
        )


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
    ) -> None:
        self._cas_dir = root.cas_dir
        self._staging_dir = root.staging_dir
        self._os = os_
        self._policy = policy
        self._db = db
        self._check = check

    def put(self, data: bytes) -> str:
        """Publish ``data`` durably and return its digest; an existing blob is verified, never rewritten.

        An existing blob whose bytes do not match is ``INTEGRITY_FAILURE``. On any failure the staging file is
        removed and the error propagates. ``put`` adds no holder: call ``Txn.hold`` once it has returned.
        """
        self._check()
        digest = digest_bytes(data)
        final = blob_path(self._cas_dir, digest)
        found = _file_digest(final)
        if found is not None:
            if found != digest:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the stored blob {digest} does not match its digest")
            return digest
        staging = self._staging_dir / f"{new_id()}.tmp"
        publisher = self._os.publisher
        try:
            try:
                publisher.write_new(staging, data)
                crashpoint("cas.after_staging_write")
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
        try:
            data = path.read_bytes()
        except FileNotFoundError as err:
            raise BrainError(ErrorCode.NOT_FOUND, f"no blob {digest}") from err
        except OSError as err:
            raise _os_error(f"cannot read blob {digest}", err) from err
        if digest_bytes(data) != digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the stored blob {digest} does not match its digest")
        return data

    def exists(self, digest: str) -> bool:
        self._check()
        return blob_path(self._cas_dir, digest).is_file()

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

    def orphans(self) -> list[str]:
        """Sorted digests of the blob files that no holder refers to."""
        self._check()
        on_disk = self._blob_digests()
        held = {str(row[0]) for row in self._query(f"SELECT DISTINCT digest FROM {HOLDERS_TABLE}", ())}
        return sorted(on_disk - held)

    def _query(self, sql: str, params: tuple[str, ...]) -> list[tuple[object, ...]]:
        try:
            return self._db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise io_error("cannot read the blob holders", exc) from exc

    def _blob_digests(self) -> set[str]:
        found: set[str] = set()
        try:
            with os.scandir(self._cas_dir) as entries:
                shards = [s for s in entries if _SHARD_NAME.fullmatch(s.name) and s.is_dir(follow_symlinks=False)]
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
            raise _os_error(f"cannot list the blobs in {self._cas_dir}", err) from err
        return found

    def _ensure_shard(self, shard: Path) -> None:
        """Create a missing shard, secure it, and make its entry in ``cas/`` durable; an existing one is kept."""
        try:
            shard.mkdir(mode=0o700)
        except FileExistsError:
            return
        except OSError as err:
            raise _os_error(f"cannot create the blob shard {shard}", err) from err
        self._os.permissions.secure_directory(shard)
        self._os.publisher.sync_directory(self._cas_dir)
