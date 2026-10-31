"""Backups (spec 5.6, 5.7): self-contained snapshots, a verifier that trusts only the snapshot, and pruning.

A backup is the directory ``backups/<kind>-<UTC yyyymmddThhmmssZ>-<id>/`` holding:

- the snapshot, ``brain.db`` (store kinds) or ``policy.db``: one file in rollback-journal mode, with no companions;
- for store kinds, ``cas/<aa>/<64 hex>``: a copy of every blob the backup lists;
- ``manifest.json``, the canonical JSON of the ``BackupManifest`` fields except ``logical_verified``, written last.
  A directory without it is incomplete and never verifies.

Kinds: ``store`` (closure: from an open ``Store``, the blobs its snapshot's holders refer to), ``store_full``
(maintenance, by path: every blob in ``cas/``) and ``policy``. ``verify_backup`` never trusts the manifest: it
derives ``store_id``, ``schema_version``, the ledger high-water, the trust generation and the roots from the
snapshot itself and compares them with the manifest, and it checks the blob files independently of the roots.

Every snapshot is taken by ``_snapshot_db``, the only caller of ``sqlite3.Connection.backup``; tests inject faults by
patching it, so it is always called through this module's global. ``copy_database`` is the one copy of a closed
database with its ``-wal``, shared with migration.
"""

import json
import os
import re
import shutil
import sqlite3
import stat
import sys
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.os import OsAdapters
from superbrain.storage.cas import HOLDERS_TABLE, blob_digests, blob_path, check_blob_location, file_digest, is_link
from superbrain.storage.errors import os_error, sqlite_error
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.prune import MANIFEST_NAME, backup_dir_name, prune_backups
from superbrain.storage.schema import Migration, SchemaInfo, ensure_readable, read_schema_info
from superbrain.storage.sqlite import db_files, open_immutable
from superbrain.storage.writer import WriterLease

if TYPE_CHECKING:
    from superbrain.storage.policy_store import PolicyStore
    from superbrain.storage.store import Store

__all__ = [
    "BackupKind",
    "BackupManifest",
    "copy_blobs",
    "copy_database",
    "create_maintenance_backup",
    "create_policy_backup",
    "create_store_backup",
    "new_directory",
    "prune_backups",
    "verify_backup",
    "write_new_file",
]

BackupKind = Literal["store", "store_full", "policy"]
FORMAT_VERSION = 1
_KINDS: tuple[BackupKind, ...] = ("store", "store_full", "policy")
_SNAPSHOT_NAME: dict[str, str] = {"store": "brain.db", "store_full": "brain.db", "policy": "policy.db"}
_CAS = "cas"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_SHARD_NAME = re.compile(r"[0-9a-f]{2}")
_BLOB_NAME = re.compile(r"[0-9a-f]{64}")
_FIELDS = (
    "format_version",
    "kind",
    "store_id",
    "schema_version",
    "ledger_high_water",
    "trust_generation",
    "created_at",
    "db_digest",
    "blobs",
)


@dataclass(frozen=True)
class BackupManifest:
    format_version: int
    kind: BackupKind
    store_id: str
    schema_version: int
    ledger_high_water: int
    """``max(sequence)`` of the snapshot's ledger, 0 when it is empty; always 0 for ``policy``."""
    trust_generation: int | None
    """The policy snapshot's trust generation (required for ``policy``); always ``None`` for store kinds."""
    created_at: str
    db_digest: str
    blobs: tuple[str, ...]
    """Sorted digests of the blob files in the backup."""
    logical_verified: bool
    """Set by ``verify_backup``, never stored: ``False`` only for a ``store_full`` whose schema this code cannot
    read, where only the physical facts were checked."""


def _fail(check: str, detail: str) -> BrainError:
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"backup check {check} failed: {detail}")


def _require_aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")


# --- the snapshot ------------------------------------------------------------------------------------------------


def _snapshot_db(source: sqlite3.Connection, dest: Path, os_: OsAdapters) -> None:
    """Copy ``source``, as of now, into the new file ``dest`` and make it self-contained and durable.

    The only caller of ``Connection.backup``. The copy is switched to ``journal_mode=DELETE`` (no ``-wal``), closed
    and flushed with ``os_.publisher.flush_file``, so the snapshot is one file with no companions. ``dest`` and its
    companions must not exist.
    """
    if any(os.path.lexists(p) for p in (*db_files(dest), dest.with_name(dest.name + "-journal"))):
        raise BrainError(ErrorCode.IO_ERROR, f"the snapshot {dest} already exists")
    try:
        target = sqlite3.connect(dest, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error(f"cannot create the snapshot {dest}", exc) from exc
    try:
        try:
            target.execute("PRAGMA synchronous=FULL")
            if sys.platform == "darwin":
                target.execute("PRAGMA fullfsync=ON")
            source.backup(target)
            mode = target.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        except sqlite3.Error as exc:
            raise sqlite_error(f"cannot snapshot the database into {dest}", exc) from exc
        if str(mode).lower() != "delete":
            raise BrainError(ErrorCode.IO_ERROR, f"{dest}: journal_mode is {mode!r}, DELETE did not take effect")
    finally:
        target.close()
    leftovers = [p.name for p in (*db_files(dest)[1:], dest.with_name(dest.name + "-journal")) if p.exists()]
    if leftovers:
        raise BrainError(ErrorCode.IO_ERROR, f"the snapshot {dest} kept companions {leftovers}")
    os_.publisher.flush_file(dest)


@contextmanager
def _open_snapshot(path: Path) -> Iterator[sqlite3.Connection]:
    """The closed snapshot at ``path``, opened ``immutable=1``: nothing is created or changed."""
    try:
        db = open_immutable(path)
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot open the snapshot {path}: {exc}") from exc
    try:
        yield db
    finally:
        db.close()


def _query(db: sqlite3.Connection, check: str, sql: str, params: tuple[str, ...] = ()) -> list[tuple[object, ...]]:
    try:
        return db.execute(sql, params).fetchall()
    except sqlite3.Error as exc:
        raise _fail(check, f"cannot read the snapshot: {exc}") from exc


def _has_table(db: sqlite3.Connection, check: str, name: str) -> bool:
    return bool(_query(db, check, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)))


def _schema_info(snapshot: Path) -> SchemaInfo:
    info = read_schema_info(snapshot)
    if info is None:
        raise _fail("db_digest", f"the snapshot {snapshot.name} is missing")
    return info


def _integrity(db: sqlite3.Connection) -> None:
    result = "\n".join(str(row[0]) for row in _query(db, "integrity_check", "PRAGMA integrity_check"))
    if result != "ok":
        raise _fail("integrity_check", result)


def _high_water(db: sqlite3.Connection) -> int:
    (value,) = _query(db, "ledger_high_water", "SELECT max(sequence) FROM ledger")[0]
    if value is None:
        return 0
    if type(value) is not int or value < 1:
        raise _fail("ledger_high_water", f"the snapshot's ledger sequence {value!r} is not a positive integer")
    return value


def _trust_generation(db: sqlite3.Connection) -> int:
    """The policy snapshot's ``trust`` row generation; a missing table or row is ``INTEGRITY_FAILURE``."""
    if not _has_table(db, "trust_generation", "trust"):
        raise _fail("trust_generation", "the snapshot has no trust table: it is not a policy store")
    rows = _query(db, "trust_generation", "SELECT generation FROM trust WHERE id = 1")
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise _fail("trust_generation", "the snapshot has no valid trust generation")
    return rows[0][0]


def _roots(db: sqlite3.Connection) -> frozenset[str]:
    """Every digest some holder in the snapshot's ``p_cas_holders_`` refers to."""
    if not _has_table(db, "roots", HOLDERS_TABLE):
        raise _fail("roots", f"the snapshot has no {HOLDERS_TABLE} table")
    digests = [row[0] for row in _query(db, "roots", f"SELECT DISTINCT digest FROM {HOLDERS_TABLE}")]
    if not all(isinstance(d, str) and _DIGEST.fullmatch(d) for d in digests):
        raise _fail("roots", "the snapshot holds a malformed digest")
    return frozenset(str(d) for d in digests)


# --- creating ----------------------------------------------------------------------------------------------------


def new_directory(path: Path, os_: OsAdapters) -> None:
    """Create ``path`` (which must not exist), secure it and make its entry in the parent durable."""
    try:
        path.mkdir(mode=0o700)
    except OSError as err:
        raise os_error(f"cannot create directory {path}", err) from err
    os_.permissions.secure_directory(path)
    os_.publisher.sync_directory(path.parent)


def _new_backup_dir(backups_dir: Path, kind: BackupKind, now: datetime, os_: OsAdapters) -> Path:
    path = backups_dir / backup_dir_name(kind, now)
    new_directory(path, os_)
    return path


def _secure_snapshot(snapshot: Path, os_: OsAdapters) -> None:
    os_.permissions.secure_file(snapshot)
    os_.publisher.sync_directory(snapshot.parent)


def write_new_file(path: Path, data: bytes, os_: OsAdapters) -> None:
    """Create ``path`` (which must not exist) holding ``data``, durable and owner-only."""
    try:
        os_.publisher.write_new(path, data)
    except FileExistsError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"unexpected existing file {path}") from err
    os_.permissions.secure_file(path)


def copy_blobs(source_cas: Path, dest_cas: Path, digests: Iterable[str], os_: OsAdapters) -> None:
    """Copy each blob into ``dest_cas`` (created here) after checking its location (``check_blob_location``) and its
    bytes; every directory made durable."""
    new_directory(dest_cas, os_)
    shards: set[Path] = set()
    for digest in sorted(digests):
        source = blob_path(source_cas, digest)
        check_blob_location(source, os_)
        try:
            data = source.read_bytes()
        except FileNotFoundError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the blob {digest} is missing from {source_cas}") from err
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot read blob {digest}: {err}") from err
        if digest_bytes(data) != digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the blob {digest} does not match its digest")
        dest = blob_path(dest_cas, digest)
        if dest.parent not in shards:
            new_directory(dest.parent, os_)
            shards.add(dest.parent)
        write_new_file(dest, data, os_)
    for shard in sorted(shards):
        os_.publisher.sync_directory(shard)


def _write_manifest(directory: Path, kind: BackupKind, blobs: Sequence[str], now: datetime, os_: OsAdapters) -> None:
    """Derive the manifest from the snapshot in ``directory`` and publish it as ``manifest.json``: the last step."""
    snapshot = directory / _SNAPSHOT_NAME[kind]
    info = _schema_info(snapshot)
    with _open_snapshot(snapshot) as db:
        high_water = 0 if kind == "policy" else _high_water(db)
        trust = _trust_generation(db) if kind == "policy" else None
    listed: list[JsonValue] = [*sorted(blobs)]
    fields: dict[str, JsonValue] = {
        "format_version": FORMAT_VERSION,
        "kind": kind,
        "store_id": info.store_id,
        "schema_version": info.schema_version,
        "ledger_high_water": high_water,
        "trust_generation": trust,
        "created_at": utc_timestamp(now),
        "db_digest": file_digest(snapshot),
        "blobs": listed,
    }
    staging = directory / f"{MANIFEST_NAME}.tmp-{new_id()}"
    write_new_file(staging, canonical_json(fields), os_)
    os_.publisher.publish(staging, directory / MANIFEST_NAME)


def create_store_backup(store: "Store", os_: OsAdapters, now: datetime) -> Path:
    """A ``store`` (closure) backup of the open ``store``, taken entirely under ``store.maintenance()``.

    The roots are read from the snapshot itself, so they match the copied database exactly. A failure leaves an
    incomplete backup (no manifest) that never verifies; ``prune_backups`` sets it aside after 24 hours.
    """
    _require_aware(now)
    with store.maintenance():
        root = store.root
        directory = _new_backup_dir(root.backups_dir, "store", now, os_)
        snapshot = directory / _SNAPSHOT_NAME["store"]
        store.snapshot_db(snapshot)
        _secure_snapshot(snapshot, os_)
        crashpoint("backup.after_db_snapshot")
        with _open_snapshot(snapshot) as db:
            roots = _roots(db)
        copy_blobs(root.cas_dir, directory / _CAS, roots, os_)
        crashpoint("backup.after_blob_copy")
        _write_manifest(directory, "store", sorted(roots), now, os_)
    return directory


def create_policy_backup(policy: "PolicyStore", os_: OsAdapters, now: datetime) -> Path:
    """A ``policy`` backup of the open policy store."""
    _require_aware(now)
    directory = _new_backup_dir(policy.root.backups_dir, "policy", now, os_)
    snapshot = directory / _SNAPSHOT_NAME["policy"]
    policy.snapshot_db(snapshot)
    _secure_snapshot(snapshot, os_)
    crashpoint("backup.after_db_snapshot")
    _write_manifest(directory, "policy", (), now, os_)
    return directory


def copy_database(source: Path, dest: Path, purpose: str) -> None:
    """Copy the closed database ``source`` and its ``-wal`` (never the ``-shm``, which SQLite rebuilds) to ``dest``
    and its ``-wal``, so opening the copy writable recovers the WAL into it. ``purpose`` ends the error message."""
    wal = db_files(source)[1]
    try:
        shutil.copyfile(source, dest)
        if os.path.lexists(wal):
            shutil.copyfile(wal, db_files(dest)[1])
    except OSError as err:
        raise os_error(f"cannot copy {source.name} {purpose}", err) from err


def _recover_and_snapshot(source: Path, copy: Path, snapshot: Path, os_: OsAdapters) -> None:
    """``copy_database`` ``source`` to ``copy``, open the copy writable so SQLite recovers the WAL into it, and run
    ``_snapshot_db`` from there; the copy is always closed."""
    copy_database(source, copy, "for a maintenance backup")
    try:
        db = sqlite3.connect(copy, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error(f"cannot open the copy of {source.name}", exc) from exc
    try:
        _snapshot_db(db, snapshot, os_)
    finally:
        db.close()


def _snapshot_closed_db(source: Path, work: Path, snapshot: Path, os_: OsAdapters) -> None:
    """Snapshot the closed database ``source`` without opening it, through a recovered copy in the private
    directory ``work``. ``work`` is removed whether this succeeds or fails; a failure to remove it after another
    failure is attached to that error as a note, never hiding it."""
    new_directory(work, os_)
    try:
        _recover_and_snapshot(source, work / source.name, snapshot, os_)
    except BaseException as err:
        try:
            shutil.rmtree(work)
        except OSError as cleanup:
            err.add_note(f"the work directory {work} could not be removed: {cleanup}")
        raise
    try:
        shutil.rmtree(work)
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot remove the work directory {work.name}: {err}") from err
    os_.publisher.sync_directory(work.parent)


def create_maintenance_backup(
    root: DataRoot, lease: WriterLease, os_: OsAdapters, *, target: Literal["store", "policy"], now: datetime
) -> Path:
    """Back up the closed ``target`` database by path, for migration and maintenance; any schema version works.

    ``target="store"`` makes a ``store_full`` backup (the snapshot and every blob file in ``cas/``),
    ``target="policy"`` a ``policy`` one. An open ``target`` handle is ``STORE_BUSY``. The source files are only
    copied, never opened by SQLite (``_snapshot_closed_db``), so they stay byte-for-byte unchanged, and a WAL left
    by a writer that died is recovered into the snapshot, not ignored.
    """
    if not lease.held or lease.root != root:
        raise AssertionError("a maintenance backup needs a held writer lease for this data root")
    if target not in ("store", "policy"):
        raise BrainError(ErrorCode.INVALID_INPUT, f"unknown backup target {target!r}")
    _require_aware(now)
    if target in lease.open_handles():
        raise BrainError(ErrorCode.STORE_BUSY, f"the {target} database is open; close it before a maintenance backup")
    kind: BackupKind = "store_full" if target == "store" else "policy"
    source = root.store_db if target == "store" else root.policy_db
    if not source.is_file():
        raise BrainError(ErrorCode.NOT_FOUND, f"no {target} database at {source}")
    directory = _new_backup_dir(root.backups_dir, kind, now, os_)
    snapshot = directory / _SNAPSHOT_NAME[kind]
    _snapshot_closed_db(source, directory / f".work-{new_id()}", snapshot, os_)
    _secure_snapshot(snapshot, os_)
    crashpoint("backup.after_db_snapshot")
    blobs: list[str] = []
    if kind == "store_full":
        blobs = sorted(blob_digests(root.cas_dir, os_))
        copy_blobs(root.cas_dir, directory / _CAS, blobs, os_)
        crashpoint("backup.after_blob_copy")
    _write_manifest(directory, kind, blobs, now, os_)
    return directory


# --- verifying ---------------------------------------------------------------------------------------------------


def _load_manifest(path: Path) -> BackupManifest:
    """``manifest.json``, strictly: exactly the manifest fields, well-typed, sorted blobs, canonical bytes."""
    try:
        raw = (path / MANIFEST_NAME).read_bytes()
    except FileNotFoundError as err:
        raise _fail("manifest", f"{path} has no {MANIFEST_NAME}: the backup is incomplete") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read the manifest of {path}: {err}") from err
    try:
        data = json.loads(raw)
    except ValueError as err:
        raise _fail("manifest", "it is not valid JSON") from err
    if not isinstance(data, dict) or sorted(data) != sorted(_FIELDS):
        raise _fail("manifest", f"it must be an object with exactly the fields {sorted(_FIELDS)}")

    def integer(name: str, minimum: int) -> int:
        value = data[name]
        if type(value) is not int or value < minimum:
            raise _fail("manifest", f"{name} must be an integer >= {minimum}")
        return value

    if integer("format_version", FORMAT_VERSION) != FORMAT_VERSION:
        raise _fail("manifest", f"format_version {data['format_version']} is not {FORMAT_VERSION}")
    kind, store_id, created_at = data["kind"], data["store_id"], data["created_at"]
    trust, db_digest, blobs = data["trust_generation"], data["db_digest"], data["blobs"]
    if kind not in _KINDS:
        raise _fail("manifest", f"unknown kind {kind!r}")
    if not isinstance(store_id, str) or not store_id:
        raise _fail("manifest", "store_id must be a non-empty string")
    if kind == "policy" and (type(trust) is not int or trust < 1):
        raise _fail("manifest", "a policy backup's trust_generation must be an integer >= 1")
    if kind != "policy" and trust is not None:
        raise _fail("manifest", "a store backup's trust_generation must be null")
    if not isinstance(created_at, str) or not _TIMESTAMP.fullmatch(created_at):
        raise _fail("manifest", "created_at must be a canonical UTC timestamp")
    if not isinstance(db_digest, str) or not _DIGEST.fullmatch(db_digest):
        raise _fail("manifest", "db_digest must be a sha256 digest")
    if not isinstance(blobs, list) or not all(isinstance(b, str) and _DIGEST.fullmatch(b) for b in blobs):
        raise _fail("manifest", "blobs must be a list of sha256 digests")
    if blobs != sorted(set(blobs)):
        raise _fail("manifest", "blobs must be sorted and unique")
    manifest = BackupManifest(
        format_version=FORMAT_VERSION,
        kind=kind,
        store_id=store_id,
        schema_version=integer("schema_version", 1),
        ledger_high_water=integer("ledger_high_water", 0),
        trust_generation=trust,
        created_at=created_at,
        db_digest=db_digest,
        blobs=tuple(blobs),
        logical_verified=False,
    )
    if canonical_json(data) != raw:
        raise _fail("manifest", "it is not canonical JSON")
    return manifest


def _check_entries(path: Path, kind: BackupKind) -> None:
    """The backup holds the manifest, the snapshot as a regular file, and ``cas/`` for store kinds: nothing else
    (in particular no ``-wal``/``-shm``/``-journal`` next to the snapshot)."""
    allowed = {MANIFEST_NAME, _SNAPSHOT_NAME[kind]} | ({_CAS} if kind != "policy" else set())
    snapshot = path / _SNAPSHOT_NAME[kind]
    try:
        extra = sorted(set(os.listdir(path)) - allowed)
        regular = os.path.lexists(snapshot) and stat.S_ISREG(os.lstat(snapshot).st_mode)
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot list the backup {path}: {err}") from err
    if extra:
        raise _fail("entries", f"unexpected entries {extra}; a snapshot is one file with no companions")
    if not regular:
        raise _fail("db_digest", f"the snapshot {snapshot.name} is missing or not a regular file")


def _blob_files(cas: Path) -> set[str]:
    """Digests of the blob files in the backup's ``cas/``; any other entry there, a link or reparse point included
    (a Windows junction lists as a directory), is ``INTEGRITY_FAILURE`` and is never entered."""
    found: set[str] = set()
    unexpected: list[str] = []
    try:
        if not os.path.lexists(cas):
            return found
        if is_link(os.lstat(cas)) or not stat.S_ISDIR(os.lstat(cas).st_mode):
            raise _fail("blob files", "cas is not a directory")
        with os.scandir(cas) as shards:
            for shard in shards:
                linked = is_link(shard.stat(follow_symlinks=False))
                if linked or not (_SHARD_NAME.fullmatch(shard.name) and shard.is_dir(follow_symlinks=False)):
                    unexpected.append(shard.name)
                    continue
                with os.scandir(shard.path) as blobs:
                    for blob in blobs:
                        if (
                            _BLOB_NAME.fullmatch(blob.name)
                            and blob.name.startswith(shard.name)
                            and blob.is_file(follow_symlinks=False)
                            and not is_link(blob.stat(follow_symlinks=False))
                        ):
                            found.add("sha256:" + blob.name)
                        else:
                            unexpected.append(f"{shard.name}/{blob.name}")
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot list the blobs in {cas}: {err}") from err
    if unexpected:
        raise _fail("blob files", f"unexpected entries in cas/: {sorted(unexpected)}")
    return found


def _check_blob_files(path: Path, listed: tuple[str, ...]) -> None:
    """Physical completeness: the blob files are exactly ``listed``, and each hashes to its name."""
    cas = path / _CAS
    found = _blob_files(cas)
    if found != set(listed):
        missing, unlisted = sorted(set(listed) - found), sorted(found - set(listed))
        raise _fail("blob files", f"missing {missing}, not listed {unlisted}")
    for digest in listed:
        if file_digest(blob_path(cas, digest)) != digest:
            raise _fail("sha256", f"the blob file {digest} does not match its name")


def _readable(info: SchemaInfo, migrations: Sequence[Migration], kind: BackupKind) -> bool:
    """Whether this code can read the snapshot's schema; only ``store_full`` may be unreadable (``False``)."""
    try:
        ensure_readable(info, migrations)
    except BrainError as err:
        if kind != "store_full" or err.code is not ErrorCode.UNSUPPORTED_VERSION:
            raise
        return False
    return True


def verify_backup(
    path: Path,
    *,
    expected_kind: BackupKind | frozenset[str],
    expected_store_id: str,
    migrations: Sequence[Migration],
) -> BackupManifest:
    """Check the backup at ``path`` against its own snapshot and blob files; returns the manifest on success.

    Every inconsistency is ``INTEGRITY_FAILURE`` naming the failed check: a missing or malformed manifest, a kind
    not in ``expected_kind``, unexpected entries, a snapshot whose digest differs from ``db_digest``, a failed
    ``integrity_check``, a ``store_id``/``schema_version``/high-water/trust generation in the manifest that differs
    from the snapshot's, a store id other than ``expected_store_id``, blob files that are not exactly ``blobs`` or
    do not hash to their names, and roots (the snapshot's holders) that are not exactly ``blobs`` (``store``) or not
    a subset of them (``store_full``). A ``store``/``policy`` schema ``migrations`` cannot read is
    ``UNSUPPORTED_VERSION``; for such a ``store_full`` only the physical facts and ``meta`` are checked and
    ``logical_verified`` is ``False``.
    """
    expected = frozenset({expected_kind}) if isinstance(expected_kind, str) else expected_kind
    manifest = _load_manifest(path)
    if manifest.kind not in expected:
        raise _fail("kind", f"the backup is {manifest.kind!r}, expected {sorted(expected)}")
    _check_entries(path, manifest.kind)
    snapshot = path / _SNAPSHOT_NAME[manifest.kind]
    if file_digest(snapshot) != manifest.db_digest:
        raise _fail("db_digest", f"the snapshot {snapshot.name} does not match the manifest's db_digest")
    info = _schema_info(snapshot)
    readable = _readable(info, migrations, manifest.kind)
    store_kind = manifest.kind != "policy"
    derived: dict[str, object] = {"store_id": info.store_id, "schema_version": info.schema_version}
    roots: frozenset[str] = frozenset()
    with _open_snapshot(snapshot) as db:
        _integrity(db)
        if readable:
            derived["ledger_high_water"] = _high_water(db) if store_kind else 0
            derived["trust_generation"] = None if store_kind else _trust_generation(db)
            roots = _roots(db) if store_kind else frozenset()
    for name, value in derived.items():
        if getattr(manifest, name) != value:
            raise _fail(name, f"the manifest says {getattr(manifest, name)!r}, the snapshot {value!r}")
    if info.store_id != expected_store_id:
        raise _fail("store_id", f"the backup belongs to store {info.store_id!r}, expected {expected_store_id!r}")
    _check_blob_files(path, manifest.blobs)
    if readable and manifest.kind == "store" and roots != set(manifest.blobs):
        raise _fail("roots", f"the snapshot's roots {sorted(roots)} are not exactly the listed blobs")
    if readable and manifest.kind == "store_full" and not roots <= set(manifest.blobs):
        raise _fail("roots", f"the snapshot's roots {sorted(roots - set(manifest.blobs))} are not in the backup")
    return replace(manifest, logical_verified=readable)
