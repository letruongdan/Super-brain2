"""Read-only verification of a store/policy backup directory against its manifest."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.storage import cas
from superbrain.storage.cas import blob_path, file_digest, is_link
from superbrain.storage.prune import MANIFEST_NAME
from superbrain.storage.schema import Migration, SchemaInfo, ensure_readable

if TYPE_CHECKING:
    pass
from superbrain.storage import backup as _m


def _load_manifest(path: Path) -> _m.BackupManifest:
    """``manifest.json``, strictly: exactly the manifest fields, well-typed, sorted blobs, canonical bytes."""
    try:
        raw = (path / MANIFEST_NAME).read_bytes()
    except FileNotFoundError as err:
        raise _m._fail("manifest", f"{path} has no {MANIFEST_NAME}: the backup is incomplete") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read the manifest of {path}: {err}") from err
    try:
        data = json.loads(raw)
    except ValueError as err:
        raise _m._fail("manifest", "it is not valid JSON") from err
    if not isinstance(data, dict) or sorted(data) != sorted(_m._FIELDS):
        raise _m._fail("manifest", f"it must be an object with exactly the fields {sorted(_m._FIELDS)}")

    def integer(name: str, minimum: int) -> int:
        value = data[name]
        if type(value) is not int or value < minimum:
            raise _m._fail("manifest", f"{name} must be an integer >= {minimum}")
        return value

    if integer("format_version", _m.FORMAT_VERSION) != _m.FORMAT_VERSION:
        raise _m._fail("manifest", f"format_version {data['format_version']} is not {_m.FORMAT_VERSION}")
    kind, store_id, created_at = data["kind"], data["store_id"], data["created_at"]
    trust, db_digest, blobs = data["trust_generation"], data["db_digest"], data["blobs"]
    if kind not in _m._KINDS:
        raise _m._fail("manifest", f"unknown kind {kind!r}")
    if not isinstance(store_id, str) or not store_id:
        raise _m._fail("manifest", "store_id must be a non-empty string")
    if kind == "policy" and (type(trust) is not int or trust < 1):
        raise _m._fail("manifest", "a policy backup's trust_generation must be an integer >= 1")
    if kind != "policy" and trust is not None:
        raise _m._fail("manifest", "a store backup's trust_generation must be null")
    if not isinstance(created_at, str) or not _m._TIMESTAMP.fullmatch(created_at):
        raise _m._fail("manifest", "created_at must be a canonical UTC timestamp")
    if not isinstance(db_digest, str) or not _m._DIGEST.fullmatch(db_digest):
        raise _m._fail("manifest", "db_digest must be a sha256 digest")
    if not isinstance(blobs, list) or not all(isinstance(b, str) and _m._DIGEST.fullmatch(b) for b in blobs):
        raise _m._fail("manifest", "blobs must be a list of sha256 digests")
    if blobs != sorted(set(blobs)):
        raise _m._fail("manifest", "blobs must be sorted and unique")
    manifest = _m.BackupManifest(
        format_version=_m.FORMAT_VERSION,
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
        raise _m._fail("manifest", "it is not canonical JSON")
    return manifest


def _check_entries(path: Path, kind: _m.BackupKind) -> None:
    """The backup holds the manifest, the snapshot as a regular file, and ``cas/`` for store kinds: nothing else
    (in particular no ``-wal``/``-shm``/``-journal`` next to the snapshot)."""
    allowed = {MANIFEST_NAME, _m._SNAPSHOT_NAME[kind]} | ({_m._CAS} if kind != "policy" else set())
    snapshot = path / _m._SNAPSHOT_NAME[kind]
    try:
        extra = sorted(set(os.listdir(path)) - allowed)
        regular = os.path.lexists(snapshot) and stat.S_ISREG(os.lstat(snapshot).st_mode)
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot list the backup {path}: {err}") from err
    if extra:
        raise _m._fail("entries", f"unexpected entries {extra}; a snapshot is one file with no companions")
    if not regular:
        raise _m._fail("db_digest", f"the snapshot {snapshot.name} is missing or not a regular file")


def _blob_files(cas: Path) -> set[str]:
    """Digests of the blob files in the backup's ``cas/``; any other entry there, a link or reparse point included
    (a Windows junction lists as a directory), is ``INTEGRITY_FAILURE`` and is never entered."""
    found: set[str] = set()
    unexpected: list[str] = []
    try:
        if not os.path.lexists(cas):
            return found
        if is_link(os.lstat(cas)) or not stat.S_ISDIR(os.lstat(cas).st_mode):
            raise _m._fail("blob files", "cas is not a directory")
        with os.scandir(cas) as shards:
            for shard in shards:
                linked = is_link(shard.stat(follow_symlinks=False))
                if linked or not (_m._SHARD_NAME.fullmatch(shard.name) and shard.is_dir(follow_symlinks=False)):
                    unexpected.append(shard.name)
                    continue
                with os.scandir(shard.path) as blobs:
                    for blob in blobs:
                        if (
                            _m._BLOB_NAME.fullmatch(blob.name)
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
        raise _m._fail("blob files", f"unexpected entries in cas/: {sorted(unexpected)}")
    return found


def _check_blob_files(path: Path, listed: tuple[str, ...]) -> None:
    """Physical completeness: the blob files are exactly ``listed``, and each hashes to its name."""
    cas = path / _m._CAS
    found = _blob_files(cas)
    if found != set(listed):
        missing, unlisted = sorted(set(listed) - found), sorted(found - set(listed))
        raise _m._fail("blob files", f"missing {missing}, not listed {unlisted}")
    for digest in listed:
        if file_digest(blob_path(cas, digest)) != digest:
            raise _m._fail("sha256", f"the blob file {digest} does not match its name")


def _readable(info: SchemaInfo, migrations: Sequence[Migration], kind: _m.BackupKind) -> bool:
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
    expected_kind: _m.BackupKind | frozenset[str],
    expected_store_id: str,
    migrations: Sequence[Migration],
    os_: OsAdapters,
) -> _m.BackupManifest:
    """Check the backup at ``path`` against its own snapshot and blob files; returns the manifest on success.

    Every inconsistency is ``INTEGRITY_FAILURE`` naming the failed check: a missing or malformed manifest, a kind
    not in ``expected_kind``, unexpected entries, a snapshot whose digest differs from ``db_digest``, a failed
    ``integrity_check``, a ``store_id``/``schema_version``/high-water/trust generation in the manifest that differs
    from the snapshot's, a store id other than ``expected_store_id``, blob files that are not exactly ``blobs`` or
    do not hash to their names, and roots (the snapshot's holders) that are not exactly ``blobs`` (``store``) or not
    a subset of them (``store_full``). A ``store``/``policy`` schema ``migrations`` cannot read is
    ``UNSUPPORTED_VERSION``; for such a ``store_full`` only the physical facts and ``meta`` are checked and
    ``logical_verified`` is ``False``. First, before anything is read, every file and directory of the backup must
    pass ``cas.check_backup_tree`` with ``os_`` (owner-only, no link: ``INSECURE_PERMISSIONS``/``UNSAFE_PATH``).
    """
    cas.check_backup_tree(path, os_)
    expected = frozenset({expected_kind}) if isinstance(expected_kind, str) else expected_kind
    manifest = _load_manifest(path)
    if manifest.kind not in expected:
        raise _m._fail("kind", f"the backup is {manifest.kind!r}, expected {sorted(expected)}")
    _check_entries(path, manifest.kind)
    snapshot = path / _m._SNAPSHOT_NAME[manifest.kind]
    if file_digest(snapshot) != manifest.db_digest:
        raise _m._fail("db_digest", f"the snapshot {snapshot.name} does not match the manifest's db_digest")
    info = _m._schema_info(snapshot)
    readable = _readable(info, migrations, manifest.kind)
    store_kind = manifest.kind != "policy"
    derived: dict[str, object] = {"store_id": info.store_id, "schema_version": info.schema_version}
    roots: frozenset[str] = frozenset()
    with _m._open_snapshot(snapshot) as db:
        _m._integrity(db)
        if readable:
            derived["ledger_high_water"] = _m._high_water(db) if store_kind else 0
            derived["trust_generation"] = None if store_kind else _m._trust_generation(db)
            roots = _m._roots(db) if store_kind else frozenset()
    for name, value in derived.items():
        if getattr(manifest, name) != value:
            raise _m._fail(name, f"the manifest says {getattr(manifest, name)!r}, the snapshot {value!r}")
    if info.store_id != expected_store_id:
        raise _m._fail("store_id", f"the backup belongs to store {info.store_id!r}, expected {expected_store_id!r}")
    _check_blob_files(path, manifest.blobs)
    if readable and manifest.kind == "store" and roots != set(manifest.blobs):
        raise _m._fail("roots", f"the snapshot's roots {sorted(roots)} are not exactly the listed blobs")
    if readable and manifest.kind == "store_full" and not roots <= set(manifest.blobs):
        raise _m._fail("roots", f"the snapshot's roots {sorted(roots - set(manifest.blobs))} are not in the backup")
    return replace(manifest, logical_verified=readable)
