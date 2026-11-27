"""256-bucket sharded durable dedup binding storage for hook outbox streams (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import (
    CaptureEventRecord,
    OutboxDirRenamer,
    OutboxPermissionsPort,
    require_capture_sequence,
    require_iso_utc_timestamp,
)
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    active_deadline_check,
    ensure_dir_tree_atomic,
    entry_is_link,
    is_link_path,
    replace_file_resilient,
    sync_dir,
    unlink_before_deadline,
    verify_owner_only,
    write_all_fd,
)

_BINDINGS_DIR = ".bindings"
_BINDINGS_SCHEMA_VERSION = 3
_MAX_BUCKET_BYTES = 262_144
DEFAULT_MAX_STREAM_BINDING_KEYS = 65_536


@dataclass(frozen=True)
class HookBindingRecord:
    """Immutable durable dedup binding entry mapping an opaque ``dedup_key`` to its bound event slot."""

    key: str
    sequence: int
    event_id: str
    recorded_at: str
    payload_digest: str | None = None


def bucket_name_for_key(dedup_key: str) -> str:
    """Return deterministic two-hex-digit bucket filename for a validated ``sha256:...`` dedup key."""
    require_sha256_digest(dedup_key)
    return f"{dedup_key[7:9]}.json"


def _verify_bindings_dir_node(stream_dir: Path, perms: OutboxPermissionsPort) -> Path | None:
    """Verify ``stream_dir`` and ``.bindings`` node are non-link, typed, and owner-only without full scan."""
    if os.path.lexists(stream_dir) and is_link_path(stream_dir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
    bdir = stream_dir / _BINDINGS_DIR
    if not os.path.lexists(bdir):
        return None
    if is_link_path(bdir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "bindings directory is a link")
    if not stat.S_ISDIR(os.lstat(bdir).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "bindings path is not a directory")
    verify_owner_only(bdir, perms)
    return bdir


def verify_bindings_dir(stream_dir: Path, perms: OutboxPermissionsPort) -> Path | None:
    """Verify ``.bindings`` directory inside ``stream_dir`` is safe and owner-only, sweeping ``.part`` files."""
    bdir = _verify_bindings_dir_node(stream_dir, perms)
    if bdir is None:
        return None
    with os.scandir(bdir) as it:
        for entry in it:
            if entry_is_link(entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "binding bucket is a link")
            if entry.name.endswith(_PART_SUFFIX):
                unlink_before_deadline(Path(entry.path))
    return bdir


def parse_binding_row(row: object) -> HookBindingRecord:
    """Validate and decode a serialized 5-element binding row."""
    if (
        not isinstance(row, list)
        or len(row) != 5
        or not isinstance(row[0], str)
        or not isinstance(row[2], str)
        or not row[2]
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt hook binding entry")
    try:
        key = require_sha256_digest(row[0])
    except BrainError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt hook binding key") from err
    seq = require_capture_sequence(row[1])
    rec_at = require_iso_utc_timestamp(row[3])
    digest_val = row[4]
    if digest_val is not None:
        if not isinstance(digest_val, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt hook binding digest")
        try:
            require_sha256_digest(digest_val)
        except BrainError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt hook binding digest") from err
    return HookBindingRecord(key, seq, row[2], rec_at, digest_val)


def read_binding_bucket(
    stream_dir: Path, bucket_name: str, perms: OutboxPermissionsPort
) -> dict[str, HookBindingRecord]:
    """Load and validate one shard file ``.bindings/<bucket_name>``."""
    bdir = _verify_bindings_dir_node(stream_dir, perms)
    if bdir is None:
        return {}
    path = bdir / bucket_name
    if not os.path.lexists(path):
        return {}
    if is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "binding bucket is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "binding bucket is not a regular file")
    verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    try:
        raw_bytes = os.read(fd, _MAX_BUCKET_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw_bytes) > _MAX_BUCKET_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "binding bucket exceeds size bound")
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt binding bucket") from err
    if (
        not isinstance(obj, dict)
        or type(obj.get("schema_version")) is not int
        or obj.get("schema_version") != _BINDINGS_SCHEMA_VERSION
        or not isinstance(obj.get("entries"), list)
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt binding bucket schema")
    out: dict[str, HookBindingRecord] = {}
    for row in obj["entries"]:
        rec = parse_binding_row(row)
        if bucket_name_for_key(rec.key) != bucket_name or rec.key in out:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt binding bucket entry key")
        out[rec.key] = rec
    return out


def count_all_bindings(stream_dir: Path, perms: OutboxPermissionsPort) -> int:
    """Count distinct durable bindings across every ``.bindings/*.json`` shard in ``stream_dir``."""
    bdir = verify_bindings_dir(stream_dir, perms)
    if bdir is None:
        return 0
    total = 0
    with os.scandir(bdir) as it:
        for entry in it:
            if entry.name.endswith(".json"):
                total += len(read_binding_bucket(stream_dir, entry.name, perms))
    return total


def lookup_binding(stream_dir: Path, dedup_key: str, perms: OutboxPermissionsPort) -> HookBindingRecord | None:
    """Look up ``dedup_key`` in its 256-way sharded bucket without loading sibling buckets."""
    rec, _bucket, _entries = lookup_binding_with_bucket(stream_dir, dedup_key, perms)
    return rec


def lookup_binding_with_bucket(
    stream_dir: Path, dedup_key: str, perms: OutboxPermissionsPort
) -> tuple[HookBindingRecord | None, str, dict[str, HookBindingRecord]]:
    """Look up ``dedup_key`` and return ``(record_or_none, bucket_name, bucket_entries)``."""
    bucket = bucket_name_for_key(dedup_key)
    entries = read_binding_bucket(stream_dir, bucket, perms)
    return entries.get(dedup_key), bucket, entries


def _merge_binding(entries: dict[str, HookBindingRecord], binding: HookBindingRecord) -> tuple[bool, bool]:
    """Apply upsert semantics in memory and return ``(changed, added)``; a conflicting slot raises."""
    existing = entries.get(binding.key)
    if existing is None:
        entries[binding.key] = binding
        return True, True
    if existing.sequence != binding.sequence or existing.event_id != binding.event_id:
        raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
    if None not in (existing.payload_digest, binding.payload_digest) and (
        existing.payload_digest != binding.payload_digest
    ):
        raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
    if existing.payload_digest is None and binding.payload_digest is not None:
        entries[binding.key] = HookBindingRecord(
            existing.key, existing.sequence, existing.event_id, existing.recorded_at, binding.payload_digest
        )
        return True, False
    return False, False


def _serialize_bucket(entries: dict[str, HookBindingRecord]) -> bytes:
    rows = [[e.key, e.sequence, e.event_id, e.recorded_at, e.payload_digest] for _k, e in sorted(entries.items())]
    payload = canonical_json({"schema_version": _BINDINGS_SCHEMA_VERSION, "entries": rows})
    if len(payload) > _MAX_BUCKET_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook dedup binding bucket full")
    return payload


def project_recovered_buckets(
    stream_dir: Path, items: Sequence[HookBindingRecord], perms: OutboxPermissionsPort
) -> dict[str, dict[str, HookBindingRecord]]:
    """Read-only: each bucket as recovery will publish it after flushing ``items`` in order (size-checked)."""
    projected: dict[str, dict[str, HookBindingRecord]] = {}
    for item in items:
        name = bucket_name_for_key(item.key)
        if name not in projected:
            projected[name] = read_binding_bucket(stream_dir, name, perms)
        if _merge_binding(projected[name], item)[0]:
            _serialize_bucket(projected[name])
    return projected


def prepare_binding_upsert(
    stream_dir: Path,
    binding: HookBindingRecord,
    perms: OutboxPermissionsPort,
    *,
    preloaded_entries: dict[str, HookBindingRecord] | None = None,
) -> tuple[str, bytes | None, bool]:
    """Validate conflicts and bucket capacity read-only; return ``(bucket, payload_or_none, added)``."""
    bucket_name = bucket_name_for_key(binding.key)
    entries = (
        dict(preloaded_entries)
        if preloaded_entries is not None
        else read_binding_bucket(stream_dir, bucket_name, perms)
    )
    changed, added = _merge_binding(entries, binding)
    return bucket_name, (_serialize_bucket(entries) if changed else None), added


def write_prepared_binding_bucket(
    stream_dir: Path,
    bucket_name: str,
    payload: bytes,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Persist validated ``payload`` atomically into ``.bindings/<bucket_name>``."""
    bdir = _verify_bindings_dir_node(stream_dir, perms)
    if bdir is None:
        bdir = stream_dir / _BINDINGS_DIR
        ensure_dir_tree_atomic(bdir, perms, renamer, check_deadline=check_deadline)
    final_path = bdir / bucket_name
    tmp_path = bdir / f".bucket-{uuid.uuid4().hex}{_PART_SUFFIX}"
    fd = -1
    committed = False
    try:
        fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
        write_all_fd(fd, payload)
        perms.secure_file(tmp_path)
        dl = check_deadline or active_deadline_check()
        if dl is not None:
            dl()
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if dl is not None:
            dl()
        replace_file_resilient(tmp_path, final_path)
        sync_dir(bdir)
        committed = True
    except BrainError:
        raise
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot write hook binding bucket: {err}") from err
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if not committed:
            tmp_path.unlink(missing_ok=True)


def upsert_binding(
    stream_dir: Path,
    binding: HookBindingRecord,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> bool:
    """Persist ``binding`` atomically in its shard file; returns ``True`` if a new key was added."""
    bucket_name, payload, added = prepare_binding_upsert(stream_dir, binding, perms)
    if payload is not None:
        write_prepared_binding_bucket(
            stream_dir, bucket_name, payload, perms, renamer=renamer, check_deadline=check_deadline
        )
    return added


def backfill_binding_digest_if_missing(
    stream_dir: Path,
    cached: HookBindingRecord | None,
    payload_digest: str,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None,
) -> None:
    """Backfill ``payload_digest`` on a v1-migrated binding when first observed on retry."""
    if cached is None or cached.payload_digest is not None:
        return
    updated = HookBindingRecord(cached.key, cached.sequence, cached.event_id, cached.recorded_at, payload_digest)
    upsert_binding(stream_dir, updated, perms, renamer=renamer, check_deadline=check_deadline)


def prepare_hook_binding_upsert(
    stream_dir: Path,
    *,
    dedup_key: str | None,
    record: CaptureEventRecord,
    payload_digest: str,
    perms: OutboxPermissionsPort,
    preloaded_entries: dict[str, HookBindingRecord] | None = None,
) -> tuple[HookBindingRecord, str, bytes | None, bool] | None:
    """Validate and serialize sharded binding update before mutating cursor state."""
    if dedup_key is None:
        return None
    binding = HookBindingRecord(dedup_key, record.sequence, record.event_id, record.recorded_at, payload_digest)
    bucket_name, payload, added = prepare_binding_upsert(
        stream_dir, binding, perms, preloaded_entries=preloaded_entries
    )
    return binding, bucket_name, payload, added
