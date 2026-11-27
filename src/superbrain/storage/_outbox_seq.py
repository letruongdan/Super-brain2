"""Crash-safe per-stream outbox sequence cursor with lossless sharded dedup binding support (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    MAX_CAPTURE_ENTRY_BYTES,
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxDirRenamer,
    OutboxPermissionsPort,
    default_outbox_dir_renamer,
    require_capture_sequence,
    require_iso_utc_timestamp,
)
from superbrain.storage._outbox_acks import (
    compute_updated_acks,
    is_seq_acked_in_pages,
    prune_obsolete_ack_pages,
    read_ack_pages,
    write_ack_pages,
)
from superbrain.storage._outbox_bindings import (
    HookBindingRecord,
    count_all_bindings,
    lookup_binding_with_bucket,
    parse_binding_row,
    prepare_binding_upsert,
    upsert_binding,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    _STREAMS_DIR,
    is_link_path,
    parse_frame_filename_identity,
    replace_file_resilient,
    sync_dir,
    verify_owner_only,
    write_all_fd,
)

_ACKS_SUBDIR = ".acks"
_CURSOR_FILENAME = ".seq_cursor.json"
_CURSOR_V3_SCHEMA_VERSION = 3
_CURSOR_V4_SCHEMA_VERSION = 4
_MAX_CURSOR_BYTES = 262_144
_LEGACY_STATES: frozenset[str] = frozenset({"bound", "published", "acked"})


def merge_acked_ranges(
    existing: Iterable[tuple[int, int]],
    extra: Iterable[tuple[int, int]] = (),
) -> tuple[tuple[int, int], ...]:
    """Normalize and merge closed integer intervals ``(lo, hi)`` in ascending order."""
    intervals: list[tuple[int, int]] = []
    for lo, hi in (*existing, *extra):
        if lo <= hi and lo >= 1:
            intervals.append((lo, hi))
    if not intervals:
        return ()
    intervals.sort()
    merged: list[tuple[int, int]] = [intervals[0]]
    for lo, hi in intervals[1:]:
        prev_lo, prev_hi = merged[-1]
        if prev_hi + 1 >= lo:
            merged[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def _split_contig_and_sparse(ranges: tuple[tuple[int, int], ...]) -> tuple[int, tuple[tuple[int, int], ...]]:
    if ranges and ranges[0][0] == 1:
        return ranges[0][1], ranges[1:]
    return 0, ranges


@dataclass(frozen=True)
class StreamSeqCursor:
    """Durable per-stream monotonic sequence cursor persisted atomically inside stream directory."""

    next_seq: int
    binding_count: int = 0
    acked_ranges: tuple[tuple[int, int], ...] = ()
    pending_binding: HookBindingRecord | None = None
    legacy_recent: tuple[HookBindingRecord, ...] = ()
    contiguous_acked_through: int = 0
    acked_pages: tuple[tuple[int, bytes], ...] = ()
    legacy_acked_ranges: tuple[tuple[int, int], ...] = ()
    schema_v4: bool = False

    def is_event_acked(self, sequence: int) -> bool:
        """Return ``True`` if ``sequence`` has been committed by an event ACK."""
        if sequence <= self.contiguous_acked_through:
            return True
        if any(lo <= sequence <= hi for lo, hi in (*self.acked_ranges, *self.legacy_acked_ranges)):
            return True
        return is_seq_acked_in_pages(sequence, self.acked_pages)

    def with_binding_state(
        self,
        *,
        next_seq: int | None = None,
        binding_count: int | None = None,
        pending_binding: HookBindingRecord | None = None,
    ) -> StreamSeqCursor:
        """Return updated cursor preserving ACK watermark, sparse pages, and schema version state."""
        return StreamSeqCursor(
            next_seq=self.next_seq if next_seq is None else next_seq,
            binding_count=self.binding_count if binding_count is None else binding_count,
            acked_ranges=self.acked_ranges,
            pending_binding=pending_binding,
            legacy_recent=self.legacy_recent,
            contiguous_acked_through=self.contiguous_acked_through,
            acked_pages=self.acked_pages,
            legacy_acked_ranges=self.legacy_acked_ranges,
            schema_v4=self.schema_v4,
        )

    def mark_acked(self, ack: CaptureBatchAck) -> StreamSeqCursor:
        """Compute updated ACK watermark and sparse bitset pages for ``ack``."""
        acked, _obsolete, _dirty = _apply_ack_update(self, ack)
        return acked

    def bump_next_seq(self, sequence: int) -> StreamSeqCursor:
        """Ensure ``next_seq > sequence`` without disturbing bindings or ACK state."""
        if self.next_seq > sequence:
            return self
        return self.with_binding_state(next_seq=sequence + 1, pending_binding=self.pending_binding)


def cursor_exists(stream_dir: Path) -> bool:
    """Return ``True`` when ``.seq_cursor.json`` exists (including as a link) inside ``stream_dir``."""
    return os.path.lexists(stream_dir / _CURSOR_FILENAME)


def _parse_legacy_cursor(obj: dict[str, object], *, schema_ver: int, next_seq: int) -> StreamSeqCursor:
    raw_recent = obj.get("recent", [])
    if not isinstance(raw_recent, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor recent list")
    expected_len = 4 if schema_ver == 1 else 6
    parsed: list[HookBindingRecord] = []
    acked_pts: list[tuple[int, int]] = []
    for row in raw_recent:
        if (
            not isinstance(row, list)
            or len(row) != expected_len
            or not isinstance(row[0], str)
            or not isinstance(row[2], str)
            or not row[2]
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor entry")
        key = require_sha256_digest(row[0])
        seq, rec_at = require_capture_sequence(row[1]), require_iso_utc_timestamp(row[3])
        digest_val: str | None = None
        if schema_ver == 2:
            state_val = row[4]
            if not isinstance(state_val, str) or state_val not in _LEGACY_STATES:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor state")
            if row[5] is not None:
                if not isinstance(row[5], str):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor digest")
                digest_val = require_sha256_digest(row[5])
            if state_val == "acked":
                acked_pts.append((seq, seq))
        parsed.append(HookBindingRecord(key, seq, row[2], rec_at, digest_val))
    contig, sparse = _split_contig_and_sparse(merge_acked_ranges(acked_pts))
    return StreamSeqCursor(
        next_seq=next_seq, binding_count=len({rec.key for rec in parsed}),
        legacy_recent=tuple(parsed), contiguous_acked_through=contig,
        legacy_acked_ranges=sparse, schema_v4=bool(sparse),
    )


def _needs_cursor_recovery(cursor: StreamSeqCursor) -> bool:
    return bool(cursor.legacy_recent or cursor.legacy_acked_ranges or cursor.pending_binding is not None)


def read_stream_cursor(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Load and validate ``.seq_cursor.json`` (v1, v2, v3, or v4) and ``.acks`` inside ``stream_dir``."""
    path = stream_dir / _CURSOR_FILENAME
    has_acks_dir = os.path.lexists(stream_dir / _ACKS_SUBDIR)
    if not os.path.lexists(path):
        if has_acks_dir:
            read_ack_pages(stream_dir, perms)
        return StreamSeqCursor(next_seq=1)
    if is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream cursor is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream cursor is not a regular file")
    verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    try:
        raw_bytes = os.read(fd, _MAX_CURSOR_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw_bytes) > _MAX_CURSOR_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream cursor exceeds size bound")
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor") from err
    if not isinstance(obj, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor")
    schema_ver = obj.get("schema_version")
    if type(schema_ver) is not int or schema_ver not in (1, 2, _CURSOR_V3_SCHEMA_VERSION, _CURSOR_V4_SCHEMA_VERSION):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
    next_seq = require_capture_sequence(obj.get("next_seq"))
    if schema_ver in (1, 2):
        legacy_c = _parse_legacy_cursor(obj, schema_ver=schema_ver, next_seq=next_seq)
        pages = read_ack_pages(stream_dir, perms) if has_acks_dir else ()
        return StreamSeqCursor(
            next_seq=legacy_c.next_seq, binding_count=legacy_c.binding_count, legacy_recent=legacy_c.legacy_recent,
            contiguous_acked_through=legacy_c.contiguous_acked_through, acked_pages=pages,
            legacy_acked_ranges=legacy_c.legacy_acked_ranges, schema_v4=legacy_c.schema_v4 or bool(pages),
        )
    binding_count = obj.get("binding_count", 0)
    if type(binding_count) is not int or binding_count < 0:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor binding_count")
    raw_pending = obj.get("pending_binding")
    pending = parse_binding_row(raw_pending) if raw_pending is not None else None
    if schema_ver == _CURSOR_V4_SCHEMA_VERSION:
        raw_contig = obj.get("contiguous_acked_through")
        if "acked_ranges" in obj or type(raw_contig) is not int or raw_contig < 0:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
        pages = read_ack_pages(stream_dir, perms)
        return StreamSeqCursor(
            next_seq=next_seq, binding_count=binding_count, pending_binding=pending,
            contiguous_acked_through=raw_contig, acked_pages=pages, schema_v4=True,
        )
    raw_ranges = obj.get("acked_ranges", [])
    if not isinstance(raw_ranges, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor acked_ranges")
    parsed_ranges: list[tuple[int, int]] = []
    for rng in raw_ranges:
        if not isinstance(rng, list) or len(rng) != 2:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor range")
        lo, hi = require_capture_sequence(rng[0]), require_capture_sequence(rng[1])
        if lo > hi:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor range order")
        parsed_ranges.append((lo, hi))
    contig, sparse = _split_contig_and_sparse(merge_acked_ranges(parsed_ranges))
    pages = read_ack_pages(stream_dir, perms) if has_acks_dir else ()
    return StreamSeqCursor(
        next_seq=next_seq, binding_count=binding_count, pending_binding=pending,
        contiguous_acked_through=contig, acked_pages=pages,
        legacy_acked_ranges=sparse, schema_v4=bool(sparse or pages),
    )


def verify_stream_dir_safe(stream_dir: Path, perms: OutboxPermissionsPort) -> bool:
    """Verify ``stream_dir`` (and ``.streams`` parent if present) are safe non-link dirs; return exists."""
    parent = stream_dir.parent
    if os.path.lexists(parent):
        if is_link_path(parent):
            raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
        if not stat.S_ISDIR(os.lstat(parent).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams entry is not a directory")
        if parent.name == _STREAMS_DIR:
            verify_owner_only(parent, perms)
    if not os.path.lexists(stream_dir):
        return False
    if is_link_path(stream_dir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
    if not stat.S_ISDIR(os.lstat(stream_dir).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream entry is not a directory")
    verify_owner_only(stream_dir, perms)
    return True


def _persist_cursor_payload(stream_dir: Path, payload: bytes, perms: OutboxPermissionsPort) -> None:
    if len(payload) > _MAX_CURSOR_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "stream cursor exceeds size bound")
    final_path = stream_dir / _CURSOR_FILENAME
    tmp_path = stream_dir / f".cursor-{uuid.uuid4().hex}{_PART_SUFFIX}"
    fd = -1
    committed = False
    try:
        fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
        write_all_fd(fd, payload)
        perms.secure_file(tmp_path)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        replace_file_resilient(tmp_path, final_path)
        sync_dir(stream_dir)
        committed = True
    except BrainError:
        raise
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot write stream cursor: {err}") from err
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if not committed:
            tmp_path.unlink(missing_ok=True)


def write_stream_cursor(stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort) -> None:
    """Persist v3/v4 ``cursor`` atomically inside ``stream_dir`` enforcing ``_MAX_CURSOR_BYTES``."""
    if cursor.legacy_recent or cursor.legacy_acked_ranges or cursor.acked_ranges:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unflushed legacy cursor state")
    pb = cursor.pending_binding
    pending_row: JsonValue = (
        [pb.key, pb.sequence, pb.event_id, pb.recorded_at, pb.payload_digest] if pb is not None else None
    )
    if cursor.schema_v4 or cursor.acked_pages:
        body: dict[str, JsonValue] = {
            "schema_version": _CURSOR_V4_SCHEMA_VERSION, "next_seq": cursor.next_seq,
            "binding_count": cursor.binding_count, "contiguous_acked_through": cursor.contiguous_acked_through,
            "pending_binding": pending_row,
        }
    else:
        contig = cursor.contiguous_acked_through
        body = {
            "schema_version": _CURSOR_V3_SCHEMA_VERSION, "next_seq": cursor.next_seq,
            "binding_count": cursor.binding_count, "acked_ranges": [[1, contig]] if contig > 0 else [],
            "pending_binding": pending_row,
        }
    _persist_cursor_payload(stream_dir, canonical_json(body), perms)


def recover_stream_cursor(
    stream_dir: Path,
    cursor: StreamSeqCursor,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> StreamSeqCursor:
    """Flush any in-flight ``pending_binding``, ``legacy_recent``, or ``legacy_acked_ranges``."""
    if not _needs_cursor_recovery(cursor):
        return cursor
    if cursor.legacy_recent or cursor.pending_binding is not None:
        for item in cursor.legacy_recent:
            upsert_binding(stream_dir, item, perms, renamer=renamer, check_deadline=check_deadline)
        if cursor.pending_binding is not None:
            upsert_binding(stream_dir, cursor.pending_binding, perms, renamer=renamer, check_deadline=check_deadline)
        count = count_all_bindings(stream_dir, perms)
    else:
        count = cursor.binding_count
    contig, pages, obsolete, dirty = compute_updated_acks(
        contiguous_acked_through=cursor.contiguous_acked_through,
        existing_pages=cursor.acked_pages,
        extra_ranges=cursor.legacy_acked_ranges,
    )
    if dirty:
        write_ack_pages(stream_dir, dirty, perms, renamer=renamer, check_deadline=check_deadline)
    recovered = StreamSeqCursor(
        next_seq=cursor.next_seq, binding_count=count,
        contiguous_acked_through=contig, acked_pages=pages,
        schema_v4=cursor.schema_v4 or bool(pages) or bool(cursor.legacy_acked_ranges),
    )
    write_stream_cursor(stream_dir, recovered, perms)
    if obsolete:
        prune_obsolete_ack_pages(stream_dir, obsolete, perms)
    return recovered


def lookup_stream_binding_with_bucket(
    stream_dir: Path, cursor: StreamSeqCursor, dedup_key: str, perms: OutboxPermissionsPort
) -> tuple[HookBindingRecord | None, str | None, dict[str, HookBindingRecord] | None]:
    """Look up ``dedup_key`` in pending/legacy state or sharded bucket, returning loaded bucket."""
    if cursor.pending_binding is not None and cursor.pending_binding.key == dedup_key:
        return cursor.pending_binding, None, None
    for item in cursor.legacy_recent:
        if item.key == dedup_key:
            return item, None, None
    if not os.path.lexists(stream_dir):
        return None, None, None
    return lookup_binding_with_bucket(stream_dir, dedup_key, perms)


def lookup_stream_binding(
    stream_dir: Path, cursor: StreamSeqCursor, dedup_key: str, perms: OutboxPermissionsPort
) -> HookBindingRecord | None:
    """Look up ``dedup_key`` in pending/legacy cursor state first, then in sharded ``.bindings``."""
    rec, _b, _entries = lookup_stream_binding_with_bucket(stream_dir, cursor, dedup_key, perms)
    return rec


def _apply_ack_update(
    cur: StreamSeqCursor, ack: CaptureBatchAck
) -> tuple[StreamSeqCursor, tuple[int, ...], dict[int, bytes]]:
    ev_max = (max(ack.committed_event_sequences) + 1) if ack.committed_event_sequences else 1
    gap_max = (max(ack.acked_producer_gap_sequences) + 1) if ack.acked_producer_gap_sequences else 1
    next_val = max(cur.next_seq, ack.contiguous_event_acked_through + 1, ev_max, gap_max)
    contig, pages, obsolete, dirty = compute_updated_acks(
        contiguous_acked_through=cur.contiguous_acked_through, existing_pages=cur.acked_pages,
        extra_sequences=ack.committed_event_sequences, floor_contiguous=ack.contiguous_event_acked_through,
    )
    acked = StreamSeqCursor(
        next_seq=next_val, binding_count=cur.binding_count,
        contiguous_acked_through=contig, acked_pages=pages, schema_v4=True,
    )
    return acked, obsolete, dirty


def persist_cursor_ack(
    stream_dir: Path, ack: CaptureBatchAck, perms: OutboxPermissionsPort, *, renamer: OutboxDirRenamer | None = None
) -> None:
    """Flush pending/legacy state and persist sharded ACK pages before cursor bump & frame unlink."""
    if not verify_stream_dir_safe(stream_dir, perms) or not cursor_exists(stream_dir):
        return
    ren = renamer if renamer is not None else default_outbox_dir_renamer()
    cur = read_stream_cursor(stream_dir, perms)
    if _needs_cursor_recovery(cur):
        cur = recover_stream_cursor(stream_dir, cur, perms, renamer=ren)
    acked, obsolete, dirty = _apply_ack_update(cur, ack)
    if dirty:
        write_ack_pages(stream_dir, dirty, perms, renamer=ren)
    if acked != cur:
        write_stream_cursor(stream_dir, acked, perms)
    if obsolete:
        prune_obsolete_ack_pages(stream_dir, obsolete, perms)


def advance_cursor_next_seq(
    stream_dir: Path, sequence: int, perms: OutboxPermissionsPort, *, renamer: OutboxDirRenamer | None = None
) -> None:
    """If ``stream_dir`` already maintains a hook cursor, flush legacy/pending state and advance."""
    if not verify_stream_dir_safe(stream_dir, perms) or not cursor_exists(stream_dir):
        return
    cur = read_stream_cursor(stream_dir, perms)
    if _needs_cursor_recovery(cur):
        ren = renamer if renamer is not None else default_outbox_dir_renamer()
        cur = recover_stream_cursor(stream_dir, cur, perms, renamer=ren)
    bumped = cur.bump_next_seq(sequence)
    if bumped != cur:
        write_stream_cursor(stream_dir, bumped, perms)


def prepare_outbox_frame_bytes(
    *,
    record_kind: str,
    producer_stream: str,
    sequence: int,
    entry_id: str,
    payload_dict: dict[str, JsonValue],
) -> tuple[str, bytes]:
    """Serialize, bound-check, and CRC32-wrap an outbox frame."""
    payload_bytes = canonical_json(payload_dict)
    if len(payload_bytes) > MAX_CAPTURE_ENTRY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    payload_json = payload_bytes.decode("utf-8")
    payload_digest = digest_bytes(payload_bytes)
    core_fields: dict[str, JsonValue] = {
        "byte_size": len(payload_bytes), "entry_id": entry_id, "payload_digest": payload_digest,
        "payload_json": payload_json, "producer_stream": producer_stream,
        "record_kind": record_kind, "sequence": sequence,
    }
    core_fields["frame_crc32"] = f"{zlib.crc32(canonical_json(core_fields)) & 0xFFFFFFFF:08x}"
    return payload_digest, canonical_json(core_fields) + b"\n"


def max_frame_seq_in_paths(frame_paths: Iterable[Path]) -> int:
    """Return the highest frame sequence number across ``frame_paths``, or ``0`` if none."""
    high = 0
    for fp in frame_paths:
        ident = parse_frame_filename_identity(fp.name)
        if ident is not None and ident[1] > high:
            high = ident[1]
    return high


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


def load_or_recover_hook_cursor(
    stream_dir: Path,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None,
) -> StreamSeqCursor:
    """Load cursor if ``stream_dir`` exists and flush any pending/legacy bindings or ACKs."""
    if not verify_stream_dir_safe(stream_dir, perms):
        return StreamSeqCursor(1)
    cursor = read_stream_cursor(stream_dir, perms)
    if _needs_cursor_recovery(cursor):
        return recover_stream_cursor(stream_dir, cursor, perms, renamer=renamer, check_deadline=check_deadline)
    return cursor


def reconcile_matched_hook_frame_cursor(
    stream_dir: Path,
    cursor: StreamSeqCursor,
    *,
    dedup_key: str | None,
    cached: HookBindingRecord | None,
    record: CaptureEventRecord,
    payload_digest: str,
    perms: OutboxPermissionsPort,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None,
) -> None:
    """Ensure sharded binding and cursor ``next_seq`` reflect a pre-existing matched frame."""
    if dedup_key is not None and cached is None:
        b_exist = HookBindingRecord(dedup_key, record.sequence, record.event_id, record.recorded_at, payload_digest)
        bucket_name, payload, added = prepare_binding_upsert(stream_dir, b_exist, perms)
        next_seq = max(cursor.next_seq, record.sequence + 1)
        new_count = cursor.binding_count + (1 if added else 0)
        if payload is not None:
            bound_c = cursor.with_binding_state(next_seq=next_seq, binding_count=new_count, pending_binding=b_exist)
            write_stream_cursor(stream_dir, bound_c, perms)
            write_prepared_binding_bucket(
                stream_dir, bucket_name, payload, perms, renamer=renamer, check_deadline=check_deadline
            )
        cleared_c = cursor.with_binding_state(next_seq=next_seq, binding_count=new_count, pending_binding=None)
        if payload is not None or cleared_c != cursor:
            write_stream_cursor(stream_dir, cleared_c, perms)
        return
    if cached is not None and cached.payload_digest is None:
        backfill_binding_digest_if_missing(
            stream_dir, cached, payload_digest, perms, renamer=renamer, check_deadline=check_deadline
        )
    if cursor.next_seq <= record.sequence:
        write_stream_cursor(stream_dir, cursor.bump_next_seq(record.sequence), perms)


def allocate_event_id(dedup_key: str | None) -> str:
    """Derive a collision-free opaque ``event_id`` (deterministic when ``dedup_key`` is given)."""
    if dedup_key is not None and dedup_key.startswith("sha256:"):
        return f"ev-{dedup_key.removeprefix('sha256:')[:24]}"
    return f"ev-{new_id()}"


def resolve_hook_envelope_slot(
    cursor: StreamSeqCursor,
    *,
    cached: HookBindingRecord | None = None,
    max_frame_seq: int,
    explicit_sequence: int | None,
    explicit_event_id: str | None,
    dedup_key: str | None,
    fallback_recorded_at: str,
) -> tuple[int, str, str]:
    """Choose deterministic retry slot from ``cached`` binding or allocate next monotonic stream sequence."""
    if cached is not None:
        if (explicit_sequence is not None and explicit_sequence != cached.sequence) or (
            explicit_event_id is not None and explicit_event_id != cached.event_id
        ):
            raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
        return cached.sequence, cached.event_id, cached.recorded_at
    seq = explicit_sequence if explicit_sequence is not None else max(cursor.next_seq, max_frame_seq + 1)
    ev_id = explicit_event_id if explicit_event_id is not None else allocate_event_id(dedup_key)
    return seq, ev_id, fallback_recorded_at
