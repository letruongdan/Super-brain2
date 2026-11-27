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
from superbrain.storage._outbox_bindings import (
    HookBindingRecord,
    lookup_binding,
    parse_binding_row,
    upsert_binding,
)
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    is_link_path,
    parse_frame_filename_identity,
    replace_file_resilient,
    sync_dir,
    verify_owner_only,
    write_all_fd,
)

_CURSOR_FILENAME = ".seq_cursor.json"
_CURSOR_SCHEMA_VERSION = 3
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


@dataclass(frozen=True)
class StreamSeqCursor:
    """Durable per-stream monotonic sequence cursor persisted atomically inside stream directory."""

    next_seq: int
    binding_count: int = 0
    acked_ranges: tuple[tuple[int, int], ...] = ()
    pending_binding: HookBindingRecord | None = None
    legacy_recent: tuple[HookBindingRecord, ...] = ()

    def is_event_acked(self, sequence: int) -> bool:
        """Return ``True`` if ``sequence`` has been committed by an event ACK."""
        return any(lo <= sequence <= hi for lo, hi in self.acked_ranges)

    def mark_acked(self, ack: CaptureBatchAck) -> StreamSeqCursor:
        """Record committed event sequences (never gap-only ACKs) and advance ``next_seq``."""
        ev_max = (max(ack.committed_event_sequences) + 1) if ack.committed_event_sequences else 1
        gap_max = (max(ack.acked_producer_gap_sequences) + 1) if ack.acked_producer_gap_sequences else 1
        next_val = max(self.next_seq, ack.contiguous_event_acked_through + 1, ev_max, gap_max)
        extra: list[tuple[int, int]] = []
        if ack.contiguous_event_acked_through >= 1:
            extra.append((1, ack.contiguous_event_acked_through))
        for seq_val in ack.committed_event_sequences:
            extra.append((seq_val, seq_val))
        new_ranges = merge_acked_ranges(self.acked_ranges, extra)
        return StreamSeqCursor(
            next_seq=next_val,
            binding_count=self.binding_count,
            acked_ranges=new_ranges,
            pending_binding=None,
            legacy_recent=(),
        )

    def bump_next_seq(self, sequence: int) -> StreamSeqCursor:
        """Ensure ``next_seq > sequence`` without disturbing bindings or ACK intervals."""
        if self.next_seq > sequence:
            return self
        return StreamSeqCursor(
            next_seq=sequence + 1,
            binding_count=self.binding_count,
            acked_ranges=self.acked_ranges,
            pending_binding=self.pending_binding,
            legacy_recent=self.legacy_recent,
        )


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
        seq = require_capture_sequence(row[1])
        rec_at = require_iso_utc_timestamp(row[3])
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
    return StreamSeqCursor(
        next_seq=next_seq,
        binding_count=len(parsed),
        acked_ranges=merge_acked_ranges(acked_pts),
        pending_binding=None,
        legacy_recent=tuple(parsed),
    )


def read_stream_cursor(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Load and validate ``.seq_cursor.json`` (v1, v2, or v3) inside ``stream_dir``."""
    path = stream_dir / _CURSOR_FILENAME
    if not os.path.lexists(path):
        return StreamSeqCursor(next_seq=1)
    if is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream cursor is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream cursor is not a regular file")
    verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    try:
        raw_bytes = os.read(fd, 262_144 + 1)
    finally:
        os.close(fd)
    if len(raw_bytes) > 262_144:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream cursor exceeds size bound")
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor") from err
    if not isinstance(obj, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor")
    schema_ver = obj.get("schema_version")
    if type(schema_ver) is not int or schema_ver not in (1, 2, _CURSOR_SCHEMA_VERSION):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
    next_seq = require_capture_sequence(obj.get("next_seq"))
    if schema_ver in (1, 2):
        return _parse_legacy_cursor(obj, schema_ver=schema_ver, next_seq=next_seq)
    binding_count = obj.get("binding_count", 0)
    if type(binding_count) is not int or binding_count < 0:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor binding_count")
    raw_ranges = obj.get("acked_ranges", [])
    if not isinstance(raw_ranges, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor acked_ranges")
    parsed_ranges: list[tuple[int, int]] = []
    for rng in raw_ranges:
        if not isinstance(rng, list) or len(rng) != 2:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor range")
        lo = require_capture_sequence(rng[0])
        hi = require_capture_sequence(rng[1])
        if lo > hi:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor range order")
        parsed_ranges.append((lo, hi))
    raw_pending = obj.get("pending_binding")
    pending = parse_binding_row(raw_pending) if raw_pending is not None else None
    return StreamSeqCursor(
        next_seq=next_seq,
        binding_count=binding_count,
        acked_ranges=merge_acked_ranges(parsed_ranges),
        pending_binding=pending,
        legacy_recent=(),
    )


def write_stream_cursor(stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort) -> None:
    """Persist v3 ``cursor`` atomically inside ``stream_dir`` (temp -> fsync -> os.replace -> sync_dir)."""
    final_path = stream_dir / _CURSOR_FILENAME
    tmp_path = stream_dir / f".cursor-{uuid.uuid4().hex}{_PART_SUFFIX}"
    pb = cursor.pending_binding
    pending_row = [pb.key, pb.sequence, pb.event_id, pb.recorded_at, pb.payload_digest] if pb is not None else None
    payload = canonical_json(
        {
            "schema_version": _CURSOR_SCHEMA_VERSION,
            "next_seq": cursor.next_seq,
            "binding_count": cursor.binding_count,
            "acked_ranges": [[lo, hi] for lo, hi in cursor.acked_ranges],
            "pending_binding": pending_row,
        }
    )
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


def recover_stream_cursor(
    stream_dir: Path,
    cursor: StreamSeqCursor,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> StreamSeqCursor:
    """Flush any in-flight ``pending_binding`` or ``legacy_recent`` entries to sharded ``.bindings``."""
    count = cursor.binding_count
    added_any = False
    if cursor.legacy_recent:
        unique_count = 0
        for item in cursor.legacy_recent:
            if upsert_binding(stream_dir, item, perms, renamer=renamer, check_deadline=check_deadline):
                unique_count += 1
        count = unique_count
        added_any = True
    if cursor.pending_binding is not None:
        upsert_binding(stream_dir, cursor.pending_binding, perms, renamer=renamer, check_deadline=check_deadline)
    if not added_any and cursor.pending_binding is None:
        return cursor
    recovered = StreamSeqCursor(
        next_seq=cursor.next_seq,
        binding_count=count,
        acked_ranges=cursor.acked_ranges,
        pending_binding=None,
        legacy_recent=(),
    )
    write_stream_cursor(stream_dir, recovered, perms)
    return recovered


def lookup_stream_binding(
    stream_dir: Path,
    cursor: StreamSeqCursor,
    dedup_key: str,
    perms: OutboxPermissionsPort,
) -> HookBindingRecord | None:
    """Look up ``dedup_key`` in pending/legacy cursor state first, then in sharded ``.bindings``."""
    if cursor.pending_binding is not None and cursor.pending_binding.key == dedup_key:
        return cursor.pending_binding
    for item in cursor.legacy_recent:
        if item.key == dedup_key:
            return item
    if not os.path.lexists(stream_dir):
        return None
    return lookup_binding(stream_dir, dedup_key, perms)


def persist_cursor_ack(
    stream_dir: Path,
    ack: CaptureBatchAck,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None = None,
) -> None:
    """Flush pending/legacy bindings to ``.bindings`` and mark event ACK intervals before frame unlink."""
    if not cursor_exists(stream_dir):
        return
    cur = read_stream_cursor(stream_dir, perms)
    if cur.legacy_recent or cur.pending_binding is not None:
        cur = recover_stream_cursor(
            stream_dir,
            cur,
            perms,
            renamer=renamer if renamer is not None else default_outbox_dir_renamer(),
        )
    acked = cur.mark_acked(ack)
    if acked != cur:
        write_stream_cursor(stream_dir, acked, perms)


def advance_cursor_next_seq(stream_dir: Path, sequence: int, perms: OutboxPermissionsPort) -> None:
    """If ``stream_dir`` already maintains a hook cursor, ensure ``next_seq > sequence``."""
    if not cursor_exists(stream_dir):
        return
    cur = read_stream_cursor(stream_dir, perms)
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


def load_or_recover_hook_cursor(
    stream_dir: Path,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None,
) -> StreamSeqCursor:
    """Load cursor if ``stream_dir`` exists and flush any pending/legacy bindings cleanly."""
    if not os.path.lexists(stream_dir):
        return StreamSeqCursor(1)
    cursor = read_stream_cursor(stream_dir, perms)
    if cursor.legacy_recent or cursor.pending_binding is not None:
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
        if upsert_binding(stream_dir, b_exist, perms, renamer=renamer, check_deadline=check_deadline):
            next_c = StreamSeqCursor(
                max(cursor.next_seq, record.sequence + 1), cursor.binding_count + 1, cursor.acked_ranges
            )
            write_stream_cursor(stream_dir, next_c, perms)
            return
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
