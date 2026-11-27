"""Crash-safe per-stream outbox sequence cursor with authenticated ACK page manifests (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxDirRenamer,
    OutboxPermissionsPort,
    default_outbox_dir_renamer,
    require_capture_sequence,
    require_iso_utc_timestamp,
)
from superbrain.storage import _outbox_acks as _acks
from superbrain.storage import _outbox_io as _io
from superbrain.storage._outbox_bindings import (
    _BINDINGS_DIR,
    HookBindingRecord,
    backfill_binding_digest_if_missing,
    count_all_bindings,
    lookup_binding,
    lookup_binding_with_bucket,
    parse_binding_row,
    prepare_binding_upsert,
    upsert_binding,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_io import verify_stream_dir_safe as verify_stream_dir_safe

_CURSOR_FILENAME = ".seq_cursor.json"
_CURSOR_V3_SCHEMA_VERSION = 3
_CURSOR_V4_SCHEMA_VERSION = 4
_MAX_CURSOR_BYTES = 262_144
_LEGACY_STATES: frozenset[str] = frozenset({"bound", "published", "acked"})
_V4_CURSOR_KEYS: frozenset[str] = frozenset(
    {"schema_version", "next_seq", "binding_count", "contiguous_acked_through", "acked_pages", "pending_binding"}
)


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
    acked_page_refs: tuple[tuple[int, str], ...] = ()
    legacy_acked_ranges: tuple[tuple[int, int], ...] = ()
    schema_v4: bool = False

    def is_event_acked(self, sequence: int) -> bool:
        """Return ``True`` if ``sequence`` has been committed by an event ACK."""
        if sequence <= self.contiguous_acked_through:
            return True
        if any(lo <= sequence <= hi for lo, hi in (*self.acked_ranges, *self.legacy_acked_ranges)):
            return True
        return _acks.is_seq_acked_in_pages(sequence, self.acked_pages)

    def with_binding_state(
        self, *, next_seq: int | None = None, binding_count: int | None = None,
        pending_binding: HookBindingRecord | None = None, schema_v4: bool | None = None,
    ) -> StreamSeqCursor:
        """Return updated cursor preserving ACK watermark, sparse page manifest, and schema state."""
        return StreamSeqCursor(
            next_seq=self.next_seq if next_seq is None else next_seq,
            binding_count=self.binding_count if binding_count is None else binding_count,
            acked_ranges=self.acked_ranges, pending_binding=pending_binding, legacy_recent=self.legacy_recent,
            contiguous_acked_through=self.contiguous_acked_through, acked_pages=self.acked_pages,
            acked_page_refs=self.acked_page_refs, legacy_acked_ranges=self.legacy_acked_ranges,
            schema_v4=self.schema_v4 if schema_v4 is None else schema_v4,
        )

    def mark_acked(self, ack: CaptureBatchAck) -> StreamSeqCursor:
        """Compute updated ACK watermark and sparse bitset page manifest for ``ack``."""
        acked, _dirty = _apply_ack_update(self, ack)
        return acked

    def bump_next_seq(self, sequence: int) -> StreamSeqCursor:
        """Ensure ``next_seq > sequence`` without disturbing bindings or ACK state."""
        return self if self.next_seq > sequence else self.with_binding_state(
            next_seq=sequence + 1, pending_binding=self.pending_binding
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
            if not isinstance(row[4], str) or row[4] not in _LEGACY_STATES:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor state")
            if row[5] is not None:
                if not isinstance(row[5], str):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor digest")
                digest_val = require_sha256_digest(row[5])
            if row[4] == "acked":
                acked_pts.append((seq, seq))
        parsed.append(HookBindingRecord(key, seq, row[2], rec_at, digest_val))
    contig, sparse = _acks.split_contig_and_sparse(_acks.merge_acked_ranges(acked_pts))
    return StreamSeqCursor(
        next_seq=next_seq, binding_count=len({rec.key for rec in parsed}),
        legacy_recent=tuple(parsed), contiguous_acked_through=contig,
        legacy_acked_ranges=sparse, schema_v4=bool(sparse),
    )


def _needs_cursor_recovery(cursor: StreamSeqCursor) -> bool:
    return bool(cursor.legacy_recent or cursor.legacy_acked_ranges or cursor.pending_binding is not None)


def _parse_v3_ranges(raw_ranges: object) -> tuple[int, tuple[tuple[int, int], ...]]:
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
    return _acks.split_contig_and_sparse(_acks.merge_acked_ranges(parsed_ranges))


def read_stream_cursor(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Load and validate ``.seq_cursor.json`` (v1, v2, v3, or v4) and pinned ``.acks`` pages."""
    path = stream_dir / _CURSOR_FILENAME
    has_acks_dir = os.path.lexists(stream_dir / _acks._ACKS_DIR)
    if not os.path.lexists(path):
        if has_acks_dir and _acks.has_committed_ack_page_files(stream_dir, perms):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "orphan acks directory without cursor")
        return StreamSeqCursor(next_seq=1)
    if _io.is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream cursor is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream cursor is not a regular file")
    _io.verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _io._O_BINARY | _io._O_NOFOLLOW)
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
        if has_acks_dir:
            _acks.verify_acks_dir(stream_dir, perms)
        return legacy_c
    binding_count = obj.get("binding_count", 0)
    if type(binding_count) is not int or binding_count < 0:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor binding_count")
    raw_pending = obj.get("pending_binding")
    pending = parse_binding_row(raw_pending) if raw_pending is not None else None
    if schema_ver == _CURSOR_V4_SCHEMA_VERSION:
        raw_contig = obj.get("contiguous_acked_through")
        if set(obj.keys()) != _V4_CURSOR_KEYS or type(raw_contig) is not int or raw_contig < 0:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
        page_refs = _acks.parse_v4_page_refs(obj["acked_pages"])
        pages = _acks.read_ack_pages_for_cursor(stream_dir, perms, expected_refs=page_refs, contig=raw_contig)
        return StreamSeqCursor(
            next_seq=next_seq, binding_count=binding_count, pending_binding=pending,
            contiguous_acked_through=raw_contig, acked_pages=pages, acked_page_refs=page_refs, schema_v4=True,
        )
    contig, sparse = _parse_v3_ranges(obj.get("acked_ranges", []))
    if has_acks_dir:
        _acks.verify_acks_dir(stream_dir, perms)
    return StreamSeqCursor(
        next_seq=next_seq, binding_count=binding_count, pending_binding=pending,
        contiguous_acked_through=contig, legacy_acked_ranges=sparse, schema_v4=bool(sparse),
    )


def _persist_cursor_payload(stream_dir: Path, payload: bytes, perms: OutboxPermissionsPort) -> None:
    dl = _io.active_deadline_check()
    if dl is not None:
        dl()
    if len(payload) > _MAX_CURSOR_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "stream cursor exceeds size bound")
    final_path = stream_dir / _CURSOR_FILENAME
    tmp_path = stream_dir / f".cursor-{uuid.uuid4().hex}{_io._PART_SUFFIX}"
    fd, committed = -1, False
    try:
        fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _io._O_BINARY | _io._O_NOFOLLOW, 0o600)
        _io.write_all_fd(fd, payload)
        perms.secure_file(tmp_path)
        if dl is not None:
            dl()
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if dl is not None:
            dl()
        _io.replace_file_resilient(tmp_path, final_path)
        _io.sync_dir(stream_dir)
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


def _serialize_cursor_bytes(cursor: StreamSeqCursor) -> bytes:
    if cursor.legacy_recent or cursor.legacy_acked_ranges or cursor.acked_ranges:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unflushed legacy cursor state")
    pb = cursor.pending_binding
    pending_row: JsonValue = (
        [pb.key, pb.sequence, pb.event_id, pb.recorded_at, pb.payload_digest] if pb is not None else None
    )
    if cursor.schema_v4 or cursor.acked_pages or cursor.acked_page_refs:
        body: dict[str, JsonValue] = {
            "schema_version": _CURSOR_V4_SCHEMA_VERSION, "next_seq": cursor.next_seq,
            "binding_count": cursor.binding_count, "contiguous_acked_through": cursor.contiguous_acked_through,
            "acked_pages": [[p, h] for p, h in cursor.acked_page_refs],
            "pending_binding": pending_row,
        }
    else:
        contig = cursor.contiguous_acked_through
        body = {
            "schema_version": _CURSOR_V3_SCHEMA_VERSION, "next_seq": cursor.next_seq,
            "binding_count": cursor.binding_count, "acked_ranges": [[1, contig]] if contig > 0 else [],
            "pending_binding": pending_row,
        }
    payload = canonical_json(body)
    if len(payload) > _MAX_CURSOR_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "stream cursor exceeds size bound")
    return payload


def _is_outbox_v4_fenced(stream_dir: Path) -> bool:
    return stream_dir.parent.name == _io._STREAMS_DIR and os.path.lexists(stream_dir.parent / _io._V4_FENCE_FILE)


def write_stream_cursor(stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort) -> None:
    """Persist v3/v4 ``cursor`` atomically inside ``stream_dir`` enforcing ``_MAX_CURSOR_BYTES``."""
    target = cursor.with_binding_state(pending_binding=cursor.pending_binding, schema_v4=True) if (
        not cursor.schema_v4 and _is_outbox_v4_fenced(stream_dir)
    ) else cursor
    _persist_cursor_payload(stream_dir, _serialize_cursor_bytes(target), perms)


def _upgrade_sibling_streams_before_v4_fence(
    streams_dir: Path, exclude_stream_dir: Path, perms: OutboxPermissionsPort,
    *, renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None,
) -> None:
    _io.ensure_dir_tree_atomic(streams_dir, perms, renamer, check_deadline=check_deadline)
    if os.path.lexists(streams_dir / _io._V4_FENCE_FILE):
        return
    pending: list[tuple[Path, StreamSeqCursor]] = []
    with os.scandir(streams_dir) as it:
        for sd_entry in it:
            if check_deadline is not None:
                check_deadline()
            if _io.is_link_path(Path(sd_entry.path)):
                raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
            sdir_path = Path(sd_entry.path)
            if sdir_path == exclude_stream_dir or not stat.S_ISDIR(sd_entry.stat(follow_symlinks=False).st_mode):
                continue
            if cursor_exists(sdir_path):
                sib = read_stream_cursor(sdir_path, perms)
                if _needs_cursor_recovery(sib) or not sib.schema_v4:
                    _preview_recovered_cursor(sib, force_v4=True)
                    pending.append((sdir_path, sib))
    for sib_dir, sib in pending:
        recover_stream_cursor(
            sib_dir, sib, perms, renamer=renamer, check_deadline=check_deadline, force_v4=True, skip_fence=True
        )


def _commit_v4_pages_and_cursor(
    stream_dir: Path, *, prior_refs: tuple[tuple[int, str], ...], new_cursor: StreamSeqCursor,
    dirty_payloads: dict[tuple[int, str], bytes], perms: OutboxPermissionsPort,
    renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None, skip_fence: bool = False,
) -> None:
    _serialize_cursor_bytes(new_cursor)
    if not skip_fence and new_cursor.schema_v4 and stream_dir.parent.name == _io._STREAMS_DIR:
        if not os.path.lexists(stream_dir.parent / _io._V4_FENCE_FILE):
            _upgrade_sibling_streams_before_v4_fence(
                stream_dir.parent, stream_dir, perms, renamer=renamer, check_deadline=check_deadline
            )
        _io.ensure_v4_fence(stream_dir.parent, perms, renamer=renamer, check_deadline=check_deadline)
    if os.path.lexists(stream_dir / _acks._ACKS_DIR):
        _acks.prune_unreferenced_ack_pages(stream_dir, prior_refs, perms)
    if dirty_payloads:
        _acks.write_ack_pages(stream_dir, dirty_payloads, perms, renamer=renamer, check_deadline=check_deadline)
    if check_deadline is not None:
        check_deadline()
    write_stream_cursor(stream_dir, new_cursor, perms)
    if os.path.lexists(stream_dir / _acks._ACKS_DIR):
        _acks.prune_unreferenced_ack_pages(stream_dir, new_cursor.acked_page_refs, perms)


def _preview_recovered_cursor(
    cursor: StreamSeqCursor, *, force_v4: bool = False
) -> tuple[StreamSeqCursor, dict[tuple[int, str], bytes]]:
    contig, pages, page_refs, dirty = _acks.compute_updated_acks(
        contiguous_acked_through=cursor.contiguous_acked_through, existing_pages=cursor.acked_pages,
        existing_refs=dict(cursor.acked_page_refs), extra_ranges=cursor.legacy_acked_ranges,
    )
    target_v4 = force_v4 or cursor.schema_v4 or bool(pages) or bool(cursor.legacy_acked_ranges)
    est_count = cursor.binding_count + len(cursor.legacy_recent) + (1 if cursor.pending_binding else 0)
    preview = StreamSeqCursor(
        next_seq=cursor.next_seq, binding_count=est_count, contiguous_acked_through=contig,
        acked_pages=pages, acked_page_refs=page_refs, schema_v4=target_v4,
    )
    _serialize_cursor_bytes(preview)
    return preview, dirty


def recover_stream_cursor(
    stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort,
    *, renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None = None,
    force_v4: bool = False, skip_fence: bool = False,
) -> StreamSeqCursor:
    """Validate capacity pre-mutation, flush bindings and ACK pages, then commit cursor."""
    want_v4 = force_v4 or _is_outbox_v4_fenced(stream_dir)
    if not _needs_cursor_recovery(cursor) and (cursor.schema_v4 or not want_v4):
        return cursor
    preview, dirty = _preview_recovered_cursor(cursor, force_v4=want_v4)
    if cursor.legacy_recent or cursor.pending_binding is not None:
        for item in cursor.legacy_recent:
            upsert_binding(stream_dir, item, perms, renamer=renamer, check_deadline=check_deadline)
        if cursor.pending_binding is not None:
            upsert_binding(stream_dir, cursor.pending_binding, perms, renamer=renamer, check_deadline=check_deadline)
        count = count_all_bindings(stream_dir, perms)
    else:
        count = cursor.binding_count
    recovered = preview.with_binding_state(binding_count=count, pending_binding=None)
    _commit_v4_pages_and_cursor(
        stream_dir, prior_refs=cursor.acked_page_refs, new_cursor=recovered, dirty_payloads=dirty,
        perms=perms, renamer=renamer, check_deadline=check_deadline, skip_fence=skip_fence,
    )
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
    return lookup_stream_binding_with_bucket(stream_dir, cursor, dedup_key, perms)[0]


def _apply_ack_update(
    cur: StreamSeqCursor, ack: CaptureBatchAck
) -> tuple[StreamSeqCursor, dict[tuple[int, str], bytes]]:
    ev_max = (max(ack.committed_event_sequences) + 1) if ack.committed_event_sequences else 1
    gap_max = (max(ack.acked_producer_gap_sequences) + 1) if ack.acked_producer_gap_sequences else 1
    next_val = max(cur.next_seq, ack.contiguous_event_acked_through + 1, ev_max, gap_max)
    contig, pages, page_refs, dirty = _acks.compute_updated_acks(
        contiguous_acked_through=cur.contiguous_acked_through, existing_pages=cur.acked_pages,
        existing_refs=dict(cur.acked_page_refs), extra_sequences=ack.committed_event_sequences,
        floor_contiguous=ack.contiguous_event_acked_through,
    )
    acked = StreamSeqCursor(
        next_seq=next_val, binding_count=cur.binding_count, contiguous_acked_through=contig,
        acked_pages=pages, acked_page_refs=page_refs, schema_v4=True,
    )
    return acked, dirty


def verify_stream_cursor_integrity(stream_dir: Path, perms: OutboxPermissionsPort) -> None:
    """Validate existing cursor and pinned ``.acks`` pages (or reject orphan ``.acks``) read-only."""
    if cursor_exists(stream_dir) or os.path.lexists(stream_dir / _acks._ACKS_DIR):
        read_stream_cursor(stream_dir, perms)


def persist_cursor_ack(
    stream_dir: Path, ack: CaptureBatchAck, perms: OutboxPermissionsPort,
    *, renamer: OutboxDirRenamer | None = None, check_deadline: Callable[[], None] | None = None,
) -> None:
    """Flush pending/legacy state and persist authenticated ACK pages before cursor bump & frame unlink."""
    if not verify_stream_dir_safe(stream_dir, perms):
        return
    if not cursor_exists(stream_dir):
        if os.path.lexists(stream_dir / _acks._ACKS_DIR) and _acks.has_committed_ack_page_files(stream_dir, perms):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "orphan acks directory without cursor")
        return
    ren = renamer if renamer is not None else default_outbox_dir_renamer()
    cur = read_stream_cursor(stream_dir, perms)
    if _needs_cursor_recovery(cur):
        preview, _ = _preview_recovered_cursor(cur)
        acked_pre, _ = _apply_ack_update(preview, ack)
        _serialize_cursor_bytes(acked_pre)
        cur = recover_stream_cursor(stream_dir, cur, perms, renamer=ren, check_deadline=check_deadline)
    acked, dirty = _apply_ack_update(cur, ack)
    if acked != cur:
        _commit_v4_pages_and_cursor(
            stream_dir, prior_refs=cur.acked_page_refs, new_cursor=acked, dirty_payloads=dirty,
            perms=perms, renamer=ren, check_deadline=check_deadline,
        )


def prepare_cursor_for_direct_enqueue(
    stream_dir: Path, sequence: int, perms: OutboxPermissionsPort,
    *, renamer: OutboxDirRenamer | None = None, check_deadline: Callable[[], None] | None = None,
) -> StreamSeqCursor | None:
    """Fence/recover stream cursor and pre-check capacity BEFORE publishing a direct frame."""
    if not verify_stream_dir_safe(stream_dir, perms):
        return None
    if not cursor_exists(stream_dir):
        if os.path.lexists(stream_dir / _acks._ACKS_DIR) and _acks.has_committed_ack_page_files(stream_dir, perms):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "orphan acks directory without cursor")
        return None
    ren = renamer if renamer is not None else default_outbox_dir_renamer()
    cur = read_stream_cursor(stream_dir, perms)
    if _needs_cursor_recovery(cur):
        preview, _ = _preview_recovered_cursor(cur)
        _serialize_cursor_bytes(preview.bump_next_seq(sequence))
        cur = recover_stream_cursor(stream_dir, cur, perms, renamer=ren, check_deadline=check_deadline)
    _serialize_cursor_bytes(cur.bump_next_seq(sequence))
    return cur


def commit_bumped_cursor(
    stream_dir: Path, cur: StreamSeqCursor | None, sequence: int, perms: OutboxPermissionsPort
) -> None:
    """Persist bumped ``next_seq`` after a direct frame publication completes."""
    if cur is not None and (bumped := cur.bump_next_seq(sequence)) != cur:
        write_stream_cursor(stream_dir, bumped, perms)


def advance_cursor_next_seq(
    stream_dir: Path, sequence: int, perms: OutboxPermissionsPort, *, renamer: OutboxDirRenamer | None = None
) -> None:
    """If ``stream_dir`` already maintains a hook cursor, flush legacy/pending state and advance."""
    cur = prepare_cursor_for_direct_enqueue(stream_dir, sequence, perms, renamer=renamer)
    commit_bumped_cursor(stream_dir, cur, sequence, perms)


def read_hook_cursor_readonly(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Read stream cursor without mutating disk (returns fresh cursor when stream absent)."""
    return read_stream_cursor(stream_dir, perms) if verify_stream_dir_safe(stream_dir, perms) else StreamSeqCursor(1)


def compute_projected_hook_recovery(
    stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort
) -> tuple[StreamSeqCursor, int]:
    """Compute post-recovery cursor preview and exact deduplicated binding count read-only."""
    want_v4 = cursor.schema_v4 or _is_outbox_v4_fenced(stream_dir)
    if not _needs_cursor_recovery(cursor):
        cur = cursor.with_binding_state(pending_binding=cursor.pending_binding, schema_v4=True) if want_v4 else cursor
        return cur, cursor.binding_count
    preview, _ = _preview_recovered_cursor(cursor, force_v4=want_v4)
    pending_keys = {it.key for it in cursor.legacy_recent}
    if cursor.pending_binding is not None:
        pending_keys.add(cursor.pending_binding.key)
    has_bdir = os.path.lexists(stream_dir / _BINDINGS_DIR)
    base_count = count_all_bindings(stream_dir, perms) if has_bdir else 0
    added = sum(1 for k in pending_keys if not has_bdir or lookup_binding(stream_dir, k, perms) is None)
    projected = base_count + added
    return preview.with_binding_state(binding_count=projected, pending_binding=None), projected


def preflight_hook_cursor_size(
    stream_dir: Path, preview: StreamSeqCursor, *, sequence: int,
    prepared: tuple[HookBindingRecord, str, bytes | None, bool] | None,
) -> None:
    """Validate serialized hook cursor byte limit before any durable mutation."""
    new_count = preview.binding_count + (1 if (prepared is not None and prepared[3]) else 0)
    pending_b = prepared[0] if (prepared is not None and prepared[2] is not None) else None
    bound_c = preview.with_binding_state(
        next_seq=max(preview.next_seq, sequence + 1), binding_count=new_count,
        pending_binding=pending_b, schema_v4=preview.schema_v4 or _is_outbox_v4_fenced(stream_dir),
    )
    _serialize_cursor_bytes(bound_c)
    _serialize_cursor_bytes(bound_c.with_binding_state(pending_binding=None))


def load_or_recover_hook_cursor(
    stream_dir: Path, perms: OutboxPermissionsPort,
    *, renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None,
) -> StreamSeqCursor:
    """Load cursor if ``stream_dir`` exists and flush any pending/legacy bindings or ACKs."""
    raw = read_hook_cursor_readonly(stream_dir, perms)
    return recover_stream_cursor(stream_dir, raw, perms, renamer=renamer, check_deadline=check_deadline)


def reconcile_matched_hook_frame_cursor(
    stream_dir: Path, cursor: StreamSeqCursor, *, dedup_key: str | None,
    cached: HookBindingRecord | None, record: CaptureEventRecord, payload_digest: str,
    perms: OutboxPermissionsPort, renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None,
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
    cursor: StreamSeqCursor, *, cached: HookBindingRecord | None = None, max_frame_seq: int,
    explicit_sequence: int | None, explicit_event_id: str | None, dedup_key: str | None, fallback_recorded_at: str,
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
