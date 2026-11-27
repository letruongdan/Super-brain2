"""Crash-safe per-stream outbox sequence cursor and bounded idempotency cache (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.capture import (
    OUTBOX_RECORD_EVENT,
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxPermissionsPort,
    require_capture_sequence,
    require_iso_utc_timestamp,
)
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    is_link_path,
    sync_dir,
    verify_owner_only,
    write_all_fd,
)

_CURSOR_FILENAME = ".seq_cursor.json"
_CURSOR_SCHEMA_VERSION = 2
_MAX_RECENT_KEYS = 512
_STATE_RANK: dict[str, int] = {"bound": 0, "published": 1, "acked": 2}


@dataclass(frozen=True)
class RecentHookReceipt:
    """Sanitized recent hook envelope entry keyed by opaque dedup digest (zero raw secrets)."""

    key: str
    sequence: int
    event_id: str
    recorded_at: str
    state: str = "published"
    payload_digest: str | None = None


@dataclass(frozen=True)
class StreamSeqCursor:
    """Durable per-stream monotonic sequence cursor persisted atomically inside stream directory."""

    next_seq: int
    recent: tuple[RecentHookReceipt, ...]

    def lookup(self, key: str) -> RecentHookReceipt | None:
        for item in self.recent:
            if item.key == key:
                return item
        return None

    def advance(
        self,
        *,
        sequence: int,
        dedup_key: str | None,
        event_id: str,
        recorded_at: str,
        payload_digest: str | None = None,
        state: str = "published",
    ) -> StreamSeqCursor:
        if state not in _STATE_RANK:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        next_val = max(self.next_seq, sequence + 1)
        items = list(self.recent)
        if dedup_key is not None:
            prev = self.lookup(dedup_key)
            eff_state = state
            eff_digest = payload_digest
            if prev is not None and prev.sequence == sequence and prev.event_id == event_id:
                if _STATE_RANK[prev.state] > _STATE_RANK[state]:
                    eff_state = prev.state
                if payload_digest is None:
                    eff_digest = prev.payload_digest
            items = [item for item in items if item.key != dedup_key]
            items.append(RecentHookReceipt(dedup_key, sequence, event_id, recorded_at, eff_state, eff_digest))
            if len(items) > _MAX_RECENT_KEYS:
                excess = len(items) - _MAX_RECENT_KEYS
                drop_indices: set[int] = set()
                for idx, item in enumerate(items):
                    if item.state != "bound":
                        drop_indices.add(idx)
                        if len(drop_indices) == excess:
                            break
                if drop_indices:
                    items = [item for idx, item in enumerate(items) if idx not in drop_indices]
                if len(items) > _MAX_RECENT_KEYS:
                    items = items[-_MAX_RECENT_KEYS:]
        return StreamSeqCursor(next_seq=next_val, recent=tuple(items))

    def mark_acked(self, ack: CaptureBatchAck) -> StreamSeqCursor:
        ev_max = (max(ack.committed_event_sequences) + 1) if ack.committed_event_sequences else 1
        gap_max = (max(ack.acked_producer_gap_sequences) + 1) if ack.acked_producer_gap_sequences else 1
        next_val = max(self.next_seq, ack.contiguous_event_acked_through + 1, ev_max, gap_max)
        updated: list[RecentHookReceipt] = []
        for item in self.recent:
            if item.state != "acked" and ack.allows_eviction(OUTBOX_RECORD_EVENT, item.sequence):
                updated.append(
                    RecentHookReceipt(
                        item.key, item.sequence, item.event_id, item.recorded_at, "acked", item.payload_digest
                    )
                )
            else:
                updated.append(item)
        return StreamSeqCursor(next_seq=next_val, recent=tuple(updated))

    def bump_next_seq(self, sequence: int) -> StreamSeqCursor:
        if self.next_seq > sequence:
            return self
        return StreamSeqCursor(next_seq=sequence + 1, recent=self.recent)


def cursor_exists(stream_dir: Path) -> bool:
    """Return ``True`` when ``.seq_cursor.json`` exists (including as a link) inside ``stream_dir``."""
    return os.path.lexists(stream_dir / _CURSOR_FILENAME)


def read_stream_cursor(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Load and validate ``.seq_cursor.json`` inside ``stream_dir``, or return initial state."""
    path = stream_dir / _CURSOR_FILENAME
    if not os.path.lexists(path):
        return StreamSeqCursor(next_seq=1, recent=())
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
    schema_ver = obj.get("schema_version") if isinstance(obj, dict) else None
    if not isinstance(obj, dict) or schema_ver not in (1, _CURSOR_SCHEMA_VERSION):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
    next_seq = require_capture_sequence(obj.get("next_seq"))
    raw_recent = obj.get("recent", [])
    if not isinstance(raw_recent, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor recent list")
    expected_len = 4 if schema_ver == 1 else 6
    parsed_recent: list[RecentHookReceipt] = []
    for row in raw_recent:
        if (
            not isinstance(row, list)
            or len(row) != expected_len
            or not isinstance(row[0], str)
            or not row[0].startswith("sha256:")
            or not isinstance(row[2], str)
            or not row[2]
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor entry")
        seq = require_capture_sequence(row[1])
        rec_at = require_iso_utc_timestamp(row[3])
        if schema_ver == 1:
            parsed_recent.append(RecentHookReceipt(row[0], seq, row[2], rec_at, "published", None))
        else:
            state_val = row[4]
            digest_val = row[5]
            if not isinstance(state_val, str) or state_val not in _STATE_RANK:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor state")
            if digest_val is not None:
                if not isinstance(digest_val, str):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor digest")
                require_sha256_digest(digest_val)
            parsed_recent.append(RecentHookReceipt(row[0], seq, row[2], rec_at, state_val, digest_val))
    return StreamSeqCursor(next_seq=next_seq, recent=tuple(parsed_recent[-_MAX_RECENT_KEYS:]))


def write_stream_cursor(stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort) -> None:
    """Persist ``cursor`` atomically inside ``stream_dir`` (temp -> fsync -> os.replace -> sync_dir)."""
    final_path = stream_dir / _CURSOR_FILENAME
    tmp_path = stream_dir / f".cursor-{uuid.uuid4().hex}{_PART_SUFFIX}"
    payload = canonical_json(
        {
            "schema_version": _CURSOR_SCHEMA_VERSION,
            "next_seq": cursor.next_seq,
            "recent": [
                [r.key, r.sequence, r.event_id, r.recorded_at, r.state, r.payload_digest]
                for r in cursor.recent
            ],
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
        os.replace(tmp_path, final_path)
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


def advance_and_persist_cursor(
    stream_dir: Path,
    cursor: StreamSeqCursor,
    *,
    record: CaptureEventRecord,
    dedup_key: str | None,
    payload_digest: str,
    state: str,
    perms: OutboxPermissionsPort,
) -> StreamSeqCursor:
    """Advance ``cursor`` monotonically for ``record`` and persist only if state/seq/cache changed."""
    next_c = cursor.advance(
        sequence=record.sequence,
        dedup_key=dedup_key,
        event_id=record.event_id,
        recorded_at=record.recorded_at,
        payload_digest=payload_digest,
        state=state,
    )
    if next_c != cursor:
        write_stream_cursor(stream_dir, next_c, perms)
    return next_c


def persist_cursor_ack(stream_dir: Path, ack: CaptureBatchAck, perms: OutboxPermissionsPort) -> None:
    """Mark committed event sequences in ``.seq_cursor.json`` as ``acked`` before frame unlink."""
    if not cursor_exists(stream_dir):
        return
    cur = read_stream_cursor(stream_dir, perms)
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


def allocate_event_id(dedup_key: str | None) -> str:
    """Derive a collision-free opaque ``event_id`` (deterministic when ``dedup_key`` is given)."""
    if dedup_key is not None and dedup_key.startswith("sha256:"):
        return f"ev-{dedup_key.removeprefix('sha256:')[:24]}"
    return f"ev-{new_id()}"


def resolve_hook_envelope_slot(
    cursor: StreamSeqCursor,
    *,
    max_frame_seq: int,
    explicit_sequence: int | None,
    explicit_event_id: str | None,
    dedup_key: str | None,
    fallback_recorded_at: str,
) -> tuple[int, str, str]:
    """Choose deterministic retry slot from ``cursor`` or allocate the next monotonic stream sequence."""
    cached = cursor.lookup(dedup_key) if dedup_key is not None else None
    if cached is not None:
        if (explicit_sequence is not None and explicit_sequence != cached.sequence) or (
            explicit_event_id is not None and explicit_event_id != cached.event_id
        ):
            raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
        return cached.sequence, cached.event_id, cached.recorded_at
    seq = explicit_sequence if explicit_sequence is not None else max(cursor.next_seq, max_frame_seq + 1)
    ev_id = explicit_event_id if explicit_event_id is not None else allocate_event_id(dedup_key)
    return seq, ev_id, fallback_recorded_at
