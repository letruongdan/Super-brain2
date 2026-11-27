"""Crash-safe per-stream outbox sequence cursor and bounded idempotency cache (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.capture import OutboxPermissionsPort, require_capture_sequence, require_iso_utc_timestamp
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
_CURSOR_SCHEMA_VERSION = 1
_MAX_RECENT_KEYS = 512


@dataclass(frozen=True)
class RecentHookReceipt:
    """Sanitized recent hook envelope entry keyed by opaque dedup digest (zero raw secrets)."""

    key: str
    sequence: int
    event_id: str
    recorded_at: str


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
    ) -> StreamSeqCursor:
        next_val = max(self.next_seq, sequence + 1)
        items = list(self.recent)
        if dedup_key is not None:
            items = [item for item in items if item.key != dedup_key]
            items.append(RecentHookReceipt(dedup_key, sequence, event_id, recorded_at))
            if len(items) > _MAX_RECENT_KEYS:
                items = items[-_MAX_RECENT_KEYS:]
        return StreamSeqCursor(next_seq=next_val, recent=tuple(items))


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
    if not isinstance(obj, dict) or obj.get("schema_version") != _CURSOR_SCHEMA_VERSION:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor schema")
    next_seq = require_capture_sequence(obj.get("next_seq"))
    raw_recent = obj.get("recent", [])
    if not isinstance(raw_recent, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor recent list")
    parsed_recent: list[RecentHookReceipt] = []
    for row in raw_recent:
        if (
            not isinstance(row, list)
            or len(row) != 4
            or not isinstance(row[0], str)
            or not row[0].startswith("sha256:")
            or not isinstance(row[2], str)
            or not row[2]
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor entry")
        seq = require_capture_sequence(row[1])
        rec_at = require_iso_utc_timestamp(row[3])
        parsed_recent.append(RecentHookReceipt(row[0], seq, row[2], rec_at))
    return StreamSeqCursor(next_seq=next_seq, recent=tuple(parsed_recent[-_MAX_RECENT_KEYS:]))


def write_stream_cursor(stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort) -> None:
    """Persist ``cursor`` atomically inside ``stream_dir`` (temp -> fsync -> os.replace -> sync_dir)."""
    final_path = stream_dir / _CURSOR_FILENAME
    tmp_path = stream_dir / f".cursor-{uuid.uuid4().hex}{_PART_SUFFIX}"
    payload = canonical_json(
        {
            "schema_version": _CURSOR_SCHEMA_VERSION,
            "next_seq": cursor.next_seq,
            "recent": [[r.key, r.sequence, r.event_id, r.recorded_at] for r in cursor.recent],
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
    if (
        cached is not None
        and (explicit_sequence is None or explicit_sequence == cached.sequence)
        and (explicit_event_id is None or explicit_event_id == cached.event_id)
    ):
        return cached.sequence, cached.event_id, cached.recorded_at
    seq = explicit_sequence if explicit_sequence is not None else max(cursor.next_seq, max_frame_seq + 1)
    ev_id = explicit_event_id if explicit_event_id is not None else allocate_event_id(dedup_key)
    return seq, ev_id, fallback_recorded_at
