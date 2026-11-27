"""Sharded 4096-bit page store for durable bounded outbox stream ACK tracking (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OutboxDirRenamer, OutboxPermissionsPort
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    ensure_dir_tree_atomic,
    entry_is_link,
    is_link_path,
    replace_file_resilient,
    sync_dir,
    verify_owner_only,
    write_all_fd,
)

_ACKS_DIR = ".acks"
_ACKS_SCHEMA_VERSION = 4
_ACK_PAGE_BITS = 4096
_ACK_PAGE_BYTES = _ACK_PAGE_BITS // 8
_MAX_ACK_PAGE_BYTES = 4096
_MAX_ACK_PAGES = 1024
_HEX_CHARS = frozenset("0123456789abcdef")


def ack_page_filename(page: int) -> str:
    """Return deterministic hex filename for 4096-bit page ``page``."""
    return f"p{page:016x}.json"


def _parse_ack_page_filename(name: str) -> int | None:
    if len(name) != 22 or not name.startswith("p") or not name.endswith(".json"):
        return None
    hex_part = name[1:17]
    if any(ch not in _HEX_CHARS for ch in hex_part):
        return None
    return int(hex_part, 16)


def _verify_acks_dir_node(stream_dir: Path, perms: OutboxPermissionsPort) -> Path | None:
    """Verify ``stream_dir`` and ``.acks`` node are non-link, typed, and owner-only without full scan."""
    if os.path.lexists(stream_dir) and is_link_path(stream_dir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
    adir = stream_dir / _ACKS_DIR
    if not os.path.lexists(adir):
        return None
    if is_link_path(adir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "acks directory is a link")
    if not stat.S_ISDIR(os.lstat(adir).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "acks path is not a directory")
    verify_owner_only(adir, perms)
    return adir


def verify_acks_dir(stream_dir: Path, perms: OutboxPermissionsPort) -> Path | None:
    """Verify ``.acks`` directory and sweep ``.part`` files, rejecting links and unexpected entries."""
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        return None
    with os.scandir(adir) as it:
        for entry in it:
            if entry_is_link(entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "ack page is a link")
            if entry.name.endswith(_PART_SUFFIX):
                Path(entry.path).unlink(missing_ok=True)
                continue
            if _parse_ack_page_filename(entry.name) is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unexpected entry in acks directory")
    return adir


def _read_ack_page_file(path: Path, expected_page: int, perms: OutboxPermissionsPort) -> bytes:
    if is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "ack page is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "ack page is not a regular file")
    verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    try:
        raw_bytes = os.read(fd, _MAX_ACK_PAGE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw_bytes) > _MAX_ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "ack page exceeds size bound")
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page") from err
    if (
        not isinstance(obj, dict)
        or type(obj.get("schema_version")) is not int
        or obj.get("schema_version") != _ACKS_SCHEMA_VERSION
        or type(obj.get("page")) is not int
        or obj.get("page") != expected_page
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page schema")
    bitmap_hex = obj.get("bitmap_hex")
    if not isinstance(bitmap_hex, str) or len(bitmap_hex) != _ACK_PAGE_BYTES * 2:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    try:
        bitmap = bytes.fromhex(bitmap_hex)
    except ValueError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap") from err
    if len(bitmap) != _ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    return bitmap


def read_ack_pages(stream_dir: Path, perms: OutboxPermissionsPort) -> tuple[tuple[int, bytes], ...]:
    """Load and validate all sparse ACK bitset pages under ``.acks``."""
    adir = verify_acks_dir(stream_dir, perms)
    if adir is None:
        return ()
    candidates: list[tuple[int, Path]] = []
    with os.scandir(adir) as it:
        for entry in it:
            page = _parse_ack_page_filename(entry.name)
            if page is not None:
                candidates.append((page, Path(entry.path)))
    if len(candidates) > _MAX_ACK_PAGES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "hook ack page count exceeds bound")
    candidates.sort(key=lambda item: item[0])
    pages: list[tuple[int, bytes]] = []
    for page, path in candidates:
        bitmap = _read_ack_page_file(path, page, perms)
        if any(bitmap):
            pages.append((page, bitmap))
    return tuple(pages)


def is_seq_acked_in_pages(sequence: int, pages: Iterable[tuple[int, bytes]]) -> bool:
    """Return ``True`` if ``sequence`` is marked set in ``pages``."""
    if sequence < 1:
        return False
    target_page, bit_idx = divmod(sequence - 1, _ACK_PAGE_BITS)
    byte_idx, bit_off = divmod(bit_idx, 8)
    for page, bitmap in pages:
        if page == target_page:
            return bool((bitmap[byte_idx] >> bit_off) & 1)
    return False


def _serialize_ack_page(page: int, bitmap: bytes) -> bytes:
    if len(bitmap) != _ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    payload = canonical_json({"schema_version": _ACKS_SCHEMA_VERSION, "page": page, "bitmap_hex": bitmap.hex()})
    if len(payload) > _MAX_ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page exceeds size bound")
    return payload


def _set_page_bit(page_map: dict[int, bytearray], seq: int, *, max_pages: int) -> None:
    page, bit_idx = divmod(seq - 1, _ACK_PAGE_BITS)
    buf = page_map.get(page)
    if buf is None:
        if len(page_map) >= max_pages:
            raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")
        buf = bytearray(_ACK_PAGE_BYTES)
        page_map[page] = buf
    buf[bit_idx >> 3] |= 1 << (bit_idx & 7)


def compute_updated_acks(
    *,
    contiguous_acked_through: int,
    existing_pages: tuple[tuple[int, bytes], ...],
    extra_ranges: Iterable[tuple[int, int]] = (),
    extra_sequences: Iterable[int] = (),
    floor_contiguous: int = 0,
) -> tuple[int, tuple[tuple[int, bytes], ...], tuple[int, ...], dict[int, bytes]]:
    """Compute watermark compaction, serialized dirty pages, and obsolete pages read-only."""
    max_pages = _MAX_ACK_PAGES
    new_contig = max(0, contiguous_acked_through, floor_contiguous)
    orig_pages = dict(existing_pages)
    page_map: dict[int, bytearray] = {}
    for page, bitmap in orig_pages.items():
        if (page + 1) * _ACK_PAGE_BITS > new_contig:
            page_map[page] = bytearray(bitmap)
    if len(page_map) > max_pages:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")

    sorted_ranges = sorted((lo, hi) for lo, hi in extra_ranges if 1 <= lo <= hi)
    for lo, hi in sorted_ranges:
        if hi <= new_contig:
            continue
        if lo <= new_contig + 1:
            new_contig = hi
            continue
        lo_page = (lo - 1) // _ACK_PAGE_BITS
        hi_page = (hi - 1) // _ACK_PAGE_BITS
        if (hi_page - lo_page + 1) > max_pages:
            raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")
        for seq in range(lo, hi + 1):
            _set_page_bit(page_map, seq, max_pages=max_pages)

    for seq in sorted({s for s in extra_sequences if s >= 1}):
        if seq <= new_contig:
            continue
        if seq == new_contig + 1:
            new_contig = seq
        else:
            _set_page_bit(page_map, seq, max_pages=max_pages)

    while True:
        next_s = new_contig + 1
        p, bit_idx = divmod(next_s - 1, _ACK_PAGE_BITS)
        buf = page_map.get(p)
        if buf is None or not ((buf[bit_idx >> 3] >> (bit_idx & 7)) & 1):
            break
        new_contig = next_s

    final_pages: dict[int, bytes] = {}
    dirty_payloads: dict[int, bytes] = {}
    for page in sorted(page_map):
        buf = page_map[page]
        page_base = page * _ACK_PAGE_BITS + 1
        if new_contig >= page_base:
            clear_bits = min(_ACK_PAGE_BITS, new_contig - page_base + 1)
            full_bytes, rem_bits = divmod(clear_bits, 8)
            for idx in range(full_bytes):
                buf[idx] = 0
            if rem_bits:
                buf[full_bytes] &= ~((1 << rem_bits) - 1) & 0xFF
        raw = bytes(buf)
        if not any(raw):
            continue
        final_pages[page] = raw
        if orig_pages.get(page) != raw:
            dirty_payloads[page] = _serialize_ack_page(page, raw)

    if len(final_pages) > max_pages:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")
    obsolete = tuple(sorted(p for p in orig_pages if p not in final_pages))
    return new_contig, tuple((p, final_pages[p]) for p in sorted(final_pages)), obsolete, dirty_payloads


def write_ack_pages(
    stream_dir: Path,
    dirty_payloads: dict[int, bytes],
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Persist dirty serialized ``.acks`` pages atomically before advancing cursor."""
    if not dirty_payloads:
        return
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        adir = stream_dir / _ACKS_DIR
        ensure_dir_tree_atomic(adir, perms, renamer, check_deadline=check_deadline)
    for page in sorted(dirty_payloads):
        final_path = adir / ack_page_filename(page)
        tmp_path = adir / f".ack-{uuid.uuid4().hex}{_PART_SUFFIX}"
        fd = -1
        committed = False
        try:
            fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
            write_all_fd(fd, dirty_payloads[page])
            perms.secure_file(tmp_path)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            replace_file_resilient(tmp_path, final_path)
            committed = True
        except BrainError:
            raise
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot write ack page: {err}") from err
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if not committed:
                tmp_path.unlink(missing_ok=True)
    sync_dir(adir)


def prune_obsolete_ack_pages(
    stream_dir: Path, obsolete_pages: Iterable[int], perms: OutboxPermissionsPort
) -> None:
    """Remove obsolete ``.acks`` shard files compacted below ``contiguous_acked_through``."""
    obs = tuple(obsolete_pages)
    if not obs:
        return
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        return
    for page in obs:
        (adir / ack_page_filename(page)).unlink(missing_ok=True)
    sync_dir(adir)
