"""Immutable content-addressed 4096-bit page store for durable bounded outbox ACK tracking (SP2-5)."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OutboxDirRenamer, OutboxPermissionsPort
from superbrain.storage._outbox_durable import raise_storage_error
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    active_deadline_check,
    ensure_dir_tree_atomic,
    entry_is_link,
    is_link_path,
    replace_file_resilient,
    staging_cleanup_allowed,
    sync_dir,
    unlink_before_deadline,
    verify_owner_only,
    write_all_fd,
)

_ACKS_DIR = ".acks"
_ACKS_SCHEMA_VERSION = 4
_ACK_PAGE_BITS = 4096
_ACK_PAGE_BYTES = _ACK_PAGE_BITS // 8
_MAX_ACK_PAGE_BYTES = 4096
_MAX_ACK_PAGES = 1024
_ACK_PAGE_KEYS: frozenset[str] = frozenset({"schema_version", "page", "bitmap_hex"})
_HEX_CHARS = frozenset("0123456789abcdef")


def ack_page_filename(page: int, digest_hex64: str) -> str:
    """Return immutable content-addressed filename for 4096-bit page ``page``."""
    return f"p{page:016x}_{digest_hex64[:16]}.json"


def _parse_ack_page_filename(name: str) -> tuple[int, str] | None:
    if len(name) != 39 or not name.startswith("p") or not name.endswith(".json") or name[17] != "_":
        return None
    page_hex = name[1:17]
    tag_hex = name[18:34]
    if any(ch not in _HEX_CHARS for ch in page_hex) or any(ch not in _HEX_CHARS for ch in tag_hex):
        return None
    return int(page_hex, 16), tag_hex


def is_valid_hex64(value: object) -> bool:
    """Return ``True`` iff ``value`` is a lowercase 64-char SHA-256 hex digest."""
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX_CHARS for ch in value)


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


def verify_acks_dir(stream_dir: Path, perms: OutboxPermissionsPort, *, sweep: bool = False) -> Path | None:
    """Verify ``.acks`` directory, rejecting links and unexpected entries; remove ``.part`` only on a sweep."""
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        return None
    page_files = 0
    max_transitional = _MAX_ACK_PAGES * 2
    with os.scandir(adir) as it:
        for entry in it:
            if entry_is_link(entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "ack page is a link")
            if entry.name.endswith(_PART_SUFFIX):
                if sweep:
                    unlink_before_deadline(Path(entry.path))
                continue
            if _parse_ack_page_filename(entry.name) is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unexpected entry in acks directory")
            page_files += 1
            if page_files > max_transitional:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "acks directory transitional count exceeds bound")
    return adir


def has_committed_ack_page_files(stream_dir: Path, perms: OutboxPermissionsPort) -> bool:
    """Verify ``.acks`` safely and return ``True`` if any page files remain."""
    adir = verify_acks_dir(stream_dir, perms)
    if adir is None:
        return False
    with os.scandir(adir) as it:
        for entry in it:
            if _parse_ack_page_filename(entry.name) is not None:
                return True
    return False


def _read_ack_page_file(
    path: Path,
    expected_page: int,
    expected_hex64: str,
    contig: int,
    perms: OutboxPermissionsPort,
) -> bytes:
    if not os.path.lexists(path):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "missing committed ack page")
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
    actual_hex64 = digest_bytes(raw_bytes).removeprefix("sha256:")
    if actual_hex64 != expected_hex64:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "ack page digest mismatch")
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page") from err
    if (
        not isinstance(obj, dict)
        or set(obj.keys()) != _ACK_PAGE_KEYS
        or type(obj.get("schema_version")) is not int
        or obj["schema_version"] != _ACKS_SCHEMA_VERSION
        or type(obj.get("page")) is not int
        or obj["page"] != expected_page
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page schema")
    bitmap_hex = obj.get("bitmap_hex")
    if not isinstance(bitmap_hex, str) or len(bitmap_hex) != _ACK_PAGE_BYTES * 2:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    try:
        bitmap = bytes.fromhex(bitmap_hex)
    except ValueError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap") from err
    if len(bitmap) != _ACK_PAGE_BYTES or not any(bitmap):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    page_base = expected_page * _ACK_PAGE_BITS + 1
    if (expected_page + 1) * _ACK_PAGE_BITS <= contig:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "obsolete ack page referenced by cursor")
    if contig >= page_base:
        clear_bits = contig - page_base + 1
        full_bytes, rem_bits = divmod(clear_bits, 8)
        if any(bitmap[:full_bytes]) or (rem_bits and (bitmap[full_bytes] & ((1 << rem_bits) - 1))):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "ack page contains bits at or below watermark")
    return bitmap


def parse_v4_page_refs(raw_pages: object) -> tuple[tuple[int, str], ...]:
    """Validate sorted ``[[page, sha256_hex64], ...]`` manifest list inside cursor v4."""
    if not isinstance(raw_pages, list) or len(raw_pages) > _MAX_ACK_PAGES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor acked_pages")
    refs: list[tuple[int, str]] = []
    prev_page = -1
    for item in raw_pages:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or type(item[0]) is not int
            or item[0] <= prev_page
            or not is_valid_hex64(item[1])
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt stream cursor acked_pages entry")
        prev_page = item[0]
        refs.append((item[0], item[1]))
    return tuple(refs)


def merge_acked_ranges(
    existing: Iterable[tuple[int, int]],
    extra: Iterable[tuple[int, int]] = (),
) -> tuple[tuple[int, int], ...]:
    """Normalize and merge closed integer intervals ``(lo, hi)`` in ascending order."""
    intervals: list[tuple[int, int]] = [(lo, hi) for lo, hi in (*existing, *extra) if 1 <= lo <= hi]
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


def split_contig_and_sparse(ranges: tuple[tuple[int, int], ...]) -> tuple[int, tuple[tuple[int, int], ...]]:
    """Split contiguous prefix ``[1, contig]`` from sparse ACK intervals."""
    if ranges and ranges[0][0] == 1:
        return ranges[0][1], ranges[1:]
    return 0, ranges


def read_ack_pages_for_cursor(
    stream_dir: Path,
    perms: OutboxPermissionsPort,
    *,
    expected_refs: tuple[tuple[int, str], ...],
    contig: int,
) -> tuple[tuple[int, bytes], ...]:
    """Load and authenticate every committed ACK page referenced by cursor v4."""
    if len(expected_refs) > _MAX_ACK_PAGES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "hook ack page count exceeds bound")
    adir = verify_acks_dir(stream_dir, perms)
    if not expected_refs:
        return ()
    if adir is None:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "missing acks directory for committed cursor pages")
    pages: list[tuple[int, bytes]] = []
    for page, hex64 in expected_refs:
        bitmap = _read_ack_page_file(adir / ack_page_filename(page, hex64), page, hex64, contig, perms)
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


def _serialize_ack_page(page: int, bitmap: bytes) -> tuple[str, bytes]:
    if len(bitmap) != _ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt ack page bitmap")
    payload = canonical_json({"schema_version": _ACKS_SCHEMA_VERSION, "page": page, "bitmap_hex": bitmap.hex()})
    if len(payload) > _MAX_ACK_PAGE_BYTES:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page exceeds size bound")
    return digest_bytes(payload).removeprefix("sha256:"), payload


def _set_page_bit(page_map: dict[int, bytearray], seq: int, *, scratch_limit: int) -> None:
    page, bit_idx = divmod(seq - 1, _ACK_PAGE_BITS)
    buf = page_map.get(page)
    if buf is None:
        if len(page_map) >= scratch_limit:
            raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")
        buf = bytearray(_ACK_PAGE_BYTES)
        page_map[page] = buf
    buf[bit_idx >> 3] |= 1 << (bit_idx & 7)


def _advance_watermark(page_map: dict[int, bytearray], new_contig: int) -> int:
    while True:
        next_s = new_contig + 1
        p, bit_idx = divmod(next_s - 1, _ACK_PAGE_BITS)
        buf = page_map.get(p)
        if buf is None or not ((buf[bit_idx >> 3] >> (bit_idx & 7)) & 1):
            break
        new_contig = next_s
        if (new_contig % _ACK_PAGE_BITS) == 0:
            page_map.pop(p, None)
    return new_contig


def compute_updated_acks(
    *,
    contiguous_acked_through: int,
    existing_pages: tuple[tuple[int, bytes], ...],
    existing_refs: Mapping[int, str] | None = None,
    extra_ranges: Iterable[tuple[int, int]] = (),
    extra_sequences: Iterable[int] = (),
    floor_contiguous: int = 0,
) -> tuple[
    int,
    tuple[tuple[int, bytes], ...],
    tuple[tuple[int, str], ...],
    dict[tuple[int, str], bytes],
]:
    """Compute watermark compaction, committed page digests, and immutable staged payloads read-only."""
    max_pages = _MAX_ACK_PAGES
    scratch_limit = max_pages * 2
    new_contig = max(0, contiguous_acked_through, floor_contiguous)
    orig_pages = dict(existing_pages)
    orig_refs = dict(existing_refs or {})
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
            new_contig = _advance_watermark(page_map, hi)
            continue
        lo_page = (lo - 1) // _ACK_PAGE_BITS
        hi_page = (hi - 1) // _ACK_PAGE_BITS
        if (hi_page - lo_page + 1) > max_pages:
            raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")
        for seq in range(lo, hi + 1):
            _set_page_bit(page_map, seq, scratch_limit=scratch_limit)

    for seq in sorted({s for s in extra_sequences if s >= 1}):
        if seq <= new_contig:
            continue
        if seq == new_contig + 1:
            new_contig = _advance_watermark(page_map, seq)
        else:
            _set_page_bit(page_map, seq, scratch_limit=scratch_limit)

    new_contig = _advance_watermark(page_map, new_contig)

    final_raw: list[tuple[int, bytes]] = []
    for page in sorted(page_map):
        if (page + 1) * _ACK_PAGE_BITS <= new_contig:
            continue
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
        if any(raw):
            final_raw.append((page, raw))

    if len(final_raw) > max_pages:
        raise BrainError(ErrorCode.STORAGE_FULL, "hook ack page limit exceeded")

    final_refs: list[tuple[int, str]] = []
    dirty_payloads: dict[tuple[int, str], bytes] = {}
    for page, raw in final_raw:
        existing_hex = orig_refs.get(page) if orig_pages.get(page) == raw else None
        if existing_hex is not None:
            final_refs.append((page, existing_hex))
        else:
            hex64, serialized = _serialize_ack_page(page, raw)
            final_refs.append((page, hex64))
            dirty_payloads[(page, hex64)] = serialized

    return new_contig, tuple(final_raw), tuple(final_refs), dirty_payloads


def prune_unreferenced_ack_pages(
    stream_dir: Path,
    keep_refs: Iterable[tuple[int, str]],
    perms: OutboxPermissionsPort,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Remove any ``.acks`` page files not referenced by ``keep_refs``."""
    keep_names = {ack_page_filename(page, hex64) for page, hex64 in keep_refs}
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        return
    removed = False
    with os.scandir(adir) as it:
        for entry in it:
            if entry_is_link(entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "ack page is a link")
            if entry.name.endswith(_PART_SUFFIX) or (
                _parse_ack_page_filename(entry.name) is not None and entry.name not in keep_names
            ):
                unlink_before_deadline(Path(entry.path), check_deadline)
                removed = True
    if removed:
        sync_dir(adir)


def write_ack_pages(
    stream_dir: Path,
    dirty_payloads: Mapping[tuple[int, str], bytes],
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Persist immutable content-addressed ``.acks`` pages before advancing cursor."""
    if not dirty_payloads:
        return
    if check_deadline is not None:
        check_deadline()
    adir = _verify_acks_dir_node(stream_dir, perms)
    if adir is None:
        adir = stream_dir / _ACKS_DIR
        ensure_dir_tree_atomic(adir, perms, renamer, check_deadline=check_deadline)
    for (page, hex64), payload in sorted(dirty_payloads.items()):
        if check_deadline is not None:
            check_deadline()
        final_path = adir / ack_page_filename(page, hex64)
        if os.path.lexists(final_path):
            continue
        tmp_path = adir / f".ack-{uuid.uuid4().hex}{_PART_SUFFIX}"
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
            committed = True
        except BrainError:
            raise
        except OSError as err:
            raise raise_storage_error(err, "cannot write ack page") from err
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if not committed and staging_cleanup_allowed():
                tmp_path.unlink(missing_ok=True)
    sync_dir(adir)
