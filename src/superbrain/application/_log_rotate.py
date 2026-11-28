"""Write-ahead move-based log rotation and interrupted-rotation recovery (spec 13, R3-I2)."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from superbrain.core.errors import BrainError, ErrorCode, describe_exception
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.doctor import MAX_LOG_BYTES
from superbrain.ports.os import OsAdapters, PhysicalObjectId

__all__ = ["rotate_logs"]

_ACTIVE_NAME = "brain.log"
_STATE_PREFIX = ".rotate-state-"
_STATE_SUFFIX = ".json"
_ROTATING_PREFIX = ".brain.log.rotating-"
_ROTATED_RE = re.compile(r"^brain\.log\.([1-9][0-9]*)$")
_REPARSE_POINT = 0x400
_BUSY_WINERRORS = frozenset({5, 32, 33})  # ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION


def _is_link_stat(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _require_non_link(path: Path, os_: OsAdapters) -> PhysicalObjectId | None:
    os_.paths.reject_links(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _map_busy_or_io(exc, f"inspecting {path.name}") from exc
    if _is_link_stat(st):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link in logs directory: {path.name}")
    if os_.physical is not None:
        ident = os_.physical.stat_physical_identity(path)
        if ident is not None and ident.is_link:
            raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link in logs directory: {path.name}")
        return ident
    return None


def _map_busy_or_io(exc: OSError, what: str) -> BrainError:
    winerr = getattr(exc, "winerror", None)
    if (isinstance(winerr, int) and winerr in _BUSY_WINERRORS) or exc.errno in (errno.EBUSY, errno.EACCES):
        return BrainError(ErrorCode.FILESYSTEM_BUSY, f"filesystem busy while {what}")
    return BrainError(ErrorCode.IO_ERROR, f"I/O error while {what}: {describe_exception(exc)}")


def _sha256_file(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                total += len(chunk)
                h.update(chunk)
    except OSError as exc:
        raise _map_busy_or_io(exc, f"reading {path.name}") from exc
    return total, h.hexdigest()


def _sha256_prefix(path: Path, size: int) -> tuple[int, str]:
    """``(total_size, digest of the first size bytes)``; bytes appended after the digest are kept, not judged."""
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                if total < size:
                    h.update(chunk[: size - total])
                total += len(chunk)
    except OSError as exc:
        raise _map_busy_or_io(exc, f"reading {path.name}") from exc
    return total, h.hexdigest()


def _parse_state(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"corrupt rotation state {path.name}") from exc
    if not isinstance(data, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid rotation state {path.name}")
    phase = data.get("phase")
    rot_id = data.get("id")
    size = data.get("size")
    digest = data.get("digest")
    shift_order = data.get("shift_order", [])
    if (
        phase not in ("pending_move", "shifting")
        or not isinstance(rot_id, str)
        or not rot_id
        or type(size) is not int
        or size < 0
        or not isinstance(digest, str)
        or not digest
        or not isinstance(shift_order, list)
        or not all(type(n) is int and n >= 1 for n in shift_order)
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"malformed rotation state {path.name}")
    return dict(data)


def _write_state_publish(logs_dir: Path, state_file: Path, payload: dict[str, Any], os_: OsAdapters) -> None:
    tmp = logs_dir / f".{state_file.name}.tmp-{new_id()}"
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    os_.publisher.write_new(tmp, encoded)
    os_.permissions.secure_file(tmp)
    os_.publisher.publish(tmp, state_file)
    os_.permissions.secure_file(state_file)
    os_.publisher.sync_directory(logs_dir)


def _rotated_indices_desc(logs_dir: Path, os_: OsAdapters) -> list[int]:
    found: list[int] = []
    with os.scandir(logs_dir) as it:
        for entry in it:
            _require_non_link(Path(entry.path), os_)
            m = _ROTATED_RE.fullmatch(entry.name)
            if m is not None:
                found.append(int(m.group(1)))
    found.sort(reverse=True)
    return found


def _publish_move(src: Path, dst: Path, os_: OsAdapters) -> None:
    pre_id = _require_non_link(src, os_)
    _require_non_link(dst, os_)
    cur_id = os_.physical.stat_physical_identity(src) if os_.physical is not None else None
    if pre_id is not None and cur_id != pre_id:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"log target identity changed before move: {src.name}")
    try:
        os_.publisher.publish(src, dst)
    except OSError as exc:
        raise _map_busy_or_io(exc, f"moving {src.name} to {dst.name}") from exc


def _finish_shifting(
    logs_dir: Path,
    state_file: Path,
    state: dict[str, Any],
    rotating: Path,
    os_: OsAdapters,
) -> None:
    if state["phase"] == "pending_move":
        shift_order = _rotated_indices_desc(logs_dir, os_)
        next_state = {
            "id": state["id"],
            "phase": "shifting",
            "size": state["size"],
            "digest": state["digest"],
            "shift_order": shift_order,
        }
        _write_state_publish(logs_dir, state_file, next_state, os_)
    else:
        shift_order = list(state["shift_order"])

    for idx in shift_order:
        src = logs_dir / f"{_ACTIVE_NAME}.{idx}"
        dst = logs_dir / f"{_ACTIVE_NAME}.{idx + 1}"
        if os.path.lexists(src) and not os.path.lexists(dst):
            _publish_move(src, dst, os_)

    rot1 = logs_dir / f"{_ACTIVE_NAME}.1"
    if os.path.lexists(rotating) and not os.path.lexists(rot1):
        _publish_move(rotating, rot1, os_)

    active = logs_dir / _ACTIVE_NAME
    if not os.path.lexists(active):
        os_.publisher.write_new(active, b"")
        os_.permissions.secure_file(active)

    with contextlib.suppress(FileNotFoundError):
        os.unlink(state_file)
    os_.publisher.sync_directory(logs_dir)


class RotationStopped(Exception):  # noqa: N818 - a stop signal, not an error
    """The write gate closed before a rotation step started; ``recovered`` interrupted rotations were finished."""

    def __init__(self, recovered: int) -> None:
        super().__init__("log rotation stopped")
        self.recovered = recovered


def _open_gate(may_write: Callable[[], bool] | None, recovered: int) -> None:
    if may_write is not None and not may_write():
        raise RotationStopped(recovered)


def _recover_interrupted_rotations(
    logs_dir: Path, os_: OsAdapters, may_write: Callable[[], bool] | None = None
) -> bool:
    state_files: dict[str, Path] = {}
    rotating_files: dict[str, Path] = {}
    with os.scandir(logs_dir) as it:
        for entry in sorted(it, key=lambda e: e.name):
            epath = Path(entry.path)
            _require_non_link(epath, os_)
            if entry.name.startswith(_STATE_PREFIX) and entry.name.endswith(_STATE_SUFFIX):
                rot_id = entry.name.removeprefix(_STATE_PREFIX).removesuffix(_STATE_SUFFIX)
                state_files[rot_id] = epath
            elif entry.name.startswith(_ROTATING_PREFIX):
                rot_id = entry.name.removeprefix(_ROTATING_PREFIX)
                rotating_files[rot_id] = epath

    orphan_rotating = sorted(set(rotating_files) - set(state_files))
    if orphan_rotating:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"orphaned staged log rotation: {orphan_rotating[0]}")

    finished = 0
    for rot_id in sorted(state_files):
        state_file = state_files[rot_id]
        state = _parse_state(state_file)
        if state["id"] != rot_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"rotation state id mismatch in {state_file.name}")
        rotating = logs_dir / f"{_ROTATING_PREFIX}{rot_id}"
        if os.path.lexists(rotating):
            # A writer that appended after the digest was taken leaves a longer file: its recorded prefix must
            # still match, and the extra bytes travel with it into brain.log.1.
            r_size, r_digest = _sha256_file(rotating)
            if r_size > state["size"]:
                r_size, r_digest = _sha256_prefix(rotating, int(state["size"]))
            if r_size < state["size"] or r_digest != str(state["digest"]).removeprefix("sha256:"):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"staged log digest/size mismatch: {rotating.name}")
        _open_gate(may_write, finished)  # every check of this journal is done; the next line writes
        if os.path.lexists(rotating):
            _finish_shifting(logs_dir, state_file, state, rotating, os_)
        elif state["phase"] == "shifting":
            _finish_shifting(logs_dir, state_file, state, rotating, os_)
        else:
            os.unlink(state_file)
            os_.publisher.sync_directory(logs_dir)
        finished += 1
    return finished > 0


def rotate_logs(
    logs_dir: Path,
    os_: OsAdapters,
    *,
    max_bytes: int = MAX_LOG_BYTES,
    force: bool = False,
    quiesce_hook: Callable[[], AbstractContextManager[None]] | None = None,
    may_write: Callable[[], bool] | None = None,
) -> tuple[bool, str]:
    """Recover any interrupted rotation and atomically rotate oversized ``brain.log`` without losing bytes.

    ``may_write`` is asked immediately before each write group starts (each recovered journal, then the new
    rotation's journal), after all of that group's reads and checks; when it returns ``False`` the rotation raises
    ``RotationStopped`` and nothing further is written. Every group leaves a journal the next run can finish.
    """
    scope = quiesce_hook() if quiesce_hook is not None else contextlib.nullcontext()
    with scope:
        if not os.path.lexists(logs_dir):
            return False, "logs directory absent"
        _require_non_link(logs_dir, os_)
        with os.scandir(logs_dir) as it:
            for entry in it:
                _require_non_link(Path(entry.path), os_)

        recovered = _recover_interrupted_rotations(logs_dir, os_, may_write)
        active = logs_dir / _ACTIVE_NAME
        if not os.path.lexists(active):
            return recovered, "recovered interrupted rotation" if recovered else "no active brain.log"

        pre_id = _require_non_link(active, os_)
        try:
            st = os.lstat(active)
        except OSError as exc:
            raise _map_busy_or_io(exc, "stating active brain.log") from exc
        if not stat.S_ISREG(st.st_mode):
            raise BrainError(ErrorCode.INVALID_INPUT, "brain.log is not a regular file")
        if st.st_size < max_bytes and not (force and st.st_size > 0):
            return (
                (True, "recovered interrupted rotation while preserving active brain.log")
                if recovered
                else (False, f"brain.log size {st.st_size}B below threshold {max_bytes}B")
            )

        rot_id = new_id()
        size, digest = _sha256_file(active)
        _open_gate(may_write, int(recovered))
        state_file = logs_dir / f"{_STATE_PREFIX}{rot_id}{_STATE_SUFFIX}"
        rotating = logs_dir / f"{_ROTATING_PREFIX}{rot_id}"
        state_payload: dict[str, Any] = {
            "id": rot_id,
            "phase": "pending_move",
            "size": size,
            "digest": digest,
            "shift_order": [],
        }
        os_.publisher.write_new(state_file, json.dumps(state_payload, sort_keys=True).encode("utf-8"))
        os_.permissions.secure_file(state_file)
        os_.publisher.sync_directory(logs_dir)
        try:
            if pre_id is not None and os_.physical is not None:
                cur_id = os_.physical.stat_physical_identity(active)
                if cur_id != pre_id:
                    raise BrainError(ErrorCode.UNSAFE_PATH, "brain.log identity changed before stage move")
            _publish_move(active, rotating, os_)
        except BaseException:
            if not os.path.lexists(rotating) and os.path.lexists(active):
                with contextlib.suppress(OSError):
                    os.unlink(state_file)
            raise

        os_.publisher.sync_directory(logs_dir)
        crashpoint("doctor.fix.after_log_rotate_stage")
        _finish_shifting(logs_dir, state_file, state_payload, rotating, os_)
        return True, f"rotated {size}B brain.log to brain.log.1"
