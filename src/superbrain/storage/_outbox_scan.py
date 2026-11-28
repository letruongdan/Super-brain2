"""Single-pass outbox directory scans; staging is removed only when the caller asked for a sweep."""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OutboxPermissionsPort
from superbrain.storage import _outbox_io as _io
from superbrain.storage._outbox_acks import _ACKS_DIR, _verify_acks_dir_node, verify_acks_dir
from superbrain.storage._outbox_bindings import _BINDINGS_DIR, _verify_bindings_dir_node, verify_bindings_dir

_DEADLINE_CHECK_STRIDE = 64

ScanResult = tuple[int, int, Path | None, int, dict[str, Path], bool]


def _is_creation_stage(name: str) -> bool:
    return name.startswith(".") and ".init-" in name


def _is_root_stage(name: str) -> bool:
    # The lock file's own stage is created before the lock is held, so only the streams directory stage is swept.
    return name.startswith(f".{_io._STREAMS_DIR}.init-")


def _sweep_stage(entry: os.DirEntry[str]) -> None:
    # Creation stages are made only under the spool lock, so a leftover one belongs to a dead attempt.
    if entry.is_dir(follow_symlinks=False):
        dl = _io.active_deadline_check()
        if dl is not None:
            dl()
        shutil.rmtree(entry.path, ignore_errors=True)
    else:
        _io.unlink_before_deadline(Path(entry.path))


def scan_stream_dir(
    sdir: Path, *, perms: OutboxPermissionsPort, check: Callable[[], None], match_suffix: str | None,
    counter: list[int], sweep: bool, frames_out: dict[str, Path] | None,
) -> tuple[int, int, Path | None, int]:
    """Sum frame bytes in one stream, track the highest order and sequence, and locate ``match_suffix``."""
    _io.verify_owner_only(sdir, perms)
    check()
    total_bytes = highest_order = max_frame_seq = 0
    matched_path: Path | None = None
    with os.scandir(sdir) as sit:
        for fe in sit:
            counter[0] += 1
            if (counter[0] & (_DEADLINE_CHECK_STRIDE - 1)) == 0:
                check()
            if _io.entry_is_link(fe):
                raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
            name = fe.name
            if name == _BINDINGS_DIR:
                verify_bindings_dir(sdir, perms, sweep=True) if sweep else _verify_bindings_dir_node(sdir, perms)
                continue
            if name == _ACKS_DIR:
                verify_acks_dir(sdir, perms, sweep=True) if sweep else _verify_acks_dir_node(sdir, perms)
                continue
            if name.endswith(_io._PART_SUFFIX) or _is_creation_stage(name):
                if sweep:
                    _sweep_stage(fe)
                continue
            if name.endswith(_io._FRAME_SUFFIX):
                st = fe.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "frame entry is not a regular file")
                total_bytes += st.st_size
                highest_order = max(highest_order, _io.parse_frame_order(Path(fe.path))[0])
                if frames_out is not None:
                    frames_out[name] = Path(fe.path)
                    ident = _io.parse_frame_filename_identity(name)
                    if ident is not None:
                        max_frame_seq = max(max_frame_seq, ident[1])
                if match_suffix is not None and name.endswith(match_suffix):
                    matched_path = Path(fe.path)
    return total_bytes, highest_order, matched_path, max_frame_seq


def scan_outbox(
    root: Path, *, perms: OutboxPermissionsPort, check: Callable[[], None], match_stream_key: str | None,
    match_suffix: str | None, sweep: bool, collect_stream_frames: bool,
) -> ScanResult:
    """Reject links, sum frame bytes, optionally collect one stream's frames; sweep staging only when asked."""
    stream_frames: dict[str, Path] = {}
    if not os.path.lexists(root):
        return 0, 0, None, 0, stream_frames, False
    total_bytes = highest_order = max_stream_seq = 0
    matched_path: Path | None = None
    stream_verified = False
    counter = [0]
    streams_dir: Path | None = None
    with os.scandir(root) as root_it:
        for re_entry in root_it:
            counter[0] += 1
            if (counter[0] & (_DEADLINE_CHECK_STRIDE - 1)) == 0:
                check()
            if _io.entry_is_link(re_entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            rname = re_entry.name
            if rname.endswith(_io._PART_SUFFIX) or _is_root_stage(rname):
                if sweep:
                    _sweep_stage(re_entry)
            elif rname == _io._STREAMS_DIR:
                if not stat.S_ISDIR(re_entry.stat(follow_symlinks=False).st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams entry is not a directory")
                streams_dir = Path(re_entry.path)
    if streams_dir is None:
        return 0, 0, None, 0, stream_frames, False
    _io.verify_owner_only(streams_dir, perms)
    check()
    with os.scandir(streams_dir) as st_it:
        for sd_entry in st_it:
            check()
            if _io.entry_is_link(sd_entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
            if sd_entry.name == _io._V4_FENCE_FILE:
                _io.verify_v4_fence_file(Path(sd_entry.path), perms)
                continue
            if _io.is_v4_fence_part_name(sd_entry.name) or _is_creation_stage(sd_entry.name):
                if sweep:
                    _sweep_stage(sd_entry)
                continue
            if not stat.S_ISDIR(sd_entry.stat(follow_symlinks=False).st_mode):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream entry is not a directory")
            is_target = match_stream_key is not None and sd_entry.name == match_stream_key
            stream_verified = stream_verified or is_target
            sb, so, mp, s_max_seq = scan_stream_dir(
                Path(sd_entry.path), perms=perms, check=check, match_suffix=match_suffix if is_target else None,
                counter=counter, sweep=sweep,
                frames_out=stream_frames if (collect_stream_frames and is_target) else None,
            )
            total_bytes += sb
            highest_order = max(highest_order, so)
            max_stream_seq = max(max_stream_seq, s_max_seq)
            if mp is not None:
                matched_path = mp
    check()
    return total_bytes, highest_order, matched_path, max_stream_seq, stream_frames, stream_verified


def collect_regular_frames(directory: Path, perms: OutboxPermissionsPort) -> list[Path]:
    """List regular ``.frame`` files in one stream directory, refusing links and non-regular frames."""
    if _io.is_link_path(directory):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
    if not stat.S_ISDIR(os.lstat(directory).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream path is not a directory")
    _io.verify_owner_only(directory, perms)
    found: list[Path] = []
    with os.scandir(directory) as it:
        for entry in it:
            if _io.entry_is_link(entry):
                raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
            if entry.name.endswith(_io._FRAME_SUFFIX):
                if not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "frame entry is not a regular file")
                found.append(Path(entry.path))
    return found
