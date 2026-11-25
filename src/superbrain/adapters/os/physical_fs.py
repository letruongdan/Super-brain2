"""Physical object identity, non-following target verification, and apply staging selection (spec 11.2, I3-2)."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import normalize_proposal_rel_path, validate_journal_id
from superbrain.ports.os import OsAdapters, PhysicalFsPort, PhysicalObjectId

__all__ = [
    "OsPhysicalFs",
    "atomic_append_no_follow",
    "select_apply_staging_dir",
    "stat_physical_identity",
    "verify_physical_target",
]

_REPARSE_POINT = 0x400
_DIR_ATTR = 0x10
_WIN_NOT_FOUND = frozenset({2, 3})
_WIN_ERROR_DISK_FULL = 112

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _OPEN_EXISTING = 3
    _FILE_APPEND_DATA_SYNC = 0x0004 | 0x00100000  # FILE_APPEND_DATA | SYNCHRONIZE (no FILE_WRITE_DATA -> atomic EOF)
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    _FILE_FLAGS_NOFOLLOW = 0x02000000 | 0x00200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    _FILE_ID_INFO_CLASS = 18

    class _Filetime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _ByHandleFileInfo(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _Filetime),
            ("ftLastAccessTime", _Filetime),
            ("ftLastWriteTime", _Filetime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", ctypes.c_ubyte * 16)]

    _CREATE_FILE_W = _KERNEL32.CreateFileW
    _CREATE_FILE_W.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CREATE_FILE_W.restype = wintypes.HANDLE
    _CLOSE_HANDLE = _KERNEL32.CloseHandle
    _CLOSE_HANDLE.argtypes = [wintypes.HANDLE]
    _CLOSE_HANDLE.restype = wintypes.BOOL
    _GET_FILE_INFO_BY_HANDLE = _KERNEL32.GetFileInformationByHandle
    _GET_FILE_INFO_BY_HANDLE.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInfo)]
    _GET_FILE_INFO_BY_HANDLE.restype = wintypes.BOOL
    _GET_FILE_INFO_BY_HANDLE_EX = _KERNEL32.GetFileInformationByHandleEx
    _GET_FILE_INFO_BY_HANDLE_EX.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _GET_FILE_INFO_BY_HANDLE_EX.restype = wintypes.BOOL
    _WRITE_FILE = _KERNEL32.WriteFile
    _WRITE_FILE.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _WRITE_FILE.restype = wintypes.BOOL

    def _win_atomic_append_no_follow(path: Path, data: bytes) -> None:
        handle = _CREATE_FILE_W(
            str(path),
            _FILE_APPEND_DATA_SYNC,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAGS_NOFOLLOW,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE or not handle:
            err_code = ctypes.get_last_error()
            if err_code == _WIN_ERROR_DISK_FULL:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            raise BrainError(ErrorCode.IO_ERROR, f"cannot open {path} for atomic append: winerror {err_code}")
        try:
            bh = _ByHandleFileInfo()
            if not _GET_FILE_INFO_BY_HANDLE(handle, ctypes.byref(bh)):
                err_code = ctypes.get_last_error()
                raise BrainError(ErrorCode.IO_ERROR, f"cannot inspect handle for {path}: winerror {err_code}")
            if bh.dwFileAttributes & _REPARSE_POINT:
                raise BrainError(ErrorCode.UNSAFE_PATH, f"refusing symlink or reparse point: {path}")
            if bh.dwFileAttributes & _DIR_ATTR:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"target is a directory: {path}")
            if not data:
                return
            total = len(data)
            buf = ctypes.create_string_buffer(data, total)
            written = 0
            while written < total:
                chunk_written = wintypes.DWORD(0)
                ok = _WRITE_FILE(
                    handle,
                    ctypes.c_void_p(ctypes.addressof(buf) + written),
                    total - written,
                    ctypes.byref(chunk_written),
                    None,
                )
                if not ok:
                    err_code = ctypes.get_last_error()
                    if err_code == _WIN_ERROR_DISK_FULL:
                        raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
                    raise BrainError(ErrorCode.IO_ERROR, f"cannot append to {path}: winerror {err_code}")
                if chunk_written.value <= 0:
                    raise BrainError(ErrorCode.IO_ERROR, f"short write while appending to {path}")
                written += chunk_written.value
        finally:
            _CLOSE_HANDLE(handle)

    def _win_stat_physical(path: Path) -> PhysicalObjectId | None:
        handle = _CREATE_FILE_W(str(path), 0, _FILE_SHARE_ALL, None, _OPEN_EXISTING, _FILE_FLAGS_NOFOLLOW, None)
        if handle == _INVALID_HANDLE_VALUE or not handle:
            err_code = ctypes.get_last_error()
            if err_code in _WIN_NOT_FOUND:
                return None
            raise BrainError(ErrorCode.IO_ERROR, f"cannot open handle for {path}: winerror {err_code}")
        try:
            bh = _ByHandleFileInfo()
            if not _GET_FILE_INFO_BY_HANDLE(handle, ctypes.byref(bh)):
                raise BrainError(ErrorCode.IO_ERROR, f"cannot read file attributes for {path}")
            is_link = bool(bh.dwFileAttributes & _REPARSE_POINT)
            is_dir = bool(bh.dwFileAttributes & _DIR_ATTR)
            id_info = _FileIdInfo()
            if _GET_FILE_INFO_BY_HANDLE_EX(
                handle, _FILE_ID_INFO_CLASS, ctypes.byref(id_info), ctypes.sizeof(id_info)
            ):
                vol = f"winvol:{id_info.VolumeSerialNumber:016x}"
                obj = f"winid:{bytes(id_info.FileId).hex()}"
                return PhysicalObjectId(volume_id=vol, object_id=obj, is_link=is_link, is_dir=is_dir)
            vol = f"winvol:{bh.dwVolumeSerialNumber:08x}"
            idx = (bh.nFileIndexHigh << 32) | bh.nFileIndexLow
            obj = f"winidx:{idx:016x}"
            return PhysicalObjectId(volume_id=vol, object_id=obj, is_link=is_link, is_dir=is_dir)
        finally:
            _CLOSE_HANDLE(handle)


def stat_physical_identity(path: Path) -> PhysicalObjectId | None:
    """Return non-following ``PhysicalObjectId`` for ``path``, or ``None`` if absent."""
    if sys.platform == "win32":
        return _win_stat_physical(path)
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot lstat {path}: {err}") from err
    return PhysicalObjectId(
        volume_id=f"dev:{st.st_dev}",
        object_id=f"ino:{st.st_ino}",
        is_link=stat.S_ISLNK(st.st_mode),
        is_dir=stat.S_ISDIR(st.st_mode),
    )


def atomic_append_no_follow(path: Path, data: bytes) -> None:
    """Append ``data`` atomically at EOF without following symlinks or reparse points."""
    if sys.platform == "win32":
        _win_atomic_append_no_follow(path, data)
        return
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    eloop = getattr(errno, "ELOOP", None)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as err:
        if err.errno in (errno.ENOSPC, errno.EDQUOT):
            raise BrainError(ErrorCode.STORAGE_FULL, "storage full") from err
        if eloop is not None and err.errno == eloop:
            raise BrainError(ErrorCode.UNSAFE_PATH, f"refusing symlink: {path}") from err
        if err.errno == errno.EISDIR:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"target is a directory: {path}") from err
        raise BrainError(ErrorCode.IO_ERROR, f"cannot open {path} for atomic append: {err}") from err
    try:
        st = os.fstat(fd)
        if stat.S_ISLNK(st.st_mode):
            raise BrainError(ErrorCode.UNSAFE_PATH, f"refusing symlink: {path}")
        if stat.S_ISDIR(st.st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"target is a directory: {path}")
        if not stat.S_ISREG(st.st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"path {path} is not a regular file")
        view = memoryview(data)
        written = 0
        while written < len(data):
            try:
                n = os.write(fd, view[written:])
            except OSError as err:
                if err.errno in (errno.ENOSPC, errno.EDQUOT):
                    raise BrainError(ErrorCode.STORAGE_FULL, "storage full") from err
                raise BrainError(ErrorCode.IO_ERROR, f"cannot append to {path}: {err}") from err
            if n <= 0:
                raise BrainError(ErrorCode.IO_ERROR, f"short write while appending to {path}")
            written += n
    finally:
        os.close(fd)


def _nearest_existing(path: Path) -> Path:
    cur = Path(os.path.abspath(path))
    while not os.path.lexists(cur) and cur != cur.parent:
        cur = cur.parent
    return cur


class OsPhysicalFs(PhysicalFsPort):
    """Real ``PhysicalFsPort`` implementation backed by ``stat_physical_identity``."""

    def stat_physical_identity(self, path: Path) -> PhysicalObjectId | None:
        return stat_physical_identity(path)

    def same_volume(self, first: Path, second: Path) -> bool:
        a_id = self.stat_physical_identity(_nearest_existing(first))
        b_id = self.stat_physical_identity(_nearest_existing(second))
        if a_id is None or b_id is None:
            return False
        return a_id.volume_id == b_id.volume_id


def _reject_path_spelling(raw: str, os_: OsAdapters) -> None:
    if not raw or "\x00" in raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if raw.startswith(("\\\\", "//")):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
    if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    os_.paths.reject_unsafe_path(raw)


def verify_physical_target(
    root: Path, rel_path: str, os_: OsAdapters
) -> tuple[PhysicalObjectId, PhysicalObjectId | None]:
    """Validate ``root / rel_path`` safety/links/ancestors and return ``(parent_id, target_id_or_None)``."""
    _reject_path_spelling(str(root), os_)
    if not root.is_absolute():
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    norm_rel = normalize_proposal_rel_path(rel_path)
    target = root.joinpath(*norm_rel.split("/"))
    os_.paths.reject_links(target)
    if os_.permissions.check_ancestors(target):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    phys = os_.physical if os_.physical is not None else OsPhysicalFs()
    parent_id = phys.stat_physical_identity(target.parent)
    if parent_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if parent_id.is_link:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not parent_id.is_dir:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    target_id = phys.stat_physical_identity(target)
    if target_id is not None:
        if target_id.is_link:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        if target_id.is_dir:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return parent_id, target_id


def _ensure_trusted_dir(path: Path, os_: OsAdapters) -> None:
    os_.paths.reject_links(path)
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except (FileExistsError, NotADirectoryError) as err:
        raise BrainError(ErrorCode.INVALID_INPUT, f"staging path is not a directory: {path}") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot create staging dir {path}: {err}") from err
    os_.paths.reject_links(path)
    if not path.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.permissions.secure_directory(path)
    if os_.permissions.check_ancestors(path) or os_.permissions.object_problems(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


def select_apply_staging_dir(
    target_root: Path, data_root: Path, journal_id: str, owner_id: str, os_: OsAdapters
) -> Path:
    """Validate link/permission safety BEFORE creating same-volume or cross-volume apply staging directory."""
    _reject_path_spelling(str(target_root), os_)
    _reject_path_spelling(str(data_root), os_)
    if not target_root.is_absolute() or not data_root.is_absolute():
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    validate_journal_id(journal_id)
    os_.paths.reject_links(target_root, entries=[target_root.parent])
    os_.paths.reject_links(data_root)
    if os_.permissions.check_ancestors(target_root) or os_.permissions.check_ancestors(data_root):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    phys = os_.physical if os_.physical is not None else OsPhysicalFs()
    if phys.same_volume(target_root, data_root):
        if os_.permissions.object_problems(data_root):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        base = data_root / "apply_staging"
    else:
        owner_tag = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()[:12]
        base = target_root.parent / f".ensemble-brain-apply-{owner_tag}"
    _ensure_trusted_dir(base, os_)
    staging = base / journal_id
    _ensure_trusted_dir(staging, os_)
    return staging
