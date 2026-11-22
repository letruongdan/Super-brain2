"""Durable publishing of files and directories, and an honest durability tier.

``_fsync_directory`` is extracted from the old ``ensemble_brain/storage/artifacts.py`` (blob b0bb49c).
The tier claim must never be stronger than what the OS and filesystem provide: ``power_loss_durable``
is reported only for an allow-listed local filesystem, outside a cloud-synced folder, after a passing probe.
"""

import contextlib
import errno
import importlib
import os
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import DurabilityReport, DurabilityTier, FsInfo, NoReplacePublisher

_ERROR_SHARING_VIOLATION = 32
_ERROR_ACCESS_DENIED = 5
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_ERROR_DISK_FULL = 112
_BUSY_WINERRORS = frozenset({_ERROR_SHARING_VIOLATION, _ERROR_ACCESS_DENIED})
_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8)
# F_FULLFSYNC unsupported by the filesystem (SMB, FAT, some FUSE mounts): fall back to fsync.
_FULLFSYNC_UNSUPPORTED = frozenset({errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL, errno.ENOTTY})
# fsync of a directory descriptor unsupported by the OS or filesystem. EBADF counts too: the descriptor was just
# opened here, so EBADF can only mean the platform cannot fsync a directory opened read-only.
_DIR_FSYNC_UNSUPPORTED = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EBADF})

MOVEFILE_REPLACE_EXISTING = 0x1
MOVEFILE_WRITE_THROUGH = 0x8

_DRIVE_FIXED = 3
_DRIVE_REMOTE = 4

_VOLATILE_FS = frozenset({"tmpfs", "ramfs"})
_REMOTE_FS = frozenset({"nfs", "nfs4", "cifs", "smb3", "9p"})
_ONEDRIVE_VARS = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
_PROBE_PREFIX = ".durability-probe-"


# --------------------------------------------------------------------------------------------------
# Low-level helpers


def _winerror(err: OSError) -> int | None:
    value = getattr(err, "winerror", None)
    return value if isinstance(value, int) else None


def _is_disk_full(err: OSError) -> bool:
    return err.errno in (errno.ENOSPC, errno.EDQUOT) or _winerror(err) == _ERROR_DISK_FULL


def map_os_error(err: OSError, what: str) -> BrainError:
    """Translate an OS failure for the adapters (``storage.errors.os_error`` is the storage twin, which
    ``storage`` uses because it never imports ``adapters``); the caller chains it with ``from err``."""
    if _is_disk_full(err):
        return BrainError(ErrorCode.STORAGE_FULL, f"no space left while {what}")
    return BrainError(ErrorCode.IO_ERROR, f"I/O error while {what}: {err}")


def full_fsync(fd: int, *, platform: str = sys.platform) -> bool:
    """Flush ``fd`` as hard as the platform allows; ``False`` if only a weaker flush was possible.

    On macOS ``fsync`` does not reach stable storage, so this uses ``F_FULLFSYNC``; where the filesystem does not
    support it (``ENOTSUP``/``EINVAL``/``ENOTTY``) it falls back to ``fsync`` and returns ``False``. Elsewhere it is
    ``fsync``. Any other error propagates.
    """
    if platform == "darwin":
        fcntl = importlib.import_module("fcntl")  # macOS-only names, so not a static import
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return True
        except OSError as err:
            if err.errno not in _FULLFSYNC_UNSUPPORTED:
                raise
        os.fsync(fd)
        return False
    os.fsync(fd)
    return True


def _fsync_directory(path: Path, *, nt: bool = os.name == "nt") -> bool:
    """Persist directory entries (extracted from the old ``_fsync_directory``, blob b0bb49c); ``False`` if the
    entries could not be flushed as hard as a file.

    Windows cannot open directory handles through ``os.open``; there ``MOVEFILE_WRITE_THROUGH`` does the job. Where
    the OS or filesystem cannot fsync a directory (``EINVAL``/``ENOTSUP``/``ENOSYS``/``EBADF``) this returns ``False``
    and the caller continues; ``durability()`` reports such a filesystem below power-loss. ``EIO``, ``ENOSPC`` and
    every other error propagate.
    """
    if nt:
        return True
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        return full_fsync(descriptor)
    except OSError as err:
        if err.errno in _DIR_FSYNC_UNSUPPORTED:
            return False
        raise
    finally:
        os.close(descriptor)


# --------------------------------------------------------------------------------------------------
# Filesystem detection


def _unescape_mountinfo(field: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(field):
        if field[i] == 0x5C and i + 4 <= len(field) and field[i + 1 : i + 4].isdigit():
            out.append(int(field[i + 1 : i + 4], 8) & 0xFF)
            i += 4
        else:
            out.append(field[i])
            i += 1
    return bytes(out)


def _components(path: bytes) -> list[bytes]:
    return [part for part in path.split(b"/") if part]


def _fs_from_mountinfo(data: bytes, path: bytes) -> FsInfo:
    """Return the fs of the longest mount point that is a path prefix of ``path`` (Linux mountinfo).

    Works on bytes so a mount point that is not valid UTF-8 can never be mis-matched.
    """
    target = _components(path)
    best: tuple[int, str] | None = None
    for line in data.splitlines():
        head, separator, tail = line.partition(b" - ")
        fields = head.split()
        tail_fields = tail.split()
        if not separator or len(fields) < 5 or not tail_fields:
            continue
        mount = _components(_unescape_mountinfo(fields[4]))
        if target[: len(mount)] == mount and (best is None or len(mount) >= best[0]):
            best = (len(mount), tail_fields[0].decode("ascii", errors="replace"))
    if best is None:
        return FsInfo("unknown", False)
    fs_type = best[1]
    return FsInfo(fs_type, fs_type in _REMOTE_FS or fs_type.startswith("fuse."))


def _existing_ancestor(path: Path) -> Path:
    candidate = path.resolve()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


if sys.platform == "win32":
    import ctypes as _win_ctypes
    from ctypes import wintypes as _win_wintypes

    _KERNEL32 = _win_ctypes.WinDLL("kernel32", use_last_error=True)
    _MOVE_FILE_EX_W = _KERNEL32.MoveFileExW
    _MOVE_FILE_EX_W.argtypes = [_win_wintypes.LPCWSTR, _win_wintypes.LPCWSTR, _win_wintypes.DWORD]
    _MOVE_FILE_EX_W.restype = _win_wintypes.BOOL
    _GET_VOLUME_PATH_NAME_W = _KERNEL32.GetVolumePathNameW
    _GET_VOLUME_PATH_NAME_W.argtypes = [_win_wintypes.LPCWSTR, _win_wintypes.LPWSTR, _win_wintypes.DWORD]
    _GET_VOLUME_PATH_NAME_W.restype = _win_wintypes.BOOL
    _GET_VOLUME_INFORMATION_W = _KERNEL32.GetVolumeInformationW
    _GET_VOLUME_INFORMATION_W.argtypes = [
        _win_wintypes.LPCWSTR,
        _win_wintypes.LPWSTR,
        _win_wintypes.DWORD,
        _win_wintypes.LPDWORD,
        _win_wintypes.LPDWORD,
        _win_wintypes.LPDWORD,
        _win_wintypes.LPWSTR,
        _win_wintypes.DWORD,
    ]
    _GET_VOLUME_INFORMATION_W.restype = _win_wintypes.BOOL
    _GET_DRIVE_TYPE_W = _KERNEL32.GetDriveTypeW
    _GET_DRIVE_TYPE_W.argtypes = [_win_wintypes.LPCWSTR]
    _GET_DRIVE_TYPE_W.restype = _win_wintypes.UINT

    def _move_file_ex(src: str, dst: str, flags: int) -> None:
        """Call kernel32 ``MoveFileExW``; raise ``OSError`` carrying ``winerror`` on failure."""
        if not _MOVE_FILE_EX_W(src, dst, flags):
            raise _win_ctypes.WinError(_win_ctypes.get_last_error())

    def _detect_windows(path: Path) -> FsInfo:
        root = _win_ctypes.create_unicode_buffer(32768)
        if not _GET_VOLUME_PATH_NAME_W(str(_existing_ancestor(path)), root, len(root)):
            raise _win_ctypes.WinError(_win_ctypes.get_last_error())
        name = _win_ctypes.create_unicode_buffer(261)
        if not _GET_VOLUME_INFORMATION_W(root.value, None, 0, None, None, None, name, len(name)):
            raise _win_ctypes.WinError(_win_ctypes.get_last_error())
        kind = _GET_DRIVE_TYPE_W(root.value)
        if kind == _DRIVE_REMOTE:
            return FsInfo(name.value, True)
        if kind != _DRIVE_FIXED:
            # Removable, RAM disk or undetermined drives are never claimed power-loss durable.
            return FsInfo(f"{name.value} (drive type {kind})", False)
        return FsInfo(name.value, False)
else:

    def _move_file_ex(src: str, dst: str, flags: int) -> None:
        """Call kernel32 ``MoveFileExW``; raise ``OSError`` carrying ``winerror`` on failure."""
        raise OSError(errno.ENOSYS, "MoveFileExW is only available on Windows")

    def _detect_windows(path: Path) -> FsInfo:
        raise OSError(errno.ENOSYS, "Windows only")


def _detect_linux(path: Path) -> FsInfo:
    with open("/proc/self/mountinfo", "rb") as handle:
        return _fs_from_mountinfo(handle.read(), os.fsencode(_existing_ancestor(path)))


def _detect_darwin(path: Path) -> FsInfo:
    import ctypes

    class StatFs(ctypes.Structure):
        # struct statfs from <sys/mount.h> with 64-bit inodes (MAC_OS_X_VERSION >= 10.6 default layout).
        _fields_ = (
            ("f_bsize", ctypes.c_uint32),
            ("f_iosize", ctypes.c_int32),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_uint64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_uint64),
            ("f_fsid", ctypes.c_int32 * 2),
            ("f_owner", ctypes.c_uint32),
            ("f_type", ctypes.c_uint32),
            ("f_flags", ctypes.c_uint32),
            ("f_fssubtype", ctypes.c_uint32),
            ("f_fstypename", ctypes.c_char * 16),
            ("f_mntonname", ctypes.c_char * 1024),
            ("f_mntfromname", ctypes.c_char * 1024),
            ("f_reserved", ctypes.c_uint32 * 8),
        )

    mnt_local = 0x00001000
    libc = ctypes.CDLL(None, use_errno=True)
    # On x86_64 the plain symbol is the legacy 32-bit-inode layout; the 64-bit one carries a suffix.
    try:
        function = libc["statfs$INODE64"]
    except AttributeError:
        function = libc["statfs"]
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(StatFs)]
    function.restype = ctypes.c_int
    buffer = StatFs()
    if function(os.fsencode(_existing_ancestor(path)), ctypes.byref(buffer)) != 0:
        raise OSError(ctypes.get_errno(), "statfs failed")
    fs_type = bytes(buffer.f_fstypename).decode(errors="replace").lower()
    return FsInfo(fs_type, not buffer.f_flags & mnt_local)


def _rename_noreplace(src: Path, dst: Path) -> None:
    """Invoke kernel atomic no-replace rename (`renameat2` / `renamex_np`), or raise ``ENOSYS``/``ENOTSUP``."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    rc: int
    if sys.platform == "darwin":
        fn = getattr(libc, "renamex_np", None)
        if fn is None:
            raise OSError(errno.ENOSYS, "renamex_np unavailable")
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        rc = fn(os.fsencode(src), os.fsencode(dst), 0x4)  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        fn = getattr(libc, "renameat2", None)
        if fn is None:
            raise OSError(errno.ENOSYS, "renameat2 unavailable")
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        rc = fn(-100, os.fsencode(src), -100, os.fsencode(dst), 0x1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise OSError(errno.ENOSYS, "no-replace rename unavailable")
    if rc != 0:
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            raise FileExistsError(errno.EEXIST, os.strerror(err), str(dst))
        raise OSError(err, os.strerror(err))


def detect_fs(path: Path) -> FsInfo:
    """Best-effort filesystem identity of ``path``; ``FsInfo("unknown", False)`` if detection fails."""
    try:
        if sys.platform == "win32":
            return _detect_windows(path)
        if sys.platform == "darwin":
            return _detect_darwin(path)
        return _detect_linux(path)
    except (OSError, RuntimeError, ValueError, AttributeError):
        return FsInfo("unknown", False)


# --------------------------------------------------------------------------------------------------
# Publishers


class _BasePublisher:
    """Shared flow; subclasses supply the platform's rename and directory-sync primitives."""

    _durable_fs: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        sleep: Callable[[float], None] = time.sleep,
        fs_info: Callable[[Path], FsInfo] = detect_fs,
    ) -> None:
        self._sleep = sleep
        self._fs_info = fs_info

    # -- primitives overridden per platform
    def _replace(self, src: Path, dst: Path) -> None:
        os.replace(src, dst)

    def _rename_dir(self, src: Path, dst: Path) -> None:
        # The existence check is not atomic against another process; acceptable because the single
        # writer holds the store lock (spec 5.5).
        if os.path.lexists(dst):
            raise FileExistsError(errno.EEXIST, "target directory exists", str(dst))
        os.rename(src, dst)

    def _sync_dir(self, directory: Path) -> bool:
        return _fsync_directory(directory)

    # -- public operations
    def sync_directory(self, directory: Path) -> None:
        self._synced(directory)

    def flush_file(self, path: Path) -> None:
        self._flushed(path)

    def write_new(self, path: Path, data: bytes) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise  # port contract: callers translate it; nothing was created
        except OSError as err:
            raise map_os_error(err, f"creating {path}") from err
        try:
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                full_fsync(fd)
            finally:
                os.close(fd)
        except BaseException as err:
            with contextlib.suppress(OSError):
                path.unlink()
            if isinstance(err, OSError):
                raise map_os_error(err, f"writing {path}") from err
            raise

    def publish(self, staging: Path, final: Path) -> None:
        self._guard(lambda: self._replace(staging, final), f"publishing {staging} to {final}")
        self.sync_directory(final.parent)

    def _noreplace(self, src: Path, dst: Path) -> None:
        try:
            _rename_noreplace(src, dst)
        except FileExistsError:
            raise
        except (OSError, AttributeError) as err:
            err_no = getattr(err, "errno", None)
            if isinstance(err, OSError) and err_no not in (
                errno.ENOSYS,
                errno.EINVAL,
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
                95,
            ):
                raise
            os.link(src, dst)
            self.sync_directory(dst.parent)
            os.unlink(src)
            self.sync_directory(src.parent)
            return
        self.sync_directory(dst.parent)
        self.sync_directory(src.parent)

    def publish_no_replace(self, staging: Path, final: Path) -> None:
        self._guard(lambda: self._noreplace(staging, final), f"publishing {staging} to {final}")

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._guard(lambda: self._rename_dir(src, dst), f"renaming directory {src} to {dst}")
        self.sync_directory(dst.parent)

    def _synced(self, directory: Path) -> bool:
        """``sync_directory``; ``False`` if the directory could not be flushed as hard as a file."""
        try:
            return self._sync_dir(directory)
        except OSError as err:
            raise map_os_error(err, f"syncing directory {directory}") from err

    def _flushed(self, path: Path) -> bool:
        """``flush_file``; ``False`` if only a weaker flush than the platform's full one was possible. Opened for
        writing because Windows flushes (``FlushFileBuffers``) only through a handle with write access."""
        try:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
        except OSError as err:
            raise map_os_error(err, f"opening {path} to flush it") from err
        try:
            try:
                return full_fsync(fd)
            finally:
                os.close(fd)
        except OSError as err:
            raise map_os_error(err, f"flushing {path}") from err

    def _guard(self, action: Callable[[], None], what: str) -> None:
        try:
            action()
        except FileExistsError:
            raise
        except OSError as err:
            raise map_os_error(err, what) from err

    def _readonly_reasons(self, directory: Path, env: Mapping[str, str]) -> tuple[bool, tuple[str, ...]]:
        try:
            exists = directory.is_dir()
        except (OSError, RuntimeError) as err:
            reason = f"cannot inspect directory: {type(err).__name__}"
            return False, (reason,)
        if not exists:
            return False, ("directory does not exist",)
        reasons: list[str] = []
        info = self._fs_info(directory)
        if info.remote:
            reasons.append("remote filesystem")
        elif info.fs_type in _VOLATILE_FS:
            reasons.append(f"volatile filesystem {info.fs_type}")
        elif info.fs_type not in self._durable_fs:
            reasons.append(f"unknown filesystem {info.fs_type}")
        reasons.extend(_onedrive_reasons(directory, env))
        return True, tuple(reasons)

    def durability_readonly(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        """Inspect filesystem durability metadata cleanly without creating or writing probe files."""
        exists, reasons = self._readonly_reasons(directory, env)
        if not exists or reasons:
            return DurabilityReport(DurabilityTier.PROCESS_CRASH, reasons)
        return DurabilityReport(DurabilityTier.POWER_LOSS, ())

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        exists, base_reasons = self._readonly_reasons(directory, env)
        if not exists:
            return DurabilityReport(DurabilityTier.PROCESS_CRASH, base_reasons)
        reasons = list(base_reasons)
        if not reasons:
            probe_reason = self._probe(directory)
            if probe_reason is not None:
                reasons.append(probe_reason)
        if reasons:
            return DurabilityReport(DurabilityTier.PROCESS_CRASH, tuple(reasons))
        return DurabilityReport(DurabilityTier.POWER_LOSS, ())

    def _probe(self, directory: Path) -> str | None:
        name = f"{_PROBE_PREFIX}{uuid.uuid4().hex}"
        staging = directory / f"{name}.tmp"
        final = directory / name
        try:
            self.write_new(staging, b"durability probe")
            self.publish(staging, final)
            if not self._flushed(final):
                return "sync probe: no F_FULLFSYNC on this filesystem, only fsync"
            if not self._synced(directory):
                return "sync probe: this filesystem cannot fsync a directory"
        except FileExistsError as err:
            return f"sync probe failed: {errno.errorcode.get(err.errno or 0, err.errno)}"
        except BrainError as err:
            cause = err.__cause__
            if isinstance(cause, OSError):
                return f"sync probe failed: {errno.errorcode.get(cause.errno or 0, cause.errno)}"
            return f"sync probe failed: {err.code.value}"
        finally:
            for leftover in (staging, final):
                with contextlib.suppress(OSError):
                    leftover.unlink(missing_ok=True)
        return None


def _onedrive_reasons(directory: Path, env: Mapping[str, str]) -> list[str]:
    try:
        resolved = directory.resolve()
    except (OSError, RuntimeError) as err:
        return [f"cannot inspect directory: {type(err).__name__}"]
    reasons: list[str] = []
    for key in _ONEDRIVE_VARS:
        value = env.get(key)
        if not value:
            continue
        try:
            inside = resolved.is_relative_to(Path(value).resolve())
        except (OSError, RuntimeError) as err:
            reasons.append(f"cannot inspect {key} path: {type(err).__name__}")
            continue
        if inside and "cloud-synced folder (OneDrive)" not in reasons:
            reasons.append("cloud-synced folder (OneDrive)")
    return reasons


class PosixPublisher(_BasePublisher):
    _durable_fs = frozenset({"ext4", "ext3", "xfs", "btrfs", "f2fs", "zfs"})


class DarwinPublisher(_BasePublisher):
    """macOS. The class only names the durable filesystems: ``F_FULLFSYNC`` (``fsync`` does not reach stable storage
    there) is chosen by the module-level ``full_fsync`` from the platform, for every publisher and the lock file."""

    _durable_fs = frozenset({"apfs", "hfs"})


class WindowsPublisher(_BasePublisher):
    _durable_fs = frozenset({"NTFS", "ReFS"})

    def _replace(self, src: Path, dst: Path) -> None:
        self._move(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)

    def _noreplace(self, src: Path, dst: Path) -> None:
        try:
            self._move(src, dst, MOVEFILE_WRITE_THROUGH)
        except OSError as err:
            if _winerror(err) in (_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS):
                raise FileExistsError(errno.EEXIST, "target exists", str(dst)) from err
            raise

    def _rename_dir(self, src: Path, dst: Path) -> None:
        try:
            self._move(src, dst, MOVEFILE_WRITE_THROUGH)
        except OSError as err:
            if _winerror(err) in (_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS):
                raise FileExistsError(errno.EEXIST, "target directory exists", str(dst)) from err
            raise

    def _sync_dir(self, directory: Path) -> bool:
        """No separate operation: ``MOVEFILE_WRITE_THROUGH`` makes the rename durable."""
        return True

    def _move(self, src: Path, dst: Path, flags: int) -> None:
        for attempt in range(len(_RETRY_DELAYS) + 1):
            try:
                _move_file_ex(str(src), str(dst), flags)
                return
            except OSError as err:
                if _winerror(err) not in _BUSY_WINERRORS:
                    raise
                if attempt == len(_RETRY_DELAYS):
                    raise BrainError(
                        ErrorCode.FILESYSTEM_BUSY,
                        f"{dst.name} is held by another process (antivirus or indexer?)",
                    ) from err
                self._sleep(_RETRY_DELAYS[attempt])


def publisher_for(platform: str, *, fs_info: Callable[[Path], FsInfo] = detect_fs) -> NoReplacePublisher:
    if platform == "win32":
        return WindowsPublisher(fs_info=fs_info)
    if platform == "darwin":
        return DarwinPublisher(fs_info=fs_info)
    return PosixPublisher(fs_info=fs_info)
