"""Durable publishing of files and directories, and an honest durability tier.

``_fsync_directory`` is extracted from the old ``ensemble_brain/storage/artifacts.py`` (blob b0bb49c).
The tier claim must never be stronger than what the OS and filesystem provide: ``power_loss_durable``
is reported only for an allow-listed local filesystem, outside a cloud-synced folder, after a passing probe.
"""

import contextlib
import errno
import os
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import DurabilityReport, DurabilityTier, DurablePublisher, FsInfo

_ERROR_SHARING_VIOLATION = 32
_ERROR_ACCESS_DENIED = 5
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_ERROR_DISK_FULL = 112
_BUSY_WINERRORS = frozenset({_ERROR_SHARING_VIOLATION, _ERROR_ACCESS_DENIED})
_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8)

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


def _full_fsync(fd: int) -> None:
    """Flush ``fd`` as hard as the platform allows (``F_FULLFSYNC`` on macOS)."""
    if sys.platform == "darwin":
        import fcntl

        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    else:
        os.fsync(fd)


def _fsync_directory(path: Path) -> None:
    """Persist directory entries (extracted from the old ``_fsync_directory``, blob b0bb49c).

    Windows cannot open directory handles through ``os.open``; there ``MOVEFILE_WRITE_THROUGH`` does the job.
    """
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _full_fsync(descriptor)
    finally:
        os.close(descriptor)


def _move_file_ex(src: str, dst: str, flags: int) -> None:
    """Call kernel32 ``MoveFileExW``; raise ``OSError`` carrying ``winerror`` on failure."""
    if sys.platform != "win32":
        raise OSError(errno.ENOSYS, "MoveFileExW is only available on Windows")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel32.MoveFileExW
    function.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    function.restype = wintypes.BOOL
    if not function(src, dst, flags):
        raise ctypes.WinError(ctypes.get_last_error())


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


def _detect_windows(path: Path) -> FsInfo:
    if sys.platform != "win32":
        raise OSError(errno.ENOSYS, "Windows only")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    volume_path = kernel32.GetVolumePathNameW
    volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    volume_path.restype = wintypes.BOOL
    volume_info = kernel32.GetVolumeInformationW
    volume_info.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    volume_info.restype = wintypes.BOOL
    drive_type = kernel32.GetDriveTypeW
    drive_type.argtypes = [wintypes.LPCWSTR]
    drive_type.restype = wintypes.UINT

    root = ctypes.create_unicode_buffer(32768)
    if not volume_path(str(_existing_ancestor(path)), root, len(root)):
        raise ctypes.WinError(ctypes.get_last_error())
    name = ctypes.create_unicode_buffer(261)
    if not volume_info(root.value, None, 0, None, None, None, name, len(name)):
        raise ctypes.WinError(ctypes.get_last_error())
    kind = drive_type(root.value)
    if kind == _DRIVE_REMOTE:
        return FsInfo(name.value, True)
    if kind != _DRIVE_FIXED:
        # Removable, RAM disk or undetermined drives are never claimed power-loss durable.
        return FsInfo(f"{name.value} (drive type {kind})", False)
    return FsInfo(name.value, False)


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

    def _sync_dir(self, directory: Path) -> None:
        _fsync_directory(directory)

    # -- public operations
    def sync_directory(self, directory: Path) -> None:
        self._guard(lambda: self._sync_dir(directory), f"syncing directory {directory}")

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
                _full_fsync(fd)
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

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._guard(lambda: self._rename_dir(src, dst), f"renaming directory {src} to {dst}")
        self.sync_directory(dst.parent)

    def _guard(self, action: Callable[[], None], what: str) -> None:
        try:
            action()
        except FileExistsError:
            raise
        except OSError as err:
            raise map_os_error(err, what) from err

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        try:
            exists = directory.is_dir()
        except (OSError, RuntimeError) as err:
            reason = f"cannot inspect directory: {type(err).__name__}"
            return DurabilityReport(DurabilityTier.PROCESS_CRASH, (reason,))
        if not exists:
            return DurabilityReport(DurabilityTier.PROCESS_CRASH, ("directory does not exist",))
        reasons: list[str] = []
        info = self._fs_info(directory)
        if info.remote:
            reasons.append("remote filesystem")
        elif info.fs_type in _VOLATILE_FS:
            reasons.append(f"volatile filesystem {info.fs_type}")
        elif info.fs_type not in self._durable_fs:
            reasons.append(f"unknown filesystem {info.fs_type}")
        reasons.extend(_onedrive_reasons(directory, env))
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
            self.sync_directory(directory)
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
    """macOS: ``fsync`` does not reach stable storage, so ``_full_fsync`` uses ``F_FULLFSYNC``."""

    _durable_fs = frozenset({"apfs", "hfs"})


class WindowsPublisher(_BasePublisher):
    _durable_fs = frozenset({"NTFS", "ReFS"})

    def _replace(self, src: Path, dst: Path) -> None:
        self._move(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)

    def _rename_dir(self, src: Path, dst: Path) -> None:
        try:
            self._move(src, dst, MOVEFILE_WRITE_THROUGH)
        except OSError as err:
            if _winerror(err) in (_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS):
                raise FileExistsError(errno.EEXIST, "target directory exists", str(dst)) from err
            raise

    def _sync_dir(self, directory: Path) -> None:
        """No separate operation: ``MOVEFILE_WRITE_THROUGH`` makes the rename durable."""

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


def publisher_for(platform: str, *, fs_info: Callable[[Path], FsInfo] = detect_fs) -> DurablePublisher:
    if platform == "win32":
        return WindowsPublisher(fs_info=fs_info)
    if platform == "darwin":
        return DarwinPublisher(fs_info=fs_info)
    return PosixPublisher(fs_info=fs_info)
