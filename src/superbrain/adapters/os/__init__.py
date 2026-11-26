"""OS adapters."""

import os
import sys
import tempfile
from pathlib import Path

from superbrain.adapters.os.clock import SystemClock, SystemMonotonicClock
from superbrain.adapters.os.durable import publisher_for
from superbrain.adapters.os.locks import OsLockFactory
from superbrain.adapters.os.paths import OsPathSafety
from superbrain.adapters.os.physical_fs import OsPhysicalFs
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.os import OsAdapters, PermissionGuard, PlatformTraits

if sys.platform == "win32":
    from superbrain.adapters.os.permissions import WindowsPermissionGuard

    def _permission_guard() -> PermissionGuard:
        return WindowsPermissionGuard()

else:
    from superbrain.adapters.os.permissions import PosixPermissionGuard

    def _permission_guard() -> PermissionGuard:
        return PosixPermissionGuard()


def _default_windows_scratch_base() -> Path | None:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(os.path.abspath(local_app_data)) / "superbrain-scratch"
    return None


def _system_temp_dir() -> Path:
    return Path(tempfile.gettempdir())


def system_temp_dir() -> Path:
    """Return the platform temporary directory path."""
    return _system_temp_dir()


def host_platform() -> str:
    """The running host OS as ``sys.platform`` names it (the value native capture receipts record)."""
    return sys.platform


def _find_in_abs_dirs(name: str, dirs: list[str], *, exts: tuple[str, ...]) -> Path | None:
    for raw_dir in dirs:
        if not raw_dir:
            continue
        directory = Path(raw_dir)
        if not directory.is_absolute():
            continue
        for ext in exts:
            candidate = directory / f"{name}{ext}"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    return None


def find_ssh_keygen() -> Path | None:
    """Locate the OpenSSH ``ssh-keygen`` executable without ever searching CWD or relative ``PATH`` entries."""
    if sys.platform == "win32":
        system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
        system_candidate = system_root / "System32" / "OpenSSH" / "ssh-keygen.exe"
        if system_candidate.is_file():
            return system_candidate
        raw_exts = [ext.strip() for ext in os.environ.get("PATHEXT", ".EXE;.BAT;.CMD").split(os.pathsep) if ext.strip()]
        exts = tuple(raw_exts) or (".EXE",)
        return _find_in_abs_dirs("ssh-keygen", os.environ.get("PATH", "").split(os.pathsep), exts=exts)
    return _find_in_abs_dirs("ssh-keygen", os.environ.get("PATH", "").split(os.pathsep), exts=("",))


def platform_traits(platform: str = sys.platform) -> PlatformTraits:
    """Construct the ``PlatformTraits`` for ``platform`` (defaults to the running host OS)."""
    if platform == "win32":
        return PlatformTraits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=_default_windows_scratch_base,
            resolve_temp_links=False,
            temp_dir=_system_temp_dir,
            stage_private_dirs=True,
        )
    if platform == "darwin":
        return PlatformTraits(
            sqlite_full_fsync=True,
            restrict_umask=True,
            default_scratch_base=None,
            resolve_temp_links=True,
            temp_dir=_system_temp_dir,
        )
    return PlatformTraits(
        sqlite_full_fsync=False,
        restrict_umask=True,
        default_scratch_base=None,
        resolve_temp_links=False,
        temp_dir=_system_temp_dir,
    )


def os_adapters(clock: Clock | None = None, *, monotonic: MonotonicClock | None = None) -> OsAdapters:
    """The real adapters for the running OS."""
    return OsAdapters(
        paths=OsPathSafety(),
        permissions=_permission_guard(),
        publisher=publisher_for(sys.platform),
        locks=OsLockFactory(),
        clock=clock if clock is not None else SystemClock(),
        traits=platform_traits(sys.platform),
        monotonic=monotonic if monotonic is not None else SystemMonotonicClock(),
        physical=OsPhysicalFs(),
    )
