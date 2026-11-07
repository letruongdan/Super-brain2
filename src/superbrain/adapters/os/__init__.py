"""OS adapters."""

import os
import sys
import tempfile
from pathlib import Path

from superbrain.adapters.os.clock import SystemClock
from superbrain.adapters.os.durable import publisher_for
from superbrain.adapters.os.locks import OsLockFactory
from superbrain.adapters.os.paths import OsPathSafety
from superbrain.ports.clock import Clock
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


def platform_traits(platform: str = sys.platform) -> PlatformTraits:
    """Construct the ``PlatformTraits`` for ``platform`` (defaults to the running host OS)."""
    if platform == "win32":
        return PlatformTraits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=_default_windows_scratch_base,
            resolve_temp_links=False,
            temp_dir=_system_temp_dir,
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


def os_adapters(clock: Clock | None = None) -> OsAdapters:
    """The real adapters for the running OS."""
    return OsAdapters(
        paths=OsPathSafety(),
        permissions=_permission_guard(),
        publisher=publisher_for(sys.platform),
        locks=OsLockFactory(),
        clock=clock if clock is not None else SystemClock(),
        traits=platform_traits(sys.platform),
    )
