"""OS adapters."""

import sys

from superbrain.adapters.os.clock import SystemClock
from superbrain.adapters.os.durable import publisher_for
from superbrain.adapters.os.locks import OsLockFactory
from superbrain.adapters.os.paths import OsPathSafety
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters, PermissionGuard

if sys.platform == "win32":
    from superbrain.adapters.os.permissions import WindowsPermissionGuard

    def _permission_guard() -> PermissionGuard:
        return WindowsPermissionGuard()

else:
    from superbrain.adapters.os.permissions import PosixPermissionGuard

    def _permission_guard() -> PermissionGuard:
        return PosixPermissionGuard()


def os_adapters(clock: Clock | None = None) -> OsAdapters:
    """The real adapters for the running OS."""
    return OsAdapters(
        paths=OsPathSafety(),
        permissions=_permission_guard(),
        publisher=publisher_for(sys.platform),
        locks=OsLockFactory(),
        clock=clock if clock is not None else SystemClock(),
    )
