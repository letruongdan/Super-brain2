"""When did the OS create this process, on the monotonic clock? Lets the capture hook count its 2 s hard cap from
the host's spawn instead of from the first Python line (interpreter start-up and imports included)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

__all__ = ["process_start_monotonic_ns"]

_FILETIME_UNIT_NS = 100


def _age_ns_windows() -> int | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE  # the pseudo-handle (-1) must not be truncated to an int
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), *(ctypes.byref(t) for t in times)):
        return None
    now = wintypes.FILETIME()
    kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(now))

    def _ticks(ft: wintypes.FILETIME) -> int:
        return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)

    return (_ticks(now) - _ticks(times[0])) * _FILETIME_UNIT_NS


def _age_ns_linux() -> int | None:
    if sys.platform != "linux":
        return None
    import os

    stat = Path("/proc/self/stat").read_text(encoding="ascii")
    fields = stat[stat.rindex(")") + 2:].split()  # the command name may hold spaces; it ends at the last ")"
    start_ticks = int(fields[19])  # field 22 overall: starttime, in clock ticks since boot
    uptime_s = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    return int((uptime_s - start_ticks / os.sysconf("SC_CLK_TCK")) * 1e9)


_PROC_PIDTBSDINFO = 3
_BSDINFO_SIZE = 136  # struct proc_bsdinfo
_BSDINFO_START_OFFSET = 120  # uint64 pbi_start_tvsec, then uint64 pbi_start_tvusec


def _age_ns_darwin() -> int | None:
    if sys.platform != "darwin":
        return None
    import ctypes
    import os
    import struct

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    buf = ctypes.create_string_buffer(_BSDINFO_SIZE)
    if libproc.proc_pidinfo(os.getpid(), _PROC_PIDTBSDINFO, ctypes.c_uint64(0), buf, _BSDINFO_SIZE) != _BSDINFO_SIZE:
        return None
    sec, usec = struct.unpack_from("<QQ", buf.raw, _BSDINFO_START_OFFSET)
    # wall clock: an NTP step skews it; the hook bounds the result to one cap before module entry
    return time.time_ns() - (int(sec) * 1_000_000_000 + int(usec) * 1_000)


def process_start_monotonic_ns() -> int | None:
    """The process creation time as a ``time.monotonic_ns()`` value, or ``None`` where the OS does not say."""
    try:
        if sys.platform == "win32":
            age = _age_ns_windows()
        elif sys.platform == "darwin":
            age = _age_ns_darwin()
        else:
            age = _age_ns_linux()
    except (OSError, ValueError, IndexError, AttributeError):
        return None
    if age is None or age < 0:
        return None
    return time.monotonic_ns() - age
