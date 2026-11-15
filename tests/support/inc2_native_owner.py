"""Test-only wheel owner driver and same-daemon verifier for Task 9 integration tests.

Runs the real production owner composition (``owner_entry._explicit_owner_adapters`` + ``daemon_entry.serve``)
inside the installed wheel interpreter (enforced under ``python -I`` when launched as a subprocess), tapping
``LoopbackServer._release_owner_reply`` and ``write_json_response`` without performing disk I/O inside
``AuthGate`` locks, request deadlines, or SQLite transactions.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import ipaddress
import itertools
import json
import os
import queue
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import Ready
    from tests.support.inc2_fixture import InstalledEnv
    from tests.support.inc2_native import (
        NativeConnectionProbe,
        OwnerCallObservation,
        ProcessIdentity,
        SocketObservation,
    )

__all__ = [
    "ObservedWheelOwner",
    "load_owner_observations",
    "process_started_at_for_pid",
    "run_observed_owner",
    "spawn_observed_wheel_owner",
    "utc_now_z",
    "verify_same_daemon",
]


_READINESS_ENV_VAR = "SUPERBRAIN_TEST_SOCKET_READINESS"
_OWNER_READINESS_TOKEN_ENV = "_SUPERBRAIN_OWNER_SOCKET_READINESS_TOKEN"
_READINESS_PATH = "/__test_socket_readiness"
_MAX_READINESS_BODY_BYTES = 4096


@dataclass(frozen=True)
class ObservedWheelOwner:
    process_identity: ProcessIdentity
    endpoint_port: int
    store_id: str
    writer_epoch: int
    instance_id: str
    module_file: str
    schema_sha256: str
    evidence_dir: Path
    client_readiness_env: Mapping[str, str] = field(default_factory=dict)


def _init_real_win32_dll_cls() -> Any:
    if sys.platform != "win32":
        return None
    import ctypes

    return getattr(ctypes, "WinDLL", None)


_REAL_WIN32_DLL_CLS: Any = _init_real_win32_dll_cls()


def _resolve_win32_precise_utc_fn() -> Any:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:
        return None
    if _REAL_WIN32_DLL_CLS is not None and not isinstance(kernel32, _REAL_WIN32_DLL_CLS):
        return None
    fn = getattr(kernel32, "GetSystemTimePreciseAsFileTime", None)
    if fn is None:
        return None
    fn.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
    fn.restype = None
    return fn


_WIN32_PRECISE_UTC_FN: Any = _resolve_win32_precise_utc_fn()
_WIN32_PRECISE_UTC_LOOKED_UP = _WIN32_PRECISE_UTC_FN is not None


def utc_now_z() -> str:
    """Return canonical UTC RFC3339 timestamp with sub-millisecond OS kernel precision on Windows."""
    if sys.platform == "win32":
        global _WIN32_PRECISE_UTC_FN, _WIN32_PRECISE_UTC_LOOKED_UP
        import ctypes
        from ctypes import wintypes

        if _WIN32_PRECISE_UTC_FN is None and not _WIN32_PRECISE_UTC_LOOKED_UP:
            fn = _resolve_win32_precise_utc_fn()
            if fn is not None:
                _WIN32_PRECISE_UTC_FN = fn
                _WIN32_PRECISE_UTC_LOOKED_UP = True
        if _WIN32_PRECISE_UTC_FN is not None:
            ft = wintypes.FILETIME()
            _WIN32_PRECISE_UTC_FN(ctypes.byref(ft))
            ticks_100ns = (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)
            dt = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks_100ns // 10)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_utc_now_z = utc_now_z

# Monotonic tie-breaker for coarse OS clocks (e.g., Windows Python 3.11 monotonic_ns uses ~15.6 ms ticks).
_ORDER_SEQ = itertools.count(1)


def _stamp_ns() -> tuple[int, int]:
    return time.monotonic_ns(), next(_ORDER_SEQ)


def _before(a_ns: int, a_seq: int | None, b_ns: int, b_seq: int | None) -> bool:
    if a_ns != b_ns:
        return a_ns < b_ns
    if a_seq is not None and b_seq is not None:
        return a_seq < b_seq
    return False


# When a lookup first saw the holder of the client socket (per lookup thread): a uniqueness scan may finish after the
# connection starts closing, but the binding is only as late as that sighting, not as the end of the scan.
_SIGHTING = threading.local()


def _store_sighting(
    pid: int | None, started_at: str | None, stamp: tuple[int, int], observed_at: str
) -> None:
    _SIGHTING.pid = pid
    _SIGHTING.started_at = started_at
    _SIGHTING.ns, _SIGHTING.seq = stamp
    _SIGHTING.at = observed_at


def _process_start_or_none(pid: int) -> str | None:
    try:
        return process_started_at_for_pid(pid)
    except (OSError, subprocess.SubprocessError):
        return None


def _note_sighting(pid: int | None = None, started_before: str | None = None) -> None:
    if getattr(_SIGHTING, "ns", None) is None:
        stamp = _stamp_ns()
        observed_at = _utc_now_z()
        started_after = _process_start_or_none(pid) if pid is not None else None
        # Keep an unknown identity unknown. A later query after the uniqueness
        # scan may see no process, or a different process reusing the PID.
        _store_sighting(pid, started_before if started_before == started_after else None, stamp, observed_at)


def _linux_boot_parameters() -> tuple[float, int]:
    if sys.platform == "win32":
        raise OSError("process clock unavailable")
    for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1]), int(os.sysconf("SC_CLK_TCK"))
    raise OSError("process clock unavailable")


@contextmanager
def _lookup_process_clock() -> Iterator[None]:
    previous = getattr(_SIGHTING, "linux_boot_parameters", None)
    try:
        if sys.platform.startswith("linux") and previous is None:
            _SIGHTING.linux_boot_parameters = _linux_boot_parameters()
        yield
    finally:
        _SIGHTING.linux_boot_parameters = previous


def _read_linux_process_start(pid: int, proc_dir_fd: int | None = None) -> str:
    boot_parameters = getattr(_SIGHTING, "linux_boot_parameters", None)
    if boot_parameters is None:
        boot_parameters = _linux_boot_parameters()
    btime_s, hz = boot_parameters
    try:
        if proc_dir_fd is None:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        else:
            with open(
                "stat", encoding="ascii", opener=lambda name, flags: os.open(name, flags, dir_fd=proc_dir_fd)
            ) as f:
                raw = f.read()
        if not raw.startswith(f"{pid} ("):
            raise ValueError("unexpected PID")
        start_ticks = int(raw.rpartition(")")[2].split()[19])
    except (IndexError, ValueError) as error:
        raise OSError("process creation time unavailable") from error
    dt = datetime.fromtimestamp(btime_s + (start_ticks / float(hz)), tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def process_started_at_for_pid(pid: int) -> str:
    """Return canonical UTC RFC3339 process creation timestamp for ``pid``."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        close_handle = False
        if pid == os.getpid():
            handle = kernel32.GetCurrentProcess()
        else:
            handle = kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                raise OSError(ctypes.get_last_error(), "OpenProcess failed")
            close_handle = True
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
            ticks_100ns = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
            dt = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks_100ns // 10)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        finally:
            if close_handle:
                kernel32.CloseHandle(handle)

    if sys.platform.startswith("linux"):
        return _read_linux_process_start(pid)

    if sys.platform == "darwin":
        started = _libproc_started_at(pid)
        if started is not None:
            return started
    # Whole-second ps output cannot distinguish two lifetimes of a reused PID.
    raise OSError("process creation time unavailable")


_LINUX_PROC_ROOT = Path("/proc")


def _normalize_ip_addr(host: str) -> str:
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text.lower()
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _format_host_header(ip_str: str, port: int) -> str:
    if ":" in ip_str:
        return f"[{ip_str}]:{port}"
    return f"{ip_str}:{port}"


def _ip_hex_proc_net_tcp(ip_str: str, *, ipv6: bool) -> str | None:
    try:
        addr = ipaddress.ip_address(_normalize_ip_addr(ip_str))
    except ValueError:
        return None
    if not ipv6:
        if not isinstance(addr, ipaddress.IPv4Address):
            return None
        word = struct.unpack("=I", addr.packed)[0]
        return f"{word:08X}"
    if isinstance(addr, ipaddress.IPv4Address):
        addr6 = ipaddress.ip_address(f"::ffff:{addr}")
    else:
        addr6 = addr
    assert isinstance(addr6, ipaddress.IPv6Address)
    words = struct.unpack("=4I", addr6.packed)
    return "".join(f"{w:08X}" for w in words)


def _parse_proc_net_tcp_inode(
    text: str,
    *,
    client_port: int,
    listen_port: int,
    client_ip: str = "127.0.0.1",
    server_ip: str = "127.0.0.1",
    ipv6: bool = False,
) -> int | None:
    """Return unique socket inode matching ``client_ip:client_port -> server_ip:listen_port`` from ``/proc/net``."""
    local_hex = _ip_hex_proc_net_tcp(client_ip, ipv6=ipv6)
    remote_hex = _ip_hex_proc_net_tcp(server_ip, ipv6=ipv6)
    if local_hex is None or remote_hex is None:
        return None
    local_target = f"{local_hex}:{client_port:04X}"
    remote_target = f"{remote_hex}:{listen_port:04X}"
    matched_inodes: set[int] = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        if parts[1].upper() == local_target and parts[2].upper() == remote_target and parts[3].upper() != "0A":
            try:
                inode = int(parts[9])
            except ValueError:
                continue
            if inode > 0:
                matched_inodes.add(inode)
    return next(iter(matched_inodes)) if len(matched_inodes) == 1 else None


def _single(holders: set[int]) -> int | None:
    """The holder PID when exactly one process holds the socket; an fd shared by two processes is ambiguous."""
    return next(iter(holders)) if len(holders) == 1 else None


def _find_pid_by_socket_inode(inode: int, *, proc_root: Path | None = None) -> int | None:
    """The single PID whose ``/proc/<pid>/fd/*`` references ``socket:[inode]`` (``None`` if none or several)."""
    return _single(_socket_inode_holders(inode, proc_root=proc_root))


_RECENT_CLIENT_PIDS_LOCK = threading.Lock()
_RECENT_CLIENT_PIDS: deque[int] = deque(maxlen=16)


def _remember_recent_client_pid(pid: int) -> None:
    with _RECENT_CLIENT_PIDS_LOCK:
        with contextlib.suppress(ValueError):
            _RECENT_CLIENT_PIDS.remove(pid)
        _RECENT_CLIENT_PIDS.appendleft(pid)


def _linux_socket_holder(pid: int, pid_dir: Path, target: str) -> bool:
    """Inspect descriptors and matching process metadata through one pinned procfs directory."""
    if sys.platform == "win32":
        return False
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        proc_dir_fd = os.open(pid_dir, flags)
        try:
            fd_dir = os.open("fd", flags, dir_fd=proc_dir_fd)
            try:
                with os.scandir(fd_dir) as scan:
                    for entry in scan:
                        try:
                            link = os.readlink(entry.name, dir_fd=fd_dir)
                        except OSError:
                            continue
                        if link != target:
                            continue
                        if getattr(_SIGHTING, "ns", None) is None:
                            stamp, observed_at = _stamp_ns(), _utc_now_z()
                            started_at = None
                            with contextlib.suppress(OSError):
                                started_at = _read_linux_process_start(pid, proc_dir_fd)
                            _store_sighting(pid, started_at, stamp, observed_at)
                        return True
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd_dir)
        finally:
            with contextlib.suppress(OSError):
                os.close(proc_dir_fd)
    except OSError:
        pass
    return False


def _socket_inode_holders(inode: int, *, proc_root: Path | None = None) -> set[int]:
    """Every PID whose ``/proc/<pid>/fd/*`` references ``socket:[inode]``."""
    root = _LINUX_PROC_ROOT if proc_root is None else proc_root
    target = f"socket:[{inode}]"
    holders: set[int] = set()

    def scan_pid(pid: int) -> None:
        if _linux_socket_holder(pid, root / str(pid), target):
            holders.add(pid)

    my_pid: int | None = None
    if proc_root is None:
        my_pid = os.getpid()
        scan_pid(my_pid)

    try:
        with os.scandir(root) as proc_scan:
            pids = [int(entry.name) for entry in proc_scan if entry.name.isdigit()]
    except OSError:
        return holders

    if proc_root is None:
        assert my_pid is not None
        pid_set = set(pids)
        with _RECENT_CLIENT_PIDS_LOCK:
            recent_snapshot = list(_RECENT_CLIENT_PIDS)
        scanned: set[int] = {my_pid}
        ordered_pids: list[int] = []
        for rpid in recent_snapshot:
            if rpid in pid_set and rpid not in scanned:
                scanned.add(rpid)
                ordered_pids.append(rpid)
        # Child shims spawned right after this daemon have PIDs just above my_pid; scan ascending first
        # so distant higher-PID shards do not delay sighting, then check remaining lower PIDs descending.
        ordered_pids.extend(sorted(p for p in pids if p > my_pid and p not in scanned))
        ordered_pids.extend(sorted((p for p in pids if p < my_pid and p not in scanned), reverse=True))
        for pid in ordered_pids:
            scan_pid(pid)
        for pid in ordered_pids:
            if pid in holders:
                _remember_recent_client_pid(pid)
    else:
        # Preserve descending numeric order for explicit proc_root test fixtures.
        pids.sort(reverse=True)
        for pid in pids:
            scan_pid(pid)
    return holders


def _parse_lsof_client_pid(output: str, *, client_port: int, listen_port: int) -> int | None:
    """Parse ``lsof -nP -F pn`` output and return the PID owning ``127.0.0.1:client_port->127.0.0.1:listen_port``."""
    target_name = f"127.0.0.1:{client_port}->127.0.0.1:{listen_port}"
    current_pid: int | None = None
    holders: set[int] = set()
    for raw_line in output.splitlines():
        if raw_line.startswith("p"):
            try:
                current_pid = int(raw_line[1:])
            except ValueError:
                current_pid = None
        elif raw_line.startswith("n") and current_pid is not None:
            if raw_line[1:].strip() == target_name:
                holders.add(current_pid)
    return _single(holders)


# xnu bsd/sys/proc_info.h: struct socket_fdinfo = proc_fileinfo (24) + socket_info; offsets below are into it.
_PROC_ALL_PIDS = 1
_PROC_UID_ONLY = 4  # a non-root process can read only fd tables of its own effective uid (xnu CHECK_SAME_USER)
_PROC_PIDLISTFDS = 1
_PROX_FDTYPE_SOCKET = 2
_PROC_PIDFDSOCKETINFO = 3
_SOCKET_FDINFO_SIZE = 792
_SOI_FAMILY_OFF = 24 + 160
_SOI_PROTOCOL_OFF = 24 + 156
_SOI_KIND_OFF = 24 + 232
_INSI_OFF = 24 + 240  # union soi_proto: in_sockinfo (SOCKINFO_IN=1) or tcp_sockinfo starting with it (SOCKINFO_TCP=2)


_PROC_PIDTBSDINFO = 3
_PROC_BSDINFO_SIZE = 136  # struct proc_bsdinfo: pbi_pid at 12, pbi_start_tvsec at 120, pbi_start_tvusec at 128


def _libproc_started_at(pid: int) -> str | None:
    """Canonical UTC process start time from ``proc_bsdinfo`` (microseconds); ``None`` if unavailable."""
    import ctypes

    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    buf = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
    if lib.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, buf, _PROC_BSDINFO_SIZE) != _PROC_BSDINFO_SIZE:
        return None
    if struct.unpack_from("<I", buf.raw, 12)[0] != pid:
        return None
    sec, usec = struct.unpack_from("<QQ", buf.raw, 120)
    dt = datetime.fromtimestamp(sec, tz=UTC) + timedelta(microseconds=usec)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_socket_fdinfo(buf: bytes) -> tuple[str, int, str, int] | None:
    """``(local_addr, local_port, remote_addr, remote_port)`` of an IPv4 TCP ``socket_fdinfo``, else ``None``."""
    if len(buf) < _INSI_OFF + 64:
        return None
    family = struct.unpack_from("<i", buf, _SOI_FAMILY_OFF)[0]
    kind = struct.unpack_from("<i", buf, _SOI_KIND_OFF)[0]
    protocol = struct.unpack_from("<i", buf, _SOI_PROTOCOL_OFF)[0]
    # SOCKINFO_IN (1) also covers UDP, whose port namespace can share the tuple: TCP only (SOCKINFO_TCP=2, proto 6).
    if family != socket.AF_INET or kind != 2 or protocol != socket.IPPROTO_TCP:
        return None
    fport, lport = struct.unpack_from("<ii", buf, _INSI_OFF)
    faddr = socket.inet_ntoa(buf[_INSI_OFF + 32 + 12 : _INSI_OFF + 32 + 16])  # in4in6_addr: 3 pad words, then v4
    laddr = socket.inet_ntoa(buf[_INSI_OFF + 48 + 12 : _INSI_OFF + 48 + 16])
    return laddr, socket.ntohs(lport & 0xFFFF), faddr, socket.ntohs(fport & 0xFFFF)


def _libproc_client_pid(client_port: int, listen_port: int) -> int | None:
    """The single PID holding ``127.0.0.1:client_port -> 127.0.0.1:listen_port`` via libproc, else ``None``."""
    return _single(_libproc_client_holders(client_port, listen_port) or set())


def _libproc_client_holders(client_port: int, listen_port: int) -> set[int] | None:
    """PIDs holding the client TCP socket via libproc; ``None`` when libproc is unavailable or lists no processes."""
    import ctypes

    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    want = ("127.0.0.1", client_port, "127.0.0.1", listen_port)
    found: set[int] = set()
    euid = int(getattr(os, "geteuid", lambda: 0)())  # POSIX only
    list_kind, list_arg = (_PROC_UID_ONLY, euid) if euid else (_PROC_ALL_PIDS, 0)  # root reads every fd table
    count = lib.proc_listpids(list_kind, list_arg, None, 0)
    if count <= 0:
        return None
    pids = (ctypes.c_int * (count // 4 + 64))()
    got = lib.proc_listpids(list_kind, list_arg, pids, ctypes.sizeof(pids))
    for pid in sorted(pids[: max(0, got) // 4], reverse=True):  # newest first: clients are recent processes
        if pid <= 0:
            continue
        started_before = _process_start_or_none(int(pid))
        size = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, None, 0)
        if size <= 0:
            continue
        fds = (ctypes.c_int32 * (size // 4 + 64))()  # struct proc_fdinfo {int32 proc_fd; uint32 proc_fdtype;}
        used = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, fds, ctypes.sizeof(fds))
        for i in range(0, max(0, used) // 4 - 1, 2):
            if fds[i + 1] != _PROX_FDTYPE_SOCKET:
                continue
            info = ctypes.create_string_buffer(_SOCKET_FDINFO_SIZE + 256)
            n = lib.proc_pidfdinfo(pid, fds[i], _PROC_PIDFDSOCKETINFO, info, ctypes.sizeof(info))
            if n > 0 and _parse_socket_fdinfo(info.raw[:n]) == want:
                _note_sighting(int(pid), started_before)
                found.add(int(pid))
    return found


def _win32_tcp_client_pids(client_port: int, listen_port: int) -> set[int]:
    if sys.platform != "win32":
        return set()
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
    buf = (ctypes.c_ubyte * (size.value + 4096))()
    size2 = wintypes.DWORD(len(buf))
    if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size2), False, 2, 5, 0) != 0:
        return set()
    num = ctypes.c_uint32.from_buffer(buf, 0).value
    found: set[int] = set()
    for idx in range(num):
        base = 4 + idx * 24
        _state, laddr, lport_net, raddr, rport_net, pid = (
            ctypes.c_uint32.from_buffer(buf, base + offset * 4).value for offset in range(6)
        )
        if socket.inet_ntoa(struct.pack("<I", laddr)) != "127.0.0.1":
            continue
        if socket.inet_ntoa(struct.pack("<I", raddr)) != "127.0.0.1":
            continue
        if socket.ntohs(lport_net & 0xFFFF) == client_port and socket.ntohs(rport_net & 0xFFFF) == listen_port:
            if pid > 0:
                found.add(int(pid))
    return found


def _lookup_loopback_client_pid(
    client_port: int,
    listen_port: int,
    **kwargs: Any,
) -> int | None:
    if client_port <= 0 or listen_port <= 0:
        return None
    conn_state = kwargs.get("conn_state")
    expected_tuple = conn_state.get("expected_tuple") if isinstance(conn_state, dict) else None
    client_ip = "127.0.0.1"
    server_ip = "127.0.0.1"
    if isinstance(expected_tuple, tuple) and len(expected_tuple) == 4:
        if int(expected_tuple[1]) != int(client_port) or int(expected_tuple[3]) != int(listen_port):
            return None
        client_ip = _normalize_ip_addr(str(expected_tuple[0]))
        server_ip = _normalize_ip_addr(str(expected_tuple[2]))
    matched_tuple = (client_ip, int(client_port), server_ip, int(listen_port))

    if sys.platform == "win32":
        if (client_ip, server_ip) != ("127.0.0.1", "127.0.0.1"):
            return None
        pid = _single(_win32_tcp_client_pids(client_port, listen_port))
        if pid is None:
            return None
        started_before = _process_start_or_none(pid)
        # The initial table only discovers a candidate. Re-observe the row
        # inside the creation-time bracket so PID reuse cannot relabel it.
        if _win32_tcp_client_pids(client_port, listen_port) != {pid}:
            return None
        _SIGHTING.tuple = matched_tuple
        _note_sighting(pid, started_before)
        return pid
    if sys.platform.startswith("linux"):
        for attempt in range(4):
            for name, is_v6 in (("tcp", False), ("tcp6", True)):
                try:
                    text = (_LINUX_PROC_ROOT / "net" / name).read_text(encoding="ascii", errors="replace")
                except OSError:
                    continue
                inode = _parse_proc_net_tcp_inode(
                    text,
                    client_port=client_port,
                    listen_port=listen_port,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    ipv6=is_v6,
                )
                if inode is not None:
                    holders = _socket_inode_holders(inode)
                    if holders:
                        pid = _single(holders)  # final: a later table must not resolve an ambiguous holder set
                        if pid is not None and getattr(_SIGHTING, "pid", None) == pid:
                            _SIGHTING.tuple = matched_tuple
                        return pid
            if attempt >= 3:
                break
            if conn_state is not None:
                closed_ev = conn_state.get("closed_event")
                if conn_state.get("closing") or (closed_ev is not None and closed_ev.is_set()):
                    break
            time.sleep(0.001)
        return None
    if sys.platform == "darwin":
        if (client_ip, server_ip) != ("127.0.0.1", "127.0.0.1"):
            return None
        # lsof (fork+exec, tens of ms) loses short-lived loopback connections; the libproc kernel query does not.
        holders = _libproc_client_holders(client_port, listen_port)
        if holders:
            pid = _single(holders)  # final: lsof must not resolve what libproc found ambiguous
            if pid is not None and getattr(_SIGHTING, "pid", None) == pid:
                _SIGHTING.tuple = matched_tuple
            return pid
        try:
            proc = subprocess.run(
                ["lsof", "-nP", "-F", "pn", f"-iTCP@127.0.0.1:{client_port}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 and not proc.stdout:
            return None
        pid = _parse_lsof_client_pid(proc.stdout, client_port=client_port, listen_port=listen_port)
        if pid is not None and getattr(_SIGHTING, "pid", None) == pid:
            _SIGHTING.tuple = matched_tuple
        return pid
    return None


def _run_event_writer(evidence_dir: Path, event_queue: queue.SimpleQueue[dict[str, JsonValue] | None]) -> None:
    events_path = evidence_dir / "owner-events.jsonl"
    sockets_path = evidence_dir / "socket-observations.jsonl"
    ready_path = evidence_dir / "owner-ready.json"
    from superbrain.core.canonical import canonical_json

    with events_path.open("ab") as events_fh, sockets_path.open("ab") as sockets_fh:
        while True:
            item = event_queue.get()
            if item is None:
                break
            kind = item.get("event")
            if kind == "ready":
                tmp = evidence_dir / f".ready-{os.getpid()}.tmp"
                tmp.write_bytes(canonical_json(item) + b"\n")
                os.replace(tmp, ready_path)
            elif kind == "socket_observation":
                sockets_fh.write(canonical_json(item) + b"\n")
                sockets_fh.flush()
            else:
                events_fh.write(canonical_json(item) + b"\n")
                events_fh.flush()


def _install_loopback_server_hooks(
    *,
    eq: Any,
    daemon_pid: int,
    daemon_started_at: str,
    store_id: str | None = None,
    instance_id: str | None = None,
    initial_ready: bool = True,
    collector_timeout_s: float = 1.5,
    socket_readiness_token: str | None = None,
) -> dict[str, Any]:
    from concurrent.futures import Future, ThreadPoolExecutor

    from superbrain.application._auth_gate import AuthGate
    from superbrain.cli_api import _loopback_server, _server_http
    from superbrain.cli_api._http_frames import HttpFramingError, write_all
    from superbrain.core.canonical import digest_bytes
    from superbrain.core.wire import encode_envelope

    hook_lock = threading.Lock()
    conn_ctx_by_tid: dict[
        int,
        tuple[
            str,
            str,
            str,
            int,
            str,
            int,
            Future[tuple[int | None, str | None, str | None, int | None]],
            dict[str, Any],
        ],
    ] = {}
    conn_state_by_conn_key: dict[tuple[int, int], dict[str, Any]] = {}
    conn_states_by_server: dict[int, set[tuple[int, int]]] = {}
    conn_state_by_sock_id: dict[int, dict[str, Any]] = {}
    pending_cmds: dict[
        int,
        tuple[
            str,
            dict[str, JsonValue] | None,
            str,
            str,
            int,
            str,
            int,
            str,
            str,
            Future[tuple[int | None, str | None, str | None, int | None]],
            dict[str, Any] | None,
        ],
    ] = {}
    flush_by_thread: dict[int, tuple[int | None, str | None]] = {}
    stamp_result_by_tid: dict[int, bool] = {}
    active_finalizers: list[threading.Thread] = []
    ready_seen = initial_ready
    lookup_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="inc2-obs-lookup")
    with contextlib.suppress(Exception):
        for pre_fut in [lookup_pool.submit(lambda: None) for _ in range(4)]:
            pre_fut.result(timeout=1.0)

    loopback_mod: Any = _loopback_server
    server_http_mod: Any = _server_http
    auth_gate_cls: Any = AuthGate
    orig_read_cmd = loopback_mod.read_admitted_tool_command
    orig_write_json = loopback_mod.write_json_response
    orig_handle_ident = loopback_mod.handle_identity_request
    orig_release = _loopback_server.LoopbackServer._release_owner_reply
    orig_conn_worker = _loopback_server.LoopbackServer._conn_worker
    orig_release_conn = _loopback_server.LoopbackServer._release_conn
    orig_abort_all = _loopback_server.LoopbackServer._abort_all_active_sockets
    orig_graceful_close = loopback_mod._graceful_close_conn
    orig_abort_sock = loopback_mod._abort_socket
    orig_graceful_reject = loopback_mod._graceful_reject_socket
    orig_srv_graceful_close = server_http_mod._graceful_close_conn
    orig_srv_abort_sock = server_http_mod._abort_socket
    orig_srv_graceful_reject = server_http_mod._graceful_reject_socket
    orig_authorize_stamp = AuthGate.authorize_stamp

    def _register_conn_sock(c_state: dict[str, Any] | None, sock: Any) -> None:
        if c_state is None or sock is None:
            return
        with hook_lock:
            if c_state.get("ssl_sock") is None and sock is not c_state.get("raw_sock"):
                c_state["ssl_sock"] = sock
            conn_state_by_sock_id[id(sock)] = c_state

    def _mark_conn_closing(c_state: dict[str, Any] | None) -> None:
        if c_state is None:
            return
        with c_state["lock"]:
            if not c_state["closing"]:
                c_state["closing"] = True
                closing_ns, closing_seq = _stamp_ns()
                c_state["closing_ns"] = closing_ns
                c_state["closing_seq"] = closing_seq
                c_state["closing_at"] = _utc_now_z()
            wake = c_state.get("readiness_wakeup")
            if wake is not None:
                wake.set()

    def _lookup_state_for_socks(*socks: Any) -> dict[str, Any] | None:
        with hook_lock:
            for sock in socks:
                if sock is not None:
                    found = conn_state_by_sock_id.get(id(sock))
                    if found is not None:
                        return found
        return None

    def _safe_client_identity(
        peer_port: int,
        listen_port: int,
        conn_state: dict[str, Any] | None = None,
    ) -> tuple[int | None, str | None, str | None, int | None]:
        if peer_port <= 0 or listen_port <= 0:
            return None, None, None, None
        if conn_state is not None and (conn_state["closed_event"].is_set() or conn_state["closing"]):
            return None, None, None, None
        client_pid: int | None = None
        client_started_at: str | None = None
        observed_at: str | None = None
        observed_ns: int | None = None
        observed_seq: int | None = None
        sighted = False
        sighted_tuple: tuple[str, int, str, int] | None = None
        expected_tuple = conn_state.get("expected_tuple") if conn_state is not None else None
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            _SIGHTING.ns = _SIGHTING.seq = _SIGHTING.at = None
            _SIGHTING.pid = _SIGHTING.started_at = None
            _SIGHTING.tuple = None
            with _lookup_process_clock():
                try:
                    client_pid = _lookup_loopback_client_pid(peer_port, listen_port, conn_state=conn_state)
                except TypeError:
                    client_pid = _lookup_loopback_client_pid(peer_port, listen_port)
            if client_pid is not None:
                sighted = _SIGHTING.ns is not None
                if not sighted:
                    # A PID returned after an external scan (e.g. lsof) does
                    # not establish its creation identity at a live sighting.
                    return None, None, None, None
                if _SIGHTING.pid != client_pid or _SIGHTING.started_at is None:
                    return None, None, None, None
                sighted_tuple = getattr(_SIGHTING, "tuple", None)
                client_started_at = _SIGHTING.started_at
                observed_ns = _SIGHTING.ns
                observed_seq = getattr(_SIGHTING, "seq", None)
                observed_at = _SIGHTING.at
        if (
            client_pid is None
            or client_started_at is None
            or observed_at is None
            or observed_ns is None
        ):
            return None, None, None, None
        if isinstance(expected_tuple, tuple) and len(expected_tuple) == 4:
            if (int(expected_tuple[1]), int(expected_tuple[3])) != (int(peer_port), int(listen_port)):
                return None, None, None, None
            if sighted_tuple is not None and sighted_tuple != expected_tuple:
                return None, None, None, None
        if conn_state is not None:
            with conn_state["lock"]:
                closing_ns = conn_state["closing_ns"]
                if sighted:  # the holder was seen at observed_ns; only a close that began before it disqualifies
                    late = closing_ns is not None and _before(
                        closing_ns,
                        conn_state.get("closing_seq"),
                        observed_ns,
                        observed_seq,
                    )
                else:
                    late = conn_state["closing"] or conn_state["closed_event"].is_set()
                if late or _before(
                    observed_ns,
                    observed_seq,
                    conn_state["conn_started_ns"],
                    conn_state.get("conn_started_seq"),
                ):
                    return None, None, None, None
                conn_state["observed_seq"] = observed_seq
                if "sighted_tuple" in conn_state:
                    conn_state["sighted_tuple"] = sighted_tuple or expected_tuple
        return client_pid, client_started_at, observed_at, observed_ns

    def _submit_lookup(
        peer_port: int,
        listen_port: int,
        conn_state: dict[str, Any] | None,
    ) -> Future[tuple[int | None, str | None, str | None, int | None]]:
        try:
            return lookup_pool.submit(_safe_client_identity, peer_port, listen_port, conn_state)
        except Exception:  # noqa: BLE001 - degraded collector never breaks daemon worker
            fallback: Future[tuple[int | None, str | None, str | None, int | None]] = Future()
            fallback.set_result((None, None, None, None))
            return fallback

    def _resolve_principal_and_cred(
        gate: Any,
        grant_stamp: Any,
        auth_matched: bool,
    ) -> tuple[str, str]:
        if not auth_matched or grant_stamp is None:
            return "<unknown>", "<unknown>"
        cred_id = getattr(grant_stamp, "credential_id", None)
        if not isinstance(cred_id, str) or not cred_id:
            return "<unknown>", "<unknown>"
        view = gate.current()
        cred_rec = view.auth.credentials.get(cred_id) if view is not None else None
        if cred_rec is None:
            return "<unknown>", "<unknown>"
        return str(cred_rec.principal.principal_id), str(cred_id)

    def _schedule_emit(
        *,
        gate: Any,
        connection_id: str,
        conn_started_at: str,
        lookup_fut: Future[tuple[int | None, str | None, str | None, int | None]],
        conn_state: dict[str, Any] | None,
        principal_id: str,
        credential_id: str,
        tool_name: str,
        ready_val: bool,
        auth_matched: bool,
        response_flushed_ok: bool,
        resp_digest: str | None,
        listen_host: str,
        listen_port: int,
        peer_host: str,
        peer_port: int,
        req_started_at: str,
        ended_at: str,
        selected_scope: dict[str, JsonValue] | None,
    ) -> None:
        ident = gate.identity
        eff_store_id = ident.store_id if ident is not None else (store_id or "")
        eff_writer_epoch = ident.writer_epoch if ident is not None else 0
        eff_instance_id = ident.instance_id if ident is not None else (instance_id or "")

        def _emit_events(
            *,
            obs_status: str,
            client_pid: int | None,
            client_started_at: str | None,
            observed_at: str | None,
            so_ended_at: str | None,
        ) -> None:
            with contextlib.suppress(Exception):
                eq.put_nowait(
                    {
                        "event": "owner_call",
                        "connection_id": connection_id,
                        "observation_status": obs_status,
                        "daemon_pid": daemon_pid,
                        "daemon_started_at": daemon_started_at,
                        "store_id": eff_store_id,
                        "writer_epoch": eff_writer_epoch,
                        "instance_id": eff_instance_id,
                        "principal_id": principal_id,
                        "credential_id": credential_id,
                        "tool_name": tool_name,
                        "ready": ready_val,
                        "auth_stamp_matched": auth_matched,
                        "response_flushed_ok": response_flushed_ok,
                        "response_digest": resp_digest,
                        "listen_host": listen_host,
                        "listen_port": listen_port,
                        "client_host": peer_host,
                        "client_port": peer_port if peer_port > 0 else None,
                        "client_pid": client_pid,
                        "client_started_at": client_started_at,
                        "started_at": req_started_at,
                        "ended_at": ended_at,
                        "call_id": None,
                        "selected_scope": selected_scope,
                    }
                )
            if eff_writer_epoch >= 1 and peer_port > 0 and listen_port > 0 and so_ended_at is not None:
                if so_ended_at < conn_started_at:
                    so_ended_at = conn_started_at
                with contextlib.suppress(Exception):
                    eq.put_nowait(
                        {
                            "event": "socket_observation",
                            "connection_id": connection_id,
                            "observation_status": obs_status,
                            "client_pid": client_pid if obs_status == "ok" else None,
                            "client_started_at": client_started_at if obs_status == "ok" else None,
                            "daemon_pid": daemon_pid,
                            "daemon_started_at": daemon_started_at,
                            "local_addr": peer_host,
                            "local_port": peer_port,
                            "remote_addr": listen_host,
                            "remote_port": listen_port,
                            "store_id": eff_store_id,
                            "writer_epoch": eff_writer_epoch,
                            "instance_id": eff_instance_id,
                            "started_at": conn_started_at,
                            "observed_at": observed_at if obs_status == "ok" else None,
                            "ended_at": so_ended_at,
                        }
                    )

        def _finalize(wait_s: float) -> None:
            client_pid: int | None = None
            client_started_at: str | None = None
            observed_at: str | None = None
            observed_ns: int | None = None
            try:
                client_pid, client_started_at, observed_at, observed_ns = lookup_fut.result(timeout=max(0.0, wait_s))
            except Exception:  # noqa: BLE001 - observation collector failure stays off request path
                client_pid, client_started_at, observed_at, observed_ns = None, None, None, None

            closed_at: str | None = None
            closed_ns: int | None = None
            closed_seq: int | None = None
            closing_ns: int | None = None
            closing_seq: int | None = None
            observed_seq: int | None = None
            conn_started_ns: int | None = None
            conn_started_seq: int | None = None
            if conn_state is not None:
                with contextlib.suppress(Exception):
                    conn_state["closed_event"].wait(timeout=max(0.0, wait_s))
                with conn_state["lock"]:
                    closing_ns = conn_state["closing_ns"]
                    closing_seq = conn_state.get("closing_seq")
                    closed_at = conn_state["closed_at"]
                    closed_ns = conn_state["closed_ns"]
                    closed_seq = conn_state.get("closed_seq")
                    observed_seq = conn_state.get("observed_seq")
                    conn_started_ns = conn_state["conn_started_ns"]
                    conn_started_seq = conn_state.get("conn_started_seq")

            obs_ok = (
                client_pid is not None
                and client_started_at is not None
                and observed_at is not None
                and observed_ns is not None
                and closing_ns is not None
                and closed_at is not None
                and closed_ns is not None
                and conn_started_ns is not None
                and not _before(observed_ns, observed_seq, conn_started_ns, conn_started_seq)
                and not _before(closing_ns, closing_seq, observed_ns, observed_seq)
                and not _before(closed_ns, closed_seq, closing_ns, closing_seq)
                and conn_started_at <= observed_at <= closed_at
            )
            obs_status = "ok" if obs_ok else "observation_incomplete"
            _emit_events(
                obs_status=obs_status,
                client_pid=client_pid if obs_ok else None,
                client_started_at=client_started_at if obs_ok else None,
                observed_at=observed_at if obs_ok else None,
                so_ended_at=closed_at,
            )

        if lookup_fut.done() and (conn_state is None or conn_state["closed_event"].is_set()):
            _finalize(0.0)
            return

        try:
            th = threading.Thread(
                target=_finalize,
                args=(collector_timeout_s,),
                name=f"inc2-obs-finalize-{connection_id}",
                daemon=True,
            )
            th.start()
        except Exception:  # noqa: BLE001 - finalizer start failure degrades evidence without breaking worker
            fallback_closed = conn_state["closed_at"] if conn_state is not None else None
            _emit_events(
                obs_status="observation_incomplete",
                client_pid=None,
                client_started_at=None,
                observed_at=None,
                so_ended_at=fallback_closed,
            )
            return
        with hook_lock:
            active_finalizers[:] = [t for t in active_finalizers if t.is_alive()]
            active_finalizers.append(th)

    class _ReplayHeadReader:
        """Replay an already-parsed HTTP request head when a connection opts out of readiness."""

        def __init__(self, inner: Any, head: Any) -> None:
            self._inner = inner
            self._head: Any | None = head

        def read_request_head(self, deadline_ns: int) -> Any:
            if self._head is not None:
                head = self._head
                self._head = None
                return head
            return self._inner.read_request_head(deadline_ns)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    def _sock_live_tuple(sock: Any) -> tuple[str, int, str, int] | None:
        try:
            if sock is None or sock.fileno() == -1:
                return None
            shost, sport = sock.getsockname()[:2]
            phost, pport = sock.getpeername()[:2]
        except OSError:
            return None
        return (_normalize_ip_addr(str(phost)), int(pport), _normalize_ip_addr(str(shost)), int(sport))

    def _write_readiness_response(
        sock: Any,
        *,
        status: int,
        ok_val: bool,
        ready_val: bool,
        close_conn: bool,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> bool:
        body = json.dumps({"ok": ok_val, "ready": ready_val}, separators=(",", ":"), sort_keys=True).encode("utf-8")
        reason = "OK" if status == 200 else "Service Unavailable"
        conn_hdr = "close" if close_conn else "keep-alive"
        frame = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: {conn_hdr}\r\n\r\n"
        ).encode("ascii") + body
        try:
            write_all(sock, frame, deadline_ns, monotonic_ns)
        except (OSError, HttpFramingError):
            return False
        return True

    def _tap_handle_ident(
        ssl_sock: Any,
        reader: Any,
        ready: Any,
        *,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> bool:
        tid = threading.get_ident()
        with hook_lock:
            conn_ctx = conn_ctx_by_tid.get(tid)
        conn_state = conn_ctx[7] if conn_ctx is not None else None
        if conn_state is not None:
            _register_conn_sock(conn_state, ssl_sock)
        if not socket_readiness_token:
            return bool(
                orig_handle_ident(
                    ssl_sock,
                    reader,
                    ready,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            )
        try:
            head = reader.read_request_head(deadline_ns)
        except HttpFramingError as err:
            server_http_mod.handle_framing_failure(
                ssl_sock,
                err,
                deadline_ns=deadline_ns,
                monotonic_ns=monotonic_ns,
            )
            return False
        if head.method != "POST" or head.target != _READINESS_PATH:
            replay_reader = _ReplayHeadReader(reader, head)
            return bool(
                orig_handle_ident(
                    ssl_sock,
                    replay_reader,
                    ready,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            )

        if (
            conn_ctx is None
            or conn_state is None
            or head.get_all("Authorization")
            or head.content_length is None
            or head.content_length <= 0
            or head.content_length > _MAX_READINESS_BODY_BYTES
        ):
            _write_readiness_response(
                ssl_sock,
                status=503,
                ok_val=False,
                ready_val=False,
                close_conn=True,
                deadline_ns=deadline_ns,
                monotonic_ns=monotonic_ns,
            )
            return False

        try:
            raw_body = reader.read_exact(head.content_length, deadline_ns)
            has_pipelined = bool(reader.has_pipelined_bytes(deadline_ns))
        except HttpFramingError as err:
            server_http_mod.handle_framing_failure(
                ssl_sock,
                err,
                deadline_ns=deadline_ns,
                monotonic_ns=monotonic_ns,
            )
            return False

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            payload = None

        token_valid = (
            isinstance(payload, dict)
            and set(payload.keys()) == {"token"}
            and isinstance(payload.get("token"), str)
            and hmac.compare_digest(payload["token"], socket_readiness_token)
        )
        live_tuple = _sock_live_tuple(ssl_sock)
        expected_tuple = conn_state.get("expected_tuple")
        host_vals = head.get_all("Host")
        host_valid = (
            live_tuple is not None
            and len(host_vals) == 1
            and host_vals[0] == _format_host_header(live_tuple[2], live_tuple[3])
        )
        if not token_valid or has_pipelined or live_tuple is None or live_tuple != expected_tuple or not host_valid:
            _write_readiness_response(
                ssl_sock,
                status=503,
                ok_val=False,
                ready_val=False,
                close_conn=True,
                deadline_ns=deadline_ns,
                monotonic_ns=monotonic_ns,
            )
            return False

        with conn_state["lock"]:
            if conn_state["closing"] or conn_state["closed_event"].is_set() or conn_state["closing_ns"] is not None:
                return False

        lookup_fut = conn_ctx[6]
        conn_state["client_readiness_requested"].set()
        wake_ev = conn_state["readiness_wakeup"]
        while not lookup_fut.done():
            with conn_state["lock"]:
                if (
                    conn_state["closing"]
                    or conn_state["closed_event"].is_set()
                    or conn_state["closing_ns"] is not None
                ):
                    break
            rem_ns = deadline_ns - monotonic_ns()
            if rem_ns <= 0 or ssl_sock.fileno() == -1:
                break
            wake_ev.wait(timeout=min(0.02, rem_ns / 1_000_000_000.0))

        post_wait_tuple = _sock_live_tuple(ssl_sock)
        c_pid: int | None = None
        c_started_at: str | None = None
        c_obs_at: str | None = None
        c_obs_ns: int | None = None
        if lookup_fut.done() and not lookup_fut.cancelled():
            with contextlib.suppress(Exception):
                c_pid, c_started_at, c_obs_at, c_obs_ns = lookup_fut.result()

        ack_allowed = False
        already_closing = True
        with conn_state["lock"]:
            already_closing = bool(
                conn_state["closing"]
                or conn_state["closed_event"].is_set()
                or conn_state["closing_ns"] is not None
            )
            ack_allowed = (
                not already_closing
                and monotonic_ns() < deadline_ns
                and post_wait_tuple == live_tuple
                and isinstance(c_pid, int)
                and c_pid > 0
                and isinstance(c_started_at, str)
                and bool(c_started_at)
                and isinstance(c_obs_at, str)
                and bool(c_obs_at)
                and isinstance(c_obs_ns, int)
                and conn_state.get("observed_seq") is not None
                and conn_state.get("sighted_tuple") == live_tuple
            )

        if not ack_allowed:
            if not already_closing and monotonic_ns() < deadline_ns and ssl_sock.fileno() != -1:
                _write_readiness_response(
                    ssl_sock,
                    status=503,
                    ok_val=False,
                    ready_val=False,
                    close_conn=True,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            return False

        if not _write_readiness_response(
            ssl_sock,
            status=200,
            ok_val=True,
            ready_val=True,
            close_conn=False,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        ):
            return False
        return bool(
            orig_handle_ident(
                ssl_sock,
                reader,
                ready,
                deadline_ns=deadline_ns,
                monotonic_ns=monotonic_ns,
            )
        )

    def _tap_read_cmd(
        ssl_sock: Any,
        reader: Any,
        ready: Any,
        *,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> Any:
        tid = threading.get_ident()
        with hook_lock:
            flush_by_thread.pop(tid, None)
            stamp_result_by_tid.pop(tid, None)
            conn_ctx = conn_ctx_by_tid.get(tid)
        if conn_ctx is not None:
            _register_conn_sock(conn_ctx[7], ssl_sock)
        cmd = orig_read_cmd(ssl_sock, reader, ready, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        if cmd is not None:
            with contextlib.suppress(Exception):
                scope_dict = cmd.selected_scope.to_dict() if cmd.selected_scope is not None else None
                listen_host = conn_ctx[2] if conn_ctx is not None else "127.0.0.1"
                listen_port = conn_ctx[3] if conn_ctx is not None else 0
                peer_host = conn_ctx[4] if conn_ctx is not None else "127.0.0.1"
                peer_port = conn_ctx[5] if conn_ctx is not None else 0
                if listen_port <= 0 or peer_port <= 0:
                    with contextlib.suppress(OSError):
                        lhost, lport = ssl_sock.getsockname()[:2]
                        phost, pport = ssl_sock.getpeername()[:2]
                        listen_host, listen_port = str(lhost), int(lport)
                        peer_host, peer_port = str(phost), int(pport)
                connection_id = conn_ctx[0] if conn_ctx is not None else f"conn-tid-{tid}"
                conn_started_at = conn_ctx[1] if conn_ctx is not None else _utc_now_z()
                c_state = conn_ctx[7] if conn_ctx is not None else None
                lookup_fut = (
                    conn_ctx[6]
                    if conn_ctx is not None
                    else _submit_lookup(peer_port, listen_port, c_state)
                )
                with hook_lock:
                    pending_cmds[tid] = (
                        str(cmd.tool),
                        scope_dict,
                        _utc_now_z(),
                        listen_host,
                        listen_port,
                        peer_host,
                        peer_port,
                        connection_id,
                        conn_started_at,
                        lookup_fut,
                        c_state,
                    )
        return cmd

    def _tap_write_json(
        ssl_sock: Any,
        *,
        status: int,
        body: bytes,
        close_conn: bool,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> None:
        tid = threading.get_ident()
        with hook_lock:
            conn_ctx = conn_ctx_by_tid.get(tid)
        if conn_ctx is not None:
            _register_conn_sock(conn_ctx[7], ssl_sock)
        orig_write_json(
            ssl_sock,
            status=status,
            body=body,
            close_conn=close_conn,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        with contextlib.suppress(Exception), hook_lock:
            flush_by_thread[tid] = (int(status), digest_bytes(body))

    def _tap_authorize_stamp(gate_self: Any, stamp: Any) -> bool:
        res = bool(orig_authorize_stamp(gate_self, stamp))
        with hook_lock:
            stamp_result_by_tid[threading.get_ident()] = res
        return res

    def _tap_conn_worker(self: Any, conn_id: Any, raw_sock: Any, accept_ns: int) -> None:
        tid = threading.get_ident()
        conn_id_int = int(conn_id)
        conn_key = (id(self), conn_id_int)
        connection_id = f"conn-{conn_id_int}"
        conn_started_at = _utc_now_z()
        conn_started_ns, conn_started_seq = _stamp_ns()
        listen_host = "127.0.0.1"
        listen_port = 0
        peer_host = "127.0.0.1"
        peer_port = 0
        with contextlib.suppress(OSError):
            lhost, lport = raw_sock.getsockname()[:2]
            phost, pport = raw_sock.getpeername()[:2]
            listen_host, listen_port = str(lhost), int(lport)
            peer_host, peer_port = str(phost), int(pport)
        expected_tuple = (
            (_normalize_ip_addr(peer_host), peer_port, _normalize_ip_addr(listen_host), listen_port)
            if peer_port > 0 and listen_port > 0
            else None
        )
        conn_state: dict[str, Any] = {
            "lock": threading.Lock(),
            "conn_started_ns": conn_started_ns,
            "conn_started_seq": conn_started_seq,
            "closed_event": threading.Event(),
            "worker_entered_event": threading.Event(),
            "client_readiness_requested": threading.Event(),
            "readiness_wakeup": threading.Event(),
            "expected_tuple": expected_tuple,
            "sighted_tuple": None,
            "closing": False,
            "closing_ns": None,
            "closing_seq": None,
            "closing_at": None,
            "observed_seq": None,
            "closed_at": None,
            "closed_ns": None,
            "closed_seq": None,
            "raw_sock": raw_sock,
            "ssl_sock": None,
        }
        with hook_lock:
            conn_state_by_conn_key[conn_key] = conn_state
            conn_states_by_server.setdefault(id(self), set()).add(conn_key)
            if raw_sock is not None:
                conn_state_by_sock_id[id(raw_sock)] = conn_state
        lookup_fut = _submit_lookup(peer_port, listen_port, conn_state)
        wake_ev: threading.Event = conn_state["readiness_wakeup"]

        def _signal_readiness_wakeup(_fut: Future[Any], *, ev: threading.Event = wake_ev) -> None:
            ev.set()

        lookup_fut.add_done_callback(_signal_readiness_wakeup)
        with hook_lock:
            conn_ctx_by_tid[tid] = (
                connection_id,
                conn_started_at,
                listen_host,
                listen_port,
                peer_host,
                peer_port,
                lookup_fut,
                conn_state,
            )
        try:
            conn_state["worker_entered_event"].set()
            time.sleep(0)
            orig_conn_worker(self, conn_id, raw_sock, accept_ns)
        finally:
            _mark_conn_closing(conn_state)
            with conn_state["lock"]:
                closed_ns, closed_seq = _stamp_ns()
                conn_state["closed_ns"] = closed_ns
                conn_state["closed_seq"] = closed_seq
                conn_state["closed_at"] = _utc_now_z()
                ssl_sock_ref = conn_state.get("ssl_sock")
                conn_state["raw_sock"] = None
                conn_state["ssl_sock"] = None
                conn_state["closed_event"].set()
            with hook_lock:
                conn_state_by_conn_key.pop(conn_key, None)
                srv_set = conn_states_by_server.get(id(self))
                if srv_set is not None:
                    srv_set.discard(conn_key)
                    if not srv_set:
                        conn_states_by_server.pop(id(self), None)
                if raw_sock is not None:
                    conn_state_by_sock_id.pop(id(raw_sock), None)
                if ssl_sock_ref is not None:
                    conn_state_by_sock_id.pop(id(ssl_sock_ref), None)
                conn_ctx_by_tid.pop(tid, None)
                cmd_info = pending_cmds.pop(tid, None)
                flushed_status, flushed_digest = flush_by_thread.pop(tid, (None, None))
                stamp_result_by_tid.pop(tid, None)
            if cmd_info is not None:
                (
                    tool_name,
                    selected_scope,
                    req_started_at,
                    c_listen_host,
                    c_listen_port,
                    c_peer_host,
                    c_peer_port,
                    c_conn_id,
                    c_started_at,
                    c_lookup_fut,
                    c_state,
                ) = cmd_info
                fallback_ended_at = conn_state["closed_at"] or _utc_now_z()
                with contextlib.suppress(Exception):
                    gate = self._owner.auth_gate
                    principal_id, credential_id = _resolve_principal_and_cred(gate, None, False)
                    _schedule_emit(
                        gate=gate,
                        connection_id=c_conn_id,
                        conn_started_at=c_started_at,
                        lookup_fut=c_lookup_fut,
                        conn_state=c_state,
                        principal_id=principal_id,
                        credential_id=credential_id,
                        tool_name=tool_name,
                        ready_val=False,
                        auth_matched=False,
                        response_flushed_ok=bool(flushed_status == 200 and flushed_digest is not None),
                        resp_digest=flushed_digest,
                        listen_host=c_listen_host,
                        listen_port=c_listen_port,
                        peer_host=c_peer_host,
                        peer_port=c_peer_port,
                        req_started_at=req_started_at,
                        ended_at=fallback_ended_at,
                        selected_scope=selected_scope,
                    )

    def _tap_release_conn(
        self: Any,
        conn_id: Any,
        raw_sock: Any,
        ssl_sock: Any,
        *,
        drain: bool,
    ) -> None:
        conn_key = (id(self), int(conn_id))
        with hook_lock:
            c_state = conn_state_by_conn_key.get(conn_key)
        if c_state is None:
            c_state = _lookup_state_for_socks(ssl_sock, raw_sock)
        _mark_conn_closing(c_state)
        orig_release_conn(self, conn_id, raw_sock, ssl_sock, drain=drain)

    def _tap_abort_all(self: Any) -> None:
        with hook_lock:
            keys = list(conn_states_by_server.get(id(self), ()))
            states = [conn_state_by_conn_key[k] for k in keys if k in conn_state_by_conn_key]
        for st in states:
            _mark_conn_closing(st)
        orig_abort_all(self)

    def _make_graceful_close_tap(orig_fn: Any) -> Any:
        def _tap_graceful_close(
            ssl_sock: Any,
            raw_sock: Any,
            *,
            drain: bool,
            stop_deadline: float | None = None,
        ) -> None:
            _mark_conn_closing(_lookup_state_for_socks(ssl_sock, raw_sock))
            orig_fn(ssl_sock, raw_sock, drain=drain, stop_deadline=stop_deadline)

        return _tap_graceful_close

    def _make_sock_close_tap(orig_fn: Any) -> Any:
        def _tap_sock_close(sock: Any) -> None:
            _mark_conn_closing(_lookup_state_for_socks(sock))
            orig_fn(sock)

        return _tap_sock_close

    _tap_graceful_close = _make_graceful_close_tap(orig_graceful_close)
    _tap_srv_graceful_close = _make_graceful_close_tap(orig_srv_graceful_close)
    _tap_abort_sock = _make_sock_close_tap(orig_abort_sock)
    _tap_srv_abort_sock = _make_sock_close_tap(orig_srv_abort_sock)
    _tap_graceful_reject = _make_sock_close_tap(orig_graceful_reject)
    _tap_srv_graceful_reject = _make_sock_close_tap(orig_srv_graceful_reject)

    def _tap_release(self: Any, ssl_sock: Any, reply: Any, tool_deadline_ns: int) -> None:
        tid = threading.get_ident()
        with hook_lock:
            cmd_info = pending_cmds.pop(tid, None)
            conn_ctx = conn_ctx_by_tid.get(tid)
        tool_name = cmd_info[0] if cmd_info is not None else None
        selected_scope = cmd_info[1] if cmd_info is not None else None
        req_started_at = cmd_info[2] if cmd_info is not None else _utc_now_z()

        listen_host = cmd_info[3] if cmd_info is not None else (conn_ctx[2] if conn_ctx is not None else "127.0.0.1")
        listen_port = cmd_info[4] if cmd_info is not None else (conn_ctx[3] if conn_ctx is not None else 0)
        peer_host = cmd_info[5] if cmd_info is not None else (conn_ctx[4] if conn_ctx is not None else "127.0.0.1")
        peer_port = cmd_info[6] if cmd_info is not None else (conn_ctx[5] if conn_ctx is not None else 0)
        connection_id = (
            cmd_info[7] if cmd_info is not None else (conn_ctx[0] if conn_ctx is not None else f"conn-tid-{tid}")
        )
        conn_started_at = (
            cmd_info[8] if cmd_info is not None else (conn_ctx[1] if conn_ctx is not None else req_started_at)
        )
        conn_state = cmd_info[10] if cmd_info is not None else (conn_ctx[7] if conn_ctx is not None else None)
        lookup_fut = (
            cmd_info[9]
            if cmd_info is not None
            else (
                conn_ctx[6]
                if conn_ctx is not None
                else _submit_lookup(peer_port, listen_port, conn_state)
            )
        )

        gate = self._owner.auth_gate
        grant_stamp = getattr(reply, "grant_stamp", None)
        expected_env_digest: str | None = None
        release_completed = False
        try:
            if listen_port <= 0 or peer_port <= 0:
                with contextlib.suppress(OSError):
                    lhost, lport = ssl_sock.getsockname()[:2]
                    phost, pport = ssl_sock.getpeername()[:2]
                    listen_host, listen_port = str(lhost), int(lport)
                    peer_host, peer_port = str(phost), int(pport)
            expected_env_digest = digest_bytes(encode_envelope(reply.envelope))
            orig_release(self, ssl_sock, reply, tool_deadline_ns)
            release_completed = True
        finally:
            with contextlib.suppress(Exception):
                with hook_lock:
                    flushed_status, flushed_digest = flush_by_thread.pop(tid, (None, None))
                    stamp_result = stamp_result_by_tid.pop(tid, None)

                ended_at = _utc_now_z()
                env_ok = isinstance(reply.envelope, dict) and reply.envelope.get("ok") is True
                if not release_completed or expected_env_digest is None:
                    auth_matched = False
                    response_flushed_ok = bool(flushed_status == 200 and flushed_digest is not None)
                elif env_ok:
                    if stamp_result is not None:
                        auth_matched = bool(
                            stamp_result and flushed_status == 200 and flushed_digest == expected_env_digest
                        )
                    else:
                        auth_matched = bool(
                            grant_stamp is not None and flushed_status == 200 and flushed_digest == expected_env_digest
                        )
                    response_flushed_ok = bool(
                        auth_matched and flushed_status == 200 and flushed_digest == expected_env_digest
                    )
                else:
                    auth_matched = False
                    response_flushed_ok = bool(flushed_status == 200 and flushed_digest == expected_env_digest)

                principal_id, credential_id = _resolve_principal_and_cred(gate, grant_stamp, auth_matched)
                if not auth_matched:
                    ready_val = False
                elif tool_name == "get_health":
                    data = reply.envelope.get("data") if isinstance(reply.envelope, dict) else None
                    ready_val = bool(isinstance(data, dict) and data.get("ready") is True)
                else:
                    ready_val = ready_seen

                if tool_name is not None:
                    _schedule_emit(
                        gate=gate,
                        connection_id=connection_id,
                        conn_started_at=conn_started_at,
                        lookup_fut=lookup_fut,
                        conn_state=conn_state,
                        principal_id=principal_id,
                        credential_id=credential_id,
                        tool_name=tool_name,
                        ready_val=ready_val,
                        auth_matched=auth_matched,
                        response_flushed_ok=response_flushed_ok,
                        resp_digest=flushed_digest,
                        listen_host=listen_host,
                        listen_port=listen_port,
                        peer_host=peer_host,
                        peer_port=peer_port,
                        req_started_at=req_started_at,
                        ended_at=ended_at,
                        selected_scope=selected_scope,
                    )

    def _set_ready(value: bool) -> None:
        nonlocal ready_seen
        ready_seen = value

    def _pending_count() -> int:
        with hook_lock:
            return len(pending_cmds)

    def _flush(*, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        with hook_lock:
            threads = list(active_finalizers)
        for th in threads:
            rem = deadline - time.monotonic()
            if rem <= 0.0:
                break
            th.join(timeout=rem)

    loopback_mod.read_admitted_tool_command = _tap_read_cmd
    loopback_mod.write_json_response = _tap_write_json
    loopback_mod.handle_identity_request = _tap_handle_ident
    loopback_mod._graceful_close_conn = _tap_graceful_close
    loopback_mod._abort_socket = _tap_abort_sock
    loopback_mod._graceful_reject_socket = _tap_graceful_reject
    server_http_mod._graceful_close_conn = _tap_srv_graceful_close
    server_http_mod._abort_socket = _tap_srv_abort_sock
    server_http_mod._graceful_reject_socket = _tap_srv_graceful_reject
    loopback_mod.LoopbackServer._release_owner_reply = _tap_release
    loopback_mod.LoopbackServer._conn_worker = _tap_conn_worker
    loopback_mod.LoopbackServer._release_conn = _tap_release_conn
    loopback_mod.LoopbackServer._abort_all_active_sockets = _tap_abort_all
    auth_gate_cls.authorize_stamp = _tap_authorize_stamp

    def _uninstall() -> None:
        loopback_mod.read_admitted_tool_command = orig_read_cmd
        loopback_mod.write_json_response = orig_write_json
        loopback_mod.handle_identity_request = orig_handle_ident
        loopback_mod._graceful_close_conn = orig_graceful_close
        loopback_mod._abort_socket = orig_abort_sock
        loopback_mod._graceful_reject_socket = orig_graceful_reject
        server_http_mod._graceful_close_conn = orig_srv_graceful_close
        server_http_mod._abort_socket = orig_srv_abort_sock
        server_http_mod._graceful_reject_socket = orig_srv_graceful_reject
        loopback_mod.LoopbackServer._release_owner_reply = orig_release
        loopback_mod.LoopbackServer._conn_worker = orig_conn_worker
        loopback_mod.LoopbackServer._release_conn = orig_release_conn
        loopback_mod.LoopbackServer._abort_all_active_sockets = orig_abort_all
        auth_gate_cls.authorize_stamp = orig_authorize_stamp
        _flush(timeout=collector_timeout_s + 0.5)
        lookup_pool.shutdown(wait=False, cancel_futures=True)

    return {
        "uninstall": _uninstall,
        "pending_count": _pending_count,
        "set_ready": _set_ready,
        "flush": _flush,
    }


def run_observed_owner(
    config_path: Path,
    evidence_dir: Path,
    stop: threading.Event,
    *,
    socket_readiness_token: str | None = None,
) -> int:
    """Run the production owner loop via ``_explicit_owner_adapters`` and record sanitized call observations."""
    if not isinstance(config_path, Path) or not config_path.is_absolute():
        raise ValueError("absolute config_path required")
    if not isinstance(evidence_dir, Path) or not evidence_dir.is_absolute():
        raise ValueError("absolute evidence_dir required")

    import superbrain
    import superbrain.composition.daemon_entry as daemon_entry
    import superbrain.composition.owner_entry as owner_entry
    from superbrain.adapters.os import daemon_config as daemon_config_mod
    from superbrain.core.canonical import digest_bytes
    from superbrain.core.wire import load_catalog

    evidence_dir.mkdir(parents=True, exist_ok=True)
    daemon_pid = os.getpid()
    daemon_started_at = process_started_at_for_pid(daemon_pid)
    module_file = str(Path(superbrain.__file__).resolve()) if superbrain.__file__ else ""
    schema_sha256 = load_catalog().schema_sha256

    captured_digests: list[str] = []
    orig_checked_read = daemon_config_mod._read_checked_file_bytes
    target_cfg_norm = os.path.normcase(os.path.abspath(config_path))

    def _single_read_config(path: Path, os_: Any, *, max_bytes: int, **kwargs: Any) -> bytes:
        raw = orig_checked_read(path, os_, max_bytes=max_bytes, **kwargs)
        if os.path.normcase(os.path.abspath(path)) == target_cfg_norm:
            captured_digests.append(digest_bytes(raw))
        return raw

    daemon_config_mod._read_checked_file_bytes = _single_read_config
    try:
        cfg, adapters, scratch_base = owner_entry._explicit_owner_adapters(config_path)
    finally:
        daemon_config_mod._read_checked_file_bytes = orig_checked_read
    if len(captured_digests) != 1:
        raise RuntimeError(f"Expected single checked config read for {config_path}, got {len(captured_digests)}")
    config_digest = captured_digests[0]
    event_queue: queue.SimpleQueue[dict[str, JsonValue] | None] = queue.SimpleQueue()
    writer_thread = threading.Thread(
        target=_run_event_writer,
        args=(evidence_dir, event_queue),
        daemon=True,
    )
    writer_thread.start()

    hook_state = _install_loopback_server_hooks(
        eq=event_queue,
        daemon_pid=daemon_pid,
        daemon_started_at=daemon_started_at,
        initial_ready=False,
        socket_readiness_token=socket_readiness_token,
    )

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        hook_state["set_ready"](True)
        shutil.rmtree(scratch_base, ignore_errors=True)
        event_queue.put_nowait(
            {
                "event": "ready",
                "daemon_pid": daemon_pid,
                "daemon_started_at": daemon_started_at,
                "port": ready.endpoint.port,
                "store_id": ready.identity.store_id,
                "writer_epoch": ready.identity.writer_epoch,
                "instance_id": ready.identity.instance_id,
                "module_file": module_file,
                "schema_sha256": schema_sha256,
                "config_digest": config_digest,
            }
        )

    try:
        return int(daemon_entry.serve(cfg, os_=adapters, stop_event=stop, on_ready=_on_ready))
    finally:
        hook_state["flush"](timeout=2.5)
        hook_state["uninstall"]()
        shutil.rmtree(scratch_base, ignore_errors=True)
        event_queue.put_nowait(None)
        writer_thread.join(timeout=5.0)


def load_owner_observations(
    evidence_dir: Path,
) -> tuple[dict[str, Any] | None, tuple[OwnerCallObservation, ...], tuple[SocketObservation, ...]]:
    """Read ready metadata, owner call observations, and loopback socket observations strictly from ``evidence_dir``."""
    from dataclasses import asdict

    from tests.support.inc2_native import (
        parse_owner_events_jsonl,
        parse_owner_ready,
        parse_socket_observations_jsonl,
    )

    ready_path = evidence_dir / "owner-ready.json"
    ready_meta: dict[str, Any] | None = None
    if ready_path.is_file():
        ready_meta = asdict(parse_owner_ready(ready_path.read_bytes()))

    events_path = evidence_dir / "owner-events.jsonl"
    owners: tuple[OwnerCallObservation, ...] = ()
    if events_path.is_file():
        owners = parse_owner_events_jsonl(events_path.read_bytes())

    sockets_path = evidence_dir / "socket-observations.jsonl"
    sockets: tuple[SocketObservation, ...] = ()
    if sockets_path.is_file():
        sockets = parse_socket_observations_jsonl(sockets_path.read_bytes())
    return ready_meta, owners, sockets


@contextmanager
def spawn_observed_wheel_owner(
    env: InstalledEnv,
    config_path: Path,
    evidence_dir: Path,
    *,
    cwd: Path,
    socket_readiness: bool = False,
) -> Iterator[ObservedWheelOwner]:
    """Spawn ``inc2_native_owner.py`` under ``env.venv_python -I`` and wait until ready."""
    from tests.support.inc2_cli import clean_installed_subprocess_env
    from tests.support.inc2_native import OwnerReadyObservation, ProcessIdentity, parse_owner_ready

    evidence_dir.mkdir(parents=True, exist_ok=True)
    readiness_token = secrets.token_hex(16) if socket_readiness else None
    client_readiness_env: dict[str, str] = (
        {_READINESS_ENV_VAR: readiness_token} if readiness_token is not None else {}
    )
    owner_extra_env: dict[str, str] | None = (
        {_OWNER_READINESS_TOKEN_ENV: readiness_token} if readiness_token is not None else None
    )
    cmd = [
        str(env.venv_python),
        "-I",
        str(Path(__file__).resolve()),
        "--config",
        str(config_path),
        "--evidence-dir",
        str(evidence_dir),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=clean_installed_subprocess_env(owner_extra_env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    ready_file = evidence_dir / "owner-ready.json"
    deadline = time.monotonic() + 15.0
    ready_obs: OwnerReadyObservation | None = None
    try:
        while time.monotonic() < deadline:
            if ready_file.is_file():
                try:
                    raw = ready_file.read_bytes()
                    if raw:
                        ready_obs = parse_owner_ready(raw)
                        break
                except (OSError, ValueError):
                    pass
            rc = proc.poll()
            if rc is not None:
                out_b, err_b = proc.communicate(timeout=5.0)
                raise RuntimeError(
                    f"observed wheel owner exited early (rc={rc}): "
                    f"out={out_b.decode('utf-8', 'replace')!r} err={err_b.decode('utf-8', 'replace')!r}"
                )
            time.sleep(0.02)
        if ready_obs is None:
            raise TimeoutError("observed wheel owner never wrote owner-ready.json")

        owner = ObservedWheelOwner(
            process_identity=ProcessIdentity(
                pid=ready_obs.daemon_pid,
                started_at=ready_obs.daemon_started_at,
            ),
            endpoint_port=ready_obs.port,
            store_id=ready_obs.store_id,
            writer_epoch=ready_obs.writer_epoch,
            instance_id=ready_obs.instance_id,
            module_file=ready_obs.module_file,
            schema_sha256=ready_obs.schema_sha256,
            evidence_dir=evidence_dir,
            client_readiness_env=client_readiness_env,
        )
        yield owner
    finally:
        with contextlib.suppress(OSError):
            if proc.stdin is not None:
                proc.stdin.close()
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5.0)
        if proc.stdout is not None:
            with contextlib.suppress(OSError):
                proc.stdout.read()
        if proc.stderr is not None:
            with contextlib.suppress(OSError):
                proc.stderr.read()


def verify_same_daemon(first: NativeConnectionProbe, second: NativeConnectionProbe) -> bool:
    """True iff both passed probes link distinct principals on one live daemon, store, epoch, and runtime."""
    from tests.support.inc2_native import ProbeValidationError, _all_passed_fields_present, _validate_probe_invariants

    for item in (first, second):
        try:
            _validate_probe_invariants(item)
        except ProbeValidationError:
            return False
        if item.status != "passed" or item.reason_code is not None or not _all_passed_fields_present(item):
            return False
        assert item.terminal_facts is not None and item.path_check is not None
        if not (
            item.terminal_facts.ready
            and item.terminal_facts.ok
            and item.terminal_facts.auth_granted
            and item.terminal_facts.response_flushed
            and item.terminal_facts.response_digest is not None
        ):
            return False
        if not (
            item.path_check.physical_root_ok
            and item.path_check.ancestors_ok
            and item.path_check.symlink_or_reparse_rejected
        ):
            return False

    assert first.daemon_process is not None and second.daemon_process is not None
    assert first.binding is not None and second.binding is not None
    assert first.token_context is not None and second.token_context is not None
    if (
        first.kind != second.kind
        or first.os != second.os
        or first.source_commit != second.source_commit
        or first.config_digest != second.config_digest
        or first.binding.environment != second.binding.environment
    ):
        return False
    if first.binding.principal_id == second.binding.principal_id:
        return False
    if first.token_context.credential_id == second.token_context.credential_id:
        return False

    return (
        first.daemon_process == second.daemon_process
        and first.binding.store_id == second.binding.store_id
        and first.binding.writer_epoch == second.binding.writer_epoch
        and first.binding.instance_id == second.binding.instance_id
    )


def _wheel_child_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--evidence-dir", required=True)
    ns = parser.parse_args(argv)
    stop = threading.Event()

    def _watch_stdin() -> None:
        try:
            while sys.stdin.buffer.read(1):
                pass
        except OSError:
            pass
        finally:
            stop.set()

    for sig_name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if isinstance(sig, signal.Signals):
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, lambda _s, _f: stop.set())

    readiness_token = os.environ.pop(_OWNER_READINESS_TOKEN_ENV, None)
    threading.Thread(target=_watch_stdin, daemon=True).start()
    return run_observed_owner(
        Path(ns.config),
        Path(ns.evidence_dir),
        stop,
        socket_readiness_token=readiness_token,
    )


def _child_bootstrap() -> int:
    import superbrain

    if superbrain.__file__ is None:
        sys.stderr.write("wheel_check_failed_no_file\n")
        return 3
    mod_path = Path(superbrain.__file__).resolve()
    venv_path = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix or not mod_path.is_relative_to(venv_path):
        sys.stderr.write("wheel_check_failed_outside_venv\n")
        return 3

    from superbrain.core.wire import load_catalog

    _ = load_catalog().schema_sha256
    repo_root = str(Path(__file__).resolve().parents[2])
    if repo_root not in sys.path:
        sys.path.append(repo_root)

    from tests.support.inc2_native_owner import _wheel_child_main as entry

    return entry(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(_child_bootstrap())
