"""Test support helpers for SP1 Increment 2 Task 7 (`T7b.2`: CLI, MCP shim, and wheel).

Provides:
- Installed wheel console-script runners (``brain`` and ``brain-mcp``) executing with a clean
  environment (``PYTHONPATH``/``VIRTUAL_ENV`` stripped) and outside the repository checkout.
- Owner-only file writers for ``ClientProfile``, ``DaemonConfig``, ``ca.pem``, and ``credential.txt``.
- Foreground ``brain serve`` subprocess controller with Windows ``CreateToolhelp32Snapshot``
  descendant worker PID tracking, ``CTRL_BREAK_EVENT`` / ``SIGTERM`` graceful stop, and
  ``writer.lock`` release verification.
- ``ShimTestDomain`` implementing ``KernelToolDomain`` over ``kernel_store_extensions()`` for
  both in-process loopback tests and installed-wheel fixture-daemon subprocess tests.
"""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import ctypes.wintypes
import datetime as dt
import io
import os
import queue
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import zip_longest
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, cast

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.adapters.os.locks import OsLockFactory
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.composition.daemon_entry import serve_config_path
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
    Endpoint,
    ObjectRef,
    Principal,
    ResourceDigest,
    Scope,
    StoredResult,
    require_opaque_id,
)
from superbrain.core.wire import load_catalog, parse_json
from superbrain.mcp.stdio import ToolCaller, run_stdio
from superbrain.ports.kernel import KernelTx

if TYPE_CHECKING:
    from tests.support.inc2_fixture import InstalledEnv
    from tests.support.inc2_transport import TransportTemplate

INC2_CLI_PATH = Path(__file__).resolve()
_WHEEL_ISOLATION_CACHE: dict[str, dict[str, JsonValue]] = {}
_SHARED_T7_TEMPLATE: list[TransportTemplate] = []
_SHARED_T7_TEMPLATE_LOCK = threading.Lock()
_STDIN_WRITE_TIMEOUT_S = 15.0
_STDERR_DRAIN_TIMEOUT_S = 2.0
_DIAGNOSTIC_TAIL_BYTES = 64 * 1024  # Not imported from tests: this module also runs as a standalone fixture daemon.

_STRIPPED_ENV_KEYS: frozenset[str] = frozenset(
    {
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "PYTHONPATH",
        "PYTHONHOME",
        "SUPERBRAIN_CRASHPOINT",
        "SUPERBRAIN_PAUSEPOINT",
        "SUPERBRAIN_HOME",
        "SUPERBRAIN_TEST_SOCKET_READINESS",
        "_SUPERBRAIN_OWNER_SOCKET_READINESS_TOKEN",
    }
)


# ---------------------------------------------------------------------------
# Installed wheel & console script helpers
# ---------------------------------------------------------------------------


def installed_script_path(env: InstalledEnv, script_name: str) -> Path:
    """Locate an installed console script (``brain`` or ``brain-mcp``) inside ``env.venv_dir``."""
    if sys.platform == "win32":
        scripts_dir = env.venv_dir / "Scripts"
        exe_candidate = scripts_dir / f"{script_name}.exe"
        if exe_candidate.exists():
            return exe_candidate
        return scripts_dir / script_name
    return env.venv_dir / "bin" / script_name


def clean_installed_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a clean environment dictionary with repo/venv/fault variables stripped."""
    env = {k: v for k, v in os.environ.items() if k not in _STRIPPED_ENV_KEYS}
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra is not None:
        for key, value in extra.items():
            env[key] = value
    return env


def run_installed_command(
    env: InstalledEnv,
    script_name: str,
    args: Sequence[str],
    *,
    cwd: Path,
    stdin_bytes: bytes = b"",
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 45.0,
) -> subprocess.CompletedProcess[bytes]:
    """Run an installed wheel console script (``brain`` or ``brain-mcp``) in a clean environment."""
    script = installed_script_path(env, script_name)
    assert script.is_file(), f"Installed console script not found: {script}"
    return subprocess.run(
        [str(script), *args],
        cwd=cwd,
        env=clean_installed_subprocess_env(extra_env),
        input=stdin_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def verify_installed_wheel_isolation(env: InstalledEnv, *, cwd: Path) -> dict[str, JsonValue]:
    """Verify ``env.venv_python -I`` loads ``superbrain`` and packaged schema strictly from ``site-packages``."""
    cache_key = str(env.venv_dir)
    cached = _WHEEL_ISOLATION_CACHE.get(cache_key)
    if cached is not None:
        return dict(cached)
    probe_code = "\n".join(
        [
            "import importlib.resources, json, pathlib, superbrain",
            "from superbrain.core.wire import load_catalog",
            "cat = load_catalog()",
            "ref = importlib.resources.files('superbrain.core').joinpath('data', 'mcp-tools-v2.json')",
            "with importlib.resources.as_file(ref) as p:",
            "    schema_file = str(pathlib.Path(p).resolve())",
            "print(json.dumps({",
            "    'module_file': str(pathlib.Path(superbrain.__file__).resolve()),",
            "    'schema_file': schema_file,",
            "    'schema_sha256': cat.schema_sha256,",
            "    'tool_names': list(cat.tools.keys()),",
            "}))",
        ]
    )
    proc = subprocess.run(
        [str(env.venv_python), "-I", "-c", probe_code],
        cwd=cwd,
        env=clean_installed_subprocess_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=True,
    )
    parsed = parse_json(proc.stdout.strip().encode("utf-8"))
    assert isinstance(parsed, dict)
    _WHEEL_ISOLATION_CACHE[cache_key] = dict(parsed)
    return parsed


def get_shared_t7_transport_template() -> TransportTemplate:
    """Return a session-cached ``TransportTemplate`` shared across T7 CLI and shim tests."""
    with _SHARED_T7_TEMPLATE_LOCK:
        if _SHARED_T7_TEMPLATE:
            return _SHARED_T7_TEMPLATE[0]
        from tests.support.inc2_transport import create_transport_template

        tpl = create_transport_template("inc2-t7-shared-tpl")
        atexit.register(lambda: shutil.rmtree(tpl.base_dir, ignore_errors=True))
        _SHARED_T7_TEMPLATE.append(tpl)
        return tpl


# ---------------------------------------------------------------------------
# Owner-only configuration & profile writers
# ---------------------------------------------------------------------------


def write_owner_only_bytes(path: Path, data: bytes) -> Path:
    """Write ``data`` to ``path`` and restrict file permissions to the current owner."""
    adapters = os_adapters()
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        adapters.permissions.secure_directory(path.parent)
    path.write_bytes(data)
    adapters.permissions.secure_file(path)
    return path


def write_credential_file(path: Path, token: str, *, line_ending: str = "\n") -> Path:
    """Write an owner-only bearer credential file."""
    return write_owner_only_bytes(path, f"{token}{line_ending}".encode())


def write_ca_file(path: Path, ca_pem: str | bytes) -> Path:
    """Write an owner-only CA PEM file."""
    raw = ca_pem.encode("utf-8") if isinstance(ca_pem, str) else ca_pem
    return write_owner_only_bytes(path, raw)


def write_daemon_config_file(
    path: Path,
    *,
    data_root: Path,
    expected_store_id: str,
    cert_path: Path,
    key_path: Path,
) -> Path:
    """Write an owner-only ``DaemonConfig`` v1 JSON file."""
    payload: dict[str, JsonValue] = {
        "version": 1,
        "data_root": str(data_root),
        "expected_store_id": expected_store_id,
        "cert_path": str(cert_path),
        "key_path": str(key_path),
    }
    return write_owner_only_bytes(path, canonical_json(payload))


def write_client_profile_file(
    path: Path,
    *,
    endpoint_path: Path,
    expected_store_id: str,
    ca_file: Path,
    leaf_cert_sha256: str,
    credential_file: Path,
    workspace: Mapping[str, JsonValue] | None = None,
) -> tuple[Path, str]:
    """Write an owner-only ``ClientProfile`` v1 JSON file and return ``(path, sha256_digest)``."""
    payload: dict[str, JsonValue] = {
        "version": 1,
        "endpoint_path": str(endpoint_path),
        "expected_store_id": expected_store_id,
        "ca_file": str(ca_file),
        "leaf_cert_sha256": leaf_cert_sha256,
        "credential_file": str(credential_file),
    }
    if workspace is not None:
        payload["workspace"] = dict(workspace)
    raw = canonical_json(payload)
    write_owner_only_bytes(path, raw)
    return path, digest_bytes(raw)


# ---------------------------------------------------------------------------
# Process tree inspection & foreground serve controller
# ---------------------------------------------------------------------------


def _win32_handle_creation_ticks(handle: int) -> int | None:
    """Return 100ns FILETIME creation ticks for an already-open Win32 process handle."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessTimes.argtypes = [ctypes.wintypes.HANDLE, *[ctypes.POINTER(ctypes.wintypes.FILETIME)] * 4]
    kernel32.GetProcessTimes.restype = ctypes.wintypes.BOOL
    times = [ctypes.wintypes.FILETIME() for _ in range(4)]
    if not kernel32.GetProcessTimes(ctypes.wintypes.HANDLE(int(handle)), *(ctypes.byref(t) for t in times)):
        return None
    return (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)


def _win32_handle_identity(handle: int) -> tuple[int, int, int] | None:
    """Return ``(pid, ppid, creation_ticks)`` from one open Win32 process handle."""
    if sys.platform != "win32":
        return None
    ticks = _win32_handle_creation_ticks(handle)
    if ticks is None:
        return None

    class _ProcessBasicInformation(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_size_t),
            ("InheritedFromUniqueProcessId", ctypes.c_size_t),
        ]

    ntdll = ctypes.WinDLL("ntdll")
    pbi = _ProcessBasicInformation()
    ret_len = ctypes.wintypes.ULONG()
    status = ntdll.NtQueryInformationProcess(
        ctypes.wintypes.HANDLE(int(handle)),
        0,
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(ret_len),
    )
    if int(status) != 0:
        return None
    return int(pbi.UniqueProcessId), int(pbi.InheritedFromUniqueProcessId), ticks


def _win32_is_handle_in_job(proc_handle: int, job_handle: int) -> bool | None:
    """Return whether ``proc_handle`` belongs to OS Job Object ``job_handle`` (``None`` on API error)."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.IsProcessInJob.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.BOOL),
    ]
    kernel32.IsProcessInJob.restype = ctypes.wintypes.BOOL
    in_job = ctypes.wintypes.BOOL()
    if not kernel32.IsProcessInJob(
        ctypes.wintypes.HANDLE(int(proc_handle)),
        ctypes.wintypes.HANDLE(int(job_handle)),
        ctypes.byref(in_job),
    ):
        return None
    return bool(in_job.value)


def _win32_job_pids(job_handle: int) -> tuple[int, ...] | None:
    """Return live OS-managed member PIDs inside ``job_handle``, or ``None`` if unavailable."""
    if sys.platform != "win32":
        return ()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = ctypes.wintypes.BOOL
    error_more_data = 234
    cap = 64
    while cap <= 4096:

        class _JobObjectBasicProcessIdList(ctypes.Structure):
            _fields_ = [
                ("NumberOfAssignedProcesses", ctypes.wintypes.DWORD),
                ("NumberOfProcessIdsInList", ctypes.wintypes.DWORD),
                ("ProcessIdList", ctypes.c_size_t * cap),
            ]

        buf = _JobObjectBasicProcessIdList()
        ret_len = ctypes.wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = kernel32.QueryInformationJobObject(
            ctypes.wintypes.HANDLE(int(job_handle)),
            3,
            ctypes.byref(buf),
            ctypes.sizeof(buf),
            ctypes.byref(ret_len),
        )
        if ok:
            count = min(cap, int(buf.NumberOfProcessIdsInList))
            return tuple(int(buf.ProcessIdList[i]) for i in range(count) if int(buf.ProcessIdList[i]) > 0)
        err = ctypes.get_last_error()
        if err == error_more_data:
            assigned = int(buf.NumberOfAssignedProcesses)
            next_cap = max(cap * 2, assigned)
            if next_cap > 4096 or next_cap <= cap:
                return None
            cap = next_cap
            continue
        return None
    return None


class _Win32ProcessJob:
    """OS-managed Win32 Job Object pinning descendant membership across subprocess spawns."""

    def __init__(self, *, kill_on_close: bool = False) -> None:
        self._handle: int | None = None
        self.assigned: bool = False
        if sys.platform != "win32":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return
        self._handle = int(handle)
        if kill_on_close:
            _set_win32_job_kill_on_close(self._handle)

    @property
    def handle(self) -> int | None:
        return self._handle

    def assign_process(self, proc_handle: int | None) -> bool:
        if sys.platform != "win32" or self._handle is None or proc_handle is None:
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = ctypes.wintypes.BOOL
        ok = bool(
            kernel32.AssignProcessToJobObject(
                ctypes.wintypes.HANDLE(self._handle),
                ctypes.wintypes.HANDLE(int(proc_handle)),
            )
        )
        if ok:
            self.assigned = True
        return ok

    def query_pids(self) -> tuple[int, ...] | None:
        if self._handle is None:
            return None
        return _win32_job_pids(self._handle)

    def terminate_and_wait(self, *, timeout_s: float = 2.0) -> bool:
        if sys.platform != "win32":
            return True
        if self._handle is None or not self.assigned:
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]
        kernel32.TerminateJobObject.restype = ctypes.wintypes.BOOL
        if not kernel32.TerminateJobObject(ctypes.wintypes.HANDLE(self._handle), 9):
            return False
        deadline = time.monotonic() + max(0.0, timeout_s)
        while True:
            pids = self.query_pids()
            if pids == ():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def close(self) -> None:
        if sys.platform != "win32" or self._handle is None:
            return
        handle = self._handle
        self._handle = None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
        with contextlib.suppress(OSError):
            kernel32.CloseHandle(ctypes.wintypes.HANDLE(handle))


def _set_win32_job_kill_on_close(job_handle: int) -> None:
    if sys.platform != "win32":
        return

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _BasicLimitInfo(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.wintypes.DWORD),
            ("SchedulingClass", ctypes.wintypes.DWORD),
        ]

    class _ExtendedLimitInfo(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInfo),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    info = _ExtendedLimitInfo()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = ctypes.wintypes.BOOL
    kernel32.SetInformationJobObject(
        ctypes.wintypes.HANDLE(job_handle),
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(info),
        ctypes.sizeof(info),
    )


def _win32_resume_process(proc_handle: int | None) -> bool:
    """Resume all threads in a suspended Win32 process handle via NtResumeProcess."""
    if sys.platform != "win32" or proc_handle is None:
        return False
    try:
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [ctypes.wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        status = int(ntdll.NtResumeProcess(ctypes.wintypes.HANDLE(int(proc_handle))))
        return bool(status == 0)
    except Exception:  # noqa: BLE001 - non-fatal resume failure
        return False


@contextlib.contextmanager
def _rollback_child_setup(
    proc: subprocess.Popen[Any] | None,
    job: _Win32ProcessJob | None,
    *,
    readers: Sequence[threading.Thread] = (),
) -> Iterator[None]:
    """Release setup-owned processes, pipes and Job if initialization fails."""
    try:
        yield
    except BaseException as setup_error:
        try:
            if job is not None and job.assigned:
                try:
                    if not job.terminate_and_wait():
                        setup_error.add_note("Could not verify termination of all Win32 Job members")
                except OSError as err:
                    setup_error.add_note(f"Win32 Job termination failed: {err}")
            if proc is not None:
                with contextlib.suppress(OSError):
                    proc.kill()
                try:
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as err:
                    setup_error.add_note(f"Could not verify termination of process {proc.pid}: {err}")
                if proc.stdin is not None:
                    with contextlib.suppress(OSError, ValueError):
                        proc.stdin.close()
                for reader, pipe in zip_longest(readers, (proc.stdout, proc.stderr)):
                    if reader is not None and reader.ident is not None:
                        reader.join(timeout=0.5)
                    if reader is not None and reader.is_alive():
                        setup_error.add_note("A child pipe reader remained blocked during rollback")
                    elif pipe is not None:
                        with contextlib.suppress(OSError, ValueError):
                            pipe.close()
        finally:
            if job is not None:
                try:
                    job.close()
                except OSError as err:
                    setup_error.add_note(f"Win32 Job handle close failed: {err}")
        raise


def _win32_spawn_in_job(
    job: _Win32ProcessJob | None,
    popen_args: Sequence[str | Path | os.PathLike[str]],
    *,
    creationflags: int = 0,
    **popen_kwargs: Any,
) -> tuple[subprocess.Popen[Any], bool]:
    """Attach the suspended child before resuming it; release the Job on setup failure."""
    if sys.platform != "win32" or job is None:
        return subprocess.Popen(popen_args, creationflags=creationflags, **popen_kwargs), False

    if job.handle is None:
        raise RuntimeError("Win32 Job Object handle is missing or closed before spawn")

    create_suspended = 0x00000004
    with _rollback_child_setup(None, job):
        proc = subprocess.Popen(popen_args, creationflags=creationflags | create_suspended, **popen_kwargs)
    with _rollback_child_setup(proc, job):
        proc_handle = getattr(proc, "_handle", None)
        if not job.assign_process(proc_handle):
            raise RuntimeError(f"Failed to assign process {proc.pid} to Win32 Job Object before execution")
        if not _win32_resume_process(proc_handle):
            raise RuntimeError(f"Failed to resume process {proc.pid} in Win32 Job Object")
    return proc, True


def _win32_process_snapshot() -> list[tuple[int, int, int]] | None:
    """Capture one atomic ``(pid, ppid, creation_ticks)`` process snapshot on Windows."""
    if sys.platform != "win32":
        return []

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.wintypes.USHORT),
            ("MaximumLength", ctypes.wintypes.USHORT),
            ("Buffer", ctypes.c_void_p),
        ]

    class _SystemProcessInfo(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", ctypes.wintypes.ULONG),
            ("NumberOfThreads", ctypes.wintypes.ULONG),
            ("WorkingSetPrivateSize", ctypes.c_int64),
            ("HardFaultCount", ctypes.wintypes.ULONG),
            ("NumberOfThreadsHighWatermark", ctypes.wintypes.ULONG),
            ("CycleTime", ctypes.c_uint64),
            ("CreateTime", ctypes.c_int64),
            ("UserTime", ctypes.c_int64),
            ("KernelTime", ctypes.c_int64),
            ("ImageName", _UnicodeString),
            ("BasePriority", ctypes.wintypes.LONG),
            ("UniqueProcessId", ctypes.c_size_t),
            ("InheritedFromUniqueProcessId", ctypes.c_size_t),
        ]

    ntdll = ctypes.WinDLL("ntdll")
    status_info_length_mismatch = 0xC0000004
    buf_size = 512 * 1024
    while buf_size <= 64 * 1024 * 1024:
        buf = (ctypes.c_ubyte * buf_size)()
        needed = ctypes.wintypes.ULONG()
        status = int(ntdll.NtQuerySystemInformation(5, buf, buf_size, ctypes.byref(needed))) & 0xFFFFFFFF
        if status == status_info_length_mismatch:
            buf_size = max(buf_size * 2, int(needed.value) + 65536)
            continue
        if status != 0:
            return None
        rows: list[tuple[int, int, int]] = []
        offset = 0
        while True:
            entry = _SystemProcessInfo.from_buffer(buf, offset)
            rows.append(
                (
                    int(entry.UniqueProcessId),
                    int(entry.InheritedFromUniqueProcessId),
                    int(entry.CreateTime),
                )
            )
            if entry.NextEntryOffset == 0:
                break
            offset += int(entry.NextEntryOffset)
        return rows
    return None


def _win32_process_creation_ticks(pid: int) -> int | None:
    """Return 100ns FILETIME creation ticks for ``pid``, or ``None`` if unavailable."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return None
    try:
        return _win32_handle_creation_ticks(int(handle))
    finally:
        kernel32.CloseHandle(handle)


def _win32_popen_creation_ticks(proc: subprocess.Popen[Any]) -> int | None:
    """Pin creation ticks from ``proc``'s direct OS handle first (no PID reopen race)."""
    if sys.platform != "win32":
        return None
    proc_handle = getattr(proc, "_handle", None)
    if proc_handle is not None:
        with contextlib.suppress(TypeError, ValueError, OSError):
            ticks = _win32_handle_creation_ticks(int(proc_handle))
            if ticks is not None:
                return ticks
    return _win32_process_creation_ticks(proc.pid)


def _win32_open_and_verify_handle(
    pid: int,
    *,
    expected_ppid: int | None,
    expected_snap_ticks: int | None,
    min_parent_ticks: int | None,
    job_handle: int | None,
) -> tuple[int | None, bool]:
    """Open ``pid`` once and verify on that kernel handle that parentage, snapshot ticks, and job membership match.

    Returns ``(verified_ticks_or_None, verification_failed)``.
    """
    if sys.platform != "win32":
        return None, True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return None, True
    try:
        ident = _win32_handle_identity(int(handle))
        if ident is None:
            return None, True
        actual_pid, actual_ppid, actual_ticks = ident
        if actual_pid != int(pid):
            return None, True
        if expected_ppid is not None and actual_ppid != expected_ppid:
            return None, True
        if expected_snap_ticks is not None and actual_ticks != expected_snap_ticks:
            return None, True
        if min_parent_ticks is not None and actual_ticks < min_parent_ticks:
            return None, True
        if job_handle is not None and _win32_is_handle_in_job(int(handle), job_handle) is not True:
            return None, True
        hooked_ticks = _win32_process_creation_ticks(pid)
        if hooked_ticks is None or hooked_ticks != actual_ticks:
            return None, True
        if min_parent_ticks is not None and hooked_ticks < min_parent_ticks:
            return None, True
        return actual_ticks, False
    finally:
        kernel32.CloseHandle(handle)


def _win32_descendant_identities_checked(
    root_pid: int,
    *,
    root_ticks: int | None = None,
    job_handle: int | None = None,
) -> tuple[list[tuple[int, int]], bool]:
    """Enumerate verified ``(pid, creation_ticks)`` descendants and flag unverified candidates."""
    if sys.platform != "win32":
        return [], False

    unverified = False
    live_root_ticks = _win32_process_creation_ticks(root_pid)
    root_alive_or_open = True
    if root_ticks is not None:
        eff_root_ticks = root_ticks
        if live_root_ticks is None or live_root_ticks != root_ticks:
            root_alive_or_open = False
    else:
        if live_root_ticks is None:
            return [], True
        eff_root_ticks = live_root_ticks

    snap_rows = _win32_process_snapshot()
    if snap_rows is None:
        unverified = True
        snap_rows = []

    children_by_parent: dict[int, list[tuple[int, int]]] = {}
    snap_ticks_by_pid: dict[int, int] = {}
    for pid, ppid, snap_ticks in snap_rows:
        if pid > 0:
            snap_ticks_by_pid[pid] = snap_ticks
            if pid != ppid:
                children_by_parent.setdefault(ppid, []).append((pid, snap_ticks))

    snap_root_ticks = snap_ticks_by_pid.get(root_pid)
    if snap_root_ticks is not None and snap_root_ticks != eff_root_ticks:
        root_alive_or_open = False

    descendants: list[tuple[int, int]] = []
    start_ticks: dict[int, int] = {root_pid: eff_root_ticks}
    seen = {root_pid}
    frontier = [root_pid] if root_alive_or_open else []

    while frontier:
        curr = frontier.pop(0)
        parent_ticks = start_ticks[curr]
        curr_live = _win32_process_creation_ticks(curr)
        if curr_live is None or curr_live != parent_ticks:
            if curr != root_pid:
                unverified = True
            continue
        for child_pid, snap_child_ticks in children_by_parent.get(curr, ()):
            if child_pid in seen:
                continue
            if snap_child_ticks < parent_ticks:
                continue
            verified_ticks, failed = _win32_open_and_verify_handle(
                child_pid,
                expected_ppid=curr,
                expected_snap_ticks=snap_child_ticks,
                min_parent_ticks=parent_ticks,
                job_handle=job_handle,
            )
            if failed or verified_ticks is None:
                unverified = True
                continue
            if _win32_process_creation_ticks(curr) != parent_ticks:
                unverified = True
                continue
            seen.add(child_pid)
            start_ticks[child_pid] = verified_ticks
            descendants.append((child_pid, verified_ticks))
            frontier.append(child_pid)

    if job_handle is not None:
        job_pids = _win32_job_pids(job_handle)
        if job_pids is None:
            unverified = True
        else:
            for jpid in job_pids:
                if jpid == root_pid or jpid in seen:
                    continue
                verified_ticks, failed = _win32_open_and_verify_handle(
                    jpid,
                    expected_ppid=None,
                    expected_snap_ticks=None,
                    min_parent_ticks=eff_root_ticks,
                    job_handle=job_handle,
                )
                if failed or verified_ticks is None:
                    unverified = True
                    continue
                seen.add(jpid)
                descendants.append((jpid, verified_ticks))

    return descendants, unverified


def _win32_descendant_identities(
    root_pid: int,
    *,
    root_ticks: int | None = None,
    job_handle: int | None = None,
) -> list[tuple[int, int]]:
    """Enumerate verified live ``(pid, creation_ticks)`` descendants of ``root_pid`` on Windows."""
    identities, _ = _win32_descendant_identities_checked(
        root_pid, root_ticks=root_ticks, job_handle=job_handle
    )
    return identities


def _win32_descendant_pids(root_pid: int) -> list[int]:
    """Enumerate all live descendant PIDs of ``root_pid`` on Windows via verified kernel snapshot + handle checks."""
    return [pid for pid, _ in _win32_descendant_identities(root_pid)]


def _win32_wait_or_terminate_pid(
    pid: int,
    *,
    expected_ticks: int | None = None,
    job_handle: int | None = None,
    terminate: bool,
    timeout_s: float,
) -> bool:
    """Wait for ``pid`` (optionally terminating); require pinned ticks/job on the open handle."""
    assert sys.platform == "win32"
    if expected_ticks is None or isinstance(expected_ticks, bool) or not isinstance(expected_ticks, int):
        return False
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32process

    access = win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_LIMITED_INFORMATION
    if terminate:
        access |= win32con.PROCESS_TERMINATE
    try:
        handle = win32api.OpenProcess(access, False, pid)
    except pywintypes.error as err:
        error_invalid_parameter = getattr(win32con, "ERROR_INVALID_PARAMETER", 87)
        if getattr(err, "winerror", None) == error_invalid_parameter:
            return True
        return False
    try:
        actual_ticks = _win32_handle_creation_ticks(int(handle))
        if actual_ticks is None:
            return False
        if actual_ticks != expected_ticks:
            # Target process exited and OS recycled its PID; do not touch the new occupant.
            return True
        if job_handle is not None and _win32_is_handle_in_job(int(handle), job_handle) is not True:
            return False
        if terminate:
            with contextlib.suppress(pywintypes.error):
                win32process.TerminateProcess(handle, 9)
        timeout_ms = max(1, int(timeout_s * 1000))
        wait_rc = win32event.WaitForSingleObject(handle, timeout_ms)
        if wait_rc != win32event.WAIT_OBJECT_0:
            return False
        code = win32process.GetExitCodeProcess(handle)
        return bool(code != win32con.STILL_ACTIVE)
    finally:
        win32api.CloseHandle(handle)


def is_writer_lock_held(data_root: Path) -> bool:
    """Return ``True`` iff ``data_root / 'writer.lock'`` is currently held by another process/handle."""
    lock_path = data_root / "writer.lock"
    if not lock_path.exists():
        return False
    factory = OsLockFactory()
    try:
        handle = factory.acquire(lock_path)
    except BrainError as err:
        if err.code is ErrorCode.WRITER_HELD:
            return True
        raise
    handle.release()
    return False


def _probe_loopback_tls_ready(host: str, port: int, timeout_s: float) -> bool:
    """Return whether ``(host, port)`` accepts TCP and completes a TLS handshake within ``timeout_s``."""
    step_timeout = min(max(timeout_s, 0.05), 0.5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=step_timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


class InstalledServeProcess:
    """Subprocess controller for foreground ``brain serve --config <abs>`` or wheel fixture daemon."""

    def __init__(
        self,
        args: Sequence[str],
        *,
        data_root: Path,
        cwd: Path,
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        self._data_root = data_root
        self._endpoint_path = data_root / "endpoint.json"
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if sys.platform == "win32" else 0
        start_new_session = sys.platform != "win32"
        child_env = clean_installed_subprocess_env(extra_env)
        self._job: _Win32ProcessJob | None = (
            _Win32ProcessJob(kill_on_close=True) if sys.platform == "win32" else None
        )
        self._proc, self._job_assigned = _win32_spawn_in_job(
            self._job,
            list(args),
            cwd=cwd,
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
        with _rollback_child_setup(self._proc, self._job):
            if sys.platform == "win32" and not self._job_assigned:
                raise RuntimeError("InstalledServeProcess requires Win32 Job Object assignment")
            self._job_handle: int | None = (
                self._job.handle if (self._job is not None and self._job_assigned) else None
            )
            self._proc_ticks: int | None = (
                _win32_popen_creation_ticks(self._proc) if sys.platform == "win32" else None
            )
            self._descendant_identities: list[tuple[int, int]] = []
            self._closed = False
            self.cleanup_unverified = bool(self._job is not None and not self._job_assigned)

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def descendant_pids(self) -> tuple[int, ...]:
        return tuple(pid for pid, _ in self._descendant_identities)

    def poll(self) -> int | None:
        return self._proc.poll()

    def snapshot_descendant_identities(self) -> tuple[tuple[int, int], ...]:
        if sys.platform == "win32":
            if self._proc_ticks is None:
                self.cleanup_unverified = True
                return tuple(self._descendant_identities)
            identities, unverified = _win32_descendant_identities_checked(
                self._proc.pid,
                root_ticks=self._proc_ticks,
                job_handle=self._job_handle,
            )
            if unverified:
                self.cleanup_unverified = True
            seen = set(self._descendant_identities)
            for ident in identities:
                if ident not in seen:
                    seen.add(ident)
                    self._descendant_identities.append(ident)
        return tuple(self._descendant_identities)

    def snapshot_descendant_pids(self) -> tuple[int, ...]:
        return tuple(pid for pid, _ in self.snapshot_descendant_identities())

    def wait_ready(self, timeout: float = 15.0) -> Endpoint:
        """Poll ``endpoint.json`` until published, TLS-ready, and verified while the foreground process stays alive."""
        adapters = os_adapters()
        deadline = time.perf_counter() + timeout
        last_err: Exception | None = None
        while time.perf_counter() < deadline:
            rc = self._proc.poll()
            if rc is not None:
                out_b, err_b = self._proc.communicate(timeout=2.0)
                raise AssertionError(
                    f"Serve process exited prematurely with code {rc}.\n"
                    f"stdout: {out_b.decode('utf-8', errors='replace')}\n"
                    f"stderr: {err_b.decode('utf-8', errors='replace')}"
                )
            if self._endpoint_path.exists():
                try:
                    ep = read_client_endpoint(self._endpoint_path, adapters)
                except (BrainError, OSError) as err:
                    last_err = err
                else:
                    if _probe_loopback_tls_ready(ep.host, ep.port, deadline - time.perf_counter()):
                        self.snapshot_descendant_pids()
                        return ep
                    last_err = OSError("loopback TLS listener not yet accepting handshakes")
            time.sleep(0.01)
        raise AssertionError(f"Timed out waiting for endpoint.json at {self._endpoint_path} (last_err={last_err})")

    def signal_and_wait_exit(self, timeout: float = 15.0) -> tuple[int, str, str, tuple[int, ...]]:
        """Send graceful foreground stop signal and verify launcher + all worker descendants exit."""
        tracked_identities = self.snapshot_descendant_identities()
        tracked_pids = tuple(pid for pid, _ in tracked_identities)
        if sys.platform == "win32":
            ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
            assert ctrl_break is not None
            os.kill(self._proc.pid, int(ctrl_break))
        else:
            self._proc.send_signal(signal.SIGTERM)

        out_b, err_b = self._proc.communicate(timeout=timeout)
        rc = self._proc.returncode
        assert rc is not None

        if sys.platform == "win32":
            for child_pid, child_ticks in tracked_identities:
                exited = _win32_wait_or_terminate_pid(
                    child_pid,
                    expected_ticks=child_ticks,
                    job_handle=self._job_handle,
                    terminate=False,
                    timeout_s=timeout,
                )
                assert exited, f"Descendant worker process pid={child_pid} still running after serve exit"
            if self._job is not None and self._job_assigned:
                job_deadline = time.monotonic() + min(1.0, max(0.0, timeout))
                job_pids = self._job.query_pids()
                while job_pids:
                    if time.monotonic() >= job_deadline:
                        break
                    time.sleep(0.01)
                    job_pids = self._job.query_pids()
                assert job_pids == (), f"Descendant worker processes still active in job after serve exit: {job_pids}"
                self._job.close()

        self._closed = True
        return (
            rc,
            out_b.decode("utf-8", errors="replace"),
            err_b.decode("utf-8", errors="replace"),
            tracked_pids,
        )

    def close(self, timeout: float = 10.0) -> None:
        if self._closed:
            return
        self._closed = True
        tracked_identities = self.snapshot_descendant_identities()
        if self._proc.poll() is None:
            with contextlib.suppress(OSError, ValueError, subprocess.TimeoutExpired):
                if sys.platform == "win32":
                    ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
                    if ctrl_break is not None:
                        os.kill(self._proc.pid, int(ctrl_break))
                else:
                    self._proc.send_signal(signal.SIGTERM)
                self._proc.communicate(timeout=min(3.0, timeout))
        if self._proc.poll() is None:
            with contextlib.suppress(OSError):
                self._proc.kill()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                self._proc.communicate(timeout=2.0)
        if sys.platform == "win32":
            try:
                if self._job is not None and self._job_assigned:
                    if not self._job.terminate_and_wait(timeout_s=2.0):
                        self.cleanup_unverified = True
                for pid, ticks in tracked_identities:
                    with contextlib.suppress(Exception):
                        if not _win32_wait_or_terminate_pid(
                            pid,
                            expected_ticks=ticks,
                            job_handle=self._job_handle,
                            terminate=True,
                            timeout_s=2.0,
                        ):
                            self.cleanup_unverified = True
                if self._proc_ticks is None:
                    self.cleanup_unverified = True
                else:
                    with contextlib.suppress(Exception):
                        if not _win32_wait_or_terminate_pid(
                            self._proc.pid,
                            expected_ticks=self._proc_ticks,
                            job_handle=self._job_handle,
                            terminate=True,
                            timeout_s=2.0,
                        ):
                            self.cleanup_unverified = True
            finally:
                if self._job is not None:
                    self._job.close()

    def __enter__(self) -> InstalledServeProcess:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def spawn_installed_brain_serve(
    env: InstalledEnv,
    config_path: Path,
    *,
    data_root: Path,
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> InstalledServeProcess:
    """Spawn ``brain serve --config <config_path>`` from the installed wheel venv."""
    brain_bin = installed_script_path(env, "brain")
    return InstalledServeProcess(
        [str(brain_bin), "serve", "--config", str(config_path)],
        data_root=data_root,
        cwd=cwd,
        extra_env=extra_env,
    )


def spawn_installed_fixture_daemon(
    env: InstalledEnv,
    config_path: Path,
    *,
    data_root: Path,
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> InstalledServeProcess:
    """Spawn ``venv_python -I inc2_cli.py serve-fixture-domain <config_path>`` on the installed wheel."""
    return InstalledServeProcess(
        [str(env.venv_python), "-I", str(INC2_CLI_PATH), "serve-fixture-domain", str(config_path)],
        data_root=data_root,
        cwd=cwd,
        extra_env=extra_env,
    )


# ---------------------------------------------------------------------------
# Stdio JSON-RPC framing helpers
# ---------------------------------------------------------------------------


def mcp_init_frames(
    req_id: int | str = 1,
    protocol_version: str = "2025-06-18",
) -> list[dict[str, JsonValue]]:
    """Return canonical ``initialize`` + ``notifications/initialized`` MCP stdio frames."""
    return [
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "inc2-test-host", "version": "1.0.0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
    ]


def mcp_call_frame(
    req_id: int | str,
    name: str,
    arguments: Mapping[str, JsonValue],
    *,
    meta: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Build a ``tools/call`` JSON-RPC request frame."""
    params: dict[str, JsonValue] = {
        "name": name,
        "arguments": dict(arguments),
    }
    if meta is not None:
        params["_meta"] = dict(meta)
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": params,
    }


def encode_stdio_frames(frames: Sequence[Mapping[str, JsonValue]], *, line_ending: bytes = b"\n") -> bytes:
    """Encode JSON-RPC frames as newline-delimited UTF-8 bytes."""
    return b"".join(canonical_json(dict(frame)) + line_ending for frame in frames)


def decode_stdio_frames(raw_stdout: bytes) -> list[dict[str, JsonValue]]:
    """Decode newline-delimited JSON-RPC response frames from ``stdout``."""
    out: list[dict[str, JsonValue]] = []
    for raw_line in raw_stdout.splitlines():
        if not raw_line.strip():
            continue
        parsed = parse_json(raw_line)
        assert isinstance(parsed, dict)
        out.append(parsed)
    return out


def run_inprocess_stdio(
    caller: ToolCaller,
    frames: Sequence[Mapping[str, JsonValue]],
) -> tuple[int, list[dict[str, JsonValue]]]:
    """Run ``run_stdio`` in-process over ``frames`` and return ``(exit_code, decoded_responses)``."""
    stdin_buf = io.BytesIO(encode_stdio_frames(frames))
    stdout_buf = io.BytesIO()
    rc = run_stdio(stdin_buf, stdout_buf, caller)
    return rc, decode_stdio_frames(stdout_buf.getvalue())


class InstalledMcpPipeSession:
    """Interactive open-pipe MCP stdio controller for installed ``brain-mcp`` and ``brain mcp``."""

    def __init__(
        self,
        env: InstalledEnv,
        script_name: str,
        args: Sequence[str],
        *,
        cwd: Path,
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        script = installed_script_path(env, script_name)
        assert script.is_file(), f"Installed console script not found: {script}"
        self._label = f"{script_name} {' '.join(args)}".strip()
        child_env = clean_installed_subprocess_env(extra_env)
        self._job: _Win32ProcessJob | None = (
            _Win32ProcessJob(kill_on_close=False) if sys.platform == "win32" else None
        )
        self._proc, self._job_assigned = _win32_spawn_in_job(
            self._job,
            [str(script), *args],
            cwd=cwd,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        readers: list[threading.Thread] = []
        with _rollback_child_setup(self._proc, self._job, readers=readers):
            if sys.platform == "win32" and not self._job_assigned:
                raise RuntimeError("InstalledMcpPipeSession requires Win32 Job Object assignment")
            assert self._proc.stdin is not None
            assert self._proc.stdout is not None
            assert self._proc.stderr is not None
            self._stdin = self._proc.stdin
            self._stdout = self._proc.stdout
            self._stderr = self._proc.stderr
            self._lines: queue.Queue[bytes] = queue.Queue()
            self._reader = threading.Thread(target=self._read_stdout_lines, daemon=True)
            self._stderr_bytes = bytearray()
            self._stderr_pump = threading.Thread(target=self._drain_stderr, daemon=True)
            self._writer: threading.Thread | None = None
            self._write_error: OSError | ValueError | None = None
            self._job_handle: int | None = (
                self._job.handle if (self._job is not None and self._job_assigned) else None
            )
            self._proc_ticks: int | None = (
                _win32_popen_creation_ticks(self._proc) if sys.platform == "win32" else None
            )
            self._descendants: list[tuple[int, int]] = []
            self._closed = False
            self.cleanup_unverified = bool(self._job is not None and not self._job_assigned)
            readers.extend((self._reader, self._stderr_pump))
            self._reader.start()
            self._stderr_pump.start()

    def _read_stdout_lines(self) -> None:
        try:
            while True:
                line = self._stdout.readline()
                self._lines.put(line)
                if not line:
                    break
        except (OSError, ValueError):
            self._lines.put(b"")

    def _drain_stderr(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            while chunk := os.read(self._stderr.fileno(), 65536):
                self._stderr_bytes += chunk

    def _stderr_tail(self) -> str:
        return bytes(self._stderr_bytes[-_DIAGNOSTIC_TAIL_BYTES:]).decode("utf-8", errors="replace")

    def _write_chunks(self, chunks: Sequence[bytes]) -> None:
        try:
            for chunk in chunks:
                self._stdin.write(chunk)
                self._stdin.flush()
        except (OSError, ValueError) as err:
            self._write_error = err

    def _close_stdin(self) -> None:
        if self._writer is None or not self._writer.is_alive():  # Closing under a blocked write would block too.
            with contextlib.suppress(OSError, ValueError):
                self._stdin.close()

    def _snapshot_descendant_identities(self) -> tuple[tuple[int, int], ...]:
        if sys.platform == "win32":
            if self._proc_ticks is None:
                self.cleanup_unverified = True
                return tuple(self._descendants)
            identities, unverified = _win32_descendant_identities_checked(
                self._proc.pid,
                root_ticks=self._proc_ticks,
                job_handle=self._job_handle,
            )
            if unverified:
                self.cleanup_unverified = True
            seen = set(self._descendants)
            for ident in identities:
                if ident not in seen:
                    seen.add(ident)
                    self._descendants.append(ident)
        return tuple(self._descendants)

    def _snapshot_descendants(self) -> tuple[int, ...]:
        return tuple(pid for pid, _ in self._snapshot_descendant_identities())

    def write_chunks_and_expect_response(
        self,
        chunks: Sequence[bytes],
        *,
        timeout: float = 2.0,
        require_alive_after: bool = True,
    ) -> dict[str, JsonValue]:
        """Write raw byte chunks to open ``stdin``, flush each, and wait for one response line."""
        assert not self._stdin.closed, f"{self._label}: stdin must remain open before sending frame"
        assert self._proc.poll() is None, f"{self._label}: process exited before frame was sent"
        assert self._writer is None or not self._writer.is_alive(), f"{self._label}: previous write is still blocked"
        self._writer = threading.Thread(target=self._write_chunks, args=(chunks,), daemon=True)
        self._writer.start()
        self._writer.join(_STDIN_WRITE_TIMEOUT_S)
        if self._writer.is_alive():
            raise AssertionError(
                f"{self._label}: stdin write did not finish within {_STDIN_WRITE_TIMEOUT_S:.1f}s "
                f"(process_alive={self._proc.poll() is None})\nstderr tail:\n{self._stderr_tail()}"
            )
        if self._write_error is not None:
            raise self._write_error
        self._snapshot_descendant_identities()
        try:
            raw_line = self._lines.get(timeout=timeout)
        except queue.Empty as err:
            alive = self._proc.poll() is None
            raise AssertionError(
                f"{self._label}: timed out after {timeout:.1f}s waiting for MCP response while stdin open "
                f"(process_alive={alive}, stdin_closed={self._stdin.closed})\nstderr tail:\n{self._stderr_tail()}"
            ) from err
        assert raw_line, (
            f"{self._label}: stdout reached EOF without emitting expected MCP response\n"
            f"stderr tail:\n{self._stderr_tail()}"
        )
        assert not self._stdin.closed, f"{self._label}: stdin was unexpectedly closed"
        if require_alive_after:
            assert self._proc.poll() is None, f"{self._label}: process exited while interactive pipe should stay open"
        decoded = decode_stdio_frames(raw_line)
        assert len(decoded) == 1, f"{self._label}: expected single response frame, got {decoded!r}"
        return decoded[0]

    def send_frames_and_expect_response(
        self,
        frames: Sequence[Mapping[str, JsonValue]],
        *,
        timeout: float = 2.0,
    ) -> dict[str, JsonValue]:
        """Encode ``frames`` with LF, send on open ``stdin``, and return the single decoded response frame."""
        return self.write_chunks_and_expect_response([encode_stdio_frames(frames)], timeout=timeout)

    def finish(self, *, timeout: float = 5.0) -> tuple[int, bytes]:
        """Close ``stdin``, wait for clean process exit, and return ``(returncode, stderr_bytes)``."""
        self._snapshot_descendant_identities()
        self._close_stdin()
        try:
            rc = self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as err:
            raise AssertionError(
                f"{self._label}: did not exit within {timeout:.1f}s of stdin close\nstderr tail:\n{self._stderr_tail()}"
            ) from err
        self._reader.join(timeout=2.0)
        self._stderr_pump.join(timeout=_STDERR_DRAIN_TIMEOUT_S)
        assert not self._stderr_pump.is_alive(), f"{self._label}: a descendant still holds stderr after exit"
        stderr_bytes = bytes(self._stderr_bytes)
        self.close()
        return rc, stderr_bytes

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        tracked = (
            self._snapshot_descendant_identities()
            if self._proc.poll() is None
            else tuple(self._descendants)
        )
        self._close_stdin()
        if self._proc.poll() is None and self._stdin.closed:
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                self._proc.wait(timeout=2.0)
        if self._proc.poll() is None:
            with contextlib.suppress(OSError):
                self._proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                self._proc.wait(timeout=2.0)
        if sys.platform == "win32":
            try:
                for pid, ticks in tracked:
                    with contextlib.suppress(Exception):
                        if not _win32_wait_or_terminate_pid(
                            pid,
                            expected_ticks=ticks,
                            job_handle=self._job_handle,
                            terminate=True,
                            timeout_s=2.0,
                        ):
                            self.cleanup_unverified = True
                if self._proc_ticks is None:
                    self.cleanup_unverified = True
                else:
                    with contextlib.suppress(Exception):
                        if not _win32_wait_or_terminate_pid(
                            self._proc.pid,
                            expected_ticks=self._proc_ticks,
                            job_handle=self._job_handle,
                            terminate=True,
                            timeout_s=2.0,
                        ):
                            self.cleanup_unverified = True
            finally:
                if self._job is not None:
                    self._job.close()
        if self._writer is not None:
            self._writer.join(timeout=1.0)
        self._close_stdin()
        for thread, stream in ((self._reader, self._stdout), (self._stderr_pump, self._stderr)):
            thread.join(timeout=_STDERR_DRAIN_TIMEOUT_S)
            if not thread.is_alive():  # Closing under a blocked reader would block on its lock.
                with contextlib.suppress(OSError, ValueError):
                    stream.close()

    def __enter__(self) -> InstalledMcpPipeSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


# ---------------------------------------------------------------------------
# ShimTestDomain implementing KernelToolDomain
# ---------------------------------------------------------------------------


@dataclass
class ShimTestDomain(KernelToolDomain):
    """Fixture ``KernelToolDomain`` for Task 7 integration and wheel tests.

    Supports ``prepare_task``, ``get_artifact``, ``record_outcome``, and ``submit_episode`` with:
    - Strict ``selected_scope`` and checkout-level authorization for ``get_artifact`` and
      ``record_outcome`` BEFORE staging CAS blobs or mutating the ledger.
    - Optional ``pause_idem_keys`` barrier inside ``apply(tx)`` for commit-cutoff testing.
    - Packaged ``mcp-tools-v2.json`` schema SHA-256 recorded in ``prepare_task`` CAS blob and
      ``context.summary_md`` for wheel-to-daemon catalog verification.
    """

    alias_to_scope: dict[str, Scope] = field(default_factory=dict)
    checkout_scoped_artifacts: dict[str, Scope] = field(default_factory=dict)
    pause_idem_keys: set[str] = field(default_factory=set)
    apply_entered: threading.Event = field(default_factory=threading.Event)
    allow_apply_finish: threading.Event = field(default_factory=threading.Event)
    on_apply_hook: Callable[[str, str], None] | None = None
    received_calls: list[Call] = field(default_factory=list)
    prepared_calls: list[Call] = field(default_factory=list)
    task_scopes: dict[str, tuple[str, Scope]] = field(default_factory=dict)
    deliveries: dict[str, tuple[str, Scope, str, str]] = field(default_factory=dict)
    stored_meta: dict[str, dict[str, JsonValue]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.allow_apply_finish.set()

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if deep:
            return False
        return tool in {"prepare_task", "get_artifact", "record_outcome", "submit_episode"}

    def _require_concrete_scope(self, call: Call, *, expected_repo_id: str | None = None) -> Scope:
        scope = call.selected_scope
        if scope is None or scope.checkout_id is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        if expected_repo_id is not None and scope.repo_id != expected_repo_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return scope

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: dt.datetime) -> PreparedEffect:
        del now
        with self._lock:
            self.received_calls.append(call)

        if call.tool == "prepare_task":
            return self._prepare_task_mutation(call, ctx)
        if call.tool == "get_artifact":
            return self._prepare_get_artifact(call, ctx)
        if call.tool == "record_outcome":
            return self._prepare_record_outcome(call, ctx)
        if call.tool == "submit_episode":
            return self._prepare_submit_episode(call, ctx)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _prepare_task_mutation(self, call: Call, ctx: CallContext) -> PreparedEffect:
        scope = self._require_concrete_scope(call)
        assert scope.checkout_id is not None

        args = call.arguments
        if "workspace_hint" in args:
            hint = str(args["workspace_hint"])
            expected_by_alias = self.alias_to_scope.get(hint)
            if expected_by_alias is not None and expected_by_alias != scope:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        elif "workspace_id" in args and "checkout_id" in args:
            if (str(args["workspace_id"]), str(args["checkout_id"])) != (scope.repo_id, scope.checkout_id):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        else:
            raise BrainError(ErrorCode.INVALID_INPUT, "missing workspace selector")

        raw_task_id = args.get("task_id")
        task_id = require_opaque_id(raw_task_id, label="task_id") if isinstance(raw_task_id, str) else new_id()
        with self._lock:
            existing_task = self.task_scopes.get(task_id)
            if existing_task is not None and existing_task != (ctx.principal.owner_id, scope):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            self.prepared_calls.append(call)

        res_id = new_id()
        delivery_id = new_id()
        assignment_id = new_id()
        catalog_sha256 = load_catalog().schema_sha256
        meta: dict[str, JsonValue] = {
            "kind": "delivery_result",
            "result_id": res_id,
            "delivery_id": delivery_id,
            "assignment_id": assignment_id,
            "task_id": task_id,
            "owner_id": ctx.principal.owner_id,
            "repo_id": scope.repo_id,
            "checkout_id": scope.checkout_id,
            "schema_sha256": catalog_sha256,
        }
        blob = canonical_json(meta)
        ref = ObjectRef(kind="delivery_result", id=res_id, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            tx.hold_blob(blob, holder_id=res_id)
            with self._lock:
                self.task_scopes[task_id] = (ctx.principal.owner_id, scope)
                self.deliveries[delivery_id] = (ctx.principal.owner_id, scope, assignment_id, task_id)
                self.stored_meta[res_id] = meta
            return StoredResult(result_id=res_id, assignment_id=assignment_id, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def _prepare_get_artifact(self, call: Call, ctx: CallContext) -> PreparedEffect:
        ws_id = require_opaque_id(call.arguments["workspace_id"], label="workspace_id")
        scope = self._require_concrete_scope(call, expected_repo_id=ws_id)
        assert scope.checkout_id is not None

        task_id = require_opaque_id(call.arguments["task_id"], label="task_id")
        artifact_id = require_opaque_id(call.arguments["artifact_id"], label="artifact_id")
        revision = int(cast(int, call.arguments["revision"]))
        level = str(call.arguments["level"])

        with self._lock:
            task_binding = self.task_scopes.get(task_id)
            if task_binding is not None and task_binding != (ctx.principal.owner_id, scope):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            bound_art_scope = self.checkout_scoped_artifacts.get(artifact_id)
            if bound_art_scope is not None and bound_art_scope != scope:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            self.prepared_calls.append(call)

        res_id = new_id()
        meta: dict[str, JsonValue] = {
            "kind": "artifact_result",
            "result_id": res_id,
            "task_id": task_id,
            "artifact_id": artifact_id,
            "revision": revision,
            "level": level,
            "owner_id": ctx.principal.owner_id,
            "repo_id": scope.repo_id,
            "checkout_id": scope.checkout_id,
        }
        blob = canonical_json(meta)
        ref = ObjectRef(kind="artifact_result", id=res_id, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            tx.hold_blob(blob, holder_id=res_id)
            with self._lock:
                self.stored_meta[res_id] = meta
            return StoredResult(result_id=res_id, assignment_id=None, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def _prepare_record_outcome(self, call: Call, ctx: CallContext) -> PreparedEffect:
        ws_arg = call.arguments.get("workspace_id")
        expected_repo = require_opaque_id(ws_arg, label="workspace_id") if isinstance(ws_arg, str) else None
        scope = self._require_concrete_scope(call, expected_repo_id=expected_repo)
        assert scope.checkout_id is not None

        delivery_id = require_opaque_id(call.arguments["delivery_id"], label="delivery_id")

        with self._lock:
            deliv = self.deliveries.get(delivery_id)
            if deliv is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            d_owner, d_scope, d_assign, _d_task = deliv
            if d_owner != ctx.principal.owner_id or d_scope != scope:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            assignment_id = d_assign

            raw_refs = call.arguments.get("applied_refs")
            if isinstance(raw_refs, list):
                for item in raw_refs:
                    if isinstance(item, Mapping):
                        ref_id = str(item.get("id", ""))
                        bound_scope = self.checkout_scoped_artifacts.get(ref_id)
                        if bound_scope is not None and bound_scope != scope:
                            raise BrainError(ErrorCode.NOT_FOUND, "not found")
            self.prepared_calls.append(call)

        outcome_id = new_id()
        meta: dict[str, JsonValue] = {
            "kind": "outcome_result",
            "result_id": outcome_id,
            "owner_id": ctx.principal.owner_id,
            "repo_id": scope.repo_id,
            "checkout_id": scope.checkout_id,
        }
        blob = canonical_json(meta)
        ref = ObjectRef(kind="outcome_result", id=outcome_id, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            tx.hold_blob(blob, holder_id=outcome_id)
            with self._lock:
                self.stored_meta[outcome_id] = meta
            return StoredResult(result_id=outcome_id, assignment_id=assignment_id, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def _prepare_submit_episode(self, call: Call, ctx: CallContext) -> PreparedEffect:
        ws_id = require_opaque_id(call.arguments["workspace_id"], label="workspace_id")
        chk_id = require_opaque_id(call.arguments["checkout_id"], label="checkout_id")
        scope = self._require_concrete_scope(call, expected_repo_id=ws_id)
        if scope.checkout_id != chk_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        idem_key = str(call.arguments.get("idempotency_key", ""))
        with self._lock:
            self.prepared_calls.append(call)

        episode_id = new_id()
        meta: dict[str, JsonValue] = {
            "kind": "episode_result",
            "result_id": episode_id,
            "owner_id": ctx.principal.owner_id,
            "repo_id": scope.repo_id,
            "checkout_id": scope.checkout_id,
        }
        blob = canonical_json(meta)
        ref = ObjectRef(kind="episode_result", id=episode_id, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            with self._lock:
                should_pause = idem_key in self.pause_idem_keys
            if self.on_apply_hook is not None:
                self.on_apply_hook(idem_key, episode_id)
            if should_pause:
                self.apply_entered.set()
                if not self.allow_apply_finish.wait(timeout=15.0):
                    raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            tx.hold_blob(blob, holder_id=episode_id)
            with self._lock:
                self.stored_meta[episode_id] = meta
            return StoredResult(result_id=episode_id, assignment_id=None, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        del call, ctx
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        with self._lock:
            meta = self.stored_meta.get(result.result_id)
        if meta is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        owner_id = str(meta["owner_id"])
        repo_id = str(meta["repo_id"])
        checkout_id = str(meta["checkout_id"])
        expected_scope = Scope(repo_id=repo_id, checkout_id=checkout_id)
        if principal.owner_id != owner_id or selected_scope != expected_scope:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        kind = str(meta["kind"])
        if kind == "delivery_result":
            schema_sha256 = str(meta["schema_sha256"])
            return {
                "workspace_id": repo_id,
                "checkout_id": checkout_id,
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": str(meta["task_id"]),
                "delivery_id": str(meta["delivery_id"]),
                "assignment_id": str(meta["assignment_id"]),
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": {
                    "summary_md": f"catalog_sha256={schema_sha256}",
                    "sources": [],
                    "unknown_source": False,
                },
                "finishing_gates": [],
            }
        if kind == "artifact_result":
            artifact_id = str(meta["artifact_id"])
            revision = int(cast(int, meta["revision"]))
            level = str(meta["level"])
            content = f"# Skill {artifact_id}@{revision} ({level})\n"
            return {
                "artifact_id": artifact_id,
                "revision": revision,
                "level": level,
                "status": "ok",
                "resources": [
                    {
                        "name": f"{level}.md",
                        "digest": digest_bytes(content.encode("utf-8")),
                        "encoding": "utf-8",
                        "content": content,
                    }
                ],
            }
        if kind == "outcome_result":
            return {
                "outcome_id": str(meta["result_id"]),
                "status": "declared",
            }
        if kind == "episode_result":
            return {
                "episode_id": str(meta["result_id"]),
                "evidence_ids": [],
                "candidate_lesson_id": None,
            }
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unknown stored result kind")

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        del rendered, selected_scope
        if not result.refs or result.refs[0].kind != "artifact_result":
            return None
        with self._lock:
            meta = self.stored_meta.get(result.result_id)
        if meta is None:
            return None
        artifact_id = str(meta["artifact_id"])
        revision = int(cast(int, meta["revision"]))
        level = str(meta["level"])
        task_id = str(meta["task_id"])
        content = f"# Skill {artifact_id}@{revision} ({level})\n"
        return ArtifactSendSpec(
            logical_result_id=result.result_id,
            principal_id=principal.principal_id,
            task_id=task_id,
            artifact_id=artifact_id,
            revision=revision,
            resource_digests=(ResourceDigest(name=f"{level}.md", digest=digest_bytes(content.encode("utf-8"))),),
            level=level,
        )


def _cli_main(argv: Sequence[str]) -> int:
    if len(argv) == 3 and argv[1] == "serve-fixture-domain":
        config_path = Path(argv[2])
        domain = ShimTestDomain()
        return serve_config_path(config_path, domain=domain)
    sys.stderr.write("invalid_input\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli_main(sys.argv))
