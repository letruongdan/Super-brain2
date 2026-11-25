"""Subprocess harness for SP1 Increment 2 Task 6a daemon ``serve`` and ``migrate_offline`` tests.

Spawns an isolated interpreter via ``[sys.executable, "-I", "-c", _RUNPY, ...]`` with a dedicated
JSON-line control pipe separated from ``sys.stdout``/``sys.stderr`` (fd ``1`` duplicated to ``ctrl_out``
before redirecting ``1 -> 2``). On Windows, ``.venv\\Scripts\\python.exe`` is a launcher process whose
child interpreter holds ``writer.lock`` and loopback sockets; ``kill_and_verify`` terminates and waits on
BOTH ``inner_pid`` and ``launcher_pid`` without ``time.sleep``.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import traceback
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from superbrain.application.owner_loop import OwnerLoop
    from tests.support.inc2_cli import _Win32ProcessJob

from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DEFAULT_SHUTDOWN_GRACE_S, Endpoint, Ready

INC2_CHILD_PATH = Path(__file__).resolve()
DEFAULT_CHILD_TIMEOUT_S = 15.0
_CHILD_PAUSE_TIMEOUT_S = 30.0
_PUMP_JOIN_S = 2.0
_RUNPY = "import runpy,sys; sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')"
_STRIPPED_ENV_VARS: tuple[str, ...] = (
    "VIRTUAL_ENV",
    "UV_PROJECT_ENVIRONMENT",
    "PYTHONPATH",
    "PYTHONHOME",
    "SUPERBRAIN_CRASHPOINT",
    "SUPERBRAIN_PAUSEPOINT",
)


@dataclass(frozen=True)
class ChildOutcome:
    """Terminal control-pipe outcome and OS exit code from an ``Inc2ChildProcess``."""

    ok: bool
    exit_code: int | None
    error_code: str | None
    returncode: int
    writer_epoch: int | None = None
    noop: bool | None = None
    stderr: str = ""


def inc2_child_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build an isolated child environment stripped of venv/PYTHONPATH and fault-injection variables."""
    env = {k: v for k, v in os.environ.items() if k not in _STRIPPED_ENV_VARS}
    if overrides:
        env.update(overrides)
    return env


def inc2_child_command(operation: str, config_path: Path, extra_args: Sequence[str] = ()) -> list[str]:
    """Construct the ``sys.executable -I`` command line targeting ``inc2_child.py``."""
    return [sys.executable, "-I", str(INC2_CHILD_PATH), operation, str(config_path), *extra_args]


def _win32_handle_creation_ticks(handle: int) -> int | None:
    """Return 100ns FILETIME creation ticks for an already-open Win32 process handle."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel32.GetProcessTimes(wintypes.HANDLE(int(handle)), *(ctypes.byref(t) for t in times)):
        return None
    return (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)


def _current_win32_creation_ticks() -> int | None:
    """Return 100ns creation ticks of the current Win32 process via ``GetCurrentProcess()``."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    return _win32_handle_creation_ticks(int(kernel32.GetCurrentProcess()))


def _win32_terminate_and_wait_pid(
    pid: int,
    timeout_s: float,
    *,
    expected_ticks: int | None = None,
    job_handle: int | None = None,
) -> bool:
    """Terminate ``pid`` via Win32 kernel handle only when ``expected_ticks`` (and optional ``job_handle``) matches."""
    assert sys.platform == "win32"
    if expected_ticks is None or isinstance(expected_ticks, bool) or not isinstance(expected_ticks, int):
        return False
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32process

    access = win32con.PROCESS_TERMINATE | win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_LIMITED_INFORMATION
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
            return True  # Target exited and PID was recycled; do not touch new occupant.
        if job_handle is not None:
            from tests.support.inc2_cli import _win32_is_handle_in_job

            if _win32_is_handle_in_job(int(handle), job_handle) is not True:
                return False
        with contextlib.suppress(pywintypes.error):
            win32process.TerminateProcess(handle, 9)
        timeout_ms = max(1, int(timeout_s * 1000))
        wait_rc = win32event.WaitForSingleObject(handle, timeout_ms)
        if wait_rc != win32event.WAIT_OBJECT_0:
            raise AssertionError(f"Windows child process pid={pid} did not exit within {timeout_s}s (rc={wait_rc})")
        code = win32process.GetExitCodeProcess(handle)
        if code == win32con.STILL_ACTIVE:
            raise AssertionError(f"Windows child process pid={pid} still reports STILL_ACTIVE after wait")
        return True
    finally:
        win32api.CloseHandle(handle)


class Inc2ChildProcess:
    """Parent controller for one isolated ``serve`` or ``migrate`` child interpreter."""

    def __init__(
        self,
        args: Sequence[str | Path],
        *,
        env_overrides: Mapping[str, str] | None = None,
        unmanaged_descendants_allowed: bool = False,
    ) -> None:
        self.args = tuple(str(a) for a in args)
        self._unmanaged_descendants_allowed = bool(unmanaged_descendants_allowed)
        from tests.support.inc2_cli import _rollback_child_setup, _win32_spawn_in_job, _Win32ProcessJob

        child_env = inc2_child_env(env_overrides)
        self._job: _Win32ProcessJob | None = None
        self._job_assigned = False
        self._job_handle: int | None = None
        if sys.platform == "win32":
            self._job = _Win32ProcessJob(kill_on_close=False)
            self._proc, self._job_assigned = _win32_spawn_in_job(
                self._job,
                list(args),
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        else:
            self._proc = subprocess.Popen(
                list(args),
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        readers: list[threading.Thread] = []
        with _rollback_child_setup(self._proc, self._job, readers=readers):
            if self._job is not None:
                if not self._job_assigned:
                    raise RuntimeError("Inc2ChildProcess requires Win32 Job Object assignment")
                self._job_handle = self._job.handle
            assert self._proc.stdin is not None
            assert self._proc.stdout is not None
            assert self._proc.stderr is not None

            self._lock = threading.Lock()
            self._hello_event = threading.Event()
            self._inner_pid: int | None = None
            self._inner_ticks: int | None = None
            proc_handle = getattr(self._proc, "_handle", None)
            self._proc_ticks: int | None = (
                _win32_handle_creation_ticks(int(proc_handle))
                if proc_handle is not None
                else None
            )
            self.cleanup_unverified = bool(self._job is not None and not self._job_assigned)
            self._events: queue.Queue[dict[str, JsonValue] | None] = queue.Queue()
            self._buffered_events: list[dict[str, JsonValue]] = []
            self._terminal_result_event: dict[str, JsonValue] | None = None
            self._stderr_lines: list[str] = []
            self._closed = False

            self._ctrl_pump = threading.Thread(
                target=self._pump_control,
                args=(self._proc.stdout,),
                name="inc2-child-ctrl-pump",
                daemon=True,
            )
            self._err_pump = threading.Thread(
                target=self._pump_stderr,
                args=(self._proc.stderr,),
                name="inc2-child-stderr-pump",
                daemon=True,
            )
            readers.extend((self._ctrl_pump, self._err_pump))
            self._ctrl_pump.start()
            self._err_pump.start()

    @property
    def launcher_pid(self) -> int:
        return self._proc.pid

    @property
    def inner_pid(self) -> int | None:
        with self._lock:
            return self._inner_pid

    def stderr_text(self) -> str:
        with self._lock:
            return "".join(self._stderr_lines)

    def _pump_control(self, stream: IO[str]) -> None:
        try:
            with contextlib.suppress(OSError, ValueError):
                for raw_line in stream:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parsed = json.loads(line)
                    if not isinstance(parsed, dict):
                        continue
                    if parsed.get("event") == "hello" and type(parsed.get("pid")) is int:
                        raw_ticks = parsed.get("creation_ticks")
                        with self._lock:
                            self._inner_pid = int(parsed["pid"])
                            self._inner_ticks = int(raw_ticks) if type(raw_ticks) is int else None
                        self._hello_event.set()
                        continue
                    self._events.put(parsed)
        finally:
            self._events.put(None)

    def _pump_stderr(self, stream: IO[str]) -> None:
        with contextlib.suppress(OSError, ValueError):
            for line in stream:
                with self._lock:
                    self._stderr_lines.append(line)

    def wait_hello(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> int:
        """Block until the child emits ``hello`` with its actual interpreter PID."""
        if not self._hello_event.wait(timeout=timeout):
            raise AssertionError(
                f"Child (launcher_pid={self.launcher_pid}) did not emit hello within {timeout}s.\n"
                f"stderr:\n{self.stderr_text()}"
            )
        pid = self.inner_pid
        assert pid is not None
        return pid

    def _next_event(
        self,
        predicate_desc: str,
        *,
        accept_events: frozenset[str],
        timeout: float,
    ) -> dict[str, JsonValue]:
        if "result" in accept_events and self._terminal_result_event is not None:
            return self._terminal_result_event

        for idx, buffered in enumerate(self._buffered_events):
            ev_name = buffered.get("event")
            if isinstance(ev_name, str) and ev_name in accept_events:
                popped = self._buffered_events.pop(idx)
                if ev_name == "result":
                    self._terminal_result_event = popped
                return popped

        while True:
            try:
                item = self._events.get(timeout=timeout)
            except queue.Empty as err:
                raise AssertionError(
                    f"Timed out after {timeout}s waiting for {predicate_desc} "
                    f"(launcher_pid={self.launcher_pid}, inner_pid={self.inner_pid}).\n"
                    f"stderr:\n{self.stderr_text()}"
                ) from err
            if item is None:
                rc = self._proc.poll()
                raise AssertionError(
                    f"Control pipe closed before {predicate_desc} "
                    f"(returncode={rc}, launcher_pid={self.launcher_pid}, inner_pid={self.inner_pid}).\n"
                    f"stderr:\n{self.stderr_text()}"
                )
            ev_name = item.get("event")
            if ev_name == "result":
                self._terminal_result_event = item
            if isinstance(ev_name, str) and ev_name in accept_events:
                return item
            self._buffered_events.append(item)

    def wait_ready_or_result(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> dict[str, JsonValue]:
        """Wait until the child emits either ``ready`` or terminal ``result``."""
        self.wait_hello(timeout=timeout)
        return self._next_event(
            "ready or result",
            accept_events=frozenset({"ready", "result"}),
            timeout=timeout,
        )

    def wait_ready(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> tuple[Endpoint, str]:
        """Wait for ``ready`` and return ``(Endpoint, leaf_cert_sha256)``, failing if startup refused."""
        ev = self.wait_ready_or_result(timeout=timeout)
        if ev.get("event") != "ready":
            raise AssertionError(
                f"Expected child ready event, got {ev!r}.\nstderr:\n{self.stderr_text()}"
            )
        raw_ep = ev.get("endpoint")
        leaf_sha = ev.get("leaf_cert_sha256")
        if not isinstance(raw_ep, dict) or not isinstance(leaf_sha, str):
            raise AssertionError(f"Malformed child ready payload: {ev!r}")
        return Endpoint.from_dict(raw_ep), leaf_sha

    def wait_paused_in_migrate(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> None:
        """Wait until ``migrate_offline`` pauses at ``_after_policy_step`` while holding ``writer.lock``."""
        self.wait_hello(timeout=timeout)
        ev = self._next_event(
            "paused_in_migrate or result",
            accept_events=frozenset({"paused_in_migrate", "result"}),
            timeout=timeout,
        )
        if ev.get("event") != "paused_in_migrate":
            raise AssertionError(
                f"Expected migrate child to pause in _after_policy_step, got {ev!r}.\n"
                f"stderr:\n{self.stderr_text()}"
            )

    def send_command(self, cmd: str) -> None:
        """Send a JSON-line command (``stop`` or ``resume``) over the child's control ``stdin``."""
        assert self._proc.stdin is not None
        payload = json.dumps({"cmd": cmd}, separators=(",", ":")) + "\n"
        self._proc.stdin.write(payload)
        self._proc.stdin.flush()

    def wait_result(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> ChildOutcome:
        """Wait for the child's terminal ``result`` event and OS process exit."""
        self.wait_hello(timeout=timeout)
        ev = self._next_event("result", accept_events=frozenset({"result"}), timeout=timeout)
        try:
            rc = self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as err:
            self.kill_and_verify(timeout=5.0)
            raise AssertionError(
                f"Child emitted result {ev!r} but did not exit within {timeout}s.\n"
                f"stderr:\n{self.stderr_text()}"
            ) from err
        self._close_pipes_and_join_pumps()
        ok = bool(ev.get("ok"))
        exit_code = ev.get("exit_code")
        error_code = ev.get("error_code")
        writer_epoch = ev.get("writer_epoch")
        noop = ev.get("noop")
        return ChildOutcome(
            ok=ok,
            exit_code=exit_code if type(exit_code) is int else None,
            error_code=error_code if isinstance(error_code, str) else None,
            returncode=rc,
            writer_epoch=writer_epoch if type(writer_epoch) is int else None,
            noop=noop if isinstance(noop, bool) else None,
            stderr=self.stderr_text(),
        )

    def request_stop_and_wait(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> ChildOutcome:
        """Send ``{"cmd": "stop"}`` to a ``serve`` child and wait for clean exit."""
        self.send_command("stop")
        return self.wait_result(timeout=timeout)

    def resume_and_wait(self, timeout: float = DEFAULT_CHILD_TIMEOUT_S) -> ChildOutcome:
        """Send ``{"cmd": "resume"}`` to a paused ``migrate`` child and wait for completion."""
        self.send_command("resume")
        return self.wait_result(timeout=timeout)

    def kill_and_verify(self, timeout: float = 10.0) -> None:
        """Terminate the supervised process and require verified cleanup."""
        if self._proc.poll() is None and self.inner_pid is None:
            self._hello_event.wait(timeout=min(timeout, 3.0))
        self.close(timeout=timeout)
        assert self._proc.poll() is not None
        assert not self.cleanup_unverified, "Child process cleanup could not be verified"

    def _close_pipes_and_join_pumps(self) -> None:
        if self._proc.stdin is not None:
            with contextlib.suppress(OSError, ValueError):
                self._proc.stdin.close()
        for pump, stream in ((self._ctrl_pump, self._proc.stdout), (self._err_pump, self._proc.stderr)):
            pump.join(timeout=_PUMP_JOIN_S)
            if stream is not None and not pump.is_alive():  # Closing under a blocked reader would block on its lock.
                with contextlib.suppress(OSError, ValueError):
                    stream.close()

    def close(self, timeout: float = 10.0) -> None:
        """Stop owned processes and flag cleanup that could not be verified."""
        if self._closed:
            return
        self._closed = True
        try:
            inner = self.inner_pid
            launcher = self.launcher_pid
            with self._lock:
                inner_ticks = self._inner_ticks

            if sys.platform == "win32":
                # 1. Terminate and verify managed inner child if known.
                if inner is not None and inner != launcher:
                    if inner_ticks is None or not _win32_terminate_and_wait_pid(
                        inner,
                        timeout,
                        expected_ticks=inner_ticks,
                        job_handle=self._job_handle,
                    ):
                        self.cleanup_unverified = True

                # 2. Terminate and verify launcher process.
                if self._proc.poll() is None:
                    with contextlib.suppress(OSError):
                        self._proc.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                        self._proc.wait(timeout=timeout)

                if self._proc_ticks is None or not _win32_terminate_and_wait_pid(
                    launcher,
                    timeout,
                    expected_ticks=self._proc_ticks,
                    job_handle=self._job_handle,
                ):
                    self.cleanup_unverified = True

                # 3. Terminate Job members if unmanaged descendants are not allowed.
                if not self._unmanaged_descendants_allowed:
                    if self._job is not None and self._job_assigned:
                        if not self._job.terminate_and_wait(timeout_s=timeout):
                            self.cleanup_unverified = True
                        pids = self._job.query_pids()
                        if pids is None or len(pids) > 0:
                            self.cleanup_unverified = True
                    elif self._job is not None:
                        self.cleanup_unverified = True
            else:
                if self._proc.poll() is None:
                    with contextlib.suppress(OSError):
                        self._proc.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                        self._proc.wait(timeout=timeout)

            self._close_pipes_and_join_pumps()
            if sys.platform != "win32":
                # POSIX Popen owns the direct process. A PID from the control
                # pipe cannot establish ownership of a different process.
                reported_inner = self.inner_pid
                self.cleanup_unverified = (
                    self._proc.poll() is None
                    or (reported_inner is not None and reported_inner != launcher)
                    or (
                        not self._unmanaged_descendants_allowed
                        and (self._ctrl_pump.is_alive() or self._err_pump.is_alive())
                    )
                )
        finally:
            if self._job is not None:
                self._job.close()

    def __enter__(self) -> Inc2ChildProcess:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def spawn_serve_child(
    config_path: Path,
    *,
    shutdown_grace_s: float = DEFAULT_SHUTDOWN_GRACE_S,
    env_overrides: Mapping[str, str] | None = None,
) -> Inc2ChildProcess:
    """Spawn a real ``serve_config_path`` child interpreter over ``config_path``."""
    return Inc2ChildProcess(
        inc2_child_command("serve", config_path, ("--grace", str(shutdown_grace_s))),
        env_overrides=env_overrides,
    )


def spawn_migrate_child(
    config_path: Path,
    *,
    pause_in_migrate: bool = False,
    env_overrides: Mapping[str, str] | None = None,
) -> Inc2ChildProcess:
    """Spawn a real ``migrate_offline`` child interpreter over ``config_path``."""
    extra: tuple[str, ...] = ("--pause",) if pause_in_migrate else ()
    return Inc2ChildProcess(
        inc2_child_command("migrate", config_path, extra),
        env_overrides=env_overrides,
    )


# ---------------------------------------------------------------------------
# Child interpreter entrypoint (executed under ``python -I``)
# ---------------------------------------------------------------------------


def _emit(ctrl_out: IO[str], payload: Mapping[str, object]) -> None:
    ctrl_out.write(json.dumps(dict(payload), separators=(",", ":")) + "\n")
    ctrl_out.flush()


def _watch_stdin_for_cmd(expected_cmd: str, target_event: threading.Event) -> None:
    with contextlib.suppress(OSError, ValueError):
        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            msg = json.loads(line)
            if isinstance(msg, dict) and msg.get("cmd") == expected_cmd:
                target_event.set()
                return


def _run_serve_child(config_path: Path, extra_args: Sequence[str], ctrl_out: IO[str]) -> int:
    from superbrain.composition.daemon_entry import serve_config_path

    grace_s = DEFAULT_SHUTDOWN_GRACE_S
    idx = 0
    while idx < len(extra_args):
        if extra_args[idx] == "--grace" and idx + 1 < len(extra_args):
            grace_s = float(extra_args[idx + 1])
            idx += 2
        else:
            raise ValueError(f"Unknown serve child argument: {extra_args[idx]!r}")

    stop_event = threading.Event()
    watcher = threading.Thread(
        target=_watch_stdin_for_cmd,
        args=("stop", stop_event),
        name="inc2-child-stdin-stop",
        daemon=True,
    )
    watcher.start()

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        _emit(
            ctrl_out,
            {
                "event": "ready",
                "endpoint": ready.endpoint.to_dict(),
                "leaf_cert_sha256": ready.leaf_cert_sha256,
            },
        )

    rc = serve_config_path(
        config_path,
        stop_event=stop_event,
        shutdown_grace_s=grace_s,
        on_ready=_on_ready,
    )
    _emit(ctrl_out, {"event": "result", "ok": True, "exit_code": rc})
    return rc


def _run_migrate_child(config_path: Path, extra_args: Sequence[str], ctrl_out: IO[str]) -> int:
    pause = False
    for arg in extra_args:
        if arg == "--pause":
            pause = True
        else:
            raise ValueError(f"Unknown migrate child argument: {arg!r}")

    resume_event = threading.Event()
    if pause:
        watcher = threading.Thread(
            target=_watch_stdin_for_cmd,
            args=("resume", resume_event),
            name="inc2-child-stdin-resume",
            daemon=True,
        )
        watcher.start()

    def _after_policy_step() -> None:
        _emit(ctrl_out, {"event": "paused_in_migrate"})
        if not resume_event.wait(timeout=_CHILD_PAUSE_TIMEOUT_S):
            raise TimeoutError("migrate_offline child timed out waiting for resume command")

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import read_daemon_config
    from superbrain.composition.migrate_entry import migrate_offline

    adapters = os_adapters()
    cfg = read_daemon_config(config_path, adapters)
    report = migrate_offline(
        cfg,
        adapters,
        _after_policy_step=_after_policy_step if pause else None,
    )
    _emit(
        ctrl_out,
        {
            "event": "result",
            "ok": True,
            "exit_code": 0,
            "writer_epoch": report.writer_epoch,
            "noop": report.noop,
        },
    )
    return 0


def _child_main(argv: Sequence[str]) -> int:
    ctrl_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    ctrl_out = os.fdopen(ctrl_fd, "w", encoding="utf-8", buffering=1)
    try:
        _emit(
            ctrl_out,
            {
                "event": "hello",
                "pid": os.getpid(),
                "creation_ticks": _current_win32_creation_ticks(),
            },
        )
        if len(argv) < 3:
            raise ValueError(f"Expected <operation> <config_path>, got {list(argv)!r}")
        operation = argv[1]
        config_path = Path(argv[2])
        extra_args = argv[3:]
        if operation == "serve":
            return _run_serve_child(config_path, extra_args, ctrl_out)
        if operation == "migrate":
            return _run_migrate_child(config_path, extra_args, ctrl_out)
        raise ValueError(f"Unsupported inc2_child operation: {operation!r}")
    except BrainError as err:
        _emit(ctrl_out, {"event": "result", "ok": False, "error_code": err.code.value})
        return 2
    except BaseException as exc:  # noqa: BLE001 — report unexpected child crashes cleanly on ctrl_out
        traceback.print_exc(file=sys.stderr)
        _emit(ctrl_out, {"event": "result", "ok": False, "error_code": f"unexpected:{type(exc).__name__}"})
        return 3
    finally:
        with contextlib.suppress(OSError):
            ctrl_out.close()


if __name__ == "__main__":
    raise SystemExit(_child_main(sys.argv))
