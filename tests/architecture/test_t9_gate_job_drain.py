"""Whole-job cleanup contract; real Win32/image RED is retained outside the timed suite.

These fast tests script only the OS ABI and clock. They call the actual gate helper
and cover state/size/error/deadline siblings of the physical debug-event oracle.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import gate


class ApiCall:
    def __init__(self, action: Any) -> None:
        self.action = action

    def __call__(self, *args: Any) -> Any:
        return self.action(*args)


class JobOs:
    """A stateful OS edge: termination request and observed process exit differ."""

    job = 901

    def __init__(self, pids: list[int], *, delay: float = 0.001) -> None:
        self.active = set(pids)
        self.initial = set(pids)
        self.opened: dict[int, int] = {}
        self.closed: list[int] = []
        self.waited: set[int] = set()
        self.events: list[tuple[str, int]] = []
        self.query_sizes: list[int] = []
        self.open_errors: dict[int, int] = {}
        self.query_error: int | None = None
        self.terminate_error: int | None = None
        self.wait_result: int | None = None
        self.spawn_once: int | None = None
        self.always_more_data = False
        self.partial_success_once = False
        self.listed_ids: list[int] | None = None
        self.close_errors: set[int] = set()
        self.last_error = 0
        self.now = 0.0
        self.delay = delay
        self.termination_requests = 0
        for name, action in (
            ("QueryInformationJobObject", self.query), ("OpenProcess", self.open_process),
            ("TerminateJobObject", self.terminate), ("WaitForSingleObject", self.wait),
            ("CloseHandle", self.close),
            ("CreateJobObjectW", lambda *_a: self.job),
            ("SetInformationJobObject", lambda *_a: 1),
            ("AssignProcessToJobObject", lambda *_a: 1),
        ):
            setattr(self, name, ApiCall(action))

    @staticmethod
    def number(value: Any) -> int:
        return int(value.value) if hasattr(value, "value") else int(value)

    def query(self, job: Any, kind: Any, buffer: Any, size: Any, returned: Any) -> int:
        assert self.number(job) == self.job
        assert self.number(kind) == 3  # JobObjectBasicProcessIdList (actual Win32 ABI).
        size_value = self.number(size)
        header_size = 2 * ctypes.sizeof(wintypes.DWORD)
        slots = (size_value - header_size) // ctypes.sizeof(ctypes.c_size_t)
        self.query_sizes.append(slots)
        self.events.append(("query", len(self.active)))
        if self.query_error is not None:
            self.last_error = self.query_error
            return 0
        if self.always_more_data:
            self.now += 0.01
        header = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))
        listed = sorted(self.active) if self.listed_ids is None else self.listed_ids
        reported = max(16385, len(listed)) if self.always_more_data else len(listed)
        header[0] = reported
        count = min(slots, len(listed))
        partial = self.partial_success_once and count > 0
        if partial:
            count -= 1
            self.partial_success_once = False
        header[1] = count
        address = ctypes.addressof(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)).contents) + header_size
        ids = ctypes.cast(address, ctypes.POINTER(ctypes.c_size_t))
        for index, pid in enumerate(listed[:count]):
            ids[index] = pid
        if self.always_more_data or slots < len(self.active):
            self.last_error = 234  # ERROR_MORE_DATA never certifies the truncated list.
            return 0
        return 1

    def open_process(self, access: Any, inherit: Any, pid: Any) -> int:
        value = self.number(pid)
        assert self.number(access) & 0x00100000  # SYNCHRONIZE, not PID polling alone.
        assert not inherit
        self.events.append(("open", value))
        if value in self.open_errors:
            self.last_error = self.open_errors[value]
            if self.last_error == 87:
                self.active.discard(value)
            return 0
        handle = 10000 + value
        self.opened[handle] = value
        return handle

    def terminate(self, job: Any, exit_code: Any) -> int:
        assert self.number(job) == self.job
        self.events.append(("terminate", self.number(job)))
        self.termination_requests += 1
        if self.terminate_error is not None:
            self.last_error = self.terminate_error
            return 0
        if self.spawn_once is not None:
            self.active.add(self.spawn_once)
            self.spawn_once = None
        return 1

    def wait(self, handle: Any, timeout_ms: Any) -> int:
        value = self.number(handle)
        assert value in self.opened and value not in self.closed
        assert self.termination_requests, "observed exit must follow the actual termination request"
        timeout = self.number(timeout_ms) / 1000
        assert 0 <= timeout <= 1.001, "one child cannot receive a fresh unbounded drain budget"
        self.events.append(("wait", self.opened[value]))
        if self.wait_result is not None:
            self.last_error = 5
            return self.wait_result
        self.now += min(timeout, self.delay)
        if timeout < self.delay:
            return 258  # WAIT_TIMEOUT: the process/image is not proved terminal.
        pid = self.opened[value]
        self.waited.add(pid)
        self.active.discard(pid)
        return 0

    def close(self, handle: Any) -> int:
        value = self.number(handle)
        assert value not in self.closed, "an owned OS handle was closed twice"
        self.closed.append(value)
        self.events.append(("close", value))
        return 0 if value in self.close_errors else 1

    def install(self, monkeypatch: pytest.MonkeyPatch, *, clock: bool = True) -> None:
        monkeypatch.setattr(gate, "sys", SimpleNamespace(platform="win32"))
        if clock:
            monkeypatch.setattr(gate, "time", SimpleNamespace(monotonic=lambda: self.now,
                               sleep=lambda delay: setattr(self, "now", self.now + delay)))
        monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_kw: self, raising=False)
        monkeypatch.setattr(ctypes, "get_last_error", lambda: self.last_error, raising=False)
        monkeypatch.setattr(ctypes, "set_last_error", lambda value: setattr(self, "last_error", value), raising=False)

    def assert_all_handles_closed(self) -> None:
        assert self.job in self.closed
        assert set(self.opened) <= set(self.closed)


def test_empty_job_closes_without_process_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = JobOs([])
    edge.install(monkeypatch)
    gate._win32_close_job(edge.job, terminate=False)
    assert not edge.opened and not edge.waited and edge.now == 0
    assert edge.closed == [edge.job]


@pytest.mark.parametrize("terminate", [False, True])
def test_job_close_observes_all_processes_beyond_one_win32_wait_group(
    monkeypatch: pytest.MonkeyPatch, terminate: bool
) -> None:
    edge = JobOs(list(range(1, 66)))
    edge.install(monkeypatch)
    gate._win32_close_job(edge.job, terminate=terminate)
    assert edge.waited == edge.initial, "a truncated or merely terminated process list is not a drained Job"
    assert not edge.active
    edge.assert_all_handles_closed()
    close_position = edge.events.index(("close", edge.job))
    assert all(edge.events.index(("wait", pid)) < close_position for pid in edge.initial)


def test_job_close_rechecks_children_created_during_the_first_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = JobOs([1])
    edge.spawn_once = 2
    edge.install(monkeypatch)
    gate._win32_close_job(edge.job, terminate=True)
    assert edge.waited == {1, 2}, "the initial PID snapshot does not cover a later child"
    assert not edge.active
    edge.assert_all_handles_closed()


@pytest.mark.parametrize("failure", ["query", "open", "terminate", "wait-failed", "wait-unknown"])
def test_unknown_job_state_refuses_and_closes_every_acquired_handle(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    edge = JobOs([1, 2])
    if failure == "query":
        edge.query_error = 5
    elif failure == "open":
        edge.open_errors[2] = 5
    elif failure == "terminate":
        edge.terminate_error = 5
    else:
        edge.wait_result = 0xFFFFFFFF if failure == "wait-failed" else 128
    edge.install(monkeypatch)
    with pytest.raises(RuntimeError):
        gate._win32_close_job(edge.job, terminate=True)
    edge.assert_all_handles_closed()


def test_already_gone_process_is_not_an_unknown_live_process(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = JobOs([1])
    edge.open_errors[1] = 87
    edge.install(monkeypatch)
    gate._win32_close_job(edge.job, terminate=True)
    assert not edge.active and not edge.opened
    edge.assert_all_handles_closed()


def test_job_drain_uses_one_deadline_for_all_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = JobOs([1, 2, 3, 4], delay=0.4)
    edge.install(monkeypatch)
    with pytest.raises(RuntimeError):
        gate._win32_close_job(edge.job, terminate=True)
    assert edge.now <= 1.005, "a per-child timeout multiplied the whole-job drain budget"
    assert edge.active, "the fixture must retain an unobserved process at the cutoff"
    edge.assert_all_handles_closed()


def test_persistent_incomplete_job_enumeration_never_becomes_success(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = JobOs([1])
    edge.always_more_data = True
    edge.install(monkeypatch)
    with pytest.raises(RuntimeError):
        gate._win32_close_job(edge.job, terminate=True)
    assert len(edge.query_sizes) <= 16, "an incomplete enumeration was retried without a useful bound"
    edge.assert_all_handles_closed()


def test_successful_but_partial_process_list_does_not_drop_an_owned_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge = JobOs([1, 2])
    edge.partial_success_once = True
    edge.install(monkeypatch)
    gate._win32_close_job(edge.job, terminate=False)
    assert edge.waited == {1, 2} and not edge.active
    assert len(edge.query_sizes) >= 2
    edge.assert_all_handles_closed()


@pytest.mark.parametrize("listed", [[0, 1], [1, 0x100000000], [1, 1]])
def test_invalid_or_duplicate_process_identity_never_opens_a_handle(
    monkeypatch: pytest.MonkeyPatch, listed: list[int]
) -> None:
    edge = JobOs([1, 2])
    edge.listed_ids = listed
    edge.install(monkeypatch)
    with pytest.raises(RuntimeError):
        gate._win32_close_job(edge.job, terminate=False)
    assert not edge.opened and edge.termination_requests == 0
    edge.assert_all_handles_closed()


@pytest.mark.parametrize("failed_handle", [10001, JobOs.job])
def test_handle_close_failure_still_attempts_all_owned_handles_then_refuses(
    monkeypatch: pytest.MonkeyPatch, failed_handle: int
) -> None:
    edge = JobOs([1, 2])
    edge.close_errors.add(failed_handle)
    edge.install(monkeypatch)
    with pytest.raises(RuntimeError):
        gate._win32_close_job(edge.job, terminate=True)
    # A failed CloseHandle is unknown; this checks every close was attempted, not that the OS closed it.
    assert set(edge.closed) == set(edge.opened) | {edge.job}


class ToolProcess:
    pid = 222
    _handle = 333

    def __init__(self, *, timeout: bool) -> None:
        self.timeout = timeout
        self.communications = 0
        self.returncode = 0

    def communicate(self, *, timeout: float) -> tuple[str, None]:
        self.communications += 1
        if self.timeout and self.communications == 1:
            raise subprocess.TimeoutExpired("fixture-tool", timeout)
        return "ORIGINAL_CHILD_OUTPUT", None

    def kill(self) -> None:
        self.returncode = -9


def test_timeout_with_unknown_job_cleanup_preserves_timeout_output_and_single_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edge = JobOs([])
    edge.query_error = 5
    edge.install(monkeypatch)
    process = ToolProcess(timeout=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: process)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0))
    code, output, _ = gate.run(["fixture-tool"], cwd=tmp_path, timeout_s=0.1)
    assert code is None and "ORIGINAL_CHILD_OUTPUT" in output
    assert "draining the timed-out process tree failed" in output
    assert "query failed" in output
    assert edge.closed == [edge.job], "timeout and finally must not close the same Job twice"


@pytest.mark.parametrize("query_error", [None, 5])
def test_normal_job_cleanup_unknown_is_recorded_as_receipt_refusal_with_a_positive_twin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query_error: int | None
) -> None:
    from tests.architecture.test_gate_receipt import FakeRunner
    from tests.architecture.test_remediation_c08_gate_environment import facts

    edge = JobOs([])
    edge.query_error = query_error
    edge.install(monkeypatch, clock=False)
    real_popen = subprocess.Popen

    class Win32ProcessBoundary:
        # Only the unavailable native handle is synthetic; stdout, PID, waits and clock stay real.
        _handle = 333

        def __init__(self, process: subprocess.Popen[str]) -> None:
            self.process = process

        def __getattr__(self, name: str) -> Any:
            return getattr(self.process, name)

    def popen_with_native_handle(*args: Any, **kwargs: Any) -> Win32ProcessBoundary:
        return Win32ProcessBoundary(real_popen(*args, **kwargs))

    monkeypatch.setattr(subprocess, "Popen", popen_with_native_handle)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", lambda *_a, **_kw: facts())
    real_run = gate.run
    external = FakeRunner(tmp_path, codes={})

    def runner(cmd: Any, *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        if list(cmd)[:2] == ["uv", "sync"]:
            return real_run([sys.executable, "-c", "print('ORIGINAL_CHILD_OUTPUT', flush=True)"],
                            cwd=cwd, timeout_s=timeout_s)
        return external(cmd, cwd=cwd, timeout_s=timeout_s)

    monkeypatch.setattr(gate, "run", runner)
    evidence_dir = tmp_path / "evidence"
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14", evidence_dir=evidence_dir)
    assert receipt["accepted"] is (query_error is None), receipt["reasons"]
    steps = receipt["steps"]
    assert isinstance(steps, list)
    sync_step = next(step for step in steps if isinstance(step, dict) and step.get("name") == "uv-sync")
    pid = sync_step["pid"]
    assert isinstance(pid, int) and pid > 0
    output_path = sync_step["output"]
    assert isinstance(output_path, str)
    attempt = next(evidence_dir.glob("attempt-*"))
    assert "ORIGINAL_CHILD_OUTPUT" in (attempt / output_path).read_text(encoding="utf-8"), (
        "a cleanup refusal must retain the real completed child's stdout")
    duration = sync_step["duration_s"]
    assert isinstance(duration, (int, float))
    assert duration > 0, "a cleanup refusal must retain the child's actual elapsed time"
    if query_error is not None:
        error = sync_step["error"]
        assert isinstance(error, str)
        assert "failed while running" in error and "query failed" in error
        reasons = receipt["reasons"]
        assert isinstance(reasons, list)
        assert any(isinstance(reason, str) and "uv sync failed" in reason and "query failed" in reason
                   for reason in reasons)
    assert len(external.removed) == 1 and not Path(external.removed[0]).exists()
    assert edge.closed == [edge.job]
