"""I2-T7-R09: the worker harness gets a response or an error within a bounded wait, through a real child process.

Each harness call runs under a test-side watchdog, so a harness that blocks fails at the watchdog assertion instead
of hanging the suite.
"""

from __future__ import annotations

import ast
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TypeVar

import pytest

from tests.support.bounded_worker import DIAGNOSTIC_TAIL_BYTES, MAX_RESPONSE_BYTES, BoundedJsonWorker, WorkerFailure
from tests.support.inc2_cli import _win32_wait_or_terminate_pid

_T = TypeVar("_T")

# Generous for a loaded host, and only ever waited in full when the harness is broken.
_WATCHDOG_S = 30.0
_SHORT_TIMEOUT_S = 0.3
_FLOOD_BYTES = 1 << 20
_NOTE = "diagnostic-note-7f3a"
_FLOOD_END = "flood-end-9c1e"

_CHILD = r"""
import json, os, sys, time

pid_path, on_eof = sys.argv[1], sys.argv[2]
FLOOD_BYTES = 1 << 20
HANG_S = 120  # A leaked probe still ends by itself.

def reply(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def note(text):
    sys.stderr.write(text + "\n")
    sys.stderr.flush()

with open(pid_path + ".tmp", "w") as fh:
    fh.write(str(os.getpid()))
os.replace(pid_path + ".tmp", pid_path)

if on_eof == "never_read":
    time.sleep(HANG_S)
    sys.exit(0)
if on_eof == "answer_early":
    sys.stdin.buffer.read(1)
    reply({"early": True})
    time.sleep(HANG_S)
    sys.exit(0)

for raw in sys.stdin:
    req = json.loads(raw)
    op = req["op"]
    if op == "echo":
        reply({"echo": req["value"]})
    elif op == "note":
        note(req["text"])
        reply({"noted": True})
    elif op == "flood_reply":
        sys.stderr.write("d" * FLOOD_BYTES + "\n" + req["end"] + "\n")
        sys.stderr.flush()
        reply({"status": "accepted"})
    elif op == "two_lines":
        reply({"line": 1})
        reply({"line": 2})
    elif op == "hang":
        time.sleep(HANG_S)
    elif op == "exit":
        note(req["text"])
        os._exit(req["code"])
    elif op == "reply_exit":
        reply({"bye": True})
        note(req["text"])
        os._exit(req["code"])
    elif op == "raw":
        sys.stdout.write(req["text"])
        sys.stdout.flush()
        if req.get("then") == "exit":
            os._exit(0)
    elif op == "oversized":
        sys.stdout.write("x" * req["size"])
        sys.stdout.flush()
        time.sleep(HANG_S)

if on_eof == "hang":
    time.sleep(HANG_S)
elif on_eof == "fail":
    note("fail-on-eof-note")
    sys.exit(3)
"""


def _bounded(call: Callable[[], _T]) -> _T:
    """Run a harness call on a watched thread; fail here if it does not return or raise within the bound."""
    outcome: list[_T] = []
    raised: list[BaseException] = []

    def _target() -> None:
        try:
            outcome.append(call())
        except BaseException as err:  # noqa: BLE001 - handed to the test thread below
            raised.append(err)

    thread = threading.Thread(target=_target, name="bounded-worker-watchdog", daemon=True)
    thread.start()
    thread.join(_WATCHDOG_S)
    assert not thread.is_alive(), f"harness call did not return or raise within {_WATCHDOG_S}s"
    if raised:
        raise raised[0]
    return outcome[0]


def _bounded_failure(call: Callable[[], object]) -> WorkerFailure:
    with pytest.raises(WorkerFailure) as exc:
        _bounded(call)
    return exc.value


def _process_gone(pid: int) -> bool:
    if sys.platform == "win32":
        return _win32_wait_or_terminate_pid(pid, terminate=False, timeout_s=5.0)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


@dataclass(frozen=True)
class _Probe:
    worker: BoundedJsonWorker
    inner_pid: int

    def assert_gone(self) -> None:
        assert self.worker.returncode is not None, "worker process still running"
        assert _process_gone(self.inner_pid), f"worker interpreter pid={self.inner_pid} still running"


_Spawn = Callable[..., _Probe]


@pytest.fixture
def spawn(tmp_path: Path) -> Iterator[_Spawn]:
    workers: list[BoundedJsonWorker] = []

    def _spawn(on_eof: str = "exit") -> _Probe:
        index = len(workers)
        pid_path = tmp_path / f"probe-{index}.pid"
        worker = BoundedJsonWorker(
            [sys.executable, "-I", "-S", "-c", _CHILD, str(pid_path), on_eof],
            cwd=tmp_path,
            stderr_path=tmp_path / f"probe-{index}.stderr.log",
            label=f"probe-{index}",
        )
        workers.append(worker)
        deadline = time.monotonic() + _WATCHDOG_S
        while True:
            try:
                return _Probe(worker, int(pid_path.read_text(encoding="ascii")))
            except OSError:  # Not written yet, or Windows denies the read during the child's rename.
                assert worker.returncode is None, f"probe child exited at startup:\n{worker.diagnostics()}"
                assert time.monotonic() < deadline, "probe child never started"
                time.sleep(0.005)

    yield _spawn
    for worker in workers:
        worker.abort()


def test_response_arrives_after_large_diagnostics(spawn: _Spawn) -> None:
    """(a) 1 MiB on stderr before the reply must not stall the worker."""
    probe = spawn()
    response = _bounded(lambda: probe.worker.request({"op": "flood_reply", "end": _FLOOD_END}))
    assert response == {"status": "accepted"}
    tail = probe.worker.diagnostics()
    assert _FLOOD_END in tail and "d" * 1024 in tail
    assert len(tail) <= DIAGNOSTIC_TAIL_BYTES < _FLOOD_BYTES
    assert _bounded(probe.worker.close) == 0
    probe.assert_gone()


def test_hung_worker_times_out_with_diagnostics_and_is_gone(spawn: _Spawn) -> None:
    """(b) A worker that never answers yields a bounded error with diagnostics, leaves no process, is not reused."""
    probe = spawn()
    assert _bounded(lambda: probe.worker.request({"op": "note", "text": _NOTE})) == {"noted": True}

    started = time.monotonic()
    failure = _bounded_failure(lambda: probe.worker.request({"op": "hang"}, timeout_s=_SHORT_TIMEOUT_S))
    elapsed = time.monotonic() - started

    assert failure.kind == "timeout"
    assert elapsed >= _SHORT_TIMEOUT_S
    assert _NOTE in failure.diagnostics and _NOTE in str(failure)
    assert failure.survivors == ()
    probe.assert_gone()
    assert _bounded_failure(lambda: probe.worker.request({"op": "echo", "value": 1})) is failure
    _bounded(probe.worker.close)  # Teardown after the reported failure must not raise a second error.


def test_worker_exiting_without_response_reports_status_and_diagnostics(spawn: _Spawn) -> None:
    """(c) Exit without an answer yields an error with the worker's own exit code and diagnostics."""
    probe = spawn()
    failure = _bounded_failure(lambda: probe.worker.request({"op": "exit", "text": _NOTE, "code": 7}))
    assert failure.kind == "exited"
    assert failure.returncode == 7
    assert _NOTE in failure.diagnostics
    probe.assert_gone()


def test_request_to_already_exited_worker_reports_status_and_diagnostics(spawn: _Spawn) -> None:
    """(c) A worker gone before the write is the same failure, not a raw pipe error."""
    probe = spawn()
    assert _bounded(lambda: probe.worker.request({"op": "reply_exit", "text": _NOTE, "code": 5})) == {"bye": True}
    deadline = time.monotonic() + _WATCHDOG_S
    while probe.worker.returncode is None:
        assert time.monotonic() < deadline, "worker did not exit"
        time.sleep(0.005)
    failure = _bounded_failure(lambda: probe.worker.request({"op": "echo", "value": 1}))
    assert failure.kind == "exited"
    assert failure.returncode == 5
    assert _NOTE in failure.diagnostics


def test_quiet_worker_answers_in_order_and_closes_cleanly(spawn: _Spawn) -> None:
    """(d) Positive twin: no diagnostics, each reply matches its request, clean close."""
    probe = spawn()
    for value in (1, 2, 3):
        assert _bounded(partial(probe.worker.request, {"op": "echo", "value": value})) == {"echo": value}
    assert probe.worker.diagnostics() == ""
    assert _bounded(probe.worker.close) == 0
    probe.assert_gone()
    assert _bounded(probe.worker.close) == 0
    assert _bounded_failure(lambda: probe.worker.request({"op": "echo", "value": 4})).kind == "protocol"


def test_worker_that_stops_reading_stdin_cannot_block_the_request(spawn: _Spawn) -> None:
    """A request larger than the pipe buffer, sent to a worker not reading, is still bounded."""
    probe = spawn("never_read")
    payload: dict[str, object] = {"op": "echo", "value": "p" * _FLOOD_BYTES}
    failure = _bounded_failure(lambda: probe.worker.request(payload, timeout_s=_SHORT_TIMEOUT_S))
    assert failure.kind == "timeout"
    probe.assert_gone()


def test_answer_before_reading_the_whole_request_fails_closed(spawn: _Spawn) -> None:
    """A reply cannot belong to a request the worker has not finished reading."""
    probe = spawn("answer_early")
    payload: dict[str, object] = {"op": "echo", "value": "p" * _FLOOD_BYTES}
    failure = _bounded_failure(lambda: probe.worker.request(payload, timeout_s=_SHORT_TIMEOUT_S))
    assert failure.kind in {"protocol", "timeout"}  # "timeout" only if the host delays the early reply past the bound.
    probe.assert_gone()


def test_unsolicited_output_is_not_taken_as_the_next_response(spawn: _Spawn) -> None:
    probe = spawn()
    assert _bounded(lambda: probe.worker.request({"op": "two_lines"})) == {"line": 1}
    deadline = time.monotonic() + _WATCHDOG_S
    while not probe.worker.has_unread_output():
        assert time.monotonic() < deadline, "second line never arrived"
        time.sleep(0.005)
    failure = _bounded_failure(lambda: probe.worker.request({"op": "echo", "value": 1}))
    assert failure.kind == "protocol"
    probe.assert_gone()


def test_close_of_worker_ignoring_eof_is_bounded_and_kills_it(spawn: _Spawn) -> None:
    probe = spawn("hang")
    assert _bounded(lambda: probe.worker.request({"op": "note", "text": _NOTE})) == {"noted": True}
    failure = _bounded_failure(lambda: probe.worker.close(timeout_s=_SHORT_TIMEOUT_S))
    assert failure.kind == "close_timeout"
    assert _NOTE in failure.diagnostics
    assert failure.survivors == ()
    probe.assert_gone()


def test_close_reports_nonzero_exit_with_diagnostics(spawn: _Spawn) -> None:
    probe = spawn("fail")
    assert _bounded(lambda: probe.worker.request({"op": "echo", "value": 1})) == {"echo": 1}
    failure = _bounded_failure(probe.worker.close)
    assert failure.kind == "exit_status"
    assert failure.returncode == 3
    assert "fail-on-eof-note" in failure.diagnostics
    probe.assert_gone()


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"op": "raw", "text": '{"a": 1', "then": "exit"}, id="truncated"),
        pytest.param({"op": "raw", "text": "not json\n"}, id="non-json"),
        pytest.param({"op": "raw", "text": "[1, 2]\n"}, id="non-object"),
        pytest.param({"op": "oversized", "size": MAX_RESPONSE_BYTES + 16}, id="oversized"),
    ],
)
def test_malformed_response_fails_closed_and_ends_worker(spawn: _Spawn, payload: dict[str, object]) -> None:
    probe = spawn()
    failure = _bounded_failure(lambda: probe.worker.request(payload))
    assert failure.kind == "protocol"
    probe.assert_gone()


def test_both_historical_workers_use_the_bounded_harness() -> None:
    """The persistent workers cannot be exercised with injected diagnostics, so pin that they use this harness."""
    source = Path(__file__).resolve().parents[1] / "storage" / "test_kernel_revocation.py"
    calls = [
        node.func for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))) if isinstance(node, ast.Call)
    ]
    names = [fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "" for fn in calls]
    assert names.count("BoundedJsonWorker") == 2
    assert names.count("Popen") == 0
