"""Bounded request/response harness for long-lived JSON-line worker processes.

Invariant: the harness obtains a response or an error from the worker within a bounded wait, whatever the
worker writes to its diagnostics stream.

- ``stderr`` goes to a per-worker file, so a chatty worker can never block on a full pipe.
- ``stdout`` is read by a dedicated thread and every request waits on it with a deadline.
- ``stdin`` is written on a separate thread under the same deadline, so a worker that stops reading cannot block
  the caller on a full pipe either.
- Timeout, unexpected exit and malformed output all end the worker and raise ``WorkerFailure`` carrying the exit
  status and the tail of the worker's diagnostics. A failed worker is never reused, so a late reply cannot be
  matched to a later request.

On Windows ``.venv\\Scripts\\python.exe`` is a launcher whose child interpreter is the real worker, so terminating
the ``Popen`` handle alone would leak it. Termination walks the process tree and verifies each exit.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import IO

from tests.support.inc2_cli import _win32_descendant_pids, _win32_wait_or_terminate_pid

# A real request finishes in seconds; the ceiling only has to stop a hang without flaking on a loaded Windows host.
DEFAULT_RESPONSE_TIMEOUT_S = 120.0
DEFAULT_CLOSE_TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 1 << 20
DIAGNOSTIC_TAIL_BYTES = 64 * 1024
_TERMINATE_TIMEOUT_S = 10.0
_EOF_EXIT_GRACE_S = 5.0


class WorkerFailure(AssertionError):
    """A worker timed out, exited, or broke the one-JSON-object-per-line protocol."""

    def __init__(
        self,
        *,
        label: str,
        kind: str,
        detail: str,
        returncode: int | None,
        diagnostics: str,
        survivors: tuple[int, ...],
    ) -> None:
        super().__init__(
            f"{label} {kind}: {detail} (rc={returncode}, surviving_pids={list(survivors)})\n"
            f"--- diagnostics tail ---\n{diagnostics}"
        )
        self.kind = kind
        self.returncode = returncode
        self.diagnostics = diagnostics
        self.survivors = survivors


def _terminate_tree(proc: subprocess.Popen[bytes], timeout_s: float) -> tuple[int, ...]:
    """Terminate ``proc`` and its descendants, deepest first; return the PIDs that could not be confirmed gone."""
    survivors: list[int] = []
    if sys.platform == "win32":
        # Popen keeps the launcher's process handle open, so its PID cannot have been reused for this walk.
        for pid in reversed(_win32_descendant_pids(proc.pid)):
            if not _win32_wait_or_terminate_pid(pid, terminate=True, timeout_s=timeout_s):
                survivors.append(pid)
    with contextlib.suppress(OSError):
        proc.kill()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        survivors.append(proc.pid)
    return tuple(survivors)


class BoundedJsonWorker:
    """One long-lived child answering one JSON object per line on ``stdout`` for each line on ``stdin``."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        stderr_path: Path,
        label: str,
        response_timeout_s: float = DEFAULT_RESPONSE_TIMEOUT_S,
        close_timeout_s: float = DEFAULT_CLOSE_TIMEOUT_S,
    ) -> None:
        self._label = label
        self._stderr_path = stderr_path
        self._response_timeout_s = response_timeout_s
        self._close_timeout_s = close_timeout_s
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self._writer: threading.Thread | None = None
        self._failure: WorkerFailure | None = None
        self._closed = False
        with stderr_path.open("wb") as sink:
            self._proc = subprocess.Popen(
                list(argv),
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sink,
            )
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._stdin: IO[bytes] = self._proc.stdin
        self._stdout: IO[bytes] = self._proc.stdout
        self._reader = threading.Thread(target=self._pump_stdout, name=f"{label}-stdout", daemon=True)
        try:
            self._reader.start()
        except BaseException:
            _terminate_tree(self._proc, _TERMINATE_TIMEOUT_S)
            raise

    @property
    def returncode(self) -> int | None:
        return self._proc.poll()

    def diagnostics(self) -> str:
        """Return the last ``DIAGNOSTIC_TAIL_BYTES`` the worker wrote to its diagnostics stream."""
        try:
            with self._stderr_path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - DIAGNOSTIC_TAIL_BYTES))
                return fh.read(DIAGNOSTIC_TAIL_BYTES).decode("utf-8", errors="replace")
        except OSError as err:
            return f"<diagnostics unavailable: {type(err).__name__}>"

    def request(self, payload: dict[str, object], *, timeout_s: float | None = None) -> dict[str, object]:
        """Send ``payload`` and return the worker's reply, or raise ``WorkerFailure`` within the bound."""
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise self._fail("protocol", "request after close")
        bound = self._response_timeout_s if timeout_s is None else timeout_s
        deadline = time.monotonic() + bound
        request_label = f"request mode={payload.get('mode', payload.get('op'))!r}"
        try:
            if not self._lines.empty():
                stale = self._lines.get_nowait()
                if stale is None:
                    raise self._fail("exited", f"exited before {request_label}", grace_s=_EOF_EXIT_GRACE_S)
                raise self._fail("protocol", f"unsolicited output before {request_label}")
            data = json.dumps(payload).encode("utf-8") + b"\n"
            writer = threading.Thread(target=self._write, args=(data,), name=f"{self._label}-stdin", daemon=True)
            self._writer = writer
            writer.start()
            try:
                line = self._lines.get(timeout=bound)
            except queue.Empty:
                raise self._fail("timeout", f"no response to {request_label} within {bound}s") from None
            if line is None:
                raise self._fail("exited", f"exited without answering {request_label}", grace_s=_EOF_EXIT_GRACE_S)
            if not line.endswith(b"\n"):
                raise self._fail("protocol", f"truncated or oversized response to {request_label}")
            try:
                parsed = json.loads(line)
            except ValueError:
                raise self._fail("protocol", f"non-JSON response to {request_label}") from None
            if not isinstance(parsed, dict):
                raise self._fail("protocol", f"non-object response to {request_label}")
            writer.join(max(0.0, deadline - time.monotonic()))
            if writer.is_alive():
                raise self._fail("protocol", f"answered before reading all of {request_label}")
            return parsed
        except WorkerFailure:
            raise
        except BaseException:
            self.abort()
            raise

    def close(self, *, timeout_s: float | None = None) -> int | None:
        """Close ``stdin`` and wait for a clean exit; raise ``WorkerFailure`` on timeout or a non-zero status.

        Idempotent. After a failure the worker is already gone and the error already raised, so this returns.
        """
        if self._closed or self._failure is not None:
            self._closed = True
            return self._proc.returncode
        self._closed = True
        bound = self._close_timeout_s if timeout_s is None else timeout_s
        try:
            with contextlib.suppress(OSError, ValueError):
                self._stdin.close()
            try:
                rc = self._proc.wait(timeout=bound)
            except subprocess.TimeoutExpired:
                raise self._fail("close_timeout", f"did not exit within {bound}s of stdin close") from None
            if rc != 0:
                raise self._fail("exit_status", f"exited with {rc}")
            survivors = self._reap()
            if survivors:
                raise self._fail("exit_status", "left descendants running after a clean exit")
            return rc
        except WorkerFailure:
            raise
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        """End the worker without raising; idempotent teardown for failure paths."""
        self._closed = True
        self._reap()

    def _pump_stdout(self) -> None:
        try:
            while True:
                line = self._stdout.readline(MAX_RESPONSE_BYTES + 1)
                if not line:
                    return
                self._lines.put(line)
                if not line.endswith(b"\n"):
                    return  # Oversized or truncated: the caller fails the worker, so stop buffering.
        except (OSError, ValueError):
            return
        finally:
            self._lines.put(None)

    def _write(self, data: bytes) -> None:
        with contextlib.suppress(OSError, ValueError):
            self._stdin.write(data)
            self._stdin.flush()

    def _reap(self) -> tuple[int, ...]:
        """Terminate the tree and release the pipes without closing a stream another thread may be blocked on."""
        survivors = _terminate_tree(self._proc, _TERMINATE_TIMEOUT_S)
        self._reader.join(_TERMINATE_TIMEOUT_S)
        writer = self._writer
        if writer is not None:
            writer.join(_TERMINATE_TIMEOUT_S)
        if writer is None or not writer.is_alive():
            with contextlib.suppress(OSError, ValueError):
                self._stdin.close()
        if not self._reader.is_alive():
            with contextlib.suppress(OSError, ValueError):
                self._stdout.close()
        return survivors

    def _fail(self, kind: str, detail: str, *, grace_s: float = 0.0) -> WorkerFailure:
        """End the worker, collect its status and diagnostics, and remember the failure."""
        with contextlib.suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=grace_s)  # An exiting worker keeps its real status instead of a kill status.
        survivors = self._reap()
        self._failure = WorkerFailure(
            label=self._label,
            kind=kind,
            detail=detail,
            returncode=self._proc.returncode,
            diagnostics=self.diagnostics(),
            survivors=survivors,
        )
        return self._failure
