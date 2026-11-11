"""Run ``crash_child.py`` operations in a fresh interpreter, for crash, pause and lock tests.

The child is started as ``python -I -c "<runpy>" <crash_child.py> <operation> <data_root> *args``, so it imports
``superbrain`` from the installed (editable) checkout and never from ``tests``.
"""

import contextlib
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

REPO = Path(__file__).resolve().parents[2]
CHILD = Path(__file__).resolve().with_name("crash_child.py")
CRASH_EXIT = 86
CHILD_TIMEOUT = 60.0
PAUSE_DEADLINE = 30.0
PUMP_JOIN_S = CHILD_TIMEOUT
_FAULT_VARS = ("SUPERBRAIN_CRASHPOINT", "SUPERBRAIN_PAUSEPOINT")
_RUNPY = "import runpy,sys; runpy.run_path(sys.argv[1], run_name='__main__')"


@dataclass(frozen=True)
class ChildResult:
    returncode: int
    stdout: str
    stderr: str
    error_code: str | None
    hit: str | None


def child_command(operation: str, data_root: Path, args: Sequence[str]) -> list[str]:
    return [sys.executable, "-I", "-c", _RUNPY, str(CHILD), operation, str(data_root), *args]


def child_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """``os.environ`` without inherited fault-injection variables, plus ``overrides``."""
    env = {k: v for k, v in os.environ.items() if k not in _FAULT_VARS}
    env.update(overrides or {})
    return env


def _tagged(text: str, tag: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(f"{tag} "):
            return line[len(tag) + 1 :].strip()
    return None


def run_child(operation: str, data_root: Path, *args: str, env: Mapping[str, str] | None = None) -> ChildResult:
    done = subprocess.run(
        child_command(operation, data_root, args),
        env=child_env(env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    return ChildResult(
        returncode=done.returncode,
        stdout=done.stdout,
        stderr=done.stderr,
        error_code=_tagged(done.stdout, "ERROR"),
        hit=_tagged(done.stderr, "CRASHPOINT_HIT"),
    )


def run_until_crash(operation: str, crashpoint: str, data_root: Path, *args: str) -> ChildResult:
    result = run_child(operation, data_root, *args, env={"SUPERBRAIN_CRASHPOINT": crashpoint})
    assert result.returncode == CRASH_EXIT and result.hit == crashpoint, (
        f"{operation!r} did not crash at {crashpoint!r}: returncode={result.returncode}, hit={result.hit!r}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result


def _pump(stream: IO[str], lines: "queue.Queue[str | None]") -> None:
    for line in stream:
        lines.put(line)
    lines.put(None)


def wait_for_pause(lines: "queue.Queue[str | None]", pausepoint: str, deadline: float) -> None:
    """Consume ``lines`` until ``PAUSED <pausepoint>``; fail on end of stream or after ``deadline`` seconds."""
    seen: list[str] = []
    end = time.monotonic() + deadline
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            stderr = "".join(seen)
            raise AssertionError(f"child did not reach pausepoint {pausepoint!r} in {deadline}s; stderr:\n{stderr}")
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty:
            continue
        if line is None:
            raise AssertionError(f"child exited before pausepoint {pausepoint!r}; stderr:\n{''.join(seen)}")
        seen.append(line)
        if line.strip() == f"PAUSED {pausepoint}":
            return


def _finish(proc: "subprocess.Popen[str]") -> None:
    """Resume a paused child (or reap a killed one) and wait for it to exit."""
    assert proc.stdin is not None
    if proc.poll() is None:
        # The child may die between poll() and the write; its pipe is then broken, which is fine.
        with contextlib.suppress(BrokenPipeError, OSError):
            proc.stdin.write("\n")
            proc.stdin.flush()
    with contextlib.suppress(BrokenPipeError, OSError):
        proc.stdin.close()
    try:
        proc.wait(timeout=CHILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=CHILD_TIMEOUT)
        raise AssertionError(f"paused child did not exit within {CHILD_TIMEOUT}s after resume") from None


@contextlib.contextmanager
def paused_child(
    operation: str, pausepoint: str, data_root: Path, *args: str, deadline: float = PAUSE_DEADLINE
) -> Iterator["subprocess.Popen[str]"]:
    """Start ``operation`` with ``SUPERBRAIN_PAUSEPOINT=pausepoint``, yield it once paused, then resume it."""
    proc = subprocess.Popen(
        child_command(operation, data_root, args),
        env=child_env({"SUPERBRAIN_PAUSEPOINT": pausepoint}),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    assert proc.stdout is not None and proc.stderr is not None
    stderr_lines: queue.Queue[str | None] = queue.Queue()
    pumps = [
        threading.Thread(target=_pump, args=(proc.stderr, stderr_lines), daemon=True),
        # Drained only so a chatty child can never block on a full stdout pipe.
        threading.Thread(target=_pump, args=(proc.stdout, queue.Queue()), daemon=True),
    ]
    for pump in pumps:
        pump.start()
    try:
        try:
            wait_for_pause(stderr_lines, pausepoint, deadline)
        except AssertionError:
            proc.kill()
            raise
        yield proc
    finally:
        _finish(proc)
        for pump, stream in zip(pumps, (proc.stderr, proc.stdout), strict=True):
            pump.join(timeout=PUMP_JOIN_S)
            if not pump.is_alive():  # Closing a stream a thread is still reading would block on its lock.
                stream.close()
