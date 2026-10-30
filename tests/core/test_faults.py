import os
import subprocess
import sys

import pytest

from superbrain.core.faults import KNOWN_CRASHPOINTS, KNOWN_PAUSEPOINTS, crashpoint, pausepoint

SAME = "from superbrain.core.faults import crashpoint; crashpoint('cas.after_rename'); print('alive')"


def run_python(code: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", code],
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_crashpoint_reports_hit_and_exits_86() -> None:
    r = run_python(SAME, env={"SUPERBRAIN_CRASHPOINT": "cas.after_rename"})
    assert r.returncode == 86 and "CRASHPOINT_HIT cas.after_rename" in r.stderr and "alive" not in r.stdout


def test_crashpoint_is_inert_for_other_names() -> None:
    r = run_python(SAME, env={"SUPERBRAIN_CRASHPOINT": "ledger.after_commit"})
    assert r.returncode == 0 and r.stdout.strip() == "alive"


def test_unregistered_crashpoint_is_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        crashpoint("not.registered")


def test_unregistered_pausepoint_is_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        pausepoint("not.registered")


def test_registry_contents() -> None:
    assert len(KNOWN_CRASHPOINTS) == 19
    assert "writer.mid_slot_write" in KNOWN_CRASHPOINTS and "migrating.policy.between_renames" in KNOWN_CRASHPOINTS
    assert KNOWN_PAUSEPOINTS == KNOWN_CRASHPOINTS | {"writer.held"}


PAUSE = "from superbrain.core.faults import pausepoint; pausepoint('writer.held'); print('resumed')"


def test_pausepoint_blocks_until_a_line_arrives_on_stdin() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", PAUSE],
        env={**os.environ, "SUPERBRAIN_PAUSEPOINT": "writer.held"},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert proc.stderr is not None and proc.stdin is not None and proc.stdout is not None
        assert proc.stderr.readline().strip() == "PAUSED writer.held"
        assert proc.poll() is None
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert proc.wait(timeout=60) == 0
        assert proc.stdout.read().strip() == "resumed"
    finally:
        if proc.poll() is None:
            proc.kill()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def test_pausepoint_is_inert_without_matching_env() -> None:
    r = run_python(PAUSE, env={"SUPERBRAIN_PAUSEPOINT": "cas.after_rename"})
    assert r.returncode == 0 and r.stdout.strip() == "resumed" and "PAUSED" not in r.stderr


def test_every_crashpoint_is_also_a_pausepoint() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", SAME],
        env={**os.environ, "SUPERBRAIN_PAUSEPOINT": "cas.after_rename"},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert proc.stderr is not None and proc.stdin is not None and proc.stdout is not None
        assert proc.stderr.readline().strip() == "PAUSED cas.after_rename"
        assert proc.poll() is None
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert proc.wait(timeout=60) == 0  # resumed, and the crashpoint itself stayed inert
        assert proc.stdout.read().strip() == "alive" and "CRASHPOINT_HIT" not in proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
