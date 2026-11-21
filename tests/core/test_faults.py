import os
import subprocess
import sys
import threading

import pytest

from superbrain.core.faults import KNOWN_CRASHPOINTS, KNOWN_PAUSEPOINTS, crashpoint, pausepoint

SAME = "from superbrain.core.faults import crashpoint; crashpoint('cas.after_rename'); print('alive')"


def run_python(code: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", code],
        env={**os.environ, **(env or {})},
        stdin=subprocess.DEVNULL,  # a pause reads end-of-file at once instead of blocking the test
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


DISABLE = "SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST"


def test_disabled_crashpoint_neither_pauses_nor_crashes() -> None:
    selected = {"SUPERBRAIN_CRASHPOINT": "cas.after_rename", "SUPERBRAIN_PAUSEPOINT": "cas.after_rename"}
    r = run_python(SAME, env={**selected, DISABLE: "ledger.after_commit, cas.after_rename"})
    assert r.returncode == 0 and r.stdout.strip() == "alive"
    assert "PAUSED" not in r.stderr and "CRASHPOINT_HIT" not in r.stderr


def test_disabling_other_crashpoints_changes_nothing() -> None:
    r = run_python(SAME, env={"SUPERBRAIN_CRASHPOINT": "cas.after_rename", DISABLE: "cas.after_staging_write"})
    assert r.returncode == 86 and "CRASHPOINT_HIT cas.after_rename" in r.stderr and "alive" not in r.stdout


def test_unregistered_crashpoint_is_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        crashpoint("not.registered")


def test_unregistered_pausepoint_is_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        pausepoint("not.registered")


def test_registry_contents() -> None:
    assert len(KNOWN_CRASHPOINTS) == 42
    assert "writer.mid_slot_write" in KNOWN_CRASHPOINTS and "migrating.policy.between_renames" in KNOWN_CRASHPOINTS
    for name in (
        "apply.after_policy_turn_intent",
        "apply.before_move_original",
        "apply.after_move_before_phase",
        "apply.before_publish_replacement",
        "apply.after_publish_before_phase",
        "rollback.after_policy_turn_intent",
        "rollback.before_first_move",
        "rollback.after_move_replacement",
        "rollback.after_restore_last_original",
        "apply.after_policy_grant_ended",
        "restoring.store.after_swap_before_effect_drain",
        "capture.outbox.after_write_before_fsync",
        "capture.daemon.after_commit_before_ack",
    ):
        assert name in KNOWN_CRASHPOINTS
    assert KNOWN_PAUSEPOINTS == KNOWN_CRASHPOINTS | {"writer.held"}


PAUSE = "from superbrain.core.faults import pausepoint; pausepoint('writer.held'); print('resumed')"
PAUSE_MARKER_TIMEOUT_S = 30.0


def read_pause_marker(proc: subprocess.Popen[str]) -> str:
    """Return the child's next stderr line, or "" after killing a child that never writes one."""
    assert proc.stderr is not None
    stream = proc.stderr
    line: list[str] = []
    reader = threading.Thread(target=lambda: line.append(stream.readline()), daemon=True)
    reader.start()
    reader.join(PAUSE_MARKER_TIMEOUT_S)
    if reader.is_alive():
        proc.kill()
        reader.join(10.0)
    return "".join(line)


def test_pausepoint_blocks_until_a_line_arrives_on_stdin() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", PAUSE],
        env={**os.environ, "SUPERBRAIN_PAUSEPOINT": "writer.held"},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert proc.stderr is not None and proc.stdin is not None and proc.stdout is not None
        assert read_pause_marker(proc).strip() == "PAUSED writer.held"
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
        assert read_pause_marker(proc).strip() == "PAUSED cas.after_rename"
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
