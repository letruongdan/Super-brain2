"""C08: valid Windows syntax on an unavailable drive must promptly refuse, never loop.

Requirement: real physical path admission (spec 4.3/5.9 and C08 parity), plus
typed runtime refusal. A missing drive has no existing directory ancestor; both
real preflight and runtime must terminate. Only child processes call the boundary;
the child records successful imports and ENTERED before a bounded observation.
"""

import ctypes
import json
import os
import string
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

import superbrain
from tests.support.platform import windows_only

CHILD = r'''
import json, os, sys
from datetime import UTC, datetime
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.environment import OsEnvironmentProbe, DATA_ROOT_ROLE, collect, assess
from superbrain.core.errors import BrainError
from superbrain.storage.runtime import open_runtime
import superbrain
print("IMPORTED " + str(superbrain.__file__), flush=True)
boundary, path = sys.argv[2], Path(sys.argv[3])
entered = {"pid": os.getpid(), "entered_at": datetime.now(UTC).isoformat(),
           "boundary": boundary, "configured": str(path)}
print("ENTERED " + json.dumps(entered), flush=True)
try:
    if boundary == "admission":
        facts = OsEnvironmentProbe().check_root(path, DATA_ROOT_ROLE)
        result = {"kind": "admission", "exists": facts.exists, "problems": list(facts.problems)}
    elif boundary == "preflight":
        facts = collect(OsEnvironmentProbe(), {DATA_ROOT_ROLE: path}, sys.platform)
        result = {"kind": "preflight", "receipt": assess(facts, required=[DATA_ROOT_ROLE])}
    else:
        runtime = open_runtime(path, os_adapters())
        runtime.close()
        result = {"kind": "accepted"}
except BrainError as error:
    result = {"kind": "refused", "code": error.code.value}
print("RESULT " + json.dumps(result), flush=True)
'''


@windows_only
@pytest.mark.parametrize("boundary", ["admission", "preflight", "runtime"])
def test_an_unavailable_drive_is_promptly_refused(tmp_path: Path, boundary: str) -> None:
    if sys.platform != "win32":
        raise AssertionError("native Windows-only probe")
    drives = ctypes.windll.kernel32.GetLogicalDrives()
    drive = next(letter for i, letter in reversed(list(enumerate(string.ascii_uppercase))) if not drives & (1 << i))
    configured = Path(drive + ":/superbrain-unavailable-drive/root")
    assert not os.path.lexists(configured.anchor), "the chosen drive became available"
    assert superbrain.__file__ is not None
    source = Path(superbrain.__file__).parent.parent
    command = [sys.executable, "-I", "-u", "-c", CHILD, str(source), boundary, str(configured)]
    receipt_path = tmp_path / f"unavailable-drive-{boundary}.json"
    started = datetime.now(UTC).isoformat()
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timed_out = False
    try:
        stdout, stderr = child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()  # only this explicitly owned fault-probe child; wait retains its terminal exit
        stdout, stderr = child.communicate(timeout=5)
    entered = [json.loads(line.removeprefix("ENTERED ")) for line in stdout.splitlines() if line.startswith("ENTERED ")]
    worker_pid = entered[0]["pid"] if entered else None
    worker_terminal = True
    if timed_out and worker_pid is not None:
        # uv/venv may redirect to a different worker PID. Reap that owned probe too
        # if launcher termination did not already terminate its child job.
        from ctypes import wintypes

        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.restype = wintypes.HANDLE
        handle = kernel.OpenProcess(0x100001, False, worker_pid)  # SYNCHRONIZE | PROCESS_TERMINATE
        if handle:
            try:
                if kernel.WaitForSingleObject(wintypes.HANDLE(handle), 0) == 258:
                    kernel.TerminateProcess(wintypes.HANDLE(handle), 1)
                worker_terminal = kernel.WaitForSingleObject(wintypes.HANDLE(handle), 5000) == 0
            finally:
                kernel.CloseHandle(wintypes.HANDLE(handle))
        else:
            worker_terminal = kernel.GetLastError() == 87  # nonexistent PID, not access denied
    receipt = {"command": command, "launcher_pid": child.pid, "started_at": started, "boundary": boundary,
               "configured": str(configured), "timed_out": timed_out, "exit": child.returncode,
               "worker_pid": worker_pid, "worker_terminal": worker_terminal, "stdout": stdout, "stderr": stderr}
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    assert "IMPORTED " in stdout and "ENTERED " in stdout, f"probe setup did not reach boundary: {receipt}"
    assert worker_terminal, f"owned probe worker did not terminate: {receipt}"
    assert not timed_out, f"{boundary} hung after successful imports and ENTERED: {receipt}; receipt={receipt_path}"
    assert child.returncode == 0, receipt
    results = [json.loads(line.removeprefix("RESULT ")) for line in stdout.splitlines() if line.startswith("RESULT ")]
    assert len(results) == 1, receipt
    result = results[0]
    if boundary == "admission":
        assert result["kind"] == "admission" and result["problems"], receipt
        assert result["exists"] is False, receipt
    elif boundary == "preflight":
        assert result["kind"] == "preflight" and result["receipt"]["accepted"] is False, receipt
    else:
        assert result["kind"] == "refused", receipt
    assert not os.path.lexists(configured.anchor), "the probe created or mounted a drive"
