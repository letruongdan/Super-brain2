"""Windows ephemeral dependencies cannot share mapped outer-runner cache images.

The frozen Server 2022 DLL oracle proves the physical failure; these cheap cases
freeze the common environment policy used by initial sync and subsequent uv run.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import gate


@pytest.mark.parametrize("platform_name", ["win32", "linux", "darwin"])
@pytest.mark.parametrize("inherited", [None, "hardlink", "clone", "copy"])
def test_gate_environment_isolates_windows_and_preserves_posix_installation_policy(
    monkeypatch: pytest.MonkeyPatch, platform_name: str, inherited: str | None
) -> None:
    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform=platform_name))
    if inherited is None:
        monkeypatch.delenv("UV_LINK_MODE", raising=False)
    else:
        monkeypatch.setenv("UV_LINK_MODE", inherited)
    original = dict(os.environ)
    cleaned = gate._clean_env()
    expected = "copy" if platform_name == "win32" else inherited
    assert cleaned.get("UV_LINK_MODE") == expected
    assert ("UV_LINK_MODE" in cleaned) is (expected is not None)
    assert dict(os.environ) == original, "per-child policy must not mutate the outer runner environment"


def test_initial_sync_and_subsequent_uv_run_receive_the_windows_isolation_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tests.architecture.test_gate_receipt import FakeRunner
    from tests.architecture.test_remediation_c08_gate_environment import facts

    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setenv("UV_LINK_MODE", "hardlink")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", lambda *_a, **_kw: facts())
    real_run = gate.run
    external = FakeRunner(tmp_path, codes={})
    observed: dict[str, str | None] = {}

    def runner(cmd: Any, *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        prefix = list(cmd)[:2]
        if prefix in (["uv", "sync"], ["uv", "run"]) and prefix[1] not in observed:
            code, output, _ = real_run([sys.executable, "-c",
                "import json,os; print(json.dumps(os.environ.get('UV_LINK_MODE')))"],
                cwd=cwd, timeout_s=timeout_s)
            assert code == 0, output
            observed[prefix[1]] = json.loads(output)
        return external(cmd, cwd=cwd, timeout_s=timeout_s)

    monkeypatch.setattr(gate, "run", runner)
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    assert receipt["accepted"] is True, receipt["reasons"]
    assert observed == {"sync": "copy", "run": "copy"}, (
        "both installation entrypoints must isolate child dependencies from mapped outer-runner images")
    assert os.environ["UV_LINK_MODE"] == "hardlink"
