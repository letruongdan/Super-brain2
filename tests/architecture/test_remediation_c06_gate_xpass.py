"""SP1-C06: the gate must not count a non-strict unexpected pass (XPASS) as an ordinary pass.

Requirement (spec 17.2: the receipt binds "kết quả cuối" for every test, and "Không xóa, skip hay giảm assertion";
review SP1-C06; ledger C06): the gate's outcome policy accepts only ``NON_FAILING = {passed, skipped, xfailed}``.
An XPASS is outside that set, so a run containing one must be NOT accepted, with a reason naming the test (whether
the gate records it as ``xpassed`` or makes it a strict failure). Ruling (ledger, 2026-10-31): the fix lives in
``scripts/gate.py``; ``pyproject.toml`` keeps no ``xfail_strict`` (the runner configuration stays sealed).

The test drives the real ``run_gate`` orchestration. Only the external tools are replaced at ``gate.run``: git, uv,
ruff, mypy and lint-imports answer green, while every ``pytest`` command the gate issues (with exactly the arguments
the gate chose) is executed for real against a probe project that uses this repository's own ``pyproject.toml``.
So the JUnit report and terminal output the gate judges are real pytest output.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from scripts import gate

REPO = Path(__file__).resolve().parents[2]
PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"
PROBE = "tests/test_probe.py"

XPASS_PROJECT = """
import pytest


def test_plain() -> None:
    pass


@pytest.mark.xfail(reason="requirement-derived gate probe", strict=False)
def test_unexpectedly_passes() -> None:
    pass
"""

CONTROL_PROJECT = """
import pytest


def test_plain() -> None:
    pass


@pytest.mark.xfail(reason="known failure", strict=False)
def test_expected_failure() -> None:
    assert False
"""


class RealPytestRunner:
    """Stands in for ``gate.run``: fakes git/uv/static tools, runs every pytest command for real in the worktree."""

    def __init__(self, probe_source: str) -> None:
        self.probe_source = probe_source
        self.worktree: Path | None = None
        self.pytest_calls: list[list[str]] = []

    def _create_worktree(self, path: Path) -> None:
        self.worktree = path
        (path / "src" / "superbrain").mkdir(parents=True)
        (path / "tests").mkdir()
        (path / PROBE).write_text(textwrap.dedent(self.probe_source), encoding="utf-8")
        shutil.copyfile(REPO / "pyproject.toml", path / "pyproject.toml")  # the real, sealed runner configuration
        (path / "uv.lock").write_text("lock", encoding="utf-8")

    def _git(self, sub: list[str]) -> tuple[int | None, str, float]:
        if sub[:2] == ["worktree", "add"]:
            self._create_worktree(Path(sub[3]))
        elif sub[:2] == ["worktree", "remove"]:
            shutil.rmtree(sub[3])
        elif sub[:1] == ["rev-parse"]:
            return 0, "a" * 40 + "\n", 0.0
        return 0, "", 0.0  # status --porcelain (clean), ls-files -s

    def _pytest(self, args: list[str]) -> tuple[int | None, str, float]:
        assert self.worktree is not None
        self.pytest_calls.append(args)
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
        env["PYTHONPATH"] = str(REPO)  # so a gate-side pytest plugin under scripts/ stays importable
        began = time.monotonic()
        done = subprocess.run(
            [sys.executable, "-m", "pytest", *args],
            cwd=self.worktree,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        return done.returncode, done.stdout + done.stderr, time.monotonic() - began

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        if argv[0] == "git":
            return self._git(argv[3:])
        if argv[:2] == ["uv", "sync"]:
            return 0, "", 0.0
        tool = argv[argv.index("--python") + 2 :] if argv[:2] == ["uv", "run"] else argv
        if tool[:1] == ["pytest"]:
            return self._pytest(tool[1:])
        if gate.PREFLIGHT_CODE in tool:
            assert self.worktree is not None
            info = {
                "executable": sys.executable,
                "version": sys.version,
                "implementation": sys.implementation.name,
                "package_file": str(self.worktree / "src" / "superbrain" / "__init__.py"),
            }
            return 0, json.dumps(info) + "\n", 0.0
        return 0, "", 0.0  # ruff, mypy, lint-imports: green


def run_gate_on(probe_source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    runner = RealPytestRunner(probe_source)
    monkeypatch.setattr(gate, "run", runner)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    receipt, _ = gate.run_gate(tmp_path / "repo", PYTHON)
    assert any("--collect-only" not in call for call in runner.pytest_calls), "the gate ran no pytest phase"
    return dict(receipt)


def reasons_naming(receipt: dict[str, Any], test_id: str) -> list[str]:
    return [str(r) for r in receipt["reasons"] if test_id in str(r)]


def test_a_run_with_a_non_strict_xpass_is_not_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = run_gate_on(XPASS_PROJECT, tmp_path, monkeypatch)
    counts = receipt["counts"]
    xpass_id = f"{PROBE}::test_unexpectedly_passes"

    assert counts["passed"] == 1, f"the unexpected pass was counted as an ordinary pass: {counts}"
    assert counts["xpassed"] + counts["failed"] == 1, counts
    assert receipt["accepted"] is False
    assert reasons_naming(receipt, xpass_id), f"no reason names {xpass_id}: {receipt['reasons']}"
    assert receipt["test_count"] == 2


def test_passes_and_expected_failures_are_still_classified_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = run_gate_on(CONTROL_PROJECT, tmp_path, monkeypatch)
    counts = receipt["counts"]

    assert counts["passed"] == 1 and counts["xfailed"] == 1, counts
    assert counts["failed"] == 0 and counts["error"] == 0 and counts["xpassed"] == 0, counts
    assert not reasons_naming(receipt, PROBE), receipt["reasons"]
    pytest_phase = next(p for p in receipt["phases"] if p["name"] == "pytest")
    assert pytest_phase["exit_code"] == 0
