"""The gate receipt accepts only a complete, source-bound, fully-accounted run."""

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from scripts.gate import (
    REQUIRED_PHASES,
    InterpreterInfo,
    PhaseResult,
    SourceIdentity,
    build_receipt,
    parse_collected,
    parse_junit,
)
from superbrain.core.canonical import canonical_json, digest_bytes

CLEAN = SourceIdentity("c" * 40, True, "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64)
WORKTREE = str(Path(tempfile.gettempdir()) / "superbrain-gate-fixture")
GOOD_INTERPRETER = InterpreterInfo(
    executable=str(Path(WORKTREE) / ".venv" / "python"),
    version="3.14.3 (main, Feb  3 2026)",
    implementation="cpython",
    package_file=str(Path(WORKTREE) / "src" / "superbrain" / "__init__.py"),
)
PHASES = tuple(PhaseResult(name, 0, 1.0) for name in REQUIRED_PHASES)


def ok(**overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "start": CLEAN,
        "end": CLEAN,
        "phases": PHASES,
        "collected_ids": ["a", "b"],
        "junit_ids": ["a", "b"],
        "junit_outcomes": {"a": "passed", "b": "passed"},
        "python": "3.14.3",
        "implementation": "cpython",
        "platform": "win32",
        "interpreter": GOOD_INTERPRETER,
        "worktree": WORKTREE,
        "requested_python": "3.14",
    }
    args.update(overrides)
    return args


def accepted(**overrides: Any) -> bool:
    return bool(build_receipt(**ok(**overrides))["accepted"])


def with_pytest(**changes: Any) -> tuple[PhaseResult, ...]:
    return tuple(replace(p, **changes) if p.name == "pytest" else p for p in PHASES)


def test_clean_complete_run_is_accepted() -> None:
    receipt = build_receipt(**ok())
    assert receipt["accepted"] is True
    assert receipt["reasons"] == []


def test_dirty_tree_is_not_accepted() -> None:
    dirty = replace(CLEAN, tree_clean=False)
    assert not accepted(start=dirty, end=dirty)


def test_source_change_during_run_is_not_accepted() -> None:
    assert not accepted(end=replace(CLEAN, tracked_digest="sha256:" + "9" * 64))
    assert not accepted(end=replace(CLEAN, commit="d" * 40))
    assert not accepted(end=replace(CLEAN, lock_digest="sha256:" + "9" * 64))
    assert not accepted(end=replace(CLEAN, config_digest="sha256:" + "9" * 64))


def test_missing_phase_is_not_accepted() -> None:
    assert not accepted(phases=tuple(p for p in PHASES if p.name != "mypy"))


def test_duplicate_phase_is_not_accepted() -> None:
    assert not accepted(phases=(*PHASES, PhaseResult("ruff", 0, 1.0)))


def test_unknown_phase_is_not_accepted() -> None:
    assert not accepted(phases=(*PHASES, PhaseResult("extra", 0, 1.0)))


def test_failed_phase_is_not_accepted() -> None:
    assert not accepted(phases=tuple(replace(p, exit_code=1) if p.name == "ruff" else p for p in PHASES))


def test_timeout_is_not_accepted() -> None:
    assert not accepted(phases=with_pytest(exit_code=None))


def test_over_budget_is_not_accepted() -> None:
    assert accepted(phases=with_pytest(duration_s=300.0))
    assert not accepted(phases=with_pytest(duration_s=301))


def test_junit_not_matching_inventory_is_not_accepted() -> None:
    assert not accepted(junit_ids=["a"])


def test_duplicate_test_ids_are_not_accepted() -> None:
    assert not accepted(collected_ids=["a", "a"], junit_ids=["a", "a"], junit_outcomes={"a": "passed"})


def test_failure_is_not_accepted() -> None:
    assert not accepted(junit_outcomes={"a": "failed", "b": "passed"})
    assert not accepted(junit_outcomes={"a": "error", "b": "passed"})
    assert not accepted(junit_outcomes={"a": "xpassed", "b": "passed"})


def test_missing_outcome_is_not_accepted() -> None:
    assert not accepted(junit_outcomes={"a": "passed"})


def test_empty_outcomes_are_not_accepted() -> None:
    assert not accepted(collected_ids=["a"], junit_ids=["a"], junit_outcomes={})


def test_extra_outcome_id_is_not_accepted() -> None:
    assert not accepted(collected_ids=["a"], junit_ids=["a"], junit_outcomes={"a": "passed", "z": "passed"})


def test_unknown_outcome_value_is_not_accepted() -> None:
    assert not accepted(junit_outcomes={"a": "maybe", "b": "passed"})


def test_empty_inventory_is_not_accepted() -> None:
    assert not accepted(collected_ids=[], junit_ids=[], junit_outcomes={})


def test_every_refusal_carries_a_reason() -> None:
    receipt = build_receipt(**ok(junit_outcomes={"a": "failed", "b": "passed"}))
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and reasons and all(isinstance(r, str) and r for r in reasons)


def test_skips_are_reported() -> None:
    receipt = build_receipt(**ok(junit_outcomes={"a": "passed", "b": "skipped"}))
    assert receipt["accepted"] is True
    counts = receipt["counts"]
    assert isinstance(counts, dict) and counts["skipped"] == 1 and counts["passed"] == 1


def test_inventory_digest_is_order_independent() -> None:
    one = build_receipt(**ok(collected_ids=["a", "b"], junit_ids=["b", "a"]))
    two = build_receipt(**ok(collected_ids=["b", "a"], junit_ids=["a", "b"]))
    assert one["test_inventory_digest"] == two["test_inventory_digest"]
    assert one["test_inventory_digest"] == digest_bytes(canonical_json(["a", "b"]))


def test_receipt_binds_source_phases_and_platform() -> None:
    receipt = build_receipt(**ok())
    assert receipt["start"] == receipt["end"]
    assert receipt["python"] == "3.14.3" and receipt["implementation"] == "cpython" and receipt["platform"] == "win32"
    phases = receipt["phases"]
    assert isinstance(phases, list) and [p["name"] for p in phases if isinstance(p, dict)] == list(REQUIRED_PHASES)


def interpreter(tmp_path: Path, **changes: str) -> InterpreterInfo:
    base = InterpreterInfo(
        executable=str(tmp_path / ".venv" / "python"),
        version="3.14.3 (main, Feb  3 2026)",
        implementation="cpython",
        package_file=str(tmp_path / "src" / "superbrain" / "__init__.py"),
    )
    return replace(base, **changes)


def test_interpreter_in_worktree_with_matching_version_is_accepted(tmp_path: Path) -> None:
    assert accepted(interpreter=interpreter(tmp_path), worktree=str(tmp_path), requested_python="3.14")


def test_package_outside_worktree_src_is_not_accepted(tmp_path: Path) -> None:
    other = str(tmp_path.parent / "other" / "src" / "superbrain" / "__init__.py")
    info = interpreter(tmp_path, package_file=other)
    assert not accepted(interpreter=info, worktree=str(tmp_path), requested_python="3.14")
    sibling = str(tmp_path / "srcx" / "superbrain" / "__init__.py")
    info = interpreter(tmp_path, package_file=sibling)
    assert not accepted(interpreter=info, worktree=str(tmp_path), requested_python="3.14")


def test_interpreter_version_mismatch_is_not_accepted(tmp_path: Path) -> None:
    assert not accepted(interpreter=interpreter(tmp_path), worktree=str(tmp_path), requested_python="3.11")
    # "3.1" must not match "3.14"
    assert not accepted(interpreter=interpreter(tmp_path), worktree=str(tmp_path), requested_python="3.1")


def test_missing_interpreter_when_required_is_not_accepted(tmp_path: Path) -> None:
    assert not accepted(interpreter=None, worktree=str(tmp_path), requested_python="3.14")


def test_cleanup_failure_is_not_accepted() -> None:
    receipt = build_receipt(**ok(cleanup_error="could not remove worktree"))
    assert receipt["accepted"] is False
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and any("could not remove worktree" in str(r) for r in reasons)


def test_extra_reasons_make_the_receipt_not_accepted() -> None:
    assert not accepted(extra_reasons=("uv sync failed",))


# --- JUnit parsing against a real pytest-produced file -------------------------------------------------


def write_junit(tmp_path: Path, cases: list[tuple[str, str]]) -> Path:
    body = []
    for name, kind in cases:
        child = "" if kind == "passed" else f"<{kind} message='m'/>"
        body.append(f'<testcase classname="t" name="{name}">{child}</testcase>')
    path = tmp_path / "junit.xml"
    path.write_text(f'<testsuites><testsuite name="x">{"".join(body)}</testsuite></testsuites>', encoding="utf-8")
    return path


def test_parse_junit_rejects_duplicate_testcase(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        parse_junit(write_junit(tmp_path, [("a", "passed"), ("a", "failure")]))


SAMPLE_PROJECT = """
import pytest


@pytest.mark.parametrize("value", ["a.b", "x/y", "p::q", 3])
def test_param(value):
    pass


def test_plain():
    pass


class TestGroup:
    def test_method(self):
        pass

    class TestNested:
        def test_deep(self):
            pass


@pytest.mark.skip(reason="no")
def test_skipped():
    pass


@pytest.mark.xfail(reason="known")
def test_xfail():
    assert False


@pytest.mark.xfail(reason="odd")
def test_xpass():
    pass


def test_fails():
    assert False


def test_errors(missing_fixture):
    pass
"""


def test_parse_junit_maps_real_pytest_output_to_collected_node_ids(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / "pkg").mkdir(parents=True)
    (project / "pkg" / "test_sample.py").write_text(textwrap.dedent(SAMPLE_PROJECT), encoding="utf-8")
    junit = tmp_path / "junit.xml"
    base = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--rootdir", str(project)]
    collected = subprocess.run(
        [*base, "--collect-only", "-q"], cwd=project, capture_output=True, text=True, check=False, timeout=120
    )
    ids = parse_collected(collected.stdout)
    subprocess.run([*base, f"--junitxml={junit}"], cwd=project, capture_output=True, check=False, timeout=120)
    junit_ids, outcomes = parse_junit(junit, root=project)
    assert sorted(junit_ids) == sorted(ids)
    assert set(outcomes) == set(ids)
    p = "pkg/test_sample.py::"
    assert outcomes[p + "test_param[a.b]"] == "passed"
    assert outcomes[p + "test_param[x/y]"] == "passed"
    assert outcomes[p + "test_param[p::q]"] == "passed"
    assert outcomes[p + "test_param[3]"] == "passed"
    assert outcomes[p + "test_plain"] == "passed"
    assert outcomes[p + "TestGroup::test_method"] == "passed"
    assert outcomes[p + "TestGroup::TestNested::test_deep"] == "passed"
    assert outcomes[p + "test_skipped"] == "skipped"
    assert outcomes[p + "test_xfail"] == "xfailed"
    assert outcomes[p + "test_fails"] == "failed"
    assert outcomes[p + "test_errors"] == "error"
    assert outcomes[p + "test_xpass"] == "passed"


def test_parse_collected_ignores_summary_lines_and_checks_the_count() -> None:
    text = "a/test_x.py::test_a\na/test_x.py::T::test_b[1-2]\n\n2 tests collected in 0.01s\n"
    assert parse_collected(text) == ["a/test_x.py::test_a", "a/test_x.py::T::test_b[1-2]"]
    with pytest.raises(ValueError):
        parse_collected("a/test_x.py::test_a\n\n5 tests collected in 0.01s\n")


def test_junit_inventory_digest_is_reported_and_tracks_junit_ids() -> None:
    receipt = build_receipt(**ok())
    assert receipt["junit_inventory_digest"] == receipt["test_inventory_digest"]
    other = build_receipt(**ok(junit_ids=["a", "z"]))
    assert other["junit_inventory_digest"] != other["test_inventory_digest"]


def test_interpreter_is_a_required_argument() -> None:
    args = ok()
    del args["interpreter"]
    with pytest.raises(TypeError):
        build_receipt(**args)


# --- orchestration: run_gate with a fake command runner ------------------------------------------------

SYNC_KEY = "sync"
JUNIT_XML = '<testsuites><testsuite><testcase classname="t.test_a" name="test_a"/></testsuite></testsuites>'


class FakeRunner:
    """Stands in for ``gate.run``: records commands, creates and removes the worktree directory."""

    def __init__(self, tmp_path: Path, *, codes: dict[str, int | None], remove_fails: bool = False) -> None:
        self.tmp_path = tmp_path
        self.codes = codes
        self.remove_fails = remove_fails
        self.calls: list[list[str]] = []
        self.removed: list[str] = []
        self.worktree: Path | None = None

    @staticmethod
    def key(cmd: list[str]) -> str:
        if cmd[:2] == ["uv", "sync"]:
            return SYNC_KEY
        if cmd[0] == "git":
            return "git"
        tool = cmd[cmd.index("--python") + 2 :]
        if tool[:1] == ["python"]:
            return "preflight"
        if tool[:1] == ["pytest"] and "--collect-only" in tool:
            return "collect"
        return tool[0]

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        self.calls.append(argv)
        key = self.key(argv)
        if key == "git":
            sub = argv[3:]
            if sub[:2] == ["worktree", "add"]:
                self.worktree = Path(sub[3])
                (self.worktree / "src" / "superbrain").mkdir(parents=True)
                (self.worktree / "t").mkdir()
                (self.worktree / "t" / "test_a.py").write_text("")
                (self.worktree / "uv.lock").write_text("lock")
                (self.worktree / "pyproject.toml").write_text("cfg")
                return 0, "", 0.0
            if sub[:2] == ["worktree", "remove"]:
                if self.remove_fails:
                    return 1, "locked", 0.0
                self.removed.append(sub[3])
                shutil.rmtree(sub[3])
                return 0, "", 0.0
            if sub[0] == "rev-parse":
                return 0, "a" * 40 + "\n", 0.0
            return 0, "", 0.0  # status --porcelain (clean) and ls-files -s
        if key == "preflight":
            assert self.worktree is not None
            info = {
                "executable": str(self.worktree / ".venv" / "python"),
                "version": "3.14.3 (main)",
                "implementation": "cpython",
                "package_file": str(self.worktree / "src" / "superbrain" / "__init__.py"),
            }
            return self.codes.get(key, 0), json.dumps(info) + "\n", 0.0
        if key == "collect":
            return self.codes.get(key, 0), "t/test_a.py::test_a\n\n1 test collected in 0.01s\n", 0.0
        if key == "pytest":
            junit = next(a for a in argv if a.startswith("--junitxml=")).split("=", 1)[1]
            Path(junit).write_text(JUNIT_XML)
        return self.codes.get(key, 0), "output", 1.0


def run_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeRunner) -> dict[str, Any]:
    monkeypatch.setattr(gate, "run", fake)
    monkeypatch.setattr(gate.tempfile, "gettempdir", lambda: str(tmp_path))
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    return dict(receipt)


def test_run_gate_all_green_with_fakes_is_accepted_and_removes_the_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner(tmp_path, codes={})
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is True, receipt["reasons"]
    assert len(fake.removed) == 1 and not Path(fake.removed[0]).exists()


def test_phase_failure_is_not_accepted_and_worktree_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner(tmp_path, codes={"mypy": 1})
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is False
    assert any("mypy" in r for r in receipt["reasons"])
    assert len(fake.removed) == 1


def test_phase_timeout_is_recorded_as_none_and_worktree_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner(tmp_path, codes={"pytest": None})
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is False
    pytest_phase = next(p for p in receipt["phases"] if p["name"] == "pytest")
    assert pytest_phase["exit_code"] is None
    assert any("timed out" in r for r in receipt["reasons"])
    assert len(fake.removed) == 1


def test_failed_worktree_removal_is_reported_and_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner(tmp_path, codes={}, remove_fails=True)
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is False
    assert any("not removed" in r for r in receipt["reasons"])


def test_failed_uv_sync_is_not_accepted_and_worktree_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner(tmp_path, codes={SYNC_KEY: 1})
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is False
    assert any("uv sync" in r for r in receipt["reasons"])
    assert len(fake.removed) == 1
    assert not any(fake.key(c) == "ruff" for c in fake.calls)


def test_failed_preflight_is_not_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRunner(tmp_path, codes={"preflight": 3})
    receipt = run_with(tmp_path, monkeypatch, fake)
    assert receipt["accepted"] is False
    assert any("preflight exited with 3" in r for r in receipt["reasons"])


def test_junit_temp_file_is_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_with(tmp_path, monkeypatch, FakeRunner(tmp_path, codes={"pytest": None}))
    assert not list(tmp_path.glob("*-junit.xml"))


def test_run_kills_a_process_that_exceeds_its_timeout(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    code = f"import time; time.sleep(6); open({str(marker)!r}, 'w').write('x')"
    began = time.monotonic()
    exit_code, _, _ = gate.run([sys.executable, "-c", code], cwd=tmp_path, timeout_s=1.0)
    assert exit_code is None
    assert time.monotonic() - began < 5
    time.sleep(6)
    assert not marker.exists()


def test_run_does_not_wait_forever_for_a_killed_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Hung:
        pid = 0
        returncode = None

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            raise subprocess.TimeoutExpired("cmd", timeout or 0)

        def kill(self) -> None:
            pass

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: Hung())
    monkeypatch.setattr(gate, "_kill_tree", lambda proc: None)
    monkeypatch.setattr(gate, "KILL_GRACE_S", 0.01)
    exit_code, output, _ = gate.run(["x"], cwd=tmp_path, timeout_s=0.01)
    assert exit_code is None and gate.KILL_HANG_MARKER in output
