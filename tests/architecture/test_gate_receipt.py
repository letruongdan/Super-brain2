"""The gate receipt accepts only a complete, source-bound, fully-accounted run."""

import inspect
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
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
from tests.architecture.test_remediation_c08_gate_environment import facts as clean_facts

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
    # T8.5: ``test_job_seconds`` becomes a required keyword. The complete-run fixture supplies a value well inside the
    # budget once the gate exposes the parameter, so the pre-T8.5 tests above keep judging exactly what they judged.
    if "test_job_seconds" in inspect.signature(build_receipt).parameters:
        args["test_job_seconds"] = 10.0
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
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
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


# =========================================================================================================
# T8.5 - aggregate budget, locked environment, attempt evidence and CI
#
# Requirement: plan 2026-11-11-sp1-increment2-task8 section 8.5 and Global Constraints ("from interpreter preflight
# to the end of pytest is < 300 s"), review T8-P04, spec 17.2-17.5. Oracle derived from that text, not from the
# current gate. Seams this suite fixes (test author's rulings where the plan leaves the shape open):
#
# * ``gate.run(cmd, *, cwd, timeout_s) -> (exit | None, output, seconds)`` stays the only process seam (every older
#   fake uses it). ``uv run`` commands keep ``--python X`` immediately before the tool, so ``--locked`` goes earlier.
# * The aggregate clock is ``time.monotonic()`` read through the module-level ``time`` import of ``scripts/gate.py``.
# * ``main`` derives the repository from ``__file__`` at call time (lets the CLI run against a fake repository).
# * With an evidence dir, each attempt gets exactly one new subdirectory holding every artifact plus one terminal
#   receipt (the only JSON file there with an ``accepted`` key). Its fields: ``evidence.manifest`` maps each other
#   file's POSIX path relative to the attempt dir to ``digest_bytes`` of its bytes; ``receipt_digest`` is
#   ``digest_bytes(canonical_json(receipt without receipt_digest))``; ``steps`` is a list of step records with at
#   least ``STEP_KEYS`` whose string values that name manifest paths hold the step output; ``timing`` has
#   ``setup_s``, ``test_job_s``, ``teardown_s``, ``total_s``; ``host``; ``outcomes`` maps every collected node ID to
#   its terminal outcome.
# =========================================================================================================

BUDGET_S = 300.0
STEP_KEYS = {"command", "cwd", "pid", "started_at", "exit_code", "duration_s"}
BUDGET_WORDS = ("budget", "deadline", "skip", "not started", "cutoff")


# --- build_receipt: aggregate test-job budget --------------------------------------------------------------


@pytest.mark.parametrize(
    ("test_job_seconds", "accepted"),
    [(299.999, True), (300.0, False), (300.001, False)],
)
def test_gate_rejects_aggregate_budget_at_and_above_limit(test_job_seconds: float, accepted: bool) -> None:
    receipt = build_receipt(**ok(test_job_seconds=test_job_seconds))
    assert receipt["accepted"] is accepted


@pytest.mark.parametrize(
    "value", [None, math.nan, math.inf, -math.inf, -1.0], ids=["none", "nan", "inf", "minus-inf", "negative"]
)
def test_gate_refuses_unknown_or_invalid_test_job_time_with_a_reason(value: float | None) -> None:
    receipt = build_receipt(**ok(test_job_seconds=value))
    assert receipt["accepted"] is False
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and reasons and all(isinstance(r, str) and r for r in reasons)
    canonical_json(receipt)  # an unknown time still yields a writable (finite, canonical) refused receipt


def test_test_job_seconds_is_a_required_keyword() -> None:
    args = ok()
    args.pop("test_job_seconds", None)
    with pytest.raises(TypeError):
        build_receipt(**args)


@pytest.mark.parametrize("missing", ["start", "end"])
def test_receipt_without_a_source_probe_is_refused_and_records_null(missing: str) -> None:
    receipt = build_receipt(**ok(**{missing: None}))
    assert receipt["accepted"] is False
    assert receipt[missing] is None
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and any("source" in str(r) for r in reasons), reasons


# --- fakes: monotonic clock and a runner that spends it ------------------------------------------------------


class FakeClock:
    """Replaces ``gate.time``: ``monotonic()`` reads ``now``; everything else is the real ``time`` module."""

    def __init__(self, start: float = 1024.0) -> None:
        self.now = start

    def monotonic(self) -> float:
        return self.now

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


def tool_key(argv: list[str]) -> str:
    if argv[:2] == ["uv", "sync"]:
        return SYNC_KEY
    if argv[0] == "git":
        return "git"
    tool = argv[argv.index("--python") + 2 :]
    if gate.PREFLIGHT_CODE in tool:
        return "preflight"
    if tool[:1] == ["pytest"] and "--collect-only" in tool:
        return "collect"
    return tool[0]


@dataclass
class Call:
    key: str
    argv: list[str]
    cwd: Path
    timeout_s: float
    clock: float


class ClockRunner:
    """Stands in for ``gate.run``. Each call may advance a fake clock (``steps[key] = (gap, duration)``), may spend
    its whole timeout (``hog``), may end exactly ``finish_short[key]`` seconds before its timeout, and may delete the
    worktree (``vanish_at``). A call whose cwd is the deleted worktree raises what ``Popen`` raises."""

    def __init__(
        self,
        *,
        clock: FakeClock | None = None,
        steps: dict[str, tuple[float, float]] | None = None,
        codes: dict[str, int | None] | None = None,
        hog: str | None = None,
        finish_short: dict[str, float] | None = None,
        vanish_at: str | None = None,
        junit: str | bytes | None = JUNIT_XML,
        sync_output: str = "OUT-sync",
        fail_rev_parse: bool = False,
        on_call: Callable[[str], None] | None = None,
    ) -> None:
        self.clock = clock or FakeClock()
        self.steps = steps or {}
        self.codes = codes or {}
        self.hog = hog
        self.finish_short = finish_short or {}
        self.vanish_at = vanish_at
        self.junit = junit
        self.sync_output = sync_output
        self.fail_rev_parse = fail_rev_parse
        self.on_call = on_call
        self.calls: list[Call] = []
        self.worktree: Path | None = None

    def keys(self) -> list[str]:
        return [c.key for c in self.calls]

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        key = tool_key(argv)
        self.calls.append(Call(key, argv, Path(cwd), timeout_s, self.clock.now))
        if self.on_call is not None:
            self.on_call(key)
        if self.worktree is not None and not self.worktree.exists() and Path(cwd) == self.worktree:
            raise FileNotFoundError(2, "No such file or directory", str(cwd))
        gap, duration = self.steps.get(key, (0.0, 0.0))
        self.clock.now += gap
        if key == self.hog:
            self.clock.now += timeout_s
            return None, f"OUT-{key}", gap + timeout_s
        if key in self.finish_short:
            duration = timeout_s - self.finish_short[key]
        self.clock.now += duration
        seconds = gap + duration
        code = self.codes.get(key, 0)
        if key == "git":
            return self._git(argv[3:], seconds)
        if key == self.vanish_at and self.worktree is not None:
            shutil.rmtree(self.worktree)
        if key == SYNC_KEY:
            return code, self.sync_output, seconds
        if key == "preflight":
            assert self.worktree is not None
            info = {
                "executable": str(self.worktree / ".venv" / "python"),
                "version": "3.14.3 (main)",
                "implementation": "cpython",
                "package_file": str(self.worktree / "src" / "superbrain" / "__init__.py"),
            }
            return code, json.dumps(info) + "\n", seconds
        if key == "collect":
            return code, "t/test_a.py::test_a\n\n1 test collected in 0.01s\n", seconds
        if key == "pytest" and self.junit is not None:
            junit = Path(next(a for a in argv if a.startswith("--junitxml=")).split("=", 1)[1])
            if isinstance(self.junit, bytes):
                junit.write_bytes(self.junit)
            else:
                junit.write_text(self.junit, encoding="utf-8")
        return code, f"OUT-{key}", seconds

    def _git(self, sub: list[str], seconds: float) -> tuple[int | None, str, float]:
        if sub[:2] == ["worktree", "add"]:
            self.worktree = Path(sub[3])
            (self.worktree / "src" / "superbrain").mkdir(parents=True)
            (self.worktree / "t").mkdir()
            (self.worktree / "t" / "test_a.py").write_text("")
            (self.worktree / "uv.lock").write_text("lock")
            (self.worktree / "pyproject.toml").write_text("cfg")
            return 0, "", seconds
        if sub[:2] == ["worktree", "remove"]:
            if not Path(sub[3]).exists():
                return 128, f"fatal: '{sub[3]}' is not a working tree", seconds
            shutil.rmtree(sub[3])
            return 0, "", seconds
        if sub[:1] == ["rev-parse"]:
            if self.fail_rev_parse:
                return 128, "fatal: not a git repository", seconds
            return 0, "a" * 40 + "\n", seconds
        return 0, "", seconds  # status --porcelain (clean) and ls-files -s


def clean_environment(*args: object, **kwargs: object) -> Any:
    """A clean acceptance environment: these tests judge timing/evidence, the host ACL is judged by the C08 suite."""
    return clean_facts()


def gate_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: ClockRunner,
    *,
    use_clock: bool = False,
    evidence_dir: Path | None = None,
) -> dict[str, Any]:
    monkeypatch.setattr(gate, "run", runner)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", clean_environment)
    if use_clock:
        monkeypatch.setattr(gate, "time", runner.clock)
    kwargs: dict[str, Any] = {} if evidence_dir is None else {"evidence_dir": evidence_dir}
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14", **kwargs)
    return dict(receipt)


def gate_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    runner: Any,
    *extra: str,
    python: str = "3.14",
) -> tuple[int, str, str]:
    """``scripts/gate.py --python X *extra`` against a fake repository ``tmp_path/repo``; returns (exit, out, err)."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (tmp_path / "wt").mkdir(exist_ok=True)
    monkeypatch.setattr(gate, "run", runner)
    monkeypatch.setattr(gate, "__file__", str(repo / "scripts" / "gate.py"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path / "wt"))
    monkeypatch.setattr(gate, "collect_environment", clean_environment)
    try:
        code = gate.main(["--python", python, *extra])
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else 2
    out = capsys.readouterr()
    return code, out.out, out.err


GREEN_STEPS: dict[str, tuple[float, float]] = {
    "git": (0.0, 3.0),
    SYNC_KEY: (5.0, 45.0),
    "preflight": (1.0, 2.0),
    "collect": (1.0, 20.0),
    "ruff": (1.0, 10.0),
    "mypy": (1.0, 150.0),
    "lint-imports": (1.0, 10.0),
    "pytest": (1.0, 50.0),
}
JOB_KEYS = ("preflight", "collect", *REQUIRED_PHASES)


def budget_reason(receipt: dict[str, Any], phase: str) -> bool:
    return any(phase in str(r) and any(w in str(r).lower() for w in BUDGET_WORDS) for r in receipt["reasons"])


# --- run_gate: one monotonic deadline from interpreter preflight to the end of pytest ------------------------


def test_run_gate_measures_the_test_job_and_bounds_each_phase_by_the_remaining_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ClockRunner(steps=GREEN_STEPS)
    receipt = gate_run(tmp_path, monkeypatch, runner, use_clock=True)
    calls = {c.key: c for c in runner.calls if c.key != "git"}
    start = calls["preflight"].clock
    caps: dict[str, float] = {"collect": gate.COLLECT_TIMEOUT_S, **gate.PHASE_TIMEOUTS_S}
    timeouts = {k: calls[k].timeout_s for k in caps}
    expected = {k: min(caps[k], BUDGET_S - (calls[k].clock - start)) for k in caps}
    assert timeouts == pytest.approx(expected), f"timeout per phase must be min(cap, remaining): {timeouts}"
    # preflight..pytest spends gap+duration per step, inter-phase gaps included; uv sync and git are outside it
    job = sum(sum(GREEN_STEPS[k]) for k in JOB_KEYS)
    assert job == 248.0
    timing = receipt.get("timing")
    assert isinstance(timing, dict), f"the receipt has no timing section: {sorted(receipt)}"
    assert timing.get("test_job_s") == pytest.approx(job)
    assert timing["setup_s"] >= sum(GREEN_STEPS[SYNC_KEY])
    assert timing["teardown_s"] >= GREEN_STEPS["git"][1]
    assert timing["total_s"] >= timing["setup_s"] + timing["test_job_s"] + timing["teardown_s"]
    assert receipt["accepted"] is True, receipt["reasons"]


@pytest.mark.parametrize("hog", ["collect", "mypy"])
def test_run_gate_starts_no_phase_after_the_budget_is_spent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hog: str
) -> None:
    runner = ClockRunner(steps=GREEN_STEPS, hog=hog)
    receipt = gate_run(tmp_path, monkeypatch, runner, use_clock=True)
    later = REQUIRED_PHASES[REQUIRED_PHASES.index(hog) + 1 :] if hog in REQUIRED_PHASES else REQUIRED_PHASES
    started = [k for k in later if k in runner.keys()]
    assert not started, f"phases {started} were started after the {BUDGET_S}s budget was spent"
    assert receipt["accepted"] is False
    missing = [p for p in later if not budget_reason(receipt, p)]
    assert not missing, f"no budget/skip reason names {missing}: {receipt['reasons']}"


@pytest.mark.parametrize(("short_by", "accepted"), [(0.0, False), (0.5, True)])
def test_run_gate_refuses_a_test_job_that_ends_at_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, short_by: float, accepted: bool
) -> None:
    runner = ClockRunner(steps={**GREEN_STEPS, "pytest": (0.0, 0.0)}, finish_short={"pytest": short_by})
    receipt = gate_run(tmp_path, monkeypatch, runner, use_clock=True)
    timing = receipt.get("timing")
    assert isinstance(timing, dict) and timing.get("test_job_s") == pytest.approx(BUDGET_S - short_by), timing
    assert receipt["accepted"] is accepted, receipt["reasons"]


# --- locked environment ----------------------------------------------------------------------------------------


def test_run_gate_syncs_and_runs_every_tool_locked_with_the_selected_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ClockRunner()
    receipt = gate_run(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is True, receipt["reasons"]
    uv_calls = [c.argv for c in runner.calls if c.argv[0] == "uv"]
    assert {tool_key(a) for a in uv_calls} >= {SYNC_KEY, *JOB_KEYS}
    for argv in uv_calls:
        head = argv if argv[1] == "sync" else argv[: argv.index("--python") + 2]
        assert "--locked" in head, f"not locked: {argv}"
        assert head[head.index("--python") + 1] == "3.14", f"not the selected interpreter: {argv}"


def test_locked_drift_is_refused_and_its_output_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    drift = "error: The lockfile at `uv.lock` needs to be updated, but `--locked` was provided."
    runner = ClockRunner(codes={SYNC_KEY: 2}, sync_output=drift)
    evidence = tmp_path / "ev"
    receipt = gate_run(tmp_path, monkeypatch, runner, evidence_dir=evidence)
    assert receipt["accepted"] is False
    assert any("uv sync" in str(r) for r in receipt["reasons"]), receipt["reasons"]
    assert not any(k in runner.keys() for k in REQUIRED_PHASES)
    attempt, _, on_disk = load_attempt(evidence)
    assert any(drift.encode() in (attempt / rel).read_bytes() for rel in on_disk["evidence"]["manifest"])


# --- attempt evidence ------------------------------------------------------------------------------------------


def load_attempt(evidence: Path) -> tuple[Path, Path, dict[str, Any]]:
    """The single attempt dir under ``evidence``, its terminal receipt file and that receipt, all checked."""
    attempts = [p for p in evidence.iterdir() if p.is_dir()] if evidence.is_dir() else []
    assert len(attempts) == 1, f"expected one attempt dir under {evidence}, found {attempts}"
    attempt = attempts[0]
    receipts: list[tuple[Path, dict[str, Any]]] = []
    for path in attempt.rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(data, dict) and "accepted" in data:
            receipts.append((path, data))
    assert len(receipts) == 1, f"expected one terminal receipt in {attempt}, found {[p for p, _ in receipts]}"
    path, receipt = receipts[0]
    payload = {k: v for k, v in receipt.items() if k != "receipt_digest"}
    assert receipt.get("receipt_digest") == digest_bytes(canonical_json(payload)), "receipt digest mismatch"
    evidence_section = receipt.get("evidence")
    manifest = evidence_section.get("manifest") if isinstance(evidence_section, dict) else None
    assert isinstance(manifest, dict) and manifest, f"no evidence manifest in {sorted(receipt)}"
    for rel, digest in manifest.items():
        artifact = attempt / rel
        assert artifact.resolve().is_relative_to(attempt.resolve()), rel
        assert digest_bytes(artifact.read_bytes()) == digest, f"manifest digest does not match {rel}"
    files = {p.relative_to(attempt).as_posix() for p in attempt.rglob("*") if p.is_file()}
    assert files - {path.relative_to(attempt).as_posix()} == set(manifest), "unlisted or missing artifacts"
    return attempt, path, receipt


def step_bytes(attempt: Path, manifest: dict[str, str], step: dict[str, Any]) -> bytes:
    return b"".join((attempt / v).read_bytes() for v in step.values() if isinstance(v, str) and v in manifest)


def test_attempt_evidence_records_every_step_source_host_and_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ClockRunner()
    evidence = tmp_path / "ev"
    receipt = gate_run(tmp_path, monkeypatch, runner, evidence_dir=evidence)
    assert receipt["accepted"] is True, receipt["reasons"]
    attempt, _, on_disk = load_attempt(evidence)
    assert runner.worktree is not None and not attempt.resolve().is_relative_to(runner.worktree.resolve())
    manifest = on_disk["evidence"]["manifest"]
    steps = on_disk.get("steps")
    assert isinstance(steps, list) and steps, "no step records"
    for call in runner.calls:
        if call.key == "git":
            continue
        step = next((s for s in steps if isinstance(s, dict) and s.get("command") == call.argv), None)
        assert step is not None, f"no step record for {call.argv}"
        assert STEP_KEYS <= set(step), f"step {call.key} lacks {STEP_KEYS - set(step)}"
        assert step["exit_code"] == 0 and isinstance(step["cwd"], str) and step["cwd"]
        if call.key not in ("preflight", "collect"):
            assert f"OUT-{call.key}".encode() in step_bytes(attempt, manifest, step), f"{call.key} output not kept"
    assert on_disk["start"]["commit"] == "a" * 40 and on_disk["end"] == on_disk["start"]
    assert {"lock_digest", "config_digest", "tracked_digest"} <= set(on_disk["start"])
    assert on_disk["interpreter"]["implementation"] == "cpython" and on_disk["interpreter"]["version"]
    assert platform.node() in json.dumps(on_disk.get("host")), on_disk.get("host")
    assert on_disk.get("outcomes") == {"t/test_a.py::test_a": "passed"}
    assert any((attempt / rel).read_bytes() == JUNIT_XML.encode() for rel in manifest), "raw JUnit not copied"
    assert isinstance(on_disk.get("timing"), dict)


def test_each_run_gets_its_own_attempt_dir_and_a_legacy_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    for _ in range(2):
        code, _, err = gate_cli(tmp_path, monkeypatch, capsys, ClockRunner(), "--evidence-dir", str(evidence))
        assert code == 0, err
    attempts = [p for p in evidence.iterdir() if p.is_dir()]
    assert len(attempts) == 2
    legacy = list((tmp_path / "repo" / ".gate").glob("receipt-" + "a" * 12 + "*.json"))
    assert legacy, "legacy .gate/ receipt named by source was not written"


@pytest.mark.parametrize("junit", [None, b"<testsuites><testcase"], ids=["missing", "unparseable"])
def test_missing_or_unparseable_junit_keeps_a_reason_and_raw_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, junit: bytes | None
) -> None:
    evidence = tmp_path / "ev"
    receipt = gate_run(tmp_path, monkeypatch, ClockRunner(junit=junit), evidence_dir=evidence)
    assert receipt["accepted"] is False
    assert any("junit" in str(r).lower() for r in receipt["reasons"]), receipt["reasons"]
    attempt, _, on_disk = load_attempt(evidence)
    kept = [rel for rel in on_disk["evidence"]["manifest"] if (attempt / rel).read_bytes() == junit]
    assert bool(kept) == (junit is not None), "raw JUnit bytes must be kept exactly when pytest wrote any"


def test_missing_and_unparseable_junit_have_different_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found: list[set[str]] = []
    for i, junit in enumerate((None, b"<testsuites><testcase")):
        root = tmp_path / str(i)
        root.mkdir()
        receipt = gate_run(root, monkeypatch, ClockRunner(junit=junit), evidence_dir=root / "ev")
        found.append({str(r) for r in receipt["reasons"] if "junit" in str(r).lower()})
    assert found[0] and found[1] and found[0] != found[1], found


def test_gate_preserves_failed_attempt_after_worktree_disappears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    runner = ClockRunner(vanish_at="mypy")
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", str(evidence))
    assert code == 1, err
    assert runner.worktree is not None and not runner.worktree.exists()
    attempt, _, on_disk = load_attempt(evidence)
    assert on_disk["end"] is None
    assert on_disk["accepted"] is False and on_disk["reasons"]
    manifest = on_disk["evidence"]["manifest"]
    assert any(b"OUT-ruff" in (attempt / rel).read_bytes() for rel in manifest), "phase output before the loss lost"


@pytest.mark.parametrize("project", ["control", "xpass"])
def test_full_real_pytest_attempt_is_judged_and_its_manifest_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], project: str
) -> None:
    from tests.architecture.test_remediation_c06_gate_xpass import (
        CONTROL_PROJECT,
        PROBE,
        PYTHON,
        XPASS_PROJECT,
        RealPytestRunner,
    )

    evidence = tmp_path / "ev"
    evidence.mkdir()
    runner = RealPytestRunner(CONTROL_PROJECT if project == "control" else XPASS_PROJECT)
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", str(evidence), python=PYTHON)
    attempt, _, on_disk = load_attempt(evidence)
    outcomes = on_disk.get("outcomes")
    assert isinstance(outcomes, dict) and outcomes.get(f"{PROBE}::test_plain") == "passed", outcomes
    junit_kept = [rel for rel in on_disk["evidence"]["manifest"] if b"<testcase" in (attempt / rel).read_bytes()]
    assert junit_kept, "the real JUnit report was not copied into the attempt dir"
    if project == "control":
        assert outcomes[f"{PROBE}::test_expected_failure"] == "xfailed"
        assert code == 0 and on_disk["accepted"] is True, (err, on_disk["reasons"])
    else:  # a non-strict XPASS is never an ordinary pass
        assert outcomes[f"{PROBE}::test_unexpectedly_passes"] in ("xpassed", "failed")
        assert code == 1 and on_disk["accepted"] is False


def test_unreadable_start_identity_still_writes_a_refused_unverified_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    runner = ClockRunner(fail_rev_parse=True)
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", str(evidence))
    assert code == 1, err
    _, _, on_disk = load_attempt(evidence)
    assert on_disk["start"] is None and on_disk["accepted"] is False
    assert any("source" in str(r) for r in on_disk["reasons"]), on_disk["reasons"]


@pytest.mark.parametrize("when", ["before", "during"])
def test_evidence_write_failure_exits_non_zero_with_a_reason_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], when: str
) -> None:
    evidence = tmp_path / "ev"
    if when == "before":
        evidence.write_text("not a directory")
    else:
        evidence.mkdir()

    def sabotage(key: str) -> None:  # the evidence root turns into a file while pytest runs
        if when == "during" and key == "pytest" and evidence.is_dir():
            shutil.rmtree(evidence)
            evidence.write_text("not a directory")

    runner = ClockRunner(on_call=sabotage)
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", str(evidence))
    assert code != 0
    assert "unrecognized arguments" not in err, err  # --evidence-dir itself must be understood
    assert "evidence" in err.lower(), err
    if when == "during":
        assert "pytest" in runner.keys(), "the run never reached the sabotaged step"


def test_evidence_dir_must_be_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = ClockRunner()
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", "relative/ev")
    assert code == 2 and "absolute" in err.lower(), err
    assert runner.worktree is None, "a refused input must not start a run"
    absolute = tmp_path / "ev"
    absolute.mkdir()
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, ClockRunner(), "--evidence-dir", str(absolute))
    assert code == 0, err


# --- preflight / collect timeouts ------------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["preflight", "collect"])
def test_preflight_and_collect_timeouts_are_refused_as_timeouts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    receipt = gate_run(tmp_path, monkeypatch, ClockRunner(codes={key: None}))
    assert receipt["accepted"] is False
    assert any(key in str(r) and "timed out" in str(r) for r in receipt["reasons"]), receipt["reasons"]


# --- CI workflow -----------------------------------------------------------------------------------------------

CI_FILE = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
MATRIX_PY = r"\$\{\{\s*matrix\.python\s*\}\}"


def ci_steps() -> list[str]:
    """Each step of the single job as raw text (the ``- `` items directly under ``steps:``)."""
    lines = CI_FILE.read_text(encoding="utf-8").splitlines()
    at = next(i for i, line in enumerate(lines) if line.strip() == "steps:")
    items = [i for i in range(at + 1, len(lines)) if lines[i].lstrip().startswith("- ")]
    indent = len(lines[items[0]]) - len(lines[items[0]].lstrip())
    starts = [i for i in items if len(lines[i]) - len(lines[i].lstrip()) == indent]
    ends = [*starts[1:], len(lines)]
    return ["\n".join(lines[s:e]) for s, e in zip(starts, ends, strict=True)]


def ci_matrix_list(name: str) -> list[str]:
    match = re.search(rf"^\s*{name}:\s*\[(.*?)\]", CI_FILE.read_text(encoding="utf-8"), re.M)
    assert match, f"matrix.{name} is not an inline list"
    return [v.strip().strip("'\"") for v in match.group(1).split(",")]


def test_ci_keeps_the_six_matrix_cells() -> None:
    text = CI_FILE.read_text(encoding="utf-8")
    assert set(ci_matrix_list("os")) == {"windows-latest", "macos-latest", "ubuntu-latest"}
    assert ci_matrix_list("python") == ["3.11", "3.14"]
    assert "exclude:" not in text and "include:" not in text


def test_ci_runs_the_locked_gate_with_evidence_and_uploads_it_always() -> None:
    steps = ci_steps()
    gate_at = next((i for i, s in enumerate(steps) if "scripts/gate.py" in s), None)
    assert gate_at is not None
    step = steps[gate_at]
    assert re.search(rf"uv run --locked --python {MATRIX_PY} python scripts/gate\.py --python {MATRIX_PY}", step), step
    assert "--evidence-dir" in step and "runner.temp" in step, step
    assert re.search(r"mkdir|New-Item", step), "the evidence dir is not created"
    assert re.search(r"2>(?!&)\s*\S", step) and re.search(r"(?<![0-9&>])>(?!&)\s*\S", step), "stdout/stderr not saved"
    assert re.search(r"(>|Out-File|Set-Content|tee)[^\n]*exit", step, re.I), "the outer exit code is not saved"
    assert re.search(r"^\s*exit\s+\S", step, re.M), "the saved exit code is not returned"
    uploads = [s for s in steps if "upload-artifact" in s]
    assert uploads and all(re.search(r"if:\s*always\(\)", s) for s in uploads), uploads
    assert any(".gate/" in s for s in uploads) and any("runner.temp" in s for s in uploads), uploads
    bench_at = next((i for i, s in enumerate(steps) if "tests.integration.test_kernel_performance" in s), None)
    assert bench_at is not None and bench_at > gate_at, "no benchmark step after the gate"
    bench = steps[bench_at]
    assert re.search(r"python -m tests\.integration\.test_kernel_performance --evidence-dir", bench), bench
    assert "--locked" in bench and not re.search(r"always\(\)|failure\(\)|cancelled\(\)", bench), bench


# =========================================================================================================
# T8.5 review round 1 (review-8.5.md, R85-01..R85-05)
#
# * R85-01: once an attempt dir exists, every way out of the gate ends with exactly one terminal receipt, refused
#   with a reason, and exit 1 (exit 2 is only for input refused before anything ran). A step that started and then
#   failed (its kill failed, its runner raised mid-step) is never reported as "could not start".
# * R85-02: every receipt written (attempt or legacy ``.gate/``) carries a ``receipt_digest`` of its own payload.
# * R85-03: only a measured number (int/float, not bool) can be the test-job time.
# * R85-04: one artifact that cannot be written refuses the attempt with a reason naming it, while the attempt dir
#   and the terminal receipt stay writable.
# * R85-05: the outcome keys must be exactly the JUnit IDs, even when the counts agree.
# =========================================================================================================

NOT_STARTED_WORDS = ("could not start", "not started")
NOTHING_RAN_WORDS = ("nothing ran", "could not be prepared")


def cli_or_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], runner: Any, evidence: Path
) -> tuple[int, str, str]:
    """``gate_cli`` with an evidence dir; an exception escaping ``main`` is itself the failure under test."""
    try:
        return gate_cli(tmp_path, monkeypatch, capsys, runner, "--evidence-dir", str(evidence))
    except Exception as err:  # noqa: BLE001 - the oracle: nothing may escape once the attempt dir exists
        receipts = list(evidence.rglob("receipt.json"))
        pytest.fail(f"{type(err).__name__} escaped the gate: {err}; terminal receipts: {receipts}")


def assert_refused_attempt(code: int, err: str, evidence: Path) -> dict[str, Any]:
    assert code == 1, f"exit {code}, expected 1 (attempted, refused); stderr:\n{err}"
    assert not any(w in err for w in NOTHING_RAN_WORDS), f"stderr claims nothing ran:\n{err}"
    _, _, receipt = load_attempt(evidence)  # exactly one terminal receipt, digest and manifest checked
    assert receipt["accepted"] is False
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and reasons and all(isinstance(r, str) and r for r in reasons), reasons
    return receipt


class TimedOutProcess:
    """A ``Popen`` stand-in that exceeds its timeout once, then returns its output after the kill attempt."""

    pid = 4242
    returncode = None

    def __init__(self, output: str = "OUT-killed") -> None:
        self.output = output
        self.calls = 0

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired("cmd", timeout or 0)
        return self.output, ""

    def kill(self) -> None:
        pass


def test_junit_read_error_after_pytest_still_ends_with_a_refused_terminal_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    real = Path.read_bytes

    def locked(self: Path) -> bytes:  # the temp JUnit report is locked (AV/indexer) after pytest wrote it
        if self.name.endswith("-junit.xml"):
            raise PermissionError(13, "locked by another process", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", locked)
    runner = ClockRunner()
    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, runner, evidence)
    monkeypatch.undo()
    assert "pytest" in runner.keys(), "the run never reached pytest"
    receipt = assert_refused_attempt(code, err, evidence)
    assert any("junit" in r.lower() for r in receipt["reasons"]), receipt["reasons"]


@pytest.mark.parametrize(
    "raised",
    [subprocess.TimeoutExpired(["taskkill"], 60), RuntimeError("unexpected runner failure")],
    ids=["kill-helper-timeout", "unexpected-exception"],
)
def test_runner_exception_mid_step_still_ends_with_a_refused_terminal_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raised: Exception
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    base = ClockRunner()

    def runner(cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        if tool_key(list(cmd)) == "mypy":
            base.calls.append(Call("mypy", list(cmd), Path(cwd), timeout_s, base.clock.now))
            raise raised
        return base(cmd, cwd=cwd, timeout_s=timeout_s)

    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, runner, evidence)
    receipt = assert_refused_attempt(code, err, evidence)
    named = [r for r in receipt["reasons"] if "mypy" in r]
    assert named, f"no reason names the failed step: {receipt['reasons']}"
    if isinstance(raised, subprocess.TimeoutExpired):  # the step had started; only its kill hung
        assert not any(w in r for r in named for w in NOT_STARTED_WORDS), named


@pytest.mark.parametrize(
    "kill_error",
    [PermissionError(1, "Operation not permitted"), subprocess.TimeoutExpired(["taskkill"], 60)],
    ids=["oserror", "kill-timeout"],
)
def test_run_reports_a_timeout_when_killing_the_timed_out_process_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kill_error: Exception
) -> None:
    def failing_kill(proc: Any) -> None:
        raise kill_error

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: TimedOutProcess())
    monkeypatch.setattr(gate, "_kill_tree", failing_kill)
    monkeypatch.setattr(gate, "KILL_GRACE_S", 0.01)
    try:
        exit_code, output, _ = gate.run(["x"], cwd=tmp_path, timeout_s=0.01)
    except Exception as err:  # noqa: BLE001 - the oracle: a failed kill must not escape run()
        pytest.fail(f"{type(err).__name__} escaped run() after the timeout: {err}")
    assert exit_code is None, "a process that exceeded its timeout is a timeout, whatever the kill did"
    assert isinstance(output, str)


def test_failed_kill_of_a_started_phase_is_not_reported_as_could_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_kill(proc: Any) -> None:
        raise PermissionError(1, "Operation not permitted")

    real_run = gate.run
    base = ClockRunner()

    def runner(cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        if tool_key(list(cmd)) == "pytest":  # the real run() on a process that times out and cannot be killed
            base.calls.append(Call("pytest", list(cmd), Path(cwd), timeout_s, base.clock.now))
            return real_run(cmd, cwd=cwd, timeout_s=timeout_s)
        return base(cmd, cwd=cwd, timeout_s=timeout_s)

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: TimedOutProcess("OUT-pytest-killed"))
    monkeypatch.setattr(gate, "_kill_tree", failing_kill)
    monkeypatch.setattr(gate, "KILL_GRACE_S", 0.01)
    evidence = tmp_path / "ev"
    evidence.mkdir()
    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, runner, evidence)
    receipt = assert_refused_attempt(code, err, evidence)
    named = [r for r in receipt["reasons"] if "pytest" in r and "junit" not in r.lower()]
    assert named, f"no reason names the timed-out pytest phase: {receipt['reasons']}"
    assert not any(w in r for r in named for w in NOT_STARTED_WORDS), named
    pytest_steps = [s for s in receipt["steps"] if isinstance(s, dict) and s.get("name") == "pytest"]
    assert len(pytest_steps) == 1 and pytest_steps[0]["pid"] == TimedOutProcess.pid, pytest_steps  # it did start
    assert pytest_steps[0]["exit_code"] is None, pytest_steps


def test_legacy_receipt_digest_matches_its_payload_after_the_terminal_receipt_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    evidence.mkdir()
    real = os.replace

    def failing(src: Any, dst: Any) -> None:
        if Path(dst).name == "receipt.json":
            raise PermissionError(13, "denied", str(dst))
        real(src, dst)

    monkeypatch.setattr(os, "replace", failing)  # gate.py calls os.replace
    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, ClockRunner(), evidence)
    assert code == 1, err
    (legacy,) = (tmp_path / "repo" / ".gate").glob("receipt-*.json")
    data = json.loads(legacy.read_text(encoding="utf-8"))
    payload = {k: v for k, v in data.items() if k != "receipt_digest"}
    assert data["receipt_digest"] == digest_bytes(canonical_json(payload)), "legacy receipt digest is stale"
    assert data["accepted"] is False
    assert any("receipt" in str(r).lower() for r in data["reasons"]), data["reasons"]


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_gate_refuses_a_bool_test_job_time_with_a_reason(value: bool) -> None:
    receipt = build_receipt(**ok(test_job_seconds=value))
    assert receipt["accepted"] is False, "a bool is not a measured time"
    reasons = receipt["reasons"]
    assert isinstance(reasons, list) and reasons and all(isinstance(r, str) and r for r in reasons)


def _step_log(name: str) -> Callable[[Path], bool]:
    return lambda p: p.parent.name == "steps" and p.name.endswith(f"-{name}.log")


def _named(name: str) -> Callable[[Path], bool]:
    return lambda p: p.name == name


@pytest.mark.parametrize(
    ("artifact", "matches"),
    [
        (None, None),
        ("ruff.log", _step_log("ruff")),
        ("junit.xml", _named("junit.xml")),
        ("source.json", _named("source.json")),
    ],
    ids=["control", "step-log", "junit-copy", "source"],
)
def test_one_artifact_write_failure_is_refused_with_a_reason_naming_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact: str | None,
    matches: Callable[[Path], bool] | None,
) -> None:
    """Only that artifact fails (no space); the attempt dir and the terminal receipt stay writable."""
    evidence = tmp_path / "ev"
    evidence.mkdir()
    real = Path.write_bytes
    hit: list[Path] = []

    def no_space(self: Path, data: Any) -> int:
        if matches is not None and self.is_relative_to(evidence) and matches(self):
            hit.append(self)
            raise OSError(28, "No space left on device", str(self))
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", no_space)
    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, ClockRunner(), evidence)
    monkeypatch.undo()
    if artifact is None:  # positive twin: the same run with every write succeeding is accepted
        assert code == 0, err
        _, _, receipt = load_attempt(evidence)
        assert receipt["accepted"] is True, receipt["reasons"]
        return
    assert hit, f"the run never tried to write {artifact}"
    receipt = assert_refused_attempt(code, err, evidence)
    assert any(artifact in r for r in receipt["reasons"]), receipt["reasons"]
    assert artifact in err, err


def test_outcome_key_swapped_for_an_unknown_id_with_equal_counts_is_not_accepted() -> None:
    receipt = build_receipt(**ok(junit_outcomes={"a": "passed", "x": "passed"}))
    assert receipt["accepted"] is False
    assert receipt["reasons"], "a refusal carries a reason"


@pytest.mark.parametrize(
    ("key", "label", "skipped"),
    [
        ("preflight", "interpreter preflight", ("collect", *REQUIRED_PHASES)),
        ("collect", "pytest --collect-only", REQUIRED_PHASES),
        ("mypy", "phase mypy", ("lint-imports", "pytest")),
    ],
)
@pytest.mark.parametrize(
    "raised",
    [subprocess.TimeoutExpired(["taskkill"], 60), RuntimeError("unexpected runner failure")],
    ids=["kill-helper-timeout", "unexpected-exception"],
)
def test_started_runner_exception_keeps_its_step_and_reasons_for_every_later_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    key: str,
    label: str,
    skipped: tuple[str, ...],
    raised: Exception,
) -> None:
    base = ClockRunner()
    evidence = tmp_path / "ev"
    evidence.mkdir()

    def runner(cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        if tool_key(list(cmd)) == key:
            base.calls.append(Call(key, list(cmd), cwd, timeout_s, base.clock.now))
            raise raised
        return base(cmd, cwd=cwd, timeout_s=timeout_s)

    code, _, err = cli_or_fail(tmp_path, monkeypatch, capsys, runner, evidence)
    receipt = assert_refused_attempt(code, err, evidence)
    (call,) = [call for call in base.calls if call.key == key]
    records = [step for step in receipt["steps"] if step["name"] == key]
    assert len(records) == 1, f"started {key} did not leave exactly one step: {records}"
    (record,) = records
    assert record["command"] == call.argv and record["cwd"] == str(call.cwd)
    assert record["exit_code"] is None
    assert record["error"].startswith(f"failed while running: {type(raised).__name__}")
    assert record["output"] in receipt["evidence"]["manifest"]
    assert any(reason.startswith(f"{label} failed while running") for reason in receipt["reasons"])
    recorded_names = {step["name"] for step in receipt["steps"]}
    assert not (set(skipped) & recorded_names)
    for name in skipped:
        step_label = "pytest --collect-only" if name == "collect" else f"phase {name}"
        assert any(reason.startswith(f"{step_label} not started") for reason in receipt["reasons"]), name


# --- T8.5s: split by file, run concurrently, bind the raw reports to the unchanged inventory --------------------

SHARD_FILES = ("t/test_a.py", "t/test_b.py")
SHARD_IDS = {
    "t/test_a.py": ("t/test_a.py::test_a", "t/test_a.py::test_param[with::colon]"),
    "t/test_b.py": ("t/test_b.py::test_b",),
}
ALL_SHARD_IDS = [node for nodes in SHARD_IDS.values() for node in nodes]


@pytest.mark.parametrize("shards", [-1, 1, 2, 4, 20])
def test_shard_file_partition_is_complete_disjoint_and_deterministic(shards: int) -> None:
    inventory = [*ALL_SHARD_IDS, "t/nested/test_c.py::TestClass::test_case", "tests/test_d.py::test_d"]
    files = {node.split("::", 1)[0] for node in inventory}
    partition = getattr(gate, "shard_files", None)
    assert callable(partition), "gate has no deterministic file partition"
    groups = partition(inventory, shards)
    assert groups == partition(inventory, shards)
    assert 1 <= len(groups) <= min(max(shards, 1), len(files))
    assert all(groups)
    selected = [path for group in groups for path in group]
    assert set(selected) == files and len(selected) == len(files)


def test_gate_defaults_to_at_most_four_shards() -> None:
    assert getattr(gate, "PYTEST_SHARDS", None) == min(4, os.cpu_count() or 1)


def _junit_for_shard(ids: Sequence[str]) -> bytes:
    cases = []
    for node in ids:
        path, name = node.split("::", 1)
        module = path.removesuffix(".py").replace("/", ".")
        cases.append(f'<testcase classname="{module}" name="{name}"/>')
    return ("<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>").encode()


def _selected_pytest_files(argv: Sequence[str], cwd: Path) -> list[str]:
    files = [Path(arg) for arg in argv if arg.endswith(".py")]
    return [(path.relative_to(cwd) if path.is_absolute() else path).as_posix() for path in files]


class ShardRunner(ClockRunner):
    """Synthetic subprocess results at the gate's command seam, with two files in the same collected inventory."""

    def __init__(self, *, behavior: str = "ok", measure_overlap: bool = False, spent: bool = False) -> None:
        steps = {"mypy": (0.0, 200.0), "lint-imports": (0.0, 100.0)} if spent else {}
        if measure_overlap:
            steps = {"preflight": (0.0, 2.0), "collect": (0.0, 3.0), "lint-imports": (0.0, 287.0)}
        super().__init__(steps=steps)
        self.behavior = behavior
        self.overlap = threading.Barrier(2, timeout=3.0) if measure_overlap else None
        self.lock = threading.Lock()
        self.run_process: Callable[..., tuple[int | None, str, float]] | None = None

    def _git(self, sub: list[str], seconds: float) -> tuple[int | None, str, float]:
        result = super()._git(sub, seconds)
        if sub[:2] == ["worktree", "add"]:
            assert self.worktree is not None
            (self.worktree / SHARD_FILES[1]).touch()
        return result

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        key = tool_key(argv)
        if key == "collect":
            code, _, seconds = super().__call__(cmd, cwd=cwd, timeout_s=timeout_s)
            inventory = "\n".join(ALL_SHARD_IDS)
            return code, f"{inventory}\n\n{len(ALL_SHARD_IDS)} tests collected in 0.01s\n", seconds
        if key != "pytest":
            return super().__call__(cmd, cwd=cwd, timeout_s=timeout_s)
        with self.lock:
            start = self.clock.now
            self.calls.append(Call(key, argv, cwd, timeout_s, start))
        files = _selected_pytest_files(argv, cwd)
        if files and self.run_process is not None:
            return self.run_process(cmd, cwd=cwd, timeout_s=timeout_s)
        duration = 0.0
        if files and self.overlap is not None:
            self.overlap.wait()
            duration = 7.0 if SHARD_FILES[1] in files else 2.0
            with self.lock:
                self.clock.now = max(self.clock.now, start + duration)
        behavior = self.behavior if files == [SHARD_FILES[1]] else "ok"
        exit_code, output = self.report(argv, files or list(SHARD_FILES), behavior)
        return exit_code, output, duration

    @staticmethod
    def report(argv: list[str], files: list[str], behavior: str) -> tuple[int | None, str]:
        ids = [node for path in files for node in SHARD_IDS[path]]
        report = Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--junitxml=")))
        if behavior == "omitted":
            ids = []
        elif behavior == "duplicate":
            ids.extend(SHARD_IDS[SHARD_FILES[0]])
        if behavior != "missing":
            report.write_bytes(b"<testsuites" if behavior == "unparseable" else _junit_for_shard(ids))
        label = ",".join(files)
        if behavior in ("xpass", "foreign-xpass"):
            node = SHARD_IDS[SHARD_FILES[1 if behavior == "xpass" else 0]][0]
            return 0, f"OUT-{label}\nXPASS {node} - reason\n1 xpassed in 0.01s\n"
        return {"failed": 1, "timed-out": None}.get(behavior, 0), f"OUT-{label}"


def _run_shards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: ShardRunner
) -> tuple[Path, dict[str, Any]]:
    monkeypatch.setattr(gate, "run", runner)
    monkeypatch.setattr(gate, "time", runner.clock)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", clean_environment)
    evidence = tmp_path / "ev"
    kwargs: dict[str, Any] = {"evidence_dir": evidence}
    # On the original gate, exercise its real serial behavior and judge the receipt rather than raising TypeError.
    if "shards" in inspect.signature(gate.run_gate).parameters:
        kwargs["shards"] = 2
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14", **kwargs)
    attempt, _, on_disk = load_attempt(evidence)
    assert on_disk == receipt
    return attempt, on_disk


def _pytest_calls(runner: ShardRunner) -> list[Call]:
    return [call for call in runner.calls if call.key == "pytest"]


def _shard_steps(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    steps = [step for step in receipt["steps"] if step["name"].startswith("pytest-shard-")]
    assert {step["name"] for step in steps} == {"pytest-shard-0", "pytest-shard-1"}, receipt["steps"]
    assert len(steps) == 2
    return steps


def _pytest_phase(receipt: dict[str, Any]) -> dict[str, Any]:
    phases: list[dict[str, Any]] = receipt["phases"]
    (phase,) = [phase for phase in phases if phase["name"] == "pytest"]
    return phase


class StartedShard:
    """Only returns after both worker PIDs exist, so a single global PID cannot identify both steps."""

    returncode = 0

    def __init__(self, pid: int, output: str, started: threading.Barrier) -> None:
        self.pid = pid
        self.output = output
        self.started = started

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self.started.wait()
        return self.output, ""


def test_gate_binds_each_overlapping_shard_command_pid_output_and_raw_junit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ShardRunner()
    runner.run_process = gate.run
    started = threading.Barrier(2, timeout=3.0)
    pid_by_file = dict(zip(SHARD_FILES, (4242, 5252), strict=True))
    start_by_file: dict[str, datetime] = {}

    def popen(argv: list[str], *, cwd: Path, **kwargs: Any) -> StartedShard:
        files = _selected_pytest_files(argv, cwd)
        (file,) = files
        with runner.lock:
            start_by_file[file] = datetime.now(UTC)
        _, output = runner.report(argv, files, "ok")
        return StartedShard(pid_by_file[file], output, started)

    monkeypatch.setattr(subprocess, "Popen", popen)
    before = datetime.now(UTC)
    attempt, receipt = _run_shards(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is True, receipt["reasons"]
    steps = _shard_steps(receipt)
    calls = _pytest_calls(runner)
    assert len(calls) == 2
    assert len({step["output"] for step in steps}) == 2
    manifest = receipt["evidence"]["manifest"]
    observed_files = []
    for call in calls:
        (file,) = _selected_pytest_files(call.argv, call.cwd)
        observed_files.append(file)
        assert "--locked" in call.argv and call.argv[call.argv.index("--python") + 1] == "3.14"
        (step,) = [step for step in steps if step["command"] == call.argv]
        assert step["cwd"] == str(call.cwd) and step["exit_code"] == 0
        assert step["pid"] == pid_by_file[file], f"incorrect process attribution for {file}: {step}"
        assert before <= datetime.fromisoformat(step["started_at"]) <= start_by_file[file]
        assert step["duration_s"] >= 0
        assert step_bytes(attempt, manifest, step) == f"OUT-{file}".encode()
        index = step["name"].removeprefix("pytest-shard-")
        assert (attempt / f"junit-shard-{index}.xml").read_bytes() == _junit_for_shard(SHARD_IDS[file])
        report_path = Path(next(arg.split("=", 1)[1] for arg in call.argv if arg.startswith("--junitxml=")))
        assert not report_path.exists(), f"temporary JUnit still exists: {report_path}"
    assert sorted(observed_files) == list(SHARD_FILES)
    assert receipt["test_count"] == len(ALL_SHARD_IDS)
    assert receipt["outcomes"] == dict.fromkeys(ALL_SHARD_IDS, "passed")
    assert _pytest_phase(receipt)["exit_code"] == 0


@pytest.mark.parametrize("behavior", ["failed", "timed-out", "missing", "unparseable", "omitted", "duplicate"])
def test_one_bad_shard_refuses_the_attempt_and_preserves_the_other_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, behavior: str
) -> None:
    attempt, receipt = _run_shards(tmp_path, monkeypatch, ShardRunner(behavior=behavior))
    assert receipt["accepted"] is False, f"shard failure went undetected: {behavior}"
    steps = _shard_steps(receipt)
    (bad,) = [step for step in steps if SHARD_FILES[1] in _selected_pytest_files(step["command"], Path(step["cwd"]))]
    (good,) = [step for step in steps if step is not bad]
    assert any(bad["name"] in reason or "shard" in reason.lower() for reason in receipt["reasons"]), receipt["reasons"]
    for node in SHARD_IDS[SHARD_FILES[0]]:
        assert receipt["outcomes"][node] == "passed"
    expected_exit = {"failed": 1, "timed-out": None}.get(behavior, 0)
    assert bad["exit_code"] == expected_exit
    assert _pytest_phase(receipt)["exit_code"] == expected_exit
    good_index = good["name"].removeprefix("pytest-shard-")
    assert (attempt / f"junit-shard-{good_index}.xml").read_bytes() == _junit_for_shard(SHARD_IDS[SHARD_FILES[0]])
    bad_index = bad["name"].removeprefix("pytest-shard-")
    bad_xml = attempt / f"junit-shard-{bad_index}.xml"
    if behavior == "missing":
        assert not bad_xml.exists()
    elif behavior == "unparseable":
        assert bad_xml.read_bytes() == b"<testsuites"


@pytest.mark.parametrize("behavior", ["xpass", "foreign-xpass"])
def test_xpass_is_validated_against_only_that_shards_junit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, behavior: str
) -> None:
    _, receipt = _run_shards(tmp_path, monkeypatch, ShardRunner(behavior=behavior))
    assert receipt["accepted"] is False, "a zero-exit pytest shard with an XPASS was accepted"
    _shard_steps(receipt)
    expected = dict.fromkeys(ALL_SHARD_IDS, "passed")
    if behavior == "xpass":
        expected[SHARD_IDS[SHARD_FILES[1]][0]] = "xpassed"
    else:
        assert any("xpass" in reason.lower() for reason in receipt["reasons"])
    assert receipt["outcomes"] == expected
    assert receipt["counts"]["xpassed"] == (1 if behavior == "xpass" else 0)


def test_shards_share_the_remaining_deadline_and_measure_wall_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ShardRunner(measure_overlap=True)
    _, receipt = _run_shards(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is True, receipt["reasons"]
    _shard_steps(receipt)
    calls = _pytest_calls(runner)
    assert len(calls) == 2 and all(call.timeout_s == 8.0 for call in calls)
    assert _pytest_phase(receipt)["duration_s"] == 7.0
    assert receipt["timing"]["test_job_s"] == 299.0


def test_no_shard_starts_when_the_preceding_phases_spend_the_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ShardRunner(spent=True)
    _, receipt = _run_shards(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is False
    assert not _pytest_calls(runner)
    assert budget_reason(receipt, "pytest")
    assert receipt["timing"]["test_job_s"] == 300.0


def test_cli_shards_one_retains_the_serial_attempt_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "ev"
    runner = ShardRunner()
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--shards", "1", "--evidence-dir", str(evidence))
    assert code == 0, err
    attempt, _, receipt = load_attempt(evidence)
    assert receipt["accepted"] is True, receipt["reasons"]
    (call,) = _pytest_calls(runner)
    assert not _selected_pytest_files(call.argv, call.cwd)
    assert [step["name"] for step in receipt["steps"] if step["name"].startswith("pytest")] == ["pytest"]
    assert (attempt / "junit.xml").read_bytes() == _junit_for_shard(ALL_SHARD_IDS)
    assert receipt["outcomes"] == dict.fromkeys(ALL_SHARD_IDS, "passed")


def test_cli_rejects_a_zero_shard_count_before_starting_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = ShardRunner()
    code, _, err = gate_cli(tmp_path, monkeypatch, capsys, runner, "--shards", "0")
    assert code == 2 and "shards" in err
    assert not runner.calls


def test_shard_thread_start_failure_preserves_every_finished_shard_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ShardRunner()
    first_running = threading.Event()
    finish = threading.Event()
    start = threading.Thread.start
    starts = 0

    def report(argv: list[str], files: list[str], behavior: str) -> tuple[int | None, str]:
        first_running.set()
        assert finish.wait(timeout=5.0), "the second worker did not reach the fault boundary"
        return ShardRunner.report(argv, files, behavior)

    def fail_second_start(thread: threading.Thread) -> None:
        nonlocal starts
        starts += 1
        if starts == 2:
            assert first_running.wait(timeout=5.0), "no healthy shard started before the launch fault"
            finish.set()
            raise RuntimeError("synthetic thread start failure")
        start(thread)

    monkeypatch.setattr(runner, "report", report)
    monkeypatch.setattr(threading.Thread, "start", fail_second_start)
    try:
        attempt, receipt = _run_shards(tmp_path, monkeypatch, runner)
    finally:
        finish.set()
    assert starts >= 2
    assert receipt["accepted"] is False
    calls = _pytest_calls(runner)
    assert calls, "the launch fault was never tested against a started shard"
    expected: dict[str, str] = {}
    # A callable queued before the failed Thread.start can run when the first worker drains its queue.
    # Require evidence for each invocation observed at the process seam, independently of that scheduling choice.
    for call in calls:
        (file,) = _selected_pytest_files(call.argv, call.cwd)
        (step,) = [step for step in receipt["steps"] if step["command"] == call.argv]
        assert step["exit_code"] == 0
        index = step["name"].removeprefix("pytest-shard-")
        xml = attempt / f"junit-shard-{index}.xml"
        assert xml.is_file(), f"completed {step['name']} lost its raw JUnit after another worker failed to start"
        assert xml.read_bytes() == _junit_for_shard(SHARD_IDS[file])
        expected.update(dict.fromkeys(SHARD_IDS[file], "passed"))
    assert receipt["outcomes"] == expected
    assert any(
        "pytest" in reason.lower() and "shard" in reason.lower()
        and any(word in reason.lower() for word in ("launch", "start", "thread"))
        for reason in receipt["reasons"]
    ), receipt["reasons"]


def test_unknown_junit_encoding_keeps_its_raw_bytes_and_later_shard_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ShardRunner()
    bad_xml = b'<?xml version="1.0" encoding="x-no-such-encoding"?><testsuites/>'
    (bad_file,), (healthy_file,) = gate.shard_files(ALL_SHARD_IDS, 2)

    def report(argv: list[str], files: list[str], behavior: str) -> tuple[int | None, str]:
        result = ShardRunner.report(argv, files, behavior)
        if files == [bad_file]:
            path = Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--junitxml=")))
            path.write_bytes(bad_xml)
        return result

    monkeypatch.setattr(runner, "report", report)
    attempt, receipt = _run_shards(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is False
    assert all(step["exit_code"] == 0 for step in _shard_steps(receipt))
    assert (attempt / "junit-shard-0.xml").read_bytes() == bad_xml
    healthy_xml = attempt / "junit-shard-1.xml"
    assert healthy_xml.is_file(), "the encoding error discarded the healthy shard's raw JUnit"
    assert healthy_xml.read_bytes() == _junit_for_shard(SHARD_IDS[healthy_file])
    assert receipt["outcomes"] == dict.fromkeys(SHARD_IDS[healthy_file], "passed")
    assert any(
        "pytest-shard-0" in reason and any(word in reason.lower() for word in ("encoding", "parse"))
        for reason in receipt["reasons"]
    ), receipt["reasons"]
