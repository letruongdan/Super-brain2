"""The gate receipt accepts only a complete, source-bound, fully-accounted run."""

import inspect
import json
import math
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
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
