"""The local gate's test-job budget is an explicit, recorded option (owner decision 2026-11-25, I4 handoff section C).

Requirement: ``scripts/gate.py --time-budget-s <float>`` sets the single test-job deadline (interpreter preflight
through the end of pytest). Omitted, it is 300 s exactly as before. It is refused (exit 2, ``gate refused:``) before
any worktree or evidence work when non-finite, <= 0, > 600, or combined with ``--partition`` (hosted workers stay on
the default). Collect and every pytest step (single or shard) may run up to that deadline; the other per-phase caps
are unchanged. The receipt records ``time_budget_s`` and judges the job against it, and budget-spent reasons name the
budget actually used. The ``aggregate`` subcommand is out of scope.

Fast unit-level oracle: ``main`` with ``run_gate``/``tree_is_clean`` replaced to prove refusals never reach them, and
``run_gate`` driven by the fake clock and runner of ``test_gate_receipt.py``.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from scripts import gate
from scripts.gate import build_receipt
from tests.architecture.test_gate_receipt import GREEN_STEPS, ClockRunner, clean_environment, ok

DEFAULT_BUDGET_S = 300.0
LOCAL_BUDGET_S = 420.0
# Short phases before pytest so the remaining 420 s budget at collect and at each pytest step is still over 300 s.
LIGHT_STEPS: dict[str, tuple[float, float]] = {**GREEN_STEPS, "mypy": (1.0, 10.0), "pytest": (1.0, 5.0)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Reached:
    def __init__(self) -> None:
        self.run_gate: list[dict[str, Any]] = []
        self.clean_checks = 0


def _cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, str, _Reached]:
    """``gate.main(["--python", "3.14", *args])`` with ``run_gate`` and ``tree_is_clean`` recorded, not run."""
    reached = _Reached()

    def _tree_is_clean(repo: Path) -> bool:
        reached.clean_checks += 1
        return True

    def _run_gate(repo: Path, python: str, **kwargs: Any) -> tuple[dict[str, Any], str]:
        reached.run_gate.append(kwargs)
        raise gate.EvidenceDirError("i4-budget-oracle: stop after recording the call")

    monkeypatch.setattr(gate, "tree_is_clean", _tree_is_clean)
    monkeypatch.setattr(gate, "run_gate", _run_gate)
    try:
        code = gate.main(["--python", "3.14", *args])
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else 2
    return code, capsys.readouterr().err, reached


def _drive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: ClockRunner, **kwargs: Any
) -> dict[str, Any]:
    monkeypatch.setattr(gate, "run", runner)
    monkeypatch.setattr(gate, "time", runner.clock)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", clean_environment)
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14", **kwargs)
    return dict(receipt)


def _timeouts(runner: ClockRunner, key: str) -> list[float]:
    return [c.timeout_s for c in runner.calls if c.key == key]


class _TwoFileRunner(ClockRunner):
    """Collect reports two test files so ``shards=2`` runs two pytest shard steps."""

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        code, output, seconds = super().__call__(cmd, cwd=cwd, timeout_s=timeout_s)
        if self.calls[-1].key == "collect":
            output = "t/test_a.py::test_a\nt/test_b.py::test_b\n\n2 tests collected in 0.01s\n"
        return code, output, seconds


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_default_budget_is_300(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Control: without the option ``run_gate`` runs on the 300 s budget, exactly as before."""
    _code, _err, reached = _cli(monkeypatch, capsys)
    assert len(reached.run_gate) == 1, "precondition: run_gate was reached"
    assert reached.run_gate[0].get("time_budget_s", DEFAULT_BUDGET_S) == DEFAULT_BUDGET_S, reached.run_gate


@pytest.mark.parametrize("value", ["420", "600", "0.5"])
def test_cli_time_budget_is_passed_to_run_gate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    code, err, reached = _cli(monkeypatch, capsys, "--time-budget-s", value)
    assert len(reached.run_gate) == 1, f"--time-budget-s {value} must reach run_gate (exit {code}): {err}"
    assert reached.run_gate[0].get("time_budget_s") == float(value), reached.run_gate


@pytest.mark.parametrize(
    "args",
    [
        ["--time-budget-s", "nan"],
        ["--time-budget-s", "inf"],
        ["--time-budget-s=-inf"],  # "=" form: argparse would read a bare "-inf" as an option
        ["--time-budget-s", "0"],
        ["--time-budget-s", "-1"],
        ["--time-budget-s", "600.001"],
        ["--time-budget-s", "601"],
        ["--time-budget-s", "420", "--partition", "0/2"],
    ],
    ids=["nan", "inf", "neg-inf", "zero", "negative", "just-over-600", "over-600", "with-partition"],
)
def test_cli_refuses_invalid_budget_before_any_work(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], args: list[str]
) -> None:
    code, err, reached = _cli(monkeypatch, capsys, *args)
    assert code == 2, f"{args}: expected exit 2, got {code}"
    assert "gate refused:" in err, f"{args}: stderr must carry a 'gate refused:' message: {err!r}"
    assert not reached.run_gate and reached.clean_checks == 0, f"{args}: refused only after work began"


# ---------------------------------------------------------------------------
# run_gate: the deadline, collect and pytest timeouts follow the budget
# ---------------------------------------------------------------------------


def test_run_gate_default_budget_keeps_300_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: no budget argument -> every job timeout <= 300 and the receipt records 300."""
    runner = ClockRunner(steps=GREEN_STEPS)
    receipt = _drive(tmp_path, monkeypatch, runner)
    assert receipt["time_budget_s"] == DEFAULT_BUDGET_S
    assert max(_timeouts(runner, "collect") + _timeouts(runner, "pytest")) <= DEFAULT_BUDGET_S
    assert receipt["accepted"] is True, receipt["reasons"]


def test_run_gate_budget_lifts_collect_and_pytest_timeouts_past_300(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = ClockRunner(steps=LIGHT_STEPS)
    receipt = _drive(tmp_path, monkeypatch, runner, time_budget_s=LOCAL_BUDGET_S)
    calls = {c.key: c for c in runner.calls if c.key != "git"}
    start = calls["preflight"].clock
    for key in ("collect", "pytest"):
        remaining = LOCAL_BUDGET_S - (calls[key].clock - start)
        assert calls[key].timeout_s == pytest.approx(remaining), f"{key} must get the remaining budget"
        assert calls[key].timeout_s > DEFAULT_BUDGET_S, f"{key} still capped at 300s: {calls[key].timeout_s}"
    # The other per-phase caps are unchanged.
    for key in ("ruff", "mypy", "lint-imports"):
        assert calls[key].timeout_s == pytest.approx(gate.PHASE_TIMEOUTS_S[key]), (key, calls[key].timeout_s)
    assert receipt["time_budget_s"] == LOCAL_BUDGET_S
    assert receipt["accepted"] is True, receipt["reasons"]


def test_run_gate_budget_lifts_every_pytest_shard_timeout_past_300(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _TwoFileRunner(steps=LIGHT_STEPS)
    _drive(tmp_path, monkeypatch, runner, time_budget_s=LOCAL_BUDGET_S, shards=2)
    shard_timeouts = _timeouts(runner, "pytest")
    assert len(shard_timeouts) == 2, f"precondition: two pytest shards ran: {shard_timeouts}"
    assert all(t > DEFAULT_BUDGET_S for t in shard_timeouts), f"shard timeouts capped at 300s: {shard_timeouts}"
    assert all(t <= LOCAL_BUDGET_S for t in shard_timeouts), shard_timeouts


# ---------------------------------------------------------------------------
# Acceptance and reasons follow the budget used
# ---------------------------------------------------------------------------


def _slow_steps(pytest_s: float) -> dict[str, tuple[float, float]]:
    return {**GREEN_STEPS, "pytest": (1.0, pytest_s)}


def test_run_gate_350s_job_accepted_with_420_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = ClockRunner(steps=_slow_steps(150.0))  # job = 198 + 151 = 349 s plus the default gaps
    receipt = _drive(tmp_path, monkeypatch, runner, time_budget_s=LOCAL_BUDGET_S)
    job = receipt["timing"]["test_job_s"]
    assert DEFAULT_BUDGET_S < job < LOCAL_BUDGET_S, f"precondition: job between budgets: {job}"
    assert receipt["time_budget_s"] == LOCAL_BUDGET_S
    assert receipt["accepted"] is True, receipt["reasons"]


def test_run_gate_350s_job_refused_with_default_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: the same job on the default budget is refused and the reason names 300."""
    runner = ClockRunner(steps=_slow_steps(150.0))
    receipt = _drive(tmp_path, monkeypatch, runner)
    assert receipt["timing"]["test_job_s"] > DEFAULT_BUDGET_S
    assert receipt["accepted"] is False
    assert any("300" in str(r) for r in receipt["reasons"]), receipt["reasons"]


def test_run_gate_budget_spent_reasons_name_the_budget_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Collect spends its whole timeout (the full remaining 420 s budget): later steps are not started and every
    budget reason names 420, never the old 300."""
    runner = ClockRunner(steps=GREEN_STEPS, hog="collect")
    receipt = _drive(tmp_path, monkeypatch, runner, time_budget_s=LOCAL_BUDGET_S)
    reasons = [str(r) for r in receipt["reasons"]]
    assert receipt["accepted"] is False
    assert any("420s test-job budget was spent" in r for r in reasons), reasons
    assert not any("300s" in r or "300.0s" in r for r in reasons), reasons


def test_build_receipt_judges_job_against_given_budget() -> None:
    """Control (existing parameter): 350 s is accepted under 420 and refused under the default 300."""
    under = build_receipt(**ok(test_job_seconds=350.0), time_budget_s=LOCAL_BUDGET_S)
    default = build_receipt(**ok(test_job_seconds=350.0))
    assert under["accepted"] is True and under["time_budget_s"] == LOCAL_BUDGET_S, under["reasons"]
    assert default["accepted"] is False and default["time_budget_s"] == DEFAULT_BUDGET_S
    assert any("300" in str(r) for r in cast(list[Any], default["reasons"])), default["reasons"]
