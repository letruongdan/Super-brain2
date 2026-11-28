"""The gate's serial phase: wall-clock deadline tests leave the parallel shards and run alone afterwards.

Every collected node still has exactly one final outcome: shards deselect the serial nodes, the serial run reports
exactly them, and a missing node refuses the attempt like any shard inventory mismatch.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from tests.architecture.test_gate_receipt import (
    ALL_SHARD_IDS,
    SHARD_FILES,
    SHARD_IDS,
    ShardRunner,
    _junit_for_shard,
    _pytest_calls,
    _run_shards,
    tool_key,
)

REPO = Path(__file__).resolve().parents[2]
SERIAL_NODE = "t/test_a.py::test_param[with::colon]"


def _named(argv: list[str]) -> list[str]:
    return [a for a in argv if "::" in a and not a.startswith("--")]


class _SerialAwareRunner(ShardRunner):
    """Reports the nodes a real pytest would run for the argv: files minus ``--deselect`` prefixes, plus node IDs."""

    def __init__(self, *, drop_serial: bool = False) -> None:
        super().__init__()
        self.drop_serial = drop_serial

    def report(self, argv: list[str], files: list[str], behavior: str) -> tuple[int | None, str]:  # type: ignore[override]
        deselected = tuple(a.split("=", 1)[1] for a in argv if a.startswith("--deselect="))
        ids = [n for f in files if f in SHARD_IDS for n in SHARD_IDS[f] if not n.startswith(deselected)]
        named = _named(argv)
        ids += [] if self.drop_serial else named
        report = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--junitxml=")))
        report.write_bytes(_junit_for_shard(ids))
        return 0, f"OUT-{','.join(files) or ','.join(named)}"

    def __call__(self, cmd: Any, *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        if tool_key(argv) == "pytest" and _named(argv):
            with self.lock:
                self.calls.append(type(self.calls[0])("pytest", argv, cwd, timeout_s, self.clock.now))
            code, output = self.report(argv, [], "ok")
            return code, output, 0.0
        return super().__call__(cmd, cwd=cwd, timeout_s=timeout_s)


def test_split_serial_selects_by_node_prefix() -> None:
    parallel, serial = gate.split_serial(
        [
            "tests/integration/test_i4_a1_a2_job_lifecycle.py::test_p2_12_x[a]",
            "tests/integration/test_i4_a1_a2_job_lifecycle.py::test_p2_1_clean",
            "tests/integration/test_hook_deadline_gap.py::test_any",
        ]
    )
    assert serial == [
        "tests/integration/test_i4_a1_a2_job_lifecycle.py::test_p2_12_x[a]",
        "tests/integration/test_hook_deadline_gap.py::test_any",
    ]
    assert parallel == ["tests/integration/test_i4_a1_a2_job_lifecycle.py::test_p2_1_clean"]


@pytest.mark.parametrize("prefix", gate.SERIAL_NODE_PREFIXES)
def test_every_serial_prefix_names_a_real_test(prefix: str) -> None:
    # a renamed test would silently drop back into the contended shards
    path, _, func = prefix.partition("::")
    source = REPO / path
    assert source.is_file(), prefix
    names = [n.name for n in ast.parse(source.read_text(encoding="utf-8")).body if isinstance(n, ast.FunctionDef)]
    assert any(name.startswith(func or "test_") for name in names), prefix


def test_serial_nodes_run_alone_after_the_shards_with_one_outcome_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "SERIAL_NODE_PREFIXES", (SERIAL_NODE,))
    runner = _SerialAwareRunner()
    attempt, receipt = _run_shards(tmp_path, monkeypatch, runner)
    assert receipt["accepted"] is True, receipt["reasons"]
    calls = _pytest_calls(runner)
    serial_calls = [c for c in calls if _named(c.argv)]
    shard_calls = [c for c in calls if not _named(c.argv)]
    assert len(serial_calls) == 1 and calls[-1] is serial_calls[0]  # after every shard
    assert _named(serial_calls[0].argv) == [SERIAL_NODE]
    a_shard = next(c for c in shard_calls if any(a.endswith(SHARD_FILES[0]) for a in c.argv))
    assert f"--deselect={SERIAL_NODE}" in a_shard.argv
    assert sorted(receipt["outcomes"]) == sorted(ALL_SHARD_IDS)
    assert (attempt / "junit-serial.xml").is_file()
    assert any(step["name"] == "pytest-serial" for step in receipt["steps"])


def test_a_serial_run_that_reports_nothing_refuses_the_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "SERIAL_NODE_PREFIXES", (SERIAL_NODE,))
    _, receipt = _run_shards(tmp_path, monkeypatch, _SerialAwareRunner(drop_serial=True))
    assert receipt["accepted"] is False
    assert any("pytest-serial" in reason for reason in receipt["reasons"]), receipt["reasons"]
