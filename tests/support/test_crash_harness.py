import ast
import queue
import sys
import time
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.storage.layout import prepare_data_root
from superbrain.storage.writer import acquire_writer
from tests.support.crash import CHILD, REPO, paused_child, run_child, run_until_crash, wait_for_pause


def test_child_imports_this_checkout() -> None:  # fixes I1-09
    r = run_child("ping", Path("."))
    assert r.returncode == 0 and Path(r.stdout.strip()).is_relative_to(REPO / "src")


def test_run_until_crash_fails_when_point_is_not_hit(tmp_path: Path) -> None:
    with pytest.raises(AssertionError):
        run_until_crash("ping", "ledger.after_commit", tmp_path)


def test_run_until_crash_reports_the_hit(trusted_tmp: Path) -> None:
    r = run_until_crash("acquire_writer", "writer.mid_slot_write", trusted_tmp / "r")
    assert r.hit == "writer.mid_slot_write" and r.returncode == 86


def test_child_reports_brain_error_code(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    with acquire_writer(root, os_adapters()):
        r = run_child("acquire_writer", root.root)
    assert (r.returncode, r.error_code) == (1, "writer_held")


def test_child_does_not_inherit_fault_variables(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERBRAIN_CRASHPOINT", "writer.mid_slot_write")
    monkeypatch.setenv("SUPERBRAIN_PAUSEPOINT", "writer.mid_slot_write")
    r = run_child("acquire_writer", trusted_tmp / "r")
    assert (r.returncode, r.hit) == (0, None), r.stderr


def test_paused_child_resumes_and_waits_for_exit(trusted_tmp: Path) -> None:
    with paused_child("acquire_writer_and_pause", "writer.held", trusted_tmp / "r") as child:
        assert child.poll() is None
    assert child.returncode == 0


def test_paused_child_fails_when_child_exits_without_pausing(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="exited before pausepoint"):
        with paused_child("ping", "writer.held", tmp_path):
            pytest.fail("yielded without a pause")


def test_wait_for_pause_gives_up_at_the_deadline() -> None:
    lines: queue.Queue[str | None] = queue.Queue()
    lines.put("some other line\n")
    start = time.monotonic()
    with pytest.raises(AssertionError, match="did not reach pausepoint"):
        wait_for_pause(lines, "writer.held", deadline=0.2)
    assert time.monotonic() - start < 5


def test_crash_child_imports_only_superbrain_and_stdlib() -> None:
    tree = ast.parse(CHILD.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module
            roots.add(node.module.split(".")[0])
    assert roots - {"superbrain"} <= set(sys.stdlib_module_names)
    assert "superbrain" in roots
