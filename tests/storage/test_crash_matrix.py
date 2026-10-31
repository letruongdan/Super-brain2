"""The crash-point table (spec 5.4): every registered crashpoint fires in a real child process, and the reopened data
root holds concrete, expected state. ``docs/design/sp1-crash-table.md`` has exactly one row per crashpoint."""

from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import KNOWN_CRASHPOINTS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.runtime import open_runtime
from tests.storage.conftest import DEMO_KINDS
from tests.support.crash_cases import CRASH_CASES, CRASH_TABLE, CrashCase, crash, parse_crash_table


def test_every_known_crashpoint_has_a_case_and_a_doc_row() -> None:
    assert sorted(c.crashpoint for c in CRASH_CASES) == sorted(KNOWN_CRASHPOINTS)  # exactly one case each
    rows = parse_crash_table(CRASH_TABLE)
    assert set(rows) == KNOWN_CRASHPOINTS and len(rows) == len(KNOWN_CRASHPOINTS)  # exactly one row each


@pytest.mark.parametrize("case", CRASH_CASES, ids=lambda c: f"{c.operation}@{c.crashpoint}")
def test_crash_case(trusted_tmp: Path, case: CrashCase) -> None:
    seeded = case.seed(trusted_tmp)
    crash(case, trusted_tmp)  # asserts exit 86 at exactly case.crashpoint
    rt = open_runtime(
        trusted_tmp,
        os_adapters(),
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=case.store_migrations,
        policy_migrations=case.policy_migrations,
    )
    try:
        case.expect(rt, seeded)
        assert rt.store.db_integrity() == "ok"  # a secondary check, never the main oracle
    finally:
        rt.close()
    if case.refused_migrations is not None:  # the unpublished migration really was abandoned
        store_migrations, policy_migrations = case.refused_migrations
        with pytest.raises(BrainError) as e:
            open_runtime(
                trusted_tmp, os_adapters(), store_migrations=store_migrations, policy_migrations=policy_migrations
            )
        assert e.value.code == ErrorCode.MIGRATION_REQUIRED


def test_matrix_detects_a_removed_crashpoint(monkeypatch: pytest.MonkeyPatch, trusted_tmp: Path) -> None:
    (case,) = [c for c in CRASH_CASES if c.crashpoint == "cas.after_rename"]
    case.seed(trusted_tmp)
    monkeypatch.setenv("SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST", "cas.after_rename")  # the child skips this point
    with pytest.raises(AssertionError) as e:
        crash(case, trusted_tmp)
    assert "returncode=0, hit=None" in str(e.value)  # the operation ran to completion instead of crashing
