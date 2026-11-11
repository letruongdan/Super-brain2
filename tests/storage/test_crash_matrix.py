"""The crash-point table (spec 5.4): every registered crashpoint fires in a real child process, and the reopened data
root holds concrete, expected state. ``docs/design/sp1-crash-table.md`` has exactly one row per crashpoint.

The increment 1 cases (``CRASH_CASES``) run here. The kernel cases of increment 2 Task 8 (``KERNEL_CRASH_CASES``) crash
the installed wheel and run in ``tests/integration/test_kernel_crash_recovery.py``; this module pins the exact name
set across the registry, both case groups and the table."""

from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import KNOWN_CRASHPOINTS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.runtime import open_runtime
from tests.storage.conftest import DEMO_KINDS
from tests.support.crash_cases import (
    CRASH_CASES,
    CRASH_TABLE,
    KERNEL_CRASH_CASES,
    CrashCase,
    crash,
    parse_crash_table,
)

I1_CRASHPOINTS = frozenset(
    {
        "writer.mid_slot_write",
        "ledger.before_commit",
        "ledger.after_commit",
        "cas.after_staging_write",
        "cas.after_rename",
        "policy.after_intent_commit",
        "intents.after_store_apply",
        "backup.after_db_snapshot",
        "backup.after_blob_copy",
        "restoring.store.after_stage",
        "restoring.store.between_renames",
        "restoring.policy.after_generation_persist",
        "restoring.policy.after_stage",
        "restoring.policy.between_renames",
        "restoring.policy.before_hwm_update",
        "migrating.store.after_stage",
        "migrating.store.between_renames",
        "migrating.policy.after_stage",
        "migrating.policy.between_renames",
    }
)
T8_1_CRASHPOINTS = frozenset(
    {
        "daemon.after_bind_before_endpoint",
        "daemon.after_endpoint_publish",
        "kernel.migrate.after_policy_swap",
    }
)
"""Task 8.1's three kernel boundaries."""
T8_2_CRASHPOINTS = frozenset({"kernel.before_commit", "kernel.after_commit_before_response"})
"""Task 8.2's two request-path boundaries. Part 8.3 brings the Task 8 names to all ten (exactly 29 in total)."""


def test_every_known_crashpoint_has_a_case_and_a_doc_row() -> None:
    names = [c.crashpoint for c in CRASH_CASES] + [c.crashpoint for c in KERNEL_CRASH_CASES]
    assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)  # one case per name
    assert set(names) == KNOWN_CRASHPOINTS
    rows = parse_crash_table(CRASH_TABLE)
    assert len(rows) == len(set(rows)), sorted(r for r in rows if rows.count(r) > 1)  # one row per name
    assert set(rows) == KNOWN_CRASHPOINTS


def test_registry_is_exactly_the_increment_1_names_plus_the_task_8_names() -> None:
    assert len(I1_CRASHPOINTS) == 19 and len(T8_1_CRASHPOINTS) == 3 and len(T8_2_CRASHPOINTS) == 2
    assert {c.crashpoint for c in CRASH_CASES} == I1_CRASHPOINTS  # every I1 oracle stays, under its old node ID
    assert {c.crashpoint for c in KERNEL_CRASH_CASES} == T8_1_CRASHPOINTS | T8_2_CRASHPOINTS
    assert KNOWN_CRASHPOINTS == I1_CRASHPOINTS | T8_1_CRASHPOINTS | T8_2_CRASHPOINTS
    assert len(KNOWN_CRASHPOINTS) == 24


def test_kernel_cases_keep_operation_at_crashpoint_ids_and_all_run() -> None:
    """Node IDs stay ``operation@crashpoint``; every kernel operation is one the recovery module parametrizes over."""
    ids = [c.node_id for c in KERNEL_CRASH_CASES]
    assert ids == [f"{c.operation}@{c.crashpoint}" for c in KERNEL_CRASH_CASES] and len(set(ids)) == len(ids)
    assert {c.operation for c in KERNEL_CRASH_CASES} == {"serve", "serve-fixture", "migrate"}
    for case in KERNEL_CRASH_CASES:  # a request-path crashpoint needs a request to reach it, a startup one must not
        assert (case.trigger is not None) == case.crashpoint.startswith(("kernel.before_", "kernel.after_commit"))


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
