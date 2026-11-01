"""The crash-point table as data: one ``CrashCase`` per registered crashpoint (spec 5.4, plan Task 16).

Each case seeds ACKed state in this process, has a child process (``crash_child.py``) crash at its point with exit
86, and then checks concrete state in the runtime ``test_crash_matrix`` reopens: ledger entries, holders, the
effect of a policy intent, trust generation and high-water mark, writer epoch, schema version, incomplete backups
and the directories a swap set aside. ``docs/design/sp1-crash-table.md`` (``CRASH_TABLE``) is the same table in
prose, one row per crashpoint; ``parse_crash_table`` reads its first column.

The seeds and expectations are those of the focused crash tests in ``tests/storage``, reused through their helpers.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import BackupKind, verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import LedgerEntry
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, read_schema_info
from superbrain.storage.store import Store
from superbrain.storage.writer import acquire_writer
from tests.storage.conftest import DEMO_KINDS, STORE_ID
from tests.storage.test_backup import only_backup_dir, verify_store
from tests.storage.test_migrate import POLICY_V2, STORE_V2
from tests.storage.test_restore import (
    count_entries,
    every_original_dir_still_exists,
    generation_in,
    markers,
    seed_before_backup_after,
    seed_policy_backup,
)
from tests.support.crash import REPO, ChildResult, run_until_crash
from tests.support.crash_child import EVENT_ID, EVENT_PAYLOAD

CRASH_TABLE = REPO / "docs" / "design" / "sp1-crash-table.md"
EVENT_DIGEST = digest_bytes(EVENT_PAYLOAD)
PAYLOAD_DIGEST = digest_bytes(b"payload")  # what crash_child.put_and_hold stores


@dataclass(frozen=True)
class SeedState:
    """The ACKed state just before the crashing operation started, read back through a runtime."""

    store_id: str
    epoch: int
    """The writer epoch of the last runtime opened while seeding."""
    generation: int
    """The trust generation, equal to the lock's high-water mark after that open."""
    entries: tuple[LedgerEntry, ...]


@dataclass(frozen=True)
class CrashCase:
    operation: str
    crashpoint: str
    seed: Callable[[Path], SeedState]
    expect: Callable[[Runtime, SeedState], None]
    store_migrations: Sequence[Migration] = STORE_MIGRATIONS
    policy_migrations: Sequence[Migration] = POLICY_MIGRATIONS
    args: tuple[str, ...] = ()
    refused_migrations: tuple[Sequence[Migration], Sequence[Migration]] | None = None
    """``(store, policy)`` migrations that, once the recovered runtime is closed, must still be refused with
    ``MIGRATION_REQUIRED``: the crash came before the migrated copy was published."""


def crash(case: CrashCase, data_root: Path) -> ChildResult:
    """Run ``case.operation`` in a child that must exit 86 at exactly ``case.crashpoint``."""
    return run_until_crash(case.operation, case.crashpoint, data_root, *case.args)


def parse_crash_table(path: Path) -> list[str]:
    """The crashpoints of ``path``'s table rows, in order: every markdown table row whose first cell is a name in
    backticks (``| `ledger.after_commit` | ...``). Header, separator and prose lines are ignored."""
    row = re.compile(r"^\|\s*`([a-z_]+(?:\.[a-z_]+)+)`\s*\|")
    return [m.group(1) for line in path.read_text(encoding="utf-8").splitlines() if (m := row.match(line))]


# --- seeding -----------------------------------------------------------------------------------------------------


def capture(data_root: Path) -> SeedState:
    """Open the seeded data root once and record what the expectations compare against."""
    rt = open_runtime(data_root, os_adapters(), kinds=KindRegistry(DEMO_KINDS))
    try:
        generation = rt.policy.trust_generation()
        assert rt.lease.state().trust_generation_hwm == generation
        return SeedState(rt.store.store_id, rt.lease.epoch, generation, tuple(rt.store.entries()))
    finally:
        rt.close()


def seed_named_store(data_root: Path) -> SeedState:
    """A policy store and an empty main store bound to ``STORE_ID``, the id the ``append_demo`` and
    ``put_and_hold`` children open the store with."""
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        try:
            Store.create(root, lease, os_, policy, (), KindRegistry(DEMO_KINDS)).close()
        finally:
            policy.close()
    return capture(data_root)


def seed_event(data_root: Path) -> SeedState:
    """The event payload held by ``("event", EVENT_ID)``, as ``crash_child.seed_event`` does."""
    rt = open_runtime(data_root, os_adapters())
    try:
        rt.store.store_content(EVENT_PAYLOAD, "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
    finally:
        rt.close()
    return capture(data_root)


def seed_quarantined_event(data_root: Path) -> SeedState:
    """The event payload, held and then quarantined: the intent is recorded and applied to the store."""
    rt = open_runtime(data_root, os_adapters())
    try:
        rt.store.store_content(EVENT_PAYLOAD, "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": EVENT_DIGEST})
        assert rt.store.reconcile_policy() == 1
    finally:
        rt.close()
    return capture(data_root)


def seed_runtime(data_root: Path) -> SeedState:
    open_runtime(data_root, os_adapters()).close()
    return capture(data_root)


def seed_restore(data_root: Path) -> SeedState:
    seed_before_backup_after(data_root)
    return capture(data_root)


def seed_policy_restore(data_root: Path) -> SeedState:
    assert seed_policy_backup(data_root) == 5
    return capture(data_root)


# --- shared checks -----------------------------------------------------------------------------------------------


def check_epoch(rt: Runtime, seed: SeedState, acquired: int) -> None:
    """``acquired`` epochs were taken since seeding (the crashed child's, if it got one, and the matrix's own);
    a swap the crash interrupted never bumps it, and neither does its recovery."""
    assert rt.lease.epoch == seed.epoch + acquired


def check_generation(rt: Runtime, generation: int) -> None:
    assert rt.policy.trust_generation() == generation == rt.lease.state().trust_generation_hwm


def set_aside(rt: Runtime, target: str) -> list[tuple[str, Path]]:
    """``(label, path)`` of every ``<target>.*`` directory, e.g. ``("store.replaced", ...)``."""
    found = [(p.name.split("-")[0], p) for p in rt.root.root.iterdir() if p.name.startswith(f"{target}.")]
    return sorted(found)


def schema_version(path: Path) -> int:
    info = read_schema_info(path)
    assert info is not None
    return info.schema_version


def check_event_held(rt: Runtime) -> None:
    assert rt.store.cas.holders(EVENT_DIGEST) == [("event", EVENT_ID, RetentionClass.EVENT_PAYLOAD)]
    assert rt.store.cas.read(EVENT_DIGEST) == EVENT_PAYLOAD


def check_quarantined(rt: Runtime) -> None:
    assert rt.policy.is_quarantined(EVENT_DIGEST) and count_entries(rt.store, "policy.quarantine") == 1
    with pytest.raises(BrainError) as e:
        rt.store.cas.read(EVENT_DIGEST)
    assert e.value.code == ErrorCode.QUARANTINED and rt.store.reconcile_policy() == 0


# --- expectations ------------------------------------------------------------------------------------------------


def expect_torn_slot(rt: Runtime, seed: SeedState) -> None:
    """The torn slot is ignored: the crashed acquire never counted, so this open has the next epoch."""
    check_epoch(rt, seed, 1)
    check_generation(rt, seed.generation)
    assert tuple(rt.store.entries()) == seed.entries


def expect_no_entry(rt: Runtime, seed: SeedState) -> None:
    check_epoch(rt, seed, 2)
    assert tuple(rt.store.entries()) == seed.entries == ()


def expect_one_entry(rt: Runtime, seed: SeedState) -> None:
    check_epoch(rt, seed, 2)
    entries = tuple(rt.store.entries())
    assert len(entries) == len(seed.entries) + 1 and entries[:-1] == seed.entries
    assert (entries[-1].kind, dict(entries[-1].meta)) == ("demo.count", {"n": 1})


def expect_no_blob(rt: Runtime, seed: SeedState) -> None:
    check_epoch(rt, seed, 2)
    assert not rt.store.cas.exists(PAYLOAD_DIGEST) and rt.store.cas.orphans() == []
    assert list(rt.root.staging_dir.iterdir()) == [] and tuple(rt.store.entries()) == seed.entries


def expect_orphan_blob(rt: Runtime, seed: SeedState) -> None:
    check_epoch(rt, seed, 2)
    assert rt.store.cas.orphans() == [PAYLOAD_DIGEST] and rt.store.cas.holders(PAYLOAD_DIGEST) == []
    assert rt.store.cas.read(PAYLOAD_DIGEST) == b"payload" and tuple(rt.store.entries()) == seed.entries


def expect_tombstoned_once(rt: Runtime, seed: SeedState) -> None:
    """Recorded in the policy store before the crash, applied exactly once: by the reopen or before the crash."""
    check_epoch(rt, seed, 2)
    assert rt.policy.is_tombstoned("event", EVENT_ID) and len(rt.policy.intents()) == 1
    assert rt.store.cas.holders(EVENT_DIGEST) == [] and rt.store.cas.orphans() == [EVENT_DIGEST]
    assert count_entries(rt.store, "policy.tombstone") == 1 and count_entries(rt.store, "cas.release") == 1
    assert rt.store.reconcile_policy() == 0


def expect_incomplete_backup(*, blobs_copied: bool) -> Callable[[Runtime, SeedState], None]:
    def expect(rt: Runtime, seed: SeedState) -> None:
        """The store is untouched (no persistent pin to undo) and the half-made backup never verifies."""
        check_epoch(rt, seed, 2)
        check_event_held(rt)
        assert tuple(rt.store.entries()) == seed.entries
        partial = only_backup_dir(rt.root)
        assert partial.name.startswith("store-") and not (partial / "manifest.json").exists()
        assert (partial / "brain.db").is_file() and (partial / "cas").is_dir() == blobs_copied
        with pytest.raises(BrainError) as e:
            verify_store(partial, seed.store_id)
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE

    return expect


def expect_store_restore(*, published: bool) -> Callable[[Runtime, SeedState], None]:
    def expect(rt: Runtime, seed: SeedState) -> None:
        """Before the first rename the stage is set aside; between the renames the backup is published."""
        check_epoch(rt, seed, 2)
        check_generation(rt, seed.generation)
        assert markers(rt.store) == (["before"] if published else ["before", "after"])
        assert every_original_dir_still_exists(rt.root.root)
        label = "store.replaced" if published else "store.restoring.abandoned"
        assert [name for name, _ in set_aside(rt, "store")] == [label]

    return expect


def expect_policy_restore(*, published: bool, epoch_bumped: bool) -> Callable[[Runtime, SeedState], None]:
    def expect(rt: Runtime, seed: SeedState) -> None:
        """The generation never goes down or gets reused: published, it is one above everything before it, and
        the lock's mark catches up on open; not published, the staged generation is set aside unused."""
        staged = seed.generation + 1
        check_epoch(rt, seed, 3 if epoch_bumped else 2)
        check_generation(rt, staged if published else seed.generation)
        ((label, aside),) = set_aside(rt, "policy")
        assert label == ("policy.replaced" if published else "policy.restoring.abandoned")
        assert generation_in(aside / "policy.db") == (seed.generation if published else staged)
        assert rt.policy.store_id == rt.store.store_id == seed.store_id and rt.store.reconcile_policy() == 0

    return expect


def expect_migration(*, target: Literal["store", "policy"], published: bool) -> Callable[[Runtime, SeedState], None]:
    def expect(rt: Runtime, seed: SeedState) -> None:
        """The verified backup exists either way; the data is the same in the old and the migrated schema."""
        check_epoch(rt, seed, 2)
        check_generation(rt, seed.generation)
        live = rt.root.store_db if target == "store" else rt.root.policy_db
        assert schema_version(live) == (2 if published else 1)
        ((label, aside),) = set_aside(rt, target)
        assert label == (f"{target}.replaced" if published else f"{target}.migrating.abandoned")
        if published:
            assert schema_version(aside / live.name) == 1
        kind: BackupKind = "store_full" if target == "store" else "policy"
        (backup,) = [p for p in rt.root.backups_dir.iterdir() if p.name.startswith(f"{kind}-")]
        base = STORE_MIGRATIONS if target == "store" else POLICY_MIGRATIONS
        verify_backup(backup, expected_kind=kind, expected_store_id=seed.store_id, migrations=base, os_=os_adapters())
        assert tuple(rt.store.entries()) == seed.entries
        if target == "store":
            check_event_held(rt)
        else:
            check_quarantined(rt)

    return expect


# --- the table ---------------------------------------------------------------------------------------------------

_NAMED = (STORE_ID,)
_V1_REFUSED_BY_STORE_V2 = (STORE_V2, POLICY_MIGRATIONS)
_V1_REFUSED_BY_POLICY_V2 = (STORE_MIGRATIONS, POLICY_V2)

CRASH_CASES: tuple[CrashCase, ...] = (
    CrashCase("acquire_writer", "writer.mid_slot_write", seed_runtime, expect_torn_slot),
    CrashCase("append_demo", "ledger.before_commit", seed_named_store, expect_no_entry, args=_NAMED),
    CrashCase("append_demo", "ledger.after_commit", seed_named_store, expect_one_entry, args=_NAMED),
    CrashCase("put_and_hold", "cas.after_staging_write", seed_named_store, expect_no_blob, args=_NAMED),
    CrashCase("put_and_hold", "cas.after_rename", seed_named_store, expect_orphan_blob, args=_NAMED),
    CrashCase("tombstone_event", "policy.after_intent_commit", seed_event, expect_tombstoned_once),
    CrashCase("tombstone_event", "intents.after_store_apply", seed_event, expect_tombstoned_once),
    CrashCase("backup_store", "backup.after_db_snapshot", seed_event, expect_incomplete_backup(blobs_copied=False)),
    CrashCase("backup_store", "backup.after_blob_copy", seed_event, expect_incomplete_backup(blobs_copied=True)),
    CrashCase(
        "restore_from_latest", "restoring.store.after_stage", seed_restore, expect_store_restore(published=False)
    ),
    CrashCase(
        "restore_from_latest", "restoring.store.between_renames", seed_restore, expect_store_restore(published=True)
    ),
    CrashCase(
        "restore_policy_from_latest",
        "restoring.policy.after_generation_persist",
        seed_policy_restore,
        expect_policy_restore(published=False, epoch_bumped=False),
    ),
    CrashCase(
        "restore_policy_from_latest",
        "restoring.policy.after_stage",
        seed_policy_restore,
        expect_policy_restore(published=False, epoch_bumped=False),
    ),
    CrashCase(
        "restore_policy_from_latest",
        "restoring.policy.between_renames",
        seed_policy_restore,
        expect_policy_restore(published=True, epoch_bumped=False),
    ),
    CrashCase(
        "restore_policy_from_latest",
        "restoring.policy.before_hwm_update",
        seed_policy_restore,
        expect_policy_restore(published=True, epoch_bumped=True),
    ),
    CrashCase(
        "migrate_store_to_v2",
        "migrating.store.after_stage",
        seed_event,
        expect_migration(target="store", published=False),
        refused_migrations=_V1_REFUSED_BY_STORE_V2,
    ),
    CrashCase(
        "migrate_store_to_v2",
        "migrating.store.between_renames",
        seed_event,
        expect_migration(target="store", published=True),
        store_migrations=STORE_V2,
    ),
    CrashCase(
        "migrate_policy_to_v2",
        "migrating.policy.after_stage",
        seed_quarantined_event,
        expect_migration(target="policy", published=False),
        refused_migrations=_V1_REFUSED_BY_POLICY_V2,
    ),
    CrashCase(
        "migrate_policy_to_v2",
        "migrating.policy.between_renames",
        seed_quarantined_event,
        expect_migration(target="policy", published=True),
        policy_migrations=POLICY_V2,
    ),
)
