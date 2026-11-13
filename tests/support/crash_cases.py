"""The crash-point table as data: one ``CrashCase`` per registered crashpoint (spec 5.4, plan Task 16).

Each case seeds ACKed state in this process, has a child process (``crash_child.py``) crash at its point with exit
86, and then checks concrete state in the runtime ``test_crash_matrix`` reopens: ledger entries, holders, the
effect of a policy intent, trust generation and high-water mark, writer epoch, schema version, incomplete backups
and the directories a swap set aside. ``docs/design/sp1-crash-table.md`` (``CRASH_TABLE``) is the same table in
prose, one row per crashpoint; ``parse_crash_table`` reads its first column.

The seeds and expectations are those of the focused crash tests in ``tests/storage``, reused through their helpers.
"""

import contextlib
import dataclasses
import datetime as dt
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition.client_entry import read_status
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import ENDPOINT_HOST, ENDPOINT_VERSION, Endpoint
from superbrain.core.wire import parse_json
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import BackupKind, verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import ENDPOINT_STAGE_PREFIX, DataRoot, prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import LedgerEntry
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, read_schema_info
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.store import Store
from superbrain.storage.writer import acquire_writer, acquire_writer_unbumped
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
from tests.support.clock import FakeClock
from tests.support.crash import CRASH_EXIT, REPO, ChildResult, _pump, _tagged, run_until_crash
from tests.support.crash_child import EVENT_ID, EVENT_PAYLOAD
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    InstalledServeProcess,
    _rollback_child_setup,
    _win32_descendant_identities_checked,
    _win32_popen_creation_ticks,
    _win32_spawn_in_job,
    _win32_wait_or_terminate_pid,
    _Win32ProcessJob,
    clean_installed_subprocess_env,
    installed_script_path,
    is_writer_lock_held,
    mcp_call_frame,
    mcp_init_frames,
    run_installed_command,
    spawn_installed_brain_serve,
    write_client_profile_file,
    write_credential_file,
    write_daemon_config_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import InstalledEnv
from tests.support.inc2_t8_job_cases import (
    cancel_args,
    expect_cancel,
    expect_lease,
    expect_reserve,
    expect_running,
    expect_settle,
    seed_job,
    seed_usage,
    settle_args,
)
from tests.support.inc2_transport import TransportTemplate, clone_owner_only_tree
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

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


# --- kernel cases (SP1 increment 2, Task 8.1) ---------------------------------------------------------------------
#
# A ``KernelCrashCase`` crashes the installed wheel's owner composition (``inc2_t8_child.py serve|migrate``) instead
# of a ``crash_child.py`` operation. Its seed builds a data root plus an absolute ``DaemonConfig``; its expectation
# reads the state the dead process left (mixed schemas included) without opening a runtime, then drives the installed
# ``brain serve`` / ``brain migrate --offline`` / ``brain-mcp`` for refuse, resume and restart. Node IDs keep the
# ``operation@crashpoint`` form. ``tests/integration/test_kernel_crash_recovery.py`` runs every case.

T8_CHILD = Path(__file__).resolve().with_name("inc2_t8_child.py")
T8_CHILD_TIMEOUT = 60.0
T8_STOP_TIMEOUT = 15.0
_MARKERS = ("PPID", "MODULE", "SCHEMA", "ENTERED", "READY", "CRASHPOINT_HIT", "PAUSED", "DRIVER_ERROR")


@dataclass(frozen=True)
class MarkedRun:
    """One owner process run: exit, output, and the driver's stderr control markers (absent for ``brain``)."""

    result: ChildResult
    launcher_pid: int
    parent_pid: int | None
    entered: tuple[int, str] | None
    """``(pid, start)`` printed by the driver right before the owner operation."""
    ready: Endpoint | None
    """The endpoint the driver printed in ``READY``; the process was then stopped gracefully."""
    timed_out: bool
    owner_stderr: tuple[str, ...]
    """Stderr lines that are not control markers: the owner's own static error code, if any."""

    def describe(self) -> str:
        r = self.result
        return (
            f"returncode={r.returncode}, hit={r.hit!r}, ready={self.ready is not None}, timed_out={self.timed_out}\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )


def _stop_tree(
    proc: "subprocess.Popen[str]",
    *,
    job: _Win32ProcessJob | None = None,
) -> None:
    """Graceful foreground stop (CTRL_BREAK / SIGTERM to the process group), then kill whatever is left."""
    root_ticks = _win32_popen_creation_ticks(proc) if sys.platform == "win32" else None
    job_handle = job.handle if (job is not None and job.assigned) else None
    tracked: list[tuple[int, int]] = []
    if sys.platform == "win32" and root_ticks is not None:
        tracked, _ = _win32_descendant_identities_checked(
            proc.pid, root_ticks=root_ticks, job_handle=job_handle
        )
    with contextlib.suppress(OSError, ValueError):
        if sys.platform == "win32":
            os.kill(proc.pid, int(signal.CTRL_BREAK_EVENT))
        else:
            proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=T8_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=T8_STOP_TIMEOUT)
    if sys.platform == "win32":
        if job is not None and job.assigned:
            job.terminate_and_wait(timeout_s=T8_STOP_TIMEOUT)
        for pid, ticks in tracked:
            with contextlib.suppress(Exception):
                _win32_wait_or_terminate_pid(
                    pid,
                    expected_ticks=ticks,
                    job_handle=job_handle,
                    terminate=True,
                    timeout_s=T8_STOP_TIMEOUT,
                )
        if root_ticks is not None:
            with contextlib.suppress(Exception):
                _win32_wait_or_terminate_pid(
                    proc.pid,
                    expected_ticks=root_ticks,
                    job_handle=job_handle,
                    terminate=True,
                    timeout_s=T8_STOP_TIMEOUT,
                )


def run_marked(
    cmd: Sequence[str],
    *,
    cwd: Path,
    crashpoint: str | None = None,
    while_ready: Callable[[Endpoint], None] | None = None,
    timeout: float = T8_CHILD_TIMEOUT,
) -> MarkedRun:
    """Run ``cmd`` in a clean environment (``SUPERBRAIN_CRASHPOINT=crashpoint`` when given) until it exits.

    On ``READY`` the process is alive and serving: ``while_ready(endpoint)`` runs, then the process is stopped
    gracefully and its exit is recorded. A process that neither exits nor reports ``READY`` within ``timeout`` is
    stopped and reported with ``timed_out=True``. No sleep orders anything: every step waits on the child's output.
    """
    extra = {"SUPERBRAIN_CRASHPOINT": crashpoint} if crashpoint is not None else None
    child_env = clean_installed_subprocess_env(extra)
    job: _Win32ProcessJob | None = _Win32ProcessJob(kill_on_close=True) if sys.platform == "win32" else None
    proc, _job_assigned = _win32_spawn_in_job(
        job,
        list(cmd),
        cwd=cwd,
        env=child_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if sys.platform == "win32" else 0,
        start_new_session=sys.platform != "win32",
    )
    pumps: list[threading.Thread] = []
    with _rollback_child_setup(proc, job, readers=pumps):
        if sys.platform == "win32" and not _job_assigned:
            raise RuntimeError("run_marked requires Win32 Job Object assignment")
        assert proc.stdout is not None and proc.stderr is not None
        stderr_lines: queue.Queue[str | None] = queue.Queue()
        stdout_box: list[str] = []
        out = proc.stdout
        pumps.extend((
            threading.Thread(target=lambda: stdout_box.append(out.read()), daemon=True),
            threading.Thread(target=_pump, args=(proc.stderr, stderr_lines), daemon=True),
        ))
        for pump in pumps:
            pump.start()

    seen: list[str] = []
    ready: Endpoint | None = None
    timed_out = False
    end = time.monotonic() + timeout
    try:
        while True:
            try:
                line = stderr_lines.get(timeout=max(0.0, end - time.monotonic()))
            except queue.Empty:
                timed_out = True
                break
            if line is None:
                break
            seen.append(line)
            if line.startswith("READY ") and ready is None:
                ready = Endpoint.from_canonical(line[len("READY ") :].strip().encode("utf-8"))
                if while_ready is not None:
                    while_ready(ready)
                _stop_tree(proc, job=job)
    finally:
        try:
            if proc.poll() is None:
                _stop_tree(proc, job=job)
            elif sys.platform == "win32" and job is not None and job.assigned:
                job.terminate_and_wait(timeout_s=T8_STOP_TIMEOUT)
            proc.wait(timeout=T8_STOP_TIMEOUT)
            for pump in pumps:
                pump.join(timeout=T8_STOP_TIMEOUT)
        finally:
            if job is not None:
                job.close()
    while not stderr_lines.empty():
        rest = stderr_lines.get_nowait()
        if rest is not None:
            seen.append(rest)
    stderr = "".join(seen)
    entered = _tagged(stderr, "ENTERED")
    parent = _tagged(stderr, "PPID")
    owner = tuple(s for s in (ln.strip() for ln in seen) if s and s.split(" ")[0] not in _MARKERS)
    pid_text, _, start_text = (entered or "").partition(" ")
    return MarkedRun(
        result=ChildResult(
            returncode=proc.returncode,
            stdout="".join(stdout_box),
            stderr=stderr,
            error_code=owner[-1] if owner else None,
            hit=_tagged(stderr, "CRASHPOINT_HIT"),
        ),
        launcher_pid=proc.pid,
        parent_pid=int(parent) if parent is not None else None,
        entered=(int(pid_text), start_text) if entered is not None else None,
        ready=ready,
        timed_out=timed_out,
        owner_stderr=owner,
    )


def t8_child_command(env: InstalledEnv, mode: str, config: Path, args: Sequence[str] = ()) -> list[str]:
    return [str(env.venv_python), "-I", str(T8_CHILD), mode, str(config), *args]


def run_t8_child(
    env: InstalledEnv,
    mode: str,
    config: Path,
    *,
    cwd: Path,
    crashpoint: str | None = None,
    while_ready: Callable[[Endpoint], None] | None = None,
    args: Sequence[str] = (),
) -> MarkedRun:
    cmd = t8_child_command(env, mode, config, args)
    return run_marked(cmd, cwd=cwd, crashpoint=crashpoint, while_ready=while_ready)


def assert_entered(run: MarkedRun) -> None:
    """The driver printed ``ENTERED`` with this launch's real PID (itself, or the venv redirector's child)."""
    assert run.entered is not None, f"no ENTERED marker\n{run.describe()}"
    pid, start = run.entered
    assert pid == run.launcher_pid or run.parent_pid == run.launcher_pid, (
        f"ENTERED pid {pid} (ppid {run.parent_pid}) is not launch {run.launcher_pid}\n{run.describe()}"
    )
    assert pid > 0 and start, run.describe()


def assert_t8_crashed(run: MarkedRun, crashpoint: str) -> None:
    """This invocation printed ``CRASHPOINT_HIT <crashpoint>`` and exited 86, after ``ENTERED``, before ``READY``."""
    r = run.result
    assert r.returncode == CRASH_EXIT and r.hit == crashpoint and run.ready is None and not run.timed_out, (
        f"did not crash at {crashpoint!r}: {run.describe()}"
    )
    assert_entered(run)
    assert r.stderr.index("ENTERED ") < r.stderr.index("CRASHPOINT_HIT "), run.describe()
    assert r.stdout == "", run.describe()


@dataclass(frozen=True)
class KernelCrashContext:
    env: InstalledEnv
    template: TransportTemplate
    case_dir: Path
    """Trusted, owner-only directory of this case: data root, config, client files."""
    cwd: Path
    """Working directory of every child, outside the checkout."""


@dataclass(frozen=True)
class KernelSeed:
    data_root: Path
    config: Path
    store_id: str
    epoch: int
    """The writer epoch in ``writer.lock`` once seeding finished."""
    snapshot: dict[str, list[tuple[object, ...]]]
    stale: Endpoint | None = None
    """An ``endpoint.json`` of a previous epoch present before the crashing run."""
    notes: dict[str, object] = dataclasses.field(default_factory=dict)
    """What a request-triggered crash observed (the old shim's response frame), for the expectation."""


@dataclass(frozen=True)
class KernelCrashCase:
    operation: Literal["serve", "serve-fixture", "migrate", "serve-jobs", "job-operation"]
    """The ``inc2_t8_child.py`` mode."""
    crashpoint: str
    seed: Callable[[KernelCrashContext], KernelSeed]
    expect: Callable[[KernelCrashContext, KernelSeed, MarkedRun], None]
    trigger: Callable[[KernelCrashContext, KernelSeed, Endpoint], None] | None = None
    """For a crashpoint on a request path: runs once the daemon is READY (the crash must come from it)."""
    args: Callable[[KernelSeed], tuple[str, ...]] | None = None
    """Optional driver arguments derived from the seed's pinned job/principal/invocation IDs."""

    @property
    def node_id(self) -> str:
        return f"{self.operation}@{self.crashpoint}"


def run_kernel_case(case: KernelCrashCase, ctx: KernelCrashContext) -> None:
    seeded = case.seed(ctx)
    args = case.args(seeded) if case.args is not None else ()
    if case.trigger is None:
        run = run_t8_child(ctx.env, case.operation, seeded.config, cwd=ctx.cwd, crashpoint=case.crashpoint, args=args)
        assert_t8_crashed(run, case.crashpoint)
    else:
        trigger = case.trigger
        run = run_t8_child(
            ctx.env,
            case.operation,
            seeded.config,
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
            while_ready=lambda ready: trigger(ctx, seeded, ready),
            args=args,
        )
        assert_request_crashed(run, case.crashpoint)
    case.expect(ctx, seeded, run)


def assert_request_crashed(run: MarkedRun, crashpoint: str) -> None:
    """The daemon reached READY, then the triggering request made this invocation exit 86 at ``crashpoint``."""
    r = run.result
    assert r.returncode == CRASH_EXIT and r.hit == crashpoint and run.ready is not None and not run.timed_out, (
        f"the request did not crash the daemon at {crashpoint!r}: {run.describe()}"
    )
    assert_entered(run)
    assert r.stderr.index("READY ") < r.stderr.index("CRASHPOINT_HIT "), run.describe()


# --- kernel reads without a runtime --------------------------------------------------------------------------------


def lock_epoch(data_root: Path) -> int:
    """The writer epoch recorded in ``writer.lock``, read under the lock without bumping it."""
    lease = acquire_writer_unbumped(DataRoot.at(data_root), os_adapters())
    try:
        return lease.epoch
    finally:
        lease.release()


def _rows(db_path: Path, scratch: Path, sql: str) -> list[tuple[object, ...]]:
    scratch.mkdir(exist_ok=True)
    with contextlib.closing(open_readonly(db_path, scratch_dir=scratch)) as db:
        return [tuple(row) for row in db.execute(sql)]


def store_rows(data_root: Path, scratch: Path) -> dict[str, list[tuple[object, ...]]]:
    db = DataRoot.at(data_root).store_db
    return {
        "ledger": _rows(db, scratch, "SELECT sequence, entry_id, kind FROM ledger ORDER BY sequence"),
        "applied_intents": _rows(db, scratch, "SELECT intent_id, applied_sequence FROM applied_intents ORDER BY 1"),
    }


def pair_rows(data_root: Path, scratch: Path) -> dict[str, list[tuple[object, ...]]]:
    """IDs, intents and authority of both databases, in whatever schema each one is."""
    db = DataRoot.at(data_root).policy_db
    return {
        **store_rows(data_root, scratch),
        "intents": _rows(db, scratch, "SELECT intent_id, kind, payload FROM intents ORDER BY intent_id"),
        "quarantine": _rows(db, scratch, "SELECT digest, intent_id FROM quarantine ORDER BY digest"),
        "trust": _rows(db, scratch, "SELECT generation FROM trust"),
        "principal": _rows(db, scratch, "SELECT id, owner_id, harness_id, machine_id FROM principal ORDER BY id"),
        "credential": _rows(
            db, scratch, "SELECT id, principal_id, secret_digest, revoked_intent_id FROM credential ORDER BY id"
        ),
        "request_digest_key": _rows(db, scratch, "SELECT id, active FROM request_digest_key ORDER BY id"),
    }


def schema_versions(data_root: Path) -> tuple[int, int]:
    """``(policy, store)`` schema versions."""
    root = DataRoot.at(data_root)
    return schema_version(root.policy_db), schema_version(root.store_db)


def endpoint_stages(data_root: Path) -> list[str]:
    return sorted(p.name for p in data_root.iterdir() if p.name.startswith(ENDPOINT_STAGE_PREFIX))


def _free_loopback_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((ENDPOINT_HOST, 0))
        return int(sock.getsockname()[1])


# --- kernel client probes ------------------------------------------------------------------------------------------


def _client_profile(ctx: KernelCrashContext, seed: KernelSeed, name: str, endpoint_path: Path) -> Path:
    tls = ctx.template.tls
    client = ctx.case_dir / "client"
    cred = client / "credential.txt"
    if not cred.exists():
        write_credential_file(cred, ctx.template.cred.token)
    profile, _ = write_client_profile_file(
        client / f"profile-{name}.json",
        endpoint_path=endpoint_path,
        expected_store_id=seed.store_id,
        ca_file=tls.ca_cert_path,
        leaf_cert_sha256=tls.leaf_cert_sha256,
        credential_file=cred,
    )
    return profile


def assert_old_tuple_refused(
    ctx: KernelCrashContext, seed: KernelSeed, old: Endpoint, name: str, allowed: frozenset[str]
) -> str:
    """A shallow ``get_health`` aimed at ``old`` fails closed with one of ``allowed``; returns the code."""
    tuple_file = write_owner_only_bytes(ctx.case_dir / "client" / f"tuple-{name}.json", old.encode_canonical())
    envelope = read_status(_client_profile(ctx, seed, name, tuple_file), os_adapters())
    error = envelope.get("error")
    assert envelope.get("ok") is False and isinstance(error, dict), f"old tuple {name} was served: {envelope!r}"
    assert error.get("code") in allowed, f"old tuple {name}: {envelope!r}"
    return str(error["code"])


def _tool_result(frame: dict[str, JsonValue]) -> dict[str, JsonValue]:
    result = frame.get("result")
    assert "error" not in frame and isinstance(result, dict), frame
    content = result.get("structuredContent")
    assert isinstance(content, dict), frame
    return content


def shim_health_and_job(
    ctx: KernelCrashContext, seed: KernelSeed, job_id: str
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Shallow ``get_health`` and global ``get_job`` through the installed ``brain-mcp`` on the live endpoint."""
    profile = _client_profile(ctx, seed, "live", DataRoot.at(seed.data_root).endpoint_path)
    init, initialized = mcp_init_frames(1)
    with InstalledMcpPipeSession(ctx.env, "brain-mcp", ("--profile", str(profile)), cwd=ctx.cwd) as shim:
        assert shim.send_frames_and_expect_response([init], timeout=10.0).get("id") == 1
        health = shim.send_frames_and_expect_response(
            [initialized, mcp_call_frame(2, "get_health", {"schema_version": "2.0"})], timeout=10.0
        )
        job = shim.send_frames_and_expect_response(
            [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_id})], timeout=10.0
        )
        rc, stderr = shim.finish()
    assert rc == 0 and stderr == b"", (rc, stderr)
    return _tool_result(health), _tool_result(job)


# --- kernel seeds --------------------------------------------------------------------------------------------------


def _seed_daemon_root(ctx: KernelCrashContext, *, stale_endpoint: bool) -> KernelSeed:
    """A clone of the session's admitted (store 4, policy 3) template: credentials, workspaces, two ACKed jobs."""
    tpl = ctx.template
    data_root = ctx.case_dir / "data"
    clone_owner_only_tree(tpl.root, data_root)
    config = write_daemon_config_file(
        ctx.case_dir / "daemon-config.json",
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=tpl.tls.cert_path,
        key_path=tpl.tls.key_path,
    )
    epoch = lock_epoch(data_root)
    stale = None
    if stale_endpoint:
        stale = Endpoint(
            version=ENDPOINT_VERSION,
            host=ENDPOINT_HOST,
            port=_free_loopback_port(),
            store_id=tpl.store_id,
            writer_epoch=epoch,
            instance_id=new_id(),
        )
        write_owner_only_bytes(DataRoot.at(data_root).endpoint_path, stale.encode_canonical())
    snapshot = store_rows(data_root, ctx.case_dir / "ro-scratch")
    assert snapshot["ledger"], "the seeded root must hold ACKed ledger entries"
    return KernelSeed(data_root, config, tpl.store_id, epoch, snapshot, stale)


def seed_daemon_root_with_stale_endpoint(ctx: KernelCrashContext) -> KernelSeed:
    return _seed_daemon_root(ctx, stale_endpoint=True)


def seed_daemon_root(ctx: KernelCrashContext) -> KernelSeed:
    return _seed_daemon_root(ctx, stale_endpoint=False)


def seed_legacy_pair(ctx: KernelCrashContext) -> KernelSeed:
    """An increment 1 pair at (store 2, policy 2): two durable blobs, a quarantine intent applied to the store, an
    active credential, and TLS material for its own store id."""
    clock = FakeClock(dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=5))
    adapters = os_adapters(clock=clock)
    data_root = ctx.case_dir / "data"
    rt = open_runtime(
        data_root,
        adapters,
        store_migrations=KERNEL_STORE_MIGRATIONS[:2],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:2],
    )
    try:
        rt.store.store_content(b"t8-legacy-durable", "evidence", new_id(), RetentionClass.DURABLE, None)
        blocked = rt.store.store_content(b"t8-legacy-quarantined", "evidence", new_id(), RetentionClass.DURABLE, None)
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": blocked})
        assert rt.store.reconcile_policy() == 1
        seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1")
        store_id, generation = rt.store.store_id, rt.policy.trust_generation()
    finally:
        rt.close()
    auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id,
        trust_generation=generation,
        expires_at=clock.now() + dt.timedelta(hours=2),
        destination=ctx.case_dir / "tls",
    )
    tls = create_store_tls(store_id, ctx.case_dir / "tls", auth, clock, adapters)
    config = write_daemon_config_file(
        ctx.case_dir / "daemon-config.json",
        data_root=data_root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
    )
    assert schema_versions(data_root) == (2, 2)
    snapshot = pair_rows(data_root, ctx.case_dir / "ro-scratch")
    assert snapshot["intents"] and snapshot["quarantine"] and snapshot["credential"] and snapshot["ledger"]
    return KernelSeed(data_root, config, store_id, lock_epoch(data_root), snapshot)


# --- kernel expectations -------------------------------------------------------------------------------------------

_DEAD_TUPLE_CODES = frozenset(
    {ErrorCode.DAEMON_UNAVAILABLE.value, ErrorCode.IDENTITY_MISMATCH.value, ErrorCode.DEADLINE_EXCEEDED.value}
)
"""Nothing listens on the dead port: refused at once (POSIX) or after Windows' loopback SYN retries ran out the
client's 2 s connect budget. Every one of them is a fail-closed refusal with no request sent."""
_REUSED_PORT_CODES = frozenset({ErrorCode.IDENTITY_MISMATCH.value})


def _wait_for_new_endpoint(serve: InstalledServeProcess, old: Sequence[Endpoint]) -> Endpoint:
    """``wait_ready`` returns whatever ``endpoint.json`` holds; skip the old descriptors still on disk."""
    old_ids = {o.identity for o in old}
    deadline = time.monotonic() + T8_CHILD_TIMEOUT
    while (current := serve.wait_ready()).identity in old_ids:
        assert time.monotonic() < deadline, "the restarted daemon never replaced the old endpoint.json"
        time.sleep(0.01)
    return current


def assert_acked_kept(seed: KernelSeed, after: dict[str, list[tuple[object, ...]]]) -> None:
    """Every ACKed ledger entry is still there, in order and unchanged (recovery may append), and no applied intent
    was lost."""
    acked = seed.snapshot["ledger"]
    assert after["ledger"][: len(acked)] == acked, "ACKed ledger entries changed or vanished"
    assert set(seed.snapshot["applied_intents"]) <= set(after["applied_intents"]), "applied intents were lost"


def expect_daemon_restart(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun, dead: Endpoint | None) -> None:
    """Shared by both daemon crashpoints, after the case-specific check of what the dead process left on disk.

    The dead process took the next epoch and released the lock by dying. Its own published tuple fails closed while
    nothing serves it. Every old tuple (the stale one of the epoch before, and the dead process's own) fails closed
    again once a new daemon listens on its port. The installed ``brain serve`` then takes the lease (epoch + 2, new
    instance), its endpoint matches that lease, and shallow ``get_health`` and the ACKed global job answer through
    the installed ``brain-mcp``. While it is alive a second owner is fenced with ``writer_held`` (and, never reaching
    the hook, prints no hit).
    """
    root = DataRoot.at(seed.data_root)
    assert is_writer_lock_held(seed.data_root) is False
    assert lock_epoch(seed.data_root) == seed.epoch + 1, "the crashed owner must have taken exactly one epoch"
    old = [e for e in (seed.stale, dead) if e is not None]
    if dead is not None:  # the retry of the dead process's own tuple
        assert_old_tuple_refused(ctx, seed, dead, "dead", _DEAD_TUPLE_CODES)
    assert ctx.template.global_job_id is not None

    with spawn_installed_brain_serve(ctx.env, seed.config, data_root=seed.data_root, cwd=ctx.cwd) as serve:
        current = _wait_for_new_endpoint(serve, old)
        assert current.store_id == seed.store_id and current.writer_epoch == seed.epoch + 2
        assert all(current.instance_id != o.instance_id for o in old)
        assert root.endpoint_path.read_bytes() == current.encode_canonical()
        for i, ep in enumerate(old):  # the old tuple aimed at the port a new daemon now listens on
            reused = dataclasses.replace(ep, port=current.port)
            assert_old_tuple_refused(ctx, seed, reused, f"reused-{i}", _REUSED_PORT_CODES)

        health, job = shim_health_and_job(ctx, seed, ctx.template.global_job_id)
        assert health.get("ok") is True, health
        h = health["data"]
        assert isinstance(h, dict) and h.get("ready") is True, health
        assert (h.get("store_id"), h.get("writer_epoch")) == (seed.store_id, current.writer_epoch), health
        assert job.get("ok") is True, job
        j = job["data"]
        assert isinstance(j, dict) and j.get("job_id") == ctx.template.global_job_id, job

        fenced = run_t8_child(ctx.env, "serve", seed.config, cwd=ctx.cwd, crashpoint=run.result.hit)
        assert (fenced.result.returncode, fenced.result.error_code) == (1, ErrorCode.WRITER_HELD.value), (
            fenced.describe()
        )
        assert fenced.result.hit is None and fenced.ready is None, fenced.describe()
        assert_entered(fenced)
        assert root.endpoint_path.read_bytes() == current.encode_canonical()

        rc, _, _, _ = serve.signal_and_wait_exit()
        assert rc == 0
    assert not root.endpoint_path.exists()
    assert_acked_kept(seed, store_rows(seed.data_root, ctx.case_dir / "ro-scratch"))


def expect_crash_after_bind(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    """Bound but never published: ``endpoint.json`` still holds the previous epoch's bytes, no stage is left."""
    assert seed.stale is not None
    assert DataRoot.at(seed.data_root).endpoint_path.read_bytes() == seed.stale.encode_canonical()
    assert endpoint_stages(seed.data_root) == []
    assert_acked_kept(seed, store_rows(seed.data_root, ctx.case_dir / "ro-scratch"))
    expect_daemon_restart(ctx, seed, run, dead=None)


def expect_crash_after_publish(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    """Published but never ready: the dead process's endpoint (its epoch, the seeded store) is what clients see."""
    dead = read_client_endpoint(DataRoot.at(seed.data_root).endpoint_path, os_adapters())
    assert (dead.store_id, dead.writer_epoch) == (seed.store_id, seed.epoch + 1)
    assert endpoint_stages(seed.data_root) == []
    assert_acked_kept(seed, store_rows(seed.data_root, ctx.case_dir / "ro-scratch"))
    expect_daemon_restart(ctx, seed, run, dead=dead)


def _owner_envelope(done: "subprocess.CompletedProcess[bytes]") -> dict[str, JsonValue]:
    assert done.returncode == 0 and done.stderr == b"", (done.returncode, done.stdout, done.stderr)
    envelope = parse_json(done.stdout.strip())
    assert isinstance(envelope, dict) and envelope.get("ok") is True, envelope
    data = envelope["data"]
    assert isinstance(data, dict), envelope
    return data


def expect_crash_after_policy_swap(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    """Policy published at v3, store still v2 and untouched; ``brain serve`` refuses, ``brain migrate --offline``
    resumes only the store, a repeat is a no-op, and neither run fires the hook again although its env stays set."""
    data_root, scratch = seed.data_root, ctx.case_dir / "ro-scratch"
    root = DataRoot.at(data_root)
    assert schema_versions(data_root) == (3, 2)
    aside = sorted(p.name.split("-")[0] for p in data_root.iterdir() if p.name.startswith(("policy.", "store.")))
    assert aside == ["policy.replaced"], aside  # the store migration never started
    assert pair_rows(data_root, scratch) == seed.snapshot
    assert is_writer_lock_held(data_root) is False

    brain = installed_script_path(ctx.env, "brain")
    refused = run_marked([str(brain), "serve", "--config", str(seed.config)], cwd=ctx.cwd)
    assert (refused.result.returncode, refused.owner_stderr) == (1, (ErrorCode.MIGRATION_REQUIRED.value,)), (
        refused.describe()
    )
    assert refused.result.stdout == "" and refused.ready is None
    assert not root.endpoint_path.exists() and endpoint_stages(data_root) == []
    assert schema_versions(data_root) == (3, 2) and pair_rows(data_root, scratch) == seed.snapshot

    hook_env = {"SUPERBRAIN_CRASHPOINT": run.result.hit or ""}
    migrate = ("migrate", "--offline", "--config", str(seed.config))
    resumed = _owner_envelope(run_installed_command(ctx.env, "brain", migrate, cwd=ctx.cwd, extra_env=hook_env))
    assert resumed["policy"] == {"status": "skipped", "from_version": 3, "to_version": 3}, resumed
    assert resumed["store"] == {"status": "migrated", "from_version": 2, "to_version": 4}, resumed
    assert (resumed["store_id"], resumed["noop"]) == (seed.store_id, False), resumed
    assert schema_versions(data_root) == (3, 4) and pair_rows(data_root, scratch) == seed.snapshot

    repeat = _owner_envelope(run_installed_command(ctx.env, "brain", migrate, cwd=ctx.cwd, extra_env=hook_env))
    assert repeat["policy"] == {"status": "skipped", "from_version": 3, "to_version": 3}, repeat
    assert repeat["store"] == {"status": "skipped", "from_version": 4, "to_version": 4}, repeat
    assert repeat["noop"] is True and pair_rows(data_root, scratch) == seed.snapshot

    with spawn_installed_brain_serve(ctx.env, seed.config, data_root=data_root, cwd=ctx.cwd) as serve:
        current = serve.wait_ready()
        assert current.store_id == seed.store_id
        rc, _, _, _ = serve.signal_and_wait_exit()
        assert rc == 0
    assert not root.endpoint_path.exists()
    after = pair_rows(data_root, scratch)
    assert after["ledger"][: len(seed.snapshot["ledger"])] == seed.snapshot["ledger"]
    assert {k: v for k, v in after.items() if k != "ledger"} == {
        k: v for k, v in seed.snapshot.items() if k != "ledger"
    }


# --- request-path kernel cases (Task 8.2): the durable fixture domain behind the installed daemon -----------------
#
# ``serve-fixture`` runs the installed wheel's owner composition with ``FixtureKernelDomain`` bound on the owner thread
# (``inc2_t8_child.py``). The trigger sends one ``prepare_task`` with an explicit task and key through an installed
# ``brain-mcp`` once the daemon is READY; the crashpoint on the request path must kill the daemon during that request.
# The expectation reads what the dead process left without a runtime, then restarts ``serve-fixture`` on the same root
# and retries through a new shim of the same principal.

T8_TASK_ID = "task-t8-response-loss"
T8_KEY = "idem-t8-response-loss-0001"
FIXTURE_DELIVERY_KIND = "fixture.delivery_result_recorded"
REQUEST_TABLES = ("deliveries", "delivery_items", "task_bindings", "holders", "idempotency", "hwm")
"""Every row a ``prepare_task`` effect writes besides its ledger entries (projection, ref holders, idempotency,
C4 high-water mark)."""


def t8_prepare_args(description: str = "t8 response loss") -> dict[str, JsonValue]:
    """``prepare_task`` with an explicit task and key; the shim adds the workspace hint of its profile."""
    return {"schema_version": "2.0", "task_id": T8_TASK_ID, "description": description, "idempotency_key": T8_KEY}


def fixture_rows(data_root: Path, scratch: Path) -> dict[str, list[tuple[object, ...]]]:
    """Ledger, applied intents and every request table of the fixture store, read-only (the daemon may be live)."""
    db = DataRoot.at(data_root).store_db

    def q(sql: str) -> list[tuple[object, ...]]:
        return _rows(db, scratch, sql)

    return {
        **store_rows(data_root, scratch),
        "deliveries": q(
            "SELECT result_id, delivery_id, assignment_id, task_id, record_digest FROM p_fixture_domain_deliveries "
            "ORDER BY 1"
        ),
        "delivery_items": q(
            "SELECT result_id, slot, position, ref_id, ref_revision, ref_digest FROM p_fixture_domain_delivery_items "
            "ORDER BY 1, 2, 3"
        ),
        "task_bindings": q(
            "SELECT task_id, delivery_id, assignment_id, snapshot_status FROM p_task_lineage_bindings ORDER BY 1"
        ),
        "holders": q("SELECT holder_kind, holder_id, digest FROM p_cas_holders_ ORDER BY 1, 2, 3"),
        "idempotency": q(
            "SELECT principal_id, tool, key_hash, request_digest, result_id, assignment_id FROM idempotency "
            "ORDER BY 1, 2, 3"
        ),
        "hwm": q("SELECT value FROM meta WHERE key = 'idempotency_clock_hwm_utc'"),
        "artifacts": q("SELECT artifact_id, revision, artifact_digest FROM p_fixture_domain_artifacts ORDER BY 1"),
    }


def open_fixture_runtime(data_root: Path, store_id: str) -> Runtime:
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
    from tests.support.inc2_kernel_domain import fixture_store_extensions

    handlers, kinds = fixture_store_extensions()
    return open_runtime_under_lease(
        admit_existing_pair(data_root, store_id, os_adapters(), purpose="serve"), handlers=handlers, kinds=kinds
    )


def seed_fixture_root(ctx: KernelCrashContext) -> KernelSeed:
    """The admitted template plus the fixture scenario (three artifacts of ``ws-a``), seeded before any daemon."""
    from tests.support.inc2_kernel_domain import FixtureKernelDomain
    from tests.support.inc2_t8_domain import seed_scenario

    tpl = ctx.template
    data_root = ctx.case_dir / "data"
    clone_owner_only_tree(tpl.root, data_root)
    config = write_daemon_config_file(
        ctx.case_dir / "daemon-config.json",
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=tpl.tls.cert_path,
        key_path=tpl.tls.key_path,
    )
    rt = open_fixture_runtime(data_root, tpl.store_id)
    try:
        seed_scenario(FixtureKernelDomain(store=rt.store, policy=rt.policy, clock=rt.os_.clock), rt)
    finally:
        rt.close()
    snapshot = fixture_rows(data_root, ctx.case_dir / "ro-scratch")
    assert snapshot["ledger"] and len(snapshot["artifacts"]) == 3, "the scenario was not seeded"
    assert snapshot["deliveries"] == [] and snapshot["idempotency"] == [] and snapshot["task_bindings"] == []
    return KernelSeed(data_root, config, tpl.store_id, lock_epoch(data_root), snapshot)


def _ws_profile(ctx: KernelCrashContext, seed: KernelSeed, name: str, token: str) -> Path:
    ws = ctx.template.ws_a
    assert ws is not None
    client = ctx.case_dir / f"client-{name}"
    cred = write_credential_file(client / "credential.txt", token)
    profile, _ = write_client_profile_file(
        client / "profile.json",
        endpoint_path=DataRoot.at(seed.data_root).endpoint_path,
        expected_store_id=seed.store_id,
        ca_file=ctx.template.tls.ca_cert_path,
        leaf_cert_sha256=ctx.template.tls.leaf_cert_sha256,
        credential_file=cred,
        workspace={
            "alias": ws.alias,
            "checkout_path": str(ws.checkout_path),
            "expected_workspace_id": ws.repo_id,
            "expected_checkout_id": ws.checkout_id,
        },
    )
    return profile


def shim_calls(
    ctx: KernelCrashContext,
    seed: KernelSeed,
    name: str,
    token: str,
    calls: Sequence[tuple[str, dict[str, JsonValue]]],
    *,
    entrypoint: Literal["brain-mcp", "brain"] = "brain-mcp",
    quiet: bool = True,
) -> list[dict[str, JsonValue]]:
    """Tool results (``result`` objects) of ``calls`` through one installed shim in the workspace: ``brain-mcp`` or
    the equivalent ``brain mcp``. ``quiet`` also requires an empty shim stderr."""
    ws = ctx.template.ws_a
    assert ws is not None
    profile = _ws_profile(ctx, seed, name, token)
    args = ("--profile", str(profile)) if entrypoint == "brain-mcp" else ("mcp", "--profile", str(profile))
    init, initialized = mcp_init_frames(1)
    results: list[dict[str, JsonValue]] = []
    with InstalledMcpPipeSession(ctx.env, entrypoint, args, cwd=Path(ws.checkout_path)) as s:
        assert s.send_frames_and_expect_response([init], timeout=10.0).get("id") == 1
        for i, (tool, tool_args) in enumerate(calls):
            frames = [initialized] if i == 0 else []
            frame = s.send_frames_and_expect_response([*frames, mcp_call_frame(i + 2, tool, tool_args)], timeout=10.0)
            result = frame.get("result")
            assert "error" not in frame and isinstance(result, dict), frame
            results.append(result)
        rc, stderr = s.finish()
    assert rc == 0, (rc, stderr)
    if quiet:
        assert stderr == b"", stderr
    return results


def content(result: dict[str, JsonValue]) -> dict[str, JsonValue]:
    sc = result.get("structuredContent")
    assert isinstance(sc, dict), result
    return sc


def assert_uncertain(result: dict[str, JsonValue]) -> None:
    """The old shim sent the request and got no success: an uncertain ``daemon_unavailable`` tool error."""
    assert result.get("isError") is True, result
    meta = result.get("_meta")
    assert isinstance(meta, dict) and meta.get("superbrain/request_may_have_run") is True, result
    error = content(result).get("error")
    assert isinstance(error, dict) and error.get("code") == ErrorCode.DAEMON_UNAVAILABLE.value, result


def ok_data(result: dict[str, JsonValue]) -> dict[str, JsonValue]:
    sc = content(result)
    assert result.get("isError") is False and sc.get("ok") is True, result
    data = sc["data"]
    assert isinstance(data, dict)
    return data


def error_code(result: dict[str, JsonValue]) -> str:
    sc = content(result)
    error = sc.get("error")
    assert result.get("isError") is True and sc.get("ok") is False and isinstance(error, dict), result
    return str(error["code"])


def cast_result(value: object) -> dict[str, JsonValue]:
    assert isinstance(value, dict), value
    return value


def trigger_prepare_task(ctx: KernelCrashContext, seed: KernelSeed, ready: Endpoint) -> None:
    """With the daemon READY: record the durable state, then send the request the crashpoint must interrupt."""
    assert (ready.store_id, ready.writer_epoch) == (seed.store_id, seed.epoch + 1)
    seed.notes["before"] = fixture_rows(seed.data_root, ctx.case_dir / "ro-scratch")
    (result,) = shim_calls(
        ctx, seed, "crash", ctx.template.cred.token, [("prepare_task", t8_prepare_args())], quiet=False
    )
    seed.notes["first"] = result


def _restart_fixture(
    ctx: KernelCrashContext, seed: KernelSeed, during: Callable[[Endpoint], None], *, crashpoint: str | None = None
) -> MarkedRun:
    """``serve-fixture`` again on the same root (new epoch); ``during`` runs while it serves. With ``crashpoint`` the
    fault env stays set and the run must still not hit it."""
    epoch = lock_epoch(seed.data_root) + 1
    run = run_t8_child(ctx.env, "serve-fixture", seed.config, cwd=ctx.cwd, crashpoint=crashpoint, while_ready=during)
    assert run.ready is not None and run.result.hit is None and run.result.returncode == 0, run.describe()
    assert (run.ready.store_id, run.ready.writer_epoch) == (seed.store_id, epoch), run.describe()
    assert_wheel_provenance(run, ctx)
    return run


def assert_wheel_provenance(run: MarkedRun, ctx: KernelCrashContext) -> None:
    """The driver imported ``superbrain`` from the installed wheel venv and loaded the packaged tool schema whose
    digest equals the checkout's ``schemas/mcp-tools-v2.json``."""
    module = _tagged(run.result.stderr, "MODULE")
    assert module is not None, run.describe()
    assert Path(module).resolve().is_relative_to(ctx.env.venv_dir.resolve()), (module, ctx.env.venv_dir)
    schema = _tagged(run.result.stderr, "SCHEMA")
    assert schema is not None and schema.removeprefix("sha256:") == ctx.env.source_schema_sha256.removeprefix(
        "sha256:"
    ), run.describe()


def _request_tables(rows: dict[str, list[tuple[object, ...]]]) -> dict[str, list[tuple[object, ...]]]:
    return {k: rows[k] for k in REQUEST_TABLES}


def _replay_stable(rows: dict[str, list[tuple[object, ...]]]) -> dict[str, list[tuple[object, ...]]]:
    """The request tables a replay must leave alone: all but the C4 high-water mark, which a replay advances."""
    return {k: v for k, v in _request_tables(rows).items() if k != "hwm"}


def _delivery_events(data_root: Path, scratch: Path) -> int:
    rows = _rows(DataRoot.at(data_root).store_db, scratch, "SELECT kind FROM ledger")
    return sum(1 for (kind,) in rows if kind == FIXTURE_DELIVERY_KIND)


def _items_by_id(data: dict[str, JsonValue], slot: str) -> dict[str, dict[str, JsonValue]]:
    items = data[slot]
    assert isinstance(items, list), data
    return {str(item["id"]): item for item in items if isinstance(item, dict)}


def expect_crash_before_commit(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    """Rolled back: no event, projection, ref holder, idempotency row or HWM move; the ACKed ledger is exactly what it
    was when the request arrived (a staged blob may stay in ``cas/`` without a holder). A new daemon applies the retry
    with the same key exactly once, and a second retry replays the same Delivery and assignment."""
    scratch = ctx.case_dir / "ro-scratch"
    assert_wheel_provenance(run, ctx)
    assert_uncertain(cast_result(seed.notes["first"]))
    before = seed.notes["before"]
    assert isinstance(before, dict)
    after = fixture_rows(seed.data_root, scratch)
    assert after == before, "the transaction that crashed before COMMIT left durable state"
    assert _delivery_events(seed.data_root, scratch) == 0
    retried: list[dict[str, JsonValue]] = []

    def retry(ready: Endpoint) -> None:
        retried.extend(
            shim_calls(
                ctx,
                seed,
                "retry",
                ctx.template.cred.token,
                [("prepare_task", t8_prepare_args()), ("prepare_task", t8_prepare_args())],
            )
        )

    _restart_fixture(ctx, seed, retry)
    first, again = (ok_data(r) for r in retried)
    assert first["task_id"] == T8_TASK_ID
    assert (again["delivery_id"], again["assignment_id"]) == (first["delivery_id"], first["assignment_id"])
    final = fixture_rows(seed.data_root, scratch)
    ((_result_id, delivery_id, assignment_id, task_id, _digest),) = final["deliveries"]
    assert (delivery_id, assignment_id, task_id) == (first["delivery_id"], first["assignment_id"], T8_TASK_ID)
    assert len(final["idempotency"]) == 1 and _delivery_events(seed.data_root, scratch) == 1
    assert [row[:3] for row in final["task_bindings"]] == [(T8_TASK_ID, delivery_id, assignment_id)]
    assert final["delivery_items"] and len(final["holders"]) >= len(before["holders"])
    assert final["ledger"][: len(before["ledger"])] == before["ledger"]


def tighten_policy_offline(ctx: KernelCrashContext, seed: KernelSeed) -> str:
    """With no daemon running: quarantine the redactable ref's digest and revoke the second credential of the same
    principal. Returns that digest."""
    from tests.support.inc2_t8_domain import ART_REDACTABLE

    cred_b = ctx.template.cred_b
    assert cred_b is not None and cred_b.principal == ctx.template.cred.principal
    rt = open_fixture_runtime(seed.data_root, seed.store_id)
    try:
        with rt.store.transaction() as txn:
            row = txn.db.execute(
                "SELECT artifact_digest FROM p_fixture_domain_artifacts WHERE artifact_id = ?", (ART_REDACTABLE,)
            ).fetchone()
        assert row is not None
        digest = str(row[0])
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest})
        auth = make_bootstrap_auth(
            store_id=seed.store_id,
            owner_id=cred_b.principal.owner_id,
            action="credential_revoke",
            subject_id=cred_b.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=rt.os_.clock.now() + dt.timedelta(hours=1),
        )
        rt.policy.record_authorized_revocation(cred_b.credential_id, auth)
        rt.store.reconcile_policy()
    finally:
        rt.close()
    return digest


def expect_crash_after_commit(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    """Committed, response lost. A new daemon (fault env still set, never hit on replay) and a new shim of the same
    principal replay the same Delivery, result and assignment from durable state (one event, one effect), under the
    current policy: the allowed ref keeps its digest, the ref tightened since is redacted, a changed payload under the
    old key is ``idempotency_conflict``, a revoked credential of that same principal is refused before any replay
    (unchanged or changed payload). ``brain mcp`` replays the same IDs as ``brain-mcp``."""
    from tests.support.inc2_t8_domain import ART_ALLOWED, ART_REDACTABLE

    scratch = ctx.case_dir / "ro-scratch"
    assert_wheel_provenance(run, ctx)
    assert_uncertain(cast_result(seed.notes["first"]))
    before = seed.notes["before"]
    assert isinstance(before, dict)
    committed = fixture_rows(seed.data_root, scratch)
    assert committed["ledger"][: len(before["ledger"])] == before["ledger"]
    assert len(committed["deliveries"]) == len(before["deliveries"]) + 1 == 1
    assert len(committed["idempotency"]) == len(before["idempotency"]) + 1 == 1
    ((result_id, delivery_id, assignment_id, task_id, record_digest),) = committed["deliveries"]
    assert task_id == T8_TASK_ID and assignment_id is not None
    assert committed["idempotency"][0][4:] == (result_id, assignment_id)
    assert [row[:3] for row in committed["task_bindings"]] == [(T8_TASK_ID, delivery_id, assignment_id)]
    assert _delivery_events(seed.data_root, scratch) == 1
    allowed_digest = next(d for a, _r, d in committed["artifacts"] if a == ART_ALLOWED)
    redacted_digest = tighten_policy_offline(ctx, seed)
    tightened = _replay_stable(fixture_rows(seed.data_root, scratch))
    assert {k: v for k, v in tightened.items() if k != "holders"} == {
        k: v for k, v in _replay_stable(committed).items() if k != "holders"
    }
    cred_b = ctx.template.cred_b
    assert cred_b is not None
    seen: dict[str, list[dict[str, JsonValue]]] = {}

    def replay(ready: Endpoint) -> None:
        seen["cred"] = shim_calls(
            ctx,
            seed,
            "replay",
            ctx.template.cred.token,
            [("prepare_task", t8_prepare_args()), ("prepare_task", t8_prepare_args("a changed payload"))],
        )
        seen["revoked"] = shim_calls(
            ctx,
            seed,
            "revoked",
            cred_b.token,
            [("prepare_task", t8_prepare_args()), ("prepare_task", t8_prepare_args("a changed payload"))],
        )
        seen["brain"] = shim_calls(
            ctx, seed, "brain", ctx.template.cred.token, [("prepare_task", t8_prepare_args())], entrypoint="brain"
        )

    _restart_fixture(ctx, seed, replay, crashpoint=run.result.hit)
    replayed, changed = seen["cred"]
    data = ok_data(replayed)
    assert (data["delivery_id"], data["assignment_id"], data["task_id"]) == (delivery_id, assignment_id, T8_TASK_ID)
    skills = _items_by_id(data, "skills")
    assert set(skills) == {ART_ALLOWED, ART_REDACTABLE}, skills
    assert skills[ART_ALLOWED].get("status") == "ok" and skills[ART_ALLOWED].get("digest") == allowed_digest, skills
    redacted = skills[ART_REDACTABLE]
    assert redacted.get("status") == "redacted" and "digest" not in redacted and redacted.get("reason"), skills
    assert redacted_digest not in str(data), "the tightened ref's digest leaked in the replay"
    assert error_code(changed) == ErrorCode.IDEMPOTENCY_CONFLICT.value
    assert [error_code(r) for r in seen["revoked"]] == [ErrorCode.UNAUTHENTICATED.value] * 2
    (via_brain,) = seen["brain"]
    brain_data = ok_data(via_brain)
    assert (brain_data["delivery_id"], brain_data["assignment_id"]) == (delivery_id, assignment_id)
    assert _items_by_id(brain_data, "skills") == skills
    final = fixture_rows(seed.data_root, scratch)
    assert _replay_stable(final) == tightened, "a replay or refusal wrote request state"
    assert final["deliveries"] == [(result_id, delivery_id, assignment_id, T8_TASK_ID, record_digest)]
    assert _delivery_events(seed.data_root, scratch) == 1


KERNEL_CRASH_CASES: tuple[KernelCrashCase, ...] = (
    KernelCrashCase(
        "serve", "daemon.after_bind_before_endpoint", seed_daemon_root_with_stale_endpoint, expect_crash_after_bind
    ),
    KernelCrashCase("serve", "daemon.after_endpoint_publish", seed_daemon_root, expect_crash_after_publish),
    KernelCrashCase("migrate", "kernel.migrate.after_policy_swap", seed_legacy_pair, expect_crash_after_policy_swap),
    KernelCrashCase(
        "serve-fixture",
        "kernel.before_commit",
        seed_fixture_root,
        expect_crash_before_commit,
        trigger=trigger_prepare_task,
    ),
    KernelCrashCase(
        "serve-fixture",
        "kernel.after_commit_before_response",
        seed_fixture_root,
        expect_crash_after_commit,
        trigger=trigger_prepare_task,
    ),
    KernelCrashCase("serve-jobs", "jobs.after_lease", seed_job, expect_lease),
    KernelCrashCase("serve-jobs", "jobs.after_running", seed_job, expect_running),
    KernelCrashCase(
        "job-operation", "jobs.after_invocation_reserve", seed_job, expect_reserve, args=lambda _: ("reserve",)
    ),
    KernelCrashCase("job-operation", "jobs.after_cancel_commit", seed_job, expect_cancel, args=cancel_args),
    KernelCrashCase("job-operation", "jobs.after_usage_settle_commit", seed_usage, expect_settle, args=settle_args),
)
