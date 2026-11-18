"""Task 3 workspace identity, lookup-only binding, event-sourced snapshots/lineage and S1=A labeled delivery."""

from __future__ import annotations

import ast
import builtins
import datetime as dt
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from superbrain.adapters.os.workspaces import (
    build_registration,
    canonical_remote_locator,
    physical_checkout,
)
from superbrain.application.lineage import (
    evaluate_egress_eligibility,
    prepare_labeled_delivery,
    register_snapshot,
    resolve_binding,
    resolve_task_binding,
)
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    AuthSnapshot,
    DeliveryItem,
    FilterPolicy,
    LabeledDelivery,
    LineagedField,
    LineageRef,
    ObjectRef,
    Principal,
    Scope,
    SelectorPath,
    SelectorReason,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    WorkspaceBinding,
    WorkspaceRegistration,
    WorkspaceSelector,
    field_path_digest,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.kernel_schema import (
    KERNEL_POLICY_KINDS,
    KERNEL_POLICY_MIGRATIONS,
    KERNEL_STORE_MIGRATIONS,
    KERNEL_WORKSPACE_KINDS,
)
from superbrain.storage.ledger import LedgerEntry
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import Runtime, admit_existing_pair, open_runtime_under_lease
from superbrain.storage.workspaces import (
    FieldLineageProjection,
    KernelWorkspaceStore,
    SnapshotProjection,
    StoreSourceRestrictions,
    StoreWorkspaceMirror,
    TaskLineageProjection,
    WorkspaceRegistryMirrorProjection,
)
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_cloned_runtime
from tests.support.inc2_observer import DirectorySnapshotObserver
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

MS = 1_000_000
SRC = Path(__file__).resolve().parents[2] / "src" / "superbrain"
REMOTE = "https://github.example/dan/super-brain2.git"
LOCAL_TABLE_PREFIXES = ("p_source_snapshots_", "p_task_lineage_", "p_field_lineage_")
TREE_1 = "sha256:" + "1" * 64
TREE_2 = "sha256:" + "2" * 64


# --- helpers ------------------------------------------------------------------------------------------------------


class Mono:
    """Injected monotonic clock in nanoseconds."""

    def __init__(self, start: int = 50_000 * MS) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now

    def advance(self, ns: int) -> None:
        self.now += ns


@dataclass
class FakeObserver:
    descriptor: SnapshotDescriptor | None = None
    mono: Mono | None = None
    consume_ns: int = 0
    status: SnapshotStatus = SnapshotStatus.AVAILABLE
    calls: list[tuple[WorkspaceBinding, int]] = field(default_factory=list)

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        self.calls.append((binding, deadline_ns))
        if self.mono is not None:
            self.mono.advance(self.consume_ns)
        if self.status is SnapshotStatus.AVAILABLE:
            return SnapshotObservation(SnapshotStatus.AVAILABLE, self.descriptor)
        return SnapshotObservation(self.status, None)


def _desc(tree: str = TREE_1, *, dirty_digest: str | None = None) -> SnapshotDescriptor:
    return SnapshotDescriptor(
        kind="git",
        tree_or_head_digest=tree,
        dirty=dirty_digest is not None,
        dirty_digest=dirty_digest,
        observed_at="2026-11-06T03:04:05.000000Z",
    )


def _open(root: Path, os_: OsAdapters) -> Runtime:
    handlers, kinds = kernel_store_extensions()
    return open_cloned_runtime(
        root,
        os_,
        role="kernel-b" if root.name in {"root-b", "foreign-root", "other", "b"} else "kernel",
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def _reopen(root: Path, store_id: str, os_: OsAdapters) -> Runtime:
    handlers, kinds = kernel_store_extensions()
    return open_runtime_under_lease(
        admit_existing_pair(root, store_id, os_, purpose="serve"), handlers=handlers, kinds=kinds
    )


def _register(
    rt: Runtime,
    clock: FakeClock,
    seeded: SeededCredential,
    *,
    alias: str,
    checkout: Path,
    remote: str | None = REMOTE,
    egress: bool = False,
) -> WorkspaceBinding:
    checkout.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias=alias,
        raw_path=str(checkout),
        raw_remote=remote,
        provider_egress_enabled=egress,
    )
    return rt.policy.register_authorized_workspace(
        reg,
        make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=seeded.principal.owner_id,
            action="workspace_register",
            subject_id=reg.subject_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        ),
    )


def _entries(rt: Runtime, kind: str) -> list[LedgerEntry]:
    return [entry for entry in rt.store.entries() if entry.kind == kind]


def _rows(rt: Runtime, prefixes: tuple[str, ...] = LOCAL_TABLE_PREFIXES) -> dict[str, list[tuple[object, ...]]]:
    with rt.store.transaction() as txn:
        names = [
            str(row[0])
            for row in txn.db.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall()
            if str(row[0]).startswith(prefixes)
        ]
        return {name: sorted(txn.db.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr) for name in names}


def _source(rt_binding: WorkspaceBinding, ident: str) -> LineageRef:
    return LineageRef(
        owner_id=rt_binding.owner_id,
        repo_id=rt_binding.repo_id,
        source=ObjectRef(kind="artifact", id=ident, revision=1, digest=digest_bytes(ident.encode())),
    )


def _prepare(
    rt: Runtime,
    principal: Principal,
    selector: WorkspaceSelector,
    *,
    task_id: str,
    mono: Mono,
    observer: FakeObserver | None,
    total_ns: int = 1_500 * MS,
    items: tuple[DeliveryItem, ...] = (),
    served: tuple[LineageRef, ...] = (),
    selected_scope: Scope | None = None,
) -> LabeledDelivery:
    start = mono()
    return prepare_labeled_delivery(
        store=KernelWorkspaceStore(rt.store, rt.policy),
        policy=rt.policy,
        principal=principal,
        selector=selector,
        task_id=task_id,
        payload={"schema_version": "2.0", "description": "fix the login bug"},
        filter_policy=FilterPolicy(),
        items=items,
        served_sources=served,
        observer=observer,
        monotonic_ns=mono,
        local_phase_start_ns=start,
        total_deadline_ns=start + total_ns,
        selected_scope=selected_scope,
    )


@pytest.fixture
def kernel(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    rt = _open(trusted_tmp / "kroot", os_)
    try:
        yield rt
    finally:
        rt.close()


@pytest.fixture
def dan(kernel: Runtime) -> SeededCredential:
    return seed_principal_and_credential(kernel.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")


def _no_fs_net_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("filesystem, network or subprocess access is forbidden here")

    for target, name in (
        (os, "stat"),
        (os, "lstat"),
        (os, "scandir"),
        (os, "listdir"),
        (os.path, "realpath"),
        (builtins, "open"),
        (socket, "socket"),
        (socket, "create_connection"),
        (subprocess, "Popen"),
    ):
        monkeypatch.setattr(target, name, refuse)


# --- workspace identity -------------------------------------------------------------------------------------------


def test_worktrees_sharing_remote_share_repo_and_get_distinct_checkouts(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    a = _register(kernel, clock, dan, alias="wt-a", checkout=trusted_tmp / "wt-a")
    b = _register(
        kernel,
        clock,
        dan,
        alias="wt-b",
        checkout=trusted_tmp / "wt-b",
        remote="https://dan:hunter2@GITHUB.example:443/dan/super-brain2.git/?ref=x#frag",
    )
    assert a.repo_id == b.repo_id
    assert a.checkout_id != b.checkout_id
    assert a.locator_digest == b.locator_digest == canonical_remote_locator(REMOTE).locator_digest


def test_adding_or_rotating_remote_keeps_repo_and_checkout(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    first = _register(kernel, clock, dan, alias="solo", checkout=trusted_tmp / "solo", remote=None)
    added = _register(kernel, clock, dan, alias="solo", checkout=trusted_tmp / "solo", remote=REMOTE)
    rotated = _register(
        kernel, clock, dan, alias="solo", checkout=trusted_tmp / "solo", remote="git@github.example:dan/mirror.git"
    )
    assert (first.repo_id, first.checkout_id) == (added.repo_id, added.checkout_id)
    assert (rotated.repo_id, rotated.checkout_id) == (first.repo_id, first.checkout_id)
    assert rotated.locator_digest == canonical_remote_locator("ssh://github.example/dan/mirror").locator_digest


def test_remote_ambiguity_fails_with_revision_conflict(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    x = _register(kernel, clock, dan, alias="x", checkout=trusted_tmp / "x", remote=None)
    y = _register(kernel, clock, dan, alias="y", checkout=trusted_tmp / "y", remote="https://h.example/o/y.git")
    assert x.repo_id != y.repo_id
    with pytest.raises(BrainError) as exc:
        _register(kernel, clock, dan, alias="x", checkout=trusted_tmp / "x", remote="https://h.example/o/y.git")
    assert exc.value.code is ErrorCode.REVISION_CONFLICT
    assert resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="x"), kernel.policy).repo_id == x.repo_id


def test_no_remote_move_creates_distinct_checkout_and_no_link(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    place_1 = trusted_tmp / "place-1" / "proj"
    old = _register(kernel, clock, dan, alias="m1", checkout=place_1, remote=None)
    (trusted_tmp / "place-2").mkdir()
    place_2 = trusted_tmp / "place-2" / "proj"
    os.rename(place_1, place_2)  # the same directory (same file ID) now lives elsewhere
    moved = _register(kernel, clock, dan, alias="m2", checkout=place_2, remote=None)
    assert old.repo_id != moved.repo_id
    assert old.checkout_id != moved.checkout_id
    assert moved.checkout_path == os.path.realpath(place_2)
    still_old = resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="m1"), kernel.policy)
    assert still_old == old  # the old alias does not silently follow the moved directory
    assert still_old.checkout_path != moved.checkout_path


def test_reused_file_id_never_carries_checkout_identity(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_stat = os.stat

    def same_file_id(path: str | os.PathLike[str], *, follow_symlinks: bool = True) -> os.stat_result:
        r = real_stat(path, follow_symlinks=follow_symlinks)
        return os.stat_result(
            (
                r.st_mode,
                4242,
                77,
                r.st_nlink,
                r.st_uid,
                r.st_gid,
                r.st_size,
                int(r.st_atime),
                int(r.st_mtime),
                int(r.st_ctime),
            )
        )

    first_dir = trusted_tmp / "gone" / "proj"
    first_dir.mkdir(parents=True)
    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", same_file_id)
        first = _register(kernel, clock, dan, alias="i1", checkout=first_dir, remote=None)
    shutil.rmtree(first_dir.parent)
    reused_dir = trusted_tmp / "fresh" / "proj"
    reused_dir.mkdir(parents=True)
    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", same_file_id)  # the file system handed the old file ID to a new directory
        reused = _register(kernel, clock, dan, alias="i2", checkout=reused_dir, remote=None)
        assert physical_checkout(str(reused_dir)).path_identity != physical_checkout(str(trusted_tmp)).path_identity
    assert (reused.repo_id, reused.checkout_id) != (first.repo_id, first.checkout_id)
    assert resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="i1"), kernel.policy) == first


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("https://github.example/dan/repo.git", "https://github.example/dan/repo"),
        ("https://u:p@GitHub.Example:443/dan/repo/?q=1#x", "https://github.example/dan/repo"),
        ("https://github.example:8443/dan/repo", "https://github.example:8443/dan/repo"),
        ("ssh://git@github.example:22/dan/repo.git", "ssh://github.example/dan/repo"),
        ("ssh://git@github.example:2222/dan/repo.git", "ssh://github.example:2222/dan/repo"),
        ("git@github.example:dan/repo.git", "ssh://github.example/dan/repo"),
        ("file:///srv/git/repo.git", "file:///srv/git/repo"),
        ("/srv/git/repo.git", "file:///srv/git/repo"),
        ("C:\\git\\repo.git", "file:///C:/git/repo"),
        ("https://h.example/o/Repo.GIT", "https://h.example/o/Repo"),
    ],
)
def test_canonical_locator_strips_userinfo_query_and_fragment(
    raw: str, canonical: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as guard:
        _no_fs_net_exec(guard)
        loc = canonical_remote_locator(raw)
    assert loc.canonical_locator == canonical
    assert loc.locator_digest == digest_bytes(canonical.encode("utf-8"))
    assert "@" not in loc.canonical_locator and "?" not in loc.canonical_locator and "#" not in loc.canonical_locator


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "http://github.example/dan/repo.git",
        "ftp://github.example/dan/repo.git",
        "https:///nohost",
        "https://github.example/dan/../etc",
        "https://github.example/dan/re po",
        "https://github.example/dan/repo\x00",
        "git@github.example:../escape.git",
        "\\\\server\\share\\repo",
        "//server/share/repo",
        "file://server/share/repo",
        "\\\\?\\C:\\git\\repo",
        "C:\\git\\repo:stream",
        "relative/repo.git",
        "ext::sh -c touch% /tmp/pwned",
    ],
)
def test_canonical_locator_rejects_unsupported_shapes_without_echo(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as guard, pytest.raises(BrainError) as exc:
        _no_fs_net_exec(guard)
        canonical_remote_locator(raw)
    assert exc.value.code is ErrorCode.INVALID_INPUT
    if raw:
        assert raw not in str(exc.value)


def test_physical_identity_uses_real_filesystem_identity(trusted_tmp: Path) -> None:
    real = trusted_tmp / "RepoCase"
    real.mkdir()
    other = trusted_tmp / "Other"
    other.mkdir()
    base = physical_checkout(str(real))
    assert base.checkout_path == os.path.realpath(real)
    assert physical_checkout(str(other)).path_identity != base.path_identity
    link = trusted_tmp / "alias-link"
    if sys.platform == "win32":
        import _winapi

        upper = physical_checkout(str(real).upper())
        assert upper.path_identity == base.path_identity
        assert upper.checkout_path == base.checkout_path  # real on-disk case, not the caller's spelling
        _winapi.CreateJunction(str(real), str(link))
    else:
        lower = trusted_tmp / "repocase"
        lower.mkdir(exist_ok=True)
        same_directory = lower.samefile(real)
        assert (physical_checkout(str(lower)).path_identity == base.path_identity) == same_directory
        link.symlink_to(real, target_is_directory=True)
    linked = physical_checkout(str(link))
    assert linked.path_identity == base.path_identity
    assert linked.checkout_path == base.checkout_path


@pytest.mark.parametrize(
    "raw",
    ["relative/path", "\\\\server\\share\\repo", "\\\\?\\C:\\repo", "//server/share", "C:\\repo:ads", "x\x00y"],
)
def test_physical_identity_rejects_unc_device_ads_and_relative_paths(raw: str) -> None:
    with pytest.raises(BrainError) as exc:
        physical_checkout(raw)
    assert exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT, ErrorCode.NOT_FOUND}
    assert raw not in str(exc.value)


def test_snapshot_descriptor_registration_dedupes_and_dirty_digest_changes_id(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="snap", checkout=trusted_tmp / "snap")
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    clean = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc()))
    again = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc()))
    dirty_a = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(dirty_digest="sha256:" + "a" * 64)))
    dirty_b = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(dirty_digest="sha256:" + "b" * 64)))
    assert clean == again
    assert len({clean, dirty_a, dirty_b}) == 3
    observed = _entries(kernel, "snapshot.observed")
    assert len(observed) == 3
    for entry in observed:
        assert entry.meta["owner_id"] == "dan"
        assert entry.meta["repo_id"] == binding.repo_id
        assert entry.meta["checkout_id"] == binding.checkout_id
        assert entry.refs == (entry.meta["descriptor_digest"],)
        assert kernel.store.cas.holders(str(entry.meta["descriptor_digest"]))
    snap = kstore.transact(lambda tx: tx.read_source_snapshot(clean))
    assert snap is not None and snap.checkout_id == binding.checkout_id and snap.dirty is False


def test_registered_owner_and_machine_are_verified(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="own", checkout=trusted_tmp / "own")
    other_machine = seed_principal_and_credential(kernel.policy, owner_id="dan", harness_id="codex", machine_id="box-2")
    eve = seed_principal_and_credential(kernel.policy, owner_id="eve", harness_id="claude-code", machine_id="box-1")
    ids = WorkspaceSelector(workspace_id=binding.repo_id, checkout_id=binding.checkout_id)
    with pytest.raises(BrainError) as exc_machine:
        resolve_binding(other_machine.principal, ids, kernel.policy)
    assert exc_machine.value.code is ErrorCode.IDENTITY_MISMATCH
    with pytest.raises(BrainError) as exc_owner:
        resolve_binding(eve.principal, ids, kernel.policy)
    assert exc_owner.value.code is ErrorCode.NOT_FOUND
    with pytest.raises(BrainError) as exc_repo:
        resolve_binding(
            dan.principal, WorkspaceSelector(workspace_id="other-repo", checkout_id=binding.checkout_id), kernel.policy
        )
    assert exc_repo.value.code is ErrorCode.NOT_FOUND


# --- lookup-only binding ------------------------------------------------------------------------------------------


def test_prepare_task_hint_returns_binding_without_client_uuid(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="sb2", checkout=trusted_tmp / "sb2")
    resolved = resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="sb2"), kernel.policy)
    assert resolved == binding
    assert (resolved.owner_id, resolved.machine_id, resolved.alias) == ("dan", "box-1", "sb2")
    delivery = _prepare(
        kernel, dan.principal, WorkspaceSelector(workspace_hint="sb2"), task_id="task-1", mono=Mono(), observer=None
    )
    assert (delivery.binding.repo_id, delivery.binding.checkout_id) == (binding.repo_id, binding.checkout_id)
    assert delivery.binding.owner_id == "dan"
    # Hints valid by the wire grammar but never registrable as aliases resolve cleanly to not_found (handoff 1).
    for hint in ("-sb2", "_sb2", ".sb2"):
        with pytest.raises(BrainError) as exc:
            resolve_binding(dan.principal, WorkspaceSelector(workspace_hint=hint), kernel.policy)
        assert exc.value.code is ErrorCode.NOT_FOUND
        with pytest.raises(BrainError):
            WorkspaceRegistration(
                owner_id="dan",
                principal_id=dan.principal.principal_id,
                machine_id="box-1",
                alias=hint,
                checkout_path=str(trusted_tmp / "sb2"),
                path_identity="fsid:1:2",
            )


class _AmbiguousPolicy:
    def __init__(self, principal: Principal, base: AuthSnapshot) -> None:
        dup = {
            cid: WorkspaceBinding(
                owner_id=principal.owner_id,
                repo_id=f"repo-{n}",
                checkout_id=cid,
                machine_id=principal.machine_id,
                alias="twin",
                checkout_path=f"/tmp/{cid}",
            )
            for n, cid in enumerate(("chk-1", "chk-2"))
        }
        self._snap = AuthSnapshot(store_id=base.store_id, trust_generation=base.trust_generation, checkouts=dup)
        self.calls: list[str] = []

    def snapshot(self) -> AuthSnapshot:
        self.calls.append("snapshot")
        return self._snap

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        self.calls.append("allows")
        return True

    def register_authorized_workspace(self, *args: object) -> object:
        raise AssertionError("lookup must never register")


def test_unknown_or_ambiguous_hint_never_registers_or_reads_path(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(kernel, clock, dan, alias="known", checkout=trusted_tmp / "known")
    before = kernel.policy.snapshot()
    intents_before = len(kernel.policy.intents())
    observer = FakeObserver(_desc())
    ambiguous = _AmbiguousPolicy(dan.principal, before)
    with monkeypatch.context() as guard:
        _no_fs_net_exec(guard)
        with pytest.raises(BrainError) as exc_unknown:
            resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="never-registered"), kernel.policy)
        with pytest.raises(BrainError) as exc_ambiguous:
            resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="twin"), ambiguous)  # type: ignore[arg-type]
        with pytest.raises(BrainError) as exc_prepare:
            _prepare(
                kernel,
                dan.principal,
                WorkspaceSelector(workspace_hint="ghost"),
                task_id="t-x",
                mono=Mono(),
                observer=observer,
            )
    assert exc_unknown.value.code is ErrorCode.NOT_FOUND
    assert exc_ambiguous.value.code is ErrorCode.REVISION_CONFLICT
    assert exc_prepare.value.code is ErrorCode.NOT_FOUND
    assert "allows" not in ambiguous.calls
    assert observer.calls == []
    after = kernel.policy.snapshot()
    assert after.checkouts == before.checkouts and after.grants == before.grants
    assert after.repo_policies == before.repo_policies
    assert len(kernel.policy.intents()) == intents_before
    assert _entries(kernel, "lineage.task_bound") == []


def test_retry_after_tree_changes_keeps_original_snapshot(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    _register(kernel, clock, dan, alias="retry", checkout=trusted_tmp / "retry")
    sel = WorkspaceSelector(workspace_hint="retry")
    first = _prepare(kernel, dan.principal, sel, task_id="task-r", mono=Mono(), observer=FakeObserver(_desc(TREE_1)))
    changed = FakeObserver(_desc(TREE_2))
    again = _prepare(kernel, dan.principal, sel, task_id="task-r", mono=Mono(), observer=changed)
    assert first.binding.snapshot_status is SnapshotStatus.AVAILABLE
    assert first.binding.source_snapshot_id is not None
    assert again.replayed is True and first.replayed is False
    assert again.binding == first.binding
    assert changed.calls == []
    assert len(_entries(kernel, "snapshot.observed")) == 1
    assert len(_entries(kernel, "lineage.task_bound")) == 1


def test_submit_episode_uses_existing_task_binding(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    main = _register(kernel, clock, dan, alias="main", checkout=trusted_tmp / "main")
    side = _register(kernel, clock, dan, alias="side", checkout=trusted_tmp / "side")
    _prepare(
        kernel, dan.principal, WorkspaceSelector(workspace_hint="main"), task_id="task-s", mono=Mono(), observer=None
    )
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    bound = resolve_task_binding(kstore, kernel.policy, dan.principal, "task-s")
    assert (bound.repo_id, bound.checkout_id) == (main.repo_id, main.checkout_id)
    same = resolve_task_binding(
        kstore, kernel.policy, dan.principal, "task-s", workspace_id=main.repo_id, checkout_id=main.checkout_id
    )
    assert same == bound
    other_machine = seed_principal_and_credential(kernel.policy, owner_id="dan", harness_id="codex", machine_id="box-2")
    refusals: tuple[Callable[[], object], ...] = (
        lambda: resolve_task_binding(kstore, kernel.policy, dan.principal, "task-s", checkout_id=side.checkout_id),
        lambda: resolve_task_binding(kstore, kernel.policy, dan.principal, "no-such-task"),
        lambda: resolve_task_binding(kstore, kernel.policy, other_machine.principal, "task-s"),
        lambda: resolve_task_binding(
            kstore, kernel.policy, dan.principal, "task-s", selected_scope=Scope(side.repo_id, side.checkout_id)
        ),
    )
    for call in refusals:
        with pytest.raises(BrainError) as exc:
            call()
        assert exc.value.code is ErrorCode.NOT_FOUND


# --- S1=A labeled delivery ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["missing", "slow"])
def test_missing_or_slow_observer_produces_labeled_delivery_with_known_lineage(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, mode: str
) -> None:
    binding = _register(kernel, clock, dan, alias="lab", checkout=trusted_tmp / "lab", egress=True)
    repo_a = _register(
        kernel, clock, dan, alias="repo-a", checkout=trusted_tmp / "ra", remote="https://h.example/o/a.git", egress=True
    )
    source_a = _source(repo_a, "art-a")
    mono = Mono()
    observer = None if mode == "missing" else FakeObserver(_desc(), mono=mono, consume_ns=150 * MS)
    items = (
        DeliveryItem(path=("context", "known"), sources=frozenset({source_a})),
        DeliveryItem(path=("context", "mystery"), sources=frozenset(), unknown_source=True),
        DeliveryItem(path=("finishing_gates", 0), sources=frozenset({source_a}), snapshot_dependent=True),
    )
    delivery = _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="lab"),
        task_id=f"task-{mode}",
        mono=mono,
        observer=observer,
        items=items,
        served=(source_a,),
    )
    expected_status = SnapshotStatus.UNAVAILABLE if mode == "missing" else SnapshotStatus.DEADLINE
    expected_code = "snapshot_unavailable" if mode == "missing" else "snapshot_deadline"
    assert delivery.binding.snapshot_status is expected_status
    assert delivery.binding.source_snapshot_id is None
    assert delivery.degraded_codes == (expected_code,)
    assert delivery.binding.selector_path is SelectorPath.RULES
    assert delivery.binding.selector_reason is SelectorReason.PROVIDER_UNAVAILABLE
    assert {ref.repo_id for ref in delivery.task_lineage} == {binding.repo_id, repo_a.repo_id}
    assert source_a in delivery.task_lineage
    assert delivery.task_unknown is True
    by_path = {item.field_path_digest: item for item in delivery.items}
    known = by_path[field_path_digest(("context", "known"))]
    mystery = by_path[field_path_digest(("context", "mystery"))]
    assert known.unknown_source is False and source_a in known.sources
    assert mystery.unknown_source is True
    assert delivery.omitted_items == (field_path_digest(("finishing_gates", 0)),)
    assert _entries(kernel, "snapshot.observed") == []
    (bound,) = _entries(kernel, "lineage.task_bound")
    assert bound.meta["snapshot_status"] == expected_status.value
    assert bound.meta["source_snapshot_id"] is None
    assert bound.meta["selector_path"] == "rules"
    assert bound.meta["selector_reason"] == "provider_unavailable"
    known_field = LineagedField(value=None, sources=known.sources, unknown_source=known.unknown_source)
    mystery_field = LineagedField(value=None, sources=mystery.sources, unknown_source=True)
    restrictions = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": source_a.__eq__})
    assert evaluate_egress_eligibility(known_field, kernel.policy, restrictions=restrictions) is True
    assert evaluate_egress_eligibility(mystery_field, kernel.policy, restrictions=restrictions) is False


def test_unknown_snapshot_replay_does_not_upgrade_after_observer_recovers(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    _register(kernel, clock, dan, alias="up", checkout=trusted_tmp / "up")
    sel = WorkspaceSelector(workspace_hint="up")
    first = _prepare(kernel, dan.principal, sel, task_id="task-u", mono=Mono(), observer=None)
    recovered = FakeObserver(_desc())
    replay = _prepare(kernel, dan.principal, sel, task_id="task-u", mono=Mono(), observer=recovered)
    assert replay.replayed is True
    assert replay.binding.delivery_id == first.binding.delivery_id
    assert replay.binding.assignment_id == first.binding.assignment_id
    assert replay.binding.snapshot_status is SnapshotStatus.UNAVAILABLE
    assert replay.binding.source_snapshot_id is None
    assert replay.degraded_codes == ("snapshot_unavailable",)
    assert recovered.calls == []
    assert _entries(kernel, "snapshot.observed") == []


def test_explicit_invalid_snapshot_or_scope_never_downgrades_to_success(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    one = _register(kernel, clock, dan, alias="one", checkout=trusted_tmp / "one")
    two = _register(kernel, clock, dan, alias="two", checkout=trusted_tmp / "two")
    lone = _register(kernel, clock, dan, alias="lone", checkout=trusted_tmp / "lone", remote=None)
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    snap_one = kstore.transact(lambda tx: register_snapshot(tx, one, _desc(TREE_1)))
    snap_two = kstore.transact(lambda tx: register_snapshot(tx, two, _desc(TREE_2)))
    ok = _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="one", source_snapshot_id=snap_one),
        task_id="task-ok",
        mono=Mono(),
        observer=FakeObserver(_desc(TREE_2)),
    )
    assert ok.binding.snapshot_status is SnapshotStatus.AVAILABLE
    assert ok.binding.source_snapshot_id == snap_one
    observer = FakeObserver(_desc())
    cases: list[tuple[str, WorkspaceSelector, Scope | None, ErrorCode]] = [
        ("t-unknown", WorkspaceSelector(workspace_hint="one", source_snapshot_id=new_id()), None, ErrorCode.NOT_FOUND),
        ("t-foreign", WorkspaceSelector(workspace_hint="one", source_snapshot_id=snap_two), None, ErrorCode.NOT_FOUND),
        ("t-scope", WorkspaceSelector(workspace_hint="one"), Scope(two.repo_id, two.checkout_id), ErrorCode.NOT_FOUND),
        (
            "t-ids",
            WorkspaceSelector(workspace_id=lone.repo_id, checkout_id=one.checkout_id),
            None,
            ErrorCode.NOT_FOUND,
        ),
    ]
    snap_digest = kstore.transact(lambda tx: tx.read_source_snapshot(snap_one))
    assert snap_digest is not None
    kernel.policy.record_intent(IntentKind.QUARANTINE, {"digest": snap_digest.descriptor_digest})
    kernel.store.reconcile_policy()
    cases.append(
        ("t-quar", WorkspaceSelector(workspace_hint="one", source_snapshot_id=snap_one), None, ErrorCode.QUARANTINED)
    )
    for task_id, selector, scope, code in cases:
        with pytest.raises(BrainError) as exc:
            _prepare(
                kernel, dan.principal, selector, task_id=task_id, mono=Mono(), observer=observer, selected_scope=scope
            )
        assert exc.value.code is code, task_id
    assert observer.calls == []
    assert [e.meta["task_id"] for e in _entries(kernel, "lineage.task_bound")] == ["task-ok"]


def test_observer_uses_remaining_local_budget(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    _register(kernel, clock, dan, alias="bud", checkout=trusted_tmp / "bud")
    sel = WorkspaceSelector(workspace_hint="bud")
    far = Mono()
    far_start = far()
    observer = FakeObserver(_desc())
    _prepare(kernel, dan.principal, sel, task_id="b-far", mono=far, observer=observer)
    assert observer.calls[-1][1] == far_start + 100 * MS
    near = Mono()
    observer_near = FakeObserver(_desc(TREE_2), mono=near, consume_ns=10 * MS)
    start = near()
    delivery = _prepare(
        kernel, dan.principal, sel, task_id="b-near", mono=near, observer=observer_near, total_ns=250 * MS
    )
    assert observer_near.calls[-1][1] == start + 50 * MS
    assert delivery.binding.snapshot_status is SnapshotStatus.AVAILABLE
    exhausted = Mono()
    late_desc = _desc("sha256:" + "3" * 64)
    late = FakeObserver(late_desc, mono=exhausted, consume_ns=101 * MS)
    labeled = _prepare(kernel, dan.principal, sel, task_id="b-late", mono=exhausted, observer=late)
    assert labeled.binding.snapshot_status is SnapshotStatus.DEADLINE
    assert labeled.binding.source_snapshot_id is None
    recorded = [e.meta["descriptor_digest"] for e in _entries(kernel, "snapshot.observed")]
    assert recorded == [_desc(TREE_1).descriptor_digest, _desc(TREE_2).descriptor_digest]
    assert late_desc.descriptor_digest not in recorded  # the late descriptor is never recorded


def test_total_deadline_has_no_committed_delivery_before_commit(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    _register(kernel, clock, dan, alias="dl", checkout=trusted_tmp / "dl")
    sel = WorkspaceSelector(workspace_hint="dl")
    expired_observer = FakeObserver(_desc())
    with pytest.raises(BrainError) as exc_expired:
        _prepare(kernel, dan.principal, sel, task_id="d-1", mono=Mono(), observer=expired_observer, total_ns=200 * MS)
    assert exc_expired.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert expired_observer.calls == []
    mono = Mono()
    eats_window = FakeObserver(_desc(), mono=mono, consume_ns=60 * MS)
    with pytest.raises(BrainError) as exc_window:
        _prepare(kernel, dan.principal, sel, task_id="d-2", mono=mono, observer=eats_window, total_ns=250 * MS)
    assert exc_window.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert len(eats_window.calls) == 1
    assert _entries(kernel, "lineage.task_bound") == []
    assert _entries(kernel, "snapshot.observed") == []
    remaining = _rows(kernel, ("p_task_lineage_", "p_source_snapshots_"))
    assert remaining and all(rows == [] for rows in remaining.values())


def test_missing_snapshot_preserves_known_lineage_and_has_no_snapshot_record(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="nos", checkout=trusted_tmp / "nos")
    served = _source(binding, "art-served")
    delivery = _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="nos"),
        task_id="task-n",
        mono=Mono(),
        observer=None,
        served=(served,),
    )
    assert delivery.binding.source_snapshot_id is None
    assert delivery.task_unknown is False
    added = {
        (e.meta["source_kind"], e.meta["source_id"], e.meta["repo_id"])
        for e in _entries(kernel, "lineage.task_source_added")
    }
    assert ("workspace_binding", binding.checkout_id, binding.repo_id) in added
    assert ("artifact", "art-served", binding.repo_id) in added
    assert _entries(kernel, "snapshot.observed") == []
    assert all(rows == [] for name, rows in _rows(kernel, ("p_source_snapshots_",)).items())
    assert _entries(kernel, "lineage.task_unknown_marked") == []


# --- rebuild, quarantine and authority ----------------------------------------------------------------------------


def test_snapshot_and_lineage_rebuild_from_ledger(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _register(kernel, clock, dan, alias="rb", checkout=trusted_tmp / "rb")
    src = _source(binding, "art-rb")
    _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="rb"),
        task_id="rb-1",
        mono=Mono(),
        observer=FakeObserver(_desc()),
        items=(DeliveryItem(("a",), frozenset({src})),),
        served=(src,),
    )
    _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="rb"),
        task_id="rb-2",
        mono=Mono(),
        observer=None,
        items=(DeliveryItem(("b", 1), frozenset(), unknown_source=True),),
    )
    before = _rows(kernel)
    assert before and all(before.values())
    with kernel.store.transaction() as txn:
        for name in before:
            txn.db.execute(f'DROP TABLE "{name}"')
    import superbrain.core.ids as ids_mod

    with monkeypatch.context() as guard:
        _no_fs_net_exec(guard)
        guard.setattr(ids_mod._default, "next", lambda: (_ for _ in ()).throw(AssertionError("no new ids")))
        kernel.store.rebuild_projections()
    assert _rows(kernel) == before


def test_lineage_unknown_survives_quarantine_and_rebuild(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="qr", checkout=trusted_tmp / "qr", egress=True)
    src = _source(binding, "art-q")
    delivery = _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="qr"),
        task_id="q-1",
        mono=Mono(),
        observer=FakeObserver(_desc()),
        items=(DeliveryItem(("k",), frozenset({src})), DeliveryItem(("u",), frozenset(), unknown_source=True)),
        served=(src,),
    )
    snapshot_id = delivery.binding.source_snapshot_id
    assert snapshot_id is not None
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    snap = kstore.transact(lambda tx: tx.read_source_snapshot(snapshot_id))
    assert snap is not None
    kernel.policy.record_intent(IntentKind.QUARANTINE, {"digest": snap.descriptor_digest})
    kernel.policy.record_intent(IntentKind.QUARANTINE, {"digest": src.source.digest})
    kernel.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": snapshot_id})
    kernel.store.reconcile_policy()
    kernel.store.rebuild_projections()
    fields = kstore.transact(lambda tx: tx.read_field_lineage("q-1"))
    unknown = fields[field_path_digest(("u",))]
    known = fields[field_path_digest(("k",))]
    assert unknown.unknown_source is True
    assert src in known.sources
    lineage, task_unknown = kstore.transact(lambda tx: tx.read_task_lineage("q-1"))
    assert task_unknown is True and src in lineage
    assert kstore.transact(lambda tx: tx.read_source_snapshot(snapshot_id)) == snap
    restrictions = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": src.__eq__})
    known_field = LineagedField(value=None, sources=known.sources)
    assert evaluate_egress_eligibility(known_field, kernel.policy, restrictions=restrictions) is False
    unknown_field = LineagedField(None, unknown.sources, True)
    assert evaluate_egress_eligibility(unknown_field, kernel.policy, restrictions=restrictions) is False


def test_restore_store_older_than_registration_keeps_ids_and_grants(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "restore-root"
    rt = _open(root, os_)
    try:
        store_id = rt.policy.store_id
        seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        clock.advance(dt.timedelta(seconds=5))
        old_backup = create_store_backup(rt.store, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        binding = _register(rt, clock, seeded, alias="kept", checkout=trusted_tmp / "kept")
        # killed before Store.reconcile_policy: the registration exists only in policy
    finally:
        rt.close()
    clock.advance(dt.timedelta(hours=2))  # the ingress authorization has long expired
    with maintenance_lease(root, os_) as (mroot, mlease):
        pol = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(mroot, mlease, os_, old_backup, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()
    for _round in (1, 2):
        clock.advance(dt.timedelta(seconds=5))
        again = _reopen(root, store_id, os_)
        try:
            resolved = resolve_binding(seeded.principal, WorkspaceSelector(workspace_hint="kept"), again.policy)
            assert (resolved.repo_id, resolved.checkout_id) == (binding.repo_id, binding.checkout_id)
            assert again.policy.allows(
                seeded.principal, Scope(binding.repo_id, binding.checkout_id), action="prepare_task"
            )
            audits = _entries(again, "policy.workspace_register")
            assert len(audits) == 1 and audits[0].meta["checkout_id"] == binding.checkout_id
            mirror = StoreWorkspaceMirror(again.store).mirror_candidates(alias="kept")
            assert [(m.repo_id, m.checkout_id) for m in mirror] == [(binding.repo_id, binding.checkout_id)]
        finally:
            again.close()


def test_policy_rollback_does_not_resurrect_registry_from_main(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "rollback-root"
    rt = _open(root, os_)
    try:
        store_id = rt.policy.store_id
        seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        clock.advance(dt.timedelta(seconds=5))
        old_policy = create_policy_backup(rt.policy, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        binding = _register(rt, clock, seeded, alias="gone", checkout=trusted_tmp / "gone")
        rt.store.reconcile_policy()
        _prepare(
            rt, seeded.principal, WorkspaceSelector(workspace_hint="gone"), task_id="t-old", mono=Mono(), observer=None
        )
    finally:
        rt.close()
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root, os_) as (mroot, mlease):
        restore_policy(
            mroot, mlease, os_, old_policy, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )
    again = _reopen(root, store_id, os_)
    try:
        assert StoreWorkspaceMirror(again.store).mirror_candidates(alias="gone")  # the stale mirror is still there
        for selector in (
            WorkspaceSelector(workspace_hint="gone"),
            WorkspaceSelector(workspace_id=binding.repo_id, checkout_id=binding.checkout_id),
        ):
            with pytest.raises(BrainError) as exc:
                resolve_binding(seeded.principal, selector, again.policy)
            assert exc.value.code is ErrorCode.NOT_FOUND
        assert (
            again.policy.allows(seeded.principal, Scope(binding.repo_id, binding.checkout_id), action="prepare_task")
            is False
        )
        with pytest.raises(BrainError) as exc_task:
            resolve_task_binding(
                KernelWorkspaceStore(again.store, again.policy), again.policy, seeded.principal, "t-old"
            )
        assert exc_task.value.code is ErrorCode.NOT_FOUND
        snap = again.policy.snapshot()
        assert snap.checkouts == {} and snap.repo_policies == {} and snap.grants == frozenset()
    finally:
        again.close()


def test_workspace_authorization_ignores_main_mirror(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    real = _register(kernel, clock, dan, alias="real", checkout=trusted_tmp / "real")
    kernel.store.reconcile_policy()
    with kernel.store.transaction() as txn:
        cols = [str(r[1]) for r in txn.db.execute("PRAGMA table_info(p_workspace_registry_checkouts)").fetchall()]
        forged: dict[str, object] = {name: None for name in cols}
        forged.update(
            checkout_id="forged-chk",
            repo_id=real.repo_id,
            principal_id=dan.principal.principal_id,
            machine_id="box-1",
            alias="forged",
            intent_id=new_id(),
            handler_version=2,
            sequence=999,
        )
        txn.db.execute(
            f"INSERT INTO p_workspace_registry_checkouts ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            [forged[c] for c in cols],
        )
    assert StoreWorkspaceMirror(kernel.store).mirror_candidates(alias="forged")
    with pytest.raises(BrainError) as exc:
        resolve_binding(dan.principal, WorkspaceSelector(workspace_hint="forged"), kernel.policy)
    assert exc.value.code is ErrorCode.NOT_FOUND
    with pytest.raises(BrainError):
        resolve_binding(
            dan.principal, WorkspaceSelector(workspace_id=real.repo_id, checkout_id="forged-chk"), kernel.policy
        )
    assert kernel.policy.allows(dan.principal, Scope(real.repo_id, "forged-chk"), action="prepare_task") is False
    kernel.store.rebuild_projections()
    assert StoreWorkspaceMirror(kernel.store).mirror_candidates(alias="forged") == ()
    assert len(StoreWorkspaceMirror(kernel.store).mirror_candidates(alias="real")) == 1

    # AST/import guard: application authorization never reaches the main-store mirror or storage.
    for path in sorted((SRC / "application").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        imported = {(node.module or "") for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        }
        assert "WorkspaceMirrorReadPort" not in names | attrs, path
        assert "mirror_candidates" not in names | attrs, path
        assert not any("p_workspace_registry" in c for c in consts), path
        assert not any(m.startswith(("superbrain.storage", "superbrain.adapters")) for m in imported), path
    lineage_tree = ast.parse((SRC / "application" / "lineage.py").read_text(encoding="utf-8"))
    funcs = {n.name: n for n in ast.walk(lineage_tree) if isinstance(n, ast.FunctionDef)}
    if "resolve_binding" not in funcs:  # re-exported from an internal application module
        for path in sorted((SRC / "application").glob("_*.py")):
            sub = ast.parse(path.read_text(encoding="utf-8"))
            funcs.update({n.name: n for n in ast.walk(sub) if isinstance(n, ast.FunctionDef)})
    policy_arg = next(a for a in funcs["resolve_binding"].args.args if a.arg == "policy")
    assert ast.unparse(policy_arg.annotation) == "KernelPolicyPort"  # type: ignore[arg-type]
    ports_tree = ast.parse((SRC / "ports" / "kernel.py").read_text(encoding="utf-8"))
    classes = {n.name: n for n in ast.walk(ports_tree) if isinstance(n, ast.ClassDef)}
    policy_methods = {n.name for n in classes["KernelPolicyPort"].body if isinstance(n, ast.FunctionDef)}
    mirror_methods = {n.name for n in classes["WorkspaceMirrorReadPort"].body if isinstance(n, ast.FunctionDef)}
    assert not policy_methods & mirror_methods
    assert "mirror_candidates" not in policy_methods
    assert not {"allows", "snapshot", "resolve_credential"} & mirror_methods


def test_mirror_projection_accepts_legacy_v1_and_v2_entries() -> None:
    proj = WorkspaceRegistryMirrorProjection()
    assert proj.handler_version == 2
    ws_kind = next(k for k in KERNEL_POLICY_KINDS if k.kind == "policy.workspace_register")
    assert proj.handler_version == ws_kind.handler_version
    assert SnapshotProjection().handler_version == 1
    assert TaskLineageProjection().handler_version == 1
    assert FieldLineageProjection().handler_version == 1
    db = sqlite3.connect(":memory:")
    proj.create_tables(db, "p_workspace_registry_")
    base: dict[str, JsonValue] = {
        "intent_id": new_id(),
        "repo_id": "repo-1",
        "checkout_id": "chk-1",
        "principal_id": "p-1",
        "machine_id": "box-1",
        "alias": "legacy",
        "locator_digest": None,
    }

    def entry(seq: int, hv: int, meta: Mapping[str, JsonValue]) -> LedgerEntry:
        return LedgerEntry(
            seq,
            new_id(),
            "policy.workspace_register",
            3,
            hv,
            1,
            "system:policy",
            None,
            "2026-11-06T00:00:00.000000Z",
            meta,
            (),
        )

    proj.apply(db, "p_workspace_registry_", entry(1, 1, base), _NoPolicy())
    proj.apply(
        db,
        "p_workspace_registry_",
        entry(2, 2, {**base, "checkout_id": "chk-2", "alias": "v2-null", "subject_id": None}),
        _NoPolicy(),
    )
    proj.apply(
        db,
        "p_workspace_registry_",
        entry(3, 2, {**base, "checkout_id": "chk-3", "alias": "v2", "subject_id": "sha256:" + "e" * 64}),
        _NoPolicy(),
    )
    rows = db.execute(
        "SELECT checkout_id, subject_id, handler_version FROM p_workspace_registry_checkouts ORDER BY checkout_id"
    ).fetchall()
    assert rows == [("chk-1", None, 1), ("chk-2", None, 2), ("chk-3", "sha256:" + "e" * 64, 2)]
    bad_metas: tuple[dict[str, JsonValue], ...] = (
        {**base, "subject_id": "nope"},
        {**base, "repo_id": 7},
        {k: v for k, v in base.items() if k != "alias"},
    )
    for bad in bad_metas:
        with pytest.raises(BrainError) as exc:
            proj.apply(db, "p_workspace_registry_", entry(9, 2, bad), _NoPolicy())
        assert exc.value.code is ErrorCode.INTEGRITY_FAILURE
    handlers, kinds = kernel_store_extensions()
    assert {h.name for h in handlers} == {
        "workspace_registry",
        "source_snapshots",
        "task_lineage",
        "field_lineage",
        "jobs",  # Task 5 reducers are registered by the same composition function (task-5-brief, reconciliation)
        "provider_invocations",
    }
    assert {k.kind for k in KERNEL_WORKSPACE_KINDS} <= kinds.kinds()


class _NoPolicy:
    def is_quarantined(self, digest: str) -> bool:
        return False

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        return False


def test_snapshot_cache_does_not_trust_mtime_size(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkout = trusted_tmp / "observed"
    (checkout / "src").mkdir(parents=True)
    target = checkout / "src" / "f.txt"
    target.write_bytes(b"AAAA")
    stamp = os.stat(target)
    binding = WorkspaceBinding(
        owner_id="dan",
        repo_id="repo-o",
        checkout_id="chk-o",
        machine_id="box-1",
        alias="obs",
        checkout_path=os.path.realpath(checkout),
    )
    observer = DirectorySnapshotObserver(clock=FakeClock(dt.datetime(2026, 11, 6, tzinfo=dt.UTC)))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no exec")))
    far = 10**30
    first = observer.observe(binding, far)
    target.write_bytes(b"BBBB")
    os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert os.stat(target).st_size == stamp.st_size and os.stat(target).st_mtime_ns == stamp.st_mtime_ns
    second = observer.observe(binding, far)
    assert first.status is SnapshotStatus.AVAILABLE and second.status is SnapshotStatus.AVAILABLE
    assert first.descriptor is not None and second.descriptor is not None
    assert first.descriptor.descriptor_digest != second.descriptor.descriptor_digest
    expired = observer.observe(binding, 0)
    assert expired.status is SnapshotStatus.DEADLINE and expired.descriptor is None


# --- fix round 1 ------------------------------------------------------------------------------------------------


def _snapshot_ref(binding: WorkspaceBinding, snapshot_id: str, descriptor_digest: str) -> LineageRef:
    return LineageRef(
        owner_id=binding.owner_id,
        repo_id=binding.repo_id,
        source=ObjectRef(kind="source_snapshot", id=snapshot_id, revision=1, digest=descriptor_digest),
    )


def test_source_restrictions_cover_any_unresolvable_source(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="rs", checkout=trusted_tmp / "rs", egress=True)
    src = _source(binding, "art-r")
    delivery = _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="rs"),
        task_id="rs-1",
        mono=Mono(),
        observer=FakeObserver(_desc()),
        served=(src,),
    )
    snapshot_id = delivery.binding.source_snapshot_id
    assert snapshot_id is not None
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    lineage, _unknown = kstore.transact(lambda tx: tx.read_task_lineage("rs-1"))
    binding_ref = next(ref for ref in lineage if ref.source.kind == "workspace_binding")
    snap = _desc().descriptor_digest
    snap_ref = _snapshot_ref(binding, snapshot_id, snap)
    plain = StoreSourceRestrictions(kernel.store, kernel.policy)
    assert plain.is_restricted(binding_ref) is False
    assert plain.is_restricted(snap_ref) is False
    assert plain.is_restricted(src) is True  # no resolver for the kind: unresolvable, so restricted
    forged_binding = LineageRef(
        binding.owner_id, binding.repo_id, ObjectRef("workspace_binding", "chk-forged", 1, binding_ref.source.digest)
    )
    tampered_binding = LineageRef(
        binding.owner_id, binding.repo_id, ObjectRef("workspace_binding", binding.checkout_id, 1, "sha256:" + "f" * 64)
    )
    for ref in (
        forged_binding,
        tampered_binding,
        _snapshot_ref(binding, new_id(), snap),
        _snapshot_ref(binding, snapshot_id, "sha256:" + "e" * 64),
        LineageRef("dan", binding.repo_id, ObjectRef("lesson", "les-1", 1, digest_bytes(b"x"))),
    ):
        assert plain.is_restricted(ref) is True, ref
    resolving = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": src.__eq__})
    assert resolving.is_restricted(src) is False
    assert resolving.is_restricted(_source(binding, "art-other")) is True
    blob_path(kernel.root.cas_dir, snap).unlink()
    assert plain.is_restricted(snap_ref) is True  # descriptor blob missing
    kernel.policy.record_intent(IntentKind.QUARANTINE, {"digest": src.source.digest})
    kernel.store.reconcile_policy()
    assert resolving.is_restricted(src) is True


def test_explicit_tombstoned_or_blobless_snapshot_is_refused(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="ex", checkout=trusted_tmp / "ex")
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    tombstoned = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
    blobless = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_2)))
    kernel.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": tombstoned})
    kernel.store.reconcile_policy()
    blob_path(kernel.root.cas_dir, _desc(TREE_2).descriptor_digest).unlink()
    observer = FakeObserver(_desc())
    for task_id, snapshot_id in (("ex-t", tombstoned), ("ex-b", blobless)):
        with pytest.raises(BrainError) as exc:
            _prepare(
                kernel,
                dan.principal,
                WorkspaceSelector(workspace_hint="ex", source_snapshot_id=snapshot_id),
                task_id=task_id,
                mono=Mono(),
                observer=observer,
            )
        assert exc.value.code is ErrorCode.NOT_FOUND, task_id
    assert observer.calls == []
    assert _entries(kernel, "lineage.task_bound") == []


def test_snapshot_dedupe_never_reuses_a_restricted_snapshot(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    binding = _register(kernel, clock, dan, alias="dd", checkout=trusted_tmp / "dd")
    sel = WorkspaceSelector(workspace_hint="dd")
    digest = _desc().descriptor_digest
    first = _prepare(kernel, dan.principal, sel, task_id="dd-1", mono=Mono(), observer=FakeObserver(_desc()))
    s1 = first.binding.source_snapshot_id
    assert s1 is not None
    kernel.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": s1})
    kernel.store.reconcile_policy()
    second = _prepare(kernel, dan.principal, sel, task_id="dd-2", mono=Mono(), observer=FakeObserver(_desc()))
    s2 = second.binding.source_snapshot_id
    assert second.binding.snapshot_status is SnapshotStatus.AVAILABLE and s2 not in (None, s1)
    blob_path(kernel.root.cas_dir, digest).unlink()
    third = _prepare(kernel, dan.principal, sel, task_id="dd-3", mono=Mono(), observer=FakeObserver(_desc()))
    assert third.binding.snapshot_status is SnapshotStatus.AVAILABLE
    assert third.binding.source_snapshot_id not in (None, s1, s2)
    assert kernel.store.cas.blob_intact(digest)
    kernel.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest})
    kernel.store.reconcile_policy()
    fourth = _prepare(kernel, dan.principal, sel, task_id="dd-4", mono=Mono(), observer=FakeObserver(_desc()))
    assert fourth.binding.snapshot_status is SnapshotStatus.UNAVAILABLE
    assert fourth.binding.source_snapshot_id is None
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    with pytest.raises(BrainError) as exc:
        kstore.transact(lambda tx: register_snapshot(tx, binding, _desc()))
    assert exc.value.code is ErrorCode.QUARANTINED


def test_handoff_lineage_from_stored_t1_is_inherited_by_t2(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    repo_a = _register(kernel, clock, dan, alias="ha", checkout=trusted_tmp / "ha", remote="https://h.example/o/a.git")
    repo_b = _register(kernel, clock, dan, alias="hb", checkout=trusted_tmp / "hb", remote="https://h.example/o/b.git")
    repo_c = _register(kernel, clock, dan, alias="hc", checkout=trusted_tmp / "hc", remote="https://h.example/o/c.git")
    src_a = _source(repo_a, "art-a")
    _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="hb"),
        task_id="T1",
        mono=Mono(),
        observer=None,
        items=(DeliveryItem(("handoff",), frozenset({src_a})),),
        served=(src_a,),
    )
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    kernel.store.rebuild_projections()  # T2 must see what the ledger/projection holds, not T1's in-memory result
    t1 = resolve_task_binding(kstore, kernel.policy, dan.principal, "T1")
    assert t1.repo_id == repo_b.repo_id
    t1_lineage, t1_unknown = kstore.transact(lambda tx: tx.read_task_lineage("T1"))
    _prepare(
        kernel,
        dan.principal,
        WorkspaceSelector(workspace_hint="hc"),
        task_id="T2",
        mono=Mono(),
        observer=None,
        items=(DeliveryItem(("derived",), t1_lineage, unknown_source=t1_unknown),),
    )
    stored = kstore.transact(lambda tx: tx.read_field_lineage("T2"))[field_path_digest(("derived",))]
    assert src_a in stored.sources
    # I2-T3-R02 (spec 14.2: content created in a task inherits the task's current lineage, not only its repo): the
    # field derived inside T2 (bound to C) carries A+B from the T1 handoff plus C. The earlier {A, B} oracle locked
    # the defect the Task 3 review reproduced; corrected by the independent test author.
    assert {ref.repo_id for ref in stored.sources} == {repo_a.repo_id, repo_b.repo_id, repo_c.repo_id}
    t2_lineage, _ = kstore.transact(lambda tx: tx.read_task_lineage("T2"))
    assert {ref.repo_id for ref in t2_lineage} == {repo_a.repo_id, repo_b.repo_id, repo_c.repo_id}
