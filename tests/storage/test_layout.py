import dataclasses
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import DurabilityReport, DurablePublisher, OsAdapters, PermissionGuard, PermissionProblem
from superbrain.storage.layout import RESERVED_ENTRIES, DataRoot, prepare_data_root, secure_subdirectories
from superbrain.storage.writer import acquire_writer
from tests.support.fs import digest_tree, fake_link, modes_tree
from tests.support.platform import posix_only, windows_only


def make_entry(root: Path, entry: str) -> None:
    target = root / entry
    target.parent.mkdir(parents=True, exist_ok=True)
    if Path(entry).suffix in {".lock", ".db"}:
        target.write_bytes(b"existing")
    else:
        target.mkdir()


class SpyGuard:
    """Delegates to the real guard; records secured directories and can inject problems."""

    def __init__(self, real: PermissionGuard, *, ancestor_problem_on_call: int = 0, tree_problem: bool = False):
        self.real = real
        self.secured: list[Path] = []
        self.ancestor_calls = 0
        self.ancestor_problem_on_call = ancestor_problem_on_call
        self.tree_problem = tree_problem

    def secure_directory(self, path: Path) -> None:
        self.secured.append(path)
        self.real.secure_directory(path)

    def secure_file(self, path: Path) -> None:
        self.real.secure_file(path)

    def object_problems(self, path: Path) -> list[PermissionProblem]:
        return self.real.object_problems(path)

    def problems(self, root: Path) -> list[PermissionProblem]:
        if self.tree_problem:
            return [PermissionProblem(root, "injected")]
        return self.real.problems(root)

    def check_ancestors(self, path: Path) -> list[PermissionProblem]:
        self.ancestor_calls += 1
        if self.ancestor_calls == self.ancestor_problem_on_call:
            return [PermissionProblem(path.parent, "injected")]
        return self.real.check_ancestors(path)


def with_guard(guard: SpyGuard) -> OsAdapters:
    return dataclasses.replace(os_adapters(), permissions=guard)


class SyncSpy:
    """Delegates to the real publisher and records every ``sync_directory`` call."""

    def __init__(self, real: DurablePublisher) -> None:
        self.real = real
        self.synced: list[Path] = []

    def write_new(self, path: Path, data: bytes) -> None:
        self.real.write_new(path, data)

    def publish(self, staging: Path, final: Path) -> None:
        self.real.publish(staging, final)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self.real.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self.synced.append(directory)
        self.real.sync_directory(directory)

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        return self.real.durability(directory, env)


def with_sync_spy(spy: SyncSpy) -> OsAdapters:
    return dataclasses.replace(os_adapters(), publisher=spy)


def loosen(path: Path) -> None:
    """Grant others read access to ``path``."""
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(path, "S-1-1-0", 0x120089)  # Everyone: FILE_GENERIC_READ
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def make_owner_only_dir(path: Path) -> None:
    path.mkdir()  # on Windows it inherits the owner-only rules (mode=0o700 would add Administrators on 3.13+)
    if sys.platform != "win32":
        os.chmod(path, 0o700)


def make_owner_only_file(path: Path, data: bytes = b"existing") -> None:
    path.write_bytes(data)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def existing_root(base: Path) -> Path:
    """A root made by hand; on Windows its entries inherit owner-only rules instead of having them set."""
    root = base / "r"
    make_owner_only_dir(root)
    make_owner_only_file(root / "writer.lock", b"")
    make_owner_only_dir(root / "store")
    make_owner_only_file(root / "store" / "x.db")
    make_owner_only_dir(root / "store.x")
    return root


def test_reserved_entries() -> None:
    assert RESERVED_ENTRIES == (
        "writer.lock",
        "policy",
        "policy/policy.db",
        "policy/policy.db-wal",
        "policy/policy.db-shm",
        "store",
        "store/brain.db",
        "store/brain.db-wal",
        "store/brain.db-shm",
        "store/cas",
        "store/staging",
        "outbox",
        "logs",
        "backups",
    )


def test_data_root_paths(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    r = trusted_tmp / "r"
    assert root == DataRoot(
        root=r,
        lock_path=r / "writer.lock",
        policy_dir=r / "policy",
        store_dir=r / "store",
        outbox_dir=r / "outbox",
        logs_dir=r / "logs",
        backups_dir=r / "backups",
    )
    assert (root.policy_db, root.store_db, root.cas_dir, root.staging_dir) == (
        r / "policy" / "policy.db",
        r / "store" / "brain.db",
        r / "store" / "cas",
        r / "store" / "staging",
    )


@pytest.mark.parametrize(
    "entry", ["writer.lock", "store", "policy", "store/brain.db", "store/cas", "store/staging", "store.restoring"]
)
def test_prepare_refuses_linked_reserved_entry_before_touching_anything(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    # ported from test_runtime_refuses_linked_state_before_opening_writer (blob 7c48659)
    root = trusted_tmp / "r"
    make_entry(root, entry)
    fake_link(monkeypatch, root / entry)
    before = digest_tree(trusted_tmp)
    modes = modes_tree(trusted_tmp)
    with pytest.raises(BrainError) as e:
        prepare_data_root(root, os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH and digest_tree(trusted_tmp) == before
    assert modes_tree(trusted_tmp) == modes


def test_prepare_refuses_linked_root(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = trusted_tmp / "r"
    root.mkdir()
    fake_link(monkeypatch, root)
    with pytest.raises(BrainError) as e:
        prepare_data_root(root, os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH and not (root / "writer.lock").exists()


@windows_only
def test_prepare_refuses_unsafe_path_spelling(trusted_tmp: Path) -> None:
    with pytest.raises(BrainError) as e:
        prepare_data_root(Path("\\\\?\\" + str(trusted_tmp / "r")), os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH and not (trusted_tmp / "r").exists()


def test_prepare_touches_only_root_and_lock(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    assert sorted(p.name for p in root.root.iterdir()) == ["writer.lock"]
    assert os_adapters().permissions.problems(root.root) == []


def test_prepare_is_idempotent_and_keeps_existing_content(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    with acquire_writer(root, os_adapters()):
        pass
    lock_bytes = root.lock_path.read_bytes()
    assert prepare_data_root(trusted_tmp / "r", os_adapters()) == root
    assert root.lock_path.read_bytes() == lock_bytes


def test_prepare_refuses_insecure_ancestor_before_creating_anything(trusted_tmp: Path) -> None:
    guard = SpyGuard(os_adapters().permissions, ancestor_problem_on_call=1)
    before = digest_tree(trusted_tmp)
    with pytest.raises(BrainError) as e:
        prepare_data_root(trusted_tmp / "a" / "r", with_guard(guard))
    assert e.value.code == ErrorCode.INSECURE_PERMISSIONS
    assert digest_tree(trusted_tmp) == before and guard.secured == []


@pytest.mark.parametrize("problem", ["ancestor", "tree"])
def test_prepare_fails_closed_on_problems_found_after_creation(trusted_tmp: Path, problem: str) -> None:
    if problem == "ancestor":
        guard = SpyGuard(os_adapters().permissions, ancestor_problem_on_call=2)
    else:
        guard = SpyGuard(os_adapters().permissions, tree_problem=True)
    with pytest.raises(BrainError) as e:
        prepare_data_root(trusted_tmp / "a" / "r", with_guard(guard))
    assert e.value.code == ErrorCode.INSECURE_PERMISSIONS


def test_prepare_creates_and_secures_each_missing_directory(trusted_tmp: Path) -> None:
    guard = SpyGuard(os_adapters().permissions)
    prepare_data_root(trusted_tmp / "a" / "b" / "r", with_guard(guard))
    a = trusted_tmp / "a"
    assert guard.secured[:3] == [a, a / "b", a / "b" / "r"]
    assert os_adapters().permissions.problems(a) == []


def test_prepare_leaves_an_existing_root_untouched(trusted_tmp: Path) -> None:
    root = existing_root(trusted_tmp)
    before, modes = digest_tree(trusted_tmp), modes_tree(trusted_tmp)
    assert prepare_data_root(root, os_adapters()).root == root
    assert digest_tree(trusted_tmp) == before and modes_tree(trusted_tmp) == modes


@pytest.mark.parametrize("loose", ["root", "writer.lock"])
def test_prepare_refuses_an_existing_entry_others_can_access(trusted_tmp: Path, loose: str) -> None:
    root = existing_root(trusted_tmp)
    if loose == "root":
        (root / "writer.lock").unlink()  # a missing lock would be created if the check came too late
    loosen(root if loose == "root" else root / "writer.lock")
    before, modes = digest_tree(trusted_tmp), modes_tree(trusted_tmp)
    with pytest.raises(BrainError) as e:
        prepare_data_root(root, os_adapters())
    assert e.value.code == ErrorCode.INSECURE_PERMISSIONS
    assert digest_tree(trusted_tmp) == before and modes_tree(trusted_tmp) == modes


def test_prepare_syncs_the_parent_of_everything_it_creates(trusted_tmp: Path) -> None:
    spy = SyncSpy(os_adapters().publisher)
    a = trusted_tmp / "a"
    prepare_data_root(a / "r", with_sync_spy(spy))
    assert spy.synced == [trusted_tmp, a, a / "r"]  # after creating a, r, then writer.lock


def test_prepare_syncs_nothing_for_an_existing_root(trusted_tmp: Path) -> None:
    spy = SyncSpy(os_adapters().publisher)
    prepare_data_root(existing_root(trusted_tmp), with_sync_spy(spy))
    assert spy.synced == []


@windows_only
def test_created_directories_do_not_keep_inherited_takeover_aces(trusted_tmp: Path) -> None:
    # check_ancestors skips inherit-only ACEs, so a directory created below one would inherit them unless secured.
    from tests.support.winacl import grant

    object_inherit, container_inherit, inherit_only = 0x1, 0x2, 0x8
    grant(trusted_tmp, "S-1-1-0", 0x1F01FF, object_inherit | container_inherit | inherit_only)  # FILE_ALL_ACCESS
    root = prepare_data_root(trusted_tmp / "a" / "r", os_adapters())
    assert os_adapters().permissions.check_ancestors(root.root) == []
    assert os_adapters().permissions.problems(trusted_tmp / "a") == []


@posix_only
def test_prepare_sets_owner_only_umask(trusted_tmp: Path) -> None:
    prepare_data_root(trusted_tmp / "r", os_adapters())
    current = os.umask(0o077)
    assert current == 0o077
    assert stat.S_IMODE((trusted_tmp / "r" / "writer.lock").stat().st_mode) == 0o600


def test_subdirectories_are_secured_under_lease(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "Lê Trung", os_adapters())  # Review Focus 1
    with acquire_writer(root, os_adapters()) as lease:
        secure_subdirectories(root, lease, os_adapters())
    for directory in (root.policy_dir, root.store_dir, root.cas_dir, root.staging_dir, root.outbox_dir):
        assert directory.is_dir()
    assert root.logs_dir.is_dir() and root.backups_dir.is_dir()
    assert os_adapters().permissions.problems(root.root) == []


def test_secure_subdirectories_syncs_the_parent_of_each_new_directory(trusted_tmp: Path) -> None:
    spy = SyncSpy(os_adapters().publisher)
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    with acquire_writer(root, os_adapters()) as lease:
        secure_subdirectories(root, lease, with_sync_spy(spy))
    r, store = root.root, root.store_dir
    # policy, store, store/cas, store/staging, outbox, logs, backups
    assert spy.synced == [r, r, store, store, r, r, r]


def test_secure_subdirectories_leaves_existing_subdirectories_untouched(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    make_owner_only_dir(root.store_dir)
    make_owner_only_file(root.store_dir / "x.db")
    before, modes = digest_tree(root.store_dir), modes_tree(root.store_dir)
    with acquire_writer(root, os_adapters()) as lease:
        secure_subdirectories(root, lease, os_adapters())
    after_digest, after_modes = digest_tree(root.store_dir), modes_tree(root.store_dir)
    # cas/ and staging/ are new; everything that existed is unchanged.
    assert {k: after_digest[k] for k in before} == before and {k: after_modes[k] for k in modes} == modes


def test_secure_subdirectories_refuses_an_existing_loose_subdirectory(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    make_owner_only_dir(root.store_dir)
    loosen(root.store_dir)
    with acquire_writer(root, os_adapters()) as lease:
        # writer.lock is not read here: on Windows its locked byte 0 is unreadable during the lease.
        modes = modes_tree(root.root)
        with pytest.raises(BrainError) as e:
            secure_subdirectories(root, lease, os_adapters())
        assert e.value.code == ErrorCode.INSECURE_PERMISSIONS and modes_tree(root.root) == modes


def test_secure_subdirectories_rechecks_links(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    root.store_dir.mkdir()
    fake_link(monkeypatch, root.store_dir)
    with acquire_writer(root, os_adapters()) as lease:
        with pytest.raises(BrainError) as e:
            secure_subdirectories(root, lease, os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH and not root.cas_dir.exists()


def test_secure_subdirectories_requires_a_held_lease(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    with acquire_writer(root, os_adapters()) as lease:
        pass
    with pytest.raises(AssertionError):
        secure_subdirectories(root, lease, os_adapters())
    assert not root.store_dir.exists()


@windows_only  # case-insensitive names are a Windows filesystem property
def test_reserved_sibling_match_ignores_case_on_windows(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = trusted_tmp / "r"
    make_entry(root, "Store.Migrating")
    fake_link(monkeypatch, root / "Store.Migrating")
    with pytest.raises(BrainError) as e:
        prepare_data_root(root, os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH
