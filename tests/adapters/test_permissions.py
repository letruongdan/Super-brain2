import os
import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from superbrain.adapters.os.clock import SystemClock
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import PermissionGuard
from tests.support.clock import FakeClock
from tests.support.platform import posix_only, windows_only
from tests.support.winacl import fake_owner, grant


@pytest.fixture
def guard() -> PermissionGuard:
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard

        return WindowsPermissionGuard()
    else:
        from superbrain.adapters.os.permissions import PosixPermissionGuard

        return PosixPermissionGuard()


def secured_file(tmp_path: Path, guard: PermissionGuard) -> Path:
    d = tmp_path / "root"
    d.mkdir()
    guard.secure_directory(d)
    f = d / "x.db"
    f.write_bytes(b"x")
    guard.secure_file(f)
    return f


def test_secured_tree_has_no_problems(tmp_path: Path, guard: PermissionGuard) -> None:
    d = tmp_path / "root"
    d.mkdir()
    guard.secure_directory(d)
    f = d / "x.db"
    f.write_bytes(b"x")
    guard.secure_file(f)
    assert guard.problems(d) == []


def test_unsecured_nested_entry_is_found_recursively(tmp_path: Path, guard: PermissionGuard) -> None:
    f = secured_file(tmp_path, guard)
    sub = f.parent / "sub"
    sub.mkdir()
    guard.secure_directory(sub)
    inner = sub / "y.db"
    inner.write_bytes(b"y")
    if sys.platform != "win32":
        os.chmod(inner, 0o644)
    else:
        grant(inner, "S-1-1-0", 0x120089)  # FILE_GENERIC_READ
    assert [p.path for p in guard.problems(f.parent)] == [inner]


def test_securing_a_missing_path_raises_brain_error(tmp_path: Path, guard: PermissionGuard) -> None:
    with pytest.raises(BrainError) as err:
        guard.secure_directory(tmp_path / "missing")
    assert err.value.code is ErrorCode.INSECURE_PERMISSIONS


@posix_only
def test_posix_secure_modes(tmp_path: Path, guard: PermissionGuard) -> None:
    f = secured_file(tmp_path, guard)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700


@posix_only
def test_group_readable_file_is_reported(tmp_path: Path, guard: PermissionGuard) -> None:
    f = secured_file(tmp_path, guard)
    os.chmod(f, 0o640)
    assert [p.path for p in guard.problems(f.parent)] == [f]


@windows_only
def test_everyone_ace_is_reported(tmp_path: Path, guard: PermissionGuard) -> None:
    import ntsecuritycon

    f = secured_file(tmp_path, guard)
    grant(f, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    assert [p.path for p in guard.problems(f.parent)] == [f]


@windows_only
def test_foreign_owner_is_reported_even_with_safe_dacl(
    tmp_path: Path, guard: PermissionGuard, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = secured_file(tmp_path, guard)
    fake_owner(monkeypatch, f, "S-1-5-21-1-2-3-1001")
    assert [p.path for p in guard.problems(f.parent)] == [f]


@windows_only
def test_ancestor_with_delete_child_for_users_is_reported(tmp_path: Path, guard: PermissionGuard) -> None:
    import ntsecuritycon

    parent = tmp_path / "p"
    parent.mkdir()
    grant(parent, "S-1-5-32-545", ntsecuritycon.FILE_DELETE_CHILD)
    assert guard.check_ancestors(parent / "root") != []


@windows_only
def test_ancestor_with_only_add_file_for_users_is_accepted(tmp_path: Path, guard: PermissionGuard) -> None:
    import ntsecuritycon

    parent = tmp_path / "p"
    parent.mkdir()
    guard.secure_directory(parent)
    grant(parent, "S-1-5-32-545", ntsecuritycon.FILE_ADD_FILE | ntsecuritycon.FILE_ADD_SUBDIRECTORY)
    assert [x for x in guard.check_ancestors(parent / "root") if x.path == parent] == []


@windows_only
def test_foreign_owned_ancestor_with_safe_looking_dacl_is_reported(
    tmp_path: Path, guard: PermissionGuard, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "p"
    parent.mkdir()
    guard.secure_directory(parent)
    fake_owner(monkeypatch, parent, "S-1-5-21-1-2-3-1001")  # owner is another account; DACL is still user + SYSTEM
    assert [x.path for x in guard.check_ancestors(parent / "root") if x.path == parent] == [parent]


@windows_only
def test_trusted_owner_chain_is_accepted(tmp_path: Path, guard: PermissionGuard) -> None:
    # Hermetic: the chain below ``base`` is protected and owned by the current user. Whatever ACEs the machine's
    # temp directory carries (for example a sandbox account) must not influence the result.
    base = tmp_path / "base"
    base.mkdir()
    guard.secure_directory(base)
    nested = base / "a"
    nested.mkdir()
    problems = guard.check_ancestors(nested / "root")
    assert [x for x in problems if x.path.is_relative_to(base)] == []


@posix_only
def test_world_writable_ancestor_without_sticky_is_reported(tmp_path: Path, guard: PermissionGuard) -> None:
    p = tmp_path / "open"
    p.mkdir()
    os.chmod(p, 0o777)
    assert guard.check_ancestors(p / "root") != []


@posix_only
def test_sticky_world_writable_ancestor_is_accepted(tmp_path: Path, guard: PermissionGuard) -> None:
    p = tmp_path / "tmpdir"
    p.mkdir()
    os.chmod(p, 0o1777)
    assert [x for x in guard.check_ancestors(p / "root") if x.path == p] == []


def test_system_clock_is_utc_aware() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None and now.utcoffset() == timedelta(0)


def test_fake_clock_advances_and_sets() -> None:
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    clock.advance(timedelta(seconds=5))
    assert clock.now() == datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
    clock.set(datetime(2027, 1, 1, tzinfo=timezone(timedelta(hours=7))))
    assert clock.now() == datetime(2026, 12, 31, 17, tzinfo=UTC)


def test_fake_clock_refuses_naive_datetimes() -> None:
    with pytest.raises(AssertionError):
        FakeClock(datetime(2026, 1, 1))
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    with pytest.raises(AssertionError):
        clock.set(datetime(2026, 1, 1))
