"""Independent RED oracle for SP1 Increment 4 R7 remediation (Fix 1 & Fix 2).

Requirement sources:
- Fix 1 (shared scratch directory atomic creation race):
  - ``storage.runtime._ensure_scratch_base`` and ``composition.operator_entry._verified_ssh_scratch_dir``
  - Invariant: a shared scratch directory must never exist at its published path with inherited non-owner-only
    permissions (no creation-to-securing race window on Windows or POSIX); pre-existing or race-planted
    non-owner-only directories, regular files, and symlinks/reparse points must fail closed and must never be
    silently re-secured.
- Fix 2 (vanished-and-recreated transient entry race in permission walks):
  - ``application._doctor_fix.tighten_data_root_permissions``, ``adapters.os.permissions.problems``,
    ``storage._doctor_probes.check_permissions_strict``, and
    ``composition._doctor_fix_wiring.fresh_report_matches_live_state``
  - Invariant: when an entry listed below a walk root vanishes during inspection/scan/repair/pre-stat and is
    immediately recreated before follow-up lookup, the walk re-inspects the live entry rather than failing closed
    on a stale not-found error or identity mismatch -- succeeding when the recreated entry is clean owner-only,
    repairing/reporting it when widened, and failing closed when it is a link/junction, uninspectable, or the
    walk root itself.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application._doctor_fix import ensure_no_links_in_tree, tighten_data_root_permissions
from superbrain.composition.operator_entry import _verified_ssh_scratch_dir
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.doctor import DoctorScanLimits, PrivacyCanaryProbeResult, PrivacyScannerPort
from superbrain.ports.os import OsAdapters, PermissionProblem, PhysicalFsPort, PhysicalObjectId
from superbrain.storage._doctor_probes import run_privacy_rescan
from superbrain.storage._doctor_storage_probes import _collect_cas_digests
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import _ensure_scratch_base
from tests.integration.test_doctor_fix import _acl_or_mode, _grant_wide_access, _make_dir_link
from tests.integration.test_i4_vanished_entry_walk import (
    _clean_tree,
    _deny,
    _DenyLstat,
    _key,
    _matches,
    _not_found_then_deny_lookup,
    _patch_get_security,
    _patch_scandir,
    _patch_set_security,
    _probe,
    _tree,
    _Trigger,
)

if sys.platform == "win32":
    import ntsecuritycon
    import pywintypes


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _grant_inheritable_admin_ace(parent: Path) -> None:
    """Grant ``BUILTIN\\Administrators`` an inheritable ACE on ``parent`` while keeping ``check_ancestors`` clean.

    ``check_ancestors`` trusts ``S-1-5-32-544``, whereas ``object_problems`` rejects any SID outside
    ``{current_user, SYSTEM}``. A child created via ``mkdir()`` under ``parent`` therefore inherits
    ``S-1-5-32-544`` and fails ``object_problems`` until explicitly secured.
    """
    if sys.platform != "win32":
        raise AssertionError("Windows-only helper")
    else:
        from tests.support.winacl import grant

        grant(
            parent,
            "S-1-5-32-544",
            ntsecuritycon.FILE_ALL_ACCESS,
            flags=ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE,
        )


def _adapters_with_scratch_base(os_: OsAdapters, base: Path) -> OsAdapters:
    return replace(os_, traits=replace(os_.traits, default_scratch_base=base))


class _SecureDirHookPermissions:
    """Proxy ``PermissionGuard`` that fires ``on_secure(path)`` before delegating ``secure_directory``."""

    def __init__(self, inner: Any, on_secure: Callable[[Path], None]) -> None:
        self._inner = inner
        self._on_secure = on_secure

    def secure_directory(self, path: Path) -> None:
        self._on_secure(path)
        self._inner.secure_directory(path)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _adapters_with_secure_hook(os_: OsAdapters, on_secure: Callable[[Path], None]) -> OsAdapters:
    return replace(os_, permissions=_SecureDirHookPermissions(os_.permissions, on_secure))


def _plant_squatter_hook(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    os_: OsAdapters,
    *,
    widen: bool = True,
) -> list[bool]:
    """Intercept ``mkdir`` / ``rename`` / ``replace`` / ``rename_dir`` on ``target`` to plant a directory once."""
    real_mkdir = Path.mkdir
    real_os_mkdir = os.mkdir
    real_rename = os.rename
    real_replace = os.replace
    pub_cls = type(os_.publisher)
    real_rename_dir = pub_cls.rename_dir
    planted = [False]
    target_key = _key(target)

    def _same(candidate: object) -> bool:
        return isinstance(candidate, (str, os.PathLike)) and _key(candidate) == target_key

    def _plant_once(candidate: object) -> None:
        if not planted[0] and _same(candidate) and not os.path.lexists(target):
            planted[0] = True
            real_mkdir(target, mode=0o700, parents=False, exist_ok=False)
            if widen:
                _grant_wide_access(target)

    def racing_mkdir(self: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        _plant_once(self)
        real_mkdir(self, mode=mode, parents=parents, exist_ok=exist_ok)

    def racing_os_mkdir(path: Any, mode: int = 0o777, **kwargs: Any) -> None:
        _plant_once(path)
        real_os_mkdir(path, mode=mode, **kwargs)

    def racing_rename(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        _plant_once(dst)
        real_rename(src, dst, *args, **kwargs)

    def racing_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        _plant_once(dst)
        real_replace(src, dst, *args, **kwargs)

    def racing_rename_dir(self_pub: Any, src: Path, dst: Path) -> None:
        _plant_once(dst)
        real_rename_dir(self_pub, src, dst)

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)
    monkeypatch.setattr(os, "mkdir", racing_os_mkdir)
    monkeypatch.setattr(os, "rename", racing_rename)
    monkeypatch.setattr(os, "replace", racing_replace)
    monkeypatch.setattr(pub_cls, "rename_dir", racing_rename_dir)
    return planted


def _make_wide_dir(path: Path, os_: OsAdapters) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(path, 0o755)
    else:
        _grant_wide_access(path)
    assert os_.permissions.object_problems(path), f"precondition: {path} must be non-owner-only"


def _win_not_found(api_name: str) -> BaseException:
    if sys.platform != "win32":
        raise AssertionError("Windows-only helper")
    else:
        return cast(BaseException, pywintypes.error(2, api_name, "The system cannot find the file specified."))


def _subtree(parent: Path, name: str, os_: OsAdapters) -> tuple[Path, Path, Path, Path]:
    sub = parent / name
    sub.mkdir()
    os_.permissions.secure_directory(sub)
    return _tree(sub, os_)


def _clean_subtree(parent: Path, name: str, os_: OsAdapters) -> tuple[Path, Path]:
    sub = parent / name
    sub.mkdir()
    os_.permissions.secure_directory(sub)
    return _clean_tree(sub, os_)


def _vanish_recreate_file(path: Path, *, widen: bool = False, api_name: str | None = None) -> Callable[[], None]:
    def _do() -> None:
        path.unlink()
        path.write_bytes(b"recreated-journal")
        if widen:
            _grant_wide_access(path)
        if api_name is not None:
            raise _win_not_found(api_name)

    return _do


def _vanish_recreate_dir(
    path: Path, *, inner_file_name: str | None = None, raise_fnf: bool = True, api_name: str | None = None
) -> Callable[[], None]:
    def _do() -> None:
        shutil.rmtree(path)
        (path / "store").mkdir(parents=True)
        if inner_file_name is not None:
            (path / "store" / inner_file_name).write_bytes(b"recreated-inner")
        if api_name is not None:
            raise _win_not_found(api_name)
        if raise_fnf:
            raise FileNotFoundError(2, "The system cannot find the path specified", os.fspath(path))

    return _do


def _vanish_recreate_junction(
    path: Path, outside_target: Path, *, api_name: str | None = None, raise_fnf: bool = False
) -> Callable[[], None]:
    def _do() -> None:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        _make_dir_link(path, outside_target)
        if api_name is not None:
            raise _win_not_found(api_name)
        if raise_fnf:
            raise FileNotFoundError(2, "The system cannot find the path specified", os.fspath(path))

    return _do


class _WrapPhysicalPreStat:
    """PhysicalFs proxy firing ``action()`` -> returning ``None`` on a specific ``stat_physical_identity`` call."""

    def __init__(
        self,
        inner: PhysicalFsPort,
        target: Path,
        *,
        on_call: int,
        action: Callable[[], None],
    ) -> None:
        self._inner = inner
        self._target = _key(target)
        self._on_call = on_call
        self._action = action
        self.calls = 0
        self.fired = False

    def stat_physical_identity(self, path: Path) -> PhysicalObjectId | None:
        if _key(path) == self._target:
            self.calls += 1
            if self.calls == self._on_call and not self.fired:
                self.fired = True
                self._action()
                return None
        return self._inner.stat_physical_identity(path)

    def same_volume(self, first: Path, second: Path) -> bool:
        return self._inner.same_volume(first, second)


# ---------------------------------------------------------------------------
# Deliverable A: Shared scratch directory atomic creation race (Fix 1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows parent ACE inheritance window on mkdir()")
@pytest.mark.parametrize("levels", [1, 2])
def test_r7_ensure_scratch_base_never_exposes_inheriting_acl_window_on_race(
    trusted_tmp: Path, levels: int
) -> None:
    """Invariant: a newly created scratch base (and intermediate dirs) must never exist at its final path with
    inherited non-owner-only permissions, and a concurrent ``_ensure_scratch_base`` must succeed cleanly."""
    real_os = os_adapters()
    parent = trusted_tmp / f"inherit-parent-{levels}"
    parent.mkdir()
    real_os.permissions.secure_directory(parent)
    _grant_inheritable_admin_ace(parent)

    probe = parent / "probe-inherits"
    probe.mkdir()
    try:
        assert real_os.permissions.check_ancestors(probe) == []
        assert real_os.permissions.object_problems(probe), "precondition: mkdir() inherits S-1-5-32-544 from parent"
    finally:
        probe.rmdir()

    root = trusted_tmp / "data-root"
    root.mkdir()
    real_os.permissions.secure_directory(root)
    base = parent / "superbrain-scratch" if levels == 1 else parent / "nested" / "superbrain-scratch"
    expected_created = [base] if levels == 1 else [base.parent, base]
    target_keys = {_key(p) for p in expected_created}
    pause_key = _key(base)

    exposed_observations: list[tuple[Path, list[PermissionProblem]]] = []
    ready_for_racer = threading.Event()
    release_creator = threading.Event()
    errors: dict[str, BaseException] = {}

    def _on_secure(path: Path) -> None:
        key = _key(path)
        if key in target_keys:
            problems = real_os.permissions.object_problems(path)
            if problems:
                exposed_observations.append((path, problems))
            if key == pause_key:
                ready_for_racer.set()
                release_creator.wait(timeout=5.0)

    spy_os = _adapters_with_secure_hook(real_os, _on_secure)

    def _creator() -> None:
        try:
            _ensure_scratch_base(base, root, spy_os)
        except BaseException as exc:  # noqa: BLE001
            errors["creator"] = exc
        finally:
            ready_for_racer.set()

    def _racer() -> None:
        try:
            assert ready_for_racer.wait(timeout=5.0)
            _ensure_scratch_base(base, root, real_os)
        except BaseException as exc:  # noqa: BLE001
            errors["racer"] = exc
        finally:
            release_creator.set()

    t_creator = threading.Thread(target=_creator, name="r7-scratch-creator")
    t_racer = threading.Thread(target=_racer, name="r7-scratch-racer")
    t_creator.start()
    t_racer.start()
    t_creator.join(timeout=10.0)
    t_racer.join(timeout=10.0)

    assert not t_creator.is_alive() and not t_racer.is_alive()
    assert not exposed_observations, f"directory existed at target path before securing: {exposed_observations}"
    assert errors == {}, f"concurrent _ensure_scratch_base failed under race: {errors}"
    for created in expected_created:
        assert created.is_dir()
        assert not real_os.permissions.object_problems(created)
    assert {p.name for p in parent.iterdir()} == {expected_created[0].name}


def test_r7_ensure_scratch_base_concurrent_barrier_race(trusted_tmp: Path) -> None:
    """Invariant: two concurrent callers racing to initialize the same missing scratch base both succeed cleanly,
    leave the target owner-only, and leak zero temporary staging directories."""
    real_os = os_adapters()
    parent = trusted_tmp / "barrier-parent"
    parent.mkdir()
    real_os.permissions.secure_directory(parent)
    if sys.platform == "win32":
        _grant_inheritable_admin_ace(parent)

    root = trusted_tmp / "data-root"
    root.mkdir()
    real_os.permissions.secure_directory(root)

    for idx in range(8):
        base = parent / f"race-{idx}" / "superbrain-scratch"
        barrier = threading.Barrier(2)
        errs: list[BaseException] = []
        err_lock = threading.Lock()

        def _worker(
            target_base: Path = base,
            start: threading.Barrier = barrier,
            out_errs: list[BaseException] = errs,
            lock: threading.Lock = err_lock,
        ) -> None:
            try:
                start.wait(timeout=5.0)
                _ensure_scratch_base(target_base, root, real_os)
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    out_errs.append(exc)

        t1 = threading.Thread(target=_worker)
        t2 = threading.Thread(target=_worker)
        t1.start()
        t2.start()
        t1.join(timeout=10.0)
        t2.join(timeout=10.0)
        assert not errs, f"concurrent barrier race {idx} failed: {errs}"
        assert not real_os.permissions.object_problems(base.parent)
        assert not real_os.permissions.object_problems(base)
        assert {p.name for p in base.parent.iterdir()} == {"superbrain-scratch"}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows parent ACE inheritance window on mkdir()")
def test_r7_verified_ssh_scratch_dir_never_exposes_inheriting_acl_window_on_race(trusted_tmp: Path) -> None:
    """Invariant: ``_verified_ssh_scratch_dir`` must never expose ``superbrain-scratch`` or ``ssh-verify`` at
    their final paths with inherited non-owner-only permissions, and concurrent callers must succeed cleanly."""
    real_os = os_adapters()
    parent = trusted_tmp / "ssh-inherit-parent"
    parent.mkdir()
    real_os.permissions.secure_directory(parent)
    _grant_inheritable_admin_ace(parent)

    custom_base = parent / "superbrain-scratch"
    expected_scratch = custom_base / "ssh-verify"
    target_keys = {_key(custom_base), _key(expected_scratch)}
    pause_key = _key(expected_scratch)

    exposed_observations: list[tuple[Path, list[PermissionProblem]]] = []
    ready_for_racer = threading.Event()
    release_creator = threading.Event()
    errors: dict[str, BaseException] = {}
    results: dict[str, Path] = {}

    def _on_secure(path: Path) -> None:
        key = _key(path)
        if key in target_keys:
            problems = real_os.permissions.object_problems(path)
            if problems:
                exposed_observations.append((path, problems))
            if key == pause_key:
                ready_for_racer.set()
                release_creator.wait(timeout=5.0)

    real_adapters = _adapters_with_scratch_base(real_os, custom_base)
    spy_adapters = _adapters_with_secure_hook(real_adapters, _on_secure)

    def _creator() -> None:
        try:
            results["creator"] = _verified_ssh_scratch_dir(spy_adapters)
        except BaseException as exc:  # noqa: BLE001
            errors["creator"] = exc
        finally:
            ready_for_racer.set()

    def _racer() -> None:
        try:
            assert ready_for_racer.wait(timeout=5.0)
            results["racer"] = _verified_ssh_scratch_dir(real_adapters)
        except BaseException as exc:  # noqa: BLE001
            errors["racer"] = exc
        finally:
            release_creator.set()

    t_creator = threading.Thread(target=_creator, name="r7-ssh-creator")
    t_racer = threading.Thread(target=_racer, name="r7-ssh-racer")
    t_creator.start()
    t_racer.start()
    t_creator.join(timeout=10.0)
    t_racer.join(timeout=10.0)

    assert not t_creator.is_alive() and not t_racer.is_alive()
    assert not exposed_observations, f"SSH scratch existed before securing: {exposed_observations}"
    assert errors == {}, f"concurrent _verified_ssh_scratch_dir failed under race: {errors}"
    assert results.get("creator") == expected_scratch and results.get("racer") == expected_scratch
    assert not real_os.permissions.object_problems(custom_base)
    assert not real_os.permissions.object_problems(expected_scratch)
    assert {p.name for p in parent.iterdir()} == {"superbrain-scratch"}
    assert {p.name for p in custom_base.iterdir()} == {"ssh-verify"}


def test_r7_verified_ssh_scratch_dir_concurrent_barrier_race(trusted_tmp: Path) -> None:
    """Invariant: two concurrent callers racing on ``_verified_ssh_scratch_dir`` both succeed cleanly with zero
    leftover temporary staging directories."""
    real_os = os_adapters()
    parent = trusted_tmp / "ssh-barrier-parent"
    parent.mkdir()
    real_os.permissions.secure_directory(parent)
    if sys.platform == "win32":
        _grant_inheritable_admin_ace(parent)

    for idx in range(8):
        custom_base = parent / f"slot-{idx}" / "superbrain-scratch"
        adapters = _adapters_with_scratch_base(real_os, custom_base)
        barrier = threading.Barrier(2)
        errs: list[BaseException] = []
        paths: list[Path] = []
        lock = threading.Lock()

        def _worker(
            adp: OsAdapters = adapters,
            start: threading.Barrier = barrier,
            out_paths: list[Path] = paths,
            out_errs: list[BaseException] = errs,
            out_lock: threading.Lock = lock,
        ) -> None:
            try:
                start.wait(timeout=5.0)
                out = _verified_ssh_scratch_dir(adp)
                with out_lock:
                    out_paths.append(out)
            except BaseException as exc:  # noqa: BLE001
                with out_lock:
                    out_errs.append(exc)

        t1 = threading.Thread(target=_worker)
        t2 = threading.Thread(target=_worker)
        t1.start()
        t2.start()
        t1.join(timeout=10.0)
        t2.join(timeout=10.0)
        assert not errs, f"concurrent SSH barrier race {idx} failed: {errs}"
        assert paths == [custom_base / "ssh-verify", custom_base / "ssh-verify"]
        assert not real_os.permissions.object_problems(custom_base)
        assert not real_os.permissions.object_problems(custom_base / "ssh-verify")
        assert {p.name for p in custom_base.iterdir()} == {"ssh-verify"}


@pytest.mark.parametrize("target_fn", ["ensure_scratch_base", "verified_ssh_scratch_dir"])
def test_r7_scratch_race_planted_wide_dir_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, target_fn: str
) -> None:
    """Invariant: if a squatter plants an insecure directory during creation/publication (``FileExistsError``),
    neither ``_ensure_scratch_base`` nor ``_verified_ssh_scratch_dir`` may swallow it or re-secure it."""
    os_ = os_adapters()
    root = trusted_tmp / "data-root"
    root.mkdir()
    os_.permissions.secure_directory(root)

    if target_fn == "ensure_scratch_base":
        target = trusted_tmp / "squat-base"
        planted = _plant_squatter_hook(monkeypatch, target, os_, widen=True)
        with pytest.raises(BrainError) as info:
            _ensure_scratch_base(target, root, os_)
    else:
        custom_base = trusted_tmp / "ssh-base"
        custom_base.mkdir()
        os_.permissions.secure_directory(custom_base)
        target = custom_base / "ssh-verify"
        adapters = _adapters_with_scratch_base(os_, custom_base)
        planted = _plant_squatter_hook(monkeypatch, target, os_, widen=True)
        with pytest.raises(BrainError) as info:
            _verified_ssh_scratch_dir(adapters)

    assert planted[0], "squatter race injector never fired"
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value
    assert os_.permissions.object_problems(target), "squatted directory must NOT be silently re-secured"


@pytest.mark.parametrize("target_fn", ["ensure_scratch_base", "verified_ssh_scratch_dir"])
@pytest.mark.parametrize("kind", ["wide_dir", "regular_file", "symlink_or_junction"])
def test_r7_scratch_preexisting_invalid_targets_fail_closed(
    trusted_tmp: Path, target_fn: str, kind: str
) -> None:
    """Invariant: pre-existing wide-ACL directories, regular files, and links/junctions at the scratch target
    always fail closed with the exact error code and without silently altering a pre-existing wide directory."""
    os_ = os_adapters()
    root = trusted_tmp / "data-root"
    root.mkdir()
    os_.permissions.secure_directory(root)

    if target_fn == "ensure_scratch_base":
        target = trusted_tmp / f"pre-{kind}"
    else:
        custom_base = trusted_tmp / f"ssh-pre-{kind}"
        custom_base.mkdir()
        os_.permissions.secure_directory(custom_base)
        target = custom_base / "ssh-verify"

    before_acl: str | None = None
    if kind == "wide_dir":
        _make_wide_dir(target, os_)
        before_acl = _acl_or_mode(target)
        expected_code = ErrorCode.INSECURE_PERMISSIONS
    elif kind == "regular_file":
        target.write_bytes(b"not-a-dir")
        os_.permissions.secure_file(target)
        expected_code = ErrorCode.INVALID_INPUT
    else:
        outside = trusted_tmp / "outside-target"
        outside.mkdir()
        os_.permissions.secure_directory(outside)
        _make_dir_link(target, outside)
        expected_code = ErrorCode.UNSAFE_PATH

    with pytest.raises(BrainError) as info:
        if target_fn == "ensure_scratch_base":
            _ensure_scratch_base(target, root, os_)
        else:
            _verified_ssh_scratch_dir(_adapters_with_scratch_base(os_, target.parent))

    assert info.value.code is expected_code, (target_fn, kind, info.value)
    if kind == "wide_dir":
        assert _acl_or_mode(target) == before_acl
        assert os_.permissions.object_problems(target)


# ---------------------------------------------------------------------------
# Deliverable B: Vanished-and-recreated transient entry race in permission walks (Fix 2)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_tighten_walk_file_vanished_and_recreated_clean_at_inspect(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: when ``brain.db-journal`` vanishes at ``GetNamedSecurityInfo`` and is immediately recreated as a
    clean owner-only file before ``os.lstat``, ``tighten_data_root_permissions`` re-verifies it and succeeds."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _vanish_recreate_file(journal, widen=False, api_name="GetNamedSecurityInfo"))
    _patch_get_security(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "vanish-and-recreate trigger never fired"
    assert journal.exists()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(journal)
    assert not os_.permissions.object_problems(widened)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_tighten_walk_dir_vanished_and_recreated_clean_at_scandir(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: when a snapshot subdir vanishes at ``os.scandir`` and is immediately recreated cleanly,
    ``tighten_data_root_permissions`` handles it cleanly without failing closed."""
    os_ = os_adapters()
    data, store, _journal, widened = _tree(trusted_tmp, os_)
    snap = store.parent
    trig = _Trigger(snap, _vanish_recreate_dir(snap, inner_file_name="brain.db-journal", raise_fnf=True))
    _patch_scandir(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "vanish-and-recreate scandir trigger never fired"
    assert snap.is_dir()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(widened)
    assert not os_.permissions.problems(data)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_tighten_walk_file_vanished_and_recreated_clean_at_repair(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: when a widened ``brain.db-journal`` vanishes at ``SetNamedSecurityInfo`` and is immediately
    recreated as a clean owner-only file before ``os.lstat``, ``tighten_data_root_permissions`` succeeds."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    _grant_wide_access(journal)
    assert os_.permissions.object_problems(journal), "precondition: journal is initially widened"
    trig = _Trigger(journal, _vanish_recreate_file(journal, widen=False, api_name="SetNamedSecurityInfo"))
    _patch_set_security(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "vanish-and-recreate SetNamedSecurityInfo trigger never fired"
    assert journal.exists()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(journal)
    assert not os_.permissions.object_problems(widened)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL / physical pre-stat race")
@pytest.mark.parametrize("recreate_mode", ["clean", "widened"])
def test_r7_tighten_walk_file_vanished_and_recreated_at_pre_stat(
    trusted_tmp: Path, recreate_mode: str
) -> None:
    """Invariant: if ``brain.db-journal`` vanishes right before initial ``stat_physical_identity`` (returning ``None``)
    and is immediately recreated before ``_verify_and_secure``, ``tighten_data_root_permissions`` must NOT fail with
    ``target identity changed before ACL repair``; clean recreations succeed and widened recreations are repaired."""
    base_os = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, base_os)
    assert base_os.physical is not None
    # Call #1 happens inside ensure_no_links_in_tree (_is_link); call #2 is the pre-stat at listing in tighten.
    wrapped_phys = _WrapPhysicalPreStat(
        base_os.physical,
        journal,
        on_call=2,
        action=_vanish_recreate_file(journal, widen=(recreate_mode == "widened")),
    )
    os_ = replace(base_os, physical=wrapped_phys)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert wrapped_phys.fired, "pre-stat trigger never fired on second stat_physical_identity call"
    assert journal.exists()
    assert not base_os.permissions.object_problems(journal)
    assert not base_os.permissions.object_problems(widened)
    expected_changed = 2 if recreate_mode == "widened" else 1
    assert changed == expected_changed, changed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
@pytest.mark.parametrize("boundary", ["inspect_file", "scandir_dir"])
def test_r7_adapter_problems_survives_vanish_and_recreate(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """Invariant: ``os_.permissions.problems(data)`` re-verifies an entry below ``data`` that vanished and was
    immediately recreated cleanly, reporting only the genuinely widened sibling."""
    os_ = os_adapters()
    data, store, journal, widened = _tree(trusted_tmp, os_)
    if boundary == "inspect_file":
        trig = _Trigger(journal, _vanish_recreate_file(journal, widen=False, api_name="GetNamedSecurityInfo"))
        _patch_get_security(monkeypatch, trig)
    else:
        snap = store.parent
        trig = _Trigger(snap, _vanish_recreate_dir(snap, inner_file_name="brain.db-journal", raise_fnf=True))
        _patch_scandir(monkeypatch, trig)

    found = os_.permissions.problems(data)

    assert trig.fired
    assert {_key(p.path) for p in found} == {_key(widened)}, found


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
@pytest.mark.parametrize("boundary", ["inspect_file", "scandir_dir"])
def test_r7_report_probe_survives_vanish_and_recreate(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """Invariant: ``check_permissions_strict`` records zero errors when a transient entry vanishes and is immediately
    recreated cleanly during inspection or directory scan, while still reporting the widened sibling."""
    os_ = os_adapters()
    data, store, journal, widened = _tree(trusted_tmp, os_)
    if boundary == "inspect_file":
        trig = _Trigger(journal, _vanish_recreate_file(journal, widen=False, api_name="GetNamedSecurityInfo"))
        _patch_get_security(monkeypatch, trig)
    else:
        snap = store.parent
        trig = _Trigger(snap, _vanish_recreate_dir(snap, inner_file_name="brain.db-journal", raise_fnf=True))
        _patch_scandir(monkeypatch, trig)

    errors, perm = _probe(data, os_)

    assert trig.fired
    assert errors == [], errors
    assert any(widened.name in p for p in perm), perm


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_fresh_report_match_survives_vanish_and_recreate(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: ``fresh_report_matches_live_state`` returns True for a clean tree even when a transient journal
    vanishes and is immediately recreated cleanly mid-walk."""
    os_ = os_adapters()
    data, journal = _clean_tree(trusted_tmp, os_)
    trig = _Trigger(journal, _vanish_recreate_file(journal, widen=False, api_name="GetNamedSecurityInfo"))
    _patch_get_security(monkeypatch, trig)

    assert _matches(data, os_) is True
    assert trig.fired


# ---------------------------------------------------------------------------
# Deliverable B: Strict fail-closed controls
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_control_vanished_and_recreated_widened_is_repaired_and_reported(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: if a vanished entry is immediately recreated with **wide** permissions,
    ``tighten_data_root_permissions`` must repair it, ``problems()`` and ``check_permissions_strict()`` must report it,
    and ``fresh_report_matches_live_state`` must return False."""
    os_ = os_adapters()

    # 1. tighten at GetNamedSecurityInfo
    with monkeypatch.context() as mp:
        data, _store, journal, widened = _subtree(trusted_tmp, "tighten-get", os_)
        trig = _Trigger(journal, _vanish_recreate_file(journal, widen=True, api_name="GetNamedSecurityInfo"))
        _patch_get_security(mp, trig)
        changed, _ = tighten_data_root_permissions((data, data / "backups"), os_)
        assert trig.fired
        assert changed == 2, changed
        assert not os_.permissions.object_problems(journal)
        assert not os_.permissions.object_problems(widened)

    # 2. tighten at SetNamedSecurityInfo
    with monkeypatch.context() as mp:
        data2, _store2, journal2, widened2 = _subtree(trusted_tmp, "tighten-set", os_)
        _grant_wide_access(journal2)
        trig2 = _Trigger(journal2, _vanish_recreate_file(journal2, widen=True, api_name="SetNamedSecurityInfo"))
        _patch_set_security(mp, trig2)
        changed2, _ = tighten_data_root_permissions((data2, data2 / "backups"), os_)
        assert trig2.fired
        assert changed2 == 2, changed2
        assert not os_.permissions.object_problems(journal2)
        assert not os_.permissions.object_problems(widened2)

    # 3. problems() & check_permissions_strict() & fresh_report_matches_live_state()
    with monkeypatch.context() as mp:
        data3, _store3, journal3, widened3 = _subtree(trusted_tmp, "probe-wide", os_)
        trig3 = _Trigger(journal3, _vanish_recreate_file(journal3, widen=True, api_name="GetNamedSecurityInfo"))
        _patch_get_security(mp, trig3)
        found = os_.permissions.problems(data3)
        assert trig3.fired
        assert {_key(p.path) for p in found} == {_key(journal3), _key(widened3)}, found

    with monkeypatch.context() as mp:
        data4, _store4, journal4, widened4 = _subtree(trusted_tmp, "strict-wide", os_)
        trig4 = _Trigger(journal4, _vanish_recreate_file(journal4, widen=True, api_name="GetNamedSecurityInfo"))
        _patch_get_security(mp, trig4)
        errors4, perm4 = _probe(data4, os_)
        assert trig4.fired
        assert errors4 == [], errors4
        assert any(journal4.name in p for p in perm4), perm4
        assert any(widened4.name in p for p in perm4), perm4

    with monkeypatch.context() as mp:
        data5, journal5 = _clean_subtree(trusted_tmp, "fresh-wide", os_)
        trig5 = _Trigger(journal5, _vanish_recreate_file(journal5, widen=True, api_name="GetNamedSecurityInfo"))
        _patch_get_security(mp, trig5)
        assert _matches(data5, os_) is False
        assert trig5.fired


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL / NTFS junction controls")
@pytest.mark.parametrize("site", ["get_security", "set_security", "scandir", "pre_stat"])
def test_r7_control_vanished_and_recreated_junction_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    """Control: if a vanished entry is immediately recreated as a junction/symlink (even pointing to an owner-only
    outside directory), ``tighten_data_root_permissions`` MUST fail closed with ``UNSAFE_PATH``."""
    base_os = os_adapters()
    outside = trusted_tmp / f"outside-{site}"
    outside.mkdir()
    base_os.permissions.secure_directory(outside)

    data, store, journal, _widened = _subtree(trusted_tmp, f"junc-{site}", base_os)
    os_ = base_os

    if site == "get_security":
        trig = _Trigger(journal, _vanish_recreate_junction(journal, outside, api_name="GetNamedSecurityInfo"))
        _patch_get_security(monkeypatch, trig)
    elif site == "set_security":
        _grant_wide_access(journal)
        trig = _Trigger(journal, _vanish_recreate_junction(journal, outside, api_name="SetNamedSecurityInfo"))
        _patch_set_security(monkeypatch, trig)
    elif site == "scandir":
        snap = store.parent
        trig = _Trigger(snap, _vanish_recreate_junction(snap, outside, raise_fnf=True))
        _patch_scandir(monkeypatch, trig)
    else:
        assert base_os.physical is not None
        phys = _WrapPhysicalPreStat(
            base_os.physical,
            journal,
            on_call=2,
            action=_vanish_recreate_junction(journal, outside),
        )
        os_ = replace(base_os, physical=phys)
        trig = cast(_Trigger, phys)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired
    assert info.value.code is ErrorCode.UNSAFE_PATH, (site, info.value)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL / NTFS junction controls")
@pytest.mark.parametrize("site", ["get_security", "scandir"])
def test_r7_control_probe_and_problems_fail_closed_on_recreated_junction(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    """Control: ``os_.permissions.problems`` and ``check_permissions_strict`` never silently pass when a vanished
    entry is recreated as a junction/symlink."""
    os_ = os_adapters()
    outside = trusted_tmp / f"outside-probe-{site}"
    outside.mkdir()
    os_.permissions.secure_directory(outside)

    with monkeypatch.context() as mp:
        data, store, journal, _widened = _subtree(trusted_tmp, f"prob-j-{site}", os_)
        if site == "get_security":
            trig = _Trigger(journal, _vanish_recreate_junction(journal, outside, api_name="GetNamedSecurityInfo"))
            _patch_get_security(mp, trig)
        else:
            snap = store.parent
            trig = _Trigger(snap, _vanish_recreate_junction(snap, outside, raise_fnf=True))
            _patch_scandir(mp, trig)
        with pytest.raises(BrainError) as info:
            os_.permissions.problems(data)
        assert trig.fired
        assert info.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INSECURE_PERMISSIONS}, info.value

    with monkeypatch.context() as mp:
        data2, store2, journal2, _widened2 = _subtree(trusted_tmp, f"strict-j-{site}", os_)
        if site == "get_security":
            trig2 = _Trigger(journal2, _vanish_recreate_junction(journal2, outside, api_name="GetNamedSecurityInfo"))
            _patch_get_security(mp, trig2)
        else:
            snap2 = store2.parent
            trig2 = _Trigger(snap2, _vanish_recreate_junction(snap2, outside, raise_fnf=True))
            _patch_scandir(mp, trig2)
        errors2, _perm2 = _probe(data2, os_)
        assert trig2.fired
        assert errors2, f"check_permissions_strict silently passed on recreated junction at {site}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_control_existing_not_found_with_denied_lstat_still_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: ``not found`` from OS inspection when ``os.lstat`` raises ``PermissionError`` still fails closed."""
    os_ = os_adapters()

    with monkeypatch.context() as mp:
        data, _store, journal, _widened = _subtree(trusted_tmp, "deny-fix", os_)
        deny = _DenyLstat(mp, journal)
        trig = _Trigger(journal, _not_found_then_deny_lookup(deny, "acl", journal))
        _patch_get_security(mp, trig)
        with pytest.raises(BrainError) as info:
            tighten_data_root_permissions((data, data / "backups"), os_)
        deny.armed = False
        assert trig.fired and deny.hit
        assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value

    with monkeypatch.context() as mp:
        data2, _store2, journal2, _widened2 = _subtree(trusted_tmp, "deny-prob", os_)
        deny2 = _DenyLstat(mp, journal2)
        trig2 = _Trigger(journal2, _not_found_then_deny_lookup(deny2, "acl", journal2))
        _patch_get_security(mp, trig2)
        with pytest.raises(BrainError) as info2:
            os_.permissions.problems(data2)
        deny2.armed = False
        assert trig2.fired and deny2.hit
        assert info2.value.code is ErrorCode.INSECURE_PERMISSIONS, info2.value

    with monkeypatch.context() as mp:
        data3, _store3, journal3, _widened3 = _subtree(trusted_tmp, "deny-probe", os_)
        deny3 = _DenyLstat(mp, journal3)
        trig3 = _Trigger(journal3, _not_found_then_deny_lookup(deny3, "acl", journal3))
        _patch_get_security(mp, trig3)
        errors3, _perm3 = _probe(data3, os_)
        deny3.armed = False
        assert trig3.fired and deny3.hit
        assert any("permission check error" in e for e in errors3), errors3


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
@pytest.mark.parametrize("boundary", ["inspect", "scandir", "repair"])
def test_r7_control_walk_root_vanished_and_recreated_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """Control: if the walk's own root vanishes and is recreated mid-walk, both ``tighten_data_root_permissions``
    and ``os_.permissions.problems`` still fail closed with ``INSECURE_PERMISSIONS``."""
    os_ = os_adapters()

    with monkeypatch.context() as mp:
        data, _store, _journal, _widened = _subtree(trusted_tmp, f"root-fix-{boundary}", os_)
        if boundary == "inspect":
            trig = _Trigger(
                data, _vanish_recreate_dir(data, inner_file_name=None, raise_fnf=False, api_name="GetNamedSecurityInfo")
            )
            _patch_get_security(mp, trig)
        elif boundary == "scandir":
            trig = _Trigger(data, _vanish_recreate_dir(data, inner_file_name=None, raise_fnf=True))
            _patch_scandir(mp, trig)
        else:
            _grant_wide_access(data)
            trig = _Trigger(
                data, _vanish_recreate_dir(data, inner_file_name=None, raise_fnf=False, api_name="SetNamedSecurityInfo")
            )
            _patch_set_security(mp, trig)

        with pytest.raises(BrainError) as info:
            tighten_data_root_permissions([data], os_)
        assert trig.fired
        assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value

    if boundary in ("inspect", "scandir"):
        with monkeypatch.context() as mp:
            data2, _store2, _journal2, _widened2 = _subtree(trusted_tmp, f"root-prob-{boundary}", os_)
            if boundary == "inspect":
                trig2 = _Trigger(
                    data2,
                    _vanish_recreate_dir(data2, inner_file_name=None, raise_fnf=False, api_name="GetNamedSecurityInfo"),
                )
                _patch_get_security(mp, trig2)
            else:
                trig2 = _Trigger(data2, _vanish_recreate_dir(data2, inner_file_name=None, raise_fnf=True))
                _patch_scandir(mp, trig2)

            with pytest.raises(BrainError) as info2:
                os_.permissions.problems(data2)
            assert trig2.fired
            assert info2.value.code is ErrorCode.INSECURE_PERMISSIONS, info2.value


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
def test_r7_control_static_access_denied_at_set_security_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: ``ERROR_ACCESS_DENIED (5)`` from ``SetNamedSecurityInfo`` on an existing widened file fails closed."""
    os_ = os_adapters()
    data, _store, _journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(widened, _deny())
    _patch_set_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired
    assert widened.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


# ---------------------------------------------------------------------------
# R8 Oracle: Finding 1 (PermissionGuard entry.stat races), Finding 2 (direct
# entry.stat link return + sibling scans), and adjacent type-flip variant
# ---------------------------------------------------------------------------


class _RawWinNotFoundOSError(OSError):
    """Non-``FileNotFoundError`` ``OSError`` carrying ``winerror = 2`` (``ERROR_FILE_NOT_FOUND``)."""

    winerror = 2


class _RawPosixEnoentOSError(OSError):
    """Non-``FileNotFoundError`` ``OSError`` carrying ``errno.ENOENT``."""


class _ScandirStatEntryProxy:
    """Proxy over ``os.DirEntry`` delegating metadata calls while intercepting ``stat(follow_symlinks=False)``."""

    def __init__(
        self,
        inner: os.DirEntry[str],
        on_stat: Callable[[os.DirEntry[str]], os.stat_result | None],
    ) -> None:
        self._inner = inner
        self._on_stat = on_stat

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def path(self) -> str:
        return self._inner.path

    def is_symlink(self) -> bool:
        return self._inner.is_symlink()

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._inner.is_dir(follow_symlinks=follow_symlinks)

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return self._inner.is_file(follow_symlinks=follow_symlinks)

    def inode(self) -> int:
        return self._inner.inode()

    def __fspath__(self) -> str:
        return self._inner.__fspath__()

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        if not follow_symlinks:
            override = self._on_stat(self._inner)
            if override is not None:
                return override
        return self._inner.stat(follow_symlinks=follow_symlinks)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _ScandirIterProxy:
    """Context-manager + iterator wrapper returned by patched ``os.scandir``."""

    def __init__(
        self,
        inner: Any,
        on_stat: Callable[[os.DirEntry[str]], os.stat_result | None],
    ) -> None:
        self._inner = inner
        self._on_stat = on_stat

    def __enter__(self) -> _ScandirIterProxy:
        self._inner.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        return self._inner.__exit__(exc_type, exc, tb)

    def __iter__(self) -> _ScandirIterProxy:
        return self

    def __next__(self) -> _ScandirStatEntryProxy:
        return _ScandirStatEntryProxy(next(self._inner), self._on_stat)

    def close(self) -> None:
        self._inner.close()


def _patch_scandir_entry_stat(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    action: Callable[[os.DirEntry[str]], os.stat_result | None],
    *,
    on_call: int | None = 1,
    scanned_dirs: list[str] | None = None,
) -> list[int]:
    """Patch ``os.scandir`` so ``entry.stat(follow_symlinks=False)`` on ``target`` invokes ``action`` at ``on_call``
    (or on every call when ``on_call is None``)."""
    real_scandir = os.scandir
    target_key = _key(target)
    calls = [0]
    lock = threading.Lock()

    def _on_stat(entry: os.DirEntry[str]) -> os.stat_result | None:
        if _key(entry.path) != target_key:
            return None
        with lock:
            calls[0] += 1
            hit = on_call is None or calls[0] == on_call
        if hit:
            return action(entry)
        return None

    def _wrapped(path: Any = ".") -> Any:
        if scanned_dirs is not None:
            scanned_dirs.append(_key(path))
        return _ScandirIterProxy(real_scandir(path), _on_stat)

    monkeypatch.setattr(os, "scandir", _wrapped)
    return calls


def _wrap_path_is_symlink(monkeypatch: pytest.MonkeyPatch, enabled: bool) -> None:
    """When ``enabled``, wrap ``Path.is_symlink`` so ``_non_symlink_tree`` takes the ``_tree`` code path."""
    if not enabled:
        return
    orig = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: orig(self))


def _raise_not_found_variant(kind: str, path: Path) -> BaseException:
    if kind == "fnf":
        return FileNotFoundError(errno.ENOENT, "The system cannot find the file specified", os.fspath(path))
    if kind == "raw_win_not_found":
        return _RawWinNotFoundOSError(errno.EIO, "The system cannot find the file specified")
    if kind == "raw_posix_enoent":
        return _RawPosixEnoentOSError(errno.ENOENT, "No such file or directory")
    raise AssertionError(f"unknown kind: {kind}")


def _reparse_file_stat(size: int = 20) -> os.stat_result:
    if sys.platform != "win32":
        raise AssertionError("Windows-only helper")
    else:
        return os.stat_result(
            (stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, size, 0, 0, 0),
            {"st_file_attributes": 0x400},
        )


def _symlink_mode_stat() -> os.stat_result:
    return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))


class _RecordingPrivacyScanner(PrivacyScannerPort):
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def check_canary_channels(self) -> tuple[PrivacyCanaryProbeResult, ...]:
        return ()

    def scan_bytes(self, data: bytes) -> tuple[str, ...]:
        self.calls.append(data)
        return ("canary_rule",) if b"SECRET" in data else ()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL + DirEntry.stat race controls")
@pytest.mark.parametrize("wrap_is_symlink", [False, True])
@pytest.mark.parametrize("exc_kind", ["fnf", "raw_win_not_found", "raw_posix_enoent"])
def test_r8_f1_entry_stat_recreated_widened_file_is_reported(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, wrap_is_symlink: bool, exc_kind: str
) -> None:
    """Finding 1 (a): if ``entry.stat(follow_symlinks=False)`` fails with ``FileNotFoundError`` or a
    non-``FileNotFoundError`` not-found ``OSError`` and the file is immediately recreated widened,
    ``problems()``, ``check_permissions_strict()``, and ``fresh_report_matches_live_state()`` must report it."""
    os_ = os_adapters()

    with monkeypatch.context() as mp:
        _wrap_path_is_symlink(mp, wrap_is_symlink)
        data, _store, journal, widened = _subtree(trusted_tmp, f"f1a-prob-{wrap_is_symlink}-{exc_kind}", os_)

        def _act(_entry: os.DirEntry[str]) -> None:
            journal.unlink()
            journal.write_bytes(b"recreated-wide")
            _grant_wide_access(journal)
            raise _raise_not_found_variant(exc_kind, journal)

        calls = _patch_scandir_entry_stat(mp, journal, _act, on_call=1)
        found = os_.permissions.problems(data)
        assert calls[0] >= 1
        assert {_key(p.path) for p in found} == {_key(journal), _key(widened)}, found

    with monkeypatch.context() as mp:
        _wrap_path_is_symlink(mp, wrap_is_symlink)
        data2, _store2, journal2, widened2 = _subtree(trusted_tmp, f"f1a-strict-{wrap_is_symlink}-{exc_kind}", os_)

        def _act2(_entry: os.DirEntry[str]) -> None:
            journal2.unlink()
            journal2.write_bytes(b"recreated-wide")
            _grant_wide_access(journal2)
            raise _raise_not_found_variant(exc_kind, journal2)

        # Call #1 is check_permissions_strict's own link scan; call #2 is inside os_.permissions.problems().
        calls2 = _patch_scandir_entry_stat(mp, journal2, _act2, on_call=2)
        errors2, perm2 = _probe(data2, os_)
        assert calls2[0] >= 2
        assert errors2 == [], errors2
        assert any(journal2.name in p for p in perm2), perm2
        assert any(widened2.name in p for p in perm2), perm2

    with monkeypatch.context() as mp:
        _wrap_path_is_symlink(mp, wrap_is_symlink)
        data3, journal3 = _clean_subtree(trusted_tmp, f"f1a-fresh-{wrap_is_symlink}-{exc_kind}", os_)

        def _act3(_entry: os.DirEntry[str]) -> None:
            journal3.unlink()
            journal3.write_bytes(b"recreated-wide")
            _grant_wide_access(journal3)
            raise _raise_not_found_variant(exc_kind, journal3)

        calls3 = _patch_scandir_entry_stat(mp, journal3, _act3, on_call=1)
        assert _matches(data3, os_) is False
        assert calls3[0] >= 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL + DirEntry.stat race controls")
@pytest.mark.parametrize("wrap_is_symlink", [False, True])
def test_r8_f1_entry_stat_recreated_dir_with_widened_child_descends_and_reports(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, wrap_is_symlink: bool
) -> None:
    """Finding 1 (b): if ``entry.stat(follow_symlinks=False)`` on a listed directory fails not-found and the
    directory is immediately recreated with a widened child inside it, ``problems()`` must descend and report it."""
    os_ = os_adapters()
    _wrap_path_is_symlink(monkeypatch, wrap_is_symlink)
    data, store, _journal, widened = _subtree(trusted_tmp, f"f1b-{wrap_is_symlink}", os_)
    snap = store.parent
    inner_wide = snap / "store" / "inner_wide.txt"

    def _act(_entry: os.DirEntry[str]) -> None:
        shutil.rmtree(snap)
        (snap / "store").mkdir(parents=True)
        inner_wide.write_bytes(b"wide-inner")
        _grant_wide_access(inner_wide)
        raise FileNotFoundError(errno.ENOENT, "not found", os.fspath(snap))

    calls = _patch_scandir_entry_stat(monkeypatch, snap, _act, on_call=1)
    found = os_.permissions.problems(data)

    assert calls[0] >= 1
    assert {_key(p.path) for p in found} == {_key(inner_wide), _key(widened)}, found


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL / NTFS junction + DirEntry.stat controls")
@pytest.mark.parametrize("wrap_is_symlink", [False, True])
@pytest.mark.parametrize("target_kind", ["file_entry", "dir_entry"])
def test_r8_f1_entry_stat_recreated_junction_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, wrap_is_symlink: bool, target_kind: str
) -> None:
    """Finding 1 (c): if ``entry.stat(follow_symlinks=False)`` fails not-found and the entry is immediately
    recreated as a junction, ``problems()`` MUST raise ``BrainError(UNSAFE_PATH)`` and ``check_permissions_strict``
    MUST record an error."""
    os_ = os_adapters()
    outside = trusted_tmp / f"f1c-outside-{wrap_is_symlink}-{target_kind}"
    outside.mkdir()
    os_.permissions.secure_directory(outside)

    with monkeypatch.context() as mp:
        _wrap_path_is_symlink(mp, wrap_is_symlink)
        data, store, journal, _widened = _subtree(trusted_tmp, f"f1c-prob-{wrap_is_symlink}-{target_kind}", os_)
        target = journal if target_kind == "file_entry" else store.parent

        def _act(_entry: os.DirEntry[str]) -> None:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            _make_dir_link(target, outside)
            raise FileNotFoundError(errno.ENOENT, "not found", os.fspath(target))

        calls = _patch_scandir_entry_stat(mp, target, _act, on_call=1)
        with pytest.raises(BrainError) as info:
            os_.permissions.problems(data)
        assert calls[0] >= 1
        assert info.value.code is ErrorCode.UNSAFE_PATH, info.value

    with monkeypatch.context() as mp:
        _wrap_path_is_symlink(mp, wrap_is_symlink)
        data2, store2, journal2, _widened2 = _subtree(trusted_tmp, f"f1c-strict-{wrap_is_symlink}-{target_kind}", os_)
        target2 = journal2 if target_kind == "file_entry" else store2.parent

        def _act2(_entry: os.DirEntry[str]) -> None:
            if target2.is_dir():
                shutil.rmtree(target2)
            else:
                target2.unlink()
            _make_dir_link(target2, outside)
            raise FileNotFoundError(errno.ENOENT, "not found", os.fspath(target2))

        calls2 = _patch_scandir_entry_stat(mp, target2, _act2, on_call=2)
        errors2, _perm2 = _probe(data2, os_)
        assert calls2[0] >= 2
        assert errors2, "check_permissions_strict failed to record error when problems() hit recreated junction"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL + DirEntry.stat race controls")
@pytest.mark.parametrize("wrap_is_symlink", [False, True])
def test_r8_f1_entry_stat_not_found_with_denied_lstat_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, wrap_is_symlink: bool
) -> None:
    """Finding 1 (d): if ``entry.stat(follow_symlinks=False)`` raises ``FileNotFoundError`` while follow-up
    ``os.lstat(path)`` raises ``PermissionError``, ``problems()`` MUST fail closed with ``INSECURE_PERMISSIONS``."""
    os_ = os_adapters()
    _wrap_path_is_symlink(monkeypatch, wrap_is_symlink)
    data, _store, journal, _widened = _subtree(trusted_tmp, f"f1d-{wrap_is_symlink}", os_)
    deny = _DenyLstat(monkeypatch, journal)

    def _act(_entry: os.DirEntry[str]) -> None:
        deny.armed = True
        raise FileNotFoundError(errno.ENOENT, "not found", os.fspath(journal))

    calls = _patch_scandir_entry_stat(monkeypatch, journal, _act, on_call=1)
    with pytest.raises(BrainError) as info:
        os_.permissions.problems(data)
    deny.armed = False

    assert calls[0] >= 1 and deny.hit
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL + DirEntry.stat race controls")
@pytest.mark.parametrize("wrap_is_symlink", [False, True])
@pytest.mark.parametrize("exc_kind", ["fnf", "raw_win_not_found", "raw_posix_enoent"])
def test_r8_f1_control_entry_stat_truly_vanished_is_skipped(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, wrap_is_symlink: bool, exc_kind: str
) -> None:
    """Finding 1 (e): when ``entry.stat(follow_symlinks=False)`` raises a not-found error and the file stays
    absent (not recreated), ``os_.permissions.problems(data)`` skips it cleanly and still reports ``widened``."""
    os_ = os_adapters()
    _wrap_path_is_symlink(monkeypatch, wrap_is_symlink)
    data, _store, journal, widened = _subtree(trusted_tmp, f"f1e-{wrap_is_symlink}-{exc_kind}", os_)

    def _act(_entry: os.DirEntry[str]) -> None:
        journal.unlink()
        raise _raise_not_found_variant(exc_kind, journal)

    calls = _patch_scandir_entry_stat(monkeypatch, journal, _act, on_call=1)
    found = os_.permissions.problems(data)

    assert calls[0] >= 1
    assert not journal.exists()
    assert {_key(p.path) for p in found} == {_key(widened)}, found


@pytest.mark.skipif(sys.platform != "win32", reason="Windows NTFS reparse stat_result + DirEntry.stat controls")
def test_r8_f2_entry_stat_direct_junction_result_fails_closed_without_descending(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 2 (a, Windows junction): when ``entry.stat(follow_symlinks=False)`` returns a real NTFS junction
    ``stat_result`` (``S_ISDIR=True`` and ``FILE_ATTRIBUTE_REPARSE_POINT=0x400``) after ``is_symlink``/``_is_link``
    passed, both ``ensure_no_links_in_tree`` and ``check_permissions_strict`` fail closed without descending."""
    os_ = os_adapters()
    outside = trusted_tmp / "f2a-outside"
    outside.mkdir()
    os_.permissions.secure_directory(outside)
    (outside / "inner_wide.txt").write_bytes(b"secret")
    _grant_wide_access(outside / "inner_wide.txt")

    real_junc = trusted_tmp / "f2a-real-junc"
    _make_dir_link(real_junc, outside)
    junc_stat = os.lstat(real_junc)
    assert stat.S_ISDIR(junc_stat.st_mode) and bool(getattr(junc_stat, "st_file_attributes", 0) & 0x400)

    with monkeypatch.context() as mp:
        data, store, _journal, _widened = _subtree(trusted_tmp, "f2a-fix", os_)
        snap = store.parent
        scanned: list[str] = []
        calls = _patch_scandir_entry_stat(mp, snap, lambda _e: junc_stat, on_call=1, scanned_dirs=scanned)
        with pytest.raises(BrainError) as info:
            ensure_no_links_in_tree(data, os_)
        assert calls[0] == 1
        assert info.value.code is ErrorCode.UNSAFE_PATH, info.value
        assert _key(snap) not in scanned, f"walk descended into junction directory {snap}"

    with monkeypatch.context() as mp:
        data2, store2, _journal2, _widened2 = _subtree(trusted_tmp, "f2a-strict", os_)
        snap2 = store2.parent
        scanned2: list[str] = []
        calls2 = _patch_scandir_entry_stat(mp, snap2, lambda _e: junc_stat, on_call=None, scanned_dirs=scanned2)
        errors2, perm2 = _probe(data2, os_)
        assert calls2[0] >= 1
        assert _key(snap2) not in scanned2, f"strict probe descended into junction directory {snap2}"
        assert any("forbidden symlink/reparse point" in e for e in errors2), errors2
        assert any("forbidden symlink/reparse point" in p for p in perm2), perm2


def test_r8_f2_entry_stat_direct_symlink_mode_fails_closed_without_physical(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 2 (a, ``S_IFLNK`` + ``os_.physical=None``): when ``entry.stat(follow_symlinks=False)`` returns a
    symlink-mode ``stat_result`` (``S_IFLNK``), ``ensure_no_links_in_tree``, ``tighten_data_root_permissions``,
    and ``check_permissions_strict`` fail closed even when ``os_.physical`` is ``None``."""
    os_no_phys = replace(os_adapters(), physical=None)
    lnk_stat = _symlink_mode_stat()
    assert stat.S_ISLNK(lnk_stat.st_mode)

    with monkeypatch.context() as mp:
        data, _store, journal, _widened = _subtree(trusted_tmp, "f2a-lnk-ens", os_no_phys)
        calls = _patch_scandir_entry_stat(mp, journal, lambda _e: lnk_stat, on_call=None)
        with pytest.raises(BrainError) as info:
            ensure_no_links_in_tree(data, os_no_phys)
        assert calls[0] == 1
        assert info.value.code is ErrorCode.UNSAFE_PATH, info.value

    with monkeypatch.context() as mp:
        data2, _store2, journal2, _widened2 = _subtree(trusted_tmp, "f2a-lnk-tighten", os_no_phys)
        calls2 = _patch_scandir_entry_stat(mp, journal2, lambda _e: lnk_stat, on_call=None)
        with pytest.raises(BrainError) as info2:
            tighten_data_root_permissions((data2, data2 / "backups"), os_no_phys)
        assert calls2[0] == 1
        assert info2.value.code is ErrorCode.UNSAFE_PATH, info2.value

    with monkeypatch.context() as mp:
        data3, _store3, journal3, _widened3 = _subtree(trusted_tmp, "f2a-lnk-strict", os_no_phys)
        calls3 = _patch_scandir_entry_stat(mp, journal3, lambda _e: lnk_stat, on_call=None)
        errors3, perm3 = _probe(data3, os_no_phys)
        assert calls3[0] >= 1
        assert any("forbidden symlink/reparse point" in e for e in errors3), errors3
        assert any("forbidden symlink/reparse point" in p for p in perm3), perm3


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL security boundary injections")
@pytest.mark.parametrize("flip_kind", ["file_to_dir", "dir_to_file"])
@pytest.mark.parametrize(
    ("phys_mode", "boundary"),
    [
        ("with_physical", "get_security"),
        ("without_physical", "get_security"),
        ("with_physical", "set_security"),
        ("without_physical", "set_security"),
        ("with_physical", "pre_stat"),
    ],
)
@pytest.mark.parametrize("recreated_wide", [False, True])
def test_r8_f2_adjacent_type_flip_in_verify_and_secure_fails_closed(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    flip_kind: str,
    phys_mode: str,
    boundary: str,
    recreated_wide: bool,
) -> None:
    """Adjacent type-flip variant (``_verify_and_secure``): if a listed file (``is_dir=False``) vanishes and is
    recreated as a directory, or a listed directory (``is_dir=True``) vanishes and is recreated as a regular file,
    ``tighten_data_root_permissions`` MUST fail closed with ``UNSAFE_PATH`` (both with and without ``os_.physical``)
    and must never apply ``secure_file`` to a directory or ``secure_directory`` to a file."""
    base_os = os_adapters()
    test_os: OsAdapters = replace(base_os, physical=None) if phys_mode == "without_physical" else base_os
    data, store, journal, _widened = _subtree(
        trusted_tmp, f"flip-{flip_kind}-{phys_mode}-{boundary}-{recreated_wide}", base_os
    )
    target = journal if flip_kind == "file_to_dir" else store.parent

    def _flip_action(*, api_name: str | None) -> Callable[[], None]:
        def _do() -> None:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            if flip_kind == "file_to_dir":
                target.mkdir()
                (target / "nested_unwalked.txt").write_bytes(b"unwalked")
            else:
                target.write_bytes(b"flipped-to-file")
            if recreated_wide:
                _grant_wide_access(target)
            if api_name is not None:
                raise _win_not_found(api_name)

        return _do

    if boundary == "get_security":
        trig = _Trigger(target, _flip_action(api_name="GetNamedSecurityInfo"))
        _patch_get_security(monkeypatch, trig)
    elif boundary == "set_security":
        _grant_wide_access(target)
        trig = _Trigger(target, _flip_action(api_name="SetNamedSecurityInfo"))
        _patch_set_security(monkeypatch, trig)
    else:
        assert base_os.physical is not None
        phys = _WrapPhysicalPreStat(
            base_os.physical,
            target,
            on_call=2,
            action=_flip_action(api_name=None),
        )
        test_os = replace(base_os, physical=phys)
        trig = cast(_Trigger, phys)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), test_os)

    assert trig.fired, f"type-flip trigger never fired for {(flip_kind, phys_mode, boundary, recreated_wide)}"
    assert info.value.code is ErrorCode.UNSAFE_PATH, (flip_kind, phys_mode, boundary, recreated_wide, info.value)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows FILE_ATTRIBUTE_REPARSE_POINT stat_result test")
def test_r8_f2_sibling_run_privacy_rescan_skips_reparse_entry_stat(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 2 (c): ``run_privacy_rescan`` must reject a ``logs/*.log`` entry whose
    ``ent.stat(follow_symlinks=False)`` reports ``FILE_ATTRIBUTE_REPARSE_POINT`` even when ``S_ISREG`` is True, without
    opening or scanning it."""
    os_ = os_adapters()
    data, _store, _journal, _widened = _subtree(trusted_tmp, "f2c-priv", os_)
    root = DataRoot.at(data)
    root.logs_dir.mkdir(exist_ok=True)
    log_file = root.logs_dir / "leak.log"
    payload = b"SECRET_CANARY_TOKEN\n"
    log_file.write_bytes(payload)
    os_.permissions.secure_file(log_file)

    # Positive control: normal log file is scanned.
    ctrl_scanner = _RecordingPrivacyScanner()
    ctrl_summary = run_privacy_rescan(root, [], DoctorScanLimits(), ctrl_scanner)
    assert ctrl_summary.scanned_items == 1 and len(ctrl_summary.findings) == 1

    # Reparse-point stat_result returned by ent.stat(follow_symlinks=False): must be skipped, never read.
    reparse_stat = _reparse_file_stat(len(payload))
    scanner = _RecordingPrivacyScanner()
    calls = _patch_scandir_entry_stat(monkeypatch, log_file, lambda _e: reparse_stat, on_call=1)
    summary = run_privacy_rescan(root, [], DoctorScanLimits(), scanner)

    assert calls[0] == 1
    assert summary.scanned_items == 0, summary
    assert summary.findings == (), summary
    assert scanner.calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows NTFS junction / reparse stat_result test")
def test_r8_f2_sibling_collect_cas_digests_skips_reparse_shard_and_blob_entry_stat(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 2 (c): ``_collect_cas_digests`` must not descend into a CAS shard or record a CAS blob whose
    ``entry.stat(follow_symlinks=False)`` carries ``FILE_ATTRIBUTE_REPARSE_POINT``."""
    os_ = os_adapters()
    outside = trusted_tmp / "f2c-cas-outside"
    outside.mkdir()
    os_.permissions.secure_directory(outside)
    real_junc = trusted_tmp / "f2c-cas-junc"
    _make_dir_link(real_junc, outside)
    junc_stat = os.lstat(real_junc)

    data, _store, _journal, _widened = _subtree(trusted_tmp, "f2c-cas", os_)
    root = DataRoot.at(data)
    shard_dir = root.cas_dir / "ab"
    shard_dir.mkdir(parents=True)
    os_.permissions.secure_directory(shard_dir)
    blob_hex = "a" * 64
    blob_file = shard_dir / blob_hex
    blob_data = b"cas-payload"
    blob_file.write_bytes(blob_data)
    os_.permissions.secure_file(blob_file)

    # Positive control: normal shard and blob are collected.
    ctrl_errors: list[str] = []
    ctrl_items = _collect_cas_digests(root.cas_dir, ctrl_errors)
    assert ctrl_errors == [] and [(d, p) for d, p, _s in ctrl_items] == [(f"sha256:{blob_hex}", blob_file)]

    # 1. shard_ent.stat returns NTFS junction stat_result: must not descend into shard_dir.
    with monkeypatch.context() as mp:
        scanned: list[str] = []
        calls = _patch_scandir_entry_stat(mp, shard_dir, lambda _e: junc_stat, on_call=1, scanned_dirs=scanned)
        errors: list[str] = []
        items = _collect_cas_digests(root.cas_dir, errors)
        assert calls[0] == 1
        assert errors == [], errors
        assert items == [], items
        assert _key(shard_dir) not in scanned

    # 2. blob_ent.stat returns regular-mode FILE_ATTRIBUTE_REPARSE_POINT stat_result: must skip blob_file.
    with monkeypatch.context() as mp:
        blob_reparse_stat = _reparse_file_stat(len(blob_data))
        calls2 = _patch_scandir_entry_stat(mp, blob_file, lambda _e: blob_reparse_stat, on_call=1)
        errors2: list[str] = []
        items2 = _collect_cas_digests(root.cas_dir, errors2)
        assert calls2[0] == 1
        assert errors2 == [], errors2
        assert items2 == [], items2
