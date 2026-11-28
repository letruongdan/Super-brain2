"""Independent RED oracle: permission walks tolerate entries removed concurrently (SP1 increment 4, r4 gate run).

Observed defect: an online ``brain doctor --fix`` (``tighten_permissions``) listed a transient SQLite
``brain.db-journal`` that the background doctor job was writing under ``scratch/doctor-snap-*/store/``; the file
vanished before its ACL was inspected and the whole fix failed with ``insecure_permissions``.

Requirement under test:
- R1: a permission walk over the data root treats an entry removed concurrently -- after it was listed, before it
  is inspected or repaired -- as needing no repair, never as an error. Walks covered: the ``doctor --fix``
  ``tighten_permissions`` walk (online daemon route and ``tighten_data_root_permissions``), the adapter
  ``permissions.problems(root)`` walk, the doctor report ``check_permissions_strict`` probe, and
  ``fresh_report_matches_live_state``.
- R2 (fail-closed controls, green before and after the fix): an entry that still exists but cannot be inspected or
  repaired still fails closed; a genuinely widened entry is still tightened / reported; a missing walk root keeps
  failing where it failed before.

The vanish is injected deterministically at the OS boundary: the target is deleted inside a wrapper around
``win32security.GetNamedSecurityInfo`` / ``SetNamedSecurityInfo`` / ``os.scandir`` immediately before the real call
on that exact path. Windows-only (the host): the injection points are the Windows DACL calls.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application._doctor_fix import tighten_data_root_permissions
from superbrain.composition._doctor_fix_wiring import fresh_report_matches_live_state
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_probes import check_permissions_strict
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_fix import _acl_or_mode, _grant_wide_access
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, _base_utc_now, _init_doctor_root, _running_serve
from tests.integration.test_i4_owner_thread_remediation import _post_operator
from tests.support.clock import FakeClock
from tests.support.inc2_transport import FakeMonotonicClock

if sys.platform == "win32":
    import pywintypes
    import win32security

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="injection points are the Windows DACL calls")

ERROR_ACCESS_DENIED = 5


def _key(path: object) -> str:
    return str(os.path.normcase(os.path.abspath(os.fspath(cast(Any, path)))))


class _Trigger:
    """Runs ``action`` once, the first time the wrapped OS call is made on ``target``, before the real call."""

    def __init__(self, target: Path, action: Callable[[], None]) -> None:
        self.target = _key(target)
        self._action = action
        self._lock = threading.Lock()
        self.armed = True
        self.fired = False

    def maybe_fire(self, path: object) -> None:
        if not self.armed or _key(path) != self.target:
            return
        with self._lock:
            if self.fired:
                return
            self.fired = True
        self._action()


def _remove(path: Path) -> Callable[[], None]:
    def _do() -> None:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

    return _do


def _deny() -> Callable[[], None]:
    def _do() -> None:
        if sys.platform == "win32":  # Windows-only module: a platform block lets mypy check this file on every platform
            raise pywintypes.error(ERROR_ACCESS_DENIED, "GetNamedSecurityInfo", "Access is denied.")
        raise AssertionError("Windows-only helper")

    return _do


def _patch_get_security(monkeypatch: pytest.MonkeyPatch, trigger: _Trigger) -> None:
    if sys.platform != "win32":  # Windows-only module: a platform block lets mypy check this file on every platform
        raise AssertionError("Windows-only helper")
    else:
        real = win32security.GetNamedSecurityInfo

        def wrapper(path: Any, *args: Any) -> Any:
            trigger.maybe_fire(path)
            return real(path, *args)

        monkeypatch.setattr(win32security, "GetNamedSecurityInfo", wrapper)


def _patch_set_security(monkeypatch: pytest.MonkeyPatch, trigger: _Trigger) -> None:
    if sys.platform != "win32":  # Windows-only module: a platform block lets mypy check this file on every platform
        raise AssertionError("Windows-only helper")
    else:
        real = win32security.SetNamedSecurityInfo

        def wrapper(path: Any, *args: Any) -> Any:
            trigger.maybe_fire(path)
            return real(path, *args)

        monkeypatch.setattr(win32security, "SetNamedSecurityInfo", wrapper)


def _patch_scandir(monkeypatch: pytest.MonkeyPatch, trigger: _Trigger) -> None:
    real = os.scandir

    def wrapper(path: Any = ".") -> Any:
        trigger.maybe_fire(path)
        return real(path)

    monkeypatch.setattr(os, "scandir", wrapper)


def _tree(base: Path, os_: OsAdapters) -> tuple[Path, Path, Path, Path]:
    """``data/`` with a doctor-snap-like ``scratch/doctor-snap-x/store/brain.db-journal`` and a widened sibling."""
    data = base / "data"
    data.mkdir()
    os_.permissions.secure_directory(data)
    store = data / "scratch" / "doctor-snap-x" / "store"
    store.mkdir(parents=True)
    (store / "brain.db").write_bytes(b"db")
    journal = store / "brain.db-journal"
    journal.write_bytes(b"journal")
    widened = data / "logs" / "widened.txt"
    widened.parent.mkdir()
    widened.write_bytes(b"w")
    _grant_wide_access(widened)
    assert os_.permissions.object_problems(widened), "precondition: sibling is widened"
    assert not os_.permissions.object_problems(journal), "precondition: journal is owner-only"
    return data, store, journal, widened


# ---------------------------------------------------------------------------
# R1 (a): doctor --fix tighten_permissions walk
# ---------------------------------------------------------------------------


def test_fix_walk_file_vanished_before_acl_inspection_needs_no_repair(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a file listed by the tighten walk and removed before its ACL is read is skipped, not an error;
    the rest of the walk still repairs the widened sibling."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _remove(journal))
    _patch_get_security(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "the injected vanish never ran: the walk did not inspect the journal"
    assert not journal.exists()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(widened)


def test_fix_walk_directory_vanished_before_listing_needs_no_repair(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a directory listed by its parent and removed (with its contents) before the tighten walk scans it
    is skipped, not an error; the widened sibling is still repaired."""
    os_ = os_adapters()
    data, store, _journal, widened = _tree(trusted_tmp, os_)
    snap = store.parent
    trig = _Trigger(snap, _remove(snap))
    _patch_scandir(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "the injected vanish never ran: the walk did not scan the snapshot directory"
    assert not snap.exists()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(widened)


def test_fix_walk_file_vanished_before_acl_repair_needs_no_repair(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a widened file removed after it was inspected but before its ACL is rewritten needs no repair and
    is not counted as changed; the walk does not fail."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    _grant_wide_access(journal)
    assert os_.permissions.object_problems(journal), "precondition: journal is widened"
    trig = _Trigger(journal, _remove(journal))
    _patch_set_security(monkeypatch, trig)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired, "the injected vanish never ran: the walk did not try to repair the journal"
    assert not journal.exists()
    assert changed == 1, changed
    assert not os_.permissions.object_problems(widened)


def test_control_fix_walk_existing_uninspectable_entry_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: an entry that still exists but whose ACL cannot be read fails the walk with
    INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    data, _store, journal, _widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _deny())
    _patch_get_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired
    assert journal.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_fix_walk_existing_unrepairable_entry_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: a widened entry that still exists but whose ACL cannot be rewritten fails the walk with
    INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    data, _store, _journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(widened, _deny())
    _patch_set_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired
    assert widened.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_fix_walk_tightens_widened_entry(trusted_tmp: Path) -> None:
    """R2 invariant: with nothing vanishing, the tighten walk repairs every widened entry and counts it."""
    os_ = os_adapters()
    data, _store, _journal, widened = _tree(trusted_tmp, os_)

    changed, _detail = tighten_data_root_permissions((data, data / "backups"), os_)

    assert changed == 1, changed
    assert not os_.permissions.object_problems(widened)


@pytest.mark.parametrize("boundary", ["inspect", "scandir", "repair"])
def test_control_fix_walk_root_vanished_mid_walk_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """R2 invariant: the walk's own root is never "removed after it was listed"; if it exists when the tighten walk
    starts and is removed before its own scan, ACL read or ACL rewrite, the walk fails closed instead of reporting
    success."""
    os_ = os_adapters()
    data, _store, _journal, _widened = _tree(trusted_tmp, os_)
    trig = _Trigger(data, _remove(data))
    if boundary == "inspect":
        _patch_get_security(monkeypatch, trig)
    elif boundary == "scandir":
        _patch_scandir(monkeypatch, trig)
    else:
        _grant_wide_access(data)
        assert os_.permissions.object_problems(data), "precondition: root is widened"
        _patch_set_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions([data], os_)

    assert trig.fired, "the injected root vanish never ran"
    assert not data.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


# ---------------------------------------------------------------------------
# R1 (c): adapter permissions.problems(root) walk
# ---------------------------------------------------------------------------


def test_adapter_problems_skips_file_vanished_before_inspection(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: ``problems(root)`` skips a listed file removed before its ACL is read and still reports the widened
    sibling."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _remove(journal))
    _patch_get_security(monkeypatch, trig)

    found = os_.permissions.problems(data)

    assert trig.fired
    paths = {_key(p.path) for p in found}
    assert paths == {_key(widened)}, found


def test_adapter_problems_skips_directory_vanished_before_scan(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: ``problems(root)`` skips a listed directory removed before it is scanned and still reports the
    widened sibling."""
    os_ = os_adapters()
    data, store, _journal, widened = _tree(trusted_tmp, os_)
    snap = store.parent
    trig = _Trigger(snap, _remove(snap))
    _patch_scandir(monkeypatch, trig)

    found = os_.permissions.problems(data)

    assert trig.fired
    paths = {_key(p.path) for p in found}
    assert paths == {_key(widened)}, found


def test_control_adapter_problems_existing_uninspectable_entry_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: ``problems(root)`` raises INSECURE_PERMISSIONS for an entry that exists but cannot be read."""
    os_ = os_adapters()
    data, _store, journal, _widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _deny())
    _patch_get_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        os_.permissions.problems(data)

    assert trig.fired
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_adapter_problems_missing_root_fails_closed(trusted_tmp: Path) -> None:
    """R2 invariant: ``problems(root)`` on a walk root that does not exist still raises INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    with pytest.raises(BrainError) as info:
        os_.permissions.problems(trusted_tmp / "never-created")
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


@pytest.mark.parametrize("boundary", ["inspect", "scandir"])
def test_control_adapter_problems_root_vanished_mid_walk_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    """R2 invariant: ``problems(root)`` never treats its own root as "removed after it was listed"; a root that
    exists when the walk starts and is removed before its own ACL read or scan raises INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    data, _store, _journal, _widened = _tree(trusted_tmp, os_)
    trig = _Trigger(data, _remove(data))
    if boundary == "inspect":
        _patch_get_security(monkeypatch, trig)
    else:
        _patch_scandir(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        os_.permissions.problems(data)

    assert trig.fired, "the injected root vanish never ran"
    assert not data.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_adapter_problems_reports_widened_entry(trusted_tmp: Path) -> None:
    """R2 invariant: ``problems(root)`` reports exactly the widened entry when nothing vanishes."""
    os_ = os_adapters()
    data, _store, _journal, widened = _tree(trusted_tmp, os_)
    assert {_key(p.path) for p in os_.permissions.problems(data)} == {_key(widened)}


# ---------------------------------------------------------------------------
# R1 (b): doctor report probe check_permissions_strict
# ---------------------------------------------------------------------------


def _probe(data: Path, os_: OsAdapters) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    perm: list[str] = []
    check_permissions_strict(DataRoot.at(data), os_, errors, perm, [], [])
    return errors, perm


def test_report_probe_records_no_error_for_file_vanished_before_inspection(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: the report permission probe records no error for a file removed between listing and ACL read, and
    still reports the widened sibling."""
    os_ = os_adapters()
    data, _store, journal, widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _remove(journal))
    _patch_get_security(monkeypatch, trig)

    errors, perm = _probe(data, os_)

    assert trig.fired
    assert errors == [], errors
    assert any(widened.name in p for p in perm), perm


def test_report_probe_records_no_error_for_directory_vanished_before_scan(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: the report permission probe records no error for a directory removed between listing and its own
    scan, and still reports the widened sibling."""
    os_ = os_adapters()
    data, store, _journal, widened = _tree(trusted_tmp, os_)
    snap = store.parent
    trig = _Trigger(snap, _remove(snap))
    _patch_scandir(monkeypatch, trig)

    errors, perm = _probe(data, os_)

    assert trig.fired
    assert errors == [], errors
    assert any(widened.name in p for p in perm), perm


def test_control_report_probe_records_error_for_existing_uninspectable_entry(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: the report probe records a permission check error for an entry that exists but cannot be read."""
    os_ = os_adapters()
    data, _store, journal, _widened = _tree(trusted_tmp, os_)
    trig = _Trigger(journal, _deny())
    _patch_get_security(monkeypatch, trig)

    errors, _perm = _probe(data, os_)

    assert trig.fired
    assert any("permission check error" in e for e in errors), errors


def test_control_report_probe_reports_widened_entry(trusted_tmp: Path) -> None:
    """R2 invariant: with nothing vanishing the report probe has no errors and lists the widened entry."""
    os_ = os_adapters()
    data, _store, _journal, widened = _tree(trusted_tmp, os_)
    errors, perm = _probe(data, os_)
    assert errors == [], errors
    assert any(widened.name in p for p in perm), perm


# ---------------------------------------------------------------------------
# R2: "not found" from inspection is not "removed" when the entry cannot be looked up for another reason
# ---------------------------------------------------------------------------


class _DenyLstat:
    """Once armed, ``os.lstat`` on ``target`` raises PermissionError (the entry exists but cannot be looked up)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
        self.target = _key(target)
        self.armed = False
        self.hit = False
        real = os.lstat

        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            if self.armed and _key(path) == self.target:
                self.hit = True
                raise PermissionError(13, "Access is denied", os.fspath(path))
            return real(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", wrapper)


def _not_found_then_deny_lookup(deny: _DenyLstat, kind: str, path: Path) -> Callable[[], None]:
    """The inspection reports "not found" for an entry that still exists; from then on its lookup is denied."""

    def _do() -> None:
        deny.armed = True
        if kind == "acl":
            if sys.platform == "win32":  # Windows-only module (mypy platform block)
                raise pywintypes.error(2, "GetNamedSecurityInfo", "The system cannot find the file specified.")
            raise AssertionError("Windows-only helper")
        raise FileNotFoundError(2, "The system cannot find the path specified", os.fspath(path))

    return _do


def test_control_fix_walk_not_found_with_denied_lookup_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: only a confirmed "not found" lookup makes a listed entry "removed"; an entry whose ACL read
    says not found but whose lookup is denied still fails the tighten walk with INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    data, _store, journal, _widened = _tree(trusted_tmp, os_)
    deny = _DenyLstat(monkeypatch, journal)
    trig = _Trigger(journal, _not_found_then_deny_lookup(deny, "acl", journal))
    _patch_get_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        tighten_data_root_permissions((data, data / "backups"), os_)

    assert trig.fired and deny.hit, (trig.fired, deny.hit)
    deny.armed = False
    assert journal.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_adapter_problems_not_found_with_denied_lookup_fails_closed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: ``problems(root)`` does not skip an entry whose ACL read says not found while its lookup is
    denied; it raises INSECURE_PERMISSIONS."""
    os_ = os_adapters()
    data, _store, journal, _widened = _tree(trusted_tmp, os_)
    deny = _DenyLstat(monkeypatch, journal)
    trig = _Trigger(journal, _not_found_then_deny_lookup(deny, "acl", journal))
    _patch_get_security(monkeypatch, trig)

    with pytest.raises(BrainError) as info:
        os_.permissions.problems(data)

    assert trig.fired and deny.hit, (trig.fired, deny.hit)
    deny.armed = False
    assert journal.exists()
    assert info.value.code is ErrorCode.INSECURE_PERMISSIONS, info.value


def test_control_report_probe_scan_not_found_with_denied_lookup_records_error(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: the report probe's link scan records an error for a listed subdirectory whose scan says not
    found while its lookup is denied; it is not silently skipped as removed."""
    os_ = os_adapters()
    data, store, _journal, _widened = _tree(trusted_tmp, os_)
    snap = store.parent
    deny = _DenyLstat(monkeypatch, snap)
    trig = _Trigger(snap, _not_found_then_deny_lookup(deny, "scan", snap))
    _patch_scandir(monkeypatch, trig)

    errors, _perm = _probe(data, os_)

    assert trig.fired and deny.hit, (trig.fired, deny.hit)
    deny.armed = False
    assert snap.exists()
    assert any(snap.name in e for e in errors), errors


# ---------------------------------------------------------------------------
# R1 (c): fresh_report_matches_live_state
# ---------------------------------------------------------------------------


def _clean_tree(base: Path, os_: OsAdapters) -> tuple[Path, Path]:
    data, _store, journal, widened = _tree(base, os_)
    os_.permissions.secure_file(widened)
    assert not os_.permissions.problems(data), "precondition: live tree is owner-only"
    return data, journal


_PASS_REPORT: dict[str, JsonValue] = {"checks": [{"name": "permissions.tree", "status": "PASS"}]}


def _matches(data: Path, os_: OsAdapters) -> bool:
    rt = SimpleNamespace(root=DataRoot.at(data))
    return bool(fresh_report_matches_live_state(cast(Any, rt), os_, _PASS_REPORT))


def test_fresh_report_match_ignores_file_vanished_before_inspection(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a cached PASS report still matches a clean live tree when an entry vanishes mid-walk; the vanish is
    not drift."""
    os_ = os_adapters()
    data, journal = _clean_tree(trusted_tmp, os_)
    trig = _Trigger(journal, _remove(journal))
    _patch_get_security(monkeypatch, trig)

    assert _matches(data, os_) is True
    assert trig.fired


def test_control_fresh_report_mismatch_for_existing_uninspectable_entry(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2 invariant: an existing entry whose ACL cannot be read makes the cached PASS report stale (fail closed)."""
    os_ = os_adapters()
    data, journal = _clean_tree(trusted_tmp, os_)
    trig = _Trigger(journal, _deny())
    _patch_get_security(monkeypatch, trig)

    assert _matches(data, os_) is False
    assert trig.fired


def test_control_fresh_report_mismatch_for_widened_entry(trusted_tmp: Path) -> None:
    """R2 invariant: a widened live entry makes a cached PASS report stale; a clean tree matches it."""
    os_ = os_adapters()
    data, journal = _clean_tree(trusted_tmp, os_)
    assert _matches(data, os_) is True
    _grant_wide_access(journal)
    assert _matches(data, os_) is False


# ---------------------------------------------------------------------------
# R1 (a): real online daemon fix flow
# ---------------------------------------------------------------------------


def test_online_fix_survives_snapshot_journal_vanishing_mid_walk(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: ``POST /v2/operator/doctor/fix`` with ``tighten_permissions`` completes when a doctor-snapshot
    ``brain.db-journal`` is removed after the walk listed it and before its ACL is read, and still tightens a widened
    entry in the same run."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    base_os = os_adapters(clock=clock)
    _rep, cfg, _priv, ca_pem, _leaf, cli_token, _ = _init_doctor_root(trusted_tmp / "vanish", clock, os_=base_os)
    root = DataRoot.at(cfg.data_root)
    with _running_serve(cfg, os_=base_os, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        store = root.scratch_dir / "doctor-snap-i4vanish" / "store"
        store.mkdir(parents=True)
        journal = store / "brain.db-journal"
        journal.write_bytes(b"transient sqlite journal")
        assert not base_os.permissions.object_problems(journal), "precondition: journal is owner-only"
        root.logs_dir.mkdir(parents=True, exist_ok=True)
        widened = root.logs_dir / "i4-vanish-widened.txt"
        widened.write_bytes(b"w")
        _grant_wide_access(widened)
        before = _acl_or_mode(widened)
        assert base_os.permissions.object_problems(widened), "precondition: target is widened"
        trig = _Trigger(journal, _remove(journal))
        _patch_get_security(monkeypatch, trig)
        env = _post_operator(
            ready, ca_pem, "/v2/operator/doctor/fix", cli_token, {"actions": ["tighten_permissions"]}, 15.0
        )
        trig.armed = False

    assert trig.fired, "the injected vanish never ran: the fix walk did not inspect the journal"
    assert not journal.exists()
    assert env.get("ok") is True, f"fix failed when a listed entry vanished mid-walk: {env}"
    data = cast(dict[str, Any], env["data"])
    fix = cast(dict[str, Any], data["fix"])
    by_name = {a["action"]: a["status"] for a in cast(list[dict[str, Any]], fix["actions"])}
    assert by_name.get("tighten_permissions") == "applied", by_name
    assert _acl_or_mode(widened) != before
    assert not base_os.permissions.object_problems(widened)
