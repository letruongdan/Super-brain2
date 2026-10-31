"""SP1-C08 round 2: the real environment probe takes its facts from the token API and from the real ACLs.

Requirement (spec 4.3 owner policy of 2026-10-31: "token của tiến trình, đường dẫn vật lý và ACL thật của data root
cùng các thư mục cha"; spec 5.9 trusted set unchanged; ledger C08; independent review round 1, mutants M08d "probe
hard-codes app_container=False" and M08e "probe ancestor check always clean"):

* ``OsEnvironmentProbe().app_container()`` is the value the OS token API returns. The OS-call seam is
  ``advapi32!GetTokenInformation`` with ``TokenIsAppContainer`` (information class 29), loaded through
  ``ctypes.WinDLL("advapi32", ...)`` at query time. A controllable fake at that seam must change the probe's answer,
  and a failed query must never be reported as "not an AppContainer" (raise ``OSError`` or return ``None``).
* A real ancestor ACE that grants another account takeover rights over the default data root's parent (spec 5.9)
  surfaces, through the real ``run_gate`` preflight path, as a receipt reason naming ``default_data_root``.
"""

import ctypes
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from tests.architecture.test_remediation_c08_gate_environment import GreenRunner
from tests.support.platform import posix_only, windows_only

TOKEN_IS_APP_CONTAINER = 29
EVERYONE = "S-1-1-0"
FILE_DELETE_CHILD = 0x40


class _Function:
    """A callable that, like a ctypes function pointer, accepts ``argtypes``/``restype``/``errcheck``."""

    def __init__(self, call: Callable[..., int]) -> None:
        self._call = call
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: Any) -> int:
        return self._call(*args)


class FakeAdvapi32:
    """``advapi32`` whose ``GetTokenInformation(TokenIsAppContainer)`` answers ``value`` (``None``: the call fails);
    every other information class goes to the real DLL."""

    def __init__(self, real: Any, value: int | None) -> None:
        self.classes: list[int] = []
        self._real = real
        self._value = value
        self.GetTokenInformation = _Function(self._get_token_information)

    def _get_token_information(self, handle: Any, cls: int, buffer: Any, size: Any, returned: Any) -> int:
        self.classes.append(int(cls))
        if int(cls) != TOKEN_IS_APP_CONTAINER:
            function = self._real.GetTokenInformation
            function.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
            return int(function(handle, cls, buffer, size, returned))
        if self._value is None:
            return 0
        target = getattr(buffer, "_obj", buffer)
        answer = ctypes.c_uint32(self._value)
        ctypes.memmove(ctypes.addressof(target), ctypes.addressof(answer), ctypes.sizeof(answer))
        return 1

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def fake_token_api(monkeypatch: pytest.MonkeyPatch, value: int | None) -> FakeAdvapi32:
    real_windll: Callable[..., Any] = ctypes.WinDLL  # type: ignore[attr-defined,unused-ignore]
    fake = FakeAdvapi32(real_windll("advapi32", use_last_error=True), value)

    def windll(name: str, *args: Any, **kwargs: Any) -> Any:
        if Path(name).stem.lower() == "advapi32":
            return fake
        return real_windll(name, *args, **kwargs)

    monkeypatch.setattr(ctypes, "WinDLL", windll)
    return fake


def independent_app_container_query() -> bool:
    """The test's own ``GetTokenInformation(TokenIsAppContainer)`` call on this process's token."""
    from ctypes import wintypes

    windll: Any = ctypes.WinDLL  # type: ignore[attr-defined,unused-ignore]
    advapi32 = windll("advapi32", use_last_error=True)
    kernel32 = windll("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    assert advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token))
    try:
        value, size = wintypes.DWORD(), wintypes.DWORD()
        assert advapi32.GetTokenInformation(token, TOKEN_IS_APP_CONTAINER, ctypes.byref(value), 4, ctypes.byref(size))
    finally:
        kernel32.CloseHandle(token)
    return value.value != 0


def problems(section: dict[str, Any]) -> list[str]:
    found = section["problems"]
    assert isinstance(found, list)
    return [str(p) for p in found]


# --- the AppContainer flag comes from the token API ---------------------------------------------------------------


@windows_only
def test_the_real_probe_matches_an_independent_token_query() -> None:
    assert gate.OsEnvironmentProbe().app_container() is independent_app_container_query()


@windows_only
def test_the_real_probe_reports_an_app_container_token_from_the_token_api(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_token_api(monkeypatch, value=1)

    flag = gate.OsEnvironmentProbe().app_container()
    facts = gate.collect_environment(gate.OsEnvironmentProbe(), env=os.environ, platform=sys.platform)

    assert flag is True, "the probe did not report the AppContainer flag the token API returned"
    assert TOKEN_IS_APP_CONTAINER in fake.classes
    assert facts.app_container is True
    assert any("AppContainer" in p for p in problems(gate.assess_environment(facts)))


@windows_only
def test_the_real_probe_reports_an_ordinary_token_from_the_token_api(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_token_api(monkeypatch, value=0)

    assert gate.OsEnvironmentProbe().app_container() is False
    assert TOKEN_IS_APP_CONTAINER in fake.classes


@windows_only
def test_a_failed_token_query_is_never_reported_as_an_ordinary_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_token_api(monkeypatch, value=None)

    try:
        flag = gate.OsEnvironmentProbe().app_container()
    except OSError:
        return
    assert flag is None, f"a failed token query was reported as app_container={flag!r}"


@windows_only
def test_run_gate_refuses_when_the_token_api_reports_an_app_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_token_api(monkeypatch, value=1)

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False
    assert any(str(r).startswith("environment: ") and "AppContainer" in str(r) for r in receipt["reasons"])


# --- a real insecure ancestor reaches the receipt -----------------------------------------------------------------


def run_gate_with_real_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``run_gate`` with green fake tools; the environment preflight is the real one (nothing patched in gate)."""
    import tempfile

    monkeypatch.setattr(gate, "run", GreenRunner())
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    return dict(receipt)


def insecure_parent(trusted_tmp: Path) -> Path:
    """A directory in the trusted test root where another account could rename or replace entries (spec 5.9)."""
    parent = trusted_tmp / "shared-parent"
    parent.mkdir()
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard
        from tests.support.winacl import grant

        WindowsPermissionGuard().secure_directory(parent)
        grant(parent, EVERYONE, FILE_DELETE_CHILD)
    else:
        parent.chmod(0o777)  # world-writable without the sticky bit
    return parent


def assert_ancestor_problem_is_a_reason(receipt: dict[str, Any], parent: Path) -> None:
    assert receipt["accepted"] is False, "a data root under a takeover-able parent was accepted"
    reasons = [str(r) for r in receipt["reasons"]]
    assert any(r.startswith("environment: ") and "default_data_root" in r and parent.name in r for r in reasons), (
        reasons
    )
    environment = receipt["environment"]
    assert isinstance(environment, dict)
    assert environment["paths"]["default_data_root"]["ancestor_problems"], environment


@windows_only
def test_run_gate_reports_a_real_takeover_ace_on_the_data_root_parent(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = insecure_parent(trusted_tmp)
    monkeypatch.setenv("SUPERBRAIN_HOME", str(parent / "ensemble-brain"))

    assert_ancestor_problem_is_a_reason(run_gate_with_real_preflight(tmp_path, monkeypatch), parent)


@posix_only
def test_run_gate_reports_a_real_world_writable_data_root_parent(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = insecure_parent(trusted_tmp)
    monkeypatch.setenv("SUPERBRAIN_HOME", str(parent / "ensemble-brain"))

    assert_ancestor_problem_is_a_reason(run_gate_with_real_preflight(tmp_path / "gate", monkeypatch), parent)
