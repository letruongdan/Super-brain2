"""SP1-C08 round 6: the environment preflight checks each existing role path ITSELF, not only its ancestors.

Requirement (spec 4.3 owner policy of 2026-10-31: "ACL thật của data root cùng các thư mục cha" — the real ACL of
the data root AND of its parents; spec 5.9 owner-only data root and the unchanged sticky-bit rule for shared
parents; ledger C08 and the ruling of 2026-11-01; owner Codex re-review SP1-C08 P2: an existing data root at
0755/0777 got ``accepted=true`` while ``open_runtime`` refuses it): through the real ``run_gate`` and the real
preflight (real ``OsEnvironmentProbe``, real ``PermissionGuard``, real ACLs/modes; only the external tools are
faked by ``GreenRunner``):

* an EXISTING default data root (``SUPERBRAIN_HOME``) that is not owner-only (POSIX ``0755``/``0777``; Windows an
  access-allowed ACE for an untrusted SID, here Everyone with read access, which is not a takeover right) makes the
  environment and the receipt NOT accepted, with a reason naming the role and the root;
* the trusted test root ITSELF is checked with the rule for a shared parent: another account must not be able to
  rename or replace its entries (Windows: no takeover ACE for an untrusted SID; POSIX: world/group-writable only with
  the sticky bit). A ``1777`` trusted root (like ``/tmp``) stays acceptable; owner-only is NOT required of it;
* an ABSENT data root is recorded as absent and is not a problem by itself; its nearest existing ancestor is still
  checked, so an insecure parent is still a reason;
* an owner-only existing data root under clean parents is accepted.

C08 ROUND-6 CONTRACT ADDITIONS (``scripts/gate.py`` / ``adapters.os.environment``)
-------------------------------------------------------------------------------------
* ``receipt["environment"]["paths"][role]`` gains ``"exists": bool`` (whether the physical path exists) and
  ``"root_problems": [str]`` (problems of the path itself).
* Each root problem becomes a problem, and so a receipt reason ``"environment: ..."``, that names the role and the
  path.
* ``PathFacts`` gains ``exists: bool | None = None`` and ``root_problems: tuple[str, ...] = ()``.
* ``EnvironmentProbe`` gains ``check_root(path: Path, role: str) -> list[str] | None``. It returns ``None`` when the
  path does not exist, and otherwise the problems of the path itself: for ``default_data_root``, the type, link,
  owner and owner-only check that ``open_runtime`` applies; for ``trusted_test_root``, the shared-parent rule above.
  The test doubles in ``test_remediation_c08_gate_environment.py`` implement it.

The trusted test root is redirected to a directory made by the test (``LOCALAPPDATA`` on Windows, ``TMPDIR`` on
POSIX), so the machine's own roots do not decide these outcomes.
"""

import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from superbrain.adapters.os import os_adapters
from tests.architecture.test_remediation_c08_gate_environment import GreenRunner
from tests.support.platform import posix_only, windows_only

EVERYONE = "S-1-1-0"
FILE_GENERIC_READ = 0x120089
FILE_DELETE_CHILD = 0x40
INSECURE_ROOT_VARIANTS = [
    pytest.param("everyone-read", marks=windows_only, id="everyone-read"),
    pytest.param("0755", marks=posix_only, id="0755"),
    pytest.param("0777", marks=posix_only, id="0777"),
]


def secure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(path)
    return path


def grant(path: Path, mask: int) -> None:
    from tests.support.winacl import grant as add_ace

    add_ace(path, EVERYONE, mask)


def redirect_trusted_root(base: Path, monkeypatch: pytest.MonkeyPatch, *, posix_mode: int = 0o1777) -> Path:
    """Point the trusted-test-root role at a directory made here; returns that directory."""
    if sys.platform == "win32":
        local = secure_dir(base / "Local")
        monkeypatch.setenv("LOCALAPPDATA", str(local))
        return secure_dir(local / "superbrain-tests")
    shared = base / "shared-tmp"
    shared.mkdir()
    shared.chmod(posix_mode)
    monkeypatch.setenv("TMPDIR", str(shared))
    return shared


def run_gate_with_real_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    gate_tmp = tmp_path / "gate"
    gate_tmp.mkdir(exist_ok=True)
    monkeypatch.setattr(gate, "run", GreenRunner())
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(gate_tmp))
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    return dict(receipt)


def environment_of(receipt: dict[str, Any]) -> dict[str, Any]:
    environment = receipt.get("environment")
    assert isinstance(environment, dict), receipt["reasons"]
    return environment


def reasons_naming(receipt: dict[str, Any], role: str, name: str) -> list[str]:
    return [
        str(r) for r in receipt["reasons"] if str(r).startswith("environment: ") and role in str(r) and name in str(r)
    ]


def path_entry(receipt: dict[str, Any], role: str) -> dict[str, Any]:
    entry = environment_of(receipt)["paths"][role]
    assert isinstance(entry, dict)
    return entry


# --- the data root itself ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("variant", INSECURE_ROOT_VARIANTS)
def test_an_existing_data_root_that_is_not_owner_only_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    data_root = secure_dir(secure_dir(trusted_tmp / "homes") / "data-root-loose")
    if variant == "everyone-read":
        grant(data_root, FILE_GENERIC_READ)
    else:
        data_root.chmod(int(variant, 8))
    assert os_adapters().permissions.object_problems(data_root)  # the real guard: not owner-only
    assert os_adapters().permissions.check_ancestors(data_root) == []  # its parents are clean
    monkeypatch.setenv("SUPERBRAIN_HOME", str(data_root))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "an existing data root open to other accounts was accepted"
    assert reasons_naming(receipt, "default_data_root", data_root.name), receipt["reasons"]
    assert environment_of(receipt)["accepted"] is False
    entry = path_entry(receipt, "default_data_root")
    assert entry.get("exists") is True and entry.get("root_problems"), entry


def test_an_existing_owner_only_data_root_is_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    data_root = secure_dir(secure_dir(trusted_tmp / "homes") / "data-root-ok")
    monkeypatch.setenv("SUPERBRAIN_HOME", str(data_root))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert environment_of(receipt)["problems"] == []
    entry = path_entry(receipt, "default_data_root")
    assert entry.get("exists") is True and entry.get("root_problems") == [], entry


# --- an absent data root -------------------------------------------------------------------------------------------


def test_an_absent_data_root_is_recorded_as_absent_and_not_a_problem(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    absent = secure_dir(trusted_tmp / "homes") / "not-created-yet"
    monkeypatch.setenv("SUPERBRAIN_HOME", str(absent))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert environment_of(receipt)["problems"] == []
    entry = path_entry(receipt, "default_data_root")
    assert entry.get("exists") is False and entry.get("root_problems") == [], entry


def test_an_absent_data_root_under_an_insecure_parent_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    parent = secure_dir(trusted_tmp / "takeover-parent")
    if sys.platform == "win32":
        grant(parent, FILE_DELETE_CHILD)
    else:
        parent.chmod(0o777)  # world-writable without the sticky bit
    monkeypatch.setenv("SUPERBRAIN_HOME", str(parent / "absent" / "data-root"))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False
    assert reasons_naming(receipt, "default_data_root", parent.name), receipt["reasons"]
    assert path_entry(receipt, "default_data_root").get("exists") is False


# --- the trusted test root itself ------------------------------------------------------------------------------------


def test_a_trusted_test_root_that_others_can_take_over_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = redirect_trusted_root(trusted_tmp, monkeypatch, posix_mode=0o777)  # POSIX: no sticky bit
    if sys.platform == "win32":
        grant(trusted, FILE_DELETE_CHILD)  # a takeover right for Everyone on the root itself
    monkeypatch.setenv("SUPERBRAIN_HOME", str(secure_dir(trusted_tmp / "homes") / "absent-root"))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "a trusted test root whose entries others can replace was accepted"
    assert reasons_naming(receipt, "trusted_test_root", trusted.name), receipt["reasons"]


@posix_only
def test_a_sticky_world_writable_trusted_test_root_like_tmp_is_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch, posix_mode=0o1777)
    monkeypatch.setenv("SUPERBRAIN_HOME", str(secure_dir(trusted_tmp / "homes") / "absent-root"))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert not [r for r in receipt["reasons"] if "trusted_test_root" in str(r)], receipt["reasons"]
    assert environment_of(receipt)["problems"] == []
