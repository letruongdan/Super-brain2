"""C08 raw configured-path admission, before resolution can erase invalid input.

Approved plan Task 3 forbids Windows extended/device/UNC prefixes and colons
outside the drive letter; 4.3/5.9 and C08 require real preflight/runtime parity.
Every existing ancestor must be a directory, even when the final root is absent.
This file adds only those missing classes; r6/r8/r9 retain links, existing target
type, object/ancestor permissions and token checks. Plain Vietnamese/space paths
remain accepted both absent and initialized. No production security is mocked.
"""

import os
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters, paths
from superbrain.adapters.os.environment import DATA_ROOT_ROLE, OsEnvironmentProbe
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.runtime import open_runtime
from tests.architecture.test_remediation_c08_r6_root_itself import (
    environment_of,
    path_entry,
    reasons_naming,
    redirect_trusted_root,
    run_gate_with_real_preflight,
    secure_dir,
)
from tests.architecture.test_remediation_c08_r8_root_links import make_directory_link
from tests.support.platform import windows_only


@windows_only
@pytest.mark.parametrize("syntax", ["ads", "extended", "device", "unc"])
def test_forbidden_windows_raw_syntax_is_not_admitted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, syntax: str
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    ordinary = secure_dir(trusted_tmp / "homes") / "absent-root"
    if syntax == "ads":
        configured = Path(str(ordinary) + ":stream")
    elif syntax == "extended":
        configured = Path("\\\\?\\" + str(ordinary))
    elif syntax == "device":
        configured = Path("\\\\.\\" + str(ordinary))
    else:
        # A loopback UNC spelling only: no external host, share creation or credential change.
        configured = Path("\\\\localhost\\" + ordinary.drive.rstrip(":") + "$" + str(ordinary)[2:])
    before = sorted(ordinary.parent.iterdir())
    with pytest.raises(BrainError) as refused:
        open_runtime(configured, os_adapters())
    assert refused.value.code == ErrorCode.UNSAFE_PATH
    monkeypatch.setenv("SUPERBRAIN_HOME", str(configured))
    io_calls: list[str] = []
    if syntax == "unc":
        # Keep the real native syntax/security logic. Only the unavailable UNC
        # filesystem edge is instrumented; no network/share operation may occur.
        original_exists = os.path.lexists
        original_links = paths.OsPathSafety.reject_links
        original_resolve = OsEnvironmentProbe.resolve
        original_ancestors = OsEnvironmentProbe.check_ancestors

        def lexists(raw: str | Path) -> bool:
            if str(raw) == str(configured):
                io_calls.append("metadata")
                return False
            return original_exists(raw)

        def reject_links(self: paths.OsPathSafety, path: Path, *, entries: tuple[Path, ...] = ()) -> None:
            if path == configured:
                io_calls.append("links")
                return
            original_links(self, path, entries=entries)

        def resolve(self: OsEnvironmentProbe, path: Path) -> Path:
            if path == configured:
                io_calls.append("resolve")
                return path
            return original_resolve(self, path)

        def ancestors(self: OsEnvironmentProbe, path: Path) -> list[str]:
            if path == configured:
                io_calls.append("ancestors")
                return []
            return original_ancestors(self, path)

        monkeypatch.setattr(os.path, "lexists", lexists)
        monkeypatch.setattr(paths.OsPathSafety, "reject_links", reject_links)
        monkeypatch.setattr(OsEnvironmentProbe, "resolve", resolve)
        monkeypatch.setattr(OsEnvironmentProbe, "check_ancestors", ancestors)

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    # Check the real raw admission boundary too: unrelated UNC resolution/ACL errors
    # cannot count as proof that the explicit syntax rule was applied.
    facts = OsEnvironmentProbe().check_root(configured, DATA_ROOT_ROLE)
    assert facts.problems, f"forbidden {syntax} syntax received clean raw-path admission"
    assert io_calls == [], "UNC filesystem was queried before forbidden raw syntax was rejected"
    assert receipt["accepted"] is False, f"forbidden {syntax} syntax was accepted by preflight"
    assert environment_of(receipt)["accepted"] is False
    assert reasons_naming(receipt, "default_data_root", "absent-root"), receipt["reasons"]
    assert sorted(ordinary.parent.iterdir()) == before


@pytest.mark.parametrize("missing_depth", [0, 1])
def test_an_absent_root_below_a_regular_file_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_depth: int
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    regular = secure_dir(trusted_tmp / "homes") / "regular-ancestor"
    regular.write_bytes(b"preserved regular ancestor")
    os_adapters().permissions.secure_file(regular)
    configured = regular.joinpath(*(["missing"] * missing_depth), "absent-root")
    with pytest.raises(BrainError) as refused:
        open_runtime(configured, os_adapters())
    assert refused.value.code in (ErrorCode.IO_ERROR, ErrorCode.INSECURE_PERMISSIONS)
    monkeypatch.setenv("SUPERBRAIN_HOME", str(configured))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "an absent root below a regular-file ancestor was accepted"
    assert environment_of(receipt)["accepted"] is False
    assert path_entry(receipt, "default_data_root")["exists"] is False
    assert reasons_naming(receipt, "default_data_root", configured.name), receipt["reasons"]
    assert regular.read_bytes() == b"preserved regular ancestor"


@pytest.mark.parametrize("initialized", [False, True])
@pytest.mark.parametrize("missing_parents", [0, 2])
def test_an_ordinary_vietnamese_space_path_remains_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initialized: bool, missing_parents: int
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    configured = secure_dir(trusted_tmp / "Lê Trung").joinpath(*(["missing"] * missing_parents), "thư mục dữ liệu")
    if initialized:
        open_runtime(configured, os_adapters()).close()
    monkeypatch.setenv("SUPERBRAIN_HOME", str(configured))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is True, receipt["reasons"]
    assert environment_of(receipt)["accepted"] is True
    assert path_entry(receipt, "default_data_root")["exists"] is initialized
    open_runtime(configured, os_adapters()).close()


def test_a_trusted_shared_root_below_a_linked_ancestor_remains_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shared-parent role may have linked ancestors, unlike the private data-root role."""
    homes = secure_dir(trusted_tmp / "homes")
    target = secure_dir(homes / "real-shared-parent")
    linked = homes / "linked-shared-parent"
    make_directory_link(linked, target)
    if sys.platform == "win32":
        secure_dir(target / "superbrain-tests")
        monkeypatch.setenv("LOCALAPPDATA", str(linked))
    else:
        shared = secure_dir(target / "shared-tmp")
        shared.chmod(0o1777)
        monkeypatch.setenv("TMPDIR", str(linked / "shared-tmp"))
    monkeypatch.setenv("SUPERBRAIN_HOME", str(homes / "absent-private-root"))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is True, receipt["reasons"]
    assert environment_of(receipt)["accepted"] is True
    assert path_entry(receipt, "trusted_test_root")["exists"] is True
