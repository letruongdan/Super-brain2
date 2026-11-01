"""SP1-C08 round 8: a role path that is a link, junction or regular file makes the environment not accepted.

Requirement (spec 4.3 owner policy: the acceptance environment is checked for real, "đường dẫn vật lý và ACL thật";
spec 5.9 and ``prepare_data_root``: a data root that is or passes through a link is ``UNSAFE_PATH``; ledger C08,
ruling "Review round 4" S1: the preflight checks the CONFIGURED role path (unresolved) for a link or junction BEFORE
resolving it and records it as a problem, matching the runtime; a data root that is a regular file is not accepted
either; review R4.5 survivors R8c and R8d): through the real ``run_gate`` and the real preflight (real probe, real
``PermissionGuard``, real links; only the external tools are faked):

* a data root (``SUPERBRAIN_HOME``) that is a junction (Windows) or symlink (POSIX) to an owner-only directory;
* a trusted test root that is a junction (Windows) or symlink (POSIX) to an acceptable directory;
* a data root that is an owner-only regular file;

each makes the environment and the receipt NOT accepted, with a reason naming the role and the configured path.
The link targets themselves are acceptable, so only the link (or the file type) can be the reason.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from tests.architecture.test_remediation_c08_r6_root_itself import (
    environment_of,
    reasons_naming,
    redirect_trusted_root,
    run_gate_with_real_preflight,
    secure_dir,
)

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def make_directory_link(link: Path, target: Path) -> None:
    """A real Windows junction (``mklink /J``), or a POSIX directory symlink."""
    if sys.platform == "win32":
        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert getattr(os.lstat(link), "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    else:
        link.symlink_to(target, target_is_directory=True)


def test_a_data_root_that_is_a_link_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    homes = secure_dir(trusted_tmp / "homes")
    target = secure_dir(homes / "real-data-root")  # owner-only, clean parents: acceptable in itself
    link = homes / "linked-data-root"
    make_directory_link(link, target)
    monkeypatch.setenv("SUPERBRAIN_HOME", str(link))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "a data root that is a link or junction was accepted"
    assert reasons_naming(receipt, "default_data_root", link.name), receipt["reasons"]
    assert environment_of(receipt)["accepted"] is False


def test_a_trusted_test_root_that_is_a_link_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "win32":
        local = secure_dir(trusted_tmp / "Local")
        target = secure_dir(trusted_tmp / "real-tests-root")
        link = local / "superbrain-tests"
        make_directory_link(link, target)
        monkeypatch.setenv("LOCALAPPDATA", str(local))
    else:
        target = trusted_tmp / "real-shared-tmp"
        target.mkdir()
        target.chmod(0o1777)  # sticky, like /tmp: acceptable in itself
        link = trusted_tmp / "linked-tmp"
        make_directory_link(link, target)
        monkeypatch.setenv("TMPDIR", str(link))
    monkeypatch.setenv("SUPERBRAIN_HOME", str(secure_dir(trusted_tmp / "homes") / "absent-root"))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "a trusted test root that is a link or junction was accepted"
    assert reasons_naming(receipt, "trusted_test_root", link.name), receipt["reasons"]


def test_a_data_root_that_is_a_regular_file_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    data_root = secure_dir(trusted_tmp / "homes") / "data-root-file"
    data_root.write_bytes(b"not a directory")
    os_adapters().permissions.secure_file(data_root)
    assert os_adapters().permissions.object_problems(data_root) == []  # owner-only: only the type is wrong
    monkeypatch.setenv("SUPERBRAIN_HOME", str(data_root))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is False, "a data root that is a regular file was accepted"
    assert reasons_naming(receipt, "default_data_root", data_root.name), receipt["reasons"]
