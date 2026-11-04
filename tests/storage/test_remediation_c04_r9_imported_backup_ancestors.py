"""C04: exported/imported backup ancestors obey spec 5.9 before verify/restore.

Spec 5.9 explicitly checks parents when exporting backups: a non-owner account
must not be able to rename/replace the backup tree. Each backup object is kept
owner-only; only its immediate parent grants takeover (POSIX nonsticky 0777,
Windows Everyone FILE_DELETE_CHILD). Real verify and each restore API must refuse
before changing live state. Store and policy backups have the same parent rule.
"""

import shutil
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.layout import DataRoot
from tests.storage.test_remediation_c04_r8_backup_files import (
    attempt_restore,
    live_state,
    make_backup,
    verify,
)
from tests.support.fs import digest_tree


def imported_backup(trusted_tmp: Path, kind: str) -> tuple[Path, Path, Path, str]:
    data_root = trusted_tmp / "r"
    original, store_id = make_backup(data_root, kind)
    guard = os_adapters().permissions
    parent = trusted_tmp / "export-parent"
    parent.mkdir()
    guard.secure_directory(parent)
    imported = parent / original.name
    shutil.copytree(original, imported)
    for entry in (imported, *imported.rglob("*")):
        if entry.is_dir():
            guard.secure_directory(entry)
        else:
            guard.secure_file(entry)
    verify(imported, kind, store_id)
    return data_root, parent, imported, store_id


@pytest.mark.parametrize("kind", ["store", "policy"])
@pytest.mark.parametrize("boundary", ["verify", "restore"])
def test_an_imported_backup_under_a_takeover_parent_is_refused(
    trusted_tmp: Path, kind: str, boundary: str
) -> None:
    data_root, parent, imported, store_id = imported_backup(trusted_tmp, kind)
    guard = os_adapters().permissions
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(parent, "S-1-1-0", 0x40)  # FILE_DELETE_CHILD, deliberately not inherited
    else:
        parent.chmod(0o777)  # no sticky bit
    assert guard.check_ancestors(imported), "the backup parent still forbids takeover"
    for entry in (imported, *imported.rglob("*")):
        assert guard.object_problems(entry) == [], entry
    root = DataRoot.at(data_root)
    before = live_state(root)
    source_before = digest_tree(parent)

    if boundary == "verify":
        with pytest.raises(BrainError) as refused:
            verify(imported, kind, store_id)
        assert refused.value.code == ErrorCode.INSECURE_PERMISSIONS
    else:
        code = attempt_restore(data_root, imported, kind, store_id)
        assert code == ErrorCode.INSECURE_PERMISSIONS, f"restore accepted a replaceable backup (outcome {code})"

    assert live_state(root) == before, "refusing the imported backup changed live state"
    assert digest_tree(parent) == source_before, "refusing the imported backup changed its source"


@pytest.mark.parametrize("kind", ["store", "policy"])
@pytest.mark.parametrize("boundary", ["verify", "restore"])
def test_an_imported_backup_under_a_safe_parent_remains_usable(trusted_tmp: Path, kind: str, boundary: str) -> None:
    """Owner-only parents work; POSIX additionally retains the explicitly allowed sticky-parent rule."""
    data_root, parent, imported, store_id = imported_backup(trusted_tmp, kind)
    if sys.platform != "win32":
        parent.chmod(0o1777)
    assert os_adapters().permissions.check_ancestors(imported) == []
    before = digest_tree(parent)

    if boundary == "verify":
        verify(imported, kind, store_id)
    else:
        assert attempt_restore(data_root, imported, kind, store_id) is None

    assert digest_tree(parent) == before
