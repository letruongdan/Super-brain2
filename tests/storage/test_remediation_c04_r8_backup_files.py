"""SP1-C04 round 8: every file and directory in a backup is admitted before anything in it is read or copied.

Requirement (spec 5.9: the whole data root, backups included, is owner-only; spec 5.7: a backup is checked before it
touches live data; review SP1-C04 "nothing is read through a link"; ledger C04, ruling "Review round 4" (supersedes
the directory-only scope): ``verify_backup`` and restore check EVERY file and directory of the backup contract (the
backup directory, ``manifest.json``, every snapshot file, ``cas/``, shards and blobs) for type, no link or reparse
point, owner and owner-only permission, with ``os_.permissions``, before reading any of them; review R4.6 S2, S3, S4
and survivor R4ef):

* S2/S3: a backup whose ``manifest.json`` or snapshot file is not owner-only (POSIX ``0644``/``0666``; Windows an
  access-allowed ACE for Everyone with read access), while everything else stays owner-only, is refused by
  ``verify_backup``, ``restore_store`` (store backups) and ``restore_policy`` (policy backups);
* S4: the same when ``manifest.json`` or the snapshot is a symlink to an identical file outside the data root
  (POSIX; Windows only where this account may create a file symlink, otherwise skipped with the reason);
* R4ef: a backup directory that is itself a link (Windows junction, POSIX symlink) to an identical copy outside the
  data root is refused.

A refusal is ``INSECURE_PERMISSIONS``, ``UNSAFE_PATH`` or ``INTEGRITY_FAILURE``. A refused restore copies nothing:
the data-root listing and the live ``store/`` and ``policy/`` trees are unchanged, and the outside files are unchanged.
"""

import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.backup import BackupKind, create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS
from tests.storage.conftest import maintenance_lease
from tests.support.fs import digest_tree
from tests.support.platform import posix_only, windows_only

PAYLOAD = b"c04 round 8: a held blob"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0481"
REFUSALS = (ErrorCode.INSECURE_PERMISSIONS, ErrorCode.UNSAFE_PATH, ErrorCode.INTEGRITY_FAILURE)
EVERYONE = "S-1-1-0"
FILE_GENERIC_READ = 0x120089
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
SNAPSHOT = {"store": "brain.db", "policy": "policy.db"}
KINDS = ["store", "policy"]
FILES = ["manifest", "snapshot"]
LOOSE = [
    pytest.param("everyone-read", marks=windows_only, id="everyone-read"),
    pytest.param("0644", marks=posix_only, id="0644"),
    pytest.param("0666", marks=posix_only, id="0666"),
]
LINK_KINDS = [
    pytest.param("junction", marks=windows_only, id="junction"),
    pytest.param("symlink", marks=posix_only, id="symlink"),
]


def make_backup(data_root: Path, kind: str) -> tuple[Path, str]:
    """A verified ``store`` or ``policy`` backup of a root holding one blob; returns ``(backup, store_id)``."""
    rt = open_runtime(data_root, os_adapters())
    try:
        rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        if kind == "store":
            backup = create_store_backup(rt.store, rt.os_, datetime.now(UTC))
        else:
            backup = create_policy_backup(rt.policy, rt.os_, datetime.now(UTC))
        store_id = rt.store.store_id
    finally:
        rt.close()
    verify(backup, kind, store_id)
    return backup, store_id


def verify(backup: Path, kind: str, store_id: str) -> None:
    migrations = STORE_MIGRATIONS if kind == "store" else POLICY_MIGRATIONS
    expected: BackupKind = "store" if kind == "store" else "policy"
    verify_backup(backup, expected_kind=expected, expected_store_id=store_id, migrations=migrations, os_=os_adapters())


def target_file(backup: Path, kind: str, which: str) -> Path:
    return backup / ("manifest.json" if which == "manifest" else SNAPSHOT[kind])


def loosen(path: Path, variant: str) -> None:
    if variant == "everyone-read":
        from tests.support.winacl import grant

        grant(path, EVERYONE, FILE_GENERIC_READ)
    else:
        path.chmod(int(variant, 8))
    assert os_adapters().permissions.object_problems(path), f"{path} is still owner-only"


def assert_rest_owner_only(backup: Path, except_path: Path) -> None:
    guard = os_adapters().permissions
    for entry in (backup, *backup.rglob("*")):
        if entry != except_path and not entry.is_symlink():
            assert guard.object_problems(entry) == [], entry


def live_state(root: DataRoot) -> tuple[list[str], dict[str, str], dict[str, str]]:
    from tests.support.fs import digest_data_root

    return sorted(os.listdir(root.root)), digest_data_root(root.store_dir), digest_data_root(root.policy_dir)


def attempt_restore(data_root: Path, backup: Path, kind: str, store_id: str) -> ErrorCode | None:
    """Restore ``backup`` with the matching API; the refusal code, or ``None`` if the restore went through."""
    try:
        if kind == "store":
            rt = open_runtime(data_root, os_adapters())
            try:
                rt.store.close()
                restore_store(rt.root, rt.lease, rt.os_, backup, rt.policy, datetime.now(UTC))
            finally:
                rt.close()
        else:
            with maintenance_lease(data_root) as (root, lease):
                restore_policy(root, lease, os_adapters(), backup, store_id=store_id, now=datetime.now(UTC))
    except BrainError as err:
        return err.code
    return None


def check_refused(data_root: Path, backup: Path, kind: str, store_id: str) -> None:
    with pytest.raises(BrainError) as refused:
        verify(backup, kind, store_id)
    assert refused.value.code in REFUSALS
    root = DataRoot.at(data_root)
    before = live_state(root)
    code = attempt_restore(data_root, backup, kind, store_id)
    assert code in REFUSALS, f"the restore went through (outcome {code})"
    assert live_state(root) == before, "a refused restore changed the data root"


# --- S2/S3: a manifest or snapshot file that is not owner-only -------------------------------------------------------


@pytest.mark.parametrize("variant", LOOSE)
@pytest.mark.parametrize("which", FILES)
@pytest.mark.parametrize("kind", KINDS)
def test_a_backup_file_that_is_not_owner_only_is_refused_before_it_is_read(
    trusted_tmp: Path, kind: str, which: str, variant: str
) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = make_backup(data_root, kind)
    path = target_file(backup, kind, which)
    loosen(path, variant)
    assert_rest_owner_only(backup, path)

    check_refused(data_root, backup, kind, store_id)


# --- S4: a manifest or snapshot file that is a symlink ---------------------------------------------------------------


def link_file_outside(path: Path, outside_dir: Path) -> Path:
    """Move ``path`` outside the data root and put a file symlink to it in its place; skip where not permitted."""
    outside_dir.mkdir()
    os_adapters().permissions.secure_directory(outside_dir)
    target = outside_dir / path.name
    shutil.move(str(path), target)
    try:
        os.symlink(target, path)
    except OSError as err:
        shutil.move(str(target), path)
        if sys.platform == "win32":
            pytest.skip(f"this Windows account may not create a file symlink ({err}); S4 is covered on POSIX")
        raise
    return target


@pytest.mark.parametrize("which", FILES)
@pytest.mark.parametrize("kind", KINDS)
def test_a_backup_file_that_is_a_symlink_is_refused(trusted_tmp: Path, kind: str, which: str) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = make_backup(data_root, kind)
    target = link_file_outside(target_file(backup, kind, which), trusted_tmp / "outside")
    outside_before = digest_tree(target.parent)

    check_refused(data_root, backup, kind, store_id)

    assert digest_tree(target.parent) == outside_before


# --- R4ef: the backup directory itself is a link ---------------------------------------------------------------------


def make_directory_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert getattr(os.lstat(link), "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    else:
        link.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize("link_kind", LINK_KINDS)
@pytest.mark.parametrize("kind", KINDS)
def test_a_backup_directory_that_is_a_link_is_refused(trusted_tmp: Path, kind: str, link_kind: str) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = make_backup(data_root, kind)
    outside = trusted_tmp / "outside"
    outside.mkdir()
    os_adapters().permissions.secure_directory(outside)
    moved = outside / backup.name
    backup.rename(moved)  # the very same, valid backup, now outside the data root
    make_directory_link(backup, moved)
    outside_before = digest_tree(outside)

    check_refused(data_root, backup, kind, store_id)

    assert digest_tree(outside) == outside_before
