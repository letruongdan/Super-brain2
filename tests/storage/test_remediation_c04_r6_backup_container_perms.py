"""SP1-C04 round 6: verify and restore refuse a backup whose ``cas/`` container, or the backup directory itself, is
not owner-only.

Requirement (spec 5.9: the whole data root, backups included, is accessible to the owner account only (Windows: the
current user plus SYSTEM; Unix: directories ``0700``); spec 5.7: a backup is checked before it touches live data;
ledger C04 and the ruling of 2026-11-01: ``verify_backup`` and restore check, before entering or copying, the type,
link status, owner and owner-only permissions of the backup's ``cas/`` container and of every directory in the
backup contract, with the real ``PermissionGuard``; owner Codex re-review SP1-C04 P2).

The backup contract (``backup._check_entries``, spec 5.7) has these directories: the backup directory itself, its
``cas/`` and the shards under it (files: ``manifest.json``, the snapshot and the blobs). Shards and blobs are already
covered (round 1); these tests make only ONE directory non-owner-only, the ``cas/`` container or the backup
directory, and keep every shard and blob owner-only, as the real guard confirms. Expected: ``verify_backup`` and
``restore_store`` refuse (``INSECURE_PERMISSIONS``, or ``INTEGRITY_FAILURE`` from verification), and the refused
restore copies nothing: the live store, its CAS and the data-root listing stay unchanged.

Windows: an access-allowed ACE for Everyone (``S-1-1-0``, generic read, not inherited). POSIX: mode ``0755`` and
``0777``.
"""

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.backup import create_store_backup, verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import restore_store
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS
from tests.support.fs import digest_tree
from tests.support.platform import posix_only, windows_only

BACKED_UP = b"c04 round 6: in the backup"
LIVE_ONLY = b"c04 round 6: written after the backup"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0461"
LATER_HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0462"
REFUSALS = (ErrorCode.INSECURE_PERMISSIONS, ErrorCode.INTEGRITY_FAILURE)
EVERYONE = "S-1-1-0"
FILE_GENERIC_READ = 0x120089
VARIANTS = [
    pytest.param("everyone-read", marks=windows_only, id="everyone-read"),
    pytest.param("0755", marks=posix_only, id="0755"),
    pytest.param("0777", marks=posix_only, id="0777"),
]
TARGETS = ["cas-container", "backup-directory"]


def loosen(path: Path, variant: str) -> None:
    if variant == "everyone-read":
        from tests.support.winacl import grant

        grant(path, EVERYONE, FILE_GENERIC_READ)
    else:
        path.chmod(int(variant, 8))
    assert os_adapters().permissions.object_problems(path), f"{path} is still owner-only"


def backup_with_a_later_live_blob(data_root: Path) -> tuple[Path, str, str]:
    """A verified store backup holding one blob; afterwards the live store gets another blob the backup lacks."""
    rt = open_runtime(data_root, os_adapters())
    try:
        rt.store.store_content(BACKED_UP, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        backup = create_store_backup(rt.store, rt.os_, datetime.now(UTC))
        later = rt.store.store_content(LIVE_ONLY, "event", LATER_HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        store_id = rt.store.store_id
    finally:
        rt.close()
    verify_backup(backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS)
    return backup, store_id, later


def loosen_target(backup: Path, target: str, variant: str) -> None:
    loosen(backup / "cas" if target == "cas-container" else backup, variant)
    guard = os_adapters().permissions
    for shard in (backup / "cas").iterdir():  # the shards and blobs themselves stay owner-only
        assert guard.object_problems(shard) == [], shard
        for blob in shard.iterdir():
            assert guard.object_problems(blob) == [], blob


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("variant", VARIANTS)
def test_verify_backup_refuses_a_backup_directory_that_is_not_owner_only(
    trusted_tmp: Path, variant: str, target: str
) -> None:
    backup, store_id, _ = backup_with_a_later_live_blob(trusted_tmp / "r")
    loosen_target(backup, target, variant)

    with pytest.raises(BrainError) as refused:
        verify_backup(backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS)

    assert refused.value.code in REFUSALS


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("variant", VARIANTS)
def test_restore_store_refuses_a_backup_directory_that_is_not_owner_only_and_copies_nothing(
    trusted_tmp: Path, variant: str, target: str
) -> None:
    data_root = trusted_tmp / "r"
    backup, _, later = backup_with_a_later_live_blob(data_root)
    loosen_target(backup, target, variant)
    root = DataRoot.at(data_root)
    entries_before = sorted(os.listdir(root.root))
    store_before = digest_tree(root.store_dir)

    rt = open_runtime(data_root, os_adapters())
    try:
        rt.store.close()
        with pytest.raises(BrainError) as refused:
            restore_store(rt.root, rt.lease, rt.os_, backup, rt.policy, datetime.now(UTC))
    finally:
        rt.close()

    assert refused.value.code in REFUSALS
    assert sorted(os.listdir(root.root)) == entries_before, "a restore stage or retired copy was created"
    assert digest_tree(root.store_dir) == store_before, "the live store changed"
    rt = open_runtime(data_root, os_adapters())
    try:
        assert rt.store.cas.read(later) == LIVE_ONLY  # the live store was not replaced by the backup
    finally:
        rt.close()


def test_the_backup_contract_directories_are_these(trusted_tmp: Path) -> None:
    """Pins the scope of the tests above: a store backup holds only manifest, snapshot and cas/<aa>/<blob>."""
    backup, _, _ = backup_with_a_later_live_blob(trusted_tmp / "r")
    directories = sorted(p.relative_to(backup).as_posix() for p in backup.rglob("*") if p.is_dir())
    assert directories[0] == "cas" and all(d == "cas" or d.startswith("cas/") for d in directories), directories
    assert sys.platform == "win32" or all(os.stat(backup / d).st_mode & 0o077 == 0 for d in directories)
