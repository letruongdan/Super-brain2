"""SP1-C04 round 5: ``verify_backup`` refuses a backup whose ``cas/`` directory itself is a link or junction.

Requirement (spec 5.7: a backup is self-contained, and a snapshot with missing blobs or the wrong subject is refused
before it touches live data; spec 5.9 and review SP1-C04: nothing is read or used through a link, junction or
reparse point; independent review round 2, item R2.6 #2, mutant M4v3, which lets ``verify_backup`` follow a backup
``cas/`` that is itself a link): a real store backup, whose ``cas/`` is moved outside the backup and replaced by a
junction (Windows, ``mklink /J``) or a symlink (POSIX) to it, does not verify. The refusal is ``INTEGRITY_FAILURE``
or ``UNSAFE_PATH``, and the directory outside the backup is left exactly as it was.
"""

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.backup import create_store_backup, verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS
from tests.support.fs import digest_tree
from tests.support.platform import posix_only, windows_only

PAYLOAD = b"c04 round 5: a backup whose cas/ is a link"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0451"
LINK_REFUSALS = (ErrorCode.INTEGRITY_FAILURE, ErrorCode.UNSAFE_PATH)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
LINK_KINDS = [
    pytest.param("junction", marks=windows_only, id="junction"),
    pytest.param("symlink", marks=posix_only, id="symlink"),
]


def make_directory_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert getattr(os.lstat(link), "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    else:
        link.symlink_to(target, target_is_directory=True)
    assert link.is_dir()


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_verify_backup_refuses_a_backup_whose_cas_directory_is_a_link(trusted_tmp: Path, kind: str) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        backup = create_store_backup(rt.store, rt.os_, datetime.now(UTC))
        store_id = rt.store.store_id
    finally:
        rt.close()
    verify_backup(
        backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS, os_=os_adapters()
    )
    outside = trusted_tmp / "outside"
    outside.mkdir()
    os_adapters().permissions.secure_directory(outside)
    moved = outside / "cas"
    (backup / "cas").rename(moved)  # the very same, valid blob files, now outside the backup
    make_directory_link(backup / "cas", moved)
    outside_before = digest_tree(outside)

    with pytest.raises(BrainError) as refused:
        verify_backup(
            backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS, os_=os_adapters()
        )

    assert refused.value.code in LINK_REFUSALS
    assert digest_tree(outside) == outside_before
