"""SP1-C01 round 4: private ``<db>.reading-*`` copies left by a killed reader are removed at the next start-up.

Requirement (spec 5.9: the whole data root holds owner data only, and nothing outlives what retention allows; spec
5.6: forgotten or tombstoned data must not survive in stray copies; independent review round 1 open item 5, probe
P2; ledger round-2 ruling): ``open_readonly`` recovers a WAL in a private ``<db>.reading-<id>/`` directory next to
the database. A reader killed mid-way leaves that full copy behind. The next ``open_runtime`` (under the writer
lease) removes such leftovers next to ``brain.db`` and ``policy.db``. A link, junction or reparse point that merely
has such a name is never followed: its target and the target's contents stay exactly as they were. Normal data
(the databases, their committed content and the CAS) is untouched.

The leftover is produced for real: a child commits in WAL mode and dies (no ``-shm``), then a second child starts
``read_schema_info`` on that database and is killed with ``os._exit`` while the private copy exists.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import open_runtime
from tests.storage.test_remediation_c01_wal_admission import commit_in_wal_then_crash
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT
from tests.support.fs import digest_tree
from tests.support.platform import posix_only, windows_only

PAYLOAD = b"c01 round 4: normal data next to a reader leftover"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0141"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DATABASES = ["brain.db", "policy.db"]
# A committed write that leaves real WAL frames (SQLite writes none for a no-op UPDATE).
COMMIT_IN_WAL = {
    "brain.db": "INSERT INTO meta (key, value) VALUES ('c01_r4_probe', '1')",
    "policy.db": "UPDATE trust SET generation = generation + 1 WHERE id = 1",
}

# A reader is killed while its private recovery copy exists: after the second file copy into it.
_KILL_READER_MID_COPY = f"""
import os, shutil, sys
from pathlib import Path
from superbrain.storage.schema import read_schema_info

real_copyfile = shutil.copyfile
copies = []

def copy_then_die(src, dst, *args, **kwargs):
    result = real_copyfile(src, dst, *args, **kwargs)
    copies.append(dst)
    if len(copies) == 2:
        sys.stderr.write("READER_KILLED\\n")
        sys.stderr.flush()
        os._exit({CRASH_EXIT})
    return result

shutil.copyfile = copy_then_die
read_schema_info(Path(sys.argv[1]))
sys.stderr.write("READER_FINISHED\\n")
"""


def database(root: DataRoot, name: str) -> Path:
    return root.store_db if name == "brain.db" else root.policy_db


def leftovers(db: Path) -> list[str]:
    return sorted(n for n in os.listdir(db.parent) if n.startswith(db.name + ".reading-"))


def seeded_root(data_root: Path) -> tuple[DataRoot, str, str]:
    """A data root with one held payload; returns ``(root, digest, store_id)``."""
    rt = open_runtime(data_root, os_adapters())
    try:
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        store_id = rt.store.store_id
    finally:
        rt.close()
    return DataRoot.at(data_root), digest, store_id


def kill_a_reader(db: Path) -> None:
    commit_in_wal_then_crash(db, COMMIT_IN_WAL[db.name])
    done = subprocess.run(
        [sys.executable, "-I", "-c", _KILL_READER_MID_COPY, str(db)],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "READER_KILLED" in done.stderr, done.stderr


def assert_normal_data_intact(data_root: Path, digest: str, store_id: str) -> None:
    rt = open_runtime(data_root, os_adapters())
    try:
        assert rt.store.store_id == store_id == rt.policy.store_id
        assert rt.store.cas.read(digest) == PAYLOAD
        assert [(k, h) for k, h, _ in rt.store.cas.holders(digest)] == [("event", HOLDER)]
    finally:
        rt.close()


@pytest.mark.parametrize("name", DATABASES)
def test_a_killed_readers_private_copy_is_removed_at_the_next_start(trusted_tmp: Path, name: str) -> None:
    data_root = trusted_tmp / "r"
    root, digest, store_id = seeded_root(data_root)
    db = database(root, name)
    kill_a_reader(db)
    found = leftovers(db)
    assert len(found) == 1 and (db.parent / found[0]).is_dir()
    assert (db.parent / found[0] / db.name).is_file()  # a full copy of the database was left behind

    open_runtime(data_root, os_adapters()).close()

    assert leftovers(db) == [], f"the reader leftover {found} survived the next start-up"
    assert_normal_data_intact(data_root, digest, store_id)


def make_directory_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert getattr(os.lstat(link), "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    else:
        link.symlink_to(target, target_is_directory=True)


STRAY_LINK_ID = "0192f3a4-5b6c-7d8e-9f01-00000000dead"


def a_link_named_like_a_leftover_is_not_followed(trusted_tmp: Path, name: str) -> None:
    data_root = trusted_tmp / "r"
    root, digest, store_id = seeded_root(data_root)
    db = database(root, name)
    outside = trusted_tmp / "outside"
    outside.mkdir()
    os_adapters().permissions.secure_directory(outside)
    (outside / db.name).write_bytes(b"not a database: must survive")
    (outside / "nested").mkdir()
    (outside / "nested" / "keep.txt").write_bytes(b"keep")
    outside_before = digest_tree(outside)
    link = db.parent / f"{db.name}.reading-{STRAY_LINK_ID}"
    make_directory_link(link, outside)

    try:
        open_runtime(data_root, os_adapters()).close()
    except BrainError:
        pass  # refusing the stray link is acceptable; following it is not

    assert digest_tree(outside) == outside_before, "the target of a link named like a reader leftover was changed"
    if os.path.lexists(link):  # the link itself may stay; remove it (never its target) to check the data
        if sys.platform == "win32":
            os.rmdir(link)
        else:
            os.unlink(link)
    assert digest_tree(outside) == outside_before
    assert_normal_data_intact(data_root, digest, store_id)


@windows_only
@pytest.mark.parametrize("name", DATABASES)
def test_a_junction_named_like_a_reader_leftover_is_not_followed(trusted_tmp: Path, name: str) -> None:
    a_link_named_like_a_leftover_is_not_followed(trusted_tmp, name)


@posix_only
@pytest.mark.parametrize("name", DATABASES)
def test_a_symlink_named_like_a_reader_leftover_is_not_followed(trusted_tmp: Path, name: str) -> None:
    a_link_named_like_a_leftover_is_not_followed(trusted_tmp, name)
