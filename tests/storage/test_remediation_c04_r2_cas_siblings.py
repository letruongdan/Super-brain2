"""SP1-C04 round 2: the listing, GC, backup-copy and backup-verify siblings never reach through a linked shard.

Requirement (spec 5.9 owner-only data root, spec 5.5 layout, spec 5.7 self-contained backups; review SP1-C04 "kiểm
shard/blob hiện hữu ... trước reuse/read/write"; ledger C04; independent review round 1, mutants M04d, M04f, M04dg,
M04df and probe P3/P3b): every CAS operation that lists, deletes or copies blob files, and the verification of a
backup's own ``cas/``, refuses (or at least never lists, touches, deletes or copies) a file reached through a shard
that is a link, a Windows junction or a reparse point. The directory outside the root is never changed and none
of its bytes end up in a backup. A refusal is ``UNSAFE_PATH`` or ``INTEGRITY_FAILURE``.

Windows junctions (``mklink /J``) and POSIX symlinks are separate cases; each linked-shard test has both.
"""

import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.backup import copy_blobs, create_maintenance_backup, create_store_backup, verify_backup
from superbrain.storage.cas import RetentionClass, blob_path
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS
from tests.storage.conftest import maintenance_lease
from tests.support.fs import digest_tree, set_mtime
from tests.support.inc2_fixture import open_cloned_runtime
from tests.support.platform import posix_only, windows_only

PAYLOAD = b"c04 round 2: a blob reached through a linked shard"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0411"
LINK_REFUSALS = (ErrorCode.UNSAFE_PATH, ErrorCode.INTEGRITY_FAILURE)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
LONG_AGO = datetime(2001, 1, 1, tzinfo=UTC)
LINK_KINDS = [
    pytest.param("junction", marks=windows_only, id="junction"),
    pytest.param("symlink", marks=posix_only, id="symlink"),
]


def hex_of(digest: str) -> str:
    return digest[len("sha256:") :]


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
    assert link.is_dir()


def outside_directory(trusted_tmp: Path) -> Path:
    """An owner-only directory next to the data root: only its being outside the root is wrong."""
    outside = trusted_tmp / "outside"
    outside.mkdir()
    os_adapters().permissions.secure_directory(outside)
    return outside


def outside_blob_behind_a_linked_shard(trusted_tmp: Path, cas_dir: Path) -> tuple[str, Path]:
    """A correctly named, correctly hashed, old blob file in an outside directory that ``cas/<aa>`` links to.
    Returns ``(digest, outside directory)``; no holder refers to it, so it looks like an orphan through the link."""
    digest = digest_bytes(PAYLOAD)
    outside = outside_directory(trusted_tmp)
    blob = outside / hex_of(digest)
    blob.write_bytes(PAYLOAD)
    os_adapters().permissions.secure_file(blob)
    set_mtime(blob, LONG_AGO)
    shard = cas_dir / hex_of(digest)[:2]
    assert not os.path.lexists(shard)
    make_directory_link(shard, outside)
    return digest, outside


def held_blob_moved_behind_a_linked_shard(trusted_tmp: Path, data_root: Path) -> tuple[str, Path]:
    """Store ``PAYLOAD`` with a holder, then move its real shard outside the root and link it back in."""
    rt = open_cloned_runtime(data_root, os_adapters(), role="c04r2-held")
    try:
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
    finally:
        rt.close()
    shard = blob_path(DataRoot.at(data_root).cas_dir, digest).parent
    outside = outside_directory(trusted_tmp)
    moved = outside / shard.name
    shard.rename(moved)
    make_directory_link(shard, moved)
    return digest, outside


def with_runtime(data_root: Path, operation: Callable[[Runtime], object]) -> tuple[ErrorCode | None, object]:
    """Open the runtime and run ``operation``: ``(refusal code, None)`` or ``(None, result)``."""
    try:
        rt = open_runtime(data_root, os_adapters())
    except BrainError as err:
        return err.code, None
    try:
        return None, operation(rt)
    except BrainError as err:
        return err.code, None
    finally:
        rt.close()


def fresh_root(data_root: Path) -> DataRoot:
    open_cloned_runtime(data_root, os_adapters(), role="c04r2-fresh").close()
    return DataRoot.at(data_root)


def complete_backups(root: DataRoot) -> list[str]:
    return sorted(p.name for p in root.backups_dir.iterdir() if (p / "manifest.json").exists())


# --- listing and GC -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_orphan_listing_never_lists_a_blob_through_a_linked_shard(trusted_tmp: Path, kind: str) -> None:
    data_root = trusted_tmp / "r"
    digest, outside = outside_blob_behind_a_linked_shard(trusted_tmp, fresh_root(data_root).cas_dir)
    outside_before = digest_tree(outside)

    code, listed = with_runtime(data_root, lambda rt: rt.store.cas.orphans())

    assert code in LINK_REFUSALS or (isinstance(listed, list) and digest not in listed), (
        f"orphans() listed a file outside the data root (outcome {code}, listed {listed})"
    )
    assert digest_tree(outside) == outside_before


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_gc_never_deletes_a_blob_through_a_linked_shard(trusted_tmp: Path, kind: str) -> None:
    data_root = trusted_tmp / "r"
    digest, outside = outside_blob_behind_a_linked_shard(trusted_tmp, fresh_root(data_root).cas_dir)
    outside_before = digest_tree(outside)
    later = datetime.now(UTC) + timedelta(days=30)

    code, report = with_runtime(data_root, lambda rt: rt.store.cas.collect_garbage(now=later))

    assert digest_tree(outside) == outside_before, f"GC changed a directory outside the data root (outcome {code})"
    assert (outside / hex_of(digest)).read_bytes() == PAYLOAD
    assert code in LINK_REFUSALS or digest not in getattr(report, "deleted", ()), (code, report)


# --- backup copies ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_store_backup_refuses_a_held_blob_behind_a_linked_shard(trusted_tmp: Path, kind: str) -> None:
    data_root = trusted_tmp / "r"
    fresh_root(data_root)
    digest, outside = held_blob_moved_behind_a_linked_shard(trusted_tmp, data_root)
    outside_before = digest_tree(outside)
    now = datetime.now(UTC)

    code, _ = with_runtime(data_root, lambda rt: create_store_backup(rt.store, rt.os_, now))

    assert code in LINK_REFUSALS, f"a store backup copied a blob through a linked shard (outcome {code})"
    assert complete_backups(DataRoot.at(data_root)) == []
    assert digest_tree(outside) == outside_before


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_full_store_backup_refuses_a_linked_shard(trusted_tmp: Path, kind: str) -> None:
    data_root = trusted_tmp / "r"
    _, outside = outside_blob_behind_a_linked_shard(trusted_tmp, fresh_root(data_root).cas_dir)
    outside_before = digest_tree(outside)

    with pytest.raises(BrainError) as refused, maintenance_lease(data_root) as (root, lease):
        create_maintenance_backup(root, lease, os_adapters(), target="store", now=datetime.now(UTC))

    assert refused.value.code in LINK_REFUSALS
    assert complete_backups(DataRoot.at(data_root)) == []
    assert digest_tree(outside) == outside_before


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_copy_blobs_refuses_a_linked_source_shard(trusted_tmp: Path, kind: str) -> None:
    """``copy_blobs`` is the copy step of every store backup and of restore: it checks each source itself."""
    source_cas = trusted_tmp / "source-cas"
    source_cas.mkdir()
    os_adapters().permissions.secure_directory(source_cas)
    digest, outside = outside_blob_behind_a_linked_shard(trusted_tmp, source_cas)
    dest_cas = trusted_tmp / "dest-cas"

    with pytest.raises(BrainError) as refused:
        copy_blobs(source_cas, dest_cas, [digest], os_adapters())

    assert refused.value.code in LINK_REFUSALS
    assert not blob_path(dest_cas, digest).exists(), "bytes from outside the root were copied"


@posix_only
def test_copy_blobs_refuses_a_blob_that_is_a_symlink(trusted_tmp: Path) -> None:
    source_cas = trusted_tmp / "source-cas"
    digest = digest_bytes(PAYLOAD)
    shard = source_cas / hex_of(digest)[:2]
    shard.mkdir(parents=True)
    for directory in (source_cas, shard):
        os_adapters().permissions.secure_directory(directory)
    outside = outside_directory(trusted_tmp) / "blob"
    outside.write_bytes(PAYLOAD)
    os_adapters().permissions.secure_file(outside)
    (shard / hex_of(digest)).symlink_to(outside)
    dest_cas = trusted_tmp / "dest-cas"

    with pytest.raises(BrainError) as refused:
        copy_blobs(source_cas, dest_cas, [digest], os_adapters())

    assert refused.value.code in LINK_REFUSALS
    assert not blob_path(dest_cas, digest).exists()


# --- a backup's own cas/ ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_verify_backup_refuses_a_backup_whose_shard_is_a_link(trusted_tmp: Path, kind: str) -> None:
    data_root = trusted_tmp / "r"
    rt = open_cloned_runtime(data_root, os_adapters(), role="c04r2-verify-bak")
    try:
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        backup = create_store_backup(rt.store, rt.os_, datetime.now(UTC))
        store_id = rt.store.store_id
    finally:
        rt.close()
    verify_backup(
        backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS, os_=os_adapters()
    )
    shard = blob_path(backup / "cas", digest).parent
    outside = outside_directory(trusted_tmp)
    moved = outside / shard.name
    shard.rename(moved)
    make_directory_link(shard, moved)
    outside_before = digest_tree(outside)

    with pytest.raises(BrainError) as refused:
        verify_backup(
            backup, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS, os_=os_adapters()
        )

    assert refused.value.code in LINK_REFUSALS
    assert digest_tree(outside) == outside_before
