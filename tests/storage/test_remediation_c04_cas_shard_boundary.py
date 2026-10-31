"""SP1-C04: an existing CAS shard or blob is checked before it is reused, read or written through.

Requirement (spec 5.9 "Toàn bộ data root ... chỉ tài khoản owner truy cập được", spec 5.5 data-root layout, review
SP1-C04, ledger C04): an existing ``cas/<aa>`` shard or blob that is a link/junction/reparse point, the wrong kind of
object, outside the data root, or not owner-only is refused **before any I/O outside the root**. The link target
outside the root receives no new file, a read through the link is refused, and nothing outside the root is
re-secured or changed. Valid shards and deduplication keep working.

Expected refusal codes: a link or a wrong object is ``UNSAFE_PATH`` (the code every other link check of the data
root uses) or ``INTEGRITY_FAILURE``; a shard or blob that others can access is ``INSECURE_PERMISSIONS`` (the code of
every other owner-only check). The refusal may come from ``open_runtime`` or from the CAS call itself.

A Windows junction (``mklink /J``) and a POSIX symlink are covered separately; they are different OS objects.
"""

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import ContentStore, RetentionClass, blob_path
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import open_runtime
from tests.support.fs import digest_tree, modes_tree
from tests.support.platform import posix_only, windows_only

PAYLOAD = b"c04: payload whose shard is replaced"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0401"
OTHER_HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0402"
LINK_REFUSALS = (ErrorCode.UNSAFE_PATH, ErrorCode.INTEGRITY_FAILURE)
EVERYONE = "S-1-1-0"
FILE_GENERIC_READ = 0x120089
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def shard_of(payload: bytes) -> str:
    return digest_bytes(payload)[len("sha256:") :][:2]


def same_shard_payload(payload: bytes) -> bytes:
    """Another payload whose digest lands in the same shard as ``payload``."""
    for i in range(100_000):
        candidate = f"c04: same shard {i}".encode()
        if candidate != payload and shard_of(candidate) == shard_of(payload):
            return candidate
    raise AssertionError("no payload found for the shard")


def fresh_root(data_root: Path) -> DataRoot:
    open_runtime(data_root, os_adapters()).close()
    return DataRoot.at(data_root)


def store_payload(data_root: Path, payload: bytes, holder: str = HOLDER) -> str:
    rt = open_runtime(data_root, os_adapters())
    try:
        return rt.store.store_content(payload, "event", holder, RetentionClass.EVENT_PAYLOAD, None)
    finally:
        rt.close()


def outside_directory(trusted_tmp: Path, name: str = "outside") -> Path:
    """An owner-only directory next to the data root (so only its being outside the root is wrong)."""
    outside = trusted_tmp / name
    outside.mkdir()
    os_adapters().permissions.secure_directory(outside)
    return outside


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


def attempt(data_root: Path, operation: Callable[[ContentStore], object]) -> tuple[ErrorCode | None, object]:
    """Open the runtime and run ``operation`` on its CAS: ``(refusal code, None)`` or ``(None, result)``."""
    try:
        rt = open_runtime(data_root, os_adapters())
    except BrainError as err:
        return err.code, None
    try:
        return None, operation(rt.store.cas)
    except BrainError as err:
        return err.code, None
    finally:
        rt.close()


def make_readable_by_others(path: Path) -> None:
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(path, EVERYONE, FILE_GENERIC_READ)
    else:
        path.chmod(0o755 if path.is_dir() else 0o644)


# --- a linked shard ----------------------------------------------------------------------------------------------


def put_through_a_linked_new_shard(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    root = fresh_root(data_root)
    shard = root.cas_dir / shard_of(PAYLOAD)
    assert not os.path.lexists(shard)
    outside = outside_directory(trusted_tmp)
    make_directory_link(shard, outside)
    outside_access = modes_tree(outside)

    code, _ = attempt(data_root, lambda cas: cas.put(PAYLOAD))

    assert sorted(os.listdir(outside)) == [], "the put wrote outside the data root"
    assert code in LINK_REFUSALS, f"a put through a linked shard was not refused (outcome {code})"
    assert modes_tree(outside) == outside_access, "the access rights of a directory outside the root were changed"


def read_through_a_linked_existing_shard(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    fresh_root(data_root)
    digest = store_payload(data_root, PAYLOAD)
    root = DataRoot.at(data_root)
    shard = blob_path(root.cas_dir, digest).parent
    outside = outside_directory(trusted_tmp)
    moved = outside / shard.name
    shard.rename(moved)
    make_directory_link(shard, moved)
    outside_before = digest_tree(outside)

    read_code, read_result = attempt(data_root, lambda cas: cas.read(digest))
    put_code, _ = attempt(data_root, lambda cas: cas.put(same_shard_payload(PAYLOAD)))

    assert read_result != PAYLOAD and read_code in LINK_REFUSALS, (
        f"a read through a linked shard was not refused (outcome {read_code})"
    )
    assert put_code in LINK_REFUSALS, f"a put into a linked shard was not refused (outcome {put_code})"
    assert digest_tree(outside) == outside_before, "a file outside the data root was written"


@windows_only
def test_put_through_a_junction_shard_is_refused_before_writing_outside_the_root(trusted_tmp: Path) -> None:
    put_through_a_linked_new_shard(trusted_tmp)


@windows_only
def test_read_through_a_junction_shard_is_refused(trusted_tmp: Path) -> None:
    read_through_a_linked_existing_shard(trusted_tmp)


@posix_only
def test_put_through_a_symlink_shard_is_refused_before_writing_outside_the_root(trusted_tmp: Path) -> None:
    put_through_a_linked_new_shard(trusted_tmp)


@posix_only
def test_read_through_a_symlink_shard_is_refused(trusted_tmp: Path) -> None:
    read_through_a_linked_existing_shard(trusted_tmp)


def test_a_shard_that_is_a_file_is_refused_and_left_unchanged(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    root = fresh_root(data_root)
    shard = root.cas_dir / shard_of(PAYLOAD)
    shard.write_bytes(b"not a directory")
    os_adapters().permissions.secure_file(shard)

    code, _ = attempt(data_root, lambda cas: cas.put(PAYLOAD))

    assert code is not None
    assert shard.is_file() and shard.read_bytes() == b"not a directory"


# --- an existing shard or blob that others can access ------------------------------------------------------------


def test_an_existing_shard_that_others_can_read_is_refused_before_reuse(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    fresh_root(data_root)
    digest = store_payload(data_root, PAYLOAD)
    shard = blob_path(DataRoot.at(data_root).cas_dir, digest).parent
    make_readable_by_others(shard)
    shard_before = digest_tree(shard)
    other = same_shard_payload(PAYLOAD)

    outcomes = {
        "read": attempt(data_root, lambda cas: cas.read(digest))[0],
        "put of the same payload": attempt(data_root, lambda cas: cas.put(PAYLOAD))[0],
        "put of a new payload": attempt(data_root, lambda cas: cas.put(other))[0],
    }

    assert outcomes == dict.fromkeys(outcomes, ErrorCode.INSECURE_PERMISSIONS), outcomes
    assert digest_tree(shard) == shard_before


def test_an_existing_blob_that_others_can_read_is_refused_before_reuse(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    fresh_root(data_root)
    digest = store_payload(data_root, PAYLOAD)
    blob = blob_path(DataRoot.at(data_root).cas_dir, digest)
    make_readable_by_others(blob)

    outcomes = {
        "read": attempt(data_root, lambda cas: cas.read(digest))[0],
        "put of the same payload": attempt(data_root, lambda cas: cas.put(PAYLOAD))[0],
    }

    assert outcomes == dict.fromkeys(outcomes, ErrorCode.INSECURE_PERMISSIONS), outcomes


# --- valid shards keep working ----------------------------------------------------------------------------------


def test_valid_shards_and_deduplication_keep_working(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    fresh_root(data_root)
    other = same_shard_payload(PAYLOAD)
    first = store_payload(data_root, PAYLOAD, HOLDER)
    again = store_payload(data_root, PAYLOAD, OTHER_HOLDER)
    second = store_payload(data_root, other, HOLDER)
    shard = blob_path(DataRoot.at(data_root).cas_dir, first).parent

    assert first == again and first != second
    assert sorted(p.name for p in shard.iterdir()) == sorted({first[7:], second[7:]})
    assert attempt(data_root, lambda cas: cas.read(first)) == (None, PAYLOAD)
    assert attempt(data_root, lambda cas: cas.read(second)) == (None, other)
