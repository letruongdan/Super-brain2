"""I3-2 oracle: physical object identity, link/reparse guards, no-replace publish, and staging selection.

Requirement sources: spec rev 22 §11.2 (lines 1055-1089), §20 cases 94, 95, 105, 106; ledger §2.2, §4;
plan I3-2 Step 1 & shared contracts (``PhysicalObjectId``, ``publish_no_replace``, same-volume staging).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import durable, os_adapters
from superbrain.adapters.os.durable import MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, publisher_for
from superbrain.adapters.os.physical_fs import (
    OsPhysicalFs,
    select_apply_staging_dir,
    stat_physical_identity,
    verify_physical_target,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters, PhysicalFsPort, PhysicalObjectId
from tests.support.platform import posix_only, windows_only


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_physical_identity_missing_file_dir_and_same_path_replacement(trusted_tmp: Path) -> None:
    missing = trusted_tmp / "does-not-exist.txt"
    assert stat_physical_identity(missing) is None

    dir_path = trusted_tmp / "subdir"
    dir_path.mkdir()
    dir_id = stat_physical_identity(dir_path)
    assert isinstance(dir_id, PhysicalObjectId)
    assert dir_id.is_dir is True and dir_id.is_link is False and dir_id.token()

    file_a = trusted_tmp / "config.md"
    file_b = trusted_tmp / "replacement.md"
    file_a.write_bytes(b"identical-bytes\n")
    id_a = stat_physical_identity(file_a)
    assert id_a is not None and id_a.is_dir is False and id_a.is_link is False

    # Create file_b BEFORE unlinking file_a so the OS cannot reuse file_a's inode / file_id.
    file_b.write_bytes(b"identical-bytes\n")
    id_b = stat_physical_identity(file_b)
    assert id_b is not None and id_b.token() != id_a.token()

    file_a.unlink()
    os.replace(file_b, file_a)
    id_after = stat_physical_identity(file_a)
    assert id_after is not None
    assert id_after.token() == id_b.token()
    assert id_after.token() != id_a.token(), "same-path replacement with identical bytes must change PhysicalObjectId"


def test_physical_identity_does_not_follow_links_and_rejects_surrogate_ancestor(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    checkout = trusted_tmp / "checkout"
    real_sub = checkout / "real-sub"
    surrogate_sub = trusted_tmp / "surrogate-outside"
    checkout.mkdir()
    real_sub.mkdir()
    surrogate_sub.mkdir()

    real_file = real_sub / "CLAUDE.md"
    surrogate_file = surrogate_sub / "CLAUDE.md"
    real_file.write_bytes(b"# Same content\n")
    surrogate_file.write_bytes(b"# Same content\n")

    parent_id, target_id = verify_physical_target(checkout, "real-sub/CLAUDE.md", os_)
    assert parent_id.is_dir is True and parent_id.is_link is False
    assert target_id is not None and target_id.is_dir is False and target_id.is_link is False

    # Case 94: replace subdir with a link/junction to an outside directory containing identical bytes.
    linked_sub = checkout / "linked-sub"
    _make_dir_link(linked_sub, surrogate_sub)
    link_stat = stat_physical_identity(linked_sub)
    assert link_stat is not None and link_stat.is_link is True

    with pytest.raises(BrainError) as link_exc:
        verify_physical_target(checkout, "linked-sub/CLAUDE.md", os_)
    assert link_exc.value.code is ErrorCode.UNSAFE_PATH

    # Also test a missing file inside a linked/junctioned parent directory (case 94 absent target).
    with pytest.raises(BrainError) as absent_link_exc:
        verify_physical_target(checkout, "linked-sub/new-file.md", os_)
    assert absent_link_exc.value.code is ErrorCode.UNSAFE_PATH


def test_verify_physical_target_rejects_unc_device_ads_and_escape(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    checkout = trusted_tmp / "checkout"
    checkout.mkdir()

    bad_rels = (
        "../outside.txt",
        "sub/../../outside.txt",
        "notes.txt:stream",
        "\\\\server\\share\\x",
        "\\\\?\\C:\\x",
    )
    for bad_rel in bad_rels:
        with pytest.raises(BrainError) as exc:
            verify_physical_target(checkout, bad_rel, os_)
        assert exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}, bad_rel

    if sys.platform == "win32":
        for bad_root in (Path(r"\\server\share\checkout"), Path(r"\\?\C:\checkout")):
            with pytest.raises(BrainError) as root_exc:
                verify_physical_target(bad_root, "CLAUDE.md", os_)
            assert root_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}


def test_publish_no_replace_preserves_physical_id_and_refuses_late_target(trusted_tmp: Path) -> None:
    pub = publisher_for(sys.platform)
    staging = trusted_tmp / "staged-config"
    final = trusted_tmp / "CLAUDE.md"
    staging.write_bytes(b"brain replacement\n")
    staged_id = stat_physical_identity(staging)
    assert staged_id is not None

    pub.publish_no_replace(staging, final)
    assert not staging.exists()
    assert final.read_bytes() == b"brain replacement\n"
    final_id = stat_physical_identity(final)
    assert final_id is not None and final_id.token() == staged_id.token()

    # Case 95: late user file appearing at final MUST NOT be overwritten.
    late_staging = trusted_tmp / "late-staged"
    late_staging.write_bytes(b"do not clobber\n")
    user_existing = trusted_tmp / "user-created.md"
    user_existing.write_bytes(b"precious user file\n")
    user_id = stat_physical_identity(user_existing)

    with pytest.raises(FileExistsError):
        pub.publish_no_replace(late_staging, user_existing)

    assert user_existing.read_bytes() == b"precious user file\n"
    assert stat_physical_identity(user_existing) == user_id
    assert late_staging.read_bytes() == b"do not clobber\n"


@windows_only
def test_windows_publish_no_replace_uses_write_through_without_replace_existing(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pub = publisher_for("win32")
    flags_seen: list[int] = []
    orig_move = durable._move_file_ex

    def _spy_move(src: str, dst: str, flags: int) -> None:
        flags_seen.append(flags)
        orig_move(src, dst, flags)

    monkeypatch.setattr(durable, "_move_file_ex", _spy_move)
    staging = trusted_tmp / "win-staged"
    final = trusted_tmp / "win-final"
    staging.write_bytes(b"hello win\n")
    pub.publish_no_replace(staging, final)

    assert flags_seen == [MOVEFILE_WRITE_THROUGH]
    assert not (flags_seen[0] & MOVEFILE_REPLACE_EXISTING)


@posix_only
def test_posix_publish_no_replace_hardlink_fallback_preserves_late_target(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pub = publisher_for(sys.platform)
    # Force fallback path if renameat2/renamex_np helper raises ENOSYS/AttributeError.
    if hasattr(durable, "_rename_noreplace"):
        monkeypatch.setattr(
            durable,
            "_rename_noreplace",
            lambda _s, _d: (_ for _ in ()).throw(OSError(95, "not supported")),
        )
    staging = trusted_tmp / "posix-staged"
    final = trusted_tmp / "posix-final"
    staging.write_bytes(b"hello posix\n")
    staged_id = stat_physical_identity(staging)
    pub.publish_no_replace(staging, final)
    assert stat_physical_identity(final) == staged_id

    late = trusted_tmp / "posix-late"
    late.write_bytes(b"late\n")
    with pytest.raises(FileExistsError):
        pub.publish_no_replace(late, final)
    assert final.read_bytes() == b"hello posix\n" and late.exists()


class _CrossVolumePhysicalFs:
    """Delegates stat_physical_identity to real OsPhysicalFs while simulating a distinct volume for cross-volume."""

    def __init__(self, real: PhysicalFsPort, checkout_root: Path) -> None:
        self._real = real
        self._checkout_root = checkout_root

    def stat_physical_identity(self, path: Path) -> PhysicalObjectId | None:
        return self._real.stat_physical_identity(path)

    def same_volume(self, first: Path, second: Path) -> bool:
        a, b = first.resolve(), second.resolve()
        if (a == self._checkout_root.resolve() or self._checkout_root.resolve() in a.parents) ^ (
            b == self._checkout_root.resolve() or self._checkout_root.resolve() in b.parents
        ):
            return False
        return self._real.same_volume(first, second)


def test_select_apply_staging_dir_same_and_cross_volume_keeps_git_clean(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    data_root = trusted_tmp / "data"
    data_root.mkdir()
    os_.permissions.secure_directory(data_root)

    parent = trusted_tmp / "repos"
    parent.mkdir()
    os_.permissions.secure_directory(parent)
    checkout = parent / "checkout-a"
    checkout.mkdir()
    if shutil.which("git") is not None:
        subprocess.run(["git", "-C", str(checkout), "init", "-q"], check=True, timeout=20)
        (checkout / "README.md").write_text("clean\n", encoding="utf-8", newline="\n")
        subprocess.run(["git", "-C", str(checkout), "add", "README.md"], check=True, timeout=20)
        subprocess.run(
            ["git", "-C", str(checkout), "-c", "user.name=t", "-c", "user.email=t@e.com", "commit", "-qm", "init"],
            check=True,
            timeout=20,
        )

    git_dir = checkout / ".git"
    try:
        jid = new_id()
        same_dir = select_apply_staging_dir(checkout, data_root, jid, "dan", os_)
        assert same_dir == data_root / "apply_staging" / jid
        assert same_dir.is_dir() and os_.permissions.object_problems(same_dir) == []

        # Cross-volume puts staging outside checkout working tree under owner-hashed sibling dir.
        real_phys: PhysicalFsPort = OsPhysicalFs()
        cross_os = OsAdapters(
            paths=os_.paths,
            permissions=os_.permissions,
            publisher=os_.publisher,
            locks=os_.locks,
            clock=os_.clock,
            traits=os_.traits,
            monotonic=os_.monotonic,
            physical=_CrossVolumePhysicalFs(real_phys, checkout),
        )
        cross_dir = select_apply_staging_dir(checkout, data_root, jid, "dan", cross_os)
        owner_tag = hashlib.sha256(b"dan").hexdigest()
        assert cross_dir.parent.parent == parent
        assert cross_dir.parent.name.startswith(".ensemble-brain-apply-")
        assert owner_tag[:8] in cross_dir.parent.name
        assert cross_dir.name == jid
        assert not cross_dir.is_relative_to(checkout)
        assert os_.permissions.check_ancestors(cross_dir) == []
        assert os_.permissions.object_problems(cross_dir) == []

        if shutil.which("git") is not None:
            status = subprocess.check_output(
                ["git", "-C", str(checkout), "status", "--porcelain"], text=True, timeout=20
            )
            assert status == "", f"cross-volume staging dirtied git worktree: {status!r}"
    finally:
        if git_dir.exists():
            for root_dir, dirnames, filenames in os.walk(git_dir):
                for name in (*dirnames, *filenames):
                    p = Path(root_dir) / name
                    os.chmod(p, p.stat().st_mode | stat.S_IWRITE)

    # Symlinked/junctioned checkout parent must be refused BEFORE creating staging.
    real_parent = trusted_tmp / "real-parent"
    real_parent.mkdir()
    sym_parent = trusted_tmp / "sym-parent"
    _make_dir_link(sym_parent, real_parent)
    sym_checkout = sym_parent / "checkout-b"
    sym_checkout.mkdir()
    with pytest.raises(BrainError) as bad_exc:
        select_apply_staging_dir(sym_checkout, data_root, new_id(), "dan", cross_os)
    assert bad_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INSECURE_PERMISSIONS}
