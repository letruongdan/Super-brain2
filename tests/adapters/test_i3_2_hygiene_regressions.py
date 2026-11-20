"""I3-2 Round-2 RED regressions for I3-2-R02, I3-2-R03, and I3-2-R04.

Covers Windows NTFS trailing dots/spaces & reserved device Q25 bypasses, relative root Q25 bypass,
staging traversal/link-before-mkdir/non-0700 parent handling, atomic handle stat, TOML sibling/1-seg
comment preservation, Markdown delimiter injection, and clean CRLF removal.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block, remove_markdown_block
from superbrain.adapters.harness_config.toml_tables import remove_toml_table
from superbrain.adapters.os import os_adapters, physical_fs
from superbrain.adapters.os.physical_fs import select_apply_staging_dir, stat_physical_identity
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.proposals import assert_not_skill_or_internal_target, normalize_proposal_rel_path
from superbrain.ports.os import OsAdapters, PermissionGuard, PermissionProblem
from tests.support.platform import windows_only


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


class _NonOwnerParentPermissions:
    """Delegates permissions while marking a real repo parent dir as non-0700 (e.g. 0755/Admin ACE)."""

    def __init__(self, inner: PermissionGuard, shared_parent: Path) -> None:
        self._inner = inner
        self._shared_parent = shared_parent.resolve()

    def secure_directory(self, path: Path) -> None:
        self._inner.secure_directory(path)

    def secure_file(self, path: Path) -> None:
        self._inner.secure_file(path)

    def problems(self, data_root: Path) -> list[PermissionProblem]:
        return self._inner.problems(data_root)

    def object_problems(self, path: Path) -> list[PermissionProblem]:
        if path.resolve() == self._shared_parent:
            return [PermissionProblem(path=path, reason="ACE grants access to S-1-5-32-544")]
        return self._inner.object_problems(path)

    def check_ancestors(self, path: Path) -> list[PermissionProblem]:
        return self._inner.check_ancestors(path)


def test_r02_q25_ntfs_trailing_dot_space_reserved_devices_and_relative_root(trusted_tmp: Path) -> None:
    """I3-2-R02: NTFS trailing dot/space, reserved Win32 devices, and relative roots MUST be rejected."""
    checkout = trusted_tmp / "repo"
    data_root = trusted_tmp / "data"
    home_dir = trusted_tmp / "home"
    checkout.mkdir()

    ntfs_skill_bypasses = (
        ".claude/skills./x/SKILL.md",
        ".claude/skills /x/SKILL.md",
        ".claude./skills/x/SKILL.md",
        ".codex/skills./a/SKILL.md",
        ".agents/skills ./a/SKILL.md",
        ".git./hooks/pre-commit",
        "trailing-dot.",
        "sub/trailing-space ",
        " leading-space/x.md",
    )
    for rel in ntfs_skill_bypasses:
        with pytest.raises(BrainError) as exc:
            assert_not_skill_or_internal_target(str(checkout), rel, data_root=str(data_root), home_dir=str(home_dir))
        assert exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}, rel

    for dev_rel in ("NUL.md", "COM1", "LPT9.txt", "sub/aux.json", "nested/con", "PRN"):
        with pytest.raises(BrainError) as dev_exc:
            normalize_proposal_rel_path(dev_rel)
        assert dev_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}, dev_rel

    # Relative target_root MUST be refused instead of mismatching absolute data_anchor / home_anchor.
    with pytest.raises(BrainError) as rel_root_exc:
        assert_not_skill_or_internal_target(
            "data", "policy/policy.db", data_root=str(data_root), home_dir=str(home_dir)
        )
    assert rel_root_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}

    # Trailing-dot root suffix inside target_root itself must not slip past Q25 matching.
    bad_root = checkout / ".claude" / "skills."
    with pytest.raises(BrainError) as root_dot_exc:
        assert_not_skill_or_internal_target(
            str(bad_root), "SKILL.md", data_root=str(data_root), home_dir=str(home_dir)
        )
    assert root_dot_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}


def test_r03_staging_rejects_dotdot_journal_id_preexisting_file_and_allows_non0700_parent(trusted_tmp: Path) -> None:
    """I3-2-R03: staging validates journal_id, checks links before mkdir, and accepts normal repo parents."""
    os_ = os_adapters()
    data_root = trusted_tmp / "data"
    data_root.mkdir()
    os_.permissions.secure_directory(data_root)

    shared_parent = trusted_tmp / "workspace-parent"
    shared_parent.mkdir()
    os_.permissions.secure_directory(shared_parent)
    checkout = shared_parent / "repo-a"
    checkout.mkdir()

    for bad_jid in ("..", ".", "a/b", "a\\b", "id:ads", "", "abc.", "lead space"):
        with pytest.raises(BrainError) as jid_exc:
            select_apply_staging_dir(checkout, data_root, bad_jid, "dan", os_)
        assert jid_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH}, bad_jid

    # Pre-existing regular file at base or staging path MUST raise BrainError, never raw FileExistsError.
    blocker_data = trusted_tmp / "data-blocker"
    blocker_data.mkdir()
    os_.permissions.secure_directory(blocker_data)
    (blocker_data / "apply_staging").write_bytes(b"not a directory\n")
    with pytest.raises(BrainError) as file_exc:
        select_apply_staging_dir(checkout, blocker_data, new_id(), "dan", os_)
    assert file_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH, ErrorCode.IO_ERROR}

    # Pre-existing junction/symlink at staging leaf must be rejected BEFORE mkdir touches target.
    outside_dir = trusted_tmp / "outside-target"
    outside_dir.mkdir()
    link_data = trusted_tmp / "data-link"
    link_data.mkdir()
    os_.permissions.secure_directory(link_data)
    (link_data / "apply_staging").mkdir()
    os_.permissions.secure_directory(link_data / "apply_staging")
    bad_link_id = new_id()
    _make_dir_link(link_data / "apply_staging" / bad_link_id, outside_dir)
    with pytest.raises(BrainError) as sym_exc:
        select_apply_staging_dir(checkout, link_data, bad_link_id, "dan", os_)
    assert sym_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INSECURE_PERMISSIONS}

    # Real repo parent failing object_problems(parent) (e.g. 0755 / Admin ACE) while check_ancestors == []
    # MUST succeed for same-volume AND cross-volume staging, while base & staging are still 0700/owner-only.
    perm_os = OsAdapters(
        paths=os_.paths,
        permissions=_NonOwnerParentPermissions(os_.permissions, shared_parent),
        publisher=os_.publisher,
        locks=os_.locks,
        clock=os_.clock,
        traits=os_.traits,
        monotonic=os_.monotonic,
        physical=os_.physical,
    )
    same_stage = select_apply_staging_dir(checkout, data_root, new_id(), "dan", perm_os)
    assert same_stage.is_dir() and os_.permissions.object_problems(same_stage) == []

    class _FakeCross:
        def stat_physical_identity(self, path: Path) -> Any:
            assert os_.physical is not None
            return os_.physical.stat_physical_identity(path)

        def same_volume(self, first: Path, second: Path) -> bool:
            return False

    cross_perm_os = OsAdapters(
        paths=perm_os.paths,
        permissions=perm_os.permissions,
        publisher=perm_os.publisher,
        locks=perm_os.locks,
        clock=perm_os.clock,
        traits=perm_os.traits,
        monotonic=perm_os.monotonic,
        physical=_FakeCross(),
    )
    cross_stage = select_apply_staging_dir(checkout, data_root, new_id(), "dan", cross_perm_os)
    assert cross_stage.is_dir()
    assert os_.permissions.object_problems(cross_stage.parent) == []
    assert os_.permissions.object_problems(cross_stage) == []


@windows_only
def test_r03_win_stat_physical_reads_link_attrs_from_opened_handle(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R03: _win_stat_physical must read is_link/is_dir from the opened kernel handle, not prior lstat."""
    outside = trusted_tmp / "outside-junc"
    outside.mkdir()
    probe = trusted_tmp / "probe"
    probe.write_bytes(b"regular file before CreateFileW\n")

    assert sys.platform == "win32"
    real_create = vars(physical_fs)["_CREATE_FILE_W"]
    assert callable(real_create)
    swapped = [False]

    def _toctou_create(path_str: str, *rest: Any) -> Any:
        if not swapped[0] and os.path.normcase(path_str) == os.path.normcase(str(probe)):
            swapped[0] = True
            probe.unlink()
            _make_dir_link(probe, outside)
        return real_create(path_str, *rest)

    monkeypatch.setattr(physical_fs, "_CREATE_FILE_W", _toctou_create)
    ident = stat_physical_identity(probe)
    assert swapped[0] is True
    assert ident is not None
    assert ident.is_link is True and ident.is_dir is True


def test_r04_toml_removal_preserves_trailing_comments_with_siblings_and_single_segment() -> None:
    """I3-2-R04: remove_toml_table must preserve trailing user comments in ALL structural layouts."""
    sibling_toml = (
        "[mcp_servers.github]\n"
        'command = "gh"\n\n'
        "[mcp_servers.super-brain]\n"
        'command = "brain-mcp"\n\n'
        "# KEEP THIS USER COMMENT\n"
        "[profiles.deep]\n"
        'mode = "strict"\n'
    )
    out_sib = remove_toml_table(
        sibling_toml, table_path=("mcp_servers", "super-brain"), expected_slice_digest=None
    )
    assert "# KEEP THIS USER COMMENT" in out_sib.updated_text
    assert "super-brain" not in out_sib.updated_text
    parsed_sib: dict[str, Any] = tomlkit.parse(out_sib.updated_text).unwrap()
    assert parsed_sib["mcp_servers"]["github"]["command"] == "gh"
    assert parsed_sib["profiles"]["deep"]["mode"] == "strict"

    single_seg_toml = (
        "[super-brain]\n"
        'command = "brain-mcp"\n\n'
        "# KEEP SINGLE TOP COMMENT\n"
        "[other]\n"
        "x = 1\n"
    )
    out_top = remove_toml_table(single_seg_toml, table_path=("super-brain",), expected_slice_digest=None)
    assert "# KEEP SINGLE TOP COMMENT" in out_top.updated_text
    assert "super-brain" not in out_top.updated_text
    parsed_top: dict[str, Any] = tomlkit.parse(out_top.updated_text).unwrap()
    assert parsed_top["other"]["x"] == 1


def test_r04_markdown_rejects_delimiter_injection_and_clean_crlf_removal() -> None:
    """I3-2-R04: reject embedded delimiter injection in block_body and strip CRLF cleanly on removal."""
    for bad_body in (
        "safe\n<!-- ensemble-brain:end:s1 -->\ninjected",
        "<!-- ensemble-brain:begin:s1 -->",
        "text <!-- ensemble-brain:begin:other -->",
    ):
        with pytest.raises(BrainError) as inj_exc:
            merge_markdown_block("# Title\n", slice_id="s1", block_body=bad_body, expected_slice_digest=None)
        assert inj_exc.value.code is ErrorCode.INVALID_INPUT

    crlf_doc = (
        "# Header\r\n\r\n"
        "<!-- ensemble-brain:begin:s1 -->\r\nRule\r\n<!-- ensemble-brain:end:s1 -->\r\n\r\n"
        "# Footer\r\n"
    )
    removed = remove_markdown_block(crlf_doc, slice_id="s1", expected_slice_digest=None)
    assert removed.changed is True
    assert "# Header" in removed.updated_text and "# Footer" in removed.updated_text
    assert "\r\n\n" not in removed.updated_text
    assert "\n\n\r\n" not in removed.updated_text
    for idx, ch in enumerate(removed.updated_text):
        if ch == "\r":
            assert idx + 1 < len(removed.updated_text) and removed.updated_text[idx + 1] == "\n"
