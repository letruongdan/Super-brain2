import subprocess
from collections.abc import Mapping
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

import pytest

from superbrain.adapters.os.paths import OsPathSafety, default_data_root
from superbrain.core.errors import BrainError, ErrorCode
from tests.support.fs import fake_link
from tests.support.platform import windows_only


@pytest.mark.parametrize(
    "platform,env,expected",
    [
        (
            "win32",
            {"LOCALAPPDATA": r"C:\Users\Lê Trung\AppData\Local"},
            PureWindowsPath(r"C:\Users\Lê Trung\AppData\Local\ensemble-brain"),
        ),
        ("darwin", {"HOME": "/Users/u"}, PurePosixPath("/Users/u/Library/Application Support/ensemble-brain")),
        ("linux", {"HOME": "/home/u"}, PurePosixPath("/home/u/.local/share/ensemble-brain")),
        ("linux", {"HOME": "/home/u", "XDG_DATA_HOME": "/data"}, PurePosixPath("/data/ensemble-brain")),
        ("linux", {"SUPERBRAIN_HOME": "/srv/brain"}, PurePosixPath("/srv/brain")),
    ],
)
def test_default_data_root(platform: str, env: Mapping[str, str], expected: PurePath) -> None:
    assert default_data_root(env, platform) == expected


def test_linked_root_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ported from test_runtime_refuses_linked_root_before_resolving_alias
    root = tmp_path / "runtime"
    root.mkdir()
    fake_link(monkeypatch, root)
    with pytest.raises(BrainError) as e:
        OsPathSafety().reject_links(root)
    assert e.value.code == ErrorCode.UNSAFE_PATH


def test_linked_ancestor_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parent = tmp_path / "alias"
    child = parent / "runtime"
    child.mkdir(parents=True)
    fake_link(monkeypatch, parent)
    with pytest.raises(BrainError) as e:
        OsPathSafety().reject_links(child)
    assert e.value.code == ErrorCode.UNSAFE_PATH


def test_linked_entry_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "runtime"
    (root / "store").mkdir(parents=True)
    fake_link(monkeypatch, root / "store")
    with pytest.raises(BrainError) as e:
        OsPathSafety().reject_links(root, entries=[root / "store"])
    assert e.value.code == ErrorCode.UNSAFE_PATH


def test_missing_entry_is_ignored(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    OsPathSafety().reject_links(root, entries=[root / "absent.db"])


@windows_only
def test_real_junction_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "root"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    with pytest.raises(BrainError) as e:
        OsPathSafety().reject_links(link)
    assert e.value.code == ErrorCode.UNSAFE_PATH


@pytest.mark.parametrize("raw", [r"\\?\C:\x", r"\\.\pipe\x", r"\\server\share\x", r"C:\x\file.db:stream"])
@windows_only
def test_reject_unsafe_windows_path(raw: str) -> None:
    with pytest.raises(BrainError) as e:
        OsPathSafety().reject_unsafe_path(raw)
    assert e.value.code == ErrorCode.UNSAFE_PATH


@windows_only
def test_plain_windows_path_is_accepted() -> None:
    OsPathSafety().reject_unsafe_path(r"C:\Users\Lê Trung\data")


def test_vietnamese_and_space_path_is_accepted(tmp_path: Path) -> None:
    root = tmp_path / "thư mục có dấu" / "Lê Trung"
    root.mkdir(parents=True)
    OsPathSafety().reject_links(root)
