"""Filesystem test helpers."""

import hashlib
import os
import sys
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

import pytest


def fake_link(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Make ``Path.is_symlink`` return True for exactly ``path`` and defer to the original otherwise."""
    original = Path.is_symlink
    target = path.absolute()

    def is_symlink(self: Path) -> bool:
        if self.absolute() == target:
            return True
        return original(self)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)


def digest_tree(path: Path) -> dict[str, str]:
    """Relative POSIX path -> sha256 of the content (``"<dir>"`` for directories), without following links."""
    root_str = os.fspath(path)
    prefix_len = len(root_str) if root_str.endswith(("/", "\\")) else len(root_str) + 1
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root_str):
        rel_dir = dirpath[prefix_len:].replace("\\", "/")
        dir_prefix = f"{rel_dir}/" if rel_dir else ""
        for name in dirnames:
            found[f"{dir_prefix}{name}"] = "<dir>"
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            with open(full_path, "rb") as f:
                found[f"{dir_prefix}{name}"] = hashlib.sha256(f.read()).hexdigest()
    return found


def digest_data_root(path: Path) -> dict[str, str]:
    """``digest_tree`` of a tree holding a data root, except that ``writer.lock`` is digested from byte 1: on
    Windows the writer locks byte 0, and reading it through another handle fails while the lock is held."""
    root_str = os.fspath(path)
    prefix_len = len(root_str) if root_str.endswith(("/", "\\")) else len(root_str) + 1
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root_str):
        rel_dir = dirpath[prefix_len:].replace("\\", "/")
        dir_prefix = f"{rel_dir}/" if rel_dir else ""
        for name in dirnames:
            found[f"{dir_prefix}{name}"] = "<dir>"
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            with open(full_path, "rb") as f:
                if name == "writer.lock":
                    f.seek(1)
                found[f"{dir_prefix}{name}"] = hashlib.sha256(f.read()).hexdigest()
    return found


def file_identity(path: Path) -> tuple[int, int]:
    """``(st_dev, st_ino)`` of ``path``: equal identities mean the same file, not just equal content."""
    st = os.stat(path, follow_symlinks=False)
    return st.st_dev, st.st_ino


def read_all_bytes(paths: Iterable[Path]) -> bytes:
    """The concatenated content of ``paths``, in the given order."""
    return b"".join(Path(p).read_bytes() for p in paths)


def corrupt_bytes(path: Path, *, offsets: Iterable[int]) -> None:
    """Flip every bit of the byte at each offset of ``path`` (the file must already reach that offset)."""
    data = bytearray(path.read_bytes())
    for offset in offsets:
        data[offset] ^= 0xFF
    path.write_bytes(bytes(data))


def modes_tree(path: Path) -> dict[str, str]:
    """Relative POSIX path -> access description: the POSIX mode, or the owner and DACL as SDDL on Windows."""
    found: dict[str, str] = {}
    for entry in (path, *(Path(d) / n for d, ds, fs in os.walk(path) for n in (*ds, *fs))):
        rel = entry.relative_to(path).as_posix()
        if sys.platform == "win32":
            from tests.support.winacl import security_sddl

            found[rel] = security_sddl(entry)
        else:
            found[rel] = oct(os.lstat(entry).st_mode)
    return found


def db_files(path: Path) -> list[Path]:
    """``[db, db-wal, db-shm]``, only those that exist."""
    candidates = [path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")]
    return [p for p in candidates if p.exists()]


def set_mtime(path: Path, when: datetime) -> None:
    """Set the access and modification time of ``path`` to ``when`` (timezone-aware)."""
    stamp = when.timestamp()
    os.utime(path, (stamp, stamp))
