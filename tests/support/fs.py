"""Filesystem test helpers."""

import hashlib
import os
import sys
from collections.abc import Iterable
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
    found: dict[str, str] = {}
    for directory, dirnames, filenames in os.walk(path):
        base = Path(directory)
        for name in dirnames:
            found[(base / name).relative_to(path).as_posix()] = "<dir>"
        for name in filenames:
            entry = base / name
            found[entry.relative_to(path).as_posix()] = hashlib.sha256(entry.read_bytes()).hexdigest()
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
