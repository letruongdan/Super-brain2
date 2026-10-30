"""Filesystem test helpers."""

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
