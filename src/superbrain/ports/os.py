"""OS-facing ports."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class PathSafety(Protocol):
    def reject_unsafe_path(self, raw: str) -> None:
        """Raise ``BrainError(UNSAFE_PATH)`` for path spellings that bypass normal path rules."""
        ...

    def reject_links(self, path: Path, *, entries: Sequence[Path] = ()) -> None:
        """Raise ``BrainError(UNSAFE_PATH)`` if ``path``, an existing ancestor or an existing entry is a link."""
        ...


@dataclass(frozen=True)
class PermissionProblem:
    path: Path
    reason: str


class PermissionGuard(Protocol):
    def secure_directory(self, path: Path) -> None:
        """Make ``path`` accessible to the current user (and SYSTEM on Windows) only."""
        ...

    def secure_file(self, path: Path) -> None:
        """Make the file ``path`` accessible to the current user (and SYSTEM on Windows) only."""
        ...

    def problems(self, root: Path) -> list[PermissionProblem]:
        """Recursively report entries under ``root`` (including ``root``) that others can access."""
        ...

    def check_ancestors(self, path: Path) -> list[PermissionProblem]:
        """Report ancestors of ``path`` where another account could rename, delete or replace entries."""
        ...
