"""OS-facing ports."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
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


class DurabilityTier(StrEnum):
    POWER_LOSS = "power_loss_durable"
    PROCESS_CRASH = "process_crash_durable"


@dataclass(frozen=True)
class DurabilityReport:
    tier: DurabilityTier
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class FsInfo:
    fs_type: str
    remote: bool


class DurablePublisher(Protocol):
    def write_new(self, path: Path, data: bytes) -> None:
        """Create ``path`` exclusively, write all of ``data`` and make the content durable."""
        ...

    def publish(self, staging: Path, final: Path) -> None:
        """Atomically move ``staging`` to ``final`` (replacing it), then make the directory entry durable."""
        ...

    def rename_dir(self, src: Path, dst: Path) -> None:
        """Rename a directory; ``FileExistsError`` if ``dst`` exists; then make the parent durable."""
        ...

    def sync_directory(self, directory: Path) -> None:
        """Make the entries of ``directory`` durable (a no-op where the OS does that on rename)."""
        ...

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        """Report the tier ``directory`` can honestly claim, with reasons for anything below power-loss."""
        ...
