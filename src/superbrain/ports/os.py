"""OS-facing ports."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from superbrain.ports.clock import Clock


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

    def object_problems(self, path: Path) -> list[PermissionProblem]:
        """Like ``problems``, for ``path`` itself only (never its children)."""
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

    def flush_file(self, path: Path) -> None:
        """Make the content of the existing file ``path``, which nothing else is writing, durable."""
        ...

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        """Report the tier ``directory`` can honestly claim, with reasons for anything below power-loss."""
        ...


class LockHandle(Protocol):
    """An exclusive inter-process lock on a lock file, plus its payload (the bytes after the lock region)."""

    def read_payload(self) -> bytes:
        """The whole payload; payload offset 0 is the first byte after the lock region (empty for a new file)."""
        ...

    def write_payload(self, offset: int, data: bytes) -> None:
        """Write ``data`` at payload ``offset`` and make it durable before returning."""
        ...

    def release(self) -> None:
        """Unlock and close; never deletes the lock file. Idempotent."""
        ...


class LockFactory(Protocol):
    def acquire(self, path: Path) -> LockHandle:
        """Lock the existing file ``path`` without waiting; ``BrainError(WRITER_HELD)`` if another holder has it."""
        ...


@dataclass(frozen=True)
class PlatformTraits:
    sqlite_full_fsync: bool
    restrict_umask: bool
    default_scratch_base: Path | Callable[[], Path | None] | None = None
    resolve_temp_links: bool = False
    temp_dir: Path | Callable[[], Path] | None = None

    def resolved_default_scratch_base(self) -> Path | None:
        """Evaluate ``default_scratch_base`` when callable, or return it directly."""
        value = self.default_scratch_base
        if value is None or isinstance(value, Path):
            return value
        return value()

    def resolved_temp_dir(self) -> Path | None:
        """Evaluate ``temp_dir`` when callable, or return it directly."""
        value = self.temp_dir
        if value is None or isinstance(value, Path):
            return value
        return value()


@dataclass(frozen=True)
class OsAdapters:
    paths: PathSafety
    permissions: PermissionGuard
    publisher: DurablePublisher
    locks: LockFactory
    clock: Clock
    traits: PlatformTraits
