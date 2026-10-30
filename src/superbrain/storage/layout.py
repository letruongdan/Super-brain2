"""Data-root layout (spec 5.5, 5.9): checks and creation of the root, ``writer.lock`` and, under a lease, the
subdirectories.

``prepare_data_root`` touches nothing but ``root`` (and missing directories above it) and ``writer.lock``; every
``store*``/``policy*`` entry stays untouched until a ``WriterLease`` is held.
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters, PermissionProblem

if TYPE_CHECKING:
    from superbrain.storage.writer import WriterLease

LOCK_NAME = "writer.lock"
RESERVED_ENTRIES: tuple[str, ...] = (
    LOCK_NAME,
    "policy",
    "policy/policy.db",
    "policy/policy.db-wal",
    "policy/policy.db-shm",
    "store",
    "store/brain.db",
    "store/brain.db-wal",
    "store/brain.db-shm",
    "store/cas",
    "store/staging",
    "outbox",
    "logs",
    "backups",
)
# Restore/migrate staging and retired copies: store.restoring/, policy.replaced-<UTC>-<id>/, ...
_RESERVED_SIBLING_PREFIXES = ("store.", "policy.")


@dataclass(frozen=True)
class DataRoot:
    root: Path
    lock_path: Path
    policy_dir: Path
    store_dir: Path
    outbox_dir: Path
    logs_dir: Path
    backups_dir: Path

    @classmethod
    def at(cls, root: Path) -> "DataRoot":
        return cls(
            root=root,
            lock_path=root / LOCK_NAME,
            policy_dir=root / "policy",
            store_dir=root / "store",
            outbox_dir=root / "outbox",
            logs_dir=root / "logs",
            backups_dir=root / "backups",
        )

    @property
    def policy_db(self) -> Path:
        return self.policy_dir / "policy.db"

    @property
    def store_db(self) -> Path:
        return self.store_dir / "brain.db"

    @property
    def cas_dir(self) -> Path:
        return self.store_dir / "cas"

    @property
    def staging_dir(self) -> Path:
        return self.store_dir / "staging"

    def subdirectories(self) -> tuple[Path, ...]:
        """The directories ``secure_subdirectories`` creates, parents first."""
        return (
            self.policy_dir,
            self.store_dir,
            self.cas_dir,
            self.staging_dir,
            self.outbox_dir,
            self.logs_dir,
            self.backups_dir,
        )


def _existing_reserved_entries(root: Path) -> list[Path]:
    """Every reserved entry that exists (links included, never followed), plus existing ``store.*``/``policy.*``."""
    found = [root / rel for rel in RESERVED_ENTRIES if os.path.lexists(root / rel)]
    if os.path.isdir(root):
        try:
            names = os.listdir(root)
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot list data root {root}: {err}") from err
        found.extend(root / n for n in sorted(names) if os.path.normcase(n).startswith(_RESERVED_SIBLING_PREFIXES))
    return found


def _reject_links(root: Path, os_: OsAdapters) -> None:
    # The root and its ancestors first, so the entry listing never goes through a linked root.
    os_.paths.reject_links(root)
    os_.paths.reject_links(root, entries=_existing_reserved_entries(root))


def _insecure(problems: list[PermissionProblem], what: str) -> BrainError:
    detail = "; ".join(f"{p.path}: {p.reason}" for p in problems)
    return BrainError(ErrorCode.INSECURE_PERMISSIONS, f"{what}: {detail}")


def _make_directory(path: Path) -> bool:
    """Create ``path`` (its parent must exist); ``False`` if it already existed."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return False
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot create directory {path}: {err}") from err
    return True


def _create_lock_file(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot create lock file {path}: {err}") from err
    os.close(fd)


def prepare_data_root(root: Path, os_: OsAdapters) -> DataRoot:
    """Check ``root``, then create and secure it and ``writer.lock``. Nothing else is created or modified."""
    os_.paths.reject_unsafe_path(str(root))
    root = Path(os.path.abspath(root))
    _reject_links(root, os_)
    ancestor_problems = os_.permissions.check_ancestors(root)
    if ancestor_problems:
        raise _insecure(ancestor_problems, "an ancestor of the data root is not trusted")
    if os.path.lexists(root) and not root.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, f"data root {root} is not a directory")

    if sys.platform != "win32":
        os.umask(0o077)
    missing: list[Path] = []
    candidate = root
    while not os.path.lexists(candidate):
        missing.append(candidate)
        candidate = candidate.parent
    created = False
    for directory in reversed(missing):
        # One at a time, each secured at once: a new directory may inherit ACEs that check_ancestors skips.
        if _make_directory(directory):
            created = True
            os_.permissions.secure_directory(directory)
    os_.permissions.secure_directory(root)
    _create_lock_file(root / LOCK_NAME)
    os_.permissions.secure_file(root / LOCK_NAME)

    if created:
        problems = os_.permissions.check_ancestors(root) + os_.permissions.problems(root)
        if problems:
            raise _insecure(problems, "the new data root is not owner-only")
    return DataRoot.at(root)


def secure_subdirectories(root: DataRoot, lease: "WriterLease", os_: OsAdapters) -> None:
    """Under the writer lease: re-check links, then create and secure every subdirectory of the layout."""
    if not lease.held or lease.root != root:
        raise AssertionError("secure_subdirectories needs a held writer lease for this data root")
    _reject_links(root.root, os_)
    for directory in root.subdirectories():
        _make_directory(directory)
        os_.permissions.secure_directory(directory)
