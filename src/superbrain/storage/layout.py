"""Data-root layout (spec 5.5, 5.9): checks and creation of the root, ``writer.lock`` and, under a lease, the
subdirectories.

``prepare_data_root`` creates and secures nothing but a missing ``root`` (and missing directories above it) and a
missing ``writer.lock``; existing entries are only checked. Every ``store*``/``policy*`` entry stays untouched until
a ``WriterLease`` is held.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters, PermissionProblem
from superbrain.storage.errors import os_error

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
        raise os_error(f"cannot create directory {path}", err) from err
    return True


def _create_lock_file(path: Path) -> bool:
    """Create ``path`` exclusively; ``False`` if it already existed."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    except OSError as err:
        raise os_error(f"cannot create lock file {path}", err) from err
    os.close(fd)
    return True


def _create_directory(directory: Path, os_: OsAdapters) -> bool:
    """Create, secure and durably record ``directory``; ``False`` (and untouched) if it already existed."""
    if not _make_directory(directory):
        return False
    os_.permissions.secure_directory(directory)
    os_.publisher.sync_directory(directory.parent)
    return True


def _require_owner_only(path: Path, os_: OsAdapters) -> None:
    # Existing entries are checked, never re-secured: securing an existing directory on Windows pushes the new
    # DACL into every child, which would touch store*/policy* entries.
    problems = os_.permissions.object_problems(path)
    if problems:
        raise _insecure(problems, f"existing {path} is not owner-only")


def prepare_data_root(root: Path, os_: OsAdapters) -> DataRoot:
    """Check ``root``, then create and secure it and ``writer.lock`` if missing. Nothing else is modified."""
    os_.paths.reject_unsafe_path(str(root))
    root = Path(os.path.abspath(root))
    lock = root / LOCK_NAME
    _reject_links(root, os_)
    ancestor_problems = os_.permissions.check_ancestors(root)
    if ancestor_problems:
        raise _insecure(ancestor_problems, "an ancestor of the data root is not trusted")
    root_existed = os.path.lexists(root)
    if root_existed and not root.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, f"data root {root} is not a directory")
    if root_existed:
        _require_owner_only(root, os_)
    lock_existed = os.path.lexists(lock)
    if lock_existed:
        _require_owner_only(lock, os_)

    if os_.traits.restrict_umask:
        os.umask(0o077)
    missing: list[Path] = []
    for candidate in (root, *root.parents):
        if os.path.lexists(candidate):
            break
        missing.append(candidate)
    else:
        raise BrainError(ErrorCode.IO_ERROR, f"no existing directory ancestor is available for {root}")
    # One at a time, each secured at once: a new directory may inherit ACEs that check_ancestors skips.
    created = [directory for directory in reversed(missing) if _create_directory(directory, os_)]
    if not root_existed and root not in created:  # created concurrently by another process
        _require_owner_only(root, os_)
    if _create_lock_file(lock):
        os_.permissions.secure_file(lock)
        os_.publisher.sync_directory(root)
    elif not lock_existed:
        _require_owner_only(lock, os_)

    if created:
        problems = os_.permissions.check_ancestors(root)
        if root in created:
            problems += os_.permissions.problems(root)
        if problems:
            raise _insecure(problems, "the new data root is not owner-only")
    return DataRoot.at(root)


def verify_existing_data_root(root: Path, os_: OsAdapters) -> DataRoot:
    """Check an already-initialized ``root`` and ``writer.lock`` without creating or modifying any file or directory."""
    os_.paths.reject_unsafe_path(str(root))
    if not root.is_absolute():
        raise BrainError(ErrorCode.UNSAFE_PATH, f"data root {root} must be an absolute path")
    root = Path(os.path.abspath(root))
    _reject_links(root, os_)
    ancestor_problems = os_.permissions.check_ancestors(root)
    if ancestor_problems:
        raise _insecure(ancestor_problems, "an ancestor of the data root is not trusted")
    if not os.path.lexists(root):
        raise BrainError(ErrorCode.NOT_FOUND, f"data root {root} does not exist")
    if not root.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, f"data root {root} is not a directory")
    _require_owner_only(root, os_)
    lock = root / LOCK_NAME
    if not os.path.lexists(lock):
        raise BrainError(ErrorCode.NOT_FOUND, f"writer lock {lock} does not exist")
    if not lock.is_file():
        raise BrainError(ErrorCode.INVALID_INPUT, f"writer lock {lock} is not a regular file")
    for entry in _existing_reserved_entries(root):
        _require_owner_only(entry, os_)
    return DataRoot.at(root)


def secure_subdirectories(root: DataRoot, lease: "WriterLease", os_: OsAdapters) -> None:
    """Under the writer lease: re-check links and existing subdirectories, then create and secure missing ones."""
    if not lease.held or lease.root != root:
        raise AssertionError("secure_subdirectories needs a held writer lease for this data root")
    _reject_links(root.root, os_)
    directories = root.subdirectories()
    existing = [directory for directory in directories if os.path.lexists(directory)]
    for directory in existing:
        _require_owner_only(directory, os_)
    for directory in directories:
        if directory not in existing and not _create_directory(directory, os_):
            _require_owner_only(directory, os_)
