"""Backup directory names and pruning (spec 5.6).

A backup lives in ``backups/<kind>-<UTC yyyymmddThhmmssZ>-<id>/`` and is complete once it has ``manifest.json``
(``superbrain.storage.backup`` creates them). This module owns that naming, which pruning parses: ages and order come
from the name, never from mtime.
"""

import os
import re
import shutil
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.storage.errors import os_error

if TYPE_CHECKING:
    from superbrain.storage.writer import WriterLease

MANIFEST_NAME = "manifest.json"
INCOMPLETE_SUFFIX = ".incomplete"
DELETING_SUFFIX = ".deleting-"
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_DIR_NAME = re.compile(
    r"(store|store_full|policy)-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_INCOMPLETE_AFTER = timedelta(hours=24)


def backup_dir_name(kind: str, now: datetime) -> str:
    """``<kind>-<UTC yyyymmddThhmmssZ>-<new id>``; ``now`` must be timezone-aware."""
    return f"{kind}-{now.astimezone(UTC).strftime(STAMP_FORMAT)}-{new_id()}"


def _rename(os_: OsAdapters, path: Path, target: Path) -> None:
    try:
        os_.publisher.rename_dir(path, target)
    except FileExistsError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot rename {path}: {target.name} exists") from err


def has_complete_backup(backups_dir: Path, kinds: Collection[str]) -> bool:
    """Whether ``backups_dir`` (which may not exist) holds a complete backup (one with a manifest) of one of
    ``kinds``."""
    try:
        names = sorted(os.listdir(backups_dir))
    except FileNotFoundError:
        return False
    except OSError as err:
        raise os_error(f"cannot list {backups_dir}", err) from err
    for name in names:
        match = _DIR_NAME.fullmatch(name)
        path = backups_dir / name
        if match and match.group(1) in kinds and not path.is_symlink() and (path / MANIFEST_NAME).is_file():
            return True
    return False


def prune_backups(
    backups_dir: Path, *, lease: "WriterLease", os_: OsAdapters, keep: int = 7, now: datetime
) -> list[Path]:
    """Keep the ``keep`` newest complete backups of each kind and delete the rest; returns what it changed, sorted.

    It deletes, so it runs only under ``lease``, held for the data root whose ``backups/`` is ``backups_dir``.

    Complete means the directory has a ``manifest.json``; age and order come from the timestamp in the name, never
    from mtime. A backup to delete is first renamed to ``<name>.deleting-<id>`` and only then removed, so a failed
    removal never leaves a directory that looks complete; ``.deleting-*`` entries are never counted. An incomplete
    backup older than 24 hours is renamed to ``<name>.incomplete`` (its new path is returned), never deleted.
    Entries whose names are not backup names are left alone.
    """
    if not lease.held or lease.root.backups_dir != backups_dir:
        raise AssertionError("pruning backups needs the held writer lease of their data root")
    if type(keep) is not int or keep < 1:
        raise BrainError(ErrorCode.INVALID_INPUT, "keep must be an integer >= 1")
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
    try:
        names = sorted(os.listdir(backups_dir))
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot list {backups_dir}: {err}") from err
    complete: dict[str, list[tuple[datetime, str]]] = {}
    changed: list[Path] = []
    for name in names:
        match = _DIR_NAME.fullmatch(name)  # ``.incomplete`` and ``.deleting-*`` names never match
        path = backups_dir / name
        if match is None or path.is_symlink() or not path.is_dir():
            continue
        try:
            created = datetime.strptime(match.group(2), STAMP_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            continue  # not a real date, so not a backup name
        if (path / MANIFEST_NAME).is_file():
            complete.setdefault(match.group(1), []).append((created, name))
        elif created < now - _INCOMPLETE_AFTER:
            target = path.with_name(name + INCOMPLETE_SUFFIX)
            _rename(os_, path, target)
            changed.append(target)
    for found in complete.values():
        for _, name in sorted(found, reverse=True)[keep:]:
            doomed = backups_dir / f"{name}{DELETING_SUFFIX}{new_id()}"
            _rename(os_, backups_dir / name, doomed)
            try:
                shutil.rmtree(doomed)
            except OSError as err:
                raise BrainError(ErrorCode.IO_ERROR, f"cannot delete the old backup {doomed.name}: {err}") from err
            os_.publisher.sync_directory(backups_dir)
            changed.append(backups_dir / name)
    return sorted(changed)
