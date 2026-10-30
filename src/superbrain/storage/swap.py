"""Directory swaps for restore and migrate (spec 5.5, 5.7), and their recovery under the writer lease.

A swap replaces ``store/`` or ``policy/`` (the target) with a directory built beside it, by renaming only:

1. build the new content in ``<target>.<purpose>/`` (the stage), created fresh and owner-only;
2. write the ``READY`` marker and make it durable;
3. rename ``<target>/`` to ``<target>.replaced-<UTC>-<id>/``;
4. rename the stage to ``<target>/`` (its ``READY`` marker stays inside), then bump the writer epoch.

Nothing is deleted: the old directory is kept as ``*.replaced-*``, a stage that is not published is set aside as
``<target>.<purpose>.abandoned-<UTC>-<id>/``. ``writer.lock`` is never touched, and the lease is held throughout.

A crash leaves one of two states, which ``recover_interrupted_swaps`` resolves at the next start-up, under the lease
and before anything opens ``store*``/``policy*``: the target is gone and the stage is ``READY`` (the crash fell
between the renames), so the swap is completed; or the target is intact, so the stage is set aside.
"""

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.storage.layout import DataRoot
from superbrain.storage.prune import STAMP_FORMAT
from superbrain.storage.writer import WriterLease

Target = Literal["store", "policy"]
Purpose = Literal["restoring", "migrating"]
TARGETS: tuple[Target, ...] = ("store", "policy")
PURPOSES: tuple[Purpose, ...] = ("restoring", "migrating")
READY = "READY"
"""The marker file a stage gets once its content is complete and durable."""


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("a swap needs a held writer lease for this data root")


def _target_dir(root: DataRoot, target: Target) -> Path:
    return root.store_dir if target == "store" else root.policy_dir


def _stage_dir(root: DataRoot, target: Target, purpose: Purpose) -> Path:
    return root.root / f"{target}.{purpose}"


def _aside(path: Path, label: str, now: datetime) -> Path:
    """``<path>.<label>-<UTC yyyymmddThhmmssZ>-<new id>``, beside ``path``."""
    return path.with_name(f"{path.name}.{label}-{now.astimezone(UTC).strftime(STAMP_FORMAT)}-{new_id()}")


def _rename(src: Path, dst: Path, os_: OsAdapters) -> None:
    try:
        os_.publisher.rename_dir(src, dst)
    except FileExistsError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot rename {src.name}: {dst.name} already exists") from err


def _new_stage(stage: Path, os_: OsAdapters) -> None:
    try:
        stage.mkdir(mode=0o700)
    except FileExistsError as err:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE, f"{stage.name} already exists; recovery should have set it aside"
        ) from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot create {stage.name}: {err}") from err
    os_.permissions.secure_directory(stage)
    os_.publisher.sync_directory(stage.parent)


def _mark_ready(stage: Path, os_: OsAdapters) -> None:
    marker = stage / READY
    try:
        os_.publisher.write_new(marker, b"")
    except FileExistsError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the build wrote its own {READY} into {stage.name}") from err
    os_.permissions.secure_file(marker)
    os_.publisher.sync_directory(stage)


def stage_and_swap(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    *,
    target: Target,
    purpose: Purpose,
    build: Callable[[Path], None],
    now: datetime,
) -> Path:
    """Replace ``<target>/`` with the directory ``build`` fills, by renames only; returns the ``*.replaced-*`` path.

    An open ``target`` handle is ``STORE_BUSY`` and an existing stage ``INTEGRITY_FAILURE``, both before anything is
    created. If ``build`` (or writing ``READY``) fails, the stage is renamed to ``*.abandoned-*`` and the original
    error propagates, with a note if that rename fails too (recovery then sets the stage aside). The ``<UTC>`` in
    the new names comes from ``now``, which must be timezone-aware.
    """
    _check_lease(root, lease)
    if target not in TARGETS or purpose not in PURPOSES:
        raise BrainError(ErrorCode.INVALID_INPUT, f"unknown swap {target!r}/{purpose!r}")
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
    if target in lease.open_handles():
        raise BrainError(ErrorCode.STORE_BUSY, f"the {target} database is open; close it before replacing it")
    live, stage = _target_dir(root, target), _stage_dir(root, target, purpose)
    if not live.is_dir():
        raise BrainError(ErrorCode.NOT_FOUND, f"there is no {live.name} directory to replace")
    _new_stage(stage, os_)
    try:
        build(stage)
        _mark_ready(stage, os_)
    except BaseException as err:
        abandoned = _aside(stage, "abandoned", now)
        try:
            _rename(stage, abandoned, os_)
        except BrainError as cleanup:
            err.add_note(f"the failed stage {stage.name} could not be set aside as {abandoned.name}: {cleanup}")
        raise
    crashpoint(f"{purpose}.{target}.after_stage")
    replaced = _aside(live, "replaced", now)
    _rename(live, replaced, os_)
    crashpoint(f"{purpose}.{target}.between_renames")
    _rename(stage, live, os_)
    os_.publisher.sync_directory(root.root)
    lease.bump_epoch()
    return replaced


def _is_directory(path: Path) -> bool:
    return os.path.isdir(path) and not os.path.islink(path)


def recover_interrupted_swaps(root: DataRoot, lease: WriterLease, os_: OsAdapters) -> list[str]:
    """Resolve every swap a crash interrupted; returns what it did, one sentence per action. Never deletes anything.

    For each target, at most one stage may exist. Target gone and stage ``READY``: the stage is published (the
    second rename is redone). Target intact: the stage, ready or not, is set aside as ``*.abandoned-*``. Everything
    is checked before anything is renamed, and these are ``INTEGRITY_FAILURE`` with nothing touched: two stages for
    one target, a stage that is not a directory, and a missing target whose stage is not ``READY`` (the original
    was moved aside but the new content never completed; there is nothing safe to guess).
    """
    _check_lease(root, lease)
    plan: list[tuple[Target, Path, bool]] = []  # (target, stage, publish it)
    for target in TARGETS:
        stages = [_stage_dir(root, target, p) for p in PURPOSES if os.path.lexists(_stage_dir(root, target, p))]
        if not stages:
            continue
        if len(stages) > 1:
            names = ", ".join(s.name for s in stages)
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"two swaps of {target} were interrupted at once: {names}")
        (stage,) = stages
        if not _is_directory(stage):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{stage.name} is not a directory")
        if os.path.lexists(_target_dir(root, target)):
            plan.append((target, stage, False))
        elif os.path.isfile(stage / READY):
            plan.append((target, stage, True))
        else:
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE,
                f"{target}/ is missing and {stage.name} was never marked {READY}; restore {target} by hand from "
                f"the {target}.replaced-* directory or a backup",
            )
    actions: list[str] = []
    for target, stage, publish in plan:
        if publish:
            _rename(stage, _target_dir(root, target), os_)
            os_.publisher.sync_directory(root.root)
            actions.append(f"completed the interrupted swap: published {stage.name} as {target}/")
        else:
            abandoned = _aside(stage, "abandoned", os_.clock.now())
            _rename(stage, abandoned, os_)
            actions.append(f"set aside the unfinished {stage.name} as {abandoned.name}")
    return actions
