"""Port-only physical path checks, staging selection, and no-replace file ops for ``ReviewApplyService``."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from superbrain.core._kernel_approval import RecoveryGrant
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import (
    ApplyJournal,
    FileJournalEntry,
    FileJournalPhase,
    ProposalStatus,
    normalize_proposal_rel_path,
    validate_journal_id,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters, PhysicalFsPort, PhysicalObjectId
from superbrain.ports.proposals import ApplyAuthorityPort, ProposalStorePort

__all__ = [
    "ensure_parent_dirs",
    "file_digest",
    "mark_recovery_required_state",
    "publish_no_replace",
    "read_utf8_text",
    "require_physical_fs",
    "select_staging_dir",
    "target_path",
    "verified_move_to_backup",
    "verify_active_grant",
    "verify_backup_file",
    "verify_target",
    "with_journal_entry",
]


def target_path(root: Path, norm_rel: str) -> Path:
    return root.joinpath(*norm_rel.split("/"))


def require_physical_fs(os_: OsAdapters) -> PhysicalFsPort:
    if os_.physical is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "physical fs adapter unavailable")
    return os_.physical


def reject_path_spelling(raw: str, os_: OsAdapters) -> None:
    if not raw or "\x00" in raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if raw.startswith(("\\\\", "//")):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
    if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    os_.paths.reject_unsafe_path(raw)


def file_digest(path: Path) -> str:
    try:
        return digest_bytes(path.read_bytes())
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {err}") from err


def verify_target(
    root: Path,
    rel_path: str,
    os_: OsAdapters,
    *,
    allow_missing_parent: bool = False,
) -> tuple[PhysicalObjectId, PhysicalObjectId | None, bool]:
    """Verify target & ancestor safety and return ``(parent_or_ancestor_id, target_id_or_None, parent_existed)``."""
    reject_path_spelling(str(root), os_)
    norm_rel = normalize_proposal_rel_path(rel_path)
    tgt = target_path(root, norm_rel)
    os_.paths.reject_links(tgt)
    if os_.permissions.check_ancestors(tgt):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    phys = require_physical_fs(os_)
    parent_id = phys.stat_physical_identity(tgt.parent)
    parent_existed = parent_id is not None
    if parent_id is None:
        if not allow_missing_parent:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        anc = tgt.parent.parent
        while anc != anc.parent and phys.stat_physical_identity(anc) is None:
            anc = anc.parent
        parent_id = phys.stat_physical_identity(anc)
        if parent_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if parent_id.is_link:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not parent_id.is_dir:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    tgt_id = phys.stat_physical_identity(tgt)
    if tgt_id is not None:
        if tgt_id.is_link:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        if tgt_id.is_dir:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return parent_id, tgt_id, parent_existed


def _ensure_trusted_dir(path: Path, os_: OsAdapters) -> None:
    os_.paths.reject_links(path)
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except (FileExistsError, NotADirectoryError) as err:
        raise BrainError(ErrorCode.INVALID_INPUT, f"staging path is not a directory: {path}") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot create staging dir {path}: {err}") from err
    os_.paths.reject_links(path)
    if not path.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.permissions.secure_directory(path)
    if os_.permissions.check_ancestors(path) or os_.permissions.object_problems(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


def ensure_parent_dirs(directory: Path, root: Path, os_: OsAdapters) -> None:
    """Create missing relative subdirectories under ``root`` safely without following links."""
    os_.paths.reject_links(directory)
    missing: list[Path] = []
    cur = directory
    phys = require_physical_fs(os_)
    while phys.stat_physical_identity(cur) is None and cur != root and cur != cur.parent:
        missing.append(cur)
        cur = cur.parent
    for sub in reversed(missing):
        _ensure_trusted_dir(sub, os_)
    os_.paths.reject_links(directory)


def select_staging_dir(
    target_root: Path, data_root: Path, journal_id: str, owner_id: str, os_: OsAdapters
) -> Path:
    """Validate target/data_root ancestors and select/create same- or cross-volume staging dir."""
    reject_path_spelling(str(target_root), os_)
    reject_path_spelling(str(data_root), os_)
    if not target_root.is_absolute() or not data_root.is_absolute():
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    validate_journal_id(journal_id)
    os_.paths.reject_links(target_root, entries=[target_root.parent])
    os_.paths.reject_links(data_root)
    if os_.permissions.check_ancestors(target_root) or os_.permissions.check_ancestors(data_root):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    phys = require_physical_fs(os_)
    if phys.same_volume(target_root, data_root):
        if os_.permissions.object_problems(data_root):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        base = data_root / "apply_staging"
    else:
        tag = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()[:12]
        base = target_root.parent / f".ensemble-brain-apply-{tag}"
    _ensure_trusted_dir(base, os_)
    staging = base / journal_id
    _ensure_trusted_dir(staging, os_)
    return staging


def publish_no_replace(os_: OsAdapters, staging: Path, final: Path) -> None:
    pub = cast(NoReplacePublisher, os_.publisher)
    if not hasattr(pub, "publish_no_replace"):
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "no-replace publisher unavailable")
    pub.publish_no_replace(staging, final)


def read_utf8_text(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {err}") from err
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err


_UNSET: object = object()


def with_journal_entry(
    entry: FileJournalEntry,
    *,
    phase: FileJournalPhase | None = None,
    backup_path: str | None | object = _UNSET,
    replacement_physical_id: str | None | object = _UNSET,
    parent_physical_id: str | None | object = _UNSET,
) -> FileJournalEntry:
    new_bak = entry.backup_path if backup_path is _UNSET else backup_path
    new_rep_id = (
        entry.replacement_physical_id if replacement_physical_id is _UNSET else replacement_physical_id
    )
    new_par_id = entry.parent_physical_id if parent_physical_id is _UNSET else parent_physical_id
    return FileJournalEntry(
        normalized_rel_path=entry.normalized_rel_path,
        target_root=entry.target_root,
        managed_format=entry.managed_format,
        slice_id=entry.slice_id,
        original=entry.original,
        phase=entry.phase if phase is None else phase,
        original_digest=entry.original_digest,
        original_physical_id=entry.original_physical_id,
        replacement_digest=entry.replacement_digest,
        replacement_staging_path=entry.replacement_staging_path,
        backup_path=new_bak if isinstance(new_bak, str) or new_bak is None else entry.backup_path,
        replacement_physical_id=(
            new_rep_id if isinstance(new_rep_id, str) or new_rep_id is None else entry.replacement_physical_id
        ),
        parent_physical_id=(
            new_par_id if isinstance(new_par_id, str) or new_par_id is None else entry.parent_physical_id
        ),
    )


def mark_recovery_required_state(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort | None,
    journal: ApplyJournal,
    entries: list[FileJournalEntry],
    now: str,
) -> None:
    if authority is not None:
        try:
            g = authority.recovery_grant(journal.grant_id)
            if g.state == "active":
                authority.end_recovery_grant(
                    grant_id=journal.grant_id, reason="recovery_required", final_status="recovery_required"
                )
        except BrainError:
            pass
    updated = ApplyJournal(
        journal_id=journal.journal_id,
        proposal_id=journal.proposal_id,
        direction=journal.direction,
        status=ProposalStatus.RECOVERY_REQUIRED,
        grant_id=journal.grant_id,
        staging_dir=journal.staging_dir,
        files=tuple(entries),
        created_at=journal.created_at,
        updated_at=now,
    )
    proposals.update_journal(updated)
    proposals.update_proposal_status(
        journal.proposal_id, ProposalStatus.RECOVERY_REQUIRED, active_journal_id=journal.journal_id, updated_at=now
    )


def verify_active_grant(authority: ApplyAuthorityPort, grant_id: str) -> RecoveryGrant:
    grant = authority.recovery_grant(grant_id)
    if grant.state != "active" or grant.trust_generation != authority.trust_generation():
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    return grant


def verify_backup_file(
    bak_path: Path,
    os_: OsAdapters,
    *,
    expected_digest: str | None,
    expected_physical_id: str | None,
) -> bool:
    phys = require_physical_fs(os_)
    try:
        os_.paths.reject_links(bak_path)
    except BrainError:
        return False
    bak_id = phys.stat_physical_identity(bak_path)
    if bak_id is None or bak_id.is_link or bak_id.is_dir:
        return False
    if expected_physical_id is not None and bak_id.token() != expected_physical_id:
        return False
    try:
        return file_digest(bak_path) == expected_digest
    except BrainError:
        return False


def verified_move_to_backup(
    os_: OsAdapters,
    *,
    tgt: Path,
    bak: Path,
    expected_digest: str | None,
    expected_physical_id: str | None,
) -> tuple[bool, str | None]:
    """Move ``tgt -> bak`` and verify `(no-link, PhysicalObjectId, digest)`.

    On mismatch, attempts ``publish_no_replace(bak, tgt)``; if target is occupied, preserves ``bak`` and returns
    ``(False, str(bak))``.
    """
    os_.publisher.publish(tgt, bak)
    if verify_backup_file(
        bak, os_, expected_digest=expected_digest, expected_physical_id=expected_physical_id
    ):
        return True, str(bak)
    try:
        publish_no_replace(os_, bak, tgt)
        return False, None
    except FileExistsError:
        return False, str(bak)
