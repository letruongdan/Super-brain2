"""Interrupted-turn rollback pre-verification and recovery execution for ``ReviewApplyService`` (I3-2, I3-3)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from superbrain.application._review_apply_ops import (
    file_digest,
    mark_recovery_required_state,
    publish_no_replace,
    require_physical_fs,
    target_path,
    verified_move_to_backup,
    verify_active_grant,
    verify_backup_file,
    verify_target,
    with_journal_entry,
)
from superbrain.core._kernel_approval import RecoveryScope
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.proposals import (
    ApplyJournal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ProposalStatus,
)
from superbrain.ports.os import OsAdapters, PhysicalFsPort
from superbrain.ports.proposals import ApplyAuthorityPort, ProposalStorePort

__all__ = ["execute_interrupted_rollback"]


def _invalid(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def _conflict(message: str = "revision conflict") -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, message)


def _save_rolling_back(
    proposals: ProposalStorePort, journal: ApplyJournal, entries: list[FileJournalEntry], now: str
) -> ApplyJournal:
    return proposals.update_journal(
        ApplyJournal(
            journal_id=journal.journal_id,
            proposal_id=journal.proposal_id,
            direction=journal.direction,
            status=ProposalStatus.ROLLING_BACK,
            grant_id=journal.grant_id,
            staging_dir=journal.staging_dir,
            files=tuple(entries),
            created_at=journal.created_at,
            updated_at=now,
        )
    )


def _plan_interrupted_entry(
    entry: FileJournalEntry, idx: int, journal_staging_dir: str, os_: OsAdapters, phys: PhysicalFsPort
) -> tuple[str, Path | None]:
    if entry.phase in (FileJournalPhase.RESTORED, FileJournalPhase.DELETED):
        return "done", None
    root = Path(entry.target_root)
    tgt = target_path(root, entry.normalized_rel_path)
    p_id, curr_id, p_existed = verify_target(root, entry.normalized_rel_path, os_, allow_missing_parent=True)
    if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
        raise _conflict("target parent identity changed")

    entry_staging = (
        Path(entry.replacement_staging_path).parent
        if entry.replacement_staging_path
        else Path(journal_staging_dir)
    )
    bak_path = Path(entry.backup_path) if entry.backup_path is not None else (entry_staging / f"bak-{idx}")
    hold_path = entry_staging / f"rb-hold-{idx}"

    if entry.phase is FileJournalPhase.PLANNED:
        if entry.original is FileOriginalState.PRESENT:
            if curr_id is not None:
                if (
                    curr_id.token() != entry.original_physical_id
                    or file_digest(tgt) != entry.original_digest
                    or phys.stat_physical_identity(bak_path) is not None
                ):
                    raise _conflict()
                return "noop_restored", None
            if verify_backup_file(
                bak_path, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
            ):
                return "restore_bak", bak_path
            raise _conflict()
        if curr_id is None:
            return "noop_deleted", None
        if curr_id.token() == entry.replacement_physical_id and file_digest(tgt) == entry.replacement_digest:
            return "hold_only", None
        raise _conflict()

    if entry.phase is FileJournalPhase.ORIGINAL_MOVED:
        if entry.original is not FileOriginalState.PRESENT or entry.backup_path is None:
            raise _conflict()
        if (
            curr_id is not None
            and not curr_id.is_link
            and not curr_id.is_dir
            and entry.original_physical_id is not None
            and curr_id.token() == entry.original_physical_id
            and file_digest(tgt) == entry.original_digest
            and phys.stat_physical_identity(bak_path) is None
        ):
            return "noop_restored", None
        if not verify_backup_file(
            bak_path, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
        ):
            raise _conflict()
        if curr_id is None:
            return "restore_bak", bak_path
        if curr_id.token() == entry.replacement_physical_id and file_digest(tgt) == entry.replacement_digest:
            return "hold_then_restore", bak_path
        raise _conflict()

    if entry.phase is FileJournalPhase.REPLACEMENT_PUBLISHED:
        if curr_id is None and verify_backup_file(
            hold_path,
            os_,
            expected_digest=entry.replacement_digest,
            expected_physical_id=entry.replacement_physical_id,
        ):
            if entry.original is FileOriginalState.PRESENT:
                if entry.backup_path is None or not verify_backup_file(
                    bak_path,
                    os_,
                    expected_digest=entry.original_digest,
                    expected_physical_id=entry.original_physical_id,
                ):
                    raise _conflict()
                return "restore_bak", bak_path
            return "noop_deleted", None
        if (
            entry.original is FileOriginalState.PRESENT
            and curr_id is not None
            and not curr_id.is_link
            and not curr_id.is_dir
            and entry.original_physical_id is not None
            and curr_id.token() == entry.original_physical_id
            and file_digest(tgt) == entry.original_digest
            and phys.stat_physical_identity(bak_path) is None
            and verify_backup_file(
                hold_path,
                os_,
                expected_digest=entry.replacement_digest,
                expected_physical_id=entry.replacement_physical_id,
            )
        ):
            return "noop_restored", None
        if (
            curr_id is None
            or curr_id.token() != entry.replacement_physical_id
            or file_digest(tgt) != entry.replacement_digest
        ):
            raise _conflict()
        if entry.original is FileOriginalState.PRESENT:
            if entry.backup_path is None or not verify_backup_file(
                bak_path, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
            ):
                raise _conflict()
            return "hold_then_restore", bak_path
        return "hold_only", None

    raise _conflict()


def execute_interrupted_rollback(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    now_utc: str,
    done_utc_fn: Callable[[], str],
    journal_id: str,
    check_q25_fn: Callable[[Path, str], str] | None = None,
    emit_crashpoints: bool = False,
    allow_rollback_journal: bool = False,
) -> ApplyJournal:
    """Verify every required backup before touching file 1, then roll back interrupted apply in reverse order."""
    journal = proposals.get_journal(journal_id)
    allowed_dirs = (
        (JournalDirection.APPLY, JournalDirection.ROLLBACK)
        if allow_rollback_journal
        else (JournalDirection.APPLY,)
    )
    if journal.direction not in allowed_dirs or journal.status not in (
        ProposalStatus.APPLYING,
        ProposalStatus.PARTIALLY_APPLIED,
        ProposalStatus.ROLLING_BACK,
    ):
        raise _conflict()
    mut_entries = list(journal.files)
    try:
        grant = verify_active_grant(authority, journal.grant_id)
    except BrainError:
        mark_recovery_required_state(proposals, authority, journal, mut_entries, now_utc)
        raise
    if grant.recovery_scope not in (RecoveryScope.ROLLBACK, RecoveryScope.CONTINUE_OR_ROLLBACK):
        raise _invalid("recovery_grant scope does not allow rollback")

    phys = require_physical_fs(os_)
    planned_actions: list[tuple[str, Path | None]] = []
    for idx, entry in enumerate(mut_entries):
        try:
            if check_q25_fn is not None:
                check_q25_fn(Path(entry.target_root), entry.normalized_rel_path)
            planned_actions.append(_plan_interrupted_entry(entry, idx, journal.staging_dir, os_, phys))
        except BrainError:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, now_utc)
            raise

    authority.open_turn_intent(
        journal_id=journal.journal_id, approval_id=grant.approval_id, direction=JournalDirection.ROLLBACK
    )
    if emit_crashpoints:
        crashpoint("rollback.before_first_move")

    for idx in range(len(mut_entries) - 1, -1, -1):
        entry = mut_entries[idx]
        action, bak_path = planned_actions[idx]
        if action == "done":
            continue
        root = Path(entry.target_root)
        tgt = target_path(root, entry.normalized_rel_path)
        entry_staging = (
            Path(entry.replacement_staging_path).parent
            if entry.replacement_staging_path
            else Path(journal.staging_dir)
        )
        try:
            verify_active_grant(authority, grant.grant_id)
            if check_q25_fn is not None:
                check_q25_fn(root, entry.normalized_rel_path)
            p_id, _, p_existed = verify_target(root, entry.normalized_rel_path, os_, allow_missing_parent=True)
            if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                raise _conflict("target parent identity changed")
        except BrainError:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
            raise

        if action in ("hold_then_restore", "hold_only"):
            holding = entry_staging / f"rb-hold-{idx}"
            ok, _ = verified_move_to_backup(
                os_,
                tgt=tgt,
                bak=holding,
                expected_digest=entry.replacement_digest,
                expected_physical_id=entry.replacement_physical_id,
            )
            if not ok:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                raise _conflict()
            if emit_crashpoints:
                crashpoint("rollback.after_move_replacement")

        if action in ("restore_bak", "hold_then_restore"):
            assert bak_path is not None
            try:
                publish_no_replace(os_, bak_path, tgt)
            except FileExistsError as err:
                mut_entries[idx] = with_journal_entry(
                    entry, phase=FileJournalPhase.CONFLICT, backup_path=str(bak_path)
                )
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                raise _conflict() from err
            restored_id = phys.stat_physical_identity(tgt)
            if (
                restored_id is None
                or restored_id.is_link
                or restored_id.is_dir
                or (entry.original_physical_id is not None and restored_id.token() != entry.original_physical_id)
                or file_digest(tgt) != entry.original_digest
            ):
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "restored target verification failed")
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.RESTORED)
        elif action == "noop_restored":
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.RESTORED)
        else:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.DELETED)
        journal = _save_rolling_back(proposals, journal, mut_entries, done_utc_fn())

    if emit_crashpoints:
        crashpoint("rollback.after_restore_last_original")
    done_at = done_utc_fn()
    authority.end_recovery_grant(grant_id=grant.grant_id, reason="journal_closed", final_status="rolled_back")
    final_j = ApplyJournal(
        journal_id=journal.journal_id,
        proposal_id=journal.proposal_id,
        direction=journal.direction,
        status=ProposalStatus.ROLLED_BACK,
        grant_id=journal.grant_id,
        staging_dir=journal.staging_dir,
        files=tuple(mut_entries),
        created_at=journal.created_at,
        updated_at=done_at,
    )
    final_j = proposals.update_journal(final_j)
    proposals.update_proposal_status(
        journal.proposal_id, ProposalStatus.ROLLED_BACK, active_journal_id=None, updated_at=done_at
    )
    return final_j
