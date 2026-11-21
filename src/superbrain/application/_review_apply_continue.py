"""Shared staging, forward execution, and continuation helpers for ``ApplyJournal`` (I3-3)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from superbrain.application._review_apply_ops import (
    ensure_parent_dirs,
    file_digest,
    mark_recovery_required_state,
    publish_no_replace,
    require_physical_fs,
    select_staging_dir,
    target_path,
    verified_move_to_backup,
    verify_active_grant,
    verify_backup_file,
    verify_target,
    with_journal_entry,
)
from superbrain.core._kernel_approval import RecoveryGrant, RecoveryScope
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedSliceManifest,
    ProposalStatus,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.proposals import ApplyAuthorityPort, ProposalStorePort

__all__ = [
    "build_proposal_manifests",
    "continue_apply_journal_impl",
    "execute_apply_entries",
    "stage_apply_journal",
]


def _invalid(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def _conflict(message: str = "revision conflict") -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, message)


def build_proposal_manifests(prop: ChangeProposal, updated_at: str) -> list[ManagedSliceManifest]:
    return [
        ManagedSliceManifest(
            proposal_id=prop.proposal_id,
            normalized_rel_path=t.normalized_rel_path,
            managed_format=t.managed_format,
            slice_id=t.slice_id,
            slice_digest=t.managed_slice_digest,
            full_file_digest=str(t.replacement_digest),
            updated_at=updated_at,
            target_root=t.target_root,
        )
        for t in prop.targets
        if t.managed_slice_digest is not None
    ]


def stage_apply_journal(
    proposals: ProposalStorePort,
    os_: OsAdapters,
    *,
    prop: ChangeProposal,
    journal_id: str,
    grant: RecoveryGrant,
    data_root: Path,
    now_utc: str,
    check_q25_fn: Callable[[Path, str], str] | None = None,
) -> ApplyJournal:
    """Create per-volume staging files, pin IDs, and persist initial ``APPLYING`` journal + proposal status."""
    staging_by_root: dict[str, Path] = {}
    for t in prop.targets:
        if t.target_root not in staging_by_root:
            staging_by_root[t.target_root] = select_staging_dir(
                Path(t.target_root), data_root, journal_id, prop.owner_id, os_
            )
    staging_dir = staging_by_root[prop.targets[0].target_root]
    phys = require_physical_fs(os_)
    entries: list[FileJournalEntry] = []
    for idx, t in enumerate(prop.targets):
        assert t.replacement_digest is not None
        if check_q25_fn is not None:
            check_q25_fn(Path(t.target_root), t.normalized_rel_path)
        p_id, _, p_existed = verify_target(
            Path(t.target_root), t.normalized_rel_path, os_, allow_missing_parent=True
        )
        if t.parent_physical_id and p_id.token() != t.parent_physical_id:
            raise BrainError(ErrorCode.UNSAFE_PATH, "target parent identity changed")
        rep_bytes = proposals.read_payload_bytes(t.replacement_digest)
        entry_staging = staging_by_root[t.target_root]
        staged = entry_staging / f"rep-{idx}"
        os_.paths.reject_links(staged)
        if not os.path.lexists(staged):
            os_.publisher.write_new(staged, rep_bytes)
        os_.permissions.secure_file(staged)
        staged_id = phys.stat_physical_identity(staged)
        if staged_id is None or staged_id.is_link or staged_id.is_dir or file_digest(staged) != t.replacement_digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "staged replacement verification failed")
        entries.append(
            FileJournalEntry(
                normalized_rel_path=t.normalized_rel_path,
                target_root=t.target_root,
                managed_format=t.managed_format,
                slice_id=t.slice_id,
                original=FileOriginalState.PRESENT if t.base_present else FileOriginalState.ABSENT,
                phase=FileJournalPhase.PLANNED,
                original_digest=t.base_digest,
                original_physical_id=t.base_physical_id,
                replacement_digest=t.replacement_digest,
                replacement_staging_path=str(staged),
                backup_path=None,
                replacement_physical_id=staged_id.token(),
                parent_physical_id=p_id.token() if p_existed else None,
            )
        )
    journal = ApplyJournal(
        journal_id=journal_id,
        proposal_id=prop.proposal_id,
        direction=JournalDirection.APPLY,
        status=ProposalStatus.APPLYING,
        grant_id=grant.grant_id,
        staging_dir=str(staging_dir),
        files=tuple(entries),
        created_at=now_utc,
        updated_at=now_utc,
    )
    saved = proposals.save_journal(journal)
    proposals.update_proposal_status(
        prop.proposal_id, ProposalStatus.APPLYING, active_journal_id=journal_id, updated_at=now_utc
    )
    return saved


def _save_partial(
    proposals: ProposalStorePort,
    journal: ApplyJournal,
    entries: list[FileJournalEntry],
    proposal_id: str,
    now_fn: Callable[[], str],
) -> ApplyJournal:
    now = now_fn()
    updated = ApplyJournal(
        journal_id=journal.journal_id,
        proposal_id=journal.proposal_id,
        direction=journal.direction,
        status=ProposalStatus.PARTIALLY_APPLIED,
        grant_id=journal.grant_id,
        staging_dir=journal.staging_dir,
        files=tuple(entries),
        created_at=journal.created_at,
        updated_at=now,
    )
    saved = proposals.update_journal(updated)
    proposals.update_proposal_status(
        proposal_id, ProposalStatus.PARTIALLY_APPLIED, active_journal_id=journal.journal_id, updated_at=now
    )
    return saved


def execute_apply_entries(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    prop: ChangeProposal,
    journal: ApplyJournal,
    grant: RecoveryGrant,
    check_q25_fn: Callable[[Path, str], str],
    now_fn: Callable[[], str],
    emit_crashpoints: bool,
    resume: bool,
) -> ApplyJournal:
    """Execute forward or resumed ``APPLY`` entries through policy-before-store closure."""
    if emit_crashpoints:
        crashpoint("apply.before_move_original")

    phys = require_physical_fs(os_)
    mut_entries = list(journal.files)
    for idx, entry in enumerate(mut_entries):
        try:
            verify_active_grant(authority, grant.grant_id)
            root = Path(entry.target_root)
            check_q25_fn(root, entry.normalized_rel_path)
            p_id, curr_id, p_existed = verify_target(root, entry.normalized_rel_path, os_, allow_missing_parent=True)
            if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                raise BrainError(ErrorCode.UNSAFE_PATH, "target parent identity changed")
        except BrainError:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
            raise

        tgt = target_path(root, entry.normalized_rel_path)
        entry_staging = Path(entry.replacement_staging_path).parent if entry.replacement_staging_path else Path(
            journal.staging_dir
        )
        bak = Path(entry.backup_path) if entry.backup_path is not None else (entry_staging / f"bak-{idx}")

        if resume:
            if entry.phase is FileJournalPhase.REPLACEMENT_PUBLISHED:
                if (
                    curr_id is None
                    or curr_id.is_link
                    or curr_id.is_dir
                    or (entry.replacement_physical_id is not None and curr_id.token() != entry.replacement_physical_id)
                    or file_digest(tgt) != entry.replacement_digest
                ):
                    mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                    mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                    raise _conflict()
                continue
            if (
                curr_id is not None
                and not curr_id.is_link
                and not curr_id.is_dir
                and entry.replacement_physical_id is not None
                and curr_id.token() == entry.replacement_physical_id
                and file_digest(tgt) == entry.replacement_digest
            ):
                bak_str: str | None = None
                if entry.original is FileOriginalState.PRESENT:
                    if not verify_backup_file(
                        bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
                    ):
                        mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                        mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                        raise _conflict()
                    bak_str = str(bak)
                mut_entries[idx] = with_journal_entry(
                    entry, phase=FileJournalPhase.REPLACEMENT_PUBLISHED, backup_path=bak_str
                )
                journal = _save_partial(proposals, journal, mut_entries, prop.proposal_id, now_fn)
                continue

        if entry.phase is FileJournalPhase.PLANNED and entry.original is FileOriginalState.PRESENT:
            if (
                resume
                and curr_id is None
                and verify_backup_file(
                    bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
                )
            ):
                mut_entries[idx] = with_journal_entry(
                    entry, phase=FileJournalPhase.ORIGINAL_MOVED, backup_path=str(bak)
                )
                entry = mut_entries[idx]
                journal = _save_partial(proposals, journal, mut_entries, prop.proposal_id, now_fn)
            else:
                if resume and (
                    curr_id is None
                    or curr_id.token() != entry.original_physical_id
                    or file_digest(tgt) != entry.original_digest
                ):
                    mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                    mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                    raise _conflict()
                ok, bak_kept = verified_move_to_backup(
                    os_,
                    tgt=tgt,
                    bak=bak,
                    expected_digest=entry.original_digest,
                    expected_physical_id=entry.original_physical_id,
                )
                if not ok:
                    mut_entries[idx] = with_journal_entry(
                        entry, phase=FileJournalPhase.CONFLICT, backup_path=bak_kept
                    )
                    mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                    if bak_kept is not None:
                        raise _conflict("backup verification failed")
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "backup verification failed")
                if emit_crashpoints:
                    crashpoint("apply.after_move_before_phase")
                mut_entries[idx] = with_journal_entry(
                    entry, phase=FileJournalPhase.ORIGINAL_MOVED, backup_path=str(bak)
                )
                entry = mut_entries[idx]
                journal = _save_partial(proposals, journal, mut_entries, prop.proposal_id, now_fn)
        elif entry.phase is FileJournalPhase.PLANNED:
            if curr_id is not None:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                raise _conflict()
        elif entry.phase is FileJournalPhase.ORIGINAL_MOVED:
            if curr_id is not None or not verify_backup_file(
                bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
            ):
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
                raise _conflict()
        else:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
            raise _conflict()

        ensure_parent_dirs(tgt.parent, root, os_)
        if entry.parent_physical_id is None:
            created_parent = phys.stat_physical_identity(tgt.parent)
            if created_parent is not None:
                entry = with_journal_entry(entry, parent_physical_id=created_parent.token())
                mut_entries[idx] = entry
        if emit_crashpoints:
            crashpoint("apply.before_publish_replacement")
        try:
            publish_no_replace(os_, Path(entry.replacement_staging_path), tgt)
        except FileExistsError as err:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
            raise _conflict() from err

        pub_id = phys.stat_physical_identity(tgt)
        if (
            pub_id is None
            or pub_id.is_link
            or pub_id.is_dir
            or (entry.replacement_physical_id is not None and pub_id.token() != entry.replacement_physical_id)
            or file_digest(tgt) != entry.replacement_digest
        ):
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "published target verification failed")
        if emit_crashpoints:
            crashpoint("apply.after_publish_before_phase")
        mut_entries[idx] = with_journal_entry(
            entry, phase=FileJournalPhase.REPLACEMENT_PUBLISHED, replacement_physical_id=pub_id.token()
        )
        journal = _save_partial(proposals, journal, mut_entries, prop.proposal_id, now_fn)

    done_at = now_fn()
    authority.end_recovery_grant(grant_id=grant.grant_id, reason="journal_closed", final_status="applied")
    if emit_crashpoints:
        crashpoint("apply.after_policy_grant_ended")
    manifests = build_proposal_manifests(prop, done_at)
    if manifests:
        proposals.save_manifests(manifests)
    final_journal = ApplyJournal(
        journal_id=journal.journal_id,
        proposal_id=journal.proposal_id,
        direction=journal.direction,
        status=ProposalStatus.APPLIED,
        grant_id=journal.grant_id,
        staging_dir=journal.staging_dir,
        files=tuple(mut_entries),
        created_at=journal.created_at,
        updated_at=done_at,
    )
    final_journal = proposals.update_journal(final_journal)
    proposals.update_proposal_status(
        prop.proposal_id, ProposalStatus.APPLIED, active_journal_id=None, updated_at=done_at
    )
    return final_journal


def continue_apply_journal_impl(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    journal_id: str,
    check_q25_fn: Callable[[Path, str], str],
    now_fn: Callable[[], str],
    emit_crashpoints: bool = False,
) -> ApplyJournal:
    """Resume an interrupted ``APPLY`` journal past nonce expiry; refuses ``ROLLBACK`` without mutating status."""
    journal = proposals.get_journal(journal_id)
    turn_intent = authority.turn_intent_for_journal(journal_id)
    if journal.direction is not JournalDirection.APPLY or (
        turn_intent is not None and turn_intent.direction is not JournalDirection.APPLY
    ):
        raise _invalid("cannot continue a rollback journal")
    if journal.status not in (ProposalStatus.APPLYING, ProposalStatus.PARTIALLY_APPLIED):
        raise _conflict()

    mut_entries = list(journal.files)
    try:
        grant = verify_active_grant(authority, journal.grant_id)
    except BrainError:
        mark_recovery_required_state(proposals, authority, journal, mut_entries, now_fn())
        raise
    if grant.recovery_scope not in (RecoveryScope.CONTINUE, RecoveryScope.CONTINUE_OR_ROLLBACK):
        raise _invalid("recovery_grant scope does not allow continue")

    prop = proposals.get_proposal(journal.proposal_id)
    return execute_apply_entries(
        proposals,
        authority,
        os_,
        prop=prop,
        journal=journal,
        grant=grant,
        check_q25_fn=check_q25_fn,
        now_fn=now_fn,
        emit_crashpoints=emit_crashpoints,
        resume=True,
    )
