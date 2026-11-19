"""Rollback planning and applied rollback execution for ``ReviewApplyService`` (I3-2, I3-3)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from superbrain.application._review_apply_ops import (
    file_digest,
    mark_recovery_required_state,
    publish_no_replace,
    read_utf8_text,
    require_physical_fs,
    select_staging_dir,
    target_path,
    verified_move_to_backup,
    verify_active_grant,
    verify_backup_file,
    verify_target,
    with_journal_entry,
)
from superbrain.application._review_apply_rollback_int import execute_interrupted_rollback
from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryGrant,
    RecoveryScope,
    TargetFile,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ProposalStatus,
)
from superbrain.ports.os import OsAdapters, PhysicalFsPort
from superbrain.ports.proposals import (
    ApplyAuthorityPort,
    ConfigMergerPort,
    ProposalStorePort,
    RollbackPlan,
    RollbackPlanTarget,
)

__all__ = [
    "execute_applied_rollback",
    "execute_interrupted_rollback",
    "plan_rollback_targets_impl",
    "run_applied_rollback_entries",
    "stage_applied_rollback_journal",
]


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


def plan_rollback_targets_impl(
    proposals: ProposalStorePort,
    os_: OsAdapters,
    config_merger: ConfigMergerPort | None,
    proposal_id: str,
    *,
    check_q25_fn: Callable[[Path, str], str] | None = None,
) -> RollbackPlan:
    prop = proposals.get_proposal(proposal_id)
    if prop.status is not ProposalStatus.APPLIED:
        raise _conflict()
    applied_j = proposals.find_latest_apply_journal(proposal_id)
    all_manifests = proposals.list_manifests(proposal_id)
    manifests = {(m.target_root, m.normalized_rel_path, m.managed_format, m.slice_id): m for m in all_manifests}
    legacy_manifests = {
        (m.normalized_rel_path, m.managed_format, m.slice_id): m for m in all_manifests if not m.target_root
    }

    plan_targets: list[RollbackPlanTarget] = []
    target_files: list[TargetFile] = []
    res_digests: list[ResourceDigest] = []
    for idx, entry in enumerate(applied_j.files):
        root = Path(entry.target_root)
        if check_q25_fn is not None:
            check_q25_fn(root, entry.normalized_rel_path)
        parent_id, curr_id, _ = verify_target(root, entry.normalized_rel_path, os_)
        if entry.parent_physical_id is not None and parent_id.token() != entry.parent_physical_id:
            raise BrainError(ErrorCode.UNSAFE_PATH, "target parent identity changed")
        tgt = target_path(root, entry.normalized_rel_path)
        if curr_id is None or curr_id.is_link or curr_id.is_dir:
            raise _conflict()
        curr_digest = file_digest(tgt)

        if curr_digest == entry.replacement_digest and curr_id.token() == entry.replacement_physical_id:
            if entry.original is FileOriginalState.PRESENT:
                assert entry.original_digest is not None
                rep_bytes: bytes | None = proposals.read_payload_bytes(entry.original_digest)
                rep_digest: str | None = entry.original_digest
            else:
                rep_bytes = None
                rep_digest = None
        else:
            if entry.managed_format is ManagedFormat.RAW or config_merger is None:
                raise _conflict()
            manifest = manifests.get(
                (entry.target_root, entry.normalized_rel_path, entry.managed_format, entry.slice_id)
            ) or legacy_manifests.get((entry.normalized_rel_path, entry.managed_format, entry.slice_id))
            if manifest is None:
                raise _conflict("missing managed slice manifest")
            curr_text = read_utf8_text(tgt)
            removed = config_merger.remove_slice(
                curr_text,
                managed_format=entry.managed_format,
                slice_id=entry.slice_id,
                expected_slice_digest=manifest.slice_digest,
            )
            rep_bytes = removed.updated_text.encode("utf-8")
            rep_digest = digest_bytes(rep_bytes)

        plan_targets.append(
            RollbackPlanTarget(
                normalized_rel_path=entry.normalized_rel_path,
                target_root=entry.target_root,
                managed_format=entry.managed_format,
                slice_id=entry.slice_id,
                base_present=True,
                base_digest=curr_digest,
                base_physical_id=curr_id.token(),
                replacement_bytes=rep_bytes,
                replacement_digest=rep_digest,
            )
        )
        target_files.append(
            TargetFile(
                root_path=entry.target_root,
                normalized_rel_path=entry.normalized_rel_path,
                parent_physical_id=parent_id.token(),
                target_physical_id=curr_id.token(),
                original_digest=curr_digest,
                original_present=True,
            )
        )
        res_digests.append(ResourceDigest(f"rollback:{idx}", rep_digest or curr_digest))

    return RollbackPlan(
        proposal_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=tuple(res_digests),
        targets=tuple(plan_targets),
        target_files=tuple(target_files),
    )


def stage_applied_rollback_journal(
    proposals: ProposalStorePort,
    os_: OsAdapters,
    *,
    prop: ChangeProposal,
    plan: RollbackPlan,
    journal_id: str,
    grant: RecoveryGrant,
    data_root: Path,
    now_utc: str,
    check_q25_fn: Callable[[Path, str], str] | None = None,
) -> ApplyJournal:
    """Stage ``rb-rep-*`` files per volume, pin IDs, and save ``ROLLING_BACK`` journal + proposal."""
    phys = require_physical_fs(os_)
    staging_by_root: dict[str, Path] = {}
    for pt in plan.targets:
        if pt.target_root not in staging_by_root:
            staging_by_root[pt.target_root] = select_staging_dir(
                Path(pt.target_root), data_root, journal_id, prop.owner_id, os_
            )
    staging_dir = staging_by_root[plan.targets[0].target_root]

    entries: list[FileJournalEntry] = []
    for idx, pt in enumerate(plan.targets):
        if check_q25_fn is not None:
            check_q25_fn(Path(pt.target_root), pt.normalized_rel_path)
        p_id, _, p_existed = verify_target(Path(pt.target_root), pt.normalized_rel_path, os_)
        if not p_existed:
            raise _conflict()
        expected_parent_id = plan.target_files[idx].parent_physical_id if idx < len(plan.target_files) else None
        if expected_parent_id and p_id.token() != expected_parent_id:
            raise BrainError(ErrorCode.UNSAFE_PATH, "target parent identity changed")
        entry_staging = staging_by_root[pt.target_root]
        staged_path = ""
        rep_phys_id: str | None = None
        if pt.replacement_bytes is not None:
            staged = entry_staging / f"rb-rep-{idx}"
            os_.paths.reject_links(staged)
            if not os.path.lexists(staged):
                os_.publisher.write_new(staged, pt.replacement_bytes)
            os_.permissions.secure_file(staged)
            staged_id = phys.stat_physical_identity(staged)
            if (
                staged_id is None
                or staged_id.is_link
                or staged_id.is_dir
                or file_digest(staged) != pt.replacement_digest
            ):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "staged rollback replacement verification failed")
            staged_path = str(staged)
            rep_phys_id = staged_id.token()
        entries.append(
            FileJournalEntry(
                normalized_rel_path=pt.normalized_rel_path,
                target_root=pt.target_root,
                managed_format=pt.managed_format,
                slice_id=pt.slice_id,
                original=FileOriginalState.PRESENT,
                phase=FileJournalPhase.PLANNED,
                original_digest=pt.base_digest,
                original_physical_id=pt.base_physical_id,
                replacement_digest=pt.replacement_digest,
                replacement_staging_path=staged_path,
                backup_path=None,
                replacement_physical_id=rep_phys_id,
                parent_physical_id=p_id.token(),
            )
        )
    journal = ApplyJournal(
        journal_id=journal_id,
        proposal_id=prop.proposal_id,
        direction=JournalDirection.ROLLBACK,
        status=ProposalStatus.ROLLING_BACK,
        grant_id=grant.grant_id,
        staging_dir=str(staging_dir),
        files=tuple(entries),
        created_at=now_utc,
        updated_at=now_utc,
    )
    saved = proposals.save_journal(journal)
    proposals.update_proposal_status(
        prop.proposal_id, ProposalStatus.ROLLING_BACK, active_journal_id=journal_id, updated_at=now_utc
    )
    return saved


def _plan_applied_rb_entry(
    entry: FileJournalEntry, idx: int, journal_staging_dir: str, os_: OsAdapters, phys: PhysicalFsPort
) -> tuple[str, Path]:
    root = Path(entry.target_root)
    tgt = target_path(root, entry.normalized_rel_path)
    p_id, curr_id, p_existed = verify_target(root, entry.normalized_rel_path, os_)
    if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
        raise BrainError(ErrorCode.UNSAFE_PATH, "rollback parent identity changed")

    entry_staging = (
        Path(entry.replacement_staging_path).parent
        if entry.replacement_staging_path
        else Path(journal_staging_dir)
    )
    bak = Path(entry.backup_path) if entry.backup_path is not None else (entry_staging / f"rb-bak-{idx}")

    if entry.phase is FileJournalPhase.REPLACEMENT_PUBLISHED:
        if (
            not entry.replacement_staging_path
            or curr_id is None
            or curr_id.token() != entry.replacement_physical_id
            or file_digest(tgt) != entry.replacement_digest
        ):
            raise _conflict()
        return "done", bak
    if entry.phase is FileJournalPhase.DELETED:
        if entry.replacement_staging_path or curr_id is not None:
            raise _conflict()
        return "done", bak

    if (
        entry.phase in (FileJournalPhase.PLANNED, FileJournalPhase.ORIGINAL_MOVED)
        and entry.replacement_staging_path
        and curr_id is not None
        and not curr_id.is_link
        and not curr_id.is_dir
        and entry.replacement_physical_id is not None
        and curr_id.token() == entry.replacement_physical_id
        and file_digest(tgt) == entry.replacement_digest
        and verify_backup_file(
            bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
        )
    ):
        return "mark_published", bak

    if entry.replacement_staging_path:
        staged = Path(entry.replacement_staging_path)
        if not verify_backup_file(
            staged,
            os_,
            expected_digest=entry.replacement_digest,
            expected_physical_id=entry.replacement_physical_id,
        ):
            raise _conflict()

    if entry.phase is FileJournalPhase.PLANNED:
        if curr_id is not None:
            if curr_id.token() != entry.original_physical_id or file_digest(tgt) != entry.original_digest:
                raise _conflict()
            return "move_and_publish", bak
        if verify_backup_file(
            bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
        ):
            return "publish_only", bak
        raise _conflict()

    if entry.phase is FileJournalPhase.ORIGINAL_MOVED:
        if curr_id is not None or not verify_backup_file(
            bak, os_, expected_digest=entry.original_digest, expected_physical_id=entry.original_physical_id
        ):
            raise _conflict()
        return "publish_only", bak

    raise _conflict()


def run_applied_rollback_entries(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    prop: ChangeProposal,
    journal: ApplyJournal,
    grant: RecoveryGrant,
    done_utc_fn: Callable[[], str],
    check_q25_fn: Callable[[Path, str], str] | None = None,
    emit_crashpoints: bool,
    resume: bool,
) -> ApplyJournal:
    """Verify and execute ``ROLLING_BACK`` entries through policy-before-store closure."""
    phys = require_physical_fs(os_)
    mut_entries = list(journal.files)
    actions: list[tuple[str, Path]] = []
    if resume:
        for idx, entry in enumerate(mut_entries):
            try:
                actions.append(_plan_applied_rb_entry(entry, idx, journal.staging_dir, os_, phys))
            except BrainError:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                raise
    else:
        for idx, entry in enumerate(mut_entries):
            entry_staging = (
                Path(entry.replacement_staging_path).parent
                if entry.replacement_staging_path
                else Path(journal.staging_dir)
            )
            actions.append(("move_and_publish", entry_staging / f"rb-bak-{idx}"))

    if emit_crashpoints:
        crashpoint("rollback.before_first_move")

    for idx, entry in enumerate(mut_entries):
        action, bak = actions[idx]
        if action == "done":
            continue
        root = Path(entry.target_root)
        tgt = target_path(root, entry.normalized_rel_path)
        try:
            verify_active_grant(authority, grant.grant_id)
            if check_q25_fn is not None:
                check_q25_fn(root, entry.normalized_rel_path)
            p_id, _, p_existed = verify_target(root, entry.normalized_rel_path, os_)
            if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                raise BrainError(ErrorCode.UNSAFE_PATH, "rollback parent identity changed")
        except BrainError:
            mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
            mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
            raise
        if action == "mark_published":
            mut_entries[idx] = with_journal_entry(
                entry, phase=FileJournalPhase.REPLACEMENT_PUBLISHED, backup_path=str(bak)
            )
            journal = _save_rolling_back(proposals, journal, mut_entries, done_utc_fn())
            continue

        if action == "move_and_publish":
            ok, bak_kept = verified_move_to_backup(
                os_,
                tgt=tgt,
                bak=bak,
                expected_digest=entry.original_digest,
                expected_physical_id=entry.original_physical_id,
            )
            if not ok:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT, backup_path=bak_kept)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                if bak_kept is not None:
                    raise _conflict("rollback backup verification failed")
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "rollback backup verification failed")
            if emit_crashpoints:
                crashpoint("rollback.after_move_replacement")
            mut_entries[idx] = with_journal_entry(
                entry, phase=FileJournalPhase.ORIGINAL_MOVED, backup_path=str(bak)
            )
            entry = mut_entries[idx]
            journal = _save_rolling_back(proposals, journal, mut_entries, done_utc_fn())
        elif entry.phase is FileJournalPhase.PLANNED:
            mut_entries[idx] = with_journal_entry(
                entry, phase=FileJournalPhase.ORIGINAL_MOVED, backup_path=str(bak)
            )
            entry = mut_entries[idx]
            journal = _save_rolling_back(proposals, journal, mut_entries, done_utc_fn())

        if entry.replacement_staging_path:
            try:
                publish_no_replace(os_, Path(entry.replacement_staging_path), tgt)
            except FileExistsError as err:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
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
                mark_recovery_required_state(proposals, authority, journal, mut_entries, done_utc_fn())
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "published rollback verification failed")
            phase = FileJournalPhase.REPLACEMENT_PUBLISHED
        else:
            phase = FileJournalPhase.DELETED
        mut_entries[idx] = with_journal_entry(entry, phase=phase)
        journal = _save_rolling_back(proposals, journal, mut_entries, done_utc_fn())

    if emit_crashpoints:
        crashpoint("rollback.after_restore_last_original")
    done_at = done_utc_fn()
    authority.end_recovery_grant(grant_id=grant.grant_id, reason="journal_closed", final_status="rolled_back")
    final_j = ApplyJournal(
        journal_id=journal.journal_id,
        proposal_id=journal.proposal_id,
        direction=JournalDirection.ROLLBACK,
        status=ProposalStatus.ROLLED_BACK,
        grant_id=journal.grant_id,
        staging_dir=journal.staging_dir,
        files=tuple(mut_entries),
        created_at=journal.created_at,
        updated_at=done_at,
    )
    final_j = proposals.update_journal(final_j)
    proposals.update_proposal_status(
        prop.proposal_id, ProposalStatus.ROLLED_BACK, active_journal_id=None, updated_at=done_at
    )
    return final_j


def execute_applied_rollback(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    data_root: Path,
    now_utc: str,
    done_utc_fn: Callable[[], str],
    validate_fn: Callable[..., None],
    proposal_id: str,
    approval: ApprovalMessage,
    signer_id: str | None,
    channel: ApprovalChannel,
    plan: RollbackPlan,
    new_sign_count: int | None = None,
    check_q25_fn: Callable[[Path, str], str] | None = None,
    emit_crashpoints: bool = False,
) -> ApplyJournal:
    prop = proposals.get_proposal(proposal_id)
    if prop.status is not ProposalStatus.APPLIED or plan.proposal_id != proposal_id:
        raise _conflict()
    validate_fn(
        prop,
        approval,
        expected_action=ApprovalAction.ROLLBACK,
        expected_targets=plan.target_files,
        expected_digests=plan.resource_digests,
    )
    if approval.recovery_scope is not RecoveryScope.ROLLBACK:
        raise _invalid()

    for pt in plan.targets:
        root = Path(pt.target_root)
        if check_q25_fn is not None:
            check_q25_fn(root, pt.normalized_rel_path)
        _, curr_id, _ = verify_target(root, pt.normalized_rel_path, os_)
        tgt = target_path(root, pt.normalized_rel_path)
        if curr_id is None or curr_id.token() != pt.base_physical_id or file_digest(tgt) != pt.base_digest:
            raise _conflict()

    journal_id = new_id()
    receipt = authority.consume_approval(
        approval, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count
    )
    grant, _ = authority.begin_journal_turn(
        approval_id=receipt.approval_id, journal_id=journal_id, direction=JournalDirection.ROLLBACK
    )
    if emit_crashpoints:
        crashpoint("rollback.after_policy_turn_intent")

    journal = stage_applied_rollback_journal(
        proposals,
        os_,
        prop=prop,
        plan=plan,
        journal_id=journal_id,
        grant=grant,
        data_root=data_root,
        now_utc=now_utc,
        check_q25_fn=check_q25_fn,
    )
    return run_applied_rollback_entries(
        proposals,
        authority,
        os_,
        prop=prop,
        journal=journal,
        grant=grant,
        done_utc_fn=done_utc_fn,
        check_q25_fn=check_q25_fn,
        emit_crashpoints=emit_crashpoints,
        resume=False,
    )
