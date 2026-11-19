"""Startup journal reconciliation and direction-first crash classifier (spec 11.2, R21-01, I3-3)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from superbrain.application._review_apply_continue import (
    build_proposal_manifests,
    continue_apply_journal_impl,
    stage_apply_journal,
)
from superbrain.application._review_apply_ops import (
    file_digest,
    mark_recovery_required_state,
    require_physical_fs,
    target_path,
    verify_target,
    with_journal_entry,
)
from superbrain.application._review_apply_rollback import (
    plan_rollback_targets_impl,
    run_applied_rollback_entries,
    stage_applied_rollback_journal,
)
from superbrain.application._review_apply_rollback_int import execute_interrupted_rollback
from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalMessage,
    RecoveryGrant,
    RecoveryScope,
    TargetFile,
    canonical_utc,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import (
    ApplyJournal,
    ApplyTurnIntent,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ProposalStatus,
    assert_not_skill_or_internal_target,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.proposals import ApplyAuthorityPort, ConfigMergerPort, ProposalStorePort

__all__ = ["RecoveryReport", "reconcile_and_classify_journals"]


@dataclass(frozen=True)
class RecoveryReport:
    projected_journals: int
    continued_journals: int
    rolled_back_journals: int
    recovery_required_journals: int
    touched_journal_ids: tuple[str, ...]


def _is_applied_rollback_journal(journal: ApplyJournal) -> bool:
    if journal.direction is not JournalDirection.ROLLBACK:
        return False
    return all(
        not entry.replacement_staging_path or Path(entry.replacement_staging_path).name.startswith("rb-rep-")
        for entry in journal.files
    )


def _verify_applied_on_disk(journal: ApplyJournal, os_: OsAdapters) -> bool:
    phys = require_physical_fs(os_)
    for entry in journal.files:
        root = Path(entry.target_root)
        try:
            p_id, curr_id, p_existed = verify_target(root, entry.normalized_rel_path, os_)
        except BrainError:
            return False
        if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
            return False
        tgt = target_path(root, entry.normalized_rel_path)
        if curr_id is None or curr_id.is_link or curr_id.is_dir:
            return False
        if entry.replacement_physical_id is not None and curr_id.token() != entry.replacement_physical_id:
            return False
        try:
            if file_digest(tgt) != entry.replacement_digest:
                return False
        except BrainError:
            return False
    _ = phys
    return True


def _verify_rolled_back_on_disk(journal: ApplyJournal, os_: OsAdapters) -> bool:
    applied_rb = _is_applied_rollback_journal(journal)
    for entry in journal.files:
        root = Path(entry.target_root)
        try:
            p_id, curr_id, p_existed = verify_target(root, entry.normalized_rel_path, os_, allow_missing_parent=True)
        except BrainError:
            return False
        if entry.parent_physical_id is not None and p_existed and p_id.token() != entry.parent_physical_id:
            return False
        tgt = target_path(root, entry.normalized_rel_path)
        if applied_rb:
            if entry.replacement_staging_path:
                if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                    return False
                if curr_id is None or curr_id.is_link or curr_id.is_dir:
                    return False
                if entry.replacement_physical_id is not None and curr_id.token() != entry.replacement_physical_id:
                    return False
                try:
                    if file_digest(tgt) != entry.replacement_digest:
                        return False
                except BrainError:
                    return False
            elif curr_id is not None:
                return False
        elif entry.original is FileOriginalState.PRESENT:
            if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                return False
            if curr_id is None or curr_id.is_link or curr_id.is_dir:
                return False
            if entry.original_physical_id is None or curr_id.token() != entry.original_physical_id:
                return False
            try:
                if file_digest(tgt) != entry.original_digest:
                    return False
            except BrainError:
                return False
        elif curr_id is not None:
            return False
    return True


def _validate_turn_approval(
    msg: ApprovalMessage | None,
    *,
    proposal_id: str,
    subject_revision: int,
    expected_action: ApprovalAction,
    expected_targets: tuple[TargetFile, ...],
    expected_digests: tuple[ResourceDigest, ...],
    allowed_scopes: tuple[RecoveryScope, ...],
) -> None:
    if (
        msg is None
        or msg.action is not expected_action
        or msg.subject_id != proposal_id
        or msg.subject_revision != subject_revision
        or msg.recovery_scope not in allowed_scopes
        or sorted(msg.target_files, key=lambda f: (f.root_path, f.normalized_rel_path))
        != sorted(expected_targets, key=lambda f: (f.root_path, f.normalized_rel_path))
        or sorted(msg.resource_digests, key=lambda d: d.name) != sorted(expected_digests, key=lambda d: d.name)
    ):
        raise BrainError(ErrorCode.REVISION_CONFLICT, "signed approval no longer matches proposal or live state")


def _save_recovery_marker(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    grant: RecoveryGrant,
    turn: ApplyTurnIntent,
    staging_dir: Path,
    now_utc: str,
) -> None:
    if grant.state == "active":
        try:
            authority.end_recovery_grant(
                grant_id=grant.grant_id, reason="journal_closed", final_status="recovery_required"
            )
        except BrainError:
            pass
    prop = proposals.get_proposal(grant.subject_id)
    marker = ApplyJournal(
        journal_id=turn.journal_id,
        proposal_id=prop.proposal_id,
        direction=turn.direction,
        status=ProposalStatus.RECOVERY_REQUIRED,
        grant_id=grant.grant_id,
        staging_dir=str(staging_dir),
        files=(),
        created_at=now_utc,
        updated_at=now_utc,
    )
    proposals.save_journal(marker)
    proposals.update_proposal_status(
        prop.proposal_id, ProposalStatus.RECOVERY_REQUIRED, active_journal_id=turn.journal_id, updated_at=now_utc
    )


def _project_missing_turns(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    data_root: Path,
    config_merger: ConfigMergerPort | None,
    check_q25_fn: Callable[[Path, str], str],
    now_utc_fn: Callable[[], str],
    incomplete: dict[str, ApplyJournal],
) -> tuple[int, int, list[str]]:
    projected = 0
    recovery_required = 0
    touched: list[str] = []
    grants_by_journal = {g.journal_id: g for g in authority.list_recovery_grants()}
    for turn in authority.list_turn_intents():
        if turn.journal_id in incomplete:
            continue
        try:
            proposals.get_journal(turn.journal_id)
            continue
        except BrainError as err:
            if err.code is not ErrorCode.NOT_FOUND:
                raise
        grant = grants_by_journal.get(turn.journal_id)
        if grant is None:
            continue
        if grant.state != "active" and grant.end_reason == "journal_closed" and turn.state == "recovery_required":
            continue
        prop = proposals.get_proposal(grant.subject_id)
        if grant.state != "active" or grant.trust_generation != authority.trust_generation():
            _save_recovery_marker(
                proposals, authority, grant, turn, data_root / "apply_staging" / turn.journal_id, now_utc_fn()
            )
            projected += 1
            recovery_required += 1
            touched.append(turn.journal_id)
            continue

        try:
            msg = authority.approval_message(turn.approval_id)
            if turn.direction is JournalDirection.ROLLBACK:
                if prop.status is not ProposalStatus.APPLIED:
                    raise BrainError(ErrorCode.REVISION_CONFLICT, "rollback turn without applied proposal")
                plan = plan_rollback_targets_impl(
                    proposals, os_, config_merger, prop.proposal_id, check_q25_fn=check_q25_fn
                )
                _validate_turn_approval(
                    msg,
                    proposal_id=prop.proposal_id,
                    subject_revision=prop.subject_revision,
                    expected_action=ApprovalAction.ROLLBACK,
                    expected_targets=plan.target_files,
                    expected_digests=plan.resource_digests,
                    allowed_scopes=(RecoveryScope.ROLLBACK, RecoveryScope.CONTINUE_OR_ROLLBACK),
                )
                j = stage_applied_rollback_journal(
                    proposals,
                    os_,
                    prop=prop,
                    plan=plan,
                    journal_id=turn.journal_id,
                    grant=grant,
                    data_root=data_root,
                    now_utc=now_utc_fn(),
                    check_q25_fn=check_q25_fn,
                )
            else:
                _validate_turn_approval(
                    msg,
                    proposal_id=prop.proposal_id,
                    subject_revision=prop.subject_revision,
                    expected_action=ApprovalAction.APPLY,
                    expected_targets=prop.to_target_files(),
                    expected_digests=prop.resource_digests,
                    allowed_scopes=(RecoveryScope.CONTINUE, RecoveryScope.CONTINUE_OR_ROLLBACK),
                )
                j = stage_apply_journal(
                    proposals,
                    os_,
                    prop=prop,
                    journal_id=turn.journal_id,
                    grant=grant,
                    data_root=data_root,
                    now_utc=now_utc_fn(),
                    check_q25_fn=check_q25_fn,
                )
            projected += 1
            incomplete[j.journal_id] = j
        except BrainError:
            _save_recovery_marker(
                proposals, authority, grant, turn, data_root / "apply_staging" / turn.journal_id, now_utc_fn()
            )
            projected += 1
            recovery_required += 1
            touched.append(turn.journal_id)
    return projected, recovery_required, touched


def _settle_case93_ended_grant(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    journal: ApplyJournal,
    turn: ApplyTurnIntent | None,
    grant: RecoveryGrant,
    now_utc: str,
) -> tuple[str, str]:
    if grant.end_reason == "journal_closed" and turn is not None and turn.state == "applied":
        if _verify_applied_on_disk(journal, os_):
            prop = proposals.get_proposal(journal.proposal_id)
            existing = {
                (m.target_root, m.normalized_rel_path, m.managed_format, m.slice_id)
                for m in proposals.list_manifests(prop.proposal_id)
            }
            missing = [
                m
                for m in build_proposal_manifests(prop, now_utc)
                if (m.target_root, m.normalized_rel_path, m.managed_format, m.slice_id) not in existing
            ]
            if missing:
                proposals.save_manifests(missing)
            settled = tuple(
                with_journal_entry(e, phase=FileJournalPhase.REPLACEMENT_PUBLISHED) for e in journal.files
            )
            proposals.update_journal(
                ApplyJournal(
                    journal_id=journal.journal_id,
                    proposal_id=journal.proposal_id,
                    direction=journal.direction,
                    status=ProposalStatus.APPLIED,
                    grant_id=journal.grant_id,
                    staging_dir=journal.staging_dir,
                    files=settled,
                    created_at=journal.created_at,
                    updated_at=now_utc,
                )
            )
            proposals.update_proposal_status(
                prop.proposal_id, ProposalStatus.APPLIED, active_journal_id=None, updated_at=now_utc
            )
            return "continued", journal.journal_id
    elif grant.end_reason == "journal_closed" and turn is not None and turn.state == "rolled_back":
        if _verify_rolled_back_on_disk(journal, os_):
            applied_rb = _is_applied_rollback_journal(journal)
            settled_rb = tuple(
                with_journal_entry(
                    e,
                    phase=(
                        (
                            FileJournalPhase.REPLACEMENT_PUBLISHED
                            if e.replacement_staging_path
                            else FileJournalPhase.DELETED
                        )
                        if applied_rb
                        else (
                            FileJournalPhase.RESTORED
                            if e.original is FileOriginalState.PRESENT
                            else FileJournalPhase.DELETED
                        )
                    ),
                )
                for e in journal.files
            )
            proposals.update_journal(
                ApplyJournal(
                    journal_id=journal.journal_id,
                    proposal_id=journal.proposal_id,
                    direction=journal.direction,
                    status=ProposalStatus.ROLLED_BACK,
                    grant_id=journal.grant_id,
                    staging_dir=journal.staging_dir,
                    files=settled_rb,
                    created_at=journal.created_at,
                    updated_at=now_utc,
                )
            )
            proposals.update_proposal_status(
                journal.proposal_id, ProposalStatus.ROLLED_BACK, active_journal_id=None, updated_at=now_utc
            )
            return "rolled_back", journal.journal_id

    mark_recovery_required_state(proposals, authority, journal, list(journal.files), now_utc)
    return "recovery_required", journal.journal_id


def reconcile_and_classify_journals(
    proposals: ProposalStorePort,
    authority: ApplyAuthorityPort,
    os_: OsAdapters,
    *,
    data_root: Path,
    home_dir: Path | None = None,
    config_merger: ConfigMergerPort | None = None,
    now_utc_fn: Callable[[], str] | None = None,
) -> RecoveryReport:
    """Reconcile ``policy.db`` turns/grants into ``brain.db`` and resume/rollback by ``direction`` first."""
    clock_now = now_utc_fn if now_utc_fn is not None else (lambda: canonical_utc(os_.clock.now()))
    home_str = str(home_dir) if home_dir is not None else None

    def _check_q25(root_path: Path, rel_path: str) -> str:
        return assert_not_skill_or_internal_target(
            str(root_path), rel_path, data_root=str(data_root), home_dir=home_str
        )

    incomplete = {j.journal_id: j for j in proposals.list_incomplete_journals()}
    projected, recovery_required, touched = _project_missing_turns(
        proposals,
        authority,
        os_,
        data_root=data_root,
        config_merger=config_merger,
        check_q25_fn=_check_q25,
        now_utc_fn=clock_now,
        incomplete=incomplete,
    )
    continued = 0
    rolled_back = 0

    for journal in sorted(incomplete.values(), key=lambda j: (j.created_at, j.journal_id)):
        jid = journal.journal_id
        turn = authority.turn_intent_for_journal(jid)
        grant = authority.find_recovery_grant_for_journal(jid)
        direction = turn.direction if turn is not None else journal.direction

        if grant is None:
            mark_recovery_required_state(proposals, authority, journal, list(journal.files), clock_now())
            recovery_required += 1
            touched.append(jid)
            continue
        if grant.state != "active":
            outcome, tid = _settle_case93_ended_grant(
                proposals, authority, os_, journal=journal, turn=turn, grant=grant, now_utc=clock_now()
            )
            if outcome == "continued":
                continued += 1
            elif outcome == "rolled_back":
                rolled_back += 1
            else:
                recovery_required += 1
            touched.append(tid)
            continue
        if grant.trust_generation != authority.trust_generation():
            mark_recovery_required_state(proposals, authority, journal, list(journal.files), clock_now())
            recovery_required += 1
            touched.append(jid)
            continue

        if direction is JournalDirection.APPLY:
            if grant.recovery_scope in (RecoveryScope.CONTINUE, RecoveryScope.CONTINUE_OR_ROLLBACK):
                try:
                    continue_apply_journal_impl(
                        proposals,
                        authority,
                        os_,
                        journal_id=jid,
                        check_q25_fn=_check_q25,
                        now_fn=clock_now,
                        emit_crashpoints=False,
                    )
                    continued += 1
                except BrainError:
                    recovery_required += 1
            else:
                try:
                    execute_interrupted_rollback(
                        proposals,
                        authority,
                        os_,
                        now_utc=clock_now(),
                        done_utc_fn=clock_now,
                        journal_id=jid,
                        check_q25_fn=_check_q25,
                        emit_crashpoints=False,
                        allow_rollback_journal=True,
                    )
                    rolled_back += 1
                except BrainError:
                    recovery_required += 1
            touched.append(jid)
            continue

        if grant.recovery_scope not in (RecoveryScope.ROLLBACK, RecoveryScope.CONTINUE_OR_ROLLBACK):
            mark_recovery_required_state(proposals, authority, journal, list(journal.files), clock_now())
            recovery_required += 1
            touched.append(jid)
            continue

        if _is_applied_rollback_journal(journal):
            prop = proposals.get_proposal(journal.proposal_id)
            try:
                run_applied_rollback_entries(
                    proposals,
                    authority,
                    os_,
                    prop=prop,
                    journal=journal,
                    grant=grant,
                    done_utc_fn=clock_now,
                    check_q25_fn=_check_q25,
                    emit_crashpoints=False,
                    resume=True,
                )
                rolled_back += 1
            except BrainError:
                recovery_required += 1
        else:
            try:
                execute_interrupted_rollback(
                    proposals,
                    authority,
                    os_,
                    now_utc=clock_now(),
                    done_utc_fn=clock_now,
                    journal_id=jid,
                    check_q25_fn=_check_q25,
                    emit_crashpoints=False,
                    allow_rollback_journal=True,
                )
                rolled_back += 1
            except BrainError:
                recovery_required += 1
        touched.append(jid)

    return RecoveryReport(
        projected_journals=projected,
        continued_journals=continued,
        rolled_back_journals=rolled_back,
        recovery_required_journals=recovery_required,
        touched_journal_ids=tuple(touched),
    )
