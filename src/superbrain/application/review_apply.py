"""Application service for ChangeProposal, server risk ranking, ApplyJournal & dual rollback (I3-2)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
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
    verify_target,
    with_journal_entry,
)
from superbrain.application._review_apply_rollback import (
    execute_applied_rollback,
    execute_interrupted_rollback,
    plan_rollback_targets_impl,
)
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    TargetFile,
    canonical_utc,
    classify_proposal_risk,
)
from superbrain.core._kernel_base import ResourceDigest, require_opaque_id, require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ManagedSliceManifest,
    ProposalStatus,
    ProposalTarget,
    assert_not_skill_or_internal_target,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.proposals import (
    ApplyAuthorityPort,
    ConfigMergerPort,
    ProposalStorePort,
    RollbackPlan,
)

__all__ = ["ReviewApplyService", "TargetWriteInput"]


def _invalid(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def _conflict(message: str = "revision conflict") -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, message)


@dataclass(frozen=True)
class TargetWriteInput:
    root_path: Path
    rel_path: str
    replacement_bytes: bytes
    managed_format: ManagedFormat
    slice_id: str
    managed_slice_digest: str | None = None


class ReviewApplyService:
    """Orchestrates proposals, server-enforced Q25/risk guards, and ApplyJournal apply/rollback."""

    def __init__(
        self,
        proposals: ProposalStorePort,
        authority: ApplyAuthorityPort,
        os_: OsAdapters,
        *,
        data_root: Path,
        home_dir: Path | None = None,
        config_merger: ConfigMergerPort | None = None,
    ) -> None:
        self._proposals = proposals
        self._authority = authority
        self._os = os_
        self._data_root = data_root
        self._home_dir = home_dir
        self._config_merger = config_merger

    def _now_utc(self) -> str:
        return canonical_utc(self._os.clock.now())

    def _check_q25(self, root_path: Path, rel_path: str) -> str:
        home_str = str(self._home_dir) if self._home_dir is not None else None
        return assert_not_skill_or_internal_target(
            str(root_path),
            rel_path,
            data_root=str(self._data_root),
            home_dir=home_str,
        )

    def create_proposal(
        self,
        *,
        owner_id: str,
        kind: str,
        reason: str,
        resources: Sequence[RiskResource],
        targets: Sequence[TargetWriteInput],
        client_risk_hint: str | None = None,
    ) -> ChangeProposal:
        require_opaque_id(owner_id)
        require_opaque_id(kind)
        if not isinstance(reason, str) or not reason or "\x00" in reason or not resources or not targets:
            raise _invalid()

        risk_level = classify_proposal_risk(resources, client_hint=client_risk_hint)
        proposal_targets: list[ProposalTarget] = []
        payloads: dict[str, bytes] = {}
        digests: list[ResourceDigest] = [
            ResourceDigest(
                "resources",
                digest_bytes(
                    canonical_json(
                        [
                            {
                                "component": r.component,
                                "executable": r.executable,
                                "command_reference": r.command_reference,
                                "outside_guidance_block": r.outside_guidance_block,
                            }
                            for r in resources
                        ]
                    )
                ),
            )
        ]
        seen_paths: set[tuple[str, str]] = set()
        for idx, item in enumerate(targets):
            if not isinstance(item.replacement_bytes, bytes):
                raise _invalid()
            if item.managed_format is not ManagedFormat.RAW and self._config_merger is not None:
                if item.managed_slice_digest is None:
                    raise _invalid("managed_slice_digest is required for structured targets")
                require_sha256_digest(item.managed_slice_digest)
            norm_rel = self._check_q25(item.root_path, item.rel_path)
            key = (str(item.root_path), norm_rel)
            if key in seen_paths:
                raise _invalid("duplicate target path")
            seen_paths.add(key)

            parent_id, tgt_id, _ = verify_target(item.root_path, norm_rel, self._os, allow_missing_parent=True)
            tgt = target_path(item.root_path, norm_rel)
            base_present = tgt_id is not None
            if base_present:
                try:
                    base_bytes = tgt.read_bytes()
                except OSError as err:
                    raise BrainError(ErrorCode.IO_ERROR, f"cannot read {tgt}: {err}") from err
                base_digest: str | None = digest_bytes(base_bytes)
                assert base_digest is not None
                payloads[base_digest] = base_bytes
            else:
                base_digest = None
            base_phys = tgt_id.token() if tgt_id is not None else None
            rep_digest = digest_bytes(item.replacement_bytes)
            payloads[rep_digest] = item.replacement_bytes
            digests.append(ResourceDigest(f"target:{idx}", rep_digest))
            proposal_targets.append(
                ProposalTarget(
                    rel_path=item.rel_path,
                    normalized_rel_path=norm_rel,
                    managed_format=item.managed_format,
                    slice_id=item.slice_id,
                    base_present=base_present,
                    base_digest=base_digest,
                    base_physical_id=base_phys,
                    replacement_digest=rep_digest,
                    managed_slice_digest=item.managed_slice_digest,
                    target_root=str(item.root_path),
                    parent_physical_id=parent_id.token(),
                )
            )

        now = self._now_utc()
        proposal = ChangeProposal(
            proposal_id=new_id(),
            owner_id=owner_id,
            kind=kind,
            reason=reason,
            status=ProposalStatus.PENDING,
            subject_revision=1,
            risk_level=risk_level,
            resources=tuple(resources),
            resource_digests=tuple(digests),
            targets=tuple(proposal_targets),
            created_at=now,
            updated_at=now,
        )
        return self._proposals.create_proposal(proposal, payloads)

    def list_proposals(self) -> tuple[ChangeProposal, ...]:
        return self._proposals.list_proposals()

    def get_proposal(self, proposal_id: str) -> ChangeProposal:
        return self._proposals.get_proposal(proposal_id)

    def get_journal(self, journal_id: str) -> ApplyJournal:
        return self._proposals.get_journal(journal_id)

    def _validate_proposal_approval(
        self,
        prop: ChangeProposal,
        approval: ApprovalMessage,
        *,
        expected_action: ApprovalAction,
        expected_targets: tuple[TargetFile, ...],
        expected_digests: tuple[ResourceDigest, ...],
    ) -> None:
        if not isinstance(approval, ApprovalMessage) or approval.action is not expected_action:
            raise _invalid()
        if approval.risk_policy_version != RISK_POLICY_VERSION:
            raise _conflict()
        if (
            approval.owner_id != prop.owner_id
            or approval.subject_id != prop.proposal_id
            or approval.subject_revision != prop.subject_revision
            or approval.risk_level is not prop.risk_level
            or tuple(approval.resource_digests) != expected_digests
            or tuple(approval.target_files) != expected_targets
        ):
            raise _conflict()

    def approve_proposal(
        self,
        proposal_id: str,
        *,
        approval: ApprovalMessage,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ChangeProposal:
        prop = self._proposals.get_proposal(proposal_id)
        if prop.status is not ProposalStatus.PENDING:
            raise _conflict()
        self._validate_proposal_approval(
            prop,
            approval,
            expected_action=ApprovalAction.APPROVE,
            expected_targets=prop.to_target_files(),
            expected_digests=prop.resource_digests,
        )
        self._authority.consume_approval(approval, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count)
        return self._proposals.update_proposal_status(proposal_id, ProposalStatus.APPROVED, updated_at=self._now_utc())

    def reject_proposal(
        self,
        proposal_id: str,
        *,
        approval: ApprovalMessage,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ChangeProposal:
        prop = self._proposals.get_proposal(proposal_id)
        if prop.status is not ProposalStatus.PENDING:
            raise _conflict()
        self._validate_proposal_approval(
            prop,
            approval,
            expected_action=ApprovalAction.REJECT,
            expected_targets=prop.to_target_files(),
            expected_digests=prop.resource_digests,
        )
        self._authority.consume_approval(approval, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count)
        return self._proposals.update_proposal_status(proposal_id, ProposalStatus.REJECTED, updated_at=self._now_utc())

    def _preflight_apply_targets(self, prop: ChangeProposal) -> None:
        for t in prop.targets:
            root = Path(t.target_root)
            self._check_q25(root, t.normalized_rel_path)
            parent_id, tgt_id, _ = verify_target(root, t.normalized_rel_path, self._os, allow_missing_parent=True)
            if t.parent_physical_id and parent_id.token() != t.parent_physical_id:
                raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
            tgt = target_path(root, t.normalized_rel_path)
            if t.base_present:
                if tgt_id is None or tgt_id.token() != t.base_physical_id:
                    raise _conflict()
                if file_digest(tgt) != t.base_digest:
                    raise _conflict()
            elif tgt_id is not None:
                raise _conflict()

    def apply_proposal(
        self,
        proposal_id: str,
        *,
        approval: ApprovalMessage,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ApplyJournal:
        prop = self._proposals.get_proposal(proposal_id)
        if prop.status not in (ProposalStatus.PENDING, ProposalStatus.APPROVED):
            raise _conflict()
        self._validate_proposal_approval(
            prop,
            approval,
            expected_action=ApprovalAction.APPLY,
            expected_targets=prop.to_target_files(),
            expected_digests=prop.resource_digests,
        )
        if approval.recovery_scope not in (RecoveryScope.CONTINUE, RecoveryScope.CONTINUE_OR_ROLLBACK):
            raise _invalid()

        self._preflight_apply_targets(prop)
        journal_id = new_id()
        staging_by_root: dict[str, Path] = {}
        for t in prop.targets:
            if t.target_root not in staging_by_root:
                staging_by_root[t.target_root] = select_staging_dir(
                    Path(t.target_root), self._data_root, journal_id, prop.owner_id, self._os
                )
        staging_dir = staging_by_root[prop.targets[0].target_root]

        receipt = self._authority.consume_approval(
            approval, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count
        )
        grant = self._authority.open_recovery_grant(approval_id=receipt.approval_id, journal_id=journal_id)

        phys = require_physical_fs(self._os)
        entries: list[FileJournalEntry] = []
        for idx, t in enumerate(prop.targets):
            assert t.replacement_digest is not None
            rep_bytes = self._proposals.read_payload_bytes(t.replacement_digest)
            entry_staging = staging_by_root[t.target_root]
            staged = entry_staging / f"rep-{idx}"
            self._os.publisher.write_new(staged, rep_bytes)
            self._os.permissions.secure_file(staged)
            staged_id = phys.stat_physical_identity(staged)
            if (
                staged_id is None
                or staged_id.is_link
                or staged_id.is_dir
                or file_digest(staged) != t.replacement_digest
            ):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "staged replacement verification failed")
            p_id, _, p_existed = verify_target(
                Path(t.target_root), t.normalized_rel_path, self._os, allow_missing_parent=True
            )
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

        now = self._now_utc()
        journal = ApplyJournal(
            journal_id=journal_id,
            proposal_id=prop.proposal_id,
            direction=JournalDirection.APPLY,
            status=ProposalStatus.APPLYING,
            grant_id=grant.grant_id,
            staging_dir=str(staging_dir),
            files=tuple(entries),
            created_at=now,
            updated_at=now,
        )
        journal = self._proposals.save_journal(journal)
        self._proposals.update_proposal_status(
            prop.proposal_id, ProposalStatus.APPLYING, active_journal_id=journal_id, updated_at=now
        )

        mut_entries = list(journal.files)
        for idx, entry in enumerate(mut_entries):
            try:
                verify_active_grant(self._authority, grant.grant_id)
                root = Path(entry.target_root)
                self._check_q25(root, entry.normalized_rel_path)
                p_id, _, p_existed = verify_target(root, entry.normalized_rel_path, self._os, allow_missing_parent=True)
                if entry.parent_physical_id is not None and (not p_existed or p_id.token() != entry.parent_physical_id):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "target parent identity changed")
            except BrainError:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                self._mark_recovery_required(journal, mut_entries, prop.proposal_id)
                raise

            tgt = target_path(root, entry.normalized_rel_path)
            entry_staging = Path(entry.replacement_staging_path).parent
            if entry.original is FileOriginalState.PRESENT:
                bak = entry_staging / f"bak-{idx}"
                ok, bak_kept = verified_move_to_backup(
                    self._os,
                    tgt=tgt,
                    bak=bak,
                    expected_digest=entry.original_digest,
                    expected_physical_id=entry.original_physical_id,
                )
                if not ok:
                    mut_entries[idx] = with_journal_entry(
                        entry, phase=FileJournalPhase.CONFLICT, backup_path=bak_kept
                    )
                    self._mark_recovery_required(journal, mut_entries, prop.proposal_id)
                    if bak_kept is not None:
                        raise _conflict("backup verification failed")
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "backup verification failed")
                mut_entries[idx] = with_journal_entry(
                    entry, phase=FileJournalPhase.ORIGINAL_MOVED, backup_path=str(bak)
                )
                entry = mut_entries[idx]
                journal = self._save_partial_journal(journal, mut_entries, prop.proposal_id)

            ensure_parent_dirs(tgt.parent, root, self._os)
            if entry.parent_physical_id is None:
                created_parent = phys.stat_physical_identity(tgt.parent)
                if created_parent is not None:
                    entry = with_journal_entry(entry, parent_physical_id=created_parent.token())
                    mut_entries[idx] = entry
            try:
                publish_no_replace(self._os, Path(entry.replacement_staging_path), tgt)
            except FileExistsError as err:
                mut_entries[idx] = with_journal_entry(entry, phase=FileJournalPhase.CONFLICT)
                self._mark_recovery_required(journal, mut_entries, prop.proposal_id)
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
                self._mark_recovery_required(journal, mut_entries, prop.proposal_id)
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "published target verification failed")
            mut_entries[idx] = with_journal_entry(
                entry, phase=FileJournalPhase.REPLACEMENT_PUBLISHED, replacement_physical_id=pub_id.token()
            )
            journal = self._save_partial_journal(journal, mut_entries, prop.proposal_id)

        done_at = self._now_utc()
        manifests = [
            ManagedSliceManifest(
                proposal_id=prop.proposal_id,
                normalized_rel_path=t.normalized_rel_path,
                managed_format=t.managed_format,
                slice_id=t.slice_id,
                slice_digest=t.managed_slice_digest,
                full_file_digest=str(t.replacement_digest),
                updated_at=done_at,
                target_root=t.target_root,
            )
            for t in prop.targets
            if t.managed_slice_digest is not None
        ]
        if manifests:
            self._proposals.save_manifests(manifests)
        self._authority.end_recovery_grant(grant_id=grant.grant_id, reason="journal_closed", final_status="applied")
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
        final_journal = self._proposals.update_journal(final_journal)
        self._proposals.update_proposal_status(
            prop.proposal_id, ProposalStatus.APPLIED, active_journal_id=None, updated_at=done_at
        )
        return final_journal

    def _save_partial_journal(
        self, journal: ApplyJournal, entries: list[FileJournalEntry], proposal_id: str
    ) -> ApplyJournal:
        now = self._now_utc()
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
        saved = self._proposals.update_journal(updated)
        self._proposals.update_proposal_status(
            proposal_id, ProposalStatus.PARTIALLY_APPLIED, active_journal_id=journal.journal_id, updated_at=now
        )
        return saved

    def _mark_recovery_required(
        self, journal: ApplyJournal, entries: list[FileJournalEntry], proposal_id: str
    ) -> None:
        _ = proposal_id
        mark_recovery_required_state(self._proposals, self._authority, journal, entries, self._now_utc())

    def plan_rollback_targets(self, proposal_id: str) -> RollbackPlan:
        return plan_rollback_targets_impl(self._proposals, self._os, self._config_merger, proposal_id)

    def rollback_applied_proposal(
        self,
        proposal_id: str,
        *,
        approval: ApprovalMessage,
        signer_id: str | None,
        channel: ApprovalChannel,
        plan: RollbackPlan,
        new_sign_count: int | None = None,
    ) -> ApplyJournal:
        return execute_applied_rollback(
            self._proposals,
            self._authority,
            self._os,
            data_root=self._data_root,
            now_utc=self._now_utc(),
            done_utc_fn=self._now_utc,
            validate_fn=self._validate_proposal_approval,
            proposal_id=proposal_id,
            approval=approval,
            signer_id=signer_id,
            channel=channel,
            plan=plan,
            new_sign_count=new_sign_count,
        )

    def rollback_interrupted_journal(self, journal_id: str) -> ApplyJournal:
        return execute_interrupted_rollback(
            self._proposals,
            self._authority,
            self._os,
            now_utc=self._now_utc(),
            done_utc_fn=self._now_utc,
            journal_id=journal_id,
        )
