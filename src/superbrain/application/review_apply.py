"""Application service for ChangeProposal, server risk ranking, ApplyJournal & dual rollback (I3-2)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.application._review_apply_continue import (
    continue_apply_journal_impl,
    execute_apply_entries,
    stage_apply_journal,
)
from superbrain.application._review_apply_ops import (
    file_digest,
    target_path,
    verify_target,
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
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    JournalDirection,
    ManagedFormat,
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

    def active_slice_digests(self, checkout_root: Path, *, owner_id: str) -> dict[tuple[str, str], str]:
        """Return active ``(normalized_rel_path, slice_id) -> slice_digest`` for ``checkout_root``."""
        require_opaque_id(owner_id, label="owner_id")
        phys = self._os.physical
        target_id = phys.stat_physical_identity(checkout_root) if phys is not None else None
        resolved_root = str(checkout_root.resolve())
        digests: dict[tuple[str, str], str] = {}
        seen_slices: set[tuple[str, str]] = set()
        for manifest, status in self._proposals.list_latest_manifests_for_owner(owner_id):
            m_root = Path(manifest.target_root)
            if target_id is not None and phys is not None:
                m_id = phys.stat_physical_identity(m_root)
                matches = m_id == target_id if m_id is not None else str(m_root.resolve()) == resolved_root
            else:
                matches = str(m_root.resolve()) == resolved_root
            if not matches:
                continue
            slice_key = (manifest.normalized_rel_path, manifest.slice_id)
            if slice_key in seen_slices:
                continue
            seen_slices.add(slice_key)
            if status is ProposalStatus.APPLIED:
                digests[slice_key] = manifest.slice_digest
        return digests

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
        expected_sorted_digests = sorted(expected_digests, key=lambda d: d.name)
        actual_sorted_digests = sorted(approval.resource_digests, key=lambda d: d.name)
        expected_sorted_targets = sorted(expected_targets, key=lambda f: (f.root_path, f.normalized_rel_path))
        actual_sorted_targets = sorted(approval.target_files, key=lambda f: (f.root_path, f.normalized_rel_path))
        if (
            approval.owner_id != prop.owner_id
            or approval.subject_id != prop.proposal_id
            or approval.subject_revision != prop.subject_revision
            or approval.risk_level is not prop.risk_level
            or actual_sorted_digests != expected_sorted_digests
            or actual_sorted_targets != expected_sorted_targets
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
        receipt = self._authority.consume_approval(
            approval, signer_id=signer_id, channel=channel, new_sign_count=new_sign_count
        )
        grant, _ = self._authority.begin_journal_turn(
            approval_id=receipt.approval_id, journal_id=journal_id, direction=JournalDirection.APPLY
        )
        crashpoint("apply.after_policy_turn_intent")

        journal = stage_apply_journal(
            self._proposals,
            self._os,
            prop=prop,
            journal_id=journal_id,
            grant=grant,
            data_root=self._data_root,
            now_utc=self._now_utc(),
            check_q25_fn=self._check_q25,
        )
        return execute_apply_entries(
            self._proposals,
            self._authority,
            self._os,
            prop=prop,
            journal=journal,
            grant=grant,
            check_q25_fn=self._check_q25,
            now_fn=self._now_utc,
            emit_crashpoints=True,
            resume=False,
        )

    def plan_rollback_targets(self, proposal_id: str) -> RollbackPlan:
        return plan_rollback_targets_impl(
            self._proposals, self._os, self._config_merger, proposal_id, check_q25_fn=self._check_q25
        )

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
            check_q25_fn=self._check_q25,
            emit_crashpoints=True,
        )

    def rollback_interrupted_journal(self, journal_id: str) -> ApplyJournal:
        return execute_interrupted_rollback(
            self._proposals,
            self._authority,
            self._os,
            now_utc=self._now_utc(),
            done_utc_fn=self._now_utc,
            journal_id=journal_id,
            check_q25_fn=self._check_q25,
            emit_crashpoints=True,
        )

    def continue_interrupted_journal(self, journal_id: str) -> ApplyJournal:
        return continue_apply_journal_impl(
            self._proposals,
            self._authority,
            self._os,
            journal_id=journal_id,
            check_q25_fn=self._check_q25,
            now_fn=self._now_utc,
            emit_crashpoints=False,
        )
