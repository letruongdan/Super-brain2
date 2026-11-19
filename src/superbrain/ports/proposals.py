"""Proposal, config-merger and apply-authority ports (spec 5.8, 11.2, I3-2)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from superbrain.core._kernel_approval import (
    ApprovalChannel,
    ApprovalMessage,
    ApprovalReceipt,
    RecoveryGrant,
    TargetFile,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.proposals import (
    ApplyJournal,
    ApplyTurnIntent,
    ChangeProposal,
    JournalDirection,
    ManagedFormat,
    ManagedSliceManifest,
    ProposalStatus,
)

__all__ = [
    "ApplyAuthorityPort",
    "ConfigMergerPort",
    "MergeOutput",
    "ProposalStorePort",
    "RollbackPlan",
    "RollbackPlanTarget",
]


@dataclass(frozen=True)
class MergeOutput:
    updated_text: str
    slice_digest: str
    changed: bool


@dataclass(frozen=True)
class RollbackPlanTarget:
    normalized_rel_path: str
    target_root: str
    managed_format: ManagedFormat
    slice_id: str
    base_present: bool
    base_digest: str | None
    base_physical_id: str | None
    replacement_bytes: bytes | None
    replacement_digest: str | None


@dataclass(frozen=True)
class RollbackPlan:
    proposal_id: str
    subject_revision: int
    resource_digests: tuple[ResourceDigest, ...]
    targets: tuple[RollbackPlanTarget, ...]
    target_files: tuple[TargetFile, ...]


class ConfigMergerPort(Protocol):
    def apply_slice(
        self,
        existing_text: str | None,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        replacement_bytes: bytes,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        """Insert or update Brain's managed slice, refusing unmanaged collision or in-slice drift."""
        ...

    def remove_slice(
        self,
        existing_text: str,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        """Remove Brain's managed slice while preserving out-of-band user edits and comments."""
        ...


class ProposalStorePort(Protocol):
    @property
    def store_id(self) -> str: ...

    def create_proposal(self, proposal: ChangeProposal, payloads: Mapping[str, bytes]) -> ChangeProposal: ...

    def get_proposal(self, proposal_id: str) -> ChangeProposal: ...

    def list_proposals(self) -> tuple[ChangeProposal, ...]: ...

    def update_proposal_status(
        self,
        proposal_id: str,
        status: ProposalStatus,
        *,
        subject_revision: int | None = None,
        active_journal_id: str | None = None,
        updated_at: str,
    ) -> ChangeProposal: ...

    def read_payload_bytes(self, digest: str) -> bytes: ...

    def save_journal(self, journal: ApplyJournal) -> ApplyJournal: ...

    def update_journal(self, journal: ApplyJournal) -> ApplyJournal: ...

    def get_journal(self, journal_id: str) -> ApplyJournal: ...

    def find_latest_apply_journal(self, proposal_id: str) -> ApplyJournal: ...

    def list_incomplete_journals(self) -> tuple[ApplyJournal, ...]: ...

    def save_manifests(self, manifests: Sequence[ManagedSliceManifest]) -> None: ...

    def list_manifests(self, proposal_id: str) -> tuple[ManagedSliceManifest, ...]: ...


class ApplyAuthorityPort(Protocol):
    def trust_generation(self) -> int: ...

    def consume_approval(
        self,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ApprovalReceipt: ...

    def approval_message(self, approval_id: str) -> ApprovalMessage | None: ...

    def open_recovery_grant(self, *, approval_id: str, journal_id: str) -> RecoveryGrant: ...

    def recovery_grant(self, grant_id: str) -> RecoveryGrant: ...

    def find_recovery_grant_for_journal(self, journal_id: str) -> RecoveryGrant | None: ...

    def list_recovery_grants(self) -> tuple[RecoveryGrant, ...]: ...

    def open_turn_intent(
        self, *, journal_id: str, approval_id: str, direction: JournalDirection
    ) -> ApplyTurnIntent: ...

    def begin_journal_turn(
        self, *, approval_id: str, journal_id: str, direction: JournalDirection
    ) -> tuple[RecoveryGrant, ApplyTurnIntent]: ...

    def turn_intent_for_journal(self, journal_id: str) -> ApplyTurnIntent | None: ...

    def list_turn_intents(self) -> tuple[ApplyTurnIntent, ...]: ...

    def end_recovery_grant(
        self, *, grant_id: str, reason: str = "journal_closed", final_status: str | None = None
    ) -> RecoveryGrant: ...
