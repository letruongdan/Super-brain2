"""Read-only diagnostic snapshot DTOs and reader port for ``brain doctor`` (spec 13, 14.2, I3-5)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from superbrain.core._kernel_approval import Layer2State, SignerRecord

__all__ = [
    "DoctorAccountingLock",
    "DoctorBootstrapDrift",
    "DoctorJournalInfo",
    "DoctorLayer2HarnessStatus",
    "DoctorPendingTombstones",
    "DoctorProposalSummary",
    "DoctorSchemaVersions",
    "DoctorSnapshot",
    "DoctorSnapshotReaderPort",
    "DoctorTurnIntentInfo",
]


@dataclass(frozen=True)
class DoctorSchemaVersions:
    """Observed vs expected schema versions for ``brain.db`` and ``policy.db``."""

    store_version: int | None
    policy_version: int | None
    expected_store_version: int
    expected_policy_version: int


@dataclass(frozen=True)
class DoctorLayer2HarnessStatus:
    """Recorded Layer-2 state for one connected or observed harness."""

    harness_id: str
    host_version: str | None
    config_digest: str | None
    state: Layer2State
    created_at: str | None


@dataclass(frozen=True)
class DoctorAccountingLock:
    """Unreconciled post-restore accounting lock row."""

    lock_key: str
    owner_id: str
    period_key: str
    backup_created_at: str
    locked_at: str


@dataclass(frozen=True)
class DoctorPendingTombstones:
    """Status of ``store/pending_restore_tombstones.json``."""

    present: bool
    restore_epoch: int | None
    expired_holders_count: int
    corrupt_error: str | None = None


@dataclass(frozen=True)
class DoctorProposalSummary:
    """Non-terminal proposal needing operator review, apply, or continuation."""

    proposal_id: str
    status: str
    kind: str
    active_journal_id: str | None


@dataclass(frozen=True)
class DoctorTurnIntentInfo:
    """Active ``apply_turn_intent`` row recorded in ``policy.db`` (e.g. Case 107 mid-crash state)."""

    turn_id: str
    journal_id: str
    approval_id: str
    direction: str
    state: str
    created_at: str


@dataclass(frozen=True)
class DoctorJournalInfo:
    """Non-terminal ``ApplyJournal`` row in ``store/brain.db``."""

    journal_id: str
    proposal_id: str
    direction: str
    status: str
    grant_id: str
    updated_at: str


@dataclass(frozen=True)
class DoctorBootstrapDrift:
    """Applied proposal target whose on-disk state drifted or became unsafe."""

    proposal_id: str
    target_root: str
    rel_path: str
    reason: str
    current_digest: str | None
    expected_digest: str | None


@dataclass(frozen=True)
class DoctorSnapshot:
    """Complete strictly read-only storage and checkout snapshot inspected by ``brain doctor``."""

    data_root: Path
    store_id: str | None
    schema: DoctorSchemaVersions
    restore_epoch: int | None
    trust_generation: int | None
    signer_reset_recorded: bool
    signers: tuple[SignerRecord, ...]
    terminal_channel_eligible: bool
    layer2_harnesses: tuple[DoctorLayer2HarnessStatus, ...]
    unresolved_accounting_locks: tuple[DoctorAccountingLock, ...]
    pending_restore_tombstones: DoctorPendingTombstones
    pending_proposals: tuple[DoctorProposalSummary, ...]
    bootstrap_drifts: tuple[DoctorBootstrapDrift, ...]
    integrity_errors: tuple[str, ...]
    active_turn_intents: tuple[DoctorTurnIntentInfo, ...] = ()
    incomplete_journals: tuple[DoctorJournalInfo, ...] = ()
    permission_problems: tuple[str, ...] = ()


class DoctorSnapshotReaderPort(Protocol):
    """Port implemented by storage to read a ``DoctorSnapshot`` with zero mutations."""

    def read_snapshot(
        self,
        data_root: Path,
        *,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
    ) -> DoctorSnapshot: ...
