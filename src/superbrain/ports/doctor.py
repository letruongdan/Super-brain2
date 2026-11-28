"""Read-only diagnostic snapshot DTOs, bounds, and shared probe/repair ports for ``brain doctor``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from superbrain.core._kernel_approval import Layer2State, SignerRecord

MAX_CAS_SAMPLE_BLOBS = 64
MAX_CAS_SAMPLE_BYTES = 16 * 1024 * 1024
MAX_PRIVACY_RESCAN_ITEMS = 128
MAX_PRIVACY_RESCAN_ITEM_BYTES = 64 * 1024
MAX_PRIVACY_RESCAN_TOTAL_BYTES = 1024 * 1024
MAX_LOG_INSPECT_FILES = 16
MAX_LOG_BYTES = 1024 * 1024
MAX_CHECKOUT_SCAN_FILES = 256
WAL_WARN_BYTES = 64 * 1024 * 1024
DISK_WARN_FREE_BYTES = 256 * 1024 * 1024
DISK_FAIL_FREE_BYTES = 64 * 1024 * 1024
BACKUP_STALE_AGE_S = 7.0 * 86_400.0
PROBE_TIMEOUT_S = 5.0
MAX_REPORT_CHECKS = 64
MAX_REPORT_STRING_LEN = 512
MAX_LIST_FINDINGS_PER_GROUP = 32
MAX_DOCTOR_REPORT_BYTES = 256 * 1024
MAX_DOCTOR_RUN_BLOB_BYTES = 64 * 1024

__all__ = [
    "BACKUP_STALE_AGE_S",
    "CaptureDoctorProbePort",
    "CaptureDoctorProbeResult",
    "CaptureDoctorSnapshot",
    "CaptureHarnessDoctorStatus",
    "DISK_FAIL_FREE_BYTES",
    "DISK_WARN_FREE_BYTES",
    "DoctorAccountingLock",
    "DoctorBootstrapDrift",
    "DoctorDaemonStats",
    "DoctorIdentityStats",
    "DoctorJevStats",
    "DoctorJournalInfo",
    "DoctorLayer2HarnessStatus",
    "DoctorPendingTombstones",
    "DoctorProposalSummary",
    "DoctorRetentionStats",
    "DoctorScanLimits",
    "DoctorSchemaVersions",
    "DoctorSnapshot",
    "DoctorSnapshotReaderPort",
    "DoctorStorageStats",
    "DoctorTurnIntentInfo",
    "MAX_CAS_SAMPLE_BLOBS",
    "MAX_CAS_SAMPLE_BYTES",
    "MAX_CHECKOUT_SCAN_FILES",
    "MAX_DOCTOR_REPORT_BYTES",
    "MAX_DOCTOR_RUN_BLOB_BYTES",
    "MAX_LIST_FINDINGS_PER_GROUP",
    "MAX_LOG_BYTES",
    "MAX_LOG_INSPECT_FILES",
    "MAX_PRIVACY_RESCAN_ITEMS",
    "MAX_PRIVACY_RESCAN_ITEM_BYTES",
    "MAX_PRIVACY_RESCAN_TOTAL_BYTES",
    "MAX_REPORT_CHECKS",
    "MAX_REPORT_STRING_LEN",
    "OutboxReplayPort",
    "OutboxReplayResult",
    "PROBE_TIMEOUT_S",
    "PrivacyCanaryProbeResult",
    "PrivacyRescanSummary",
    "PrivacyScanFinding",
    "PrivacyScannerPort",
    "SupervisorControlPort",
    "SupervisorRestartResult",
    "WAL_WARN_BYTES",
]


@dataclass(frozen=True)
class DoctorScanLimits:
    """Bounded scan counts, sizes, thresholds, and timeouts for doctor snapshot inspection."""

    max_cas_sample_blobs: int = MAX_CAS_SAMPLE_BLOBS
    max_cas_sample_bytes: int = MAX_CAS_SAMPLE_BYTES
    max_privacy_rescan_items: int = MAX_PRIVACY_RESCAN_ITEMS
    max_privacy_rescan_bytes: int = MAX_PRIVACY_RESCAN_TOTAL_BYTES
    max_privacy_item_bytes: int = MAX_PRIVACY_RESCAN_ITEM_BYTES
    max_log_files: int = MAX_LOG_INSPECT_FILES
    max_log_bytes: int = MAX_LOG_BYTES
    wal_warn_bytes: int = WAL_WARN_BYTES
    disk_warn_free_bytes: int = DISK_WARN_FREE_BYTES
    disk_fail_free_bytes: int = DISK_FAIL_FREE_BYTES
    backup_stale_age_s: float = BACKUP_STALE_AGE_S
    probe_timeout_s: float = PROBE_TIMEOUT_S


@dataclass(frozen=True)
class DoctorSchemaVersions:
    """Observed vs expected schema versions for ``brain.db`` and ``policy.db``."""

    store_version: int | None
    policy_version: int | None
    expected_store_version: int
    expected_policy_version: int
    min_store_reader_version: int | None = None
    min_policy_reader_version: int | None = None


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
class PrivacyCanaryProbeResult:
    """Outcome of running one in-memory synthetic canary secret channel through the privacy filter."""

    channel: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class PrivacyScanFinding:
    """Metadata-only privacy rescan hit; never stores raw secret bytes."""

    holder_kind: str
    holder_id: str
    digest: str
    rule_id: str


@dataclass(frozen=True)
class PrivacyRescanSummary:
    """Bounded store/log privacy rescan outcome."""

    scanned_items: int = 0
    scanned_bytes: int = 0
    truncated: bool = False
    findings: tuple[PrivacyScanFinding, ...] = ()
    error: str | None = None


class PrivacyScannerPort(Protocol):
    """Privacy check port implemented in application layer and injected into snapshot/doctor checks."""

    def check_canary_channels(self) -> tuple[PrivacyCanaryProbeResult, ...]: ...

    def scan_bytes(self, data: bytes) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class CaptureDoctorProbeResult:
    """Single-surface capture probe outcome (shared with SP2 adapter/fixtures)."""

    available: bool = True
    detail: str = ""
    status: Literal["PASS", "WARN", "FAIL"] = "PASS"
    reason: str = "ok"
    remediation: str | None = None
    outbox_backlog: int = 0
    capture_gaps: int = 0
    dead_letters: int = 0
    last_event_at: str | None = None
    active_layer: str | None = None
    timed_out: bool = False


@dataclass(frozen=True)
class CaptureHarnessDoctorStatus:
    """Detailed per-harness SP2 capture probe snapshot item."""

    harness_id: str
    last_event_at: str | None
    active_layer: str | None
    outbox_backlog: int
    capture_gaps: int
    dead_letters: int
    receipt_kind: str | None
    host_invalidated: bool = False
    probe_error: str | None = None


@dataclass(frozen=True)
class CaptureDoctorSnapshot:
    """Complete SP2 capture probe snapshot across all harnesses."""

    harnesses: tuple[CaptureHarnessDoctorStatus, ...] = ()
    available: bool = True
    unavailable_reason: str | None = None


class CaptureDoctorProbePort(Protocol):
    """Port implemented by SP2 capture adapters/fixtures to expose capture probes to ``brain doctor``."""

    def probe_capture(self, data_root: Path) -> CaptureDoctorProbeResult: ...


@dataclass(frozen=True)
class OutboxReplayResult:
    """Structured SP2-compatible outbox replay summary returned by ``OutboxReplayPort``."""

    status: Literal["applied", "noop", "capability_unavailable", "failed"]
    replayed_events: int = 0
    committed_event_sequences: tuple[int, ...] = ()
    contiguous_event_acked_through: int | None = None
    acked_producer_gap_sequences: tuple[int, ...] = ()
    pending_remaining: int = 0
    detail: str = ""


class OutboxReplayPort(Protocol):
    """SP2 outbox replay port invoked by ``brain doctor --fix`` when wired."""

    def replay_outbox(self, *, now: datetime) -> OutboxReplayResult: ...


@dataclass(frozen=True)
class SupervisorRestartResult:
    """Daemon restart status returned by ``SupervisorControlPort``."""

    status: Literal["applied", "capability_unavailable", "failed"]
    restarted: bool = False
    pid: int | None = None
    detail: str = ""


class SupervisorControlPort(Protocol):
    """External process supervisor port invoked by ``brain doctor --fix`` when wired."""

    def restart_daemon(self, config_path: Path) -> SupervisorRestartResult: ...


@dataclass(frozen=True)
class DoctorDaemonStats:
    """Read-only daemon lock, epoch, and endpoint observations."""

    writer_lock_present: bool = True
    writer_lock_held: bool = False
    writer_epoch: int | None = None
    lock_error: str | None = None
    endpoint_present: bool = False
    endpoint_valid: bool | None = None
    endpoint_detail: str = "stopped cleanly"


@dataclass(frozen=True)
class DoctorIdentityStats:
    """Read-only credential, harness coverage, and signer summary."""

    active_credentials: int = 0
    revoked_credentials: int = 0
    active_harness_ids: tuple[str, ...] = ()
    registered_harness_ids: tuple[str, ...] = ()
    missing_harness_credentials: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class DoctorStorageStats:
    """Read-only SQLite, WAL, CAS, ledger/projection, backup, disk, and durability observations."""

    store_integrity_ok: bool | None = None
    policy_integrity_ok: bool | None = None
    integrity_detail: str = "not checked"
    wal_store_bytes: int = 0
    wal_policy_bytes: int = 0
    wal_warn_bytes: int = WAL_WARN_BYTES
    cas_sampled_blobs: int = 0
    cas_sampled_bytes: int = 0
    cas_total_blobs: int = 0
    cas_truncated: bool = False
    cas_mismatches: tuple[str, ...] = ()
    orphan_blobs_count: int = 0
    orphan_blobs_sample: tuple[str, ...] = ()
    orphan_truncated: bool = False
    ledger_projection_match: bool | None = None
    ledger_projection_detail: str = "not checked"
    unapplied_policy_intents: int | None = None
    disk_free_bytes: int | None = None
    disk_warn_free_bytes: int = DISK_WARN_FREE_BYTES
    disk_fail_free_bytes: int = DISK_FAIL_FREE_BYTES
    disk_error: str | None = None
    latest_backup_id: str | None = None
    latest_backup_age_s: float | None = None
    latest_backup_valid: bool | None = None
    backup_stale_age_s: float = BACKUP_STALE_AGE_S
    latest_backup_detail: str = "no backup recorded"
    durability_tier: str = "power_loss_durable"
    durability_detail: str = "power_loss_durable"
    durability_error: str | None = None


@dataclass(frozen=True)
class DoctorRetentionStats:
    """Read-only retention expiry, GC run, and tombstone/CAS holder agreement stats."""

    last_gc_at: str | None = None
    expired_due_count: int = 0
    tombstone_holder_mismatch_count: int = 0
    mismatch_detail: str = ""
    check_skipped_reason: str | None = None


@dataclass(frozen=True)
class DoctorJevStats:
    """Passive, network-free Jev accounting and configuration summary."""

    key_configured: bool = False
    provider_invocations: int = 0
    fallback_rate: float | None = None
    total_cost_spent: str | None = None
    cost_ceiling: str | None = None
    price_drift_detected: bool = False
    recent_latency_ms: float | None = None


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
    ancestor_permission_problems: tuple[str, ...] = ()
    backup_permission_problems: tuple[str, ...] = ()
    daemon_stats: DoctorDaemonStats | None = None
    identity_stats: DoctorIdentityStats | None = None
    storage_stats: DoctorStorageStats | None = None
    retention_stats: DoctorRetentionStats | None = None
    privacy_canaries: tuple[PrivacyCanaryProbeResult, ...] = ()
    privacy_rescan: PrivacyRescanSummary | None = None
    capture_probe_result: CaptureDoctorProbeResult | None = None
    jev_stats: DoctorJevStats | None = None
    limits: DoctorScanLimits = DoctorScanLimits()


class DoctorSnapshotReaderPort(Protocol):
    """Port implemented by storage to read a ``DoctorSnapshot`` with zero mutations."""

    def read_snapshot(
        self,
        data_root: Path,
        *,
        db_root: Path | None = None,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: PrivacyScannerPort | None = None,
        capture_probe: CaptureDoctorProbePort | None = None,
        limits: DoctorScanLimits | None = None,
    ) -> DoctorSnapshot: ...
