"""Kernel ports shared across storage, adapters and application layers.

``KernelPolicyPort`` is the only workspace authority (policy DB). ``WorkspaceMirrorReadPort`` reads the main-store
registry mirror for audit/preview candidates and is deliberately disjoint from it: authorization code never takes
the mirror port, so a stale or forged mirror row can neither grant access nor mint IDs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Protocol, TypeVar

from superbrain.core.kernel import (
    ArtifactReadAck,
    ArtifactSendAttempt,
    ArtifactSendSpec,
    AuthSnapshot,
    BootstrapAuthorization,
    FieldLineage,
    IdempotencyRow,
    Identity,
    InvocationRecord,
    InvocationState,
    JobRecord,
    KernelRecord,
    LineageRef,
    LineageSet,
    MirrorCandidate,
    Principal,
    RequestAuthView,
    RetentionClass,
    Scope,
    SendAttemptCompletion,
    SnapshotObservation,
    SourceSnapshot,
    StagedBlob,
    StoredResult,
    TaskBinding,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.ports.policy import Intent

_T = TypeVar("_T")


class KernelPolicyPort(Protocol):
    """Read/write authority interface over the policy database (``policy/policy.db``)."""

    def resolve_credential(self, token: str) -> Principal:
        """Resolve ``<credential_uuidv7>.<base64url>`` to an active ``Principal``."""
        ...

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        """Return True iff ``principal`` is active and authorized for ``scope`` and ``action``."""
        ...

    def snapshot(self) -> AuthSnapshot:
        """Return an immutable point-in-time snapshot of principals, credentials, grants, and checkouts."""
        ...

    def record_authorized_revocation(self, credential_id: str, authorization: BootstrapAuthorization) -> Intent:
        """Commit an authorized ``credential_revoke`` intent and mark ``credential_id`` revoked."""
        ...

    def register_authorized_workspace(
        self, registration: WorkspaceRegistration, authorization: BootstrapAuthorization
    ) -> WorkspaceBinding:
        """Commit an authorized workspace registration, repo grant, and ``workspace_register`` intent."""
        ...

    def request_digest_key(self) -> tuple[str, bytes]:
        """Return the active ``(key_id, key_bytes)`` 32-byte per-store HMAC secret."""
        ...

    def request_digest_key_by_id(self, key_id: str) -> bytes | None:
        """Return the 32-byte HMAC secret for ``key_id`` (active or retained), or ``None`` if absent."""
        ...


class SnapshotObserver(Protocol):
    """Optional, bounded observation of an approved binding; never runs project code, Git or the network."""

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        """Observe ``binding`` by monotonic ``deadline_ns``: ``DEADLINE`` when the budget ran out first."""
        ...


class KernelTx(Protocol):
    """One business write transaction on the main store (``Store.transaction()``), typed records only."""

    def append_record(self, record: KernelRecord) -> None:
        """Validate and append ``record`` to the ledger, applying every projection in the same transaction."""
        ...

    def hold_blob(
        self,
        data: bytes,
        *,
        holder_id: str,
        retention: RetentionClass = RetentionClass.DURABLE,
        expires_at: datetime | str | None = None,
    ) -> str:
        """Publish ``data`` (verified if already present), then hold it for ``holder_id`` under ``retention``."""
        ...

    def blob_restricted(self, digest: str) -> bool:
        """True iff policy blocks the blob ``digest`` (quarantined)."""
        ...

    def holder_tombstoned(self, holder_id: str) -> bool:
        """True iff policy tombstoned the business holder ``holder_id`` (a snapshot, say)."""
        ...

    def snapshot_held(self, snapshot_id: str, descriptor_digest: str) -> bool:
        """True iff the exact hold ``(event, snapshot_id, descriptor_digest)`` currently exists."""
        ...

    def blob_present(self, digest: str) -> bool:
        """True iff the blob ``digest`` exists in CAS and hashes to its digest."""
        ...

    def find_source_snapshots(self, checkout_id: str, descriptor_digest: str) -> tuple[SourceSnapshot, ...]:
        """Every recorded snapshot of ``checkout_id`` with this content, oldest first."""
        ...

    def read_source_snapshot(self, snapshot_id: str) -> SourceSnapshot | None: ...

    def read_task_binding(self, task_id: str) -> TaskBinding | None: ...

    def read_task_lineage(self, task_id: str) -> tuple[LineageSet, bool]:
        """``(sources, unknown)`` of ``task_id``; both only ever grow."""
        ...

    def read_field_lineage(self, task_id: str) -> Mapping[str, FieldLineage]:
        """Field lineage of ``task_id`` keyed by ``field_path_digest``."""
        ...

    def read_idempotency(self, principal_id: str, tool: str, key_hash: str) -> IdempotencyRow | None:
        """Read the operational idempotency row for ``(principal_id, tool, key_hash)``, if present."""
        ...

    def save_idempotency(self, row: IdempotencyRow) -> None:
        """Persist or atomically replace the operational idempotency row inside the write transaction."""
        ...

    def read_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt | None:
        """Read the operational ``artifact_send_attempt`` row by primary key ``send_attempt_id``."""
        ...

    def read_read_ack_by_receipt(self, served_receipt_id: str) -> ArtifactReadAck | None:
        """Read the operational ``artifact_read_ack`` row by unique ``served_receipt_id``."""
        ...

    def save_read_ack(self, ack: ArtifactReadAck) -> None:
        """Insert ``ack`` into ``artifact_read_ack`` inside the caller's ``Store.transaction()``."""
        ...

    def release_blob(self, digest: str, *, holder_id: str, reason: str) -> None:
        """Release the ``event`` hold of ``holder_id`` on ``digest`` (reason ``expired`` only); absent hold: no-op."""
        ...

    def read_held_blob(
        self,
        digest: str,
        *,
        holder_id: str,
        holder_kind: str = "event",
        now: datetime | None = None,
    ) -> bytes | None:
        """Bytes of ``digest`` iff actively held by ``(holder_kind, holder_id)`` at ``now`` and not restricted."""
        ...

    def read_job(self, job_id: str) -> JobRecord | None:
        """The ``p_jobs_state`` row of ``job_id``, if present."""
        ...

    def read_invocation(self, invocation_id: str) -> InvocationRecord | None:
        """The ``p_provider_invocations_state`` row of ``invocation_id``, if present."""
        ...

    def read_job_accounting_states(self, job_id: str) -> frozenset[InvocationState]:
        """Distinct ``InvocationState`` values recorded for ``job_id`` across every invocation."""
        ...

    def due_jobs(self, now: datetime, limit: int) -> tuple[JobRecord, ...]:
        """Up to ``limit`` queued jobs with ``retry_at <= now``, in ``(retry_at, job_id)`` order."""
        ...

    def due_jobs_by_kinds(
        self, now: datetime, kinds: Sequence[str], limit: int, *, exclude: bool = False
    ) -> tuple[JobRecord, ...]:
        """Up to ``limit`` queued jobs matching (or excluding) ``kinds`` with ``retry_at <= now``."""
        ...

    def active_jobs_by_kinds(self, kinds: Sequence[str], limit: int) -> tuple[JobRecord, ...]:
        """Up to ``limit`` ``queued|leased|running`` jobs matching ``kinds`` in ``(sequence, job_id)`` order."""
        ...

    def claimed_jobs_by_kinds(self, kinds: Sequence[str], epoch: int, limit: int) -> tuple[JobRecord, ...]:
        """Up to ``limit`` ``leased|running`` jobs matching ``kinds`` leased in writer ``epoch``, by ``job_id``."""
        ...

    def stale_jobs(self, epoch: int, limit: int) -> tuple[JobRecord, ...]:
        """Up to ``limit`` ``leased|running`` jobs whose lease epoch is older than ``epoch``, by ``job_id``."""
        ...

    def unsettled_invocations(self, epoch: int, limit: int) -> tuple[InvocationRecord, ...]:
        """Up to ``limit`` ``reserved`` invocations whose epoch is older than ``epoch``, by ``invocation_id``."""
        ...

    def expired_dead_letters(self, cutoff: datetime, limit: int) -> tuple[JobRecord, ...]:
        """Up to ``limit`` ``dead_letter`` jobs finished at or before ``cutoff``, by ``(finished_at, job_id)``."""
        ...


class KernelStorePort(Protocol):
    def transact(self, operation: Callable[[KernelTx], _T]) -> _T:
        """Run ``operation`` inside one ``Store.transaction()``: all of it commits or none of it does."""
        ...


class KernelBlobStagePort(Protocol):
    """Owner-thread CAS pre-staging port outside SQLite business transactions (C2)."""

    def stage_blob(self, data: bytes) -> StagedBlob:
        """Durably stage safe ``data`` into CAS outside any SQLite transaction and return its ``StagedBlob``."""
        ...


class RequestAuthStatePort(Protocol):
    """Read-only port over the owner-published RAM ``RequestAuthView`` (C3)."""

    def current(self) -> RequestAuthView | None:
        """Return the currently published ``RequestAuthView`` for this root, or ``None`` if unavailable."""
        ...


class KernelIdempotencyPort(Protocol):
    """Owner-thread operational idempotency and C4 wall-clock high-water mark port over ``store4``."""

    def clock_untrusted(self) -> bool:
        """True iff C4 detected wall-clock regression or missing/corrupt watermark state."""
        ...

    def lookup_for_owner(self, *, principal_id: str, tool: str, key_hash: str, now: datetime) -> IdempotencyRow | None:
        """Validate C4 wall clock at ``now`` and read ``(principal_id, tool, key_hash)``."""
        ...

    def record_replay(self, *, row: IdempotencyRow, now: datetime) -> None:
        """Advance the durable C4 operational watermark on replay without altering ``row.committed_at``."""
        ...

    def commit_prepared_effect(
        self,
        *,
        staged_blobs: Sequence[StagedBlob],
        principal_id: str,
        tool: str,
        key_hash: str,
        active_key_id: str,
        request_digest: str,
        now: datetime,
        verify_raced_row: Callable[[IdempotencyRow], bool],
        apply: Callable[[KernelTx], StoredResult],
    ) -> tuple[StoredResult, bool]:
        """Atomically execute ``apply(strict_tx)``, persist the idempotency row, and advance the C4 watermark.

        Returns ``(stored_result, was_live_replay)``.
        """
        ...

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        """Validate C4 clock + retained keys and delete at most ``limit`` (`1..100`) expired idempotency rows."""
        ...


class KernelSendAttemptPort(Protocol):
    """Owner-thread operational send-attempt audit port over ``store4`` ``artifact_send_attempt`` (C5)."""

    def record_pending_attempt(self, spec: ArtifactSendSpec) -> ArtifactSendAttempt:
        """Persist a fresh ``pending`` ``artifact_send_attempt`` row in its own owner transaction."""
        ...

    def read_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt | None:
        """Read ``artifact_send_attempt`` by primary key ``send_attempt_id``."""
        ...

    def finalize_attempt(
        self,
        completion: SendAttemptCompletion,
        *,
        expected_identity: Identity,
    ) -> ArtifactSendAttempt:
        """Fence ``completion`` against ``expected_identity`` and subject, moving ``pending -> served_only``."""
        ...

    def interrupt_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt:
        """Record an interrupted flush as ``pending -> unknown`` (idempotent on ``unknown``)."""
        ...

    def recover_pending_attempts(self) -> int:
        """Transition all ``pending`` ``artifact_send_attempt`` rows to ``unknown`` on reopen/recovery."""
        ...


class WorkspaceMirrorReadPort(Protocol):
    """Main-store ``p_workspace_registry_*`` mirror: non-authoritative candidates for audit and I3 preview."""

    def mirror_candidates(
        self, *, alias: str | None = None, checkout_id: str | None = None
    ) -> tuple[MirrorCandidate, ...]: ...


class SourceRestrictionPort(Protocol):
    def is_restricted(self, ref: LineageRef) -> bool:
        """True iff the source of ``ref`` is quarantined, tombstoned, missing or cannot be resolved (any kind)."""
        ...


class PolicyAccountingPort(Protocol):
    """Self-contained ``policy.db`` accounting authority over reservations, usage settlements, and epochs."""

    def reserve_accounting_invocation(
        self,
        *,
        invocation_id: str,
        job_id: str,
        owner_id: str,
        writer_epoch: int,
        max_amount: str,
        now: datetime,
    ) -> object: ...

    def settle_accounting_invocation(
        self,
        *,
        invocation_id: str,
        amount: str | None,
        complete: bool,
        now: datetime,
    ) -> object: ...

    def recover_accounting_epochs(self, *, current_epoch: int, now: datetime) -> int: ...
