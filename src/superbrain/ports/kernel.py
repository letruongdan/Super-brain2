"""Kernel ports shared across storage, adapters and application layers.

``KernelPolicyPort`` is the only workspace authority (policy DB). ``WorkspaceMirrorReadPort`` reads the main-store
registry mirror for audit/preview candidates and is deliberately disjoint from it: authorization code never takes
the mirror port, so a stale or forged mirror row can neither grant access nor mint IDs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol, TypeVar

from superbrain.core.kernel import (
    AuthSnapshot,
    BootstrapAuthorization,
    FieldLineage,
    KernelRecord,
    LineageRef,
    LineageSet,
    MirrorCandidate,
    Principal,
    Scope,
    SnapshotObservation,
    SourceSnapshot,
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

    def record_authorized_revocation(
        self, credential_id: str, authorization: BootstrapAuthorization
    ) -> Intent:
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

    def hold_blob(self, data: bytes, *, holder_id: str) -> str:
        """Publish ``data`` durably (verified if already present), then hold it for ``holder_id``; its digest."""
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


class KernelStorePort(Protocol):
    def transact(self, operation: Callable[[KernelTx], _T]) -> _T:
        """Run ``operation`` inside one ``Store.transaction()``: all of it commits or none of it does."""
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
