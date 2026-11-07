"""Task 4a storage adapters: strict pre-staged CAS transaction wrapper, blob stager, and idempotency store."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from types import MappingProxyType
from typing import cast

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    IDEMPOTENCY_TTL,
    IdempotencyRow,
    StagedBlob,
    StoredResult,
    is_strict_int,
    require_aware_utc,
    require_opaque_id,
)
from superbrain.ports.kernel import KernelBlobStagePort, KernelIdempotencyPort, KernelPolicyPort, KernelTx
from superbrain.ports.policy import PolicyView
from superbrain.storage._idempotency_sql import (
    advance_c4_hwm,
    delete_idempotency_rows,
    read_idempotency_row,
    select_expired_rows,
    validate_c4_clock,
    write_idempotency_row,
)
from superbrain.storage.cas import ContentStore
from superbrain.storage.kinds import RetentionClass, is_uuid
from superbrain.storage.ledger import Txn
from superbrain.storage.store import Store
from superbrain.storage.workspaces import StoreKernelTx

_HOLDER_KIND = "event"


class StrictKernelTx(StoreKernelTx):
    """Task 4 ``KernelTx`` enforcing C2: ``hold_blob`` accepts ONLY root-bound pre-staged ``StagedBlob``s.

    Never calls ``cas.put``, stages, publishes, or flushes new bytes inside a SQLite business transaction.
    """

    def __init__(
        self,
        txn: Txn,
        cas: ContentStore,
        policy: PolicyView,
        *,
        store_id: str,
        staged_blobs: Sequence[StagedBlob],
    ) -> None:
        super().__init__(txn, cas, policy)
        require_opaque_id(store_id, label="store_id")
        by_digest: dict[str, StagedBlob] = {}
        for item in staged_blobs:
            if not isinstance(item, StagedBlob):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if item.store_id != store_id:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            prev = by_digest.get(item.digest)
            if prev is not None and prev.size_bytes != item.size_bytes:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            by_digest[item.digest] = item
        self._store_id = store_id
        self._staged_by_digest = MappingProxyType(by_digest)

    def hold_blob(self, data: bytes, *, holder_id: str) -> str:
        if type(data) is not bytes or not is_uuid(holder_id):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        digest = digest_bytes(data)
        staged = self._staged_by_digest.get(digest)
        if staged is None or staged.store_id != self._store_id or staged.size_bytes != len(data):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if not self._cas.blob_intact(digest):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        try:
            self._txn.hold(digest, _HOLDER_KIND, holder_id, RetentionClass.DURABLE, None)
        except BrainError as err:
            if err.code is ErrorCode.NOT_FOUND:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
            raise
        return digest


class KernelBlobStager(KernelBlobStagePort):
    """Owner-thread CAS blob stager executing strictly outside SQLite business transactions (C2)."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def stage_blob(self, data: bytes) -> StagedBlob:
        if type(data) is not bytes:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self._store.in_transaction:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        digest = self._store.cas.put(data)
        return StagedBlob(store_id=self._store.store_id, digest=digest, size_bytes=len(data))


class KernelIdempotencyStore(KernelIdempotencyPort):
    """Operational ``store4`` idempotency store and C4 wall-clock high-water mark authority."""

    def __init__(self, store: Store, policy: KernelPolicyPort, *, policy_view: PolicyView | None = None) -> None:
        self._store = store
        self._policy = policy
        self._policy_view = policy_view if policy_view is not None else cast(PolicyView, policy)
        self._epoch_hwm_utc: datetime | None = None
        self._clock_untrusted = False

    def clock_untrusted(self) -> bool:
        return self._clock_untrusted

    def _validate_clock(self, db: sqlite3.Connection, now: datetime) -> tuple[datetime, str, str | None]:
        try:
            now_utc, now_str = require_aware_utc(now)
            durable_hwm = validate_c4_clock(db, now_utc, epoch_hwm_utc=self._epoch_hwm_utc)
        except BrainError as err:
            if err.code is ErrorCode.INTEGRITY_FAILURE:
                self._clock_untrusted = True
            raise
        self._epoch_hwm_utc = now_utc if self._epoch_hwm_utc is None else max(self._epoch_hwm_utc, now_utc)
        self._clock_untrusted = False
        return now_utc, now_str, durable_hwm

    def lookup_for_owner(self, *, principal_id: str, tool: str, key_hash: str, now: datetime) -> IdempotencyRow | None:
        with self._store.transaction() as txn:
            self._validate_clock(txn.db, now)
            return read_idempotency_row(txn.db, principal_id, tool, key_hash)

    def record_replay(self, *, row: IdempotencyRow, now: datetime) -> None:
        _ = row
        with self._store.transaction() as txn:
            _now_utc, now_str, durable_hwm = self._validate_clock(txn.db, now)
            advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)

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
        verify_raced_row: Callable[[IdempotencyRow], None],
        apply: Callable[[KernelTx], StoredResult],
    ) -> tuple[StoredResult, bool]:
        with self._store.transaction() as txn:
            now_utc, now_str, durable_hwm = self._validate_clock(txn.db, now)
            existing = read_idempotency_row(txn.db, principal_id, tool, key_hash)
            if existing is not None:
                verify_raced_row(existing)
                if now_utc < existing.committed_at_utc() + IDEMPOTENCY_TTL:
                    advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)
                    return (
                        StoredResult(
                            result_id=existing.result_id,
                            assignment_id=existing.assignment_id,
                            refs=existing.refs,
                        ),
                        True,
                    )

            strict_tx = StrictKernelTx(
                txn,
                self._store.cas,
                self._policy_view,
                store_id=self._store.store_id,
                staged_blobs=staged_blobs,
            )
            stored = apply(strict_tx)
            if not isinstance(stored, StoredResult):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            new_row = IdempotencyRow(
                principal_id=principal_id,
                tool=tool,
                key_hash=key_hash,
                request_digest_key_id=active_key_id,
                request_digest=request_digest,
                result_id=stored.result_id,
                assignment_id=stored.assignment_id,
                refs=stored.refs,
                committed_at=now_str,
            )
            write_idempotency_row(txn.db, new_row)
            advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)
        return stored, False

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        if not is_strict_int(limit) or not (1 <= limit <= 100):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._store.transaction() as txn:
            now_utc, now_str, durable_hwm = self._validate_clock(txn.db, now)
            cutoff_str = (now_utc - IDEMPOTENCY_TTL).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            candidates = select_expired_rows(txn.db, cutoff_str, limit)
            keys_to_delete: list[tuple[str, str, str]] = []
            for cand in candidates:
                if now_utc < cand.committed_at_utc() + IDEMPOTENCY_TTL:
                    continue
                if self._policy.request_digest_key_by_id(cand.request_digest_key_id) is None:
                    raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
                keys_to_delete.append((cand.principal_id, cand.tool, cand.key_hash))
            deleted = delete_idempotency_rows(txn.db, keys_to_delete)
            advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)
        return deleted
