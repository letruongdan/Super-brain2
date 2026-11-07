"""Task 4a storage adapters: strict pre-staged CAS transaction wrapper, blob stager, and idempotency store."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from types import MappingProxyType
from typing import TypeVar, cast

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    IDEMPOTENCY_TTL,
    IdempotencyRow,
    StagedBlob,
    StoredResult,
    is_strict_int,
    parse_canonical_utc,
    require_aware_utc,
    require_opaque_id,
)
from superbrain.ports.kernel import (
    KernelBlobStagePort,
    KernelIdempotencyPort,
    KernelPolicyPort,
    KernelStorePort,
    KernelTx,
)
from superbrain.ports.policy import PolicyView
from superbrain.storage._idempotency_sql import (
    advance_c4_hwm,
    delete_idempotency_rows,
    select_expired_rows,
    validate_c4_clock,
)
from superbrain.storage._pair_admission import verify_admitted_store_pair, verify_live_store_handle
from superbrain.storage.cas import ContentStore
from superbrain.storage.kinds import RetentionClass, is_uuid
from superbrain.storage.ledger import Txn
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store
from superbrain.storage.workspaces import StoreKernelTx

_HOLDER_KIND = "event"
_T = TypeVar("_T")


def _default_is_expired(committed_at: str | datetime, now: datetime) -> bool:
    committed_utc = (
        parse_canonical_utc(committed_at) if isinstance(committed_at, str) else require_aware_utc(committed_at)[0]
    )
    now_utc, _ = require_aware_utc(now)
    return now_utc >= committed_utc + IDEMPOTENCY_TTL


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


class StrictKernelStore(KernelStorePort):
    """Task 4 ``KernelStorePort`` running ``operation(strict_tx)`` inside one ``Store.transaction()`` (C2:81)."""

    def __init__(
        self,
        store: Store,
        policy_view: PolicyView,
        *,
        staged_blobs: Sequence[StagedBlob] = (),
        policy_store: PolicyStore | None = None,
        writer_epoch: int | None = None,
        before_body: Callable[[Txn], None] | None = None,
        after_body: Callable[[Txn], None] | None = None,
    ) -> None:
        if policy_store is not None:
            verify_admitted_store_pair(store, policy_store, writer_epoch=writer_epoch)
        else:
            verify_live_store_handle(store)
        self._store = store
        self._policy_view = policy_view
        self._staged_blobs = tuple(staged_blobs)
        self._policy_store = policy_store
        self._writer_epoch = writer_epoch
        self._before_body = before_body
        self._after_body = after_body

    def transact(self, operation: Callable[[KernelTx], _T]) -> _T:
        if self._policy_store is not None:
            verify_admitted_store_pair(self._store, self._policy_store, writer_epoch=self._writer_epoch)
        else:
            verify_live_store_handle(self._store)
        with self._store.transaction() as txn:
            if self._before_body is not None:
                self._before_body(txn)
            strict_tx = StrictKernelTx(
                txn,
                self._store.cas,
                self._policy_view,
                store_id=self._store.store_id,
                staged_blobs=self._staged_blobs,
            )
            result = operation(strict_tx)
            if self._after_body is not None:
                self._after_body(txn)
            return result


class KernelBlobStager(KernelBlobStagePort):
    """Owner-thread CAS blob stager executing strictly outside SQLite business transactions (C2)."""

    def __init__(self, store: Store) -> None:
        verify_live_store_handle(store)
        self._store = store

    def stage_blob(self, data: bytes) -> StagedBlob:
        if type(data) is not bytes:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        verify_live_store_handle(self._store)
        if self._store.in_transaction:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        digest = self._store.cas.put(data)
        return StagedBlob(store_id=self._store.store_id, digest=digest, size_bytes=len(data))


class KernelIdempotencyStore(KernelIdempotencyPort):
    """Operational ``store4`` idempotency store and C4 wall-clock high-water mark authority."""

    def __init__(
        self,
        store: Store,
        policy: KernelPolicyPort,
        *,
        policy_view: PolicyView | None = None,
        writer_epoch: int | None = None,
        is_expired: Callable[[str | datetime, datetime], bool] | None = None,
    ) -> None:
        policy_store = policy if isinstance(policy, PolicyStore) else None
        if policy_store is not None:
            verify_admitted_store_pair(store, policy_store, writer_epoch=writer_epoch)
        else:
            verify_live_store_handle(store)
        self._store = store
        self._policy = policy
        self._policy_store = policy_store
        self._policy_view = policy_view if policy_view is not None else cast(PolicyView, policy)
        self._writer_epoch = writer_epoch
        self._is_expired = is_expired if is_expired is not None else _default_is_expired
        self._epoch_hwm_utc: datetime | None = None
        self._clock_untrusted = False

    def clock_untrusted(self) -> bool:
        return self._clock_untrusted

    def _check_live(self) -> None:
        if self._policy_store is not None:
            verify_admitted_store_pair(self._store, self._policy_store, writer_epoch=self._writer_epoch)
        else:
            verify_live_store_handle(self._store)

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
        self._check_live()
        with self._store.transaction() as txn:
            self._validate_clock(txn.db, now)
            ktx = StoreKernelTx(txn, self._store.cas, self._policy_view)
            return ktx.read_idempotency(principal_id, tool, key_hash)

    def record_replay(self, *, row: IdempotencyRow, now: datetime) -> None:
        _ = row
        self._check_live()
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
        verify_raced_row: Callable[[IdempotencyRow], bool],
        apply: Callable[[KernelTx], StoredResult],
    ) -> tuple[StoredResult, bool]:
        clock_state: list[tuple[datetime, str, str | None]] = []

        def _before(txn: Txn) -> None:
            clock_state.append(self._validate_clock(txn.db, now))

        def _after(txn: Txn) -> None:
            _now_utc, now_str, durable_hwm = clock_state[0]
            advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)

        def _body(strict_tx: KernelTx) -> tuple[StoredResult, bool]:
            _now_utc, now_str, _durable_hwm = clock_state[0]
            existing = strict_tx.read_idempotency(principal_id, tool, key_hash)
            if existing is not None and verify_raced_row(existing):
                return (
                    StoredResult(
                        result_id=existing.result_id,
                        assignment_id=existing.assignment_id,
                        refs=existing.refs,
                    ),
                    True,
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
            strict_tx.save_idempotency(new_row)
            return stored, False

        strict_store = StrictKernelStore(
            self._store,
            self._policy_view,
            staged_blobs=staged_blobs,
            policy_store=self._policy_store,
            writer_epoch=self._writer_epoch,
            before_body=_before,
            after_body=_after,
        )
        return strict_store.transact(_body)

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        if not is_strict_int(limit) or not (1 <= limit <= 100):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._check_live()
        with self._store.transaction() as txn:
            now_utc, now_str, durable_hwm = self._validate_clock(txn.db, now)
            cutoff_str = (now_utc - IDEMPOTENCY_TTL).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            candidates = select_expired_rows(txn.db, cutoff_str, limit)
            keys_to_delete: list[tuple[str, str, str]] = []
            for cand in candidates:
                if not self._is_expired(cand.committed_at, now_utc):
                    continue
                if self._policy.request_digest_key_by_id(cand.request_digest_key_id) is None:
                    raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
                keys_to_delete.append((cand.principal_id, cand.tool, cand.key_hash))
            deleted = delete_idempotency_rows(txn.db, keys_to_delete)
            advance_c4_hwm(txn.db, now_str, current_hwm=durable_hwm)
        return deleted
