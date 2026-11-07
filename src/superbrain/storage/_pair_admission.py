"""Admitted single-root ``(Store, PolicyStore)`` + held ``WriterLease`` verification (I2-T4A-R01)."""

from __future__ import annotations

import os
import threading

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import require_positive_int
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


def verify_live_store_handle(store: Store, *, writer_epoch: int | None = None) -> None:
    """Verify ``store`` is open on its owner thread under a held ``WriterLease`` without raising ``AssertionError``."""
    if writer_epoch is not None:
        require_positive_int(writer_epoch)
    if not isinstance(store, Store):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if store.closed or threading.get_ident() != store.owner_thread_id:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    lease = store.lease
    if not lease.held or "store" not in lease.open_handles():
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if writer_epoch is not None and lease.epoch != writer_epoch:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


def verify_admitted_store_pair(
    store: Store,
    policy: PolicyStore,
    *,
    writer_epoch: int | None = None,
) -> None:
    """Verify ``(store, policy)`` belong to one live admitted ``DataRoot`` and held ``WriterLease`` (I2-T4A-R01)."""
    if writer_epoch is not None:
        require_positive_int(writer_epoch)
    if not isinstance(store, Store) or not isinstance(policy, PolicyStore):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if policy.closed and not store.closed:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    if store.closed:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    tid = threading.get_ident()
    if tid != store.owner_thread_id or tid != policy.owner_thread_id:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    lease = store.lease
    if lease is not policy.lease or not lease.held:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    handles = lease.open_handles()
    if "policy" not in handles:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    if "store" not in handles:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if writer_epoch is not None and lease.epoch != writer_epoch:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if store.root != policy.root or store.root != lease.root:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    try:
        same_root = os.path.samefile(store.root.root, policy.root.root) and os.path.samefile(
            store.root.root, lease.root.root
        )
    except OSError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from exc
    if not same_root:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if store.store_id != policy.store_id or not store.has_policy_source(policy):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
