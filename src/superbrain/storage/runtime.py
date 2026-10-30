"""Runtime start-up (spec 5.5): the one entry point that opens a data root for writing, in the fixed order.

``prepare_data_root`` -> ``acquire_writer`` -> (recovery of interrupted swaps) -> ``secure_subdirectories`` ->
policy store -> main store. Nothing touches ``store*``/``policy*`` before the lease is held, and the policy store is
open before the main store, which reconciles every policy intent as it opens.
"""

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.os import OsAdapters
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot, prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import ProjectionHandler
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration
from superbrain.storage.store import Store
from superbrain.storage.writer import WriterLease, acquire_writer


@dataclass(frozen=True)
class Runtime:
    """An open data root: the writer lease, the policy store and the main store, all on the opening thread."""

    root: DataRoot
    lease: WriterLease
    policy: PolicyStore
    store: Store
    os_: OsAdapters

    def close(self) -> None:
        """Close the store, then the policy store, then release the lease. Calling it again does nothing."""
        try:
            if not self.store.closed:
                self.store.close()
        finally:
            try:
                if not self.policy.closed:
                    self.policy.close()
            finally:
                self.lease.release()


def open_runtime(
    path: Path,
    os_: OsAdapters,
    *,
    handlers: Sequence[ProjectionHandler] = (),
    kinds: KindRegistry | None = None,
    store_migrations: Sequence[Migration] = STORE_MIGRATIONS,
    policy_migrations: Sequence[Migration] = POLICY_MIGRATIONS,
) -> Runtime:
    """Open (creating what is missing) the data root at ``path`` for writing.

    A missing policy store is created with a new store id, a missing main store with the policy store's id. A
    missing policy store next to an existing main store is ``INTEGRITY_FAILURE``, raised before anything is created.
    ``Store.open`` and ``Store.create`` reconcile the policy intents. The migration sequences are passed straight
    to ``PolicyStore`` and ``Store``. On any failure, whatever was opened is closed and the lease released before
    the error propagates.
    """
    root = prepare_data_root(path, os_)
    lease = acquire_writer(root, os_)
    policy: PolicyStore | None = None
    try:
        # Task 14: recover_interrupted_swaps(root, lease, os_) runs here, under the lease and before anything
        # touches store*/policy* (including secure_subdirectories).
        secure_subdirectories(root, lease, os_)
        if os.path.lexists(root.policy_db):
            policy = PolicyStore.open(root, lease, os_, migrations=policy_migrations)
        elif os.path.lexists(root.store_db):
            # A new policy store would silently reset trust, quarantine and tombstones for existing data.
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, "policy store missing for an existing data store; restore a policy backup"
            )
        else:
            policy = PolicyStore.create(root, lease, os_, store_id=new_id(), migrations=policy_migrations)
        registry = kinds if kinds is not None else KindRegistry(())
        if os.path.lexists(root.store_db):
            store = Store.open(root, lease, os_, policy, handlers, registry, migrations=store_migrations)
        else:
            store = Store.create(root, lease, os_, policy, handlers, registry, migrations=store_migrations)
    except BaseException as err:
        if policy is not None and not policy.closed:
            try:
                policy.close()
            except BrainError as cleanup:
                err.add_note(f"closing the policy store after the failure also failed: {cleanup}")
        lease.release()
        raise
    return Runtime(root=root, lease=lease, policy=policy, store=store, os_=os_)
