"""Runtime start-up (spec 5.5): the one entry point that opens a data root for writing, in the fixed order.

``prepare_data_root`` -> ``acquire_writer`` -> ``recover_interrupted_swaps`` -> the missing-policy guard ->
``secure_subdirectories`` -> policy store -> main store. Nothing touches ``store*``/``policy*`` before the lease is
held, and the policy store is open before the main store, which reconciles every policy intent as it opens.
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
from superbrain.storage.swap import recover_interrupted_swaps
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
        """Close the store, then the policy store, then release the lease. Once it succeeded, a new call does nothing.

        The policy store is closed even if closing the store fails, but the lease is released only once both closed
        without error: if either raises, the error propagates and the writer lock stays held (until a later
        ``close`` succeeds, or the process exits), so no other process becomes the writer while a handle of ours
        may still be open.
        """
        try:
            if not self.store.closed:
                self.store.close()
        finally:
            if not self.policy.closed:
                self.policy.close()
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

    Under the lease, swaps a crash interrupted are recovered first. Then a missing policy store next to an existing
    main store is ``INTEGRITY_FAILURE``, raised before any subdirectory or database is created. A missing policy
    store is created with a new store id, a missing main store with the policy store's id. ``Store.open`` and
    ``Store.create`` reconcile the policy intents. The migration sequences are passed straight to ``PolicyStore``
    and ``Store``. On any failure, whatever was opened is closed and the lease released before the error
    propagates; a ``BrainError`` from that close is attached to it as a note.
    """
    root = prepare_data_root(path, os_)
    lease = acquire_writer(root, os_)
    policy: PolicyStore | None = None
    try:
        recover_interrupted_swaps(root, lease, os_)
        if not os.path.lexists(root.policy_db) and os.path.lexists(root.store_db):
            # A new policy store would silently reset trust, quarantine and tombstones for existing data.
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, "policy store missing for an existing data store; restore a policy backup"
            )
        secure_subdirectories(root, lease, os_)
        if os.path.lexists(root.policy_db):
            policy = PolicyStore.open(root, lease, os_, migrations=policy_migrations)
        else:
            policy = PolicyStore.create(root, lease, os_, store_id=new_id(), migrations=policy_migrations)
        registry = kinds if kinds is not None else KindRegistry(())
        if os.path.lexists(root.store_db):
            store = Store.open(root, lease, os_, policy, handlers, registry, migrations=store_migrations)
        else:
            store = Store.create(root, lease, os_, policy, handlers, registry, migrations=store_migrations)
    except BaseException as err:
        try:
            if policy is not None and not policy.closed:
                policy.close()
        except BrainError as cleanup:
            err.add_note(f"closing the policy store after the failure also failed: {cleanup}")
        finally:
            if lease.open_handles():  # never release under an open handle; the lock stays held instead
                err.add_note(f"the writer lock stays held: {sorted(lease.open_handles())} could not be closed")
            else:
                lease.release()
        raise
    return Runtime(root=root, lease=lease, policy=policy, store=store, os_=os_)
