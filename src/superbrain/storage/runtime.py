"""Runtime start-up (spec 5.5): the one entry point that opens a data root for writing, in the fixed order.

``prepare_data_root`` -> ``acquire_writer`` -> ``recover_interrupted_swaps`` -> the missing-policy and
missing-store guards -> ``secure_subdirectories`` -> policy store -> main store. Nothing touches ``store*``/``policy*``
before the lease is held, and the policy store is open before the main store, which reconciles every policy intent as
it opens.
"""

import contextlib
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import require_opaque_id
from superbrain.ports.os import OsAdapters
from superbrain.storage.errors import os_error, sqlite_error
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import (
    DataRoot,
    check_endpoint_entries_under_lease,
    prepare_data_root,
    secure_subdirectories,
    verify_existing_data_root,
)
from superbrain.storage.ledger import ProjectionHandler
from superbrain.storage.policy_store import STORE_PUBLISHED, PolicyStore
from superbrain.storage.prune import has_complete_backup
from superbrain.storage.schema import (
    POLICY_MIGRATIONS,
    STORE_MIGRATIONS,
    Migration,
    SchemaInfo,
    code_version,
    read_schema_info,
)
from superbrain.storage.sqlite import db_files, open_readonly, remove_unfinished_reads
from superbrain.storage.store import Store
from superbrain.storage.swap import PURPOSES, READY, Target, recover_interrupted_swaps
from superbrain.storage.writer import WriterLease, acquire_writer, acquire_writer_unbumped


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


def _policy_has_history(policy_db: Path) -> bool:
    """Whether the closed ``policy_db`` (if any) records an intent or ``meta.store_published`` (the main store was
    published, C02); its committed state is read through ``open_readonly``, nothing is changed."""
    if not os.path.lexists(policy_db):
        return False
    try:
        db = open_readonly(policy_db)
        try:
            tables = {str(row[0]) for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if not {"intents", "meta"} <= tables:
                return False  # not a policy schema this code knows; PolicyStore.open reports it
            if db.execute("SELECT 1 FROM intents LIMIT 1").fetchone() is not None:
                return True
            published = "SELECT 1 FROM meta WHERE key = ? AND value = '1'"
            return db.execute(published, (STORE_PUBLISHED,)).fetchone() is not None
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise sqlite_error(f"cannot read the history of {policy_db}", exc) from exc


def _cas_has_content(cas_dir: Path) -> bool:
    """Whether ``cas/`` holds any entry. Shards and blobs are only created by ``put`` on an open store, and a blob
    is published before its ref is written and ACKed (spec 5.4): any entry shows that a ``brain.db`` existed and was
    written to. Fail closed: which of its entries were ACKed is unknowable once it is lost."""
    try:
        with os.scandir(cas_dir) as entries:
            return any(True for _ in entries)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise os_error(f"cannot list {cas_dir}", exc) from exc


def _store_has_history(root: DataRoot) -> bool:
    """History a new, empty ``brain.db`` would silently lose or orphan: a policy store with intents or the
    published-store marker, a complete store backup, or content in ``cas/`` (whose holders were in the lost
    database). If ``policy.db`` and ``brain.db`` are both lost, nothing here remains and the root looks fresh."""
    return (
        _policy_has_history(root.policy_db)
        or has_complete_backup(root.backups_dir, ("store", "store_full"))
        or _cas_has_content(root.cas_dir)
    )


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

    Under the lease, swaps a crash interrupted are recovered first and ``open_readonly`` copies a crash left behind
    are removed. Then a missing policy store next to an existing main store is ``INTEGRITY_FAILURE``, and so is a
    missing main store next to history: a policy store with intents or with ``meta.store_published``, a complete
    ``store``/``store_full`` backup, or content in ``cas/``. Both are raised before any subdirectory or database is
    created. Otherwise a missing policy store is created with a new store id, a missing main store with the policy
    store's id. ``Store.open`` and ``Store.create`` reconcile the policy intents; once either succeeded the policy
    store is marked durably (``PolicyStore.mark_store_published``, idempotent). The migration sequences are passed
    straight to ``PolicyStore`` and ``Store``. On any failure, whatever was opened is closed and the lease released
    before the error propagates; a ``BrainError`` from that close is attached to it as a note (and a handle that
    could not be closed keeps the lease held).
    """
    root = prepare_data_root(path, os_)
    lease = acquire_writer(root, os_)
    policy: PolicyStore | None = None
    store: Store | None = None
    try:
        recover_interrupted_swaps(root, lease, os_)
        remove_unfinished_reads(root.policy_db)
        remove_unfinished_reads(root.store_db)
        if not os.path.lexists(root.policy_db) and os.path.lexists(root.store_db):
            # A new policy store would silently reset trust, quarantine and tombstones for existing data.
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, "policy store missing for an existing data store; restore a policy backup"
            )
        if not os.path.lexists(root.store_db) and _store_has_history(root):
            # A new, empty store would silently drop the data the intents and backups show existed.
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE,
                "data store missing for a policy store with history; restore a store backup",
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
        policy.mark_store_published()
    except BaseException as err:
        try:
            if store is not None and not store.closed:
                store.close()
        except BrainError as cleanup:
            err.add_note(f"closing the store after the failure also failed: {cleanup}")
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


@dataclass(frozen=True)
class AdmittedWriter:
    """A verified existing data root whose writer lease has been acquired and admitted."""

    root: DataRoot
    lease: WriterLease
    os_: OsAdapters
    policy_info: SchemaInfo
    store_info: SchemaInfo

    def release(self) -> None:
        self.lease.release()

    def __enter__(self) -> "AdmittedWriter":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if not self.lease.open_handles():
            self.lease.release()


def _check_db_companions(directory: Path, db_path: Path, os_: OsAdapters) -> Path | None:
    existing_companions = [p for p in db_files(db_path) if os.path.lexists(p)]
    if existing_companions:
        os_.paths.reject_links(directory, entries=existing_companions)
        for p in existing_companions:
            if os_.permissions.object_problems(p):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"{p} is not owner-only")
    return db_path if os.path.lexists(db_path) else None


def _effective_target_db(root: DataRoot, target: Target, os_: OsAdapters) -> tuple[Path | None, Path | None]:
    live = root.store_dir if target == "store" else root.policy_dir
    db_name = "brain.db" if target == "store" else "policy.db"
    stages = [root.root / f"{target}.{p}" for p in PURPOSES if os.path.lexists(root.root / f"{target}.{p}")]
    if len(stages) > 1:
        names = ", ".join(s.name for s in stages)
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"two swaps of {target} were interrupted at once: {names}")
    extra_ready_stage_db: Path | None = None
    if stages:
        (stage,) = stages
        os_.paths.reject_links(stage)
        if not stage.is_dir():
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{stage.name} is not a directory")
        marker = stage / READY
        if os.path.lexists(live):
            if not live.is_dir():
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{live.name} is not a directory")
            effective_dir = live
            if os.path.lexists(marker):
                os_.paths.reject_links(marker)
                if os.path.isfile(marker):
                    if os_.permissions.object_problems(marker):
                        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"{marker} is not owner-only")
                    extra_ready_stage_db = _check_db_companions(stage, stage / db_name, os_)
                    if extra_ready_stage_db is None:
                        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{stage.name} marked {READY} without {db_name}")
        else:
            os_.paths.reject_links(marker)
            if not os.path.isfile(marker):
                raise BrainError(
                    ErrorCode.INTEGRITY_FAILURE,
                    f"{target}/ is missing and {stage.name} was never marked {READY}",
                )
            if os_.permissions.object_problems(marker):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"{marker} is not owner-only")
            effective_dir = stage
    else:
        if not os.path.lexists(live):
            return None, None
        if not live.is_dir():
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{live.name} is not a directory")
        effective_dir = live

    return _check_db_companions(effective_dir, effective_dir / db_name, os_), extra_ready_stage_db


def _ensure_scratch_base(base: Path, root: Path, os_: OsAdapters) -> None:
    os_.paths.reject_unsafe_path(str(base))
    if base == root or root in base.parents or base in root.parents:
        raise BrainError(ErrorCode.UNSAFE_PATH, "pre-admission scratch directory must be outside data_root")
    os_.paths.reject_links(base)
    anc = os_.permissions.check_ancestors(base)
    if anc:
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch ancestor is not trusted: {anc[0].path}")

    missing: list[Path] = []
    for candidate in (base, *base.parents):
        if os.path.lexists(candidate):
            break
        missing.append(candidate)
    else:
        raise BrainError(ErrorCode.IO_ERROR, f"no existing directory ancestor is available for {base}")

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            os_.paths.reject_links(directory)
            if not directory.is_dir():
                raise BrainError(ErrorCode.INVALID_INPUT, f"scratch base {directory} is not a directory") from None
            if os_.permissions.object_problems(directory):
                raise BrainError(
                    ErrorCode.INSECURE_PERMISSIONS, f"scratch base {directory} is not owner-only"
                ) from None
        except OSError as exc:
            raise os_error(f"cannot create scratch base {directory}", exc) from exc
        else:
            os_.paths.reject_links(directory)
            os_.permissions.secure_directory(directory)

    os_.paths.reject_links(base)
    anc = os_.permissions.check_ancestors(base)
    if anc:
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch ancestor is not trusted: {anc[0].path}")
    if not base.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, f"scratch base {base} is not a directory")
    if os_.permissions.object_problems(base):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch base {base} is not owner-only")


@contextlib.contextmanager
def _preadmission_scratch(root: Path, os_: OsAdapters, scratch_base: Path | None) -> Iterator[Path]:
    default_base = os_.traits.resolved_default_scratch_base() if scratch_base is None else None
    if scratch_base is not None:
        os_.paths.reject_unsafe_path(str(scratch_base))
        base: Path | None = Path(os.path.abspath(scratch_base))
    elif default_base is not None:
        os_.paths.reject_unsafe_path(str(default_base))
        base = Path(os.path.abspath(default_base))
    else:
        base = None

    if base is None:
        raw_tmp = os_.traits.resolved_temp_dir()
        if raw_tmp is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "no pre-admission scratch temp_dir is configured")
        os_.paths.reject_unsafe_path(str(raw_tmp))
        tmp_dir = raw_tmp.resolve() if os_.traits.resolve_temp_links else Path(os.path.abspath(raw_tmp))
        os_.paths.reject_unsafe_path(str(tmp_dir))
        if tmp_dir == root or root in tmp_dir.parents:
            raise BrainError(ErrorCode.UNSAFE_PATH, "pre-admission scratch directory must be outside data_root")
        os_.paths.reject_links(tmp_dir)
        try:
            work = Path(os.path.abspath(tempfile.mkdtemp(prefix="superbrain-admit-", dir=str(tmp_dir))))
        except OSError as exc:
            raise os_error(f"cannot create scratch directory in {tmp_dir}", exc) from exc
        try:
            if work == root or root in work.parents or work in root.parents:
                raise BrainError(ErrorCode.UNSAFE_PATH, "pre-admission scratch directory must be outside data_root")
            os_.paths.reject_links(work)
            anc = os_.permissions.check_ancestors(work)
            if anc:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch ancestor is not trusted: {anc[0].path}")
            if not work.is_dir():
                raise BrainError(ErrorCode.INVALID_INPUT, f"scratch directory {work} is not a directory")
            os_.permissions.secure_directory(work)
            if os_.permissions.object_problems(work):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch directory {work} is not owner-only")
            yield work
        finally:
            with contextlib.suppress(OSError):
                shutil.rmtree(work)
        return

    _ensure_scratch_base(base, root, os_)
    work = base / f"admit-{new_id()}"
    try:
        work.mkdir(mode=0o700)
    except OSError as exc:
        raise os_error(f"cannot create scratch directory {work}", exc) from exc
    try:
        os_.paths.reject_links(work)
        os_.permissions.secure_directory(work)
        if os_.permissions.object_problems(work):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"scratch directory {work} is not owner-only")
        yield work
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(work)


def _check_pair_admission(
    policy_info: SchemaInfo,
    store_info: SchemaInfo,
    *,
    expected_store_id: str,
    purpose: Literal["serve", "migrate"],
    policy_migrations: Sequence[Migration],
    store_migrations: Sequence[Migration],
) -> None:
    if policy_info.store_id != store_info.store_id:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "policy and store belong to different store_ids")
    if policy_info.store_id != expected_store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "store_id does not match expected_store_id")
    target_policy = code_version(policy_migrations)
    target_store = code_version(store_migrations)
    if policy_info.schema_version > target_policy or policy_info.min_reader_version > target_policy:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"policy schema {policy_info.schema_version} exceeds code version {target_policy}",
        )
    if store_info.schema_version > target_store or store_info.min_reader_version > target_store:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"store schema {store_info.schema_version} exceeds code version {target_store}",
        )
    if purpose == "serve" and (
        policy_info.schema_version < target_policy or store_info.schema_version < target_store
    ):
        raise BrainError(
            ErrorCode.MIGRATION_REQUIRED,
            f"pair ({policy_info.schema_version}, {store_info.schema_version}) requires offline migration "
            f"to ({target_policy}, {target_store})",
        )


def admit_existing_pair(
    path: Path,
    expected_store_id: str,
    os_: OsAdapters,
    *,
    purpose: Literal["serve", "migrate"],
    store_migrations: Sequence[Migration] = KERNEL_STORE_MIGRATIONS,
    policy_migrations: Sequence[Migration] = KERNEL_POLICY_MIGRATIONS,
    scratch_base: Path | None = None,
) -> AdmittedWriter:
    """Verify and admit an existing ``(policy, store)`` pair before mutating ``writer.lock`` or swaps."""
    require_opaque_id(expected_store_id, label="expected_store_id")
    if purpose not in ("serve", "migrate"):
        raise BrainError(ErrorCode.INVALID_INPUT, f"unknown admission purpose {purpose!r}")
    code_version(policy_migrations)
    code_version(store_migrations)

    root = verify_existing_data_root(path, os_)
    lease = acquire_writer_unbumped(root, os_)
    try:
        check_endpoint_entries_under_lease(root, lease, os_)
        eff_policy_db, extra_policy_stage = _effective_target_db(root, "policy", os_)
        eff_store_db, extra_store_stage = _effective_target_db(root, "store", os_)
        if eff_policy_db is None and eff_store_db is None:
            if _cas_has_content(root.cas_dir) or has_complete_backup(root.backups_dir, ("store", "store_full")):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "databases missing for data root with history")
            raise BrainError(ErrorCode.NOT_FOUND, f"no initialized databases at {root.root}")
        if eff_policy_db is None or eff_store_db is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "incomplete policy/store database pair")

        with _preadmission_scratch(root.root, os_, scratch_base) as scratch_dir:
            policy_info = read_schema_info(eff_policy_db, scratch_dir=scratch_dir)
            store_info = read_schema_info(eff_store_db, scratch_dir=scratch_dir)
            extra_stage_checks = (
                (extra_policy_stage, policy_migrations),
                (extra_store_stage, store_migrations),
            )
            for extra_db, migs in extra_stage_checks:
                if extra_db is None:
                    continue
                extra_info = read_schema_info(extra_db, scratch_dir=scratch_dir)
                if extra_info is None:
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"stage database missing at {extra_db}")
                if extra_info.store_id != expected_store_id:
                    raise BrainError(ErrorCode.IDENTITY_MISMATCH, "stage store_id does not match expected_store_id")
                max_ver = code_version(migs)
                if extra_info.schema_version > max_ver or extra_info.min_reader_version > max_ver:
                    raise BrainError(
                        ErrorCode.UNSUPPORTED_VERSION,
                        f"stage schema {extra_info.schema_version} exceeds code version {max_ver}",
                    )
        if policy_info is None or store_info is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "effective policy or store database missing")

        _check_pair_admission(
            policy_info,
            store_info,
            expected_store_id=expected_store_id,
            purpose=purpose,
            policy_migrations=policy_migrations,
            store_migrations=store_migrations,
        )

        # Admission passed: now record the new writer_epoch and complete any compatible interrupted swaps.
        lease.bump_epoch()
        recover_interrupted_swaps(root, lease, os_)
        remove_unfinished_reads(root.policy_db)
        remove_unfinished_reads(root.store_db)
        secure_subdirectories(root, lease, os_)

        live_policy = read_schema_info(root.policy_db)
        live_store = read_schema_info(root.store_db)
        if live_policy is None or live_store is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "live policy or store missing after swap recovery")
        _check_pair_admission(
            live_policy,
            live_store,
            expected_store_id=expected_store_id,
            purpose=purpose,
            policy_migrations=policy_migrations,
            store_migrations=store_migrations,
        )
    except BaseException:
        lease.release()
        raise

    return AdmittedWriter(
        root=root,
        lease=lease,
        os_=os_,
        policy_info=live_policy,
        store_info=live_store,
    )


def open_runtime_under_lease(
    admitted: AdmittedWriter,
    *,
    handlers: Sequence[ProjectionHandler] = (),
    kinds: KindRegistry | None = None,
    store_migrations: Sequence[Migration] = KERNEL_STORE_MIGRATIONS,
    policy_migrations: Sequence[Migration] = KERNEL_POLICY_MIGRATIONS,
) -> Runtime:
    """Open existing ``PolicyStore`` and ``Store`` under an already-admitted ``AdmittedWriter`` lease."""
    root, lease, os_ = admitted.root, admitted.lease, admitted.os_
    if not lease.held or lease.root != root:
        raise AssertionError("open_runtime_under_lease requires a held admitted writer lease")
    policy: PolicyStore | None = None
    store: Store | None = None
    try:
        policy = PolicyStore.open(root, lease, os_, migrations=policy_migrations)
        registry = kinds if kinds is not None else KindRegistry(())
        store = Store.open(root, lease, os_, policy, handlers, registry, migrations=store_migrations)
        policy.mark_store_published()
    except BaseException as err:
        try:
            if store is not None and not store.closed:
                store.close()
        except BrainError as cleanup:
            err.add_note(f"closing the store after the failure also failed: {cleanup}")
        try:
            if policy is not None and not policy.closed:
                policy.close()
        except BrainError as cleanup:
            err.add_note(f"closing the policy store after the failure also failed: {cleanup}")
        finally:
            if lease.open_handles():
                err.add_note(f"the writer lock stays held: {sorted(lease.open_handles())} could not be closed")
            else:
                lease.release()
        raise
    return Runtime(root=root, lease=lease, policy=policy, store=store, os_=os_)
