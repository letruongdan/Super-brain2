"""Operations run in a child interpreter by ``tests/support/crash.py``.

Started through ``runpy`` under ``python -I``: it imports only ``superbrain`` and the standard library, never
``tests``. Usage: ``crash_child.py <operation> <data_root> [args...]``. A ``BrainError`` prints ``ERROR <code>``
to stdout and exits 1; success exits 0. Later tasks add the operations their tests need to ``OPERATIONS``.
"""

import sqlite3
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import superbrain
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError
from superbrain.core.faults import pausepoint
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage.backup import create_store_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.migrate import migrate_database
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS, Migration
from superbrain.storage.store import Store
from superbrain.storage.swap import recover_interrupted_swaps
from superbrain.storage.writer import acquire_writer

# Mirrors tests/storage/conftest.py DEMO_KINDS (this file must not import tests).
_DEMO_KINDS = (*CORE_KINDS, EntryKind("demo.count", 1, {"n": FieldType.INT}, {}))
PUT_AND_HOLD_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000aa"
EVENT_ID = "0192f3a4-5b6c-7d8e-9f01-000000000e01"
EVENT_PAYLOAD = b"event payload"


class _Policy:
    """A ``PolicySource`` with nothing quarantined, tombstoned or queued."""

    def __init__(self, store_id: str) -> None:
        self.store_id = store_id

    def is_quarantined(self, digest: str) -> bool:
        return False

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        return False

    def intents(self) -> Sequence[Intent]:
        return ()


def ping(data_root: Path, args: list[str]) -> None:
    print(superbrain.__file__)


def acquire_writer_once(data_root: Path, args: list[str]) -> None:
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_):
        pass


def acquire_writer_and_pause(data_root: Path, args: list[str]) -> None:
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_):
        pausepoint("writer.held")


def create_store(data_root: Path, args: list[str]) -> None:
    """args: ``<store_id>``. Create an empty store with no projection handlers."""
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        Store.create(root, lease, os_, _Policy(args[0]), [], KindRegistry(_DEMO_KINDS)).close()


def append_demo(data_root: Path, args: list[str]) -> None:
    """args: ``<store_id>``. Open the store and append one ``demo.count`` entry with ``n = 1``."""
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.open(root, lease, os_, _Policy(args[0]), [], KindRegistry(_DEMO_KINDS))
        with store.transaction() as txn:
            txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        store.close()


def put_and_hold(data_root: Path, args: list[str]) -> None:
    """args: ``<store_id>``. Open the store and ``store_content(b"payload")`` held by event ``PUT_AND_HOLD_ID``."""
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.open(root, lease, os_, _Policy(args[0]), [], KindRegistry(_DEMO_KINDS))
        store.store_content(b"payload", "event", PUT_AND_HOLD_ID, RetentionClass.EVENT_PAYLOAD, None)
        store.close()


def seed_event(data_root: Path, args: list[str]) -> None:
    """Create the runtime and ``store_content(EVENT_PAYLOAD)`` held by ``("event", EVENT_ID)``."""
    runtime = open_runtime(data_root, os_adapters())
    try:
        runtime.store.store_content(EVENT_PAYLOAD, "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
    finally:
        runtime.close()


def tombstone_event(data_root: Path, args: list[str]) -> None:
    """Open the runtime, record a TOMBSTONE intent for ``("event", EVENT_ID)``, then reconcile the store."""
    runtime = open_runtime(data_root, os_adapters())
    try:
        runtime.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": EVENT_ID})
        runtime.store.reconcile_policy()
    finally:
        runtime.close()


def backup_store(data_root: Path, args: list[str]) -> None:
    """Open the runtime and take a ``store`` backup (the crash tests stop it at a ``backup.*`` crashpoint)."""
    runtime = open_runtime(data_root, os_adapters())
    try:
        create_store_backup(runtime.store, runtime.os_, datetime.now(UTC))
    finally:
        runtime.close()


def open_runtime_once(data_root: Path, args: list[str]) -> None:
    open_runtime(data_root, os_adapters()).close()


def _latest_backup(backups_dir: Path, kinds: tuple[str, ...]) -> Path:
    """The newest complete backup of one of ``kinds``: names are ``<kind>-<UTC stamp>-<UUIDv7>``."""
    found = []
    for entry in backups_dir.iterdir():
        kind, _, stamp_and_id = entry.name.partition("-")
        if kind in kinds and "." not in entry.name and (entry / "manifest.json").is_file():
            found.append((stamp_and_id, entry))
    if not found:
        raise AssertionError(f"no {kinds} backup in {backups_dir}")
    return max(found)[1]


def restore_from_latest(data_root: Path, args: list[str]) -> None:
    """Open the runtime, close its store and restore the newest ``store``/``store_full`` backup under its lease."""
    runtime = open_runtime(data_root, os_adapters())
    try:
        runtime.store.close()
        backup = _latest_backup(runtime.root.backups_dir, ("store", "store_full"))
        restore_store(runtime.root, runtime.lease, runtime.os_, backup, runtime.policy, datetime.now(UTC))
    finally:
        runtime.close()


def restore_policy_from_latest(data_root: Path, args: list[str]) -> None:
    """Open the runtime, close both stores and restore the newest ``policy`` backup under its lease."""
    runtime = open_runtime(data_root, os_adapters())
    try:
        store_id = runtime.store.store_id
        runtime.store.close()
        runtime.policy.close()
        backup = _latest_backup(runtime.root.backups_dir, ("policy",))
        restore_policy(runtime.root, runtime.lease, runtime.os_, backup, store_id=store_id, now=datetime.now(UTC))
    finally:
        runtime.close()


def _add_table(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE added_in_v2(a)")


def migrate_store_to_v2(data_root: Path, args: list[str]) -> None:
    """Migrate the store to a v2 that adds a table, under a maintenance lease (no Store or PolicyStore is opened)."""
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    v2 = Migration(to_version=2, min_reader_version=1, apply=_add_table)
    with acquire_writer(root, os_) as lease:
        recover_interrupted_swaps(root, lease, os_)
        secure_subdirectories(root, lease, os_)
        migrate_database(root, lease, os_, target="store", migrations=(*STORE_MIGRATIONS, v2), now=datetime.now(UTC))


OPERATIONS: dict[str, Callable[[Path, list[str]], None]] = {
    "ping": ping,
    "acquire_writer": acquire_writer_once,
    "acquire_writer_and_pause": acquire_writer_and_pause,
    "create_store": create_store,
    "append_demo": append_demo,
    "put_and_hold": put_and_hold,
    "seed_event": seed_event,
    "tombstone_event": tombstone_event,
    "backup_store": backup_store,
    "open_runtime": open_runtime_once,
    "restore_from_latest": restore_from_latest,
    "restore_policy_from_latest": restore_policy_from_latest,
    "migrate_store_to_v2": migrate_store_to_v2,
}


def main(argv: list[str]) -> int:
    # -I ignores PYTHONIOENCODING, so make the pipes UTF-8 explicitly (paths may hold non-ASCII characters).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")
    if len(argv) < 2 or argv[0] not in OPERATIONS:
        sys.stderr.write(f"usage: crash_child.py <{'|'.join(OPERATIONS)}> <data_root> [args...]\n")
        return 2
    operation, data_root, *args = argv
    try:
        OPERATIONS[operation](Path(data_root), args)
    except BrainError as err:
        print(f"ERROR {err.code.value}")
        return 1
    return 0


if __name__ == "__main__":
    # argv: ["-c", <this file>, <operation>, <data_root>, *args]
    sys.exit(main(sys.argv[2:]))
