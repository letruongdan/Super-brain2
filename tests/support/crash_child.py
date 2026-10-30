"""Operations run in a child interpreter by ``tests/support/crash.py``.

Started through ``runpy`` under ``python -I``: it imports only ``superbrain`` and the standard library, never
``tests``. Usage: ``crash_child.py <operation> <data_root> [args...]``. A ``BrainError`` prints ``ERROR <code>``
to stdout and exits 1; success exits 0. Later tasks add the operations their tests need to ``OPERATIONS``.
"""

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import superbrain
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError
from superbrain.core.faults import pausepoint
from superbrain.ports.policy import Intent
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.store import Store
from superbrain.storage.writer import acquire_writer

# Mirrors tests/storage/conftest.py DEMO_KINDS (this file must not import tests).
_DEMO_KINDS = (*CORE_KINDS, EntryKind("demo.count", 1, {"n": FieldType.INT}, {}))
PUT_AND_HOLD_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000aa"


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


OPERATIONS: dict[str, Callable[[Path, list[str]], None]] = {
    "ping": ping,
    "acquire_writer": acquire_writer_once,
    "acquire_writer_and_pause": acquire_writer_and_pause,
    "create_store": create_store,
    "append_demo": append_demo,
    "put_and_hold": put_and_hold,
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
