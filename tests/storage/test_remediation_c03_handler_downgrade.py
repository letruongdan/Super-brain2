"""SP1-C03: an older projection handler must not reopen (and write to) a store whose history needs a newer one.

Requirement (spec 5.4 "Gặp handler_version không biết thì dừng ... không đoán", 5.8 "Handler gặp handler_version
không biết thì báo lỗi, không đoán" and "Không hỗ trợ hạ phiên bản"; review SP1-C03; ledger C03): when the ledger
already holds entries written by handler version 2 of a kind, opening the store with that kind and handler at
version 1 is ``UNSUPPORTED_VERSION`` at open, or at the latest at the first write, before anything is written.
Live projection tables existing is no proof of compatibility. The ledger and the projections stay unchanged, and
the correct version 2 still opens, writes and rebuilds. The SQLite schema version is 1 throughout.
"""

import sqlite3
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import PolicyView
from superbrain.storage.kinds import EntryKind, FieldType, KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import LedgerEntry
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import read_schema_info

KIND = "review.count"


class Counter:
    """Sums ``n`` of every ``review.count`` entry into ``p_review_counter_state``."""

    name = "review_counter"
    kinds = frozenset({KIND})

    def __init__(self, version: int) -> None:
        self.handler_version = version

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}state (k INTEGER PRIMARY KEY CHECK (k = 1), n INTEGER NOT NULL)")
        db.execute(f"INSERT INTO {prefix}state (k, n) VALUES (1, 0)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        n = entry.meta["n"]
        assert isinstance(n, int)
        db.execute(f"UPDATE {prefix}state SET n = n + ? WHERE k = 1", (n,))


def registry(version: int) -> KindRegistry:
    return KindRegistry((EntryKind(KIND, version, {"n": FieldType.INT}, {}),))


def append(data_root: Path, version: int, n: int) -> None:
    rt = open_runtime(data_root, os_adapters(), handlers=(Counter(version),), kinds=registry(version))
    try:
        with rt.store.transaction() as txn:
            txn.append(KIND, actor="user:cli", owner_id="dan", meta={"n": n})
    finally:
        rt.close()


def committed_state(root: DataRoot) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    """The ledger rows and the counter projection rows, read from the closed database by SQLite itself."""
    con = sqlite3.connect(root.store_db)
    try:
        ledger = con.execute("SELECT * FROM ledger ORDER BY sequence").fetchall()
        projection = con.execute("SELECT * FROM p_review_counter_state").fetchall()
    finally:
        con.close()
    return ledger, projection


def open_v1_and_append(data_root: Path) -> ErrorCode | None:
    """Open with kind and handler at version 1, then append once; the refusal code, or ``None`` if it wrote."""
    try:
        rt = open_runtime(data_root, os_adapters(), handlers=(Counter(1),), kinds=registry(1))
    except BrainError as err:
        return err.code
    try:
        with rt.store.transaction() as txn:
            txn.append(KIND, actor="user:cli", owner_id="dan", meta={"n": 1})
    except BrainError as err:
        return err.code
    finally:
        rt.close()
    return None


def test_handler_downgrade_with_live_tables_is_refused_before_any_write(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    append(data_root, version=2, n=2)
    root = DataRoot.at(data_root)
    info = read_schema_info(root.store_db)
    assert info is not None and info.schema_version == 1
    ledger_before, projection_before = committed_state(root)
    assert [row[4] for row in ledger_before if row[2] == KIND] == [2]  # handler_version of the v2 entry
    assert projection_before == [(1, 2)]

    outcome = open_v1_and_append(data_root)

    assert outcome == ErrorCode.UNSUPPORTED_VERSION, (
        f"a version-1 handler reopened a store whose ledger needs version 2 (outcome {outcome})"
    )
    assert committed_state(root) == (ledger_before, projection_before), "the ledger or projection changed"


def test_the_matching_version_still_opens_writes_and_rebuilds(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    append(data_root, version=2, n=2)
    append(data_root, version=2, n=3)

    rt = open_runtime(data_root, os_adapters(), handlers=(Counter(2),), kinds=registry(2))
    try:
        assert rt.store.rebuild_projections() == len(list(rt.store.entries()))
    finally:
        rt.close()
    ledger, projection = committed_state(DataRoot.at(data_root))
    assert [row[4] for row in ledger if row[2] == KIND] == [2, 2]
    assert projection == [(1, 5)]
