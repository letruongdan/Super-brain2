"""One disk-full mapping everywhere: the shared helpers, and the sites that used to map it on their own (or not)."""

import errno
import shutil
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_maintenance_backup
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import migrate_database
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS, Migration
from tests.storage.conftest import Env, maintenance_lease
from tests.support.fs import digest_tree

ERROR_DISK_FULL = 112
STORE_V2 = (*STORE_MIGRATIONS, Migration(to_version=2, min_reader_version=1, apply=lambda db: None))


def os_err(code: int, winerror: int | None = None) -> OSError:
    err = OSError(code, "injected")
    if winerror is not None:
        err.winerror = winerror  # settable; simulates Windows on every platform
    return err


def sqlite_err(code: int | None) -> sqlite3.Error:
    exc = sqlite3.OperationalError("injected")
    if code is not None:
        exc.sqlite_errorcode = code  # what the sqlite3 module sets on SQLite errors
    return exc


@pytest.mark.parametrize(
    ("err", "sharing_busy", "code"),
    [
        (os_err(errno.ENOSPC), False, ErrorCode.STORAGE_FULL),
        (os_err(errno.EDQUOT), False, ErrorCode.STORAGE_FULL),
        (os_err(errno.EIO, ERROR_DISK_FULL), False, ErrorCode.STORAGE_FULL),
        (os_err(errno.EACCES, 32), True, ErrorCode.FILESYSTEM_BUSY),
        (os_err(errno.EACCES, 5), True, ErrorCode.FILESYSTEM_BUSY),
        (os_err(errno.EACCES, 32), False, ErrorCode.IO_ERROR),
        (os_err(errno.ENOSPC, 32), True, ErrorCode.STORAGE_FULL),
        (os_err(errno.EIO), False, ErrorCode.IO_ERROR),
        (os_err(errno.EIO), True, ErrorCode.IO_ERROR),
    ],
)
def test_os_error_mapping(err: OSError, sharing_busy: bool, code: ErrorCode) -> None:
    from superbrain.storage.errors import os_error

    mapped = os_error("doing it", err, sharing_busy=sharing_busy)
    assert mapped.code is code and "doing it" in mapped.message


@pytest.mark.parametrize(
    ("errorcode", "busy", "code"),
    [
        (sqlite3.SQLITE_FULL, False, ErrorCode.STORAGE_FULL),
        (sqlite3.SQLITE_FULL, True, ErrorCode.STORAGE_FULL),
        (sqlite3.SQLITE_BUSY, True, ErrorCode.STORE_BUSY),
        (sqlite3.SQLITE_LOCKED, True, ErrorCode.STORE_BUSY),
        (sqlite3.SQLITE_BUSY | (2 << 8), True, ErrorCode.STORE_BUSY),  # SQLITE_BUSY_SNAPSHOT: extended code
        (sqlite3.SQLITE_BUSY, False, ErrorCode.IO_ERROR),
        (sqlite3.SQLITE_IOERR, False, ErrorCode.IO_ERROR),
        (None, True, ErrorCode.IO_ERROR),
    ],
)
def test_sqlite_error_mapping(errorcode: int | None, busy: bool, code: ErrorCode) -> None:
    from superbrain.storage.errors import sqlite_error

    mapped = sqlite_error("doing it", sqlite_err(errorcode), busy=busy)
    assert mapped.code is code and "doing it" in mapped.message


def test_a_real_sqlite_full_maps_to_storage_full() -> None:
    from superbrain.storage.errors import sqlite_error

    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE t (x BLOB)")
        db.execute(f"PRAGMA max_page_count = {db.execute('PRAGMA page_count').fetchone()[0]}")
        with pytest.raises(sqlite3.Error) as e:
            db.execute("INSERT INTO t VALUES (?)", (bytes(100_000),))
    finally:
        db.close()
    assert sqlite_error("inserting", e.value).code is ErrorCode.STORAGE_FULL


def cap_database(db: sqlite3.Connection) -> None:
    """Forbid the live connection ``db`` to grow: the next write that needs a new page is ``SQLITE_FULL``."""
    db.execute(f"PRAGMA max_page_count = {db.execute('PRAGMA page_count').fetchone()[0]}")


def test_sqlite_full_during_a_ledger_append_is_storage_full(env: Env) -> None:
    cap_database(env.store._db)
    with pytest.raises(BrainError) as e:
        for i in range(10_000):
            with env.store.transaction() as t:
                t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": i})
    assert e.value.code is ErrorCode.STORAGE_FULL
    assert isinstance(e.value.__cause__, sqlite3.Error)


def test_a_transaction_sqlite_rolled_back_refuses_further_appends(env: Env) -> None:
    cap_database(env.store._db)
    with pytest.raises(BrainError) as committed, env.store.transaction() as t:
        with pytest.raises(BrainError) as e:
            for i in range(10_000):
                t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": i})
        assert e.value.code is ErrorCode.STORAGE_FULL
        with pytest.raises(AssertionError, match="rolled it back"):
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": -1})
    assert committed.value.code is ErrorCode.IO_ERROR  # the COMMIT finds no transaction: nothing was written
    assert list(env.store.entries()) == []


def test_sqlite_full_while_recording_a_policy_intent_is_storage_full(env: Env) -> None:
    cap_database(env.policy._db)
    with pytest.raises(BrainError) as e:
        for i in range(10_000):
            env.policy.record_intent(IntentKind.QUARANTINE, {"digest": f"sha256:{i:064x}"})
    assert e.value.code is ErrorCode.STORAGE_FULL


def failing_copy(err: OSError, when: Callable[[Path], bool]) -> Callable[[Path, Path], object]:
    real = shutil.copyfile

    def copy(src: Path, dst: Path) -> object:
        if when(Path(dst)):
            raise err
        return real(src, dst)

    return copy


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_disk_full_while_copying_for_a_maintenance_backup_is_storage_full(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    monkeypatch.setattr(shutil, "copyfile", failing_copy(OSError(code, "injected"), lambda dst: True))
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        create_maintenance_backup(root, lease, os_adapters(), target="store", now=os_adapters().clock.now())
    assert e.value.code is ErrorCode.STORAGE_FULL and isinstance(e.value.__cause__, OSError)


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_disk_full_while_copying_into_the_migration_stage_is_storage_full(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    store_dir = DataRoot.at(trusted_tmp).store_dir
    before = digest_tree(store_dir)
    in_stage = lambda dst: dst.parent.name.endswith(".migrating")  # noqa: E731
    monkeypatch.setattr(shutil, "copyfile", failing_copy(OSError(code, "injected"), in_stage))
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=os_adapters().clock.now())
    assert e.value.code is ErrorCode.STORAGE_FULL and isinstance(e.value.__cause__, OSError)
    assert digest_tree(store_dir) == before
