import sqlite3
from pathlib import Path

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.storage.schema import (
    POLICY_MIGRATIONS,
    STORE_MIGRATIONS,
    Migration,
    SchemaInfo,
    code_version,
    ensure_readable,
    ensure_writable,
    initialize,
    read_schema_info,
)
from superbrain.storage.sqlite import connect
from tests.support.fs import db_files, read_all_bytes


def pragma(db: sqlite3.Connection, name: str) -> object:
    return db.execute(f"PRAGMA {name}").fetchone()[0]


def make_db_with_meta(tmp_path: Path, *, schema_version: int, min_reader_version: int) -> Path:
    path = tmp_path / "s.db"
    db = connect(path)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.executemany(
        "INSERT INTO meta VALUES (?, ?)",
        [("schema_version", str(schema_version)), ("min_reader_version", str(min_reader_version)), ("store_id", "sid")],
    )
    db.close()
    return path


def snapshot(path: Path, *, ignore_shm: bool) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in db_files(path) if not (ignore_shm and p.name.endswith("-shm"))}


def read_unchanged(path: Path, *, live_writer: bool = False) -> SchemaInfo | None:
    """``read_schema_info`` while asserting that the file set and every file's bytes are untouched.

    With a live writer the ``-shm`` wal-index legitimately records the reader's read mark, so its bytes (not its
    existence) are exempt.
    """
    names = [p.name for p in db_files(path)]
    before = snapshot(path, ignore_shm=live_writer)
    try:
        return read_schema_info(path)
    finally:
        assert [p.name for p in db_files(path)] == names
        assert snapshot(path, ignore_shm=live_writer) == before


def checkpoint_and_remove_wal(path: Path) -> None:
    """Leave a WAL-mode database file on its own, with no ``-wal``/``-shm``."""
    db = connect(path)
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    for p in db_files(path)[1:]:
        p.unlink()


def test_connection_pragmas(tmp_path: Path) -> None:
    db = connect(tmp_path / "a.db")
    assert pragma(db, "journal_mode") == "wal" and pragma(db, "synchronous") == 2 and pragma(db, "secure_delete") == 1
    assert pragma(db, "foreign_keys") == 1 and pragma(db, "busy_timeout") == 5000
    assert db.isolation_level is None
    db.close()


def test_darwin_enables_fullfsync(tmp_path: Path) -> None:
    db = connect(tmp_path / "a.db", platform="darwin")
    assert pragma(db, "fullfsync") == 1 and pragma(db, "checkpoint_fullfsync") == 1
    db.close()


def test_other_platform_leaves_fullfsync_off(tmp_path: Path) -> None:
    db = connect(tmp_path / "a.db", platform="linux")
    assert pragma(db, "fullfsync") == 0
    db.close()


def test_readonly_keeps_journal_mode_and_rejects_writes(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    db = connect(path, readonly=True)
    assert pragma(db, "journal_mode") == "wal"
    with pytest.raises(sqlite3.OperationalError):
        db.execute("INSERT INTO meta VALUES ('x', 'y')")
    db.close()


@pytest.mark.parametrize("schema,min_reader", [(2, 1), (99, 99)])
def test_newer_schema_is_never_writable_even_if_readable(tmp_path: Path, schema: int, min_reader: int) -> None:
    path = make_db_with_meta(tmp_path, schema_version=schema, min_reader_version=min_reader)
    before = read_all_bytes(db_files(path))
    info = read_unchanged(path)
    assert info is not None
    with pytest.raises(BrainError) as e:
        ensure_writable(info, STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and read_all_bytes(db_files(path)) == before


def test_newer_schema_with_compatible_reader_is_readable(tmp_path: Path) -> None:
    info = read_unchanged(make_db_with_meta(tmp_path, schema_version=2, min_reader_version=1))
    assert info is not None
    ensure_readable(info, STORE_MIGRATIONS)


def test_incompatible_reader_version_is_unsupported(tmp_path: Path) -> None:
    info = read_unchanged(make_db_with_meta(tmp_path, schema_version=99, min_reader_version=99))
    assert info is not None
    with pytest.raises(BrainError) as e:
        ensure_readable(info, STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION


def test_older_schema_requires_explicit_migration(tmp_path: Path) -> None:
    info = read_unchanged(make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1))
    assert info is not None
    noop = Migration(1, 1, lambda db: None)
    with pytest.raises(BrainError) as e:
        ensure_writable(info, (noop, Migration(2, 1, noop.apply)))
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED


def test_current_schema_is_writable_and_readable(tmp_path: Path) -> None:
    info = read_unchanged(make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1))
    assert info == SchemaInfo(1, 1, "sid")
    ensure_writable(info, STORE_MIGRATIONS)
    ensure_readable(info, POLICY_MIGRATIONS)


def test_read_schema_info_does_not_create_wal(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    checkpoint_and_remove_wal(path)
    assert db_files(path) == [path]
    assert read_unchanged(path) == SchemaInfo(1, 1, "sid")
    assert db_files(path) == [path]


def test_read_schema_info_with_live_wal_sees_uncheckpointed_rows(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    writer = connect(path)
    writer.execute("UPDATE meta SET value='7' WHERE key='schema_version'")
    info = read_unchanged(path, live_writer=True)
    writer.close()
    assert info is not None and info.schema_version == 7


def test_stale_nonempty_wal_without_shm_is_not_touched(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    checkpoint_and_remove_wal(path)
    path.with_name(path.name + "-wal").write_bytes(bytes(range(0x30, 0x80)) * 40)
    assert read_unchanged(path) == SchemaInfo(1, 1, "sid")


def test_empty_wal_without_shm_is_not_touched(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    checkpoint_and_remove_wal(path)
    path.with_name(path.name + "-wal").write_bytes(b"")
    assert read_unchanged(path) == SchemaInfo(1, 1, "sid")


@pytest.mark.parametrize("bad", [None, " 2 ", "1_0", "+3", "-1", "\u0663", "", "x"])
@pytest.mark.parametrize("field", ["schema_version", "min_reader_version"])
def test_malformed_version_values_are_integrity_failures(tmp_path: Path, field: str, bad: str | None) -> None:
    path = tmp_path / "b.db"
    db = connect(path)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value)")
    values = {"schema_version": "3", "min_reader_version": "1", "store_id": "sid"}
    values[field] = bad  # type: ignore[assignment]
    db.executemany("INSERT INTO meta VALUES (?, ?)", list(values.items()))
    db.close()
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_schema_version_zero_is_integrity_failure(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=0, min_reader_version=0)
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_null_store_id_is_integrity_failure(tmp_path: Path) -> None:
    path = tmp_path / "b.db"
    db = connect(path)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value)")
    db.executemany(
        "INSERT INTO meta VALUES (?, ?)", [("schema_version", "1"), ("min_reader_version", "1"), ("store_id", None)]
    )
    db.close()
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_min_reader_above_schema_is_integrity_failure(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=2)
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_meta_with_wrong_columns_is_integrity_failure(tmp_path: Path) -> None:
    path = tmp_path / "w.db"
    db = connect(path)
    db.execute("CREATE TABLE meta (name TEXT, data TEXT)")
    db.close()
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_connect_rejects_when_wal_does_not_take_effect() -> None:
    with pytest.raises(BrainError) as e:
        connect(Path(":memory:"))
    assert e.value.code == ErrorCode.IO_ERROR


def test_missing_file_is_none(tmp_path: Path) -> None:
    assert read_unchanged(tmp_path / "nope.db") is None
    assert not (tmp_path / "nope.db").exists()


def test_garbage_file_is_integrity_failure(tmp_path: Path) -> None:
    path = tmp_path / "g.db"
    path.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and isinstance(e.value.__cause__, sqlite3.Error)


def test_db_without_meta_is_integrity_failure(tmp_path: Path) -> None:
    path = tmp_path / "n.db"
    db = connect(path)
    db.execute("CREATE TABLE other (x)")
    db.close()
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_meta_missing_keys_is_integrity_failure(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    db = connect(path)
    db.execute("DELETE FROM meta WHERE key='store_id'")
    db.close()
    with pytest.raises(BrainError) as e:
        read_unchanged(path)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_directory_path_is_a_brain_error(tmp_path: Path) -> None:
    with pytest.raises(BrainError) as e:
        read_schema_info(tmp_path)
    assert e.value.code in {ErrorCode.IO_ERROR, ErrorCode.INTEGRITY_FAILURE}


def test_initialize_writes_meta_and_runs_migrations(tmp_path: Path) -> None:
    ran: list[int] = []

    def v1(db: sqlite3.Connection) -> None:
        ran.append(1)
        db.execute("CREATE TABLE t (x)")

    def v2(db: sqlite3.Connection) -> None:
        ran.append(2)

    migrations = (Migration(1, 1, v1), Migration(2, 2, v2))
    path = tmp_path / "i.db"
    db = connect(path)
    sid = new_id()
    initialize(db, migrations, store_id=sid)
    db.close()
    assert ran == [1, 2]
    assert read_unchanged(path) == SchemaInfo(2, 2, sid)


def test_initialize_is_atomic_on_failing_migration(tmp_path: Path) -> None:
    def bad(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE t (x)")
        raise RuntimeError("boom")

    db = connect(tmp_path / "i.db")
    with pytest.raises(RuntimeError):
        initialize(db, (Migration(1, 1, bad),), store_id="s")
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    db.close()
    assert tables == []


def test_initialize_refuses_existing_meta(tmp_path: Path) -> None:
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1)
    db = connect(path)
    with pytest.raises(AssertionError):
        initialize(db, STORE_MIGRATIONS, store_id="s")
    assert not db.in_transaction
    db.close()


def test_initialize_on_real_migrations(tmp_path: Path) -> None:
    for name, migrations in (("store", STORE_MIGRATIONS), ("policy", POLICY_MIGRATIONS)):
        db = connect(tmp_path / f"{name}.db")
        initialize(db, migrations, store_id="s")
        db.close()
        assert read_unchanged(tmp_path / f"{name}.db") == SchemaInfo(1, 1, "s")


def test_code_version_and_migration_tuples() -> None:
    assert code_version(STORE_MIGRATIONS) == 1 and code_version(POLICY_MIGRATIONS) == 1
    assert len(STORE_MIGRATIONS) == 1 and len(POLICY_MIGRATIONS) == 1
    noop = Migration(1, 1, lambda db: None)
    with pytest.raises(AssertionError):
        code_version((Migration(2, 1, noop.apply),))
    with pytest.raises(AssertionError):
        code_version((noop, Migration(3, 1, noop.apply)))
    with pytest.raises(AssertionError):
        code_version(())
