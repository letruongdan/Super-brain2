"""PlatformTraits and OsAdapters.traits behavioural regressions for I2-OS-01 (Rules 2-5)."""

from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters, PermissionGuard, PermissionProblem
from superbrain.storage.backup import (
    create_maintenance_backup,
    create_policy_backup,
    create_store_backup,
)
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import prepare_data_root
from superbrain.storage.migrate import _configure, migrate_database
from superbrain.storage.restore import restore_policy
from superbrain.storage.runtime import admit_existing_pair, open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, code_version
from superbrain.storage.sqlite import connect
from tests.storage.conftest import DEMO_KINDS, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree, fake_link

if TYPE_CHECKING:
    from superbrain.ports.os import PlatformTraits

_PRAGMA_SET_RE = re.compile(
    r"^\s*PRAGMA\s+(?:main\.)?([a-zA-Z_]+)\s*=\s*([a-zA-Z0-9_]+)\s*$",
    re.IGNORECASE,
)


def _make_traits(
    *,
    sqlite_full_fsync: bool = False,
    restrict_umask: bool = False,
    default_scratch_base: Path | Callable[[], Path | None] | None = None,
    resolve_temp_links: bool = False,
    temp_dir: Path | Callable[[], Path] | None = None,
) -> PlatformTraits:
    from superbrain.ports.os import PlatformTraits as _PlatformTraits

    return _PlatformTraits(
        sqlite_full_fsync=sqlite_full_fsync,
        restrict_umask=restrict_umask,
        default_scratch_base=default_scratch_base,
        resolve_temp_links=resolve_temp_links,
        temp_dir=temp_dir,
    )


def _os_with_traits(base: OsAdapters, traits: PlatformTraits) -> OsAdapters:
    return dataclasses.replace(base, traits=traits)


def _pragma_int(db: sqlite3.Connection, name: str) -> int:
    row = db.execute(f"PRAGMA {name}").fetchone()
    assert row is not None
    return int(row[0])


def _make_probe_apply(table_name: str) -> Callable[[sqlite3.Connection], None]:
    def apply(db: sqlite3.Connection) -> None:
        db.execute(f"CREATE TABLE {table_name} (id INTEGER PRIMARY KEY)")

    return apply


@dataclass
class _TracedConnection:
    target: str
    readonly: bool
    conn: sqlite3.Connection
    statements: list[str]


def _install_sqlite_tracer(monkeypatch: pytest.MonkeyPatch) -> list[_TracedConnection]:
    real_connect: Callable[..., sqlite3.Connection] = sqlite3.connect
    traced: list[_TracedConnection] = []

    def tracing_connect(
        database: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: object,
        **kwargs: object,
    ) -> sqlite3.Connection:
        conn = real_connect(database, *args, **kwargs)
        raw_target: str | bytes = os.fspath(database)
        target = raw_target.decode("utf-8", errors="surrogateescape") if isinstance(raw_target, bytes) else raw_target
        readonly = bool(kwargs.get("uri")) and ("immutable=1" in target or "mode=ro" in target)
        record = _TracedConnection(target=target, readonly=readonly, conn=conn, statements=[])
        conn.set_trace_callback(record.statements.append)
        traced.append(record)
        return conn

    monkeypatch.setattr(sqlite3, "connect", tracing_connect)
    return traced


def _open_connections_by_path(traced: Sequence[_TracedConnection]) -> dict[Path, sqlite3.Connection]:
    found: dict[Path, sqlite3.Connection] = {}
    for record in traced:
        if record.readonly:
            continue
        rows: list[tuple[object, ...]] | None = None
        try:
            rows = record.conn.execute("PRAGMA database_list").fetchall()
        except sqlite3.ProgrammingError:
            rows = None
        if rows is None:
            continue
        for _seq, name, filename in rows:
            if name == "main" and isinstance(filename, str) and filename:
                found[Path(filename).resolve()] = record.conn
    return found


def _parsed_pragmas(statements: Sequence[str]) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for stmt in statements:
        for chunk in stmt.split(";"):
            match = _PRAGMA_SET_RE.match(chunk)
            if match is None:
                continue
            name = match.group(1).lower()
            raw_val = match.group(2).upper()
            if name == "synchronous":
                canonical = "FULL" if raw_val in {"FULL", "2"} else raw_val
            elif raw_val in {"ON", "TRUE", "YES", "1"}:
                canonical = "ON"
            elif raw_val in {"OFF", "FALSE", "NO", "0"}:
                canonical = "OFF"
            else:
                canonical = raw_val
            parsed.setdefault(name, []).append(canonical)
    return parsed


def _assert_traced_durability_pragmas(
    statements: Sequence[str],
    *,
    require_foreign_keys: bool,
    expect_full_fsync: bool,
) -> None:
    pragmas = _parsed_pragmas(statements)
    assert pragmas.get("synchronous", [])[-1:] == ["FULL"], (pragmas, statements)
    assert pragmas.get("secure_delete", [])[-1:] == ["ON"], (pragmas, statements)
    if require_foreign_keys:
        assert pragmas.get("foreign_keys", [])[-1:] == ["ON"], (pragmas, statements)
    if expect_full_fsync:
        assert pragmas.get("fullfsync", [])[-1:] == ["ON"], (pragmas, statements)
        assert pragmas.get("checkpoint_fullfsync", [])[-1:] == ["ON"], (pragmas, statements)
    else:
        assert "ON" not in pragmas.get("fullfsync", []), (pragmas, statements)
        assert "ON" not in pragmas.get("checkpoint_fullfsync", []), (pragmas, statements)


def _find_snapshot_connection(traced: Sequence[_TracedConnection], expected_db: Path) -> _TracedConnection:
    resolved_expected = expected_db.resolve()
    direct = [r for r in traced if not r.readonly and Path(r.target).resolve() == resolved_expected]
    if direct:
        assert len(direct) == 1
        return direct[0]
    backup_dir = expected_db.parent.resolve()
    staged = [
        r
        for r in traced
        if not r.readonly
        and backup_dir in Path(r.target).resolve().parents
        and not any(part.startswith(".work-") for part in Path(r.target).parts)
    ]
    assert len(staged) == 1, [r.target for r in traced]
    return staged[0]


class _PermissionSpy:
    """Delegates to the real ``PermissionGuard`` while recording ``secure_directory`` calls."""

    def __init__(self, real: PermissionGuard) -> None:
        self._real = real
        self.secured_dirs: list[Path] = []

    def secure_directory(self, path: Path) -> None:
        self.secured_dirs.append(path)
        self._real.secure_directory(path)

    def secure_file(self, path: Path) -> None:
        self._real.secure_file(path)

    def problems(self, root: Path) -> list[PermissionProblem]:
        return self._real.problems(root)

    def object_problems(self, path: Path) -> list[PermissionProblem]:
        return self._real.object_problems(path)

    def check_ancestors(self, path: Path) -> list[PermissionProblem]:
        return self._real.check_ancestors(path)


def _build_uncheckpointed_wal_root(
    root_path: Path, os_: OsAdapters
) -> tuple[str, Callable[[], None]]:
    """Create a v3 root with uncheckpointed WAL frames and no ``-shm``, plus a reset callback."""
    rt = open_runtime(
        root_path,
        os_,
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt.store.store_id
    rt.store.store_content(b"wal-scratch-probe", "artifact", new_id(), RetentionClass.DURABLE, None)
    rt.close()

    store_db = root_path / "store" / "brain.db"
    wal_file = root_path / "store" / "brain.db-wal"
    shm_file = root_path / "store" / "brain.db-shm"
    conn = sqlite3.connect(store_db, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('noop_probe', '1')")
        conn.execute("COMMIT")
        raw_main = store_db.read_bytes()
        raw_wal = wal_file.read_bytes()
    finally:
        conn.close()

    def reset_wal_without_shm() -> None:
        store_db.write_bytes(raw_main)
        wal_file.write_bytes(raw_wal)
        if shm_file.exists():
            shm_file.unlink()
        os_.permissions.secure_file(store_db)
        os_.permissions.secure_file(wal_file)
        assert wal_file.stat().st_size > 32 and not shm_file.exists()

    reset_wal_without_shm()
    return store_id, reset_wal_without_shm


# --- Rule 2: SQLite durability pragmas across all durable writers ------------------------------------------------


def test_host_os_adapters_populates_platform_traits(os_: OsAdapters) -> None:
    sample = _make_traits()
    traits: PlatformTraits = os_.traits
    assert isinstance(traits, type(sample))
    assert traits.sqlite_full_fsync is (sys.platform == "darwin")
    assert traits.restrict_umask is (sys.platform != "win32")
    assert traits.resolve_temp_links is (sys.platform == "darwin")
    frozen_field = "sqlite_full_fsync"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(traits, frozen_field, not traits.sqlite_full_fsync)


def test_sqlite_connect_pragmas_follow_injected_traits(tmp_path: Path) -> None:
    for full in (True, False):
        traits = _make_traits(
            sqlite_full_fsync=full,
            restrict_umask=False,
            default_scratch_base=None,
            resolve_temp_links=False,
            temp_dir=tmp_path,
        )
        db = connect(tmp_path / f"conn-{int(full)}.db", traits=traits)
        try:
            assert _pragma_int(db, "synchronous") == 2
            assert _pragma_int(db, "secure_delete") == 1
            assert _pragma_int(db, "foreign_keys") == 1
            assert _pragma_int(db, "fullfsync") == int(full)
            assert _pragma_int(db, "checkpoint_fullfsync") == int(full)
        finally:
            db.close()


def test_open_runtime_applies_durability_pragmas_to_store_and_policy(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    traced = _install_sqlite_tracer(monkeypatch)
    for full in (True, False):
        tmp_dir = trusted_tmp / f"rt-tmp-{int(full)}"
        tmp_dir.mkdir()
        os_.permissions.secure_directory(tmp_dir)
        custom_os = _os_with_traits(
            os_,
            _make_traits(
                sqlite_full_fsync=full,
                restrict_umask=False,
                default_scratch_base=None,
                resolve_temp_links=False,
                temp_dir=tmp_dir,
            ),
        )
        root_dir = trusted_tmp / f"rt-root-{int(full)}"
        for phase in ("create", "reopen"):
            traced.clear()
            rt = open_runtime(root_dir, custom_os)
            try:
                open_by_path = _open_connections_by_path(traced)
                store_conn = open_by_path[rt.root.store_db.resolve()]
                policy_conn = open_by_path[rt.root.policy_db.resolve()]
                for label, conn in (("store", store_conn), ("policy", policy_conn)):
                    assert _pragma_int(conn, "synchronous") == 2, (phase, full, label)
                    assert _pragma_int(conn, "secure_delete") == 1, (phase, full, label)
                    assert _pragma_int(conn, "foreign_keys") == 1, (phase, full, label)
                    assert _pragma_int(conn, "fullfsync") == int(full), (phase, full, label)
                    assert _pragma_int(conn, "checkpoint_fullfsync") == int(full), (phase, full, label)
            finally:
                rt.close()


def test_migration_staging_executes_durability_pragmas_from_traits(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    traced = _install_sqlite_tracer(monkeypatch)
    for full in (True, False):
        tmp_dir = trusted_tmp / f"mig-tmp-{int(full)}"
        tmp_dir.mkdir()
        os_.permissions.secure_directory(tmp_dir)
        traits = _make_traits(
            sqlite_full_fsync=full,
            restrict_umask=False,
            default_scratch_base=None,
            resolve_temp_links=False,
            temp_dir=tmp_dir,
        )
        custom_os = _os_with_traits(os_, traits)

        # Direct _configure(db, traits) compatibility seam.
        traced.clear()
        direct_db = sqlite3.connect(tmp_dir / "direct-configure.db")
        try:
            _configure(direct_db, traits)
            assert _pragma_int(direct_db, "synchronous") == 2
            assert _pragma_int(direct_db, "secure_delete") == 1
            assert _pragma_int(direct_db, "foreign_keys") == 1
            assert _pragma_int(direct_db, "fullfsync") == int(full)
            assert _pragma_int(direct_db, "checkpoint_fullfsync") == int(full)
        finally:
            direct_db.close()
        assert len(traced) == 1
        _assert_traced_durability_pragmas(
            traced[0].statements, require_foreign_keys=True, expect_full_fsync=full
        )

        # migrate_database on both store and policy targets.
        mig_root = trusted_tmp / f"mig-db-{int(full)}"
        open_runtime(
            mig_root,
            custom_os,
            store_migrations=STORE_MIGRATIONS,
            policy_migrations=POLICY_MIGRATIONS,
        ).close()

        store_marker = f"mig_store_probe_{int(full)}"
        store_v2 = (
            *STORE_MIGRATIONS,
            Migration(
                to_version=2,
                min_reader_version=1,
                apply=_make_probe_apply(store_marker),
            ),
        )
        clock.advance(timedelta(seconds=5))
        traced.clear()
        with maintenance_lease(mig_root, custom_os) as (mroot, mlease):
            migrate_database(mroot, mlease, custom_os, target="store", migrations=store_v2, now=clock.now())
        matched_store = [r for r in traced if any(store_marker in s for s in r.statements)]
        assert len(matched_store) == 1
        ddl_idx = next(i for i, s in enumerate(matched_store[0].statements) if store_marker in s)
        _assert_traced_durability_pragmas(
            matched_store[0].statements[:ddl_idx], require_foreign_keys=True, expect_full_fsync=full
        )

        policy_marker = f"mig_policy_probe_{int(full)}"
        policy_v2 = (
            *POLICY_MIGRATIONS,
            Migration(
                to_version=2,
                min_reader_version=1,
                apply=_make_probe_apply(policy_marker),
            ),
        )
        clock.advance(timedelta(seconds=5))
        traced.clear()
        with maintenance_lease(mig_root, custom_os) as (mroot, mlease):
            migrate_database(mroot, mlease, custom_os, target="policy", migrations=policy_v2, now=clock.now())
        matched_policy = [r for r in traced if any(policy_marker in s for s in r.statements)]
        assert len(matched_policy) == 1
        pol_ddl_idx = next(i for i, s in enumerate(matched_policy[0].statements) if policy_marker in s)
        _assert_traced_durability_pragmas(
            matched_policy[0].statements[:pol_ddl_idx], require_foreign_keys=True, expect_full_fsync=full
        )

        # Offline two-target migration (exercises staged file migration path for policy & store).
        off_root = trusted_tmp / f"mig-offline-{int(full)}"
        rt_off = open_runtime(
            off_root,
            custom_os,
            store_migrations=STORE_MIGRATIONS,
            policy_migrations=POLICY_MIGRATIONS,
        )
        off_store_id = rt_off.store.store_id
        rt_off.close()

        next_pol_ver = code_version(KERNEL_POLICY_MIGRATIONS) + 1
        next_str_ver = code_version(KERNEL_STORE_MIGRATIONS) + 1
        off_pol_marker = f"off_pol_probe_{int(full)}"
        off_str_marker = f"off_str_probe_{int(full)}"
        off_pol_seq = (
            *KERNEL_POLICY_MIGRATIONS,
            Migration(
                to_version=next_pol_ver,
                min_reader_version=next_pol_ver,
                apply=_make_probe_apply(off_pol_marker),
            ),
        )
        off_str_seq = (
            *KERNEL_STORE_MIGRATIONS,
            Migration(
                to_version=next_str_ver,
                min_reader_version=next_str_ver,
                apply=_make_probe_apply(off_str_marker),
            ),
        )
        cfg = DaemonConfig(
            version=1,
            data_root=off_root,
            expected_store_id=off_store_id,
            cert_path=tmp_dir / "unused.pem",
            key_path=tmp_dir / "unused.key",
        )
        clock.advance(timedelta(seconds=5))
        traced.clear()
        migrate_offline(cfg, custom_os, policy_migrations=off_pol_seq, store_migrations=off_str_seq)
        for marker in (off_pol_marker, off_str_marker):
            matched = [r for r in traced if any(marker in s for s in r.statements)]
            assert len(matched) == 1
            idx = next(i for i, s in enumerate(matched[0].statements) if marker in s)
            _assert_traced_durability_pragmas(
                matched[0].statements[:idx], require_foreign_keys=True, expect_full_fsync=full
            )


def test_backup_snapshot_targets_execute_durability_pragmas_from_traits(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    traced = _install_sqlite_tracer(monkeypatch)
    for full in (True, False):
        tmp_dir = trusted_tmp / f"bak-tmp-{int(full)}"
        tmp_dir.mkdir()
        os_.permissions.secure_directory(tmp_dir)
        custom_os = _os_with_traits(
            os_,
            _make_traits(
                sqlite_full_fsync=full,
                restrict_umask=False,
                default_scratch_base=None,
                resolve_temp_links=False,
                temp_dir=tmp_dir,
            ),
        )
        root_dir = trusted_tmp / f"bak-root-{int(full)}"
        rt = open_runtime(root_dir, custom_os)
        try:
            clock.advance(timedelta(seconds=5))
            traced.clear()
            store_bak = create_store_backup(rt.store, custom_os, clock.now())
            store_snap = _find_snapshot_connection(traced, store_bak / "brain.db")
            _assert_traced_durability_pragmas(
                store_snap.statements, require_foreign_keys=False, expect_full_fsync=full
            )

            clock.advance(timedelta(seconds=5))
            traced.clear()
            pol_bak = create_policy_backup(rt.policy, custom_os, clock.now())
            pol_snap = _find_snapshot_connection(traced, pol_bak / "policy.db")
            _assert_traced_durability_pragmas(
                pol_snap.statements, require_foreign_keys=False, expect_full_fsync=full
            )
        finally:
            rt.close()

        clock.advance(timedelta(seconds=5))
        traced.clear()
        with maintenance_lease(root_dir, custom_os) as (mroot, mlease):
            maint_store_bak = create_maintenance_backup(
                mroot, mlease, custom_os, target="store", now=clock.now()
            )
        maint_store_snap = _find_snapshot_connection(traced, maint_store_bak / "brain.db")
        _assert_traced_durability_pragmas(
            maint_store_snap.statements, require_foreign_keys=False, expect_full_fsync=full
        )

        clock.advance(timedelta(seconds=5))
        traced.clear()
        with maintenance_lease(root_dir, custom_os) as (mroot, mlease):
            maint_pol_bak = create_maintenance_backup(
                mroot, mlease, custom_os, target="policy", now=clock.now()
            )
        maint_pol_snap = _find_snapshot_connection(traced, maint_pol_bak / "policy.db")
        _assert_traced_durability_pragmas(
            maint_pol_snap.statements, require_foreign_keys=False, expect_full_fsync=full
        )


def test_restore_policy_staged_db_executes_durability_pragmas_from_traits(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    traced = _install_sqlite_tracer(monkeypatch)
    for full in (True, False):
        tmp_dir = trusted_tmp / f"res-tmp-{int(full)}"
        tmp_dir.mkdir()
        os_.permissions.secure_directory(tmp_dir)
        custom_os = _os_with_traits(
            os_,
            _make_traits(
                sqlite_full_fsync=full,
                restrict_umask=False,
                default_scratch_base=None,
                resolve_temp_links=False,
                temp_dir=tmp_dir,
            ),
        )
        root_dir = trusted_tmp / f"res-root-{int(full)}"
        rt = open_runtime(root_dir, custom_os)
        store_id = rt.store.store_id
        clock.advance(timedelta(seconds=5))
        pol_bak = create_policy_backup(rt.policy, custom_os, clock.now())
        rt.close()

        clock.advance(timedelta(seconds=5))
        traced.clear()
        with maintenance_lease(root_dir, custom_os) as (mroot, mlease):
            restore_policy(mroot, mlease, custom_os, pol_bak, store_id=store_id, now=clock.now())
        writable = [r for r in traced if not r.readonly]
        assert len(writable) == 1, [r.target for r in traced]
        _assert_traced_durability_pragmas(
            writable[0].statements, require_foreign_keys=False, expect_full_fsync=full
        )


# --- Rule 3: POSIX umask via traits.restrict_umask ---------------------------------------------------------------


def test_prepare_data_root_umask_follows_restrict_umask_trait(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, object]] = []
    real_path_mkdir = Path.mkdir
    real_os_mkdir = os.mkdir

    def spy_umask(mask: int) -> int:
        events.append(("umask", mask))
        return 0o022

    def spy_path_mkdir(
        self: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False
    ) -> None:
        events.append(("mkdir", self))
        real_path_mkdir(self, mode=mode, parents=parents, exist_ok=exist_ok)

    def spy_os_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        raw = os.fspath(path)
        text = raw.decode("utf-8", errors="surrogateescape") if isinstance(raw, bytes) else raw
        events.append(("mkdir", Path(text)))
        if dir_fd is None:
            real_os_mkdir(path, mode=mode)
        else:
            real_os_mkdir(path, mode=mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "umask", spy_umask)
    monkeypatch.setattr(Path, "mkdir", spy_path_mkdir)
    monkeypatch.setattr(os, "mkdir", spy_os_mkdir)

    # restrict_umask=True: os.umask(0o077) called BEFORE creating missing parent or target root.
    posix_parent = trusted_tmp / "posix-umask-parent"
    posix_target = posix_parent / "root"
    posix_os = _os_with_traits(
        os_,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=True,
            default_scratch_base=None,
            resolve_temp_links=False,
            temp_dir=trusted_tmp,
        ),
    )
    prepared_posix = prepare_data_root(posix_target, posix_os)
    assert prepared_posix.root == posix_target and posix_target.is_dir()
    umask_indices = [i for i, (kind, val) in enumerate(events) if kind == "umask" and val == 0o077]
    mkdir_indices = [
        i
        for i, (kind, val) in enumerate(events)
        if kind == "mkdir" and val in {posix_parent, posix_target}
    ]
    assert umask_indices, f"expected os.umask(0o077), got {events}"
    assert mkdir_indices, f"expected mkdir for {posix_target}, got {events}"
    assert umask_indices[0] < mkdir_indices[0], f"os.umask must precede mkdir, got {events}"
    assert [val for kind, val in events if kind == "umask"] == [0o077] * len(umask_indices)

    # restrict_umask=False: os.umask is never called.
    events.clear()
    win_target = trusted_tmp / "win-umask-parent" / "root"
    win_os = _os_with_traits(
        os_,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=None,
            resolve_temp_links=False,
            temp_dir=trusted_tmp,
        ),
    )
    prepared_win = prepare_data_root(win_target, win_os)
    assert prepared_win.root == win_target and win_target.is_dir()
    assert [e for e in events if e[0] == "umask"] == []


# --- Rules 4 & 5: Pre-admission scratch precedence, temp link resolution, and in-root refusal --------------------


def test_preadmission_scratch_precedence_and_link_resolution_follow_traits(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    wal_root = trusted_tmp / "wal-root"
    store_id, reset_wal = _build_uncheckpointed_wal_root(wal_root, os_)
    traced = _install_sqlite_tracer(monkeypatch)
    perm_spy = _PermissionSpy(os_.permissions)
    spied_base_os = dataclasses.replace(os_, permissions=perm_spy)

    def scratch_db_paths() -> list[Path]:
        resolved_root = wal_root.resolve()
        return [
            Path(r.target).resolve()
            for r in traced
            if not r.readonly and resolved_root not in Path(r.target).resolve().parents
        ]

    # Precedence 1: explicit scratch_base wins over default_scratch_base and temp_dir.
    explicit_dir = trusted_tmp / "explicit-scratch"
    unused_default_1 = trusted_tmp / "unused-default-1"
    unused_tmp_1 = trusted_tmp / "unused-tmp-1"
    unused_tmp_1.mkdir()
    os_.permissions.secure_directory(unused_tmp_1)

    reset_wal()
    perm_spy.secured_dirs.clear()
    traced.clear()
    os_p1 = _os_with_traits(
        spied_base_os,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=unused_default_1,
            resolve_temp_links=False,
            temp_dir=unused_tmp_1,
        ),
    )
    admitted = admit_existing_pair(wal_root, store_id, os_p1, purpose="serve", scratch_base=explicit_dir)
    admitted.release()
    assert any(p == explicit_dir or explicit_dir in p.parents for p in perm_spy.secured_dirs)
    assert any(explicit_dir.resolve() in db_p.parents for db_p in scratch_db_paths())
    assert not unused_default_1.exists()
    assert not any(p == unused_tmp_1 or unused_tmp_1 in p.parents for p in perm_spy.secured_dirs)

    # Precedence 2: scratch_base=None with default_scratch_base set uses default_scratch_base (static & callable).
    win_scratch_dir = trusted_tmp / "win-default-scratch"
    unused_tmp_2 = trusted_tmp / "unused-tmp-2"
    unused_tmp_2.mkdir()
    os_.permissions.secure_directory(unused_tmp_2)

    reset_wal()
    perm_spy.secured_dirs.clear()
    traced.clear()
    os_p2 = _os_with_traits(
        spied_base_os,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=win_scratch_dir,
            resolve_temp_links=False,
            temp_dir=unused_tmp_2,
        ),
    )
    admitted = admit_existing_pair(wal_root, store_id, os_p2, purpose="serve", scratch_base=None)
    admitted.release()
    assert any(p == win_scratch_dir or win_scratch_dir in p.parents for p in perm_spy.secured_dirs)
    assert any(win_scratch_dir.resolve() in db_p.parents for db_p in scratch_db_paths())
    assert not any(p == unused_tmp_2 or unused_tmp_2 in p.parents for p in perm_spy.secured_dirs)

    win_callable_dir = trusted_tmp / "win-callable-scratch"
    reset_wal()
    perm_spy.secured_dirs.clear()
    traced.clear()
    os_p2_callable = _os_with_traits(
        spied_base_os,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=lambda: win_callable_dir,
            resolve_temp_links=False,
            temp_dir=unused_tmp_2,
        ),
    )
    admitted = admit_existing_pair(wal_root, store_id, os_p2_callable, purpose="serve", scratch_base=None)
    admitted.release()
    assert any(p == win_callable_dir or win_callable_dir in p.parents for p in perm_spy.secured_dirs)
    assert any(win_callable_dir.resolve() in db_p.parents for db_p in scratch_db_paths())

    # Precedence 3: scratch_base=None and default_scratch_base=None creates an admit scratch dir inside temp_dir.
    posix_tmp_dir = trusted_tmp / "posix-tmp"
    posix_tmp_dir.mkdir()
    os_.permissions.secure_directory(posix_tmp_dir)

    reset_wal()
    perm_spy.secured_dirs.clear()
    traced.clear()
    os_p3 = _os_with_traits(
        spied_base_os,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=None,
            resolve_temp_links=False,
            temp_dir=posix_tmp_dir,
        ),
    )
    admitted = admit_existing_pair(wal_root, store_id, os_p3, purpose="serve", scratch_base=None)
    admitted.release()
    admit_dirs = [
        p for p in perm_spy.secured_dirs if posix_tmp_dir in p.parents and "admit" in p.name.lower()
    ]
    assert admit_dirs, f"expected an admit scratch dir inside {posix_tmp_dir}, got {perm_spy.secured_dirs}"
    assert any(posix_tmp_dir.resolve() in db_p.parents for db_p in scratch_db_paths())
    assert list(posix_tmp_dir.iterdir()) == []

    # Link resolution: resolve_temp_links=True resolves temp_dir via .resolve(), whereas False keeps abspath.
    alias_tmp = trusted_tmp / "alias-tmp"
    real_private_tmp = trusted_tmp / "real-private-tmp"
    alias_tmp.mkdir()
    real_private_tmp.mkdir()
    os_.permissions.secure_directory(alias_tmp)
    os_.permissions.secure_directory(real_private_tmp)

    real_path_resolve = Path.resolve
    resolve_calls: list[Path] = []

    def spy_resolve(self: Path, strict: bool = False) -> Path:
        if self == alias_tmp:
            resolve_calls.append(self)
            return real_private_tmp
        return real_path_resolve(self, strict=strict)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "resolve", spy_resolve)

        # resolve_temp_links=True resolves alias_tmp -> real_private_tmp (even if alias_tmp is a link).
        with mp.context() as link_mp:
            fake_link(link_mp, alias_tmp)
            reset_wal()
            perm_spy.secured_dirs.clear()
            resolve_calls.clear()
            traced.clear()
            os_resolve_true = _os_with_traits(
                spied_base_os,
                _make_traits(
                    sqlite_full_fsync=False,
                    restrict_umask=False,
                    default_scratch_base=None,
                    resolve_temp_links=True,
                    temp_dir=alias_tmp,
                ),
            )
            admitted = admit_existing_pair(
                wal_root, store_id, os_resolve_true, purpose="serve", scratch_base=None
            )
            admitted.release()
        assert resolve_calls, "expected temp_dir.resolve() when resolve_temp_links=True"
        assert any(real_private_tmp in p.parents and "admit" in p.name.lower() for p in perm_spy.secured_dirs)
        assert not any(alias_tmp in p.parents for p in perm_spy.secured_dirs)

        # resolve_temp_links=False normalizes via abspath without resolving alias_tmp -> real_private_tmp.
        reset_wal()
        perm_spy.secured_dirs.clear()
        resolve_calls.clear()
        traced.clear()
        os_resolve_false = _os_with_traits(
            spied_base_os,
            _make_traits(
                sqlite_full_fsync=False,
                restrict_umask=False,
                default_scratch_base=None,
                resolve_temp_links=False,
                temp_dir=alias_tmp / "dotseg" / "..",
            ),
        )
        admitted = admit_existing_pair(
            wal_root, store_id, os_resolve_false, purpose="serve", scratch_base=None
        )
        admitted.release()
        assert any(alias_tmp in p.parents and "admit" in p.name.lower() for p in perm_spy.secured_dirs)
        assert not any(real_private_tmp in p.parents for p in perm_spy.secured_dirs)


def test_preadmission_scratch_refuses_in_root_candidates_across_all_sources(
    trusted_tmp: Path, os_: OsAdapters
) -> None:
    wal_root = trusted_tmp / "wal-inroot-refusal"
    store_id, reset_wal = _build_uncheckpointed_wal_root(wal_root, os_)
    safe_tmp = trusted_tmp / "safe-tmp"
    safe_tmp.mkdir()
    os_.permissions.secure_directory(safe_tmp)

    reset_wal()
    snap_before = digest_tree(wal_root)

    # 1. Explicit scratch_base inside wal_root (and equal to wal_root).
    safe_os = _os_with_traits(
        os_,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=trusted_tmp / "safe-default",
            resolve_temp_links=False,
            temp_dir=safe_tmp,
        ),
    )
    for bad_explicit in (wal_root / "sub", wal_root):
        with pytest.raises(BrainError) as exc_explicit:
            admit_existing_pair(wal_root, store_id, safe_os, purpose="serve", scratch_base=bad_explicit)
        assert exc_explicit.value.code is ErrorCode.UNSAFE_PATH
        assert digest_tree(wal_root) == snap_before

    # 2. traits.default_scratch_base inside wal_root (scratch_base=None).
    bad_default_os = _os_with_traits(
        os_,
        _make_traits(
            sqlite_full_fsync=False,
            restrict_umask=False,
            default_scratch_base=wal_root / "sub",
            resolve_temp_links=False,
            temp_dir=safe_tmp,
        ),
    )
    with pytest.raises(BrainError) as exc_default:
        admit_existing_pair(wal_root, store_id, bad_default_os, purpose="serve", scratch_base=None)
    assert exc_default.value.code is ErrorCode.UNSAFE_PATH
    assert digest_tree(wal_root) == snap_before

    # 3. traits.temp_dir equal to or inside wal_root (scratch_base=None, default_scratch_base=None).
    for bad_temp in (wal_root, wal_root / "sub"):
        bad_temp_os = _os_with_traits(
            os_,
            _make_traits(
                sqlite_full_fsync=False,
                restrict_umask=False,
                default_scratch_base=None,
                resolve_temp_links=False,
                temp_dir=bad_temp,
            ),
        )
        with pytest.raises(BrainError) as exc_temp:
            admit_existing_pair(wal_root, store_id, bad_temp_os, purpose="serve", scratch_base=None)
        assert exc_temp.value.code is ErrorCode.UNSAFE_PATH
        assert digest_tree(wal_root) == snap_before
