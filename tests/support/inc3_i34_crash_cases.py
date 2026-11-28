"""Crash case and wheel assertions for ``restoring.store.after_swap_before_effect_drain`` (SP1 I3-4)."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.storage.backup import create_store_backup
from superbrain.storage.cas import RetentionClass, held_digests
from superbrain.storage.layout import DataRoot
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    KernelCrashContext,
    MarkedRun,
    assert_entered,
    assert_t8_crashed,
    assert_wheel_provenance,
    run_marked,
)
from tests.support.inc2_cli import is_writer_lock_held, write_daemon_config_file
from tests.support.inc2_fixture import (
    InstalledEnv,
    ensure_template_base,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import clone_owner_only_tree
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

I3_4_CRASHPOINTS = frozenset({"restoring.store.after_swap_before_effect_drain"})
I34_CHILD = Path(__file__).resolve().with_name("inc3_i34_crash_child.py")
OWNER = "dan"
EVIDENCE_BYTES = b"evidence-E-case101-wheel-payload"


@dataclass(frozen=True)
class I34Seed:
    data_root: Path
    config_path: Path
    payload_path: Path
    backup_dir: Path
    store_id: str
    evidence_id: str
    evidence_digest: str
    restore_time: dt.datetime
    expires_at: dt.datetime


@dataclass(frozen=True)
class I34CrashCase:
    operation: str
    crashpoint: str

    @property
    def node_id(self) -> str:
        return f"{self.operation}@{self.crashpoint}"


@dataclass(frozen=True)
class _I34Template:
    root: Path
    store_id: str
    evidence_id: str
    evidence_digest: str
    cert_name: str
    key_name: str


_I34_TEMPLATE: _I34Template | None = None
_I34_T0 = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.UTC)


def _i34_template() -> _I34Template:
    """Build once per session: live store (E promoted DURABLE) + pre-promotion backup + TLS under the template base."""
    global _I34_TEMPLATE
    if _I34_TEMPLATE is not None and _I34_TEMPLATE.root.is_dir():
        return _I34_TEMPLATE
    root = ensure_template_base() / f"i34-seed-{uuid.uuid4().hex}"
    root.mkdir()
    clock = FakeClock(_I34_T0)
    adapters = os_adapters(clock=clock)
    evidence_id = new_id()
    rt = open_kernel_job_runtime(root / "data", adapters, role="i3-4-crash-seed")
    try:
        store_id = rt.store.store_id
        generation = rt.policy.trust_generation()
        seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m1")
        expires = _I34_T0 + dt.timedelta(days=5)
        digest = rt.store.store_content(EVIDENCE_BYTES, "evidence", evidence_id, RetentionClass.EVIDENCE, expires)
        clone_owner_only_tree(create_store_backup(rt.store, adapters, _I34_T0), root / "backup")
        # In the live store after backup, a Lesson promotes Evidence E to DURABLE (still readable later).
        rt.store.store_content(EVIDENCE_BYTES, "evidence", evidence_id, RetentionClass.DURABLE, None)
    finally:
        rt.close()
    auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id=OWNER,
        action="provision_tls",
        subject_id=store_id,
        trust_generation=generation,
        expires_at=_I34_T0 + dt.timedelta(hours=4),
        destination=root / "tls",
    )
    tls = create_store_tls(store_id, root / "tls", auth, clock, adapters)
    _I34_TEMPLATE = _I34Template(root, store_id, evidence_id, digest, tls.cert_path.name, tls.key_path.name)
    return _I34_TEMPLATE


def prepare_i34_seed(ctx: KernelCrashContext) -> I34Seed:
    """Clone the cached seed (backup with expiring E, live E promoted to DURABLE); restore time is past E's expiry."""
    tpl = _i34_template()
    root, cfg_dir, backup_dir = ctx.case_dir / "data", ctx.case_dir / "config", ctx.case_dir / "backup"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(cfg_dir)
    clone_owner_only_tree(tpl.root / "data", root)
    clone_owner_only_tree(tpl.root / "backup", backup_dir)
    clone_owner_only_tree(tpl.root / "tls", cfg_dir / "tls")
    cfg_path = write_daemon_config_file(
        cfg_dir / "daemon.json",
        data_root=root,
        expected_store_id=tpl.store_id,
        cert_path=cfg_dir / "tls" / tpl.cert_name,
        key_path=cfg_dir / "tls" / tpl.key_name,
    )
    restore_time = _I34_T0 + dt.timedelta(days=10)
    payload_path = ctx.case_dir / "i34-payload.json"
    payload_path.write_text(
        json.dumps({"backup_dir": str(backup_dir), "now_iso": restore_time.isoformat()}),
        encoding="utf-8",
    )
    return I34Seed(
        data_root=root,
        config_path=cfg_path,
        payload_path=payload_path,
        backup_dir=backup_dir,
        store_id=tpl.store_id,
        evidence_id=tpl.evidence_id,
        evidence_digest=tpl.evidence_digest,
        restore_time=restore_time,
        expires_at=_I34_T0 + dt.timedelta(days=5),
    )


def run_i34_child(
    env: InstalledEnv,
    mode: str,
    config_path: Path,
    payload_path: Path,
    *,
    cwd: Path,
    crashpoint: str | None = None,
) -> MarkedRun:
    cmd = [str(env.venv_python), "-I", str(I34_CHILD), mode, str(config_path), str(payload_path)]
    return run_marked(cmd, cwd=cwd, crashpoint=crashpoint)


def run_i34_crash_case(ctx: KernelCrashContext, case: I34CrashCase) -> I34Seed:
    seed = prepare_i34_seed(ctx)
    crashed = run_i34_child(
        ctx.env,
        case.operation,
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert_wheel_provenance(crashed, ctx)
    assert_entered(crashed)
    assert_t8_crashed(crashed, case.crashpoint)
    assert not is_writer_lock_held(seed.data_root)

    # Post-crash state BEFORE recovery: swap published store/, epoch bumped, pending tombstones exist inside
    # store/, while live policy.db does NOT yet record the tombstone intent for Evidence E.
    from superbrain.storage.cas import active_held_digests
    from superbrain.storage.restore import read_restore_epoch
    from superbrain.storage.sqlite import open_readonly

    layout = DataRoot.at(seed.data_root)
    assert list(seed.data_root.glob("store.replaced-*"))
    assert layout.pending_restore_tombstones_path.is_file()
    restored_epoch = read_restore_epoch(layout, schema_version=6, os_=os_adapters())
    assert restored_epoch >= 1

    ro_policy = open_readonly(layout.policy_db)
    try:
        tomb = ro_policy.execute(
            "SELECT 1 FROM tombstones WHERE holder_kind = 'evidence' AND holder_id = ?",
            (seed.evidence_id,),
        ).fetchone()
        assert tomb is None, "tombstone must not hit live policy.db before drain step 7"
    finally:
        ro_policy.close()

    # Startup via daemon_entry.serve MUST drain pending_restore_tombstones before READY.
    served = run_i34_child(
        ctx.env,
        "serve-recover-stop",
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
    )
    assert_wheel_provenance(served, ctx)
    assert_entered(served)
    assert served.result.returncode == 0 and served.result.hit is None, served.describe()
    assert "READY_STOPPED " in served.result.stderr and not served.timed_out, served.describe()
    assert not layout.pending_restore_tombstones_path.exists()

    # Reopen and assert E is tombstoned in policy.db and blocked on the VERY FIRST read before expire_due/GC.
    adapters = os_adapters(clock=FakeClock(seed.restore_time))
    rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, adapters)
    try:
        assert rt.policy.is_tombstoned("evidence", seed.evidence_id)
        assert read_restore_epoch(layout, schema_version=6, os_=adapters) == restored_epoch
        with rt.store.transaction() as txn:
            assert held_digests(txn.db, "evidence", seed.evidence_id) == []
            assert active_held_digests(txn.db, "evidence", seed.evidence_id, now=seed.restore_time) == []
            assert txn.read_held_blob(seed.evidence_digest, holder_id=seed.evidence_id, holder_kind="evidence") is None
        try:
            rt.store.cas.read_held(
                seed.evidence_digest, holder_kind="evidence", holder_id=seed.evidence_id, now=seed.restore_time
            )
            raise AssertionError("expected expired/tombstoned evidence to raise NOT_FOUND")
        except BrainError as err:
            assert err.code is ErrorCode.NOT_FOUND
    finally:
        rt.close()

    # Second restart STILL arming crashpoint must succeed idempotently without hitting crashpoint again.
    again = run_i34_child(
        ctx.env,
        "serve-recover-stop",
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert again.result.returncode == 0 and again.result.hit is None, again.describe()
    assert "READY_STOPPED " in again.result.stderr and not again.timed_out, again.describe()
    return seed


I3_4_CRASH_CASES: tuple[I34CrashCase, ...] = (
    I34CrashCase("restore-store", "restoring.store.after_swap_before_effect_drain"),
)
