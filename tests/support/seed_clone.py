"""Session-cached seed templates for repeated store, backup, and runtime setups in tests."""

from __future__ import annotations

import dataclasses
import json
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition import init_entry
from superbrain.composition.init_entry import InitReport, InitRequest
from superbrain.core._kernel_approval import SignerEnrollment, SignerRecord
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_store
from superbrain.storage.runtime import Runtime
from superbrain.storage.swap import READY
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import ensure_template_base, open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, clone_owner_only_tree, write_daemon_config_file

# ---------------------------------------------------------------------------
# 1. v5 Live & READY stage templates (test_restore_epoch_and_expiry.py)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _V5LiveTpl:
    root: Path
    store_id: str


@dataclass(frozen=True)
class _V5ReadyTpl:
    stage_root: Path
    store_id: str


_V5_LIVE: _V5LiveTpl | None = None
_V5_READY: _V5ReadyTpl | None = None


def v5_live_clone(target_root: Path, os_: OsAdapters) -> tuple[Path, str]:
    """Clone a session-cached clean v5 store data root."""
    global _V5_LIVE
    if _V5_LIVE is None or not _V5_LIVE.root.is_dir():
        base = ensure_template_base() / f"v5-live-{uuid.uuid4().hex}"
        rt = open_kernel_job_runtime(base, os_, role="i3-4-v5-tpl")
        store_id = rt.store.store_id
        rt.close()
        _V5_LIVE = _V5LiveTpl(base, store_id)
    clone_owner_only_tree(_V5_LIVE.root, target_root)
    return target_root, _V5_LIVE.store_id


def v5_ready_stage_clone(
    target_root: Path, os_: OsAdapters, maintenance_lease_fn: Callable[..., Any]
) -> tuple[Path, Path, DataRoot]:
    """Clone a session-cached interrupted READY store.restoring stage."""
    global _V5_READY
    if _V5_READY is None or not _V5_READY.stage_root.is_dir():
        base = ensure_template_base() / f"v5-ready-{uuid.uuid4().hex}"
        rt = open_kernel_job_runtime(base, os_, role="i3-4-v5-rtpl")
        sid = rt.store.store_id
        backup = create_store_backup(rt.store, os_, os_.clock.now())
        rt.close()
        stage_layout = DataRoot.at(base)
        with maintenance_lease_fn(base) as (root, lease):
            pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
            try:
                restore_store(root, lease, os_, backup, pol, os_.clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
            finally:
                pol.close()
        stage_dir = base / "store.restoring"
        shutil.move(str(stage_layout.store_dir), str(stage_dir))
        (stage_dir / READY).write_bytes(b"")
        os_.permissions.secure_file(stage_dir / READY)
        _V5_READY = _V5ReadyTpl(base, sid)

    clone_owner_only_tree(_V5_READY.stage_root, target_root)
    return target_root, target_root / "store.restoring", DataRoot.at(target_root)


# ---------------------------------------------------------------------------
# 2. Case 101 expiry and backup template (test_restore_epoch_and_expiry.py)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Case101Tpl:
    root: Path
    store_bak: Path
    policy_bak: Path
    store_id: str
    ev_id: str
    evid_exp_id: str
    evid_keep_id: str
    d_ev: str
    d_evid_exp: str
    d_shared: str
    shared_bytes: bytes


_C101_TPL: Case101Tpl | None = None


def case101_seeded_clone(trusted_tmp: Path, mode: str, clock: FakeClock) -> tuple[Path, Path, Path, Case101Tpl]:
    """Clone a session-cached live store + store backup + policy backup for Case 101."""
    global _C101_TPL
    if _C101_TPL is None or not _C101_TPL.root.is_dir():
        from superbrain.core.ids import new_id

        base = ensure_template_base() / f"c101-tpl-{uuid.uuid4().hex}"
        root = base / "data"
        t0 = clock.now()
        os_ = os_adapters(clock=clock)
        rt = open_kernel_job_runtime(root, os_, role="c101-tpl")
        store_id = rt.store.store_id
        ev_id, evid_exp_id, evid_keep_id = new_id(), new_id(), new_id()
        ev_bytes, evid_exp_bytes, shared_bytes = (
            b"event-payload-case101",
            b"expired-evidence-case101",
            b"shared-case101",
        )
        from datetime import timedelta

        d_ev = rt.store.store_content(ev_bytes, "event", ev_id, RetentionClass.EVENT_PAYLOAD, t0 + timedelta(days=90))
        d_evid_exp = rt.store.store_content(
            evid_exp_bytes, "evidence", evid_exp_id, RetentionClass.EVIDENCE, t0 + timedelta(days=10)
        )
        d_shared = rt.store.store_content(
            shared_bytes, "event", ev_id, RetentionClass.EVENT_PAYLOAD, t0 + timedelta(days=90)
        )
        rt.store.store_content(shared_bytes, "evidence", evid_keep_id, RetentionClass.DURABLE, None)
        store_bak = create_store_backup(rt.store, os_, t0)
        policy_bak = create_policy_backup(rt.policy, os_, t0)
        rt.close()
        bak_dir = base / "backups"
        bak_dir.mkdir(parents=True)
        clone_owner_only_tree(store_bak, bak_dir / "store_bak")
        clone_owner_only_tree(policy_bak, bak_dir / "policy_bak")
        _C101_TPL = Case101Tpl(
            root=root,
            store_bak=bak_dir / "store_bak",
            policy_bak=bak_dir / "policy_bak",
            store_id=store_id,
            ev_id=ev_id,
            evid_exp_id=evid_exp_id,
            evid_keep_id=evid_keep_id,
            d_ev=d_ev,
            d_evid_exp=d_evid_exp,
            d_shared=d_shared,
            shared_bytes=shared_bytes,
        )

    target_root = trusted_tmp / f"case101-{mode}"
    target_sbak = trusted_tmp / f"store-bak-{mode}"
    target_pbak = trusted_tmp / f"policy-bak-{mode}"
    clone_owner_only_tree(_C101_TPL.root, target_root)
    clone_owner_only_tree(_C101_TPL.store_bak, target_sbak)
    clone_owner_only_tree(_C101_TPL.policy_bak, target_pbak)
    return target_root, target_sbak, target_pbak, _C101_TPL


# ---------------------------------------------------------------------------
# 3. Recovery grant & turn intent template (test_recovery_grant_and_turn_intent.py)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _RgBaseTpl:
    root: Path
    store_id: str
    signer: SignerRecord


_RG_TPL: _RgBaseTpl | None = None


def recovery_grant_ctx_clone(
    target_root: Path, os_: OsAdapters, signer_enrollment_fn: Callable[[str], SignerEnrollment]
) -> tuple[Runtime, SignerRecord]:
    """Clone a session-cached initialized kernel store + enrolled signer."""
    global _RG_TPL
    if _RG_TPL is None or not _RG_TPL.root.is_dir():
        base = ensure_template_base() / f"rg-base-{uuid.uuid4().hex}"
        rt = open_kernel_job_runtime(base, os_, role="base-rg")
        signer = rt.policy.enroll_first_signer(signer_enrollment_fn("base-rg"))
        sid = rt.store.store_id
        rt.close()
        _RG_TPL = _RgBaseTpl(base, sid, signer)

    clone_owner_only_tree(_RG_TPL.root, target_root)
    rt = reopen_kernel_job_runtime(target_root, _RG_TPL.store_id, os_)
    return rt, _RG_TPL.signer


# ---------------------------------------------------------------------------
# 4. Restore & migration fixture template (test_restore_and_migration_i3.py)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _RmInitTpl:
    base: Path
    priv: Ed25519PrivateKey
    rep: InitReport
    ca_pem: str
    cli_token: str
    store_bak: Path
    policy_bak: Path
    gen1: int


_RM_TPL: _RmInitTpl | None = None


def restore_migration_fixture_clone(
    base_dir: Path,
    signer_key_fn: Callable[[], tuple[Ed25519PrivateKey, SignerEnrollment]],
    owner: str,
    machine: str,
) -> tuple[
    FakeClock, FakeMonotonicClock, OsAdapters, Ed25519PrivateKey, InitReport, DaemonConfig, str, str, Path, Path, int
]:
    """Clone a session-cached full init fixture + backups for restore/migration tests."""
    global _RM_TPL
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)

    if _RM_TPL is None or not _RM_TPL.base.is_dir():
        base = ensure_template_base() / f"rm-init-{uuid.uuid4().hex}"
        priv, s_enr = signer_key_fn()
        cfg_dir = base / "cfg"
        cfg_dir.mkdir(parents=True)
        os_.permissions.secure_directory(cfg_dir)
        rep = init_entry.init_store(
            InitRequest(data_root=base / "data", config_dir=cfg_dir, owner_id=owner, machine_id=machine, signer=s_enr),
            os_,
        )
        ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
        cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()
        rt = reopen_kernel_job_runtime(base / "data", rep.store_id, os_)
        try:
            store_bak = create_store_backup(rt.store, os_, clock.now())
            policy_bak = create_policy_backup(rt.policy, os_, clock.now())
            gen1 = rt.policy.trust_generation()
            baks = base / "baks"
            baks.mkdir(parents=True)
            clone_owner_only_tree(store_bak, baks / "store_bak")
            clone_owner_only_tree(policy_bak, baks / "policy_bak")
        finally:
            rt.close()
        _RM_TPL = _RmInitTpl(
            base=base,
            priv=priv,
            rep=rep,
            ca_pem=ca_pem,
            cli_token=cli_token,
            store_bak=baks / "store_bak",
            policy_bak=baks / "policy_bak",
            gen1=gen1,
        )

    cfg_dir = base_dir / "cfg"
    clone_owner_only_tree(_RM_TPL.base / "data", base_dir / "data")
    clone_owner_only_tree(_RM_TPL.base / "cfg", cfg_dir)
    target_sbak = base_dir / "store_bak"
    target_pbak = base_dir / "policy_bak"
    clone_owner_only_tree(_RM_TPL.store_bak, target_sbak)
    clone_owner_only_tree(_RM_TPL.policy_bak, target_pbak)

    raw = json.loads(_RM_TPL.rep.daemon_config_path.read_text(encoding="utf-8"))
    rel_cfg = _RM_TPL.rep.daemon_config_path.relative_to(_RM_TPL.base / "cfg")
    (cfg_dir / rel_cfg).unlink()
    write_daemon_config_file(
        cfg_dir / rel_cfg,
        data_root=base_dir / "data",
        expected_store_id=_RM_TPL.rep.store_id,
        cert_path=cfg_dir / Path(raw["cert_path"]).relative_to(_RM_TPL.base / "cfg"),
        key_path=cfg_dir / Path(raw["key_path"]).relative_to(_RM_TPL.base / "cfg"),
        os_=os_,
    )
    cfg = read_daemon_config(cfg_dir / rel_cfg, os_)
    rep_cloned = dataclasses.replace(
        _RM_TPL.rep,
        daemon_config_path=cfg_dir / rel_cfg,
        cli_credential_path=cfg_dir / _RM_TPL.rep.cli_credential_path.relative_to(_RM_TPL.base / "cfg"),
    )
    return (
        clock, mono, os_, _RM_TPL.priv, rep_cloned, cfg,
        _RM_TPL.ca_pem, _RM_TPL.cli_token, target_sbak, target_pbak, _RM_TPL.gen1,
    )
