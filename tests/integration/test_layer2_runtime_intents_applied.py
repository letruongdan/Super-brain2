"""Every policy intent the daemon records at runtime reaches ``brain.db`` in the same owner step.

The SP2-5 live Layer-2 check downgrades a drifted harness by recording a ``layer2_state_set`` intent in ``policy.db``.
Since the SP1-I4 merge the doctor counts any policy intent missing from ``brain.db.applied_intents`` as
``storage.policy_reconcile``; a downgrade left unapplied until the next daemon start is that inconsistency.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.harness.layer2_probe import compute_harness_config_digest
from superbrain.adapters.harness_config.bootstrap_templates import plan_claude_bootstrap
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.cli_api.capture_client import CaptureClient
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import init_entry
from superbrain.composition._layer2_live import reconcile_live_layer2_all
from superbrain.composition.doctor_probes_sp2_store import reconcile_harness_layer2_in_policy
from superbrain.core._kernel_approval import Layer2State
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import CaptureBatchCommand
from superbrain.ports.capture import CaptureEventRecord
from superbrain.storage.runtime import Runtime
from superbrain.storage.store import Store
from tests.integration.test_sp2_5_production_wiring import (
    _CLAUDE_VER,
    _MACHINE,
    _OWNER,
    _build_receipt,
    _install_fake_host_bins,
    _publish_capture_creds,
    _serve_daemon,
    _ssh_signer,
    _write_plan_targets,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential


def _unapplied(rt: Runtime) -> list[str]:
    applied = {str(r[0]) for r in rt.store._db.execute("SELECT intent_id FROM applied_intents").fetchall()}
    return [i.kind.value for i in rt.policy.intents() if i.intent_id not in applied]


def _verified_store(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    _install_fake_host_bins(tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()
    cfg_dir, data_root, chk = tmp / "cfg", tmp / "data", tmp / "chk"
    for d in (cfg_dir, chk):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rep = init_entry.init_store(
        init_entry.InitRequest(data_root=data_root, config_dir=cfg_dir, owner_id=_OWNER, machine_id=_MACHINE,
                               signer=s_enr),
        os_,
    )
    _write_plan_targets(chk, plan_claude_bootstrap(checkout_root=chk, profile_path=cfg_dir / "p.json").targets)
    c_dig = compute_harness_config_digest("claude-code", chk, os_)
    assert c_dig is not None
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        cap = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws = register_workspace_direct(rt, clock, cap.principal, alias="ws-l2-apply", checkout_dir=chk)
        receipt = _build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig)
        assert reconcile_harness_layer2_in_policy(
            rt.policy, harness_id="claude-code", checkout_root=chk, observed_host_version=_CLAUDE_VER, os_=os_,
            receipt=receipt,
        )[0] is Layer2State.VERIFIED
        rt.store.reconcile_policy()
        assert _unapplied(rt) == []
    finally:
        rt.close()
    return {"os_": os_, "clock": clock, "mono": mono, "rep": rep, "chk": chk, "cap": cap, "ws": ws,
            "data_root": data_root, "cfg": read_daemon_config(rep.daemon_config_path, os_),
            "ca_pem": (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")}


def test_live_layer2_downgrade_on_config_drift_is_applied_to_brain_db(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _verified_store(trusted_tmp, monkeypatch)
    settings = env["chk"] / ".claude" / "settings.local.json"
    settings.write_bytes(settings.read_bytes().replace(b'"hooks"', b'"theme":"dark","hooks"', 1))
    rt = reopen_kernel_job_runtime(env["data_root"], env["rep"].store_id, env["os_"])
    try:
        reconcile_live_layer2_all(rt.policy, store=rt.store, os_=env["os_"])
        latest = rt.policy.layer2_state("claude-code")
        assert latest is not None and latest[3] is Layer2State.UNKNOWN  # the drift really downgraded
        assert _unapplied(rt) == []
    finally:
        rt.close()


def test_capture_batch_host_version_drift_downgrade_is_applied_to_brain_db(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _verified_store(trusted_tmp, monkeypatch)
    with _serve_daemon(env["cfg"], env["os_"], env["clock"], env["mono"]) as (ready, loop):
        _publish_capture_creds(loop, [(env["cap"], "stream-l2-apply", env["ws"])])
        target = LoopbackTarget(endpoint=ready.endpoint, expected_store_id=env["rep"].store_id, ca_pem=env["ca_pem"],
                                leaf_cert_sha256=ready.leaf_cert_sha256)
        ev = CaptureEventRecord(
            event_id="ev-l2-apply-1", producer_stream="stream-l2-apply", sequence=1, harness_id="claude-code",
            kind="command_result", recorded_at="2026-11-28T10:00:00Z", payload={"cmd": "pytest"},
            source_metadata={"host_version": "9.9.9"},
        ).to_dict()
        ws = env["ws"]
        accepted = CaptureClient(LoopbackClient(monotonic_ns=env["mono"].monotonic_ns)).post_batch(
            target, CaptureBatchCommand("stream-l2-apply", ws.repo_id, ws.checkout_id, (ev,), env["cap"].token)
        ).accepted_count
        assert accepted == 1

        def _check() -> tuple[object, list[str]]:
            live_rt = cast(Any, loop._session)._rt
            latest = live_rt.policy.layer2_state("claude-code")
            return (latest[3] if latest is not None else None), _unapplied(live_rt)

        state, unapplied = loop.run_owner_action(_check).result(timeout=10.0)
        assert state is Layer2State.UNKNOWN  # the reported drift really downgraded
        assert unapplied == []


def test_a_failed_downgrade_apply_is_retried_while_the_daemon_serves(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _verified_store(trusted_tmp, monkeypatch)
    real_reconcile = Store.reconcile_policy
    failures = [1]
    calls = [0]

    def _busy_once(self: Store) -> int:
        calls[0] += 1
        if failures[0]:
            failures[0] -= 1
            raise BrainError(ErrorCode.STORE_BUSY, "store busy")
        return real_reconcile(self)

    with _serve_daemon(env["cfg"], env["os_"], env["clock"], env["mono"]) as (ready, loop):
        _publish_capture_creds(loop, [(env["cap"], "stream-l2-retry", env["ws"])])
        target = LoopbackTarget(endpoint=ready.endpoint, expected_store_id=env["rep"].store_id, ca_pem=env["ca_pem"],
                                leaf_cert_sha256=ready.leaf_cert_sha256)
        client = CaptureClient(LoopbackClient(monotonic_ns=env["mono"].monotonic_ns))
        ws = env["ws"]

        def _post(seq: int, meta: dict[str, Any]) -> int:
            ev = CaptureEventRecord(
                event_id=f"ev-l2-retry-{seq}", producer_stream="stream-l2-retry", sequence=seq,
                harness_id="claude-code", kind="command_result", recorded_at="2026-11-28T10:00:00Z",
                payload={"cmd": "pytest"}, source_metadata=meta,
            ).to_dict()
            return client.post_batch(
                target, CaptureBatchCommand("stream-l2-retry", ws.repo_id, ws.checkout_id, (ev,), env["cap"].token)
            ).accepted_count

        monkeypatch.setattr(Store, "reconcile_policy", _busy_once)
        assert _post(1, {"host_version": "9.9.9"}) == 1  # downgrade recorded; its apply hits a busy store
        assert _post(2, {}) == 1  # no new downgrade: the pending apply must still be retried

        def _unapplied_now() -> list[str]:
            return _unapplied(cast(Any, loop._session)._rt)

        assert loop.run_owner_action(_unapplied_now).result(timeout=10.0) == []
        settled = calls[0]
        assert _post(3, {}) == 1
        assert calls[0] == settled  # nothing pending: a clean batch never pays the O(intents) reconcile
