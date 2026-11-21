"""Crash cases and wheel assertions for SP2-2 outbox & capture ingest crashpoints."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget, LoopbackTransportError
from superbrain.core.kernel import CaptureBatchCommand, Endpoint
from superbrain.storage.layout import DataRoot
from superbrain.storage.sqlite import open_readonly
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    KernelCrashContext,
    assert_request_crashed,
    assert_t8_crashed,
    assert_wheel_provenance,
    run_marked,
)
from tests.support.inc2_cli import clean_installed_subprocess_env, write_daemon_config_file
from tests.support.inc2_fixture import InstalledEnv, ensure_template_base, open_kernel_job_runtime
from tests.support.inc2_transport import clone_owner_only_tree, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential, seed_repo_grant

SP2_2_CRASHPOINTS: frozenset[str] = frozenset(
    {
        "capture.outbox.after_write_before_fsync",
        "capture.daemon.after_commit_before_ack",
    }
)
SP22_CHILD = Path(__file__).resolve().with_name("sp2_crash_child.py")
OWNER = "dan"


@dataclass(frozen=True)
class SP22CrashCase:
    operation: str
    crashpoint: str

    @property
    def node_id(self) -> str:
        return f"{self.operation}@{self.crashpoint}"


SP2_2_CRASH_CASES: tuple[SP22CrashCase, ...] = (
    SP22CrashCase("outbox-enqueue", "capture.outbox.after_write_before_fsync"),
    SP22CrashCase("capture-serve", "capture.daemon.after_commit_before_ack"),
)


@dataclass(frozen=True)
class _SP22Template:
    root: Path
    store_id: str
    repo_id: str
    checkout_id: str
    cred_id: str
    token: str
    cert_name: str
    key_name: str
    ca_pem: str
    leaf_sha256: str


_SP22_TEMPLATE: _SP22Template | None = None


def _sp22_template() -> _SP22Template:
    global _SP22_TEMPLATE
    if _SP22_TEMPLATE is not None and _SP22_TEMPLATE.root.is_dir():
        return _SP22_TEMPLATE
    root = ensure_template_base() / f"sp22-seed-{uuid.uuid4().hex}"
    root.mkdir()
    clock = FakeClock(dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=10))
    adapters = os_adapters(clock=clock)
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp2-2-crash-seed")
    try:
        store_id = rt.store.store_id
        gen = rt.policy.trust_generation()
        mcp_cred = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m1")
        cap_cred = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m1")
        ws = register_workspace_direct(
            rt,
            clock,
            mcp_cred.principal,
            alias="ws-sp22",
            checkout_dir=root / "chk-sp22",
            remote="https://github.example/dan/sp22.git",
        )
        seed_repo_grant(rt.policy, principal_id=cap_cred.principal.principal_id, repo_id=ws.repo_id, owner_id=OWNER)
    finally:
        rt.close()

    auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id=OWNER,
        action="provision_tls",
        subject_id=store_id,
        trust_generation=gen,
        expires_at=clock.now() + dt.timedelta(hours=4),
        destination=root / "tls",
    )
    tls = create_store_tls(store_id, root / "tls", auth, clock, adapters)
    _SP22_TEMPLATE = _SP22Template(
        root=root,
        store_id=store_id,
        repo_id=ws.repo_id,
        checkout_id=ws.checkout_id,
        cred_id=cap_cred.credential_id,
        token=cap_cred.token,
        cert_name=tls.cert_path.name,
        key_name=tls.key_path.name,
        ca_pem=tls.ca_cert_path.read_text(encoding="utf-8"),
        leaf_sha256=tls.leaf_cert_sha256,
    )
    return _SP22_TEMPLATE


def sp22_child_cmd(env: InstalledEnv, mode: str, target_path: Path, payload_path: Path) -> list[str]:
    return [str(env.venv_python), "-I", str(SP22_CHILD), mode, str(target_path), str(payload_path)]


def _prepare_outbox_crash_case(ctx: KernelCrashContext) -> tuple[Path, Path]:
    from superbrain.ports.capture import CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    outbox_dir = ctx.case_dir / "outbox"
    spool = OutboxSpool(outbox_dir)
    ev1 = CaptureEventRecord(
        event_id="ev-crash-1",
        producer_stream="sp22-stream",
        sequence=1,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={"ok": "committed-before-crash"},
    )
    spool.enqueue_event(ev1)

    ev2 = CaptureEventRecord(
        event_id="ev-crash-2",
        producer_stream="sp22-stream",
        sequence=2,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:01Z",
        payload={"ok": "unflushed-torn-entry"},
    )
    payload_path = ctx.case_dir / "outbox-payload.json"
    payload_path.write_text(json.dumps({"event": ev2.to_dict()}, sort_keys=True), encoding="utf-8")
    return outbox_dir, payload_path


def _prepare_daemon_crash_case(ctx: KernelCrashContext) -> tuple[Path, Path, Path, _SP22Template, dict[str, Any]]:
    from superbrain.ports.capture import CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    tpl = _sp22_template()
    data_root = ctx.case_dir / "data"
    cfg_dir = ctx.case_dir / "config"
    outbox_dir = ctx.case_dir / "daemon-outbox"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(cfg_dir)
    clone_owner_only_tree(tpl.root / "data", data_root)
    clone_owner_only_tree(tpl.root / "tls", cfg_dir / "tls")
    cfg_path = write_daemon_config_file(
        cfg_dir / "daemon.json",
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=cfg_dir / "tls" / tpl.cert_name,
        key_path=cfg_dir / "tls" / tpl.key_name,
    )
    spool = OutboxSpool(outbox_dir)
    events = (
        CaptureEventRecord(
            event_id="ev-dc-1",
            producer_stream="sp22-daemon-stream",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-21T12:01:00Z",
            payload={"step": "committed-1"},
        ),
        CaptureEventRecord(
            event_id="ev-dc-2",
            producer_stream="sp22-daemon-stream",
            sequence=2,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-21T12:01:01Z",
            payload={"step": "committed-2"},
        ),
    )
    for ev in events:
        spool.enqueue_event(ev)

    payload_path = ctx.case_dir / "daemon-payload.json"
    payload_path.write_text(
        json.dumps(
            {
                "credential_id": tpl.cred_id,
                "producer_stream": "sp22-daemon-stream",
                "repo_id": tpl.repo_id,
                "checkout_id": tpl.checkout_id,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return data_root, cfg_path, outbox_dir, tpl, {"payload_path": payload_path, "events": events}


def _drain_cmd(tpl: _SP22Template, outbox_dir: Path) -> CaptureBatchCommand:
    from superbrain.storage.outbox import OutboxSpool

    pending = OutboxSpool(outbox_dir).read_pending(limit=10, producer_stream="sp22-daemon-stream")
    events_payload = tuple(json.loads(entry.payload_json) for entry in pending)
    return CaptureBatchCommand(
        producer_stream="sp22-daemon-stream",
        repo_id=tpl.repo_id,
        checkout_id=tpl.checkout_id,
        events=events_payload,
        token=tpl.token,
        correlation_id="sp22-crash-drain",
    )


def run_sp2_2_crash_case(ctx: KernelCrashContext, case: SP22CrashCase) -> None:
    if case.crashpoint == "capture.outbox.after_write_before_fsync":
        from superbrain.ports.capture import CaptureEventRecord
        from superbrain.storage.outbox import OutboxSpool

        outbox_dir, payload_path = _prepare_outbox_crash_case(ctx)
        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, outbox_dir, payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
        )
        assert_wheel_provenance(run, ctx)
        assert_t8_crashed(run, case.crashpoint)

        # Reopen after crash: Event 1 intact, torn Event 2 discarded, retry succeeds cleanly.
        reopened = OutboxSpool(outbox_dir)
        pending = reopened.read_pending(limit=10)
        assert [e.sequence for e in pending] == [1]
        ev2 = CaptureEventRecord.from_dict(json.loads(payload_path.read_text(encoding="utf-8"))["event"])
        assert reopened.enqueue_event(ev2) == "ev-crash-2"
        assert [e.sequence for e in reopened.read_pending(limit=10)] == [1, 2]
        return

    if case.crashpoint == "capture.daemon.after_commit_before_ack":
        from superbrain.cli_api.capture_client import CaptureClient
        from superbrain.ports.capture import OUTBOX_RECORD_EVENT
        from superbrain.storage.outbox import OutboxSpool

        data_root, cfg_path, outbox_dir, tpl, extras = _prepare_daemon_crash_case(ctx)
        daemon_payload_path: Path = extras["payload_path"]
        trigger_err: list[BaseException] = []

        def _trigger(ep: Endpoint) -> None:
            client = CaptureClient(LoopbackClient())
            target = LoopbackTarget(
                endpoint=ep,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            try:
                client.post_batch(target, _drain_cmd(tpl, outbox_dir))
            except LoopbackTransportError as err:
                trigger_err.append(err)

        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, daemon_payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
            while_ready=_trigger,
        )
        assert_wheel_provenance(run, ctx)
        assert_request_crashed(run, case.crashpoint, trigger_result=trigger_err)
        assert trigger_err, "client must observe uncertain/transport failure when server exits 86 before ACK"

        # Before restart: outbox STILL holds both events un-ACKed, while brain.db already committed them.
        spool_before = OutboxSpool(outbox_dir)
        assert [(e.record_kind, e.sequence) for e in spool_before.read_pending(limit=10)] == [
            (OUTBOX_RECORD_EVENT, 1),
            (OUTBOX_RECORD_EVENT, 2),
        ]
        ro_scratch = ctx.case_dir / "ro-scratch"
        ro_scratch.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as conn:
            committed_rows = conn.execute(
                "SELECT sequence, event_id FROM capture_events ORDER BY sequence"
            ).fetchall()
            assert [tuple(r) for r in committed_rows] == [(1, "ev-dc-1"), (2, "ev-dc-2")]

        # Restart WITH crashpoint still armed: pure dedup retry MUST NOT re-fire commit crashpoint and MUST return ACK.
        acks: list[Any] = []

        def _retry_drain(ep: Endpoint) -> None:
            client = CaptureClient(LoopbackClient())
            target = LoopbackTarget(
                endpoint=ep,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            ack = client.post_batch(target, _drain_cmd(tpl, outbox_dir))
            acks.append(ack)

        restart_run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, daemon_payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
            while_ready=_retry_drain,
        )
        assert restart_run.result.hit is None and not restart_run.timed_out, restart_run.describe()
        assert len(acks) == 1
        ack = acks[0]
        assert ack.committed_event_sequences == (1, 2)
        assert ack.contiguous_event_acked_through == 2
        assert ack.deduped_count == 2 and ack.accepted_count == 0
        assert OutboxSpool(outbox_dir).apply_ack(ack) == 2
        assert OutboxSpool(outbox_dir).read_pending(limit=10) == []

        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as conn:
            after_rows = conn.execute(
                "SELECT sequence, event_id FROM capture_events ORDER BY sequence"
            ).fetchall()
            assert [tuple(r) for r in after_rows] == [(1, "ev-dc-1"), (2, "ev-dc-2")]
        return

    raise AssertionError(f"unknown SP2-2 crashpoint {case.crashpoint}")


def run_sp2_2_omission_checks(ctx: KernelCrashContext, monkeypatch: Any) -> None:
    """Confirm disabling each SP2-2 crashpoint prevents crashing so removed crashpoints cannot go undetected."""
    from superbrain.cli_api.capture_client import CaptureClient
    from superbrain.storage.outbox import OutboxSpool

    outbox_dir, payload_path = _prepare_outbox_crash_case(ctx)
    cp_out = "capture.outbox.after_write_before_fsync"
    env_out = clean_installed_subprocess_env(
        {"SUPERBRAIN_CRASHPOINT": cp_out, "SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST": cp_out}
    )
    res_out = subprocess.run(
        sp22_child_cmd(ctx.env, "outbox-enqueue", outbox_dir, payload_path),
        cwd=ctx.cwd,
        env=env_out,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30.0,
    )
    assert res_out.returncode == 0 and "CRASHPOINT_HIT" not in res_out.stderr, (res_out.returncode, res_out.stderr)
    assert [e.sequence for e in OutboxSpool(outbox_dir).read_pending(limit=10)] == [1, 2]

    # Daemon omission: disabling capture.daemon.after_commit_before_ack completes ingest + returns ACK cleanly.
    daemon_ctx = KernelCrashContext(
        env=ctx.env, template=ctx.template, case_dir=ctx.case_dir / "daemon-omit", cwd=ctx.cwd
    )
    daemon_ctx.case_dir.mkdir(parents=True, exist_ok=True)
    _data_root, cfg_path, d_outbox, tpl, extras = _prepare_daemon_crash_case(daemon_ctx)
    cp_daemon = "capture.daemon.after_commit_before_ack"
    monkeypatch.setenv("SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST", cp_daemon)
    acks: list[Any] = []

    def _trigger(ep: Endpoint) -> None:
        client = CaptureClient(LoopbackClient())
        target = LoopbackTarget(
            endpoint=ep,
            expected_store_id=tpl.store_id,
            ca_pem=tpl.ca_pem,
            leaf_cert_sha256=tpl.leaf_sha256,
        )
        acks.append(client.post_batch(target, _drain_cmd(tpl, d_outbox)))

    run_daemon = run_marked(
        sp22_child_cmd(ctx.env, "capture-serve", cfg_path, extras["payload_path"]),
        cwd=ctx.cwd,
        crashpoint=cp_daemon,
        while_ready=_trigger,
    )
    assert run_daemon.result.hit is None and not run_daemon.timed_out, run_daemon.describe()
    assert len(acks) == 1 and acks[0].accepted_count == 2
