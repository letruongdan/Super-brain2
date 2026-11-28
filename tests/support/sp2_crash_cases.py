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
from superbrain.core.kernel import CaptureBatchCommand, Endpoint, Scope, ToolCommand
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
SP2_3_CRASHPOINTS: frozenset[str] = frozenset(
    {
        "session.after_policy_bind_before_store_project",
        "continuity.worker.before_owner_commit",
    }
)
SP2_4_CRASHPOINTS: frozenset[str] = frozenset(
    {
        "handoff.after_commit_before_ack",
        "artifact_send.after_pending_before_flush",
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

SP2_3_CRASH_CASES: tuple[SP22CrashCase, ...] = (
    SP22CrashCase("session-bind", "session.after_policy_bind_before_store_project"),
    SP22CrashCase("continuity-worker", "continuity.worker.before_owner_commit"),
)

SP2_4_CRASH_CASES: tuple[SP22CrashCase, ...] = (
    SP22CrashCase("handoff-serve", "handoff.after_commit_before_ack"),
    SP22CrashCase("handoff-serve", "artifact_send.after_pending_before_flush"),
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


def _prepare_session_bind_crash_case(ctx: KernelCrashContext) -> tuple[Path, Path, dict[str, Any]]:
    import datetime as dt

    from tests.support.clock import FakeClock
    from tests.support.inc2_fixture import open_kernel_job_runtime
    from tests.support.inc2_transport import register_workspace_direct
    from tests.support.kernel_auth import seed_principal_and_credential, seed_repo_grant

    clock = FakeClock(dt.datetime(2026, 11, 21, 14, 0, tzinfo=dt.UTC))
    from superbrain.domain.continuity.sessions import compute_session_ref

    adapters = os_adapters(clock=clock)
    data_root = ctx.case_dir / "session-data"
    rt = open_kernel_job_runtime(data_root, adapters, role="sp23-bind-crash")
    raw_sid = "SP23_WHEEL_BIND_CRASH_SID"
    try:
        sid = rt.policy.store_id
        prin_a = seed_principal_and_credential(
            rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m-w"
        ).principal
        prin_b = seed_principal_and_credential(
            rt.policy, owner_id="bob", harness_id="codex", machine_id="m-w2"
        ).principal
        ws_a = register_workspace_direct(rt, clock, prin_a, alias="sp23-ws", checkout_dir=ctx.case_dir / "chk-bind")
        seed_repo_grant(rt.policy, principal_id=prin_b.principal_id, repo_id=ws_a.repo_id, owner_id=OWNER)
        rt.store.reconcile_policy()
        expected_ref = compute_session_ref(rt.policy.session_hmac_key(), raw_sid)
    finally:
        rt.close()

    payload = {
        "store_id": sid,
        "principal_id": prin_a.principal_id,
        "repo_id": ws_a.repo_id,
        "checkout_id": ws_a.checkout_id,
        "harness_id": "claude-code",
        "raw_session_id": raw_sid,
        "now_iso": clock.now().isoformat(),
    }
    payload_path = ctx.case_dir / "session-bind-payload.json"
    payload_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return data_root, payload_path, {
        "store_id": sid,
        "prin_a": prin_a,
        "prin_b": prin_b,
        "ws_a": ws_a,
        "raw_sid": raw_sid,
        "expected_ref": expected_ref,
        "clock": clock,
        "adapters": adapters,
    }


def _prepare_continuity_worker_crash_case(ctx: KernelCrashContext) -> tuple[Path, Path, dict[str, Any]]:
    import datetime as dt

    from superbrain.core.canonical import digest_bytes
    from superbrain.core.ids import new_id
    from superbrain.ports.capture import CaptureEventRecord
    from tests.support.clock import FakeClock
    from tests.support.inc2_fixture import open_kernel_job_runtime
    from tests.support.inc2_transport import register_workspace_direct
    from tests.support.kernel_auth import seed_principal_and_credential

    clock = FakeClock(dt.datetime(2026, 11, 21, 14, 0, tzinfo=dt.UTC))
    from superbrain.storage.sessions import SessionStore

    adapters = os_adapters(clock=clock)
    data_root = ctx.case_dir / "cw-data"
    rt = open_kernel_job_runtime(data_root, adapters, role="sp23-cw-crash")
    agent_ref = digest_bytes(b"sp23-wheel-live-agent-ref")
    task_id = f"task-{new_id()}"
    try:
        sid = rt.policy.store_id
        prin = seed_principal_and_credential(
            rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m-cw"
        ).principal
        ws_a = register_workspace_direct(rt, clock, prin, alias="sp23-cw-ws", checkout_dir=ctx.case_dir / "chk-cw")
        rt.store.reconcile_policy()
        ss = SessionStore(rt.store, rt.policy)
        sess = ss.bind_session(
            principal_id=prin.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id="SP23_WHEEL_CW_CRASH_SID",
            now=clock.now(),
        )
        ss.ensure_task_handoff(
            task_id=task_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            session_ref=sess.session_ref,
            now=clock.now(),
        )
        ss.apply_agent_handoff_patch(
            task_id=task_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            session_ref=sess.session_ref,
            base_revision=0,
            agent_ref=agent_ref,
            now=clock.now(),
        )
        for seq in range(1, 21):
            ss.record_session_event(
                session_ref=sess.session_ref,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                task_id=task_id,
                producer_stream="sp23-cw-stream",
                event=CaptureEventRecord(
                    event_id=f"evt-cw-wheel-{seq}",
                    producer_stream="sp23-cw-stream",
                    sequence=seq,
                    harness_id="claude-code",
                    kind="tool_post",
                    recorded_at="2026-11-21T14:00:00Z",
                    payload={"tool": "Edit", "file_path": f"f_{seq}.py"},
                    session_ref=sess.session_ref,
                ),
                now=clock.now(),
            )
    finally:
        rt.close()

    payload_path = ctx.case_dir / "cw-payload.json"
    payload_path.write_text(
        json.dumps(
            {
                "store_id": sid,
                "task_id": task_id,
                "enqueue": True,
                "recover_stale": False,
                "now_iso": clock.now().isoformat(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return data_root, payload_path, {
        "store_id": sid,
        "task_id": task_id,
        "agent_ref": agent_ref,
        "clock": clock,
        "adapters": adapters,
    }


def run_sp2_3_crash_case(ctx: KernelCrashContext, case: SP22CrashCase) -> None:
    import subprocess

    import pytest

    from superbrain.core.errors import BrainError, ErrorCode
    from tests.support.inc2_cli import clean_installed_subprocess_env
    from tests.support.inc2_fixture import reopen_kernel_job_runtime

    ro_scratch = ctx.case_dir / "ro-scratch"
    from superbrain.storage.sessions import SessionStore

    if case.crashpoint == "session.after_policy_bind_before_store_project":
        data_root, payload_path, extras = _prepare_session_bind_crash_case(ctx)
        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, data_root, payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
        )
        assert_wheel_provenance(run, ctx)
        assert_t8_crashed(run, case.crashpoint)

        ro_scratch.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(DataRoot.at(data_root).policy_db, scratch_dir=ro_scratch)) as pol_ro:
            assert (
                pol_ro.execute(
                    "SELECT principal_id FROM session_ref_bindings WHERE session_ref = ?",
                    (extras["expected_ref"],),
                ).fetchone()
                is not None
            )
        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as str_ro:
            pending_rows = str_ro.execute(
                "SELECT session_ref FROM sessions WHERE session_ref = ?",
                (extras["expected_ref"],),
            ).fetchall()
            assert pending_rows == []

        # Restart child cleanly: reconciles once and returns session_ref.
        retry = subprocess.run(
            sp22_child_cmd(ctx.env, case.operation, data_root, payload_path),
            cwd=str(ctx.cwd),
            env=clean_installed_subprocess_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30.0,
        )
        assert retry.returncode == 0, retry.stderr
        assert json.loads(retry.stdout.strip())["session_ref"] == extras["expected_ref"]

        rt = reopen_kernel_job_runtime(data_root, extras["store_id"], extras["adapters"])
        try:
            ss = SessionStore(rt.store, rt.policy)
            with pytest.raises(BrainError) as mismatch:
                ss.bind_session(
                    principal_id=extras["prin_b"].principal_id,
                    repo_id=extras["ws_a"].repo_id,
                    checkout_id=extras["ws_a"].checkout_id,
                    harness_id="codex",
                    raw_session_id=extras["raw_sid"],
                    now=extras["clock"].now(),
                )
            assert mismatch.value.code is ErrorCode.IDENTITY_MISMATCH
        finally:
            rt.close()
        return

    if case.crashpoint == "continuity.worker.before_owner_commit":
        data_root, payload_path, extras = _prepare_continuity_worker_crash_case(ctx)
        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, data_root, payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
        )
        assert_wheel_provenance(run, ctx)
        assert_t8_crashed(run, case.crashpoint)

        ro_scratch = ctx.case_dir / "ro-cw"
        ro_scratch.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as str_ro:
            row = str_ro.execute(
                "SELECT observed_ref, agent_ref, handoff_revision FROM task_handoffs WHERE task_id = ?",
                (extras["task_id"],),
            ).fetchone()
            assert row is not None and row[0] is None and row[1] == extras["agent_ref"] and int(row[2]) == 1

        # Restart cleanly with stale job recovery enabled: observed_ref commits cleanly while preserving agent_ref!
        recovery_payload = json.loads(payload_path.read_text(encoding="utf-8"))
        recovery_payload["enqueue"] = False
        recovery_payload["recover_stale"] = True
        payload_path.write_text(json.dumps(recovery_payload, sort_keys=True), encoding="utf-8")
        res = subprocess.run(
            sp22_child_cmd(ctx.env, case.operation, data_root, payload_path),
            cwd=str(ctx.cwd),
            env=clean_installed_subprocess_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30.0,
        )
        assert res.returncode == 0, res.stderr
        assert json.loads(res.stdout.strip())["observed_ref"] is not None

        rt = reopen_kernel_job_runtime(data_root, extras["store_id"], extras["adapters"])
        try:
            handoff = SessionStore(rt.store, rt.policy).read_task_handoff(extras["task_id"])
            assert handoff is not None
            assert handoff.observed_ref is not None
            assert handoff.agent_ref == extras["agent_ref"]
            assert handoff.handoff_revision == 1
        finally:
            rt.close()
        return

    raise AssertionError(f"unexpected SP2-3 crashpoint: {case.crashpoint!r}")


def _prepare_handoff_crash_case(ctx: KernelCrashContext) -> tuple[Path, Path, dict[str, Any]]:
    tpl = _sp22_template()
    data_root = ctx.case_dir / "data"
    cfg_dir = ctx.case_dir / "config"
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
    payload_path = ctx.case_dir / "handoff-payload.json"
    payload_path.write_text("{}", encoding="utf-8")
    return data_root, cfg_path, {
        "tpl": tpl,
        "payload_path": payload_path,
    }


def _call_daemon_tool(
    target: LoopbackTarget,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    scope: Scope | None = None,
) -> dict[str, Any]:
    client = LoopbackClient()
    return client.call(
        target,
        ToolCommand(tool=tool, arguments=arguments, token=token, selected_scope=scope),
    )


def run_sp2_4_crash_case(ctx: KernelCrashContext, case: SP22CrashCase) -> None:
    import subprocess

    data_root, cfg_path, extras = _prepare_handoff_crash_case(ctx)
    tpl: _SP22Template = extras["tpl"]
    tpl_scope = Scope(tpl.repo_id, tpl.checkout_id)
    payload_path: Path = extras["payload_path"]
    client_err: list[BaseException] = []
    state: dict[str, Any] = {}

    if case.crashpoint == "handoff.after_commit_before_ack":
        ep_idem = "idem-sp24-crash-ep-1"
        sub_args: dict[str, Any] = {}

        def _trigger_commit(ep: Endpoint) -> None:
            target = LoopbackTarget(
                endpoint=ep,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            prep = _call_daemon_tool(
                target,
                tpl.token,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "mode": "work",
                    "workspace_id": tpl.repo_id,
                    "checkout_id": tpl.checkout_id,
                    "description": "Crash commit continuity goal",
                    "idempotency_key": "idem-sp24-crash-prep-1",
                },
                scope=tpl_scope,
            )
            assert prep.get("ok") is True, prep
            task_id = prep["data"]["task_id"]
            fence = prep["data"]["handoff_live"]["fence"]
            state["task_id"] = task_id
            sub_args.update(
                {
                    "schema_version": "2.0",
                    "task_id": task_id,
                    "session_id": "raw-sid-sp24-crash",
                    "workspace_id": tpl.repo_id,
                    "checkout_id": tpl.checkout_id,
                    "evidence": [{"kind": "tool_post", "data": {"ok": True}}],
                    "handoff": {"working_goal": "Committed right before crash"},
                    "base_revision": 0,
                    "fence": fence,
                    "idempotency_key": ep_idem,
                }
            )
            try:
                bad_res = _call_daemon_tool(target, tpl.token, "submit_episode", sub_args, scope=tpl_scope)
                raise AssertionError(f"submit_episode returned instead of crashing at {case.crashpoint}: {bad_res!r}")
            except LoopbackTransportError as err:
                client_err.append(err)

        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
            while_ready=_trigger_commit,
        )
        assert_wheel_provenance(run, ctx)
        assert_request_crashed(run, case.crashpoint, trigger_result=client_err)
        assert client_err, "client must see transport error when server exits 86 after commit"

        ro_scratch = ctx.case_dir / "ro-handoff"
        ro_scratch.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as conn:
            hrow = conn.execute(
                "SELECT handoff_revision, current_revision FROM task_handoffs WHERE task_id = ?",
                (state["task_id"],),
            ).fetchone()
            assert hrow is not None and int(hrow[0]) == 1 and int(hrow[1]) == 1

        # Restart daemon without crashpoint: idempotent replay returns same episode_id & live holder status.
        restarted_res: list[dict[str, Any]] = []
        proc = subprocess.Popen(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, payload_path),
            cwd=str(ctx.cwd),
            env=clean_installed_subprocess_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            assert proc.stderr is not None
            ready_ep: Endpoint | None = None
            for raw_line in proc.stderr:
                if raw_line.startswith("READY "):
                    ready_ep = Endpoint.from_canonical(raw_line[6:].strip().encode("utf-8"))
                    break
            assert ready_ep is not None
            target2 = LoopbackTarget(
                endpoint=ready_ep,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            rep = _call_daemon_tool(target2, tpl.token, "submit_episode", sub_args, scope=tpl_scope)
            restarted_res.append(rep)
        finally:
            proc.terminate()
            proc.wait(timeout=10.0)
        assert len(restarted_res) == 1 and restarted_res[0].get("ok") is True
        rdata = restarted_res[0]["data"]
        assert rdata["handoff_status"] == "stored"
        assert rdata["handoff_revision"] == 1
        assert rdata["writer_status"] == "holder"
        return

    if case.crashpoint == "artifact_send.after_pending_before_flush":
        get_args: dict[str, Any] = {}

        def _trigger_send(ep: Endpoint) -> None:
            target = LoopbackTarget(
                endpoint=ep,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            prep = _call_daemon_tool(
                target,
                tpl.token,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "mode": "work",
                    "workspace_id": tpl.repo_id,
                    "checkout_id": tpl.checkout_id,
                    "description": "Flush crash goal",
                    "idempotency_key": "idem-sp24-flush-prep-1",
                },
                scope=tpl_scope,
            )
            assert prep.get("ok") is True
            tid = prep["data"]["task_id"]
            sub = _call_daemon_tool(
                target,
                tpl.token,
                "submit_episode",
                {
                    "schema_version": "2.0",
                    "task_id": tid,
                    "session_id": "raw-sid-sp24-flush",
                    "workspace_id": tpl.repo_id,
                    "checkout_id": tpl.checkout_id,
                    "evidence": [],
                    "handoff": {"working_goal": "Ready to serve"},
                    "base_revision": 0,
                    "fence": prep["data"]["handoff_live"]["fence"],
                    "idempotency_key": "idem-sp24-flush-sub-1",
                },
                scope=tpl_scope,
            )
            assert sub.get("ok") is True, sub
            state["task_id"] = tid
            get_args.update(
                {
                    "schema_version": "2.0",
                    "workspace_id": tpl.repo_id,
                    "task_id": tid,
                    "artifact_id": tid,
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-sp24-flush-get-1",
                }
            )
            try:
                _call_daemon_tool(target, tpl.token, "get_artifact", get_args, scope=tpl_scope)
            except LoopbackTransportError as err:
                client_err.append(err)

        run = run_marked(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, payload_path),
            cwd=ctx.cwd,
            crashpoint=case.crashpoint,
            while_ready=_trigger_send,
        )
        assert_wheel_provenance(run, ctx)
        assert_request_crashed(run, case.crashpoint, trigger_result=client_err)
        assert client_err

        ro_scratch = ctx.case_dir / "ro-flush"
        ro_scratch.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as conn:
            arow = conn.execute(
                "SELECT id, state FROM artifact_send_attempt WHERE task_id = ?",
                (state["task_id"],),
            ).fetchone()
            assert arow is not None and str(arow[1]) == "pending"
            aborted_id = str(arow[0])

        proc = subprocess.Popen(
            sp22_child_cmd(ctx.env, case.operation, cfg_path, payload_path),
            cwd=str(ctx.cwd),
            env=clean_installed_subprocess_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            assert proc.stderr is not None
            ready_ep2: Endpoint | None = None
            for raw_line in proc.stderr:
                if raw_line.startswith("READY "):
                    ready_ep2 = Endpoint.from_canonical(raw_line[6:].strip().encode("utf-8"))
                    break
            assert ready_ep2 is not None
            target2 = LoopbackTarget(
                endpoint=ready_ep2,
                expected_store_id=tpl.store_id,
                ca_pem=tpl.ca_pem,
                leaf_cert_sha256=tpl.leaf_sha256,
            )
            rep2 = _call_daemon_tool(target2, tpl.token, "get_artifact", get_args, scope=tpl_scope)
            assert rep2.get("ok") is True
            assert rep2["data"]["served_receipt_id"] != aborted_id
        finally:
            proc.terminate()
            proc.wait(timeout=10.0)

        with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=ro_scratch)) as conn:
            old_row = conn.execute(
                "SELECT state FROM artifact_send_attempt WHERE id = ?",
                (aborted_id,),
            ).fetchone()
            assert old_row is not None and str(old_row[0]) == "unknown"
        return

    raise AssertionError(f"unexpected SP2-4 crashpoint: {case.crashpoint!r}")
