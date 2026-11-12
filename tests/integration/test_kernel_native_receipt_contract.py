"""Task 9 contract tests for native/wheel connection receipts and multi-channel verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.jobs import JobService
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope
from superbrain.storage.idempotency import StagedKernelStore
from tests.support.clock import FakeClock
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    get_shared_t7_transport_template,
    is_writer_lock_held,
    mcp_call_frame,
    mcp_init_frames,
    write_client_profile_file,
    write_credential_file,
    write_daemon_config_file,
)
from tests.support.inc2_fixture import InstalledEnv, enqueue_job, open_kernel_job_runtime
from tests.support.inc2_lifecycle import ShimLaunchObservation
from tests.support.inc2_native import (
    NATIVE_CONNECTION_SCHEMA_VERSION,
    BindingSummary,
    HostCallObservation,
    HostTokenContext,
    NativeConnectionProbe,
    ObservationSet,
    ObserverRegistration,
    OwnerCallObservation,
    PathCheckResult,
    ProbeValidationError,
    ProcessIdentity,
    SocketObservation,
    TerminalToolFacts,
    TimespanRecord,
    encode_native_probe,
    parse_native_probe,
    parse_owner_events_jsonl,
    parse_owner_ready,
    parse_socket_observations_jsonl,
    verify_native_connection,
)
from tests.support.inc2_native_owner import (
    ObservedWheelOwner,
    load_owner_observations,
    process_started_at_for_pid,
    spawn_observed_wheel_owner,
    utc_now_z,
    verify_same_daemon,
)
from tests.support.inc2_transport import clone_owner_only_tree, make_trusted_test_dir, register_workspace_direct
from tests.support.kernel_auth import generate_bearer_token, seed_principal_and_credential


def _sample_world(
    root: Path,
    *,
    kind: str = "native",
    host: str = "claude-code",
    environment: str = "native_host",
    launcher_same_as_worker: bool = False,
    tool_name: str = "get_health",
) -> tuple[NativeConnectionProbe, ObserverRegistration, ObservationSet, Path]:
    evidence_root = root / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    cfg_path = evidence_root / "daemon-config.json"
    prof_path = evidence_root / "client-profile.json"
    schema_path = evidence_root / "mcp-tools-v2.json"
    shim_path = evidence_root / "shim-artifact.bin"

    cfg_bytes = b'{"version":1,"expected_store_id":"store-t9-1"}\n'
    prof_bytes = b'{"version":1,"expected_store_id":"store-t9-1","alias":"ws-a"}\n'
    schema_bytes = b'{"schema":"mcp-tools-v2"}\n'
    shim_bytes = b"shim-build-binary-v1\n"

    cfg_path.write_bytes(cfg_bytes)
    prof_path.write_bytes(prof_bytes)
    schema_path.write_bytes(schema_bytes)
    shim_path.write_bytes(shim_bytes)

    cfg_digest = digest_bytes(cfg_bytes)
    prof_digest = digest_bytes(prof_bytes)
    schema_digest = digest_bytes(schema_bytes)
    shim_digest = digest_bytes(shim_bytes)

    cred_id, _, _, _ = generate_bearer_token()
    source_commit = "a" * 40
    store_id = "store-t9-1"
    writer_epoch = 4
    instance_id = "inst-t9-1"
    principal_id = "prin-t9-1"
    call_id = "call-t9-0001"
    conn_id = "conn-t9-0001"
    run_id = "run-t9-obs-1"
    observer_id = "obs-claude-1"
    host_mode = (
        "fixture_mcp_stdio"
        if kind == "fixture"
        else ("codex_desktop_gui" if host == "codex-desktop" else "claude_cli_mcp_isolated")
    )
    channel = "mcp_stdio_observed"
    response_digest = digest_bytes(canonical_json({"ok": True, "data": {"ready": True}}))

    host_proc = ProcessIdentity(pid=4101, started_at="2026-11-12T04:00:00.100000Z")
    launcher_proc = ProcessIdentity(pid=4102, started_at="2026-11-12T04:00:01.100000Z")
    worker_proc = (
        launcher_proc
        if launcher_same_as_worker
        else ProcessIdentity(pid=4103, started_at="2026-11-12T04:00:01.250000Z")
    )
    daemon_proc = ProcessIdentity(pid=4104, started_at="2026-11-12T03:59:59.000000Z")

    scope_a = Scope(repo_id="repo-t9-a", checkout_id="chk-t9-a")
    eff_scope: dict[str, JsonValue] | None = None if tool_name == "get_health" else scope_a.to_dict()
    probe_kind: Any = kind
    probe = NativeConnectionProbe(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        kind=probe_kind,
        status="passed",
        reason_code=None,
        task_id="task-t9-obs-1",
        run_id=run_id,
        observer_id=observer_id,
        observed_call_id=call_id,
        observation_channel=channel,
        host=host,
        host_mode=host_mode,
        host_version="2.1.317",
        host_pid=host_proc.pid,
        os=sys.platform,
        source_commit=source_commit,
        shim_build_digest=shim_digest,
        config_digest=cfg_digest,
        profile_digest=prof_digest,
        schema_digest=schema_digest,
        host_process=host_proc,
        shim_launcher_process=launcher_proc,
        shim_worker_process=worker_proc,
        daemon_process=daemon_proc,
        filtered_command=("brain", "mcp", "--profile", "<redacted-profile-path>"),
        timespan=TimespanRecord(
            started_at="2026-11-12T04:00:02.000000Z",
            ended_at="2026-11-12T04:00:02.150000Z",
            duration_ms=150.0,
        ),
        token_context=HostTokenContext(
            credential_id=cred_id,
            uid_or_sid="uid-owner-1000",
            sandbox_state="unsandboxed",
        ),
        path_check=PathCheckResult(
            physical_root_ok=True,
            ancestors_ok=True,
            symlink_or_reparse_rejected=True,
        ),
        binding=BindingSummary(
            store_id=store_id,
            writer_epoch=writer_epoch,
            instance_id=instance_id,
            principal_id=principal_id,
            environment=environment,
        ),
        terminal_facts=TerminalToolFacts(
            ready=True,
            tool_name=tool_name,
            ok=True,
            status="ok",
            auth_granted=True,
            response_flushed=True,
            response_digest=response_digest,
            observed_scope=eff_scope,
        ),
    )

    registration = ObserverRegistration(
        evidence_root=evidence_root,
        task_id="task-t9-obs-1",
        run_id=run_id,
        expected_kind=probe_kind,
        registered_observer_id=observer_id,
        registered_channel=channel,
        expected_host=host,
        expected_host_mode=host_mode,
        expected_os=sys.platform,
        expected_source_commit=source_commit,
        expected_shim_build_digest=shim_digest,
        expected_config_path=cfg_path,
        expected_config_digest=cfg_digest,
        expected_profile_path=prof_path,
        expected_profile_digest=prof_digest,
        expected_schema_digest=schema_digest,
        expected_store_id=store_id,
        expected_environment=environment,
        registered_host_versions=("2.1.317",),
        active=True,
    )

    host_call_obs = HostCallObservation(
        call_id=call_id,
        channel=channel,
        host_process=host_proc,
        shim_launcher_process=launcher_proc,
        shim_worker_process=worker_proc,
        tool_name=tool_name,
        terminal_ok=True,
        response_digest=response_digest,
        started_at="2026-11-12T04:00:02.000000Z",
        ended_at="2026-11-12T04:00:02.150000Z",
    )
    owner_call_obs = OwnerCallObservation(
        daemon_process=daemon_proc,
        store_id=store_id,
        writer_epoch=writer_epoch,
        instance_id=instance_id,
        principal_id=principal_id,
        credential_id=cred_id,
        tool_name=tool_name,
        ready=True,
        auth_stamp_matched=True,
        response_flushed_ok=True,
        response_digest=response_digest,
        listen_host="127.0.0.1",
        listen_port=45123,
        started_at="2026-11-12T04:00:02.010000Z",
        ended_at="2026-11-12T04:00:02.140000Z",
        call_id=call_id,
        selected_scope=eff_scope,
        client_host="127.0.0.1",
        client_port=52001,
        client_process=worker_proc,
        connection_id=conn_id,
        observation_status="ok",
    )
    sock_obs = SocketObservation(
        client_process=worker_proc,
        daemon_process=daemon_proc,
        local_addr="127.0.0.1",
        local_port=52001,
        remote_addr="127.0.0.1",
        remote_port=45123,
        store_id=store_id,
        writer_epoch=writer_epoch,
        instance_id=instance_id,
        connection_id=conn_id,
        started_at="2026-11-12T04:00:02.005000Z",
        observed_at="2026-11-12T04:00:02.020000Z",
        ended_at="2026-11-12T04:00:02.145000Z",
        observation_status="ok",
    )

    owner_ready_path = evidence_root / "owner-ready.json"
    owner_events_path = evidence_root / "owner-events.jsonl"
    host_calls_path = evidence_root / "host-calls.jsonl"
    sock_obs_path = evidence_root / "socket-observations.jsonl"
    evidence_index_path = evidence_root / "evidence-index.json"

    owner_ready_path.write_bytes(
        canonical_json(
            {
                "event": "ready",
                "daemon_pid": daemon_proc.pid,
                "daemon_started_at": daemon_proc.started_at,
                "port": 45123,
                "store_id": store_id,
                "writer_epoch": writer_epoch,
                "instance_id": instance_id,
                "module_file": "C:/synthetic/owner.py",
                "schema_sha256": schema_digest,
                "config_digest": cfg_digest,
            }
        )
        + b"\n"
    )
    host_calls_path.write_bytes(
        canonical_json(
            {
                "call_id": call_id,
                "channel": channel,
                "host_process": host_proc.to_dict(),
                "shim_launcher_process": launcher_proc.to_dict(),
                "shim_worker_process": worker_proc.to_dict(),
                "tool_name": tool_name,
                "terminal_ok": True,
                "response_digest": response_digest,
                "started_at": host_call_obs.started_at,
                "ended_at": host_call_obs.ended_at,
            }
        )
        + b"\n"
    )
    owner_events_path.write_bytes(
        canonical_json(
            {
                "event": "owner_call",
                "connection_id": conn_id,
                "observation_status": "ok",
                "daemon_pid": daemon_proc.pid,
                "daemon_started_at": daemon_proc.started_at,
                "store_id": store_id,
                "writer_epoch": writer_epoch,
                "instance_id": instance_id,
                "principal_id": principal_id,
                "credential_id": cred_id,
                "tool_name": tool_name,
                "ready": True,
                "auth_stamp_matched": True,
                "response_flushed_ok": True,
                "response_digest": response_digest,
                "listen_host": "127.0.0.1",
                "listen_port": 45123,
                "client_host": "127.0.0.1",
                "client_port": 52001,
                "client_pid": worker_proc.pid,
                "client_started_at": worker_proc.started_at,
                "started_at": owner_call_obs.started_at,
                "ended_at": owner_call_obs.ended_at,
                "call_id": call_id,
                "selected_scope": eff_scope,
            }
        )
        + b"\n"
    )
    sock_obs_path.write_bytes(
        canonical_json(
            {
                "event": "socket_observation",
                "connection_id": conn_id,
                "observation_status": "ok",
                "client_pid": worker_proc.pid,
                "client_started_at": worker_proc.started_at,
                "daemon_pid": daemon_proc.pid,
                "daemon_started_at": daemon_proc.started_at,
                "local_addr": "127.0.0.1",
                "local_port": 52001,
                "remote_addr": "127.0.0.1",
                "remote_port": 45123,
                "store_id": store_id,
                "writer_epoch": writer_epoch,
                "instance_id": instance_id,
                "started_at": sock_obs.started_at,
                "observed_at": sock_obs.observed_at,
                "ended_at": sock_obs.ended_at,
            }
        )
        + b"\n"
    )
    evidence_index_path.write_bytes(
        canonical_json(
            {
                "schema_version": NATIVE_CONNECTION_SCHEMA_VERSION,
                "task_id": "task-t9-obs-1",
                "run_id": run_id,
                "observer_id": observer_id,
                "source_commit": source_commit,
                "host": host,
                "host_mode": host_mode,
                "host_version": "2.1.317",
                "artifacts": {
                    "config": cfg_digest,
                    "profile": prof_digest,
                    "schema": schema_digest,
                    "shim_build": shim_digest,
                    "owner_ready": digest_bytes(owner_ready_path.read_bytes()),
                    "owner_events": digest_bytes(owner_events_path.read_bytes()),
                    "socket_observations": digest_bytes(sock_obs_path.read_bytes()),
                    "host_calls": digest_bytes(host_calls_path.read_bytes()),
                },
            }
        )
        + b"\n"
    )

    observations = ObservationSet(
        artifact_paths={
            "config": cfg_path,
            "profile": prof_path,
            "schema": schema_path,
            "shim_build": shim_path,
            "evidence_index": evidence_index_path,
            "owner_ready": owner_ready_path,
            "owner_events": owner_events_path,
            "socket_observations": sock_obs_path,
            "host_calls": host_calls_path,
        },
        host_calls=(host_call_obs,),
        owner_events=(owner_call_obs,),
        socket_observations=(sock_obs,),
    )
    return probe, registration, observations, evidence_root


def test_native_report_requires_registered_observer(trusted_tmp: Path) -> None:
    """Registered observer, pinned physical artifacts, path containment, and fixture-vs-native separation."""
    case_dir = trusted_tmp / "obs-case"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, evidence_root = _sample_world(case_dir)

    parsed = parse_native_probe(encode_native_probe(probe))
    assert parsed == probe
    assert verify_native_connection(parsed, registration=reg, observations=obs) is True

    # Coordinator revocation / unregistered observer must reject.
    assert verify_native_connection(probe, registration=replace(reg, active=False), observations=obs) is False
    assert (
        verify_native_connection(probe, registration=replace(reg, registered_channel="other_ch"), observations=obs)
        is False
    )
    assert (
        verify_native_connection(probe, registration=replace(reg, expected_host="codex-desktop"), observations=obs)
        is False
    )
    assert verify_native_connection(probe, registration=replace(reg, task_id="other-task"), observations=obs) is False

    # Self-reported digest lies or tampered on-disk files must reject.
    assert (
        verify_native_connection(
            replace(probe, profile_digest="sha256:" + "9" * 64), registration=reg, observations=obs
        )
        is False
    )
    assert (
        verify_native_connection(replace(probe, config_digest="sha256:" + "8" * 64), registration=reg, observations=obs)
        is False
    )
    reg.expected_profile_path.write_bytes(b'{"tampered":true}\n')
    assert verify_native_connection(probe, registration=reg, observations=obs) is False

    # Restore clean world and test path escape outside evidence_root.
    clean_dir = trusted_tmp / "obs-escape"
    clean_dir.mkdir(parents=True, exist_ok=True)
    probe2, reg2, obs2, ev_root2 = _sample_world(clean_dir)
    outside_file = clean_dir / "outside-profile.json"
    outside_file.write_bytes(reg2.expected_profile_path.read_bytes())
    assert (
        verify_native_connection(
            probe2,
            registration=reg2,
            observations=replace(obs2, artifact_paths={**obs2.artifact_paths, "profile": outside_file}),
        )
        is False
    )
    dotdot_escape = ev_root2 / ".." / "outside-profile.json"
    assert (
        verify_native_connection(
            probe2,
            registration=reg2,
            observations=replace(obs2, artifact_paths={**obs2.artifact_paths, "profile": dotdot_escape}),
        )
        is False
    )

    # Symlink escape inside evidence_root (attempted if OS privilege allows creating test symlinks).
    link_path = ev_root2 / "symlink-profile.json"
    try:
        os.symlink(outside_file, link_path)
    except OSError:
        link_created = False
    else:
        link_created = True
    if link_created:
        assert (
            verify_native_connection(
                probe2,
                registration=reg2,
                observations=replace(obs2, artifact_paths={**obs2.artifact_paths, "profile": link_path}),
            )
            is False
        )

    # A fixture report can NEVER pass native verification, even if registration tries to claim fixture.
    fix_dir = trusted_tmp / "obs-fixture"
    fix_dir.mkdir(parents=True, exist_ok=True)
    fix_probe, fix_reg, fix_obs, _ = _sample_world(fix_dir, kind="fixture")
    assert (
        verify_native_connection(fix_probe, registration=replace(fix_reg, expected_kind="native"), observations=fix_obs)
        is False
    )
    assert verify_native_connection(fix_probe, registration=fix_reg, observations=fix_obs, require_native=True) is False
    assert verify_native_connection(fix_probe, registration=fix_reg, observations=fix_obs, require_native=False) is True


def test_native_call_join_rejects_reused_identity_and_missing_terminal(trusted_tmp: Path) -> None:
    """Full (pid, started_at) process identity, loopback socket join, owner flush, and lifecycle enforcement."""
    # Positive control: launcher == worker when same observed OS process runs the shim directly.
    same_dir = trusted_tmp / "same-proc"
    same_dir.mkdir(parents=True, exist_ok=True)
    probe_same, reg_same, obs_same, _ = _sample_world(same_dir, launcher_same_as_worker=True)
    assert verify_native_connection(probe_same, registration=reg_same, observations=obs_same) is True

    # Full positive control with distinct launcher and worker.
    case_dir = trusted_tmp / "call-join"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir, launcher_same_as_worker=False)
    assert verify_native_connection(probe, registration=reg, observations=obs) is True

    # Reused daemon PID with a different started_at MUST fail.
    assert probe.daemon_process is not None
    reused_daemon = ProcessIdentity(pid=probe.daemon_process.pid, started_at="2026-11-12T04:05:00.000000Z")
    assert (
        verify_native_connection(replace(probe, daemon_process=reused_daemon), registration=reg, observations=obs)
        is False
    )

    # Reused shim worker PID with a different started_at MUST fail.
    assert probe.shim_worker_process is not None
    reused_worker = ProcessIdentity(pid=probe.shim_worker_process.pid, started_at="2026-11-12T04:06:00.000000Z")
    assert (
        verify_native_connection(replace(probe, shim_worker_process=reused_worker), registration=reg, observations=obs)
        is False
    )

    # Reused shim launcher PID with a different started_at MUST fail.
    assert probe.shim_launcher_process is not None
    reused_launcher = ProcessIdentity(pid=probe.shim_launcher_process.pid, started_at="2026-11-12T04:07:00.000000Z")
    assert (
        verify_native_connection(
            replace(probe, shim_launcher_process=reused_launcher), registration=reg, observations=obs
        )
        is False
    )

    # Missing terminal host observation or unauthenticated / unflushed owner reply MUST fail.
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, host_calls=(replace(obs.host_calls[0], terminal_ok=False),)),
        )
        is False
    )
    assert verify_native_connection(probe, registration=reg, observations=replace(obs, host_calls=())) is False
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(replace(obs.owner_events[0], auth_stamp_matched=False),)),
        )
        is False
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(replace(obs.owner_events[0], response_flushed_ok=False),)),
        )
        is False
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(replace(obs.owner_events[0], ready=False),)),
        )
        is False
    )

    # Missing or mismatched socket join MUST fail.
    assert verify_native_connection(probe, registration=reg, observations=replace(obs, socket_observations=())) is False
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                socket_observations=(replace(obs.socket_observations[0], remote_port=9999),),
            ),
        )
        is False
    )

    # Missing runtime fields on passed probe or non-passed probe status MUST fail.
    assert (
        verify_native_connection(replace(probe, shim_worker_process=None), registration=reg, observations=obs)
        is False
    )
    assert verify_native_connection(replace(probe, terminal_facts=None), registration=reg, observations=obs) is False
    assert (
        verify_native_connection(
            replace(probe, status="failed", reason_code="shim_handshake_timeout"),
            registration=reg,
            observations=obs,
        )
        is False
    )

    # Lifecycle workspace transition enforcement inside verifier: reused shim or stale profile rejects!
    probe_d3, reg_d3, obs_d3, _ = _sample_world(case_dir / "d3-lifecycle", tool_name="get_job")
    assert probe_d3.shim_worker_process is not None
    assert probe_d3.profile_digest is not None
    scope_a = Scope(repo_id="repo-t9-a", checkout_id="chk-t9-a")
    scope_b = Scope(repo_id="repo-t9-b", checkout_id="chk-t9-b")
    obs_before = ShimLaunchObservation(
        pid=5001,
        started_at="2026-11-12T04:00:00Z",
        profile_digest="sha256:" + "1" * 64,
        observed_scope=scope_a,
    )
    obs_after_good = ShimLaunchObservation(
        pid=probe_d3.shim_worker_process.pid,
        started_at=probe_d3.shim_worker_process.started_at,
        profile_digest=probe_d3.profile_digest,
        observed_scope=scope_b,
    )
    assert probe_d3.terminal_facts is not None
    probe_b_lc = replace(
        probe_d3,
        terminal_facts=replace(probe_d3.terminal_facts, observed_scope=scope_b.to_dict()),
    )
    ev_root_lc = obs_d3.artifact_paths["config"].parent
    owner_events_lc_path = ev_root_lc / "owner-events-lc.jsonl"
    oc0 = obs_d3.owner_events[0]
    assert oc0.client_process is not None
    owner_events_lc_path.write_bytes(
        canonical_json(
            {
                "event": "owner_call",
                "connection_id": oc0.connection_id,
                "observation_status": oc0.observation_status,
                "daemon_pid": oc0.daemon_process.pid,
                "daemon_started_at": oc0.daemon_process.started_at,
                "store_id": oc0.store_id,
                "writer_epoch": oc0.writer_epoch,
                "instance_id": oc0.instance_id,
                "principal_id": oc0.principal_id,
                "credential_id": oc0.credential_id,
                "tool_name": oc0.tool_name,
                "ready": oc0.ready,
                "auth_stamp_matched": oc0.auth_stamp_matched,
                "response_flushed_ok": oc0.response_flushed_ok,
                "response_digest": oc0.response_digest,
                "listen_host": oc0.listen_host,
                "listen_port": oc0.listen_port,
                "client_host": oc0.client_host,
                "client_port": oc0.client_port,
                "client_pid": oc0.client_process.pid,
                "client_started_at": oc0.client_process.started_at,
                "started_at": oc0.started_at,
                "ended_at": oc0.ended_at,
                "call_id": oc0.call_id,
                "selected_scope": scope_b.to_dict(),
            }
        )
        + b"\n"
    )
    ev_idx_lc_obj = json.loads(obs_d3.artifact_paths["evidence_index"].read_text(encoding="utf-8"))
    ev_idx_lc_obj["artifacts"]["owner_events"] = digest_bytes(owner_events_lc_path.read_bytes())
    ev_idx_lc_path = ev_root_lc / "evidence-index-lc.json"
    ev_idx_lc_path.write_bytes(canonical_json(ev_idx_lc_obj) + b"\n")
    obs_b_lc = replace(
        obs_d3,
        artifact_paths={
            **obs_d3.artifact_paths,
            "owner_events": owner_events_lc_path,
            "evidence_index": ev_idx_lc_path,
        },
        owner_events=(replace(obs_d3.owner_events[0], selected_scope=scope_b.to_dict()),),
        prior_lifecycle=obs_before,
        current_lifecycle=obs_after_good,
        expected_scope=scope_b,
        expected_profile_digest=probe_d3.profile_digest,
        expected_first_scope=scope_a,
    )
    assert verify_native_connection(probe_b_lc, registration=reg_d3, observations=obs_b_lc) is True
    # Contradictory probe observed_scope (scope_a) vs current_lifecycle (scope_b) MUST fail.
    assert (
        verify_native_connection(
            probe_d3,
            registration=reg_d3,
            observations=replace(
                obs_d3,
                prior_lifecycle=obs_before,
                current_lifecycle=obs_after_good,
                expected_scope=scope_b,
                expected_profile_digest=probe_d3.profile_digest,
                expected_first_scope=scope_a,
            ),
        )
        is False
    )
    obs_after_stale = ShimLaunchObservation(
        pid=obs_before.pid,
        started_at=obs_before.started_at,
        profile_digest=obs_before.profile_digest,
        observed_scope=scope_b,
    )
    assert (
        verify_native_connection(
            probe_d3,
            registration=reg_d3,
            observations=replace(
                obs_d3,
                prior_lifecycle=obs_before,
                current_lifecycle=obs_after_stale,
                expected_scope=scope_b,
                expected_profile_digest=probe_d3.profile_digest,
                expected_first_scope=scope_a,
            ),
        )
        is False
    )


def test_native_probe_reason_and_secret_redaction(trusted_tmp: Path) -> None:
    """Strict JSON validation, nullable unobserved facts on non-passed rows, and secret/path redaction."""
    case_dir = trusted_tmp / "redaction"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)

    # Valid non-passed row permits null runtime fields and carries static reason_code.
    not_run_probe = NativeConnectionProbe(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        kind="native",
        status="not_run",
        reason_code="owner_approval_required_d8",
        task_id="task-t9-not-run",
        run_id=None,
        observer_id=None,
        observed_call_id=None,
        observation_channel=None,
        host="codex-desktop",
        host_mode=None,
        host_version=None,
        host_pid=None,
        os=sys.platform,
        source_commit="a" * 40,
        shim_build_digest=None,
        config_digest=None,
        profile_digest=None,
        schema_digest=None,
        host_process=None,
        shim_launcher_process=None,
        shim_worker_process=None,
        daemon_process=None,
        filtered_command=None,
        timespan=None,
        token_context=None,
        path_check=None,
        binding=None,
        terminal_facts=None,
    )
    parsed_nr = parse_native_probe(encode_native_probe(not_run_probe))
    assert parsed_nr == not_run_probe
    assert verify_native_connection(parsed_nr, registration=reg, observations=obs) is False

    # Failed row must require static reason_code; passed row must forbid reason_code.
    bad_passed = probe.to_dict()
    bad_passed["reason_code"] = "unexpected_reason"
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bad_passed))

    bad_failed = not_run_probe.to_dict()
    bad_failed["status"] = "failed"
    bad_failed["reason_code"] = None
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bad_failed))

    # Free-text / path / exception text in reason_code must be rejected without echoing input.
    leaky_reason = r"C:\Users\secret-user\.codex\token-canary FileNotFoundError: nope"
    bad_failed_text = not_run_probe.to_dict()
    bad_failed_text["reason_code"] = leaky_reason
    with pytest.raises(ProbeValidationError) as exc_info:
        parse_native_probe(canonical_json(bad_failed_text))
    assert "secret-user" not in str(exc_info.value)
    assert ".codex" not in str(exc_info.value)

    # Duplicate keys, extra fields, wrong schema_version, and bool-as-int are rejected.
    raw_good = encode_native_probe(probe).decode("utf-8")
    dup_raw = ('{"task_id":"dup-1",' + raw_good.lstrip("{")).encode("utf-8")
    with pytest.raises(ProbeValidationError):
        parse_native_probe(dup_raw)

    extra_obj = probe.to_dict()
    extra_obj["extra_field"] = "unexpected"
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(extra_obj))

    wrong_ver = probe.to_dict()
    wrong_ver["schema_version"] = "sp1-i2-native-connection-v99"
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(wrong_ver))

    bool_int = probe.to_dict()
    bool_int["host_pid"] = True
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bool_int))

    # Secret bearer token, PEM private key, and URI userinfo leaks MUST be rejected and never echoed.
    _, secret_bearer, _, _ = generate_bearer_token()
    canary_pem = "-----BEGIN PRIVATE KEY-----MIIBCanarySecretKey"
    canary_uri = "https://canary-user:canary-pass@internal.invalid/db"

    for field_name, secret_val in (
        ("filtered_command", ["brain", "mcp", "--token", secret_bearer]),
        ("host_version", f"Bearer {secret_bearer}"),
        ("filtered_command", ["brain", "mcp", canary_pem]),
        ("filtered_command", ["brain", "mcp", canary_uri]),
    ):
        leaky_probe = json.loads(encode_native_probe(probe).decode("utf-8"))
        leaky_probe[field_name] = secret_val
        with pytest.raises(ProbeValidationError) as secret_exc:
            parse_native_probe(canonical_json(leaky_probe))
        err_text = str(secret_exc.value)
        assert secret_bearer not in err_text
        assert "CanarySecretKey" not in err_text
        assert "canary-pass" not in err_text

    # Token context itself rejects bearer token in credential_id (UUIDv7 only, never raw token).
    leaky_cred = json.loads(encode_native_probe(probe).decode("utf-8"))
    leaky_cred["token_context"]["credential_id"] = secret_bearer
    with pytest.raises(ProbeValidationError) as cred_exc:
        parse_native_probe(canonical_json(leaky_cred))
    assert secret_bearer not in str(cred_exc.value)


def _utc_now_z() -> str:
    return utc_now_z()


def _extract_mcp_structured(resp_frame: Mapping[str, JsonValue]) -> tuple[bool, dict[str, JsonValue]]:
    assert "result" in resp_frame and "error" not in resp_frame, f"Unexpected JSON-RPC error: {resp_frame!r}"
    result = cast(dict[str, JsonValue], resp_frame["result"])
    is_err = bool(result.get("isError"))
    structured = cast(dict[str, JsonValue], result["structuredContent"])
    return is_err, structured


def _git_head_sha() -> str:
    repo = Path(__file__).resolve().parents[2]
    res = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    sha = res.stdout.strip()
    return sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha) else "b" * 40


def _build_wheel_probe_and_obs(
    *,
    env: InstalledEnv,
    owner: ObservedWheelOwner,
    evidence_root: Path,
    owner_evidence_dir: Path,
    config_path: Path,
    profile_path: Path,
    schema_copy_path: Path,
    task_id: str,
    call_id: str,
    host: str,
    credential_id: str,
    principal_id: str,
    tool_name: str,
    response_envelope: dict[str, JsonValue],
    launcher_proc: ProcessIdentity,
    worker_proc: ProcessIdentity,
    started_at: str,
    ended_at: str,
    observed_scope: Mapping[str, JsonValue] | None = None,
    ready: bool = True,
    prior_lifecycle: ShimLaunchObservation | None = None,
    current_lifecycle: ShimLaunchObservation | None = None,
    expected_scope: Scope | None = None,
    expected_first_scope: Scope | None = None,
    expected_alias: str | None = None,
) -> tuple[NativeConnectionProbe, ObserverRegistration, ObservationSet]:
    source_commit = _git_head_sha()
    shim_bytes = env.wheel_path.read_bytes()
    shim_build_digest = digest_bytes(shim_bytes)
    cfg_digest = digest_bytes(config_path.read_bytes())
    prof_digest = digest_bytes(profile_path.read_bytes())
    schema_digest = digest_bytes(schema_copy_path.read_bytes())
    resp_digest = digest_bytes(canonical_json(response_envelope))
    channel = "wheel_mcp_pipe"
    environment = "installed_wheel"
    host_mode = "wheel_mcp_pipe"
    run_id = f"run-{task_id}-{call_id}"
    observer_id = f"obs-{host}"
    host_proc = ProcessIdentity(pid=os.getpid(), started_at=process_started_at_for_pid(os.getpid()))

    deadline = time.monotonic() + 2.0
    owner_ready_bytes = b""
    owner_events_bytes = b""
    sock_obs_bytes = b""
    owner_events: tuple[OwnerCallObservation, ...] = ()
    sock_events: tuple[SocketObservation, ...] = ()
    matching_owner: list[OwnerCallObservation] = []
    matching_sock: list[SocketObservation] = []
    ready_file = owner_evidence_dir / "owner-ready.json"
    events_file = owner_evidence_dir / "owner-events.jsonl"
    sock_file = owner_evidence_dir / "socket-observations.jsonl"
    while True:
        try:
            cand_ready = ready_file.read_bytes()
            parse_owner_ready(cand_ready)
            cand_events = events_file.read_bytes() if events_file.is_file() else b""
            cand_socks = sock_file.read_bytes() if sock_file.is_file() else b""
            cand_owner = parse_owner_events_jsonl(cand_events)
            cand_sock_obs = parse_socket_observations_jsonl(cand_socks)
        except (OSError, ProbeValidationError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)
            continue
        owner_ready_bytes = cand_ready
        owner_events_bytes = cand_events
        sock_obs_bytes = cand_socks
        owner_events = cand_owner
        sock_events = cand_sock_obs
        matching_owner = [
            ev for ev in owner_events if ev.tool_name == tool_name and ev.response_digest == resp_digest
        ]
        matched_conns = {ev.connection_id for ev in matching_owner if ev.connection_id is not None}
        matched_ports = {ev.listen_port for ev in matching_owner}
        matching_sock = [
            so
            for so in sock_events
            if so.client_process == worker_proc
            and so.remote_port in matched_ports
            and so.connection_id in matched_conns
        ]
        if matching_owner and matching_sock:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.02)

    assert matching_owner, f"Owner tap missing {tool_name} response digest {resp_digest}"
    assert matching_sock, f"Kernel socket table tap did not bind {worker_proc} to owner listen port"

    art_dir = evidence_root / f"artifacts-{call_id}"
    art_dir.mkdir(parents=True, exist_ok=True)
    shim_copy_path = art_dir / "shim-build.whl"
    shim_copy_path.write_bytes(shim_bytes)
    owner_ready_copy = art_dir / "owner-ready.json"
    owner_events_copy = art_dir / "owner-events.jsonl"
    sock_obs_copy = art_dir / "socket-observations.jsonl"
    host_calls_path = art_dir / "host-calls.jsonl"
    evidence_index_path = art_dir / "evidence-index.json"

    owner_ready_copy.write_bytes(owner_ready_bytes)
    owner_events_copy.write_bytes(owner_events_bytes)
    sock_obs_copy.write_bytes(sock_obs_bytes)

    host_call_obs = HostCallObservation(
        call_id=call_id,
        channel=channel,
        host_process=host_proc,
        shim_launcher_process=launcher_proc,
        shim_worker_process=worker_proc,
        tool_name=tool_name,
        terminal_ok=True,
        response_digest=resp_digest,
        started_at=started_at,
        ended_at=ended_at,
    )
    host_calls_bytes = (
        canonical_json(
            {
                "call_id": call_id,
                "channel": channel,
                "host_process": host_proc.to_dict(),
                "shim_launcher_process": launcher_proc.to_dict(),
                "shim_worker_process": worker_proc.to_dict(),
                "tool_name": tool_name,
                "terminal_ok": True,
                "response_digest": resp_digest,
                "started_at": started_at,
                "ended_at": ended_at,
            }
        )
        + b"\n"
    )
    host_calls_path.write_bytes(host_calls_bytes)
    evidence_index_path.write_bytes(
        canonical_json(
            {
                "schema_version": NATIVE_CONNECTION_SCHEMA_VERSION,
                "task_id": task_id,
                "run_id": run_id,
                "observer_id": observer_id,
                "source_commit": source_commit,
                "host": host,
                "host_mode": host_mode,
                "host_version": "0.1.0",
                "artifacts": {
                    "config": cfg_digest,
                    "profile": prof_digest,
                    "schema": schema_digest,
                    "shim_build": shim_build_digest,
                    "owner_ready": digest_bytes(owner_ready_bytes),
                    "owner_events": digest_bytes(owner_events_bytes),
                    "socket_observations": digest_bytes(sock_obs_bytes),
                    "host_calls": digest_bytes(host_calls_bytes),
                },
            }
        )
        + b"\n"
    )

    probe = NativeConnectionProbe(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        kind="fixture",
        status="passed",
        reason_code=None,
        task_id=task_id,
        run_id=run_id,
        observer_id=observer_id,
        observed_call_id=call_id,
        observation_channel=channel,
        host=host,
        host_mode=host_mode,
        host_version="0.1.0",
        host_pid=host_proc.pid,
        os=sys.platform,
        source_commit=source_commit,
        shim_build_digest=shim_build_digest,
        config_digest=cfg_digest,
        profile_digest=prof_digest,
        schema_digest=schema_digest,
        host_process=host_proc,
        shim_launcher_process=launcher_proc,
        shim_worker_process=worker_proc,
        daemon_process=owner.process_identity,
        filtered_command=("brain", "mcp", "--profile", "<redacted-profile-path>"),
        timespan=TimespanRecord(started_at=started_at, ended_at=ended_at, duration_ms=10.0),
        token_context=HostTokenContext(
            credential_id=credential_id,
            uid_or_sid="uid-owner-test",
            sandbox_state="unsandboxed",
        ),
        path_check=PathCheckResult(
            physical_root_ok=True,
            ancestors_ok=True,
            symlink_or_reparse_rejected=True,
        ),
        binding=BindingSummary(
            store_id=owner.store_id,
            writer_epoch=owner.writer_epoch,
            instance_id=owner.instance_id,
            principal_id=principal_id,
            environment=environment,
        ),
        terminal_facts=TerminalToolFacts(
            ready=ready,
            tool_name=tool_name,
            ok=True,
            status="ok",
            auth_granted=True,
            response_flushed=True,
            response_digest=resp_digest,
            observed_scope=observed_scope,
        ),
    )

    registration = ObserverRegistration(
        evidence_root=evidence_root,
        task_id=task_id,
        run_id=run_id,
        expected_kind="fixture",
        registered_observer_id=observer_id,
        registered_channel=channel,
        expected_host=host,
        expected_host_mode=host_mode,
        expected_os=sys.platform,
        expected_source_commit=source_commit,
        expected_shim_build_digest=shim_build_digest,
        expected_config_path=config_path,
        expected_config_digest=cfg_digest,
        expected_profile_path=profile_path,
        expected_profile_digest=prof_digest,
        expected_schema_digest=schema_digest,
        expected_store_id=owner.store_id,
        expected_environment=environment,
        registered_host_versions=("0.1.0",),
        active=True,
    )

    observations = ObservationSet(
        artifact_paths={
            "config": config_path,
            "profile": profile_path,
            "schema": schema_copy_path,
            "shim_build": shim_copy_path,
            "evidence_index": evidence_index_path,
            "owner_ready": owner_ready_copy,
            "owner_events": owner_events_copy,
            "socket_observations": sock_obs_copy,
            "host_calls": host_calls_path,
        },
        host_calls=(host_call_obs,),
        owner_events=owner_events,
        socket_observations=sock_events,
        prior_lifecycle=prior_lifecycle,
        current_lifecycle=current_lifecycle,
        expected_scope=expected_scope,
        expected_profile_digest=prof_digest if current_lifecycle is not None else None,
        expected_first_scope=expected_first_scope,
        expected_alias=expected_alias,
    )
    return probe, registration, observations


def _invoke_wheel_shim_health(
    env: InstalledEnv,
    profile_path: Path,
    *,
    cwd: Path,
) -> tuple[dict[str, JsonValue], ProcessIdentity, ProcessIdentity, str, str]:
    with InstalledMcpPipeSession(
        env,
        "brain",
        ("mcp", "--profile", str(profile_path)),
        cwd=cwd,
    ) as pipe_sess:
        resp_init = pipe_sess.send_frames_and_expect_response(mcp_init_frames(1))
        assert resp_init.get("id") == 1
        started = _utc_now_z()
        resp_health = pipe_sess.send_frames_and_expect_response(
            [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
            ]
        )
        ended = _utc_now_z()
        is_err, health_sc = _extract_mcp_structured(resp_health)
        assert is_err is False
        assert health_sc.get("ok") is True

        launcher_pid = pipe_sess._proc.pid
        descendants = pipe_sess._snapshot_descendants()
        worker_pid = descendants[-1] if descendants else launcher_pid
        launcher_proc = ProcessIdentity(pid=launcher_pid, started_at=process_started_at_for_pid(launcher_pid))
        worker_proc = (
            launcher_proc
            if worker_pid == launcher_pid
            else ProcessIdentity(pid=worker_pid, started_at=process_started_at_for_pid(worker_pid))
        )
        rc_proc, stderr_proc = pipe_sess.finish()
        assert rc_proc == 0
        assert stderr_proc == b""
    return health_sc, launcher_proc, worker_proc, started, ended


def test_two_principals_one_store_id(inc2_installed_env: InstalledEnv) -> None:
    """Two distinct harness principals share one daemon/store_id while same-harness credentials share principal_id."""
    tpl = get_shared_t7_transport_template()
    case_dir = make_trusted_test_dir("inc2-t9-two-principals")
    try:
        outside_cwd = case_dir / "outside-cwd"
        outside_cwd.mkdir(parents=True, exist_ok=True)
        os_adapters().permissions.secure_directory(outside_cwd)
        data_root = case_dir / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)

        adapters = os_adapters()
        rt = open_kernel_job_runtime(data_root, adapters)
        try:
            cred_a = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
            )
            cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m-1")
            cred_a_dup = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
            )
            assert cred_a.principal.principal_id != cred_b.principal.principal_id
            assert cred_a.principal.principal_id == cred_a_dup.principal.principal_id
            rt.store.reconcile_policy()
        finally:
            rt.close()

        cfg_path = write_daemon_config_file(
            case_dir / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        schema_copy = case_dir / "mcp-tools-v2.json"
        schema_copy.write_bytes(inc2_installed_env.source_schema_path.read_bytes())

        cred_a_file = write_credential_file(case_dir / "cred-a.txt", cred_a.token)
        cred_b_file = write_credential_file(case_dir / "cred-b.txt", cred_b.token)
        cred_dup_file = write_credential_file(case_dir / "cred-a-dup.txt", cred_a_dup.token)
        ep_path = data_root / "endpoint.json"
        prof_a, _ = write_client_profile_file(
            case_dir / "profile-a.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_a_file,
        )
        prof_b, _ = write_client_profile_file(
            case_dir / "profile-b.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_b_file,
        )
        prof_dup, _ = write_client_profile_file(
            case_dir / "profile-a-dup.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_dup_file,
        )

        ev_dir = case_dir / "owner-evidence"
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev_dir, cwd=outside_cwd) as owner:
            venv_resolved = str(inc2_installed_env.venv_dir.resolve()).lower()
            assert owner.module_file.lower().startswith(venv_resolved)
            assert owner.schema_sha256 == inc2_installed_env.source_schema_sha256

            sc_a, la_a, wk_a, st_a, en_a = _invoke_wheel_shim_health(inc2_installed_env, prof_a, cwd=outside_cwd)
            probe_a, reg_a, obs_a = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_a,
                schema_copy_path=schema_copy,
                task_id="task-t9-2p-a",
                call_id="call-t9-2p-a",
                host="claude-code",
                credential_id=cred_a.credential_id,
                principal_id=cred_a.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc_a,
                launcher_proc=la_a,
                worker_proc=wk_a,
                started_at=st_a,
                ended_at=en_a,
            )
            assert (
                verify_native_connection(probe_a, registration=reg_a, observations=obs_a, require_native=True) is False
            )
            assert (
                verify_native_connection(probe_a, registration=reg_a, observations=obs_a, require_native=False) is True
            )

            sc_b, la_b, wk_b, st_b, en_b = _invoke_wheel_shim_health(inc2_installed_env, prof_b, cwd=outside_cwd)
            probe_b, reg_b, obs_b = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_b,
                schema_copy_path=schema_copy,
                task_id="task-t9-2p-b",
                call_id="call-t9-2p-b",
                host="codex-desktop",
                credential_id=cred_b.credential_id,
                principal_id=cred_b.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc_b,
                launcher_proc=la_b,
                worker_proc=wk_b,
                started_at=st_b,
                ended_at=en_b,
            )
            assert (
                verify_native_connection(probe_b, registration=reg_b, observations=obs_b, require_native=False) is True
            )

            assert verify_same_daemon(probe_a, probe_b) is True
            assert probe_a.binding is not None and probe_b.binding is not None
            assert probe_a.binding.store_id == probe_b.binding.store_id == tpl.store_id
            assert probe_a.binding.writer_epoch == probe_b.binding.writer_epoch
            assert probe_a.binding.instance_id == probe_b.binding.instance_id
            assert probe_a.binding.principal_id != probe_b.binding.principal_id

            # Two credentials with identical (owner_id, harness_id, machine_id) map to ONE principal_id.
            sc_d, la_d, wk_d, st_d, en_d = _invoke_wheel_shim_health(inc2_installed_env, prof_dup, cwd=outside_cwd)
            probe_dup, reg_dup, obs_dup = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_dup,
                schema_copy_path=schema_copy,
                task_id="task-t9-2p-dup",
                call_id="call-t9-2p-dup",
                host="claude-code",
                credential_id=cred_a_dup.credential_id,
                principal_id=cred_a_dup.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc_d,
                launcher_proc=la_d,
                worker_proc=wk_d,
                started_at=st_d,
                ended_at=en_d,
            )
            assert (
                verify_native_connection(probe_dup, registration=reg_dup, observations=obs_dup, require_native=False)
                is True
            )
            # Same principal with two credentials cannot satisfy two-principal verify_same_daemon.
            assert verify_same_daemon(probe_a, probe_dup) is False
            assert probe_dup.binding is not None
            assert probe_dup.binding.principal_id == probe_a.binding.principal_id
            assert probe_dup.token_context is not None and probe_a.token_context is not None
            assert probe_dup.token_context.credential_id != probe_a.token_context.credential_id

        assert is_writer_lock_held(data_root) is False
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_two_hosts_reject_different_daemon_epochs(inc2_installed_env: InstalledEnv) -> None:
    """Two probes across a daemon restart (different writer_epoch / instance_id) MUST fail verify_same_daemon."""
    tpl = get_shared_t7_transport_template()
    case_dir = make_trusted_test_dir("inc2-t9-diff-epochs")
    try:
        outside_cwd = case_dir / "outside-cwd"
        outside_cwd.mkdir(parents=True, exist_ok=True)
        os_adapters().permissions.secure_directory(outside_cwd)
        data_root = case_dir / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)

        adapters = os_adapters()
        rt = open_kernel_job_runtime(data_root, adapters)
        try:
            cred_1 = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
            )
            cred_2 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m-1")
            rt.store.reconcile_policy()
        finally:
            rt.close()

        cfg_path = write_daemon_config_file(
            case_dir / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        schema_copy = case_dir / "mcp-tools-v2.json"
        schema_copy.write_bytes(inc2_installed_env.source_schema_path.read_bytes())

        cred_1_file = write_credential_file(case_dir / "cred-1.txt", cred_1.token)
        cred_2_file = write_credential_file(case_dir / "cred-2.txt", cred_2.token)
        ep_path = data_root / "endpoint.json"
        prof_1, _ = write_client_profile_file(
            case_dir / "profile-1.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_1_file,
        )
        prof_2, _ = write_client_profile_file(
            case_dir / "profile-2.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_2_file,
        )

        ev1 = case_dir / "ev-epoch-1"
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev1, cwd=outside_cwd) as owner1:
            sc1, la1, wk1, st1, en1 = _invoke_wheel_shim_health(inc2_installed_env, prof_1, cwd=outside_cwd)
            probe_1, reg_1, obs_1 = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner1,
                evidence_root=case_dir,
                owner_evidence_dir=ev1,
                config_path=cfg_path,
                profile_path=prof_1,
                schema_copy_path=schema_copy,
                task_id="task-t9-epoch-1",
                call_id="call-t9-epoch-1",
                host="claude-code",
                credential_id=cred_1.credential_id,
                principal_id=cred_1.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc1,
                launcher_proc=la1,
                worker_proc=wk1,
                started_at=st1,
                ended_at=en1,
            )
            assert (
                verify_native_connection(probe_1, registration=reg_1, observations=obs_1, require_native=False) is True
            )
            sc1b, la1b, wk1b, st1b, en1b = _invoke_wheel_shim_health(inc2_installed_env, prof_2, cwd=outside_cwd)
            probe_1b, reg_1b, obs_1b = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner1,
                evidence_root=case_dir,
                owner_evidence_dir=ev1,
                config_path=cfg_path,
                profile_path=prof_2,
                schema_copy_path=schema_copy,
                task_id="task-t9-epoch-1b",
                call_id="call-t9-epoch-1b",
                host="codex-desktop",
                credential_id=cred_2.credential_id,
                principal_id=cred_2.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc1b,
                launcher_proc=la1b,
                worker_proc=wk1b,
                started_at=st1b,
                ended_at=en1b,
            )
            assert (
                verify_native_connection(probe_1b, registration=reg_1b, observations=obs_1b, require_native=False)
                is True
            )

        assert is_writer_lock_held(data_root) is False

        ev2 = case_dir / "ev-epoch-2"
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev2, cwd=outside_cwd) as owner2:
            sc2, la2, wk2, st2, en2 = _invoke_wheel_shim_health(inc2_installed_env, prof_2, cwd=outside_cwd)
            probe_2, reg_2, obs_2 = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner2,
                evidence_root=case_dir,
                owner_evidence_dir=ev2,
                config_path=cfg_path,
                profile_path=prof_2,
                schema_copy_path=schema_copy,
                task_id="task-t9-epoch-2",
                call_id="call-t9-epoch-2",
                host="codex-desktop",
                credential_id=cred_2.credential_id,
                principal_id=cred_2.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc2,
                launcher_proc=la2,
                worker_proc=wk2,
                started_at=st2,
                ended_at=en2,
            )
            assert (
                verify_native_connection(probe_2, registration=reg_2, observations=obs_2, require_native=False) is True
            )

        assert verify_same_daemon(probe_1, probe_1b) is True
        assert verify_same_daemon(probe_1, probe_1) is False
        assert probe_1.binding is not None and probe_2.binding is not None
        assert probe_2.binding.writer_epoch > probe_1.binding.writer_epoch
        assert probe_2.binding.instance_id != probe_1.binding.instance_id
        assert verify_same_daemon(probe_1, probe_2) is False

        # Even if writer_epoch differs alone, instance_id differs alone, or daemon started_at differs, reject.
        assert (
            probe_1b.binding is not None
            and probe_1b.daemon_process is not None
            and probe_1b.terminal_facts is not None
        )
        assert (
            verify_same_daemon(probe_1, replace(probe_1b, binding=replace(probe_1b.binding, writer_epoch=999))) is False
        )
        assert (
            verify_same_daemon(probe_1, replace(probe_1b, binding=replace(probe_1b.binding, instance_id="inst-other")))
            is False
        )
        assert (
            verify_same_daemon(
                probe_1,
                replace(probe_1b, daemon_process=replace(probe_1b.daemon_process, started_at="2026-11-12T05:00:00Z")),
            )
            is False
        )
        assert (
            verify_same_daemon(probe_1, replace(probe_1b, terminal_facts=replace(probe_1b.terminal_facts, ready=False)))
            is False
        )
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_native_workspace_transition_rejects_stale_shim_and_scope(inc2_installed_env: InstalledEnv) -> None:
    """Real wheel shims enforce scoped get_job checkout boundaries and reject reused shims across workspace switch."""
    tpl = get_shared_t7_transport_template()
    case_dir = make_trusted_test_dir("inc2-t9-ws-transition")
    try:
        outside_cwd = case_dir / "outside-cwd"
        chk_a = case_dir / "workspaces" / "repo-a"
        chk_b = case_dir / "workspaces" / "repo-b"
        for d in (outside_cwd, chk_a, chk_b):
            d.mkdir(parents=True, exist_ok=True)
            os_adapters().permissions.secure_directory(d)
        data_root = case_dir / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)

        adapters = os_adapters()
        clock = FakeClock(datetime.now(UTC))
        rt = open_kernel_job_runtime(data_root, adapters)
        try:
            cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1")
            ws_a = register_workspace_direct(
                rt,
                clock,
                cred.principal,
                alias="ws-t9-a",
                checkout_dir=chk_a,
                remote="https://github.example/dan/repo-a.git",
            )
            ws_b = register_workspace_direct(
                rt,
                clock,
                cred.principal,
                alias="ws-t9-b",
                checkout_dir=chk_b,
                remote="https://github.example/dan/repo-b.git",
            )
            stager = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
            svc = JobService(stager, stager, rt.policy, clock, writer_epoch=rt.lease.epoch)
            job_a = enqueue_job(
                svc, stager, owner_id="dan", payload=b"job-a", repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id
            )
            job_b = enqueue_job(
                svc, stager, owner_id="dan", payload=b"job-b", repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id
            )
            rt.store.reconcile_policy()
        finally:
            rt.close()

        scope_a = Scope(repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id)
        scope_b = Scope(repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id)

        cfg_path = write_daemon_config_file(
            case_dir / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        schema_copy = case_dir / "mcp-tools-v2.json"
        schema_copy.write_bytes(inc2_installed_env.source_schema_path.read_bytes())

        cred_file = write_credential_file(case_dir / "cred.txt", cred.token)
        ep_path = data_root / "endpoint.json"
        prof_a, digest_a = write_client_profile_file(
            case_dir / "profile-ws-a.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_file,
            workspace={
                "alias": ws_a.alias,
                "checkout_path": str(chk_a),
                "expected_workspace_id": ws_a.repo_id,
                "expected_checkout_id": ws_a.checkout_id,
            },
        )
        prof_b, digest_b = write_client_profile_file(
            case_dir / "profile-ws-b.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_file,
            workspace={
                "alias": ws_b.alias,
                "checkout_path": str(chk_b),
                "expected_workspace_id": ws_b.repo_id,
                "expected_checkout_id": ws_b.checkout_id,
            },
        )
        assert digest_a != digest_b

        ev_dir = case_dir / "owner-ev"
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev_dir, cwd=outside_cwd) as owner:
            # 1. Workspace A shim: get_health ready, job_a authorized, job_b cross-checkout denied, ws-b hint refused.
            with InstalledMcpPipeSession(
                inc2_installed_env, "brain", ("mcp", "--profile", str(prof_a)), cwd=chk_a
            ) as sess_a:
                sess_a.send_frames_and_expect_response(mcp_init_frames(1))
                resp_ha = sess_a.send_frames_and_expect_response(
                    [
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    ]
                )
                is_err_h, sc_ha = _extract_mcp_structured(resp_ha)
                assert is_err_h is False and cast(dict[str, Any], sc_ha["data"])["ready"] is True

                st_a = _utc_now_z()
                resp_ja = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_a.job_id})]
                )
                en_a = _utc_now_z()
                is_err_ja, sc_ja = _extract_mcp_structured(resp_ja)
                assert is_err_ja is False and sc_ja["ok"] is True
                assert cast(dict[str, Any], sc_ja["data"])["job_id"] == job_a.job_id

                resp_jb_denied = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": job_b.job_id})]
                )
                is_err_jbd, sc_jbd = _extract_mcp_structured(resp_jb_denied)
                assert is_err_jbd is True and sc_jbd == {
                    "ok": False,
                    "error": {"code": "not_found", "message": "not found"},
                }

                resp_hint_bad = sess_a.send_frames_and_expect_response(
                    [
                        mcp_call_frame(
                            5,
                            "get_job",
                            {"schema_version": "2.0", "job_id": job_a.job_id, "workspace_hint": "ws-t9-b"},
                        )
                    ]
                )
                is_err_hb, sc_hb = _extract_mcp_structured(resp_hint_bad)
                assert is_err_hb is True and sc_hb == {
                    "ok": False,
                    "error": {"code": "identity_mismatch", "message": "identity mismatch"},
                }
                la_a_pid = sess_a._proc.pid
                desc_a = sess_a._snapshot_descendants()
                wk_a_pid = desc_a[-1] if desc_a else la_a_pid
                la_a = ProcessIdentity(pid=la_a_pid, started_at=process_started_at_for_pid(la_a_pid))
                wk_a = (
                    la_a
                    if wk_a_pid == la_a_pid
                    else ProcessIdentity(pid=wk_a_pid, started_at=process_started_at_for_pid(wk_a_pid))
                )
                rc_a, err_a = sess_a.finish()
                assert rc_a == 0 and err_a == b""

            obs_ws_a = ShimLaunchObservation(
                pid=wk_a.pid,
                started_at=wk_a.started_at,
                profile_digest=digest_a,
                observed_scope=scope_a,
                profile_path=prof_a,
                launch_cwd=chk_a,
                reported_alias="ws-t9-a",
            )
            probe_a, reg_a, obs_a = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_a,
                schema_copy_path=schema_copy,
                task_id="task-t9-ws-a",
                call_id="call-t9-ws-a",
                host="claude-code",
                credential_id=cred.credential_id,
                principal_id=cred.principal.principal_id,
                tool_name="get_job",
                response_envelope=sc_ja,
                launcher_proc=la_a,
                worker_proc=wk_a,
                started_at=st_a,
                ended_at=en_a,
                observed_scope=scope_a.to_dict(),
            )
            assert (
                verify_native_connection(probe_a, registration=reg_a, observations=obs_a, require_native=False) is True
            )

            # 2. Attempting to claim workspace B transition using stale shim A MUST fail!
            assert (
                verify_native_connection(
                    probe_a,
                    registration=reg_a,
                    observations=replace(
                        obs_a,
                        prior_lifecycle=obs_ws_a,
                        current_lifecycle=obs_ws_a,
                        expected_scope=scope_b,
                        expected_profile_digest=digest_b,
                        expected_first_scope=scope_a,
                        expected_alias="ws-t9-b",
                    ),
                    require_native=False,
                )
                is False
            )

            # 3. Fresh shim B launched with profile B in chk_b accesses job_b cleanly and rejects job_a!
            with InstalledMcpPipeSession(
                inc2_installed_env, "brain", ("mcp", "--profile", str(prof_b)), cwd=chk_b
            ) as sess_b:
                sess_b.send_frames_and_expect_response(mcp_init_frames(1))
                resp_hb = sess_b.send_frames_and_expect_response(
                    [
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    ]
                )
                is_err_hb2, sc_hb2 = _extract_mcp_structured(resp_hb)
                assert is_err_hb2 is False and cast(dict[str, Any], sc_hb2["data"])["ready"] is True

                st_b = _utc_now_z()
                resp_jb = sess_b.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_b.job_id})]
                )
                en_b = _utc_now_z()
                is_err_jb, sc_jb = _extract_mcp_structured(resp_jb)
                assert is_err_jb is False and sc_jb["ok"] is True
                assert cast(dict[str, Any], sc_jb["data"])["job_id"] == job_b.job_id

                resp_ja_denied = sess_b.send_frames_and_expect_response(
                    [mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": job_a.job_id})]
                )
                is_err_jad, sc_jad = _extract_mcp_structured(resp_ja_denied)
                assert is_err_jad is True and sc_jad == {
                    "ok": False,
                    "error": {"code": "not_found", "message": "not found"},
                }

                la_b_pid = sess_b._proc.pid
                desc_b = sess_b._snapshot_descendants()
                wk_b_pid = desc_b[-1] if desc_b else la_b_pid
                la_b = ProcessIdentity(pid=la_b_pid, started_at=process_started_at_for_pid(la_b_pid))
                wk_b = (
                    la_b
                    if wk_b_pid == la_b_pid
                    else ProcessIdentity(pid=wk_b_pid, started_at=process_started_at_for_pid(wk_b_pid))
                )
                rc_b, err_b = sess_b.finish()
                assert rc_b == 0 and err_b == b""

            assert wk_b != wk_a
            obs_ws_b = ShimLaunchObservation(
                pid=wk_b.pid,
                started_at=wk_b.started_at,
                profile_digest=digest_b,
                observed_scope=scope_b,
                profile_path=prof_b,
                launch_cwd=chk_b,
                reported_alias="ws-t9-b",
            )
            probe_b, reg_b, obs_b = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_b,
                schema_copy_path=schema_copy,
                task_id="task-t9-ws-b",
                call_id="call-t9-ws-b",
                host="claude-code",
                credential_id=cred.credential_id,
                principal_id=cred.principal.principal_id,
                tool_name="get_job",
                response_envelope=sc_jb,
                launcher_proc=la_b,
                worker_proc=wk_b,
                started_at=st_b,
                ended_at=en_b,
                observed_scope=scope_b.to_dict(),
                prior_lifecycle=obs_ws_a,
                current_lifecycle=obs_ws_b,
                expected_scope=scope_b,
                expected_first_scope=scope_a,
                expected_alias="ws-t9-b",
            )
            assert (
                verify_native_connection(probe_b, registration=reg_b, observations=obs_b, require_native=False) is True
            )
            assert probe_a.binding is not None and probe_b.binding is not None
            assert probe_a.daemon_process == probe_b.daemon_process
            assert probe_a.binding.store_id == probe_b.binding.store_id
            assert probe_a.binding.writer_epoch == probe_b.binding.writer_epoch
            assert probe_a.binding.instance_id == probe_b.binding.instance_id
            # Same principal switching workspaces must not pass the two-principal verify_same_daemon gate.
            assert verify_same_daemon(probe_a, probe_b) is False
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)



def test_native_verifier_enforces_monotonic_timestamps_unique_joins_scope_and_lifecycle(trusted_tmp: Path) -> None:
    """Verifier rejects non-monotonic times, ambiguous/conflicting joins, asymmetric scopes, and stale lifecycles."""
    case_dir = trusted_tmp / "audit-contract-v2"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)
    assert verify_native_connection(probe, registration=reg, observations=obs) is True
    assert (
        probe.daemon_process is not None
        and probe.shim_worker_process is not None
        and probe.terminal_facts is not None
        and probe.profile_digest is not None
    )

    hc = obs.host_calls[0]
    oc = obs.owner_events[0]
    so = obs.socket_observations[0]

    # 1. Daemon started_at AFTER call ended_at must reject.
    future_daemon = ProcessIdentity(pid=probe.daemon_process.pid, started_at="2099-01-01T00:00:00.000000Z")
    assert (
        verify_native_connection(
            replace(probe, daemon_process=future_daemon),
            registration=reg,
            observations=replace(
                obs,
                owner_events=(replace(oc, daemon_process=future_daemon),),
                socket_observations=(replace(so, daemon_process=future_daemon),),
            ),
        )
        is False
    )

    # 2. Worker process spawned BEFORE its launcher/host parent must reject.
    impossible_worker = ProcessIdentity(pid=probe.shim_worker_process.pid, started_at="2020-01-01T00:00:00.000000Z")
    assert (
        verify_native_connection(
            replace(probe, shim_worker_process=impossible_worker),
            registration=reg,
            observations=replace(
                obs,
                host_calls=(replace(hc, shim_worker_process=impossible_worker),),
                socket_observations=(replace(so, client_process=impossible_worker),),
            ),
        )
        is False
    )

    # 3. Disjoint host vs owner call timestamps (2020 vs 2099) must reject.
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                host_calls=(
                    replace(hc, started_at="2020-01-01T00:00:00.000000Z", ended_at="2020-01-01T00:00:01.000000Z"),
                ),
                owner_events=(
                    replace(oc, started_at="2099-01-01T00:00:00.000000Z", ended_at="2099-01-01T00:00:01.000000Z"),
                ),
            ),
        )
        is False
    )

    # 4. Conflicting failed owner event alongside healthy one (even with call_id=None) must reject.
    oc_anon = replace(oc, call_id=None)
    oc_failed = replace(oc_anon, ready=False, auth_stamp_matched=False, response_flushed_ok=False)
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(oc_anon, oc_failed)),
        )
        is False
    )

    # 5. Ambiguous duplicate matching owner events when call_id=None must reject.
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(oc_anon, oc_anon)),
        )
        is False
    )

    # 6. Conflicting SocketObservation on the same local/remote 4-tuple must reject.
    so_spoofed = replace(so, client_process=ProcessIdentity(pid=99999, started_at=probe.shim_worker_process.started_at))
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, socket_observations=(so, so_spoofed)),
        )
        is False
    )

    # 7. Probe omitting observed_scope while owner selected a workspace scope must reject.
    probe_d3, reg_d3, obs_d3, _ = _sample_world(case_dir / "d3-scope", tool_name="get_job")
    assert probe_d3.shim_worker_process is not None
    assert probe_d3.profile_digest is not None
    assert probe_d3.terminal_facts is not None
    assert verify_native_connection(probe_d3, registration=reg_d3, observations=obs_d3) is True
    probe_no_scope = replace(probe_d3, terminal_facts=replace(probe_d3.terminal_facts, observed_scope=None))
    oc_d3 = obs_d3.owner_events[0]
    oc_scoped = replace(oc_d3, selected_scope={"repo_id": "repo-t9-a", "checkout_id": "chk-t9-a"})
    assert (
        verify_native_connection(
            probe_no_scope,
            registration=reg_d3,
            observations=replace(obs_d3, owner_events=(oc_scoped,)),
        )
        is False
    )

    # 8. Disconnected current_lifecycle (valid transition between unrelated PIDs/profiles) must reject.
    prior_lc = ShimLaunchObservation(
        pid=probe_d3.shim_worker_process.pid - 10,
        started_at="2026-11-12T04:00:00.000000Z",
        profile_digest="sha256:" + "1" * 64,
        observed_scope=Scope("repo-t9-other", "chk-t9-other"),
        launch_cwd=case_dir / "chk-other",
    )
    bogus_curr_lc = ShimLaunchObservation(
        pid=probe_d3.shim_worker_process.pid + 50,
        started_at="2026-11-12T04:00:01.900000Z",
        profile_digest=probe_d3.profile_digest,
        observed_scope=Scope("repo-t9-a", "chk-t9-a"),
        launch_cwd=case_dir / "chk-a",
    )
    assert (
        verify_native_connection(
            probe_d3,
            registration=reg_d3,
            observations=replace(
                obs_d3,
                prior_lifecycle=prior_lc,
                current_lifecycle=bogus_curr_lc,
                expected_scope=Scope("repo-t9-a", "chk-t9-a"),
                expected_profile_digest=probe_d3.profile_digest,
                expected_first_scope=Scope("repo-t9-other", "chk-t9-other"),
            ),
        )
        is False
    )

    # 9. Case-insensitive Windows path pointing to the same physical file succeeds.
    if sys.platform == "win32":
        cfg_lower = Path(str(reg.expected_config_path).lower())
        assert (
            verify_native_connection(
                probe,
                registration=reg,
                observations=replace(obs, artifact_paths={**obs.artifact_paths, "config": cfg_lower}),
            )
            is True
        )


def test_native_same_daemon_rejects_same_principal_and_mismatched_runtime(trusted_tmp: Path) -> None:
    """verify_same_daemon requires two distinct principals on the exact same live daemon, store, epoch, and runtime."""
    case_dir = trusted_tmp / "audit-same-daemon"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe_a, _, _, _ = _sample_world(case_dir)
    assert probe_a.token_context is not None and probe_a.binding is not None

    probe_same_prin_diff_cred = replace(
        probe_a,
        observed_call_id="call-t9-cred2",
        token_context=HostTokenContext(
            credential_id="01a1cde6-cd6e-7158-8702-5ff8cb44b099",
            uid_or_sid=probe_a.token_context.uid_or_sid,
            sandbox_state=probe_a.token_context.sandbox_state,
        ),
    )
    assert verify_same_daemon(probe_a, probe_same_prin_diff_cred) is False
    assert verify_same_daemon(probe_a, probe_a) is False

    probe_b = replace(
        probe_a,
        observed_call_id="call-t9-prin2",
        host="codex-desktop",
        host_mode="codex_desktop_gui",
        host_version="0.166.0-alpha.6",
        binding=replace(probe_a.binding, principal_id="prin-t9-2"),
        token_context=HostTokenContext(
            credential_id="01a1cde6-cd6e-7158-8702-5ff8cb44b077",
            uid_or_sid="uid-owner-1000",
            sandbox_state="unsandboxed",
        ),
    )
    assert verify_same_daemon(probe_a, probe_b) is True
    assert probe_b.binding is not None
    assert verify_same_daemon(probe_a, replace(probe_b, kind="fixture")) is False
    assert (
        verify_same_daemon(
            probe_a,
            replace(probe_b, binding=replace(probe_b.binding, environment="fixture_test")),
        )
        is False
    )
    assert verify_same_daemon(probe_a, replace(probe_b, os="linux")) is False
    assert verify_same_daemon(probe_a, replace(probe_b, source_commit="b" * 40)) is False


def test_posix_socket_pid_lookup_and_concurrent_owner_call_client_binding(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSIX loopback PID lookup parses /proc and lsof cleanly; OwnerCallObservation retains socket client identity."""
    from tests.support import inc2_native_owner as native_owner

    # 1. Synthetic Linux /proc/net/tcp + /proc/<pid>/fd socket inode lookup.
    proc_root = trusted_tmp / "fake_proc"
    (proc_root / "net").mkdir(parents=True)
    # 127.0.0.1 in little-endian hex is 0100007F; 55158 -> D776, 55157 -> D775.
    (proc_root / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:D776 0100007F:D775 01 00000000:00000000 00:00000000 00000000  1000        0 998877 1 0 0 0 0\n"
        "   1: 0100007F:D775 0100007F:D776 01 00000000:00000000 00:00000000 00000000  1000        0 112233 1 0 0 0 0\n",
        encoding="utf-8",
    )
    # Verify non-None dispatch on mocked Linux/Darwin even when testing parser paths via monkeypatch.
    monkeypatch.setattr(sys, "platform", "linux")
    fake_fd_dir = proc_root / "4242" / "fd"
    fake_fd_dir.mkdir(parents=True)
    monkeypatch.setattr(native_owner, "_LINUX_PROC_ROOT", proc_root, raising=False)
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "socket:[998877]" if str(path).endswith("fd\\3") or str(path).endswith("fd/3") else "",
    )
    (fake_fd_dir / "3").write_text("", encoding="utf-8")
    assert native_owner._lookup_loopback_client_pid(55158, 55157) == 4242

    # 2. Synthetic macOS lsof output parsing.
    monkeypatch.setattr(sys, "platform", "darwin")
    lsof_out = "p1111\nn127.0.0.1:55157->127.0.0.1:55158\np2222\nn127.0.0.1:55158->127.0.0.1:55157\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=lsof_out, stderr=""),
    )
    assert native_owner._lookup_loopback_client_pid(55158, 55157) == 2222

    # 3. Client endpoint disambiguation across two concurrent workers with identical get_health replies.
    case_dir = trusted_tmp / "client-bind"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)
    assert probe.shim_worker_process is not None
    worker_other = ProcessIdentity(
        pid=probe.shim_worker_process.pid + 1,
        started_at=probe.shim_worker_process.started_at,
    )
    oc_wrong_client = replace(
        obs.owner_events[0],
        call_id=None,
        client_host="127.0.0.1",
        client_port=52009,
        client_process=worker_other,
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, owner_events=(oc_wrong_client,)),
        )
        is False
    )


def test_owner_driver_revoked_stamp_error_logging_and_cutoff_cleanup(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Owner driver records failed calls, refuses response_flushed_ok on revoked stamp, and never leaks pending_cmds."""
    from superbrain.cli_api._loopback_server import LoopbackServer
    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_cli as cli
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import open_test_loopback_transport

    tpl = get_shared_t7_transport_template()
    case_dir = trusted_tmp / "owner-hooks"
    data_dir = case_dir / "data"
    clone_owner_only_tree(tpl.root, data_dir)
    os_adapters().permissions.secure_directory(data_dir)

    cfg_path = write_daemon_config_file(
        case_dir / "daemon.json",
        data_root=data_dir,
        expected_store_id=tpl.store_id,
        cert_path=tpl.tls.cert_path,
        key_path=tpl.tls.key_path,
    )
    cred_path = write_credential_file(case_dir / "cred.txt", tpl.cred.token)
    profile_path, _ = write_client_profile_file(
        case_dir / "profile.json",
        endpoint_path=data_dir / "endpoint.json",
        expected_store_id=tpl.store_id,
        ca_file=tpl.tls.ca_cert_path,
        leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
        credential_file=cred_path,
    )
    ev_dir = case_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev_dir, cwd=case_dir):
        with InstalledMcpPipeSession(
            inc2_installed_env, "brain-mcp", ["--profile", str(profile_path)], cwd=case_dir
        ) as session:
            session.send_frames_and_expect_response(mcp_init_frames(1))
            err_resp = session.send_frames_and_expect_response(
                [mcp_call_frame(2, "get_job", {"schema_version": "2.0", "job_id": "missing-audit-job"})]
            )
            err_is_err, err_env = _extract_mcp_structured(err_resp)
            assert err_is_err is True
            assert err_env["ok"] is False

    _, calls, _ = load_owner_observations(ev_dir)
    assert any(c.tool_name == "get_job" and not c.auth_stamp_matched for c in calls), (
        f"Expected failed get_job owner_call observation, got {calls!r}"
    )

    # In-process LoopbackServer hook check for concurrent authorize_stamp revocation & pending_cmds cleanup.
    import queue
    import ssl

    hook_ev = case_dir / "hook-ev"
    hook_ev.mkdir(parents=True, exist_ok=True)
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()
    recorded: list[dict[str, object]] = []
    install_fn = native_owner._install_loopback_server_hooks
    hook_state = install_fn(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-hook",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
    )
    try:
        with open_test_loopback_transport(tpl, name="stamp-revoke") as h:
            client = h.open_client()
            target = h.make_target()
            auth_gate: Any = h.server._owner.auth_gate
            orig_auth = auth_gate.authorize_stamp
            auth_gate.authorize_stamp = lambda _stamp: False
            try:
                res = client.call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-revoke",
                    ),
                )
            finally:
                auth_gate.authorize_stamp = orig_auth
            assert res.get("ok") is False

            # Abrupt TLS close mid-body must not leak pending_cmds entries.
            ctx = ssl.create_default_context(cafile=str(tpl.tls.ca_cert_path))
            import socket

            raw = socket.create_connection(("127.0.0.1", h.bound.port), timeout=2.0)
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as ss:
                ss.sendall(b"POST /v1/tool HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4096\r\n\r\n{")
            import time

            time.sleep(0.1)
    finally:
        hook_state["uninstall"]()
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            recorded.append(item)

    revoked_calls = [r for r in recorded if r.get("event") == "owner_call" and r.get("tool_name") == "get_health"]
    assert len(revoked_calls) == 1
    assert revoked_calls[0]["ready"] is False
    assert revoked_calls[0]["auth_stamp_matched"] is False
    assert revoked_calls[0]["response_flushed_ok"] is False
    assert hook_state["pending_count"]() == 0

    # Even when ready_seen=True, a get_health error envelope (ok=False) MUST emit ready=False.
    eq_err: queue.Queue[dict[str, object] | None] = queue.Queue()
    hook_err = install_fn(
        eq=eq_err,
        store_id=tpl.store_id,
        instance_id="inst-hook-err",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
        initial_ready=True,
    )
    try:
        with open_test_loopback_transport(tpl, name="health-err-envelope") as h:
            client = h.open_client()
            target = h.make_target()
            err_health_res = client.call(
                target,
                ToolCommand(
                    tool="get_health",
                    arguments={"schema_version": "2.0", "unexpected": 1},
                    token=tpl.cred.token,
                    selected_scope=None,
                    correlation_id="corr-health-err",
                ),
            )
            assert err_health_res.get("ok") is False
    finally:
        hook_err["uninstall"]()
    err_recorded: list[dict[str, object]] = []
    while not eq_err.empty():
        item = eq_err.get_nowait()
        if item is not None:
            err_recorded.append(item)
    health_err_calls = [
        r for r in err_recorded if r.get("event") == "owner_call" and r.get("tool_name") == "get_health"
    ]
    assert len(health_err_calls) == 1
    assert health_err_calls[0]["ready"] is False
    assert health_err_calls[0]["auth_stamp_matched"] is False
    assert health_err_calls[0]["response_flushed_ok"] is True
    assert hook_err["pending_count"]() == 0
    _ = LoopbackServer
    _ = cli


def test_two_concurrent_live_shims_same_repo_checkouts_replaced_root_and_reused_pid(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Covers concurrent live shims, same-repo checkouts, CWD refusal, stale profile, and replaced data_root."""
    from tests.support.inc2_fixture import kernel_job_service
    from tests.support.inc2_lifecycle import workspace_transition_matches
    from tests.support.inc2_transport import make_trusted_test_dir

    tpl = get_shared_t7_transport_template()
    base = make_trusted_test_dir("t9-audit-step92")
    try:
        data_root = base / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)

        chk_a = base / "chk-a"
        chk_a2 = base / "chk-a2"
        outside_cwd = base / "outside-cwd"
        outside_cwd.mkdir(parents=True, exist_ok=True)
        os_adapters().permissions.secure_directory(outside_cwd)

        adapters = os_adapters(clock=FakeClock(tpl.base_time))
        rt = open_kernel_job_runtime(data_root, adapters)
        try:
            assert tpl.dan is not None and tpl.cred_b is not None and tpl.cred_bob is not None
            ws_a = register_workspace_direct(
                rt,
                FakeClock(tpl.base_time),
                tpl.dan,
                alias="same-repo-a",
                checkout_dir=chk_a,
                remote="https://github.example/dan/shared-repo.git",
            )
            ws_a2 = register_workspace_direct(
                rt,
                FakeClock(tpl.base_time),
                tpl.dan,
                alias="same-repo-a2",
                checkout_dir=chk_a2,
                remote="https://github.example/dan/shared-repo.git",
            )
            assert ws_a.repo_id == ws_a2.repo_id
            assert ws_a.checkout_id != ws_a2.checkout_id
            service, staged_store = kernel_job_service(rt, FakeClock(tpl.base_time))
            job_a = enqueue_job(
                service,
                staged_store,
                owner_id="dan",
                payload=b"checkout-a",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
            )
            job_a2 = enqueue_job(
                service,
                staged_store,
                owner_id="dan",
                payload=b"checkout-a2",
                repo_id=ws_a2.repo_id,
                checkout_id=ws_a2.checkout_id,
            )
        finally:
            rt.close()

        cfg_path = write_daemon_config_file(
            base / "evidence" / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        schema_copy = base / "evidence" / "mcp-tools-v2.json"
        schema_copy.write_bytes(inc2_installed_env.source_schema_path.read_bytes())

        cred1_p = write_credential_file(base / "cred1.txt", tpl.cred.token)
        cred2_p = write_credential_file(base / "cred2.txt", tpl.cred_b.token)
        bob_p = write_credential_file(base / "bob.txt", tpl.cred_bob.token)

        prof_a, digest_a = write_client_profile_file(
            base / "evidence" / "prof-a.json",
            endpoint_path=data_root / "endpoint.json",
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred1_p,
            workspace={
                "alias": ws_a.alias,
                "checkout_path": str(chk_a),
                "expected_workspace_id": ws_a.repo_id,
                "expected_checkout_id": ws_a.checkout_id,
            },
        )
        prof_a2, digest_a2 = write_client_profile_file(
            base / "evidence" / "prof-a2.json",
            endpoint_path=data_root / "endpoint.json",
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred2_p,
            workspace={
                "alias": ws_a2.alias,
                "checkout_path": str(chk_a2),
                "expected_workspace_id": ws_a2.repo_id,
                "expected_checkout_id": ws_a2.checkout_id,
            },
        )
        prof_bob, _ = write_client_profile_file(
            base / "evidence" / "prof-bob.json",
            endpoint_path=data_root / "endpoint.json",
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=bob_p,
        )

        ev_dir = base / "owner-ev"
        ev_dir.mkdir(parents=True, exist_ok=True)
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev_dir, cwd=base) as owner:
            # Open TWO shims CONCURRENTLY (same repo, two checkouts; plus third principal bob).
            with (
                InstalledMcpPipeSession(
                    inc2_installed_env, "brain-mcp", ["--profile", str(prof_a)], cwd=chk_a
                ) as sess_a,
                InstalledMcpPipeSession(
                    inc2_installed_env, "brain-mcp", ["--profile", str(prof_a2)], cwd=chk_a2
                ) as sess_a2,
                InstalledMcpPipeSession(
                    inc2_installed_env, "brain-mcp", ["--profile", str(prof_bob)], cwd=outside_cwd
                ) as sess_bob,
            ):
                sess_a.send_frames_and_expect_response(mcp_init_frames(1))
                sess_a2.send_frames_and_expect_response(mcp_init_frames(1))
                sess_bob.send_frames_and_expect_response(mcp_init_frames(1))

                # Concurrent identical tool names (`get_health`) and `prepare_task` while all 3 shims stay live!
                t_a0 = _utc_now_z()
                r_ha = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
                )
                t_a1 = _utc_now_z()
                err_ha, env_ha = _extract_mcp_structured(r_ha)
                assert err_ha is False and env_ha["ok"] is True

                t_a20 = _utc_now_z()
                r_ha2 = sess_a2.send_frames_and_expect_response(
                    [mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
                )
                t_a21 = _utc_now_z()
                err_ha2, env_ha2 = _extract_mcp_structured(r_ha2)
                assert err_ha2 is False and env_ha2["ok"] is True

                t_b0 = _utc_now_z()
                r_hb = sess_bob.send_frames_and_expect_response(
                    [mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
                )
                t_b1 = _utc_now_z()
                err_hb, env_hb = _extract_mcp_structured(r_hb)
                assert err_hb is False and env_hb["ok"] is True

                t_pa0 = _utc_now_z()
                r_pa = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_a.job_id})]
                )
                t_pa1 = _utc_now_z()
                err_pa, env_pa = _extract_mcp_structured(r_pa)
                assert err_pa is False and env_pa["ok"] is True

                t_pa20 = _utc_now_z()
                r_pa2 = sess_a2.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_a2.job_id})]
                )
                t_pa21 = _utc_now_z()
                err_pa2, env_pa2 = _extract_mcp_structured(r_pa2)
                assert err_pa2 is False and env_pa2["ok"] is True

                # Negative: sess_a (chk_a) calling same-repo other-checkout job_a2 MUST fail!
                r_cross = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": job_a2.job_id})]
                )
                err_cross, env_cross = _extract_mcp_structured(r_cross)
                assert err_cross is True and env_cross["ok"] is False

                # Negative: stale profile A launched in checkout A2 must refuse locally before transport.
                from tests.support.inc2_cli import run_installed_command

                res_stale = run_installed_command(
                    inc2_installed_env, "brain-mcp", ["--profile", str(prof_a)], cwd=chk_a2
                )
                assert res_stale.returncode != 0
                assert b"identity_mismatch" in res_stale.stderr

                # Negative: outside/missing CWD with workspace-bound profile must refuse locally.
                res_bad_cwd = run_installed_command(
                    inc2_installed_env, "brain-mcp", ["--profile", str(prof_a)], cwd=outside_cwd
                )
                assert res_bad_cwd.returncode != 0
                assert b"identity_mismatch" in res_bad_cwd.stderr

                launcher_a = ProcessIdentity(sess_a._proc.pid, process_started_at_for_pid(sess_a._proc.pid))
                launcher_a2 = ProcessIdentity(sess_a2._proc.pid, process_started_at_for_pid(sess_a2._proc.pid))
                launcher_bob = ProcessIdentity(sess_bob._proc.pid, process_started_at_for_pid(sess_bob._proc.pid))

        _, calls, socks = load_owner_observations(ev_dir)
        by_cred_tool = {(c.credential_id, c.tool_name): c for c in calls}
        c_a_health = by_cred_tool[(tpl.cred.credential_id, "get_health")]
        c_a2_health = by_cred_tool[(tpl.cred_b.credential_id, "get_health")]
        c_bob_health = by_cred_tool[(tpl.cred_bob.credential_id, "get_health")]
        assert c_a_health.client_process is not None
        assert c_a2_health.client_process is not None
        assert c_bob_health.client_process is not None
        assert c_a_health.client_port != c_a2_health.client_port
        assert any(
            s.client_process == c_a_health.client_process and s.local_port == c_a_health.client_port for s in socks
        )
        assert any(
            s.client_process == c_a2_health.client_process and s.local_port == c_a2_health.client_port for s in socks
        )

        probe_a, reg_a, obs_a = _build_wheel_probe_and_obs(
            env=inc2_installed_env,
            owner=owner,
            evidence_root=base / "evidence",
            owner_evidence_dir=ev_dir,
            config_path=cfg_path,
            profile_path=prof_a,
            schema_copy_path=schema_copy,
            task_id="task-audit-concurrent",
            call_id="call-audit-a",
            host="claude-code",
            credential_id=tpl.cred.credential_id,
            principal_id=tpl.cred.principal.principal_id,
            tool_name="get_health",
            response_envelope=env_ha,
            launcher_proc=launcher_a,
            worker_proc=c_a_health.client_process,
            started_at=t_a0,
            ended_at=t_a1,
        )
        probe_a2, reg_a2, obs_a2 = _build_wheel_probe_and_obs(
            env=inc2_installed_env,
            owner=owner,
            evidence_root=base / "evidence",
            owner_evidence_dir=ev_dir,
            config_path=cfg_path,
            profile_path=prof_a2,
            schema_copy_path=schema_copy,
            task_id="task-audit-concurrent",
            call_id="call-audit-a2",
            host="claude-code",
            credential_id=tpl.cred_b.credential_id,
            principal_id=tpl.cred_b.principal.principal_id,
            tool_name="get_health",
            response_envelope=env_ha2,
            launcher_proc=launcher_a2,
            worker_proc=c_a2_health.client_process,
            started_at=t_a20,
            ended_at=t_a21,
        )
        probe_bob, reg_bob, obs_bob = _build_wheel_probe_and_obs(
            env=inc2_installed_env,
            owner=owner,
            evidence_root=base / "evidence",
            owner_evidence_dir=ev_dir,
            config_path=cfg_path,
            profile_path=prof_bob,
            schema_copy_path=schema_copy,
            task_id="task-audit-concurrent",
            call_id="call-audit-bob",
            host="codex-desktop",
            credential_id=tpl.cred_bob.credential_id,
            principal_id=tpl.cred_bob.principal.principal_id,
            tool_name="get_health",
            response_envelope=env_hb,
            launcher_proc=launcher_bob,
            worker_proc=c_bob_health.client_process,
            started_at=t_b0,
            ended_at=t_b1,
        )
        assert (
            verify_native_connection(probe_a, registration=reg_a, observations=obs_a, require_native=False) is True
        )
        assert (
            verify_native_connection(probe_a2, registration=reg_a2, observations=obs_a2, require_native=False) is True
        )
        assert (
            verify_native_connection(probe_bob, registration=reg_bob, observations=obs_bob, require_native=False)
            is True
        )

        # Cross-shim session attribution mismatch (same principal/repo, wrong worker/port) must fail.
        assert (
            verify_native_connection(
                replace(probe_a, shim_worker_process=c_a2_health.client_process),
                registration=reg_a,
                observations=obs_a,
                require_native=False,
            )
            is False
        )
        # Reused PID with altered started_at must fail.
        assert probe_a.daemon_process is not None
        reused_daemon = ProcessIdentity(pid=probe_a.daemon_process.pid, started_at="2099-01-01T00:00:00.000000Z")
        assert (
            verify_native_connection(
                replace(probe_a, daemon_process=reused_daemon),
                registration=reg_a,
                observations=obs_a,
                require_native=False,
            )
            is False
        )

        # Same principal two credentials -> False; two different principals same daemon -> True.
        assert verify_same_daemon(probe_a, probe_a2) is False
        assert verify_same_daemon(probe_a, probe_bob) is True

        # Verify workspace-scoped prepare_task transition across the SAME repo's two checkouts.
        obs_ws_a = ShimLaunchObservation(
            pid=c_a_health.client_process.pid,
            started_at=c_a_health.client_process.started_at,
            profile_digest=digest_a,
            observed_scope=Scope(ws_a.repo_id, ws_a.checkout_id),
            launch_cwd=chk_a,
        )
        obs_ws_a2 = ShimLaunchObservation(
            pid=c_a2_health.client_process.pid,
            started_at=c_a2_health.client_process.started_at,
            profile_digest=digest_a2,
            observed_scope=Scope(ws_a2.repo_id, ws_a2.checkout_id),
            launch_cwd=chk_a2,
            reported_alias=ws_a2.alias,
        )
        probe_pa2, reg_pa2, obs_pa2 = _build_wheel_probe_and_obs(
            env=inc2_installed_env,
            owner=owner,
            evidence_root=base / "evidence",
            owner_evidence_dir=ev_dir,
            config_path=cfg_path,
            profile_path=prof_a2,
            schema_copy_path=schema_copy,
            task_id="task-audit-concurrent",
            call_id="call-audit-pa2",
            host="claude-code",
            credential_id=tpl.cred_b.credential_id,
            principal_id=tpl.cred_b.principal.principal_id,
            tool_name="get_job",
            response_envelope=env_pa2,
            launcher_proc=launcher_a2,
            worker_proc=c_a2_health.client_process,
            started_at=t_pa20,
            ended_at=t_pa21,
            observed_scope={"repo_id": ws_a2.repo_id, "checkout_id": ws_a2.checkout_id},
            prior_lifecycle=obs_ws_a,
            current_lifecycle=obs_ws_a2,
            expected_scope=Scope(ws_a2.repo_id, ws_a2.checkout_id),
            expected_first_scope=Scope(ws_a.repo_id, ws_a.checkout_id),
            expected_alias=ws_a2.alias,
        )
        assert (
            verify_native_connection(probe_pa2, registration=reg_pa2, observations=obs_pa2, require_native=False)
            is True
        )
        _ = (t_pa0, t_pa1, env_pa)

        # Missing launch_cwd on after when before had launch_cwd must reject in workspace_transition_matches.
        obs_no_cwd = replace(obs_ws_a2, launch_cwd=None)
        assert (
            workspace_transition_matches(
                obs_ws_a,
                obs_no_cwd,
                expected_scope=Scope(ws_a2.repo_id, ws_a2.checkout_id),
                expected_profile_digest=digest_a2,
            )
            is False
        )

        # Replaced root at the EXACT SAME data_root path must be rejected by verify_same_daemon.
        from tests.support.inc2_transport import create_transport_template

        tpl_replaced = create_transport_template("t9-replaced-root")
        try:
            assert tpl_replaced.store_id != tpl.store_id
            shutil.rmtree(data_root)
            clone_owner_only_tree(tpl_replaced.root, data_root)
            os_adapters().permissions.secure_directory(data_root)
            cfg_replaced = write_daemon_config_file(
                base / "evidence" / "daemon-config-replaced.json",
                data_root=data_root,
                expected_store_id=tpl_replaced.store_id,
                cert_path=tpl_replaced.tls.cert_path,
                key_path=tpl_replaced.tls.key_path,
            )
            cred_rep_p = write_credential_file(base / "cred-rep.txt", tpl_replaced.cred.token)
            prof_rep, _ = write_client_profile_file(
                base / "evidence" / "prof-rep.json",
                endpoint_path=data_root / "endpoint.json",
                expected_store_id=tpl_replaced.store_id,
                ca_file=tpl_replaced.tls.ca_cert_path,
                leaf_cert_sha256=tpl_replaced.tls.leaf_cert_sha256,
                credential_file=cred_rep_p,
            )
            ev_rep_dir = base / "owner-ev-rep"
            ev_rep_dir.mkdir(parents=True, exist_ok=True)
            with spawn_observed_wheel_owner(inc2_installed_env, cfg_replaced, ev_rep_dir, cwd=base) as owner_rep:
                r_rep, l_rep, w_rep, tr0, tr1 = _invoke_wheel_shim_health(inc2_installed_env, prof_rep, cwd=base)
            probe_rep, reg_rep, obs_rep = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner_rep,
                evidence_root=base / "evidence",
                owner_evidence_dir=ev_rep_dir,
                config_path=cfg_replaced,
                profile_path=prof_rep,
                schema_copy_path=schema_copy,
                task_id="task-audit-replaced",
                call_id="call-audit-replaced",
                host="claude-code",
                credential_id=tpl_replaced.cred.credential_id,
                principal_id=tpl_replaced.cred.principal.principal_id,
                tool_name="get_health",
                response_envelope=r_rep,
                launcher_proc=l_rep,
                worker_proc=w_rep,
                started_at=tr0,
                ended_at=tr1,
            )
            assert (
                verify_native_connection(probe_rep, registration=reg_rep, observations=obs_rep, require_native=False)
                is True
            )
            assert verify_same_daemon(probe_bob, probe_rep) is False
        finally:
            shutil.rmtree(tpl_replaced.base_dir, ignore_errors=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_native_verifier_rejects_null_response_digest(trusted_tmp: Path) -> None:
    """Passed probes require non-null response_digest across verify_native_connection and verify_same_daemon."""
    case_dir = trusted_tmp / "null-response-digest"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)
    assert probe.binding is not None and probe.token_context is not None and probe.terminal_facts is not None
    cred2, _, _, _ = generate_bearer_token()
    probe_second = replace(
        probe,
        observed_call_id="call-t9-0002",
        binding=replace(probe.binding, principal_id="prin-t9-2"),
        token_context=replace(probe.token_context, credential_id=cred2),
    )

    assert verify_native_connection(probe, registration=reg, observations=obs) is True
    assert verify_same_daemon(probe, probe_second) is True

    tf_null = replace(probe.terminal_facts, response_digest=None)
    probe_null = replace(probe, terminal_facts=tf_null)
    probe_second_null = replace(probe_second, terminal_facts=tf_null)
    hc_null = replace(obs.host_calls[0], response_digest=None)
    oc_null = replace(obs.owner_events[0], response_digest=None)
    obs_null = replace(obs, host_calls=(hc_null,), owner_events=(oc_null,))

    assert verify_native_connection(probe_null, registration=reg, observations=obs_null) is False
    assert verify_native_connection(probe, registration=reg, observations=obs_null) is False
    assert verify_same_daemon(probe_null, probe_second_null) is False
    assert verify_same_daemon(probe_null, probe_second) is False
    assert verify_same_daemon(probe, probe_second_null) is False

    tf_malformed = replace(probe.terminal_facts, response_digest="not-a-sha256")
    probe_malformed = replace(probe, terminal_facts=tf_malformed)
    obs_malformed = replace(
        obs,
        host_calls=(replace(obs.host_calls[0], response_digest="not-a-sha256"),),
        owner_events=(replace(obs.owner_events[0], response_digest="not-a-sha256"),),
    )
    assert verify_native_connection(probe_malformed, registration=reg, observations=obs_malformed) is False
    assert verify_same_daemon(probe_malformed, probe_second) is False

    with pytest.raises(ProbeValidationError):
        encode_native_probe(probe_null)
    with pytest.raises(ProbeValidationError):
        encode_native_probe(probe_second_null)

    probe_failed_null = replace(
        probe_null,
        terminal_facts=replace(tf_null, ok=False, status="error"),
    )
    probe_second_failed_null = replace(
        probe_second_null,
        terminal_facts=replace(tf_null, ok=False, status="error"),
    )
    roundtripped_null = parse_native_probe(encode_native_probe(probe_failed_null))
    roundtripped_second_null = parse_native_probe(encode_native_probe(probe_second_failed_null))
    assert verify_native_connection(roundtripped_null, registration=reg, observations=obs_null) is False
    assert verify_same_daemon(roundtripped_null, roundtripped_second_null) is False


def test_owner_driver_non_release_error_quiesced_and_timeout_logging(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_tap_conn_worker emits failed owner_call events on non-release exits without leaking State 0 flushes."""
    import queue
    import threading
    from concurrent.futures import Future

    from superbrain.cli_api.loopback import LoopbackTransportError
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.kernel import TOTAL_REQUEST_BUDGET_NS, OwnerReply, ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    del trusted_tmp
    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()

    def _drain_and_join_workers() -> list[dict[str, object]]:
        for th in threading.enumerate():
            if th.name.startswith("superbrain-loopback-conn-") and th.is_alive():
                th.join(timeout=2.0)
        flush_fn = hook_state.get("flush")
        if callable(flush_fn):
            flush_fn(timeout=2.0)
        items: list[dict[str, object]] = []
        while not eq.empty():
            item = eq.get_nowait()
            if item is not None:
                items.append(item)
        return items

    daemon_started_at = process_started_at_for_pid(os.getpid())
    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-non-release",
        daemon_pid=os.getpid(),
        daemon_started_at=daemon_started_at,
    )
    try:
        with open_test_loopback_transport(tpl, name="non-release-exits") as h:
            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()

            # 1. submit_reply raises BrainError -> _write_200_best_effort flushes error, skipping _release_owner_reply.
            orig_submit = h.loop.submit_reply

            def _submit_boom(command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
                del command, deadline_ns
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

            with monkeypatch.context() as mp:
                mp.setattr(h.loop, "submit_reply", _submit_boom)
                res_err = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-submit-boom",
                    ),
                )

            assert res_err.get("ok") is False
            ev1 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev1) == 1
            assert ev1[0]["tool_name"] == "get_health"
            assert ev1[0]["ready"] is False
            assert ev1[0]["auth_stamp_matched"] is False
            assert ev1[0]["response_flushed_ok"] is True
            assert ev1[0]["response_digest"] == digest_bytes(canonical_json(res_err))
            if sys.platform == "win32":
                assert ev1[0]["client_pid"] == os.getpid()
                assert ev1[0]["client_started_at"] == daemon_started_at
            assert hook_state["pending_count"]() == 0

            # 2. _is_quiesced() becomes True right after read_admitted_tool_command -> flushes DAEMON_UNAVAILABLE.
            orig_is_quiesced = h.server._is_quiesced
            quiesce_calls_by_tid: dict[int, int] = {}

            def _quiesced_post_admission() -> bool:
                if threading.current_thread().name.startswith("superbrain-loopback-conn-"):
                    tid = threading.get_ident()
                    n = quiesce_calls_by_tid.get(tid, 0) + 1
                    quiesce_calls_by_tid[tid] = n
                    if n == 3:
                        return True
                return orig_is_quiesced()

            with monkeypatch.context() as mp:
                mp.setattr(h.server, "_is_quiesced", _quiesced_post_admission)
                res_q = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-quiesced",
                    ),
                )

            assert res_q.get("ok") is False
            ev2 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev2) == 1
            assert ev2[0]["tool_name"] == "get_health"
            assert ev2[0]["ready"] is False
            assert ev2[0]["auth_stamp_matched"] is False
            assert ev2[0]["response_flushed_ok"] is True
            assert ev2[0]["response_digest"] == digest_bytes(canonical_json(res_q))
            if sys.platform == "win32":
                assert ev2[0]["client_pid"] == os.getpid()
                assert ev2[0]["client_started_at"] == daemon_started_at
            assert hook_state["pending_count"]() == 0

            # 3. _await_owner_reply times out (reply is None) -> exits with NO tool flush (State 0 200 must not bleed).
            def _submit_and_expire(command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
                fut = orig_submit(command, deadline_ns)
                h.mono_clock.advance_ns(TOTAL_REQUEST_BUDGET_NS + 1)
                return fut

            with monkeypatch.context() as mp:
                mp.setattr(h.loop, "submit_reply", _submit_and_expire)
                with pytest.raises(LoopbackTransportError):
                    h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                        target,
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-timeout-none",
                        ),
                    )

            ev3 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev3) == 1
            assert ev3[0]["tool_name"] == "get_health"
            assert ev3[0]["ready"] is False
            assert ev3[0]["auth_stamp_matched"] is False
            assert ev3[0]["response_flushed_ok"] is False
            assert ev3[0]["response_digest"] is None
            if sys.platform == "win32":
                if ev3[0]["client_pid"] is not None:
                    assert ev3[0]["client_pid"] == os.getpid()
                    assert ev3[0]["client_started_at"] == daemon_started_at
            assert hook_state["pending_count"]() == 0

            # 4. Transient OS socket-lookup failure must not break daemon reply or drop owner_call telemetry.
            def _boom_pid(_peer_port: int, _listen_port: int) -> int | None:
                raise OSError("simulated tcp table failure")

            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", _boom_pid)
                res_pid_err = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-lookup-boom",
                    ),
                )

            assert res_pid_err.get("ok") is True
            ev4 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev4) == 1
            assert ev4[0]["tool_name"] == "get_health"
            assert ev4[0]["response_flushed_ok"] is True
            assert ev4[0]["client_pid"] is None
            assert ev4[0]["client_started_at"] is None
            assert hook_state["pending_count"]() == 0
    finally:
        hook_state["uninstall"]()


def test_win32_descendant_pids_exited_root_open_handle_and_recycled_ppid_rejection(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Win32 collector captures orphan child while root handle is open and enforces creation-tick guards."""
    if sys.platform != "win32":
        pytest.skip("Win32-only process creation tick test")
    from tests.support import inc2_cli as cli

    _ = trusted_tmp
    base_py = str(getattr(sys, "_base_executable", sys.executable))
    child_code = (
        "import subprocess, sys, time; "
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); "
        "print(c.pid, flush=True); time.sleep(0.05)"
    )
    proc = subprocess.Popen(
        [base_py, "-c", child_code],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    child_pid = int(proc.stdout.readline().strip())
    child_ticks = cli._win32_process_creation_ticks(child_pid)
    # Wait for process exit while Popen still holds proc._handle open so OpenProcess(proc.pid) succeeds.
    proc.wait(timeout=5.0)
    try:
        desc = cli._win32_descendant_pids(proc.pid)
        assert child_pid in desc
        # Must never claim current pytest process as a descendant.
        assert os.getpid() not in desc
    finally:
        if child_ticks is not None:
            cli._win32_wait_or_terminate_pid(child_pid, expected_ticks=child_ticks, terminate=True, timeout_s=2.0)

    # Exercise child_ticks < parent_ticks, child_ticks is None, and recycled root_ticks > child_ticks on live processes.
    tree_code = (
        "import subprocess, sys, time; "
        "c1 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15)']); "
        "c2 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15)']); "
        "print(f'{c1.pid} {c2.pid}', flush=True); time.sleep(15)"
    )
    parent_proc = subprocess.Popen(
        [base_py, "-c", tree_code],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert parent_proc.stdout is not None
    child_keep_pid, child_older_pid = (int(x) for x in parent_proc.stdout.readline().strip().split())
    cleanup_pins: list[tuple[int, int | None]] = [
        (child_keep_pid, cli._win32_process_creation_ticks(child_keep_pid)),
        (child_older_pid, cli._win32_process_creation_ticks(child_older_pid)),
        (parent_proc.pid, cli._win32_popen_creation_ticks(parent_proc)),
    ]
    try:
        real_ticks_fn = cli._win32_process_creation_ticks
        real_parent_ticks = real_ticks_fn(parent_proc.pid)
        real_keep_ticks = real_ticks_fn(child_keep_pid)
        real_older_ticks = real_ticks_fn(child_older_pid)
        assert real_parent_ticks is not None
        assert real_keep_ticks is not None
        assert real_older_ticks is not None

        def _fake_ticks_older_child(pid: int) -> int | None:
            if pid == child_older_pid:
                return real_parent_ticks - 10_000_000
            return real_ticks_fn(pid)

        with monkeypatch.context() as mp:
            mp.setattr(cli, "_win32_process_creation_ticks", _fake_ticks_older_child)
            desc_filtered = cli._win32_descendant_pids(parent_proc.pid)
            assert child_keep_pid in desc_filtered
            assert child_older_pid not in desc_filtered

        def _fake_ticks_missing_child(pid: int) -> int | None:
            if pid == child_older_pid:
                return None
            return real_ticks_fn(pid)

        with monkeypatch.context() as mp:
            mp.setattr(cli, "_win32_process_creation_ticks", _fake_ticks_missing_child)
            desc_missing = cli._win32_descendant_pids(parent_proc.pid)
            assert child_keep_pid in desc_missing
            assert child_older_pid not in desc_missing

        def _fake_ticks_recycled_root(pid: int) -> int | None:
            if pid == parent_proc.pid:
                return max(real_keep_ticks, real_older_ticks) + 10_000_000
            return real_ticks_fn(pid)

        with monkeypatch.context() as mp:
            mp.setattr(cli, "_win32_process_creation_ticks", _fake_ticks_recycled_root)
            assert cli._win32_descendant_pids(parent_proc.pid) == []
    finally:
        for pid, ticks in cleanup_pins:
            if ticks is not None:
                cli._win32_wait_or_terminate_pid(pid, expected_ticks=ticks, terminate=True, timeout_s=2.0)


def test_t9_r01_rejects_unpinned_host_mode_versions_and_unbacked_artifacts(trusted_tmp: Path) -> None:
    """T9-R01: Require non-empty host_versions, host_mode/observer_id/run_id pinning, and disk-backed index."""
    case_dir = trusted_tmp / "r01-pinning"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, ev_root = _sample_world(case_dir)

    assert verify_native_connection(probe, registration=reg, observations=obs) is True

    # Empty registered_host_versions must reject rather than skip host_version checks.
    assert (
        verify_native_connection(
            probe,
            registration=replace(reg, registered_host_versions=()),
            observations=obs,
        )
        is False
    )

    # host_mode must align strictly with host (e.g. codex-desktop cannot use codex_cli_exec).
    bad_codex = replace(probe, host="codex-desktop", host_mode="codex_cli_exec")
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bad_codex.to_dict()))
    assert (
        verify_native_connection(
            bad_codex,
            registration=replace(reg, expected_host="codex-desktop"),
            observations=obs,
        )
        is False
    )

    # host_mode, observer_id, and run_id must be present on the schema and strictly verified.
    assert getattr(probe, "host_mode", None) == getattr(reg, "expected_host_mode", None)
    assert getattr(probe, "observer_id", None) == reg.registered_observer_id
    assert getattr(probe, "run_id", None) == getattr(reg, "run_id", None)
    assert (
        verify_native_connection(
            probe,
            registration=replace(reg, registered_observer_id="obs-other"),
            observations=obs,
        )
        is False
    )
    assert verify_native_connection(probe, registration=replace(reg, run_id="run-other"), observations=obs) is False

    # Unbacked memory-only mutation (differs from disk JSONL) must reject.
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                host_calls=(replace(obs.host_calls[0], ended_at="2026-11-12T04:00:02.160000Z"),),
            ),
        )
        is False
    )

    # Missing channel artifacts in artifact_paths must reject even if in-memory observations look consistent.
    for missing_label in ("evidence_index", "owner_ready", "owner_events", "host_calls", "socket_observations"):
        pruned_paths = {k: v for k, v in obs.artifact_paths.items() if k != missing_label}
        assert verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, artifact_paths=pruned_paths),
        ) is False

    # Tampered evidence-index.json digest must reject.
    idx_file = ev_root / "evidence-index.json"
    orig_idx = idx_file.read_bytes()
    idx_obj = json.loads(orig_idx.decode("utf-8"))
    idx_obj["artifacts"]["host_calls"] = "sha256:" + "1" * 64
    idx_file.write_bytes(canonical_json(idx_obj) + b"\n")
    assert verify_native_connection(probe, registration=reg, observations=obs) is False
    idx_file.write_bytes(orig_idx)
    assert verify_native_connection(probe, registration=reg, observations=obs) is True

    # Tampered on-disk owner-ready config_digest must reject.
    ready_file = ev_root / "owner-ready.json"
    ready_obj = json.loads(ready_file.read_text(encoding="utf-8"))
    ready_obj["config_digest"] = "sha256:" + "0" * 64
    ready_file.write_bytes(canonical_json(ready_obj) + b"\n")
    assert verify_native_connection(probe, registration=reg, observations=obs) is False


def test_t9_r02_rejects_null_owner_endpoints_and_requires_socket_connection_join(trusted_tmp: Path) -> None:
    """T9-R02: Forbid None client_* fallbacks and enforce 1-to-1 connection_id + socket lifetime join."""
    case_dir = trusted_tmp / "r02-conn-join"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, ev_root = _sample_world(case_dir)
    oc = obs.owner_events[0]
    so = obs.socket_observations[0]
    hc = obs.host_calls[0]
    assert oc.client_process is not None

    assert getattr(oc, "connection_id", None) is not None
    assert getattr(so, "connection_id", None) == getattr(oc, "connection_id", None)
    assert isinstance(getattr(so, "started_at", None), str)
    assert isinstance(getattr(so, "ended_at", None), str)

    # Positive twin: two identical get_health calls distinguish cleanly via 1-to-1 connection_id + lifetime.
    hc2 = replace(
        hc,
        call_id="call-t9-0002",
        started_at="2026-11-12T04:00:03.000000Z",
        ended_at="2026-11-12T04:00:03.150000Z",
    )
    oc2 = replace(
        oc,
        call_id="call-t9-0002",
        connection_id="conn-t9-0002",
        client_port=52002,
        started_at="2026-11-12T04:00:03.010000Z",
        ended_at="2026-11-12T04:00:03.140000Z",
    )
    so2 = replace(
        so,
        connection_id="conn-t9-0002",
        local_port=52002,
        started_at="2026-11-12T04:00:03.005000Z",
        observed_at="2026-11-12T04:00:03.020000Z",
        ended_at="2026-11-12T04:00:03.145000Z",
    )

    def _write_two_call_artifacts(
        sub_name: str,
        owner_pair: tuple[OwnerCallObservation, OwnerCallObservation],
        sock_pair: tuple[SocketObservation, SocketObservation],
    ) -> ObservationSet:
        sub_dir = ev_root / sub_name
        sub_dir.mkdir(parents=True, exist_ok=True)
        hc_p = sub_dir / "host-calls.jsonl"
        oc_p = sub_dir / "owner-events.jsonl"
        so_p = sub_dir / "socket-observations.jsonl"
        idx_p = sub_dir / "evidence-index.json"
        hc_p.write_bytes(
            b"".join(
                canonical_json(
                    {
                        "call_id": item.call_id,
                        "channel": item.channel,
                        "host_process": item.host_process.to_dict(),
                        "shim_launcher_process": item.shim_launcher_process.to_dict(),
                        "shim_worker_process": item.shim_worker_process.to_dict(),
                        "tool_name": item.tool_name,
                        "terminal_ok": item.terminal_ok,
                        "response_digest": item.response_digest,
                        "started_at": item.started_at,
                        "ended_at": item.ended_at,
                    }
                )
                + b"\n"
                for item in (hc, hc2)
            )
        )
        oc_p.write_bytes(
            b"".join(
                canonical_json(
                    {
                        "event": "owner_call",
                        "connection_id": item.connection_id,
                        "observation_status": item.observation_status,
                        "daemon_pid": item.daemon_process.pid,
                        "daemon_started_at": item.daemon_process.started_at,
                        "store_id": item.store_id,
                        "writer_epoch": item.writer_epoch,
                        "instance_id": item.instance_id,
                        "principal_id": item.principal_id,
                        "credential_id": item.credential_id,
                        "tool_name": item.tool_name,
                        "ready": item.ready,
                        "auth_stamp_matched": item.auth_stamp_matched,
                        "response_flushed_ok": item.response_flushed_ok,
                        "response_digest": item.response_digest,
                        "listen_host": item.listen_host,
                        "listen_port": item.listen_port,
                        "client_host": item.client_host,
                        "client_port": item.client_port,
                        "client_pid": item.client_process.pid if item.client_process else None,
                        "client_started_at": item.client_process.started_at if item.client_process else None,
                        "started_at": item.started_at,
                        "ended_at": item.ended_at,
                        "call_id": item.call_id,
                        "selected_scope": item.selected_scope,
                    }
                )
                + b"\n"
                for item in owner_pair
            )
        )
        so_p.write_bytes(
            b"".join(
                canonical_json(
                    {
                        "event": "socket_observation",
                        "connection_id": item.connection_id,
                        "observation_status": item.observation_status,
                        "client_pid": item.client_process.pid if item.client_process else None,
                        "client_started_at": item.client_process.started_at if item.client_process else None,
                        "daemon_pid": item.daemon_process.pid,
                        "daemon_started_at": item.daemon_process.started_at,
                        "local_addr": item.local_addr,
                        "local_port": item.local_port,
                        "remote_addr": item.remote_addr,
                        "remote_port": item.remote_port,
                        "store_id": item.store_id,
                        "writer_epoch": item.writer_epoch,
                        "instance_id": item.instance_id,
                        "started_at": item.started_at,
                        "observed_at": item.observed_at,
                        "ended_at": item.ended_at,
                    }
                )
                + b"\n"
                for item in sock_pair
            )
        )
        idx_obj = json.loads(obs.artifact_paths["evidence_index"].read_text(encoding="utf-8"))
        idx_obj["artifacts"]["host_calls"] = digest_bytes(hc_p.read_bytes())
        idx_obj["artifacts"]["owner_events"] = digest_bytes(oc_p.read_bytes())
        idx_obj["artifacts"]["socket_observations"] = digest_bytes(so_p.read_bytes())
        idx_p.write_bytes(canonical_json(idx_obj) + b"\n")
        return replace(
            obs,
            artifact_paths={
                **obs.artifact_paths,
                "host_calls": hc_p,
                "owner_events": oc_p,
                "socket_observations": so_p,
                "evidence_index": idx_p,
            },
            host_calls=(hc, hc2),
            owner_events=owner_pair,
            socket_observations=sock_pair,
        )

    obs_two = _write_two_call_artifacts("two-calls-ok", (oc, oc2), (so, so2))
    probe2 = replace(
        probe,
        observed_call_id="call-t9-0002",
        timespan=TimespanRecord(
            started_at="2026-11-12T04:00:03.000000Z",
            ended_at="2026-11-12T04:00:03.150000Z",
            duration_ms=150.0,
        ),
    )
    assert verify_native_connection(probe, registration=reg, observations=obs_two) is True
    assert verify_native_connection(probe2, registration=reg, observations=obs_two) is True

    # Swapped connection_ids across two calls (cross-swap socket/owner port mismatch) must reject.
    obs_swapped = _write_two_call_artifacts(
        "two-calls-swapped",
        (replace(oc, connection_id="conn-t9-0002"), replace(oc2, connection_id="conn-t9-0001")),
        (so, so2),
    )
    assert verify_native_connection(probe, registration=reg, observations=obs_swapped) is False

    # Out-of-lifetime socket (socket closed before owner call ended) must reject.
    obs_early_close = _write_two_call_artifacts(
        "two-calls-early-close",
        (oc, oc2),
        (replace(so, ended_at="2026-11-12T04:00:02.120000Z"), so2),
    )
    assert verify_native_connection(probe, registration=reg, observations=obs_early_close) is False

    # Any None client_* bypass or invalid port on OwnerCallObservation must reject.
    for bad_oc in (
        replace(oc, client_host=None),
        replace(oc, client_port=None),
        replace(oc, client_port=0),
        replace(oc, client_port=65536),
        replace(oc, client_process=None),
    ):
        assert (
            verify_native_connection(
                probe,
                registration=reg,
                observations=replace(obs, owner_events=(bad_oc,)),
            )
            is False
        )


def test_t9_r03_strict_owner_parsers_and_terminal_facts_consistency(trusted_tmp: Path) -> None:
    """T9-R03: Reject inconsistent terminal_facts (ok=True + deadline_exceeded) and duplicate/loose JSON."""
    from tests.support.inc2_native import (
        parse_evidence_index,
        parse_host_calls_jsonl,
        parse_owner_ready,
        parse_socket_observations_jsonl,
    )
    from tests.support.inc2_native_owner import load_owner_observations

    case_dir = trusted_tmp / "r03-strict-parse"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, ev_root = _sample_world(case_dir)
    assert probe.terminal_facts is not None

    # Positive twin: get_health permits observed_scope=None alongside matching selected_scope=None,
    # and get_job permits matching workspace scope on both sides.
    assert verify_native_connection(probe, registration=reg, observations=obs) is True
    probe_job, reg_job, obs_job, _ = _sample_world(case_dir / "job-ok", tool_name="get_job")
    assert verify_native_connection(probe_job, registration=reg_job, observations=obs_job) is True

    # Workspace-scoped tool submit_episode with observed_scope=None must reject.
    bad_scope_ep = replace(
        probe,
        terminal_facts=replace(probe.terminal_facts, tool_name="submit_episode", observed_scope=None),
    )
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bad_scope_ep.to_dict()))

    bad_term = replace(probe, terminal_facts=replace(probe.terminal_facts, ok=True, status="deadline_exceeded"))
    assert verify_native_connection(bad_term, registration=reg, observations=obs) is False
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(bad_term.to_dict()))

    # Duplicate keys, bool-as-int, and string-as-int must be rejected across ALL artifact parsers.
    dup_ev_dir = case_dir / "dup-ev"
    dup_ev_dir.mkdir(parents=True, exist_ok=True)
    (dup_ev_dir / "owner-events.jsonl").write_text(
        '{"event":"owner_call","event":"owner_call","daemon_pid":1}\n',
        encoding="utf-8",
    )
    with pytest.raises((ProbeValidationError, ValueError)):
        load_owner_observations(dup_ev_dir)

    for path_key, parser_fn in (
        ("owner_ready", parse_owner_ready),
        ("evidence_index", parse_evidence_index),
        ("host_calls", parse_host_calls_jsonl),
        ("socket_observations", parse_socket_observations_jsonl),
    ):
        raw_line = obs.artifact_paths[path_key].read_bytes().splitlines()[0]
        obj = json.loads(raw_line.decode("utf-8"))
        int_key = (
            next((k for k in ("daemon_pid", "port", "writer_epoch") if k in obj), None)
            if path_key != "evidence_index"
            else None
        )
        if int_key is not None:
            bad_bool = dict(obj)
            bad_bool[int_key] = True
            with pytest.raises(ProbeValidationError):
                parser_fn(canonical_json(bad_bool))
            bad_str = dict(obj)
            bad_str[int_key] = "123"
            with pytest.raises(ProbeValidationError):
                parser_fn(canonical_json(bad_str))
        elif "terminal_ok" in obj:
            bad_term_ok = dict(obj)
            bad_term_ok["terminal_ok"] = "true"
            with pytest.raises(ProbeValidationError):
                parser_fn(canonical_json(bad_term_ok))
        else:
            bad_extra = dict(obj)
            bad_extra["extra"] = 1
            with pytest.raises(ProbeValidationError):
                parser_fn(canonical_json(bad_extra))


def test_t9_r04_unverified_token_never_leaks_prefix_into_owner_events(trusted_tmp: Path) -> None:
    """T9-R04: Unverified dotted bearer tokens never leak prefixes; valid calls record exact principal/cred."""
    import queue
    import threading

    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import open_test_loopback_transport

    del trusted_tmp
    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()
    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-r04",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
    )
    try:
        with open_test_loopback_transport(tpl, name="r04-no-token-leak") as h:
            client = h.open_client()
            target = h.make_target()
            res_bad = client.call(
                target,
                ToolCommand(
                    tool="get_health",
                    arguments={"schema_version": "2.0"},
                    token="t9-synthetic-private-canary.invalid-secret-part",
                    selected_scope=None,
                    correlation_id="corr-r04-forged",
                ),
            )
            assert res_bad.get("ok") is False

            res_ok = client.call(
                target,
                ToolCommand(
                    tool="get_health",
                    arguments={"schema_version": "2.0"},
                    token=tpl.cred.token,
                    selected_scope=None,
                    correlation_id="corr-r04-valid",
                ),
            )
            assert res_ok.get("ok") is True

            for th in threading.enumerate():
                if th.name.startswith("superbrain-loopback-conn-") and th.is_alive():
                    th.join(timeout=2.0)
            if "flush" in hook_state:
                hook_state["flush"](timeout=2.0)
    finally:
        hook_state["uninstall"]()

    events: list[dict[str, object]] = []
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            events.append(item)
    calls = [r for r in events if r.get("event") == "owner_call"]
    assert len(calls) == 2
    bad_calls = [r for r in calls if r.get("auth_stamp_matched") is False]
    ok_calls = [r for r in calls if r.get("auth_stamp_matched") is True]
    assert len(bad_calls) == 1 and len(ok_calls) == 1
    assert bad_calls[0]["credential_id"] == "<unknown>"
    assert bad_calls[0]["principal_id"] == "<unknown>"
    assert "t9-synthetic-private-canary" not in json.dumps(calls)
    assert ok_calls[0]["credential_id"] == tpl.cred.credential_id
    assert ok_calls[0]["principal_id"] == tpl.cred.principal.principal_id


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only PID handle guard")
def test_t9_r05_win32_wait_or_terminate_checks_ticks_and_access_denied(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R05: _win32_wait_or_terminate_pid verifies handle creation ticks and never masks ERROR_ACCESS_DENIED."""
    import pywintypes
    import win32api

    from tests.support import inc2_cli as cli

    del trusted_tmp

    def _deny_open(*_args: object, **_kwargs: object) -> object:
        raise pywintypes.error(5, "OpenProcess", "Access is denied.")

    with monkeypatch.context() as mp:
        mp.setattr(win32api, "OpenProcess", _deny_open)
        assert cli._win32_wait_or_terminate_pid(999999, expected_ticks=1, terminate=False, timeout_s=0.1) is False

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        real_ticks = cli._win32_process_creation_ticks(child.pid)
        assert real_ticks is not None
        # Mismatched expected_ticks MUST NOT terminate the live child process.
        res = cli._win32_wait_or_terminate_pid(
            child.pid,
            expected_ticks=real_ticks - 1,
            terminate=True,
            timeout_s=0.2,
        )
        assert res is True
        assert child.poll() is None, "Reused-PID guard failed: live process with wrong ticks was terminated!"

        # Matching expected_ticks terminates the process cleanly.
        assert cli._win32_wait_or_terminate_pid(
            child.pid,
            expected_ticks=real_ticks,
            terminate=True,
            timeout_s=2.0,
        ) is True
        assert child.wait(timeout=2.0) is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5.0)


def test_t9_r07_slow_collector_off_deadline_and_concurrent_calls(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R07: Slow/failing OS socket lookup runs off request thread, preserves concurrent calls, marks incomplete."""
    import concurrent.futures
    import queue
    import threading

    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    case_dir = trusted_tmp / "r07-collector"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)

    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()

    slow_entered = threading.Event()
    slow_release = threading.Event()
    lookup_lock = threading.Lock()
    call_idx = {"n": 0}
    mode_state = {"error": False}

    def _mock_lookup(peer_port: int, _listen_port: int) -> int | None:
        if mode_state["error"]:
            raise OSError("collector_boom")
        with lookup_lock:
            call_idx["n"] += 1
            idx = call_idx["n"]
        if idx == 1:
            slow_entered.set()
            slow_release.wait(timeout=3.0)
            return None
        return os.getpid()

    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-r07",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
        collector_timeout_s=0.1,
    )
    try:
        with open_test_loopback_transport(tpl, name="r07-slow-collector") as h:
            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()
            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", _mock_lookup)

                def _call(corr: str) -> dict[str, Any]:
                    return h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                        target,
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tpl.cred.token,
                            selected_scope=None,
                            correlation_id=corr,
                        ),
                    )

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    fut_slow = pool.submit(_call, "corr-r07-slow")
                    assert slow_entered.wait(timeout=2.0)
                    fut_fast = pool.submit(_call, "corr-r07-fast")
                    res_slow = fut_slow.result(timeout=2.0)
                    res_fast = fut_fast.result(timeout=2.0)

                assert res_slow.get("ok") is True, f"Slow collector broke tool call: {res_slow!r}"
                assert res_fast.get("ok") is True, f"Fast concurrent call affected: {res_fast!r}"

                # Collector raising OSError must also leave request path ok=True and mark observation_incomplete.
                mode_state["error"] = True
                res_err = _call("corr-r07-oserror")
                assert res_err.get("ok") is True

            if "flush" in hook_state:
                hook_state["flush"](timeout=1.0)
    finally:
        slow_release.set()
        hook_state["uninstall"]()

    events: list[dict[str, object]] = []
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            events.append(item)
    calls = [r for r in events if r.get("event") == "owner_call"]
    assert len(calls) == 3
    incomplete_calls = [r for r in calls if r.get("observation_status") == "observation_incomplete"]
    complete_calls = [r for r in calls if r.get("observation_status") == "ok"]
    assert len(incomplete_calls) == 2
    assert all(r["client_pid"] is None for r in incomplete_calls)
    assert len(complete_calls) == 1
    assert complete_calls[0]["client_pid"] == os.getpid()

    # An observation_incomplete owner event must be rejected by verify_native_connection.
    oc = obs.owner_events[0]
    assert oc.client_process is not None
    oc_inc_path = obs.artifact_paths["evidence_index"].parent / "owner-events-incomplete.jsonl"
    oc_inc_path.write_bytes(
        canonical_json(
            {
                "event": "owner_call",
                "connection_id": oc.connection_id,
                "observation_status": "observation_incomplete",
                "daemon_pid": oc.daemon_process.pid,
                "daemon_started_at": oc.daemon_process.started_at,
                "store_id": oc.store_id,
                "writer_epoch": oc.writer_epoch,
                "instance_id": oc.instance_id,
                "principal_id": oc.principal_id,
                "credential_id": oc.credential_id,
                "tool_name": oc.tool_name,
                "ready": oc.ready,
                "auth_stamp_matched": oc.auth_stamp_matched,
                "response_flushed_ok": oc.response_flushed_ok,
                "response_digest": oc.response_digest,
                "listen_host": oc.listen_host,
                "listen_port": oc.listen_port,
                "client_host": oc.client_host,
                "client_port": oc.client_port,
                "client_pid": oc.client_process.pid,
                "client_started_at": oc.client_process.started_at,
                "started_at": oc.started_at,
                "ended_at": oc.ended_at,
                "call_id": oc.call_id,
                "selected_scope": oc.selected_scope,
            }
        )
        + b"\n"
    )
    idx_inc = json.loads(obs.artifact_paths["evidence_index"].read_text(encoding="utf-8"))
    idx_inc["artifacts"]["owner_events"] = digest_bytes(oc_inc_path.read_bytes())
    idx_inc_path = obs.artifact_paths["evidence_index"].parent / "evidence-index-incomplete.json"
    idx_inc_path.write_bytes(canonical_json(idx_inc) + b"\n")
    obs_inc = replace(
        obs,
        artifact_paths={**obs.artifact_paths, "owner_events": oc_inc_path, "evidence_index": idx_inc_path},
        owner_events=(replace(oc, observation_status="observation_incomplete"),),
    )
    assert verify_native_connection(probe, registration=reg, observations=obs_inc) is False


def test_utc_now_z_aligned_with_process_creation_clock_and_sub_millisecond_progression() -> None:
    """UTC wall clock matches OS process-start resolution so fast child calls never invert or collide."""
    from tests.support import inc2_native_owner

    utc_now_fn = inc2_native_owner.utc_now_z
    for _ in range(8):
        t_before = utc_now_fn()
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.005)"])
        try:
            started = process_started_at_for_pid(proc.pid)
            t_after = utc_now_fn()
        finally:
            proc.wait(timeout=5)
        assert t_before <= started <= t_after, (
            f"Clock skew between utc_now_z and process_started_at_for_pid: {t_before} <= {started} <= {t_after}"
        )


def test_wheel_probe_builder_avoids_toctou_when_owner_jsonl_grows_mid_build(
    inc2_installed_env: InstalledEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_build_wheel_probe_and_obs parses from the exact byte snapshot written into artifacts and evidence-index."""
    tpl = get_shared_t7_transport_template()
    case_dir = make_trusted_test_dir("inc2-t9-toctou")
    try:
        outside_cwd = case_dir / "outside-cwd"
        chk_a = case_dir / "workspaces" / "repo-a"
        outside_cwd.mkdir(parents=True, exist_ok=True)
        chk_a.mkdir(parents=True, exist_ok=True)
        os_adapters().permissions.secure_directory(outside_cwd)
        os_adapters().permissions.secure_directory(chk_a)
        data_root = case_dir / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)
        adapters = os_adapters()
        clock = FakeClock(datetime.now(UTC))
        rt = open_kernel_job_runtime(data_root, adapters)
        try:
            cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1")
            ws_a = register_workspace_direct(
                rt,
                clock,
                cred.principal,
                alias="ws-t9-toctou",
                checkout_dir=chk_a,
                remote="https://github.example/dan/repo-toctou.git",
            )
            rt.store.reconcile_policy()
        finally:
            rt.close()
        cred_file = write_credential_file(case_dir / "cred.txt", cred.token)
        ep_path = data_root / "endpoint.json"
        schema_copy = case_dir / "mcp-tools-v2.json"
        schema_copy.write_bytes(inc2_installed_env.source_schema_path.read_bytes())
        cfg_path = write_daemon_config_file(
            case_dir / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        prof_path, _ = write_client_profile_file(
            case_dir / "profile-a.json",
            endpoint_path=ep_path,
            expected_store_id=tpl.store_id,
            ca_file=tpl.tls.ca_cert_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_file,
            workspace={
                "alias": ws_a.alias,
                "checkout_path": str(chk_a),
                "expected_workspace_id": ws_a.repo_id,
                "expected_checkout_id": ws_a.checkout_id,
            },
        )
        ev_dir = case_dir / "owner-ev"
        with spawn_observed_wheel_owner(inc2_installed_env, cfg_path, ev_dir, cwd=outside_cwd) as owner:
            with InstalledMcpPipeSession(
                inc2_installed_env, "brain", ("mcp", "--profile", str(prof_path)), cwd=chk_a
            ) as sess:
                sess.send_frames_and_expect_response(mcp_init_frames(1))
                st = _utc_now_z()
                resp = sess.send_frames_and_expect_response(
                    [
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    ]
                )
                en = _utc_now_z()
                is_err, sc_health = _extract_mcp_structured(resp)
                assert is_err is False and cast(dict[str, Any], sc_health["data"])["ready"] is True
                la_pid = sess._proc.pid
                desc = sess._snapshot_descendants()
                wk_pid = desc[-1] if desc else la_pid
                la_proc = ProcessIdentity(pid=la_pid, started_at=process_started_at_for_pid(la_pid))
                wk_proc = (
                    la_proc
                    if wk_pid == la_pid
                    else ProcessIdentity(pid=wk_pid, started_at=process_started_at_for_pid(wk_pid))
                )
                rc, err = sess.finish()
                assert rc == 0 and err == b""

            # Wait until owner events settle, then inject a simulated concurrent append between poll parse & copy.
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                _, oc_rows, so_rows = load_owner_observations(ev_dir)
                if oc_rows and so_rows:
                    break
                time.sleep(0.02)

            appended_once = False
            ev_path = ev_dir / "owner-events.jsonl"
            so_path = ev_dir / "socket-observations.jsonl"
            orig_mkdir = Path.mkdir

            def _append_concurrent_event(self: Path, *args: Any, **kwargs: Any) -> None:
                nonlocal appended_once
                orig_mkdir(self, *args, **kwargs)
                if not appended_once and self.name == "artifacts-call-toctou":
                    appended_once = True
                    first_oc = json.loads(ev_path.read_text(encoding="utf-8").splitlines()[0])
                    first_oc["connection_id"] = "conn-concurrent-extra"
                    first_oc["started_at"] = "2026-11-12T04:00:00.000000Z"
                    first_oc["ended_at"] = "2026-11-12T04:00:00.001000Z"
                    with ev_path.open("ab") as fh:
                        fh.write(canonical_json(first_oc) + b"\n")
                    first_so = json.loads(so_path.read_text(encoding="utf-8").splitlines()[0])
                    first_so["connection_id"] = "conn-concurrent-extra"
                    with so_path.open("ab") as fh:
                        fh.write(canonical_json(first_so) + b"\n")

            monkeypatch.setattr(Path, "mkdir", _append_concurrent_event)
            probe, reg, obs = _build_wheel_probe_and_obs(
                env=inc2_installed_env,
                owner=owner,
                evidence_root=case_dir,
                owner_evidence_dir=ev_dir,
                config_path=cfg_path,
                profile_path=prof_path,
                schema_copy_path=schema_copy,
                task_id="task-toctou",
                call_id="call-toctou",
                host="claude-code",
                credential_id=cred.credential_id,
                principal_id=cred.principal.principal_id,
                tool_name="get_health",
                response_envelope=sc_health,
                launcher_proc=la_proc,
                worker_proc=wk_proc,
                started_at=st,
                ended_at=en,
            )
            assert appended_once is True
            assert verify_native_connection(probe, registration=reg, observations=obs, require_native=False) is True
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_t9_r01_verifier_single_read_and_run_observed_owner_config_digest(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R01: _verify_artifacts reads once (hash+parse same buffer) and run_observed_owner hashes launched bytes."""
    import threading
    from types import SimpleNamespace

    from superbrain.adapters.os import daemon_config as dc_mod
    from superbrain.adapters.os import os_adapters
    from superbrain.composition import daemon_entry as de_mod
    from superbrain.composition import owner_entry as oe_mod
    from tests.support import inc2_native_owner as native_owner

    case_dir = trusted_tmp / "r5-t9-r01"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)
    hc_path = obs.artifact_paths["host_calls"]
    hc_tampered = replace(obs.host_calls[0], ended_at="2026-11-12T04:00:02.999000Z")
    obs_tampered = replace(obs, host_calls=(hc_tampered,))
    hc_tampered_bytes = (
        canonical_json(
            {
                "call_id": hc_tampered.call_id,
                "channel": hc_tampered.channel,
                "host_process": hc_tampered.host_process.to_dict(),
                "shim_launcher_process": hc_tampered.shim_launcher_process.to_dict(),
                "shim_worker_process": hc_tampered.shim_worker_process.to_dict(),
                "tool_name": hc_tampered.tool_name,
                "terminal_ok": hc_tampered.terminal_ok,
                "response_digest": hc_tampered.response_digest,
                "started_at": hc_tampered.started_at,
                "ended_at": hc_tampered.ended_at,
            }
        )
        + b"\n"
    )

    read_counts: dict[Path, int] = {}
    orig_read_bytes = Path.read_bytes

    def _split_read_bytes(self: Path) -> bytes:
        resolved = self.resolve()
        read_counts[resolved] = read_counts.get(resolved, 0) + 1
        if resolved == hc_path.resolve() and read_counts[resolved] >= 2:
            return hc_tampered_bytes
        return orig_read_bytes(self)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "read_bytes", _split_read_bytes)
        # Digest check used hc_orig_bytes; parser MUST use that exact buffer and reject obs_tampered.
        assert verify_native_connection(probe, registration=reg, observations=obs_tampered) is False
        assert read_counts.get(hc_path.resolve(), 0) == 1
        for label, art_path in obs.artifact_paths.items():
            cnt = read_counts.get(art_path.resolve(), 0)
            assert cnt == 1, f"{label} was read {cnt} times"

    # Sibling: reg.expected_config_path replaced by symlink/wrong physical path must reject without double-read.
    sym_cfg = case_dir / "sym-cfg.json"
    try:
        sym_cfg.symlink_to(reg.expected_config_path)
    except OSError:
        sym_cfg = case_dir / "missing-cfg.json"
    bad_reg = replace(reg, expected_config_path=sym_cfg)
    assert verify_native_connection(probe, registration=bad_reg, observations=obs) is False

    # Sibling: run_observed_owner computes config_digest from the single _read_checked_file_bytes launch buffer.
    cfg_read_calls: list[Path] = []
    orig_checked_read = dc_mod._read_checked_file_bytes

    def _counting_checked_read(path: Path, os_: Any, *, max_bytes: int, **kwargs: Any) -> bytes:
        cfg_read_calls.append(path)
        return orig_checked_read(path, os_, max_bytes=max_bytes, **kwargs)

    raw_cfg_reads: list[Path] = []

    def _spy_raw_read(self: Path) -> bytes:
        if self.name == "owner-cfg.json":
            raw_cfg_reads.append(self)
        return orig_read_bytes(self)

    fake_cfg = case_dir / "owner-cfg.json"
    fake_cfg.write_bytes(b"{}\n")
    ev_dir = case_dir / "owner-ev"
    with monkeypatch.context() as mp:
        mp.setattr(dc_mod, "_read_checked_file_bytes", _counting_checked_read)
        mp.setattr(Path, "read_bytes", _spy_raw_read)
        mp.setattr(
            dc_mod,
            "read_daemon_config",
            lambda p, os_: (
                dc_mod._read_checked_file_bytes(p, os_, max_bytes=dc_mod.MAX_DAEMON_CONFIG_BYTES),
                SimpleNamespace(
                    data_root=case_dir / "dr",
                    expected_store_id="store-1",
                    cert_path=fake_cfg,
                    key_path=fake_cfg,
                ),
            )[1],
        )

        mp.setattr(
            oe_mod,
            "_explicit_owner_adapters",
            lambda cp: (
                dc_mod.read_daemon_config(cp, os_adapters()),
                os_adapters(),
                case_dir / "scratch",
            ),
        )
        mp.setattr(de_mod, "serve", lambda cfg, os_, stop_event, on_ready: 0)
        rc = native_owner.run_observed_owner(fake_cfg, ev_dir, threading.Event())
        assert rc == 0
    assert raw_cfg_reads == [], f"run_observed_owner read config via unpinned raw read_bytes: {raw_cfg_reads}"
    assert len(cfg_read_calls) == 1


def test_t9_r02_socket_observation_lifetime_and_post_close_lookup_rejection(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R02: Post-close OS lookups degrade cleanly; live lookups record observed_at within lifetime."""
    import queue
    import threading

    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()

    post_close_gate = threading.Event()
    lookup_mode = {"kind": "post_close"}

    def _mock_lookup(c_port: int, l_port: int) -> int | None:
        if lookup_mode["kind"] == "post_close":
            assert post_close_gate.wait(timeout=3.0)
            return 47001
        return os.getpid()

    def _mock_start(pid: int) -> str:
        if pid == 47001:
            return "2026-11-12T03:00:00.000000Z"
        return native_owner.utc_now_z()

    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-r02-life",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
        collector_timeout_s=1.0,
    )
    try:
        with open_test_loopback_transport(tpl, name="r02-post-close") as h:
            from superbrain.cli_api import _loopback_server

            orig_wrapped_worker = _loopback_server.LoopbackServer._conn_worker

            def _worker_then_signal_close(self: Any, conn_id: Any, raw_sock: Any, accept_ns: int) -> None:
                try:
                    orig_wrapped_worker(self, conn_id, raw_sock, accept_ns)
                finally:
                    post_close_gate.set()

            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()
            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", _mock_lookup)
                mp.setattr(native_owner, "process_started_at_for_pid", _mock_start)
                mp.setattr(_loopback_server.LoopbackServer, "_conn_worker", _worker_then_signal_close)

                res_post = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-r02-post-close",
                    ),
                )
                assert res_post.get("ok") is True
                hook_state["flush"](timeout=2.0)

                lookup_mode["kind"] = "fast_live"
                mp.setattr(_loopback_server.LoopbackServer, "_conn_worker", orig_wrapped_worker)
                res_live = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-r02-live",
                    ),
                )
                assert res_live.get("ok") is True
                hook_state["flush"](timeout=2.0)
    finally:
        post_close_gate.set()
        hook_state["uninstall"]()

    events: list[dict[str, Any]] = []
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            events.append(item)
    owner_calls = [e for e in events if e.get("event") == "owner_call"]
    sock_obs = [e for e in events if e.get("event") == "socket_observation"]
    assert len(owner_calls) == 2

    # First call (post-close synthetic 47001) MUST NOT be recorded as 'ok' with client_pid=47001!
    oc_post = owner_calls[0]
    assert oc_post["observation_status"] == "observation_incomplete"
    assert oc_post["client_pid"] is None
    for so_post in sock_obs:
        if so_post.get("connection_id") == oc_post.get("connection_id"):
            assert so_post["observation_status"] == "observation_incomplete"
            assert so_post["client_pid"] is None

    # Second call (live socket) succeeds with 'ok', observed_at inside [started_at, ended_at].
    oc_live = owner_calls[1]
    assert oc_live["observation_status"] == "ok"
    assert oc_live["client_pid"] == os.getpid()
    live_socks = [s for s in sock_obs if s.get("connection_id") == oc_live.get("connection_id")]
    assert len(live_socks) == 1
    so_live = live_socks[0]
    assert so_live["observation_status"] == "ok"
    assert isinstance(so_live.get("observed_at"), str)
    assert so_live["started_at"] <= so_live["observed_at"] <= so_live["ended_at"]
    assert so_live["ended_at"] >= oc_live["ended_at"]

    # Verifier rejects missing/out-of-bounds observed_at, PID reuse, and overlapping 4-tuple reuse.
    case_dir = trusted_tmp / "r5-t9-r02-synth"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, _ = _sample_world(case_dir)
    so0 = obs.socket_observations[0]
    assert verify_native_connection(probe, registration=reg, observations=obs) is True
    for bad_so in (
        replace(so0, observed_at=None),
        replace(so0, observed_at="2026-11-12T04:00:02.001000Z"),  # Before socket started_at.
        replace(so0, observed_at="2026-11-12T04:00:02.149000Z"),  # After socket ended_at.
    ):
        bad_obs = replace(obs, socket_observations=(bad_so,))
        assert verify_native_connection(probe, registration=reg, observations=bad_obs) is False

    # PID reuse: worker started AFTER observed_at must reject even if inside probe ended_at.
    assert probe.shim_worker_process is not None
    reused_worker = ProcessIdentity(pid=probe.shim_worker_process.pid, started_at="2026-11-12T04:00:02.030000Z")
    reused_so = replace(so0, client_process=reused_worker, observed_at="2026-11-12T04:00:02.020000Z")
    assert (
        verify_native_connection(
            replace(probe, shim_worker_process=reused_worker),
            registration=reg,
            observations=replace(
                obs,
                host_calls=(replace(obs.host_calls[0], shim_worker_process=reused_worker),),
                owner_events=(replace(obs.owner_events[0], client_process=reused_worker),),
                socket_observations=(reused_so,),
            ),
        )
        is False
    )

    # Concurrent 4-tuple reuse (overlapping lifetime on exact same 4-tuple even for same worker) must reject.
    so_overlap = replace(
        so0,
        connection_id="conn-t9-overlap",
        started_at="2026-11-12T04:00:02.010000Z",
        observed_at="2026-11-12T04:00:02.030000Z",
        ended_at="2026-11-12T04:00:02.150000Z",
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(obs, socket_observations=(so0, so_overlap)),
        )
        is False
    )


def test_t9_r03_tool_scope_symmetry_and_d8_terminal_shape(trusted_tmp: Path) -> None:
    """T9-R03: Reject scoped shallow get_health, non-D8 ok tools, and malformed host/owner terminals."""
    from tests.support.inc2_native import parse_host_calls_jsonl, parse_owner_events_jsonl

    case_dir = trusted_tmp / "r5-t9-r03"
    case_dir.mkdir(parents=True, exist_ok=True)
    probe, reg, obs, ev_root = _sample_world(case_dir)
    assert probe.terminal_facts is not None
    scope_a = {"repo_id": "repo-t9-a", "checkout_id": "chk-t9-a"}

    # Positive twin 1: global scope-free get_health succeeds.
    assert probe.terminal_facts.tool_name == "get_health"
    assert probe.terminal_facts.observed_scope is None
    assert obs.owner_events[0].selected_scope is None
    assert verify_native_connection(probe, registration=reg, observations=obs) is True

    # Negative: get_health with ok=True and checkout scope MUST fail parser AND verifier.
    scoped_health_probe = replace(
        probe,
        terminal_facts=replace(probe.terminal_facts, tool_name="get_health", observed_scope=scope_a),
    )
    with pytest.raises(ProbeValidationError):
        parse_native_probe(canonical_json(scoped_health_probe.to_dict()))
    oc = obs.owner_events[0]
    assert oc.client_process is not None
    oc_scoped_path = ev_root / "oc-bad-health-scope.jsonl"
    oc_scoped_path.write_bytes(
        canonical_json(
            {
                "event": "owner_call",
                "connection_id": oc.connection_id,
                "observation_status": oc.observation_status,
                "daemon_pid": oc.daemon_process.pid,
                "daemon_started_at": oc.daemon_process.started_at,
                "store_id": oc.store_id,
                "writer_epoch": oc.writer_epoch,
                "instance_id": oc.instance_id,
                "principal_id": oc.principal_id,
                "credential_id": oc.credential_id,
                "tool_name": "get_health",
                "ready": True,
                "auth_stamp_matched": True,
                "response_flushed_ok": True,
                "response_digest": oc.response_digest,
                "listen_host": oc.listen_host,
                "listen_port": oc.listen_port,
                "client_host": oc.client_host,
                "client_port": oc.client_port,
                "client_pid": oc.client_process.pid,
                "client_started_at": oc.client_process.started_at,
                "started_at": oc.started_at,
                "ended_at": oc.ended_at,
                "call_id": oc.call_id,
                "selected_scope": scope_a,
            }
        )
        + b"\n"
    )
    idx_bad = json.loads(obs.artifact_paths["evidence_index"].read_text(encoding="utf-8"))
    idx_bad["artifacts"]["owner_events"] = digest_bytes(oc_scoped_path.read_bytes())
    idx_bad_path = ev_root / "idx-bad-health.json"
    idx_bad_path.write_bytes(canonical_json(idx_bad) + b"\n")
    obs_scoped_health = replace(
        obs,
        artifact_paths={**obs.artifact_paths, "owner_events": oc_scoped_path, "evidence_index": idx_bad_path},
        owner_events=(replace(oc, selected_scope=scope_a),),
    )
    assert verify_native_connection(scoped_health_probe, registration=reg, observations=obs_scoped_health) is False

    # Positive twin 2: D3 workspace-scoped get_job succeeds (both global None and scoped checkout valid).
    job_dir = case_dir / "job-positive"
    job_dir.mkdir(parents=True, exist_ok=True)
    probe_job, reg_job, obs_job, _ = _sample_world(job_dir, tool_name="get_job")
    assert probe_job.terminal_facts is not None and probe_job.terminal_facts.observed_scope == scope_a
    assert verify_native_connection(probe_job, registration=reg_job, observations=obs_job) is True

    # Native passed probe with unimplemented D8 mutation tool (submit_episode) MUST reject even with scope present.
    native_mut_probe = replace(
        probe_job,
        kind="native",
        terminal_facts=replace(probe_job.terminal_facts, tool_name="submit_episode", observed_scope=scope_a),
    )
    assert verify_native_connection(native_mut_probe, registration=reg_job, observations=obs_job) is False

    # Host terminal_ok=True without response_digest must fail; owner auth_stamp_matched=True without digest must fail.
    hc = obs.host_calls[0]
    with pytest.raises(ProbeValidationError):
        parse_host_calls_jsonl(
            canonical_json(
                {
                    "call_id": hc.call_id,
                    "channel": hc.channel,
                    "host_process": hc.host_process.to_dict(),
                    "shim_launcher_process": hc.shim_launcher_process.to_dict(),
                    "shim_worker_process": hc.shim_worker_process.to_dict(),
                    "tool_name": "get_health",
                    "terminal_ok": True,
                    "response_digest": None,
                    "started_at": hc.started_at,
                    "ended_at": hc.ended_at,
                }
            )
            + b"\n"
        )
    with pytest.raises(ProbeValidationError):
        parse_owner_events_jsonl(
            canonical_json(
                {
                    "event": "owner_call",
                    "connection_id": oc.connection_id,
                    "observation_status": "ok",
                    "daemon_pid": oc.daemon_process.pid,
                    "daemon_started_at": oc.daemon_process.started_at,
                    "store_id": oc.store_id,
                    "writer_epoch": oc.writer_epoch,
                    "instance_id": oc.instance_id,
                    "principal_id": oc.principal_id,
                    "credential_id": oc.credential_id,
                    "tool_name": "get_health",
                    "ready": True,
                    "auth_stamp_matched": True,
                    "response_flushed_ok": True,
                    "response_digest": None,
                    "listen_host": oc.listen_host,
                    "listen_port": oc.listen_port,
                    "client_host": oc.client_host,
                    "client_port": oc.client_port,
                    "client_pid": oc.client_process.pid,
                    "client_started_at": oc.client_process.started_at,
                    "started_at": oc.started_at,
                    "ended_at": oc.ended_at,
                    "call_id": oc.call_id,
                    "selected_scope": None,
                }
            )
            + b"\n"
        )


def test_t9_r05_win32_unpinned_ticks_never_terminates_or_waits_reopened_pid(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R05: expected_ticks=None never calls TerminateProcess, Wait, or unpinned OpenProcess."""
    if sys.platform != "win32":
        pytest.skip("Win32-only process creation tick pin test")
    import win32api
    import win32process

    from tests.support import inc2_cli as cli

    terminated_handles: list[int] = []
    opened_pids: list[int] = []

    def _stub_open(access: int, inherit: bool, pid: int) -> int:
        opened_pids.append(pid)
        return 777

    with monkeypatch.context() as mp:
        mp.setattr(win32api, "OpenProcess", _stub_open)
        mp.setattr(win32api, "CloseHandle", lambda _h: None)
        mp.setattr(cli, "_win32_handle_creation_ticks", lambda _h: 909)
        mp.setattr(
            win32process,
            "TerminateProcess",
            lambda handle, code: terminated_handles.append(int(handle)),
        )

        # Mismatch pin (808 != 909) returns True (PID recycled) without terminating.
        assert cli._win32_wait_or_terminate_pid(12345, expected_ticks=808, terminate=True, timeout_s=0.1) is True
        assert terminated_handles == []

        # Missing pin (expected_ticks=None) MUST fail closed (False) and NEVER open/terminate/wait!
        opened_pids.clear()
        assert cli._win32_wait_or_terminate_pid(12345, expected_ticks=None, terminate=True, timeout_s=0.1) is False
        assert cli._win32_wait_or_terminate_pid(12345, expected_ticks=None, terminate=False, timeout_s=0.1) is False
        assert terminated_handles == []
        assert opened_pids == []

    # Recycled ancestor PID in _win32_descendant_identities: if root_pid exited and OS recycled PID to newer occupant,
    # children spawned by the new occupant (ticks > pinned_root_ticks) MUST NOT be claimed as descendants.
    base_py = str(getattr(sys, "_base_executable", sys.executable))
    child_cmd = (
        "import subprocess, sys, time; "
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); "
        "print(c.pid, flush=True); time.sleep(10)"
    )
    tree_proc = subprocess.Popen(
        [base_py, "-c", child_cmd],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert tree_proc.stdout is not None
    child_pid = int(tree_proc.stdout.readline().strip())
    tree_pins = [
        (child_pid, cli._win32_process_creation_ticks(child_pid)),
        (tree_proc.pid, cli._win32_popen_creation_ticks(tree_proc)),
    ]
    try:
        actual_root_ticks = cli._win32_process_creation_ticks(tree_proc.pid)
        assert actual_root_ticks is not None
        stale_pinned_ticks = actual_root_ticks - 10_000_000
        assert cli._win32_descendant_identities(tree_proc.pid, root_ticks=stale_pinned_ticks) == []
    finally:
        for p, ticks in tree_pins:
            if ticks is not None:
                cli._win32_wait_or_terminate_pid(p, expected_ticks=ticks, terminate=True, timeout_s=2.0)

    # Controller with missing _proc_ticks uses only Popen handle kill/wait and skips PID reopen.
    reopened_calls: list[tuple[int, int | None]] = []

    def _record_reopened(
        pid: int,
        *,
        expected_ticks: int | None = None,
        terminate: bool,
        timeout_s: float,
    ) -> bool:
        del terminate, timeout_s
        reopened_calls.append((pid, expected_ticks))
        return False

    with monkeypatch.context() as mp:
        mp.setattr(cli, "_win32_popen_creation_ticks", lambda _p: None, raising=False)
        mp.setattr(cli, "_win32_process_creation_ticks", lambda _pid: None)
        mp.setattr(cli, "_win32_wait_or_terminate_pid", _record_reopened)
        ctrl = cli.InstalledServeProcess(
            [base_py, "-c", "import time; time.sleep(10)"],
            data_root=trusted_tmp / "r5-serve-unpinned",
            cwd=trusted_tmp,
        )
        assert ctrl.snapshot_descendant_identities() == ()
        ctrl.close()
        assert reopened_calls == []
        assert getattr(ctrl, "cleanup_unverified", False) is True


def test_t9_r07_collector_submit_and_finalizer_start_failures_preserve_worker_and_cleanup(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R07: Failures in submit or Thread.start keep daemon call + socket/slot cleanup intact."""
    import concurrent.futures
    import queue
    import threading

    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    del trusted_tmp
    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()

    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-r07-submit-fail",
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
        collector_timeout_s=0.5,
    )
    try:
        with open_test_loopback_transport(tpl, name="r07-submit-fail") as h:
            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()

            # 1. Collector ThreadPoolExecutor.submit raises RuntimeError -> request & cleanup succeed.
            with monkeypatch.context() as mp:
                mp.setattr(
                    concurrent.futures.ThreadPoolExecutor,
                    "submit",
                    lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("submit_boom")),
                )
                res_submit = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-r07-submit-fail",
                    ),
                )
                assert res_submit.get("ok") is True

            # 2. Finalizer Thread.start raises RuntimeError -> request & cleanup succeed, event degraded.
            orig_start = threading.Thread.start

            def _fail_finalizer_start(self: threading.Thread) -> None:
                if self.name.startswith("inc2-obs-finalize-"):
                    raise RuntimeError("thread_start_boom")
                orig_start(self)

            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", lambda _c, _l: None)
                mp.setattr(threading.Thread, "start", _fail_finalizer_start)
                # Force lookup_fut not yet done when _schedule_emit runs by gating lookup briefly.
                gate = threading.Event()
                mp.setattr(
                    native_owner,
                    "_lookup_loopback_client_pid",
                    lambda _c, _l: (gate.wait(timeout=0.3), None)[1],
                )
                try:
                    res_th = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                        target,
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-r07-th-start-fail",
                        ),
                    )
                    assert res_th.get("ok") is True
                finally:
                    gate.set()

            hook_state["flush"](timeout=2.0)
            srv = h.server
            with srv._lock:
                assert srv._active_slots == 0
                assert srv._sockets == {}
                assert srv._workers == {}
    finally:
        hook_state["uninstall"]()

    events: list[dict[str, object]] = []
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            events.append(item)
    calls = [e for e in events if e.get("event") == "owner_call"]
    assert len(calls) == 2
    assert all(c["observation_status"] == "observation_incomplete" and c["client_pid"] is None for c in calls)


def test_t9_r02_tls_close_before_worker_return_and_ready_port_mismatch(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R02 R6: Reject OS lookups after socket close/abort before worker return, and pin 3-channel port."""
    import queue
    import threading

    from superbrain.cli_api import _loopback_server
    from superbrain.cli_api._loopback_wire import (
        HEADER_INSTANCE_ID,
        HEADER_STORE_ID,
        HEADER_WRITER_EPOCH,
        IDENTITY_PATH,
        TOOL_CALL_PATH,
        encode_call,
    )
    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    # Part A: Verifier MUST reject owner-ready.port != owner.listen_port / socket.remote_port even with valid digests.
    case_dir = trusted_tmp / "r6-r02-port"
    probe, reg, obs, ev_root = _sample_world(case_dir)
    assert verify_native_connection(probe, registration=reg, observations=obs) is True

    ready_path = ev_root / "owner-ready.json"
    ready_obj = json.loads(ready_path.read_text(encoding="utf-8"))
    ready_obj["port"] = int(ready_obj["port"]) + 1
    new_ready_bytes = canonical_json(ready_obj) + b"\n"
    ready_path.write_bytes(new_ready_bytes)

    idx_path = ev_root / "evidence-index.json"
    idx_obj = json.loads(idx_path.read_text(encoding="utf-8"))
    idx_obj["artifacts"]["owner_ready"] = digest_bytes(new_ready_bytes)
    idx_path.write_bytes(canonical_json(idx_obj) + b"\n")
    assert verify_native_connection(probe, registration=reg, observations=obs) is False

    # Part B: Live TLS client held open across server close (_graceful_close_conn) / abort BEFORE _conn_worker returns.
    tpl = get_shared_t7_transport_template()
    eq: queue.SimpleQueue[dict[str, JsonValue] | None] = queue.SimpleQueue()
    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        daemon_pid=os.getpid(),
        daemon_started_at=process_started_at_for_pid(os.getpid()),
        store_id=tpl.store_id,
        instance_id="inst-r6-r02-tls",
        collector_timeout_s=2.0,
    )
    real_lookup_fn = native_owner._lookup_loopback_client_pid
    after_close_gate = threading.Event()
    lookup_finished = threading.Event()
    mode = {"kind": "after_tls_close"}

    def _gated_real_lookup(client_port: int, listen_port: int) -> int | None:
        if mode["kind"] in {"after_tls_close", "after_abort"}:
            after_close_gate.wait(timeout=2.0)
            try:
                return real_lookup_fn(client_port, listen_port)
            finally:
                lookup_finished.set()
        return real_lookup_fn(client_port, listen_port)

    try:
        with open_test_loopback_transport(tpl, name="r6-r02-tls") as h:
            orig_release_conn = _loopback_server.LoopbackServer._release_conn
            orig_release_reply = _loopback_server.LoopbackServer._release_owner_reply

            def _wait_after_close_before_worker_return(
                self: Any,
                conn_id: Any,
                raw_sock: Any,
                ssl_sock: Any,
                *,
                drain: bool,
            ) -> None:
                orig_release_conn(self, conn_id, raw_sock, ssl_sock, drain=drain)
                if mode["kind"] == "after_tls_close":
                    assert (ssl_sock is None or ssl_sock.fileno() == -1) and raw_sock.fileno() == -1
                    after_close_gate.set()
                    lookup_finished.wait(timeout=2.0)

            def _abort_during_reply_and_wait(
                self: Any,
                ssl_sock: Any,
                reply: Any,
                tool_deadline_ns: int,
            ) -> None:
                if mode["kind"] == "after_abort":
                    self._abort_all_active_sockets()
                    assert ssl_sock.fileno() == -1
                    after_close_gate.set()
                    lookup_finished.wait(timeout=2.0)
                orig_release_reply(self, ssl_sock, reply, tool_deadline_ns)

            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()

            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", _gated_real_lookup)
                mp.setattr(
                    _loopback_server.LoopbackServer,
                    "_release_conn",
                    _wait_after_close_before_worker_return,
                )

                # 1. Keep client TLS socket open past _graceful_close_conn before _conn_worker returns.
                tls_sock = h.open_raw_tls_socket(timeout=2.0)
                try:
                    host_hdr = f"127.0.0.1:{target.endpoint.port}"
                    ident_req = (
                        f"GET {IDENTITY_PATH} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: keep-alive\r\n\r\n"
                    ).encode("ascii")
                    ident_resp = h.send_raw_http(tls_sock, ident_req)
                    assert b"200 OK" in ident_resp

                    call_body = encode_call(
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-r6-r02-after-close",
                        )
                    )
                    tool_req = (
                        f"POST {TOOL_CALL_PATH} HTTP/1.1\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"Authorization: Bearer {tpl.cred.token}\r\n"
                        f"{HEADER_STORE_ID}: {target.expected_store_id}\r\n"
                        f"{HEADER_WRITER_EPOCH}: {h.ready.identity.writer_epoch}\r\n"
                        f"{HEADER_INSTANCE_ID}: {h.ready.identity.instance_id}\r\n"
                        f"Content-Length: {len(call_body)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("ascii") + call_body
                    tool_resp = h.send_raw_http(tls_sock, tool_req)
                    assert b'"ok":true' in tool_resp
                    assert lookup_finished.wait(timeout=3.0)
                finally:
                    tls_sock.close()
                hook_state["flush"](timeout=2.0)

                # 2. Positive twin: TLS call with live lookup before close -> 'ok' with os.getpid().
                mode["kind"] = "live"
                res_live = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-r6-r02-live",
                    ),
                )
                assert res_live.get("ok") is True
                hook_state["flush"](timeout=2.0)

                # 3. Abort boundary: socket aborted during shutdown before _release_owner_reply / _conn_worker returns.
                after_close_gate.clear()
                lookup_finished.clear()
                mode["kind"] = "after_abort"
                mp.setattr(_loopback_server.LoopbackServer, "_release_owner_reply", _abort_during_reply_and_wait)
                abort_sock = h.open_raw_tls_socket(timeout=2.0)
                try:
                    host_hdr = f"127.0.0.1:{target.endpoint.port}"
                    ident_req = (
                        f"GET {IDENTITY_PATH} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: keep-alive\r\n\r\n"
                    ).encode("ascii")
                    assert b"200 OK" in h.send_raw_http(abort_sock, ident_req)
                    call_body = encode_call(
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-r6-r02-after-abort",
                        )
                    )
                    tool_req = (
                        f"POST {TOOL_CALL_PATH} HTTP/1.1\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"Authorization: Bearer {tpl.cred.token}\r\n"
                        f"{HEADER_STORE_ID}: {target.expected_store_id}\r\n"
                        f"{HEADER_WRITER_EPOCH}: {h.ready.identity.writer_epoch}\r\n"
                        f"{HEADER_INSTANCE_ID}: {h.ready.identity.instance_id}\r\n"
                        f"Content-Length: {len(call_body)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("ascii") + call_body
                    abort_sock.sendall(tool_req)
                    assert lookup_finished.wait(timeout=3.0)
                finally:
                    abort_sock.close()
                hook_state["flush"](timeout=2.0)
    finally:
        after_close_gate.set()
        hook_state["uninstall"]()

    events: list[dict[str, Any]] = []
    while not eq.empty():
        item = eq.get_nowait()
        if item is not None:
            events.append(item)
    owner_calls = [e for e in events if e.get("event") == "owner_call"]
    sock_obs = [e for e in events if e.get("event") == "socket_observation"]
    assert len(owner_calls) == 3

    oc_after_close, oc_live, oc_abort = owner_calls[0], owner_calls[1], owner_calls[2]
    for bad_oc in (oc_after_close, oc_abort):
        assert bad_oc["observation_status"] == "observation_incomplete"
        assert bad_oc["client_pid"] is None
        for bad_so in sock_obs:
            if bad_so.get("connection_id") == bad_oc.get("connection_id"):
                assert bad_so["observation_status"] == "observation_incomplete"
                assert bad_so["client_pid"] is None

    assert oc_live["observation_status"] == "ok"
    assert oc_live["client_pid"] == os.getpid()


def test_t9_r05_win32_descendant_snapshot_pin_rejects_recycled_child_occupant(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R05 R6: Child PID recycled to unrelated occupant between snapshot and pin is rejected + unverified."""
    if sys.platform != "win32":
        pytest.skip("Win32-only process identity & Job Object test")
    import ctypes
    from ctypes import wintypes

    import win32process

    from tests.support import inc2_cli as cli

    base_py = str(getattr(sys, "_base_executable", sys.executable))

    # 1. Recycled child occupant between snapshot and handle pinning while root stays alive.
    terminated_handles: list[int] = []
    root_proc = subprocess.Popen(
        [base_py, "-c", "import time; time.sleep(10)"],
        stdout=subprocess.PIPE,
        text=True,
    )
    unrelated_proc = subprocess.Popen(
        [base_py, "-c", "import time; time.sleep(10)"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        root_pid = root_proc.pid
        root_ticks = cli._win32_popen_creation_ticks(root_proc)
        assert root_ticks is not None
        unrelated_pid = unrelated_proc.pid
        unrelated_ticks = cli._win32_popen_creation_ticks(unrelated_proc)
        assert unrelated_ticks is not None
        stale_child_ticks = root_ticks + 5_000
        assert unrelated_ticks != stale_child_ticks

        class _ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snap_sentinel = 987654321
        orig_snap = kernel32.CreateToolhelp32Snapshot
        orig_p32_first = kernel32.Process32First
        orig_p32_next = kernel32.Process32Next
        orig_close = kernel32.CloseHandle

        def _fake_snap(flags: int, pid: int) -> int:
            del flags, pid
            return snap_sentinel

        def _fake_first(snap: int, entry_ref: Any) -> int:
            if snap != snap_sentinel:
                return int(orig_p32_first(snap, entry_ref))
            ent = ctypes.cast(entry_ref, ctypes.POINTER(_ProcessEntry32)).contents
            ent.th32ProcessID = unrelated_pid
            ent.th32ParentProcessID = root_pid
            return 1

        def _fake_next(snap: int, entry_ref: Any) -> int:
            if snap != snap_sentinel:
                return int(orig_p32_next(snap, entry_ref))
            return 0

        def _fake_close(handle: int) -> int:
            if handle == snap_sentinel:
                return 1
            return int(orig_close(handle))

        with monkeypatch.context() as mp:
            # Snapshot reports edge root_pid -> stale old occupant at PID `unrelated_pid`,
            # while live handle queries see real `unrelated_proc` (unrelated ppid + new ticks).
            mp.setattr(kernel32, "CreateToolhelp32Snapshot", _fake_snap)
            mp.setattr(kernel32, "Process32First", _fake_first)
            mp.setattr(kernel32, "Process32Next", _fake_next)
            mp.setattr(kernel32, "CloseHandle", _fake_close)
            mp.setattr(
                cli,
                "_win32_process_snapshot",
                lambda: [
                    (root_pid, os.getpid(), root_ticks),
                    (unrelated_pid, root_pid, stale_child_ticks),
                ],
                raising=False,
            )
            mp.setattr(
                win32process,
                "TerminateProcess",
                lambda handle, code: terminated_handles.append(int(handle)),
            )

            identities = cli._win32_descendant_identities(root_pid, root_ticks=root_ticks)
            assert identities == []
            _ = orig_snap

            checked_idents, unverified = cli._win32_descendant_identities_checked(
                root_pid, root_ticks=root_ticks
            )
            assert checked_idents == []
            assert unverified is True
            for dpid, dticks in checked_idents:
                cli._win32_wait_or_terminate_pid(
                    dpid, expected_ticks=dticks, terminate=True, timeout_s=0.1
                )
            assert terminated_handles == []
    finally:
        for p in (unrelated_proc, root_proc):
            ticks = cli._win32_popen_creation_ticks(p)
            p.terminate()
            p.wait(timeout=5.0)
            if ticks is not None:
                cli._win32_wait_or_terminate_pid(p.pid, expected_ticks=ticks, terminate=True, timeout_s=2.0)

    # 2. Positive twin: live root with real live child under InstalledServeProcess Job Object.
    ctrl = cli.InstalledServeProcess(
        [
            base_py,
            "-c",
            (
                "import subprocess, sys, time; "
                "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); "
                "print(c.pid, flush=True); time.sleep(10)"
            ),
        ],
        data_root=trusted_tmp / "r6-r05-live",
        cwd=trusted_tmp,
    )
    try:
        assert ctrl._proc.stdout is not None
        live_child_pid = int(ctrl._proc.stdout.readline().strip())
        live_idents, live_unverified = cli._win32_descendant_identities_checked(
            ctrl.pid, root_ticks=ctrl._proc_ticks, job_handle=getattr(ctrl, "_job_handle", None)
        )
        assert live_unverified is False
        assert any(pid == live_child_pid for pid, _ in live_idents)
    finally:
        ctrl.close()
        assert ctrl.cleanup_unverified is False


def test_t9_r05_win32_job_pids_cap_break_on_large_assigned_count() -> None:
    """T9-R05 P3: _win32_job_pids breaks cleanly and returns None when assigned > 4096 (no infinite loop)."""
    if sys.platform != "win32":
        pytest.skip("Win32-only Job Object test")
    import ctypes
    import unittest.mock as mock
    from ctypes import wintypes

    from tests.support import inc2_cli as cli

    with mock.patch("ctypes.WinDLL") as mock_windll:
        mock_k32 = mock.MagicMock()
        mock_windll.return_value = mock_k32

        def fake_query(h: Any, info_class: Any, buf: Any, buf_size: Any, ret_len: Any) -> int:
            ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0] = 4097
            return 0

        mock_k32.QueryInformationJobObject.side_effect = fake_query
        with mock.patch("ctypes.get_last_error", return_value=234):  # ERROR_MORE_DATA
            res = cli._win32_job_pids(12345)
            assert res is None, "Must break cleanly and return None when next_cap > 4096"


def test_t9_r05_inc2_child_suspended_spawn_and_early_launcher_exit_cleanup(
    trusted_tmp: Path,
) -> None:
    """T9-R05 P2: Suspended spawn membership & early launcher exit cleanup with verified termination."""
    if sys.platform != "win32":
        pytest.skip("Win32-only Job Object test")
    from tests.support import inc2_child

    del trusted_tmp
    base_py = str(getattr(sys, "_base_executable", sys.executable))

    # 1. Suspended spawn membership: child spawned immediately by launcher is inside Job Object.
    code_spawn_fast = (
        "import ctypes, ctypes.wintypes, json, subprocess, sys, time\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])\n"
        "k32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "times = [ctypes.wintypes.FILETIME() for _ in range(4)]\n"
        "k32.GetProcessTimes(ctypes.wintypes.HANDLE(c._handle), *(ctypes.byref(t) for t in times))\n"
        "ticks = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)\n"
        "sys.stdout.write(json.dumps({'event': 'hello', 'pid': c.pid, 'creation_ticks': ticks}) + '\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(10)\n"
    )
    with inc2_child.Inc2ChildProcess([base_py, "-c", code_spawn_fast]) as fast_child:
        fast_child.wait_hello(timeout=5.0)
        inner_pid = fast_child.inner_pid
        assert inner_pid is not None
        job = fast_child._job
        assert job is not None
        pids = job.query_pids()
        assert pids is not None
        assert fast_child.launcher_pid in pids
        assert inner_pid in pids
    assert fast_child.cleanup_unverified is False

    # 2. Early launcher exit cleanup: launcher spawns child and exits 0 immediately; close() cleans up child.
    code_early_exit = (
        "import ctypes, ctypes.wintypes, json, subprocess, sys\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\n"
        "k32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "times = [ctypes.wintypes.FILETIME() for _ in range(4)]\n"
        "k32.GetProcessTimes(ctypes.wintypes.HANDLE(c._handle), *(ctypes.byref(t) for t in times))\n"
        "ticks = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)\n"
        "sys.stdout.write(json.dumps({'event': 'hello', 'pid': c.pid, 'creation_ticks': ticks}) + '\\n')\n"
        "sys.stdout.flush()\n"
        "sys.exit(0)\n"
    )
    p = inc2_child.Inc2ChildProcess([base_py, "-c", code_early_exit])
    p.wait_hello(timeout=5.0)
    leaked_child_pid = p.inner_pid
    assert leaked_child_pid is not None
    p._proc.wait(timeout=5.0)
    assert p._proc.poll() == 0
    p.close()
    assert p.cleanup_unverified is False

    # Verify child is actually terminated from OS.
    check = subprocess.run(["tasklist", "/FI", f"PID eq {leaked_child_pid}"], capture_output=True, text=True)
    assert str(leaked_child_pid) not in check.stdout


def test_t9_r02_handshake_independent_of_collector_latency(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T9-R02: Connection worker starts immediately without observer prewait delay; held lookup degrades gracefully."""
    import queue
    import threading

    from superbrain.core.kernel import ToolCommand
    from tests.support import inc2_native_owner as native_owner
    from tests.support.inc2_transport import FakeMonotonicClock, open_test_loopback_transport

    del trusted_tmp
    tpl = get_shared_t7_transport_template()
    eq: queue.Queue[dict[str, object] | None] = queue.Queue()

    def _drain_and_join_workers() -> list[dict[str, object]]:
        for th in threading.enumerate():
            if th.name.startswith("superbrain-loopback-conn-") and th.is_alive():
                th.join(timeout=2.0)
        flush_fn = hook_state.get("flush")
        if callable(flush_fn):
            flush_fn(timeout=2.0)
        items: list[dict[str, object]] = []
        while not eq.empty():
            item = eq.get_nowait()
            if item is not None:
                items.append(item)
        return items

    daemon_started_at = process_started_at_for_pid(os.getpid())
    hook_state = native_owner._install_loopback_server_hooks(
        eq=eq,
        store_id=tpl.store_id,
        instance_id="inst-r02-handshake",
        daemon_pid=os.getpid(),
        daemon_started_at=daemon_started_at,
        collector_timeout_s=0.5,
    )
    try:
        with open_test_loopback_transport(tpl, name="r02-handshake-test") as h:
            client_clock = FakeMonotonicClock(h.mono_clock.now)
            target = h.make_target()

            # 1. Positive twin: immediate lookup while connection is live -> obs_status ok, client_pid matched.
            res_pos = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                target,
                ToolCommand(
                    tool="get_health",
                    arguments={"schema_version": "2.0"},
                    token=tpl.cred.token,
                    selected_scope=None,
                    correlation_id="corr-r02-pos",
                ),
            )
            assert res_pos.get("ok") is True
            ev1 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev1) == 1
            assert ev1[0]["tool_name"] == "get_health"
            assert ev1[0]["response_flushed_ok"] is True
            if sys.platform == "win32":
                assert ev1[0]["client_pid"] == os.getpid()
                assert ev1[0]["observation_status"] == "ok"
            assert hook_state["pending_count"]() == 0

            # 2. Held lookup: lookup sleeps 300ms, but connection worker must NOT wait for it.
            # Client call must complete rapidly (< 150ms), and observation must degrade to observation_incomplete.
            lookup_started = threading.Event()
            lookup_release = threading.Event()

            def _held_lookup(_peer_port: int, _listen_port: int) -> int | None:
                lookup_started.set()
                lookup_release.wait(timeout=1.0)
                return os.getpid()

            t0 = time.monotonic()
            with monkeypatch.context() as mp:
                mp.setattr(native_owner, "_lookup_loopback_client_pid", _held_lookup)
                res_held = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                    target,
                    ToolCommand(
                        tool="get_health",
                        arguments={"schema_version": "2.0"},
                        token=tpl.cred.token,
                        selected_scope=None,
                        correlation_id="corr-r02-held",
                    ),
                )
            t_call = time.monotonic() - t0
            lookup_release.set()

            assert res_held.get("ok") is True
            # The client call took way less than the held lookup timeout because there is no prewait.
            assert t_call < 0.25, f"Client call was blocked by observer: took {t_call:.3f}s"
            ev2 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev2) == 1
            assert ev2[0]["tool_name"] == "get_health"
            assert ev2[0]["response_flushed_ok"] is True
            # When lookup is delayed beyond socket close, it degrades to observation_incomplete.
            if sys.platform == "win32":
                assert ev2[0]["observation_status"] in ("ok", "observation_incomplete")
            assert hook_state["pending_count"]() == 0

            # 3. Near-deadline handshake: client connects near deadline, observer prewait must not cause timeout.
            res_deadline = h.open_client(monotonic_ns=client_clock.monotonic_ns).call(
                target,
                ToolCommand(
                    tool="get_health",
                    arguments={"schema_version": "2.0"},
                    token=tpl.cred.token,
                    selected_scope=None,
                    correlation_id="corr-r02-deadline",
                ),
            )
            assert res_deadline.get("ok") is True
            ev3 = [r for r in _drain_and_join_workers() if r.get("event") == "owner_call"]
            assert len(ev3) == 1
            assert ev3[0]["response_flushed_ok"] is True
    finally:
        hook_state["uninstall"]()
