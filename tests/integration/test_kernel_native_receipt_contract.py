"""Task 9 contract tests for native/wheel connection receipts and multi-channel verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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
    verify_native_connection,
)
from tests.support.inc2_native_owner import (
    ObservedWheelOwner,
    load_owner_observations,
    process_started_at_for_pid,
    spawn_observed_wheel_owner,
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
    probe_kind: Any = kind
    probe = NativeConnectionProbe(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        kind=probe_kind,
        status="passed",
        reason_code=None,
        task_id="task-t9-obs-1",
        observed_call_id=call_id,
        observation_channel=channel,
        host=host,
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
            tool_name="get_health",
            ok=True,
            status="ok",
            auth_granted=True,
            response_flushed=True,
            response_digest=response_digest,
            observed_scope=scope_a.to_dict(),
        ),
    )

    registration = ObserverRegistration(
        evidence_root=evidence_root,
        task_id="task-t9-obs-1",
        expected_kind=probe_kind,
        registered_observer_id="obs-claude-1",
        registered_channel=channel,
        expected_host=host,
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

    observations = ObservationSet(
        artifact_paths={
            "config": cfg_path,
            "profile": prof_path,
            "schema": schema_path,
            "shim_build": shim_path,
        },
        host_calls=(
            HostCallObservation(
                call_id=call_id,
                channel=channel,
                host_process=host_proc,
                shim_launcher_process=launcher_proc,
                shim_worker_process=worker_proc,
                tool_name="get_health",
                terminal_ok=True,
                response_digest=response_digest,
                started_at="2026-11-12T04:00:02.000000Z",
                ended_at="2026-11-12T04:00:02.150000Z",
            ),
        ),
        owner_events=(
            OwnerCallObservation(
                daemon_process=daemon_proc,
                store_id=store_id,
                writer_epoch=writer_epoch,
                instance_id=instance_id,
                principal_id=principal_id,
                credential_id=cred_id,
                tool_name="get_health",
                ready=True,
                auth_stamp_matched=True,
                response_flushed_ok=True,
                response_digest=response_digest,
                listen_host="127.0.0.1",
                listen_port=45123,
                started_at="2026-11-12T04:00:02.010000Z",
                ended_at="2026-11-12T04:00:02.140000Z",
                call_id=call_id,
                selected_scope=scope_a.to_dict(),
            ),
        ),
        socket_observations=(
            SocketObservation(
                client_process=worker_proc,
                daemon_process=daemon_proc,
                local_addr="127.0.0.1",
                local_port=52001,
                remote_addr="127.0.0.1",
                remote_port=45123,
                store_id=store_id,
                writer_epoch=writer_epoch,
                instance_id=instance_id,
            ),
        ),
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
    scope_a = Scope(repo_id="repo-t9-a", checkout_id="chk-t9-a")
    scope_b = Scope(repo_id="repo-t9-b", checkout_id="chk-t9-b")
    obs_before = ShimLaunchObservation(
        pid=5001,
        started_at="2026-11-12T04:00:00Z",
        profile_digest="sha256:" + "1" * 64,
        observed_scope=scope_a,
    )
    obs_after_good = ShimLaunchObservation(
        pid=probe.shim_worker_process.pid,
        started_at=probe.shim_worker_process.started_at,
        profile_digest=probe.profile_digest or "",
        observed_scope=scope_b,
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                prior_lifecycle=obs_before,
                current_lifecycle=obs_after_good,
                expected_scope=scope_b,
                expected_profile_digest=probe.profile_digest,
                expected_first_scope=scope_a,
            ),
        )
        is True
    )
    obs_after_stale = ShimLaunchObservation(
        pid=obs_before.pid,
        started_at=obs_before.started_at,
        profile_digest=obs_before.profile_digest,
        observed_scope=scope_b,
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                prior_lifecycle=obs_before,
                current_lifecycle=obs_after_stale,
                expected_scope=scope_b,
                expected_profile_digest=probe.profile_digest,
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
        observed_call_id=None,
        observation_channel=None,
        host="codex-desktop",
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
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


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
    shim_build_digest = digest_bytes(env.wheel_path.read_bytes())
    cfg_digest = digest_bytes(config_path.read_bytes())
    prof_digest = digest_bytes(profile_path.read_bytes())
    schema_digest = digest_bytes(schema_copy_path.read_bytes())
    resp_digest = digest_bytes(canonical_json(response_envelope))
    channel = "wheel_mcp_pipe"
    environment = "installed_wheel"
    host_proc = ProcessIdentity(pid=os.getpid(), started_at=process_started_at_for_pid(os.getpid()))

    _, owner_events, sock_events = load_owner_observations(owner_evidence_dir)
    matching_owner = [
        ev for ev in owner_events if ev.tool_name == tool_name and ev.response_digest == resp_digest
    ]
    assert matching_owner, f"Owner tap missing {tool_name} response digest {resp_digest}"
    matched_ports = {ev.listen_port for ev in matching_owner}
    matching_sock = [
        so for so in sock_events if so.client_process == worker_proc and so.remote_port in matched_ports
    ]
    assert matching_sock, f"Kernel socket table tap did not bind {worker_proc} to owner listen port"

    probe = NativeConnectionProbe(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        kind="fixture",
        status="passed",
        reason_code=None,
        task_id=task_id,
        observed_call_id=call_id,
        observation_channel=channel,
        host=host,
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
        expected_kind="fixture",
        registered_observer_id=f"obs-{host}",
        registered_channel=channel,
        expected_host=host,
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
        },
        host_calls=(
            HostCallObservation(
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
            ),
        ),
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
            assert verify_same_daemon(probe_a, probe_dup) is True
            assert probe_dup.binding is not None
            assert probe_dup.binding.principal_id == probe_a.binding.principal_id

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

        assert verify_same_daemon(probe_1, probe_1) is True
        assert probe_1.binding is not None and probe_2.binding is not None
        assert probe_2.binding.writer_epoch > probe_1.binding.writer_epoch
        assert probe_2.binding.instance_id != probe_1.binding.instance_id
        assert verify_same_daemon(probe_1, probe_2) is False

        # Even if writer_epoch differs alone, instance_id differs alone, or daemon started_at differs, reject.
        assert probe_1.daemon_process is not None and probe_1.terminal_facts is not None
        assert (
            verify_same_daemon(probe_1, replace(probe_1, binding=replace(probe_1.binding, writer_epoch=999))) is False
        )
        assert (
            verify_same_daemon(probe_1, replace(probe_1, binding=replace(probe_1.binding, instance_id="inst-other")))
            is False
        )
        assert (
            verify_same_daemon(
                probe_1,
                replace(probe_1, daemon_process=replace(probe_1.daemon_process, started_at="2026-11-12T05:00:00Z")),
            )
            is False
        )
        assert (
            verify_same_daemon(probe_1, replace(probe_1, terminal_facts=replace(probe_1.terminal_facts, ready=False)))
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
                st_a = _utc_now_z()
                resp_ha = sess_a.send_frames_and_expect_response(
                    [
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    ]
                )
                is_err_h, sc_ha = _extract_mcp_structured(resp_ha)
                assert is_err_h is False and cast(dict[str, Any], sc_ha["data"])["ready"] is True

                resp_ja = sess_a.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_a.job_id})]
                )
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
                en_a = _utc_now_z()
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
                st_b = _utc_now_z()
                resp_hb = sess_b.send_frames_and_expect_response(
                    [
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    ]
                )
                is_err_hb2, sc_hb2 = _extract_mcp_structured(resp_hb)
                assert is_err_hb2 is False and cast(dict[str, Any], sc_hb2["data"])["ready"] is True

                resp_jb = sess_b.send_frames_and_expect_response(
                    [mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": job_b.job_id})]
                )
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

                en_b = _utc_now_z()
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
            assert verify_same_daemon(probe_a, probe_b) is True
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
