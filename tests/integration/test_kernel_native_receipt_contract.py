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
    assert probe.terminal_facts is not None
    probe_b_lc = replace(
        probe,
        terminal_facts=replace(probe.terminal_facts, observed_scope=scope_b.to_dict()),
    )
    obs_b_lc = replace(
        obs,
        owner_events=(replace(obs.owner_events[0], selected_scope=scope_b.to_dict()),),
        prior_lifecycle=obs_before,
        current_lifecycle=obs_after_good,
        expected_scope=scope_b,
        expected_profile_digest=probe.profile_digest,
        expected_first_scope=scope_a,
    )
    assert verify_native_connection(probe_b_lc, registration=reg, observations=obs_b_lc) is True
    # Contradictory probe observed_scope (scope_a) vs current_lifecycle (scope_b) MUST fail.
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
    probe_no_scope = replace(probe, terminal_facts=replace(probe.terminal_facts, observed_scope=None))
    oc_scoped = replace(oc, selected_scope={"repo_id": "repo-t9-a", "checkout_id": "chk-t9-a"})
    assert (
        verify_native_connection(
            probe_no_scope,
            registration=reg,
            observations=replace(obs, owner_events=(oc_scoped,)),
        )
        is False
    )

    # 8. Disconnected current_lifecycle (valid transition between unrelated PIDs/profiles) must reject.
    prior_lc = ShimLaunchObservation(
        pid=probe.shim_worker_process.pid - 10,
        started_at="2026-11-12T04:00:00.000000Z",
        profile_digest="sha256:" + "1" * 64,
        observed_scope=Scope("repo-t9-other", "chk-t9-other"),
        launch_cwd=case_dir / "chk-other",
    )
    bogus_curr_lc = ShimLaunchObservation(
        pid=probe.shim_worker_process.pid + 50,
        started_at="2026-11-12T04:00:01.900000Z",
        profile_digest=probe.profile_digest,
        observed_scope=Scope("repo-t9-a", "chk-t9-a"),
        launch_cwd=case_dir / "chk-a",
    )
    assert (
        verify_native_connection(
            probe,
            registration=reg,
            observations=replace(
                obs,
                prior_lifecycle=prior_lc,
                current_lifecycle=bogus_curr_lc,
                expected_scope=Scope("repo-t9-a", "chk-t9-a"),
                expected_profile_digest=probe.profile_digest,
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
    assert revoked_calls[0]["auth_stamp_matched"] is False
    assert revoked_calls[0]["response_flushed_ok"] is False
    assert hook_state["pending_count"]() == 0
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


def test_win32_descendant_pids_catches_exited_parent_and_rejects_recycled(trusted_tmp: Path) -> None:
    """Win32 descendant PID collector catches orphan children while handle open and skips pre-existing processes."""
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
    proc.wait(timeout=5.0)
    try:
        desc = cli._win32_descendant_pids(proc.pid)
        assert child_pid in desc
        # Must never claim current pytest process as a descendant.
        assert os.getpid() not in desc
    finally:
        subprocess.run(["taskkill", "/F", "/PID", str(child_pid)], capture_output=True, check=False)
