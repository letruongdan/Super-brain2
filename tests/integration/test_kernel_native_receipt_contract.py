"""Task 9 contract tests for native/wheel connection receipts and multi-channel verification."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.kernel import Scope
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
from tests.support.kernel_auth import generate_bearer_token


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
