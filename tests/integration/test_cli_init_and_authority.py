"""I3-1 oracle: ``brain init``, ``brain init --reset-signers`` and the ``user:cli``-only ``/v2/operator/*`` surface.

Requirement sources: spec rev 22 §5.1 (``user:cli`` system actor, ``identity_mismatch``), §5.4 (policy intent first,
reconciled exactly once), §5.5/§5.9 (writer lock, owner-only data root), §11.3 (first signer TOFU at ``brain init``;
``--reset-signers`` offline under the writer lock, invalidates pending approvals, TOFU again), §14.2 CLI; plan
"Mặt lệnh CLI" (offline ``--config <abs>`` via ``composition.init_entry``; harness bearers get ``IDENTITY_MISMATCH``
on every ``/v2/operator/*``) and I3-1 Step 2; §20 cases 12, 18, 21, 34.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.cli.main import main as brain_main
from superbrain.composition.init_entry import InitReport, InitRequest, init_store, reset_signers
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core.errors import SAFE_WIRE_MESSAGES, BrainError, ErrorCode
from superbrain.core.kernel import ResourceDigest
from superbrain.ports.os import OsAdapters
from superbrain.storage.schema import SchemaInfo, read_schema_info
from tests.support.clock import FakeClock
from tests.support.crash import paused_child
from tests.support.fs import digest_data_root, digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import (
    TransportHarness,
    TransportTemplate,
    create_transport_template,
    open_test_loopback_transport,
)
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential

OWNER = "dan"
MACHINE = "devbox-1"
OPERATOR_PATHS = (
    "/v2/operator/signer/list",
    "/v2/operator/signer/enroll",
    "/v2/operator/signer/revoke",
    "/v2/operator/credential/revoke",
    "/v2/operator/policy/set",
    "/v2/operator/workspace/link",
    "/v2/operator/backup",
    "/v2/operator/job/cancel",
)


def _ssh_enrollment() -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + len(raw).to_bytes(4, "big") + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " owner@devbox-1"
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


@pytest.fixture
def init_os() -> OsAdapters:
    return os_adapters(clock=FakeClock(datetime.now(UTC).replace(microsecond=0)))


@pytest.fixture
def config_dir(trusted_tmp: Path, init_os: OsAdapters) -> Path:
    path = trusted_tmp / "config"
    path.mkdir()
    init_os.permissions.secure_directory(path)
    return path


def _init(trusted_tmp: Path, config_dir: Path, os_: OsAdapters) -> tuple[InitRequest, InitReport]:
    request = InitRequest(
        data_root=trusted_tmp / "data",
        config_dir=config_dir,
        owner_id=OWNER,
        machine_id=MACHINE,
        signer=_ssh_enrollment(),
    )
    return request, init_store(request, os_)


def _signer_reset_rows(data_root: Path, store_id: str, os_: OsAdapters) -> int:
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        assert rt.store.reconcile_policy() == 0
        with rt.store.transaction() as txn:
            row = txn.db.execute("SELECT count(*) FROM ledger WHERE kind = 'policy.signer_reset'").fetchone()
    finally:
        rt.close()
    assert row is not None
    return int(row[0])


# --- CLI argv routing ----------------------------------------------------------------------------------------------


def test_brain_init_routes_to_the_isolated_init_entry(trusted_tmp: Path, capfd: pytest.CaptureFixture[str]) -> None:
    assert brain_main(["init", "--config", "relative/init.json"]) == 2
    missing = trusted_tmp / "missing-init.json"
    for argv in (["init", "--config", str(missing)], ["init", "--reset-signers", "--config", str(missing)]):
        capfd.readouterr()
        assert brain_main(argv) == 1, argv
        assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value, argv


def test_main_with_explicit_argv_never_replaces_the_calling_process(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``main(argv=[...])`` is a library call: it returns an int and never ``os.execv``-s (POSIX sep)."""
    missing = trusted_tmp / "missing-init.json"
    execv_calls: list[str] = []
    pid = os.getpid()
    capfd.readouterr()
    with monkeypatch.context() as patched:
        patched.setattr(os, "sep", "/")
        patched.setattr(os, "execv", lambda path, *_a: execv_calls.append(str(path)))
        rc = brain_main(["init", "--config", str(missing)])
    assert execv_calls == []
    assert rc == 1 and os.getpid() == pid
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value


@pytest.mark.skipif(os.sep == "\\", reason="POSIX CLI entry replaces the process via os.execv")
def test_cli_subprocess_on_posix_keeps_execv_replacement_semantics(trusted_tmp: Path) -> None:
    missing = trusted_tmp / "missing-init.json"
    cmd = [sys.executable, "-I", "-m", "superbrain.cli.main", "init", "--config", str(missing)]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
    assert res.returncode == 1
    assert res.stderr.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value

# --- brain init (TOFU) ---------------------------------------------------------------------------------------------


def test_brain_init_bootstraps_store_tls_cli_principal_and_tofu_signer(
    trusted_tmp: Path, config_dir: Path, init_os: OsAdapters
) -> None:
    request, report = _init(trusted_tmp, config_dir, init_os)
    data_root = request.data_root
    assert read_schema_info(data_root / "policy" / "policy.db") == SchemaInfo(4, 4, report.store_id)
    assert read_schema_info(data_root / "store" / "brain.db") == SchemaInfo(5, 5, report.store_id)

    cfg = read_daemon_config(report.daemon_config_path, init_os)
    assert (cfg.data_root, cfg.expected_store_id) == (data_root, report.store_id)
    assert cfg.cert_path.is_file() and cfg.key_path.is_file()
    assert init_os.permissions.problems(data_root) == []
    assert init_os.permissions.problems(config_dir) == []

    token = report.cli_credential_path.read_text(encoding="utf-8").strip()
    assert report.signer.tofu is True and report.signer.key_digest == request.signer.key_digest
    rt = reopen_kernel_job_runtime(data_root, report.store_id, init_os)
    try:
        principal = rt.policy.resolve_credential(token)
        assert (principal.owner_id, principal.harness_id, principal.machine_id) == (OWNER, CLI_HARNESS_ID, MACHINE)
        signers = rt.policy.active_signers()
        assert [s.signer_id for s in signers] == [report.signer.signer_id]
        assert signers[0].tofu is True and signers[0].channel is ApprovalChannel.SSH_KEY
        assert rt.policy.terminal_channel_eligible(machine_id=MACHINE) is False
        assert rt.store.reconcile_policy() == 0, "init must reconcile its policy intents exactly once"
        intents = len(rt.policy.intents())
        with rt.store.transaction() as txn:
            applied = txn.db.execute("SELECT count(*) FROM applied_intents").fetchone()
        assert applied is not None and applied[0] == intents
    finally:
        rt.close()


def test_brain_init_refuses_an_existing_store_without_touching_bytes(
    trusted_tmp: Path, config_dir: Path, init_os: OsAdapters
) -> None:
    request, _ = _init(trusted_tmp, config_dir, init_os)
    before_data, before_config = digest_tree(request.data_root), digest_tree(config_dir)
    again = InitRequest(
        data_root=request.data_root,
        config_dir=config_dir,
        owner_id=OWNER,
        machine_id=MACHINE,
        signer=_ssh_enrollment(),
    )
    with pytest.raises(BrainError) as exc:
        init_store(again, init_os)
    assert exc.value.code is ErrorCode.INVALID_INPUT
    assert digest_tree(request.data_root) == before_data
    assert digest_tree(config_dir) == before_config


# --- brain init --reset-signers -------------------------------------------------------------------------------------


def test_reset_signers_offline_replaces_signers_and_fences_old_approvals(
    trusted_tmp: Path, config_dir: Path, init_os: OsAdapters
) -> None:
    request, report = _init(trusted_tmp, config_dir, init_os)
    rt = reopen_kernel_job_runtime(request.data_root, report.store_id, init_os)
    try:
        old_generation = rt.policy.trust_generation()
        issued = rt.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id="proposal-A", risk_level=RiskLevel.HIGH
        )
        pending = ApprovalMessage(
            store_id=report.store_id,
            owner_id=OWNER,
            trust_generation=issued.trust_generation,
            action=ApprovalAction.APPROVE,
            subject_id="proposal-A",
            subject_revision=1,
            resource_digests=(ResourceDigest("CLAUDE.md", "sha256:" + "a" * 64),),
            target_files=(),
            risk_level=issued.risk_level,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=issued.nonce,
            expires_at=issued.expires_at,
        )
    finally:
        rt.close()

    replacement = _ssh_enrollment()
    result = reset_signers(report.daemon_config_path, replacement, init_os)
    assert result.store_id == report.store_id
    assert result.trust_generation > old_generation
    assert result.signer.tofu is True and result.signer.key_digest == replacement.key_digest

    rt = reopen_kernel_job_runtime(request.data_root, report.store_id, init_os)
    try:
        assert rt.policy.trust_generation() == result.trust_generation
        assert rt.lease.state().trust_generation_hwm == result.trust_generation
        assert [s.signer_id for s in rt.policy.active_signers()] == [result.signer.signer_id]
        assert rt.policy.signer_reset_recorded() is True
        for signer_id in (report.signer.signer_id, result.signer.signer_id):
            with pytest.raises(BrainError) as exc:
                rt.policy.consume_approval(pending, signer_id=signer_id, channel=ApprovalChannel.SSH_KEY)
            assert exc.value.code is ErrorCode.UNAUTHENTICATED
    finally:
        rt.close()
    assert _signer_reset_rows(request.data_root, report.store_id, init_os) == 1


def test_reset_signers_refuses_while_another_writer_holds_the_lock(
    trusted_tmp: Path, config_dir: Path, init_os: OsAdapters
) -> None:
    request, report = _init(trusted_tmp, config_dir, init_os)
    with paused_child("acquire_writer_and_pause", "writer.held", request.data_root):
        before = digest_data_root(request.data_root)
        with pytest.raises(BrainError) as exc:
            reset_signers(report.daemon_config_path, _ssh_enrollment(), init_os)
        assert exc.value.code is ErrorCode.WRITER_HELD
        assert digest_data_root(request.data_root) == before
    rt = reopen_kernel_job_runtime(request.data_root, report.store_id, init_os)
    try:
        assert [s.signer_id for s in rt.policy.active_signers()] == [report.signer.signer_id]
        assert rt.policy.signer_reset_recorded() is False
    finally:
        rt.close()


# --- /v2/operator/* is user:cli only ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def operator_template() -> Iterator[tuple[TransportTemplate, SeededCredential]]:
    template = create_transport_template("i3-1-operator-tpl")
    try:
        adapters = os_adapters(clock=FakeClock(template.base_time))
        rt = reopen_kernel_job_runtime(template.root, template.store_id, adapters)
        try:
            cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="m-1")
        finally:
            rt.close()
        yield template, cli
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


def _operator_call(h: TransportHarness, path: str, token: str, body: bytes = b"{}") -> dict[str, object]:
    identity = h.ready.identity
    host = f"127.0.0.1:{h.ready.endpoint.port}"
    with h.open_raw_tls_socket() as sock:
        h.send_raw_http(sock, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        request = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"X-Store-Id: {identity.store_id}\r\nX-Writer-Epoch: {identity.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {identity.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1") + body
        response = h.send_raw_http(sock, request)
    head, _, payload = response.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 "), response[:200]
    envelope = json.loads(payload)
    assert isinstance(envelope, dict)
    return envelope


def _error_code(envelope: dict[str, object]) -> str | None:
    if envelope.get("ok") is True:
        return None
    error = envelope.get("error")
    assert isinstance(error, dict)
    message = error.get("message")
    assert isinstance(message, str) and message in SAFE_WIRE_MESSAGES, error
    code = error.get("code")
    assert isinstance(code, str)
    return code


def test_operator_endpoints_refuse_harness_bearers_and_admit_user_cli(
    operator_template: tuple[TransportTemplate, SeededCredential],
) -> None:
    template, cli = operator_template
    with open_test_loopback_transport(template, name="i3-1-operator") as h:
        before = h.ledger_sequence()
        for path in OPERATOR_PATHS:
            assert _error_code(_operator_call(h, path, template.cred.token)) == ErrorCode.IDENTITY_MISMATCH.value, path
        assert h.ledger_sequence() == before, "a refused harness call must not write anything"
        bogus = "0192f3a4-5b6c-7d8e-9f01-00000000dead." + "A" * 43
        assert _error_code(_operator_call(h, OPERATOR_PATHS[0], bogus)) == ErrorCode.UNAUTHENTICATED.value
        for path in OPERATOR_PATHS:
            code = _error_code(_operator_call(h, path, cli.token))
            assert code not in {ErrorCode.IDENTITY_MISMATCH.value, ErrorCode.UNAUTHENTICATED.value}, (path, code)
