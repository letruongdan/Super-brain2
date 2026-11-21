"""I3-2 Round-2 RED regressions for I3-2-R05 and I3-2-R06.

Covers review_cli_entry --approval-file owner-only/size/non-object/unsafe-path guards, LoopbackClient
call_operator HTTP path validation before connect(), cli.main rejecting --approval-file on review list/show,
cross-owner proposal IDOR isolation, Phase-1 validation before Phase-2 ssh-keygen, and daemon_entry
non-masking of SQLite corruption + home_dir wiring.
"""

from __future__ import annotations

import base64
import contextlib
import shutil
import sqlite3
import struct
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.approvals import OperatorService
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli.main import main as brain_main
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import daemon_entry
from superbrain.composition.review_cli_entry import run_review_cli
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DaemonConfig, Endpoint, Principal, Ready
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.os import OsAdapters, PermissionGuard, PermissionProblem
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_client_profile_file, write_owner_only_bytes
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.inc2_transport import (
    FakeMonotonicClock,
    TransportTemplate,
    clone_owner_only_tree,
    create_transport_template,
    make_trusted_test_dir,
)
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential

OWNER_A = "dan"
OWNER_B = "alice"


def _ssh_enrollment(owner_id: str) -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@devbox"
    return SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _dummy_profile(trusted_tmp: Path, os_: OsAdapters) -> Path:
    cfg = trusted_tmp / "cli-cfg"
    cfg.mkdir()
    os_.permissions.secure_directory(cfg)
    ca = cfg / "ca.pem"
    cred = cfg / "cli.credential"
    ep = cfg / "endpoint.json"
    store_id = "0192f3a4-5b6c-7d8e-9f01-000000000001"
    inst_id = "0192f3a4-5b6c-7d8e-9f01-000000000002"
    write_owner_only_bytes(ca, b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    write_owner_only_bytes(cred, ("0192f3a4-5b6c-7d8e-9f01-00000000dead." + "A" * 43 + "\n").encode("ascii"))
    ep_obj = Endpoint(
        version=1, host="127.0.0.1", port=12345, store_id=store_id, writer_epoch=1, instance_id=inst_id
    )
    write_owner_only_bytes(ep, ep_obj.encode_canonical())
    prof, _ = write_client_profile_file(
        cfg / "profile.json",
        endpoint_path=ep,
        expected_store_id=store_id,
        ca_file=ca,
        leaf_cert_sha256="0" * 64,
        credential_file=cred,
    )
    return prof


def test_r05_cli_rejects_approval_file_on_list_show_and_enforces_owner_json_guards(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R05: reject --approval-file on list/show in cli.main and validate via read_owner_json_object."""
    os_ = os_adapters()
    prof = _dummy_profile(trusted_tmp, os_)
    appr = trusted_tmp / "approval.json"
    write_owner_only_bytes(appr, b"{}")

    # cli.main must reject --approval-file on review list / show BEFORE spawning subprocesses.
    def _no_spawn(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("cli.main should reject --approval-file on list/show before spawning subprocess")

    monkeypatch.setattr("subprocess.Popen", _no_spawn)
    for bad_argv in (
        ["review", "list", "--profile", str(prof), "--approval-file", str(appr)],
        ["review", "show", "p1", "--profile", str(prof), "--approval-file", str(appr)],
    ):
        capfd.readouterr()
        assert brain_main(bad_argv) == 2, bad_argv
        assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value
    monkeypatch.undo()

    # Non-object JSON array -> clean INVALID_INPUT exit 1.
    bad_array = trusted_tmp / "array.json"
    write_owner_only_bytes(bad_array, b"[1, 2, 3]")
    capfd.readouterr()
    assert run_review_cli(
        ["review", "approve", "p1", "--profile", str(prof), "--approval-file", str(bad_array)], os_=os_
    ) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value

    # Oversized (> 64 KiB) approval file -> INVALID_INPUT exit 1 (bounded before full read).
    huge = trusted_tmp / "huge.json"
    write_owner_only_bytes(huge, b'{"pad":"' + b"a" * 70000 + b'"}')
    capfd.readouterr()
    assert run_review_cli(
        ["review", "approve", "p1", "--profile", str(prof), "--approval-file", str(huge)], os_=os_
    ) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value

    # Directory passed as --approval-file -> clean BrainError exit 1 (NEVER raw OSError traceback!).
    dir_appr = trusted_tmp / "dir-as-file"
    dir_appr.mkdir()
    os_.permissions.secure_directory(dir_appr)
    capfd.readouterr()
    assert run_review_cli(
        ["review", "approve", "p1", "--profile", str(prof), "--approval-file", str(dir_appr)], os_=os_
    ) == 1
    err_out = capfd.readouterr().err.strip().splitlines()[-1]
    assert err_out in {e.value for e in ErrorCode}

    # Insecure ACL / permissions on --approval-file MUST be refused with INSECURE_PERMISSIONS.
    class _BadApprovalAcl:
        def __init__(self, inner: PermissionGuard, target: Path) -> None:
            self._inner = inner
            self._target = target.resolve()

        def secure_directory(self, path: Path) -> None:
            self._inner.secure_directory(path)

        def secure_file(self, path: Path) -> None:
            self._inner.secure_file(path)

        def problems(self, data_root: Path) -> list[PermissionProblem]:
            return self._inner.problems(data_root)

        def object_problems(self, path: Path) -> list[PermissionProblem]:
            if path.resolve() == self._target:
                return [PermissionProblem(path=path, reason="world-readable")]
            return self._inner.object_problems(path)

        def check_ancestors(self, path: Path) -> list[PermissionProblem]:
            return self._inner.check_ancestors(path)

    bad_perm_os = OsAdapters(
        paths=os_.paths,
        permissions=_BadApprovalAcl(os_.permissions, appr),
        publisher=os_.publisher,
        locks=os_.locks,
        clock=os_.clock,
        traits=os_.traits,
        monotonic=os_.monotonic,
        physical=os_.physical,
    )
    capfd.readouterr()
    assert run_review_cli(
        ["review", "approve", "p1", "--profile", str(prof), "--approval-file", str(appr)], os_=bad_perm_os
    ) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INSECURE_PERMISSIONS.value


def test_r05_loopback_client_call_operator_rejects_injected_paths_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I3-2-R05: call_operator validates request-line path strictly BEFORE calling connect()."""
    client = LoopbackClient()
    sid = "0192f3a4-5b6c-7d8e-9f01-000000000001"
    iid = "0192f3a4-5b6c-7d8e-9f01-000000000002"
    target = LoopbackTarget(
        endpoint=Endpoint(version=1, host="127.0.0.1", port=9999, store_id=sid, writer_epoch=1, instance_id=iid),
        expected_store_id=sid,
        ca_pem="-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        leaf_cert_sha256="0" * 64,
    )
    monkeypatch.setattr(client, "connect", lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("connect called!")))

    for bad_path in (
        "/v2/operator/proposal/list HTTP/1.1\r\nX-Injected: 1",
        "/v2/operator/proposal/list\n",
        "/v2/operator/proposal/list?foo=1",
        "/v2/tool_call",
        "v2/operator/proposal/list",
    ):
        with pytest.raises(BrainError) as exc:
            client.call_operator(target, bad_path, b"{}", "tok")
        assert exc.value.code is ErrorCode.INVALID_INPUT, bad_path


def test_r06_operator_proposal_owner_isolation_and_phase1_validation(trusted_tmp: Path) -> None:
    """I3-2-R06: cross-owner proposals hidden/NOT_FOUND, and Phase-1 checks run BEFORE Phase-2 ssh-keygen."""
    clock = FakeClock(datetime(2026, 11, 19, 10, 30, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "data"
    checkout = trusted_tmp / "checkout"
    checkout.mkdir()
    os_.permissions.secure_directory(checkout)
    rt = open_kernel_job_runtime(root, os_, role="i3-2-r2-op")
    try:
        rt.policy.enroll_first_signer(_ssh_enrollment(OWNER_A))
        proposals = StoreProposalAdapter(rt.store, os_)
        svc = ReviewApplyService(
            proposals, PolicyApplyAuthority(rt.policy), os_, data_root=root, config_merger=SharedConfigMergerAdapter()
        )
        prop_dan = svc.create_proposal(
            owner_id=OWNER_A,
            kind="bootstrap",
            reason="dan only",
            resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(checkout, "A.md", b"# A\n", ManagedFormat.RAW, "r1"),),
        )
        verifier_calls = [0]

        class _SpyVerifier:
            def verify(self, *_a: Any, **_kw: Any) -> Any:
                verifier_calls[0] += 1
                raise AssertionError("Phase 2 verifier must NOT run for Phase-1 invalid proposal/owner/action")

        op = OperatorService(rt.policy, ssh_verifier=lambda: _SpyVerifier(), review_apply=svc)
        p_alice = Principal(principal_id="p-alice", owner_id=OWNER_B, harness_id=CLI_HARNESS_ID, machine_id="m-b")

        listed = op.prepare_call("/v2/operator/proposal/list", p_alice, {}, token=None)
        assert listed.immediate == {"proposals": []}, "cross-owner MUST NOT see other owner's proposals"

        with pytest.raises(BrainError) as show_exc:
            op.prepare_call("/v2/operator/proposal/show", p_alice, {"proposal_id": prop_dan.proposal_id}, token=None)
        assert show_exc.value.code is ErrorCode.NOT_FOUND

        # Build valid signed-shape approval body for Phase-1 failure tests.
        p_dan = Principal(principal_id="p-dan", owner_id=OWNER_A, harness_id=CLI_HARNESS_ID, machine_id="m-a")
        issued = rt.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=prop_dan.proposal_id, risk_level=prop_dan.risk_level
        )
        apply_msg = ApprovalMessage(
            store_id=rt.store.store_id,
            owner_id=OWNER_A,
            trust_generation=issued.trust_generation,
            action=ApprovalAction.APPLY,
            subject_id=prop_dan.proposal_id,
            subject_revision=prop_dan.subject_revision,
            resource_digests=prop_dan.resource_digests,
            target_files=prop_dan.to_target_files(),
            risk_level=issued.risk_level,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
            nonce=issued.nonce,
            expires_at=issued.expires_at,
        )
        raw_approval: dict[str, Any] = {
            "channel": "ssh_key",
            "message": apply_msg.to_dict(),
            "signature": base64.b64encode(b"sig").decode(),
        }

        # 1. Endpoint action mismatch (/approve with APPLY message) -> Phase 1 INVALID_INPUT, 0 verifier calls.
        with pytest.raises(BrainError) as act_exc:
            op.prepare_call(
                "/v2/operator/proposal/approve",
                p_dan,
                {"proposal_id": prop_dan.proposal_id, "approval": raw_approval},
                token=None,
            )
        assert act_exc.value.code is ErrorCode.INVALID_INPUT

        # 2. Missing proposal_id -> Phase 1 NOT_FOUND, 0 verifier calls.
        with pytest.raises(BrainError) as miss_exc:
            op.prepare_call(
                "/v2/operator/proposal/apply",
                p_dan,
                {"proposal_id": "nonexistent-prop", "approval": raw_approval},
                token=None,
            )
        assert miss_exc.value.code is ErrorCode.NOT_FOUND

        # 3. Cross-owner mutation -> Phase 1 NOT_FOUND/UNAUTHENTICATED, 0 verifier calls.
        with pytest.raises(BrainError):
            op.prepare_call(
                "/v2/operator/proposal/apply",
                p_alice,
                {"proposal_id": prop_dan.proposal_id, "approval": raw_approval},
                token=None,
            )
        assert verifier_calls[0] == 0
    finally:
        rt.close()


@pytest.fixture(scope="module")
def corrupt_v5_template() -> Iterator[tuple[TransportTemplate, SeededCredential]]:
    template = create_transport_template("i3-2-r06-corrupt-tpl")
    try:
        adapters = os_adapters(clock=FakeClock(template.base_time))
        rt = reopen_kernel_job_runtime(template.root, template.store_id, adapters)
        try:
            cli = seed_principal_and_credential(
                rt.policy, owner_id=OWNER_A, harness_id=CLI_HARNESS_ID, machine_id="m-c"
            )
        finally:
            rt.close()
        with contextlib.closing(sqlite3.connect(template.root / "store" / "brain.db")) as conn:
            conn.execute("DROP TABLE p_proposals_proposals")
            conn.commit()
        yield template, cli
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


def test_r06_daemon_entry_does_not_mask_corrupt_v5_proposals_and_wires_home_dir(
    corrupt_v5_template: tuple[TransportTemplate, SeededCredential],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I3-2-R06: daemon_entry wires home_dir and does not mask missing/corrupt v5 table as CAPABILITY_UNAVAILABLE."""
    seen_home_dirs: list[Path | None] = []
    orig_cls = ReviewApplyService

    def _spy_svc(*args: Any, **kwargs: Any) -> Any:
        seen_home_dirs.append(kwargs.get("home_dir"))
        return orig_cls(*args, **kwargs)

    monkeypatch.setattr(daemon_entry, "ReviewApplyService", _spy_svc)
    template, cli = corrupt_v5_template
    case_dir = make_trusted_test_dir("i3-2-r06-daemon")
    try:
        data_root = case_dir / "data"
        clone_owner_only_tree(template.root, data_root)
        cfg = DaemonConfig(
            version=1,
            data_root=data_root,
            expected_store_id=template.store_id,
            cert_path=template.tls.cert_path,
            key_path=template.tls.key_path,
        )
        clock = FakeClock(template.base_time)
        mono = FakeMonotonicClock(1_000_000_000)
        adapters = os_adapters(clock=clock, monotonic=mono)
        ready_evt, stop_evt = threading.Event(), threading.Event()
        ready_box: list[Ready] = []

        def _on_ready(ready: Ready, _loop: object) -> None:
            ready_box.append(ready)
            ready_evt.set()

        thr = threading.Thread(
            target=daemon_entry.serve,
            kwargs={
                "config": cfg,
                "os_": adapters,
                "clock": clock,
                "monotonic_clock": mono,
                "stop_event": stop_evt,
                "shutdown_grace_s": 1.0,
                "on_ready": _on_ready,
            },
            daemon=True,
        )
        thr.start()
        try:
            assert ready_evt.wait(timeout=5.0) and ready_box
            target = LoopbackTarget(
                endpoint=ready_box[0].endpoint,
                expected_store_id=template.store_id,
                ca_pem=template.tls.ca_cert_path.read_text(encoding="utf-8"),
                leaf_cert_sha256=template.tls.leaf_cert_sha256,
            )
            resp = LoopbackClient(monotonic_ns=mono.monotonic_ns).call_operator(
                target, "/v2/operator/proposal/list", b"{}", cli.token
            )
            assert resp.get("ok") is False
            err = resp.get("error")
            assert isinstance(err, dict)
            assert err.get("code") in {ErrorCode.IO_ERROR.value, ErrorCode.INTEGRITY_FAILURE.value}
            assert seen_home_dirs and seen_home_dirs[0] == Path.home()
        finally:
            stop_evt.set()
            thr.join(timeout=5.0)
            assert not thr.is_alive()
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
