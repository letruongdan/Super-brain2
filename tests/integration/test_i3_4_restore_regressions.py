"""I3-4 Round-2 RED regressions for offline/online restore boundaries & journal reconciliation (R04, R06, N4).

Covers offline ``--approval-file`` strict ``read_owner_json_object`` checks (NTFS junctions/symlinks, missing
files, bad ACLs, oversized payloads), ``/v2/operator/restore`` + ``preview_restore`` unsafe backup path rejection
before ``lstat`` (R04), online ``/v2/operator/restore`` ``target=policy`` reconciling ``PARTIALLY_APPLIED``
journals to ``RECOVERY_REQUIRED`` (R06), and ``_daemon_restore._rebind_live`` forwarding ``service_cls`` (N4).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application import maintenance
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.composition import daemon_entry, init_entry, owner_entry
from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DaemonConfig, Ready, ResourceDigest
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.os import OsAdapters, PermissionGuard, PermissionProblem
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, read_raw_http_response

OWNER = "dan"
MACHINE = "r2-box"


def _ssh_signer() -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return priv, SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " r2@devbox",
    )


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw

    def _s(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    ns = APPROVAL_NAMESPACE.encode()
    signed = b"SSHSIG" + _s(ns) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(payload).digest())
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    body = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(ns) + _s(b"") + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    pem = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(armored[i : i + 70] for i in range(0, len(armored), 70))
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode("ascii")
    return base64.b64encode(pem).decode("ascii")


def _init_restore_env(
    base_dir: Path,
) -> tuple[FakeClock, FakeMonotonicClock, OsAdapters, Ed25519PrivateKey, init_entry.InitReport, DaemonConfig, str, str]:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()
    cfg_dir, data_root = base_dir / "cfg", base_dir / "data"
    cfg_dir.mkdir()
    os_.permissions.secure_directory(cfg_dir)
    rep = init_entry.init_store(
        init_entry.InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=OWNER, machine_id=MACHINE, signer=s_enr
        ),
        os_,
    )
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()
    return clock, mono, os_, priv, rep, cfg, ca_pem, cli_token


@contextmanager
def _daemon(cfg: DaemonConfig, os_: OsAdapters, clock: FakeClock, mono: FakeMonotonicClock) -> Iterator[Ready]:
    ready_evt, stop_evt, box, exits = threading.Event(), threading.Event(), dict[str, Ready](), list[int]()

    def _on_ready(ready: Ready, _loop: Any) -> None:
        box["ready"] = ready
        ready_evt.set()

    def _bg() -> None:
        exits.append(
            daemon_entry.serve(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_evt,
                shutdown_grace_s=1.0,
                on_ready=_on_ready,
            )
        )

    thr = threading.Thread(target=_bg, name="i3-4-r2-daemon", daemon=True)
    thr.start()
    try:
        assert ready_evt.wait(timeout=5.0), f"daemon not ready (exits={exits})"
        yield box["ready"]
    finally:
        stop_evt.set()
        thr.join(timeout=5.0)
        assert not thr.is_alive()


def _post_tls(ready: Ready, ca_pem: str, path: str, token: str, body_obj: object) -> tuple[int, dict[str, Any]]:
    host = f"{ready.endpoint.host}:{ready.endpoint.port}"
    body = json.dumps(body_obj).encode("utf-8")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with (
        socket.create_connection((ready.endpoint.host, ready.endpoint.port), timeout=2.0) as raw,
        ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock,
    ):
        sock.settimeout(3.0)
        sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        assert read_raw_http_response(sock, timeout=3.0).startswith(b"HTTP/1.1 200 ")
        hdr = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
            f"X-Store-Id: {ready.identity.store_id}\r\nX-Writer-Epoch: {ready.identity.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {ready.identity.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1")
        sock.sendall(hdr + body)
        resp = read_raw_http_response(sock, timeout=5.0)
    head, sep, data = resp.partition(b"\r\n\r\n")
    assert sep and head.startswith(b"HTTP/1.1 "), resp[:200]
    status = int(head.splitlines()[0].split()[1])
    return status, cast(dict[str, Any], json.loads(data))


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_r04_offline_restore_approval_file_link_acl_missing_and_online_unsafe_backup_paths(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-4-R04: offline --approval-file uses read_owner_json_object; restore rejects unsafe paths pre-lstat."""
    clock, mono, os_, _priv, rep, cfg, ca_pem, cli_token = _init_restore_env(trusted_tmp)
    data_root = cfg.data_root
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        store_bak = create_store_backup(rt.store, os_, clock.now())
    finally:
        rt.close()

    # 1. Junction / symlink --approval-file -> UNSAFE_PATH (not read/parsed through link).
    real_dir, link_dir = trusted_tmp / "real-appr", trusted_tmp / "link-appr"
    real_dir.mkdir()
    os_.permissions.secure_directory(real_dir)
    real_appr = real_dir / "approval.json"
    real_appr.write_bytes(b'{"invalid": true}')
    os_.permissions.secure_file(real_appr)
    _make_dir_link(link_dir, real_dir)

    def _run_off(appr_path: Path, expected_err: ErrorCode) -> None:
        capfd.readouterr()
        rc = owner_entry.main(
            [
                "restore",
                "--offline",
                "--kind",
                "store",
                "--backup",
                str(store_bak),
                "--approval-file",
                str(appr_path),
                "--config",
                str(rep.daemon_config_path),
            ]
        )
        assert rc == 1
        assert capfd.readouterr().err.strip().splitlines()[-1] == expected_err.value

    _run_off(link_dir / "approval.json", ErrorCode.UNSAFE_PATH)

    # 2. Missing --approval-file -> NOT_FOUND (never IO_ERROR).
    _run_off(trusted_tmp / "missing-approval.json", ErrorCode.NOT_FOUND)

    # 3. Oversized (>64 KiB) and insecure ACL --approval-file -> INVALID_INPUT / INSECURE_PERMISSIONS.
    huge_appr = real_dir / "huge.json"
    huge_appr.write_bytes(b'{"pad":"' + b"x" * 70_000 + b'"}')
    os_.permissions.secure_file(huge_appr)
    _run_off(huge_appr, ErrorCode.INVALID_INPUT)

    class _BadAcl:
        def __init__(self, inner: PermissionGuard, target: Path) -> None:
            self._inner, self._target = inner, target.resolve()

        def secure_directory(self, path: Path) -> None:
            self._inner.secure_directory(path)

        def secure_file(self, path: Path) -> None:
            self._inner.secure_file(path)

        def problems(self, dr: Path) -> list[PermissionProblem]:
            return self._inner.problems(dr)

        def object_problems(self, path: Path) -> list[PermissionProblem]:
            if path.resolve() == self._target:
                return [PermissionProblem(path=path, reason="world-readable")]
            return self._inner.object_problems(path)

        def check_ancestors(self, path: Path) -> list[PermissionProblem]:
            return self._inner.check_ancestors(path)

    with monkeypatch.context() as mp:
        mp.setattr(
            owner_entry,
            "os_adapters",
            lambda **kw: OsAdapters(
                paths=os_.paths,
                permissions=_BadAcl(os_.permissions, real_appr),
                publisher=os_.publisher,
                locks=os_.locks,
                clock=clock,
                traits=os_.traits,
                monotonic=mono,
                physical=os_.physical,
            ),
        )
        _run_off(real_appr, ErrorCode.INSECURE_PERMISSIONS)

    # 4. Live HTTPS /v2/operator/restore rejects NUL, .., and (on Win32) UNC/ADS backup paths with no HTTP 500.
    bad_paths: list[str] = [str(store_bak) + "\x00evil", str(trusted_tmp / "sub" / ".." / "bak")]
    if sys.platform == "win32":
        bad_paths.extend(["\\\\127.0.0.1\\c$\\nonexistent-sb2-bak", str(trusted_tmp / "bak:stream")])

    with _daemon(cfg, os_, clock, mono) as ready:
        for bad_raw in bad_paths:
            status, env = _post_tls(
                ready, ca_pem, "/v2/operator/restore", cli_token, {"target": "store", "backup": bad_raw}
            )
            assert status < 500 and env.get("ok") is False, (bad_raw, status, env)
            err = cast(dict[str, Any], env["error"])
            assert err["code"] in {ErrorCode.INVALID_INPUT.value, ErrorCode.UNSAFE_PATH.value}, (bad_raw, err)

    # 5. Direct preview_restore MUST NOT invoke os.lstat / Path.lstat on unsafe backup strings.
    lstat_targets: list[str] = []
    orig_os_lstat, orig_path_lstat = os.lstat, Path.lstat

    def _spy_os_lstat(p: Any, *a: Any, **kw: Any) -> Any:
        lstat_targets.append(os.fspath(p))
        return orig_os_lstat(p, *a, **kw)

    def _spy_path_lstat(self_p: Path, *a: Any, **kw: Any) -> Any:
        lstat_targets.append(os.fspath(self_p))
        return orig_path_lstat(self_p, *a, **kw)

    backend = ensure_maintenance_backend()
    with monkeypatch.context() as mp:
        mp.setattr(os, "lstat", _spy_os_lstat)
        mp.setattr(Path, "lstat", _spy_path_lstat)
        for bad_raw in bad_paths:
            with pytest.raises(BrainError) as prev_err:
                maintenance.preview_restore(
                    data_root,
                    os_,
                    target="store",
                    backup=Path(bad_raw),
                    store_id=rep.store_id,
                    store_migrations=KERNEL_STORE_MIGRATIONS,
                    policy_migrations=KERNEL_POLICY_MIGRATIONS,
                    backend=backend,
                )
            assert prev_err.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH}
    assert not any("127.0.0.1" in t or ":stream" in t or "\x00" in t or ".." in t for t in lstat_targets), lstat_targets


def test_r06_and_n4_online_policy_restore_reconciles_partial_journal_and_forwards_service_cls(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-4-R06 & I3-4-N4: online policy restore reconciles PARTIALLY_APPLIED -> RECOVERY_REQUIRED & reuses cls."""
    clock, mono, os_, priv, rep, cfg, ca_pem, cli_token = _init_restore_env(trusted_tmp)
    data_root, checkout, home = cfg.data_root, trusted_tmp / "repo", trusted_tmp / "home"
    for d in (checkout, home):
        d.mkdir()
        os_.permissions.secure_directory(d)

    u0_a, u0_b = "# Header A\n", "# Header B\n"
    (checkout / "CLAUDE.md").write_bytes(u0_a.encode("utf-8"))
    (checkout / "AGENTS.md").write_bytes(u0_b.encode("utf-8"))

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        bak_policy_gen1 = create_policy_backup(rt.policy, os_, clock.now())
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            PolicyApplyAuthority(rt.policy),
            os_,
            data_root=data_root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        targets = [
            TargetWriteInput(
                checkout, n, m.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "superbrain", m.slice_digest
            )
            for n, u0, lbl in (("AGENTS.md", u0_b, "## Managed B\n"), ("CLAUDE.md", u0_a, "## Managed A\n"))
            for m in (merge_markdown_block(u0, slice_id="superbrain", block_body=lbl, expected_slice_digest=None),)
        ]
        prop = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="r06", resources=[RiskResource(component="c2")], targets=targets
        )
        t_files = prop.to_target_files()
        n_app = rt.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id=prop.proposal_id, risk_level=RiskLevel.HIGH
        )
        m_app = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=1,
            action=ApprovalAction.APPROVE,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=t_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=n_app.nonce,
            expires_at=n_app.expires_at,
        )
        svc.approve_proposal(
            prop.proposal_id, approval=m_app, signer_id=rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
        n_apply = rt.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=prop.proposal_id, risk_level=RiskLevel.HIGH
        )
        m_apply = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=1,
            action=ApprovalAction.APPLY,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=t_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
            nonce=n_apply.nonce,
            expires_at=n_apply.expires_at,
        )
    finally:
        rt.close()

    tracked_instances: list[ReviewApplyService] = []

    class _TrackedReviewApply(ReviewApplyService):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            tracked_instances.append(self)

    monkeypatch.setattr(daemon_entry, "ReviewApplyService", _TrackedReviewApply)

    # Interrupt 2nd target publish during live /v2/operator/proposal/apply so journal stays PARTIALLY_APPLIED in-daemon.
    pub = cast(Any, os_.publisher)
    orig_pub = pub.publish_no_replace
    hits = [0]

    def _fail_second(stg: Path, dst: Path) -> None:
        hits[0] += 1
        if hits[0] == 2:
            raise BrainError(ErrorCode.IO_ERROR, "interrupted before second target")
        orig_pub(stg, dst)

    with _daemon(cfg, os_, clock, mono) as ready:
        assert len(tracked_instances) == 1
        with monkeypatch.context() as mp:
            mp.setattr(pub, "publish_no_replace", _fail_second)
            st_apply, env_apply = _post_tls(
                ready,
                ca_pem,
                "/v2/operator/proposal/apply",
                cli_token,
                {
                    "proposal_id": prop.proposal_id,
                    "approval": {
                        "message": m_apply.to_dict(),
                        "channel": ApprovalChannel.SSH_KEY.value,
                        "signer_id": rep.signer.signer_id,
                        "signature": _ssh_sig_b64(priv, m_apply.canonical_bytes()),
                    },
                },
            )
            assert st_apply < 500 and env_apply.get("ok") is False, env_apply
            assert env_apply["error"]["code"] == ErrorCode.IO_ERROR.value, env_apply

        st_mid, env_mid = _post_tls(
            ready, ca_pem, "/v2/operator/proposal/show", cli_token, {"proposal_id": prop.proposal_id}
        )
        assert st_mid == 200 and env_mid["data"]["proposal"]["status"] == "partially_applied"

        # Preview + execute online /v2/operator/restore target=policy (trust_generation 1 -> 2).
        _, prev_env = _post_tls(
            ready, ca_pem, "/v2/operator/restore", cli_token, {"target": "policy", "backup": str(bak_policy_gen1)}
        )
        assert prev_env.get("ok") is True, prev_env
        ch = cast(dict[str, Any], prev_env["data"]["challenge"])
        msg_res = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=int(ch["trust_generation"]),
            action=ApprovalAction.RESTORE,
            subject_id=str(ch["subject_id"]),
            subject_revision=1,
            resource_digests=(ResourceDigest("backup", str(prev_env["data"]["backup_db_digest"])),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=str(ch["nonce"]),
            expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
        )
        _, exec_env = _post_tls(
            ready,
            ca_pem,
            "/v2/operator/restore",
            cli_token,
            {
                "target": "policy",
                "backup": str(bak_policy_gen1),
                "approval": {
                    "message": msg_res.to_dict(),
                    "channel": ApprovalChannel.SSH_KEY.value,
                    "signer_id": rep.signer.signer_id,
                    "signature": _ssh_sig_b64(priv, msg_res.canonical_bytes()),
                },
            },
        )
        assert exec_env.get("ok") is True and exec_env["data"]["trust_generation"] == 2

        # R06: WITHOUT daemon restart, proposal & active journal transitioned to RECOVERY_REQUIRED!
        st_after, env_after = _post_tls(
            ready, ca_pem, "/v2/operator/proposal/show", cli_token, {"proposal_id": prop.proposal_id}
        )
        assert st_after == 200 and env_after["data"]["proposal"]["status"] == "recovery_required"
        _, cont_env = _post_tls(
            ready, ca_pem, "/v2/operator/proposal/continue", cli_token, {"proposal_id": prop.proposal_id}
        )
        assert cont_env.get("ok") is False
        assert cont_env["error"]["code"] == ErrorCode.REVISION_CONFLICT.value

        # N4: _rebind_live reused wired _TrackedReviewApply class!
        assert len(tracked_instances) >= 2
