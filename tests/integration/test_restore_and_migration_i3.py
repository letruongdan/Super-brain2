"""I3-4 oracle: 40th wheel crashpoint, Case 93 restore, online/offline ``brain restore``, and I2 ``(4,3)`` fence.

Requirement sources: spec rev 22 §5.7-§5.8, §11.2-§11.3, §14.2, §20 cases 21, 26, 32, 70, 93, 101-102; plan I3-4.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.application.journal_recovery import reconcile_and_classify_journals
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition import daemon_entry, init_entry
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.errors import SAFE_WIRE_MESSAGES, BrainError, ErrorCode
from superbrain.core.kernel import DaemonConfig, Ready, UsageReservation
from superbrain.core.proposals import ManagedFormat, ProposalStatus
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import migrate_database
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import admit_existing_pair
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.crash_cases import I3_4_CRASH_CASES, KernelCrashContext
from tests.support.fs import digest_tree
from tests.support.inc2_cli import (
    clean_installed_subprocess_env,
    get_shared_t7_transport_template,
    run_installed_command,
)
from tests.support.inc2_fixture import (
    InstalledEnv,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import FakeMonotonicClock, post_tls_http_json
from tests.support.inc3_i34_crash_cases import I34_CHILD, I34CrashCase, prepare_i34_seed, run_i34_crash_case
from tests.support.kernel_auth import seed_principal_and_credential
from tests.support.seed_clone import restore_migration_fixture_clone

OWNER = "dan"
MACHINE = "devbox-i34"


def _ssh_signer_key() -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " owner@i34"
    return priv, SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw

    def _s(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    ns = b"ensemble-brain-approval"
    signed = b"SSHSIG" + _s(ns) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(payload).digest())
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    body = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(ns) + _s(b"") + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
    pem = ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode("ascii")
    return base64.b64encode(pem).decode("ascii")


def _init_fixture(
    base_dir: Path,
) -> tuple[
    FakeClock, FakeMonotonicClock, OsAdapters, Ed25519PrivateKey,
    init_entry.InitReport, DaemonConfig, str, str, Path, Path, int

]:
    return restore_migration_fixture_clone(base_dir, _ssh_signer_key, OWNER, MACHINE)


def _restore_msg(store_id: str, ch: dict[str, Any], db_digest: str, fallback_gen: int | None = None) -> ApprovalMessage:
    return ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=int(cast(int | str, ch.get("trust_generation", fallback_gen))),
        action=ApprovalAction.RESTORE,
        subject_id=str(ch["subject_id"]),
        subject_revision=1,
        resource_digests=(ResourceDigest("backup", db_digest),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=str(ch["nonce"]),
        expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
    )


@contextmanager
def _daemon(cfg: DaemonConfig, os_: Any, clock: FakeClock, mono: FakeMonotonicClock) -> Iterator[Ready]:
    ready_evt, stop_evt, box, exits = threading.Event(), threading.Event(), dict[str, Ready](), list[int]()

    def _on_ready(r: Ready, _l: Any) -> None:
        box["ready"] = r
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

    thr = threading.Thread(target=_bg, name="i3-4-daemon", daemon=True)
    thr.start()
    try:
        assert ready_evt.wait(timeout=5.0), f"daemon did not become ready (exits={exits})"
        yield box["ready"]
    finally:
        stop_evt.set()
        thr.join(timeout=5.0)
        assert not thr.is_alive()


def _post_tls(ready: Ready, ca_pem: str, path: str, token: str, payload: bytes | object) -> dict[str, Any]:
    return post_tls_http_json(ready, ca_pem, path, token, payload)[1]


@pytest.mark.parametrize("case", I3_4_CRASH_CASES, ids=lambda c: c.node_id)
def test_installed_i34_wheel_crash_recovery_after_swap_before_effect_drain(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: I34CrashCase
) -> None:
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    ctx = KernelCrashContext(
        env=inc2_installed_env, template=get_shared_t7_transport_template(), case_dir=trusted_tmp / "case", cwd=cwd
    )
    run_i34_crash_case(ctx, case)

    # Omission detector: disabling the crashpoint prevents crashpoint firing (exit 0 without CRASHPOINT_HIT).
    omit_dir = trusted_tmp / "omit"
    omit_dir.mkdir()
    seed = prepare_i34_seed(
        KernelCrashContext(
            env=inc2_installed_env, template=get_shared_t7_transport_template(), case_dir=omit_dir, cwd=cwd
        )
    )
    cp = case.crashpoint
    env = clean_installed_subprocess_env({"SUPERBRAIN_CRASHPOINT": cp, "SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST": cp})
    cmd = [
        str(inc2_installed_env.venv_python),
        "-I",
        str(I34_CHILD),
        case.operation,
        str(seed.config_path),
        str(seed.payload_path),
    ]
    res = subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30.0
    )
    assert res.returncode == 0 and "CRASHPOINT_HIT" not in res.stderr, (res.returncode, res.stderr)


def test_case_93_restore_interrupted_apply_journal_after_ended_grant_never_revives_write(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime(2026, 10, 30, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root, checkout, home = trusted_tmp / "c93-data", trusted_tmp / "checkout", trusted_tmp / "home"
    for d in (checkout, home):
        d.mkdir()
        os_.permissions.secure_directory(d)
    u0_a, u0_b = "# Header A\n", "# Header B\n"
    f_a, f_b = checkout / "CLAUDE.md", checkout / "AGENTS.md"
    f_a.write_bytes(u0_a.encode("utf-8"))
    f_b.write_bytes(u0_b.encode("utf-8"))

    rt = open_kernel_job_runtime(root, os_, role="c93-restore")
    store_id = rt.store.store_id
    _, s_enr = _ssh_signer_key()
    signer = rt.policy.enroll_first_signer(s_enr)
    adapter = StoreProposalAdapter(rt.store, os_)
    auth = PolicyApplyAuthority(rt.policy)
    svc = ReviewApplyService(
        adapter, auth, os_, data_root=root, home_dir=home, config_merger=SharedConfigMergerAdapter()
    )

    targets = [
        TargetWriteInput(
            checkout, n, m.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "superbrain", m.slice_digest
        )
        for n, u0, lbl in (("CLAUDE.md", u0_a, "## Managed A\n"), ("AGENTS.md", u0_b, "## Managed B\n"))
        for m in (merge_markdown_block(u0, slice_id="superbrain", block_body=lbl, expected_slice_digest=None),)
    ]
    prop = svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="case93", resources=[RiskResource(component="c2")], targets=targets
    )
    t_files = prop.to_target_files()
    for act, scope in (
        (ApprovalAction.APPROVE, RecoveryScope.NONE),
        (ApprovalAction.APPLY, RecoveryScope.CONTINUE_OR_ROLLBACK),
    ):
        n = rt.policy.issue_nonce(action=act, subject_id=prop.proposal_id, risk_level=RiskLevel.HIGH)
        m = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=rt.policy.trust_generation(),
            action=act,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=t_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=scope,
            nonce=n.nonce,
            expires_at=n.expires_at,
        )
        if act is ApprovalAction.APPROVE:
            svc.approve_proposal(
                prop.proposal_id, approval=m, signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY
            )
        else:
            msg_apply = m

    pub = cast(NoReplacePublisher, os_.publisher)
    orig_pub = pub.publish_no_replace
    hits = [0]

    def _fail_second(stg: Path, dst: Path) -> None:
        hits[0] += 1
        if hits[0] == 2:
            raise RuntimeError("interrupt before AGENTS.md publish")
        orig_pub(stg, dst)

    with monkeypatch.context() as mp:
        mp.setattr(pub, "publish_no_replace", _fail_second)
        with pytest.raises(RuntimeError, match="interrupt"):
            svc.apply_proposal(
                prop.proposal_id, approval=msg_apply, signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY
            )

    bak_mid = create_store_backup(rt.store, os_, clock.now())
    j_cur = adapter.list_incomplete_journals()[0]
    svc.continue_interrupted_journal(j_cur.journal_id)
    grant = rt.policy.recovery_grant(j_cur.grant_id)
    assert grant.state == "ended"
    rt.close()

    f_b.write_bytes(u0_b.encode("utf-8"))
    clock.advance(timedelta(minutes=5))
    with maintenance_lease(root) as (dr, lease):
        pol = PolicyStore.open(dr, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(dr, lease, os_, bak_mid, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        from superbrain.storage.restore import read_restore_epoch

        assert read_restore_epoch(DataRoot.at(root), schema_version=5, os_=os_) >= 1
        assert rt2.policy.recovery_grant(grant.grant_id).state == "ended"
        reconcile_and_classify_journals(
            StoreProposalAdapter(rt2.store, os_),
            PolicyApplyAuthority(rt2.policy),
            os_,
            data_root=root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        assert f_b.read_bytes() == u0_b.encode("utf-8")
        assert rt2.policy.recovery_grant(grant.grant_id).state == "ended"
        assert (
            StoreProposalAdapter(rt2.store, os_).get_proposal(prop.proposal_id).status
            is ProposalStatus.RECOVERY_REQUIRED
        )
    finally:
        rt2.close()


def test_online_operator_restore_route_auth_preview_and_immediate_effect(trusted_tmp: Path) -> None:
    from superbrain.core.canonical import digest_bytes

    assert "/v2/operator/restore" in OPERATOR_PATHS
    clock, mono, os_, priv, rep, cfg, ca_pem, cli_token, *_ = _init_fixture(trusted_tmp)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        harness = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
        policy_bak = create_policy_backup(rt.policy, os_, clock.now())
        q_dig = digest_bytes(b"post-bak-quarantine")
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": q_dig})
    finally:
        rt.close()

    with _daemon(cfg, os_, clock, mono) as ready:
        denied = _post_tls(ready, ca_pem, "/v2/operator/restore", harness.token, b"{not-json")
        assert denied["ok"] is False and denied["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value
        assert denied["error"]["message"] in SAFE_WIRE_MESSAGES

        preview = _post_tls(
            ready, ca_pem, "/v2/operator/restore", cli_token, {"target": "policy", "backup": str(policy_bak)}
        )
        assert preview["ok"] is True, preview
        pdata = preview["data"]
        assert q_dig in pdata["diff"]["removed_quarantines"]
        ch = pdata["challenge"]
        assert ch["action"] == ApprovalAction.RESTORE.value and ch["risk_level"] == RiskLevel.HIGH.value

        manifest = verify_backup(
            policy_bak,
            expected_kind="policy",
            expected_store_id=rep.store_id,
            migrations=KERNEL_POLICY_MIGRATIONS,
            os_=os_,
        )
        base = {"target": "policy", "backup": str(policy_bak)}
        msg = _restore_msg(str(ch["store_id"]), ch, manifest.db_digest)
        term_ap = {"message": msg.to_dict(), "channel": ApprovalChannel.TERMINAL.value}
        term = _post_tls(ready, ca_pem, "/v2/operator/restore", cli_token, {**base, "approval": term_ap})
        assert term["ok"] is False and term["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        ssh_ap = {
            "message": msg.to_dict(),
            "channel": ApprovalChannel.SSH_KEY.value,
            "signer_id": rep.signer.signer_id,
            "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
        }
        signed_body = {**base, "approval": ssh_ap}
        done = _post_tls(ready, ca_pem, "/v2/operator/restore", cli_token, signed_body)
        assert done["ok"] is True and int(done["data"]["trust_generation"]) > int(ch["trust_generation"])
        post_ep = read_client_endpoint(DataRoot.at(cfg.data_root).endpoint_path, os_)
        assert post_ep.writer_epoch == int(done["data"]["new_epoch"]) > ready.identity.writer_epoch
        post_ready = replace(ready, endpoint=post_ep, identity=post_ep.identity)
        stale = _post_tls(ready, ca_pem, "/v2/operator/restore", cli_token, signed_body)
        assert stale["ok"] is False and stale["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value
        replay = _post_tls(post_ready, ca_pem, "/v2/operator/restore", cli_token, signed_body)
        assert replay["ok"] is False and replay["error"]["code"] in {
            ErrorCode.UNAUTHENTICATED.value,
            ErrorCode.REVISION_CONFLICT.value,
        }

    # Immediate post-swap accounting lock blocks reserve_invocation without any extra step!
    rt_after = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        assert len(rt_after.policy.list_accounting_locks(state="locked")) >= 1
        svc, ks = kernel_job_service(rt_after, clock)
        enqueue_job(svc, ks, owner_id=OWNER)
        lease = svc.lease_next(rt_after.lease.epoch, clock.now())
        assert lease is not None
        svc.start(lease)
        with pytest.raises(BrainError) as err_lk:
            svc.reserve_invocation(lease, UsageReservation(max_amount="0.5"))
        assert err_lk.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    finally:
        rt_after.close()


def test_offline_restore_cli_refuses_writer_held_and_recovers_missing_or_corrupt_live_dbs(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    clock, mono, os_, priv, rep, cfg, _, _, store_bak, policy_bak, gen1 = _init_fixture(trusted_tmp)
    cwd = trusted_tmp / "cli-cwd"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)
    layout = DataRoot.at(cfg.data_root)

    def _sign_from_preview(out_json: bytes, out_path: Path, db_digest: str, fallback_gen: int | None = None) -> Path:
        data = json.loads(out_json)["data"]
        ch = data.get("challenge", data)
        msg = _restore_msg(rep.store_id, ch, db_digest, fallback_gen)
        out_path.write_text(
            json.dumps(
                {
                    "message": msg.to_dict(),
                    "channel": ApprovalChannel.SSH_KEY.value,
                    "signer_id": rep.signer.signer_id,
                    "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                }
            ),
            encoding="utf-8",
        )
        os_.permissions.secure_file(out_path)
        return out_path

    def _wheel_restore(kind: str, backup: Path, *flags: str) -> Any:
        args = (
            "restore",
            "--offline",
            "--kind",
            kind,
            "--backup",
            str(backup),
            *flags,
            "--config",
            str(rep.daemon_config_path),
        )
        return run_installed_command(inc2_installed_env, "brain", args, cwd=cwd)

    # 1) WriterLease held by daemon -> brain restore --offline refuses WRITER_HELD.
    with _daemon(cfg, os_, clock, mono):
        res_held = _wheel_restore("store", store_bak, "--preview")
        assert res_held.returncode == 1 and ErrorCode.WRITER_HELD.value in res_held.stderr.decode()

    # 2) Corrupt live store/brain.db -> preview + restore via installed wheel recovers cleanly.
    layout.store_db.write_bytes(b"corrupt-store-db-bytes")
    prev_s = _wheel_restore("store", store_bak, "--preview")
    assert prev_s.returncode == 0, prev_s.stderr
    s_man = verify_backup(
        store_bak,
        expected_kind="store",
        expected_store_id=rep.store_id,
        migrations=KERNEL_STORE_MIGRATIONS,
        os_=os_,
    )
    ap_s = _sign_from_preview(prev_s.stdout, trusted_tmp / "ap-store.json", s_man.db_digest)
    res_s = _wheel_restore("store", store_bak, "--approval-file", str(ap_s))
    assert res_s.returncode == 0 and json.loads(res_s.stdout)["ok"] is True

    # 3) Missing live policy/policy.db -> verified backup signers + writer.lock HWM recovers policy.db!
    layout.policy_db.unlink()
    prev_p = _wheel_restore("policy", policy_bak, "--preview")
    assert prev_p.returncode == 0, prev_p.stderr
    p_man = verify_backup(
        policy_bak, expected_kind="policy", expected_store_id=rep.store_id, migrations=KERNEL_POLICY_MIGRATIONS, os_=os_
    )
    ap_p = _sign_from_preview(prev_p.stdout, trusted_tmp / "ap-pol.json", p_man.db_digest, fallback_gen=gen1)
    res_p = _wheel_restore("policy", policy_bak, "--approval-file", str(ap_p))
    assert res_p.returncode == 0 and int(json.loads(res_p.stdout)["data"]["trust_generation"]) > gen1

    # Corrupt policy.db + stale gen1 approval MUST fail HWM fence!
    layout.policy_db.write_bytes(b"corrupt-policy-db")
    ap_stale = _sign_from_preview(prev_p.stdout, trusted_tmp / "ap-stale.json", p_man.db_digest, fallback_gen=gen1)
    res_stale = _wheel_restore("policy", policy_bak, "--approval-file", str(ap_stale))
    assert res_stale.returncode != 0


def test_i2_schema_ceiling_4_3_refuses_5_4_before_write_on_serve_migrate_and_restore(
    trusted_tmp: Path,
) -> None:
    from superbrain.application import maintenance

    clock = FakeClock(datetime(2026, 10, 30, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "i2-fence-54"
    rt = open_kernel_job_runtime(root_path, os_, role="i2-fence")
    store_id = rt.store.store_id
    store_bak = create_store_backup(rt.store, os_, clock.now())
    policy_bak = create_policy_backup(rt.policy, os_, clock.now())
    rt.close()

    cfg = DaemonConfig(
        version=1,
        data_root=root_path,
        expected_store_id=store_id,
        cert_path=trusted_tmp / "unused.pem",
        key_path=trusted_tmp / "unused.key",
    )
    i2_store, i2_policy = KERNEL_STORE_MIGRATIONS[:4], KERNEL_POLICY_MIGRATIONS[:3]
    snap_before = digest_tree(root_path)

    def _expect_unsupported(fn: Any) -> None:
        with pytest.raises(BrainError) as err:
            fn()
        assert err.value.code is ErrorCode.UNSUPPORTED_VERSION

    for purpose in ("serve", "migrate"):
        _expect_unsupported(
            lambda p=purpose: admit_existing_pair(
                root_path, store_id, os_, purpose=p, store_migrations=i2_store, policy_migrations=i2_policy
            )
        )
    _expect_unsupported(lambda: migrate_offline(cfg, os_, policy_migrations=i2_policy, store_migrations=i2_store))
    for target_kind, bak in (("store", store_bak), ("policy", policy_bak)):
        _expect_unsupported(
            lambda k=target_kind, b=bak: maintenance.preview_restore(
                root_path,
                os_,
                target=k,
                backup=b,
                store_id=store_id,
                store_migrations=i2_store,
                policy_migrations=i2_policy,
            )
        )
    assert digest_tree(root_path) == snap_before

    with maintenance_lease(root_path) as (root, lease):
        for fn in (
            lambda: migrate_database(root, lease, os_, target="store", migrations=i2_store, now=clock.now()),
            lambda: migrate_database(root, lease, os_, target="policy", migrations=i2_policy, now=clock.now()),
            lambda: restore_policy(
                root, lease, os_, policy_bak, store_id=store_id, now=clock.now(), migrations=i2_policy
            ),
            lambda: PolicyStore.open(root, lease, os_, migrations=i2_policy),
        ):
            _expect_unsupported(fn)

    snap_after = digest_tree(root_path)
    assert {k: v for k, v in snap_after.items() if k != "writer.lock"} == {
        k: v for k, v in snap_before.items() if k != "writer.lock"
    }
