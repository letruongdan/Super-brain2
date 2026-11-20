"""SP1-I3 rereview oracle for F3 (init_store durable recovery) & F5 (UTC monthly + daily accounting locks).

Requirement sources: spec rev 22 §5.7, §9, §11.3; ``docs/reviews/2026-11-20-sp1-increment3-rereview-0b0316e.md``.
"""

from __future__ import annotations

import base64
import struct
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.composition.init_entry import InitRequest, init_store
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
    classify_policy_change_risk,
    policy_change_subject_id,
)
from superbrain.core._kernel_auth import parse_bearer_token
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import ResourceDigest
from superbrain.ports.os import DurabilityReport, NoReplacePublisher, OsAdapters
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import preview_policy_restore, read_restore_epoch, restore_policy
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime

OWNER = "dan"
MACHINE = "rereview-f3-f5"
D_DIFF = digest_bytes(b'{"reconcile_accounting":true}')


def _ssh_enrollment(tag: str) -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


class _FaultyPublisher(NoReplacePublisher):
    """Test-only publisher wrapper injecting ``IO_ERROR`` on one target file name."""

    def __init__(self, inner: Any, fail_name: str) -> None:
        self._inner = inner
        self._fail_name = fail_name

    def write_new(self, path: Path, data: bytes) -> None:
        if path.name == self._fail_name:
            raise BrainError(ErrorCode.IO_ERROR, f"injected io_error on {path.name}")
        self._inner.write_new(path, data)

    def publish(self, staging: Path, final: Path) -> None:
        if final.name == self._fail_name:
            raise BrainError(ErrorCode.IO_ERROR, f"injected io_error on {final.name}")
        self._inner.publish(staging, final)

    def publish_no_replace(self, staging: Path, final: Path) -> None:
        if final.name == self._fail_name:
            raise BrainError(ErrorCode.IO_ERROR, f"injected io_error on {final.name}")
        self._inner.publish_no_replace(staging, final)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._inner.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self._inner.sync_directory(directory)

    def flush_file(self, path: Path) -> None:
        self._inner.flush_file(path)

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        res: DurabilityReport = self._inner.durability(directory, env)
        return res


def _faulty_os(base_os: OsAdapters, fail_name: str) -> OsAdapters:
    return replace(base_os, publisher=_FaultyPublisher(base_os.publisher, fail_name))


def _verify_ca_signed_leaf(ca_pem_path: Path, leaf_pem_path: Path) -> None:
    ca_cert = x509.load_pem_x509_certificate(ca_pem_path.read_bytes())
    leaf_cert = x509.load_pem_x509_certificate(leaf_pem_path.read_bytes())
    pub = ca_cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert leaf_cert.signature_hash_algorithm is not None
    pub.verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes, ec.ECDSA(leaf_cert.signature_hash_algorithm))


def _assert_clean_completed_init(req: InitRequest, report: Any, os_: OsAdapters, clock: FakeClock) -> None:
    """Exactly one signer/credential/principal, reconciled policy, CA-signed leaf and no leftover init marker file."""
    data_root, cfg_dir = req.data_root, req.config_dir
    cfg = read_daemon_config(report.daemon_config_path, os_)
    assert (cfg.data_root, cfg.expected_store_id) == (data_root, report.store_id)
    assert verify_server_tls_files(cfg, clock, os_).store_id == report.store_id
    _verify_ca_signed_leaf(cfg_dir / "tls" / "ca.pem", cfg.cert_path)
    assert not (cfg_dir / ".init-bootstrap.json").exists()
    token = report.cli_credential_path.read_text(encoding="ascii").strip()
    cred_id, _ = parse_bearer_token(token)
    rt = reopen_kernel_job_runtime(data_root, report.store_id, os_)
    try:
        principal = rt.policy.resolve_credential(token)
        assert (principal.owner_id, principal.harness_id, principal.machine_id) == (OWNER, CLI_HARNESS_ID, MACHINE)
        snap = rt.policy.snapshot()
        assert [cid for cid, rec in snap.credentials.items() if not rec.revoked] == [cred_id]
        assert len(snap.principals) == 1
        assert rt.store.reconcile_policy() == 0
        intents = len(rt.policy.intents())
        with rt.store.transaction() as txn:
            applied = txn.db.execute("SELECT COUNT(*) FROM applied_intents").fetchone()
        assert applied is not None and int(applied[0]) == intents
        signers = rt.policy.active_signers()
        assert [s.signer_id for s in signers] == [report.signer.signer_id]
        assert signers[0].tofu is True and signers[0].key_digest == req.signer.key_digest
    finally:
        rt.close()

@pytest.mark.parametrize("fail_target", ["ca.pem", "server.pem", "daemon.json", "cli.credential"])
def test_f3_init_store_durable_recovery_across_tls_daemon_and_credential_failures(
    trusted_tmp: Path, fail_target: str
) -> None:
    """F3: retry identical InitRequest succeeds after pre-TLS, mid-TLS, daemon.json, or cli.credential I/O failure."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    base = trusted_tmp / f"f3-{fail_target}"
    data_root, cfg_dir = base / "data", base / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(cfg_dir)
    req = InitRequest(
        data_root=data_root,
        config_dir=cfg_dir,
        owner_id=OWNER,
        machine_id=MACHINE,
        signer=_ssh_enrollment(f"f3-{fail_target}"),
    )

    with pytest.raises(BrainError) as io_err:
        init_store(req, _faulty_os(os_, fail_target))
    assert io_err.value.code is ErrorCode.IO_ERROR

    # Retry identical request with healthy OS succeeds completely.
    _assert_clean_completed_init(req, init_store(req, os_), os_, clock)

    # Completed init MUST refuse any further retry without mutating bytes.
    snap_data, snap_cfg = digest_tree(data_root), digest_tree(cfg_dir)
    with pytest.raises(BrainError) as done_err:
        init_store(req, os_)
    assert done_err.value.code is ErrorCode.INVALID_INPUT
    assert digest_tree(data_root) == snap_data
    assert digest_tree(cfg_dir) == snap_cfg


def test_f3_init_store_negative_guards_do_not_mutate_existing_bytes(trusted_tmp: Path) -> None:
    """F3: mismatched retry on incomplete init, pre-existing daemon/cred, and foreign tls files refuse cleanly."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)

    # 1. Mismatched request against incomplete init (after mid-TLS failure) refuses INVALID_INPUT with 0 mutations.
    b1 = trusted_tmp / "mismatch"
    d1, c1 = b1 / "data", b1 / "cfg"
    c1.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(c1)
    signer1 = _ssh_enrollment("s1")
    req1 = InitRequest(data_root=d1, config_dir=c1, owner_id=OWNER, machine_id=MACHINE, signer=signer1)
    with pytest.raises(BrainError) as err1:
        init_store(req1, _faulty_os(os_, "server.pem"))
    assert err1.value.code is ErrorCode.IO_ERROR

    snap_d1, snap_c1 = digest_tree(d1), digest_tree(c1)
    mismatched_reqs = (
        InitRequest(
            data_root=d1,
            config_dir=c1,
            owner_id="alice",
            machine_id=MACHINE,
            signer=SignerEnrollment(owner_id="alice", channel=ApprovalChannel.SSH_KEY, public_key=signer1.public_key),
        ),
        InitRequest(data_root=d1, config_dir=c1, owner_id=OWNER, machine_id="other-box", signer=signer1),
        InitRequest(data_root=d1, config_dir=c1, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment("other")),
    )
    for bad_req in mismatched_reqs:
        with pytest.raises(BrainError) as bad_err:
            init_store(bad_req, os_)
        assert bad_err.value.code is ErrorCode.INVALID_INPUT
        assert digest_tree(d1) == snap_d1 and digest_tree(c1) == snap_c1

    # Original identical request still recovers after mismatched attempts!
    rep1 = init_store(req1, os_)
    assert rep1.daemon_config_path.is_file() and rep1.cli_credential_path.is_file()

    # 2. Pre-existing daemon.json / cli.credential / foreign tls file on fresh root -> INVALID_INPUT, 0 bytes modified.
    for case_name, rel_path, content in (
        ("pre-daemon", "daemon.json", b'{"user": true}\n'),
        ("pre-cred", "cli.credential", b"user-supplied-token\n"),
        ("pre-foreign-tls", "tls/foreign.txt", b"foreign\n"),
    ):
        base = trusted_tmp / case_name
        d_root, cfg = base / "data", base / "cfg"
        target = cfg / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(cfg)
        if target.parent != cfg:
            os_.permissions.secure_directory(target.parent)
        target.write_bytes(content)
        os_.permissions.secure_file(target)
        snap_cfg = digest_tree(cfg)
        with pytest.raises(BrainError) as pre_err:
            init_store(
                InitRequest(
                    data_root=d_root,
                    config_dir=cfg,
                    owner_id=OWNER,
                    machine_id=MACHINE,
                    signer=_ssh_enrollment(case_name),
                ),
                os_,
            )
        assert pre_err.value.code is ErrorCode.INVALID_INPUT
        assert digest_tree(cfg) == snap_cfg
        assert not (d_root / "policy" / "policy.db").exists()

    # 3. Foreign file introduced into tls/ of an interrupted init -> INVALID_INPUT, 0 bytes modified.
    b3 = trusted_tmp / "foreign-mid"
    d3, c3 = b3 / "data", b3 / "cfg"
    c3.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(c3)
    req3 = InitRequest(data_root=d3, config_dir=c3, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment("f3m"))
    with pytest.raises(BrainError) as err3:
        init_store(req3, _faulty_os(os_, "server.pem"))
    assert err3.value.code is ErrorCode.IO_ERROR
    (c3 / "tls").mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(c3 / "tls")
    (c3 / "tls" / "foreign.pem").write_bytes(b"stranger\n")
    os_.permissions.secure_file(c3 / "tls" / "foreign.pem")
    snap_d3, snap_c3 = digest_tree(d3), digest_tree(c3)
    with pytest.raises(BrainError) as f_err:
        init_store(req3, os_)
    assert f_err.value.code is ErrorCode.INVALID_INPUT
    assert digest_tree(d3) == snap_d3 and digest_tree(c3) == snap_c3


def _f3_request(trusted_tmp: Path, os_: OsAdapters, tag: str) -> InitRequest:
    base = trusted_tmp / tag
    cfg_dir = base / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(cfg_dir)
    return InitRequest(
        data_root=base / "data", config_dir=cfg_dir, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment(tag)
    )


def _fail_marker_write(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "injected marker io_error")

    monkeypatch.setattr("superbrain.composition.init_entry.write_init_bootstrap_state", boom)


def test_f3_marker_io_error_before_any_marker_then_identical_retry_completes(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F3: ``IO_ERROR`` at the marker write (before init ownership evidence) must not strand the store."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    req = _f3_request(trusted_tmp, os_, "f3-pre-marker")
    with monkeypatch.context() as mp:
        _fail_marker_write(mp)
        with pytest.raises(BrainError) as io_err:
            init_store(req, os_)
    assert io_err.value.code is ErrorCode.IO_ERROR
    assert not (req.config_dir / "daemon.json").exists()
    _assert_clean_completed_init(req, init_store(req, os_), os_, clock)


def test_f3_open_runtime_failure_before_brain_db_then_identical_retry_completes(trusted_tmp: Path) -> None:
    """F3: ``IO_ERROR`` while ``open_runtime`` publishes ``brain.db`` leaves a root an identical retry completes."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    req = _f3_request(trusted_tmp, os_, "f3-brain-db")
    with pytest.raises(BrainError) as io_err:
        init_store(req, _faulty_os(os_, "brain.db"))
    assert io_err.value.code is ErrorCode.IO_ERROR
    assert not (req.config_dir / "daemon.json").exists()
    _assert_clean_completed_init(req, init_store(req, os_), os_, clock)


@pytest.mark.parametrize("resume_fail", ["daemon.json", "cli.credential"])
def test_f3_interruption_before_marker_then_mid_resume_then_third_attempt_completes(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, resume_fail: str
) -> None:
    """F3: attempt 1 fails before the marker, attempt 2 fails mid-resume, attempt 3 completes cleanly."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    req = _f3_request(trusted_tmp, os_, f"f3-resume-{resume_fail}")
    with monkeypatch.context() as mp:
        _fail_marker_write(mp)
        with pytest.raises(BrainError) as first:
            init_store(req, os_)
    assert first.value.code is ErrorCode.IO_ERROR
    with pytest.raises(BrainError) as second:
        init_store(req, _faulty_os(os_, resume_fail))
    assert second.value.code is ErrorCode.IO_ERROR
    _assert_clean_completed_init(req, init_store(req, os_), os_, clock)


def test_f3_completed_and_user_owned_stores_refuse_init_without_mutation(trusted_tmp: Path) -> None:
    """F3 controls: a completed store (even with a planted stale marker file) and a legacy store are never adopted."""
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    done = _f3_request(trusted_tmp, os_, "f3-completed")
    init_store(done, os_)
    stale = done.config_dir / ".init-bootstrap.json"
    stale.write_bytes(b'{"status":"in_progress","stale":true}\n')
    os_.permissions.secure_file(stale)
    legacy = _f3_request(trusted_tmp, os_, "f3-legacy")
    legacy_rt = open_kernel_job_runtime(legacy.data_root, os_, role="f3-legacy")
    try:
        with legacy_rt.policy._authority_tx() as db:
            assert db.execute("SELECT value FROM meta WHERE key = 'init_bootstrap_state'").fetchone() is None
    finally:
        legacy_rt.close()
    for req in (done, legacy):
        snap_data, snap_cfg = digest_tree(req.data_root), digest_tree(req.config_dir)
        with pytest.raises(BrainError) as refused:
            init_store(req, os_)
        assert refused.value.code is ErrorCode.INVALID_INPUT
        assert digest_tree(req.data_root) == snap_data and digest_tree(req.config_dir) == snap_cfg
    assert not (legacy.config_dir / ".init-bootstrap.json").exists()
    assert not any(legacy.config_dir.iterdir())


def _reconcile_all(rt: Any, store_id: str, signer_id: str, layout: DataRoot) -> Any:
    rev = rt.policy.policy_revision()
    cur_epoch = read_restore_epoch(layout, schema_version=5, os_=rt.os_)
    assert (
        classify_policy_change_risk(
            widens_capture_or_egress=False, sets_review_harness_or_command=False, reconcile_accounting=True
        )
        is RiskLevel.HIGH
    )
    subj = policy_change_subject_id(
        repo_id_or_global="global",
        base_policy_revision=rev,
        base_trust_generation=rt.policy.trust_generation(),
        base_restore_epoch=cur_epoch,
        policy_diff_digest=D_DIFF,
    )
    nonce = rt.policy.issue_nonce(action=ApprovalAction.POLICY_CHANGE, subject_id=subj, risk_level=RiskLevel.HIGH)
    msg = ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=rt.policy.trust_generation(),
        action=ApprovalAction.POLICY_CHANGE,
        subject_id=subj,
        subject_revision=1,
        resource_digests=(ResourceDigest("policy_diff", D_DIFF),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=nonce.nonce,
        expires_at=nonce.expires_at,
    )
    return rt.policy.reconcile_accounting_locks(
        repo_id_or_global="global",
        base_policy_revision=rev,
        base_restore_epoch=cur_epoch,
        policy_diff_digest=D_DIFF,
        approval=msg,
        signer_id=signer_id,
        channel=ApprovalChannel.SSH_KEY,
        expected_restore_epoch=cur_epoch,
    )


def test_f5_utc_monthly_and_daily_accounting_locks_and_reconcile(trusted_tmp: Path) -> None:
    """F5: policy restore locks UTC month + day across midnight/month-end, unblocks at next month or reconcile."""
    clock = FakeClock(datetime(2026, 11, 19, 8, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "f5-locks"
    rt = open_kernel_job_runtime(root_path, os_, role="f5-locks")
    store_id = rt.store.store_id
    layout = DataRoot.at(root_path)
    s1 = rt.policy.enroll_first_signer(_ssh_enrollment("f5s1"))
    bak_nov19 = create_policy_backup(rt.policy, os_, clock.now())
    rt.close()

    # Restore at 2026-11-19T12:00Z -> locks ("2026-11", "2026-11-19").
    clock.set(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    diff = preview_policy_restore(
        layout, bak_nov19, store_id=store_id, os_=os_, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
    )
    assert diff.affected_periods == ("2026-11", "2026-11-19")
    with maintenance_lease(root_path, os_) as (root, lease):
        restore_policy(
            root, lease, os_, bak_nov19, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )

    rt2 = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        assert {lk.period_key for lk in rt2.policy.list_accounting_locks(state="locked")} == {"2026-11", "2026-11-19"}
        for blocked_dt in (
            datetime(2026, 11, 19, 12, 5, tzinfo=UTC),
            datetime(2026, 11, 20, 0, 0, tzinfo=UTC),
            datetime(2026, 11, 20, 12, 0, tzinfo=UTC),
            datetime(2026, 11, 30, 23, 59, 59, tzinfo=UTC),
        ):
            clock.set(blocked_dt)
            with pytest.raises(BrainError) as err_b:
                rt2.policy.reserve_accounting_invocation(
                    invocation_id=new_id(),
                    job_id=new_id(),
                    owner_id=OWNER,
                    writer_epoch=rt2.lease.epoch,
                    max_amount="0.5",
                    now=blocked_dt,
                )
            assert err_b.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # Unblocked once UTC month advances to 2026-12-01T00:00Z!
        dec1 = datetime(2026, 12, 1, 0, 0, tzinfo=UTC)
        clock.set(dec1)
        rec_dec = rt2.policy.reserve_accounting_invocation(
            invocation_id=new_id(),
            job_id=new_id(),
            owner_id=OWNER,
            writer_epoch=rt2.lease.epoch,
            max_amount="0.5",
            now=dec1,
        )
        assert rec_dec.period_key == "2026-12-01"

        # Reconcile unlocks BOTH "2026-11" and "2026-11-19" -> calls on 2026-11-19 & 2026-11-20 succeed!
        reconciled = _reconcile_all(rt2, store_id, s1.signer_id, layout)
        assert {lk.period_key for lk in reconciled} == {"2026-11", "2026-11-19"}
        assert rt2.policy.list_accounting_locks(state="locked") == ()
        for ok_dt in (datetime(2026, 11, 19, 13, 0, tzinfo=UTC), datetime(2026, 11, 20, 1, 0, tzinfo=UTC)):
            clock.set(ok_dt)
            assert rt2.policy.reserve_accounting_invocation(
                invocation_id=new_id(),
                job_id=new_id(),
                owner_id=OWNER,
                writer_epoch=rt2.lease.epoch,
                max_amount="0.25",
                now=ok_dt,
            )
    finally:
        rt2.close()

    # Repeated restore across month boundary (2026-11-19 -> 2026-12-02) carries forward live locks + adds "2026-12".
    clock.set(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    with maintenance_lease(root_path, os_) as (root, lease):
        restore_policy(
            root, lease, os_, bak_nov19, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )
    clock.set(datetime(2026, 12, 2, 8, 0, tzinfo=UTC))
    rt_mid = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        bak_dec02 = create_policy_backup(rt_mid.policy, os_, clock.now())
    finally:
        rt_mid.close()

    clock.set(datetime(2026, 12, 2, 12, 0, tzinfo=UTC))
    diff2 = preview_policy_restore(
        layout, bak_dec02, store_id=store_id, os_=os_, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
    )
    assert diff2.affected_periods == ("2026-12", "2026-12-02")
    with maintenance_lease(root_path, os_) as (root, lease):
        restore_policy(
            root, lease, os_, bak_dec02, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )
    rt3 = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        locks3 = rt3.policy.list_accounting_locks(state="locked")
        assert {lk.period_key for lk in locks3} == {"2026-11", "2026-11-19", "2026-12", "2026-12-02"}
        for dt_chk in (datetime(2026, 11, 20, 12, 0, tzinfo=UTC), datetime(2026, 12, 2, 12, 5, tzinfo=UTC)):
            clock.set(dt_chk)
            with pytest.raises(BrainError) as err_c:
                rt3.policy.reserve_accounting_invocation(
                    invocation_id=new_id(),
                    job_id=new_id(),
                    owner_id=OWNER,
                    writer_epoch=rt3.lease.epoch,
                    max_amount="0.25",
                    now=dt_chk,
                )
            assert err_c.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    finally:
        rt3.close()


def test_f5_monthly_period_cap_accumulates_across_days_and_resets_next_month(trusted_tmp: Path) -> None:
    """F5: set_period_cap enforces UTC monthly budget across days and resets at UTC month rollover."""
    clock = FakeClock(datetime(2026, 11, 19, 10, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    rt = open_kernel_job_runtime(trusted_tmp / "f5-cap", os_, role="f5-cap")
    try:
        rt.policy.set_period_cap(OWNER, "5")
        inv1 = new_id()
        rt.policy.reserve_accounting_invocation(
            invocation_id=inv1,
            job_id=new_id(),
            owner_id=OWNER,
            writer_epoch=rt.lease.epoch,
            max_amount="3",
            now=clock.now(),
        )
        rt.policy.settle_accounting_invocation(invocation_id=inv1, amount="3", complete=True, now=clock.now())
        assert rt.policy.period_committed_total(OWNER, "2026-11") == "3"
        assert rt.policy.period_committed_total(OWNER, "2026-11-19") == "3"
        assert len(rt.policy.list_accounting_invocations(owner_id=OWNER, period_key="2026-11")) == 1

        # Next UTC day (2026-11-20) shares the "2026-11" monthly cap!
        clock.set(datetime(2026, 11, 20, 10, 0, tzinfo=UTC))
        with pytest.raises(BrainError) as cap_over:
            rt.policy.reserve_accounting_invocation(
                invocation_id=new_id(),
                job_id=new_id(),
                owner_id=OWNER,
                writer_epoch=rt.lease.epoch,
                max_amount="2.5",
                now=clock.now(),
            )
        assert cap_over.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        inv2 = new_id()
        rt.policy.reserve_accounting_invocation(
            invocation_id=inv2,
            job_id=new_id(),
            owner_id=OWNER,
            writer_epoch=rt.lease.epoch,
            max_amount="2",
            now=clock.now(),
        )
        assert rt.policy.period_committed_total(OWNER, "2026-11") == "5"
        assert rt.policy.period_committed_total(OWNER, "2026-11-19") == "3"
        assert rt.policy.period_committed_total(OWNER, "2026-11-20") == "2"
        assert len(rt.policy.list_accounting_invocations(owner_id=OWNER, period_key="2026-11")) == 2

        with pytest.raises(BrainError) as cap_full:
            rt.policy.reserve_accounting_invocation(
                invocation_id=new_id(),
                job_id=new_id(),
                owner_id=OWNER,
                writer_epoch=rt.lease.epoch,
                max_amount="0.5",
                now=clock.now(),
            )
        assert cap_full.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # New UTC month 2026-12-01T00:00Z resets monthly budget to 0!
        clock.set(datetime(2026, 12, 1, 0, 0, tzinfo=UTC))
        assert rt.policy.period_committed_total(OWNER, "2026-12") == "0"
        assert rt.policy.list_accounting_invocations(owner_id=OWNER, period_key="2026-12") == ()
        rt.policy.reserve_accounting_invocation(
            invocation_id=new_id(),
            job_id=new_id(),
            owner_id=OWNER,
            writer_epoch=rt.lease.epoch,
            max_amount="5",
            now=clock.now(),
        )
        assert rt.policy.period_committed_total(OWNER, "2026-12") == "5"
        assert rt.policy.period_committed_total(OWNER, "2026-11") == "5"
    finally:
        rt.close()
