"""Shared oracle helpers for the SP1-I3 ``1d666f5`` re-review (F1 TLS identity, F2 rule scope).

Requirement sources: Plan I3 line 215 (§7.4 / §14.2), spec rev 22 D3,
``docs/reviews/2026-11-20-sp1-increment3-rereview-1d666f5.md``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import struct
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.bootstrap_templates import (
    HandoffTakeoverEditDecision,
    evaluate_takeover_edit_gate,
)
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import create_store_tls, verify_server_tls_files
from superbrain.composition.init_entry import InitRequest, init_store
from superbrain.core._kernel_approval import CLI_HARNESS_ID, ApprovalChannel, SignerEnrollment
from superbrain.core._kernel_auth import parse_bearer_token
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import WorkspaceBinding
from superbrain.ports.clock import Clock
from superbrain.ports.os import DurabilityReport, NoReplacePublisher, OsAdapters
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree, file_identity
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.kernel_auth import make_bootstrap_auth


def ssh_enrollment(tag: str, owner_id: str = "dan") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    key = f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} {tag}@devbox"
    return SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=key)


def ws_dict(ws: WorkspaceBinding, checkout: Path | None = None) -> dict[str, str]:
    co = checkout if checkout is not None else ws.checkout_path
    return {
        "alias": ws.alias, "checkout_path": str(co),
        "expected_workspace_id": ws.repo_id, "expected_checkout_id": ws.checkout_id,
    }


def prop_id(out: Mapping[str, Any]) -> str:
    assert isinstance((prop_obj := out["proposal"]), Mapping)
    return str(prop_obj["proposal_id"])

def leaf_sha(server_pem: Path) -> str:
    """The TLS pin: SHA-256 of the DER leaf certificate."""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(server_pem.read_text("utf-8"))).hexdigest()


def flip_last_hex_char(digest: str) -> str:
    return digest[:-1] + ("0" if digest[-1] != "0" else "1")


def daemon_identity(data_root: Path, cfg_dir: Path) -> dict[str, Any]:
    """Explicit daemon TLS/endpoint identity kwargs of the init store (the ones a live daemon would pass)."""
    cert = cfg_dir / "tls" / "server.pem"
    return {
        "expected_endpoint_path": data_root / "endpoint.json",
        "expected_leaf_cert_sha256": leaf_sha(cert),
        "server_cert_path": cert,
    }


def foreign_ca_file(base: Path, os_: OsAdapters, *, owner_id: str, machine_id: str, signer: SignerEnrollment) -> Path:
    """A valid PEM CA of a *different* initialized store."""
    req = InitRequest(
        data_root=base / "foreign-data", config_dir=base / "foreign-cfg", owner_id=owner_id, machine_id=machine_id,
        signer=signer,
    )
    init_store(req, os_)
    return req.config_dir / "tls" / "ca.pem"


def rotated_tls(store_id: str, tls_dir: Path, owner_id: str, clock: Clock, os_: OsAdapters) -> tuple[Path, Path, str]:
    """A daemon-rotated per-store TLS bundle: ``(server_cert, ca_file, pin)``."""
    auth = make_bootstrap_auth(
        store_id=store_id, owner_id=owner_id, action="provision_tls", subject_id=store_id,
        expires_at=clock.now() + timedelta(hours=1), destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, auth, clock, os_)
    return tls.cert_path, tls_dir / "ca.pem", leaf_sha(tls.cert_path)


def assert_f2_rule_scope(rule_text: str) -> None:
    """F2: the takeover edit gate is scoped to open-handoff takeover; ``not_stored_policy`` has both branches."""
    low = " ".join(rule_text.lower().split())
    assert "never edit any checkout file" not in low
    gate = [s for s in low.split(". ") if "writer_status=holder" in s]
    assert gate, "missing stored+holder takeover ACK gate"
    for sentence in gate:
        assert "open handoff" in sentence and any(w in sentence for w in ("takeover", "taking over", "take over"))
    at = low.index("not_stored_policy")
    clause = low[at : at + 500]
    assert "taking over an open handoff" in clause, "branch (i) takeover not stated"
    assert "do not edit" in clause and ("notify" in clause or "ask" in clause), "branch (i) must block + notify/ask"
    assert any(p in clause for p in ("not taking over", "without taking over", "no open handoff", "ordinary")), (
        "branch (ii) ordinary work not stated"
    )
    assert "proceed" in clause or "continue" in clause, "branch (ii) must proceed normally"
    assert "policy" in clause and "manual_submission" in low
    # 0f3c6d6 F2: ``not_stored_policy`` ACKs still carry the live ``writer_status`` (spec §7.4), so a ``not_holder``
    # stop/re-read is only valid for an open-handoff takeover or a stored book, never as ordinary-work order.
    stop_words = ("do not edit", "re-read", "reread", "block", "stop")
    scoped_clauses = 0
    for part in re.split(r"[.;:]\s", low):
        if "not_holder" not in part or not any(w in part for w in stop_words):
            continue
        ordinary = any(p in part for p in ("not taking over", "without taking over", "no open handoff", "ordinary"))
        takeover = any(p in part for p in ("taking over", "takeover", "take over", "open handoff"))
        assert "handoff_status=stored" in part or (takeover and not ordinary), f"unconditional not_holder: {part!r}"
        scoped_clauses += 1
    assert scoped_clauses, "missing scoped writer_status=not_holder stop + re-read clause"


def assert_not_stored_policy_not_holder_ack_pair() -> None:
    """0f3c6d6 F2: the ACK pair ``not_stored_policy`` + ``not_holder`` decides by context; ``stored`` re-reads."""
    blocked, ordinary = HandoffTakeoverEditDecision(False, "policy_disabled", False, True), HandoffTakeoverEditDecision(
        True, "proceed_without_handoff_policy"
    )

    def gate(status: str, session: str | None, *, takeover: bool, ack: bool = False) -> HandoffTakeoverEditDecision:
        return evaluate_takeover_edit_gate(
            holding_session_state=session, acknowledge_active=ack, handoff_status=status, writer_status="not_holder",
            commit_outcome_unknown=False, taking_over_open_handoff=takeover,
        )

    for session in ("ended", "active"):
        assert gate("not_stored_policy", session, takeover=True, ack=session == "active") == blocked
    opt_sessions: tuple[str | None, ...] = (None, "ended")
    for opt_session in opt_sessions:
        assert gate("not_stored_policy", opt_session, takeover=False) == ordinary
    for takeover in (True, False):
        assert gate("stored", "ended", takeover=takeover) == HandoffTakeoverEditDecision(False, "reread_handoff")


def _verify_ca_signed_leaf(ca_pem_path: Path, leaf_pem_path: Path) -> None:
    ca_cert = x509.load_pem_x509_certificate(ca_pem_path.read_bytes())
    leaf_cert = x509.load_pem_x509_certificate(leaf_pem_path.read_bytes())
    pub = ca_cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert leaf_cert.signature_hash_algorithm is not None
    pub.verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes, ec.ECDSA(leaf_cert.signature_hash_algorithm))


def assert_clean_completed_init(req: InitRequest, report: Any, os_: OsAdapters, clock: FakeClock) -> None:
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
        assert (principal.owner_id, principal.harness_id, principal.machine_id) == (
            req.owner_id, CLI_HARNESS_ID, req.machine_id,
        )
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


class FaultyPublisher(NoReplacePublisher):
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


def faulty_os(base_os: OsAdapters, fail_name: str) -> OsAdapters:
    return replace(base_os, publisher=FaultyPublisher(base_os.publisher, fail_name))


INIT_ARTIFACTS = (
    ".init-bootstrap.json", "ca.pem", "ca.key", "server.pem", "server.key", "daemon.json", "cli.credential",
)
_TLS_NAMES = frozenset({"ca.pem", "ca.key", "server.pem", "server.key"})


def artifact_rel(artifact: str) -> str:
    """Config-dir-relative POSIX path of an init/TLS artifact (TLS material lives under ``tls/``)."""
    return f"tls/{artifact}" if artifact in _TLS_NAMES else artifact


class ProcessKilledError(BaseException):
    """Simulated SIGKILL: ``BaseException`` so no in-process ``except Exception`` recovery may run."""


class CrashProbePublisher(NoReplacePublisher):
    """Records every ``write_new`` and its eventual final name; optionally hard-kills one write after byte 1.

    The kill writes ``data[:1]`` to the exact path handed to ``write_new`` and aborts WITHOUT the real
    ``write_new`` cleanup (``unlink``): the on-disk state a process kill between ``write`` and ``fsync`` leaves.
    """

    def __init__(
        self, inner: Any, cfg_dir: Path, kill_at: int | None = None,
        *, exit_code: int | None = None, record_path: Path | None = None,
    ) -> None:
        self._inner, self._cfg_dir, self._kill_at = inner, cfg_dir, kill_at
        self._exit_code, self._record_path = exit_code, record_path
        self.writes: list[Path] = []
        self._finals: dict[int, Path] = {}
        self._pending: dict[Path, int] = {}
        self.partial: Path | None = None

    def final_rels(self) -> tuple[str | None, ...]:
        """Config-dir-relative final name of each ``write_new`` call (``None`` outside the config dir)."""
        out: list[str | None] = []
        for idx, written in enumerate(self.writes):
            try:
                out.append(self._finals.get(idx, written).relative_to(self._cfg_dir).as_posix())
            except ValueError:
                out.append(None)
        return tuple(out)

    def write_new(self, path: Path, data: bytes) -> None:
        idx = len(self.writes)
        self.writes.append(path)
        self._pending[path] = idx
        if idx == self._kill_at:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
            try:
                os.write(fd, data[:1])
            finally:
                os.close(fd)
            self.partial = path
            if self._record_path is not None:
                self._record_path.write_text(str(path), encoding="utf-8")
            if self._exit_code is not None:
                os._exit(self._exit_code)
            raise ProcessKilledError(f"killed after first byte of {path.name}")
        self._inner.write_new(path, data)

    def _resolve(self, staging: Path, final: Path) -> None:
        idx = self._pending.pop(staging, None)
        if idx is not None:
            self._finals[idx] = final

    def publish(self, staging: Path, final: Path) -> None:
        self._inner.publish(staging, final)
        self._resolve(staging, final)

    def publish_no_replace(self, staging: Path, final: Path) -> None:
        self._inner.publish_no_replace(staging, final)
        self._resolve(staging, final)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._inner.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self._inner.sync_directory(directory)

    def flush_file(self, path: Path) -> None:
        self._inner.flush_file(path)

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        res: DurabilityReport = self._inner.durability(directory, env)
        return res


_WRITE_PLAN: list[tuple[str | None, ...]] = []


def init_write_plan(base: Path, os_: OsAdapters) -> tuple[str | None, ...]:
    """Final name of every ``write_new`` of one healthy ``init_store`` (computed once, in-process)."""
    if not _WRITE_PLAN:
        cfg_dir = base / "plan-cfg"
        cfg_dir.mkdir(parents=True)
        os_.permissions.secure_directory(cfg_dir)
        probe = CrashProbePublisher(os_.publisher, cfg_dir)
        req = InitRequest(
            data_root=base / "plan-data", config_dir=cfg_dir, owner_id="dan", machine_id="plan-box",
            signer=ssh_enrollment("plan"),
        )
        init_store(req, replace(os_, publisher=probe))
        _WRITE_PLAN.append(probe.final_rels())
    return _WRITE_PLAN[0]


def crash_init_after_first_byte(req: InitRequest, os_: OsAdapters, plan: tuple[str | None, ...], artifact: str) -> Path:
    """Run ``init_store``, hard-kill it right after byte 1 of ``artifact``'s first write; return the leftover."""
    probe = CrashProbePublisher(os_.publisher, req.config_dir, kill_at=plan.index(artifact_rel(artifact)))
    with pytest.raises(ProcessKilledError):
        init_store(req, replace(os_, publisher=probe))
    assert probe.partial is not None and probe.partial.is_file()
    return probe.partial


def assert_only_published_init_files(cfg_dir: Path) -> None:
    """Zero stray staging/``.tmp`` files: only the final init/TLS artifacts remain."""
    assert sorted(p.name for p in cfg_dir.iterdir()) == ["cli.credential", "daemon.json", "tls"]
    assert sorted(p.name for p in (cfg_dir / "tls").iterdir()) == sorted(_TLS_NAMES)


def _secure_user_file(path: Path, content: bytes, os_: OsAdapters) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(path.parent)
    path.write_bytes(content)
    os_.permissions.secure_file(path)


def assert_init_preserves_files(
    req: InitRequest, os_: OsAdapters, clock: FakeClock, files: Sequence[tuple[Path, bytes]]
) -> None:
    """Run ``init_store`` and require every ``(path, content)`` to stay intact whether init completes or refuses."""
    expected = [(path, content, file_identity(path)) for path, content in files]
    snap_cfg, snap_data = digest_tree(req.config_dir), digest_tree(req.data_root)
    try:
        report = init_store(req, os_)
    except BrainError as err:
        assert err.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)
        assert digest_tree(req.config_dir) == snap_cfg
        assert digest_tree(req.data_root) == snap_data
    else:
        assert_clean_completed_init(req, report, os_, clock)
    for path, content, ident in expected:
        assert path.is_file() and path.read_bytes() == content and file_identity(path) == ident, (
            f"unowned file deleted or mutated: {path}"
        )


def assert_unowned_stage_named_case_preserved(
    req: InitRequest, os_: OsAdapters, clock: FakeClock, case: str
) -> None:
    """50c3846 F3 (a): unowned ``.<artifact>.stage-<uuid7>`` files (fresh or recovery) stay byte-identical."""
    uid = new_id()
    rel_by_case = {
        "fresh-marker": f"..init-bootstrap.json.stage-{uid}",
        "fresh-daemon": f".daemon.json.stage-{uid}",
        "fresh-cred": f".cli.credential.stage-{uid}",
        "mid-tls": f"tls/.ca.pem.stage-{uid}",
        "post-tls": f"tls/.ca.pem.stage-{uid}",
        "post-tls-cfg": f".daemon.json.stage-{uid}",
    }
    fail_by_case = {"mid-tls": "server.pem", "post-tls": "daemon.json", "post-tls-cfg": "daemon.json"}
    if case in fail_by_case:
        with pytest.raises(BrainError) as io_err:
            init_store(req, faulty_os(os_, fail_by_case[case]))
        assert io_err.value.code is ErrorCode.IO_ERROR
    target = req.config_dir / rel_by_case[case]
    content = f"user-stage-{case}\n".encode("ascii")
    _secure_user_file(target, content, os_)
    assert_init_preserves_files(req, os_, clock, [(target, content)])


def assert_foreign_marker_and_stages_refused(base: Path, os_: OsAdapters) -> None:
    """50c3846 F3 (b1): foreign ``req_B`` marker + stage siblings refuse ``req_A`` with zero cfg/data mutation."""
    cfg_dir = base / "cfg"
    cfg_dir.mkdir(parents=True)
    os_.permissions.secure_directory(cfg_dir)
    req_b = InitRequest(
        data_root=base / "data-b", config_dir=cfg_dir, owner_id="bob", machine_id="box-b",
        signer=ssh_enrollment("bob", owner_id="bob"),
    )
    with pytest.raises(BrainError) as err_b:
        init_store(req_b, faulty_os(os_, "brain.db"))
    assert err_b.value.code is ErrorCode.IO_ERROR
    for rel in (f"..init-bootstrap.json.stage-{new_id()}", f".daemon.json.stage-{new_id()}"):
        _secure_user_file(cfg_dir / rel, b"{", os_)
    snap_cfg, snap_db = digest_tree(cfg_dir), digest_tree(req_b.data_root)
    req_a = InitRequest(
        data_root=base / "data-a", config_dir=cfg_dir, owner_id="dan", machine_id="box-a",
        signer=ssh_enrollment("dan", owner_id="dan"),
    )
    with pytest.raises(BrainError) as err_a:
        init_store(req_a, os_)
    assert err_a.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)
    assert digest_tree(cfg_dir) == snap_cfg, "foreign marker/stage siblings in cfg_dir were mutated"
    assert digest_tree(req_b.data_root) == snap_db
    assert digest_tree(req_a.data_root) == {}


def assert_foreign_byte1_stage_preserved(base: Path, os_: OsAdapters, clock: FakeClock, mode: str) -> None:
    """50c3846 F3 (b2): stage file created by ``req_B`` byte-1 crash is never deleted or mutated by ``req_A``."""
    plan = init_write_plan(base, os_)
    if mode in ("fresh-marker-stage", "foreign-with-tls"):
        cfg_dir = base / "cfg"
        cfg_dir.mkdir(parents=True)
        os_.permissions.secure_directory(cfg_dir)
        req_b = InitRequest(
            data_root=base / "data-b", config_dir=cfg_dir, owner_id="bob", machine_id="box-b",
            signer=ssh_enrollment("bob", owner_id="bob"),
        )
        req_a = InitRequest(
            data_root=base / "data-a", config_dir=cfg_dir, owner_id="dan", machine_id="box-a",
            signer=ssh_enrollment("dan", owner_id="dan"),
        )
        if mode == "fresh-marker-stage":
            partial_b = crash_init_after_first_byte(req_b, os_, plan, ".init-bootstrap.json")
            assert_init_preserves_files(req_a, os_, clock, [(partial_b, partial_b.read_bytes())])
            return
        partial_b = crash_init_after_first_byte(req_b, os_, plan, "daemon.json")
        snap_cfg, snap_db = digest_tree(cfg_dir), digest_tree(req_b.data_root)
        with pytest.raises(BrainError) as err_a:
            init_store(req_a, os_)
        assert err_a.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)
        assert digest_tree(cfg_dir) == snap_cfg and digest_tree(req_b.data_root) == snap_db
        assert digest_tree(req_a.data_root) == {} and partial_b.is_file()
        return

    cfg_b, cfg_a = base / "cfg-b", base / "cfg-a"
    for d in (cfg_b, cfg_a):
        d.mkdir(parents=True)
        os_.permissions.secure_directory(d)
    b_owner, b_tag, b_art, a_fail, sub = (
        ("bob", "bob", "ca.pem", "server.pem", "tls")
        if mode == "mid-tls-foreign"
        else ("dan", "dan-other", "daemon.json", "daemon.json", "")
    )
    req_b = InitRequest(
        data_root=base / "data-b", config_dir=cfg_b, owner_id=b_owner, machine_id="box-b",
        signer=ssh_enrollment(b_tag, owner_id=b_owner),
    )
    partial_b = crash_init_after_first_byte(req_b, os_, plan, b_art)
    req_a = InitRequest(
        data_root=base / "data-a", config_dir=cfg_a, owner_id="dan", machine_id="box-a",
        signer=ssh_enrollment("dan", owner_id="dan"),
    )
    with pytest.raises(BrainError) as io_err:
        init_store(req_a, faulty_os(os_, a_fail))
    assert io_err.value.code is ErrorCode.IO_ERROR
    foreign_in_a = (cfg_a / sub if sub else cfg_a) / partial_b.name
    content_b = partial_b.read_bytes()
    _secure_user_file(foreign_in_a, content_b, os_)
    assert_init_preserves_files(req_a, os_, clock, [(foreign_in_a, content_b)])


def run_byte1_kill_child() -> None:
    """Child-process entrypoint for real ``os._exit(1)`` after byte 1 of an init/TLS stage file."""
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    clock = FakeClock(datetime.fromisoformat(cfg["when"]))
    base_os = os_adapters(clock=clock)
    cfg_dir = Path(cfg["config_dir"])
    probe = CrashProbePublisher(
        base_os.publisher, cfg_dir, kill_at=int(cfg["kill_at"]),
        exit_code=1, record_path=Path(cfg["record_path"]),
    )
    req = InitRequest(
        data_root=Path(cfg["data_root"]),
        config_dir=cfg_dir,
        owner_id=cfg["owner_id"],
        machine_id=cfg["machine_id"],
        signer=SignerEnrollment(
            owner_id=cfg["owner_id"],
            channel=ApprovalChannel(cfg["channel"]),
            public_key=cfg["public_key"],
        ),
    )
    init_store(req, replace(base_os, publisher=probe))


def assert_real_subprocess_kill_recovers(
    aux_dir: Path, req: InitRequest, os_: OsAdapters, clock: FakeClock, artifact: str
) -> None:
    """50c3846 F3 (c): real child process ``os._exit(1)`` at byte 1 leaves owned stage that in-process retry cleans."""
    aux_dir.mkdir(parents=True, exist_ok=True)
    plan = init_write_plan(aux_dir, os_)
    cfg_json, record_path = aux_dir / "kill-req.json", aux_dir / "partial-path.txt"
    cfg_json.write_text(
        json.dumps(
            {
                "data_root": str(req.data_root),
                "config_dir": str(req.config_dir),
                "owner_id": req.owner_id,
                "machine_id": req.machine_id,
                "channel": req.signer.channel.value,
                "public_key": req.signer.public_key,
                "kill_at": plan.index(artifact_rel(artifact)),
                "when": clock.now().isoformat(),
                "record_path": str(record_path),
            }
        ),
        encoding="utf-8",
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    prev_pp = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(repo_root) if not prev_pp else f"{repo_root}{os.pathsep}{prev_pp}"
    proc = subprocess.run(
        [
            sys.executable, "-c",
            "from tests.support.rereview_1d666f5 import run_byte1_kill_child; run_byte1_kill_child()",
            str(cfg_json),
        ],
        cwd=str(repo_root),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60.0,
        check=False,
    )
    assert proc.returncode != 0
    assert record_path.is_file(), f"child did not reach byte-1 kill for {artifact}: stderr={proc.stderr!r}"
    partial = Path(record_path.read_text(encoding="utf-8").strip())
    final = req.config_dir / artifact_rel(artifact)
    assert not os.path.lexists(final), f"{artifact}: partial bytes left under final name"
    assert partial != final and partial.parent == final.parent and partial.is_file() and partial.stat().st_size == 1
    assert_clean_completed_init(req, init_store(req, os_), os_, clock)
    assert_only_published_init_files(req.config_dir)


__all__ = [
    "INIT_ARTIFACTS", "CrashProbePublisher", "FaultyPublisher", "ProcessKilledError", "artifact_rel",
    "assert_clean_completed_init", "assert_f2_rule_scope", "assert_foreign_byte1_stage_preserved",
    "assert_foreign_marker_and_stages_refused", "assert_init_preserves_files",
    "assert_not_stored_policy_not_holder_ack_pair", "assert_only_published_init_files",
    "assert_real_subprocess_kill_recovers", "assert_unowned_stage_named_case_preserved",
    "crash_init_after_first_byte", "daemon_identity", "faulty_os", "flip_last_hex_char", "foreign_ca_file",
    "init_write_plan", "leaf_sha", "prop_id", "rotated_tls", "run_byte1_kill_child", "ssh_enrollment", "ws_dict",
]
