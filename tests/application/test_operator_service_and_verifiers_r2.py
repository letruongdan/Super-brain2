"""Round-2 RED regression oracle for I3-1-R01, I3-1-R03, I3-1-R05 and I3-1-N1.

Covers: atomic passkey sign_count persistence + self-revocation + strict >0 monotonicity,
find_ssh_keygen path safety + verified owner-only scratch dirs, strict base64url/input
validation, clock rollback rejection in consume_approval, and SSHSIG strict parsing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.auth import ssh_sig
from superbrain.adapters.auth.ssh_sig import SshSigVerifier
from superbrain.adapters.auth.webauthn_verifier import WebAuthnApprovalVerifier
from superbrain.adapters.os import find_ssh_keygen, os_adapters, system_temp_dir
from superbrain.application import approvals as app_approvals
from superbrain.application.approvals import OperatorService
from superbrain.composition.operator_entry import build_operator_service
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
    TargetFile,
    parse_ssh_public_key,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal, ResourceDigest
from superbrain.ports.os import OsAdapters
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"
NS = APPROVAL_NAMESPACE
SK_TYPE = "sk-ssh-ed25519@openssh.com"
UP = 0x01
UV = 0x04
RP_ID = "localhost"
ORIGIN = "https://localhost:8443"
CLI = Principal(principal_id="p-cli", owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="devbox-1")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _s(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class _SshKey:
    def __init__(self, *, sk: bool = False) -> None:
        self.sk = sk
        self._key = Ed25519PrivateKey.generate()
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.blob = _s(SK_TYPE.encode()) + _s(raw) + _s(b"ssh:") if sk else _s(b"ssh-ed25519") + _s(raw)

    @property
    def public_line(self) -> str:
        key_type = SK_TYPE if self.sk else "ssh-ed25519"
        return f"{key_type} {base64.b64encode(self.blob).decode('ascii')} r2-fixture"

    def sign_raw_body(self, data: bytes, *, version: int = 1, flags: int = UP) -> bytes:
        signed = b"SSHSIG" + _s(NS.encode()) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(data).digest())
        if self.sk:
            h_ns, h_msg = hashlib.sha256(b"ssh:").digest(), hashlib.sha256(signed).digest()
            to_sign = h_ns + bytes([flags]) + struct.pack(">I", 7) + h_msg
            sig = _s(SK_TYPE.encode()) + _s(self._key.sign(to_sign)) + bytes([flags]) + struct.pack(">I", 7)
        else:
            sig = _s(b"ssh-ed25519") + _s(self._key.sign(signed))
        hdr = b"SSHSIG" + struct.pack(">I", version) + _s(self.blob) + _s(NS.encode()) + _s(b"")
        return hdr + _s(b"sha512") + _s(sig)

    def sign(self, data: bytes, *, flags: int = UP) -> bytes:
        return _armor(self.sign_raw_body(data, flags=flags))


def _armor(body: bytes) -> bytes:
    armored = base64.b64encode(body).decode("ascii")
    lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
    return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode()


class _Passkey:
    def __init__(self, label: bytes = b"cred-1") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        nums = self._key.public_key().public_numbers()
        self.credential_id = label
        self.cose_public_key: bytes = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def enrollment(self) -> SignerEnrollment:
        return SignerEnrollment(
            owner_id=OWNER,
            channel=ApprovalChannel.PASSKEY_UV,
            public_key=_b64u(self.cose_public_key),
            credential_id=_b64u(self.credential_id),
        )

    def enrollment_dict(self) -> dict[str, JsonValue]:
        return {
            "channel": ApprovalChannel.PASSKEY_UV.value,
            "public_key": _b64u(self.cose_public_key),
            "credential_id": _b64u(self.credential_id),
        }

    def assert_(self, challenge: bytes, *, sign_count: int) -> str:
        auth_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([UP | UV]) + struct.pack(">I", sign_count)
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": ORIGIN, "crossOrigin": False}
        ).encode()
        sig = self._key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return json.dumps(
            {
                "id": _b64u(self.credential_id),
                "rawId": _b64u(self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": _b64u(client_data),
                    "authenticatorData": _b64u(auth_data),
                    "signature": _b64u(sig),
                    "userHandle": None,
                },
            }
        )


def _ssh_keygen() -> Path:
    found = find_ssh_keygen()
    assert found is not None, "OpenSSH ssh-keygen is required for I3-1 regression checks"
    return found


@dataclass
class _StubVerification:
    assurance: AssuranceLevel
    new_sign_count: int


class _FixedCountWebAuthnVerifier:
    def __init__(self, new_sign_count: int) -> None:
        self._new_sign_count = new_sign_count

    def verify(
        self,
        message: ApprovalMessage,
        *,
        response_json: str,
        credential_id: bytes,
        credential_public_key: bytes,
        stored_sign_count: int,
    ) -> _StubVerification:
        del message, response_json, credential_id, credential_public_key, stored_sign_count
        return _StubVerification(AssuranceLevel.HUMAN_VERIFIED, self._new_sign_count)


@pytest.fixture
def rt_ctx(trusted_tmp: Path) -> Iterator[tuple[Runtime, FakeClock, OsAdapters]]:
    clock = FakeClock(datetime(2026, 11, 19, 6, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    rt = open_kernel_job_runtime(trusted_tmp / "root", os_, role="i3-1-r2-unit")
    try:
        yield rt, clock, os_
    finally:
        rt.close()


def _message_from_challenge(challenge: Mapping[str, Any]) -> ApprovalMessage:
    return ApprovalMessage(
        store_id=str(challenge["store_id"]),
        owner_id=OWNER,
        trust_generation=int(challenge["trust_generation"]),
        action=ApprovalAction(str(challenge["action"])),
        subject_id=str(challenge["subject_id"]),
        subject_revision=1,
        resource_digests=(ResourceDigest("CLAUDE.md", "sha256:" + "a" * 64),),
        target_files=(),
        risk_level=RiskLevel(str(challenge["risk_level"])),
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=str(challenge["nonce"]),
        expires_at=datetime.fromisoformat(str(challenge["expires_at"]).replace("Z", "+00:00")),
    )


def _challenge_from(res: dict[str, JsonValue]) -> dict[str, Any]:
    raw = res.get("challenge")
    assert isinstance(raw, dict)
    return dict(raw)


def _passkey_approval(
    passkey: _Passkey, signer_id: str, challenge: Mapping[str, Any], *, sign_count: int
) -> dict[str, JsonValue]:
    msg = _message_from_challenge(challenge)
    return {
        "message": msg.to_dict(),
        "channel": ApprovalChannel.PASSKEY_UV.value,
        "signer_id": signer_id,
        "response_json": passkey.assert_(msg.canonical_bytes(), sign_count=sign_count),
    }


def _ssh_approval(key: _SshKey, signer_id: str, challenge: Mapping[str, Any]) -> dict[str, JsonValue]:
    msg = _message_from_challenge(challenge)
    sig_b64 = base64.b64encode(key.sign(msg.canonical_bytes())).decode("ascii")
    return {
        "message": msg.to_dict(),
        "channel": ApprovalChannel.SSH_KEY.value,
        "signer_id": signer_id,
        "signature": sig_b64,
    }


def _count_immediate_writes(rt: Runtime, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    counts = [0]
    orig_immediate = rt.policy._immediate

    @contextmanager
    def _spy() -> Iterator[Any]:
        counts[0] += 1
        with orig_immediate() as db:
            yield db

    monkeypatch.setattr(rt.policy, "_immediate", _spy)
    return counts


# --- I3-1-R01 -------------------------------------------------------------------------------------------------------


def test_passkey_self_revocation_and_sign_count_are_atomic_and_strict(
    rt_ctx: tuple[Runtime, FakeClock, OsAdapters], trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt, _clock, _os = rt_ctx
    scratch = trusted_tmp / "scratch"
    scratch.mkdir()
    pk1 = _Passkey(b"cred-primary")
    pk_sync = _Passkey(b"cred-synced")
    s1 = rt.policy.enroll_first_signer(pk1.enrollment())

    svc = OperatorService(
        rt.policy,
        ssh_verifier=lambda: SshSigVerifier(ssh_keygen=_ssh_keygen(), scratch_dir=scratch),
        webauthn_verifier=WebAuthnApprovalVerifier(rp_id=RP_ID, origin=ORIGIN),
    )

    # 1. Enrolling s2 approved by s1 (sign_count 0 -> 1) must happen in a single write transaction.
    ch1 = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": pk_sync.enrollment_dict()}))
    writes = _count_immediate_writes(rt, monkeypatch)
    res_s2 = svc.handle(
        "/v2/operator/signer/enroll",
        CLI,
        {
            "enrollment": pk_sync.enrollment_dict(),
            "approval": _passkey_approval(pk1, s1.signer_id, ch1, sign_count=1),
        },
    )
    assert writes[0] == 1, f"sign_count persistence used {writes[0]} write transactions instead of 1"
    s2_signer = res_s2.get("signer")
    assert isinstance(s2_signer, dict)
    s2_id = str(s2_signer["signer_id"])
    s1_after = rt.policy.signer(s1.signer_id)
    assert s1_after is not None and s1_after.sign_count == 1

    # 2. Equal non-zero sign_count (1 -> 1) rejected strictly with zero partial commit.
    ssh_extra = _SshKey(sk=False)
    ssh_enroll_body: dict[str, JsonValue] = {
        "channel": ApprovalChannel.SSH_KEY.value,
        "public_key": ssh_extra.public_line,
    }
    ch_stale = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": ssh_enroll_body}))
    stale_nonce = str(ch_stale["nonce"])
    stale_svc = OperatorService(
        rt.policy,
        ssh_verifier=lambda: SshSigVerifier(ssh_keygen=_ssh_keygen(), scratch_dir=scratch),
        webauthn_verifier=_FixedCountWebAuthnVerifier(new_sign_count=1),
    )
    with pytest.raises(BrainError) as stale_exc:
        stale_svc.handle(
            "/v2/operator/signer/enroll",
            CLI,
            {
                "enrollment": ssh_enroll_body,
                "approval": _passkey_approval(pk1, s1.signer_id, ch_stale, sign_count=1),
            },
        )
    assert stale_exc.value.code is ErrorCode.UNAUTHENTICATED
    assert len(rt.policy.active_signers()) == 2
    s1_still = rt.policy.signer(s1.signer_id)
    assert s1_still is not None and s1_still.sign_count == 1
    with rt.policy._authority_tx() as db:
        nonce_row = db.execute("SELECT state FROM approval_nonce WHERE nonce = ?", (stale_nonce,)).fetchone()
    assert nonce_row is not None and nonce_row[0] == "pending"

    # Direct storage call with equal non-zero counter must also be rejected strictly.
    with pytest.raises(BrainError) as direct_exc:
        rt.policy.record_signer_sign_count(s1.signer_id, 1)
    assert direct_exc.value.code is ErrorCode.UNAUTHENTICATED

    # 3. Synced passkey (0 -> 0 -> 1) continues to work across approvals.
    ch_sync_0 = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": ssh_enroll_body}))
    svc.handle(
        "/v2/operator/signer/enroll",
        CLI,
        {
            "enrollment": ssh_enroll_body,
            "approval": _passkey_approval(pk_sync, s2_id, ch_sync_0, sign_count=0),
        },
    )
    ssh_other = _SshKey(sk=False)
    ssh_other_body: dict[str, JsonValue] = {
        "channel": ApprovalChannel.SSH_KEY.value,
        "public_key": ssh_other.public_line,
    }
    ch_sync_1 = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": ssh_other_body}))
    svc.handle(
        "/v2/operator/signer/enroll",
        CLI,
        {
            "enrollment": ssh_other_body,
            "approval": _passkey_approval(pk_sync, s2_id, ch_sync_1, sign_count=1),
        },
    )
    s2_after = rt.policy.signer(s2_id)
    assert s2_after is not None and s2_after.sign_count == 1

    # 4. Passkey self-revocation commits revocation AND updated sign_count atomically.
    ch_self = _challenge_from(svc.handle("/v2/operator/signer/revoke", CLI, {"signer_id": s1.signer_id}))
    rev_res = svc.handle(
        "/v2/operator/signer/revoke",
        CLI,
        {
            "signer_id": s1.signer_id,
            "approval": _passkey_approval(pk1, s1.signer_id, ch_self, sign_count=2),
        },
    )
    rev_signer = rev_res.get("signer")
    assert isinstance(rev_signer, dict) and rev_signer["signer_id"] == s1.signer_id
    s1_revoked = rt.policy.signer(s1.signer_id)
    assert s1_revoked is not None and s1_revoked.revoked is True and s1_revoked.sign_count == 2
    assert s1.signer_id not in {s.signer_id for s in rt.policy.active_signers()}


# --- I3-1-R03 -------------------------------------------------------------------------------------------------------


def test_find_ssh_keygen_resists_cwd_and_relative_path_hijack(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy_dir = trusted_tmp / "cwd-hijack"
    decoy_dir.mkdir()
    decoy_exe = decoy_dir / ("ssh-keygen.EXE" if sys.platform == "win32" else "ssh-keygen")
    decoy_exe.write_bytes(b"not-openssh")
    if sys.platform != "win32":
        decoy_exe.chmod(0o700)

    monkeypatch.chdir(decoy_dir)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "rel-bin", os.environ.get("PATH", "")]))
    found = find_ssh_keygen()
    assert found is not None
    assert found.resolve() != decoy_exe.resolve()
    if sys.platform == "win32":
        expected = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh-keygen.exe"
        assert os.path.normcase(str(found)) == os.path.normcase(str(expected))

    # Empty/relative PATH entries must not resolve to CWD/relative binaries when Windows System32 fallback is inactive.
    monkeypatch.setattr(sys, "platform", "linux")
    (decoy_dir / "ssh-keygen").write_bytes(b"#!/bin/sh\n")
    if os.name != "nt":
        (decoy_dir / "ssh-keygen").chmod(0o700)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "rel-bin"]))
    assert find_ssh_keygen() is None


def test_operator_entry_and_ssh_verifier_verify_owner_only_scratch_dir(
    rt_ctx: tuple[Runtime, FakeClock, OsAdapters], trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt, _clock, os_ = rt_ctx
    ssh_key = _SshKey(sk=False)
    signer = rt.policy.enroll_first_signer(
        SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=ssh_key.public_line)
    )
    target = _SshKey(sk=False)
    target_body: dict[str, JsonValue] = {"channel": ApprovalChannel.SSH_KEY.value, "public_key": target.public_line}

    seen_scratch: list[Path] = []
    orig_init = SshSigVerifier.__init__

    def _spy_init(self: SshSigVerifier, *args: Any, **kwargs: Any) -> None:
        orig_init(self, *args, **kwargs)
        seen_scratch.append(self._scratch_dir)

    monkeypatch.setattr(SshSigVerifier, "__init__", _spy_init)
    svc = build_operator_service(rt.policy)
    ch1 = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": target_body}))
    svc.handle(
        "/v2/operator/signer/enroll",
        CLI,
        {"enrollment": target_body, "approval": _ssh_approval(ssh_key, signer.signer_id, ch1)},
    )
    assert len(seen_scratch) == 1
    scratch_dir = seen_scratch[0]
    assert scratch_dir != system_temp_dir(), "operator_entry must not pass raw unverified system_temp_dir()"
    os_.paths.reject_links(scratch_dir)
    assert os_.permissions.check_ancestors(scratch_dir) == []
    assert os_.permissions.object_problems(scratch_dir) == []

    # Symlinked/junctioned scratch_dir must be refused both directly and when operator_entry resolves env scratch.
    real_target = trusted_tmp / "real-scratch-target"
    real_target.mkdir()
    sym_scratch = trusted_tmp / "sym-scratch"
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(real_target), str(sym_scratch))
    else:
        sym_scratch.symlink_to(real_target, target_is_directory=True)
    msg = _message_from_challenge(ch1)
    with pytest.raises(BrainError) as sym_exc:
        SshSigVerifier(ssh_keygen=_ssh_keygen(), scratch_dir=sym_scratch).verify(
            msg,
            channel=ApprovalChannel.SSH_KEY,
            public_key=ssh_key.public_line,
            signature=ssh_key.sign(msg.canonical_bytes()),
        )
    assert sym_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INSECURE_PERMISSIONS, ErrorCode.UNAUTHENTICATED}

    monkeypatch.setenv("LOCALAPPDATA", str(sym_scratch))
    monkeypatch.setenv("TEMP", str(sym_scratch))
    monkeypatch.setenv("TMP", str(sym_scratch))
    ch2 = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": target_body}))
    svc_sym = build_operator_service(rt.policy)
    with pytest.raises(BrainError):
        svc_sym.handle(
            "/v2/operator/signer/enroll",
            CLI,
            {"enrollment": target_body, "approval": _ssh_approval(ssh_key, signer.signer_id, ch2)},
        )


# --- I3-1-R05 & I3-1-N1 ---------------------------------------------------------------------------------------------


def test_strict_validation_and_bounds_on_enrollments_keys_targets_and_approvals(
    rt_ctx: tuple[Runtime, FakeClock, OsAdapters], trusted_tmp: Path
) -> None:
    rt, _clock, _os = rt_ctx
    ssh_key = _SshKey(sk=False)
    signer = rt.policy.enroll_first_signer(
        SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=ssh_key.public_line)
    )
    scratch = trusted_tmp / "scratch"
    scratch.mkdir()
    svc = OperatorService(
        rt.policy,
        ssh_verifier=lambda: SshSigVerifier(ssh_keygen=_ssh_keygen(), scratch_dir=scratch),
    )

    # Strict base64url alphabet and decoded byte limits for Passkey enrollments and _b64(urlsafe=True).
    valid_pk = _b64u(_Passkey().cose_public_key)
    valid_cred = _b64u(b"ok-cred")
    for bad in ("AQ!@#I", "AQ+/", "A B"):
        with pytest.raises(BrainError) as b64_exc:
            app_approvals._b64(bad, urlsafe=True)
        assert b64_exc.value.code is ErrorCode.INVALID_INPUT
        for field_kwargs in (
            {"public_key": bad, "credential_id": valid_cred},
            {"public_key": valid_pk, "credential_id": bad},
        ):
            with pytest.raises(BrainError) as enr_exc:
                SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.PASSKEY_UV, **field_kwargs)
            assert enr_exc.value.code is ErrorCode.INVALID_INPUT
            with pytest.raises(BrainError) as svc_exc:
                svc.handle(
                    "/v2/operator/signer/enroll",
                    CLI,
                    {"enrollment": {"channel": ApprovalChannel.PASSKEY_UV.value, **field_kwargs}},
                )
            assert svc_exc.value.code is ErrorCode.INVALID_INPUT

    for oversize in (
        {"public_key": valid_pk, "credential_id": _b64u(b"k" * 1025)},
        {"public_key": _b64u(b"p" * 4097), "credential_id": valid_cred},
    ):
        with pytest.raises(BrainError) as cap_exc:
            SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.PASSKEY_UV, **oversize)
        assert cap_exc.value.code is ErrorCode.INVALID_INPUT

    # parse_ssh_public_key must enforce strict lowercase ASCII key_type format even if lengths match.
    for bad_kt in ("SSH-ED25519", "ssh_ed25519!", "\u00e9"):
        raw_blob = _s(bad_kt.encode("ascii", errors="replace")) + _s(b"\x01" * 32)
        with pytest.raises(BrainError) as kt_exc:
            parse_ssh_public_key(f"{bad_kt} {base64.b64encode(raw_blob).decode('ascii')}")
        assert kt_exc.value.code is ErrorCode.INVALID_INPUT

    # TargetFile must reject embedded NUL in target_physical_id.
    with pytest.raises(BrainError) as nul_exc:
        TargetFile(
            root_path=str(trusted_tmp),
            normalized_rel_path="notes.md",
            parent_physical_id="parent-1",
            target_physical_id="file\x001",
            original_digest="sha256:" + "a" * 64,
            original_present=True,
        )
    assert nul_exc.value.code is ErrorCode.INVALID_INPUT

    # OperatorService._verified must reject unknown keys in the approval object without consuming the nonce.
    target = _SshKey(sk=False)
    target_body: dict[str, JsonValue] = {"channel": ApprovalChannel.SSH_KEY.value, "public_key": target.public_line}
    ch = _challenge_from(svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": target_body}))
    bad_approval = {**_ssh_approval(ssh_key, signer.signer_id, ch), "unexpected_field": True}
    with pytest.raises(BrainError) as extra_exc:
        svc.handle("/v2/operator/signer/enroll", CLI, {"enrollment": target_body, "approval": bad_approval})
    assert extra_exc.value.code is ErrorCode.INVALID_INPUT
    with rt.policy._authority_tx() as db:
        row = db.execute("SELECT state FROM approval_nonce WHERE nonce = ?", (ch["nonce"],)).fetchone()
    assert row is not None and row[0] == "pending"


def test_consume_approval_clock_rollback_and_sk_flags_strict_sshsig_bounds(
    rt_ctx: tuple[Runtime, FakeClock, OsAdapters],
) -> None:
    rt, clock, _os = rt_ctx
    ssh_key = _SshKey(sk=False)
    signer = rt.policy.enroll_first_signer(
        SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=ssh_key.public_line)
    )
    t0 = clock.now()

    def _msg_at_t0() -> ApprovalMessage:
        issued = rt.policy.issue_nonce(action=ApprovalAction.APPROVE, subject_id="prop-rb", risk_level=RiskLevel.HIGH)
        return _message_from_challenge(
            {
                "store_id": rt.policy.store_id,
                "trust_generation": issued.trust_generation,
                "action": issued.action.value,
                "subject_id": issued.subject_id,
                "risk_level": issued.risk_level.value,
                "nonce": issued.nonce,
                "expires_at": issued.expires_at.isoformat(),
            }
        )

    # Exact now == issued_at succeeds.
    m_equal = _msg_at_t0()
    receipt = rt.policy.consume_approval(m_equal, signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    assert receipt.message.nonce == m_equal.nonce

    # Clock rollback (now < issued_at) must fail UNAUTHENTICATED without consuming nonce.
    m_rollback = _msg_at_t0()
    clock.set(t0 - timedelta(seconds=1))
    with pytest.raises(BrainError) as rb_exc:
        rt.policy.consume_approval(m_rollback, signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    assert rb_exc.value.code is ErrorCode.UNAUTHENTICATED

    # _sk_flags must reject SSHSIG version != 1 and trailing bytes after the outer signature blob.
    sk_key = _SshKey(sk=True)
    payload = m_rollback.canonical_bytes()
    valid_sig = sk_key.sign(payload, flags=UP)
    assert ssh_sig._sk_flags(valid_sig) == UP

    bad_version = _armor(sk_key.sign_raw_body(payload, version=2, flags=UP))
    with pytest.raises(BrainError) as ver_exc:
        ssh_sig._sk_flags(bad_version)
    assert ver_exc.value.code is ErrorCode.UNAUTHENTICATED

    trailing = _armor(sk_key.sign_raw_body(payload, version=1, flags=UP) + b"\x99")
    with pytest.raises(BrainError) as trail_exc:
        ssh_sig._sk_flags(trailing)
    assert trail_exc.value.code is ErrorCode.UNAUTHENTICATED
