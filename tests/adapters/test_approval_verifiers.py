"""I3-1 oracle: SSH (``ssh-keygen -Y verify``) and WebAuthn approval verifiers.

Requirement sources: spec rev 22 §11.3 (channel table, "Xác minh": WebAuthn challenge/origin/RP ID/UV/sign count via
a maintained library; SSH via ``ssh-keygen -Y verify`` with a brain-managed ``allowed_signers`` and namespace
``ensemble-brain-approval``), §20 cases 16, 17; ledger §2.1 (sign count rule, I3-0-N1); owner O12 decision
(fixture-verified channels: OpenSSH test keys and a synthetic controlled WebAuthn authenticator, ``kind="fixture"``).

SSH signatures are synthesized here with ``cryptography`` in the documented SSHSIG / ``sk-ssh-ed25519`` wire format;
``test_fixture_signatures_are_accepted_by_real_ssh_keygen`` proves the fixture against the real OpenSSH binary,
independently of the product adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.auth.ssh_sig import SshSigVerifier
from superbrain.adapters.auth.webauthn_verifier import WebAuthnApprovalVerifier
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    RecoveryScope,
    RiskLevel,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ResourceDigest

NS = "ensemble-brain-approval"
SK_TYPE = "sk-ssh-ed25519@openssh.com"
UP = 0x01
UV = 0x04
RP_ID = "localhost"
ORIGIN = "https://localhost:8443"


def _message(subject: str = "proposal-0001", nonce: str = "nonce-0001") -> ApprovalMessage:
    return ApprovalMessage(
        store_id="store-i31-0001",
        owner_id="dan",
        trust_generation=1,
        action=ApprovalAction.APPROVE,
        subject_id=subject,
        subject_revision=1,
        resource_digests=(ResourceDigest("CLAUDE.md", "sha256:" + "a" * 64),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=nonce,
        expires_at=datetime(2026, 11, 19, 6, 10, tzinfo=UTC),
    )


# --- SSHSIG fixture ------------------------------------------------------------------------------------------------


def _s(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class SshTestKey:
    """An ed25519 (``ssh_key``) or ``sk-ssh-ed25519`` (FIDO, synthetic authenticator) OpenSSH test key."""

    def __init__(self, *, sk: bool) -> None:
        self.sk = sk
        self._key = Ed25519PrivateKey.generate()
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.blob = _s(SK_TYPE.encode()) + _s(raw) + _s(b"ssh:") if sk else _s(b"ssh-ed25519") + _s(raw)

    @property
    def public_line(self) -> str:
        key_type = SK_TYPE if self.sk else "ssh-ed25519"
        return f"{key_type} {base64.b64encode(self.blob).decode('ascii')} i3-1-fixture"

    def sign(self, data: bytes, *, namespace: str = NS, flags: int = UP, counter: int = 7) -> bytes:
        signed = b"SSHSIG" + _s(namespace.encode()) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(data).digest())
        if self.sk:
            to_sign = (
                hashlib.sha256(b"ssh:").digest()
                + bytes([flags])
                + struct.pack(">I", counter)
                + hashlib.sha256(signed).digest()
            )
            sig = _s(SK_TYPE.encode()) + _s(self._key.sign(to_sign)) + bytes([flags]) + struct.pack(">I", counter)
        else:
            sig = _s(b"ssh-ed25519") + _s(self._key.sign(signed))
        body = b"SSHSIG" + struct.pack(">I", 1) + _s(self.blob) + _s(namespace.encode()) + _s(b"")
        body += _s(b"sha512") + _s(sig)
        armored = base64.b64encode(body).decode("ascii")
        lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
        return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode()


def _ssh_keygen() -> Path:
    found = shutil.which("ssh-keygen")
    if found is None and sys.platform == "win32":
        candidate = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")
        found = str(candidate) if candidate.is_file() else None
    assert found is not None, "OpenSSH ssh-keygen is required for the I3-1 SSH verifier gate"
    return Path(found)


@pytest.fixture
def ssh_scratch(trusted_tmp: Path) -> Path:
    scratch = trusted_tmp / "ssh-verify-scratch"
    scratch.mkdir()
    return scratch


@pytest.fixture
def ssh_verifier(ssh_scratch: Path) -> SshSigVerifier:
    return SshSigVerifier(ssh_keygen=_ssh_keygen(), scratch_dir=ssh_scratch)


def _assert_refused(exc: pytest.ExceptionInfo[BrainError], *codes: ErrorCode) -> None:
    allowed = codes or (ErrorCode.UNAUTHENTICATED,)
    assert exc.value.code in allowed, exc.value


def test_fixture_signatures_are_accepted_by_real_ssh_keygen(trusted_tmp: Path) -> None:
    """Oracle self-check: the synthesized SSHSIG bytes verify with OpenSSH itself, and a tampered message does not."""
    data = _message().canonical_bytes()
    for sk in (False, True):
        key = SshTestKey(sk=sk)
        allowed = trusted_tmp / f"allowed-{sk}"
        allowed.write_text(f'signer namespaces="{NS}" {key.public_line}\n', encoding="ascii", newline="\n")
        signature = trusted_tmp / f"sig-{sk}"
        signature.write_bytes(key.sign(data))
        cmd = [str(_ssh_keygen()), "-Y", "verify", "-f", str(allowed), "-I", "signer", "-n", NS, "-s", str(signature)]
        good = subprocess.run(cmd, input=data, capture_output=True, check=False, timeout=30)
        assert good.returncode == 0, good.stderr
        bad = subprocess.run(cmd, input=data + b" ", capture_output=True, check=False, timeout=30)
        assert bad.returncode != 0


def test_ssh_key_signature_is_key_authorization(ssh_verifier: SshSigVerifier, ssh_scratch: Path) -> None:
    """Case 17: an ``ssh_key`` approval is recorded as ``key_authorization``."""
    key = SshTestKey(sk=False)
    message = _message()
    signature = key.sign(message.canonical_bytes())
    assurance = ssh_verifier.verify(
        message, channel=ApprovalChannel.SSH_KEY, public_key=key.public_line, signature=signature
    )
    assert assurance is AssuranceLevel.KEY_AUTHORIZATION
    assert APPROVAL_NAMESPACE == NS
    assert list(ssh_scratch.iterdir()) == [], "verifier left allowed_signers/signature files behind"


def test_ssh_key_rejects_tampered_message_wrong_key_and_wrong_namespace(ssh_verifier: SshSigVerifier) -> None:
    key = SshTestKey(sk=False)
    other = SshTestKey(sk=False)
    message = _message()
    data = message.canonical_bytes()
    cases = {
        "message_for_other_subject": (key, key.sign(_message(subject="proposal-0002").canonical_bytes())),
        "message_with_other_nonce": (key, key.sign(_message(nonce="nonce-0002").canonical_bytes())),
        "wrong_key": (other, key.sign(data)),
        "wrong_namespace": (key, key.sign(data, namespace="git")),
    }
    for name, (presented_key, signature) in cases.items():
        with pytest.raises(BrainError) as exc:
            ssh_verifier.verify(
                message, channel=ApprovalChannel.SSH_KEY, public_key=presented_key.public_line, signature=signature
            )
        assert exc.value.code is ErrorCode.UNAUTHENTICATED, name


def test_ssh_sk_requires_presence_and_sk_verified_requires_verification(ssh_verifier: SshSigVerifier) -> None:
    key = SshTestKey(sk=True)
    message = _message()
    data = message.canonical_bytes()

    def verify(channel: ApprovalChannel, flags: int) -> AssuranceLevel:
        signature = key.sign(data, flags=flags)
        return ssh_verifier.verify(message, channel=channel, public_key=key.public_line, signature=signature)

    assert verify(ApprovalChannel.SSH_SK, UP) is AssuranceLevel.HUMAN_PRESENT
    assert verify(ApprovalChannel.SSH_SK_VERIFIED, UP | UV) is AssuranceLevel.HUMAN_VERIFIED
    with pytest.raises(BrainError) as no_presence:
        verify(ApprovalChannel.SSH_SK, 0x00)
    _assert_refused(no_presence)
    with pytest.raises(BrainError) as presence_only:
        verify(ApprovalChannel.SSH_SK_VERIFIED, UP)
    _assert_refused(presence_only)
    with pytest.raises(BrainError) as tampered:
        ssh_verifier.verify(
            message, channel=ApprovalChannel.SSH_SK, public_key=key.public_line, signature=key.sign(data + b"x")
        )
    _assert_refused(tampered)


def test_ssh_channel_and_key_type_must_agree(ssh_verifier: SshSigVerifier) -> None:
    plain = SshTestKey(sk=False)
    message = _message()
    signature = plain.sign(message.canonical_bytes())
    for channel in (ApprovalChannel.SSH_SK, ApprovalChannel.SSH_SK_VERIFIED):
        with pytest.raises(BrainError) as exc:
            ssh_verifier.verify(message, channel=channel, public_key=plain.public_line, signature=signature)
        _assert_refused(exc, ErrorCode.UNAUTHENTICATED, ErrorCode.INVALID_INPUT)
    for channel in (ApprovalChannel.PASSKEY_UV, ApprovalChannel.TERMINAL):
        with pytest.raises(BrainError) as wrong_channel:
            ssh_verifier.verify(message, channel=channel, public_key=plain.public_line, signature=signature)
        _assert_refused(wrong_channel, ErrorCode.INVALID_INPUT)
    with pytest.raises(BrainError) as garbage:
        ssh_verifier.verify(
            message, channel=ApprovalChannel.SSH_KEY, public_key=plain.public_line, signature=b"not a signature"
        )
    _assert_refused(garbage, ErrorCode.UNAUTHENTICATED, ErrorCode.INVALID_INPUT)


# --- synthetic WebAuthn authenticator ------------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SyntheticPasskey:
    """A controlled ES256 authenticator producing ``navigator.credentials.get`` assertion JSON (``kind="fixture"``)."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.credential_id = b"i3-1-synthetic-credential"
        self.cose_public_key: bytes = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        )

    def assert_(
        self,
        challenge: bytes,
        *,
        flags: int = UP | UV,
        sign_count: int = 0,
        rp_id: str = RP_ID,
        origin: str = ORIGIN,
        credential_id: bytes | None = None,
        tamper: bool = False,
    ) -> str:
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": origin, "crossOrigin": False}
        ).encode()
        signature = self._key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            auth_data = auth_data[:-1] + bytes([auth_data[-1] ^ 0x01])
        cred = credential_id if credential_id is not None else self.credential_id
        return json.dumps(
            {
                "id": _b64u(cred),
                "rawId": _b64u(cred),
                "type": "public-key",
                "response": {
                    "clientDataJSON": _b64u(client_data),
                    "authenticatorData": _b64u(auth_data),
                    "signature": _b64u(signature),
                    "userHandle": None,
                },
            }
        )


@pytest.fixture
def passkey() -> SyntheticPasskey:
    return SyntheticPasskey()


@pytest.fixture
def webauthn_verifier() -> WebAuthnApprovalVerifier:
    return WebAuthnApprovalVerifier(rp_id=RP_ID, origin=ORIGIN)


def _webauthn(
    verifier: WebAuthnApprovalVerifier, passkey: SyntheticPasskey, message: ApprovalMessage, response: str, stored: int
) -> tuple[AssuranceLevel, int]:
    result = verifier.verify(
        message,
        response_json=response,
        credential_id=passkey.credential_id,
        credential_public_key=passkey.cose_public_key,
        stored_sign_count=stored,
    )
    return result.assurance, result.new_sign_count


def test_passkey_uv_challenge_is_the_canonical_approval_message(
    webauthn_verifier: WebAuthnApprovalVerifier, passkey: SyntheticPasskey
) -> None:
    message = _message()
    response = passkey.assert_(message.canonical_bytes(), sign_count=4)
    assert _webauthn(webauthn_verifier, passkey, message, response, stored=3) == (AssuranceLevel.HUMAN_VERIFIED, 4)


def test_passkey_rejects_missing_uv_wrong_origin_wrong_rp_and_other_message(
    webauthn_verifier: WebAuthnApprovalVerifier, passkey: SyntheticPasskey
) -> None:
    """Case 17: WebAuthn without UV, with a wrong origin or a wrong RP ID is refused; case 16: other subject."""
    message = _message()
    challenge = message.canonical_bytes()
    cases = {
        "uv_false": passkey.assert_(challenge, flags=UP),
        "wrong_origin": passkey.assert_(challenge, origin="https://evil.example:8443"),
        "ip_origin": passkey.assert_(challenge, origin="https://127.0.0.1:8443"),
        "wrong_rp_id": passkey.assert_(challenge, rp_id="evil.example"),
        "other_subject": passkey.assert_(_message(subject="proposal-0002").canonical_bytes()),
        "other_nonce": passkey.assert_(_message(nonce="nonce-0002").canonical_bytes()),
        "tampered": passkey.assert_(challenge, tamper=True),
        "other_credential": passkey.assert_(challenge, credential_id=b"someone-else"),
    }
    for name, response in cases.items():
        with pytest.raises(BrainError) as exc:
            _webauthn(webauthn_verifier, passkey, message, response, stored=0)
        assert exc.value.code is ErrorCode.UNAUTHENTICATED, name


def test_passkey_sign_count_must_increase_once_either_counter_is_nonzero(
    webauthn_verifier: WebAuthnApprovalVerifier, passkey: SyntheticPasskey
) -> None:
    """Ledger §2.1/I3-0-N1: strictly increasing when stored or presented counter > 0; constant 0 (synced) allowed."""
    message = _message()
    challenge = message.canonical_bytes()
    assert _webauthn(webauthn_verifier, passkey, message, passkey.assert_(challenge, sign_count=0), stored=0) == (
        AssuranceLevel.HUMAN_VERIFIED,
        0,
    )
    assert _webauthn(webauthn_verifier, passkey, message, passkey.assert_(challenge, sign_count=1), stored=0)[1] == 1
    for presented, stored in ((5, 5), (4, 5), (0, 5)):
        with pytest.raises(BrainError) as exc:
            _webauthn(webauthn_verifier, passkey, message, passkey.assert_(challenge, sign_count=presented), stored)
        assert exc.value.code is ErrorCode.UNAUTHENTICATED, (presented, stored)
