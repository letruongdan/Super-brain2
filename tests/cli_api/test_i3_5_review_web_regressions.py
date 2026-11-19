"""I3-5 Round-2 regression tests for ``review_web``, ``ReviewSession``, and localhost WebAuthn verifier.

Requirement sources: ``i3-5/review.md`` findings ``I3-5-R01``, ``I3-5-R05``, and ``I3-5-N1``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.application.review_session import ReviewOperatorBackendPort, ReviewSession
from superbrain.composition.operator_entry import build_operator_service
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.proposals import ManagedFormat
from superbrain.review_web.server import REVIEW_WEB_CSP, ReviewWebServer
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
UP = 0x01
UV = 0x04


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_http(
    port: int,
    *,
    method: str = "GET",
    target: str = "/",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    raw_head: bytes | None = None,
) -> tuple[int, dict[str, str], str | None, bytes]:
    if raw_head is not None:
        wire = raw_head + body
    else:
        lines = [f"{method} {target} HTTP/1.1".encode("ascii")]
        for k, v in headers or []:
            lines.append(f"{k}: {v}".encode("latin-1"))
        if body and not any(k.lower() == "content-length" for k, _ in (headers or [])):
            lines.append(f"Content-Length: {len(body)}".encode("ascii"))
        wire = b"\r\n".join(lines) + b"\r\n\r\n" + body
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
        sock.settimeout(3.0)
        sock.sendall(wire)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head_raw, _, rest = buf.partition(b"\r\n\r\n")
        head_lines = head_raw.decode("iso-8859-1").split("\r\n")
        status = int(head_lines[0].split(" ", 2)[1])
        hdr_map: dict[str, str] = {}
        set_cookie: str | None = None
        for line in head_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                lk = k.strip().lower()
                if lk == "set-cookie":
                    set_cookie = v.strip()
                hdr_map[lk] = v.strip()
        cl = int(hdr_map["content-length"]) if "content-length" in hdr_map else None
        chunks = [rest]
        total = len(rest)
        while True:
            if cl is not None and total >= cl:
                break
            more = sock.recv(4096)
            if not more:
                break
            chunks.append(more)
            total += len(more)
    raw_body = b"".join(chunks)
    if cl is not None:
        raw_body = raw_body[:cl]
    return status, hdr_map, set_cookie, raw_body


class _StubBackend(ReviewOperatorBackendPort):
    """Minimal in-memory ``ReviewOperatorBackendPort`` for fast ``ReviewWebServer`` / ``ReviewSession`` tests."""

    def __init__(self, proposal_id: str = "prop-r2") -> None:
        self.proposal_id = proposal_id
        self.signer = SignerRecord(
            signer_id="sig-pk-1",
            owner_id=OWNER,
            channel=ApprovalChannel.PASSKEY_UV,
            key_digest=digest_bytes(b"pk-1"),
            tofu=False,
            revoked=False,
            credential_id=_b64u(b"cred-r2"),
        )
        self.calls: list[dict[str, Any]] = []

    def list_signers(self) -> tuple[SignerRecord, ...]:
        return (self.signer,)

    def show_proposal(self, proposal_id: str) -> Mapping[str, JsonValue]:
        return {
            "proposal_id": proposal_id,
            "kind": "bootstrap",
            "reason": "r2 test",
            "status": "pending",
            "subject_revision": 1,
            "risk_level": "high",
            "targets": [{"rel_path": "CLAUDE.md", "slice_id": "s1"}],
        }

    def request_challenge(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        recovery_scope: RecoveryScope,
    ) -> tuple[ApprovalMessage, Mapping[str, JsonValue]]:
        msg = ApprovalMessage(
            store_id="01920000-0000-7000-8000-000000000001",
            owner_id=OWNER,
            trust_generation=1,
            action=action,
            subject_id=proposal_id,
            subject_revision=1,
            resource_digests=(),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=recovery_scope,
            nonce="nonce-r2-" + action.value,
            expires_at=datetime(2026, 11, 19, 13, 0, tzinfo=UTC),
        )
        return msg, self.show_proposal(proposal_id)

    def submit_approval(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        raw_approval: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        self.calls.append({"proposal_id": proposal_id, "action": action, "approval": dict(raw_approval)})
        return {"ok": True}


def _redeem_session(port: int, origin: str, token: str) -> tuple[str, str]:
    hdrs = [("Host", f"localhost:{port}"), ("Origin", origin), ("Content-Type", "application/json")]
    st, _, set_cookie, body = _raw_http(
        port, method="POST", target="/api/session", headers=hdrs, body=json.dumps({"token": token}).encode("utf-8")
    )
    assert st == 200 and set_cookie is not None
    return set_cookie.split(";", 1)[0], str(json.loads(body)["data"]["csrf_token"])


class _SelectOptionParser(HTMLParser):
    """Extract ``<option>`` value and ``selected`` flags from ``<select id="action-select">``."""

    def __init__(self) -> None:
        super().__init__()
        self.in_select = False
        self.options: list[tuple[str | None, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "select" and attr_map.get("id") == "action-select":
            self.in_select = True
        elif tag == "option" and self.in_select:
            self.options.append((attr_map.get("value"), "selected" in attr_map))

    def handle_endtag(self, tag: str) -> None:
        if tag == "select" and self.in_select:
            self.in_select = False


def test_r01_non_object_client_data_json_and_concurrent_token_redeem() -> None:
    """I3-5-R01: non-object clientDataJSON returns 401 JSON (never crashes thread) & token redeem is atomic."""
    backend = _StubBackend()
    session = ReviewSession(backend=backend, proposal_id=backend.proposal_id, expected_origin="http://localhost:0")
    with ReviewWebServer(session, host="127.0.0.1", port=0) as srv:
        session.bind_origin(srv.origin)
        cookie, csrf = _redeem_session(srv.port, srv.origin, session.bootstrap_token)
        msg, _ = backend.request_challenge(
            proposal_id=backend.proposal_id, action=ApprovalAction.APPROVE, recovery_scope=RecoveryScope.NONE
        )
        hdrs = [
            ("Host", f"localhost:{srv.port}"),
            ("Origin", srv.origin),
            ("Cookie", cookie),
            ("X-CSRF-Token", csrf),
            ("Content-Type", "application/json"),
        ]
        for non_obj in (b"[]", b"null", b'"just-a-string"', b"123"):
            bad_resp_json = json.dumps({"response": {"clientDataJSON": _b64u(non_obj)}})
            body = json.dumps(
                {
                    "action": "approve",
                    "signer_id": backend.signer.signer_id,
                    "challenge_message": msg.to_dict(),
                    "response_json": bad_resp_json,
                }
            ).encode("utf-8")
            st, r_hdrs, _, r_body = _raw_http(srv.port, method="POST", target="/api/submit", headers=hdrs, body=body)
            assert st == 401
            assert r_hdrs.get("content-security-policy") == REVIEW_WEB_CSP
            assert r_hdrs.get("x-content-type-options") == "nosniff"
            assert json.loads(r_body)["error"]["code"] == ErrorCode.UNAUTHENTICATED.value
            with pytest.raises(BrainError) as direct_err:
                session.submit_passkey(
                    action=ApprovalAction.APPROVE,
                    signer_id=backend.signer.signer_id,
                    challenge_message=msg.to_dict(),
                    response_json=bad_resp_json,
                )
            assert direct_err.value.code is ErrorCode.UNAUTHENTICATED

        # Server must stay completely healthy after handling malformed clientDataJSON payloads.
        st_alive, _, _, _ = _raw_http(srv.port, target="/review", headers=[("Host", f"localhost:{srv.port}")])
        assert st_alive == 200
    assert backend.calls == []

    # Concurrent bootstrap token redemption under barrier: strictly 1 winner per session.
    for _ in range(15):
        conc_sess = ReviewSession(backend=backend, proposal_id="prop-c", expected_origin="http://localhost:8080")
        barrier = threading.Barrier(6)
        winners: list[tuple[str, str]] = []
        denied: list[ErrorCode] = []
        lock = threading.Lock()

        def _race(
            s: ReviewSession = conc_sess,
            b: threading.Barrier = barrier,
            lk: threading.Lock = lock,
            win: list[tuple[str, str]] = winners,
            err_list: list[ErrorCode] = denied,
        ) -> None:
            b.wait(timeout=3.0)
            try:
                res = s.redeem_bootstrap_token(s.bootstrap_token)
            except BrainError as err:
                with lk:
                    err_list.append(err.code)
            else:
                with lk:
                    win.append(res)

        threads = [threading.Thread(target=_race) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
        assert len(winners) == 1 and denied == [ErrorCode.UNAUTHENTICATED] * 5


def test_r01_http_parser_rejects_colon_space_bad_content_length_and_n1_max_body() -> None:
    """I3-5-R01 & N1: strict RFC 9110/9112 headers/Content-Length (400) + configurable max_body_bytes (413)."""
    backend = _StubBackend()
    session = ReviewSession(backend=backend, proposal_id=backend.proposal_id, expected_origin="http://localhost:0")
    for bad_limit in (0, -1, True):
        with pytest.raises(BrainError) as limit_err:
            ReviewWebServer(session, host="127.0.0.1", port=0, max_body_bytes=bad_limit)
        assert limit_err.value.code is ErrorCode.INVALID_INPUT

    with ReviewWebServer(session, host="127.0.0.1", port=0, max_body_bytes=64) as srv:
        session.bind_origin(srv.origin)
        for bad_hdr_wire in (
            f"GET /review HTTP/1.1\r\nHost : localhost:{srv.port}\r\n\r\n".encode("ascii"),
            f"GET /review HTTP/1.1\r\nHost: localhost:{srv.port}\r\nX-Space\t: 1\r\n\r\n".encode("ascii"),
        ):
            st, r_hdrs, _, _ = _raw_http(srv.port, raw_head=bad_hdr_wire)
            assert st == 400 and r_hdrs.get("x-content-type-options") == "nosniff"

        for bad_cl in ("+2", "0_2", "-1", "2a", " 2 "):
            head = (
                f"POST /api/session HTTP/1.1\r\n"
                f"Host: localhost:{srv.port}\r\n"
                f"Origin: {srv.origin}\r\n"
                f"Content-Length: {bad_cl}\r\n\r\n"
            ).encode("ascii")
            st_cl, r_hdrs_cl, _, _ = _raw_http(srv.port, raw_head=head, body=b"{}")
            assert st_cl == 400 and r_hdrs_cl.get("x-content-type-options") == "nosniff", (bad_cl, st_cl)

        # N1: custom max_body_bytes=64 enforces 413 on 128-byte body.
        st_big, _, _, _ = _raw_http(
            srv.port,
            method="POST",
            target="/api/session",
            headers=[("Host", f"localhost:{srv.port}"), ("Origin", srv.origin), ("Content-Type", "application/json")],
            body=b'{"token":"' + b"a" * 116 + b'"}',
        )
        assert st_big == 413


def test_r01_localhost_webauthn_verifier_rejects_trailing_newline_and_non_dict_cdj(trusted_tmp: Path) -> None:
    """I3-5-R01: ``_LocalhostWebAuthnVerifier`` rejects ``http://localhost:8080\\n`` & list ``clientDataJSON``."""
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    cred_id = b"r2-nl-cred"
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    data_root, checkout = trusted_tmp / "data", trusted_tmp / "checkout"
    checkout.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(checkout)
    (checkout / "CLAUDE.md").write_bytes(b"# Hi\n")

    rt = open_kernel_job_runtime(data_root, os_, role="r2-verifier-test")
    try:
        signer = rt.policy.enroll_first_signer(
            SignerEnrollment(
                owner_id=OWNER,
                channel=ApprovalChannel.PASSKEY_UV,
                public_key=_b64u(cose),
                credential_id=_b64u(cred_id),
            )
        )
        cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="cli", machine_id="m-r2")
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            PolicyApplyAuthority(rt.policy),
            os_,
            data_root=data_root,
            home_dir=trusted_tmp / "home",
            config_merger=SharedConfigMergerAdapter(),
        )
        prop = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="nl origin test",
            resources=[RiskResource(component="c2")],
            targets=[TargetWriteInput(checkout, "CLAUDE.md", b"# Changed\n", ManagedFormat.RAW, "r1")],
        )
        op = build_operator_service(rt.policy, os_=os_, review_apply=svc)
        ch = op.handle("/v2/operator/proposal/approve", cli.principal, {"proposal_id": prop.proposal_id})["challenge"]
        assert isinstance(ch, Mapping)
        msg = ApprovalMessage.from_dict(ch)
        ch_b = msg.canonical_bytes()

        def _sign(origin: str, sign_count: int) -> str:
            auth = hashlib.sha256(b"localhost").digest() + bytes([UP | UV]) + struct.pack(">I", sign_count)
            cdj = json.dumps(
                {"type": "webauthn.get", "challenge": _b64u(ch_b), "origin": origin, "crossOrigin": False}
            ).encode("utf-8")
            sig = key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
            return json.dumps(
                {
                    "id": _b64u(cred_id),
                    "rawId": _b64u(cred_id),
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": _b64u(cdj),
                        "authenticatorData": _b64u(auth),
                        "signature": _b64u(sig),
                        "userHandle": None,
                    },
                }
            )

        with pytest.raises(BrainError) as nl_err:
            op.handle(
                "/v2/operator/proposal/approve",
                cli.principal,
                {
                    "proposal_id": prop.proposal_id,
                    "approval": {
                        "message": ch,
                        "channel": "passkey_uv",
                        "signer_id": signer.signer_id,
                        "response_json": _sign("http://localhost:8080\n", 1),
                    },
                },
            )
        assert nl_err.value.code is ErrorCode.UNAUTHENTICATED
        assert svc.get_proposal(prop.proposal_id).status.value == "pending"

        with pytest.raises(BrainError) as list_err:
            op.handle(
                "/v2/operator/proposal/approve",
                cli.principal,
                {
                    "proposal_id": prop.proposal_id,
                    "approval": {
                        "message": ch,
                        "channel": "passkey_uv",
                        "signer_id": signer.signer_id,
                        "response_json": json.dumps({"response": {"clientDataJSON": _b64u(b"[]")}}),
                    },
                },
            )
        assert list_err.value.code is ErrorCode.UNAUTHENTICATED

        ok_res = op.handle(
            "/v2/operator/proposal/approve",
            cli.principal,
            {
                "proposal_id": prop.proposal_id,
                "approval": {
                    "message": ch,
                    "channel": "passkey_uv",
                    "signer_id": signer.signer_id,
                    "response_json": _sign("http://localhost:8080", 1),
                },
            },
        )
        ok_prop = ok_res.get("proposal")
        assert isinstance(ok_prop, Mapping) and ok_prop.get("status") == "approved"
    finally:
        rt.close()


def test_r05_default_action_reflected_in_html_select_and_initial_api_state() -> None:
    """I3-5-R05: ``default_action`` renders ``selected`` on SSR ``<select>`` and drives default ``/api/state``."""
    for act in (ApprovalAction.APPLY, ApprovalAction.ROLLBACK, ApprovalAction.REJECT):
        backend = _StubBackend(proposal_id=f"prop-{act.value}")
        session = ReviewSession(
            backend=backend,
            proposal_id=backend.proposal_id,
            expected_origin="http://localhost:0",
            default_action=act,
        )
        with ReviewWebServer(session, host="127.0.0.1", port=0) as srv:
            session.bind_origin(srv.origin)
            st_html, _, _, raw_html = _raw_http(srv.port, target="/review", headers=[("Host", f"localhost:{srv.port}")])
            assert st_html == 200
            parser = _SelectOptionParser()
            parser.feed(raw_html.decode("utf-8"))
            selected_vals = [val for val, is_sel in parser.options if is_sel]
            assert selected_vals == [act.value], (act, parser.options)

            cookie, _ = _redeem_session(srv.port, srv.origin, session.bootstrap_token)
            st_api, _, _, raw_api = _raw_http(
                srv.port,
                target="/api/state",
                headers=[("Host", f"localhost:{srv.port}"), ("Cookie", cookie)],
            )
            assert st_api == 200
            data = json.loads(raw_api)["data"]
            assert data["action"] == act.value
            assert data["subject_summary"]["action"] == act.value
