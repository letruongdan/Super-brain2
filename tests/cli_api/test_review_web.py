"""I3-5 oracle: ``review_web`` local passkey UI, strict Host/Origin/CSRF/CSP security, & ``brain review --web``.

Requirement sources: spec rev 22 §11.2, §11.3, §20 cases 14, 16-17, 31; plan I3-5 Step 1; owner O12 decision.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import queue
import socket
import struct
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar, cast

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from superbrain.adapters.auth.webauthn_verifier import WebAuthnApprovalVerifier
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.approvals import OperatorService
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli.main import main as brain_main
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
    SignerRecord,
    canonical_utc,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.os import OsAdapters
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
_T = TypeVar("_T")
UP = 0x01
UV = 0x04
EXPECTED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'none'; frame-ancestors 'none'"
)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _SyntheticPasskey:
    """Controlled ES256 authenticator matching ``tests/adapters/test_approval_verifiers.py`` (O12 fixture)."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        nums = self._key.public_key().public_numbers()
        self.credential_id = b"i3-5-passkey-cred-01"
        self.cose_public_key = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )
        self.enrollment = SignerEnrollment(
            owner_id=OWNER,
            channel=ApprovalChannel.PASSKEY_UV,
            public_key=_b64u(self.cose_public_key),
            credential_id=_b64u(self.credential_id),
        )

    def sign_assertion(
        self,
        challenge: bytes,
        *,
        origin: str,
        rp_id: str = "localhost",
        flags: int = UP | UV,
        sign_count: int = 1,
        tamper: bool = False,
    ) -> str:
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": origin, "crossOrigin": False}
        ).encode("utf-8")
        sig = self._key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            auth_data = auth_data[:-1] + bytes([auth_data[-1] ^ 0x01])
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


def _raw_http(
    port: int,
    *,
    method: str = "GET",
    target: str = "/",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    start_line_override: bytes | None = None,
) -> tuple[int, dict[str, str], str | None, bytes]:
    req_lines = [start_line_override or f"{method} {target} HTTP/1.1".encode("ascii")]
    for k, v in headers or []:
        req_lines.append(f"{k}: {v}".encode("latin-1"))
    if body and not any(k.lower() == "content-length" for k, _ in (headers or [])):
        req_lines.append(f"Content-Length: {len(body)}".encode("ascii"))
    wire = b"\r\n".join(req_lines) + b"\r\n\r\n" + body
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
        sock.settimeout(3.0)
        sock.sendall(wire)
        chunks: list[bytes] = []
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = sock.recv(4096)
            if not data:
                break
            buf += data
        head_raw, _, rest = buf.partition(b"\r\n\r\n")
        head_lines = head_raw.decode("iso-8859-1").split("\r\n")
        status = int(head_lines[0].split(" ", 2)[1])
        hdr_map: dict[str, str] = {}
        set_cookie: str | None = None
        for line in head_lines[1:]:
            if ":" in line:
                k, val = line.split(":", 1)
                lk = k.strip().lower()
                if lk == "set-cookie":
                    set_cookie = val.strip()
                hdr_map[lk] = val.strip()
        chunks.append(rest)
        cl = int(hdr_map["content-length"]) if "content-length" in hdr_map else None
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


class _LocalOperatorBackend:
    """In-memory ReviewOperatorBackendPort owning PolicyStore + ReviewApplyService on one dedicated thread."""

    def __init__(self, root_path: Path, checkout: Path, os_: OsAdapters, passkey: _SyntheticPasskey) -> None:
        self._q: queue.Queue[tuple[Callable[[], Any], Future[Any]] | None] = queue.Queue()
        self.port_hint: int | None = None
        ready: Future[str] = Future()

        def _loop() -> None:
            rt: Any = None
            try:
                rt, svc, cli_p, pid = _setup_runtime_with_xss_proposal(root_path, checkout, os_, passkey)
                self._rt, self._svc, self._principal = rt, svc, cli_p
                ready.set_result(pid)
                while (item := self._q.get()) is not None:
                    fn, fut = item
                    try:
                        fut.set_result(fn())
                    except BaseException as exc:  # noqa: BLE001
                        fut.set_exception(exc)
            except BaseException as exc:  # noqa: BLE001
                if not ready.done():
                    ready.set_exception(exc)
            finally:
                if rt is not None:
                    rt.close()

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()
        self.proposal_id = ready.result()

    def run_on_owner(self, fn: Callable[[Any, ReviewApplyService], _T]) -> _T:
        if threading.current_thread() is self._thread:
            return fn(self._rt, self._svc)
        fut: Future[_T] = Future()
        self._q.put((lambda: fn(self._rt, self._svc), fut))
        return fut.result()

    def close(self) -> None:
        self._q.put(None)
        self._thread.join(timeout=5.0)

    def _op(self) -> OperatorService:
        assert self.port_hint is not None
        origin = f"http://localhost:{self.port_hint}"
        return OperatorService(
            self._rt.policy,
            ssh_verifier=lambda: None,
            webauthn_verifier=WebAuthnApprovalVerifier(rp_id="localhost", origin=origin),
            review_apply=self._svc,
        )

    def list_signers(self) -> tuple[SignerRecord, ...]:
        return self.run_on_owner(lambda rt, _svc: tuple(rt.policy.active_signers()))

    def show_proposal(self, proposal_id: str) -> Mapping[str, JsonValue]:
        def _do(_rt: Any, _svc: ReviewApplyService) -> Mapping[str, JsonValue]:
            out = self._op().handle("/v2/operator/proposal/show", self._principal, {"proposal_id": proposal_id})
            return cast(Mapping[str, JsonValue], out["proposal"])

        return self.run_on_owner(_do)

    def request_challenge(
        self, *, proposal_id: str, action: ApprovalAction, recovery_scope: RecoveryScope
    ) -> tuple[ApprovalMessage, Mapping[str, JsonValue]]:
        def _do(rt: Any, svc: ReviewApplyService) -> tuple[ApprovalMessage, Mapping[str, JsonValue]]:
            prop = svc.get_proposal(proposal_id)
            issued = rt.policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
            msg = ApprovalMessage(
                store_id=rt.store.store_id,
                owner_id=prop.owner_id,
                trust_generation=rt.policy.trust_generation(),
                action=action,
                subject_id=prop.proposal_id,
                subject_revision=prop.subject_revision,
                resource_digests=prop.resource_digests,
                target_files=prop.to_target_files(),
                risk_level=prop.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=recovery_scope,
                nonce=issued.nonce,
                expires_at=issued.expires_at,
            )
            return msg, {
                "proposal_id": prop.proposal_id,
                "kind": prop.kind,
                "reason": prop.reason,
                "status": prop.status.value,
                "subject_revision": prop.subject_revision,
                "risk_level": prop.risk_level.value,
                "updated_at": canonical_utc(datetime.now(UTC)),
                "targets": [{"rel_path": t.rel_path, "slice_id": t.slice_id} for t in prop.targets],
            }

        return self.run_on_owner(_do)

    def submit_approval(
        self, *, proposal_id: str, action: ApprovalAction, raw_approval: Mapping[str, JsonValue]
    ) -> Mapping[str, JsonValue]:
        path = f"/v2/operator/proposal/{action.value}"
        payload: dict[str, JsonValue] = {"proposal_id": proposal_id, "approval": dict(raw_approval)}
        return self.run_on_owner(
            lambda _rt, _svc: cast(Mapping[str, JsonValue], self._op().handle(path, self._principal, payload))
        )


def _setup_runtime_with_xss_proposal(
    root_path: Path, checkout: Path, os_: OsAdapters, passkey: _SyntheticPasskey
) -> tuple[Any, ReviewApplyService, Principal, str]:
    checkout.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(checkout)
    target = checkout / "CLAUDE.md"
    base_md = "# Base Title\n"
    target.write_bytes(base_md.encode("utf-8"))
    rt = open_kernel_job_runtime(root_path, os_, role="review-web-test")
    rt.policy.enroll_first_signer(passkey.enrollment)
    cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="cli", machine_id="m-web")
    svc = ReviewApplyService(
        StoreProposalAdapter(rt.store, os_),
        PolicyApplyAuthority(rt.policy),
        os_,
        data_root=root_path,
        home_dir=root_path.parent / "home",
        config_merger=SharedConfigMergerAdapter(),
    )
    evil_body = "<script>alert(1)</script><img src=x onerror=alert(2)>\" onclick=\"hack()\""
    m = merge_markdown_block(base_md, slice_id="s1", block_body=evil_body, expected_slice_digest=None)
    prop = svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason='<script>alert("xss")</script> javascript:alert(9)',
        resources=[RiskResource(component="c2", command_reference=True)],
        targets=[
            TargetWriteInput(
                checkout, "CLAUDE.md", m.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "s1", m.slice_digest
            )
        ],
    )
    return rt, svc, cli.principal, prop.proposal_id


def _redeem_cookie(port: int, token: str) -> tuple[str, str]:
    hdrs = [("Host", f"localhost:{port}"), ("Origin", f"http://localhost:{port}"), ("Content-Type", "application/json")]
    st, _, set_cookie, body = _raw_http(
        port, method="POST", target="/api/session", headers=hdrs, body=json.dumps({"token": token}).encode("utf-8")
    )
    assert st == 200 and set_cookie is not None, (st, body)
    cookie_pair = set_cookie.split(";", 1)[0]
    assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie
    parsed = json.loads(body)
    return cookie_pair, str(parsed["data"]["csrf_token"])


def test_review_web_loopback_host_origin_csrf_csp_xss_and_bounds(
    trusted_tmp: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """I3-5 §11.2 / Case 31: strict loopback/Host/Origin/CSRF/CSP/escaping/bounds/clean shutdown."""
    from superbrain.application.review_session import ReviewSession
    from superbrain.review_web.server import REVIEW_WEB_CSP, ReviewWebServer

    assert REVIEW_WEB_CSP == EXPECTED_CSP
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    passkey = _SyntheticPasskey()
    backend = _LocalOperatorBackend(trusted_tmp / "data", trusted_tmp / "checkout", os_, passkey)
    try:
        session = ReviewSession(
            backend=backend, proposal_id=backend.proposal_id, rp_id="localhost", expected_origin="http://localhost:0"
        )

        # Never allow wildcard 0.0.0.0 or non-127.0.0.1 bind.
        with pytest.raises(BrainError) as bad_host:
            ReviewWebServer(session, host="0.0.0.0")
        assert bad_host.value.code is ErrorCode.INVALID_INPUT

        with caplog.at_level(logging.DEBUG), ReviewWebServer(session, host="127.0.0.1", port=0) as srv:
            backend.port_hint = srv.port
            session.bind_origin(srv.origin)
            assert srv.origin == f"http://localhost:{srv.port}"
            assert srv.launch_url.startswith(f"http://localhost:{srv.port}/review#token=")

            # 1. Valid Host -> SSR HTML escapes XSS and has strict CSP/security headers with 0 inline JS/URLs.
            st_html, hdr_html, _, raw_html = _raw_http(
                srv.port, target="/review", headers=[("Host", f"localhost:{srv.port}")]
            )
            assert st_html == 200
            for hk, hv in (
                ("content-security-policy", EXPECTED_CSP),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("cache-control", "no-store"),
                ("referrer-policy", "no-referrer"),
            ):
                assert hdr_html.get(hk) == hv, (hk, hdr_html)
            html_text = raw_html.decode("utf-8")
            assert "<script>alert" not in html_text and "onerror=" not in html_text
            assert html.escape('<script>alert("xss")</script>', quote=True) in html_text
            assert "http://" not in html_text and "https://" not in html_text
            assert '<script src="/assets/review.js"></script>' in html_text

            st_js, hdr_js, _, raw_js = _raw_http(
                srv.port, target="/assets/review.js", headers=[("Host", f"localhost:{srv.port}")]
            )
            assert st_js == 200 and hdr_js.get("x-content-type-options") == "nosniff"
            js_text = raw_js.decode("utf-8")
            assert "innerHTML" not in js_text and "textContent" in js_text

            # 2. Host header DNS-rebinding & IP-literal rejections.
            for bad_host_hdr in (
                [("Host", f"127.0.0.1:{srv.port}")],
                [("Host", "evil.example")],
                [("Host", f"evil.localhost:{srv.port}")],
                [],
                [("Host", f"localhost:{srv.port}"), ("Host", "evil.example")],
            ):
                st_b, hdr_b, _, _ = _raw_http(srv.port, target="/review", headers=bad_host_hdr)
                assert st_b in (400, 403), (bad_host_hdr, st_b)
                assert hdr_b.get("x-content-type-options") == "nosniff"

            # 3. Pre-auth rejected; one-time token exchange succeeds ONCE; replay rejected.
            st_unauth, _, _, _ = _raw_http(srv.port, target="/api/state", headers=[("Host", f"localhost:{srv.port}")])
            assert st_unauth == 401
            st_bad_org, _, _, _ = _raw_http(
                srv.port,
                method="POST",
                target="/api/session",
                headers=[
                    ("Host", f"localhost:{srv.port}"),
                    ("Origin", "https://evil.example"),
                    ("Content-Type", "application/json"),
                ],
                body=json.dumps({"token": session.bootstrap_token}).encode("utf-8"),
            )
            assert st_bad_org == 403

            cookie, csrf = _redeem_cookie(srv.port, session.bootstrap_token)
            st_replay, _, _, _ = _raw_http(
                srv.port,
                method="POST",
                target="/api/session",
                headers=[
                    ("Host", f"localhost:{srv.port}"),
                    ("Origin", srv.origin),
                    ("Content-Type", "application/json"),
                ],
                body=json.dumps({"token": session.bootstrap_token}).encode("utf-8"),
            )
            assert st_replay == 401

            # 4. Origin + CSRF checks on POST /api/submit.
            h_host = ("Host", f"localhost:{srv.port}")
            for bad_hdrs in (
                [h_host, ("Cookie", cookie), ("X-CSRF-Token", csrf)],
                [h_host, ("Origin", "https://evil.example"), ("Cookie", cookie), ("X-CSRF-Token", csrf)],
                [h_host, ("Origin", f"http://127.0.0.1:{srv.port}"), ("Cookie", cookie), ("X-CSRF-Token", csrf)],
                [h_host, ("Origin", srv.origin), ("Cookie", cookie)],
                [h_host, ("Origin", srv.origin), ("Cookie", cookie), ("X-CSRF-Token", "wrong")],
            ):
                st_p, _, _, _ = _raw_http(
                    srv.port, method="POST", target="/api/submit", headers=bad_hdrs, body=b"{}"
                )
                assert st_p in (401, 403), (bad_hdrs, st_p)

            # 5. Request-line (>8 KiB), header (>16 KiB), and body (>64 KiB) ceiling enforcement + keep-alive exit.
            st_rl, _, _, _ = _raw_http(
                srv.port, start_line_override=b"GET /" + b"a" * 8200 + b" HTTP/1.1"
            )
            assert st_rl in (400, 414)
            st_hd, _, _, _ = _raw_http(
                srv.port, headers=[h_host, ("X-Pad", "z" * 16500)]
            )
            assert st_hd in (400, 431)
            st_bd, _, _, _ = _raw_http(
                srv.port,
                method="POST",
                target="/api/submit",
                headers=[
                    h_host,
                    ("Origin", srv.origin),
                    ("Cookie", cookie),
                    ("X-CSRF-Token", csrf),
                    ("Content-Type", "application/json"),
                ],
                body=b'{"pad":"' + b"x" * 70_000 + b'"}',
            )
            assert st_bd == 413

            # Open keep-alive socket and drop out of context manager: server shuts down cleanly.
            idle_sock = socket.create_connection(("127.0.0.1", srv.port), timeout=2.0)
            ka_req = f"GET /review HTTP/1.1\r\nHost: localhost:{srv.port}\r\nConnection: keep-alive\r\n\r\n"
            idle_sock.sendall(ka_req.encode("ascii"))
            idle_sock.recv(1024)
        idle_sock.close()
        assert session.bootstrap_token not in caplog.text
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", srv.port), timeout=0.5)
    finally:
        backend.close()


def test_review_web_passkey_ceremony_sign_count_and_case31_subject_refresh(trusted_tmp: Path) -> None:
    """I3-5 Case 17 & Case 31: challenge binds ApprovalMessage bytes, monotonic sign_count, refreshes on edit."""
    from superbrain.application.review_session import ReviewSession
    from superbrain.review_web.server import ReviewWebServer

    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    passkey = _SyntheticPasskey()
    backend = _LocalOperatorBackend(trusted_tmp / "data", trusted_tmp / "checkout", os_, passkey)
    pid = backend.proposal_id
    try:
        signer = backend.run_on_owner(lambda rt, _svc: rt.policy.active_signers()[0])
        session = ReviewSession(backend=backend, proposal_id=pid, rp_id="localhost", expected_origin="http://localhost:0")

        with ReviewWebServer(session, host="127.0.0.1", port=0) as srv:
            backend.port_hint = srv.port
            session.bind_origin(srv.origin)
            cookie, csrf = _redeem_cookie(srv.port, session.bootstrap_token)
            hdrs = [
                ("Host", f"localhost:{srv.port}"),
                ("Origin", srv.origin),
                ("Cookie", cookie),
                ("X-CSRF-Token", csrf),
                ("Content-Type", "application/json"),
            ]

            def _get_state(action_str: str) -> dict[str, Any]:
                st, _, _, raw = _raw_http(
                    srv.port,
                    target=f"/api/state?action={action_str}",
                    headers=[("Host", f"localhost:{srv.port}"), ("Cookie", cookie)],
                )
                assert st == 200
                return cast(dict[str, Any], json.loads(raw)["data"])

            state_app = _get_state("approve")
            ch_dict = state_app["challenge"]
            ch_bytes = ApprovalMessage.from_dict(ch_dict).canonical_bytes()
            assert state_app["subject_summary"]["subject_id"] == pid
            assert state_app["subject_summary"]["subject_revision"] == 1
            assert state_app["webauthn_options"]["rpId"] == "localhost"
            assert state_app["webauthn_options"]["userVerification"] == "required"
            assert state_app["webauthn_options"]["challenge"] == _b64u(ch_bytes)

            def _post_submit(action_str: str, ch: Mapping[str, JsonValue], resp: str) -> tuple[int, bytes]:
                payload = {
                    "action": action_str,
                    "signer_id": signer.signer_id,
                    "challenge_message": ch,
                    "response_json": resp,
                }
                st, _, _, raw = _raw_http(
                    srv.port,
                    method="POST",
                    target="/api/submit",
                    headers=hdrs,
                    body=json.dumps(payload).encode("utf-8"),
                )
                return st, raw

            # Reject missing UV, wrong origin, wrong RP ID, tampered sig WITHOUT approving proposal.
            for bad_resp in (
                passkey.sign_assertion(ch_bytes, origin=srv.origin, flags=UP, sign_count=1),
                passkey.sign_assertion(ch_bytes, origin=f"http://127.0.0.1:{srv.port}", sign_count=1),
                passkey.sign_assertion(ch_bytes, origin=srv.origin, rp_id="evil.example", sign_count=1),
                passkey.sign_assertion(ch_bytes, origin=srv.origin, tamper=True, sign_count=1),
            ):
                st_bad, _ = _post_submit("approve", ch_dict, bad_resp)
                assert st_bad in (400, 401), st_bad
                assert backend.run_on_owner(lambda _rt, svc: svc.get_proposal(pid).status.value) == "pending"

            # Valid sign_count=1 ceremony approves & persists sign_count=1.
            good_resp = passkey.sign_assertion(ch_bytes, origin=srv.origin, flags=UP | UV, sign_count=1)
            st_ok, raw_ok = _post_submit("approve", ch_dict, good_resp)
            assert st_ok == 200 and json.loads(raw_ok)["ok"] is True
            assert backend.run_on_owner(lambda _rt, svc: svc.get_proposal(pid).status.value) == "approved"
            assert backend.run_on_owner(lambda rt, _svc: rt.policy.signer(signer.signer_id).sign_count) == 1

            # Case 31: subject_revision change invalidates previously displayed challenge & refreshes state!
            state_apply = _get_state("apply")
            stale_ch = state_apply["challenge"]
            stale_bytes = ApprovalMessage.from_dict(stale_ch).canonical_bytes()
            backend.run_on_owner(
                lambda rt, svc: StoreProposalAdapter(rt.store, os_).update_proposal_status(
                    pid,
                    svc.get_proposal(pid).status,
                    subject_revision=2,
                    updated_at=canonical_utc(clock.now() + timedelta(seconds=1)),
                )
            )
            stale_resp = passkey.sign_assertion(stale_bytes, origin=srv.origin, flags=UP | UV, sign_count=2)
            st_stale, raw_stale = _post_submit("apply", stale_ch, stale_resp)
            assert st_stale == 409 and json.loads(raw_stale)["error"]["code"] == ErrorCode.REVISION_CONFLICT.value

            refreshed = _get_state("apply")
            assert refreshed["subject_summary"]["subject_revision"] == 2
            refreshed_bytes = ApprovalMessage.from_dict(refreshed["challenge"]).canonical_bytes()
            assert refreshed_bytes != stale_bytes

            # Stale sign_count=1 refused; monotonic sign_count=2 succeeds!
            r_cnt = passkey.sign_assertion(refreshed_bytes, origin=srv.origin, sign_count=1)
            st_cnt, _ = _post_submit("apply", refreshed["challenge"], r_cnt)
            assert st_cnt == 401
            r_fin = passkey.sign_assertion(refreshed_bytes, origin=srv.origin, sign_count=2)
            st_fin, _ = _post_submit("apply", refreshed["challenge"], r_fin)
            assert st_fin == 200
            assert backend.run_on_owner(lambda _rt, svc: svc.get_proposal(pid).status.value) == "applied"
            assert backend.run_on_owner(lambda rt, _svc: rt.policy.signer(signer.signer_id).sign_count) == 2
    finally:
        backend.close()


def test_review_web_cli_argv_and_python_i_dispatch(trusted_tmp: Path, capfd: pytest.CaptureFixture[str]) -> None:
    """I3-5 CLI: brain review --web rejects relative --profile pre-spawn and routes cleanly under python -I."""
    import superbrain.composition.review_web_entry as review_web_entry

    assert hasattr(review_web_entry, "open_review_web_server")
    assert brain_main(["review", "--web", "prop-1", "--profile", "relative/profile.json"]) == 2
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value

    missing = trusted_tmp / "missing-profile.json"
    capfd.readouterr()
    assert brain_main(["review", "--web", "prop-1", "--profile", str(missing)]) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value
