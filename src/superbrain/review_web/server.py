"""Hardened loopback HTTP server for local WebAuthn proposal review (spec 11.2, 11.3, Case 31)."""

from __future__ import annotations

import json
import re
import socket
import threading
from http.cookies import CookieError, SimpleCookie
from types import TracebackType
from typing import Any
from urllib.parse import parse_qs, urlparse

from superbrain.application.review_session import ReviewSession
from superbrain.core._kernel_approval import ApprovalAction
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.review_web.assets import REVIEW_CSS, REVIEW_JS, render_review_html

__all__ = ["REVIEW_WEB_CSP", "ReviewWebServer"]

REVIEW_WEB_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'none'; frame-ancestors 'none'"
)
_MAX_REQUEST_LINE_BYTES = 8192
_MAX_HEADER_BYTES = 16384
_MAX_HEADERS = 64
_MAX_BODY_BYTES = 65536
_SESSION_COOKIE_NAME = "sb_review_session"
_HEADER_NAME_RE = re.compile(r"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")

_ERROR_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_INPUT: 400,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.IDENTITY_MISMATCH: 401,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.REVISION_CONFLICT: 409,
    ErrorCode.IO_ERROR: 500,
    ErrorCode.DAEMON_UNAVAILABLE: 503,
    ErrorCode.CAPABILITY_UNAVAILABLE: 503,
    ErrorCode.DEADLINE_EXCEEDED: 504,
}

_STATUS_REASONS: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    414: "URI Too Long",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class _HttpReject(Exception):
    def __init__(self, status: int, code: ErrorCode = ErrorCode.INVALID_INPUT, message: str = "rejected") -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _security_headers() -> list[tuple[str, str]]:
    return [
        ("Content-Security-Policy", REVIEW_WEB_CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Cache-Control", "no-store"),
        ("Referrer-Policy", "no-referrer"),
    ]


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _extract_session_cookie(raw_cookie: str | None) -> str | None:
    if not raw_cookie:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw_cookie)
    except CookieError:
        return None
    morsel = jar.get(_SESSION_COOKIE_NAME)
    return None if morsel is None else morsel.value


class ReviewWebServer:
    """Loopback-only HTTP/1.1 server enforcing Host/Origin/CSRF/CSP/bounds and deterministic teardown."""

    def __init__(
        self,
        session: ReviewSession,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_body_bytes: int = _MAX_BODY_BYTES,
    ) -> None:
        if host != "127.0.0.1":
            raise BrainError(ErrorCode.INVALID_INPUT, "review_web only accepts host 127.0.0.1")
        if type(port) is not int or not 0 <= port <= 65535:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid port")
        if type(max_body_bytes) is not int or max_body_bytes <= 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid max_body_bytes")
        self._session = session
        self._host = host
        self._max_body_bytes = max_body_bytes
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(16)
        sock.settimeout(0.25)
        self._listener = sock
        self._port = int(sock.getsockname()[1])
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._accept_thread: threading.Thread | None = None
        self._closed = False

    @property
    def port(self) -> int:
        return self._port

    @property
    def origin(self) -> str:
        return f"http://localhost:{self._port}"

    @property
    def launch_url(self) -> str:
        return f"{self.origin}/review#token={self._session.bootstrap_token}"

    def start(self) -> ReviewWebServer:
        """Start background accept loop if not already started."""
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.INVALID_INPUT, "server is closed")
            if self._accept_thread is None:
                t = threading.Thread(target=self._accept_loop, name="review-web-accept", daemon=True)
                self._accept_thread = t
                t.start()
        return self

    def close(self) -> None:
        """Stop accepting, close all active keep-alive sockets immediately, and join worker threads."""
        self._stop_event.set()
        with self._lock:
            self._closed = True
            active = list(self._active_sockets)
            self._active_sockets.clear()
            accept_t = self._accept_thread
            workers = list(self._workers)
            self._workers.clear()
        try:
            self._listener.close()
        except OSError:
            pass
        for conn in active:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if accept_t is not None and accept_t.is_alive():
            accept_t.join(timeout=2.0)
        for w in workers:
            if w.is_alive():
                w.join(timeout=2.0)

    def __enter__(self) -> ReviewWebServer:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        _ = (exc_type, exc_val, exc_tb)
        self.close()

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            conn.settimeout(0.25)
            with self._lock:
                if self._stop_event.is_set():
                    try:
                        conn.close()
                    except OSError:
                        pass
                    break
                self._active_sockets.add(conn)
                t = threading.Thread(target=self._serve_connection, args=(conn,), daemon=True)
                self._workers = [w for w in self._workers if w.is_alive()]
                self._workers.append(t)
                t.start()

    def _serve_connection(self, conn: socket.socket) -> None:
        buf = bytearray()
        try:
            while not self._stop_event.is_set():
                keep_alive = False
                try:
                    req = self._read_request(conn, buf)
                    if req is None:
                        break
                    method, target, headers, body, req_keep_alive = req
                    keep_alive = req_keep_alive
                    status, content_type, resp_body, extra_headers = self._dispatch(method, target, headers, body)
                    self._send_response(
                        conn,
                        status=status,
                        content_type=content_type,
                        body=resp_body,
                        extra_headers=extra_headers,
                        keep_alive=keep_alive,
                    )
                except _HttpReject as rej:
                    self._send_response(
                        conn,
                        status=rej.status,
                        content_type="application/json; charset=utf-8",
                        body=_json_bytes({"ok": False, "error": {"code": rej.code.value, "message": rej.message}}),
                        extra_headers=(),
                        keep_alive=False,
                    )
                    try:
                        conn.shutdown(socket.SHUT_WR)
                        conn.settimeout(0.05)
                        for _ in range(16):
                            if not conn.recv(8192):
                                break
                    except OSError:
                        pass
                    break
                except BrainError as err:
                    status = _ERROR_HTTP_STATUS.get(err.code, 400)
                    self._send_response(
                        conn,
                        status=status,
                        content_type="application/json; charset=utf-8",
                        body=_json_bytes({"ok": False, "error": {"code": err.code.value, "message": err.message}}),
                        extra_headers=(),
                        keep_alive=keep_alive,
                    )
                except Exception:  # noqa: BLE001
                    err_body = _json_bytes(
                        {"ok": False, "error": {"code": ErrorCode.IO_ERROR.value, "message": "internal error"}}
                    )
                    self._send_response(
                        conn,
                        status=500,
                        content_type="application/json; charset=utf-8",
                        body=err_body,
                        extra_headers=(),
                        keep_alive=False,
                    )
                    break
                if not keep_alive:
                    break
        except (OSError, ValueError):
            pass
        finally:
            with self._lock:
                self._active_sockets.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _fill_until(self, conn: socket.socket, buf: bytearray, needle: bytes, limit: int, too_large_status: int) -> int:
        while True:
            idx = buf.find(needle)
            if idx != -1:
                if idx > limit:
                    raise _HttpReject(too_large_status)
                return idx
            if len(buf) > limit:
                raise _HttpReject(too_large_status)
            if self._stop_event.is_set():
                return -1
            try:
                chunk = conn.recv(4096)
            except TimeoutError:
                continue
            if not chunk:
                return -1
            buf.extend(chunk)

    def _read_request(
        self, conn: socket.socket, buf: bytearray
    ) -> tuple[str, str, list[tuple[str, str]], bytes, bool] | None:
        line_end = self._fill_until(conn, buf, b"\r\n", _MAX_REQUEST_LINE_BYTES, 414)
        if line_end == -1:
            return None
        req_line = bytes(buf[:line_end]).decode("iso-8859-1")
        del buf[: line_end + 2]
        parts = req_line.split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
            raise _HttpReject(400)
        method, target, version = parts

        headers: list[tuple[str, str]] = []
        raw_cl_vals: list[str] = []
        hdr_bytes = 0
        while True:
            h_end = self._fill_until(conn, buf, b"\r\n", _MAX_HEADER_BYTES - hdr_bytes, 431)
            if h_end == -1:
                raise _HttpReject(400)
            hdr_line = bytes(buf[:h_end]).decode("iso-8859-1")
            del buf[: h_end + 2]
            hdr_bytes += h_end + 2
            if not hdr_line:
                break
            if len(headers) >= _MAX_HEADERS:
                raise _HttpReject(431)
            if ":" not in hdr_line:
                raise _HttpReject(400)
            k_raw, v = hdr_line.split(":", 1)
            if not _HEADER_NAME_RE.fullmatch(k_raw):
                raise _HttpReject(400)
            low_k = k_raw.lower()
            if low_k == "content-length":
                raw_cl_vals.append(v)
            headers.append((low_k, v.strip(" \t")))

        if any(k == "transfer-encoding" for k, _ in headers):
            raise _HttpReject(400)
        if len(raw_cl_vals) > 1:
            raise _HttpReject(400)
        body_len = 0
        if raw_cl_vals:
            raw_v = raw_cl_vals[0]
            raw_cl = raw_v[1:] if raw_v.startswith(" ") else raw_v
            if not raw_cl or not raw_cl.isascii() or not raw_cl.isdigit():
                raise _HttpReject(400)
            body_len = int(raw_cl)
            if body_len > self._max_body_bytes:
                raise _HttpReject(413)

        while len(buf) < body_len:
            if self._stop_event.is_set():
                raise _HttpReject(400)
            try:
                chunk = conn.recv(min(8192, body_len - len(buf)))
            except TimeoutError:
                continue
            if not chunk:
                raise _HttpReject(400)
            buf.extend(chunk)
        body = bytes(buf[:body_len])
        del buf[:body_len]

        conn_vals = {v.lower() for k, v in headers if k == "connection"}
        keep_alive = version == "HTTP/1.1" and "close" not in conn_vals
        return method, target, headers, body, keep_alive

    def _validate_host(self, headers: list[tuple[str, str]]) -> None:
        hosts = [v for k, v in headers if k == "host"]
        if len(hosts) != 1 or hosts[0].lower() != f"localhost:{self._port}":
            raise _HttpReject(403, ErrorCode.IDENTITY_MISMATCH, "invalid Host header")

    def _validate_origin(self, headers: list[tuple[str, str]]) -> None:
        origins = [v for k, v in headers if k == "origin"]
        if len(origins) != 1 or origins[0] != self.origin:
            raise _HttpReject(403, ErrorCode.IDENTITY_MISMATCH, "invalid Origin header")

    def _require_cookie_session(self, headers: list[tuple[str, str]]) -> None:
        raw_cookies = [v for k, v in headers if k == "cookie"]
        session_val = _extract_session_cookie("; ".join(raw_cookies)) if raw_cookies else None
        if not self._session.verify_session(session_val):
            raise _HttpReject(401, ErrorCode.UNAUTHENTICATED, "unauthenticated")

    def _dispatch(
        self,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> tuple[int, str, bytes, tuple[tuple[str, str], ...]]:
        self._validate_host(headers)
        parsed = urlparse(target)
        path = parsed.path

        if method == "GET" and path in ("/", "/review"):
            html_doc = render_review_html(
                self._session.ssr_summary(),
                default_action=self._session.default_action.value,
            ).encode("utf-8")
            return 200, "text/html; charset=utf-8", html_doc, ()
        if method == "GET" and path == "/assets/review.js":
            return 200, "application/javascript; charset=utf-8", REVIEW_JS.encode("utf-8"), ()
        if method == "GET" and path == "/assets/review.css":
            return 200, "text/css; charset=utf-8", REVIEW_CSS.encode("utf-8"), ()

        if method == "POST" and path == "/api/session":
            self._validate_origin(headers)
            data = self._parse_json_obj(body)
            token = data.get("token")
            if not isinstance(token, str) or not token:
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            session_id, csrf_token = self._session.redeem_bootstrap_token(token)
            cookie = f"{_SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict; Path=/"
            return (
                200,
                "application/json; charset=utf-8",
                _json_bytes({"ok": True, "data": {"csrf_token": csrf_token}}),
                (("Set-Cookie", cookie),),
            )

        if method == "GET" and path == "/api/state":
            self._require_cookie_session(headers)
            qs = parse_qs(parsed.query, keep_blank_values=False)
            raw_act = qs.get("action", [None])[0]
            action: ApprovalAction | None = None
            if raw_act is not None:
                try:
                    action = ApprovalAction(raw_act)
                except ValueError as err:
                    raise BrainError(ErrorCode.INVALID_INPUT, "invalid action") from err
            state = self._session.render_state(action)
            return 200, "application/json; charset=utf-8", _json_bytes({"ok": True, "data": state}), ()

        if method == "POST" and path == "/api/submit":
            self._validate_origin(headers)
            self._require_cookie_session(headers)
            csrf_vals = [v for k, v in headers if k == "x-csrf-token"]
            if len(csrf_vals) != 1 or not self._session.verify_csrf(csrf_vals[0]):
                raise _HttpReject(403, ErrorCode.IDENTITY_MISMATCH, "invalid CSRF token")
            data = self._parse_json_obj(body)
            raw_act = data.get("action")
            signer_id = data.get("signer_id")
            challenge_msg = data.get("challenge_message")
            response_json = data.get("response_json")
            if (
                not isinstance(raw_act, str)
                or not isinstance(signer_id, str)
                or not isinstance(challenge_msg, dict)
                or not isinstance(response_json, str)
            ):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            try:
                action = ApprovalAction(raw_act)
            except ValueError as err:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid action") from err
            result = self._session.submit_passkey(
                action=action,
                signer_id=signer_id,
                challenge_message=challenge_msg,
                response_json=response_json,
            )
            return 200, "application/json; charset=utf-8", _json_bytes({"ok": True, "data": result}), ()

        raise _HttpReject(404, ErrorCode.NOT_FOUND, "not found")

    def _parse_json_obj(self, body: bytes) -> dict[str, Any]:
        try:
            parsed: JsonValue = json.loads(body.decode("utf-8"))
        except Exception as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid JSON body") from err
        if not isinstance(parsed, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "JSON body must be an object")
        return dict(parsed)

    def _send_response(
        self,
        conn: socket.socket,
        *,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: tuple[tuple[str, str], ...],
        keep_alive: bool,
    ) -> None:
        reason = _STATUS_REASONS.get(status, "Status")
        hdrs: list[tuple[str, str]] = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Connection", "keep-alive" if keep_alive else "close"),
            *_security_headers(),
            *extra_headers,
        ]
        head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n"
        conn.sendall(head.encode("iso-8859-1") + body)
