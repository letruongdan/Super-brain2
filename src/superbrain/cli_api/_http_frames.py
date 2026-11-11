"""Bounded HTTP/1.1 framing and deadline-aware socket I/O for loopback transport."""

from __future__ import annotations

import http.client
import http.server
import io
import select
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from superbrain.core.errors import BrainError, ErrorCode

MAX_REQUEST_LINE_BYTES = 8_192
MAX_HEADER_BLOCK_BYTES = 16_384
MAX_HEADER_FIELDS = 32
MAX_BODY_BYTES = 1_048_576
_RECV_CHUNK_BYTES = 65_536

_TCHAR_BYTES: frozenset[int] = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


class HttpFramingError(BrainError):
    """Typed HTTP/1.1 framing error carrying an HTTP status classification and clean-EOF flag."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.INVALID_INPUT,
        message: str = "invalid input",
        *,
        http_status: int = 400,
        empty_eof: bool = False,
    ) -> None:
        super().__init__(code, message)
        self.http_status = http_status
        self.empty_eof = empty_eof


@dataclass(frozen=True)
class RequestHead:
    """Parsed HTTP/1.1 request start line and raw-ordered header tuples."""

    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    version: str = "HTTP/1.1"
    content_length: int | None = None

    def get_all(self, name: str) -> tuple[str, ...]:
        needle = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == needle)


@dataclass(frozen=True)
class ResponseHead:
    """Parsed HTTP/1.1 response status line and raw-ordered header tuples."""

    status: int
    headers: tuple[tuple[str, str], ...]
    version: str = "HTTP/1.1"
    content_length: int | None = None

    def get_all(self, name: str) -> tuple[str, ...]:
        needle = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == needle)


class _SilentRequestParser(http.server.BaseHTTPRequestHandler):
    """In-memory ``BaseHTTPRequestHandler`` adapter with response/log/``100 Continue`` side effects disabled."""

    protocol_version = "HTTP/1.1"

    def __init__(self, raw_requestline: bytes, raw_header_block: bytes) -> None:
        self.raw_requestline = raw_requestline
        self.rfile = io.BytesIO(raw_header_block)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 0)
        self.requestline = ""
        self.request_version = "HTTP/1.1"
        self.command = ""
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return None

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        _ = (code, size)
        return None

    def send_response(self, code: int, message: str | None = None) -> None:
        _ = (code, message)
        return None

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        _ = (code, message, explain)
        return None

    def handle_expect_100(self) -> bool:
        return False


def _remaining_seconds(monotonic_ns: Callable[[], int], deadline_ns: int) -> float:
    if isinstance(deadline_ns, bool):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer", http_status=400)
    if not isinstance(deadline_ns, int):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    rem_ns = deadline_ns - int(monotonic_ns())
    if rem_ns <= 0:
        raise HttpFramingError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded", http_status=408)
    return rem_ns / 1_000_000_000.0


def _has_forbidden_ctl(data: bytes) -> bool:
    return any(b <= 0x08 or (0x0A <= b <= 0x1F) or b == 0x7F for b in data)


def _validate_header_line(line: bytes) -> None:
    if line[0] in (0x20, 0x09):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    colon_idx = line.find(b":")
    if colon_idx <= 0:
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    name_bytes = line[:colon_idx]
    if not all(b in _TCHAR_BYTES for b in name_bytes):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    value_bytes = line[colon_idx + 1 : -2]
    if _has_forbidden_ctl(value_bytes):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)


def _validate_framed_headers(
    headers: tuple[tuple[str, str], ...],
    *,
    forbid_expect: bool,
) -> int | None:
    content_lengths: list[str] = []
    for name, value in headers:
        low = name.lower()
        if low == "transfer-encoding":
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if forbid_expect and low == "expect":
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if low == "content-length":
            content_lengths.append(value)

    if len(content_lengths) > 1:
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    if not content_lengths:
        return None

    raw_cl = content_lengths[0].strip(" \t")
    if not raw_cl or not raw_cl.isascii() or not raw_cl.isdigit():
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    significant = raw_cl.lstrip("0") or "0"
    if len(significant) > len(str(MAX_BODY_BYTES)):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "payload exceeds size limit", http_status=413)
    length = int(significant)
    if length > MAX_BODY_BYTES:
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "payload exceeds size limit", http_status=413)
    return length


class FramedReader:
    """Single-socket buffered HTTP/1.1 reader bounded by pre-parser byte/field caps and deadlines."""

    def __init__(self, sock: socket.socket, monotonic_ns: Callable[[], int]) -> None:
        self._sock = sock
        self._monotonic_ns = monotonic_ns
        self._buf = bytearray()
        self._eof = False

    def _require_deadline(self, deadline_ns: int) -> float:
        return _remaining_seconds(self._monotonic_ns, deadline_ns)

    def _fill_once(self, deadline_ns: int) -> int:
        rem_s = self._require_deadline(deadline_ns)
        self._sock.settimeout(rem_s)
        try:
            chunk = self._sock.recv(_RECV_CHUNK_BYTES)
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError) as err:
            raise HttpFramingError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded", http_status=408) from err
        except OSError as err:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400) from err
        self._require_deadline(deadline_ns)
        if not chunk:
            self._eof = True
            return 0
        self._buf.extend(chunk)
        return len(chunk)

    def _read_raw_head(self, deadline_ns: int) -> tuple[bytes, bytes]:
        self._require_deadline(deadline_ns)

        start_line: bytes | None = None
        while start_line is None:
            self._require_deadline(deadline_ns)
            nl_idx = self._buf.find(b"\n")
            if nl_idx != -1:
                line_len = nl_idx + 1
                if line_len > MAX_REQUEST_LINE_BYTES:
                    raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
                candidate = bytes(self._buf[:line_len])
                del self._buf[:line_len]
                if len(candidate) <= 2 or not candidate.endswith(b"\r\n") or b"\r" in candidate[:-2]:
                    raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
                start_line = candidate
                break

            if len(self._buf) >= MAX_REQUEST_LINE_BYTES:
                raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
            if self._eof:
                raise HttpFramingError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    http_status=400,
                    empty_eof=(len(self._buf) == 0),
                )
            self._fill_once(deadline_ns)

        header_block_bytes = 0
        header_lines: list[bytes] = []
        while True:
            self._require_deadline(deadline_ns)
            nl_idx = self._buf.find(b"\n")
            if nl_idx != -1:
                line_len = nl_idx + 1
                header_block_bytes += line_len
                if header_block_bytes > MAX_HEADER_BLOCK_BYTES:
                    raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
                line = bytes(self._buf[:line_len])
                del self._buf[:line_len]
                if not line.endswith(b"\r\n") or b"\r" in line[:-2]:
                    raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
                if line == b"\r\n":
                    header_lines.append(line)
                    break
                if len(header_lines) >= MAX_HEADER_FIELDS:
                    raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
                _validate_header_line(line)
                header_lines.append(line)
                continue

            if header_block_bytes + len(self._buf) >= MAX_HEADER_BLOCK_BYTES:
                raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
            if self._eof:
                raise HttpFramingError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    http_status=400,
                    empty_eof=False,
                )
            self._fill_once(deadline_ns)

        return start_line, b"".join(header_lines)

    def read_request_head(self, deadline_ns: int) -> RequestHead:
        start_line, raw_header_block = self._read_raw_head(deadline_ns)
        start_body = start_line[:-2]
        if any(b < 0x20 or b >= 0x7F for b in start_body):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        parts = start_body.split(b" ")
        if len(parts) != 3:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        method_b, target_b, version_b = parts
        if not method_b or not all(b in _TCHAR_BYTES for b in method_b):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if not target_b or any(b <= 0x20 or b >= 0x7F for b in target_b):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if version_b != b"HTTP/1.1":
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        raw_target = target_b.decode("ascii")

        parser = _SilentRequestParser(start_line, raw_header_block)
        if not parser.parse_request() or parser.request_version != "HTTP/1.1" or parser.headers.defects:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)

        headers = tuple((key, val.strip(" \t")) for key, val in parser.headers.items())
        content_length = _validate_framed_headers(headers, forbid_expect=True)
        return RequestHead(
            method=parser.command,
            target=raw_target,
            headers=headers,
            version=parser.request_version,
            content_length=content_length,
        )

    def read_response_head(self, deadline_ns: int) -> ResponseHead:
        start_line, raw_header_block = self._read_raw_head(deadline_ns)
        start_body = start_line[:-2]
        if _has_forbidden_ctl(start_body) or not start_body.startswith(b"HTTP/1.1 "):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        rest = start_body[9:]
        if len(rest) < 3:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        code_bytes = rest[:3]
        if not all(0x30 <= b <= 0x39 for b in code_bytes):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if len(rest) > 3 and rest[3] != 0x20:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        status_code = int(code_bytes.decode("ascii"))
        if not (100 <= status_code <= 599):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)

        try:
            msg = http.client.parse_headers(io.BytesIO(raw_header_block))
        except http.client.HTTPException as err:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400) from err
        if msg.defects:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)

        headers = tuple((key, val.strip(" \t")) for key, val in msg.items())
        content_length = _validate_framed_headers(headers, forbid_expect=False)
        return ResponseHead(
            status=status_code,
            headers=headers,
            version="HTTP/1.1",
            content_length=content_length,
        )

    def read_exact(self, size: int, deadline_ns: int) -> bytes:
        if isinstance(size, bool):
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer", http_status=400)
        if not isinstance(size, int) or size < 0:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
        if size > MAX_BODY_BYTES:
            raise HttpFramingError(ErrorCode.INVALID_INPUT, "payload exceeds size limit", http_status=413)
        self._require_deadline(deadline_ns)
        if size == 0:
            return b""
        while len(self._buf) < size:
            if self._eof:
                raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400, empty_eof=False)
            if self._fill_once(deadline_ns) == 0:
                raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400, empty_eof=False)
        self._require_deadline(deadline_ns)
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    def has_pipelined_bytes(self, deadline_ns: int) -> bool:
        self._require_deadline(deadline_ns)
        if len(self._buf) > 0:
            return True
        if self._eof:
            return False
        pending_fn = getattr(self._sock, "pending", None)
        if callable(pending_fn):
            pending_count = pending_fn()
            if isinstance(pending_count, int) and pending_count > 0:
                return True
        readable, _, _ = select.select([self._sock], [], [], 0.0)
        if not readable:
            return False
        prev_timeout = self._sock.gettimeout()
        self._sock.setblocking(False)
        try:
            chunk = self._sock.recv(1024)
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return False
        except OSError:
            self._eof = True
            return False
        finally:
            self._sock.settimeout(prev_timeout)
        if not chunk:
            self._eof = True
            return False
        self._buf.extend(chunk)
        self._require_deadline(deadline_ns)
        return True


def write_all(
    sock: socket.socket,
    data: bytes,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Write all ``data`` bytes to ``sock`` strictly before ``deadline_ns``."""
    if not isinstance(data, bytes):
        raise HttpFramingError(ErrorCode.INVALID_INPUT, "invalid input", http_status=400)
    _remaining_seconds(monotonic_ns, deadline_ns)
    offset = 0
    total = len(data)
    while offset < total:
        rem_s = _remaining_seconds(monotonic_ns, deadline_ns)
        sock.settimeout(rem_s)
        try:
            sent = sock.send(data[offset:])
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError) as err:
            raise HttpFramingError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded", http_status=408) from err
        except OSError as err:
            raise HttpFramingError(ErrorCode.IO_ERROR, "I/O error", http_status=400) from err
        _remaining_seconds(monotonic_ns, deadline_ns)
        if sent <= 0:
            raise HttpFramingError(ErrorCode.IO_ERROR, "I/O error", http_status=400)
        offset += sent
