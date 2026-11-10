"""Bounded HTTP/1.1 framing and deadline-aware socket I/O for loopback transport."""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

from superbrain.core.errors import BrainError, ErrorCode

MAX_REQUEST_LINE_BYTES = 8_192
MAX_HEADER_BLOCK_BYTES = 16_384
MAX_HEADER_FIELDS = 32
MAX_BODY_BYTES = 1_048_576


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


class FramedReader:
    """Single-socket buffered HTTP/1.1 reader bounded by pre-parser byte/field caps and deadlines."""

    def __init__(self, sock: socket.socket, monotonic_ns: Callable[[], int]) -> None:
        self._sock = sock
        self._monotonic_ns = monotonic_ns

    def read_request_head(self, deadline_ns: int) -> RequestHead:
        _ = deadline_ns
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def read_response_head(self, deadline_ns: int) -> ResponseHead:
        _ = deadline_ns
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def read_exact(self, size: int, deadline_ns: int) -> bytes:
        _ = (size, deadline_ns)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def has_pipelined_bytes(self, deadline_ns: int) -> bool:
        _ = deadline_ns
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def write_all(
    sock: socket.socket,
    data: bytes,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Write all ``data`` bytes to ``sock`` strictly before ``deadline_ns``."""
    _ = (sock, data, deadline_ns, monotonic_ns)
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
