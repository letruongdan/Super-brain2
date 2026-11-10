"""Pin-before-secret TLS loopback client with single-use identity-fenced connections."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import CallResult, Endpoint, ToolCommand, require_opaque_id

CLIENT_CONNECT_BUDGET_NS = 2_000_000_000
CLIENT_TOOL_BUDGET_NS = 2_000_000_000

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class LoopbackTransportError(BrainError):
    """Typed loopback transport failure carrying whether the POST tool call may have executed."""

    request_may_have_run: bool

    def __init__(self, code: ErrorCode, message: str, *, request_may_have_run: bool) -> None:
        if type(request_may_have_run) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        super().__init__(code, message)
        self.request_may_have_run = request_may_have_run


@dataclass(frozen=True)
class LoopbackTarget:
    """Pre-loaded trust and endpoint parameters for connecting to a loopback daemon."""

    endpoint: Endpoint
    expected_store_id: str
    ca_pem: str
    leaf_cert_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, Endpoint):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(self.expected_store_id, label="expected_store_id")
        if not isinstance(self.ca_pem, str) or not self.ca_pem.strip():
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.leaf_cert_sha256, str) or _HEX64_RE.fullmatch(self.leaf_cert_sha256) is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


class PinnedConnection:
    """Single-use TLS connection bound to a verified loopback daemon identity."""

    def call(self, command: ToolCommand, *, deadline_ns: int | None = None) -> CallResult:
        _ = (command, deadline_ns)
        raise LoopbackTransportError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "capability unavailable",
            request_may_have_run=False,
        )

    def close(self) -> None:
        return None


class LoopbackClient:
    """TLS loopback client verifying leaf pin and live identity before sending bearer credentials."""

    def __init__(self, monotonic_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if not callable(monotonic_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._monotonic_ns = monotonic_ns

    def connect(self, target: LoopbackTarget, deadline_ns: int | None = None) -> PinnedConnection:
        _ = (target, deadline_ns)
        raise LoopbackTransportError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "capability unavailable",
            request_may_have_run=False,
        )

    def call(
        self,
        target: LoopbackTarget,
        command: ToolCommand,
        *,
        deadline_ns: int | None = None,
    ) -> CallResult:
        _ = (target, command, deadline_ns)
        raise LoopbackTransportError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "capability unavailable",
            request_may_have_run=False,
        )
