"""Internal loopback HTTP wire codecs for identity probes and v2 tool calls."""

from __future__ import annotations

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ENDPOINT_CONTRACT, CallResult, Identity, ToolCommand

IDENTITY_PATH = "/v2/identity"
TOOL_CALL_PATH = "/v2/tools/call"
HEADER_STORE_ID = "X-Store-Id"
HEADER_WRITER_EPOCH = "X-Writer-Epoch"
HEADER_INSTANCE_ID = "X-Superbrain-Instance"
MAX_CORRELATION_ID_BYTES = 128


def encode_call(command: ToolCommand) -> bytes:
    """Encode ``command`` as canonical ``KernelHttpCall`` JSON bytes."""
    _ = command
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def decode_call(body: bytes, token: str) -> ToolCommand:
    """Decode ``KernelHttpCall`` JSON bytes and bearer ``token`` into a ``ToolCommand``."""
    _ = (body, token)
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def decode_result(body: bytes) -> CallResult:
    """Decode and validate a v2 ``CallResult`` JSON response envelope."""
    _ = body
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def encode_identity_response(identity: Identity, contract: str = ENDPOINT_CONTRACT) -> bytes:
    """Encode a canonical ``GET /v2/identity`` JSON payload."""
    _ = (identity, contract)
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")


def decode_identity_response(body: bytes) -> tuple[Identity, str]:
    """Decode and validate a ``GET /v2/identity`` JSON payload."""
    _ = body
    raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
