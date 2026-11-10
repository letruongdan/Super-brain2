"""Internal loopback HTTP wire codecs for identity probes and v2 tool calls."""

from __future__ import annotations

from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER
from superbrain.core.canonical import canonical_json, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ENDPOINT_CONTRACT,
    CallResult,
    Identity,
    Scope,
    ToolCommand,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core.wire import encode_envelope, parse_json

IDENTITY_PATH = "/v2/identity"
TOOL_CALL_PATH = "/v2/tools/call"
HEADER_STORE_ID = "X-Store-Id"
HEADER_WRITER_EPOCH = "X-Writer-Epoch"
HEADER_INSTANCE_ID = "X-Superbrain-Instance"
MAX_CORRELATION_ID_BYTES = 128

_KNOWN_TOOLS: frozenset[str] = frozenset(EXPECTED_TOOL_ORDER)
_CALL_KEYS: frozenset[str] = frozenset({"tool", "arguments", "correlation_id", "selected_scope"})
_SCOPE_KEYS: frozenset[str] = frozenset({"repo_id", "checkout_id"})
_IDENTITY_KEYS: frozenset[str] = frozenset({"store_id", "writer_epoch", "instance_id", "contract"})


def _validate_correlation_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_CORRELATION_ID_BYTES):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "unpaired surrogate") from err
    if not (1 <= len(encoded) <= MAX_CORRELATION_ID_BYTES):
        raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
    return value


def encode_call(command: ToolCommand) -> bytes:
    """Encode ``command`` as canonical ``KernelHttpCall`` JSON bytes without normalizing ``arguments``."""
    if not isinstance(command, ToolCommand):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(command.tool, str) or command.tool not in _KNOWN_TOOLS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(command.arguments, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    correlation_id = _validate_correlation_id(command.correlation_id)
    if command.selected_scope is not None and not isinstance(command.selected_scope, Scope):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    payload: dict[str, JsonValue] = {
        "tool": command.tool,
        "arguments": dict(command.arguments),
        "correlation_id": correlation_id,
        "selected_scope": command.selected_scope.to_dict() if command.selected_scope is not None else None,
    }
    validate_json(payload)
    encoded = canonical_json(payload)
    parse_json(encoded)
    return encoded


def decode_call(body: bytes, token: str) -> ToolCommand:
    """Decode ``KernelHttpCall`` JSON bytes and bearer ``token`` into an unnormalized ``ToolCommand``."""
    if not isinstance(body, bytes) or not isinstance(token, str) or not token:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict) or set(parsed) != _CALL_KEYS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    tool = parsed["tool"]
    if not isinstance(tool, str) or tool not in _KNOWN_TOOLS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    arguments = parsed["arguments"]
    if not isinstance(arguments, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    correlation_id = _validate_correlation_id(parsed["correlation_id"])

    raw_scope = parsed["selected_scope"]
    if raw_scope is None:
        selected_scope: Scope | None = None
    else:
        if not isinstance(raw_scope, dict) or set(raw_scope) != _SCOPE_KEYS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        repo_id = require_opaque_id(raw_scope["repo_id"], label="repo_id")
        raw_chk = raw_scope["checkout_id"]
        checkout_id = None if raw_chk is None else require_opaque_id(raw_chk, label="checkout_id")
        selected_scope = Scope(repo_id=repo_id, checkout_id=checkout_id)

    return ToolCommand(
        tool=tool,
        arguments=arguments,
        token=token,
        selected_scope=selected_scope,
        correlation_id=correlation_id,
    )


def decode_result(body: bytes) -> CallResult:
    """Decode and validate a v2 ``CallResult`` JSON response envelope."""
    if not isinstance(body, bytes):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    encode_envelope(parsed)
    return parsed


def encode_identity_response(identity: Identity, contract: str = ENDPOINT_CONTRACT) -> bytes:
    """Encode a canonical ``GET /v2/identity`` JSON payload."""
    if not isinstance(identity, Identity):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(contract, str) or contract != ENDPOINT_CONTRACT:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return canonical_json(
        {
            "store_id": identity.store_id,
            "writer_epoch": identity.writer_epoch,
            "instance_id": identity.instance_id,
            "contract": contract,
        }
    )


def decode_identity_response(body: bytes) -> tuple[Identity, str]:
    """Decode and validate a ``GET /v2/identity`` JSON payload."""
    if not isinstance(body, bytes):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict) or set(parsed) != _IDENTITY_KEYS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    store_id = require_opaque_id(parsed["store_id"], label="store_id")
    writer_epoch = require_positive_int(parsed["writer_epoch"])
    instance_id = require_opaque_id(parsed["instance_id"], label="instance_id")
    contract = parsed["contract"]
    if not isinstance(contract, str) or contract != ENDPOINT_CONTRACT:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return Identity(store_id=store_id, writer_epoch=writer_epoch, instance_id=instance_id), contract
