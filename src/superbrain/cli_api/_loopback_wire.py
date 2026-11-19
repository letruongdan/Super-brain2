"""Internal loopback HTTP wire codecs for identity probes and v2 tool calls."""

from __future__ import annotations

import hmac

from superbrain.core._json_parse import MAX_WIRE_BODY_BYTES, _validate_wire_structure
from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ENDPOINT_CONTRACT,
    SHA256_DIGEST_RE,
    CallResult,
    CaptureBatchCommand,
    Identity,
    Scope,
    ToolCommand,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core.wire import encode_envelope, load_catalog, parse_json

IDENTITY_PATH = "/v2/identity"
TOOL_CALL_PATH = "/v2/tools/call"
CAPTURE_EVENTS_PATH = "/v2/capture/events"
HEADER_STORE_ID = "X-Store-Id"
HEADER_WRITER_EPOCH = "X-Writer-Epoch"
HEADER_INSTANCE_ID = "X-Superbrain-Instance"
MAX_CORRELATION_ID_BYTES = 128

_KNOWN_TOOLS: frozenset[str] = frozenset(EXPECTED_TOOL_ORDER)
_CALL_KEYS: frozenset[str] = frozenset({"tool", "arguments", "correlation_id", "selected_scope", "schema_digest"})
_CAPTURE_BATCH_KEYS: frozenset[str] = frozenset(
    {"producer_stream", "repo_id", "checkout_id", "events", "correlation_id", "schema_digest"}
)
_SCOPE_KEYS: frozenset[str] = frozenset({"repo_id", "checkout_id"})
_IDENTITY_CORE_KEYS: frozenset[str] = frozenset({"store_id", "writer_epoch", "instance_id", "contract"})
_IDENTITY_KEYS: frozenset[str] = _IDENTITY_CORE_KEYS | {"schema_digest"}


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


def _resolve_schema_digest(schema_digest: str | None) -> str:
    if schema_digest is None:
        return load_catalog().schema_digest
    return require_sha256_digest(schema_digest)


def _check_wire_schema_digest(raw_digest: object, *, expected_schema_digest: str | None) -> str:
    expected = _resolve_schema_digest(expected_schema_digest)
    if (
        not isinstance(raw_digest, str)
        or not SHA256_DIGEST_RE.fullmatch(raw_digest)
        or not hmac.compare_digest(raw_digest, expected)
    ):
        raise BrainError(ErrorCode.UNSUPPORTED_VERSION, "unsupported version")
    return raw_digest


def encode_call(command: ToolCommand, *, schema_digest: str | None = None) -> bytes:
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
        "schema_digest": _resolve_schema_digest(schema_digest),
    }
    _validate_wire_structure(payload)
    encoded = canonical_json(payload)
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    return encoded


def decode_call(body: bytes, token: str, *, expected_schema_digest: str | None = None) -> ToolCommand:
    """Decode ``KernelHttpCall`` JSON bytes and bearer ``token`` into an unnormalized ``ToolCommand``."""
    if not isinstance(body, bytes) or not isinstance(token, str) or not token:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _check_wire_schema_digest(parsed.get("schema_digest"), expected_schema_digest=expected_schema_digest)
    if set(parsed) != _CALL_KEYS:
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


def encode_capture_batch(command: CaptureBatchCommand, *, schema_digest: str | None = None) -> bytes:
    """Encode ``CaptureBatchCommand`` as canonical ``POST /v2/capture/events`` JSON bytes."""
    if not isinstance(command, CaptureBatchCommand):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    correlation_id = _validate_correlation_id(command.correlation_id)
    payload: dict[str, JsonValue] = {
        "producer_stream": command.producer_stream,
        "repo_id": command.repo_id,
        "checkout_id": command.checkout_id,
        "events": [dict(ev) for ev in command.events],
        "correlation_id": correlation_id,
        "schema_digest": _resolve_schema_digest(schema_digest),
    }
    _validate_wire_structure(payload)
    encoded = canonical_json(payload)
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    return encoded


def decode_capture_batch(
    body: bytes,
    token: str,
    *,
    expected_schema_digest: str | None = None,
) -> CaptureBatchCommand:
    """Decode ``POST /v2/capture/events`` JSON bytes and bearer ``token`` into ``CaptureBatchCommand``."""
    if not isinstance(body, bytes) or not isinstance(token, str) or not token:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _check_wire_schema_digest(parsed.get("schema_digest"), expected_schema_digest=expected_schema_digest)
    if set(parsed) != _CAPTURE_BATCH_KEYS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    producer_stream = require_opaque_id(parsed["producer_stream"], label="producer_stream")
    repo_id = require_opaque_id(parsed["repo_id"], label="repo_id")
    checkout_id = require_opaque_id(parsed["checkout_id"], label="checkout_id")
    correlation_id = _validate_correlation_id(parsed["correlation_id"])
    raw_events = parsed["events"]
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > 1024:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if any(not isinstance(ev, dict) for ev in raw_events):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    events: tuple[dict[str, JsonValue], ...] = tuple(dict(ev) for ev in raw_events if isinstance(ev, dict))
    return CaptureBatchCommand(
        producer_stream=producer_stream,
        repo_id=repo_id,
        checkout_id=checkout_id,
        events=events,
        token=token,
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


def encode_identity_response(
    identity: Identity,
    contract: str = ENDPOINT_CONTRACT,
    *,
    schema_digest: str | None = None,
) -> bytes:
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
            "schema_digest": _resolve_schema_digest(schema_digest),
        }
    )


def parse_identity_response(body: bytes) -> tuple[Identity, str, str | None]:
    """Parse ``GET /v2/identity`` validating core 4 identity keys before ``schema_digest``."""
    if not isinstance(body, bytes):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(body)
    if not isinstance(parsed, dict) or set(parsed) not in (_IDENTITY_CORE_KEYS, _IDENTITY_KEYS):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    store_id = require_opaque_id(parsed["store_id"], label="store_id")
    writer_epoch = require_positive_int(parsed["writer_epoch"])
    instance_id = require_opaque_id(parsed["instance_id"], label="instance_id")
    contract = parsed["contract"]
    if not isinstance(contract, str) or contract != ENDPOINT_CONTRACT:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if "schema_digest" not in parsed:
        raw_digest: str | None = None
    elif not isinstance(parsed["schema_digest"], str):
        raw_digest = ""
    else:
        raw_digest = parsed["schema_digest"]
    return Identity(store_id=store_id, writer_epoch=writer_epoch, instance_id=instance_id), contract, raw_digest


def decode_identity_response(
    body: bytes,
    *,
    expected_schema_digest: str | None = None,
) -> tuple[Identity, str, str]:
    """Decode and validate a ``GET /v2/identity`` JSON payload including ``schema_digest``."""
    identity, contract, raw_digest = parse_identity_response(body)
    digest = _check_wire_schema_digest(raw_digest, expected_schema_digest=expected_schema_digest)
    return identity, contract, digest
