"""JSON-RPC 2.0 protocol framing helpers (distinct from tool-level BrainError envelopes)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TypeAlias

from superbrain.core._json_parse import MAX_WIRE_BODY_BYTES
from superbrain.core.canonical import canonical_json, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2025-06-18"
MAX_JSONRPC_ID_BYTES = 128

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602

JsonRpcId: TypeAlias = str | int | None

_JSONRPC_ERROR_MESSAGES: dict[int, str] = {
    JSONRPC_PARSE_ERROR: "parse error",
    JSONRPC_INVALID_REQUEST: "invalid request",
    JSONRPC_METHOD_NOT_FOUND: "method not found",
    JSONRPC_INVALID_PARAMS: "invalid params",
}


class JsonRpcError(Exception):
    """Protocol-level JSON-RPC 2.0 framing error (distinct from tool-level BrainError)."""

    def __init__(self, code: int, message: str, *, request_id: JsonRpcId = None) -> None:
        safe_msg = _JSONRPC_ERROR_MESSAGES.get(code, "invalid request")
        super().__init__(f"jsonrpc {code}: {message}")
        self.code = code
        self.message = safe_msg
        self.request_id = request_id


def validate_jsonrpc_id(value: object) -> JsonRpcId:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, "boolean or float id not permitted")
    if type(value) is int:
        return value
    if isinstance(value, str):
        if len(value) > MAX_JSONRPC_ID_BYTES:
            raise JsonRpcError(JSONRPC_INVALID_REQUEST, "string id exceeds limit")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as err:
            raise JsonRpcError(JSONRPC_INVALID_REQUEST, "invalid UTF-8 in id") from err
        if len(encoded) > MAX_JSONRPC_ID_BYTES:
            raise JsonRpcError(JSONRPC_INVALID_REQUEST, "string id exceeds limit")
        return value
    raise JsonRpcError(JSONRPC_INVALID_REQUEST, "unsupported id type")


def parse_jsonrpc_frame(
    raw: bytes,
    parser: Callable[[bytes], JsonValue],
) -> tuple[JsonRpcId, str, dict[str, JsonValue] | None]:
    """Parse and validate a JSON-RPC 2.0 request or notification frame."""
    try:
        frame = parser(raw)
    except BrainError as err:
        if err.message in {"malformed JSON", "invalid UTF-8 encoding", "payload exceeds size limit"}:
            raise JsonRpcError(JSONRPC_PARSE_ERROR, err.message) from err
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, err.message) from err

    if not isinstance(frame, dict):
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, "frame must be object")
    req_id = validate_jsonrpc_id(frame.get("id")) if "id" in frame else None
    if frame.get("jsonrpc") != JSONRPC_VERSION:
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, "invalid jsonrpc version", request_id=req_id)
    if not set(frame) <= {"jsonrpc", "id", "method", "params"}:
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, "unexpected frame keys", request_id=req_id)
    method = frame.get("method")
    if not isinstance(method, str) or not (1 <= len(method) <= 128):
        raise JsonRpcError(JSONRPC_INVALID_REQUEST, "invalid method", request_id=req_id)
    params = frame.get("params")
    if params is not None and not isinstance(params, dict):
        raise JsonRpcError(JSONRPC_INVALID_PARAMS, "params must be object", request_id=req_id)
    return req_id, method, params


def build_jsonrpc_result(
    request_id: JsonRpcId,
    result: Mapping[str, JsonValue],
) -> bytes:
    checked_id = validate_jsonrpc_id(request_id)
    if not isinstance(result, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    res_dict = dict(result)
    validate_json(res_dict)
    encoded = canonical_json({"jsonrpc": JSONRPC_VERSION, "id": checked_id, "result": res_dict})
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    return encoded


def encode_jsonrpc_error(request_id: JsonRpcId, code: int, message: str | None = None) -> bytes:
    checked_id = validate_jsonrpc_id(request_id)
    safe_msg = _JSONRPC_ERROR_MESSAGES.get(code, "invalid request")
    if isinstance(message, str) and message in _JSONRPC_ERROR_MESSAGES.values():
        safe_msg = message
    encoded = canonical_json(
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": checked_id,
            "error": {"code": code, "message": safe_msg},
        }
    )
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    return encoded
