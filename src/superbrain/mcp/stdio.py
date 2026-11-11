"""Bounded MCP 2025-06-18 stdio session handler (`T7a`)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import BinaryIO, Literal, TypeAlias

from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER
from superbrain.core._wire_jsonrpc import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    JSONRPC_VERSION,
    JsonRpcError,
    JsonRpcId,
    encode_jsonrpc_error,
    parse_jsonrpc_frame,
    validate_jsonrpc_id,
)
from superbrain.core.canonical import canonical_json, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CallResult
from superbrain.core.wire import (
    MAX_WIRE_BODY_BYTES,
    MCP_PROTOCOL_VERSION,
    load_catalog,
    make_error_envelope,
    make_mcp_tool_result,
    parse_json,
)

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "SERVER_NAME",
    "SERVER_VERSION",
    "ToolCaller",
    "ToolCallUncertain",
    "run_stdio",
]

SERVER_NAME = "super-brain2"
SERVER_VERSION = "0.1.0"

JSONRPC_INTERNAL_ERROR = -32603
_READ_CHUNK_BYTES = 65_536
_KNOWN_TOOLS: frozenset[str] = frozenset(EXPECTED_TOOL_ORDER)
_UNCERTAIN_TEXT = (
    "daemon_unavailable: daemon unavailable; request_may_have_run=true; retry with the same idempotency_key"
)

ToolCaller: TypeAlias = Callable[[str, dict[str, JsonValue]], CallResult]
_SessionState: TypeAlias = Literal["new", "waiting_initialized", "ready"]


class ToolCallUncertain(Exception):
    """Raised when a tool call was sent or started on the wire and response was lost."""


def _write_frame(stdout: BinaryIO, payload: bytes) -> bool:
    try:
        stdout.write(payload + b"\n")
        stdout.flush()
    except (OSError, ValueError):
        return False
    return True


def _encode_internal_error(request_id: JsonRpcId) -> bytes:
    checked_id = validate_jsonrpc_id(request_id)
    return canonical_json(
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": checked_id,
            "error": {"code": JSONRPC_INTERNAL_ERROR, "message": "internal error"},
        }
    )


def _encode_result(request_id: JsonRpcId, result: Mapping[str, JsonValue]) -> bytes:
    checked_id = validate_jsonrpc_id(request_id)
    res_dict = dict(result)
    validate_json(res_dict)
    encoded = canonical_json({"jsonrpc": JSONRPC_VERSION, "id": checked_id, "result": res_dict})
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        return _encode_internal_error(checked_id)
    return encoded


def _valid_initialize_params(params: dict[str, JsonValue] | None) -> bool:
    if not isinstance(params, dict):
        return False
    protocol_version = params.get("protocolVersion")
    capabilities = params.get("capabilities")
    client_info = params.get("clientInfo")
    return (
        isinstance(protocol_version, str)
        and bool(protocol_version)
        and isinstance(capabilities, dict)
        and isinstance(client_info, dict)
    )


def _valid_tools_list_params(params: dict[str, JsonValue] | None) -> bool:
    if params is None:
        return True
    if not isinstance(params, dict):
        return False
    if not set(params) <= {"cursor", "_meta"}:
        return False
    return params.get("cursor") is None


def _execute_tool_call(
    request_id: JsonRpcId,
    params: dict[str, JsonValue] | None,
    call: ToolCaller,
) -> bytes:
    if not isinstance(params, dict) or not set(params) <= {"name", "arguments", "_meta"}:
        return encode_jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS)
    tool_name = params.get("name")
    arguments = params.get("arguments")
    if not isinstance(tool_name, str) or tool_name not in _KNOWN_TOOLS or not isinstance(arguments, dict):
        return encode_jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS)

    clean_args: dict[str, JsonValue] = dict(arguments)
    try:
        envelope = call(tool_name, clean_args)
    except BrainError as err:
        envelope = make_error_envelope(err)
    except ToolCallUncertain:
        err_env = make_error_envelope(BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"))
        mcp_res = make_mcp_tool_result(err_env)
        mcp_res["_meta"] = {"superbrain/request_may_have_run": True}
        mcp_res["content"] = [{"type": "text", "text": _UNCERTAIN_TEXT}]
        return _encode_result(request_id, mcp_res)

    try:
        mcp_res = make_mcp_tool_result(envelope)
    except BrainError:
        return _encode_internal_error(request_id)
    return _encode_result(request_id, mcp_res)


def _dispatch_line(
    raw_line: bytes,
    state: _SessionState,
    call: ToolCaller,
) -> tuple[_SessionState, bytes | None]:
    has_explicit_null_id = False
    has_empty_str_id = False

    def _parser(raw: bytes) -> JsonValue:
        nonlocal has_explicit_null_id, has_empty_str_id
        parsed = parse_json(raw)
        if isinstance(parsed, dict) and "id" in parsed:
            raw_id = parsed["id"]
            if raw_id is None:
                has_explicit_null_id = True
            elif raw_id == "":
                has_empty_str_id = True
        return parsed

    try:
        req_id, method, params = parse_jsonrpc_frame(raw_line, _parser)
    except JsonRpcError as err:
        if has_explicit_null_id or has_empty_str_id:
            return state, encode_jsonrpc_error(None, JSONRPC_INVALID_REQUEST)
        return state, encode_jsonrpc_error(err.request_id, err.code)

    if has_explicit_null_id or has_empty_str_id:
        return state, encode_jsonrpc_error(None, JSONRPC_INVALID_REQUEST)

    if req_id is None:
        if method == "notifications/initialized" and state == "waiting_initialized":
            return "ready", None
        return state, None

    if method == "ping":
        return state, _encode_result(req_id, {})

    if method == "initialize":
        if state != "new":
            return state, encode_jsonrpc_error(req_id, JSONRPC_INVALID_REQUEST)
        if not _valid_initialize_params(params):
            return state, encode_jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS)
        init_result: dict[str, JsonValue] = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
        return "waiting_initialized", _encode_result(req_id, init_result)

    if method == "notifications/initialized":
        return state, encode_jsonrpc_error(req_id, JSONRPC_INVALID_REQUEST)

    if state != "ready":
        return state, encode_jsonrpc_error(req_id, JSONRPC_INVALID_REQUEST)

    if method == "tools/list":
        if not _valid_tools_list_params(params):
            return state, encode_jsonrpc_error(req_id, JSONRPC_INVALID_PARAMS)
        tools_payload: dict[str, JsonValue] = {"tools": list(load_catalog().mcp_tools_list())}
        return state, _encode_result(req_id, tools_payload)

    if method == "tools/call":
        return state, _execute_tool_call(req_id, params, call)

    return state, encode_jsonrpc_error(req_id, JSONRPC_METHOD_NOT_FOUND)


def _read_chunk(stdin: BinaryIO, size: int) -> bytes:
    read1 = getattr(stdin, "read1", None)
    if callable(read1):
        chunk = read1(size)
        return chunk if isinstance(chunk, bytes) else bytes(chunk)
    return stdin.read(size)


def run_stdio(stdin: BinaryIO, stdout: BinaryIO, call: ToolCaller) -> int:
    """Run a bounded MCP 2025-06-18 JSON-RPC session over ``stdin`` and ``stdout``."""
    state: _SessionState = "new"
    buf = bytearray()

    while True:
        nl_idx = buf.find(b"\n")
        if nl_idx != -1:
            line_end = nl_idx - 1 if (nl_idx > 0 and buf[nl_idx - 1] == 0x0D) else nl_idx
            if line_end > MAX_WIRE_BODY_BYTES:
                ok = _write_frame(stdout, encode_jsonrpc_error(None, JSONRPC_PARSE_ERROR))
                return 0 if ok else 1
            raw_line = bytes(buf[:line_end])
            del buf[: nl_idx + 1]
            state, response = _dispatch_line(raw_line, state, call)
            if response is not None and not _write_frame(stdout, response):
                return 1
            continue

        if len(buf) > MAX_WIRE_BODY_BYTES + 1 or (
            len(buf) == MAX_WIRE_BODY_BYTES + 1 and buf[MAX_WIRE_BODY_BYTES] != 0x0D
        ):
            ok = _write_frame(stdout, encode_jsonrpc_error(None, JSONRPC_PARSE_ERROR))
            return 0 if ok else 1

        chunk = _read_chunk(stdin, _READ_CHUNK_BYTES)
        if not chunk:
            if not buf:
                return 0
            ok = _write_frame(stdout, encode_jsonrpc_error(None, JSONRPC_PARSE_ERROR))
            return 0 if ok else 1
        buf.extend(chunk)
