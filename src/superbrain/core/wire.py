"""Strict JSON wire codec, MCP v2 call normalizer, envelope encoder, and JSON-RPC framing."""

from __future__ import annotations

import copy
from collections.abc import Mapping

from superbrain.core._json_parse import (
    MAX_WIRE_ARRAY_LEN,
    MAX_WIRE_BODY_BYTES,
    MAX_WIRE_DEPTH,
    MAX_WIRE_TEXT_BYTES,
    _encode_wire_str,
    _validate_wire_structure,
    parse_json,
)
from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER, build_catalog
from superbrain.core._wire_jsonrpc import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    JSONRPC_VERSION,
    MAX_JSONRPC_ID_BYTES,
    JsonRpcError,
    JsonRpcId,
    build_jsonrpc_result,
    encode_jsonrpc_error,
    parse_jsonrpc_frame,
    validate_jsonrpc_id,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.client_profile import SelectedWorkspace
from superbrain.core.errors import (
    BrainError,
    ErrorCode,
    brain_error_wire_message,
    is_safe_wire_message,
)
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    IDEMPOTENCY_KEY_RE,
    Call,
    ObjectRef,
    Principal,
    ReadAckInput,
    Scope,
    ToolCatalog,
    require_object_kind,
    require_opaque_id,
    require_positive_int,
    require_workspace_hint,
)

__all__ = [
    "DEFAULT_CONTEXT_BUDGET_TOKENS",
    "DEFAULT_SEARCH_LIMIT",
    "JSONRPC_INVALID_PARAMS",
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_METHOD_NOT_FOUND",
    "JSONRPC_PARSE_ERROR",
    "JSONRPC_VERSION",
    "JsonRpcError",
    "JsonRpcId",
    "MAX_CONTEXT_BUDGET_TOKENS",
    "MAX_JSONRPC_ID_BYTES",
    "MAX_SEARCH_LIMIT",
    "MAX_WIRE_ARRAY_LEN",
    "MAX_WIRE_BODY_BYTES",
    "MAX_WIRE_DEPTH",
    "MAX_WIRE_TEXT_BYTES",
    "MCP_PROTOCOL_VERSION",
    "SCHEMA_VERSION",
    "WORKSPACE_SCOPED_TOOLS",
    "canonical_request_payload",
    "encode_envelope",
    "encode_jsonrpc_error",
    "encode_jsonrpc_result",
    "load_catalog",
    "make_error_envelope",
    "make_mcp_tool_result",
    "make_success_envelope",
    "normalize_call",
    "normalize_shim_args",
    "parse_json",
    "parse_jsonrpc_request",
    "validate_jsonrpc_id",
]

MCP_PROTOCOL_VERSION = "2025-06-18"
SCHEMA_VERSION = "2.0"

DEFAULT_CONTEXT_BUDGET_TOKENS = 4_000
MAX_CONTEXT_BUDGET_TOKENS = 4_000
DEFAULT_SEARCH_LIMIT = 20
MAX_SEARCH_LIMIT = 100

WORKSPACE_SCOPED_TOOLS: frozenset[str] = frozenset(
    {
        "prepare_task",
        "search_knowledge",
        "get_artifact",
        "submit_episode",
        "record_outcome",
        "request_improvement",
    }
)
_KNOWN_TOOLS = frozenset(EXPECTED_TOOL_ORDER)
_IDENTITY_FIELDS = ("principal_id", "owner_id", "harness_id", "machine_id")
_FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "source",
        "approval",
        "approval_receipt",
        "native_receipt",
        "snapshot_status",
        "degraded_codes",
        "unknown_source",
        "verified",
        "verification_status",
    }
)


def _require_nonempty_text(value: object, *, max_bytes: int = MAX_WIRE_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _encode_wire_str(value, max_bytes=max_bytes)
    return value


def _require_idempotency_key(value: object) -> str:
    if not isinstance(value, str) or not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def _require_bounded_int(value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if type(value) is not int or not (minimum <= value <= maximum):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def load_catalog() -> ToolCatalog:
    """Return the canonical ``mcp-tools-v2`` catalog with self-contained per-tool schemas."""
    return build_catalog(parse_json)


def _check_keys(
    obj: Mapping[str, JsonValue],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    allowed = required | optional
    for key in obj:
        if key in _FORBIDDEN_AUTHORITY_KEYS and key not in allowed:
            raise BrainError(ErrorCode.INVALID_INPUT, "forbidden client-supplied authority field")
        if key not in allowed:
            raise BrainError(ErrorCode.INVALID_INPUT, "unknown field")
    for req in required:
        if req not in obj:
            raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")


def _reject_nested_authority_keys(node: JsonValue) -> None:
    stack: list[JsonValue] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                if key in _FORBIDDEN_AUTHORITY_KEYS:
                    raise BrainError(ErrorCode.INVALID_INPUT, "forbidden client-supplied authority field")
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)


def _validate_read_acks(raw_acks: JsonValue) -> None:
    if not isinstance(raw_acks, list):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for item in raw_acks:
        if not isinstance(item, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ReadAckInput.from_dict(item)


def _normalize_prepare_task(business: dict[str, JsonValue]) -> None:
    _check_keys(
        business,
        required=frozenset({"schema_version", "description", "idempotency_key"}),
        optional=frozenset(
            {
                "workspace_hint",
                "workspace_id",
                "checkout_id",
                "source_snapshot_id",
                "task_id",
                "context_budget_tokens",
            }
        ),
    )
    has_hint = "workspace_hint" in business
    has_ws = "workspace_id" in business
    has_chk = "checkout_id" in business
    if not ((has_hint and not has_ws and not has_chk) or (not has_hint and has_ws and has_chk)):
        raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")
    if has_hint:
        require_workspace_hint(business["workspace_hint"])
    else:
        require_opaque_id(business["workspace_id"], label="workspace_id")
        require_opaque_id(business["checkout_id"], label="checkout_id")

    if "source_snapshot_id" in business:
        require_opaque_id(business["source_snapshot_id"], label="source_snapshot_id")
    if "task_id" in business:
        require_opaque_id(business["task_id"], label="task_id")
    _require_nonempty_text(business["description"])
    if "context_budget_tokens" not in business:
        business["context_budget_tokens"] = DEFAULT_CONTEXT_BUDGET_TOKENS
    _require_bounded_int(
        business["context_budget_tokens"],
        minimum=1,
        maximum=MAX_CONTEXT_BUDGET_TOKENS,
    )
    _require_idempotency_key(business["idempotency_key"])


def _normalize_submit_episode(business: dict[str, JsonValue]) -> None:
    _check_keys(
        business,
        required=frozenset({"schema_version", "task_id", "session_id", "evidence", "idempotency_key"}),
        optional=frozenset({"workspace_id", "checkout_id", "candidate_lesson", "read_acks"}),
    )
    require_opaque_id(business["task_id"], label="task_id")
    require_opaque_id(business["session_id"], label="session_id")
    if "workspace_id" in business:
        require_opaque_id(business["workspace_id"], label="workspace_id")
    if "checkout_id" in business:
        require_opaque_id(business["checkout_id"], label="checkout_id")

    evidence = business["evidence"]
    if not isinstance(evidence, list):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for item in evidence:
        if not isinstance(item, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _check_keys(item, required=frozenset({"kind", "data"}))
        require_object_kind(item["kind"])
        data = item["data"]
        if not isinstance(data, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _reject_nested_authority_keys(data)

    if "candidate_lesson" in business:
        lesson = business["candidate_lesson"]
        if not isinstance(lesson, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _check_keys(
            lesson,
            required=frozenset({"title", "content"}),
            optional=frozenset({"conditions"}),
        )
        title = _require_nonempty_text(lesson["title"])
        if len(title) > 256:
            raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
        _require_nonempty_text(lesson["content"])
        if "conditions" in lesson:
            conds = lesson["conditions"]
            if not isinstance(conds, list) or len(conds) > 64:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            for cond in conds:
                _require_nonempty_text(cond)

    if "read_acks" in business:
        _validate_read_acks(business["read_acks"])
    _require_idempotency_key(business["idempotency_key"])


def normalize_call(
    tool: str,
    args: JsonValue | Mapping[str, JsonValue],
    principal: Principal,
    *,
    selected_scope: Scope | None,
    correlation_id: str | None = None,
) -> Call:
    """Validate and normalize MCP v2 tool arguments against ``principal``."""
    if not isinstance(principal, Principal):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if selected_scope is not None and not isinstance(selected_scope, Scope):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if correlation_id is not None:
        if not isinstance(correlation_id, str) or not correlation_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _encode_wire_str(correlation_id, max_bytes=MAX_JSONRPC_ID_BYTES)
    if not isinstance(tool, str) or tool not in _KNOWN_TOOLS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(args, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    _validate_wire_structure(args)

    if "schema_version" not in args:
        raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")
    raw_version = args["schema_version"]
    if not isinstance(raw_version, str):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if raw_version != SCHEMA_VERSION:
        raise BrainError(ErrorCode.UNSUPPORTED_VERSION, "unsupported schema version")

    for id_field in _IDENTITY_FIELDS:
        if id_field in args:
            supplied = args[id_field]
            if not isinstance(supplied, str) or not supplied:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if supplied != getattr(principal, id_field):
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")

    business: dict[str, JsonValue] = {
        key: copy.deepcopy(val) for key, val in args.items() if key not in _IDENTITY_FIELDS
    }

    if tool == "prepare_task":
        _normalize_prepare_task(business)
    elif tool == "search_knowledge":
        _check_keys(
            business,
            required=frozenset({"schema_version", "workspace_id", "query"}),
            optional=frozenset({"limit"}),
        )
        require_opaque_id(business["workspace_id"], label="workspace_id")
        _require_nonempty_text(business["query"])
        if "limit" not in business:
            business["limit"] = DEFAULT_SEARCH_LIMIT
        _require_bounded_int(business["limit"], minimum=1, maximum=MAX_SEARCH_LIMIT)
    elif tool == "get_artifact":
        _check_keys(
            business,
            required=frozenset(
                {"schema_version", "workspace_id", "task_id", "artifact_id", "revision", "level", "idempotency_key"}
            ),
        )
        require_opaque_id(business["workspace_id"], label="workspace_id")
        require_opaque_id(business["task_id"], label="task_id")
        require_opaque_id(business["artifact_id"], label="artifact_id")
        require_positive_int(business["revision"])
        level = business["level"]
        if not isinstance(level, str) or level not in {"L0", "L1", "L2"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_idempotency_key(business["idempotency_key"])
    elif tool == "submit_episode":
        _normalize_submit_episode(business)
    elif tool == "record_outcome":
        _check_keys(
            business,
            required=frozenset({"schema_version", "workspace_id", "delivery_id", "outcome", "idempotency_key"}),
            optional=frozenset({"applied_refs", "read_acks"}),
        )
        require_opaque_id(business["workspace_id"], label="workspace_id")
        require_opaque_id(business["delivery_id"], label="delivery_id")
        outcome = business["outcome"]
        if not isinstance(outcome, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if outcome == "verified":
            raise BrainError(ErrorCode.INVALID_INPUT, "forbidden client-supplied authority field")
        if outcome not in {"success", "failure", "unknown"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if "applied_refs" in business:
            refs = business["applied_refs"]
            if not isinstance(refs, list):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            for ref_item in refs:
                if not isinstance(ref_item, dict):
                    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
                ObjectRef.from_dict(ref_item)
        if "read_acks" in business:
            _validate_read_acks(business["read_acks"])
        _require_idempotency_key(business["idempotency_key"])
    elif tool == "request_improvement":
        _check_keys(
            business,
            required=frozenset({"schema_version", "workspace_id", "task_id", "idempotency_key"}),
        )
        require_opaque_id(business["workspace_id"], label="workspace_id")
        require_opaque_id(business["task_id"], label="task_id")
        _require_idempotency_key(business["idempotency_key"])
    elif tool == "get_job":
        _check_keys(business, required=frozenset({"schema_version", "job_id"}))
        require_opaque_id(business["job_id"], label="job_id")
    elif tool == "get_health":
        _check_keys(
            business,
            required=frozenset({"schema_version"}),
            optional=frozenset({"deep", "idempotency_key"}),
        )
        if "deep" not in business:
            business["deep"] = False
        deep = business["deep"]
        if not isinstance(deep, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if deep:
            if "idempotency_key" not in business:
                raise BrainError(ErrorCode.INVALID_INPUT, "deep health requires idempotency_key")
            _require_idempotency_key(business["idempotency_key"])
        elif "idempotency_key" in business:
            raise BrainError(ErrorCode.INVALID_INPUT, "shallow health forbids idempotency_key")

    return Call(
        tool=tool,
        arguments=business,
        correlation_id=correlation_id,
        selected_scope=selected_scope,
    )


def _check_shim_selector_match(
    tool: str,
    out: dict[str, JsonValue],
    selected: SelectedWorkspace,
) -> None:
    has_hint = "workspace_hint" in out
    has_ws = "workspace_id" in out
    has_chk = "checkout_id" in out

    if tool == "prepare_task":
        if not has_hint and not has_ws and not has_chk:
            out["workspace_hint"] = selected.alias
            return
        if has_hint and not has_ws and not has_chk:
            hint = require_workspace_hint(out["workspace_hint"])
            if hint != selected.alias:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
            return
        if not has_hint and has_ws and has_chk:
            ws_id = require_opaque_id(out["workspace_id"], label="workspace_id")
            chk_id = require_opaque_id(out["checkout_id"], label="checkout_id")
            if ws_id != selected.scope.repo_id or chk_id != selected.scope.checkout_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
            return
        raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")

    if has_hint:
        hint = require_workspace_hint(out["workspace_hint"])
        if hint != selected.alias:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if has_ws:
        ws_id = require_opaque_id(out["workspace_id"], label="workspace_id")
        if ws_id != selected.scope.repo_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if has_chk:
        chk_id = require_opaque_id(out["checkout_id"], label="checkout_id")
        if chk_id != selected.scope.checkout_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")


def normalize_shim_args(
    tool: str,
    args: JsonValue | Mapping[str, JsonValue],
    selected: SelectedWorkspace | None,
) -> dict[str, JsonValue]:
    """Normalize client shim arguments against the profile's bound ``SelectedWorkspace`` before fingerprinting."""
    if not isinstance(tool, str) or tool not in _KNOWN_TOOLS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(args, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if selected is not None and not isinstance(selected, SelectedWorkspace):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _validate_wire_structure(args)

    out: dict[str, JsonValue] = copy.deepcopy(args)
    if "selected_scope" in out:
        raise BrainError(ErrorCode.INVALID_INPUT, "forbidden client-supplied authority field")

    if selected is None:
        if tool in WORKSPACE_SCOPED_TOOLS:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return out

    _check_shim_selector_match(tool, out, selected)
    return out


def canonical_request_payload(call: Call) -> bytes:
    """Canonical JSON bytes for request HMAC (excludes framing ``correlation_id``)."""
    payload: dict[str, JsonValue] = {
        "tool": call.tool,
        "selected_scope": call.selected_scope.to_dict() if call.selected_scope is not None else None,
        "arguments": call.arguments,
    }
    return canonical_json(payload)


def make_success_envelope(data: JsonValue) -> dict[str, JsonValue]:
    _validate_wire_structure(data)
    return {"ok": True, "data": data}


def make_error_envelope(error: BrainError) -> dict[str, JsonValue]:
    return {
        "ok": False,
        "error": {
            "code": error.code.value,
            "message": brain_error_wire_message(error),
        },
    }


def encode_envelope(result: JsonValue | Mapping[str, JsonValue]) -> bytes:
    """Validate MCP v2 result envelope shape and safe error allowlist, returning canonical JSON."""
    _validate_wire_structure(result)
    if not isinstance(result, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    ok = result.get("ok")
    if not isinstance(ok, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if ok:
        if set(result) != {"ok", "data"} or not isinstance(result["data"], dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    else:
        if set(result) != {"ok", "error"} or not isinstance(result["error"], dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        err_obj = result["error"]
        if set(err_obj) != {"code", "message"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        code, message = err_obj["code"], err_obj["message"]
        if not isinstance(code, str) or code not in {c.value for c in ErrorCode}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(message, str) or not is_safe_wire_message(message):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    encoded = canonical_json(result)
    if len(encoded) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    return encoded


def make_mcp_tool_result(envelope: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Wrap a validated v2 envelope into an MCP ``tools/call`` result payload."""
    env_dict: dict[str, JsonValue] = dict(envelope)
    canonical_text = encode_envelope(env_dict).decode("utf-8")
    return {
        "structuredContent": env_dict,
        "content": [{"type": "text", "text": canonical_text}],
        "isError": not bool(env_dict["ok"]),
    }


def parse_jsonrpc_request(raw: bytes) -> tuple[JsonRpcId, str, dict[str, JsonValue] | None]:
    """Parse and validate a JSON-RPC 2.0 request or notification frame."""
    return parse_jsonrpc_frame(raw, parse_json)


def encode_jsonrpc_result(request_id: JsonRpcId, result: Mapping[str, JsonValue]) -> bytes:
    return build_jsonrpc_result(request_id, result)
