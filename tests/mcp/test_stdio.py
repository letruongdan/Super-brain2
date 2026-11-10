"""Requirement-derived tests for the bounded MCP 2025-06-18 stdio session (`T7a`)."""

from __future__ import annotations

import copy
import io
from typing import Any

from superbrain.mcp.stdio import (
    MCP_PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    ToolCaller,
    ToolCallUncertain,
    run_stdio,
)


def _collect_local_refs(node: object) -> set[str]:
    refs: set[str] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            assert ref.startswith("#/$defs/"), f"unexpected non-local $ref: {ref}"
            refs.add(ref.removeprefix("#/$defs/"))
        for key, value in node.items():
            if key != "$defs":
                refs |= _collect_local_refs(value)
    elif isinstance(node, list):
        for item in node:
            refs |= _collect_local_refs(item)
    return refs


def _transitive_closure(root_node: dict[str, Any], defs: dict[str, Any]) -> set[str]:
    needed: set[str] = set()
    frontier = list(_collect_local_refs(root_node))
    while frontier:
        name = frontier.pop()
        assert name in defs, f"missing $defs[{name!r}] in closure"
        if name not in needed:
            needed.add(name)
            frontier.extend(_collect_local_refs(defs[name]))
    return needed


def _decode_stdout_frames(raw_stdout: bytes) -> list[dict[str, Any]]:
    from superbrain.core.wire import parse_json

    if not raw_stdout:
        return []
    assert raw_stdout.endswith(b"\n"), "every stdout frame must be newline-terminated"
    lines = raw_stdout.splitlines()
    frames: list[dict[str, Any]] = []
    for line in lines:
        assert line, "stdout must not contain empty lines"
        parsed = parse_json(line)
        assert isinstance(parsed, dict), "each stdout frame must be a JSON object"
        assert parsed.get("jsonrpc") == "2.0"
        frames.append(parsed)
    return frames


def _init_frames() -> list[bytes]:
    from superbrain.core.canonical import canonical_json

    init_req = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "sb2-test-client", "version": "1.0.0"},
        },
    }
    init_notif = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    return [
        canonical_json(init_req) + b"\n",
        canonical_json(init_notif) + b"\n",
    ]


class _BrokenStdout(io.BytesIO):
    """Binary stdout double that raises an OSError on a configured write or flush call."""

    def __init__(self, *, fail_on: str, fail_at_call: int) -> None:
        super().__init__()
        self._fail_on = fail_on
        self._fail_at_call = fail_at_call
        self.write_calls = 0
        self.flush_calls = 0

    def write(self, b: Any) -> int:
        self.write_calls += 1
        if self._fail_on == "write" and self.write_calls >= self._fail_at_call:
            raise BrokenPipeError("simulated broken pipe on stdout.write")
        return super().write(b)

    def flush(self) -> None:
        self.flush_calls += 1
        if self._fail_on == "flush" and self.flush_calls >= self._fail_at_call:
            raise OSError("simulated broken pipe on stdout.flush")
        super().flush()


def test_stdio_lifecycle_lists_eight_tools_and_calls_fixture() -> None:
    import jsonschema

    from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER
    from superbrain.core.canonical import canonical_json
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import CallResult
    from superbrain.core.wire import (
        load_catalog,
        make_error_envelope,
        make_mcp_tool_result,
        make_success_envelope,
        parse_json,
    )

    assert MCP_PROTOCOL_VERSION == "2025-06-18"
    assert SERVER_NAME == "super-brain2"
    assert SERVER_VERSION == "0.1.0"

    calls: list[tuple[str, dict[str, JsonValue]]] = []

    def fake_caller(tool: str, arguments: dict[str, JsonValue]) -> CallResult:
        calls.append((tool, copy.deepcopy(arguments)))
        if tool == "get_health":
            return make_success_envelope({"ready": True, "store_id": "store-01"})
        if tool == "search_knowledge":
            return make_error_envelope(BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable"))
        if tool == "get_job":
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        raise AssertionError(f"unexpected tool dispatch: {tool}")

    caller: ToolCaller = fake_caller

    # Clean immediate EOF returns 0 with empty stdout and zero dispatches
    empty_stdout = io.BytesIO()
    assert run_stdio(io.BytesIO(b""), empty_stdout, caller) == 0
    assert empty_stdout.getvalue() == b""
    assert calls == []

    # Full lifecycle mixing CRLF and LF delimiters
    wire_input = b"".join(
        [
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "claude-code", "version": "2.0"},
                    },
                }
            )
            + b"\r\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "ping-1",
                    "method": "ping",
                }
            )
            + b"\r\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "call-ok",
                    "method": "tools/call",
                    "params": {
                        "name": "get_health",
                        "arguments": {"schema_version": "2.0", "deep": False},
                        "_meta": {"progressToken": "tok-1", "superbrain/untrusted": True},
                    },
                }
            )
            + b"\r\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "search_knowledge",
                        "arguments": {
                            "schema_version": "2.0",
                            "workspace_id": "ws-01",
                            "query": "bounded stdio",
                        },
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "call-raised-err",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "job-404"},
                    },
                }
            )
            + b"\r\n",
        ]
    )

    stdout_buf = io.BytesIO()
    rc = run_stdio(io.BytesIO(wire_input), stdout_buf, caller)
    assert rc == 0

    responses = _decode_stdout_frames(stdout_buf.getvalue())
    assert len(responses) == 6

    # 1. initialize response
    assert responses[0] == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "super-brain2", "version": "0.1.0"},
        },
    }

    # 2. ping response (notifications/initialized emitted no frame)
    assert responses[1] == {
        "jsonrpc": "2.0",
        "id": "ping-1",
        "result": {},
    }

    # 3. tools/list response: exact 8 tools in canonical order with self-contained $defs closures
    expected_catalog_tools = load_catalog().mcp_tools_list()
    assert responses[2]["id"] == 2
    list_result = responses[2]["result"]
    assert isinstance(list_result, dict)
    tools_list = list_result.get("tools")
    assert isinstance(tools_list, list)
    assert [t["name"] for t in tools_list if isinstance(t, dict)] == list(EXPECTED_TOOL_ORDER)
    assert len(tools_list) == 8
    assert tools_list == expected_catalog_tools

    for tool_entry in tools_list:
        assert isinstance(tool_entry, dict)
        for schema_key in ("inputSchema", "outputSchema"):
            schema_obj = tool_entry[schema_key]
            assert isinstance(schema_obj, dict)
            jsonschema.Draft202012Validator.check_schema(schema_obj)
            defs = schema_obj.get("$defs")
            assert isinstance(defs, dict)
            assert set(defs) == _transitive_closure(schema_obj, defs)

    # 4. tools/call ok=True response & _meta stripping verification
    expected_ok_env = make_success_envelope({"ready": True, "store_id": "store-01"})
    assert responses[3] == {
        "jsonrpc": "2.0",
        "id": "call-ok",
        "result": make_mcp_tool_result(expected_ok_env),
    }
    res_ok = responses[3]["result"]
    assert isinstance(res_ok, dict)
    assert res_ok["isError"] is False
    assert res_ok["structuredContent"] == expected_ok_env
    assert "_meta" not in res_ok
    content_ok = res_ok["content"]
    assert isinstance(content_ok, list) and isinstance(content_ok[0], dict)
    assert parse_json(str(content_ok[0]["text"]).encode("utf-8")) == expected_ok_env

    # 5. tools/call ok=False returned error envelope
    expected_unavail_env = make_error_envelope(BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable"))
    assert responses[4] == {
        "jsonrpc": "2.0",
        "id": 3,
        "result": make_mcp_tool_result(expected_unavail_env),
    }
    res_err_env = responses[4]["result"]
    assert isinstance(res_err_env, dict)
    assert res_err_env["isError"] is True
    assert res_err_env["structuredContent"] == expected_unavail_env

    # 6. tools/call raised BrainError converted into MCP tool error result
    expected_not_found_env = make_error_envelope(BrainError(ErrorCode.NOT_FOUND, "not found"))
    assert responses[5] == {
        "jsonrpc": "2.0",
        "id": "call-raised-err",
        "result": make_mcp_tool_result(expected_not_found_env),
    }
    res_raised = responses[5]["result"]
    assert isinstance(res_raised, dict)
    assert res_raised["isError"] is True
    assert res_raised["structuredContent"] == expected_not_found_env

    # Verify exact arguments passed to ToolCaller (with params._meta stripped)
    assert calls == [
        ("get_health", {"schema_version": "2.0", "deep": False}),
        (
            "search_knowledge",
            {"schema_version": "2.0", "workspace_id": "ws-01", "query": "bounded stdio"},
        ),
        ("get_job", {"schema_version": "2.0", "job_id": "job-404"}),
    ]


def test_stdio_invalid_id_and_oversize_never_dispatch() -> None:
    from superbrain.core.canonical import canonical_json
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import CallResult
    from superbrain.core.wire import MAX_WIRE_BODY_BYTES, make_success_envelope

    calls: list[tuple[str, dict[str, JsonValue]]] = []

    def fake_caller(tool: str, arguments: dict[str, JsonValue]) -> CallResult:
        calls.append((tool, copy.deepcopy(arguments)))
        return make_success_envelope({"ready": True})

    caller: ToolCaller = fake_caller

    # Part 1: Explicit `"id": null`, invalid IDs, malformed/duplicate-key/invalid-UTF8 JSON,
    # batch array, and notification `tools/call` (missing `"id"`) never invoke `call`.
    bad_frames: list[tuple[bytes, int | None]] = [
        # Explicit `"id": null` MUST return -32600 (never collapsed into notification)
        (
            b'{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0"}}}\n',
            -32600,
        ),
        # Boolean, float, empty string, overlong string, and array/object IDs -> -32600
        (
            b'{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0"}}}\n',
            -32600,
        ),
        (
            b'{"jsonrpc":"2.0","id":false,"method":"ping"}\n',
            -32600,
        ),
        (
            b'{"jsonrpc":"2.0","id":1.5,"method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0"}}}\n',
            -32600,
        ),
        (
            b'{"jsonrpc":"2.0","id":"","method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0"}}}\n',
            -32600,
        ),
        (
            f'{{"jsonrpc":"2.0","id":"{"x" * 129}","method":"ping"}}\n'.encode(),
            -32600,
        ),
        (
            b'{"jsonrpc":"2.0","id":["bad"],"method":"ping"}\n',
            -32600,
        ),
        # JSON-RPC batch array -> -32600
        (
            b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n',
            -32600,
        ),
        # Duplicate JSON key -> -32600
        (
            b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0"}}}\n',
            -32600,
        ),
        # Malformed JSON -> -32700
        (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call"\n',
            -32700,
        ),
        # Invalid UTF-8 bytes -> -32700
        (
            b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe"}\n',
            -32700,
        ),
        # Notification `tools/call` (missing `"id"`) -> NO response on stdout and NO dispatch
        (
            b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_health","arguments":{"schema_version":"2.0","deep":false}}}\n',
            None,
        ),
    ]

    stream_part1 = b"".join(_init_frames() + [frame for frame, _ in bad_frames])
    out_part1 = io.BytesIO()
    assert run_stdio(io.BytesIO(stream_part1), out_part1, caller) == 0
    assert calls == []

    frames_part1 = _decode_stdout_frames(out_part1.getvalue())
    expected_codes = [code for _, code in bad_frames if code is not None]
    assert len(frames_part1) == 1 + len(expected_codes)
    assert frames_part1[0]["id"] == "init-1"
    for resp, exp_code in zip(frames_part1[1:], expected_codes, strict=True):
        assert resp["id"] is None
        err_obj = resp.get("error")
        assert isinstance(err_obj, dict)
        assert err_obj["code"] == exp_code

    # Part 2: Mid-frame EOF (unterminated frame without newline at EOF) -> -32700 and 0 dispatches
    mid_eof_stream = b"".join(
        _init_frames() + [b'{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"get_health"']
    )
    out_mid_eof = io.BytesIO()
    assert run_stdio(io.BytesIO(mid_eof_stream), out_mid_eof, caller) == 0
    assert calls == []
    frames_mid_eof = _decode_stdout_frames(out_mid_eof.getvalue())
    assert len(frames_mid_eof) == 2
    assert frames_mid_eof[1] == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "parse error"},
    }

    # Part 3: Exact 1,048,576-byte (`MAX_WIRE_BODY_BYTES`) frame before `\r\n` is accepted
    # and dispatches `call`, whereas 1,048,577-byte (`MAX_WIRE_BODY_BYTES + 1`) frame is
    # rejected with a single -32700 parse error and terminates the session before any
    # suffix or trailing valid `tools/call` frame can execute.
    meta_pads: dict[str, JsonValue] = {f"pad_{idx:02d}": "P" * 60_000 for idx in range(17)}
    meta_pads["tail"] = ""
    template_req: dict[str, JsonValue] = {
        "jsonrpc": "2.0",
        "id": "exact-1mib",
        "method": "tools/call",
        "params": {
            "name": "get_health",
            "arguments": {"schema_version": "2.0", "deep": False},
            "_meta": meta_pads,
        },
    }
    base_bytes = canonical_json(template_req)
    remaining = MAX_WIRE_BODY_BYTES - len(base_bytes)
    assert 0 < remaining <= 65_536
    meta_pads["tail"] = "T" * remaining
    exact_1mib_line = canonical_json(template_req)
    assert len(exact_1mib_line) == MAX_WIRE_BODY_BYTES

    out_exact = io.BytesIO()
    rc_exact = run_stdio(
        io.BytesIO(b"".join(_init_frames() + [exact_1mib_line + b"\r\n"])),
        out_exact,
        caller,
    )
    assert rc_exact == 0
    assert calls == [("get_health", {"schema_version": "2.0", "deep": False})]
    frames_exact = _decode_stdout_frames(out_exact.getvalue())
    assert len(frames_exact) == 2
    assert frames_exact[1]["id"] == "exact-1mib"
    assert isinstance(frames_exact[1].get("result"), dict)

    # Now test 1,048,577 bytes (MAX_WIRE_BODY_BYTES + 1 before `\n`) followed by a valid
    # `tools/call` line: must emit one -32700 error, close the session, and never dispatch.
    calls.clear()
    meta_pads["tail"] = "T" * (remaining + 1)
    oversize_by_one_line = canonical_json(template_req)
    assert len(oversize_by_one_line) == MAX_WIRE_BODY_BYTES + 1
    trailing_valid_call = (
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "after-oversize",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n"
    )

    out_oversize_one = io.BytesIO()
    rc_oversize_one = run_stdio(
        io.BytesIO(b"".join(_init_frames() + [oversize_by_one_line + b"\n", trailing_valid_call])),
        out_oversize_one,
        caller,
    )
    assert rc_oversize_one == 0
    assert calls == []
    frames_oversize_one = _decode_stdout_frames(out_oversize_one.getvalue())
    assert len(frames_oversize_one) == 2
    assert frames_oversize_one[1] == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "parse error"},
    }

    # Also test an oversize line where byte 1,048,577+ on the SAME line is a valid `tools/call`
    # frame (killing naive `readline(MAX_WIRE_BODY_BYTES)` that leaves the tail as a new line).
    prefix_1mib = b'{"jsonrpc":"2.0","id":"oversize","pad":"' + (b"A" * (MAX_WIRE_BODY_BYTES - 40))
    assert len(prefix_1mib) == MAX_WIRE_BODY_BYTES
    same_line_suffix_attack = prefix_1mib + trailing_valid_call
    out_suffix_attack = io.BytesIO()
    rc_suffix_attack = run_stdio(
        io.BytesIO(b"".join(_init_frames() + [same_line_suffix_attack, trailing_valid_call])),
        out_suffix_attack,
        caller,
    )
    assert rc_suffix_attack == 0
    assert calls == []
    frames_suffix = _decode_stdout_frames(out_suffix_attack.getvalue())
    assert len(frames_suffix) == 2
    assert frames_suffix[1] == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "parse error"},
    }


def test_stdio_negotiates_pinned_version_before_tools() -> None:
    from superbrain.core.canonical import canonical_json
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import CallResult
    from superbrain.core.wire import make_mcp_tool_result, make_success_envelope

    calls: list[tuple[str, dict[str, JsonValue]]] = []

    def fake_caller(tool: str, arguments: dict[str, JsonValue]) -> CallResult:
        calls.append((tool, copy.deepcopy(arguments)))
        return make_success_envelope({"ready": True})

    caller: ToolCaller = fake_caller

    # Sub-case A: Client requests older/unknown protocolVersion ("2024-11-05"), server proposes
    # pinned "2025-06-18", and client immediately closes stdin (EOF) without notifications/initialized.
    negotiate_eof_input = (
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "neg-eof-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-host", "version": "0.9"},
                },
            }
        )
        + b"\n"
    )
    out_neg_eof = io.BytesIO()
    assert run_stdio(io.BytesIO(negotiate_eof_input), out_neg_eof, caller) == 0
    assert calls == []
    assert _decode_stdout_frames(out_neg_eof.getvalue()) == [
        {
            "jsonrpc": "2.0",
            "id": "neg-eof-1",
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    ]

    # Sub-case B: Full state machine guard verification (`new -> waiting_initialized -> ready`)
    frames_in: list[bytes] = [
        # 1. In `new`: tools/list and tools/call are rejected with -32600
        canonical_json({"jsonrpc": "2.0", "id": "pre-init-list", "method": "tools/list"}) + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "pre-init-call",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n",
        # 2. Premature notifications/initialized in `new` does not advance state
        canonical_json({"jsonrpc": "2.0", "method": "notifications/initialized"}) + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "still-new-call",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n",
        # 3. Invalid initialize params are rejected with -32602 and leave state in `new`
        canonical_json({"jsonrpc": "2.0", "id": "bad-init-none", "method": "initialize"}) + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-init-list",
                "method": "initialize",
                "params": ["not-an-object"],
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-init-empty-ver",
                "method": "initialize",
                "params": {
                    "protocolVersion": "",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-init-int-ver",
                "method": "initialize",
                "params": {
                    "protocolVersion": 20250618,
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-init-caps",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": [],
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-init-client",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": "not-a-dict",
                },
            }
        )
        + b"\n",
        # 4. Valid initialize with older client version ("2024-11-05") succeeds -> `waiting_initialized`
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "good-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        # 5. In `waiting_initialized`: duplicate initialize, tools/list, tools/call, and
        # notifications/initialized with an `id` are all rejected with -32600, keeping state
        # in `waiting_initialized`.
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "dup-init-waiting",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        canonical_json({"jsonrpc": "2.0", "id": "wait-list", "method": "tools/list"}) + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "wait-call",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "notif-with-id",
                "method": "notifications/initialized",
                "params": {},
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "still-waiting-after-bad-notif",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n",
        # 6. Valid notifications/initialized (no `id`) advances session to `ready`
        canonical_json({"jsonrpc": "2.0", "method": "notifications/initialized"}) + b"\n",
        # 7. In `ready`: duplicate initialize -> -32600; unknown method -> -32601;
        # tools/list with cursor -> -32602; unknown tool or bad arguments -> -32602;
        # valid tools/call -> dispatches once!
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "dup-init-ready",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1"},
                },
            }
        )
        + b"\n",
        canonical_json({"jsonrpc": "2.0", "id": "unknown-method", "method": "resources/list"}) + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "list-with-cursor",
                "method": "tools/list",
                "params": {"cursor": "page-2"},
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "unknown-tool",
                "method": "tools/call",
                "params": {"name": "nonexistent_tool", "arguments": {"schema_version": "2.0"}},
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "bad-args-type",
                "method": "tools/call",
                "params": {"name": "get_health", "arguments": ["not-a-dict"]},
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "extra-param-key",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0"},
                    "unexpected": 1,
                },
            }
        )
        + b"\n",
        canonical_json(
            {
                "jsonrpc": "2.0",
                "id": "ready-call-ok",
                "method": "tools/call",
                "params": {
                    "name": "get_health",
                    "arguments": {"schema_version": "2.0", "deep": False},
                },
            }
        )
        + b"\n",
    ]

    out_buf = io.BytesIO()
    assert run_stdio(io.BytesIO(b"".join(frames_in)), out_buf, caller) == 0
    assert calls == [("get_health", {"schema_version": "2.0", "deep": False})]

    by_id = {resp["id"]: resp for resp in _decode_stdout_frames(out_buf.getvalue())}

    for invalid_req_id in (
        "pre-init-list",
        "pre-init-call",
        "still-new-call",
        "dup-init-waiting",
        "wait-list",
        "wait-call",
        "notif-with-id",
        "still-waiting-after-bad-notif",
        "dup-init-ready",
    ):
        err = by_id[invalid_req_id].get("error")
        assert isinstance(err, dict), f"expected error for {invalid_req_id}"
        assert err["code"] == -32600

    for invalid_params_id in (
        "bad-init-none",
        "bad-init-list",
        "bad-init-empty-ver",
        "bad-init-int-ver",
        "bad-init-caps",
        "bad-init-client",
        "list-with-cursor",
        "unknown-tool",
        "bad-args-type",
        "extra-param-key",
    ):
        err = by_id[invalid_params_id].get("error")
        assert isinstance(err, dict), f"expected error for {invalid_params_id}"
        assert err["code"] == -32602

    unknown_err = by_id["unknown-method"].get("error")
    assert isinstance(unknown_err, dict)
    assert unknown_err["code"] == -32601

    assert by_id["good-init"]["result"] == {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "super-brain2", "version": "0.1.0"},
    }
    assert by_id["ready-call-ok"]["result"] == make_mcp_tool_result(make_success_envelope({"ready": True}))


def test_stdio_uncertainty_and_failed_stdout_have_no_second_call() -> None:
    from superbrain.core.canonical import canonical_json
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import CallResult
    from superbrain.core.wire import make_error_envelope, make_success_envelope

    # Part 1: Distinguish pre-POST daemon_unavailable, ToolCallUncertain, daemon
    # commit_outcome_unknown, and outbound > 1 MiB JSON-RPC result cap.
    part1_calls: list[tuple[str, dict[str, JsonValue]]] = []
    canary = "RAW_TRANSPORT_SECRET_DO_NOT_LEAK_991122"

    half_mib_resources: list[JsonValue] = [
        {
            "name": f"seg-{idx}.txt",
            "digest": "sha256:" + ("d" * 64),
            "encoding": "utf-8",
            "content": "Y" * 60_000,
        }
        for idx in range(10)
    ]

    def part1_caller(tool: str, arguments: dict[str, JsonValue]) -> CallResult:
        part1_calls.append((tool, copy.deepcopy(arguments)))
        mode = arguments.get("job_id")
        if mode == "pre-post-down":
            return make_error_envelope(BrainError(ErrorCode.DAEMON_UNAVAILABLE, f"pre-post connect refused {canary}"))
        if mode == "post-uncertain":
            raise ToolCallUncertain(f"socket EOF after POST {canary}")
        if mode == "daemon-commit-unknown":
            return make_error_envelope(BrainError(ErrorCode.COMMIT_OUTCOME_UNKNOWN, "commit outcome unknown"))
        if mode == "oversize-outer-result":
            return make_success_envelope(
                {
                    "artifact_id": "art-half-mib",
                    "revision": 1,
                    "level": "L2",
                    "status": "ok",
                    "resources": half_mib_resources,
                }
            )
        return make_success_envelope({"job_id": str(mode), "state": "succeeded"})

    part1_input = b"".join(
        _init_frames()
        + [
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "req-pre-post",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "pre-post-down"},
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "req-uncertain",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "post-uncertain"},
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "req-commit-unknown",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "daemon-commit-unknown"},
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "req-oversize-result",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "oversize-outer-result"},
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "req-after-oversize-result",
                    "method": "tools/call",
                    "params": {
                        "name": "get_job",
                        "arguments": {"schema_version": "2.0", "job_id": "job-ok-after"},
                    },
                }
            )
            + b"\n",
        ]
    )

    out_part1 = io.BytesIO()
    assert run_stdio(io.BytesIO(part1_input), out_part1, part1_caller) == 0
    raw_part1 = out_part1.getvalue()
    assert canary.encode("utf-8") not in raw_part1
    assert len(part1_calls) == 5

    by_id = {resp["id"]: resp for resp in _decode_stdout_frames(raw_part1)}

    # 1a. Pre-POST daemon_unavailable: standard error envelope without _meta uncertainty flag
    res_pre = by_id["req-pre-post"]["result"]
    assert isinstance(res_pre, dict)
    assert res_pre["isError"] is True
    assert "_meta" not in res_pre
    assert res_pre["structuredContent"] == {
        "ok": False,
        "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
    }

    # 1b. Post-POST ToolCallUncertain: daemon_unavailable structuredContent + _meta flag + static retry guidance
    res_uncertain = by_id["req-uncertain"]["result"]
    assert isinstance(res_uncertain, dict)
    assert res_uncertain["isError"] is True
    assert res_uncertain["structuredContent"] == {
        "ok": False,
        "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
    }
    assert res_uncertain.get("_meta") == {"superbrain/request_may_have_run": True}
    content_uncertain = res_uncertain.get("content")
    assert isinstance(content_uncertain, list) and isinstance(content_uncertain[0], dict)
    uncertain_text = str(content_uncertain[0].get("text", ""))
    assert "request_may_have_run=true" in uncertain_text
    assert "retry with the same idempotency_key" in uncertain_text

    # 1c. Daemon commit_outcome_unknown: preserved as commit_outcome_unknown without transport _meta
    res_commit_unk = by_id["req-commit-unknown"]["result"]
    assert isinstance(res_commit_unk, dict)
    assert res_commit_unk["isError"] is True
    assert "_meta" not in res_commit_unk
    assert res_commit_unk["structuredContent"] == {
        "ok": False,
        "error": {"code": "commit_outcome_unknown", "message": "commit outcome unknown"},
    }

    # 1d. Outbound JSON-RPC result exceeding 1 MiB emits static -32603 error with matching ID
    assert by_id["req-oversize-result"] == {
        "jsonrpc": "2.0",
        "id": "req-oversize-result",
        "error": {"code": -32603, "message": "internal error"},
    }
    # And the session continues cleanly for the next request
    res_after = by_id["req-after-oversize-result"]["result"]
    assert isinstance(res_after, dict)
    assert res_after["isError"] is False

    # Part 2: When stdout.write or stdout.flush raises BrokenPipeError/OSError on the tool
    # response (write/flush #2, since #1 was initialize), run_stdio returns 1 and NEVER
    # invokes `call` a second time for subsequent buffered requests.
    two_calls_input = b"".join(
        _init_frames()
        + [
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "call-1",
                    "method": "tools/call",
                    "params": {
                        "name": "get_health",
                        "arguments": {"schema_version": "2.0", "deep": False},
                    },
                }
            )
            + b"\n",
            canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": "call-2-must-not-run",
                    "method": "tools/call",
                    "params": {
                        "name": "get_health",
                        "arguments": {"schema_version": "2.0", "deep": False},
                    },
                }
            )
            + b"\n",
        ]
    )

    for fail_mode in ("write", "flush"):
        dispatched: list[str] = []

        def _counting_caller(tool: str, _arguments: dict[str, JsonValue], _log: list[str] = dispatched) -> CallResult:
            _log.append(tool)
            return make_success_envelope({"ready": True})

        broken_out = _BrokenStdout(fail_on=fail_mode, fail_at_call=2)
        rc_broken = run_stdio(io.BytesIO(two_calls_input), broken_out, _counting_caller)
        assert rc_broken == 1
        assert dispatched == ["get_health"]
