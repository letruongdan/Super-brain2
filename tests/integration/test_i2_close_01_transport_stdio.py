"""Independent bug-proof oracle V2 for I2-CLOSE-01: Loopback daemon & MCP stdio U+007F integration.

Derives all expected bytes, HMAC-SHA256 digests, and JSON/wire payloads strictly from the JSON/pre-R41 canonical UTF-8
format (``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``, ``allow_nan=False``) without calling
production ``canonical_json``, ``canonical_digest``, or ``canonical_request_payload``.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from superbrain.core import errors, wire
from superbrain.core import kernel as k
from superbrain.core.jsonvalue import JsonValue
from superbrain.mcp.stdio import JSONRPC_INTERNAL_ERROR, run_stdio
from superbrain.storage import policy_store
from tests.support.inc2_cli import get_shared_t7_transport_template
from tests.support.inc2_kernel_domain import validate_response_envelope
from tests.support.inc2_t8_harness import clone_template_root, fixture_daemon
from tests.support.inc2_transport import TransportTestDomain, open_test_loopback_transport

DEL_COUNT_AT_CAP = 200


def _pre_r41_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256_tag(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pre_r41_request_bytes(tool: str, scope: k.Scope | None, arguments: Mapping[str, JsonValue]) -> bytes:
    return _pre_r41_json({"tool": tool, "selected_scope": scope.to_dict() if scope else None, "arguments": arguments})


def _pre_r41_hmac(key_bytes: bytes, raw_request: bytes) -> str:
    return "sha256:" + hmac.new(key_bytes, b"request-v1\0" + raw_request, hashlib.sha256).hexdigest()


def _pre_r41_idem_key_hash(principal_id: str, tool: str, idem_key: str) -> str:
    body = _pre_r41_json({"idempotency_key": idem_key, "principal_id": principal_id, "tool": tool})
    return _sha256_tag(b"idem-lookup-v1\0" + body)


def _fill_pad_to_bytes(
    pad: list[JsonValue], render: Callable[[], object], *, target_bytes: int, del_count: int
) -> bytes:
    while len(_pre_r41_json(render())) + 60_003 <= target_bytes - 3:
        pad.append("a" * 60_000)
    remaining = target_bytes - len(_pre_r41_json(render()))
    assert 3 <= remaining <= 60_005
    pad.append("a" * (remaining - 3))
    raw = _pre_r41_json(render())
    assert len(raw) == target_bytes and raw.count(b"\x7f") == del_count and b"\\u007f" not in raw
    return raw


def _envelope_at_bytes(target_bytes: int, *, with_unicode: bool) -> dict[str, JsonValue]:
    pad: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    data: dict[str, JsonValue] = {"pad": pad, **({"u": "é"} if with_unicode else {})}
    env: dict[str, JsonValue] = {"ok": True, "data": data}
    _fill_pad_to_bytes(pad, lambda: env, target_bytes=target_bytes, del_count=DEL_COUNT_AT_CAP)
    return env


def _submit_episode_at_bytes(
    target_bytes: int, *, with_unicode: bool, workspace_id: str
) -> tuple[dict[str, JsonValue], bytes]:
    pad: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    ep_data: dict[str, JsonValue] = {"pad": pad, **({"u": "é"} if with_unicode else {})}
    args: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_id": workspace_id,
        "task_id": "task-cap-1",
        "session_id": "sess-cap-1",
        "evidence": [{"kind": "note", "data": ep_data}],
        "idempotency_key": f"idem_cap_{target_bytes}_{int(with_unicode)}",
    }
    raw = _fill_pad_to_bytes(pad, lambda: args, target_bytes=target_bytes, del_count=DEL_COUNT_AT_CAP)
    return args, raw


def _mcp_result_at_bytes(target_bytes: int, *, with_unicode: bool) -> tuple[str, dict[str, JsonValue], bytes]:
    pad: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    env: dict[str, JsonValue] = {"ok": True, "data": {"pad": pad, **({"u": "é"} if with_unicode else {})}}

    def render_frame(req_id: str) -> bytes:
        text = _pre_r41_json(env).decode("utf-8")
        mcp_res: dict[str, object] = {
            "content": [{"text": text, "type": "text"}],
            "isError": False,
            "structuredContent": env,
        }
        return _pre_r41_json({"id": req_id, "jsonrpc": "2.0", "result": mcp_res})

    while len(render_frame("r0")) + 60_100 <= target_bytes:
        pad.append("a" * 30_000)
    pad.append("")
    rem = target_bytes - len(render_frame("r0"))
    assert 0 <= rem < 120_000
    pad[-1] = "a" * (rem // 2)
    req_id = "r0" if target_bytes - len(render_frame("r0")) == 0 else "r01"
    raw = render_frame(req_id)
    assert len(raw) == target_bytes and raw.count(b"\x7f") == 2 * DEL_COUNT_AT_CAP and b"\\u007f" not in raw
    return req_id, env, raw


def _expect_ok_prepare(res: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope("prepare_task", res)
    assert checked.get("ok") is True and isinstance(checked["data"], dict), checked
    return checked["data"]


def _expect_error_code(res: Mapping[str, JsonValue], expected_code: errors.ErrorCode) -> None:
    err = res.get("error")
    assert res.get("ok") is False and isinstance(err, dict)
    assert err.get("code") == expected_code.value


class _NearCapResponseDomain(TransportTestDomain):
    response_data: dict[str, JsonValue] = {}

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return True if tool == "search_knowledge" else super().supports_tool(tool, deep=deep)

    def execute_readonly(self, call: k.Call, ctx: k.CallContext) -> dict[str, JsonValue]:
        _ = (call, ctx)
        return dict(self.response_data)


@pytest.mark.parametrize("with_unicode", [False, True], ids=["ascii_del", "unicode_del"])
def test_loopback_daemon_pre_r41_replay_and_near_cap_framing(
    monkeypatch: pytest.MonkeyPatch, trusted_tmp: Path, with_unicode: bool
) -> None:
    tpl = get_shared_t7_transport_template()
    assert tpl.ws_a is not None
    scope = k.Scope(tpl.ws_a.repo_id, tpl.ws_a.checkout_id)
    data_root = clone_template_root(tpl, trusted_tmp / "daemon-data")
    desc = "loopback-del-\x7f-é-task" if with_unicode else "loopback-del-\x7f-task"
    idem_key = f"idem_loopback_close_01_{int(with_unicode)}"
    prep_args: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_hint": "ws-a",
        "description": desc,
        "context_budget_tokens": 4000,
        "idempotency_key": idem_key,
    }

    with fixture_daemon(monkeypatch, tpl, data_root) as (h, proxy, _tracker):
        client, target = h.open_client(), h.make_target()
        cmd = k.ToolCommand("prepare_task", prep_args, token=tpl.cred.token, selected_scope=scope)
        first_data = _expect_ok_prepare(dict(client.call(target, cmd)))
        assert proxy.inner.prepare_calls == 1

        pre_req = _pre_r41_request_bytes("prepare_task", scope, prep_args)
        key_hash = _pre_r41_idem_key_hash(tpl.cred.principal.principal_id, "prepare_task", idem_key)

        def _rewrite_idem_pre_r41() -> None:
            pol = cast(policy_store.PolicyStore, proxy.inner.policy)
            kid, kbytes = pol.request_digest_key()
            pre_hmac = _pre_r41_hmac(kbytes, pre_req)
            with proxy.inner.store.transaction() as txn:
                cur = txn.db.execute(
                    "UPDATE idempotency SET request_digest_key_id = ?, request_digest = ? "
                    "WHERE principal_id = ? AND tool = ? AND key_hash = ?",
                    (kid, pre_hmac, tpl.cred.principal.principal_id, "prepare_task", key_hash),
                )
                assert cur.rowcount == 1

        h.loop.run_owner_action(_rewrite_idem_pre_r41).result(timeout=5.0)
        assert _expect_ok_prepare(dict(client.call(target, cmd))) == first_data and proxy.inner.prepare_calls == 1
        bad_args: dict[str, JsonValue] = {**prep_args, "description": desc.replace("\x7f", "\x7e")}
        bad_cmd = k.ToolCommand("prepare_task", bad_args, token=tpl.cred.token, selected_scope=scope)
        _expect_error_code(dict(client.call(target, bad_cmd)), errors.ErrorCode.IDEMPOTENCY_CONFLICT)

        near_args, near_req_bytes = _submit_episode_at_bytes(
            wire.MAX_WIRE_BODY_BYTES - 1_024, with_unicode=with_unicode, workspace_id=tpl.ws_a.repo_id
        )
        near_cmd = k.ToolCommand("submit_episode", near_args, token=tpl.cred.token, selected_scope=scope)
        assert len(_pre_r41_request_bytes("submit_episode", scope, near_args)) <= wire.MAX_WIRE_BODY_BYTES
        assert b"\x7f" in near_req_bytes
        _expect_error_code(dict(client.call(target, near_cmd)), errors.ErrorCode.CAPABILITY_UNAVAILABLE)

        over_args, _ = _submit_episode_at_bytes(
            wire.MAX_WIRE_BODY_BYTES + 1, with_unicode=with_unicode, workspace_id=tpl.ws_a.repo_id
        )
        over_cmd = k.ToolCommand("submit_episode", over_args, token=tpl.cred.token, selected_scope=scope)
        with pytest.raises(errors.BrainError) as exc_over:
            client.call(target, over_cmd)
        assert exc_over.value.code is errors.ErrorCode.INVALID_INPUT and "size limit" in exc_over.value.message
        with h.open_raw_tls_socket() as tls_sock:
            ep = h.ready.endpoint
            id_req = f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{ep.port}\r\n\r\n".encode("ascii")
            h.send_raw_http(tls_sock, id_req)
            over_wire = _pre_r41_json(
                {
                    "tool": "submit_episode",
                    "arguments": over_args,
                    "correlation_id": None,
                    "selected_scope": scope.to_dict(),
                }
            )
            post_head = (
                f"POST /v2/tools/call HTTP/1.1\r\nHost: 127.0.0.1:{ep.port}\r\n"
                f"Authorization: Bearer {tpl.cred.token}\r\n"
                f"X-Store-Id: {ep.store_id}\r\nX-Writer-Epoch: {ep.writer_epoch}\r\n"
                f"X-Superbrain-Instance: {ep.instance_id}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(over_wire)}\r\n\r\n"
            ).encode("ascii")
            # Server rejects Content-Length > MAX_WIRE_BODY_BYTES on headers immediately and closes the socket.
            raw_413 = h.send_raw_http(tls_sock, post_head)
            assert b"413" in raw_413 and b"size limit" in raw_413

    env_ok = _envelope_at_bytes(wire.MAX_WIRE_BODY_BYTES, with_unicode=with_unicode)
    env_over = _envelope_at_bytes(wire.MAX_WIRE_BODY_BYTES + 1, with_unicode=with_unicode)
    domain = _NearCapResponseDomain(ws_a=tpl.ws_a)
    domain.response_data = cast(dict[str, JsonValue], env_ok["data"])
    with open_test_loopback_transport(tpl, name=f"close01-resp-{int(with_unicode)}", domain=domain) as h2:
        c2, t2 = h2.open_client(), h2.make_target()
        search_cmd = k.ToolCommand(
            "search_knowledge",
            {"schema_version": "2.0", "workspace_id": tpl.ws_a.repo_id, "query": "del-\x7f"},
            token=tpl.cred.token,
            selected_scope=scope,
        )
        assert dict(c2.call(t2, search_cmd)) == env_ok
        domain.response_data = cast(dict[str, JsonValue], env_over["data"])
        over_resp = dict(c2.call(t2, search_cmd))
        _expect_error_code(over_resp, errors.ErrorCode.INVALID_INPUT)
        err_obj = over_resp.get("error")
        assert isinstance(err_obj, dict) and "size limit" in str(err_obj.get("message", ""))


@pytest.mark.parametrize("with_unicode", [False, True], ids=["ascii_del", "unicode_del"])
def test_mcp_run_stdio_u007f_near_wire_limit(with_unicode: bool) -> None:
    cap = wire.MAX_WIRE_BODY_BYTES
    req_id_ok, mcp_env_ok, expected_line_ok = _mcp_result_at_bytes(cap, with_unicode=with_unicode)
    _, mcp_env_over, _ = _mcp_result_at_bytes(cap + 1, with_unicode=with_unicode)

    pad_req: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    req_args: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_id": "ws-stdio",
        "task_id": "task-stdio-1",
        "session_id": "sess-stdio-1",
        "evidence": [{"kind": "note", "data": {"pad": pad_req, **({"u": "é"} if with_unicode else {})}}],
        "idempotency_key": f"idem_stdio_{int(with_unicode)}",
    }

    def render_rpc_req(rid: str) -> dict[str, object]:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": "submit_episode", "arguments": req_args},
        }

    _fill_pad_to_bytes(pad_req, lambda: render_rpc_req(req_id_ok), target_bytes=cap, del_count=DEL_COUNT_AT_CAP)
    req_frame_ok = _pre_r41_json(render_rpc_req(req_id_ok))
    assert len(req_frame_ok) == cap

    observed_calls: list[tuple[str, dict[str, JsonValue]]] = []

    def caller(tool: str, arguments: dict[str, JsonValue]) -> k.CallResult:
        observed_calls.append((tool, arguments))
        return mcp_env_ok if len(observed_calls) == 1 else mcp_env_over

    init = _pre_r41_json(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": wire.MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "c", "version": "1"},
            },
        }
    )
    initialized = _pre_r41_json({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    over_resp_req = _pre_r41_json(
        {
            "jsonrpc": "2.0",
            "id": "over-resp",
            "method": "tools/call",
            "params": {"name": "get_health", "arguments": {"schema_version": "2.0"}},
        }
    )
    stdout = io.BytesIO()
    stdin_bytes = b"\n".join((init, initialized, req_frame_ok, over_resp_req)) + b"\n"
    assert run_stdio(io.BytesIO(stdin_bytes), stdout, caller) == 0 and len(observed_calls) == 2
    lines = stdout.getvalue().splitlines()
    assert len(lines) == 3
    assert len(lines[1]) == cap and lines[1] == expected_line_ok and b"\\u007f" not in lines[1]
    parsed_ok = json.loads(lines[1].decode("utf-8"))
    assert isinstance(parsed_ok, dict) and parsed_ok["id"] == req_id_ok and "result" in parsed_ok
    parsed_over_resp = json.loads(lines[2].decode("utf-8"))
    assert parsed_over_resp["error"]["code"] == JSONRPC_INTERNAL_ERROR

    pad_over: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    req_args_over: dict[str, JsonValue] = {**req_args, "evidence": [{"kind": "note", "data": {"pad": pad_over}}]}
    over_rpc_obj: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": "too-big",
        "method": "tools/call",
        "params": {"name": "submit_episode", "arguments": req_args_over},
    }
    over_line = _fill_pad_to_bytes(pad_over, lambda: over_rpc_obj, target_bytes=cap + 1, del_count=DEL_COUNT_AT_CAP)
    out_over, calls_over = io.BytesIO(), list[str]()

    def reject_caller(tool: str, _arguments: dict[str, JsonValue]) -> k.CallResult:
        calls_over.append(tool)
        return mcp_env_ok

    assert run_stdio(io.BytesIO(b"\n".join((init, initialized, over_line)) + b"\n"), out_over, reject_caller) == 0
    assert calls_over == []
    assert (
        json.loads(out_over.getvalue().splitlines()[-1].decode("utf-8"))["error"]["code"]
        == wire.JSONRPC_PARSE_ERROR
    )
