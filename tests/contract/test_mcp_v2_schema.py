"""Contract tests for canonical MCP tools v2 schema, strict wire codec, and wheel packaging."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import SAFE_WIRE_MESSAGES, BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from tests.support.inc2_fixture import InstalledEnv, SampleTlsMaterial

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "mcp_v2"

EXPECTED_TOOLS: dict[str, tuple[str, bool, str]] = {
    "prepare_task": (
        "conditional_work_mutation",
        False,
        "sp2-4 (discover+work-narrow) / sp4/sp5 (full) (fixture-in-i2)",
    ),
    "search_knowledge": ("read_only", False, "sp4"),
    "get_artifact": ("mutation", False, "sp2-4 (handoff) / sp4/sp5 (full) (fixture-in-i2)"),
    "submit_episode": ("mutation", False, "sp2-4 (handoff) / sp3 (skills+lessons)"),
    "record_outcome": ("mutation", False, "sp3/sp6 (fixture-in-i2)"),
    "request_improvement": ("mutation", True, "sp6"),
    "get_job": ("read_only", False, "sp1-i2"),
    "get_health": ("conditional_deep_mutation", False, "sp1-i2 (shallow) / sp1-i4 (deep)"),
}


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


def test_exact_eight_tools_and_no_v1_or_approval() -> None:
    from superbrain.core.kernel import Principal
    from superbrain.core.wire import load_catalog, normalize_call

    assert ErrorCode.UNAUTHENTICATED.value == "unauthenticated"
    assert ErrorCode.DAEMON_UNAVAILABLE.value == "daemon_unavailable"
    assert ErrorCode.POLICY_UNAVAILABLE.value == "policy_unavailable"

    catalog = load_catalog()
    assert catalog.contract == "mcp-tools-v2"
    assert catalog.tokenizer == "utf8-byte-v1"
    assert catalog.resolution == "single-checkout-owner-profile-v1"
    assert catalog.schema_id == "https://ensemble-agents.local/superbrain/mcp-tools-v2.json"
    assert set(catalog.tools) == set(EXPECTED_TOOLS)
    assert len(catalog.tools) == 8

    root_defs = catalog.schema["$defs"]
    assert isinstance(root_defs, dict)
    error_code_def = root_defs["ErrorCode"]
    assert isinstance(error_code_def, dict)
    code_enum = error_code_def["enum"]
    assert isinstance(code_enum, list)
    assert set(code_enum) == {code.value for code in ErrorCode}

    error_detail_def = root_defs["ErrorDetail"]
    assert isinstance(error_detail_def, dict)
    detail_props = error_detail_def["properties"]
    assert isinstance(detail_props, dict)
    msg_def = detail_props["message"]
    assert isinstance(msg_def, dict)
    msg_enum = msg_def["enum"]
    assert isinstance(msg_enum, list)
    assert set(msg_enum) == set(SAFE_WIRE_MESSAGES)

    for name, (side_effects, is_async, implemented_in) in EXPECTED_TOOLS.items():
        spec = catalog.tools[name]
        assert spec.name == name
        assert spec.contract == "mcp-tools-v2"
        assert spec.tokenizer == "utf8-byte-v1"
        assert spec.side_effects == side_effects
        assert spec.is_async is is_async
        assert spec.implemented_in == implemented_in

        mcp_entry = spec.to_mcp_tool()
        assert mcp_entry["name"] == name
        assert mcp_entry["x-contract"] == "mcp-tools-v2"
        assert mcp_entry["x-tokenizer"] == "utf8-byte-v1"
        assert mcp_entry["x-side-effects"] == side_effects
        assert mcp_entry["x-async"] is is_async
        assert mcp_entry["x-implemented-in"] == implemented_in

        for exported_schema in (spec.input_schema, spec.output_schema):
            jsonschema.Draft202012Validator.check_schema(exported_schema)
            assert exported_schema.get("type") == "object"
            defs = exported_schema.get("$defs")
            assert isinstance(defs, dict)
            closure = _transitive_closure(exported_schema, defs)
            assert set(defs) == closure

    principal = Principal(
        principal_id="princ-01",
        owner_id="owner-01",
        harness_id="codex-desktop",
        machine_id="mach-01",
    )

    prep_validator = jsonschema.Draft202012Validator(catalog.tools["prepare_task"].input_schema)
    v1_args: dict[str, Any] = {
        "schema_version": "1.0",
        "workspace_hint": "sb2",
        "description": "legacy v1 request",
        "idempotency_key": "idem_legacy_v1_0001",
    }
    assert not prep_validator.is_valid(v1_args)
    with pytest.raises(BrainError) as exc_info:
        normalize_call("prepare_task", v1_args, principal, selected_scope=None)
    assert exc_info.value.code == ErrorCode.UNSUPPORTED_VERSION

    # Client cannot self-declare authority/provenance fields on prepare_task, submit_episode, or record_outcome
    for forbidden_field, forbidden_val in (
        ("source", "native"),
        ("approval", {"approved": True}),
        ("native_receipt", "rcpt-native-1"),
        ("snapshot_status", "available"),
        ("degraded_codes", []),
        ("unknown_source", False),
    ):
        bad_prep: dict[str, Any] = {
            "schema_version": "2.0",
            "workspace_hint": "sb2",
            "description": "attempt authority injection",
            "idempotency_key": "idem_forbid_prep_0001",
            forbidden_field: forbidden_val,
        }
        assert not prep_validator.is_valid(bad_prep)
        with pytest.raises(BrainError) as exc_info:
            normalize_call("prepare_task", bad_prep, principal, selected_scope=None)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    submit_validator = jsonschema.Draft202012Validator(catalog.tools["submit_episode"].input_schema)
    for injected_key in ("source", "approval", "native_receipt", "verified", "verification_status"):
        bad_submit: dict[str, Any] = {
            "schema_version": "2.0",
            "task_id": "task-01",
            "session_id": "sess-01",
            "evidence": [{"kind": "cmd", "data": {"exit_code": 0, injected_key: "injected"}}],
            "idempotency_key": "idem_forbid_sub_0001",
        }
        assert not submit_validator.is_valid(bad_submit)
        with pytest.raises(BrainError) as exc_info:
            normalize_call("submit_episode", bad_submit, principal, selected_scope=None)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT

    outcome_validator = jsonschema.Draft202012Validator(catalog.tools["record_outcome"].input_schema)
    for bad_outcome in (
        {
            "schema_version": "2.0",
            "workspace_id": "repo-01",
            "delivery_id": "deliv-01",
            "outcome": "verified",
            "idempotency_key": "idem_forbid_out_0001",
        },
        {
            "schema_version": "2.0",
            "workspace_id": "repo-01",
            "delivery_id": "deliv-01",
            "outcome": "success",
            "verification_status": "verified",
            "idempotency_key": "idem_forbid_out_0002",
        },
    ):
        assert not outcome_validator.is_valid(bad_outcome)
        with pytest.raises(BrainError) as exc_info:
            normalize_call("record_outcome", bad_outcome, principal, selected_scope=None)
        assert exc_info.value.code == ErrorCode.INVALID_INPUT


def test_strict_wire_bad_inputs() -> None:
    from superbrain.core.kernel import (
        CallContext,
        Identity,
        LineagedField,
        LineageRef,
        ObjectRef,
        Principal,
        ReadAckInput,
        ResourceDigest,
        Scope,
        StoredResult,
    )
    from superbrain.core.wire import (
        JSONRPC_INVALID_REQUEST,
        JSONRPC_PARSE_ERROR,
        JsonRpcError,
        canonical_request_payload,
        encode_envelope,
        make_error_envelope,
        make_mcp_tool_result,
        make_success_envelope,
        normalize_call,
        parse_json,
        parse_jsonrpc_request,
        validate_jsonrpc_id,
    )

    canary = "CANARY_SECRET_RAW_9876543210_DO_NOT_LEAK"
    canary_bytes = canary.encode("utf-8")

    def assert_safe_wire_error(err: BrainError, expected_code: ErrorCode) -> None:
        assert err.code == expected_code
        encoded = encode_envelope(make_error_envelope(err))
        assert canary_bytes not in encoded
        decoded = parse_json(encoded)
        assert isinstance(decoded, dict)
        assert decoded["ok"] is False

    # 1. Strict JSON wire limits in parse_json
    raw_bad_cases: list[bytes] = [
        f'{{"a": 1, "a": "{canary}"}}'.encode(),  # duplicate key
        b'{"pad":"' + (canary_bytes * 40_000) + b'"}',  # > 1 MiB body
        b'{"big":"' + (b"x" * 65_500) + canary_bytes + b'"}',  # > 64 KiB ASCII string
        ('{"utf8":"' + ("€" * 21_846) + '"}').encode("utf-8"),  # <= 65536 chars, > 65536 UTF-8 bytes
        json.dumps(list(range(1025))).encode("utf-8"),  # > 1024 array items
        (b"[" * 33) + b"1" + (b"]" * 33),  # > 32 list depth
        (b'{"k":' * 33) + b"1" + (b"}" * 33),  # > 32 dict depth
        f'{{"s": "\\ud800{canary}"}}'.encode(),  # lone high surrogate
        f'{{"s": "\\udfff{canary}"}}'.encode(),  # lone low surrogate
        b'{"bad":"\xff\xfe' + canary_bytes + b'"}',  # invalid UTF-8
        b'{"n": NaN}',
        b'{"n": Infinity}',
        b'{"n": -Infinity}',
        b'{"huge_int": ' + (b"9" * 5_000) + b"}",  # > 4300 digits ValueError in Python >= 3.11
    ]
    for raw in raw_bad_cases:
        with pytest.raises(BrainError) as exc_info:
            parse_json(raw)
        assert_safe_wire_error(exc_info.value, ErrorCode.INVALID_INPUT)

    # Exactly depth 32 is permitted
    depth_32 = (b"[" * 32) + b"1" + (b"]" * 32)
    assert isinstance(parse_json(depth_32), list)

    principal = Principal(
        principal_id="princ-01",
        owner_id="owner-01",
        harness_id="claude-code",
        machine_id="mach-01",
    )
    scope = Scope(repo_id="repo-01", checkout_id="chk-a")

    # 2. Boolean rejected for integer fields, unknown fields, selector & conditional rules
    bad_calls: list[tuple[str, Any, ErrorCode]] = [
        (
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "task_id": "task-01",
                "artifact_id": "art-01",
                "revision": True,
                "level": "L0",
                "idempotency_key": "idem_bool_rev_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "search_knowledge",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "query": "test",
                "limit": False,
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "sb2",
                "description": "desc",
                "context_budget_tokens": True,
                "idempotency_key": "idem_bool_bud_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "search_knowledge",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "query": "test",
                canary: canary,
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Mixed selector on prepare_task
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "sb2",
                "workspace_id": "repo-01",
                "checkout_id": "chk-a",
                "description": "mixed selector",
                "idempotency_key": "idem_mix_sel_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Partial IDs selector on prepare_task
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "description": "missing checkout_id",
                "idempotency_key": "idem_part_sel_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Missing selector in normalized daemon prepare_task
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "description": "no selector for daemon",
                "idempotency_key": "idem_zero_sel_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Traversal / raw path in workspace_hint
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "../escape",
                "description": "bad hint",
                "idempotency_key": "idem_bad_hint_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "..",
                "description": "dotdot hint",
                "idempotency_key": "idem_bad_hint_0002",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Null source_snapshot_id on prepare_task request
        (
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "sb2",
                "source_snapshot_id": None,
                "description": "null snapshot on input",
                "idempotency_key": "idem_null_snap_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # deep=True missing idempotency_key
        (
            "get_health",
            {
                "schema_version": "2.0",
                "deep": True,
            },
            ErrorCode.INVALID_INPUT,
        ),
        # deep=False with idempotency_key
        (
            "get_health",
            {
                "schema_version": "2.0",
                "deep": False,
                "idempotency_key": "idem_shallow_health_01",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Duplicate resource_digests names in ReadAckInput
        (
            "record_outcome",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "delivery_id": "deliv-01",
                "outcome": "success",
                "read_acks": [
                    {
                        "served_receipt_id": "rcpt-01",
                        "task_id": "task-01",
                        "artifact_id": "art-01",
                        "revision_epoch": 0,
                        "revision": 1,
                        "resource_digests": [
                            {"name": "L1.md", "digest": "sha256:" + ("a" * 64)},
                            {"name": "L1.md", "digest": "sha256:" + ("b" * 64)},
                        ],
                    }
                ],
                "idempotency_key": "idem_dup_res_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        # Principal mismatch -> IDENTITY_MISMATCH
        (
            "get_job",
            {
                "schema_version": "2.0",
                "job_id": "job-01",
                "owner_id": f"wrong-{canary}",
            },
            ErrorCode.IDENTITY_MISMATCH,
        ),
        (
            "get_job",
            {
                "schema_version": "2.0",
                "job_id": "job-01",
                "machine_id": "mach-foreign",
            },
            ErrorCode.IDENTITY_MISMATCH,
        ),
        (
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "task_id": "task-01",
                "artifact_id": "art-01",
                "revision": 1,
                "level": ["L1"],
                "idempotency_key": "idem_unhash_lvl_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "task_id": "task-01",
                "artifact_id": "art-01",
                "revision": 1,
                "level": {"bad": "L1"},
                "idempotency_key": "idem_unhash_lvl_0002",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "record_outcome",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "delivery_id": "deliv-01",
                "outcome": ["success"],
                "idempotency_key": "idem_unhash_out_0001",
            },
            ErrorCode.INVALID_INPUT,
        ),
        (
            "record_outcome",
            {
                "schema_version": "2.0",
                "workspace_id": "repo-01",
                "delivery_id": "deliv-01",
                "outcome": {"bad": 1},
                "idempotency_key": "idem_unhash_out_0002",
            },
            ErrorCode.INVALID_INPUT,
        ),
    ]
    for tool, args, expected_code in bad_calls:
        with pytest.raises(BrainError) as exc_info:
            normalize_call(tool, args, principal, selected_scope=scope)
        assert_safe_wire_error(exc_info.value, expected_code)

    # Even if an internal caller puts raw canary into BrainError.message, wire error strips it
    raw_err = BrainError(ErrorCode.IO_ERROR, f"sqlite failed on {canary}")
    assert_safe_wire_error(raw_err, ErrorCode.IO_ERROR)
    with pytest.raises(BrainError) as exc_info:
        encode_envelope({"ok": False, "error": {"code": "invalid_input", "message": f"leak {canary}"}})
    assert exc_info.value.code == ErrorCode.INVALID_INPUT

    # Matching identity fields stripped + defaults filled + framing correlation_id excluded from digest
    call_with_id = normalize_call(
        "prepare_task",
        {
            "schema_version": "2.0",
            "workspace_hint": "sb2",
            "description": "same business call",
            "idempotency_key": "idem_same_call_0001",
            "principal_id": "princ-01",
            "owner_id": "owner-01",
            "harness_id": "claude-code",
            "machine_id": "mach-01",
        },
        principal,
        selected_scope=scope,
        correlation_id="rpc-frame-1",
    )
    call_explicit_default = normalize_call(
        "prepare_task",
        {
            "schema_version": "2.0",
            "workspace_hint": "sb2",
            "description": "same business call",
            "context_budget_tokens": 4000,
            "idempotency_key": "idem_same_call_0001",
        },
        principal,
        selected_scope=scope,
        correlation_id="rpc-frame-2",
    )
    assert "owner_id" not in call_with_id.arguments
    assert "principal_id" not in call_with_id.arguments
    assert call_with_id.arguments == call_explicit_default.arguments
    assert digest_bytes(canonical_request_payload(call_with_id)) == digest_bytes(
        canonical_request_payload(call_explicit_default)
    )

    # MCP tool result helper & core types validation
    ok_env = make_success_envelope({"outcome_id": "out-1", "status": "declared"})
    mcp_ok = make_mcp_tool_result(ok_env)
    assert mcp_ok["isError"] is False
    assert mcp_ok["structuredContent"] == ok_env
    assert mcp_ok["content"] == [{"type": "text", "text": encode_envelope(ok_env).decode("utf-8")}]

    err_env = make_error_envelope(BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "not yet built"))
    mcp_err = make_mcp_tool_result(err_env)
    assert mcp_err["isError"] is True

    # JSON-RPC ID and framing checks
    assert validate_jsonrpc_id("req-1") == "req-1"
    assert validate_jsonrpc_id(42) == 42
    assert validate_jsonrpc_id(None) is None
    for bad_rpc_id in (True, 1.5, "x" * 129):
        with pytest.raises(JsonRpcError) as rpc_exc:
            validate_jsonrpc_id(bad_rpc_id)
        assert rpc_exc.value.code == JSONRPC_INVALID_REQUEST
    for bad_rpc_frame in (
        b"{not-json",
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"n":' + (b"9" * 5_000) + b"}}",
    ):
        with pytest.raises(JsonRpcError) as rpc_parse:
            parse_jsonrpc_request(bad_rpc_frame)
        assert rpc_parse.value.code == JSONRPC_PARSE_ERROR
        assert rpc_parse.value.code == -32700

    # Core kernel invariants
    with pytest.raises(BrainError):
        ObjectRef(kind="skill", id="s-1", revision=True, digest="sha256:" + ("0" * 64))
    with pytest.raises(BrainError):
        ObjectRef(kind="skill", id="s-1", revision=1, digest="sha256:NOTHEX")
    with pytest.raises(BrainError):
        ReadAckInput(
            served_receipt_id="r-1",
            task_id="t-1",
            artifact_id="art-01",
            revision_epoch=0,
            revision=1,
            resource_digests=(
                ResourceDigest("L0.md", "sha256:" + ("1" * 64)),
                ResourceDigest("L0.md", "sha256:" + ("2" * 64)),
            ),
        )

    ref = ObjectRef(kind="skill", id="s-1", revision=2, digest="sha256:" + ("a" * 64))
    stored = StoredResult(result_id="res-1", assignment_id="asgn-1", refs=(ref,))
    assert StoredResult.from_canonical(stored.encode_canonical()) == stored
    lineage_ref = LineageRef(owner_id="owner-01", repo_id="repo-01", source=ref)
    lf = LineagedField(value={"k": "v"}, sources=frozenset({lineage_ref}), unknown_source=False)
    ctx = CallContext(
        principal=principal,
        identity=Identity(store_id="store-1", writer_epoch=1, instance_id="inst-1"),
        deadline_ns=1_000_000_000,
        selected_scope=scope,
    )
    assert lf.unknown_source is False and ctx.identity.writer_epoch == 1


def test_mcp_tool_result_over_64kib_encodes_in_jsonrpc_and_enforces_1mib_cap() -> None:
    from superbrain.core.wire import (
        encode_envelope,
        encode_jsonrpc_result,
        load_catalog,
        make_mcp_tool_result,
        make_success_envelope,
    )

    catalog = load_catalog()
    out_validator = jsonschema.Draft202012Validator(catalog.tools["get_artifact"].output_schema)

    for resource_payloads in (
        [("single.md", "S" * 65_500)],
        [("L1.md", "A" * 36_000), ("L2.md", "B" * 36_000)],
    ):
        envelope = make_success_envelope(
            {
                "artifact_id": "art-large-01",
                "revision": 1,
                "level": "L2",
                "status": "ok",
                "resources": [
                    {
                        "name": name,
                        "digest": digest_bytes(body.encode("utf-8")),
                        "encoding": "utf-8",
                        "content": body,
                    }
                    for name, body in resource_payloads
                ],
                "served_receipt_id": "rcpt-large-01",
            }
        )
        out_validator.validate(envelope)

        mcp_result = make_mcp_tool_result(envelope)
        content_items = mcp_result["content"]
        assert isinstance(content_items, list) and isinstance(content_items[0], dict)
        text_body = content_items[0]["text"]
        assert isinstance(text_body, str) and len(text_body.encode("utf-8")) > 65_536

        rpc_bytes = encode_jsonrpc_result("req-over-64k", mcp_result)
        assert len(rpc_bytes) <= 1_048_576
        decoded_rpc = json.loads(rpc_bytes.decode("utf-8"))
        assert decoded_rpc["jsonrpc"] == "2.0"
        assert decoded_rpc["id"] == "req-over-64k"
        assert decoded_rpc["result"]["structuredContent"] == envelope
        assert json.loads(decoded_rpc["result"]["content"][0]["text"]) == envelope

    # JSON safety checks (lone surrogates / NaN) still enforced on outgoing JSON-RPC result
    for unsafe_result in (
        {"bad": "\ud800"},
        {"bad": float("nan")},
        {"bad": float("inf")},
    ):
        with pytest.raises(BrainError) as unsafe_exc:
            encode_jsonrpc_result("req-unsafe", unsafe_result)
        assert unsafe_exc.value.code == ErrorCode.INVALID_INPUT

    # Outgoing envelope / JSON-RPC result exceeding 1 MiB body cap is rejected
    oversize_resources: list[JsonValue] = [
        {
            "name": f"part-{idx}.txt",
            "digest": "sha256:" + ("c" * 64),
            "encoding": "utf-8",
            "content": "X" * 60_000,
        }
        for idx in range(20)
    ]
    oversize_env: dict[str, JsonValue] = {
        "ok": True,
        "data": {
            "artifact_id": "art-oversize",
            "revision": 1,
            "level": "L2",
            "status": "ok",
            "resources": oversize_resources,
        },
    }
    with pytest.raises(BrainError) as env_exc:
        encode_envelope(oversize_env)
    assert env_exc.value.code == ErrorCode.INVALID_INPUT

    # Even if an envelope is ~600 KiB (< 1 MiB), duplicating it in structuredContent + text > 1 MiB fails framing
    half_mib_resources: list[JsonValue] = [
        {
            "name": f"seg-{idx}.txt",
            "digest": "sha256:" + ("d" * 64),
            "encoding": "utf-8",
            "content": "Y" * 60_000,
        }
        for idx in range(10)
    ]
    half_mib_mcp = make_mcp_tool_result(
        {
            "ok": True,
            "data": {
                "artifact_id": "art-half-mib",
                "revision": 1,
                "level": "L2",
                "status": "ok",
                "resources": half_mib_resources,
            },
        }
    )
    with pytest.raises(BrainError) as rpc_exc:
        encode_jsonrpc_result("req-over-1m", half_mib_mcp)
    assert rpc_exc.value.code == ErrorCode.INVALID_INPUT


def test_overlong_integer_digits_and_stored_result_decoders_raise_brain_error() -> None:
    from superbrain.core.kernel import StoredResult
    from superbrain.core.wire import (
        JSONRPC_PARSE_ERROR,
        JsonRpcError,
        parse_json,
        parse_jsonrpc_request,
    )

    huge_digits = "9" * 5_000

    with pytest.raises(BrainError) as pj_exc:
        parse_json(f'{{"huge": {huge_digits}}}'.encode())
    assert pj_exc.value.code == ErrorCode.INVALID_INPUT

    with pytest.raises(JsonRpcError) as rpc_exc:
        parse_jsonrpc_request(
            f'{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"n":{huge_digits}}}}}'.encode()
        )
    assert rpc_exc.value.code == JSONRPC_PARSE_ERROR

    for bad_refs_str in (
        f"[{huge_digits}]",
        '[{"kind":"skill","kind":"dup","id":"s-1","revision":1,"digest":"sha256:' + ("0" * 64) + '"}]',
        "[NaN]",
        "[" * 40 + "]" * 40,
        '"\\ud800"',
    ):
        with pytest.raises(BrainError) as refs_exc:
            StoredResult.decode_refs_json(bad_refs_str)
        assert refs_exc.value.code == ErrorCode.INVALID_INPUT

    for bad_canonical in (
        f'{{"result_id":"r-1","assignment_id":null,"refs":[{huge_digits}]}}'.encode(),
        b'{"result_id":"r-1","result_id":"r-2","assignment_id":null,"refs":[]}',
        b'{"result_id":"r-1","assignment_id":NaN,"refs":[]}',
        (b"[" * 40) + (b"]" * 40),
    ):
        with pytest.raises(BrainError) as canon_exc:
            StoredResult.from_canonical(bad_canonical)
        assert canon_exc.value.code == ErrorCode.INVALID_INPUT


def test_unhashable_enum_candidates_in_normalize_call_raise_brain_error() -> None:
    from superbrain.core.kernel import Principal
    from superbrain.core.wire import normalize_call

    principal = Principal(
        principal_id="princ-01",
        owner_id="owner-01",
        harness_id="codex-desktop",
        machine_id="mach-01",
    )
    bad_levels: tuple[JsonValue, ...] = (["L1"], {"level": "L1"})
    for bad_level in bad_levels:
        with pytest.raises(BrainError) as lvl_exc:
            normalize_call(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": "repo-01",
                    "task_id": "task-01",
                    "artifact_id": "art-01",
                    "revision": 1,
                    "level": bad_level,
                    "idempotency_key": "idem_bad_lvl_type_01",
                },
                principal,
                selected_scope=None,
            )
        assert lvl_exc.value.code == ErrorCode.INVALID_INPUT

    bad_outcomes: tuple[JsonValue, ...] = (["success"], {"outcome": "success"})
    for bad_outcome in bad_outcomes:
        with pytest.raises(BrainError) as out_exc:
            normalize_call(
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": "repo-01",
                    "delivery_id": "deliv-01",
                    "outcome": bad_outcome,
                    "idempotency_key": "idem_bad_out_type_01",
                },
                principal,
                selected_scope=None,
            )
        assert out_exc.value.code == ErrorCode.INVALID_INPUT


def test_prepare_response_snapshot_state_oneof() -> None:
    from superbrain.core.wire import load_catalog

    catalog = load_catalog()
    out_validator = jsonschema.Draft202012Validator(catalog.tools["prepare_task"].output_schema)
    in_validator = jsonschema.Draft202012Validator(catalog.tools["prepare_task"].input_schema)

    base_data: dict[str, Any] = {
        "workspace_id": "repo-01",
        "checkout_id": "chk-a",
        "source_snapshot_id": "snap-01",
        "snapshot_status": "available",
        "degraded_codes": [],
        "task_id": "task-01",
        "delivery_id": "deliv-01",
        "skills": [],
        "lessons": [],
        "continuity": [],
        "context": [],
        "finishing_gates": [],
    }

    for valid_patch in (
        {"snapshot_status": "available", "source_snapshot_id": "snap-01", "degraded_codes": []},
        {"snapshot_status": "available", "source_snapshot_id": "snap-01", "degraded_codes": ["jev_timeout"]},
        {
            "snapshot_status": "unavailable",
            "source_snapshot_id": None,
            "degraded_codes": ["snapshot_unavailable"],
        },
        {
            "snapshot_status": "deadline",
            "source_snapshot_id": None,
            "degraded_codes": ["snapshot_deadline"],
        },
    ):
        candidate = {"ok": True, "data": {**copy.deepcopy(base_data), **valid_patch}}
        out_validator.validate(candidate)

    invalid_patches: list[dict[str, JsonValue]] = [
        {"snapshot_status": "available", "source_snapshot_id": None, "degraded_codes": []},
        {
            "snapshot_status": "available",
            "source_snapshot_id": "snap-01",
            "degraded_codes": ["snapshot_unavailable"],
        },
        {
            "snapshot_status": "available",
            "source_snapshot_id": "snap-01",
            "degraded_codes": ["snapshot_deadline"],
        },
        {
            "snapshot_status": "unavailable",
            "source_snapshot_id": "snap-01",
            "degraded_codes": ["snapshot_unavailable"],
        },
        {"snapshot_status": "unavailable", "source_snapshot_id": None, "degraded_codes": []},
        {
            "snapshot_status": "unavailable",
            "source_snapshot_id": None,
            "degraded_codes": ["snapshot_unavailable", "snapshot_deadline"],
        },
        {
            "snapshot_status": "deadline",
            "source_snapshot_id": "snap-01",
            "degraded_codes": ["snapshot_deadline"],
        },
        {"snapshot_status": "deadline", "source_snapshot_id": None, "degraded_codes": []},
    ]
    for invalid_patch in invalid_patches:
        bad_candidate = {"ok": True, "data": {**copy.deepcopy(base_data), **invalid_patch}}
        assert not out_validator.is_valid(bad_candidate), f"expected invalid for {invalid_patch}"

    missing_status = copy.deepcopy(base_data)
    del missing_status["snapshot_status"]
    assert not out_validator.is_valid({"ok": True, "data": missing_status})

    for bad_client_extra in ({"snapshot_status": "available"}, {"unknown_source": True}):
        assert not in_validator.is_valid(
            {
                "schema_version": "2.0",
                "workspace_hint": "sb2",
                "description": "task",
                "idempotency_key": "idem_bad_status_0001",
                **bad_client_extra,
            }
        )


def test_schema_roundtrip_and_packaged_digest(
    inc2_installed_env: InstalledEnv,
    inc2_tls_material: SampleTlsMaterial,
    trusted_tmp: Path,
) -> None:
    from superbrain.core.kernel import Principal, Scope
    from superbrain.core.wire import (
        canonical_request_payload,
        encode_envelope,
        load_catalog,
        normalize_call,
        parse_json,
    )

    catalog = load_catalog()
    root_validator = jsonschema.Draft202012Validator(catalog.schema)
    kernel_http_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/KernelHttpCall",
        "$defs": catalog.schema["$defs"],
    }
    http_call_validator = jsonschema.Draft202012Validator(kernel_http_schema)
    root_validator.check_schema(catalog.schema)

    requests_doc = parse_json((FIXTURES_DIR / "requests.json").read_bytes())
    responses_doc = parse_json((FIXTURES_DIR / "responses.json").read_bytes())
    errors_doc = parse_json((FIXTURES_DIR / "errors.json").read_bytes())
    assert isinstance(requests_doc, dict)
    assert isinstance(responses_doc, dict)
    assert isinstance(errors_doc, dict)

    p_raw = requests_doc["principal"]
    assert isinstance(p_raw, dict)
    principal = Principal(
        principal_id=str(p_raw["principal_id"]),
        owner_id=str(p_raw["owner_id"]),
        harness_id=str(p_raw["harness_id"]),
        machine_id=str(p_raw["machine_id"]),
    )

    req_cases = requests_doc["cases"]
    assert isinstance(req_cases, list)
    seen_req_tools: set[str] = set()
    for case in req_cases:
        assert isinstance(case, dict)
        tool = str(case["tool"])
        seen_req_tools.add(tool)
        spec = catalog.tools[tool]
        client_validator = jsonschema.Draft202012Validator(spec.input_schema)
        client_args = case["client_args"]
        client_validator.validate(client_args)

        if not case["client_only"]:
            raw_scope = case["selected_scope"]
            scope = (
                Scope(
                    repo_id=str(raw_scope["repo_id"]),
                    checkout_id=str(raw_scope["checkout_id"]) if raw_scope["checkout_id"] is not None else None,
                )
                if isinstance(raw_scope, dict)
                else None
            )
            corr = str(case["correlation_id"]) if isinstance(case["correlation_id"], str) else None
            call = normalize_call(tool, client_args, principal, selected_scope=scope, correlation_id=corr)
            assert call.arguments == case["daemon_args"]

            http_payload: dict[str, Any] = {
                "tool": call.tool,
                "arguments": call.arguments,
                "correlation_id": call.correlation_id,
                "selected_scope": (
                    {"repo_id": scope.repo_id, "checkout_id": scope.checkout_id} if scope is not None else None
                ),
                "schema_digest": catalog.schema_digest,
            }
            http_call_validator.validate(http_payload)

            # Reversed key order & different correlation_id produce identical canonical request digest
            assert isinstance(client_args, dict)
            reordered_args = dict(reversed(list(client_args.items())))
            call_reordered = normalize_call(
                tool, reordered_args, principal, selected_scope=scope, correlation_id="other-corr-id"
            )
            assert canonical_request_payload(call) == canonical_request_payload(call_reordered)
    assert seen_req_tools == set(EXPECTED_TOOLS)

    resp_cases = responses_doc["cases"]
    assert isinstance(resp_cases, list)
    seen_resp_tools: set[str] = set()
    for case in resp_cases:
        assert isinstance(case, dict)
        tool = str(case["tool"])
        seen_resp_tools.add(tool)
        envelope = case["envelope"]
        jsonschema.Draft202012Validator(catalog.tools[tool].output_schema).validate(envelope)
        encoded = encode_envelope(envelope)
        assert parse_json(encoded) == envelope
    assert seen_resp_tools == set(EXPECTED_TOOLS)

    err_cases = errors_doc["cases"]
    assert isinstance(err_cases, list)
    seen_err_codes: set[str] = set()
    for case in err_cases:
        assert isinstance(case, dict)
        tool = str(case["tool"])
        envelope = case["envelope"]
        assert isinstance(envelope, dict) and isinstance(envelope["error"], dict)
        seen_err_codes.add(str(envelope["error"]["code"]))
        jsonschema.Draft202012Validator(catalog.tools[tool].output_schema).validate(envelope)
        encoded = encode_envelope(envelope)
        assert parse_json(encoded) == envelope
    assert {
        "capability_unavailable",
        "invalid_input",
        "identity_mismatch",
        "unauthenticated",
        "daemon_unavailable",
        "policy_unavailable",
        "commit_outcome_unknown",
    } <= seen_err_codes

    # Verify session TLS material fixture
    leaf_cert = x509.load_pem_x509_certificate(inc2_tls_material.leaf_cert_path.read_bytes())
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.IPv4Address("127.0.0.1") in san.get_values_for_type(x509.IPAddress)
    assert (
        hashlib.sha256(leaf_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        == inc2_tls_material.leaf_cert_sha256
    )

    # Verify installed wheel in isolated -I subprocess outside repo root (immune to CWD/env poison)
    isolated_cwd = trusted_tmp / "outside-cwd"
    isolated_cwd.mkdir()
    poison_dir = isolated_cwd / "schemas"
    poison_dir.mkdir()
    (poison_dir / "mcp-tools-v2.json").write_text('{"poison": true}', encoding="utf-8")

    probe_code = (
        "import importlib.resources, json, pathlib, superbrain; "
        "from superbrain.core.wire import load_catalog; "
        "res = importlib.resources.files('superbrain.core').joinpath('data/mcp-tools-v2.json'); "
        "cat = load_catalog(); "
        "print(json.dumps({"
        "'origin': str(pathlib.Path(superbrain.__file__).resolve()), "
        "'packaged_exists': res.is_file(), "
        "'schema_sha256': cat.schema_sha256, "
        "'tool_count': len(cat.tools)"
        "}))"
    )
    env = dict(os.environ)
    for var in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "SUPERBRAIN_SCHEMA"):
        env.pop(var, None)
    env["SUPERBRAIN_HOME"] = str(isolated_cwd)

    completed = subprocess.run(
        [str(inc2_installed_env.venv_python), "-I", "-c", probe_code],
        cwd=isolated_cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=60.0,
    )
    payload = json.loads(completed.stdout.strip())
    origin_path = Path(payload["origin"]).resolve()
    assert origin_path.is_relative_to(inc2_installed_env.venv_dir.resolve())
    assert not origin_path.is_relative_to((REPO_ROOT / "src").resolve())
    assert payload["packaged_exists"] is True
    assert payload["tool_count"] == 8
    assert payload["schema_sha256"] == inc2_installed_env.source_schema_sha256
    assert catalog.schema_sha256 == inc2_installed_env.source_schema_sha256


def test_installed_wheel_env_excludes_dev_dependencies_and_editable_pth(
    inc2_installed_env: InstalledEnv,
) -> None:
    probe_code = (
        "import cryptography, importlib.util, json, pathlib, superbrain, sysconfig; "
        "purelib = pathlib.Path(sysconfig.get_path('purelib')).resolve(); "
        "platlib = pathlib.Path(sysconfig.get_path('platlib')).resolve(); "
        "roots = sorted({purelib, platlib}, key=str); "
        "pths = {p.name: p.read_text(encoding='utf-8', errors='replace') "
        "for r in roots if r.is_dir() for p in sorted(r.glob('*.pth'))}; "
        "dev_specs = {name: (importlib.util.find_spec(name) is not None) "
        "for name in ('pytest', 'mypy', 'ruff', 'jsonschema')}; "
        "print(json.dumps({"
        "'purelib': str(purelib), "
        "'platlib': str(platlib), "
        "'superbrain_origin': str(pathlib.Path(superbrain.__file__).resolve()), "
        "'cryptography_origin': str(pathlib.Path(cryptography.__file__).resolve()), "
        "'dev_specs': dev_specs, "
        "'pths': pths"
        "}))"
    )
    env = dict(os.environ)
    for var in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "SUPERBRAIN_SCHEMA"):
        env.pop(var, None)

    completed = subprocess.run(
        [str(inc2_installed_env.venv_python), "-I", "-c", probe_code],
        cwd=inc2_installed_env.venv_dir,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=60.0,
    )
    payload = json.loads(completed.stdout.strip())
    venv_resolved = inc2_installed_env.venv_dir.resolve()
    repo_resolved = REPO_ROOT.resolve()
    purelib = Path(payload["purelib"]).resolve()
    platlib = Path(payload["platlib"]).resolve()
    sb_origin = Path(payload["superbrain_origin"]).resolve()
    crypto_origin = Path(payload["cryptography_origin"]).resolve()

    assert purelib.is_relative_to(venv_resolved)
    assert platlib.is_relative_to(venv_resolved)
    assert "site-packages" in purelib.parts or "site-packages" in platlib.parts
    assert sb_origin.is_relative_to(purelib) or sb_origin.is_relative_to(platlib)
    assert not sb_origin.is_relative_to(repo_resolved)
    assert crypto_origin.is_relative_to(purelib) or crypto_origin.is_relative_to(platlib)
    assert payload["dev_specs"] == {
        "pytest": False,
        "mypy": False,
        "ruff": False,
        "jsonschema": False,
    }

    pths = payload["pths"]
    assert isinstance(pths, dict)
    forbidden_markers = {
        os.path.normcase(str(repo_resolved)),
        os.path.normcase(repo_resolved.as_posix()),
    }
    for pth_name, pth_body in pths.items():
        norm_body = os.path.normcase(str(pth_body))
        for marker in forbidden_markers:
            assert marker not in norm_body, f".pth file {pth_name!r} references REPO_ROOT: {pth_body!r}"


def test_sp2_1_schema_and_normalizer_extensions() -> None:
    """Verify SP2-1 discover/work split, handoff fields, ReadAck, and HTTP digest contracts."""
    from superbrain.core.kernel import Principal, ReadAckInput, ResourceDigest, Scope
    from superbrain.core.wire import load_catalog, normalize_call

    catalog = load_catalog()
    expected_sha256 = hashlib.sha256((REPO_ROOT / "schemas" / "mcp-tools-v2.json").read_bytes()).hexdigest()
    assert catalog.schema_sha256 == expected_sha256
    assert catalog.schema_digest == f"sha256:{expected_sha256}"

    root_defs = catalog.schema["$defs"]
    assert isinstance(root_defs, dict)

    def _sub_validator(def_name: str) -> jsonschema.Draft202012Validator:
        return jsonschema.Draft202012Validator(
            {
                "$schema": catalog.schema["$schema"],
                "$defs": root_defs,
                "$ref": f"#/$defs/{def_name}",
            }
        )

    prep_in = jsonschema.Draft202012Validator(catalog.tools["prepare_task"].input_schema)
    prep_daemon = _sub_validator("PrepareTaskDaemonArgs")
    prep_out = jsonschema.Draft202012Validator(catalog.tools["prepare_task"].output_schema)
    get_art_in = jsonschema.Draft202012Validator(catalog.tools["get_artifact"].input_schema)
    get_art_out = jsonschema.Draft202012Validator(catalog.tools["get_artifact"].output_schema)
    submit_in = jsonschema.Draft202012Validator(catalog.tools["submit_episode"].input_schema)
    submit_out = jsonschema.Draft202012Validator(catalog.tools["submit_episode"].output_schema)
    delivered_ref_v = _sub_validator("DeliveredRefItem")
    http_call_v = _sub_validator("KernelHttpCall")

    principal = Principal(
        principal_id="princ-01",
        owner_id="owner-01",
        harness_id="codex-desktop",
        machine_id="mach-01",
    )
    scope = Scope(repo_id="repo-01", checkout_id="chk-a")

    # 1. prepare_task discover vs work normalization & validation
    assert prep_in.is_valid({"schema_version": "2.0", "mode": "discover"})
    assert not prep_daemon.is_valid(
        {"schema_version": "2.0", "mode": "discover", "context_budget_tokens": 4000}
    )

    disc_call = normalize_call(
        "prepare_task",
        {"schema_version": "2.0", "mode": "discover", "workspace_hint": "sb2"},
        principal,
        selected_scope=scope,
    )
    assert disc_call.arguments == {
        "schema_version": "2.0",
        "mode": "discover",
        "workspace_hint": "sb2",
        "context_budget_tokens": 4000,
    }
    assert prep_daemon.is_valid(disc_call.arguments)

    for forbidden_key, forbidden_val in (
        ("idempotency_key", "idem_disc_bad_0001"),
        ("description", "should be forbidden in discover"),
        (
            "resume_ref",
            {
                "artifact_id": "hand-1",
                "revision": 1,
                "handoff_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
            },
        ),
        (
            "seen_handoff_refs",
            [
                {
                    "artifact_id": "hand-2",
                    "revision_epoch": 0,
                    "revision": 1,
                    "digest": "sha256:" + ("a" * 64),
                }
            ],
        ),
        ("source_snapshot_id", "snap-1"),
    ):
        bad_disc: dict[str, Any] = {
            "schema_version": "2.0",
            "mode": "discover",
            "workspace_hint": "sb2",
            forbidden_key: forbidden_val,
        }
        assert not prep_in.is_valid(bad_disc)
        with pytest.raises(BrainError) as exc_disc:
            normalize_call("prepare_task", bad_disc, principal, selected_scope=scope)
        assert exc_disc.value.code is ErrorCode.INVALID_INPUT

    # mode defaults to "work"; resume_ref requires task_id
    work_default = normalize_call(
        "prepare_task",
        {
            "schema_version": "2.0",
            "workspace_hint": "sb2",
            "description": "default mode check",
            "idempotency_key": "idem_work_def_0001",
        },
        principal,
        selected_scope=scope,
    )
    assert work_default.arguments["mode"] == "work"
    assert prep_daemon.is_valid(work_default.arguments)

    no_task_resume: dict[str, Any] = {
        "schema_version": "2.0",
        "mode": "work",
        "workspace_id": "repo-01",
        "checkout_id": "chk-a",
        "description": "missing task_id for resume_ref",
        "resume_ref": {
            "artifact_id": "hand-1",
            "revision": 2,
            "handoff_revision": 1,
            "fence": {"restore_epoch": 1, "writer_generation": 1},
        },
        "idempotency_key": "idem_work_no_task_01",
    }
    assert not prep_in.is_valid(no_task_resume)
    with pytest.raises(BrainError) as exc_res:
        normalize_call("prepare_task", no_task_resume, principal, selected_scope=scope)
    assert exc_res.value.code is ErrorCode.INVALID_INPUT

    seen_64 = [
        {
            "artifact_id": f"hand-{i:03d}",
            "revision_epoch": 1,
            "revision": 1,
            "digest": "sha256:" + ("a" * 64),
        }
        for i in range(64)
    ]
    valid_work_resume = {**no_task_resume, "task_id": "task-1", "seen_handoff_refs": seen_64}
    assert prep_in.is_valid(valid_work_resume)
    assert not prep_in.is_valid({**valid_work_resume, "seen_handoff_refs": seen_64 + [seen_64[0]]})

    # 2. PrepareTaskResult & HandoffLive oneOf + DeliveredRefItem handoff rule
    assert prep_out.is_valid(
        {
            "ok": True,
            "data": {
                "workspace_id": "repo-01",
                "checkout_id": "chk-a",
                "continuity": [
                    {
                        "kind": "handoff",
                        "id": "hand-1",
                        "revision_epoch": 0,
                        "revision": 1,
                        "digest": "sha256:" + ("a" * 64),
                        "summary": "goal",
                    }
                ],
                "degraded_codes": [],
            },
        }
    )
    assert not prep_out.is_valid(
        {
            "ok": True,
            "data": {
                "workspace_id": "repo-01",
                "checkout_id": "chk-a",
                "continuity": [],
                "degraded_codes": [],
                "snapshot_status": "available",
            },
        }
    )

    assert delivered_ref_v.is_valid(
        {
            "kind": "handoff",
            "id": "hand-1",
            "revision_epoch": 0,
            "revision": 1,
            "digest": "sha256:" + ("b" * 64),
        }
    )
    assert not delivered_ref_v.is_valid(
        {
            "kind": "handoff",
            "id": "hand-1",
            "revision": 1,
            "digest": "sha256:" + ("b" * 64),
        }
    )
    assert not delivered_ref_v.is_valid(
        {
            "kind": "handoff",
            "id": "hand-1",
            "revision_epoch": -1,
            "revision": 1,
            "digest": "sha256:" + ("b" * 64),
        }
    )
    assert delivered_ref_v.is_valid(
        {
            "kind": "skill",
            "id": "skill-1",
            "revision": 1,
            "digest": "sha256:" + ("b" * 64),
        }
    )

    def _work_envelope(live: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "data": {
                "workspace_id": "repo-01",
                "checkout_id": "chk-a",
                "source_snapshot_id": "snap-1",
                "snapshot_status": "available",
                "degraded_codes": [],
                "task_id": "task-1",
                "delivery_id": "deliv-1",
                "handoff_live": live,
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": [],
                "finishing_gates": [],
            },
        }

    assert prep_out.is_valid(
        {
            "ok": True,
            "data": {
                "workspace_id": "repo-01",
                "checkout_id": "chk-a",
                "source_snapshot_id": "snap-1",
                "snapshot_status": "available",
                "degraded_codes": [],
                "task_id": "task-1",
                "delivery_id": "deliv-1",
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": [],
                "finishing_gates": [],
            },
        }
    )
    assert prep_out.is_valid(
        _work_envelope(
            {
                "revision": None,
                "revision_epoch": None,
                "handoff_revision": 0,
                "fence": {"restore_epoch": 2, "writer_generation": 0},
            }
        )
    )
    assert prep_out.is_valid(
        _work_envelope(
            {
                "revision": 1,
                "revision_epoch": 0,
                "handoff_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
            }
        )
    )
    for bad_live in (
        {
            "revision": None,
            "revision_epoch": 0,
            "handoff_revision": 0,
            "fence": {"restore_epoch": 0, "writer_generation": 0},
        },
        {
            "revision": None,
            "revision_epoch": None,
            "handoff_revision": 1,
            "fence": {"restore_epoch": 0, "writer_generation": 0},
        },
        {
            "revision": None,
            "revision_epoch": None,
            "handoff_revision": 0,
            "fence": {"restore_epoch": 0, "writer_generation": 1},
        },
        {
            "revision": 1,
            "revision_epoch": None,
            "handoff_revision": 0,
            "fence": {"restore_epoch": 0, "writer_generation": 0},
        },
    ):
        assert not prep_out.is_valid(_work_envelope(bad_live))

    # 3. ReadAckInput artifact_id + revision_epoch
    ack_good = ReadAckInput(
        served_receipt_id="rcpt-1",
        task_id="task-1",
        artifact_id="hand-1",
        revision_epoch=0,
        revision=1,
        resource_digests=(ResourceDigest("handoff_header", "sha256:" + ("c" * 64)),),
    )
    assert ack_good.artifact_id == "hand-1"
    assert ack_good.revision_epoch == 0
    for bad_epoch in (-1, True):
        with pytest.raises(BrainError):
            ReadAckInput(
                served_receipt_id="rcpt-1",
                task_id="task-1",
                artifact_id="hand-1",
                revision_epoch=bad_epoch,
                revision=1,
                resource_digests=(ResourceDigest("L0.md", "sha256:" + ("c" * 64)),),
            )

    # 4. get_artifact optional revision_epoch & handoff_live
    get_art_args: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_id": "repo-01",
        "task_id": "task-1",
        "artifact_id": "hand-1",
        "revision_epoch": 0,
        "revision": 2,
        "level": "L1",
        "idempotency_key": "idem_get_art_epoch_01",
    }
    assert get_art_in.is_valid(get_art_args)
    norm_art = normalize_call("get_artifact", get_art_args, principal, selected_scope=scope)
    assert norm_art.arguments["revision_epoch"] == 0
    bad_art_epoch: int
    for bad_art_epoch in (-1, True):
        bad_art_call: dict[str, JsonValue] = {**get_art_args, "revision_epoch": bad_art_epoch}
        assert not get_art_in.is_valid(bad_art_call)
        with pytest.raises(BrainError) as exc_art:
            normalize_call(
                "get_artifact",
                bad_art_call,
                principal,
                selected_scope=scope,
            )
        assert exc_art.value.code is ErrorCode.INVALID_INPUT
    assert get_art_out.is_valid(
        {
            "ok": True,
            "data": {
                "artifact_id": "hand-1",
                "revision_epoch": 0,
                "revision": 1,
                "level": "L1",
                "status": "redacted",
                "reason": "quarantined",
                "resources": [],
            },
        }
    )

    # 5. submit_episode handoff/takeover/fence bidirectional coupling & SubmitEpisodeResult oneOf
    base_ep: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "task_id": "task-1",
        "session_id": "sess-1",
        "workspace_id": "repo-01",
        "checkout_id": "chk-a",
        "evidence": [],
        "idempotency_key": "idem_submit_couple_01",
    }
    good_patch: dict[str, JsonValue] = {"working_goal": "Keep invariants strict."}
    good_fence: dict[str, JsonValue] = {"restore_epoch": 0, "writer_generation": 0}
    good_takeover: dict[str, JsonValue] = {"acknowledge_active": False, "reason": "First write"}

    valid_subs: tuple[dict[str, JsonValue], ...] = (
        base_ep,
        {**base_ep, "handoff": good_patch, "base_revision": 0, "fence": good_fence},
        {**base_ep, "takeover": good_takeover, "base_revision": 0, "fence": good_fence},
        {**base_ep, "handoff": good_patch, "takeover": good_takeover, "base_revision": 1, "fence": good_fence},
    )
    for valid_sub in valid_subs:
        assert submit_in.is_valid(valid_sub)
        normalize_call("submit_episode", valid_sub, principal, selected_scope=scope)

    bad_sub_patches: tuple[dict[str, JsonValue], ...] = (
        {"handoff": good_patch},
        {"takeover": good_takeover},
        {"handoff": good_patch, "base_revision": 0},
        {"takeover": good_takeover, "fence": good_fence},
        {"base_revision": 0, "fence": good_fence},
        {"handoff": {}},
        {
            "handoff": {
                "decisions": [
                    {"id": "d1", "decision": "x", "reason": "y", "supersedes": "d0", "reopens": "r0"}
                ]
            },
            "base_revision": 0,
            "fence": good_fence,
        },
        {
            "handoff": {"rejected": [{"id": "r1", "option": "x", "reason": "y", "merges": []}]},
            "base_revision": 0,
            "fence": good_fence,
        },
        {
            "handoff": {"closed_changes": [{"change_id": "c1", "resolution": "approved"}]},
            "base_revision": 0,
            "fence": good_fence,
        },
        {
            "handoff": {
                "plan": [{"id": f"s-{i}", "summary": "step", "status": "pending"} for i in range(65)],
            },
            "base_revision": 0,
            "fence": good_fence,
        },
    )
    bad_sub_patch: dict[str, JsonValue]
    for bad_sub_patch in bad_sub_patches:
        bad_sub: dict[str, JsonValue] = {**base_ep, **bad_sub_patch}
        assert not submit_in.is_valid(bad_sub)
        with pytest.raises(BrainError) as exc_sub:
            normalize_call("submit_episode", bad_sub, principal, selected_scope=scope)
        assert exc_sub.value.code is ErrorCode.INVALID_INPUT

    # SubmitEpisodeResult oneOf checks
    assert not submit_out.is_valid(
        {
            "ok": True,
            "data": {
                "episode_id": "ep-1",
                "evidence_ids": [],
                "handoff_status": "stored",
            },
        }
    )
    assert not submit_out.is_valid(
        {
            "ok": True,
            "data": {
                "episode_id": "ep-1",
                "evidence_ids": [],
                "handoff_revision": None,
                "handoff_status": "stored",
                "fence": good_fence,
                "writer_status": "holder",
            },
        }
    )
    assert not submit_out.is_valid(
        {
            "ok": True,
            "data": {
                "episode_id": "ep-1",
                "evidence_ids": [],
                "handoff_revision": 0,
                "handoff_status": "not_stored_policy",
                "fence": good_fence,
                "writer_status": "not_holder",
            },
        }
    )

    # 6. KernelHttpCall requires valid schema_digest
    valid_http = {
        "tool": "prepare_task",
        "arguments": disc_call.arguments,
        "correlation_id": None,
        "selected_scope": {"repo_id": "repo-01", "checkout_id": "chk-a"},
        "schema_digest": catalog.schema_digest,
    }
    assert http_call_v.is_valid(valid_http)
    assert not http_call_v.is_valid({k: v for k, v in valid_http.items() if k != "schema_digest"})
    assert not http_call_v.is_valid({**valid_http, "schema_digest": "sha256:bad"})

