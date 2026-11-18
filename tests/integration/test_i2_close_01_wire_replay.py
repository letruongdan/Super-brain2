"""Independent bug-proof oracle V2 for I2-CLOSE-01: direct/queued replay, wire/filter caps, & sibling subjects.

Derives all expected bytes, HMAC-SHA256 digests, wire/filter bounds, and subject digests strictly from the
JSON/pre-R41 canonical UTF-8 format (``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``,
``allow_nan=False``) without calling ``canonical_json``, ``canonical_digest``, or ``canonical_request_payload``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application._prequeue import admit_prequeue_request, reconstruct_queued_call
from superbrain.application._privacy_rules import MAX_TOTAL_BYTES
from superbrain.application.privacy import PrivacyFilter
from superbrain.cli_api._loopback_wire import decode_call, decode_result, encode_call
from superbrain.composition.kernel_bridge import AtomicRequestAuthState, KernelBridge
from superbrain.core import errors, wire
from superbrain.core import kernel as k
from superbrain.core._kernel_auth import TrustedLocator, WorkspaceRegistration
from superbrain.core._kernel_send_attempts import canonicalize_resource_digests, decode_resource_digests_json
from superbrain.core.jsonvalue import JsonValue
from superbrain.storage import kernel_schema, ledger, runtime
from superbrain.storage._idempotency_sql import advance_c4_hwm, write_idempotency_row
from tests.storage.conftest import CLOCK_START
from tests.support.clock import FakeClock
from tests.support.inc2_kernel_domain import FixtureKernelDomain, fixture_store_extensions, validate_response_envelope
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

TREE_A = "sha256:" + "a" * 64
REMOTE_A = "https://github.example/dan/repo-i2-close-01.git"
DEL_COUNT_AT_CAP = 200
QUOTE_COUNT_AT_CAP = 1_500


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


class _Mono:
    def __init__(self, start: int = 10_000_000_000) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now

    def monotonic_ns(self) -> int:
        return self.now


class _Observer:
    source = "fixture"

    def observe(self, binding: k.WorkspaceBinding, deadline_ns: int) -> k.SnapshotObservation:
        _ = (binding, deadline_ns)
        return k.SnapshotObservation(
            k.SnapshotStatus.AVAILABLE, k.SnapshotDescriptor("git", TREE_A, False, None, "2026-11-01T00:00:00.000000Z")
        )


class _EpisodeReplayDomain(FixtureKernelDomain):
    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return True if tool == "submit_episode" else super().supports_tool(tool, deep=deep)

    def render_stored(
        self, result: k.StoredResult, principal: k.Principal, *, selected_scope: k.Scope | None
    ) -> dict[str, JsonValue]:
        if result.refs and result.refs[0].kind == "episode_result":
            return {"episode_id": result.result_id, "ref_id": result.refs[0].id}
        return super().render_stored(result, principal, selected_scope=selected_scope)


@dataclass(frozen=True)
class _KernelEnv:
    rt: runtime.Runtime
    seeded: SeededCredential
    scope: k.Scope
    domain: FixtureKernelDomain
    auth_state: AtomicRequestAuthState
    bridge: KernelBridge
    mono: _Mono
    auth: k.PrivateRequestAuth


def _open_kernel_env(
    trusted_tmp: Path, clock: FakeClock, *, domain_cls: type[FixtureKernelDomain] = FixtureKernelDomain
) -> _KernelEnv:
    os_, (handlers, kinds_reg) = os_adapters(clock=clock), fixture_store_extensions()
    rt = runtime.open_runtime(
        trusted_tmp / "root",
        os_,
        handlers=handlers,
        kinds=kinds_reg,
        store_migrations=kernel_schema.KERNEL_STORE_MIGRATIONS,
        policy_migrations=kernel_schema.KERNEL_POLICY_MIGRATIONS,
    )
    seeded, chk = seed_principal_and_credential(rt.policy), trusted_tmp / "chk"
    chk.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias="ws-main",
        raw_path=str(chk),
        raw_remote=REMOTE_A,
        provider_egress_enabled=False,
    )
    proof = make_bootstrap_auth(
        store_id=rt.policy.store_id,
        owner_id=seeded.principal.owner_id,
        action="workspace_register",
        subject_id=reg.subject_id,
        trust_generation=rt.policy.trust_generation(),
        expires_at=clock.now() + timedelta(hours=1),
    )
    binding = rt.policy.register_authorized_workspace(reg, proof)
    rt.store.reconcile_policy()
    scope, mono = k.Scope(binding.repo_id, binding.checkout_id), _Mono()
    domain = domain_cls(store=rt.store, policy=rt.policy, clock=clock, observer=_Observer(), monotonic_ns=mono)
    auth_state = AtomicRequestAuthState(rt.store.store_id)
    bridge = KernelBridge(
        store=rt.store,
        policy=rt.policy,
        clock=clock,
        monotonic_clock=mono,
        writer_epoch=rt.lease.epoch,
        domain=domain,
        auth_state=auth_state,
    )
    bridge.publish_auth_view()
    auth = k.PrivateRequestAuth(seeded.credential_id, seeded.principal, seeded.token)
    return _KernelEnv(rt, seeded, scope, domain, auth_state, bridge, mono, auth)


def _ctx(env: _KernelEnv, canonical_payload: bytes | None = None) -> k.CallContext:
    ident = k.Identity(env.rt.store.store_id, env.rt.lease.epoch, "inst-close-01")
    return k.CallContext(
        env.seeded.principal,
        ident,
        env.mono() + k.TOTAL_REQUEST_BUDGET_NS,
        env.scope,
        canonical_payload=canonical_payload,
    )


def _expect_ok(tool: str, res: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res) if tool == "prepare_task" else res
    assert checked.get("ok") is True and isinstance(checked["data"], dict), checked
    return checked["data"]


def _expect_conflict(res: Mapping[str, JsonValue]) -> None:
    err = res.get("error")
    assert res.get("ok") is False and isinstance(err, dict)
    assert err.get("code") == errors.ErrorCode.IDEMPOTENCY_CONFLICT.value


def _admit_q(env: _KernelEnv, tool: str, args: dict[str, JsonValue]) -> k.QueuedKernelRequest:
    return admit_prequeue_request(
        expected_store_id=env.rt.store.store_id,
        writer_epoch=env.rt.lease.epoch,
        auth_state=env.auth_state,
        tool=tool,
        raw_arguments=dict(args),
        token=env.seeded.token,
        deadlines=k.RequestDeadlines.from_receive_ns(env.mono()),
        selected_scope=env.scope,
    )


def _assert_replay_and_conflicts(
    env: _KernelEnv,
    *,
    tool: str,
    args: dict[str, JsonValue],
    pre_req_bytes: bytes,
    key_id: str,
    pre_hmac: str,
    expected_data: dict[str, JsonValue],
    expected_prepare_calls: int,
    bad_variants: Sequence[dict[str, JsonValue]],
) -> None:
    direct = wire.normalize_call(tool, dict(args), env.seeded.principal, selected_scope=env.scope)
    assert _expect_ok(tool, env.bridge.dispatch(direct, _ctx(env), auth=env.auth)) == expected_data
    live_q = _admit_q(env, tool, args)
    live_res = env.bridge.dispatch(reconstruct_queued_call(live_q), _ctx(env, live_q.canonical_payload), auth=env.auth)
    assert _expect_ok(tool, live_res) == expected_data
    pre_q = k.QueuedKernelRequest(
        env.rt.store.store_id,
        env.rt.lease.epoch,
        tool,
        None,
        env.scope,
        k.RequestDeadlines.from_receive_ns(env.mono()),
        1,
        env.auth,
        pre_req_bytes,
        live_q.scope_key,
        key_id,
        pre_hmac,
    )
    pre_res = env.bridge.dispatch(reconstruct_queued_call(pre_q), _ctx(env, pre_q.canonical_payload), auth=env.auth)
    assert _expect_ok(tool, pre_res) == expected_data and env.domain.prepare_calls == expected_prepare_calls

    escaped_q = replace(pre_q, canonical_payload=pre_req_bytes.replace(b"\x7f", b"\\u007f"))
    assert b"\\u007f" in escaped_q.canonical_payload
    with pytest.raises(errors.BrainError) as exc_q:
        reconstruct_queued_call(escaped_q)
    assert exc_q.value.code is errors.ErrorCode.INTEGRITY_FAILURE

    for bad in bad_variants:
        bad_c = wire.normalize_call(tool, bad, env.seeded.principal, selected_scope=env.scope)
        _expect_conflict(env.bridge.dispatch(bad_c, _ctx(env), auth=env.auth))
        bad_q = _admit_q(env, tool, bad)
        res_bq = env.bridge.dispatch(reconstruct_queued_call(bad_q), _ctx(env, bad_q.canonical_payload), auth=env.auth)
        _expect_conflict(res_bq)


# --- 3. Retained Pre-R41 IdempotencyRow & Direct/Queued Replay -----------------------------------------------------


@pytest.mark.parametrize(
    "description",
    ["ascii-del-\x7f-task", "ctrl-del-\x1f-\x7e-\x7f-task", "unicode-del-\x1f-\x7f-\x80-é-🚀"],
    ids=["ascii_del", "ctrl_del", "unicode_del"],
)
def test_prepare_task_replay_with_retained_pre_r41_idempotency_row(trusted_tmp: Path, description: str) -> None:
    clock = FakeClock(CLOCK_START)
    env = _open_kernel_env(trusted_tmp, clock)
    try:
        idem_key = "idem_close_01_prepare_task"
        args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": description,
            "context_budget_tokens": 4000,
            "idempotency_key": idem_key,
        }
        first_call = wire.normalize_call("prepare_task", args, env.seeded.principal, selected_scope=env.scope)
        first_data = _expect_ok("prepare_task", env.bridge.dispatch(first_call, _ctx(env), auth=env.auth))
        assert env.domain.prepare_calls == 1
        key_id, key_bytes = env.rt.policy.request_digest_key()
        pre_req_bytes = _pre_r41_request_bytes("prepare_task", env.scope, first_call.arguments)
        assert b"\x7f" in pre_req_bytes and b"\\u007f" not in pre_req_bytes
        if "\x1f" in description:
            assert b"\\u001f" in pre_req_bytes
        pre_hmac = _pre_r41_hmac(key_bytes, pre_req_bytes)
        key_hash = _pre_r41_idem_key_hash(env.seeded.principal.principal_id, "prepare_task", idem_key)
        with env.rt.store.transaction() as txn:
            cur = txn.db.execute(
                "UPDATE idempotency SET request_digest_key_id = ?, request_digest = ? "
                "WHERE principal_id = ? AND tool = ? AND key_hash = ?",
                (key_id, pre_hmac, env.seeded.principal.principal_id, "prepare_task", key_hash),
            )
            assert cur.rowcount == 1
        clock.advance(timedelta(minutes=1))
        _assert_replay_and_conflicts(
            env,
            tool="prepare_task",
            args=args,
            pre_req_bytes=pre_req_bytes,
            key_id=key_id,
            pre_hmac=pre_hmac,
            expected_data=first_data,
            expected_prepare_calls=1,
            bad_variants=[{**args, "description": description.replace("\x7f", "\x7e")}],
        )
    finally:
        env.rt.close()


@pytest.mark.parametrize("with_unicode", [False, True], ids=["ascii_nested_del", "unicode_nested_del"])
def test_nested_key_and_list_replay_with_retained_pre_r41_idempotency_row(
    trusted_tmp: Path, with_unicode: bool
) -> None:
    clock = FakeClock(CLOCK_START)
    env = _open_kernel_env(trusted_tmp, clock, domain_cls=_EpisodeReplayDomain)
    try:
        idem_key = "idem_close_01_submit_episode"
        inner: dict[str, JsonValue] = {
            "items": ["\x1f", "\x7e", "\x7f", *(["\x80"] if with_unicode else [])],
            "nested\x7f": {"inner\x7f": "val\x7f", **({"u": "é🚀"} if with_unicode else {})},
        }
        args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": env.scope.repo_id,
            "task_id": "task-close-01",
            "session_id": "sess-close-01",
            "evidence": [{"kind": "note", "data": inner}],
            "idempotency_key": idem_key,
        }
        call = wire.normalize_call("submit_episode", args, env.seeded.principal, selected_scope=env.scope)
        key_id, key_bytes = env.rt.policy.request_digest_key()
        pre_req_bytes = _pre_r41_request_bytes("submit_episode", env.scope, call.arguments)
        assert b"nested\x7f" in pre_req_bytes and b"\\u007f" not in pre_req_bytes
        pre_hmac, committed_at = _pre_r41_hmac(key_bytes, pre_req_bytes), ledger.utc_timestamp(clock.now())
        row = k.IdempotencyRow(
            env.seeded.principal.principal_id,
            "submit_episode",
            _pre_r41_idem_key_hash(env.seeded.principal.principal_id, "submit_episode", idem_key),
            key_id,
            pre_hmac,
            "res-ep-01",
            None,
            (k.ObjectRef(kind="episode_result", id="ep-1", revision=1, digest=TREE_A),),
            committed_at,
        )
        with env.rt.store.transaction() as txn:
            write_idempotency_row(txn.db, row)
            advance_c4_hwm(txn.db, committed_at, current_hwm=None)
        clock.advance(timedelta(minutes=1))

        val_bad: dict[str, JsonValue] = {
            **args,
            "evidence": [{"kind": "note", "data": {**inner, "nested\x7f": {"inner\x7f": "val\x7e"}}}],
        }
        bad_inner: dict[str, JsonValue] = {"items": inner["items"], "nested\x7e": inner["nested\x7f"]}
        key_bad: dict[str, JsonValue] = {**args, "evidence": [{"kind": "note", "data": bad_inner}]}
        _assert_replay_and_conflicts(
            env,
            tool="submit_episode",
            args=args,
            pre_req_bytes=pre_req_bytes,
            key_id=key_id,
            pre_hmac=pre_hmac,
            expected_data={"episode_id": "res-ep-01", "ref_id": "ep-1"},
            expected_prepare_calls=0,
            bad_variants=[val_bad, key_bad],
        )
    finally:
        env.rt.close()


# --- 4a. Wire Limits, PrivacyFilter.apply, & Sibling Subjects --------------------------------------------------------


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


def _envelope_at_bytes(
    target_bytes: int, *, del_count: int, with_unicode: bool
) -> tuple[dict[str, JsonValue], bytes]:
    pad: list[JsonValue] = ["\x7f" * del_count]
    data: dict[str, JsonValue] = {"pad": pad}
    if with_unicode:
        data["u"] = "é"
    env: dict[str, JsonValue] = {"ok": True, "data": data}
    return env, _fill_pad_to_bytes(pad, lambda: env, target_bytes=target_bytes, del_count=del_count)


def _call_at_bytes(target_bytes: int, *, del_count: int, with_unicode: bool) -> tuple[k.ToolCommand, bytes]:
    pad: list[JsonValue] = ["\x7f" * del_count]
    args: dict[str, JsonValue] = {"schema_version": "2.0", "pad": pad}
    if with_unicode:
        args["u"] = "é"
    body: dict[str, object] = {"tool": "get_health", "arguments": args, "correlation_id": None, "selected_scope": None}
    return k.ToolCommand("get_health", args, token="cred.secret"), _fill_pad_to_bytes(
        pad, lambda: body, target_bytes=target_bytes, del_count=del_count
    )


def _mcp_result_at_bytes(target_bytes: int, *, with_unicode: bool) -> tuple[str, dict[str, JsonValue], bytes]:
    pad: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP]
    data: dict[str, JsonValue] = {"pad": pad}
    if with_unicode:
        data["u"] = "é"
    env: dict[str, JsonValue] = {"ok": True, "data": data}

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


def _assert_size_cap_rejected(fn: Callable[[], object]) -> None:
    with pytest.raises(errors.BrainError) as exc:
        fn()
    assert exc.value.code is errors.ErrorCode.INVALID_INPUT and "size limit" in exc.value.message


@pytest.mark.parametrize("with_unicode", [False, True], ids=["ascii_del", "unicode_del"])
def test_wire_body_limit_accounts_one_byte_per_u007f(with_unicode: bool) -> None:
    assert wire.MAX_WIRE_BODY_BYTES == 1_048_576
    cap = wire.MAX_WIRE_BODY_BYTES
    env_ok, env_ok_bytes = _envelope_at_bytes(cap, del_count=DEL_COUNT_AT_CAP, with_unicode=with_unicode)
    encoded_env = wire.encode_envelope(env_ok)
    assert len(encoded_env) == cap and encoded_env == env_ok_bytes and b"\\u007f" not in encoded_env
    assert decode_result(encoded_env) == env_ok and wire.parse_json(encoded_env) == env_ok
    env_over, env_over_bytes = _envelope_at_bytes(cap + 1, del_count=DEL_COUNT_AT_CAP, with_unicode=with_unicode)
    _assert_size_cap_rejected(lambda: wire.encode_envelope(env_over))
    _assert_size_cap_rejected(lambda: decode_result(env_over_bytes))

    cmd_ok, cmd_ok_bytes = _call_at_bytes(cap, del_count=DEL_COUNT_AT_CAP, with_unicode=with_unicode)
    encoded_call = encode_call(cmd_ok)
    assert len(encoded_call) == cap and encoded_call == cmd_ok_bytes and b"\\u007f" not in encoded_call
    assert decode_call(encoded_call, "cred.secret").arguments == cmd_ok.arguments
    cmd_over, cmd_over_bytes = _call_at_bytes(cap + 1, del_count=DEL_COUNT_AT_CAP, with_unicode=with_unicode)
    _assert_size_cap_rejected(lambda: encode_call(cmd_over))
    _assert_size_cap_rejected(lambda: decode_call(cmd_over_bytes, "cred.secret"))

    req_id_ok, mcp_env_ok, mcp_bytes_ok = _mcp_result_at_bytes(cap, with_unicode=with_unicode)
    mcp_res_ok = wire.make_mcp_tool_result(mcp_env_ok)
    rpc_ok = wire.encode_jsonrpc_result(req_id_ok, mcp_res_ok)
    assert len(rpc_ok) == cap and rpc_ok == mcp_bytes_ok and b"\\u007f" not in rpc_ok
    req_id_over, mcp_env_over, _ = _mcp_result_at_bytes(cap + 1, with_unicode=with_unicode)
    _assert_size_cap_rejected(
        lambda: wire.encode_jsonrpc_result(req_id_over, wire.make_mcp_tool_result(mcp_env_over))
    )


@pytest.mark.parametrize("with_unicode", [False, True], ids=["ascii_del", "unicode_del"])
def test_privacy_filter_apply_accounts_one_byte_per_u007f_at_max_total_bytes(with_unicode: bool) -> None:
    assert MAX_TOTAL_BYTES == 1_048_576
    mono = _Mono()
    flt, policy, dl = PrivacyFilter(mono.monotonic_ns), k.FilterPolicy(), mono() + 10_000_000_000
    pad_ok: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP, '"' * QUOTE_COUNT_AT_CAP]
    ok_obj: dict[str, JsonValue] = {"pad": pad_ok, **({"u": "é"} if with_unicode else {})}
    _fill_pad_to_bytes(pad_ok, lambda: ok_obj, target_bytes=MAX_TOTAL_BYTES, del_count=DEL_COUNT_AT_CAP)
    safe = flt.apply(ok_obj, policy, deadline_ns=dl)
    assert safe.value == ok_obj and safe.redacted_count == 0 and safe.stripped_keys_count == 0

    pad_over: list[JsonValue] = ["\x7f" * DEL_COUNT_AT_CAP, '"' * QUOTE_COUNT_AT_CAP]
    over_obj: dict[str, JsonValue] = {"pad": pad_over, **({"u": "é"} if with_unicode else {})}
    _fill_pad_to_bytes(pad_over, lambda: over_obj, target_bytes=MAX_TOTAL_BYTES + 1, del_count=DEL_COUNT_AT_CAP)
    with pytest.raises(errors.BrainError) as exc:
        flt.apply(over_obj, policy, deadline_ns=dl)
    assert exc.value.code is errors.ErrorCode.INVALID_INPUT and "rejected" in exc.value.message


def test_sibling_resource_digests_and_workspace_subject_id_u007f_parity(trusted_tmp: Path) -> None:
    dig_a, dig_b = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    for names in (("doc-\x7f-a.md", "doc-\x7f-b.md"), ("doc-\x7f-a.md", "doc-\x7f-é.md")):
        items = (k.ResourceDigest(names[0], dig_a), k.ResourceDigest(names[1], dig_b))
        raw_text = _pre_r41_json([d.to_dict() for d in items]).decode("utf-8")
        assert "\x7f" in raw_text and "\\u007f" not in raw_text
        assert decode_resource_digests_json(raw_text) == items
        assert canonicalize_resource_digests(items) == (items, raw_text)
        with pytest.raises(errors.BrainError) as exc:
            decode_resource_digests_json(raw_text.replace("\x7f", "\\u007f"))
        assert exc.value.code is errors.ErrorCode.INTEGRITY_FAILURE

    for suffix in ("", "-é"):
        chk = str(trusted_tmp / f"repo-\x7f{suffix}")
        loc = TrustedLocator("https", f"https://example.test/repo-\x7f{suffix}.git", dig_a)
        reg = WorkspaceRegistration("owner-1", "prin-1", "mach-1", "ws-a", chk, f"pid-\x7f{suffix}", loc, False)
        expected_payload = {
            "owner_id": "owner-1",
            "principal_id": "prin-1",
            "machine_id": "mach-1",
            "alias": "ws-a",
            "checkout_path": chk,
            "path_identity": f"pid-\x7f{suffix}",
            "locator_digest": dig_a,
            "canonical_locator": loc.canonical_locator,
            "locator_scheme": "https",
            "provider_egress_enabled": False,
        }
        assert reg.subject_id == _sha256_tag(_pre_r41_json(expected_payload))
