"""Commit cutoff, artifact send receipts and snapshot fallback with the durable fixture domain (SP1 inc2 Task 8.2).

Requirement: plan Task 8 section 8.2 (bullets 2-4), review T8-P02/P03/P06, decisions D5 and S1=A, spec rev22 sections
5.4-5.5, 6.2-6.5 and 14.2. Every test runs the real daemon composition (``create_daemon_owner_loop`` +
``LoopbackServer``) in this process on a clone of the session's admitted template, with ``FixtureKernelDomain`` bound
on the owner thread over the real ``Store``/``PolicyStore`` (``tests/support/inc2_t8_harness.py``). Clients are the
real ``LoopbackClient``, the shim's own stdio loop (``run_stdio`` + ``build_tool_caller``), or the installed
``brain-mcp`` where the plan says "real shim". A fake monotonic clock makes the cutoff race deterministic. The
installed-shim timing test measures the actual response budget. Thread ordering uses bounded barriers.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.clock import SystemMonotonicClock
from superbrain.application.lineage import evaluate_egress_eligibility
from superbrain.cli_api._loopback_wire import encode_call
from superbrain.cli_api.loopback import LoopbackTransportError
from superbrain.composition.client_entry import build_tool_caller
from superbrain.composition.daemon_entry import DaemonTestHooks
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    FieldLineage,
    LineageRef,
    ObjectRef,
    OwnerReply,
    RepoPolicy,
    Scope,
    ToolCommand,
    WorkspaceBinding,
    field_path_digest,
)
from superbrain.mcp.stdio import run_stdio
from superbrain.storage.runtime import Runtime
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    encode_stdio_frames,
    get_shared_t7_transport_template,
    mcp_call_frame,
    mcp_init_frames,
)
from tests.support.inc2_fixture import InstalledEnv
from tests.support.inc2_t8_domain import (
    ART_ALLOWED,
    ART_REDACTABLE,
    ART_UNKNOWN,
    L1_CONTENT,
    L1_NAME,
    REF_CONTENT,
    REF_NAME,
    GatedObserver,
)
from tests.support.inc2_t8_harness import (
    SendAttemptTracker,
    clone_template_root,
    count,
    fixture_daemon,
    shim_profile,
    store_rows,
)
from tests.support.inc2_transport import TransportHarness, TransportTemplate, read_raw_http_response
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)

BARRIER_S = 5.0
L1_DIGEST = digest_bytes(L1_CONTENT + ART_ALLOWED.encode())
REF_DIGEST = digest_bytes(REF_CONTENT + ART_ALLOWED.encode())
SERVED_DIGESTS: list[JsonValue] = [
    {"name": L1_NAME, "digest": L1_DIGEST},
    {"name": REF_NAME, "digest": REF_DIGEST},
]
"""Every resource ``get_artifact`` serves for ``ART_ALLOWED`` at L1, in canonical (name) order."""


@pytest.fixture
def tpl() -> TransportTemplate:
    template = get_shared_t7_transport_template()
    assert template.ws_a is not None and template.ws_b is not None and template.cred_b is not None
    return template


def ws_a(template: TransportTemplate) -> WorkspaceBinding:
    assert template.ws_a is not None
    return template.ws_a


def scope_of(binding: WorkspaceBinding) -> Scope:
    return Scope(binding.repo_id, binding.checkout_id)


def call(
    h: TransportHarness,
    tool: str,
    args: dict[str, JsonValue],
    *,
    token: str,
    scope: Scope | None,
) -> dict[str, Any]:
    cmd = ToolCommand(tool, args, token=token, selected_scope=scope)
    return dict(h.open_client().call(h.make_target(), cmd))


def prepare_args(key: str, *, hint: str = "ws-a", task_id: str | None = None) -> dict[str, JsonValue]:
    args: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_hint": hint,
        "description": f"t8.2 {key}",
        "context_budget_tokens": 4000,
        "idempotency_key": key,
    }
    if task_id is not None:
        args["task_id"] = task_id
    return args


def artifact_args(template: TransportTemplate, task_id: str, key: str) -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "workspace_id": ws_a(template).repo_id,
        "task_id": task_id,
        "artifact_id": ART_ALLOWED,
        "revision": 1,
        "level": "L1",
        "idempotency_key": key,
    }


def outcome_args(
    template: TransportTemplate, delivery_id: str, key: str, acks: list[dict[str, Any]]
) -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "workspace_id": ws_a(template).repo_id,
        "delivery_id": delivery_id,
        "outcome": "success",
        "read_acks": cast(list[JsonValue], acks),
        "idempotency_key": key,
    }


def ack(receipt_id: str, task_id: str, *, revision: int = 1, digests: list[JsonValue] | None = None) -> dict[str, Any]:
    return {
        "served_receipt_id": receipt_id,
        "task_id": task_id,
        "revision": revision,
        "resource_digests": digests if digests is not None else list(SERVED_DIGESTS),
    }


def ok(result: dict[str, Any]) -> dict[str, Any]:
    assert result.get("ok") is True, result
    data = result["data"]
    assert isinstance(data, dict)
    return data


def code(result: dict[str, Any]) -> str:
    assert result.get("ok") is False and isinstance(result.get("error"), dict), result
    return str(result["error"]["code"])


def settle(h: TransportHarness) -> None:
    """Every owner action queued so far has run (an owner-thread barrier)."""
    h.loop.run_owner_action(lambda: None).result(timeout=BARRIER_S)


def attempts(data_root: Path) -> list[tuple[Any, ...]]:
    return store_rows(data_root, "SELECT id, logical_result_id, state FROM artifact_send_attempt ORDER BY rowid")


def state_of(data_root: Path, attempt_id: str) -> str | None:
    rows = store_rows(data_root, "SELECT state FROM artifact_send_attempt WHERE id = ?", (attempt_id,))
    return str(rows[0][0]) if rows else None


def settled_state(tracker: SendAttemptTracker, data_root: Path, attempt_id: str) -> str | None:
    """The attempt's durable state once the daemon settled it (finalize or interrupt completed on the owner)."""
    tracker.wait_settled(attempt_id, timeout=BARRIER_S)
    return state_of(data_root, attempt_id)


def attempt_binding(data_root: Path, attempt_id: str) -> tuple[Any, ...]:
    (row,) = store_rows(
        data_root,
        "SELECT logical_result_id, principal_id, task_id, artifact_id, revision, digests_json "
        "FROM artifact_send_attempt WHERE id = ?",
        (attempt_id,),
    )
    return row


def digest_pairs(digests_json: object) -> list[tuple[str, str]]:
    decoded = json.loads(str(digests_json))
    assert isinstance(decoded, list), decoded
    pairs: list[tuple[str, str]] = []
    for item in decoded:
        if isinstance(item, dict):
            pairs.append((str(item["name"]), str(item["digest"])))
        else:
            name, digest = item
            pairs.append((str(name), str(digest)))
    return pairs


EXPECTED_PAIRS = [(L1_NAME, L1_DIGEST), (REF_NAME, REF_DIGEST)]


@pytest.fixture
def root(trusted_tmp: Path, tpl: TransportTemplate) -> Path:
    return clone_template_root(tpl, trusted_tmp / "data")


def intercept_sends(h: TransportHarness, on_send: Callable[[bytes, Callable[[bytes], int]], int | None]) -> list[bytes]:
    """Wrap every accepted TLS socket's ``send``; ``on_send(data, real_send)`` may take over a write. Returns the list
    of bytes the daemon wrote through the real ``send``."""
    written: list[bytes] = []
    orig_wrap = h.bound.ssl_context.wrap_socket

    def wrap(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
        ssl_sock = orig_wrap(sock, **kwargs)
        real = ssl_sock.send

        def send(data: bytes | memoryview, flags: int = 0) -> int:
            raw = bytes(data)

            def real_send(chunk: bytes) -> int:
                sent = real(chunk, flags)
                written.append(chunk[:sent])
                return sent

            taken = on_send(raw, real_send)
            return taken if taken is not None else real_send(raw)

        ssl_sock.send = send  # type: ignore[method-assign,assignment]
        return ssl_sock

    h.bound.ssl_context.wrap_socket = wrap  # type: ignore[method-assign,assignment]
    return written


def record_sends_by_connection() -> tuple[
    Callable[[bytes, Callable[[bytes], int]], int], Callable[[bytes], list[int]]
]:
    """An ``intercept_sends`` hook that timestamps every send per server connection thread, and a reader.

    ``frames_done(marker)`` returns, for each complete HTTP response frame whose body contains ``marker``, the perf
    counter ns at which its last byte was accepted. The server records a send only after ``send()`` returns, so a
    client can hold the reply before the record exists: callers wait (bounded) for the frame instead of reading
    "the last send", which may be an earlier one.
    """
    sends: dict[threading.Thread, list[tuple[int, bytes]]] = {}
    lock = threading.Lock()

    def record(raw: bytes, real: Callable[[bytes], int]) -> int:
        count = real(raw)
        done = time.perf_counter_ns()
        with lock:
            sends.setdefault(threading.current_thread(), []).append((done, raw[:count]))
        return count

    def frames_done(marker: bytes) -> list[int]:
        with lock:
            conns = [list(chunks) for chunks in sends.values()]
        found: list[int] = []
        for chunks in conns:
            stream = b"".join(chunk for _ns, chunk in chunks)
            ends: list[int] = []
            total = 0
            for _ns, chunk in chunks:
                total += len(chunk)
                ends.append(total)
            pos = 0
            while (head_end := stream.find(b"\r\n\r\n", pos)) >= 0:
                head = stream[pos:head_end]
                length = next(
                    (int(v) for k, _, v in (ln.partition(b":") for ln in head.split(b"\r\n"))
                     if k.strip().lower() == b"content-length"),
                    None,
                )
                assert length is not None, "response frame without Content-Length"
                frame_end = head_end + 4 + length
                if frame_end > len(stream):
                    break  # incomplete: its last send has not been recorded (yet)
                if marker in stream[head_end + 4:frame_end]:
                    found.append(next(ns for (ns, _c), end in zip(chunks, ends, strict=True) if end >= frame_end))
                pos = frame_end
        return found

    return record, frames_done


def wait_for_frames(frames_done: Callable[[bytes], list[int]], marker: bytes, timeout: float) -> list[int]:
    """Poll ``frames_done(marker)`` until it reports a frame or ``timeout`` seconds pass; returns the last result."""
    deadline = time.monotonic() + timeout
    while not (found := frames_done(marker)) and time.monotonic() < deadline:
        time.sleep(0.005)
    return found


def replies_done(h: TransportHarness) -> Callable[[int], None]:
    """Count owner replies; the returned ``wait(n)`` blocks until ``n`` replies completed (an owner barrier)."""
    cond = threading.Condition()
    done = [0]
    inner = h.loop.submit_reply

    def submit(command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
        fut = inner(command, deadline_ns)

        def bump(_f: Future[OwnerReply]) -> None:
            with cond:
                done[0] += 1
                cond.notify_all()

        fut.add_done_callback(bump)
        return fut

    h.loop.submit_reply = submit  # type: ignore[method-assign]

    def wait(n: int) -> None:
        with cond:
            assert cond.wait_for(lambda: done[0] >= n, timeout=BARRIER_S), f"only {done[0]} of {n} replies completed"

    return wait


# --- commit cutoff and transport uncertainty -----------------------------------------------------------------------


def test_writable_shim_observes_commit_unknown_before_release(
    monkeypatch: pytest.MonkeyPatch, inc2_installed_env: InstalledEnv, tpl: TransportTemplate, root: Path
) -> None:
    """Owner held inside the commit transaction past the 1,475 ms cutoff: the daemon flushes a complete HTTP
    ``commit_outcome_unknown`` (on its own clock within 1,500 ms of receipt) and the installed shim's error frame
    reaches the parent within 1,500 ms, while the barrier is still closed. A retry with the same key is
    ``in_progress``; after release one result and assignment exist and the retry replays them.

    Receipt (``t0``), socket writes, and the parent's observation of the installed shim's frame all use the same
    process's real perf counter. The shim subprocess supplies no timestamps."""
    received: list[int] = []
    hooks = DaemonTestHooks(after_reserve_before_enqueue=lambda r: received.append(r.deadlines.receive_ns))
    entered, release = threading.Event(), threading.Event()
    daemon_clock = SystemMonotonicClock()
    with fixture_daemon(monkeypatch, tpl, root, hooks=hooks, daemon_clock=daemon_clock) as (h, proxy, _tracker):

        def hold(_tx: object) -> None:
            entered.set()
            assert release.wait(timeout=BARRIER_S), "the test never released the commit barrier"

        proxy.inner.before_apply_hook = hold
        record, frames_done = record_sends_by_connection()
        intercept_sends(h, record)
        key = "idem-t8-commit-unknown-0001"
        frame = mcp_call_frame(
            2, "prepare_task", {"schema_version": "2.0", "description": "t8", "idempotency_key": key}
        )
        profile = shim_profile(h, ws_a(tpl), "writable", tpl.cred.token)
        init, initialized = mcp_init_frames(1)
        cwd = Path(ws_a(tpl).checkout_path)
        with InstalledMcpPipeSession(inc2_installed_env, "brain-mcp", ("--profile", str(profile)), cwd=cwd) as shim:
            assert shim.send_frames_and_expect_response([init], timeout=10.0).get("id") == 1
            def read_first() -> tuple[int, dict[str, JsonValue]]:
                reply = shim.send_frames_and_expect_response([initialized, frame], timeout=BARRIER_S)
                return time.perf_counter_ns(), reply

            with ThreadPoolExecutor(max_workers=1) as worker:
                reply_future = worker.submit(read_first)
                try:
                    assert entered.wait(timeout=BARRIER_S), "the owner never entered the commit transaction"
                    (t0,) = received
                    arrived_ns, first = reply_future.result(timeout=BARRIER_S)
                    arrival_ms = (arrived_ns - t0) / 1_000_000
                    assert 1475 <= arrival_ms <= 1500, f"shim error frame arrived at t0 + {arrival_ms:.3f} ms"
                    assert not release.is_set() and count(root, "p_fixture_domain_deliveries") == 0
                    assert count(root, "idempotency") == 0, "the held commit is already visible"
                    result = cast(dict[str, Any], first["result"])
                    sc = result["structuredContent"]
                    assert result["isError"] is True and sc["error"]["code"] == ErrorCode.COMMIT_OUTCOME_UNKNOWN.value
                    # Only a complete frame counts; the wait covers the server recording its send after the
                    # client already holds the reply.
                    flushed = wait_for_frames(frames_done, b"commit_outcome_unknown", BARRIER_S)
                    assert len(flushed) == 1, "the daemon did not flush the complete commit_outcome_unknown body"
                    flush_ms = (flushed[0] - t0) / 1_000_000
                    assert 1475 <= flush_ms <= 1500, f"daemon finished flushing at t0 + {flush_ms:.3f} ms"
                    again = shim.send_frames_and_expect_response([frame | {"id": 3}], timeout=BARRIER_S)
                    again_sc = cast(dict[str, Any], again["result"])["structuredContent"]
                    assert again_sc["error"]["code"] == ErrorCode.IN_PROGRESS.value, again
                    assert not release.is_set(), "in_progress must be observed while the commit is still held"
                finally:
                    release.set()
            settle(h)
            done = shim.send_frames_and_expect_response([frame | {"id": 4}], timeout=10.0)
            shim.finish()
        data = cast(dict[str, Any], done["result"])["structuredContent"]["data"]
        ((delivery_id, assignment_id),) = store_rows(
            root, "SELECT delivery_id, assignment_id FROM p_fixture_domain_deliveries"
        )
        assert (data["delivery_id"], data["assignment_id"]) == (delivery_id, assignment_id)
        assert proxy.inner.apply_calls == 1 and count(root, "idempotency") == 1


def test_commit_cutoff_is_single_terminal_transition(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """Fake clock 1 ns before, at and 1 ns after the handler deadline (receipt + 1,300 ms) when the owner asks to
    enter COMMITTING. Before: it commits once (one terminal success) and the retry replays it. At/after: exactly one
    terminal ``deadline_exceeded`` with no row of any kind and no apply, and the explicit retry with the same key
    commits exactly once."""
    offsets = {"idem-t8-cutoff-before-01": -1, "idem-t8-cutoff-at-0000001": 0, "idem-t8-cutoff-after-001": 1}
    pending = dict(offsets)
    current: list[str] = []

    def at_boundary(reservation: Any) -> None:
        if reservation is not None and current and current[0] in pending:
            h.mono_clock.set(reservation.deadlines.handler_deadline_ns + pending.pop(current[0]))

    hooks = DaemonTestHooks(before_enter_commit=at_boundary)
    with fixture_daemon(monkeypatch, tpl, root, hooks=hooks) as (h, proxy, _tracker):
        scope = scope_of(ws_a(tpl))
        for key, offset in offsets.items():
            current[:] = [key]
            before = (count(root, "p_fixture_domain_deliveries"), count(root, "idempotency"), proxy.inner.apply_calls)
            first = call(h, "prepare_task", prepare_args(key), token=tpl.cred.token, scope=scope)
            after_first = (
                count(root, "p_fixture_domain_deliveries"),
                count(root, "idempotency"),
                proxy.inner.apply_calls,
            )
            assert key not in pending, f"{key}: the boundary hook never ran"
            retry = ok(call(h, "prepare_task", prepare_args(key), token=tpl.cred.token, scope=scope))
            if offset < 0:
                data = ok(first)
                assert after_first == (before[0] + 1, before[1] + 1, before[2] + 1)
                assert retry["delivery_id"] == data["delivery_id"], "the retry did not replay the commit"
            else:
                assert code(first) == ErrorCode.DEADLINE_EXCEEDED.value, (key, first)
                assert after_first == before, f"{key}: a refused commit left rows or applied"
            assert (
                count(root, "p_fixture_domain_deliveries"),
                count(root, "idempotency"),
                proxy.inner.apply_calls,
            ) == (before[0] + 1, before[1] + 1, before[2] + 1), f"{key}: not exactly one effect"


def test_blocked_peer_reports_transport_uncertainty(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """(a) A peer that stops writing mid-request and never reads gets EOF (no frame: an unknown result) and nothing
    commits. (b) A peer that writes the whole request but never reads may have caused a commit it cannot see. (c) The
    real client whose response is lost after the full request reports ``request_may_have_run``, while a real error
    is a parsed error frame (no exception, nothing ran). Every case retries with the same key explicitly and ends with
    exactly one effect."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, proxy, _tracker):
        scope = scope_of(ws_a(tpl))
        host = f"127.0.0.1:{h.ready.endpoint.port}"
        replies = replies_done(h)

        def request(key: str) -> tuple[bytes, bytes]:
            body = encode_call(
                ToolCommand("prepare_task", prepare_args(key), token=tpl.cred.token, selected_scope=scope)
            )
            head = (
                f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {tpl.cred.token}\r\n"
                f"X-Store-Id: {h.ready.endpoint.store_id}\r\nX-Writer-Epoch: {h.ready.endpoint.writer_epoch}\r\n"
                f"X-Superbrain-Instance: {h.ready.endpoint.instance_id}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("iso-8859-1")
            return head, body

        def identity(sock: ssl.SSLSocket) -> None:
            h.send_raw_http(sock, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))

        # (a) the peer stalls mid-body and reads nothing until the daemon gives up on it
        stalled_key = "idem-t8-blocked-stall-01"
        head, body = request(stalled_key)
        with h.open_raw_tls_socket() as sock:
            identity(sock)
            sock.sendall(head + body[:10])
            h.mono_clock.advance_ms(1600)
            seen = read_raw_http_response(sock, timeout=2.0)
        assert b"HTTP/1.1" not in seen, f"a stalled peer must see no frame (unknown), got {seen[:80]!r}"
        assert count(root, "p_fixture_domain_deliveries") == 0 and proxy.inner.apply_calls == 0
        assert h.submit_count == 0, "a partial request reached the owner"
        assert ok(call(h, "prepare_task", prepare_args(stalled_key), token=tpl.cred.token, scope=scope))
        assert count(root, "p_fixture_domain_deliveries") == 1
        replies(1)

        # (b) the whole request is written, the peer never reads and goes away: the result is unknown to it
        blind_key = "idem-t8-blocked-blind-01"
        head, body = request(blind_key)
        with h.open_raw_tls_socket() as sock:
            identity(sock)
            sock.sendall(head + body)
            replies(2)  # the owner finished the blind request while the peer read nothing
        committed = count(root, "p_fixture_domain_deliveries")
        retried = ok(call(h, "prepare_task", prepare_args(blind_key), token=tpl.cred.token, scope=scope))
        assert count(root, "p_fixture_domain_deliveries") == committed == 2, "the blind request must apply once"
        assert store_rows(
            root, "SELECT 1 FROM p_fixture_domain_deliveries WHERE delivery_id = ?", (retried["delivery_id"],)
        )

        # (c) the real client: the response to a fully sent request never arrives -> uncertain, not an error frame
        lost_key = "idem-t8-blocked-lost-001"
        dropped = [False]

        def drop(raw: bytes, real: Callable[[bytes], int]) -> int | None:
            if not dropped[0] and b"delivery_id" in raw:
                dropped[0] = True
                raise BrokenPipeError("the peer stopped reading")
            return None

        intercept_sends(h, drop)
        with pytest.raises(LoopbackTransportError) as lost:
            call(h, "prepare_task", prepare_args(lost_key), token=tpl.cred.token, scope=scope)
        assert dropped[0] and lost.value.request_may_have_run is True, "a lost response must be reported uncertain"
        assert count(root, "p_fixture_domain_deliveries") == 3, "the lost-response request committed"
        replay = ok(call(h, "prepare_task", prepare_args(lost_key), token=tpl.cred.token, scope=scope))
        assert count(root, "p_fixture_domain_deliveries") == 3 and proxy.inner.apply_calls == 3
        assert store_rows(
            root, "SELECT 1 FROM p_fixture_domain_deliveries WHERE delivery_id = ?", (replay["delivery_id"],)
        )

        # a real error is a frame, not an unknown result
        bad = call(
            h, "prepare_task", prepare_args("idem-t8-blocked-bad-001", hint="ws-b"), token=tpl.cred.token, scope=scope
        )
        assert code(bad) == ErrorCode.NOT_FOUND.value
        assert count(root, "p_fixture_domain_deliveries") == 3 and proxy.inner.apply_calls == 3


# --- get_artifact send attempts and ReadAcks -----------------------------------------------------------------------


def _task(h: TransportHarness, template: TransportTemplate, key: str) -> tuple[str, str]:
    data = ok(call(h, "prepare_task", prepare_args(key), token=template.cred.token, scope=scope_of(ws_a(template))))
    return str(data["task_id"]), str(data["delivery_id"])


def test_partial_flush_is_unknown_and_retry_mints_a_new_attempt_for_the_same_result(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """The daemon's socket accepts only 24 bytes of the artifact response (a short write) and then breaks: the HTTP
    bytes are missing, so the attempt is ``unknown`` (never ``served_only``). A retry with the same key mints a new
    attempt ID for the same logical result, fully flushed -> ``served_only`` bound to principal, task,
    artifact/revision and every served digest. No ReadAck appears on its own."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, _proxy, tracker):
        task_id, _ = _task(h, tpl, "idem-t8-partial-prep-001")
        phase = ["armed"]

        def partial(raw: bytes, real: Callable[[bytes], int]) -> int | None:
            if phase[0] == "armed" and b"served_receipt_id" in raw:
                phase[0] = "short"
                return real(raw[:24])  # a short write: the rest of the response is still unsent
            if phase[0] == "short":
                phase[0] = "broken"
                raise BrokenPipeError("peer went away mid-response")
            return None

        intercept_sends(h, partial)
        args = artifact_args(tpl, task_id, "idem-t8-partial-art-0001")
        with pytest.raises(LoopbackTransportError) as lost:
            call(h, "get_artifact", args, token=tpl.cred.token, scope=scope_of(ws_a(tpl)))
        assert lost.value.request_may_have_run is True
        assert phase[0] == "broken", "the short write was never followed by the rest of the response"
        ((first_id, logical, _state),) = attempts(root)
        assert settled_state(tracker, root, str(first_id)) == "unknown", "missing HTTP bytes were finalized"
        data = ok(call(h, "get_artifact", args, token=tpl.cred.token, scope=scope_of(ws_a(tpl))))
        new_id = str(data["served_receipt_id"])
        assert settled_state(tracker, root, new_id) == "served_only"
        rows = {str(i): (str(lr), str(s)) for i, lr, s in attempts(root)}
        assert new_id != first_id and rows == {first_id: (logical, "unknown"), new_id: (logical, "served_only")}
        lr, principal, task, artifact, revision, digests = attempt_binding(root, new_id)
        assert (lr, principal, task, artifact, revision) == (
            logical,
            tpl.cred.principal.principal_id,
            task_id,
            ART_ALLOWED,
            1,
        )
        assert digest_pairs(digests) == EXPECTED_PAIRS
        assert count(root, "artifact_read_ack") == 0


class _BrokenStdout(io.RawIOBase):
    """Accepts the ``initialize`` answer, then fails every write that carries a served artifact."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.failed = 0

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        raw = bytes(data)
        if b"served_receipt_id" in raw:
            self.failed += 1
            raise BrokenPipeError("host stdout is gone")
        self.frames.append(raw)
        return len(raw)


def test_complete_http_with_broken_stdout_stays_served_only(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """The daemon flushes the full HTTP response, the shim cannot write it to its host: the attempt becomes
    ``served_only`` (the daemon saw a full flush) and no ReadAck appears without an explicit ``record_outcome``.
    Positive twin: that explicit ``record_outcome`` then records exactly one ReadAck for the attempt."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, _proxy, tracker):
        task_id, delivery_id = _task(h, tpl, "idem-t8-stdout-prep-0001")
        record, frames_done = record_sends_by_connection()
        intercept_sends(h, record)
        profile = shim_profile(h, ws_a(tpl), "stdout", tpl.cred.token)
        caller = build_tool_caller(profile, Path(ws_a(tpl).checkout_path), os_adapters())
        init, initialized = mcp_init_frames(1)
        args = artifact_args(tpl, task_id, "idem-t8-stdout-art-00001")
        stdin = io.BytesIO(encode_stdio_frames([init, initialized, mcp_call_frame(2, "get_artifact", args)]))
        stdout = _BrokenStdout()
        run_stdio(stdin, stdout, caller)  # type: ignore[arg-type]
        assert stdout.failed >= 1, "the shim never tried to write the artifact to its host"
        # Bounded wait: the server records its send only after send() returns, possibly after the shim read it.
        assert wait_for_frames(frames_done, b"served_receipt_id", BARRIER_S), "the daemon never flushed the artifact"
        ((attempt_id, _lr, _state),) = attempts(root)
        assert settled_state(tracker, root, str(attempt_id)) == "served_only"
        settle(h)
        assert count(root, "artifact_read_ack") == 0, "a served artifact produced an automatic ReadAck"
        recorded = call(
            h,
            "record_outcome",
            outcome_args(tpl, delivery_id, "idem-t8-stdout-ack-00001", [ack(str(attempt_id), task_id)]),
            token=tpl.cred.token,
            scope=scope_of(ws_a(tpl)),
        )
        assert ok(recorded)
        assert store_rows(root, "SELECT served_receipt_id FROM artifact_read_ack") == [(attempt_id,)]


def test_read_ack_while_pending_is_in_progress_and_restart_turns_orphan_pending_unknown(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """While the daemon has not settled the attempt (``pending``) a ReadAck is ``in_progress`` and writes nothing.
    The daemon stops with the attempt still ``pending`` on disk; the next daemon on the same root turns that orphan
    into ``unknown`` at startup, so the old receipt can never be acknowledged. Positive twin: a retry with the same
    key mints a new attempt for the same logical result, and its explicit ReadAck is recorded."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, _proxy, _tracker):
        task_id, delivery_id = _task(h, tpl, "idem-t8-pending-prep-001")
        held: list[Any] = []
        finalizer_entered = threading.Event()

        def never_finalize(completion: Any) -> Future[Any]:
            held.append(completion)
            finalizer_entered.set()
            return Future()

        h.loop.finalize_send_attempt = never_finalize  # type: ignore[method-assign]
        art = artifact_args(tpl, task_id, "idem-t8-pending-art-0001")
        data = ok(call(h, "get_artifact", art, token=tpl.cred.token, scope=scope_of(ws_a(tpl))))
        receipt = str(data["served_receipt_id"])
        # Receiving the full frame can precede the server's post-send finalizer call.
        assert finalizer_entered.wait(BARRIER_S), "the send attempt never reached the held finalizer"
        ((first_id, logical, state),) = attempts(root)
        assert held and (first_id, state) == (receipt, "pending")
        pend = call(
            h,
            "record_outcome",
            outcome_args(tpl, delivery_id, "idem-t8-pending-ack-0001", [ack(receipt, task_id)]),
            token=tpl.cred.token,
            scope=scope_of(ws_a(tpl)),
        )
        assert code(pend) == ErrorCode.IN_PROGRESS.value and count(root, "artifact_read_ack") == 0
        settle(h)
    assert state_of(root, receipt) == "pending", "the stopped daemon must leave the orphan for startup recovery"
    with fixture_daemon(monkeypatch, tpl, root) as (h2, _proxy2, tracker2):
        assert state_of(root, receipt) == "unknown", "startup did not turn the orphan pending attempt unknown"
        late = call(
            h2,
            "record_outcome",
            outcome_args(tpl, delivery_id, "idem-t8-pending-ack-0002", [ack(receipt, task_id)]),
            token=tpl.cred.token,
            scope=scope_of(ws_a(tpl)),
        )
        assert code(late) == ErrorCode.NOT_FOUND.value and count(root, "artifact_read_ack") == 0
        again = ok(call(h2, "get_artifact", art, token=tpl.cred.token, scope=scope_of(ws_a(tpl))))
        new_id = str(again["served_receipt_id"])
        assert new_id != receipt and settled_state(tracker2, root, new_id) == "served_only"
        assert attempt_binding(root, new_id)[0] == logical, "the retry is not the same logical result"
        assert ok(
            call(
                h2,
                "record_outcome",
                outcome_args(tpl, delivery_id, "idem-t8-pending-ack-0003", [ack(new_id, task_id)]),
                token=tpl.cred.token,
                scope=scope_of(ws_a(tpl)),
            )
        )
        assert store_rows(root, "SELECT served_receipt_id FROM artifact_read_ack") == [(new_id,)]


def test_explicit_read_ack_matches_the_served_attempt_and_refuses_mismatches(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """The positive twin: one ReadAck for the served attempt with every digest; a valid duplicate keeps the same
    ReadAck ID. Missing/partial/wrong digest, wrong revision, another task, another principal (subject) and a revoked
    credential are refused and write nothing."""
    other: list[SeededCredential] = []

    def second_principal(rt: Runtime) -> None:
        if other:
            return
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex-t8", machine_id="m-1")
        seed_repo_grant(rt.policy, principal_id=cred.principal.principal_id, repo_id=ws_a(tpl).repo_id, owner_id="dan")
        other.append(cred)

    hooks = DaemonTestHooks(before_job_recover=second_principal)
    with fixture_daemon(monkeypatch, tpl, root, hooks=hooks) as (h, _proxy, tracker):
        scope = scope_of(ws_a(tpl))
        task_id, delivery_id = _task(h, tpl, "idem-t8-ack-prep-000001")
        other_task, _ = _task(h, tpl, "idem-t8-ack-prep-000002")
        receipt = str(
            ok(
                call(
                    h,
                    "get_artifact",
                    artifact_args(tpl, task_id, "idem-t8-ack-art-0000001"),
                    token=tpl.cred.token,
                    scope=scope,
                )
            )["served_receipt_id"]
        )
        assert settled_state(tracker, root, receipt) == "served_only"
        seq = iter(range(100))

        def record(acks: list[dict[str, Any]], token: str = tpl.cred.token) -> dict[str, Any]:
            key = f"idem-t8-ack-out-{next(seq):08d}"
            return call(h, "record_outcome", outcome_args(tpl, delivery_id, key, acks), token=token, scope=scope)

        l1_only: list[JsonValue] = [{"name": L1_NAME, "digest": L1_DIGEST}]
        wrong: list[JsonValue] = [{"name": L1_NAME, "digest": digest_bytes(b"x")}, SERVED_DIGESTS[1]]
        renamed: list[JsonValue] = [{"name": "other.md", "digest": L1_DIGEST}, SERVED_DIGESTS[1]]
        refused = {
            "missing-digest": (record([ack(receipt, task_id, digests=[])]), ErrorCode.INVALID_INPUT),
            "partial-digest": (record([ack(receipt, task_id, digests=l1_only)]), ErrorCode.INVALID_INPUT),
            "other-name": (record([ack(receipt, task_id, digests=renamed)]), ErrorCode.INVALID_INPUT),
            "wrong-digest": (record([ack(receipt, task_id, digests=wrong)]), ErrorCode.INVALID_INPUT),
            "wrong-revision": (record([ack(receipt, task_id, revision=2)]), ErrorCode.INVALID_INPUT),
            "other-task": (record([ack(receipt, other_task)]), ErrorCode.NOT_FOUND),
            "other-principal": (record([ack(receipt, task_id)], token=other[0].token), ErrorCode.NOT_FOUND),
        }
        for name, (result, expected) in refused.items():
            assert code(result) == expected.value, (name, result)
        assert count(root, "artifact_read_ack") == 0

        assert ok(record([ack(receipt, task_id)]))
        cols = "id, served_receipt_id, principal_id, task_id, revision, digests_json"
        first = store_rows(root, f"SELECT {cols} FROM artifact_read_ack")
        assert len(first) == 1 and first[0][1:5] == (receipt, tpl.cred.principal.principal_id, task_id, 1)
        assert digest_pairs(first[0][5]) == EXPECTED_PAIRS
        assert ok(record([ack(receipt, task_id)]))
        assert store_rows(root, f"SELECT {cols} FROM artifact_read_ack") == first, "a duplicate changed the ReadAck"

        cred_b = tpl.cred_b
        assert cred_b is not None
        auth = make_bootstrap_auth(
            store_id=tpl.store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=cred_b.credential_id,
            trust_generation=1,
            expires_at=h.clock.now() + dt.timedelta(hours=1),
        )
        h.loop.revoke_credential(cred_b.credential_id, auth).result(timeout=BARRIER_S)
        assert code(record([ack(receipt, task_id)], token=cred_b.token)) == ErrorCode.UNAUTHENTICATED.value
        assert store_rows(root, f"SELECT {cols} FROM artifact_read_ack") == first


def test_fixture_receipts_have_no_native_authority(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """Receipts here come from the test fixture domain and its fixture observer (``source="fixture"``); nothing
    records or accepts a native or verified claim: the ReadAck row has no such column, the contract refuses
    self-declared fields on a ReadAck, on ``record_outcome`` and inside episode evidence, and the result of the
    accepted twin is only ``declared``."""
    observer = GatedObserver()
    with fixture_daemon(monkeypatch, tpl, root, observer=observer) as (h, proxy, tracker):
        assert type(proxy.inner).__module__ == "tests.support.inc2_kernel_domain"
        assert proxy.inner.observer is observer and observer.source == "fixture"
        scope = scope_of(ws_a(tpl))
        task_id, delivery_id = _task(h, tpl, "idem-t8-native-prep-0001")
        assert observer.calls >= 1, "the fixture observer never answered"
        receipt = str(
            ok(
                call(
                    h,
                    "get_artifact",
                    artifact_args(tpl, task_id, "idem-t8-native-art-00001"),
                    token=tpl.cred.token,
                    scope=scope,
                )
            )["served_receipt_id"]
        )
        assert settled_state(tracker, root, receipt) == "served_only"
        columns = {row[1] for row in store_rows(root, "PRAGMA table_info(artifact_read_ack)")}
        assert columns == {"id", "served_receipt_id", "principal_id", "task_id", "revision", "digests_json"}
        extras: tuple[dict[str, Any], ...] = ({"native": True}, {"verified": True}, {"source": "native"})
        for i, extra in enumerate(extras):
            claimed = call(
                h,
                "record_outcome",
                outcome_args(tpl, delivery_id, f"idem-t8-native-out-{i:05d}", [ack(receipt, task_id) | extra]),
                token=tpl.cred.token,
                scope=scope,
            )
            assert code(claimed) == ErrorCode.INVALID_INPUT.value, (extra, claimed)
        top = outcome_args(tpl, delivery_id, "idem-t8-native-out-top01", [ack(receipt, task_id)]) | {"verified": True}
        assert code(call(h, "record_outcome", top, token=tpl.cred.token, scope=scope)) == ErrorCode.INVALID_INPUT.value

        def episode(j: int, data: dict[str, JsonValue]) -> dict[str, JsonValue]:
            return {
                "schema_version": "2.0",
                "task_id": task_id,
                "session_id": "sess-t8-native",
                "evidence": [{"kind": "note", "data": data}],
                "idempotency_key": f"idem-t8-native-ep-{j:05d}",
            }

        for j, forbidden in enumerate(("source", "native_receipt", "verification_status")):
            claimed_ep = call(
                h,
                "submit_episode",
                episode(j, {forbidden: "native", "summary": "t8"}),
                token=tpl.cred.token,
                scope=scope,
            )
            assert code(claimed_ep) == ErrorCode.INVALID_INPUT.value, (forbidden, claimed_ep)
        plain_ep = call(h, "submit_episode", episode(9, {"summary": "t8"}), token=tpl.cred.token, scope=scope)
        assert code(plain_ep) == ErrorCode.CAPABILITY_UNAVAILABLE.value, plain_ep
        assert count(root, "artifact_read_ack") == 0
        accepted = ok(
            call(
                h,
                "record_outcome",
                outcome_args(tpl, delivery_id, "idem-t8-native-out-ok001", [ack(receipt, task_id)]),
                token=tpl.cred.token,
                scope=scope,
            )
        )
        assert accepted.get("status") == "declared", accepted
        assert count(root, "artifact_read_ack") == 1


# --- S1=A: snapshot fallback -----------------------------------------------------------------------------------------


def _field_lineage(data_root: Path, task_id: str, path: tuple[str | int, ...]) -> FieldLineage:
    digest = field_path_digest(path)
    rows = store_rows(
        data_root,
        "SELECT owner_id, repo_id, source_kind, source_id, source_revision, source_digest "
        "FROM p_field_lineage_sources WHERE task_id = ? AND field_path_digest = ?",
        (task_id, digest),
    )
    unknown = bool(
        store_rows(
            data_root,
            "SELECT 1 FROM p_field_lineage_unknown WHERE task_id = ? AND field_path_digest = ?",
            (task_id, digest),
        )
    )
    sources = frozenset(LineageRef(o, r, ObjectRef(kind=k, id=i, revision=v, digest=d)) for o, r, k, i, v, d in rows)
    return FieldLineage(field_path_digest=digest, sources=sources, unknown_source=unknown)


def _binding_row(data_root: Path, task_id: str) -> tuple[Any, ...]:
    (row,) = store_rows(
        data_root,
        "SELECT delivery_id, assignment_id, source_snapshot_id, snapshot_status FROM p_task_lineage_bindings "
        "WHERE task_id = ?",
        (task_id,),
    )
    return row


def test_missing_snapshot_delivery_through_real_shim_is_labeled_and_preserves_lineage(
    monkeypatch: pytest.MonkeyPatch, inc2_installed_env: InstalledEnv, tpl: TransportTemplate, root: Path
) -> None:
    """Observer held past the 100 ms local budget: ``snapshot_id=null``, ``deadline``, a durable Delivery and
    assignment, the known repo source kept and the snapshot-dependent ``context``/``finishing_gates`` items dropped.
    No observer: ``unavailable``. Observer back: the old key replays its old status without observing again; a new
    key is ``available`` with the snapshot-dependent items."""
    observer = GatedObserver()
    with fixture_daemon(monkeypatch, tpl, root, observer=observer) as (h, proxy, _tracker):
        profile = shim_profile(h, ws_a(tpl), "s1", tpl.cred.token)
        init, initialized = mcp_init_frames(1)

        def frame(i: int, key: str) -> dict[str, JsonValue]:
            return mcp_call_frame(
                i, "prepare_task", {"schema_version": "2.0", "description": "t8 s1", "idempotency_key": key}
            )

        def data_of(resp: dict[str, JsonValue]) -> dict[str, Any]:
            result = cast(dict[str, Any], resp["result"])
            assert result["isError"] is False, result
            return cast(dict[str, Any], result["structuredContent"]["data"])

        cwd = Path(ws_a(tpl).checkout_path)
        with InstalledMcpPipeSession(inc2_installed_env, "brain-mcp", ("--profile", str(profile)), cwd=cwd) as shim:
            assert shim.send_frames_and_expect_response([init], timeout=10.0).get("id") == 1
            observer.mode = "hold"
            box: list[dict[str, JsonValue]] = []
            worker = threading.Thread(
                target=lambda: box.append(
                    shim.send_frames_and_expect_response(
                        [initialized, frame(2, "idem-t8-s1-deadline-01")], timeout=10.0
                    )
                )
            )
            worker.start()
            try:
                assert observer.entered.wait(timeout=BARRIER_S)
                h.mono_clock.advance_ms(150)  # the observer answers after the 100 ms local budget
            finally:
                observer.release.set()
                worker.join(timeout=BARRIER_S)
            late = data_of(box[0])
            proxy.inner.observer = None
            absent = data_of(shim.send_frames_and_expect_response([frame(3, "idem-t8-s1-absent-0001")], timeout=10.0))
            proxy.inner.observer = observer
            observer.mode = "available"
            calls = observer.calls
            replay = data_of(shim.send_frames_and_expect_response([frame(4, "idem-t8-s1-deadline-01")], timeout=10.0))
            assert observer.calls == calls, "the replay observed the workspace again"
            fresh = data_of(shim.send_frames_and_expect_response([frame(5, "idem-t8-s1-available-1")], timeout=10.0))
            assert observer.calls == calls + 1, "the new key did not observe"
            shim.finish()

        for data, status in ((late, "deadline"), (absent, "unavailable")):
            assert (data["snapshot_status"], data["source_snapshot_id"]) == (status, None), data
            assert data["degraded_codes"], data
            assert data["context"] == [], "a snapshot-dependent context item was delivered without a snapshot"
            assert data["finishing_gates"] == [], "a snapshot-dependent gate was delivered without a snapshot"
            assert {i["id"] for i in data["skills"]} == {ART_ALLOWED, ART_REDACTABLE}
            assert [i["id"] for i in data["lessons"]] == [ART_UNKNOWN]
            assert _binding_row(root, data["task_id"]) == (data["delivery_id"], data["assignment_id"], None, status)
            assert data["assignment_id"] is not None
            known = _field_lineage(root, data["task_id"], ("skills", 0))
            assert {s.repo_id for s in known.sources} == {ws_a(tpl).repo_id}
            assert not known.unknown_source, f"{status}: a known source was relabelled unknown"
            assert _field_lineage(root, data["task_id"], ("lessons", 0)).unknown_source is True
        assert {k: replay[k] for k in ("delivery_id", "assignment_id", "snapshot_status", "source_snapshot_id")} == {
            k: late[k] for k in ("delivery_id", "assignment_id", "snapshot_status", "source_snapshot_id")
        }
        assert fresh["snapshot_status"] == "available" and fresh["source_snapshot_id"] is not None
        assert [i["id"] for i in fresh["context"]] == [ART_ALLOWED] and fresh["degraded_codes"] == []
        assert [i["id"] for i in fresh["finishing_gates"]] == [ART_ALLOWED]
        assert _binding_row(root, fresh["task_id"])[2:] == (fresh["source_snapshot_id"], "available")


class _EgressPolicy:
    """The real policy snapshot with the ``ws-a`` repo's ``provider_egress`` forced on or off, or the repo removed."""

    def __init__(self, real_snapshot: Any, repo_id: str, mode: str) -> None:
        self._real, self._repo_id, self._mode = real_snapshot, repo_id, mode

    def snapshot(self) -> Any:
        snap = self._real
        policies = dict(snap.repo_policies)
        if self._mode == "missing":
            policies.pop(self._repo_id)
        else:
            policies[self._repo_id] = RepoPolicy(self._repo_id, policies[self._repo_id].owner_id, self._mode == "on")
        return replace(snap, repo_policies=policies)


class _NoRestriction:
    def is_restricted(self, ref: LineageRef) -> bool:
        return False


def _eligible(lineage: FieldLineage, policy: _EgressPolicy) -> bool:
    return bool(evaluate_egress_eligibility(lineage, cast(Any, policy), restrictions=cast(Any, _NoRestriction())))


def test_snapshot_status_alone_does_not_disable_egress_eligibility(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """Three deliveries (available / unavailable / deadline) under one fixed policy and lineage: the known-source
    field is eligible in all three; the genuinely unknown field, a repo with egress off and a missing repo never are."""
    observer = GatedObserver()
    with fixture_daemon(monkeypatch, tpl, root, observer=observer) as (h, proxy, _tracker):
        scope = scope_of(ws_a(tpl))
        tasks: dict[str, str] = {}
        tasks["available"] = ok(
            call(h, "prepare_task", prepare_args("idem-t8-egress-avail-01"), token=tpl.cred.token, scope=scope)
        )["task_id"]
        proxy.inner.observer = None
        tasks["unavailable"] = ok(
            call(h, "prepare_task", prepare_args("idem-t8-egress-absent-1"), token=tpl.cred.token, scope=scope)
        )["task_id"]
        proxy.inner.observer = observer
        observer.mode = "hold"
        box: list[dict[str, Any]] = []
        worker = threading.Thread(
            target=lambda: box.append(
                call(h, "prepare_task", prepare_args("idem-t8-egress-late-001"), token=tpl.cred.token, scope=scope)
            )
        )
        worker.start()
        try:
            assert observer.entered.wait(timeout=BARRIER_S)
            h.mono_clock.advance_ms(150)
        finally:
            observer.release.set()
            worker.join(timeout=BARRIER_S)
        tasks["deadline"] = ok(box[0])["task_id"]
        policy = h.loop.run_owner_action(lambda: proxy.inner.policy.snapshot()).result(timeout=BARRIER_S)
        repo = ws_a(tpl).repo_id
        on, off, gone = (_EgressPolicy(policy, repo, m) for m in ("on", "off", "missing"))
        lineages = {}
        for status, task_id in tasks.items():
            assert _binding_row(root, task_id)[3] == status
            known = _field_lineage(root, task_id, ("skills", 0))
            unknown = _field_lineage(root, task_id, ("lessons", 0))
            lineages[status] = (known.sources, known.unknown_source, unknown.sources, unknown.unknown_source)
            assert _eligible(known, on) is True, status
            assert _eligible(unknown, on) is False, status
            assert _eligible(known, off) is False, status
            assert _eligible(known, gone) is False, status
        assert lineages["available"] == lineages["unavailable"] == lineages["deadline"], "lineage moved with status"


def test_snapshot_fallback_does_not_override_scope_or_policy_error(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path
) -> None:
    """With no observer every delivery would be ``unavailable``; that fallback never turns a scope or policy error
    into a degraded success, neither fresh nor on replay. Positive twin: the same principal in its own scope gets the
    labelled ``unavailable`` success."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, _proxy, _tracker):
        scope = scope_of(ws_a(tpl))
        cred_b = tpl.cred_b
        assert cred_b is not None and tpl.ws_b is not None
        wrong_scope = call(
            h, "prepare_task", prepare_args("idem-t8-fallback-scope1", hint="ws-b"), token=tpl.cred.token, scope=scope
        )
        assert code(wrong_scope) == ErrorCode.NOT_FOUND.value
        assert count(root, "p_fixture_domain_deliveries") == 0
        stored = ok(call(h, "prepare_task", prepare_args("idem-t8-fallback-revoke"), token=cred_b.token, scope=scope))
        assert stored["snapshot_status"] == "unavailable"
        other_scope = call(
            h, "prepare_task", prepare_args("idem-t8-fallback-revoke"), token=cred_b.token, scope=scope_of(tpl.ws_b)
        )
        assert other_scope.get("ok") is False, "a replay from another scope was served"
        auth = make_bootstrap_auth(
            store_id=tpl.store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=cred_b.credential_id,
            trust_generation=1,
            expires_at=h.clock.now() + dt.timedelta(hours=1),
        )
        h.loop.revoke_credential(cred_b.credential_id, auth).result(timeout=BARRIER_S)
        replay = call(h, "prepare_task", prepare_args("idem-t8-fallback-revoke"), token=cred_b.token, scope=scope)
        assert code(replay) == ErrorCode.UNAUTHENTICATED.value
        fresh = call(h, "prepare_task", prepare_args("idem-t8-fallback-fresh1"), token=cred_b.token, scope=scope)
        assert code(fresh) == ErrorCode.UNAUTHENTICATED.value
        assert count(root, "p_fixture_domain_deliveries") == 1


def _lineage_tables(data_root: Path) -> dict[str, list[tuple[Any, ...]]]:
    return {
        t: sorted(store_rows(data_root, f"SELECT * FROM {t}"), key=repr)
        for t in (
            "p_field_lineage_sources",
            "p_field_lineage_unknown",
            "p_task_lineage_bindings",
            "p_task_lineage_sources",
            "p_task_lineage_unknown",
        )
    }


def test_snapshot_fallback_preserves_known_and_unknown_sources_through_rebuild(
    monkeypatch: pytest.MonkeyPatch, tpl: TransportTemplate, root: Path,
    request: pytest.FixtureRequest,
) -> None:
    """An ``unavailable`` delivery keeps, field by field, the known source and the unknown mark in the ledger
    events, in the projections, and identically after a projection rebuild."""
    with fixture_daemon(monkeypatch, tpl, root) as (h, proxy, _tracker):
        args = prepare_args("idem-t8-rebuild-prep-01")

        def prepare() -> dict[str, Any]:
            return call(h, "prepare_task", args, token=tpl.cred.token, scope=scope_of(ws_a(tpl)))

        first: dict[str, Any] | None
        try:
            first = prepare()
        except LoopbackTransportError as error:
            assert error.code is ErrorCode.DEADLINE_EXCEEDED and error.request_may_have_run
            request.node.user_properties.append(("initial_prepare_transport", error.code.value))
            first = None
        if first is None or (
            first.get("ok") is False
            and code(first) in {ErrorCode.COMMIT_OUTCOME_UNKNOWN.value, ErrorCode.DEADLINE_EXCEEDED.value}
        ):
            if first is not None:
                request.node.user_properties.append(("initial_prepare_error", code(first)))
            # D5: finish the original owner attempt, then replay the exact same
            # business key. Each attempt retains the original protocol budgets.
            settle(h)
            first = prepare()
        data = ok(first)
        assert data["snapshot_status"] == "unavailable"
        task_id = str(data["task_id"])
        events: dict[str, set[tuple[Any, ...]]] = {}
        for kind, meta in store_rows(root, "SELECT kind, meta FROM ledger WHERE kind LIKE 'lineage.field_%'"):
            m = json.loads(bytes(meta).decode("utf-8")) if isinstance(meta, (bytes, memoryview)) else json.loads(meta)
            if m.get("task_id") != task_id:
                continue
            entry = (kind, m.get("repo_id"), m.get("source_id")) if kind.endswith("source_added") else (kind,)
            events.setdefault(str(m["field_path_digest"]), set()).add(entry)
        known, lesson = field_path_digest(("skills", 0)), field_path_digest(("lessons", 0))
        assert ("lineage.field_source_added", ws_a(tpl).repo_id, ART_ALLOWED) in events[known]
        assert ("lineage.field_unknown_marked",) not in events[known], "the known field was marked unknown"
        assert ("lineage.field_unknown_marked",) in events[lesson]
        before = _lineage_tables(root)
        skills = _field_lineage(root, task_id, ("skills", 0))
        assert skills.sources and not skills.unknown_source
        assert _field_lineage(root, task_id, ("lessons", 0)).unknown_source
        h.loop.run_owner_action(lambda: proxy.inner.store.rebuild_projections()).result(timeout=BARRIER_S)
        assert _lineage_tables(root) == before, "a rebuild changed field or task lineage"
        assert _field_lineage(root, task_id, ("skills", 0)) == skills
        assert proxy.inner.apply_calls == 1
        assert count(root, "p_fixture_domain_deliveries") == 1
        assert count(root, "idempotency") == 1
