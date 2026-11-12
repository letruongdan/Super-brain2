"""T8-W01 change 2: the owner reuses the verified canonical request bytes for the request HMAC.

Requirement (C3:92, idempotency C4): the request digest is
``HMAC(key, b"request-v1\\0" + canonical_request_payload(call))`` whichever path committed it, and a later
call with the same content is recognized as a replay.

Plan for change 2: ``CallContext`` carries an optional ``canonical_payload`` (``None`` or non-empty ``bytes``,
refused otherwise; hidden from ``repr`` and ignored by equality). The owner sets it to the bytes it has just
verified, and dispatch computes the HMAC over them instead of serializing the call again.

(a) holds before and after change 2 (a regression guard); (b) and (c) pin change 2.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

import superbrain.core.wire as wire_mod
from superbrain.adapters.os import os_adapters
from superbrain.application._prequeue import reconstruct_queued_call
from superbrain.application.idempotency import (
    compute_canonical_payload_hmac,
    compute_idempotency_key_hash,
    compute_request_hmac,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    CallContext,
    Identity,
    Principal,
    PrivateRequestAuth,
)
from superbrain.core.wire import canonical_request_payload, normalize_call
from superbrain.ports.os import OsAdapters
from tests.application.test_kernel_deadlines import (
    CLOCK_START,
    DedicatedOwnerHarness,
    FakeMonotonicClock,
    _expect_err,
    _expect_ok,
)
from tests.support.clock import FakeClock

_ORIGINAL = wire_mod.canonical_request_payload


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(CLOCK_START)


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock)


@pytest.fixture
def harness(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> Iterator[DedicatedOwnerHarness]:
    h = DedicatedOwnerHarness(
        root_dir=trusted_tmp / "root", checkout_dir=trusted_tmp / "chk", os_=os_, clock=clock, mono=FakeMonotonicClock()
    )
    try:
        yield h
    finally:
        h.close()


def _args(key: str, description: str = "canonical reuse") -> dict[str, JsonValue]:
    return {"schema_version": "2.0", "workspace_hint": "ws-main", "description": description, "idempotency_key": key}


def _stored_digest(h: DedicatedOwnerHarness, key: str) -> str:
    key_hash = compute_idempotency_key_hash(h.seeded.principal.principal_id, "prepare_task", key)

    def read() -> str:
        with h.rt.store.transaction() as txn:
            row = txn.db.execute(
                "SELECT request_digest FROM idempotency WHERE principal_id = ? AND tool = ? AND key_hash = ?",
                (h.seeded.principal.principal_id, "prepare_task", key_hash),
            ).fetchone()
        assert row is not None, "no committed idempotency row"
        return str(row[0])

    return h.run_on_owner(read)


def _active_key(h: DedicatedOwnerHarness) -> bytes:
    return h.run_on_owner(lambda: h.rt.policy.request_digest_key()[1])


class _Spy:
    """Counts ``canonical_request_payload`` calls per thread through every module binding of the function."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[int] = []
        self._lock = threading.Lock()

        def spy(call: object) -> bytes:
            with self._lock:
                self.calls.append(threading.get_ident())
            return _ORIGINAL(call)  # type: ignore[arg-type]

        for name, module in list(sys.modules.items()):
            if name.startswith("superbrain") and getattr(module, "canonical_request_payload", None) is _ORIGINAL:
                monkeypatch.setattr(module, "canonical_request_payload", spy)

    def on(self, thread_id: int) -> int:
        with self._lock:
            return sum(1 for ident in self.calls if ident == thread_id)


def _submit(h: DedicatedOwnerHarness, args: dict[str, JsonValue]) -> object:
    sub = h.bridge.submit_request("prepare_task", dict(args), token=h.seeded.token, selected_scope=h.scope)
    h.wake_owner()
    return sub


# ------------------------------------------------------------------------------------------------------------------
# (a) the committed digest is the direct-path HMAC, and the replay is recognized
# ------------------------------------------------------------------------------------------------------------------


def test_w01_queued_owner_path_commits_the_direct_path_request_hmac(harness: DedicatedOwnerHarness) -> None:
    key = "idem_w01_canonical_reuse_a"
    sub = harness.bridge.submit_request(
        "prepare_task", _args(key), token=harness.seeded.token, selected_scope=harness.scope
    )
    assert sub.queued is not None
    harness.wake_owner()
    first = _expect_ok("prepare_task", sub.wait(timeout=5.0))
    call = reconstruct_queued_call(sub.queued)
    direct = compute_request_hmac(_active_key(harness), call)
    assert _stored_digest(harness, key) == direct == sub.queued.request_digest
    harness.run_on_owner(harness.bridge.publish_auth_view)
    replay = harness.bridge.submit_request(
        "prepare_task", _args(key), token=harness.seeded.token, selected_scope=harness.scope
    )
    harness.wake_owner()
    assert _expect_ok("prepare_task", replay.wait(timeout=5.0)) == first
    tampered = harness.bridge.submit_request(
        "prepare_task", _args(key, "other content"), token=harness.seeded.token, selected_scope=harness.scope
    )
    harness.wake_owner()
    _expect_err("prepare_task", tampered.wait(timeout=5.0), ErrorCode.IDEMPOTENCY_CONFLICT)


# ------------------------------------------------------------------------------------------------------------------
# (b) CallContext.canonical_payload
# ------------------------------------------------------------------------------------------------------------------

_PRINCIPAL = Principal(principal_id="p-w01", owner_id="o-w01", harness_id="h-w01", machine_id="m-w01")
_IDENTITY = Identity(store_id="store-w01", writer_epoch=1, instance_id="inst-w01")


def _ctx(**extra: object) -> CallContext:
    return CallContext(principal=_PRINCIPAL, identity=_IDENTITY, deadline_ns=10**12, selected_scope=None, **extra)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad",
    ["text", b"", bytearray(b"{}"), memoryview(b"{}"), 1, True],
    ids=["str", "empty-bytes", "bytearray", "memoryview", "int", "bool"],
)
def test_w01_call_context_refuses_a_canonical_payload_that_is_not_non_empty_bytes(bad: object) -> None:
    with pytest.raises(BrainError) as exc:
        _ctx(canonical_payload=bad)
    assert exc.value.code is ErrorCode.INVALID_INPUT


def test_w01_call_context_hides_the_canonical_payload_and_ignores_it_in_equality() -> None:
    secret = b'{"arguments":{"description":"w01-hidden-marker"}}'
    with_bytes = _ctx(canonical_payload=secret)
    assert with_bytes.canonical_payload == secret  # type: ignore[attr-defined]
    assert _ctx().canonical_payload is None  # type: ignore[attr-defined]
    assert "w01-hidden-marker" not in repr(with_bytes) and "canonical_payload" not in repr(with_bytes)
    assert with_bytes == _ctx() == _ctx(canonical_payload=b"{}")


# ------------------------------------------------------------------------------------------------------------------
# (c) the owner path serializes the call once and dispatch reuses the verified bytes
# ------------------------------------------------------------------------------------------------------------------


def test_w01_owner_serializes_a_fresh_queued_request_at_most_once(
    harness: DedicatedOwnerHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "idem_w01_owner_once_fresh"
    spy = _Spy(monkeypatch)
    sub = _submit(harness, _args(key))
    _expect_ok("prepare_task", sub.wait(timeout=5.0))  # type: ignore[attr-defined]
    owner_calls = spy.on(harness.owner_tid)
    assert owner_calls <= 1, f"owner serialized the same queued call {owner_calls} times"
    monkeypatch.undo()
    assert _stored_digest(harness, key) == sub.queued.request_digest  # type: ignore[attr-defined]


def test_w01_owner_serializes_a_queued_replay_at_most_once(
    harness: DedicatedOwnerHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "idem_w01_owner_once_replay"
    first = _expect_ok("prepare_task", _submit(harness, _args(key)).wait(timeout=5.0))  # type: ignore[attr-defined]
    harness.run_on_owner(harness.bridge.publish_auth_view)
    spy = _Spy(monkeypatch)
    replay = _submit(harness, _args(key))
    assert _expect_ok("prepare_task", replay.wait(timeout=5.0)) == first  # type: ignore[attr-defined]
    owner_calls = spy.on(harness.owner_tid)
    assert owner_calls <= 1, f"owner serialized the same queued replay {owner_calls} times"


def test_w01_dispatch_reuses_context_bytes_without_serializing_again(
    harness: DedicatedOwnerHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "idem_w01_direct_ctx_bytes"
    principal = harness.seeded.principal
    call = normalize_call("prepare_task", _args(key), principal, selected_scope=harness.scope)
    canonical = canonical_request_payload(call)
    auth = PrivateRequestAuth(
        credential_id=harness.seeded.credential_id, principal=principal, token=harness.seeded.token
    )
    spy = _Spy(monkeypatch)

    def run() -> object:
        ctx = CallContext(
            principal=principal,
            identity=Identity(
                store_id=harness.rt.store.store_id,
                writer_epoch=harness.rt.lease.epoch,
                instance_id=harness.bridge._instance_id,
            ),
            deadline_ns=harness._mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            selected_scope=harness.scope,
            canonical_payload=canonical,  # type: ignore[call-arg]
        )
        return harness.bridge.dispatch(call, ctx, auth=auth)

    result = harness.run_on_owner(run)
    _expect_ok("prepare_task", result)  # type: ignore[arg-type]
    assert spy.on(harness.owner_tid) == 0, "dispatch serialized the call although the context carried its bytes"
    monkeypatch.undo()
    assert _stored_digest(harness, key) == compute_canonical_payload_hmac(_active_key(harness), canonical)
