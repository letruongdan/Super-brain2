"""SP1 Increment 2 Task 4b/4c remediation regressions (I2-T4B-R01 and I2-T4C-R01).

Requirement-derived oracles:
- I2-T4B-R01: Pre-queue admission (credential check, normalize_call, scope check, canonicalization, request HMAC)
  and owner local phases (recheck, binding, PrivacyFilter, SnapshotObserver) share a single <= 100 ms local budget,
  distinct from queue wait time while capped by handler_deadline_ns (1,300 ms).
- I2-T4C-R01: Under RepoFlags(manual_submission=False), privacy projection discards read_acks before any ReadAck
  lookup, state check, or persistence, while C3 raw normalized request HMAC and manual_submission=True enforcement
  remain intact.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import ParamSpec, TypeVar

import pytest

import superbrain.application._prequeue as prequeue
import superbrain.application.deadlines as deadlines_mod
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    IDEMPOTENCY_CLOCK_HWM_META_KEY,
    Call,
    CallResult,
    IdempotencyRow,
    ReadAckInput,
    RepoFlags,
    ResourceDigest,
    Scope,
)
from superbrain.core.wire import normalize_call
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import KernelIdempotencyStore
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.store import Store
from superbrain.storage.workspaces import SNAPSHOTS_TABLE
from tests.application.test_kernel_deadlines import (
    CLOCK_START,
    MS,
    TREE_A,
    FakeMonotonicClock,
    RecordingObserver,
    _count_rows,
    _desc,
    _expect_err,
    _expect_ok,
    _open_fixture_runtime,
    _register_ws,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import FixtureKernelDomain, FixtureResourceSpec
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential, seed_repo_grant

_P = ParamSpec("_P")
_R = TypeVar("_R")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(CLOCK_START)


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    from superbrain.adapters.os import os_adapters

    return os_adapters(clock)


def _wrap_timed(
    orig: Callable[_P, _R],
    mono: FakeMonotonicClock,
    delay_ns_fn: Callable[[], int],
) -> Callable[_P, _R]:
    def _measured(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        out = orig(*args, **kwargs)
        delay_ns = delay_ns_fn()
        if delay_ns:
            mono.advance(delay_ns)
        return out

    return _measured


def _wrap_normalize(
    orig: Callable[_P, Call],
    mono: FakeMonotonicClock,
    delay_ns_fn: Callable[[], int],
) -> Callable[_P, Call]:
    return _wrap_timed(orig, mono, delay_ns_fn)


def _read_all_idempotency_rows(store: Store) -> list[tuple[object, ...]]:
    with store.transaction() as txn:
        rows = txn.db.execute(
            "SELECT principal_id, tool, key_hash, request_digest_key_id, request_digest, "
            "result_id, assignment_id, refs_json, committed_at "
            "FROM idempotency ORDER BY principal_id, tool, key_hash"
        ).fetchall()
    return [tuple(r) for r in rows]


def _read_c4_hwm(store: Store) -> str | None:
    with store.transaction() as txn:
        row = txn.db.execute(
            "SELECT value FROM meta WHERE key = ?",
            (IDEMPOTENCY_CLOCK_HWM_META_KEY,),
        ).fetchone()
    return None if row is None else str(row[0])


def _count_ledger_kind(store: Store, kind: str) -> int:
    with store.transaction() as txn:
        row = txn.db.execute("SELECT COUNT(*) FROM ledger WHERE kind = ?", (kind,)).fetchone()
    assert row is not None
    return int(row[0])


def _run_tool(
    bridge: KernelBridge,
    tool: str,
    arguments: Mapping[str, JsonValue],
    *,
    token: str,
    selected_scope: Scope | None,
) -> CallResult:
    sub = bridge.submit_request(
        tool,
        arguments,
        token=token,
        selected_scope=selected_scope,
    )
    if not sub.done():
        assert bridge.process_next_queued(block=False) is True
    return sub.wait(timeout=2.0)


def _prepare_task_on(
    bridge: KernelBridge,
    *,
    token: str,
    scope: Scope,
    idem_key: str,
    hint: str = "ws-main",
) -> tuple[str, str]:
    data = _expect_ok(
        "prepare_task",
        _run_tool(
            bridge,
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": hint,
                "description": f"remediation task {idem_key}",
                "idempotency_key": idem_key,
            },
            token=token,
            selected_scope=scope,
        ),
    )
    return str(data["task_id"]), str(data["delivery_id"])


# --- I2-T4B-R01 (1): 60 ms pre-queue admission + 0 ms queue wait + 50 ms observer (> 100 ms) + replay ---------------


def test_t4b_r01_prequeue_admission_shares_100ms_local_budget_with_observer_and_replay(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mono = FakeMonotonicClock(start_ns=10_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        late_desc = _desc(TREE_A)
        obs = RecordingObserver(descriptor=late_desc, advance_ns_on_observe=50 * MS, mono=mono)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=obs,
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
        )
        bridge.publish_auth_view()

        normalize_delay_ns = 60 * MS
        monkeypatch.setattr(
            prequeue,
            "normalize_call",
            _wrap_normalize(normalize_call, mono, lambda: normalize_delay_ns),
        )

        req_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "shared 100ms local budget across prequeue admission and observer",
            "idempotency_key": "idem_t4b_r01_shared_0001",
        }
        receive_ns = mono.monotonic_ns()
        submitted = bridge.submit_request(
            "prepare_task",
            req_args,
            token=seeded.token,
            selected_scope=scope,
        )
        after_admission_ns = mono.monotonic_ns()
        owner_started_ns = mono.monotonic_ns()
        assert after_admission_ns == receive_ns + 60 * MS
        assert owner_started_ns == after_admission_ns

        assert bridge.process_next_queued(block=False) is True
        data = _expect_ok("prepare_task", submitted.wait(timeout=2.0))

        assert len(obs.calls) == 1
        assert obs.calls[0][0] == binding
        assert obs.calls[0][1] == receive_ns + 100 * MS
        assert data["snapshot_status"] == "deadline"
        assert data["source_snapshot_id"] is None
        assert data["degraded_codes"] == ["snapshot_deadline"]
        assert _count_rows(rt.store, SNAPSHOTS_TABLE) == 0
        assert _count_ledger_kind(rt.store, "snapshot.observed") == 0
        assert not rt.store.cas.holders(late_desc.descriptor_digest)
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
        assert _count_rows(rt.store, "idempotency") == 1

        # Replay with fast observer (5 ms) and 0 ms admission delay MUST return the committed "deadline" result.
        normalize_delay_ns = 0
        obs.advance_ns_on_observe = 5 * MS
        replay_sub = bridge.submit_request(
            "prepare_task",
            dict(req_args),
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        replay_data = _expect_ok("prepare_task", replay_sub.wait(timeout=2.0))

        assert replay_data == data
        assert replay_data["delivery_id"] == data["delivery_id"]
        assert replay_data["snapshot_status"] == "deadline"
        assert replay_data["source_snapshot_id"] is None
        assert replay_data["degraded_codes"] == ["snapshot_deadline"]
        assert len(obs.calls) == 1
        assert _count_rows(rt.store, SNAPSHOTS_TABLE) == 0
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
        assert _count_rows(rt.store, "idempotency") == 1
    finally:
        rt.close()


# --- I2-T4B-R01 (2): Queue wait preserves remaining local budget without expiring it or resetting to 100 ms ----------


def test_t4b_r01_queue_wait_preserves_remaining_local_budget_without_resetting_to_100ms(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mono = FakeMonotonicClock(start_ns=20_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        desc_a = _desc(TREE_A)
        obs = RecordingObserver(descriptor=desc_a, advance_ns_on_observe=30 * MS, mono=mono)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=obs,
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
        )
        bridge.publish_auth_view()

        normalize_delay_ns = 60 * MS
        monkeypatch.setattr(
            prequeue,
            "normalize_call",
            _wrap_normalize(normalize_call, mono, lambda: normalize_delay_ns),
        )

        # Request A: 60 ms pre-queue (40 ms remaining) + 500 ms queue wait + 30 ms observer -> available!
        t0 = 20_000 * MS
        mono.set_ns(t0)
        obs.descriptor = desc_a
        obs.advance_ns_on_observe = 30 * MS
        sub_a = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "request A fits inside 40ms remaining local budget after 500ms queue wait",
                "idempotency_key": "idem_t4b_r01_qwait_avail_1",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert mono.monotonic_ns() == t0 + 60 * MS
        owner_start_a = mono.advance(500 * MS)
        assert owner_start_a == t0 + 560 * MS

        assert bridge.process_next_queued(block=False) is True
        data_a = _expect_ok("prepare_task", sub_a.wait(timeout=2.0))
        assert len(obs.calls) == 1
        assert obs.calls[-1][1] == t0 + 600 * MS
        assert data_a["snapshot_status"] == "available"
        assert isinstance(data_a["source_snapshot_id"], str) and data_a["source_snapshot_id"]
        assert data_a["degraded_codes"] == []
        assert _count_rows(rt.store, SNAPSHOTS_TABLE) == 1
        assert rt.store.cas.holders(desc_a.descriptor_digest)

        # Request B: 60 ms pre-queue (40 ms remaining) + 500 ms queue wait + 50 ms observer -> deadline!
        t1 = 30_000 * MS
        mono.set_ns(t1)
        desc_b = _desc("sha256:" + "b" * 64)
        obs.descriptor = desc_b
        obs.advance_ns_on_observe = 50 * MS
        sub_b = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "request B exceeds 40ms remaining local budget after 500ms queue wait",
                "idempotency_key": "idem_t4b_r01_qwait_deadl_2",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert mono.monotonic_ns() == t1 + 60 * MS
        owner_start_b = mono.advance(500 * MS)
        assert owner_start_b == t1 + 560 * MS

        assert bridge.process_next_queued(block=False) is True
        data_b = _expect_ok("prepare_task", sub_b.wait(timeout=2.0))
        assert len(obs.calls) == 2
        assert obs.calls[-1][1] == t1 + 600 * MS
        assert data_b["snapshot_status"] == "deadline"
        assert data_b["source_snapshot_id"] is None
        assert data_b["degraded_codes"] == ["snapshot_deadline"]
        assert _count_rows(rt.store, SNAPSHOTS_TABLE) == 1
        assert not rt.store.cas.holders(desc_b.descriptor_digest)

        # Request C: 60 ms pre-queue (40 ms left) + 1,220 ms queue wait -> capped at handler_deadline_ns (1,300 ms).
        t2 = 40_000 * MS
        mono.set_ns(t2)
        obs.descriptor = desc_a
        obs.advance_ns_on_observe = 10 * MS
        sub_c = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "request C remaining local budget still capped by handler_deadline_ns",
                "idempotency_key": "idem_t4b_r01_qwait_hcap_03",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        owner_start_c = mono.advance(1_220 * MS)
        assert owner_start_c == t2 + 1_280 * MS
        assert bridge.process_next_queued(block=False) is True
        data_c = _expect_ok("prepare_task", sub_c.wait(timeout=2.0))
        assert obs.calls[-1][1] == t2 + 1_300 * MS
        assert data_c["snapshot_status"] == "available"
    finally:
        rt.close()


# --- I2-T4B-R01 (3): Over-budget pre-queue admission (>= 100 ms) & shared reduced owner filter fail closed -----------


def test_t4b_r01_over_budget_prequeue_admission_and_shared_owner_filter_fail_closed(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mono = FakeMonotonicClock(start_ns=50_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        obs = RecordingObserver(descriptor=_desc(TREE_A), mono=mono)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=obs,
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
        )
        bridge.publish_auth_view()

        normalize_delay_ns = 0
        monkeypatch.setattr(
            prequeue,
            "normalize_call",
            _wrap_normalize(normalize_call, mono, lambda: normalize_delay_ns),
        )

        # 1) Bad token still fails with UNAUTHENTICATED first even with 105 ms delay or pre-elapsed receive_ns.
        normalize_delay_ns = 105 * MS
        bad_token = f"{new_id()}.{'A' * 43}"
        for recv_override in (None, mono.monotonic_ns() - 105 * MS):
            sub_bad = bridge.submit_request(
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "workspace_hint": "ws-main",
                    "description": "unauthenticated token takes precedence over local budget",
                    "idempotency_key": "idem_t4b_r01_bad_tok_001",
                },
                token=bad_token,
                selected_scope=scope,
                receive_ns=recv_override,
            )
            assert sub_bad.done() is True
            _expect_err("prepare_task", sub_bad.wait(timeout=1.0), ErrorCode.UNAUTHENTICATED)
            assert bridge.reservations.active_count() == 0
            assert bridge.queue_depth() == 0
            assert len(obs.calls) == 0

        # 2) Valid token where normalize_call consumes 100 ms (exact boundary) and 105 ms: fails closed pre-queue!
        for idx, over_ms in enumerate((100, 105), start=1):
            mono.set_ns((50_000 + idx * 1_000) * MS)
            normalize_delay_ns = over_ms * MS
            sub_over = bridge.submit_request(
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "workspace_hint": "ws-main",
                    "description": f"prequeue admission consumed {over_ms}ms",
                    "idempotency_key": f"idem_t4b_r01_pre_{over_ms}ms_0{idx}",
                },
                token=seeded.token,
                selected_scope=scope,
            )
            assert sub_over.done() is True
            _expect_err("prepare_task", sub_over.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
            assert bridge.reservations.active_count() == 0
            assert bridge.queue_depth() == 0
            assert bridge.process_next_queued(block=False) is False
            assert len(obs.calls) == 0
            assert _count_rows(rt.store, "idempotency") == 0
            assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 0

        # 3) Valid token where normalize_call consumes 70 ms (30 ms remaining) and PrivacyFilter consumes 35 ms
        #    (< 100 ms standalone, > 30 ms remaining) -> owner fails closed with DEADLINE_EXCEEDED!
        def _install_35ms_filter_hook() -> None:
            reads = 0

            def _tick_35ms_inside_filter(cur: int) -> int:
                nonlocal reads
                reads += 1
                if reads == 12:
                    return cur + 35 * MS
                return cur

            mono.set_read_hook(_tick_35ms_inside_filter)

        t_prep = 60_000 * MS
        mono.set_ns(t_prep)
        normalize_delay_ns = 70 * MS
        sub_prep_flt = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "prepare_task filter crosses 30ms remaining local budget",
                "idempotency_key": "idem_t4b_r01_flt_prep_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert not sub_prep_flt.done()
        owner_start_prep = mono.monotonic_ns()
        assert owner_start_prep == t_prep + 70 * MS
        _install_35ms_filter_hook()
        assert bridge.process_next_queued(block=False) is True
        mono.set_read_hook(None)
        assert mono.monotonic_ns() == owner_start_prep + 35 * MS
        _expect_err("prepare_task", sub_prep_flt.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.reservations.active_count() == 0
        assert len(obs.calls) == 0
        assert _count_rows(rt.store, "idempotency") == 0
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 0

        # Seed valid task/delivery and artifact (0 ms admission delay) to exercise get_artifact and record_outcome.
        normalize_delay_ns = 0
        mono.set_ns(70_000 * MS)
        domain.seed_artifact(
            bridge,
            artifact_id="art-t4b-flt-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=binding.repo_id,
            checkout_id=binding.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=b"filter budget check", level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(
            bridge,
            token=seeded.token,
            scope=scope,
            idem_key="idem_t4b_r01_seed_prep_1",
        )
        obs.calls.clear()
        base_idem = _count_rows(rt.store, "idempotency")
        base_deliv = _count_rows(rt.store, "p_fixture_domain_deliveries")

        # 3b) get_artifact: 70 ms pre-queue + 35 ms owner PrivacyFilter -> DEADLINE_EXCEEDED, 0 new rows!
        t_gart = 80_000 * MS
        mono.set_ns(t_gart)
        normalize_delay_ns = 70 * MS
        sub_gart_flt = bridge.submit_request(
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": binding.repo_id,
                "task_id": task_id,
                "artifact_id": "art-t4b-flt-1",
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem_t4b_r01_flt_gart_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert not sub_gart_flt.done()
        owner_start_gart = mono.monotonic_ns()
        assert owner_start_gart == t_gart + 70 * MS
        _install_35ms_filter_hook()
        assert bridge.process_next_queued(block=False) is True
        mono.set_read_hook(None)
        assert mono.monotonic_ns() == owner_start_gart + 35 * MS
        _expect_err("get_artifact", sub_gart_flt.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.reservations.active_count() == 0
        assert len(obs.calls) == 0
        assert _count_rows(rt.store, "idempotency") == base_idem
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == 0
        assert _count_rows(rt.store, "artifact_send_attempt") == 0

        # 3c) record_outcome: 70 ms pre-queue + 35 ms owner PrivacyFilter -> DEADLINE_EXCEEDED, 0 new rows!
        t_rout = 90_000 * MS
        mono.set_ns(t_rout)
        normalize_delay_ns = 70 * MS
        sub_rout_flt = bridge.submit_request(
            "record_outcome",
            {
                "schema_version": "2.0",
                "workspace_id": binding.repo_id,
                "delivery_id": delivery_id,
                "outcome": "success",
                "idempotency_key": "idem_t4b_r01_flt_rout_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert not sub_rout_flt.done()
        owner_start_rout = mono.monotonic_ns()
        assert owner_start_rout == t_rout + 70 * MS
        _install_35ms_filter_hook()
        assert bridge.process_next_queued(block=False) is True
        mono.set_read_hook(None)
        assert mono.monotonic_ns() == owner_start_rout + 35 * MS
        _expect_err("record_outcome", sub_rout_flt.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.reservations.active_count() == 0
        assert len(obs.calls) == 0
        assert _count_rows(rt.store, "idempotency") == base_idem
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == base_deliv
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 0
        assert _count_rows(rt.store, "artifact_read_ack") == 0
    finally:
        mono.set_read_hook(None)
        rt.close()


# --- I2-T4C-R01: manual_submission=False discards ReadAcks while keeping C3 raw HMAC & manual_submission=True --------


def test_t4c_r01_manual_submission_false_discards_read_acks_across_served_pending_unknown_foreign_and_replay(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
) -> None:
    mono = FakeMonotonicClock(start_ns=1_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        other = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="box-1")
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        seed_repo_grant(rt.policy, principal_id=other.principal.principal_id, repo_id=ws.repo_id, owner_id="dan")
        scope = Scope(ws.repo_id, ws.checkout_id)

        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc(TREE_A), mono=mono),
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
        )
        bridge.publish_auth_view()

        content = b"non-sensitive remediation artifact resource"
        res_digest = digest_bytes(content)
        domain.seed_artifact(
            bridge,
            artifact_id="art-t4c-1",
            revision=1,
            kind="skill",
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=content, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(
            bridge,
            token=seeded.token,
            scope=scope,
            idem_key="idem_t4c_r01_prep_a_0001",
        )
        other_task_id, other_delivery_id = _prepare_task_on(
            bridge,
            token=other.token,
            scope=scope,
            idem_key="idem_t4c_r01_prep_b_0001",
        )

        def _get_receipt(idem_key: str, token: str, target_task_id: str = task_id) -> str:
            art = _expect_ok(
                "get_artifact",
                _run_tool(
                    bridge,
                    "get_artifact",
                    {
                        "schema_version": "2.0",
                        "workspace_id": ws.repo_id,
                        "task_id": target_task_id,
                        "artifact_id": "art-t4c-1",
                        "revision": 1,
                        "level": "L1",
                        "idempotency_key": idem_key,
                    },
                    token=token,
                    selected_scope=scope,
                ),
            )
            assert "served_receipt_id" in art
            return str(art["served_receipt_id"])

        served = _get_receipt("idem_t4c_r01_art_srv_01", seeded.token)
        bridge.finalize_send_attempt(bridge.build_send_completion(served))

        pending = _get_receipt("idem_t4c_r01_art_pnd_02", seeded.token)

        unknown = _get_receipt("idem_t4c_r01_art_unk_03", seeded.token)
        bridge.interrupt_send_attempt(unknown)

        foreign = _get_receipt("idem_t4c_r01_art_for_04", other.token)
        bridge.finalize_send_attempt(bridge.build_send_completion(foreign))

        served_ack = ReadAckInput(
            served_receipt_id=served,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        pending_ack = ReadAckInput(
            served_receipt_id=pending,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        unknown_ack = ReadAckInput(
            served_receipt_id=unknown,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        foreign_ack = ReadAckInput(
            served_receipt_id=foreign,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )

        # --- Matrix under RepoFlags(manual_submission=False) ---
        domain.repo_flags_overrides[ws.repo_id] = RepoFlags(manual_submission=False)

        # 1) Control without read_acks -> ok: True, 0 artifact_read_ack rows.
        out_ctrl = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "idempotency_key": "idem_t4c_r01_dis_ctrl_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert out_ctrl["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        # 2) Valid served_ack under manual_submission=False -> ok: True, 0 artifact_read_ack rows!
        served_dis_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "delivery_id": delivery_id,
            "outcome": "success",
            "read_acks": [served_ack.to_dict()],
            "idempotency_key": "idem_t4c_r01_dis_srvd_02",
        }
        out_served_dis = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", served_dis_args, token=seeded.token, selected_scope=scope),
        )
        assert out_served_dis["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        # 3) pending_ack under manual_submission=False -> ok: True (NOT in_progress), retry ok: True,
        #    finalize pending -> served_only, then same-key replay STILL ok: True and 0 artifact_read_ack rows!
        pending_dis_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "delivery_id": delivery_id,
            "outcome": "success",
            "read_acks": [pending_ack.to_dict()],
            "idempotency_key": "idem_t4c_r01_dis_pend_03",
        }
        out_pend_1 = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", pending_dis_args, token=seeded.token, selected_scope=scope),
        )
        assert out_pend_1["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        out_pend_2 = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", dict(pending_dis_args), token=seeded.token, selected_scope=scope),
        )
        assert out_pend_2 == out_pend_1
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        bridge.finalize_send_attempt(bridge.build_send_completion(pending))
        out_pend_3 = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", dict(pending_dis_args), token=seeded.token, selected_scope=scope),
        )
        assert out_pend_3 == out_pend_1
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        # 4) unknown_ack and foreign_ack under manual_submission=False -> ok: True (NOT not_found), 0 ack rows!
        out_unk_dis = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [unknown_ack.to_dict()],
                    "idempotency_key": "idem_t4c_r01_dis_unkn_04",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert out_unk_dis["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        out_for_dis = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [foreign_ack.to_dict()],
                    "idempotency_key": "idem_t4c_r01_dis_frgn_05",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert out_for_dis["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 0
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 5

        # 5) C3 raw request HMAC preservation: altering or omitting discarded read_acks under same key conflicts!
        conflict_cases: tuple[dict[str, JsonValue], ...] = (
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "delivery_id": delivery_id,
                "outcome": "success",
                "idempotency_key": "idem_t4c_r01_dis_pend_03",
            },
            {
                **pending_dis_args,
                "read_acks": [served_ack.to_dict()],
            },
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "delivery_id": delivery_id,
                "outcome": "success",
                "idempotency_key": "idem_t4c_r01_dis_srvd_02",
            },
            {
                **served_dis_args,
                "read_acks": [
                    ReadAckInput(
                        served_receipt_id=served,
                        task_id=task_id,
                        revision=1,
                        resource_digests=(ResourceDigest(name="L1.md", digest="sha256:" + "0" * 64),),
                    ).to_dict()
                ],
            },
        )
        for conflict_args in conflict_cases:
            _expect_err(
                "record_outcome",
                _run_tool(bridge, "record_outcome", conflict_args, token=seeded.token, selected_scope=scope),
                ErrorCode.IDEMPOTENCY_CONFLICT,
            )

        # --- Re-enable RepoFlags(manual_submission=True) and verify full ReadAck enforcement ---
        domain.repo_flags_overrides[ws.repo_id] = RepoFlags(manual_submission=True)

        # 6) Fresh served_ack succeeds and persists exactly 1 artifact_read_ack row.
        out_en_served = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [served_ack.to_dict()],
                    "idempotency_key": "idem_t4c_r01_ena_srvd_06",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert out_en_served["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 1

        # 7) Authorization-first under manual_submission=True: unknown_ack and foreign_ack (both with normal L1.md
        #    AND with two sensitive blocked-path names .env + .npmrc that PrivacyFilter redacts to "[redacted]")
        #    MUST fail closed with NOT_FOUND, never INVALID_INPUT!
        redacted_pair = (
            ResourceDigest(name=".env", digest=res_digest),
            ResourceDigest(name=".npmrc", digest="sha256:" + "f" * 64),
        )
        not_found_acks = (
            ("unk_plain", unknown_ack),
            (
                "unk_redacted_names",
                ReadAckInput(
                    served_receipt_id=unknown,
                    task_id=task_id,
                    revision=99,
                    resource_digests=redacted_pair,
                ),
            ),
            ("for_plain", foreign_ack),
            (
                "for_redacted_names",
                ReadAckInput(
                    served_receipt_id=foreign,
                    task_id=task_id,
                    revision=99,
                    resource_digests=redacted_pair,
                ),
            ),
        )
        for label, bad_ack in not_found_acks:
            nf_err = _expect_err(
                "record_outcome",
                _run_tool(
                    bridge,
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "workspace_id": ws.repo_id,
                        "delivery_id": delivery_id,
                        "outcome": "success",
                        "read_acks": [bad_ack.to_dict()],
                        "idempotency_key": f"idem_t4c_r01_ena_{label}"[:32],
                    },
                    token=seeded.token,
                    selected_scope=scope,
                ),
                ErrorCode.NOT_FOUND,
            )
            assert nf_err["message"] == "not found"
        assert _count_rows(rt.store, "artifact_read_ack") == 1

        # 8) Fresh unfinalized pending2 attempt fails with IN_PROGRESS for owner principal and NOT_FOUND for foreign.
        pending2 = _get_receipt("idem_t4c_r01_art_pnd_05", seeded.token)
        pending2_ack = ReadAckInput(
            served_receipt_id=pending2,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        in_prog_err = _expect_err(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [pending2_ack.to_dict()],
                    "idempotency_key": "idem_t4c_r01_ena_pnd2_07",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.IN_PROGRESS,
        )
        assert in_prog_err["message"] == "operation in progress"

        foreign_pend2_err = _expect_err(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": other_delivery_id,
                    "outcome": "success",
                    "read_acks": [
                        ReadAckInput(
                            served_receipt_id=pending2,
                            task_id=other_task_id,
                            revision=99,
                            resource_digests=redacted_pair,
                        ).to_dict()
                    ],
                    "idempotency_key": "idem_t4c_r01_ena_fpnd_08",
                },
                token=other.token,
                selected_scope=scope,
            ),
            ErrorCode.NOT_FOUND,
        )
        assert foreign_pend2_err["message"] == "not found"
        assert _count_rows(rt.store, "artifact_read_ack") == 1
    finally:
        rt.close()


# --- I2-T4B-R01 (R2): Cached replay & read-only owner admission share the <= 100 ms local budget ---------------------


def test_t4b_r01_cached_replay_and_readonly_enforce_shared_local_budget_on_owner_admission(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mono = FakeMonotonicClock(start_ns=100_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        token_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        token_b = seed_principal_and_credential(
            rt.policy,
            principal_id=token_a.principal.principal_id,
            owner_id=token_a.principal.owner_id,
            harness_id=token_a.principal.harness_id,
            machine_id=token_a.principal.machine_id,
        )
        binding = _register_ws(rt, clock, token_a, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        obs = RecordingObserver(descriptor=_desc(TREE_A), mono=mono)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=obs,
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
        )
        bridge.publish_auth_view()

        replay_record_calls = 0
        orig_record_replay = KernelIdempotencyStore.record_replay

        def _counting_record_replay(
            self_store: KernelIdempotencyStore,
            *,
            row: IdempotencyRow,
            now: dt.datetime,
        ) -> None:
            nonlocal replay_record_calls
            replay_record_calls += 1
            orig_record_replay(self_store, row=row, now=now)

        monkeypatch.setattr(KernelIdempotencyStore, "record_replay", _counting_record_replay)

        domain.seed_artifact(
            bridge,
            artifact_id="art-t4b-r2-1",
            revision=1,
            kind="skill",
            owner_id=token_a.principal.owner_id,
            repo_id=binding.repo_id,
            checkout_id=binding.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=b"r2 replay local budget", level="L1"),),
        )

        # Seed committed initial results at 0 ms delay across prepare_task, get_artifact, record_outcome,
        # and request_improvement (for get_job), plus verify baseline read-only get_health and get_job.
        prep_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "seed committed prepare_task for r2 replay budget check",
            "idempotency_key": "idem_t4b_r2_prep_seed_01",
        }
        prep_first = _expect_ok(
            "prepare_task",
            _run_tool(bridge, "prepare_task", prep_args, token=token_a.token, selected_scope=scope),
        )
        assert prep_first["snapshot_status"] == "available"
        assert isinstance(prep_first["source_snapshot_id"], str)
        task_id = str(prep_first["task_id"])
        delivery_id = str(prep_first["delivery_id"])

        gart_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": binding.repo_id,
            "task_id": task_id,
            "artifact_id": "art-t4b-r2-1",
            "revision": 1,
            "level": "L1",
            "idempotency_key": "idem_t4b_r2_gart_seed_01",
        }
        gart_first = _expect_ok(
            "get_artifact",
            _run_tool(bridge, "get_artifact", gart_args, token=token_a.token, selected_scope=scope),
        )
        receipt_1 = str(gart_first["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_1))

        rout_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": binding.repo_id,
            "delivery_id": delivery_id,
            "outcome": "success",
            "idempotency_key": "idem_t4b_r2_rout_seed_01",
        }
        rout_first = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", rout_args, token=token_a.token, selected_scope=scope),
        )
        assert rout_first["status"] == "declared"

        health_args: dict[str, JsonValue] = {"schema_version": "2.0", "deep": False}
        job_args: dict[str, JsonValue] = {"schema_version": "2.0", "job_id": "job-missing-r2-0001"}
        _expect_ok("get_health", _run_tool(bridge, "get_health", health_args, token=token_a.token, selected_scope=None))
        _expect_err(
            "get_job",
            _run_tool(bridge, "get_job", job_args, token=token_a.token, selected_scope=None),
            ErrorCode.NOT_FOUND,
        )

        # Advance wall clock so any unintended record_replay would visibly advance meta[idempotency_clock_hwm_utc].
        base_obs_calls = len(obs.calls)
        base_deliveries = _count_rows(rt.store, "p_fixture_domain_deliveries")
        base_art_results = _count_rows(rt.store, "p_fixture_domain_artifact_results")
        base_outcomes = _count_rows(rt.store, "p_fixture_domain_outcomes")
        base_idem_count = _count_rows(rt.store, "idempotency")
        base_send_attempts = _count_rows(rt.store, "artifact_send_attempt")
        base_idem_rows = _read_all_idempotency_rows(rt.store)
        base_hwm = _read_c4_hwm(rt.store)
        assert base_hwm is not None
        assert replay_record_calls == 0

        clock.advance(dt.timedelta(seconds=10))
        replayed_wall_str = utc_timestamp(clock.now())
        assert replayed_wall_str > base_hwm

        normalize_delay_ns = 0
        reconstruct_delay_ns = 0
        resolve_delay_ns = 0
        snapshot_delay_ns = 0

        real_reconstruct = deadlines_mod.reconstruct_queued_call
        monkeypatch.setattr(
            prequeue,
            "normalize_call",
            _wrap_normalize(normalize_call, mono, lambda: normalize_delay_ns),
        )
        monkeypatch.setattr(
            deadlines_mod,
            "reconstruct_queued_call",
            _wrap_timed(real_reconstruct, mono, lambda: reconstruct_delay_ns),
        )
        monkeypatch.setattr(
            rt.policy,
            "resolve_credential",
            _wrap_timed(rt.policy.resolve_credential, mono, lambda: resolve_delay_ns),
        )
        monkeypatch.setattr(
            rt.policy,
            "snapshot",
            _wrap_timed(rt.policy.snapshot, mono, lambda: snapshot_delay_ns),
        )

        step_idx = 0

        def _submit_and_run_owner(
            tool: str,
            args: Mapping[str, JsonValue],
            *,
            token: str = token_a.token,
            sel_scope: Scope | None = scope,
            pre_ms: int = 60,
            queue_ms: int = 0,
            reconstruct_ms: int = 0,
            auth_ms: int = 0,
            snap_ms: int = 0,
        ) -> CallResult:
            nonlocal step_idx, normalize_delay_ns, reconstruct_delay_ns, resolve_delay_ns, snapshot_delay_ns
            step_idx += 1
            t_start = (200_000 + step_idx * 10_000) * MS
            mono.set_ns(t_start)
            normalize_delay_ns = pre_ms * MS
            reconstruct_delay_ns = reconstruct_ms * MS
            resolve_delay_ns = auth_ms * MS
            snapshot_delay_ns = snap_ms * MS
            try:
                sub = bridge.submit_request(tool, dict(args), token=token, selected_scope=sel_scope)
                assert not sub.done()
                assert mono.monotonic_ns() == t_start + pre_ms * MS
                if sub.queued is not None:
                    assert sub.queued.remaining_local_budget_ns == (100 - pre_ms) * MS
                if queue_ms:
                    mono.advance(queue_ms * MS)
                assert bridge.process_next_queued(block=False) is True
                return sub.wait(timeout=2.0)
            finally:
                normalize_delay_ns = 0
                reconstruct_delay_ns = 0
                resolve_delay_ns = 0
                snapshot_delay_ns = 0

        def _assert_no_replay_or_business_side_effects() -> None:
            assert len(obs.calls) == base_obs_calls
            assert _count_rows(rt.store, "p_fixture_domain_deliveries") == base_deliveries
            assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == base_art_results
            assert _count_rows(rt.store, "p_fixture_domain_outcomes") == base_outcomes
            assert _count_rows(rt.store, "idempotency") == base_idem_count
            assert _read_all_idempotency_rows(rt.store) == base_idem_rows
            assert replay_record_calls == 0
            assert _read_c4_hwm(rt.store) == base_hwm
            assert _count_rows(rt.store, "artifact_send_attempt") == base_send_attempts
            assert bridge.reservations.active_count() == 0

        # --- (a.1) Fresh-key controls (60 ms pre-queue + 50 ms owner admission = 110 ms > 100 ms) ---
        for ctrl_idx, (rec_ms, auth_ms, snap_ms) in enumerate(((0, 50, 0), (50, 0, 0), (0, 0, 50)), start=1):
            _expect_err(
                "prepare_task",
                _submit_and_run_owner(
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "workspace_hint": "ws-main",
                        "description": f"fresh control {ctrl_idx}",
                        "idempotency_key": f"idem_t4b_r2_fresh_ctrl_0{ctrl_idx}",
                    },
                    pre_ms=60,
                    reconstruct_ms=rec_ms,
                    auth_ms=auth_ms,
                    snap_ms=snap_ms,
                ),
                ErrorCode.DEADLINE_EXCEEDED,
            )
            _assert_no_replay_or_business_side_effects()

        # --- (a.2) & (b) Cached replays + read-only tools MUST also fail closed with DEADLINE_EXCEEDED ---
        replay_and_readonly_targets: tuple[tuple[str, Mapping[str, JsonValue], Scope | None], ...] = (
            ("prepare_task", prep_args, scope),
            ("get_artifact", gart_args, scope),
            ("record_outcome", rout_args, scope),
            ("get_health", health_args, None),
            ("get_job", job_args, None),
        )
        for rec_ms, auth_ms, snap_ms in ((0, 50, 0), (50, 0, 0), (0, 0, 50)):
            for tool_name, tool_args, tool_scope in replay_and_readonly_targets:
                _expect_err(
                    tool_name,
                    _submit_and_run_owner(
                        tool_name,
                        tool_args,
                        sel_scope=tool_scope,
                        pre_ms=60,
                        reconstruct_ms=rec_ms,
                        auth_ms=auth_ms,
                        snap_ms=snap_ms,
                    ),
                    ErrorCode.DEADLINE_EXCEEDED,
                )
                _assert_no_replay_or_business_side_effects()

        # --- (c) Queue-wait separation (500 ms queue wait) & within-budget replay recovery (85 ms <= 100 ms) ---
        _expect_err(
            "prepare_task",
            _submit_and_run_owner(
                "prepare_task",
                prep_args,
                pre_ms=60,
                queue_ms=500,
                auth_ms=50,
            ),
            ErrorCode.DEADLINE_EXCEEDED,
        )
        _assert_no_replay_or_business_side_effects()

        _expect_err(
            "get_artifact",
            _submit_and_run_owner(
                "get_artifact",
                gart_args,
                pre_ms=60,
                queue_ms=500,
                reconstruct_ms=50,
            ),
            ErrorCode.DEADLINE_EXCEEDED,
        )
        _assert_no_replay_or_business_side_effects()

        # Within-budget recovery on the SAME prepare_task key (60 ms pre-queue + 500 ms queue wait + 25 ms auth = 85 ms)
        prep_recovered = _expect_ok(
            "prepare_task",
            _submit_and_run_owner(
                "prepare_task",
                prep_args,
                pre_ms=60,
                queue_ms=500,
                auth_ms=25,
            ),
        )
        assert prep_recovered == prep_first
        assert prep_recovered["delivery_id"] == delivery_id
        assert prep_recovered["snapshot_status"] == "available"
        assert prep_recovered["source_snapshot_id"] == prep_first["source_snapshot_id"]
        assert len(obs.calls) == base_obs_calls
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == base_deliveries
        assert _count_rows(rt.store, "idempotency") == base_idem_count
        assert _read_all_idempotency_rows(rt.store) == base_idem_rows
        assert replay_record_calls == 1
        assert _read_c4_hwm(rt.store) == replayed_wall_str

        # Within-budget recovery on the SAME get_artifact key (60 ms + 500 ms queue wait + 25 ms reconstruct = 85 ms)
        gart_recovered = _expect_ok(
            "get_artifact",
            _submit_and_run_owner(
                "get_artifact",
                gart_args,
                pre_ms=60,
                queue_ms=500,
                reconstruct_ms=25,
            ),
        )
        assert gart_recovered["artifact_id"] == gart_first["artifact_id"]
        assert gart_recovered["revision"] == gart_first["revision"]
        assert gart_recovered["resources"] == gart_first["resources"]
        assert gart_recovered["served_receipt_id"] != receipt_1
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == base_art_results
        assert _count_rows(rt.store, "artifact_send_attempt") == base_send_attempts + 1
        assert _read_all_idempotency_rows(rt.store) == base_idem_rows
        assert replay_record_calls == 2
        assert bridge.reservations.active_count() == 0

        # --- (d) Auth & scope error precedence over local deadline on over-budget cached replay (60 + 50 = 110 ms) ---
        # d.1) Revoked credential on owner MUST return UNAUTHENTICATED even when reconstruct consumed 50 ms!
        t_rev = 500_000 * MS
        mono.set_ns(t_rev)
        normalize_delay_ns = 60 * MS
        sub_revoked = bridge.submit_request("prepare_task", dict(prep_args), token=token_a.token, selected_scope=scope)
        normalize_delay_ns = 0
        assert not sub_revoked.done()

        revoke_proof = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=token_a.principal.owner_id,
            action="credential_revoke",
            subject_id=token_a.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        bridge.revoke_credential(token_a.credential_id, revoke_proof)

        reconstruct_delay_ns = 50 * MS
        assert bridge.process_next_queued(block=False) is True
        reconstruct_delay_ns = 0
        _expect_err("prepare_task", sub_revoked.wait(timeout=2.0), ErrorCode.UNAUTHENTICATED)
        assert replay_record_calls == 2
        assert bridge.reservations.active_count() == 0

        # d.2) Revoked repo grant on owner MUST return NOT_FOUND even when reconstruct consumed 50 ms!
        t_ungrant = 510_000 * MS
        mono.set_ns(t_ungrant)
        normalize_delay_ns = 60 * MS
        sub_ungrant = bridge.submit_request("prepare_task", dict(prep_args), token=token_b.token, selected_scope=scope)
        normalize_delay_ns = 0
        assert not sub_ungrant.done()

        with rt.policy._immediate() as pdb:
            pdb.execute(
                "DELETE FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
                (token_b.principal.principal_id, binding.repo_id),
            )
        bridge.publish_auth_view()

        reconstruct_delay_ns = 50 * MS
        assert bridge.process_next_queued(block=False) is True
        reconstruct_delay_ns = 0
        _expect_err("prepare_task", sub_ungrant.wait(timeout=2.0), ErrorCode.NOT_FOUND)
        assert replay_record_calls == 2
        assert _read_all_idempotency_rows(rt.store) == base_idem_rows
        assert bridge.reservations.active_count() == 0
    finally:
        rt.close()
