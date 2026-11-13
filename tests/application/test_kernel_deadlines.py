"""Task 4b: pre-queue RAM RequestAuthView admission, in-memory reservations, and non-owner deadline arbiter."""

from __future__ import annotations

import datetime as dt
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.clock import SystemClock, SystemMonotonicClock
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.deadlines import (
    AtomicRequestAuthState,
    Reservation,
    ReservationTable,
    enter_commit,
    reserve,
)
from superbrain.application.idempotency import compute_idempotency_key_hash
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    HANDLER_RESERVE_NS,
    LOCAL_PHASE_BUDGET_NS,
    RESPONSE_RESERVE_NS,
    TOTAL_REQUEST_BUDGET_NS,
    AuthSnapshot,
    CallContext,
    CallResult,
    Identity,
    PrivateRequestAuth,
    RequestAuthView,
    RequestDeadlines,
    ReservationPhase,
    ReservationScopeKey,
    Scope,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    StoredResult,
    WorkspaceBinding,
)
from superbrain.core.wire import normalize_call
from superbrain.ports.clock import MonotonicClock
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import KernelIdempotencyStore, StrictKernelStore
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.store import Store
from tests.storage.conftest import StaticPolicy
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FixtureKernelDomain,
    fixture_store_extensions,
    validate_response_envelope,
)
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
)

MS = 1_000_000
_R = TypeVar("_R")
REMOTE_A = "https://github.example/dan/repo-alpha.git"
REMOTE_B = "https://github.example/dan/repo-beta.git"
TREE_A = "sha256:" + "a" * 64
CLOCK_START = dt.datetime(2026, 11, 1, 0, 0, 0, 0, tzinfo=dt.UTC)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(CLOCK_START)


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock)


class FakeMonotonicClock:
    """Thread-safe deterministic high-resolution monotonic clock in nanoseconds."""

    def __init__(self, start_ns: int = 10_000 * MS) -> None:
        self._lock = threading.Lock()
        self._now_ns = start_ns
        self._on_read: Callable[[int], int] | None = None

    def monotonic_ns(self) -> int:
        with self._lock:
            hook = self._on_read
            if hook is not None:
                self._now_ns = hook(self._now_ns)
            return self._now_ns

    def __call__(self) -> int:
        return self.monotonic_ns()

    def advance(self, delta_ns: int) -> int:
        with self._lock:
            self._now_ns += delta_ns
            return self._now_ns

    def set_ns(self, value_ns: int) -> None:
        with self._lock:
            self._now_ns = value_ns

    def set_read_hook(self, hook: Callable[[int], int] | None) -> None:
        with self._lock:
            self._on_read = hook


@dataclass
class RecordingObserver:
    descriptor: SnapshotDescriptor | None = None
    status: SnapshotStatus = SnapshotStatus.AVAILABLE
    advance_ns_on_observe: int = 0
    mono: FakeMonotonicClock | None = None
    calls: list[tuple[WorkspaceBinding, int]] = field(default_factory=list)

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        self.calls.append((binding, deadline_ns))
        if self.mono is not None and self.advance_ns_on_observe:
            self.mono.advance(self.advance_ns_on_observe)
        if self.status is SnapshotStatus.AVAILABLE:
            return SnapshotObservation(SnapshotStatus.AVAILABLE, self.descriptor)
        return SnapshotObservation(self.status, None)


def _desc(tree: str = TREE_A) -> SnapshotDescriptor:
    return SnapshotDescriptor(
        kind="git",
        tree_or_head_digest=tree,
        dirty=False,
        dirty_digest=None,
        observed_at="2026-11-01T00:00:00.000000Z",
    )


def _open_fixture_runtime(root: Path, os_: OsAdapters) -> Runtime:
    handlers, kinds = fixture_store_extensions()
    return open_runtime(
        root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def _register_ws(
    rt: Runtime,
    clock: FakeClock,
    seeded: SeededCredential,
    *,
    alias: str,
    checkout_dir: Path,
    remote: str | None = REMOTE_A,
) -> WorkspaceBinding:
    checkout_dir.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias=alias,
        raw_path=str(checkout_dir),
        raw_remote=remote,
        provider_egress_enabled=False,
    )
    binding = rt.policy.register_authorized_workspace(
        reg,
        make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=seeded.principal.owner_id,
            action="workspace_register",
            subject_id=reg.subject_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        ),
    )
    rt.store.reconcile_policy()
    return binding


def _expect_ok(tool: str, res: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is True, f"expected ok=True for {tool}, got {checked}"
    data = checked["data"]
    assert isinstance(data, dict)
    return data


def _expect_err(tool: str, res: Mapping[str, JsonValue], code: ErrorCode) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is False, f"expected error {code.value} for {tool}, got {checked}"
    err = checked["error"]
    assert isinstance(err, dict)
    assert err["code"] == code.value
    return err


def _count_rows(store: Store, table: str) -> int:
    with store.transaction() as txn:
        row = txn.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


class DedicatedOwnerHarness:
    """Runs ``Runtime`` + ``KernelBridge`` on a dedicated owner thread so request/arbiter threads are non-owner."""

    def __init__(
        self,
        *,
        root_dir: Path,
        checkout_dir: Path,
        os_: OsAdapters,
        clock: FakeClock,
        mono: FakeMonotonicClock,
        max_queue_size: int = 16,
        observer: RecordingObserver | None = None,
        before_enter_commit: Callable[[Reservation | None], None] | None = None,
        on_commit_completed: Callable[[StoredResult], None] | None = None,
    ) -> None:
        self._root_dir = root_dir
        self._checkout_dir = checkout_dir
        self._os = os_
        self._clock = clock
        self._mono = mono
        self._max_queue_size = max_queue_size
        self._observer = observer if observer is not None else RecordingObserver(descriptor=_desc())
        self._before_enter_commit = before_enter_commit
        self._on_commit_completed = on_commit_completed

        self._ready = threading.Event()
        self._stop = False
        self._cv = threading.Condition()
        self._owner_tasks: list[tuple[Callable[[], object], list[object], list[BaseException], threading.Event]] = []
        self._auto_drain = True
        self._startup_err: BaseException | None = None

        self.rt: Runtime
        self.seeded: SeededCredential
        self.binding: WorkspaceBinding
        self.scope: Scope
        self.domain: FixtureKernelDomain
        self.bridge: KernelBridge
        self.owner_thread: threading.Thread | None = None

        self._thread = threading.Thread(target=self._owner_main, name="test-kernel-owner", daemon=True)
        self._thread.start()
        assert self._ready.wait(timeout=10.0), "owner thread failed to initialize"
        if self._startup_err is not None:
            raise self._startup_err

    def _owner_main(self) -> None:
        try:
            self.owner_thread = threading.current_thread()
            self.rt = _open_fixture_runtime(self._root_dir, self._os)
            self.seeded = seed_principal_and_credential(self.rt.policy)
            self.binding = _register_ws(
                self.rt,
                self._clock,
                self.seeded,
                alias="ws-main",
                checkout_dir=self._checkout_dir,
            )
            self.scope = Scope(self.binding.repo_id, self.binding.checkout_id)
            self.domain = FixtureKernelDomain(
                store=self.rt.store,
                policy=self.rt.policy,
                clock=self._clock,
                observer=self._observer,
                monotonic_ns=self._mono.monotonic_ns,
            )
            self.bridge = KernelBridge(
                store=self.rt.store,
                policy=self.rt.policy,
                clock=self._clock,
                monotonic_clock=self._mono,
                writer_epoch=self.rt.lease.epoch,
                domain=self.domain,
                max_queue_size=self._max_queue_size,
                before_enter_commit=self._before_enter_commit,
                on_commit_completed=self._on_commit_completed,
            )
            self.bridge.publish_auth_view()
        except BaseException as exc:  # noqa: BLE001
            self._startup_err = exc
            self._ready.set()
            return

        self._ready.set()
        try:
            while True:
                task_tuple: tuple[Callable[[], object], list[object], list[BaseException], threading.Event] | None = (
                    None
                )
                with self._cv:
                    if self._stop and not self._owner_tasks:
                        break
                    if self._owner_tasks:
                        task_tuple = self._owner_tasks.pop(0)
                    elif not self._auto_drain or self.bridge.queue_depth() == 0:
                        self._cv.wait(timeout=0.005)
                        continue
                if task_tuple is not None:
                    fn, out, err, done = task_tuple
                    try:
                        out.append(fn())
                    except BaseException as exc:  # noqa: BLE001
                        err.append(exc)
                    finally:
                        done.set()
                elif self._auto_drain:
                    self.bridge.process_next_queued(block=False)
        finally:
            self.bridge.arbitrate_deadlines(now_ns=10**18)
            self.rt.close()

    def set_auto_drain(self, enabled: bool) -> None:
        with self._cv:
            self._auto_drain = enabled
            self._cv.notify_all()

    def wake_owner(self) -> None:
        with self._cv:
            self._cv.notify_all()

    def run_on_owner(self, fn: Callable[[], _R]) -> _R:
        assert threading.current_thread() is not self.owner_thread
        out: list[object] = []
        err: list[BaseException] = []
        done = threading.Event()
        with self._cv:
            self._owner_tasks.append((fn, out, err, done))
            self._cv.notify_all()
        assert done.wait(timeout=10.0), "timed out waiting for owner task"
        if err:
            raise err[0]
        return cast(_R, out[0])

    def close(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()
        self._thread.join(timeout=10.0)
        assert not self._thread.is_alive(), "owner thread failed to stop cleanly"


# --- 1. Queue full before start -> store_busy, reservation rolled back, zero Deliveries ------------------------------


def test_queue_full_is_store_busy_before_start(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
            max_queue_size=1,
        )
        bridge.publish_auth_view()

        first_sub = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "occupy single bounded queue slot",
                "idempotency_key": "idem_queue_slot_0001",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert not first_sub.done()
        assert bridge.queue_depth() == 1

        overflow_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "overflow request while queue is full",
            "idempotency_key": "idem_queue_over_0002",
        }
        overflow_key_hash = compute_idempotency_key_hash(
            seeded.principal.principal_id, "prepare_task", "idem_queue_over_0002"
        )
        overflow_scope_key = ReservationScopeKey(seeded.principal.principal_id, "prepare_task", overflow_key_hash)

        overflow_res = bridge.submit_request(
            "prepare_task",
            overflow_args,
            token=seeded.token,
            selected_scope=scope,
        ).wait(timeout=2.0)
        _expect_err("prepare_task", overflow_res, ErrorCode.STORE_BUSY)

        # Reservation MUST be rolled back immediately on queue-full refusal, and zero rows created.
        assert not bridge.reservations.has_active(overflow_scope_key)
        assert domain.prepare_calls == 0
        assert domain.apply_calls == 0
        assert _count_rows(rt.store, "idempotency") == 0
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 0

        # Drain slot 1 on the owner thread, then verify the rolled-back overflow key executes cleanly once.
        assert bridge.process_next_queued(block=False) is True
        _expect_ok("prepare_task", first_sub.wait(timeout=2.0))
        assert bridge.queue_depth() == 0

        retry_sub = bridge.submit_request(
            "prepare_task",
            overflow_args,
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        _expect_ok("prepare_task", retry_sub.wait(timeout=2.0))
        assert _count_rows(rt.store, "idempotency") == 2
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 2
    finally:
        rt.close()


# --- 2. Duplicate & changed-digest respond while owner SQLite commit is blocked --------------------------------------


def test_duplicate_responds_while_owner_commit_is_blocked(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    in_tx_entered = threading.Event()
    release_tx = threading.Event()

    harness = DedicatedOwnerHarness(
        root_dir=trusted_tmp / "root",
        checkout_dir=trusted_tmp / "chk",
        os_=os_,
        clock=clock,
        mono=mono,
    )
    try:

        def _pause_in_tx(_tx: KernelTx) -> None:
            assert harness.rt.store.in_transaction
            in_tx_entered.set()
            assert release_tx.wait(timeout=10.0), "timed out waiting for SQLite commit barrier release"

        harness.domain.before_apply_hook = _pause_in_tx

        req_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "primary blocked commit",
            "idempotency_key": "idem_blocked_commit_01",
        }
        first_sub = harness.bridge.submit_request(
            "prepare_task",
            req_args,
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        assert in_tx_entered.wait(timeout=5.0), "owner never entered SQLite transaction"
        assert first_sub.reservation is not None
        assert first_sub.reservation.phase is ReservationPhase.COMMITTING

        # Same key + same normalized payload -> immediate IN_PROGRESS on request thread while owner is blocked!
        dup_sub = harness.bridge.submit_request(
            "prepare_task",
            dict(req_args),
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        assert dup_sub.done(), "duplicate while owner is blocked must settle synchronously pre-queue"
        _expect_err("prepare_task", dup_sub.wait(timeout=2.0), ErrorCode.IN_PROGRESS)

        # Same key + changed normalized payload -> immediate IDEMPOTENCY_CONFLICT while owner is blocked!
        conflict_args = {**req_args, "description": "mutated payload under same key"}
        conflict_sub = harness.bridge.submit_request(
            "prepare_task",
            conflict_args,
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        assert conflict_sub.done(), "conflict while owner is blocked must settle synchronously pre-queue"
        _expect_err("prepare_task", conflict_sub.wait(timeout=2.0), ErrorCode.IDEMPOTENCY_CONFLICT)

        # Owner is STILL blocked inside SQLite commit.
        assert not first_sub.done()

        release_tx.set()
        first_ok = _expect_ok("prepare_task", first_sub.wait(timeout=5.0))
        assert harness.bridge.reservations.active_count() == 0

        # Durable replay after commit returns identical result without re-running prepare/apply.
        replay_sub = harness.bridge.submit_request(
            "prepare_task",
            dict(req_args),
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        replay_ok = _expect_ok("prepare_task", replay_sub.wait(timeout=5.0))
        assert replay_ok == first_ok
        assert harness.domain.prepare_calls == 1
        assert harness.domain.apply_calls == 1
    finally:
        release_tx.set()
        harness.close()


# --- 3. Expired queued request never prepares, stages, or commits ----------------------------------------------------


def test_expired_queued_request_never_commits(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock(start_ns=1_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        obs = RecordingObserver(descriptor=_desc())
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
            max_queue_size=8,
        )
        bridge.publish_auth_view()

        # Enqueue two requests at t = 1,000 ms (handler deadline = 2,300 ms).
        sub_arbiter_swept = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "swept by arbiter while queued",
                "idempotency_key": "idem_expired_queue_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        sub_owner_claimed = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "expired when owner pops from queue",
                "idempotency_key": "idem_expired_queue_02",
            },
            token=seeded.token,
            selected_scope=scope,
        )

        # Advance past handler deadline (t = 2,300 ms = receive + 1,300 ms) and sweep ONLY via arbiter first.
        mono.set_ns(2_300 * MS)
        settled = bridge.arbitrate_deadlines()
        assert len(settled) == 2
        _expect_err("prepare_task", sub_arbiter_swept.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        _expect_err("prepare_task", sub_owner_claimed.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.reservations.active_count() == 0

        # When owner drains those queued entries later, it never prepares, observes, stages, or commits.
        assert bridge.process_next_queued(block=False) is True
        assert bridge.process_next_queued(block=False) is True
        assert domain.prepare_calls == 0
        assert domain.apply_calls == 0
        assert len(obs.calls) == 0
        assert _count_rows(rt.store, "idempotency") == 0
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 0

        # Also test direct owner claim before arbiter sweep when clock reaches handler_deadline_ns (t + 1,300 ms).
        sub_unswept = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "expired right before owner claims without prior arbiter sweep",
                "idempotency_key": "idem_expired_queue_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        mono.advance(1_300 * MS)
        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", sub_unswept.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert domain.prepare_calls == 0
        assert domain.apply_calls == 0
        assert _count_rows(rt.store, "idempotency") == 0
        assert bridge.reservations.active_count() == 0

        # Fresh submission within deadline with the same key now commits cleanly once.
        sub_fresh = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "fresh within deadline",
                "idempotency_key": "idem_expired_queue_01",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        _expect_ok("prepare_task", sub_fresh.wait(timeout=1.0))
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1
        assert _count_rows(rt.store, "idempotency") == 1
    finally:
        rt.close()


# --- 4. Race between enter_commit(reservation, now_ns) and cancel settles ONE response outside lock ------------------


def test_deadline_racing_enter_commit_has_one_response(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    # Part A: Direct unit race on ReservationTable + enter_commit(reservation, now_ns) under one state lock,
    # verifying lock is NEVER held while on_response (socket write callback) executes.
    table = ReservationTable()
    for iteration in range(25):
        t0 = 10_000 * MS
        deadlines = RequestDeadlines.from_receive_ns(t0)
        delivered: list[CallResult] = []
        lock_held_during_callback: list[bool] = []

        def _on_resp(
            env: CallResult,
            _deliv: list[CallResult] = delivered,
            _held: list[bool] = lock_held_during_callback,
        ) -> None:
            _held.append(table.state_lock_locked())
            _deliv.append(env)

        scope_key = ReservationScopeKey("p-race", "prepare_task", "sha256:" + f"{iteration:064x}")
        res = reserve(
            scope_key,
            "sha256:" + "1" * 64,
            table=table,
            deadlines=deadlines,
            request_digest_key_id="k1",
            on_response=_on_resp,
        )
        assert table.try_claim_for_owner(res, t0 + 10 * MS) is True

        barrier = threading.Barrier(2)
        entered_box: list[bool] = []

        def _owner_try(
            r: Reservation = res,
            d: RequestDeadlines = deadlines,
            box: list[bool] = entered_box,
            b: threading.Barrier = barrier,
            idx: int = iteration,
        ) -> None:
            b.wait(timeout=5.0)
            ok = enter_commit(r, d.handler_deadline_ns - 1)
            box.append(ok)
            if ok:
                table.finish_owner_execution(r, {"ok": True, "data": {"iteration": idx}})
            else:
                table.finish_owner_execution(
                    r, {"ok": False, "error": {"code": "deadline_exceeded", "message": "deadline exceeded"}}
                )

        def _arbiter_cancel(
            r: Reservation = res,
            d: RequestDeadlines = deadlines,
            b: threading.Barrier = barrier,
        ) -> None:
            b.wait(timeout=5.0)
            table.cancel_before_commit(r, d.handler_deadline_ns)

        t_owner = threading.Thread(target=_owner_try)
        t_arb = threading.Thread(target=_arbiter_cancel)
        t_owner.start()
        t_arb.start()
        t_owner.join(timeout=5.0)
        t_arb.join(timeout=5.0)

        assert len(entered_box) == 1
        assert len(delivered) == 1, f"expected exactly 1 settled response, got {delivered}"
        assert lock_held_during_callback == [False], "state lock must NEVER be held inside response callback!"
        if entered_box[0]:
            assert delivered[0]["ok"] is True
        else:
            assert delivered[0]["ok"] is False
            err_obj = delivered[0]["error"]
            assert isinstance(err_obj, dict) and err_obj["code"] == ErrorCode.DEADLINE_EXCEEDED.value
        assert not table.has_active(scope_key)

    # Part B: End-to-end KernelBridge race where arbiter cancels right before enter_commit on the owner thread.
    mono = FakeMonotonicClock(start_ns=50_000 * MS)
    at_enter_commit = threading.Event()
    proceed_enter_commit = threading.Event()

    def _before_enter_commit(_res: Reservation | None) -> None:
        at_enter_commit.set()
        assert proceed_enter_commit.wait(timeout=10.0)

    harness = DedicatedOwnerHarness(
        root_dir=trusted_tmp / "root",
        checkout_dir=trusted_tmp / "chk",
        os_=os_,
        clock=clock,
        mono=mono,
        before_enter_commit=_before_enter_commit,
    )
    try:
        callbacks: list[CallResult] = []
        callback_lock_states: list[bool] = []

        def _record_cb(env: CallResult) -> None:
            callback_lock_states.append(harness.bridge.reservations.state_lock_locked())
            callbacks.append(env)

        sub = harness.bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "paused right before enter_commit",
                "idempotency_key": "idem_race_enter_commit_1",
            },
            token=harness.seeded.token,
            selected_scope=harness.scope,
            on_response=_record_cb,
        )
        harness.wake_owner()
        assert at_enter_commit.wait(timeout=5.0)

        # Advance to handler_deadline_ns (t0 + 1,300 ms) and arbitrate on non-owner thread BEFORE enter_commit runs!
        mono.advance(1_300 * MS)
        harness.bridge.arbitrate_deadlines()

        # Caller receives DEADLINE_EXCEEDED immediately before owner even resumes enter_commit!
        _expect_err("prepare_task", sub.wait(timeout=2.0), ErrorCode.DEADLINE_EXCEEDED)

        proceed_enter_commit.set()
        # Wait briefly via run_on_owner barrier so owner finishes unwinding without starting SQLite commit.
        harness.run_on_owner(lambda: None)

        assert len(callbacks) == 1
        assert callback_lock_states == [False]
        assert harness.domain.prepare_calls == 1
        assert harness.domain.apply_calls == 0
        assert harness.run_on_owner(lambda: _count_rows(harness.rt.store, "idempotency")) == 0
        assert harness.bridge.reservations.active_count() == 0
    finally:
        proceed_enter_commit.set()
        harness.close()


# --- 5. Timeout while committing -> commit_outcome_unknown; reservation held until commit OR rollback finishes -------


def test_commit_continues_after_unknown_response(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock(start_ns=100_000 * MS)
    in_tx = threading.Event()
    release_tx = threading.Event()
    should_rollback = False

    harness = DedicatedOwnerHarness(
        root_dir=trusted_tmp / "root",
        checkout_dir=trusted_tmp / "chk",
        os_=os_,
        clock=clock,
        mono=mono,
    )
    try:

        def _hook(_tx: KernelTx) -> None:
            in_tx.set()
            assert release_tx.wait(timeout=10.0)
            if should_rollback:
                raise BrainError(ErrorCode.IO_ERROR, "I/O error")

        harness.domain.before_apply_hook = _hook

        # --- Case A: Commit finishes durably AFTER commit_outcome_unknown at 1,475 ms ---
        args_commit: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "slow sqlite commit that eventually succeeds",
            "idempotency_key": "idem_unknown_then_commit",
        }
        responses_a: list[CallResult] = []
        sub_a = harness.bridge.submit_request(
            "prepare_task",
            args_commit,
            token=harness.seeded.token,
            selected_scope=harness.scope,
            on_response=responses_a.append,
        )
        harness.wake_owner()
        assert in_tx.wait(timeout=5.0)
        assert sub_a.reservation is not None
        assert sub_a.reservation.phase is ReservationPhase.COMMITTING

        # At t0 + 1,350 ms (>= 1,300 ms handler deadline, < 1,475 ms commit-waiter cutoff), COMMITTING is NOT cut off!
        mono.advance(1_350 * MS)
        assert harness.bridge.arbitrate_deadlines() == ()
        assert not sub_a.done()

        # At t0 + 1,475 ms (commit_waiter_cutoff_ns), arbiter settles COMMIT_OUTCOME_UNKNOWN outside owner thread!
        mono.advance(125 * MS)
        settled_a = harness.bridge.arbitrate_deadlines()
        assert len(settled_a) == 1
        _expect_err("prepare_task", sub_a.wait(timeout=1.0), ErrorCode.COMMIT_OUTCOME_UNKNOWN)

        # Reservation MUST remain active while owner's SQLite commit is still running!
        dup_while_committing = harness.bridge.submit_request(
            "prepare_task",
            dict(args_commit),
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        assert dup_while_committing.done(), "active reservation must reject duplicate synchronously pre-queue"
        _expect_err("prepare_task", dup_while_committing.wait(timeout=2.0), ErrorCode.IN_PROGRESS)
        conflict_while_committing = harness.bridge.submit_request(
            "prepare_task",
            {**args_commit, "description": "changed while committing after unknown"},
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        assert conflict_while_committing.done(), "active reservation must reject conflict synchronously pre-queue"
        _expect_err("prepare_task", conflict_while_committing.wait(timeout=2.0), ErrorCode.IDEMPOTENCY_CONFLICT)

        # Let SQLite commit finish; verify single response invariant and reservation cleanup.
        release_tx.set()
        harness.run_on_owner(lambda: None)
        assert len(responses_a) == 1
        assert harness.bridge.reservations.active_count() == 0

        # Retry now hits durable idempotency row and returns the single committed Delivery/assignment!
        harness.domain.before_apply_hook = None
        replay_a = harness.bridge.submit_request(
            "prepare_task",
            dict(args_commit),
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        ok_a = _expect_ok("prepare_task", replay_a.wait(timeout=5.0))
        assert isinstance(ok_a["delivery_id"], str)
        assert harness.domain.prepare_calls == 1
        assert harness.domain.apply_calls == 1

        # --- Case B: Commit definitively rolls back AFTER commit_outcome_unknown at 1,475 ms ---
        in_tx.clear()
        release_tx.clear()
        should_rollback = True
        harness.domain.before_apply_hook = _hook

        args_rb: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "slow sqlite commit that rolls back",
            "idempotency_key": "idem_unknown_then_rollbk",
        }
        responses_b: list[CallResult] = []
        sub_b = harness.bridge.submit_request(
            "prepare_task",
            args_rb,
            token=harness.seeded.token,
            selected_scope=harness.scope,
            on_response=responses_b.append,
        )
        harness.wake_owner()
        assert in_tx.wait(timeout=5.0)

        mono.advance(1_475 * MS)
        settled_b = harness.bridge.arbitrate_deadlines()
        assert len(settled_b) == 1
        _expect_err("prepare_task", sub_b.wait(timeout=1.0), ErrorCode.COMMIT_OUTCOME_UNKNOWN)

        # Still active before rollback completes!
        dup_rb_sub = harness.bridge.submit_request(
            "prepare_task", dict(args_rb), token=harness.seeded.token, selected_scope=harness.scope
        )
        assert dup_rb_sub.done(), "active reservation must reject duplicate synchronously before rollback finishes"
        _expect_err("prepare_task", dup_rb_sub.wait(timeout=2.0), ErrorCode.IN_PROGRESS)

        # Release barrier -> explicit IO_ERROR rolls back SQLite transaction cleanly; reservation clears.
        release_tx.set()
        harness.run_on_owner(lambda: None)
        assert len(responses_b) == 1
        assert harness.bridge.reservations.active_count() == 0
        assert harness.run_on_owner(lambda: _count_rows(harness.rt.store, "idempotency")) == 1

        # Retry after definitive rollback starts cleanly once and commits!
        should_rollback = False
        harness.domain.before_apply_hook = None
        retry_b = harness.bridge.submit_request(
            "prepare_task",
            dict(args_rb),
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        ok_b = _expect_ok("prepare_task", retry_b.wait(timeout=5.0))
        assert ok_b["delivery_id"] != ok_a["delivery_id"]
        assert harness.run_on_owner(lambda: _count_rows(harness.rt.store, "idempotency")) == 2
        assert harness.run_on_owner(lambda: _count_rows(harness.rt.store, "p_fixture_domain_deliveries")) == 2
    finally:
        release_tx.set()
        harness.close()


# --- 6. Shared <= 100 ms local phase across admission/filter/observer + 1,300/1,475/1,500 ms budgets -----------------


def test_filter_phase_is_bounded_at_100ms(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    # Verify exact D5 / 4b nanosecond constants & derived deadlines.
    assert LOCAL_PHASE_BUDGET_NS == 100 * MS
    assert HANDLER_RESERVE_NS == 200 * MS
    assert RESPONSE_RESERVE_NS == 25 * MS
    assert TOTAL_REQUEST_BUDGET_NS == 1_500 * MS

    t0 = 1_000 * MS
    dl = RequestDeadlines.from_receive_ns(t0)
    assert dl.receive_ns == t0
    assert dl.handler_deadline_ns == t0 + 1_300 * MS
    assert dl.commit_waiter_cutoff_ns == t0 + 1_475 * MS
    assert dl.total_deadline_ns == t0 + 1_500 * MS
    assert dl.response_budget_ns == 25 * MS
    assert dl.local_deadline_ns(t0 + 10 * MS) == t0 + 110 * MS
    assert dl.local_deadline_ns(t0 + 1_250 * MS) == t0 + 1_300 * MS

    mono = FakeMonotonicClock(start_ns=t0)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        obs = RecordingObserver(descriptor=_desc(), mono=mono)
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

        # Case 1: PrivacyFilter scan exceeds the 100 ms local budget -> fails closed with DEADLINE_EXCEEDED,
        # SnapshotObserver is never called, and nothing is committed.
        reads = 0

        def _tick_past_100ms(cur: int) -> int:
            nonlocal reads
            reads += 1
            # Let receive_ns, owner claim, pre-dispatch check, and local_phase_start_ns read t0;
            # then advance 25 ms per monotonic read inside PrivacyFilter until >= t0 + 100 ms!
            if reads >= 5:
                return cur + 25 * MS
            return cur

        mono.set_read_hook(_tick_past_100ms)
        sub_filter_timeout = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "payload whose filter scan crosses 100ms local deadline",
                "idempotency_key": "idem_filter_100ms_0001",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", sub_filter_timeout.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert len(obs.calls) == 0
        assert _count_rows(rt.store, "idempotency") == 0

        # Case 2: Admission + filter consume 60 ms of the shared 100 ms local window; observer receives the EXACT
        # shared local_deadline_ns (start + 100 ms) with only 40 ms remaining, overruns by 50 ms -> snapshot_deadline!
        mono.set_read_hook(None)
        base_ns = 10_000 * MS
        mono.set_ns(base_ns)
        filter_ticks = 0

        def _consume_60ms_before_observer(cur: int) -> int:
            nonlocal filter_ticks
            filter_ticks += 1
            if filter_ticks == 5:
                return cur + 60 * MS
            return cur

        mono.set_read_hook(_consume_60ms_before_observer)
        obs.advance_ns_on_observe = 50 * MS  # 60 ms + 50 ms = 110 ms > 100 ms shared local budget!

        sub_shared = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "admission+filter+observer share single 100ms local window",
                "idempotency_key": "idem_filter_100ms_0002",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        mono.set_read_hook(None)
        ok_shared = _expect_ok("prepare_task", sub_shared.wait(timeout=1.0))
        assert len(obs.calls) == 1
        _observed_binding, passed_local_deadline = obs.calls[0]
        assert passed_local_deadline == base_ns + 100 * MS
        assert ok_shared["snapshot_status"] == "deadline"
        degraded = ok_shared["degraded_codes"]
        assert isinstance(degraded, list) and "snapshot_deadline" in degraded
    finally:
        rt.close()


# --- 7. Production SystemMonotonicClock (time.perf_counter_ns) resolves well under 1 ms on 3.11 & 3.14 ---------------


def test_system_monotonic_clock_resolves_sub_millisecond() -> None:
    real_os = os_adapters()
    assert isinstance(real_os.monotonic, SystemMonotonicClock)
    mono_port: MonotonicClock = real_os.monotonic
    sys_clock = SystemClock()

    t_prev = mono_port.monotonic_ns()
    s_prev = sys_clock.monotonic_ns()
    assert isinstance(t_prev, int) and isinstance(s_prev, int)

    positive_deltas: list[int] = []
    for _ in range(8):
        cur = t_prev
        spins = 0
        while cur == t_prev and spins < 1_000_000:
            cur = mono_port.monotonic_ns()
            spins += 1
        delta = cur - t_prev
        assert delta > 0, "SystemMonotonicClock failed to advance"
        positive_deltas.append(delta)
        t_prev = cur

    # Windows time.monotonic_ns ticks at ~15,625,000 ns (15.6 ms) on 3.11; perf_counter_ns resolves << 1,000,000 ns!
    assert min(positive_deltas) < 1_000_000, f"expected sub-ms resolution (<1,000,000 ns), got {positive_deltas}"


# --- 8. Pre-queue auth & HMAC use ONLY RAM RequestAuthView; missing/foreign view -> policy_unavailable ---------------


def test_prequeue_auth_and_hmac_do_not_call_policy_store_while_owner_is_blocked(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    mono = FakeMonotonicClock()
    in_tx = threading.Event()
    release_tx = threading.Event()

    harness = DedicatedOwnerHarness(
        root_dir=trusted_tmp / "root",
        checkout_dir=trusted_tmp / "chk",
        os_=os_,
        clock=clock,
        mono=mono,
    )
    rt_foreign = _open_fixture_runtime(trusted_tmp / "foreign-root", os_)
    try:

        def _pause_owner(_tx: KernelTx) -> None:
            in_tx.set()
            assert release_tx.wait(timeout=10.0)

        harness.domain.before_apply_hook = _pause_owner

        # Poison PolicyStore methods if ever invoked from a non-owner thread!
        non_owner_policy_calls: list[str] = []
        policy_obj = harness.rt.policy
        for method_name in (
            "resolve_credential",
            "allows",
            "snapshot",
            "request_digest_key",
            "request_digest_key_by_id",
        ):
            orig = getattr(policy_obj, method_name)

            def _guarded(
                *args: object,
                _m: str = method_name,
                _orig: Callable[..., object] = orig,
                **kw: object,
            ) -> object:
                if threading.current_thread() is not harness.owner_thread:
                    non_owner_policy_calls.append(_m)
                    raise AssertionError(f"PolicyStore.{_m} called off owner thread!")
                return _orig(*args, **kw)

            monkeypatch.setattr(policy_obj, method_name, _guarded)

        primary_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "owner blocked in commit",
            "idempotency_key": "idem_ram_only_primary_1",
        }
        sub_1 = harness.bridge.submit_request(
            "prepare_task",
            primary_args,
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        assert in_tx.wait(timeout=5.0)

        # 1) Duplicate & conflict replies complete on request thread using ONLY RAM RequestAuthView!
        _expect_err(
            "prepare_task",
            harness.bridge.call_tool(
                "prepare_task",
                dict(primary_args),
                token=harness.seeded.token,
                selected_scope=harness.scope,
                timeout=2.0,
            ),
            ErrorCode.IN_PROGRESS,
        )
        _expect_err(
            "prepare_task",
            harness.bridge.call_tool(
                "prepare_task",
                {**primary_args, "description": "changed"},
                token=harness.seeded.token,
                selected_scope=harness.scope,
                timeout=2.0,
            ),
            ErrorCode.IDEMPOTENCY_CONFLICT,
        )

        # 2) Bad token & bad scope rejected pre-queue from RAM view without touching PolicyStore!
        _expect_err(
            "prepare_task",
            harness.bridge.call_tool(
                "prepare_task",
                {**primary_args, "idempotency_key": "idem_ram_bad_token_001"},
                token=f"{new_id()}.{'A' * 43}",
                selected_scope=harness.scope,
                timeout=2.0,
            ),
            ErrorCode.UNAUTHENTICATED,
        )
        _expect_err(
            "prepare_task",
            harness.bridge.call_tool(
                "prepare_task",
                {**primary_args, "idempotency_key": "idem_ram_bad_scope_001"},
                token=harness.seeded.token,
                selected_scope=Scope("repo-ungranted", "chk-ungranted"),
                timeout=2.0,
            ),
            ErrorCode.NOT_FOUND,
        )

        # 3) Immutable canonical copy (C3:92): mutating caller's dict after submit cannot affect HMAC or execution,
        # and repr(queued) hides both bearer token and argument text!
        secret_marker = "immutable-caller-payload-marker"
        mutable_caller_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": secret_marker,
            "idempotency_key": "idem_immutable_copy_001",
        }
        sub_mut = harness.bridge.submit_request(
            "prepare_task",
            mutable_caller_args,
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        assert sub_mut.queued is not None
        queued_repr = repr(sub_mut.queued)
        assert harness.seeded.token not in queued_repr
        assert secret_marker not in queued_repr
        mutable_caller_args["description"] = "MUTATED_BY_CALLER_AFTER_ENQUEUE"

        # 4) Unavailable RequestAuthView refuses with POLICY_UNAVAILABLE (never STORE_BUSY) while owner is blocked!
        harness.bridge.clear_auth_view()
        _expect_err(
            "prepare_task",
            harness.bridge.call_tool(
                "prepare_task",
                {**primary_args, "idempotency_key": "idem_missing_view_0001"},
                token=harness.seeded.token,
                selected_scope=harness.scope,
                timeout=2.0,
            ),
            ErrorCode.POLICY_UNAVAILABLE,
        )

        # 5) Cross-root RequestAuthView is rejected by store-bound AtomicRequestAuthState!
        foreign_snap = rt_foreign.policy.snapshot()
        fk_id, fk_bytes = rt_foreign.policy.request_digest_key()
        foreign_view = RequestAuthView(
            version=99,
            auth=foreign_snap,
            active_request_key_id=fk_id,
            active_request_key_bytes=fk_bytes,
        )
        assert sub_1.queued is not None
        state = AtomicRequestAuthState(sub_1.queued.store_id)
        with pytest.raises(BrainError) as foreign_exc:
            state.install(foreign_view)
        assert foreign_exc.value.code is ErrorCode.INTEGRITY_FAILURE
        assert state.current() is None

        assert non_owner_policy_calls == []

        # Unblock owner so sub_1 and sub_mut complete; verify sub_mut committed with original unmutated payload!
        harness.domain.before_apply_hook = None
        release_tx.set()
        _expect_ok("prepare_task", sub_1.wait(timeout=5.0))
        ok_mut = _expect_ok("prepare_task", sub_mut.wait(timeout=5.0))

        harness.run_on_owner(harness.bridge.publish_auth_view)
        # Replay with original description matches HMAC; mutated description conflicts!
        replay_orig = harness.bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": secret_marker,
                "idempotency_key": "idem_immutable_copy_001",
            },
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        assert _expect_ok("prepare_task", replay_orig.wait(timeout=5.0)) == ok_mut

        replay_tampered = harness.bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "MUTATED_BY_CALLER_AFTER_ENQUEUE",
                "idempotency_key": "idem_immutable_copy_001",
            },
            token=harness.seeded.token,
            selected_scope=harness.scope,
        )
        harness.wake_owner()
        _expect_err("prepare_task", replay_tampered.wait(timeout=5.0), ErrorCode.IDEMPOTENCY_CONFLICT)
    finally:
        release_tx.set()
        rt_foreign.close()
        harness.close()


# --- 9. Owner rechecks actual credential when another token of same principal remains active -------------------------


def test_owner_rechecks_actual_credential_when_another_token_of_principal_is_active(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        token_a = seed_principal_and_credential(rt.policy, principal_id="p-shared", owner_id="dan")
        # Issue a second active credential (token B) for the EXACT same Principal!
        token_b = seed_principal_and_credential(
            rt.policy,
            principal_id=token_a.principal.principal_id,
            owner_id=token_a.principal.owner_id,
            harness_id=token_a.principal.harness_id,
            machine_id=token_a.principal.machine_id,
        )
        binding = _register_ws(rt, clock, token_a, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)

        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
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
        v_initial = bridge.publish_auth_view()

        req_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "queued under token A before token A revocation",
            "idempotency_key": "idem_actual_cred_0001",
        }

        # Enqueue with token A while token A is still active in v_initial.
        queued_a = bridge.submit_request(
            "prepare_task",
            req_args,
            token=token_a.token,
            selected_scope=scope,
        )
        assert not queued_a.done()

        # Revoke token A through KernelBridge's owner mutation/publication seam BEFORE owner claims queued_a!
        revoke_proof = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=token_a.principal.owner_id,
            action="credential_revoke",
            subject_id=token_a.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        bridge.revoke_credential(token_a.credential_id, revoke_proof)

        # Seam MUST install updated RequestAuthView BEFORE acknowledgment!
        v_after_revoke = bridge.auth_state.current()
        assert v_after_revoke is not None
        assert v_after_revoke.version > v_initial.version
        assert v_after_revoke.auth.credentials[token_a.credential_id].revoked is True
        assert v_after_revoke.auth.credentials[token_b.credential_id].revoked is False
        # Principal STILL has active token B, so principal-level allows() is True:
        assert rt.policy.allows(token_a.principal, scope, action="prepare_task") is True

        # New pre-queue submission with revoked token A is immediately rejected from the updated RAM view!
        _expect_err(
            "prepare_task",
            bridge.submit_request(
                "prepare_task",
                {**req_args, "idempotency_key": "idem_new_after_revoke_1"},
                token=token_a.token,
                selected_scope=scope,
            ).wait(timeout=1.0),
            ErrorCode.UNAUTHENTICATED,
        )

        # Owner claims the ALREADY-QUEUED request for token A -> live actual-credential recheck MUST fail!
        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", queued_a.wait(timeout=1.0), ErrorCode.UNAUTHENTICATED)
        assert domain.prepare_calls == 0
        assert domain.apply_calls == 0
        assert _count_rows(rt.store, "idempotency") == 0
        assert bridge.reservations.active_count() == 0

        # Active token B executes the operation cleanly once -> commits principal-scoped row.
        sub_b = bridge.submit_request(
            "prepare_task",
            req_args,
            token=token_b.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        first_ok = _expect_ok("prepare_task", sub_b.wait(timeout=1.0))
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1

        # Newly issued rotated token C for the same principal (published via apply_policy_mutation) replays that row!
        token_c = bridge.apply_policy_mutation(
            lambda pol: seed_principal_and_credential(
                pol,
                principal_id=token_a.principal.principal_id,
                owner_id=token_a.principal.owner_id,
                harness_id=token_a.principal.harness_id,
                machine_id=token_a.principal.machine_id,
            )
        )
        sub_c = bridge.submit_request(
            "prepare_task",
            req_args,
            token=token_c.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        replay_ok = _expect_ok("prepare_task", sub_c.wait(timeout=1.0))
        assert replay_ok == first_ok
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
    finally:
        rt.close()


# --- 10. I2-T4A-N01: Low-level StrictKernelStore / KernelIdempotencyStore infer PolicyStore & reject split -----------


def test_i2_t4a_n01_strict_store_infers_policy_store_and_rejects_split_authority(
    trusted_tmp: Path, os_: OsAdapters
) -> None:
    rt_a = _open_fixture_runtime(trusted_tmp / "root-a", os_)
    rt_b = _open_fixture_runtime(trusted_tmp / "root-b", os_)
    try:
        # 1) Omitting policy_store= when policy_view is a foreign PolicyStore auto-infers & rejects cross-root!
        with pytest.raises(BrainError) as exc_inferred:
            StrictKernelStore(rt_a.store, rt_b.policy)
        assert exc_inferred.value.code is ErrorCode.INTEGRITY_FAILURE

        # 2) Passing split concrete PolicyStore instances (policy_view != policy_store) is rejected!
        with pytest.raises(BrainError) as exc_split_strict:
            StrictKernelStore(rt_a.store, rt_b.policy, policy_store=rt_a.policy)
        assert exc_split_strict.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_split_idem:
            KernelIdempotencyStore(rt_a.store, rt_a.policy, policy_view=rt_b.policy)
        assert exc_split_idem.value.code is ErrorCode.INTEGRITY_FAILURE

        # 3) Pure non-PolicyStore PolicyView still enforces writer_epoch on verify_live_store_handle!
        static_view = StaticPolicy(store_id=rt_a.store.store_id)
        with pytest.raises(BrainError) as exc_epoch:
            StrictKernelStore(rt_a.store, static_view, writer_epoch=rt_a.lease.epoch + 1)
        assert exc_epoch.value.code is ErrorCode.INTEGRITY_FAILURE
    finally:
        rt_b.close()
        rt_a.close()


# --- 11. SDD R1 Finding #1: Fault-isolated on_response callbacks across arbiter, owner, and submit -------------------


def test_r1_response_callback_exceptions_isolated_across_arbiter_owner_and_submit(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = FakeMonotonicClock(start_ns=1_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
            max_queue_size=4,
        )
        bridge.publish_auth_view()

        def _broken_pipe(_env: CallResult) -> None:
            raise BrokenPipeError("simulated disconnected client socket")

        sibling_callbacks: list[CallResult] = []

        # 1) Arbiter sweep: item 0's callback raises BrokenPipeError; item 1 MUST still wake & receive its callback!
        sub_0 = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "item 0 broken pipe on arbitrate",
                "idempotency_key": "idem_r1_cb_arb_000001",
            },
            token=seeded.token,
            selected_scope=scope,
            on_response=_broken_pipe,
        )
        sub_1 = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "item 1 sibling must not be stranded",
                "idempotency_key": "idem_r1_cb_arb_000002",
            },
            token=seeded.token,
            selected_scope=scope,
            on_response=sibling_callbacks.append,
        )

        mono.advance(1_300 * MS)
        settled = bridge.arbitrate_deadlines()
        assert len(settled) == 2
        _expect_err("prepare_task", sub_0.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        _expect_err("prepare_task", sub_1.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert len(sibling_callbacks) == 1
        _expect_err("prepare_task", sibling_callbacks[0], ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.process_next_queued(block=False) is True
        assert bridge.process_next_queued(block=False) is True

        # 2) Pre-queue error callback raising BrokenPipeError inside submit() MUST NOT escape submit()!
        prequeue_err_sub = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "bad token with broken pipe callback",
                "idempotency_key": "idem_r1_cb_pre_000003",
            },
            token=f"{new_id()}.{'A' * 43}",
            selected_scope=scope,
            on_response=_broken_pipe,
        )
        assert prequeue_err_sub.done()
        _expect_err("prepare_task", prequeue_err_sub.wait(timeout=1.0), ErrorCode.UNAUTHENTICATED)

        # 3) try_claim_for_owner expired callback raising BrokenPipeError MUST NOT crash process_next_queued()!
        sub_claim_exp = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "expired at owner claim with broken pipe callback",
                "idempotency_key": "idem_r1_cb_clm_000004",
            },
            token=seeded.token,
            selected_scope=scope,
            on_response=_broken_pipe,
        )
        mono.advance(1_300 * MS)
        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", sub_claim_exp.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)

        # 4) finish_owner_execution callback raising BrokenPipeError MUST NOT crash process_next_queued()!
        sub_finish = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "normal commit finish with broken pipe callback",
                "idempotency_key": "idem_r1_cb_fin_000005",
            },
            token=seeded.token,
            selected_scope=scope,
            on_response=_broken_pipe,
        )
        assert bridge.process_next_queued(block=False) is True
        _expect_ok("prepare_task", sub_finish.wait(timeout=1.0))
        assert bridge.reservations.active_count() == 0

        # 5) cancel_before_commit callback raising BrokenPipeError MUST NOT escape cancel_before_commit()!
        table = ReservationTable()
        dl = RequestDeadlines.from_receive_ns(mono.monotonic_ns())
        res_cancel = reserve(
            ReservationScopeKey(seeded.principal.principal_id, "prepare_task", "sha256:" + "9" * 64),
            "sha256:" + "8" * 64,
            table=table,
            deadlines=dl,
            request_digest_key_id="k1",
            on_response=_broken_pipe,
        )
        assert table.cancel_before_commit(res_cancel, dl.handler_deadline_ns) is True
        settled_cancel = res_cancel.wait_response(timeout=1.0)
        assert settled_cancel is not None
        _expect_err("prepare_task", settled_cancel, ErrorCode.DEADLINE_EXCEEDED)
    finally:
        rt.close()


# --- 12. SDD R1 Finding #2: Pre-queue & owner scope/selector authorization symmetry (IDENTITY_MISMATCH / grant) ------


def test_r1_prequeue_and_owner_scope_selector_authorization_symmetry(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    mono = FakeMonotonicClock(start_ns=5_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        dan_box1 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="box-1")
        dan_box2 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="box-2")
        ws_box1 = _register_ws(
            rt, clock, dan_box1, alias="ws-same", checkout_dir=trusted_tmp / "chk-b1", remote=REMOTE_A
        )
        _register_ws(rt, clock, dan_box2, alias="ws-box2", checkout_dir=trusted_tmp / "chk-b2", remote=REMOTE_A)
        ws_beta = _register_ws(
            rt, clock, dan_box1, alias="ws-beta", checkout_dir=trusted_tmp / "chk-beta", remote=REMOTE_B
        )

        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
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

        wrong_machine_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws_box1.repo_id,
            "checkout_id": ws_box1.checkout_id,
            "description": "dan_box2 targeting dan_box1 checkout on same repo",
            "idempotency_key": "idem_r1_wrong_mach_001",
        }

        # 1) Wrong-machine checkout on same owner + granted repo MUST return IDENTITY_MISMATCH ("identity mismatch")
        #    BOTH pre-queue (selected_scope=None and Scope(repo_id, None)) AND on direct owner dispatch!
        for sel_scope in (None, Scope(ws_box1.repo_id, None)):
            sub_wm = bridge.submit_request(
                "prepare_task",
                wrong_machine_args,
                token=dan_box2.token,
                selected_scope=sel_scope,
            )
            assert sub_wm.done(), "wrong-machine checkout must be rejected pre-queue"
            wm_err = _expect_err("prepare_task", sub_wm.wait(timeout=1.0), ErrorCode.IDENTITY_MISMATCH)
            assert wm_err["message"] == "identity mismatch"

            direct_call = normalize_call(
                "prepare_task",
                wrong_machine_args,
                dan_box2.principal,
                selected_scope=sel_scope,
            )
            direct_ctx = CallContext(
                principal=dan_box2.principal,
                identity=Identity(store_id=rt.store.store_id, writer_epoch=rt.lease.epoch, instance_id="inst-r1"),
                deadline_ns=mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
                selected_scope=sel_scope,
            )
            direct_auth = PrivateRequestAuth(
                credential_id=dan_box2.credential_id,
                principal=dan_box2.principal,
                token=dan_box2.token,
            )
            direct_err = _expect_err(
                "prepare_task",
                bridge.dispatch(direct_call, direct_ctx, auth=direct_auth),
                ErrorCode.IDENTITY_MISMATCH,
            )
            assert direct_err["message"] == "identity mismatch"

        # 2) Mismatched selected_scope (repo A) + arguments.workspace_id (repo B) rejected pre-queue with NOT_FOUND!
        sub_mismatch = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_beta.repo_id,
                "checkout_id": ws_beta.checkout_id,
                "description": "selected_scope repo_a vs arguments repo_b",
                "idempotency_key": "idem_r1_scope_mis_0002",
            },
            token=dan_box1.token,
            selected_scope=Scope(ws_box1.repo_id, None),
        )
        assert sub_mismatch.done()
        _expect_err("prepare_task", sub_mismatch.wait(timeout=1.0), ErrorCode.NOT_FOUND)
        assert bridge.queue_depth() == 0

        # 3) Fresh uncached ambiguous workspace_hint is NOT resolved pre-queue: it enqueues cleanly and settles
        #    REVISION_CONFLICT on owner execution via resolve_binding!
        base_snap = rt.policy.snapshot()
        dup_checkouts = dict(base_snap.checkouts)
        dup_checkouts["chk-ambig-twin"] = WorkspaceBinding(
            owner_id=dan_box1.principal.owner_id,
            repo_id=ws_beta.repo_id,
            checkout_id="chk-ambig-twin",
            machine_id=dan_box1.principal.machine_id,
            alias="ws-same",
            checkout_path=str(trusted_tmp / "chk-beta"),
        )
        ambig_snap = AuthSnapshot(
            store_id=base_snap.store_id,
            trust_generation=base_snap.trust_generation,
            credentials=base_snap.credentials,
            principals=base_snap.principals,
            repo_policies=base_snap.repo_policies,
            grants=base_snap.grants,
            checkouts=dup_checkouts,
        )
        ambig_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-same",
            "description": "ambiguous workspace_hint across two repos on box-1",
            "idempotency_key": "idem_r1_ambig_hint_003",
        }
        with monkeypatch.context() as mp:
            mp.setattr(rt.policy, "snapshot", lambda: ambig_snap)
            bridge.publish_auth_view()
            sub_ambig = bridge.submit_request(
                "prepare_task",
                ambig_args,
                token=dan_box1.token,
                selected_scope=None,
            )
            assert not sub_ambig.done(), "mutable workspace_hint must defer resolution until owner cache miss"
            assert bridge.process_next_queued(block=False) is True
            ambig_err = _expect_err("prepare_task", sub_ambig.wait(timeout=1.0), ErrorCode.REVISION_CONFLICT)
            assert ambig_err["message"] == "revision conflict"
        bridge.publish_auth_view()

        # 4) Owner recheck symmetry when selected_scope=None: enqueue valid request for ws_beta, then revoke
        #    repo_grant on ws_beta BEFORE owner claims -> owner rejects in _verify_owner_auth_and_scope BEFORE
        #    lookup_for_owner / prepare_mutation!
        prep_calls_before = domain.prepare_calls
        queued_beta = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_beta.repo_id,
                "checkout_id": ws_beta.checkout_id,
                "description": "grant revoked while queued with selected_scope=None",
                "idempotency_key": "idem_r1_revoke_grant_4",
            },
            token=dan_box1.token,
            selected_scope=None,
        )
        assert not queued_beta.done()
        with rt.policy._immediate() as pdb:
            pdb.execute(
                "DELETE FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
                (dan_box1.principal.principal_id, ws_beta.repo_id),
            )
        bridge.publish_auth_view()

        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", queued_beta.wait(timeout=1.0), ErrorCode.NOT_FOUND)
        assert domain.prepare_calls == prep_calls_before
        assert domain.apply_calls == 0
    finally:
        rt.close()


# --- 13. SDD R1 Finding #3: Already-expired receive_ns rejected before reserving scope_key or enqueueing -------------


def test_r1_already_expired_receive_ns_rejected_before_reserve_or_queue(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = FakeMonotonicClock(start_ns=10_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(binding.repo_id, binding.checkout_id)
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
            monotonic_ns=mono.monotonic_ns,
        )
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt.lease.epoch,
            domain=domain,
            max_queue_size=1,
        )
        bridge.publish_auth_view()

        # 1) Non-full queue: already-expired receive_ns settles synchronously as DEADLINE_EXCEEDED without queueing!
        exp_key = "idem_r1_expired_recv_1"
        exp_scope_key = ReservationScopeKey(
            seeded.principal.principal_id,
            "prepare_task",
            compute_idempotency_key_hash(seeded.principal.principal_id, "prepare_task", exp_key),
        )
        sub_exp = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "already expired at submit time",
                "idempotency_key": exp_key,
            },
            token=seeded.token,
            selected_scope=scope,
            receive_ns=mono.monotonic_ns() - 1_300 * MS,
        )
        assert sub_exp.done()
        _expect_err("prepare_task", sub_exp.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert bridge.queue_depth() == 0
        assert not bridge.reservations.has_active(exp_scope_key)

        # Auth error STILL takes precedence over expired receive_ns!
        sub_bad_auth = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "unauthenticated + expired receive_ns",
                "idempotency_key": "idem_r1_expired_auth_2",
            },
            token=f"{new_id()}.{'A' * 43}",
            selected_scope=scope,
            receive_ns=mono.monotonic_ns() - 2_000 * MS,
        )
        assert sub_bad_auth.done()
        _expect_err("prepare_task", sub_bad_auth.wait(timeout=1.0), ErrorCode.UNAUTHENTICATED)

        # 2) Full queue (max_queue_size=1): already-expired receive_ns MUST return DEADLINE_EXCEEDED (never STORE_BUSY)!
        slot_filler = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "occupy bounded queue slot",
                "idempotency_key": "idem_r1_slot_filler_03",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert not slot_filler.done()
        assert bridge.queue_depth() == 1

        sub_exp_full = bridge.submit_request(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "already expired when queue is full",
                "idempotency_key": exp_key,
            },
            token=seeded.token,
            selected_scope=scope,
            receive_ns=mono.monotonic_ns() - 1_300 * MS,
        )
        assert sub_exp_full.done()
        _expect_err("prepare_task", sub_exp_full.wait(timeout=1.0), ErrorCode.DEADLINE_EXCEEDED)
        assert not bridge.reservations.has_active(exp_scope_key)
    finally:
        rt.close()


# --- 14. SDD R1 Finding #5: AtomicRequestAuthState.install rejects non-monotonic version -----------------------------


def test_r1_atomic_auth_state_rejects_non_monotonic_version(trusted_tmp: Path, os_: OsAdapters) -> None:
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        snap = rt.policy.snapshot()
        key_id, key_bytes = rt.policy.request_digest_key()
        state = AtomicRequestAuthState(rt.store.store_id)

        v5 = RequestAuthView(version=5, auth=snap, active_request_key_id=key_id, active_request_key_bytes=key_bytes)
        assert state.install(v5) is v5
        assert state.current() is v5

        # Same version (5) and older version (4) MUST fail closed with INTEGRITY_FAILURE without overwriting v5!
        for stale_ver in (5, 4):
            stale_view = RequestAuthView(
                version=stale_ver,
                auth=snap,
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
            with pytest.raises(BrainError) as exc_stale:
                state.install(stale_view)
            assert exc_stale.value.code is ErrorCode.INTEGRITY_FAILURE
            assert state.current() is v5

        # Strictly higher version (6) installs cleanly!
        v6 = RequestAuthView(version=6, auth=snap, active_request_key_id=key_id, active_request_key_bytes=key_bytes)
        assert state.install(v6) is v6
        assert state.current() is v6
    finally:
        rt.close()


# --- 15. SDD R2: Mutable workspace_hint deferred to cache miss (preserves replay & IDEMPOTENCY_CONFLICT) -------------


def test_r2_workspace_hint_replay_and_conflict_not_short_circuited_prequeue(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    mono = FakeMonotonicClock(start_ns=8_000 * MS)
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        dan_box1 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="box-1")
        ws_box1 = _register_ws(
            rt, clock, dan_box1, alias="ws-same", checkout_dir=trusted_tmp / "chk-b1", remote=REMOTE_A
        )
        ws_beta = _register_ws(
            rt, clock, dan_box1, alias="ws-beta", checkout_dir=trusted_tmp / "chk-beta", remote=REMOTE_B
        )
        scope_box1 = Scope(ws_box1.repo_id, ws_box1.checkout_id)

        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            observer=RecordingObserver(descriptor=_desc()),
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

        hint_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-same",
            "description": "commit delivery under mutable workspace_hint",
            "idempotency_key": "k_hint_replay_0001",
        }
        changed_missing_hint_args: dict[str, JsonValue] = {
            **hint_args,
            "workspace_hint": "missing-hint-99",
        }

        # 1) Enqueue k_hint_replay_0001 -> while active in ReservationTable, retrying the same key with a changed
        #    nonexistent workspace_hint MUST return IDEMPOTENCY_CONFLICT pre-queue (never NOT_FOUND)!
        sub_initial = bridge.submit_request(
            "prepare_task",
            hint_args,
            token=dan_box1.token,
            selected_scope=scope_box1,
        )
        assert not sub_initial.done()

        sub_active_conflict = bridge.submit_request(
            "prepare_task",
            changed_missing_hint_args,
            token=dan_box1.token,
            selected_scope=scope_box1,
        )
        assert sub_active_conflict.done()
        _expect_err("prepare_task", sub_active_conflict.wait(timeout=1.0), ErrorCode.IDEMPOTENCY_CONFLICT)

        # Execute and commit Delivery D1 on ws_box1.
        assert bridge.process_next_queued(block=False) is True
        committed_d1 = _expect_ok("prepare_task", sub_initial.wait(timeout=1.0))
        assert committed_d1["checkout_id"] == ws_box1.checkout_id
        assert domain.apply_calls == 1

        # 2) Make "ws-same" ambiguous across checkouts in AuthSnapshot while ws_box1 remains registered & granted:
        #    replaying k_hint_replay_0001 MUST still return ok=True with identical Delivery D1!
        base_snap = rt.policy.snapshot()
        dup_checkouts = dict(base_snap.checkouts)
        dup_checkouts["chk-ambig-twin"] = WorkspaceBinding(
            owner_id=dan_box1.principal.owner_id,
            repo_id=ws_beta.repo_id,
            checkout_id="chk-ambig-twin",
            machine_id=dan_box1.principal.machine_id,
            alias="ws-same",
            checkout_path=str(trusted_tmp / "chk-beta"),
        )
        ambig_snap = AuthSnapshot(
            store_id=base_snap.store_id,
            trust_generation=base_snap.trust_generation,
            credentials=base_snap.credentials,
            principals=base_snap.principals,
            repo_policies=base_snap.repo_policies,
            grants=base_snap.grants,
            checkouts=dup_checkouts,
        )
        with monkeypatch.context() as mp:
            mp.setattr(rt.policy, "snapshot", lambda: ambig_snap)
            bridge.publish_auth_view()
            sub_replay_ambig = bridge.submit_request(
                "prepare_task",
                hint_args,
                token=dan_box1.token,
                selected_scope=scope_box1,
            )
            assert not sub_replay_ambig.done()
            assert bridge.process_next_queued(block=False) is True
            assert _expect_ok("prepare_task", sub_replay_ambig.wait(timeout=1.0)) == committed_d1

        # 3) Repoint "ws-same" to ws_beta AND rename ws_box1's alias in policy while ws_box1 stays registered & granted:
        #    replaying k_hint_replay_0001 with selected_scope=scope_box1 STILL replays identical Delivery D1!
        with rt.policy._immediate() as pdb:
            pdb.execute(
                "UPDATE workspace_checkout SET alias = 'ws-renamed' WHERE checkout_id = ?", (ws_box1.checkout_id,)
            )
            pdb.execute("UPDATE workspace_checkout SET alias = 'ws-same' WHERE checkout_id = ?", (ws_beta.checkout_id,))
        bridge.publish_auth_view()

        sub_replay_repointed = bridge.submit_request(
            "prepare_task",
            hint_args,
            token=dan_box1.token,
            selected_scope=scope_box1,
        )
        assert not sub_replay_repointed.done()
        assert bridge.process_next_queued(block=False) is True
        assert _expect_ok("prepare_task", sub_replay_repointed.wait(timeout=1.0)) == committed_d1
        assert domain.apply_calls == 1

        # 4) Retrying committed k_hint_replay_0001 with a changed nonexistent hint ("missing-hint-99") MUST return
        #    IDEMPOTENCY_CONFLICT (never NOT_FOUND)!
        sub_committed_conflict = bridge.submit_request(
            "prepare_task",
            changed_missing_hint_args,
            token=dan_box1.token,
            selected_scope=scope_box1,
        )
        assert not sub_committed_conflict.done()
        assert bridge.process_next_queued(block=False) is True
        _expect_err("prepare_task", sub_committed_conflict.wait(timeout=1.0), ErrorCode.IDEMPOTENCY_CONFLICT)
    finally:
        rt.close()
