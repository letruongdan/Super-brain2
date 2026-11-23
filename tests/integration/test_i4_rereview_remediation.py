"""Independent RED oracle for SP1 increment 4 re-review findings I4-R2-01, I4-R2-02, I4-R2-03 (review 2026-11-23).

Requirement source: ``docs/reviews/2026-11-23-sp1-increment4-rereview-09d34c0.md``.

Invariants under test:
- I4-R2-01: an operator ``doctor --fix`` store-writing action (reconcile_policy, rebuild_projections, replay_outbox)
  must still be valid at the moment it starts executing on the owner thread. A task already queued on the owner must
  not start writing once the request cutoff/deadline passed, the daemon is shutting down, or the operator credential
  was revoked.
- I4-R2-02: a doctor report comparing store.db and policy.db comes from one consistent pair of snapshots, or is
  downgraded/retried; it never mixes two states that never coexisted.
- I4-R2-03: ``native_verified=True`` / ``m1_ready=True`` need native evidence bound to the running platform, host,
  host_version, config_digest and the registered checkout scope of the run; missing or unresolvable data fails closed.
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import superbrain.storage.backup as storage_backup
from superbrain.application.owner_loop import OwnerLoop
from superbrain.composition import daemon_entry
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.core._kernel_approval import CLI_HARNESS_ID, Layer2State
from superbrain.core._kernel_deadlines import OPERATOR_REQUEST_BUDGET_NS
from superbrain.core.canonical import digest_bytes
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    CaptureDoctorSnapshot,
    CaptureHarnessDoctorStatus,
    DoctorSnapshot,
    OutboxReplayResult,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_jobs import (
    BOUND_WAIT_S,
    MACHINE_ID,
    OWNER_DAN,
    _base_utc_now,
    _init_doctor_root,
    _ro_db,
)
from tests.integration.test_doctor_sp2_probes import (
    _apply_clean_bootstrap,
    _init_store_with_tls,
    _sp2_mod,
)
from tests.integration.test_i4_owner_thread_remediation import _is_under, _post_operator
from tests.integration.test_i4_review_remediation import _run_online_restore_helper
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

OWNER_THREAD_NAME = "superbrain-owner-loop"
DOCTOR_WORKER_PREFIX = "doctor-worker-"
STORE_ACTIONS = ["reconcile_policy", "rebuild_projections", "replay_outbox"]
CLIENT_THREAD = "i4-r2-client"
MIXED_MARKER = "i4_r2_snapshot_between_copies_marker"


# ---------------------------------------------------------------------------
# Shared harness
# ---------------------------------------------------------------------------


class _CountingOutbox:
    """Fake SP2 ``OutboxReplayPort``: each call is one observable replay side effect."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls = 0

    def replay_outbox(self, *, now: datetime) -> OutboxReplayResult:
        _ = now
        with self._lock:
            self.calls += 1
            n = self.calls
        return OutboxReplayResult(
            status="applied",
            replayed_events=1,
            committed_event_sequences=(n,),
            contiguous_event_acked_through=n,
            pending_remaining=0,
        )


@dataclass
class _Daemon:
    ready: Any
    loop: OwnerLoop
    stop_ev: threading.Event
    thread: threading.Thread
    rt_box: list[Any] = field(default_factory=list)

    @property
    def rt(self) -> Any:
        return self.rt_box[0]


@contextlib.contextmanager
def _serve(
    cfg: Any, *, os_: OsAdapters, clock: FakeClock, mono: FakeMonotonicClock, outbox: _CountingOutbox | None = None
) -> Iterator[_Daemon]:
    """``_running_serve`` plus the live runtime (``before_job_recover``) and an attached ``OutboxReplayPort``."""
    ready_ev = threading.Event()
    stop_ev = threading.Event()
    box: dict[str, Any] = {}
    rt_box: list[Any] = []
    exits: list[int] = []

    def _on_ready(ready: Any, loop: OwnerLoop) -> None:
        box["ready"], box["loop"] = ready, loop
        ready_ev.set()

    def _bg() -> None:
        exits.append(
            daemon_entry.serve(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
                hooks=DaemonTestHooks(before_job_recover=rt_box.append),
                outbox_replay=outbox,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-r2-serve", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve() did not become ready (exits={exits})"
        yield _Daemon(box["ready"], cast(OwnerLoop, box["loop"]), stop_ev, thr, rt_box)
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve thread leaked"


class _OwnerHold:
    """Spy on ``OwnerLoop.run_owner_action``: when a request thread submits its 2nd owner action (the first one after
    fix phase 1, i.e. the store action), queue a task that holds the owner thread, then ``before_action`` (optional,
    e.g. a revocation), then the store action itself, and signal ``enqueued``."""

    def __init__(self, before_action: Callable[[], None] | None = None) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._fired = False
        self.armed = False
        self.before_action = before_action
        self.held = threading.Event()
        self.release = threading.Event()
        self.enqueued = threading.Event()

    def _hold(self) -> None:
        self.held.set()
        self.release.wait(timeout=BOUND_WAIT_S * 3)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        orig = OwnerLoop.run_owner_action
        spy = self

        def _wrapped(loop_self: OwnerLoop, action: Any, *args: Any, **kwargs: Any) -> Any:
            cur = threading.current_thread()
            if (
                not spy.armed
                or cur is threading.main_thread()
                or cur.name == OWNER_THREAD_NAME
                or cur.name.startswith((DOCTOR_WORKER_PREFIX, CLIENT_THREAD))
            ):
                return orig(loop_self, action, *args, **kwargs)
            with spy._lock:
                n = spy._counts[cur.name] = spy._counts.get(cur.name, 0) + 1
                fire = n == 2 and not spy._fired
                if fire:
                    spy._fired = True
            if not fire:
                return orig(loop_self, action, *args, **kwargs)
            orig(loop_self, spy._hold)
            if spy.before_action is not None:
                spy.before_action()
            fut = orig(loop_self, action, *args, **kwargs)
            spy.armed = False
            spy.enqueued.set()
            return fut

        monkeypatch.setattr(OwnerLoop, "run_owner_action", _wrapped)


class _StoreSideEffects:
    """Observable side effects of the three store actions: applied intents, projection rebuilds, outbox replays."""

    def __init__(self, data_root: Path, outbox: _CountingOutbox) -> None:
        self._store_db = DataRoot.at(data_root).store_db
        self._outbox = outbox
        self._lock = threading.Lock()
        self.rebuilds = 0

    def spy_rebuild(self, monkeypatch: pytest.MonkeyPatch, store: Any) -> None:
        cls = type(store)
        orig = cls.rebuild_projections
        spy = self

        def _counted(self_store: Any, *args: Any, **kwargs: Any) -> Any:
            with spy._lock:
                spy.rebuilds += 1
            return orig(self_store, *args, **kwargs)

        monkeypatch.setattr(cls, "rebuild_projections", _counted)

    def applied_intents(self) -> int:
        with _ro_db(self._store_db) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM applied_intents").fetchone()[0])

    def snapshot(self) -> dict[str, int]:
        return {"applied_intents": self.applied_intents(), "rebuilds": self.rebuilds, "outbox": self._outbox.calls}

    @staticmethod
    def key(action: str) -> str:
        return {"reconcile_policy": "applied_intents", "rebuild_projections": "rebuilds", "replay_outbox": "outbox"}[
            action
        ]


def _start_fix(daemon: _Daemon, ca_pem: str, token: str, actions: list[str]) -> tuple[threading.Thread, dict[str, Any]]:
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["env"] = _post_operator(
                daemon.ready, ca_pem, "/v2/operator/doctor/fix", token, {"actions": list(actions)}, 20.0
            )
        except Exception as exc:  # noqa: BLE001
            box["exc"] = exc

    thr = threading.Thread(target=_call, name=CLIENT_THREAD, daemon=True)
    thr.start()
    return thr, box


def _action_status(env: dict[str, Any] | None, action: str) -> str | None:
    if not isinstance(env, dict) or env.get("ok") is not True:
        return None
    fix = cast(dict[str, Any], cast(dict[str, Any], env.get("data") or {}).get("fix") or {})
    for a in cast(list[dict[str, Any]], fix.get("actions") or []):
        if a.get("action") == action:
            return cast(str | None, a.get("status"))
    return None


def _r201_setup(
    trusted_tmp: Path, label: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakeClock, FakeMonotonicClock, Any, Any, str, str, OsAdapters, _CountingOutbox, Any]:
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, ca_pem, _leaf, cli_token, os_ = _init_doctor_root(trusted_tmp / label, clock)
    outbox = _CountingOutbox()
    return clock, mono, rep, cfg, ca_pem, cli_token, os_, outbox, _priv


def _seed_unapplied_intent(daemon: _Daemon, tag: str) -> None:
    """Owner thread: one pending policy intent, so ``reconcile_policy`` has real work to apply."""

    def _seed() -> None:
        daemon.rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(f"i4-r2-01-{tag}".encode())})

    daemon.loop.run_owner_action(_seed).result(timeout=BOUND_WAIT_S)


def _drain_owner(daemon: _Daemon) -> None:
    daemon.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)


# ---------------------------------------------------------------------------
# I4-R2-01: queued store action must be valid when it starts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", STORE_ACTIONS)
def test_r2_01_queued_store_action_never_starts_after_deadline(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """Invariant: a fix store action queued on a busy owner does not start writing once the request cutoff and
    deadline have passed; the client never receives ``applied`` for it."""
    clock, mono, _rep, cfg, ca_pem, cli_token, os_, outbox, _ = _r201_setup(trusted_tmp, f"a-{action}", monkeypatch)
    effects = _StoreSideEffects(Path(cfg.data_root), outbox)
    hold = _OwnerHold()
    with _serve(cfg, os_=os_, clock=clock, mono=mono, outbox=outbox) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _seed_unapplied_intent(daemon, f"a-{action}")
        effects.spy_rebuild(monkeypatch, daemon.rt.store)
        before = effects.snapshot()
        hold.install(monkeypatch)
        hold.armed = True
        admission_ns = mono.now  # frozen until advanced below
        thr, box = _start_fix(daemon, ca_pem, cli_token, [action])
        try:
            assert hold.enqueued.wait(timeout=BOUND_WAIT_S), f"store action was never sent to the owner: {box}"
            assert hold.held.wait(timeout=BOUND_WAIT_S), "owner hold task never started"
            deadline_ns = admission_ns + OPERATOR_REQUEST_BUDGET_NS
            mono.set(deadline_ns + 1_000_000_000)  # past cutoff (deadline - 0.5 s) and past the deadline
            thr.join(timeout=5.0)  # the client may already be answered while the owner is still held
        finally:
            hold.release.set()
        thr.join(timeout=BOUND_WAIT_S)
        _drain_owner(daemon)
        time.sleep(0.2)
        after = effects.snapshot()

    assert not thr.is_alive(), "fix request never returned"
    key = _StoreSideEffects.key(action)
    assert after[key] == before[key], (
        f"queued {action} ran on the owner after the request deadline: {key} {before[key]} -> {after[key]}"
    )
    assert after == before, f"store side effects changed after the deadline: {before} -> {after}"
    assert _action_status(box.get("env"), action) != "applied", f"client got applied past deadline: {box}"


@pytest.mark.parametrize("action", STORE_ACTIONS)
def test_r2_01_store_action_before_cutoff_is_applied(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """Invariant (positive twin): the same store action, run well before the cutoff, is applied and its side effect
    is observable."""
    clock, mono, _rep, cfg, ca_pem, cli_token, os_, outbox, _ = _r201_setup(trusted_tmp, f"b-{action}", monkeypatch)
    effects = _StoreSideEffects(Path(cfg.data_root), outbox)
    with _serve(cfg, os_=os_, clock=clock, mono=mono, outbox=outbox) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _seed_unapplied_intent(daemon, f"b-{action}")
        effects.spy_rebuild(monkeypatch, daemon.rt.store)
        before = effects.snapshot()
        env = _post_operator(daemon.ready, ca_pem, "/v2/operator/doctor/fix", cli_token, {"actions": [action]}, 20.0)
        _drain_owner(daemon)
        after = effects.snapshot()

    assert _action_status(env, action) == "applied", env
    key = _StoreSideEffects.key(action)
    assert after[key] > before[key], f"{action} reported applied but {key} did not change: {before} -> {after}"


@pytest.mark.parametrize("action", STORE_ACTIONS)
def test_r2_01_queued_store_action_not_run_after_shutdown(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """Invariant: once daemon shutdown started, a fix store action still waiting in the owner queue never runs."""
    clock, mono, _rep, cfg, ca_pem, cli_token, os_, outbox, _ = _r201_setup(trusted_tmp, f"c-{action}", monkeypatch)
    effects = _StoreSideEffects(Path(cfg.data_root), outbox)
    hold = _OwnerHold()
    with _serve(cfg, os_=os_, clock=clock, mono=mono, outbox=outbox) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _seed_unapplied_intent(daemon, f"c-{action}")
        effects.spy_rebuild(monkeypatch, daemon.rt.store)
        before = effects.snapshot()
        hold.install(monkeypatch)
        hold.armed = True
        thr, box = _start_fix(daemon, ca_pem, cli_token, [action])
        try:
            assert hold.enqueued.wait(timeout=BOUND_WAIT_S), f"store action was never sent to the owner: {box}"
            assert hold.held.wait(timeout=BOUND_WAIT_S), "owner hold task never started"
            daemon.stop_ev.set()
            end = time.monotonic() + BOUND_WAIT_S
            while not daemon.loop.is_stopping and time.monotonic() < end:
                time.sleep(0.02)
            assert daemon.loop.is_stopping, "daemon shutdown never started"
        finally:
            hold.release.set()
        daemon.thread.join(timeout=BOUND_WAIT_S)
        thr.join(timeout=BOUND_WAIT_S)
    after = effects.snapshot()

    key = _StoreSideEffects.key(action)
    assert after[key] == before[key], (
        f"queued {action} ran on the owner after shutdown started: {key} {before[key]} -> {after[key]}"
    )
    assert _action_status(box.get("env"), action) != "applied", f"client got applied after shutdown: {box}"


@pytest.mark.parametrize("action", STORE_ACTIONS)
def test_r2_01_queued_store_action_not_run_after_credential_revoked(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """Invariant: operator authority is checked where the store action executes; a credential revoked between fix
    phase 1 and the queued action's start stops the action."""
    clock, mono, rep, cfg, ca_pem, _cli_token, os_, outbox, _ = _r201_setup(trusted_tmp, f"d-{action}", monkeypatch)
    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID
        )
    finally:
        rt.close()
    effects = _StoreSideEffects(Path(cfg.data_root), outbox)
    with _serve(cfg, os_=os_, clock=clock, mono=mono, outbox=outbox) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _seed_unapplied_intent(daemon, f"d-{action}")
        effects.spy_rebuild(monkeypatch, daemon.rt.store)
        before = effects.snapshot()
        rev_box: dict[str, Any] = {}

        def _queue_revoke() -> None:
            auth = make_bootstrap_auth(
                store_id=rep.store_id,
                owner_id=OWNER_DAN,
                action="credential_revoke",
                subject_id=cred.credential_id,
                trust_generation=1,
                expires_at=clock.now() + timedelta(hours=1),
            )
            rev_box["fut"] = daemon.loop.revoke_credential(cred.credential_id, auth)
            # Baseline measured on the owner right after the revocation, so only the store action can move it.
            rev_box["baseline"] = daemon.loop.run_owner_action(effects.snapshot)

        hold = _OwnerHold(before_action=_queue_revoke)
        hold.install(monkeypatch)
        hold.armed = True
        thr, box = _start_fix(daemon, ca_pem, cred.token, [action])
        try:
            assert hold.enqueued.wait(timeout=BOUND_WAIT_S), f"store action was never sent to the owner: {box}"
            assert hold.held.wait(timeout=BOUND_WAIT_S), "owner hold task never started"
        finally:
            hold.release.set()
        rev_box["fut"].result(timeout=BOUND_WAIT_S)  # revocation committed before the store action's turn
        before = cast(dict[str, int], rev_box["baseline"].result(timeout=BOUND_WAIT_S))
        thr.join(timeout=BOUND_WAIT_S)
        _drain_owner(daemon)
        after = effects.snapshot()

    assert not thr.is_alive(), "fix request never returned"
    key = _StoreSideEffects.key(action)
    assert after[key] == before[key], (
        f"queued {action} ran on the owner after its operator credential was revoked: {key} {before[key]} -> "
        f"{after[key]}"
    )
    assert _action_status(box.get("env"), action) != "applied", f"client got applied with a revoked credential: {box}"


# ---------------------------------------------------------------------------
# I4-R2-02: doctor snapshot pair must be consistent
# ---------------------------------------------------------------------------


class _SnapshotBarrier:
    """Wraps ``storage.backup._snapshot_db``: after the first doctor scratch DB copy completes, block until released."""

    def __init__(self, scratch: Path) -> None:
        self._scratch = scratch
        self._lock = threading.Lock()
        self.armed = False
        self.first_dest: Path | None = None
        self.first_done = threading.Event()
        self.release = threading.Event()

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        orig = storage_backup._snapshot_db
        bar = self

        def _barrier(source: Any, dest: Path, os_arg: Any) -> None:
            orig(source, dest, os_arg)
            block = False
            if bar.armed and _is_under(Path(dest), bar._scratch) and "doctor-snap-" in str(dest):
                with bar._lock:
                    if bar.first_dest is None:
                        bar.first_dest = Path(dest)
                        block = True
            if block:
                bar.first_done.set()
                bar.release.wait(timeout=BOUND_WAIT_S * 2)

        monkeypatch.setattr(storage_backup, "_snapshot_db", _barrier)


def _start_report(daemon: _Daemon, ca_pem: str, token: str, checkout: Path) -> tuple[threading.Thread, dict[str, Any]]:
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["env"] = _post_operator(
                daemon.ready,
                ca_pem,
                "/v2/operator/doctor/report",
                token,
                {"checkout_root": str(checkout), "wait_timeout_ms": 10_000},
                20.0,
            )
        except Exception as exc:  # noqa: BLE001
            box["exc"] = exc

    thr = threading.Thread(target=_call, name=CLIENT_THREAD, daemon=True)
    thr.start()
    return thr, box


def _check(data: dict[str, Any], name: str) -> dict[str, Any]:
    for chk in cast(list[dict[str, Any]], data.get("checks") or []):
        if chk.get("name") in (name, f"storage.{name}"):
            return chk
    raise AssertionError(f"missing check storage.{name} in report checks")


def _fresh_checkout(trusted_tmp: Path, os_: OsAdapters, name: str) -> Path:
    co = trusted_tmp / name
    co.mkdir()
    os_.permissions.secure_directory(co)
    return co


def _r202_run(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, label: str, *, write: bool) -> dict[str, Any]:
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    _rep, cfg, _priv, ca_pem, _leaf, cli_token, os_ = _init_doctor_root(trusted_tmp / label, clock)
    barrier = _SnapshotBarrier(DataRoot.at(cfg.data_root).scratch_dir)
    barrier.install(monkeypatch)
    with _serve(cfg, os_=os_, clock=clock, mono=mono) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        barrier.armed = True
        thr, box = _start_report(daemon, ca_pem, cli_token, _fresh_checkout(trusted_tmp, os_, f"{label}-co"))
        try:
            assert barrier.first_done.wait(timeout=BOUND_WAIT_S), f"doctor never copied a DB into scratch: {box}"
            if write:

                def _write_and_reconcile() -> int:
                    rt = daemon.rt
                    rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(b"i4-r2-02-between")})
                    return int(rt.store.reconcile_policy())

                applied = daemon.loop.run_owner_action(_write_and_reconcile).result(timeout=BOUND_WAIT_S)
                assert applied >= 1, "precondition: the owner write did not reconcile the new intent into the store"
        finally:
            barrier.release.set()
        thr.join(timeout=BOUND_WAIT_S * 2)
    assert not thr.is_alive(), "doctor report never returned"
    assert "exc" not in box, f"doctor report transport failed: {box.get('exc')!r}"
    env = cast(dict[str, Any], box["env"])
    assert env.get("ok") is True, env
    data = cast(dict[str, Any], env["data"])
    assert data.get("status") == "completed", {k: data.get(k) for k in ("status", "job_id", "doctor_run_id")}
    return data


def test_r2_02_snapshot_pair_with_owner_write_between_copies_is_consistent(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a legitimate owner write (policy intent + reconcile) landing between the store and policy copies
    must not produce a cross-DB verdict (unapplied intent / parity mismatch) that matches neither the before nor the
    after state."""
    data = _r202_run(trusted_tmp, monkeypatch, "e-write", write=True)
    reconcile = _check(data, "policy_reconcile")
    parity = _check(data, "ledger_projection_match")
    mixed = []
    if reconcile.get("status") in {"WARN", "FAIL"} and reconcile.get("reason") == "unapplied_policy_intents":
        mixed.append(f"policy_reconcile={reconcile.get('status')} ({reconcile.get('detail')})")
    if parity.get("status") == "FAIL":
        mixed.append(f"ledger_projection_match=FAIL ({parity.get('detail')})")
    assert not mixed, (
        "doctor report mixed store/policy snapshots from two commit points (before: no intent, after: intent "
        f"applied; neither has an unapplied intent): {mixed}"
    )


def test_r2_02_snapshot_pair_without_write_is_clean(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant (no-write control): with the same barrier and no write in between, the report completes with a
    clean cross-DB verdict, so the write case is not vacuous."""
    data = _r202_run(trusted_tmp, monkeypatch, "e-control", write=False)
    assert _check(data, "policy_reconcile").get("status") == "PASS", _check(data, "policy_reconcile")
    assert _check(data, "ledger_projection_match").get("status") == "PASS", _check(data, "ledger_projection_match")


def test_r2_02_restore_between_copies_is_never_committed_as_fresh(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a doctor snapshot pair split by an online restore is never committed or returned as a fresh
    DoctorRun."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, priv, ca_pem, _leaf, cli_token, os_ = _init_doctor_root(trusted_tmp / "e-restore", clock)
    root = DataRoot.at(cfg.data_root)
    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        policy_bak = create_policy_backup(rt.policy, os_, clock.now())
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(b"i4-r2-02-post-backup")})
        rt.store.reconcile_policy()
    finally:
        rt.close()

    barrier = _SnapshotBarrier(root.scratch_dir)
    barrier.install(monkeypatch)
    orig_read = StorageDoctorReader.read_snapshot
    tagged: list[str] = []

    def _tag_split_pair(self: StorageDoctorReader, data_root: Path, **kwargs: Any) -> DoctorSnapshot:
        snap = orig_read(self, data_root, **kwargs)
        db_root = kwargs.get("db_root")
        first = barrier.first_dest
        if db_root is not None and first is not None and _is_under(first, Path(db_root)):
            tagged.append(str(db_root))
            return replace(snap, integrity_errors=(*snap.integrity_errors, MIXED_MARKER))
        return snap

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _tag_split_pair)

    with _serve(cfg, os_=os_, clock=clock, mono=mono) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        barrier.armed = True
        thr, box = _start_report(daemon, ca_pem, cli_token, _fresh_checkout(trusted_tmp, os_, "e-restore-co"))
        try:
            assert barrier.first_done.wait(timeout=BOUND_WAIT_S), f"doctor never copied a DB into scratch: {box}"
            _run_online_restore_helper(daemon.ready, rep, ca_pem, cli_token, priv, os_, "policy", policy_bak)
        finally:
            barrier.release.set()
        thr.join(timeout=BOUND_WAIT_S * 2)
        _drain_owner(daemon)
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        with _ro_db(root.store_db) as conn:
            refs = [bytes(r[0]) for r in conn.execute("SELECT refs FROM ledger WHERE kind = 'doctor.run'").fetchall()]

    assert not thr.is_alive(), "doctor report never returned"
    committed = []
    for raw in refs:
        for dig in cast(list[str], json.loads(raw.decode("utf-8"))):
            bpath = blob_path(root.cas_dir, dig)
            if bpath.is_file() and MIXED_MARKER.encode() in bpath.read_bytes():
                committed.append(dig)
    assert not committed, f"DoctorRun built from a snapshot pair split by a restore was committed: {committed}"
    assert MIXED_MARKER not in json.dumps(box.get("env"), default=str), (
        f"report built from a snapshot pair split by a restore was returned: {box.get('env')}"
    )


# ---------------------------------------------------------------------------
# I4-R2-03: M1 native evidence must be bound to the run
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _HarnessWithReceipt(CaptureHarnessDoctorStatus):
    receipt: Any = None


def _m1_setup(trusted_tmp: Path) -> tuple[Any, Any, OsAdapters, Path, dict[str, Any], dict[str, JsonValue], Path]:
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "m1", clock)
    checkout = trusted_tmp / "co-clean"
    unregistered = trusted_tmp / "co-unregistered"
    home_dir = trusted_tmp / "home"
    for d in (checkout, unregistered, home_dir):
        d.mkdir(parents=True)
        os_.permissions.secure_directory(d)
    cfg_digest = digest_bytes(b"expected-config-digest-sp2")
    host_ver, host_name = "2.1.0", "claude-code"
    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, harness_id=host_name, machine_id=MACHINE_ID)
        ws = register_workspace_direct(
            rt, clock, cred.principal, alias="ws-clean", checkout_dir=checkout, remote="https://ex/clean.git"
        )
        rt.policy.set_layer2_state(
            harness_id=host_name, host_version=host_ver, config_digest=cfg_digest, state=Layer2State.VERIFIED
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout,
            home_dir=home_dir,
            os_=os_,
            rel_path="CLAUDE.md",
            slice_id="s1",
            body="Bootstrap Applied Clean\n",
        )
    finally:
        rt.close()
    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }
    valid_receipt: dict[str, Any] = {
        "host": host_name,
        "host_version": host_ver,
        "config_digest": cfg_digest,
        "run_scope": {"repo_id": ws.repo_id, "checkout_id": ws.checkout_id},
        "os": sys.platform,
    }
    return sp2, rep, os_, checkout, valid_receipt, healthy_dh, unregistered


def _m1_probe(
    sp2: Any,
    rep: Any,
    os_: OsAdapters,
    receipt: dict[str, Any],
    dh: dict[str, JsonValue],
    checkout: Path | None,
    *,
    require_native: bool = True,
) -> dict[str, Any]:
    def _snap(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _HarnessWithReceipt(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=receipt,
                ),
            ),
            available=True,
        )

    kwargs: dict[str, Any] = {} if checkout is None else {"checkout_root": checkout}
    return cast(
        dict[str, Any],
        sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            os_=os_,
            capture_probe=sp2.build_sp2_capture_probe(_snap, require_native_receipts=require_native),
            deep_health=dh,
            require_native_receipts=require_native,
            **kwargs,
        ),
    )


def test_r2_03_m1_positive_control_bound_native_evidence(trusted_tmp: Path) -> None:
    """Invariant (positive control): native evidence bound to this platform, host, version, config and the
    registered checkout with applied bootstrap yields ``native_verified=True`` and ``m1_ready=True``."""
    sp2, rep, os_, checkout, receipt, dh, _unreg = _m1_setup(trusted_tmp)
    res = _m1_probe(sp2, rep, os_, receipt, dh, checkout)
    assert res["native_verified"] is True, res
    assert res["m1_ready"] is True, res


@pytest.mark.parametrize("variant", ["wrong_platform", "os_missing", "host_missing", "unregistered_checkout"])
def test_r2_03_m1_unbound_native_evidence_fails_closed(trusted_tmp: Path, variant: str) -> None:
    """Invariant: native evidence whose platform/host is wrong or missing, or whose run checkout is not registered,
    yields ``native_verified=False`` and ``m1_ready=False``."""
    sp2, rep, os_, checkout, receipt, dh, unregistered = _m1_setup(trusted_tmp)
    run_checkout: Path | None = checkout
    if variant == "wrong_platform":
        receipt = {**receipt, "os": "wrong-platform"}
    elif variant == "os_missing":
        receipt = {k: v for k, v in receipt.items() if k != "os"}
    elif variant == "host_missing":
        receipt = {k: v for k, v in receipt.items() if k != "host"}
    else:
        run_checkout = unregistered
    res = _m1_probe(sp2, rep, os_, receipt, dh, run_checkout)
    assert res["native_verified"] is False, f"{variant}: native_verified=True for unbound native evidence"
    assert res["m1_ready"] is False, f"{variant}: m1_ready=True for unbound native evidence"


def test_r2_03_m1_without_checkout_root_is_not_ready(trusted_tmp: Path) -> None:
    """Invariant: without a checkout_root the run scope and its applied bootstrap cannot be resolved, so
    ``m1_ready`` fails closed even when every receipt field is valid."""
    sp2, rep, os_, _checkout, receipt, dh, _unreg = _m1_setup(trusted_tmp)
    res = _m1_probe(sp2, rep, os_, receipt, dh, None)
    assert res["m1_ready"] is False, "m1_ready=True without a checkout_root (run scope unresolvable)"




def test_r2_03_m1_without_registered_checkout_is_not_ready_even_without_native_requirement(trusted_tmp: Path) -> None:
    """Invariant: M1 readiness requires applied bootstrap evidence on a resolved registered checkout; with no checkout
    the bootstrap surface is not PASS (``bootstrap_evidence_unverified``) even when native receipts are not required."""
    sp2, rep, os_, _checkout, receipt, dh, _unreg = _m1_setup(trusted_tmp)
    res = _m1_probe(sp2, rep, os_, receipt, dh, None, require_native=False)
    boot = cast(dict[str, Any], res["surfaces"][sp2.M1_SURFACE_BOOTSTRAP_DRIFT])
    assert res["m1_ready"] is False, "m1_ready=True with no registered checkout to verify applied bootstrap against"
    assert boot.get("status") != "PASS", f"bootstrap surface PASS without a resolved checkout: {boot}"
    assert boot.get("reason") == "bootstrap_evidence_unverified", boot


def test_r2_03_m1_with_registered_checkout_is_ready_without_native_requirement(trusted_tmp: Path) -> None:
    """Invariant (positive twin): the same probe with receipts not required and the registered checkout with applied
    bootstrap is ``m1_ready=True``, so the no-checkout case is not vacuous."""
    sp2, rep, os_, checkout, receipt, dh, _unreg = _m1_setup(trusted_tmp)
    res = _m1_probe(sp2, rep, os_, receipt, dh, checkout, require_native=False)
    assert res["surfaces"][sp2.M1_SURFACE_BOOTSTRAP_DRIFT]["status"] == "PASS", res["surfaces"]
    assert res["m1_ready"] is True, res
