"""Independent RED oracle for SP1 increment 4 review findings F1, F2, F3 (review 2026-11-23 at 09d34c0).

Requirement sources:
- Plan ``2026-11-21-sp1-increment4-doctor-integration.md`` I4-2 ("Worker chạy ngoài owner lock, nhận snapshot tối
  thiểu"), I4-3 ("Chờ ngoài owner với cutoff"), I4-4 (repair actions, "chạy lại check liên quan"), spec §6.5
  (``prepare_task`` 1.5 s deadline).
- Review ``2026-11-23-sp1-increment4-review-09d34c0.md`` F1, F2, F3 (and F6 for durable job termination).

Invariants under test:
- F1: every failure after the daemon claimed the background ``system.doctor`` slot releases the slot, ends the job
  durably and leaves no scratch snapshot; doctor keeps working in the same daemon process.
- F2: the SQLite snapshot copy never runs on the owner thread, and the worker snapshot holds only what the reader
  reads (no CAS, never data reached through a link out of the data root).
- F3: filesystem ``doctor --fix`` work and the post-fix recheck run off the owner thread with a cutoff 0.5 s before
  the operator deadline; nothing of the fix keeps mutating after the response.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import superbrain.storage.backup as storage_backup
from superbrain.adapters.os import os_adapters
from superbrain.core._kernel_deadlines import OPERATOR_REQUEST_BUDGET_NS, TOTAL_REQUEST_BUDGET_NS
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ToolCommand
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.cas import blob_path
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_fix import _acl_or_mode, _grant_wide_access, _make_dir_link
from tests.integration.test_doctor_jobs import (
    BOUND_WAIT_S,
    _base_utc_now,
    _init_doctor_root,
    _ro_db,
    _running_serve,
)
from tests.support.clock import FakeClock
from tests.support.inc2_transport import FakeMonotonicClock, read_raw_http_response

OWNER_THREAD_NAME = "superbrain-owner-loop"
DOCTOR_WORKER_PREFIX = "doctor-worker-"
NON_TERMINAL_JOB_STATES = ("queued", "leased", "running")
FIX_ACTIONS = ["tighten_permissions", "reconcile_policy", "rebuild_projections", "rotate_logs"]
FIX_STATUSES = {"applied", "noop", "capability_unavailable", "failed", "interrupted", "not_started"}
CUTOFF_RESERVE_NS = 500_000_000
HEALTH_REAL_TIME_BUDGET_S = 1.5


def _post_operator(ready: Any, ca_pem: str, path: str, token: str, payload: object, read_s: float) -> dict[str, Any]:
    """``_post_tls`` from test_doctor_jobs with a caller-chosen response read timeout (doctor waits up to 10 s)."""
    host = f"{ready.endpoint.host}:{ready.endpoint.port}"
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    with (
        socket.create_connection((ready.endpoint.host, ready.endpoint.port), timeout=3.0) as raw,
        ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock,
    ):
        sock.settimeout(read_s)
        sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        assert read_raw_http_response(sock, timeout=3.0).startswith(b"HTTP/1.1 200 ")
        hdr = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
            f"X-Store-Id: {ready.identity.store_id}\r\nX-Writer-Epoch: {ready.identity.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {ready.identity.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1")
        sock.sendall(hdr + body)
        resp = read_raw_http_response(sock, timeout=read_s)
    head, sep, data = resp.partition(b"\r\n\r\n")
    assert sep and head.startswith(b"HTTP/1.1 "), resp[:200]
    return cast(dict[str, Any], json.loads(data))


def _doctor_job_states(data_root: Path) -> list[tuple[str, str]]:
    with _ro_db(DataRoot.at(data_root).store_db) as conn:
        rows = conn.execute("SELECT job_id, state FROM p_jobs_state WHERE kind = 'system.doctor'").fetchall()
    return [(str(r[0]), str(r[1])) for r in rows]


def _wait_doctor_jobs_terminal(data_root: Path, timeout_s: float) -> list[tuple[str, str]]:
    end = time.monotonic() + timeout_s
    rows = _doctor_job_states(data_root)
    while time.monotonic() < end:
        if rows and all(state not in NON_TERMINAL_JOB_STATES for _, state in rows):
            return rows
        time.sleep(0.05)
        rows = _doctor_job_states(data_root)
    return rows


def _snap_dirs(data_root: Path) -> list[str]:
    scratch = DataRoot.at(data_root).scratch_dir
    return sorted(p.name for p in scratch.glob("doctor-snap-*")) if scratch.is_dir() else []


def _is_under(path: Path, root: Path) -> bool:
    p, r = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(root))
    return p == r or p.startswith(r.rstrip("\\/") + os.sep)


# ---------------------------------------------------------------------------
# F1: launch failures after the doctor slot is claimed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["snapshot_db", "thread_start"])
def test_f1_doctor_launch_failure_releases_slot_ends_job_and_doctor_recovers(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """A one-shot fault while launching the doctor worker must end the job durably, drop scratch, keep doctor usable."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    _rep, cfg, _priv, ca_pem, _leaf, cli_token, os_ = _init_doctor_root(trusted_tmp / f"f1-{fault}", clock)
    scratch = DataRoot.at(cfg.data_root).scratch_dir
    fired = threading.Event()
    fire_lock = threading.Lock()

    if fault == "snapshot_db":
        orig_snapshot = storage_backup._snapshot_db

        def _faulty_snapshot(source: Any, dest: Path, os_arg: Any) -> None:
            with fire_lock:
                hit = not fired.is_set() and _is_under(Path(dest), scratch)
                if hit:
                    fired.set()
            if hit:
                raise BrainError(ErrorCode.IO_ERROR, "io error")
            orig_snapshot(source, dest, os_arg)

        monkeypatch.setattr(storage_backup, "_snapshot_db", _faulty_snapshot)
    else:
        orig_start = threading.Thread.start

        def _faulty_start(self: threading.Thread) -> None:
            with fire_lock:
                hit = not fired.is_set() and self.name.startswith(DOCTOR_WORKER_PREFIX)
                if hit:
                    fired.set()
            if hit:
                raise RuntimeError("can't start new thread")
            orig_start(self)

        monkeypatch.setattr(threading.Thread, "start", _faulty_start)

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, _loop):
        assert fired.wait(timeout=BOUND_WAIT_S), f"injected {fault} fault never fired on the doctor launch path"
        violations: list[str] = []

        rows = _wait_doctor_jobs_terminal(cfg.data_root, BOUND_WAIT_S)
        if not rows:
            violations.append("no system.doctor job was ever recorded")
        stuck = [(j, s) for j, s in rows if s in NON_TERMINAL_JOB_STATES]
        if stuck:
            violations.append(f"(a) doctor job(s) never reached a terminal state after the {fault} fault: {stuck}")

        leftovers = _snap_dirs(cfg.data_root)
        if leftovers:
            violations.append(f"(b) scratch snapshot directories left behind: {leftovers}")

        try:
            env = _post_operator(
                ready, ca_pem, "/v2/operator/doctor/report", cli_token, {"wait_timeout_ms": 10_000}, 15.0
            )
        except Exception as exc:  # noqa: BLE001 - a dead daemon is itself the observed violation
            violations.append(f"(c) doctor report call failed after the fault: {type(exc).__name__}: {exc}")
        else:
            raw = env.get("data")
            data: dict[str, Any] = raw if isinstance(raw, dict) else {}
            if not (
                env.get("ok") is True
                and data.get("status") == "completed"
                and isinstance(data.get("doctor_run_id"), str)
                and data.get("doctor_run_id")
            ):
                summary = {k: data.get(k) for k in ("status", "job_id", "doctor_run_id")} if data else env
                violations.append(f"(c) later doctor report did not complete in the same daemon: {summary}")

        assert not violations, "F1 invariant violated:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# F2: minimal snapshot, never copied on the owner thread
# ---------------------------------------------------------------------------


def test_f2_doctor_snapshot_is_taken_off_owner_and_holds_no_cas_or_linked_data(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker snapshot is copied off the owner thread and contains only the DB/marker files the reader reads."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    _rep, cfg, _priv, ca_pem, _leaf, cli_token, os_ = _init_doctor_root(trusted_tmp / "f2", clock)
    root = DataRoot.at(cfg.data_root)

    # Non-trivial CAS on the live root.
    for i in range(24):
        payload = f"i4-f2-cas-{i:03d}-".encode() + b"y" * 256
        bpath = blob_path(root.cas_dir, digest_bytes(payload))
        bpath.parent.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(bpath.parent)
        bpath.write_bytes(payload)
        os_.permissions.secure_file(bpath)

    sentinel_name = "i4-f2-outside-sentinel.txt"
    outside = trusted_tmp / "f2-outside-target"
    outside.mkdir()
    (outside / sentinel_name).write_bytes(b"outside the data root\n")

    allowed_names = {
        p.name
        for p in (
            root.store_db,
            root.policy_db,
            root.lock_path,
            root.endpoint_path,
            root.restore_epoch_path,
            root.pending_restore_tombstones_path,
        )
    }
    db_names = {root.store_db.name, root.policy_db.name}
    allowed_names |= {n + suffix for n in db_names for suffix in ("-wal", "-shm", "-journal")}

    lock = threading.Lock()
    snapshot_threads: list[str] = []
    inspected_roots: list[str] = []
    snapshot_violations: list[str] = []

    orig_snapshot = storage_backup._snapshot_db

    def _spy_snapshot(source: Any, dest: Path, os_arg: Any) -> None:
        with lock:
            snapshot_threads.append(threading.current_thread().name)
        orig_snapshot(source, dest, os_arg)

    monkeypatch.setattr(storage_backup, "_snapshot_db", _spy_snapshot)

    orig_read = StorageDoctorReader.read_snapshot

    def _inspect_read(self: StorageDoctorReader, data_root: Path, **kwargs: Any) -> Any:
        db_root = kwargs.get("db_root")
        if db_root is not None:
            found: list[str] = []
            for dirpath, dirnames, filenames in os.walk(db_root, followlinks=False):
                rel = os.path.relpath(dirpath, db_root)
                found += [f"dir {os.path.join(rel, d)}" for d in dirnames if d == "cas"]
                found += [f"file {os.path.join(rel, f)}" for f in filenames if f not in allowed_names]
                found += [f"sentinel {os.path.join(rel, f)}" for f in filenames if f == sentinel_name]
            with lock:
                inspected_roots.append(str(db_root))
                if found:
                    snapshot_violations.append(f"{Path(db_root).name}: {sorted(found)[:12]} (total {len(found)})")
        return orig_read(self, data_root, **kwargs)

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _inspect_read)

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        # Link inside CAS pointing outside the data root, planted on the live root after startup preflight.
        _make_dir_link(root.cas_dir / "zz-i4-f2-link", outside)
        checkout = trusted_tmp / "f2-checkout"
        checkout.mkdir()
        os_.permissions.secure_directory(checkout)
        # A fresh checkout scope forces a new background run launched from the online report path.
        env = _post_operator(
            ready,
            ca_pem,
            "/v2/operator/doctor/report",
            cli_token,
            {"checkout_root": str(checkout), "wait_timeout_ms": 10_000},
            15.0,
        )

    with lock:
        owner_copies = [n for n in snapshot_threads if n == OWNER_THREAD_NAME]
        violations: list[str] = []
        if owner_copies:
            violations.append(
                f"SQLite snapshot copy ran on the owner thread {len(owner_copies)} time(s); threads={snapshot_threads}"
            )
        if snapshot_violations:
            violations.append(f"worker snapshot holds data the reader does not read: {snapshot_violations}")
        assert not violations, "F2 invariant violated:\n" + "\n".join(violations)
        assert snapshot_threads, "no doctor SQLite snapshot was taken (spy never called)"
        assert inspected_roots, "reader was never handed a scratch snapshot (db_root)"

    # Positive twin: the run still completes and the report flags the CAS link on the live root.
    assert env.get("ok") is True, env
    data = cast(dict[str, Any], env["data"])
    assert data.get("status") == "completed", {k: data.get(k) for k in ("status", "job_id")}
    assert data.get("overall_status") == "fail", data.get("overall_status")
    flagged = [str(e) for e in cast(list[Any], data.get("integrity_errors") or []) if "zz-i4-f2-link" in str(e)]
    assert flagged, f"report did not flag the link inside CAS: {data.get('integrity_errors')}"


# ---------------------------------------------------------------------------
# F3: doctor --fix off the owner thread with cutoff
# ---------------------------------------------------------------------------


class _BlockingPermissions:
    """Delegating permission guard that blocks the first daemon-thread ``object_problems`` call inside data_root."""

    def __init__(self, inner: Any, data_root: Path) -> None:
        self._inner = inner
        self._data_root = data_root
        self._lock = threading.Lock()
        self.armed = False
        self._fired = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.blocked_thread: str | None = None

    def object_problems(self, path: Path) -> Any:
        cur = threading.current_thread()
        block = False
        if self.armed and cur is not threading.main_thread() and not cur.name.startswith("i4-f3-client"):
            if _is_under(Path(path), self._data_root):
                with self._lock:
                    if not self._fired:
                        self._fired = True
                        block = True
        if block:
            self.blocked_thread = cur.name
            self.entered.set()
            self.release.wait(timeout=BOUND_WAIT_S * 2)
        return self._inner.object_problems(path)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _f3_setup(trusted_tmp: Path, label: str) -> tuple[Any, ...]:
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    base_os = os_adapters(clock=clock)
    _rep, cfg, _priv, ca_pem, _leaf, cli_token, _ = _init_doctor_root(trusted_tmp / label, clock, os_=base_os)
    guard = _BlockingPermissions(base_os.permissions, Path(cfg.data_root))
    wrapped_os = replace(base_os, permissions=cast(Any, guard))
    return clock, mono, base_os, wrapped_os, guard, cfg, ca_pem, cli_token


def _widen_target(root: DataRoot, base_os: OsAdapters) -> tuple[Path, str, str]:
    root.logs_dir.mkdir(parents=True, exist_ok=True)
    base_os.permissions.secure_directory(root.logs_dir)
    target = root.logs_dir / "i4-f3-widened.txt"
    target.write_bytes(b"i4-f3 widened\n")
    base_os.permissions.secure_file(target)
    tight = _acl_or_mode(target)
    _grant_wide_access(target)
    widened = _acl_or_mode(target)
    assert widened != tight and base_os.permissions.object_problems(target), "precondition: target is widened"
    return target, tight, widened


def _start_fix(ready: Any, ca_pem: str, token: str) -> tuple[threading.Thread, dict[str, Any]]:
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["env"] = _post_operator(
                ready, ca_pem, "/v2/operator/doctor/fix", token, {"actions": list(FIX_ACTIONS)}, 15.0
            )
        except Exception as exc:  # noqa: BLE001
            box["exc"] = exc

    thr = threading.Thread(target=_call, name="i4-f3-client", daemon=True)
    thr.start()
    return thr, box


def _timed_tool(loop: Any, mono: FakeMonotonicClock, token: str, arguments: dict[str, Any]) -> tuple[Any, float]:
    cmd = ToolCommand(tool="get_health", arguments=dict(arguments), token=token)
    t0 = time.monotonic()
    fut = loop.submit(cmd, mono.now + TOTAL_REQUEST_BUDGET_NS)
    try:
        res: Any = fut.result(timeout=HEALTH_REAL_TIME_BUDGET_S)
    except Exception as exc:  # noqa: BLE001 - a timeout is the observed violation
        res = exc
    return res, time.monotonic() - t0


def test_f3_owner_loop_stays_responsive_while_fix_tightens_permissions(trusted_tmp: Path) -> None:
    """Tool calls through the owner loop complete within 1.5 s while a fix is inside ``tighten_permissions``.

    The shallow ``get_health`` named in the contract is answered without the owner thread at 09d34c0 (it passes even
    with the owner blocked), so the owner-serialized ``get_health(deep=true)`` is the observable for the §6.5 1.5 s
    budget that every owner-loop tool (``prepare_task`` included) shares.
    """
    clock, mono, _base_os, wrapped_os, guard, cfg, ca_pem, cli_token = _f3_setup(trusted_tmp, "f3-health")
    shallow = {"schema_version": "2.0", "deep": False}
    with _running_serve(cfg, os_=wrapped_os, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _widen_target(DataRoot.at(cfg.data_root), _base_os)
        # Positive control: owner-serialized deep health answers within budget when nothing blocks the owner.
        ctrl, ctrl_s = _timed_tool(
            loop, mono, cli_token, {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_i4_f3_ctrl_01"}
        )
        assert isinstance(ctrl, dict) and ctrl.get("ok") is True, ctrl
        assert ctrl_s <= HEALTH_REAL_TIME_BUDGET_S, ctrl_s
        guard.armed = True
        thr, box = _start_fix(ready, ca_pem, cli_token)
        try:
            assert guard.entered.wait(timeout=BOUND_WAIT_S), f"fix never reached tighten_permissions: {box}"
            res_s, el_s = _timed_tool(loop, mono, cli_token, shallow)
            res_d, el_d = _timed_tool(
                loop, mono, cli_token, {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_i4_f3_busy_01"}
            )
            late = [
                f"{label}: elapsed={el:.2f}s result={type(r).__name__}"
                for label, r, el in (("shallow get_health", res_s, el_s), ("deep get_health", res_d, el_d))
                if not (isinstance(r, dict) and r.get("ok") is True and el <= HEALTH_REAL_TIME_BUDGET_S)
            ]
            assert not late, (
                f"owner-loop tool calls missed the {HEALTH_REAL_TIME_BUDGET_S}s budget while a fix tightened "
                f"permissions on thread {guard.blocked_thread!r}: {late}"
            )
        finally:
            guard.release.set()
            thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "fix request never returned after release"


def test_f3_fix_cutoff_returns_interrupted_and_stops_mutating(trusted_tmp: Path) -> None:
    """Past the cutoff (deadline - 0.5 s) the fix returns ``interrupted`` and leaves unrepaired targets untouched."""
    clock, mono, base_os, wrapped_os, guard, cfg, ca_pem, cli_token = _f3_setup(trusted_tmp, "f3-cutoff")
    root = DataRoot.at(cfg.data_root)
    with _running_serve(cfg, os_=wrapped_os, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target, _tight, widened = _widen_target(root, base_os)
        admission_ns = mono.now  # fake monotonic clock is frozen until advanced below
        guard.armed = True
        thr, box = _start_fix(ready, ca_pem, cli_token)
        try:
            assert guard.entered.wait(timeout=BOUND_WAIT_S), f"fix never reached tighten_permissions: {box}"
            assert _acl_or_mode(target) == widened, "precondition: target not yet repaired at the block point"
            deadline_ns = admission_ns + OPERATOR_REQUEST_BUDGET_NS
            mono.set(deadline_ns - CUTOFF_RESERVE_NS + 100_000_000)  # past cutoff, before deadline
            time.sleep(0.5)
        finally:
            guard.release.set()
            thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "fix request never returned"
        assert "exc" not in box, f"fix request transport failed: {box.get('exc')!r}"
        env = cast(dict[str, Any], box["env"])
        time.sleep(1.0)
        acl_after = _acl_or_mode(target)

    assert env.get("ok") is True, env
    data = cast(dict[str, Any], env["data"])
    fix = cast(dict[str, Any], data.get("fix") or {})
    actions = cast(list[dict[str, Any]], fix.get("actions") or [])
    by_name = {a.get("action"): a.get("status") for a in actions}
    assert data.get("status") == "interrupted", (
        f"fix past cutoff must report status 'interrupted'; got status={data.get('status')!r}, actions={by_name}"
    )
    names = [str(a.get("action")) for a in actions]
    assert sorted(names) == sorted(FIX_ACTIONS) and len(names) == len(set(names)), actions
    assert all(a.get("status") in FIX_STATUSES for a in actions), actions
    assert by_name["tighten_permissions"] in {"interrupted", "not_started"}, by_name
    later = FIX_ACTIONS[FIX_ACTIONS.index("tighten_permissions") + 1 :]
    assert all(by_name[n] == "not_started" for n in later), by_name
    assert fix.get("rechecked_checks") == [], fix.get("rechecked_checks")
    assert acl_after == widened, "a widened target was repaired after the interrupted fix response"


def test_f3_fix_without_blocking_completes_and_repairs(trusted_tmp: Path) -> None:
    """Positive twin: the same fix request, unblocked, returns the completed DTO and repairs the widened target."""
    clock, mono, base_os, wrapped_os, _guard, cfg, ca_pem, cli_token = _f3_setup(trusted_tmp, "f3-twin")
    root = DataRoot.at(cfg.data_root)
    with _running_serve(cfg, os_=wrapped_os, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target, _tight, widened = _widen_target(root, base_os)
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/fix", cli_token, {"actions": list(FIX_ACTIONS)}, 15.0)

    assert env.get("ok") is True, env
    data = cast(dict[str, Any], env["data"])
    assert data.get("status", "completed") == "completed", data.get("status")
    fix = cast(dict[str, Any], data["fix"])
    by_name = {a["action"]: a["status"] for a in cast(list[dict[str, Any]], fix["actions"])}
    assert sorted(by_name) == sorted(FIX_ACTIONS), by_name
    assert by_name["tighten_permissions"] == "applied", by_name
    assert not set(by_name.values()) & {"interrupted", "not_started"}, by_name
    assert fix["rechecked_checks"], fix
    assert _acl_or_mode(target) != widened
    assert not base_os.permissions.object_problems(target)
