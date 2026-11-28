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

import contextlib
import json
import os
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import superbrain.storage.backup as storage_backup
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.core._kernel_deadlines import OPERATOR_REQUEST_BUDGET_NS, TOTAL_REQUEST_BUDGET_NS
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import Endpoint, Ready, ToolCommand
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
from tests.support.inc2_transport import FakeMonotonicClock, post_tls_http_json, post_tls_raw, read_raw_http_response
from tests.support.kernel_auth import make_bootstrap_auth

OWNER_THREAD_NAME = "superbrain-owner-loop"
DOCTOR_WORKER_PREFIX = "doctor-worker-"
NON_TERMINAL_JOB_STATES = ("queued", "leased", "running")
FIX_ACTIONS = ["tighten_permissions", "reconcile_policy", "rebuild_projections", "rotate_logs"]
FIX_STATUSES = {"applied", "noop", "capability_unavailable", "failed", "interrupted", "not_started"}
CUTOFF_RESERVE_NS = 500_000_000
HEALTH_REAL_TIME_BUDGET_S = 1.5


def _post_operator(ready: Any, ca_pem: str, path: str, token: str, payload: object, read_s: float) -> dict[str, Any]:
    """``_post_tls`` from test_doctor_jobs with a caller-chosen response read timeout (doctor waits up to 10 s)."""
    return post_tls_http_json(ready, ca_pem, path, token, payload, read_timeout=read_s)[1]


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


# ---------------------------------------------------------------------------
# R9: raw TLS loopback helper resilience (pre-POST retry, post-POST & auth fail-closed)
# ---------------------------------------------------------------------------


def _r9_tls_pair(base_dir: Path, label: str, *, port: int = 1) -> tuple[Ready, str, ssl.SSLContext]:
    clock = FakeClock(_base_utc_now())
    os_ = os_adapters(clock=clock)
    store_id = new_id()
    tls_dir = base_dir / label
    auth = make_bootstrap_auth(
        store_id=store_id,
        action="provision_tls",
        subject_id=store_id,
        expires_at=clock.now() + timedelta(hours=1),
        destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, auth, clock, os_=os_)
    ca_pem = tls.ca_cert_path.read_text(encoding="utf-8")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(tls.cert_path), keyfile=str(tls.key_path))
    ep = Endpoint(version=1, host="127.0.0.1", port=port, store_id=store_id, writer_epoch=1, instance_id="inst-r9")
    ready = Ready(endpoint=ep, identity=ep.identity, tls_not_after=tls.not_after, leaf_cert_sha256=tls.leaf_cert_sha256)
    return ready, ca_pem, server_ctx


def _r9_abort_tcp(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    sock.close()


def _r9_read_http_request(sock: ssl.SSLSocket) -> bytes:
    sock.settimeout(2.0)
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\r\n\r\n" in buf:
            head_end = buf.index(b"\r\n\r\n")
            headers = buf[:head_end].decode("iso-8859-1")
            cl = 0
            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
            if len(buf) >= head_end + 4 + cl:
                break
    return bytes(buf)


def _r9_write_http_json(sock: ssl.SSLSocket, status: str, obj: object) -> None:
    body = json.dumps(obj).encode("utf-8")
    frame = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("iso-8859-1") + body
    sock.sendall(frame)


@contextlib.contextmanager
def _r9_faulty_server(
    ready_template: Ready,
    handler: Callable[[int, socket.socket], None],
) -> Iterator[tuple[Ready, list[int]]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.1)
    port = int(listener.getsockname()[1])
    ep = replace(ready_template.endpoint, port=port)
    ready = replace(ready_template, endpoint=ep)
    stop_ev = threading.Event()
    accepts = [0]

    def _serve() -> None:
        while not stop_ev.is_set():
            try:
                raw, _addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            accepts[0] += 1
            idx = accepts[0]
            try:
                handler(idx, raw)
            except (TimeoutError, ssl.SSLError, OSError):
                pass
            finally:
                try:
                    raw.close()
                except OSError:
                    pass

    thr = threading.Thread(target=_serve, daemon=True, name="r9-faulty-tls")
    thr.start()
    try:
        yield ready, accepts
    finally:
        stop_ev.set()
        try:
            listener.close()
        except OSError:
            pass
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "r9 faulty TLS server thread leaked"


def test_r9_pre_post_handshake_abort_recovers_within_three_attempts(trusted_tmp: Path) -> None:
    """Transient TCP RST/EOF before TLS handshake completes must recover within 3 attempts and send POST once."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, "r9-hs")
    post_count = [0]
    post_raws: list[bytes] = []

    def _handler(attempt: int, raw: socket.socket) -> None:
        if attempt == 1:
            raw.settimeout(1.0)
            raw.recv(1)
            _r9_abort_tcp(raw)
            return
        if attempt == 2:
            raw.settimeout(1.0)
            raw.recv(1)
            raw.close()
            return
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            ident_req = _r9_read_http_request(tls)
            assert ident_req.startswith(b"GET /v2/identity HTTP/1.1\r\n")
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            post_req = _r9_read_http_request(tls)
            post_count[0] += 1
            post_raws.append(post_req)
            _r9_write_http_json(tls, "200 OK", {"ok": True, "data": {"recovered": "handshake"}})

    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/report", "tok-r9", {"deep": True}, 2.0)

    assert accepts[0] == 3
    assert post_count[0] == 1
    assert env == {"ok": True, "data": {"recovered": "handshake"}}
    assert b"connection: close" in post_raws[0].split(b"\r\n\r\n", 1)[0].lower().split(b"\r\n")


@pytest.mark.parametrize("fault_mode", ["identity_rst", "identity_empty_eof"])
def test_r9_pre_post_identity_abort_and_empty_eof_recover_without_duplicating_post(
    trusted_tmp: Path, fault_mode: str
) -> None:
    """Abort or empty EOF on GET /v2/identity before any POST byte is written must retry cleanly once."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-id-{fault_mode}")
    post_count = [0]
    post_raws: list[bytes] = []

    def _handler(attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            ident_req = _r9_read_http_request(tls)
            assert ident_req.startswith(b"GET /v2/identity HTTP/1.1\r\n")
            if attempt == 1:
                if fault_mode == "identity_rst":
                    _r9_abort_tcp(tls)
                else:
                    tls.close()
                return
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            post_req = _r9_read_http_request(tls)
            post_count[0] += 1
            post_raws.append(post_req)
            _r9_write_http_json(tls, "200 OK", {"ok": True, "data": {"recovered": fault_mode}})

    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/report", "tok-r9", {"deep": False}, 2.0)

    assert accepts[0] == 2
    assert post_count[0] == 1
    assert env == {"ok": True, "data": {"recovered": fault_mode}}
    assert b"connection: close" in post_raws[0].split(b"\r\n\r\n", 1)[0].lower().split(b"\r\n")


@pytest.mark.parametrize("post_fault", ["after_post_rst", "after_post_empty_eof"])
def test_r9_post_sent_abort_never_retries_post_on_wire(trusted_tmp: Path, post_fault: str) -> None:
    """Once POST bytes have been sent, a dropped/empty response MUST NOT retry the POST request."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-post-{post_fault}")
    post_count = [0]

    def _handler(_attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            post_req = _r9_read_http_request(tls)
            assert post_req.startswith(b"POST /v2/operator/doctor/fix HTTP/1.1\r\n")
            post_count[0] += 1
            if post_fault == "after_post_rst":
                _r9_abort_tcp(tls)
            else:
                tls.close()

    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        with pytest.raises((OSError, AssertionError)):
            _post_operator(ready, ca_pem, "/v2/operator/doctor/fix", "tok-r9", {"actions": ["rotate_logs"]}, 2.0)

    assert accepts[0] == 1
    assert post_count[0] == 1


def test_r9_post_sendall_abort_never_retries_after_post_sent(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ConnectionAbortedError raised once POST write begins MUST propagate immediately without retrying."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, "r9-sendall-abort")
    post_send_calls = [0]
    orig_sendall = ssl.SSLSocket.sendall

    def _abort_on_post(self: ssl.SSLSocket, data: Any, flags: int = 0) -> None:
        if bytes(data).startswith(b"POST "):
            post_send_calls[0] += 1
            raise ConnectionAbortedError(10053, "simulated abort during POST send")
        orig_sendall(self, data, flags)

    def _handler(_attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            _r9_read_http_request(tls)

    monkeypatch.setattr(ssl.SSLSocket, "sendall", _abort_on_post)
    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        with pytest.raises(ConnectionAbortedError):
            _post_operator(ready, ca_pem, "/v2/operator/doctor/fix", "tok-r9", {"actions": ["rotate_logs"]}, 2.0)

    assert accepts[0] == 1
    assert post_send_calls[0] == 1


def test_r9_fail_closed_immediately_on_cert_error_and_connection_refused(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TLS cert mismatch and ConnectionRefusedError MUST fail closed on attempt 1 with zero retries."""
    ready_expected, expected_ca_pem, _ctx_expected = _r9_tls_pair(trusted_tmp, "r9-ca-expected")
    _ready_wrong, _wrong_ca_pem, wrong_server_ctx = _r9_tls_pair(trusted_tmp, "r9-ca-wrong")

    def _wrong_cert_handler(_attempt: int, raw: socket.socket) -> None:
        with wrong_server_ctx.wrap_socket(raw, server_side=True) as _tls:
            pass

    with _r9_faulty_server(ready_expected, _wrong_cert_handler) as (ready_bad_cert, accepts):
        with pytest.raises(ssl.SSLCertVerificationError):
            _post_operator(ready_bad_cert, expected_ca_pem, "/v2/operator/doctor/report", "tok-r9", {}, 2.0)
    assert accepts[0] == 1

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = int(probe.getsockname()[1])
    probe.close()
    ready_closed = replace(ready_expected, endpoint=replace(ready_expected.endpoint, port=closed_port))

    connect_calls = [0]

    class _CountingSocket(socket.socket):
        def connect(self, address: Any) -> None:
            connect_calls[0] += 1
            super().connect(address)

    monkeypatch.setattr(socket, "socket", _CountingSocket)
    with pytest.raises(ConnectionRefusedError):
        _post_operator(ready_closed, expected_ca_pem, "/v2/operator/doctor/report", "tok-r9", {}, 2.0)
    assert connect_calls[0] == 1


@pytest.mark.parametrize(
    ("trunc_mode", "raw_ident"),
    [
        ("200_partial_headers", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        ("200_short_body", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"a\""),
        ("200_missing_content_length", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"),
        ("200_malformed_content_length", b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n{}"),
        (
            "200_duplicate_content_length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 50\r\n\r\n{}",
        ),
        ("503_short_body", b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 50\r\n\r\n{\"e"),
    ],
)
def test_r9_truncated_identity_recovers_without_sending_post(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    trunc_mode: str,
    raw_ident: bytes,
) -> None:
    """Truncated/malformed State-0 HTTP responses (200 or non-200) must retry pre-POST without leaking POST."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-trunc-{trunc_mode}")
    post_count = [0]
    sent_frames: list[bytes] = []
    orig_sendall = ssl.SSLSocket.sendall

    def _spy_sendall(self: ssl.SSLSocket, data: Any, flags: int = 0) -> None:
        sent_frames.append(bytes(data))
        orig_sendall(self, data, flags)

    def _handler(attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            ident_req = _r9_read_http_request(tls)
            assert ident_req.startswith(b"GET /v2/identity HTTP/1.1\r\n")
            if attempt == 1:
                tls.sendall(raw_ident)
                return
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            post_req = _r9_read_http_request(tls)
            assert post_req.startswith(b"POST /v2/operator/doctor/report HTTP/1.1\r\n")
            post_count[0] += 1
            _r9_write_http_json(tls, "200 OK", {"ok": True, "data": {"recovered": trunc_mode}})

    monkeypatch.setattr(ssl.SSLSocket, "sendall", _spy_sendall)
    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/report", "tok-r9", {"deep": True}, 2.0)

    assert accepts[0] == 2
    assert post_count[0] == 1
    assert env == {"ok": True, "data": {"recovered": trunc_mode}}
    post_writes = [chunk for chunk in sent_frames if chunk.startswith(b"POST ") or b"tok-r9" in chunk]
    assert len(post_writes) == 1


@pytest.mark.parametrize(
    ("trunc_mode", "raw_ident"),
    [
        ("200_partial_headers", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        ("200_short_body", b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"a\""),
    ],
)
def test_r9_exhausted_incomplete_identity_never_sends_post_or_bearer(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    trunc_mode: str,
    raw_ident: bytes,
) -> None:
    """When retries exhaust on truncated State-0 200 (both modes), POST/Bearer must never be sent."""
    secret_token = "tok-secret-never-leak-r9"
    sent_frames: list[bytes] = []
    orig_sendall = ssl.SSLSocket.sendall

    def _spy_sendall(self: ssl.SSLSocket, data: Any, flags: int = 0) -> None:
        sent_frames.append(bytes(data))
        orig_sendall(self, data, flags)

    def _make_handler() -> Callable[[int, socket.socket], None]:
        def _handler(_attempt: int, raw: socket.socket) -> None:
            with server_ctx.wrap_socket(raw, server_side=True) as tls:
                assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
                tls.sendall(raw_ident)

        return _handler

    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-exhaust-{trunc_mode}")
    monkeypatch.setattr(ssl.SSLSocket, "sendall", _spy_sendall)

    with _r9_faulty_server(ready_tpl, _make_handler()) as (ready_false, accepts_false):
        ret = post_tls_raw(
            ready_false,
            ca_pem,
            "/v2/operator/doctor/report",
            secret_token,
            {"deep": True},
            ident_timeout=0.5,
            read_timeout=0.5,
            require_identity_200=False,
        )
    assert accepts_false[0] == 3
    assert ret == raw_ident
    assert not any(b"POST " in chunk or secret_token.encode("ascii") in chunk for chunk in sent_frames)

    sent_frames.clear()
    with _r9_faulty_server(ready_tpl, _make_handler()) as (ready_true, accepts_true):
        with pytest.raises(AssertionError):
            _post_operator(ready_true, ca_pem, "/v2/operator/doctor/report", secret_token, {"deep": True}, 0.5)
    assert accepts_true[0] == 3
    assert not any(b"POST " in chunk or secret_token.encode("ascii") in chunk for chunk in sent_frames)


@pytest.mark.parametrize(
    ("mode", "raw_ident"),
    [
        ("zero_cl_lowercase", b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"),
        ("mixed_case_cl", b"HTTP/1.1 200 OK\r\nCoNtEnT-lEnGtH:   14 \r\n\r\n{\"ready\":true}"),
    ],
)
def test_r9_complete_identity_zero_and_case_insensitive_content_length(
    trusted_tmp: Path, mode: str, raw_ident: bytes
) -> None:
    """Valid State-0 200 responses with Content-Length: 0 or mixed-case header succeed in 1 attempt."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-cl-{mode}")
    post_count = [0]

    def _handler(_attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            tls.sendall(raw_ident)
            post_req = _r9_read_http_request(tls)
            assert post_req.startswith(b"POST /v2/operator/doctor/report HTTP/1.1\r\n")
            post_count[0] += 1
            _r9_write_http_json(tls, "200 OK", {"ok": True, "data": {"mode": mode}})

    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/report", "tok-r9", {"deep": True}, 2.0)

    assert accepts[0] == 1
    assert post_count[0] == 1
    assert env == {"ok": True, "data": {"mode": mode}}


def test_r9_read_raw_http_response_handles_malformed_and_duplicate_content_length() -> None:
    """read_raw_http_response must never raise ValueError or stall on malformed/duplicate/zero Content-Length."""
    for raw_frame, keep_open in (
        (b"HTTP/1.1 200 OK\r\nContent-Length: not-a-number\r\n\r\nabc", True),
        (b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nabc", True),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 99\r\n\r\nok", True),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", True),
        (b"HTTP/1.1 200 OK\r\n\r\n", False),
    ):
        cli, srv = socket.socketpair()
        try:
            srv.sendall(raw_frame)
            if not keep_open:
                srv.close()
            t0 = time.monotonic()
            got = read_raw_http_response(cli, timeout=2.0)
            elapsed = time.monotonic() - t0
            assert got.startswith(raw_frame.split(b"\r\n\r\n", 1)[0])
            assert elapsed < 1.0, f"read_raw_http_response stalled ({elapsed:.2f}s) on {raw_frame!r}"
        finally:
            for s in (cli, srv):
                try:
                    s.close()
                except OSError:
                    pass


@pytest.mark.parametrize(
    ("post_mode", "raw_post_resp"),
    [
        ("post_partial_headers", b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        ("post_short_body_valid_json", b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"ok\":true}"),
        ("post_missing_content_length", b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}"),
        (
            "post_duplicate_content_length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        ),
    ],
)
def test_r9_truncated_post_response_never_retries_and_fails_closed(
    trusted_tmp: Path, post_mode: str, raw_post_resp: bytes
) -> None:
    """Truncated or malformed POST responses after post_sent=True must never retry and must fail closed."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, f"r9-posttrunc-{post_mode}")
    post_count = [0]

    def _handler(_attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            post_req = _r9_read_http_request(tls)
            assert post_req.startswith(b"POST /v2/operator/doctor/fix HTTP/1.1\r\n")
            post_count[0] += 1
            tls.sendall(raw_post_resp)

    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        with pytest.raises(AssertionError):
            _post_operator(ready, ca_pem, "/v2/operator/doctor/fix", "tok-r9", {"actions": ["rotate_logs"]}, 2.0)

    assert accepts[0] == 1
    assert post_count[0] == 1


def test_r9_pre_post_ssl_syscall_error_recovers_within_three_attempts(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Transient ssl.SSLSyscallError before POST bytes are sent must recover cleanly within 3 attempts."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, "r9-syscall")
    post_count = [0]
    handshake_calls = [0]
    orig_handshake = ssl.SSLSocket.do_handshake

    def _syscall_once(self: ssl.SSLSocket, block: bool = False) -> None:
        if not self.server_side:
            handshake_calls[0] += 1
            if handshake_calls[0] == 1:
                raise ssl.SSLSyscallError(-1, "Unexpected EOF while reading")
        orig_handshake(self, block)

    def _handler(attempt: int, raw: socket.socket) -> None:
        if attempt == 1:
            return
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            _r9_write_http_json(tls, "200 OK", {"ready": True})
            _r9_read_http_request(tls)
            post_count[0] += 1
            _r9_write_http_json(tls, "200 OK", {"ok": True, "data": {"recovered": "ssl_syscall"}})

    monkeypatch.setattr(ssl.SSLSocket, "do_handshake", _syscall_once)
    with _r9_faulty_server(ready_tpl, _handler) as (ready, accepts):
        env = _post_operator(ready, ca_pem, "/v2/operator/doctor/report", "tok-r9", {"deep": True}, 2.0)

    assert handshake_calls[0] == 2
    assert accepts[0] == 2
    assert post_count[0] == 1
    assert env == {"ok": True, "data": {"recovered": "ssl_syscall"}}


def test_r9_complete_non_200_identity_never_retries_or_sends_post(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete non-200 State-0 HTTP response must fail/return in 1 attempt without retrying or sending POST."""
    ready_tpl, ca_pem, server_ctx = _r9_tls_pair(trusted_tmp, "r9-complete-503")
    raw_503 = b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 10\r\n\r\n{"ok":0}\r\n'
    secret_token = "tok-secret-never-sent-503"
    sent_frames: list[bytes] = []
    orig_sendall = ssl.SSLSocket.sendall

    def _spy_sendall(self: ssl.SSLSocket, data: Any, flags: int = 0) -> None:
        sent_frames.append(bytes(data))
        orig_sendall(self, data, flags)

    def _handler(_attempt: int, raw: socket.socket) -> None:
        with server_ctx.wrap_socket(raw, server_side=True) as tls:
            assert _r9_read_http_request(tls).startswith(b"GET /v2/identity HTTP/1.1\r\n")
            tls.sendall(raw_503)

    monkeypatch.setattr(ssl.SSLSocket, "sendall", _spy_sendall)
    with _r9_faulty_server(ready_tpl, _handler) as (ready_false, accepts_false):
        got = post_tls_raw(
            ready_false,
            ca_pem,
            "/v2/operator/doctor/report",
            secret_token,
            {},
            require_identity_200=False,
        )
    assert accepts_false[0] == 1
    assert got == raw_503
    assert not any(b"POST " in c or secret_token.encode("ascii") in c for c in sent_frames)

    sent_frames.clear()
    with _r9_faulty_server(ready_tpl, _handler) as (ready_true, accepts_true):
        with pytest.raises(AssertionError):
            _post_operator(ready_true, ca_pem, "/v2/operator/doctor/report", secret_token, {}, 2.0)
    assert accepts_true[0] == 1
    assert not any(b"POST " in c or secret_token.encode("ascii") in c for c in sent_frames)
