"""Independent RED oracle for SP1 increment 4 re-review findings I4-R3-01, I4-R3-02, I4-R3-03 (review 2026-11-23).

Requirement source: ``docs/reviews/2026-11-23-sp1-increment4-rereview-r3.md``.

Invariants under test:
- I4-R3-01: while a ``doctor --fix`` filesystem step is still preparing, the request cutoff, the runtime generation and
  the operator credential are re-verified at the boundary where it starts writing. ``rotate_logs`` (new rotation and
  interrupted-rotation recovery) and ``tighten_permissions`` never write after the cutoff passed, the credential was
  revoked or an owner-side restore changed the generation, and no late supervisor restart follows.
- I4-R3-02: every deep-health result that feeds the M1 verdict is bound to the exact store and writer generation of
  the inspected run; a missing, mistyped or mismatched ``store_id``/``writer_epoch`` (or a snapshot whose own store
  identity or writer epoch cannot be resolved) never yields ``m1_ready=True``.
- I4-R3-03: a post-fix recheck report is returned as current only if source and generation still match after the
  scan completed; otherwise the response is interrupted (or an auth error), still reporting applied actions
  definitively.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import superbrain.application._log_rotate as log_rotate
import superbrain.composition._doctor_fix_wiring as fix_wiring
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.application.owner_loop import OwnerLoop
from superbrain.composition import daemon_entry
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core._kernel_deadlines import OPERATOR_REQUEST_BUDGET_NS
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import MAX_LOG_BYTES, CaptureDoctorSnapshot, SupervisorRestartResult
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_probes import probe_daemon_state
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_fix import _acl_or_mode
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, MACHINE_ID, OWNER_DAN, _base_utc_now, _init_doctor_root
from tests.integration.test_i4_owner_thread_remediation import _BlockingPermissions, _post_operator, _widen_target
from tests.integration.test_i4_rereview_remediation import (
    _action_status,
    _Daemon,
    _drain_owner,
    _HarnessWithReceipt,
    _m1_setup,
    _seed_unapplied_intent,
)
from tests.integration.test_i4_review_remediation import _run_online_restore_helper
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_ca_file, write_client_profile_file, write_credential_file
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

CLIENT_THREAD = "i4-r3-client"
CUTOFF_RESERVE_NS = 500_000_000
LOG_MARKER = b"i4-r3-01 active log line\n"

# ---------------------------------------------------------------------------
# Shared daemon harness
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _serve(
    cfg: Any, *, os_: OsAdapters, clock: FakeClock, mono: FakeMonotonicClock, **serve_kw: Any
) -> Iterator[_Daemon]:
    """``daemon_entry.serve`` in a thread with the live runtime captured; extra kwargs go to ``serve``."""
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
                **serve_kw,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-r3-serve", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve() did not become ready (exits={exits})"
        yield _Daemon(box["ready"], cast(OwnerLoop, box["loop"]), stop_ev, thr, rt_box)
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve thread leaked"


class _Gate:
    """One-shot block point: the first armed ``hit()`` blocks until ``release``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.armed = False
        self._fired = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def hit(self) -> None:
        with self._lock:
            fire = self.armed and not self._fired
            if fire:
                self._fired = True
        if fire:
            self.entered.set()
            self.release.wait(timeout=BOUND_WAIT_S * 3)


class _CountingSupervisor:
    def __init__(self) -> None:
        self.calls = 0

    def restart_daemon(self, config_path: Path) -> SupervisorRestartResult:
        _ = config_path
        self.calls += 1
        return SupervisorRestartResult(status="applied", restarted=True, detail="i4-r3 fake restart")


@dataclass
class _Env:
    clock: FakeClock
    mono: FakeMonotonicClock
    rep: Any
    cfg: Any
    priv: Any
    ca_pem: str
    cli_token: str
    os_: OsAdapters
    cred: Any
    policy_bak: Path


def _setup(trusted_tmp: Path, label: str, *, os_: OsAdapters | None = None) -> _Env:
    """Store + a revocable CLI credential + a policy backup taken after that credential exists (so a restore changes
    only the generation, never the fix caller's authority)."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, priv, ca_pem, _leaf, cli_token, adapters = _init_doctor_root(trusted_tmp / label, clock, os_=os_)
    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, adapters)
    try:
        cred = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID
        )
        policy_bak = create_policy_backup(rt.policy, adapters, clock.now())
    finally:
        rt.close()
    return _Env(clock, mono, rep, cfg, priv, ca_pem, cli_token, adapters, cred, policy_bak)


def _start_fix(daemon: _Daemon, env: _Env, actions: list[str]) -> tuple[threading.Thread, dict[str, Any]]:
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["env"] = _post_operator(
                daemon.ready, env.ca_pem, "/v2/operator/doctor/fix", env.cred.token, {"actions": list(actions)}, 25.0
            )
        except Exception as exc:  # noqa: BLE001
            box["exc"] = exc

    thr = threading.Thread(target=_call, name=CLIENT_THREAD, daemon=True)
    thr.start()
    return thr, box


def _inject(kind: str, daemon: _Daemon, env: _Env, admission_ns: int) -> None:
    """Change cutoff / credential / generation while the fix worker is blocked after its authorization."""
    if kind == "cutoff":
        env.mono.set(admission_ns + OPERATOR_REQUEST_BUDGET_NS - CUTOFF_RESERVE_NS + 100_000_000)
    elif kind == "revoke":
        auth = make_bootstrap_auth(
            store_id=env.rep.store_id,
            owner_id=OWNER_DAN,
            action="credential_revoke",
            subject_id=env.cred.credential_id,
            trust_generation=1,
            expires_at=env.clock.now() + timedelta(hours=1),
        )
        daemon.loop.revoke_credential(env.cred.credential_id, auth).result(timeout=BOUND_WAIT_S)
    elif kind == "restore":
        _run_online_restore_helper(
            daemon.ready, env.rep, env.ca_pem, env.cli_token, env.priv, env.os_, "policy", env.policy_bak
        )
    else:
        assert kind == "none", kind


def _run_blocked_fix(
    daemon: _Daemon, env: _Env, gate: _Gate, actions: list[str], inject: str
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    admission_ns = env.mono.now  # frozen until advanced by an injection
    gate.armed = True
    thr, box = _start_fix(daemon, env, actions)
    try:
        assert gate.entered.wait(timeout=BOUND_WAIT_S), f"fix never reached the block point: {box}"
        _inject(inject, daemon, env, admission_ns)
    finally:
        gate.release.set()
    thr.join(timeout=BOUND_WAIT_S * 2)
    assert not thr.is_alive(), "fix request never returned"
    _drain_owner(daemon)
    time.sleep(0.3)  # anything still writing after the response would land here
    assert "exc" not in box, f"fix request transport failed: {box.get('exc')!r}"
    resp = cast(dict[str, Any] | None, box.get("env"))
    return resp, box


def _data(resp: dict[str, Any] | None) -> dict[str, Any]:
    assert isinstance(resp, dict), resp
    return cast(dict[str, Any], resp.get("data") or {})


# ---------------------------------------------------------------------------
# I4-R3-01 (a, b): rotate_logs re-verifies at its write-start boundary
# ---------------------------------------------------------------------------


def _logs_state(logs: Path) -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(logs.iterdir())
        if p.name.startswith(("brain.log", ".brain.log", ".rotate-state-"))
    }


def _seed_active_log(logs: Path, os_: OsAdapters, *, oversized: bool) -> None:
    active = logs / "brain.log"
    body = LOG_MARKER * ((MAX_LOG_BYTES // len(LOG_MARKER)) + 64) if oversized else LOG_MARKER
    active.write_bytes(body)
    os_.permissions.secure_file(active)


def _seed_pending_rotation(logs: Path, os_: OsAdapters) -> tuple[Path, Path]:
    """A write-ahead journal + staged file exactly as ``rotate_logs`` leaves them after its stage move."""
    rot_id = new_id()
    staged = logs / f".brain.log.rotating-{rot_id}"
    payload = b"i4-r3-01 staged rotation bytes\n" * 64
    staged.write_bytes(payload)
    os_.permissions.secure_file(staged)
    state = logs / f".rotate-state-{rot_id}.json"
    state.write_bytes(
        json.dumps(
            {
                "id": rot_id,
                "phase": "pending_move",
                "size": len(payload),
                "digest": hashlib.sha256(payload).hexdigest(),
                "shift_order": [],
            },
            sort_keys=True,
        ).encode("utf-8")
    )
    os_.permissions.secure_file(state)
    return state, staged


def _install_block(block: str, gate: _Gate, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``quiesce``: block inside the configured ``log_quiesce_hook``; ``hash``: block in the log hash helper."""
    serve_kw: dict[str, Any] = {}
    if block == "quiesce":

        @contextlib.contextmanager
        def _hook() -> Iterator[None]:
            gate.hit()
            yield

        serve_kw["log_quiesce_hook"] = _hook
    else:
        orig = log_rotate._sha256_file

        def _blocking_hash(path: Path) -> tuple[int, str]:
            gate.hit()
            return orig(path)

        monkeypatch.setattr(log_rotate, "_sha256_file", _blocking_hash)
    return serve_kw


def _rotate_case(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, label: str, *, block: str, inject: str, recovery: bool
) -> tuple[dict[str, Any] | None, dict[str, str], dict[str, str], _CountingSupervisor, Path]:
    env = _setup(trusted_tmp, label)
    gate = _Gate()
    supervisor = _CountingSupervisor()
    serve_kw = _install_block(block, gate, monkeypatch)
    logs = DataRoot.at(env.cfg.data_root).logs_dir
    with _serve(
        env.cfg,
        os_=env.os_,
        clock=env.clock,
        mono=env.mono,
        supervisor_control=supervisor,
        config_path=env.rep.daemon_config_path,
        **serve_kw,
    ) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        logs.mkdir(parents=True, exist_ok=True)
        env.os_.permissions.secure_directory(logs)
        _seed_active_log(logs, env.os_, oversized=not recovery)
        if recovery:
            _seed_pending_rotation(logs, env.os_)
        before = _logs_state(logs)
        resp, _box = _run_blocked_fix(daemon, env, gate, ["rotate_logs", "restart_daemon"], inject)
        after = _logs_state(logs)
    return resp, before, after, supervisor, logs


def _assert_no_rotation_write(
    resp: dict[str, Any] | None, before: dict[str, str], after: dict[str, str], sup: _CountingSupervisor, what: str
) -> None:
    violations: list[str] = []
    if sorted(after) != sorted(before):
        violations.append(f"logs directory entries changed: {sorted(before)} -> {sorted(after)}")
    if "brain.log.1" in after:
        violations.append("brain.log.1 was created")
    if after.get("brain.log") != before.get("brain.log"):
        violations.append("active brain.log was moved or replaced")
    if _action_status(resp, "rotate_logs") == "applied":
        violations.append("client received rotate_logs=applied")
    if sup.calls:
        violations.append(f"supervisor restart called {sup.calls} time(s) after the injection")
    assert not violations, f"I4-R3-01 rotate_logs wrote after {what}:\n" + "\n".join(violations) + f"\nresp={resp}"


@pytest.mark.parametrize("inject", ["cutoff", "revoke", "restore"])
@pytest.mark.parametrize("block", ["quiesce", "hash"])
def test_r3_01_rotate_logs_does_not_write_after_late_invalidation(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, block: str, inject: str
) -> None:
    """Invariant: an oversized brain.log is not rotated (no journal, no move, no brain.log.1, not ``applied``, no
    restart) when the cutoff passes, the credential is revoked or a restore changes generation after the step was
    authorized but before it starts writing."""
    resp, before, after, sup, _logs = _rotate_case(
        trusted_tmp, monkeypatch, f"a-{block}-{inject}", block=block, inject=inject, recovery=False
    )
    _assert_no_rotation_write(resp, before, after, sup, f"{inject} injected at {block}")


@pytest.mark.parametrize("block", ["quiesce", "hash"])
def test_r3_01_rotate_logs_control_rotates_before_cutoff(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, block: str
) -> None:
    """Invariant (positive control): the same blocked-then-released action with nothing injected really rotates."""
    resp, before, after, _sup, logs = _rotate_case(
        trusted_tmp, monkeypatch, f"a-{block}-ctrl", block=block, inject="none", recovery=False
    )
    assert "brain.log.1" not in before
    assert "brain.log.1" in after, f"control did not rotate: {sorted(after)} resp={resp}"
    assert (logs / "brain.log.1").read_bytes().startswith(LOG_MARKER)
    assert _action_status(resp, "rotate_logs") == "applied", resp


@pytest.mark.parametrize("inject", ["cutoff", "revoke"])
@pytest.mark.parametrize("block", ["quiesce", "hash"])
def test_r3_01_rotation_recovery_does_not_write_after_late_invalidation(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, block: str, inject: str
) -> None:
    """Invariant: interrupted-rotation recovery is a write too; a pending journal and staged file stay untouched when
    the cutoff passes or the credential is revoked after authorization."""
    resp, before, after, sup, _logs = _rotate_case(
        trusted_tmp, monkeypatch, f"b-{block}-{inject}", block=block, inject=inject, recovery=True
    )
    _assert_no_rotation_write(resp, before, after, sup, f"{inject} injected at {block} (recovery branch)")


def test_r3_01_rotation_recovery_control_recovers(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant (positive control): without injection the pending journal is recovered into brain.log.1."""
    resp, before, after, _sup, _logs = _rotate_case(
        trusted_tmp, monkeypatch, "b-hash-ctrl", block="hash", inject="none", recovery=True
    )
    assert any(n.startswith(".rotate-state-") for n in before)
    assert "brain.log.1" in after and not any(n.startswith((".rotate-state-", ".brain.log.")) for n in after), after
    assert _action_status(resp, "rotate_logs") == "applied", resp


# ---------------------------------------------------------------------------
# I4-R3-01 (c): tighten_permissions re-verifies per entry
# ---------------------------------------------------------------------------


def _tighten_case(trusted_tmp: Path, label: str, inject: str) -> tuple[dict[str, Any] | None, str, str]:
    clock = FakeClock(_base_utc_now())
    base_os = os_adapters(clock=clock)
    # _BlockingPermissions needs the data root; build it from the same layout _init_doctor_root uses.
    data_root = trusted_tmp / label / "data"
    guard = _BlockingPermissions(base_os.permissions, data_root)
    wrapped_os = replace(base_os, permissions=cast(Any, guard))
    env = _setup(trusted_tmp, label, os_=base_os)
    assert Path(env.cfg.data_root) == data_root
    gate = _Gate()  # the guard is the block point; gate only mirrors its events for _run_blocked_fix
    gate.entered, gate.release = guard.entered, guard.release
    with _serve(env.cfg, os_=wrapped_os, clock=env.clock, mono=env.mono) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target, _tight, widened = _widen_target(DataRoot.at(env.cfg.data_root), base_os)
        guard.armed = True
        resp, _box = _run_blocked_fix(daemon, env, gate, ["tighten_permissions"], inject)
        acl_after = _acl_or_mode(target)
    return resp, widened, acl_after


@pytest.mark.parametrize("inject", ["cutoff", "revoke"])
def test_r3_01_tighten_permissions_does_not_change_acl_after_late_invalidation(trusted_tmp: Path, inject: str) -> None:
    """Invariant: after the first per-entry inspection, a passed cutoff or a revoked credential stops the ACL walk;
    the widened entry keeps its ACL and the client never sees ``applied``."""
    resp, widened, acl_after = _tighten_case(trusted_tmp, f"c-{inject}", inject)
    assert acl_after == widened, f"ACL of a widened entry was changed after {inject}; resp={resp}"
    assert _action_status(resp, "tighten_permissions") != "applied", resp


def test_r3_01_tighten_permissions_control_tightens(trusted_tmp: Path) -> None:
    """Invariant (positive control): without injection the widened entry is tightened."""
    resp, widened, acl_after = _tighten_case(trusted_tmp, "c-ctrl", "none")
    assert acl_after != widened, f"control did not tighten the widened entry; resp={resp}"
    assert _action_status(resp, "tighten_permissions") == "applied", resp


# ---------------------------------------------------------------------------
# I4-R3-03: post-fix recheck report needs a final fence
# ---------------------------------------------------------------------------


def _recheck_case(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, label: str, inject: str
) -> dict[str, Any] | None:
    env = _setup(trusted_tmp, label)
    gate = _Gate()
    orig_read = fix_wiring.read_doctor_snapshot

    def _blocking_read(*args: Any, **kwargs: Any) -> Any:
        gate.hit()  # the worker DB snapshot is already taken; the scan has not run yet
        return orig_read(*args, **kwargs)

    monkeypatch.setattr(fix_wiring, "read_doctor_snapshot", _blocking_read)
    with _serve(env.cfg, os_=env.os_, clock=env.clock, mono=env.mono) as daemon:
        assert daemon.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _seed_unapplied_intent(daemon, label)
        resp, _box = _run_blocked_fix(daemon, env, gate, ["reconcile_policy"], inject)
    return resp


@pytest.mark.parametrize("inject", ["restore", "cutoff"])
def test_r3_03_recheck_after_generation_change_or_cutoff_is_not_current(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, inject: str
) -> None:
    """Invariant: a restore or the cutoff landing during the recheck scan makes the response ``interrupted`` (not a
    current report) while the already applied reconcile is still reported as ``applied``."""
    resp = _recheck_case(trusted_tmp, monkeypatch, f"d-{inject}", inject)
    assert isinstance(resp, dict) and resp.get("ok") is True, resp
    data = _data(resp)
    assert data.get("status") == "interrupted", (
        f"post-fix report returned as current after {inject} during the recheck: status={data.get('status')!r}"
    )
    assert _action_status(resp, "reconcile_policy") == "applied", f"applied action lost its definite state: {resp}"


def test_r3_03_recheck_after_credential_revoked_is_not_current(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: a credential revoked during the recheck scan yields an auth error or ``interrupted``, never a normal
    current report."""
    resp = _recheck_case(trusted_tmp, monkeypatch, "d-revoke", "revoke")
    assert isinstance(resp, dict), resp
    if resp.get("ok") is True:
        assert _data(resp).get("status") == "interrupted", (
            f"post-fix report returned as current after the credential was revoked: {_data(resp).get('status')!r}"
        )


def test_r3_03_recheck_control_returns_current_report(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant (positive control): with nothing injected the blocked-then-released recheck returns the normal
    report with the applied action and rechecked checks."""
    resp = _recheck_case(trusted_tmp, monkeypatch, "d-ctrl", "none")
    assert isinstance(resp, dict) and resp.get("ok") is True, resp
    data = _data(resp)
    assert data.get("status", "completed") == "completed", data.get("status")
    assert _action_status(resp, "reconcile_policy") == "applied", resp
    assert cast(dict[str, Any], data.get("fix") or {}).get("rechecked_checks"), data


# ---------------------------------------------------------------------------
# I4-R3-02: deep health bound to store and writer generation
# ---------------------------------------------------------------------------

_MISSING = object()


def _live_writer_epoch(rep: Any, os_: OsAdapters) -> int:
    """The writer generation recorded in the store's writer.lock (what a live get_health would report)."""
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    epoch = probe_daemon_state(DataRoot.at(cfg.data_root), os_, []).writer_epoch
    assert isinstance(epoch, int) and not isinstance(epoch, bool), epoch
    return epoch


def _write_profile(trusted_tmp: Path, rep: Any, os_: OsAdapters, checkout: Path, receipt: dict[str, Any]) -> Path:
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    leaf = verify_server_tls_files(cfg, os_.clock, os_).leaf_cert_sha256
    ca_pem = (rep.daemon_config_path.parent / "tls" / "ca.pem").read_text(encoding="utf-8")
    prof_dir = trusted_tmp / "profiles"
    ca_file = write_ca_file(prof_dir / "ca.pem", ca_pem)
    token = rep.cli_credential_path.read_text(encoding="utf-8").strip()
    cred_file = write_credential_file(prof_dir / "cli.cred", token)
    scope = receipt["run_scope"]
    profile, _ = write_client_profile_file(
        prof_dir / "cli.profile.json",
        endpoint_path=DataRoot.at(cfg.data_root).endpoint_path,
        expected_store_id=rep.store_id,
        ca_file=ca_file,
        leaf_cert_sha256=leaf,
        credential_file=cred_file,
        workspace={
            "alias": "ws-clean",
            "checkout_path": str(checkout),
            "expected_workspace_id": scope["repo_id"],
            "expected_checkout_id": scope["checkout_id"],
        },
    )
    return profile


def _m1(
    sp2: Any,
    path: Path,
    os_: OsAdapters,
    receipt: dict[str, Any],
    dh: dict[str, JsonValue],
    checkout: Path,
    *,
    is_profile: bool,
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

    return cast(
        dict[str, Any],
        sp2.run_m1_handover_probe(
            path,
            is_profile=is_profile,
            checkout_root=checkout,
            os_=os_,
            capture_probe=sp2.build_sp2_capture_probe(_snap, require_native_receipts=True),
            deep_health=dh,
            require_native_receipts=True,
        ),
    )


def _r302_inputs(
    trusted_tmp: Path, mode: str
) -> tuple[Any, Path, OsAdapters, dict[str, Any], dict[str, Any], Path, bool]:
    sp2, rep, os_, checkout, receipt, dh, _unreg = _m1_setup(trusted_tmp)
    bound = {**dh, "store_id": rep.store_id, "writer_epoch": _live_writer_epoch(rep, os_)}
    if mode == "profile":
        return sp2, _write_profile(trusted_tmp, rep, os_, checkout, receipt), os_, receipt, bound, checkout, True
    return sp2, rep.daemon_config_path, os_, receipt, bound, checkout, False


@pytest.mark.parametrize("mode", ["config", "profile"])
def test_r3_02_m1_positive_control_bound_deep_health(trusted_tmp: Path, mode: str) -> None:
    """Invariant (positive control): deep health bound to this store and its live writer epoch, with bound native
    evidence, is ``m1_ready=True`` and the deep-health surface is PASS."""
    sp2, path, os_, receipt, dh, checkout, is_profile = _r302_inputs(trusted_tmp, mode)
    res = _m1(sp2, path, os_, receipt, dh, checkout, is_profile=is_profile)
    assert res["surfaces"][sp2.M1_SURFACE_DEEP_HEALTH]["status"] == "PASS", res["surfaces"]
    assert res["m1_ready"] is True, res


_DH_VARIANTS: dict[str, tuple[str, object]] = {
    "store_id_missing": ("store_id", _MISSING),
    "store_id_none": ("store_id", None),
    "store_id_empty": ("store_id", ""),
    "store_id_int": ("store_id", 12345),
    "writer_epoch_missing": ("writer_epoch", _MISSING),
    "writer_epoch_none": ("writer_epoch", None),
    "writer_epoch_wrong": ("writer_epoch", 9999),
    "writer_epoch_bool": ("writer_epoch", True),
    "writer_epoch_str": ("writer_epoch", "LIVE"),
    "writer_epoch_float": ("writer_epoch", "LIVE_FLOAT"),
}


def _apply_dh_variant(dh: dict[str, Any], variant: str) -> dict[str, Any]:
    key, value = _DH_VARIANTS[variant]
    out = dict(dh)
    if value is _MISSING:
        del out[key]
    elif value == "LIVE":
        out[key] = str(dh["writer_epoch"])
    elif value == "LIVE_FLOAT":
        out[key] = float(dh["writer_epoch"])
    else:
        out[key] = value
    return out


@pytest.mark.parametrize(
    ("mode", "variant"),
    [("config", v) for v in _DH_VARIANTS] + [("profile", "store_id_missing"), ("profile", "writer_epoch_wrong")],
)
def test_r3_02_m1_unbound_deep_health_is_not_ready(trusted_tmp: Path, mode: str, variant: str) -> None:
    """Invariant: a deep-health response whose store_id or writer_epoch is missing, mistyped or not the inspected
    store's live generation never yields ``m1_ready=True`` and its surface is not PASS."""
    sp2, path, os_, receipt, dh, checkout, is_profile = _r302_inputs(trusted_tmp, mode)
    res = _m1(sp2, path, os_, receipt, _apply_dh_variant(dh, variant), checkout, is_profile=is_profile)
    surf = res["surfaces"][sp2.M1_SURFACE_DEEP_HEALTH]
    assert res["m1_ready"] is False, f"{mode}/{variant}: m1_ready=True for deep health not bound to the run"
    assert surf["status"] != "PASS", f"{mode}/{variant}: deep-health surface PASS: {surf}"


@pytest.mark.parametrize(
    "variant", ["snapshot_store_id_none", "snapshot_writer_epoch_none", "snapshot_daemon_stats_none"]
)
def test_r3_02_m1_unresolvable_snapshot_identity_is_not_ready(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """Invariant: when the inspected snapshot's own store identity or writer epoch cannot be resolved, an otherwise
    well-formed deep-health response cannot be bound and M1 fails closed."""
    sp2, path, os_, receipt, dh, checkout, is_profile = _r302_inputs(trusted_tmp, "config")
    orig = sp2.read_doctor_snapshot

    def _unresolved(*args: Any, **kwargs: Any) -> Any:
        snap = orig(*args, **kwargs)
        if variant == "snapshot_store_id_none":
            return replace(snap, store_id=None)
        if variant == "snapshot_writer_epoch_none":
            assert snap.daemon_stats is not None
            return replace(snap, daemon_stats=replace(snap.daemon_stats, writer_epoch=None))
        return replace(snap, daemon_stats=None)

    monkeypatch.setattr(sp2, "read_doctor_snapshot", _unresolved)
    res = _m1(sp2, path, os_, receipt, dh, checkout, is_profile=is_profile)
    surf = res["surfaces"][sp2.M1_SURFACE_DEEP_HEALTH]
    assert res["m1_ready"] is False, f"{variant}: m1_ready=True with an unresolvable snapshot identity"
    assert surf["status"] != "PASS", f"{variant}: deep-health surface PASS: {surf}"



@pytest.mark.parametrize("dh_store_id", ["missing", "none"])
def test_r3_02_m1_identity_missing_on_both_sides_is_not_ready(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, dh_store_id: str
) -> None:
    """Invariant: missing identity on either side never binds; a deep-health response without store_id checked
    against a snapshot whose own store_id cannot be resolved (None == None) is not ``m1_ready``."""
    sp2, path, os_, receipt, dh, checkout, is_profile = _r302_inputs(trusted_tmp, "config")
    dh = _apply_dh_variant(dh, "store_id_missing" if dh_store_id == "missing" else "store_id_none")
    orig = sp2.read_doctor_snapshot

    def _unresolved(*args: Any, **kwargs: Any) -> Any:
        return replace(orig(*args, **kwargs), store_id=None)

    monkeypatch.setattr(sp2, "read_doctor_snapshot", _unresolved)
    res = _m1(sp2, path, os_, receipt, dh, checkout, is_profile=is_profile)
    surf = res["surfaces"][sp2.M1_SURFACE_DEEP_HEALTH]
    assert res["m1_ready"] is False, f"both-missing/{dh_store_id}: m1_ready=True with no store identity on either side"
    assert surf["status"] != "PASS", f"both-missing/{dh_store_id}: deep-health surface PASS: {surf}"
