"""Integration regressions for SP1 Increment 2 Task 6a: daemon owner loop, startup, health, auth & shutdown.

Covers all 16 named lifecycle regressions in ``task-6a-brief.md``:
- Group 1 (6a.1): writer lock exclusivity across real child processes, post-kill epoch/instance replacement,
  maintenance vs writer exclusivity, missing/wrong/unmigrated store byte-immutability, unsafe endpoint/stage
  entries refused under lease before write, recovery/publish/TLS/credential failures never publishing Ready,
  and legacy v1 incomplete settled projection + old-epoch job/invocation + pending send-attempt recovery.
- Group 2 (6a.2): zero-I/O RAM shallow health bypassing blocked write commits & full 32-slot queue, UTC-clock
  TLS expiry boundaries & admission fencing, production ``get_job`` owner/scope ACLs & ``capability_unavailable``
  domain tools, ``AuthGate`` invalidation & release-grant fencing, terminal stop fence against late publish,
  external arbiter 1,475 ms commit cutoff + late-owner clock recheck under state lock, and reserve/enqueue
  settlement race on stop or full queue.
- Group 3 (6a.3): shutdown keeping ``writer.lock`` until both DB handles close (clean & overrun + foreground
  ``serve`` cleanup wait + slow-worker fence), and ``Runtime.close`` failure retaining the lease without
  double-releasing ``AdmittedWriter``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import functools
import math
import os
import shutil
import socket
import sqlite3
import sys
import threading
import time
import uuid
import warnings
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.owner_loop import AuthGate, OwnerLoop
from superbrain.composition.daemon_entry import (
    PRODUCTION_JOB_HANDLERS,
    BoundLoopbackListener,
    DaemonTestHooks,
    create_daemon_owner_loop,
    publish_endpoint,
    remove_own_endpoint,
    serve,
)
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DAEMON_QUEUE_DEPTH,
    ENDPOINT_CONTRACT,
    ENDPOINT_HOST,
    ENDPOINT_VERSION,
    HANDLER_RESERVE_NS,
    RESPONSE_RESERVE_NS,
    TOTAL_REQUEST_BUDGET_NS,
    AccountingStatus,
    ArtifactSendSpec,
    AuthGrantStamp,
    Call,
    CallContext,
    CallResult,
    DaemonConfig,
    Endpoint,
    InvocationState,
    JobErrorCode,
    JobOutcome,
    JobRecord,
    JobSpec,
    JobState,
    KernelRecord,
    ObjectRef,
    OwnerReply,
    Principal,
    Ready,
    RecoveryCounts,
    RequestAuthView,
    ResourceDigest,
    Scope,
    SendAttemptState,
    ShutdownReport,
    ShutdownState,
    StoredResult,
    TlsMaterial,
    ToolCommand,
    UsageRecord,
    UsageReservation,
    WorkerUsage,
    WorkspaceBinding,
    usage_descriptor,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import DurabilityReport, OsAdapters
from superbrain.ports.policy import IntentKind, PolicyView
from superbrain.storage.cas import held_digests
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import EntryKind, FieldType, KindRegistry
from superbrain.storage.layout import (
    ENDPOINT_NAME,
    ENDPOINT_STAGE_PREFIX,
    DataRoot,
    check_endpoint_entries_under_lease,
    prepare_data_root,
)
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS
from superbrain.storage.send_attempts import KernelSendAttemptStore, read_send_attempt_row
from superbrain.storage.writer import acquire_writer, acquire_writer_unbumped
from superbrain.workers.executor import JobContext, JobExecutor, WorkItem
from tests.support.clock import FakeClock
from tests.support.fs import digest_data_root, digest_tree, fake_link, file_identity
from tests.support.inc2_child import spawn_migrate_child, spawn_serve_child
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
)

BOUND_WAIT_S = 8.0
REMOTE_A = "https://github.com/dan/daemon-repo-a.git"
REMOTE_EXTRA = "https://github.com/dan/daemon-repo-extra.git"
RESERVE = UsageReservation("1")


class _FakeMonotonicClock:
    """Thread-safe deterministic monotonic clock (nanoseconds) for owner/arbiter tests."""

    def __init__(self, start_ns: int = 1_000_000_000) -> None:
        self._lock = threading.Lock()
        self._now_ns = start_ns

    @property
    def now(self) -> int:
        with self._lock:
            return self._now_ns

    def set(self, value_ns: int) -> None:
        with self._lock:
            self._now_ns = value_ns

    def advance(self, delta_ns: int) -> int:
        with self._lock:
            self._now_ns += delta_ns
            return self._now_ns

    def monotonic_ns(self) -> int:
        with self._lock:
            return self._now_ns


@dataclass(frozen=True)
class _DaemonTemplate:
    base_dir: Path
    root: Path
    store_id: str
    base_time: dt.datetime
    tls: TlsMaterial
    dan: Principal
    cred_a: SeededCredential
    cred_b: SeededCredential
    bob: Principal
    cred_bob: SeededCredential
    dan_other_machine: Principal
    cred_other_machine: SeededCredential
    ws_a: WorkspaceBinding
    ws_b: WorkspaceBinding
    checkout_extra_dir: Path


def _make_module_trusted_dir(label: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard

        base = Path(os.environ["LOCALAPPDATA"]) / "superbrain-tests" / f"{label}-{uuid.uuid4()}"
        base.mkdir(parents=True)
        WindowsPermissionGuard().secure_directory(base)
        return base
    else:
        base = tmp_path_factory.mktemp(label)
        os.chmod(base, 0o700)
        return base


def _clone_owner_only_tree(src: Path, dst: Path) -> None:
    """Clone ``src`` into ``dst`` inside ``trusted_tmp`` with strict owner-only permissions."""
    dst.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(dst, 0o700)
    for cur_dir, dirnames, filenames in os.walk(src):
        rel = Path(cur_dir).relative_to(src)
        target_base = dst / rel if rel != Path(".") else dst
        for dname in dirnames:
            sub = target_base / dname
            sub.mkdir(exist_ok=True)
            if sys.platform != "win32":
                os.chmod(sub, 0o700)
        for fname in filenames:
            sfile = Path(cur_dir) / fname
            tfile = target_base / fname
            tfile.write_bytes(sfile.read_bytes())
            if sys.platform != "win32":
                os.chmod(tfile, 0o600)


def _write_daemon_config(
    config_path: Path,
    *,
    data_root: Path,
    expected_store_id: str,
    cert_path: Path,
    key_path: Path,
    os_: OsAdapters | None = None,
) -> DaemonConfig:
    adapters = os_ if os_ is not None else os_adapters()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(config_path.parent, 0o700)
    raw = canonical_json(
        {
            "version": 1,
            "data_root": str(data_root),
            "expected_store_id": expected_store_id,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
        }
    )
    adapters.publisher.write_new(config_path, raw)
    adapters.permissions.secure_file(config_path)
    return read_daemon_config(config_path, adapters)


def _provision_tls(
    store_id: str,
    dest: Path,
    clock: FakeClock,
    os_: OsAdapters,
) -> TlsMaterial:
    auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=1),
        destination=dest,
    )
    return create_store_tls(store_id, dest, auth, clock, os_)


def _register_workspace_direct(
    rt: Runtime,
    clock: FakeClock,
    principal: Principal,
    *,
    alias: str,
    checkout_dir: Path,
    remote: str = REMOTE_A,
) -> WorkspaceBinding:
    checkout_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(checkout_dir, 0o700)
    reg = build_registration(
        owner_id=principal.owner_id,
        principal_id=principal.principal_id,
        machine_id=principal.machine_id,
        alias=alias,
        raw_path=str(checkout_dir),
        raw_remote=remote,
        provider_egress_enabled=False,
    )
    proof = make_bootstrap_auth(
        store_id=rt.policy.store_id,
        owner_id=principal.owner_id,
        action="workspace_register",
        subject_id=reg.subject_id,
        trust_generation=rt.policy.trust_generation(),
        expires_at=clock.now() + dt.timedelta(hours=1),
    )
    binding = rt.policy.register_authorized_workspace(reg, proof)
    rt.store.reconcile_policy()
    return binding


@pytest.fixture(scope="module")
def _daemon_template(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_DaemonTemplate]:
    """Module-scoped initialized v2 kernel store + verified TLS material (fast F4 budget)."""
    base_dir = _make_module_trusted_dir("t6a-template", tmp_path_factory)
    try:
        base_time = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=10)
        clock = FakeClock(base_time)
        adapters = os_adapters(clock=clock)
        root = base_dir / "template-data"

        rt = open_kernel_job_runtime(root, adapters)
        store_id = rt.store.store_id
        try:
            cred_a = seed_principal_and_credential(
                rt.policy,
                owner_id="dan",
                harness_id="claude-code",
                machine_id="m-1",
            )
            cred_b = seed_principal_and_credential(
                rt.policy,
                owner_id="dan",
                harness_id="claude-code",
                machine_id="m-1",
            )
            assert cred_b.principal == cred_a.principal
            assert cred_b.credential_id != cred_a.credential_id
            cred_bob = seed_principal_and_credential(
                rt.policy,
                owner_id="bob",
                harness_id="claude-code",
                machine_id="m-2",
            )
            cred_other_machine = seed_principal_and_credential(
                rt.policy,
                owner_id="dan",
                harness_id="claude-code",
                machine_id="m-other",
            )
            ws_a = _register_workspace_direct(
                rt,
                clock,
                cred_a.principal,
                alias="ws-a",
                checkout_dir=base_dir / "chk-a",
                remote=REMOTE_A,
            )
            ws_b = _register_workspace_direct(
                rt,
                clock,
                cred_a.principal,
                alias="ws-b",
                checkout_dir=base_dir / "chk-b",
                remote=REMOTE_A,
            )
            extra_dir = base_dir / "chk-extra"
            extra_dir.mkdir(parents=True, exist_ok=True)
            if sys.platform != "win32":
                os.chmod(extra_dir, 0o700)
        finally:
            rt.close()

        tls = _provision_tls(store_id, base_dir / "tls", clock, adapters)
        yield _DaemonTemplate(
            base_dir=base_dir,
            root=root,
            store_id=store_id,
            base_time=base_time,
            tls=tls,
            dan=cred_a.principal,
            cred_a=cred_a,
            cred_b=cred_b,
            bob=cred_bob.principal,
            cred_bob=cred_bob,
            dan_other_machine=cred_other_machine.principal,
            cred_other_machine=cred_other_machine,
            ws_a=ws_a,
            ws_b=ws_b,
            checkout_extra_dir=extra_dir,
        )
    finally:
        try:
            shutil.rmtree(base_dir)
        except OSError as err:
            warnings.warn(f"could not remove module template dir {base_dir}: {err}", stacklevel=1)


def _instantiate_case(
    trusted_tmp: Path,
    name: str,
    template: _DaemonTemplate,
) -> tuple[Path, Path, DaemonConfig]:
    case_base = trusted_tmp / name
    case_base.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(case_base, 0o700)
    data_root = case_base / "data"
    _clone_owner_only_tree(template.root, data_root)
    config_path = case_base / "daemon-config.json"
    cfg = _write_daemon_config(
        config_path,
        data_root=data_root,
        expected_store_id=template.store_id,
        cert_path=template.tls.cert_path,
        key_path=template.tls.key_path,
    )
    return data_root, config_path, cfg


def _expect_brain_error(expected: ErrorCode, action: Callable[[], object]) -> BrainError:
    with pytest.raises(BrainError) as caught:
        action()
    assert caught.value.code is expected, f"expected {expected!r}, got {caught.value.code!r} ({caught.value})"
    return caught.value


def _wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = BOUND_WAIT_S,
    desc: str = "condition",
) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f"Timed out after {timeout}s waiting for {desc}")
        threading.Event().wait(0.001)


def _loosen_permissions(path: Path) -> None:
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(path, "S-1-1-0", 0x120089)  # Everyone: FILE_GENERIC_READ
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def _assert_tcp_listening(endpoint: Endpoint) -> None:
    with socket.create_connection((endpoint.host, endpoint.port), timeout=5.0):
        pass


def _episode_args(ws: WorkspaceBinding, idem_key: str, *, task_id: str = "task-ep-1") -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "task_id": task_id,
        "session_id": "sess-1",
        "workspace_id": ws.repo_id,
        "checkout_id": ws.checkout_id,
        "evidence": [],
        "idempotency_key": idem_key,
    }


def _artifact_args(ws: WorkspaceBinding, idem_key: str, *, task_id: str = "task-art-1") -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "workspace_id": ws.repo_id,
        "task_id": task_id,
        "artifact_id": "art-skill-1",
        "revision": 1,
        "level": "L1",
        "idempotency_key": idem_key,
    }


@dataclass
class _DaemonTestDomain(KernelToolDomain):
    """Lightweight test-only ``KernelToolDomain`` requiring zero extra ``EntryKind``s."""

    ws_a: WorkspaceBinding
    pause_idem_keys: set[str] = field(default_factory=set)
    apply_entered: threading.Event = field(default_factory=threading.Event)
    allow_apply_finish: threading.Event = field(default_factory=threading.Event)
    on_apply_hook: Callable[[str, str], None] | None = None
    owner_error_once: list[BrainError] = field(default_factory=list)
    executed_keys: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.allow_apply_finish.set()

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if deep:
            return False
        return tool in {"prepare_task", "get_artifact", "submit_episode"}

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: dt.datetime) -> PreparedEffect:
        del ctx, now
        if self.owner_error_once:
            raise self.owner_error_once.pop(0)

        idem_key = str(call.arguments["idempotency_key"])
        res_uuid = new_id()
        assign_uuid = new_id() if call.tool == "prepare_task" else None

        if call.tool == "get_artifact":
            ref_kind = "artifact_result"
        elif call.tool == "prepare_task":
            ref_kind = "delivery_result"
        else:
            ref_kind = "episode"

        blob = canonical_json(
            {
                "schema": "t6a-test-domain-v1",
                "tool": call.tool,
                "result_id": res_uuid,
                "assignment_id": assign_uuid,
            }
        )
        ref = ObjectRef(kind=ref_kind, id=res_uuid, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            with self._lock:
                self.executed_keys.append(idem_key)
                should_pause = idem_key in self.pause_idem_keys
            if self.on_apply_hook is not None:
                self.on_apply_hook(idem_key, res_uuid)
            if should_pause:
                self.apply_entered.set()
                if not self.allow_apply_finish.wait(timeout=BOUND_WAIT_S):
                    raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            tx.hold_blob(blob, holder_id=res_uuid)
            return StoredResult(result_id=res_uuid, assignment_id=assign_uuid, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        del call, ctx
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        del principal, selected_scope
        kind = result.refs[0].kind if result.refs else "episode"
        if kind == "artifact_result":
            content = "# Loaded Skill L1\n"
            return {
                "artifact_id": "art-skill-1",
                "revision": 1,
                "level": "L1",
                "status": "ok",
                "resources": [
                    {
                        "name": "L1.md",
                        "digest": digest_bytes(content.encode("utf-8")),
                        "encoding": "utf-8",
                        "content": content,
                    }
                ],
            }
        if kind == "delivery_result":
            assert result.assignment_id is not None
            return {
                "workspace_id": self.ws_a.repo_id,
                "checkout_id": self.ws_a.checkout_id,
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": "task-prep-1",
                "delivery_id": result.result_id,
                "assignment_id": result.assignment_id,
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": [],
                "finishing_gates": [],
            }
        return {
            "episode_id": result.result_id,
            "evidence_ids": [],
            "candidate_lesson_id": None,
        }

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        del rendered, selected_scope
        if not result.refs or result.refs[0].kind != "artifact_result":
            return None
        content_digest = digest_bytes(b"# Loaded Skill L1\n")
        return ArtifactSendSpec(
            logical_result_id=result.result_id,
            principal_id=principal.principal_id,
            task_id="task-art-1",
            artifact_id="art-skill-1",
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=content_digest),),
        )


# ===========================================================================
# Group 1 (6a.1) · Admission, recovery & endpoint
# ===========================================================================


def test_two_daemons_have_one_writer(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Two real child daemons racing on the same store yield 1 Ready writer and 1 writer_held."""
    data_root, config_path, _ = _instantiate_case(trusted_tmp, "two-writers", _daemon_template)
    endpoint_path = DataRoot.at(data_root).endpoint_path
    adapters = os_adapters()

    with spawn_serve_child(config_path) as child_a, spawn_serve_child(config_path) as child_b:
        ev_a = child_a.wait_ready_or_result()
        ev_b = child_b.wait_ready_or_result()

        events = [(child_a, ev_a), (child_b, ev_b)]
        winners = [(c, ev) for c, ev in events if ev.get("event") == "ready"]
        losers = [(c, ev) for c, ev in events if ev.get("event") == "result"]
        assert len(winners) == 1 and len(losers) == 1, f"expected 1 ready + 1 writer_held, got {events!r}"

        winner, win_ev = winners[0]
        loser, lose_ev = losers[0]
        assert lose_ev.get("ok") is False
        assert lose_ev.get("error_code") == ErrorCode.WRITER_HELD.value
        loser_out = loser.wait_result()
        assert loser_out.ok is False
        assert loser_out.error_code == ErrorCode.WRITER_HELD.value
        assert loser_out.returncode != 0

        raw_ep = win_ev["endpoint"]
        assert isinstance(raw_ep, dict)
        assert set(raw_ep) == {"version", "host", "port", "store_id", "writer_epoch", "instance_id", "contract"}
        endpoint = Endpoint.from_dict(raw_ep)
        assert endpoint.version == ENDPOINT_VERSION
        assert endpoint.host == ENDPOINT_HOST
        assert 1 <= endpoint.port <= 65535
        assert endpoint.store_id == _daemon_template.store_id
        assert endpoint.writer_epoch == 2
        assert endpoint.contract == ENDPOINT_CONTRACT
        assert win_ev["leaf_cert_sha256"] == _daemon_template.tls.leaf_cert_sha256

        assert endpoint_path.exists()
        disk_bytes = endpoint_path.read_bytes()
        assert disk_bytes == endpoint.encode_canonical()
        assert adapters.permissions.object_problems(endpoint_path) == []
        assert [p.name for p in data_root.iterdir() if p.name.lower().startswith("endpoint.json.stage-")] == []
        _assert_tcp_listening(endpoint)
        ep_identity_before = file_identity(endpoint_path)

        # A subsequent contender while winner is live also gets writer_held without altering endpoint.json.
        with spawn_serve_child(config_path) as child_c:
            out_c = child_c.wait_result()
            assert out_c.ok is False and out_c.error_code == ErrorCode.WRITER_HELD.value
        assert endpoint_path.read_bytes() == disk_bytes
        assert file_identity(endpoint_path) == ep_identity_before

        stop_out = winner.request_stop_and_wait()
        assert stop_out.ok is True and stop_out.exit_code == 0 and stop_out.returncode == 0
        assert not endpoint_path.exists()


def test_epoch_and_instance_change_after_kill(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Hard-killing the daemon leaves stale endpoint.json until the next writer bumps epoch & replaces it."""
    data_root, config_path, _ = _instantiate_case(trusted_tmp, "kill-restart", _daemon_template)
    endpoint_path = DataRoot.at(data_root).endpoint_path

    with spawn_serve_child(config_path) as child_1:
        ep1, sha1 = child_1.wait_ready()
        assert sha1 == _daemon_template.tls.leaf_cert_sha256
        assert ep1.writer_epoch == 2
        assert endpoint_path.read_bytes() == ep1.encode_canonical()
        _assert_tcp_listening(ep1)

        # Abrupt OS termination of BOTH inner interpreter and venv redirector launcher.
        child_1.kill_and_verify()

    # Stale endpoint descriptor remains untouched on disk until a new writer completes recovery & bind.
    assert endpoint_path.exists()
    assert endpoint_path.read_bytes() == ep1.encode_canonical()

    with spawn_serve_child(config_path) as child_2:
        ep2, sha2 = child_2.wait_ready()
        assert sha2 == _daemon_template.tls.leaf_cert_sha256
        assert ep2.store_id == ep1.store_id
        assert ep2.writer_epoch == ep1.writer_epoch + 1
        assert ep2.instance_id != ep1.instance_id
        assert endpoint_path.read_bytes() == ep2.encode_canonical()
        _assert_tcp_listening(ep2)

        stop_out = child_2.request_stop_and_wait()
        assert stop_out.ok is True and stop_out.exit_code == 0
        assert not endpoint_path.exists()


def test_maintenance_and_writer_are_exclusive(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """``serve`` and ``migrate_offline`` contend on the same OS ``writer.lock`` in both directions."""
    data_root, config_path, _ = _instantiate_case(trusted_tmp, "maint-exclusive", _daemon_template)
    endpoint_path = DataRoot.at(data_root).endpoint_path

    # Direction 1: live daemon holds writer.lock -> offline migrate fails closed with writer_held.
    with spawn_serve_child(config_path) as serve_1:
        ep1, _ = serve_1.wait_ready()
        assert ep1.writer_epoch == 2
        ep1_bytes = endpoint_path.read_bytes()

        with spawn_migrate_child(config_path) as mig_1:
            mig_out_1 = mig_1.wait_result()
            assert mig_out_1.ok is False
            assert mig_out_1.error_code == ErrorCode.WRITER_HELD.value
        assert endpoint_path.read_bytes() == ep1_bytes

        stop_1 = serve_1.request_stop_and_wait()
        assert stop_1.ok is True and stop_1.exit_code == 0
        assert not endpoint_path.exists()

    # Direction 2: offline migrate paused holding writer.lock -> serve fails with writer_held & no endpoint.
    with spawn_migrate_child(config_path, pause_in_migrate=True) as mig_2:
        mig_2.wait_paused_in_migrate()

        with spawn_serve_child(config_path) as serve_2:
            serve_out_2 = serve_2.wait_result()
            assert serve_out_2.ok is False
            assert serve_out_2.error_code == ErrorCode.WRITER_HELD.value
        assert not endpoint_path.exists()

        mig_out_2 = mig_2.resume_and_wait()
        assert mig_out_2.ok is True
        assert mig_out_2.writer_epoch == 3

    # After maintenance releases the lease, serve acquires epoch 4 cleanly.
    with spawn_serve_child(config_path) as serve_3:
        ep3, _ = serve_3.wait_ready()
        assert ep3.writer_epoch == 4
        stop_3 = serve_3.request_stop_and_wait()
        assert stop_3.ok is True and stop_3.exit_code == 0
        assert not endpoint_path.exists()


def test_missing_or_wrong_store_never_creates_root(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Missing root/lock/DB, wrong store_id, and unmigrated/future schemas fail without touching bytes."""
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    adapters = os_adapters(clock=clock)

    # 1. Missing root directory -> NOT_FOUND and directory is never created.
    missing_parent = trusted_tmp / "nonexistent-parent"
    missing_root = missing_parent / "store-root"
    missing_cfg = DaemonConfig(
        version=1,
        data_root=missing_root,
        expected_store_id=_daemon_template.store_id,
        cert_path=_daemon_template.tls.cert_path,
        key_path=_daemon_template.tls.key_path,
    )
    _expect_brain_error(ErrorCode.NOT_FOUND, lambda: serve(missing_cfg, os_=adapters, clock=clock))
    assert not missing_root.exists() and not missing_parent.exists()

    # 2. Missing writer.lock -> NOT_FOUND, lock not recreated, tree bytes unchanged.
    no_lock_root, _, no_lock_cfg = _instantiate_case(trusted_tmp, "missing-lock", _daemon_template)
    (no_lock_root / "writer.lock").unlink()
    snap_no_lock = digest_tree(no_lock_root)
    _expect_brain_error(ErrorCode.NOT_FOUND, lambda: serve(no_lock_cfg, os_=adapters, clock=clock))
    assert not (no_lock_root / "writer.lock").exists()
    assert digest_tree(no_lock_root) == snap_no_lock

    # 3a. Existing uninitialized root with only writer.lock (both policy.db and brain.db absent, zero history)
    #     -> NOT_FOUND without bumping writer_epoch or creating DB directories/files.
    lock_only_root = trusted_tmp / "lock-only-uninitialized"
    prepare_data_root(lock_only_root, adapters)
    lock_only_cfg = DaemonConfig(
        version=1,
        data_root=lock_only_root,
        expected_store_id=_daemon_template.store_id,
        cert_path=_daemon_template.tls.cert_path,
        key_path=_daemon_template.tls.key_path,
    )
    lock_only_before = (lock_only_root / "writer.lock").read_bytes()
    snap_lock_only = digest_tree(lock_only_root)
    _expect_brain_error(ErrorCode.NOT_FOUND, lambda: serve(lock_only_cfg, os_=adapters, clock=clock))
    assert (lock_only_root / "writer.lock").read_bytes() == lock_only_before
    assert digest_tree(lock_only_root) == snap_lock_only

    # 3b. Incomplete initialized pair (only store/brain.db OR only policy/policy.db missing)
    #     -> INTEGRITY_FAILURE without bumping writer_epoch or touching remaining bytes.
    for pair_label, rel_missing in (
        ("missing-db", Path("store/brain.db")),
        ("missing-policy", Path("policy/policy.db")),
    ):
        no_pair_root, _, no_pair_cfg = _instantiate_case(trusted_tmp, pair_label, _daemon_template)
        (no_pair_root / rel_missing).unlink()
        lock_before = (no_pair_root / "writer.lock").read_bytes()
        snap_no_pair = digest_data_root(no_pair_root)
        _expect_brain_error(
            ErrorCode.INTEGRITY_FAILURE,
            functools.partial(serve, no_pair_cfg, os_=adapters, clock=clock),
        )
        assert not (no_pair_root / rel_missing).exists()
        assert (no_pair_root / "writer.lock").read_bytes() == lock_before
        assert digest_data_root(no_pair_root) == snap_no_pair

    # 4. Wrong expected_store_id with valid TLS minted for wrong_store_id -> reaches pair admission
    #    and fails with IDENTITY_MISMATCH without bumping epoch or touching stale endpoint.json.
    wrong_root, _, _ = _instantiate_case(trusted_tmp, "wrong-store-id", _daemon_template)
    stale_ep = wrong_root / ENDPOINT_NAME
    stale_ep.write_bytes(b'{"stale":true}')
    if sys.platform != "win32":
        os.chmod(stale_ep, 0o600)
    wrong_store_id = new_id()
    wrong_tls = _provision_tls(wrong_store_id, trusted_tmp / "wrong-tls", clock, adapters)
    wrong_cfg = DaemonConfig(
        version=1,
        data_root=wrong_root,
        expected_store_id=wrong_store_id,
        cert_path=wrong_tls.cert_path,
        key_path=wrong_tls.key_path,
    )
    wrong_lock_before = (wrong_root / "writer.lock").read_bytes()
    wrong_snap_before = digest_data_root(wrong_root)
    _expect_brain_error(ErrorCode.IDENTITY_MISMATCH, lambda: serve(wrong_cfg, os_=adapters, clock=clock))
    assert (wrong_root / "writer.lock").read_bytes() == wrong_lock_before
    assert digest_data_root(wrong_root) == wrong_snap_before

    # 5. Unmigrated v1 store/policy AND mixed schema (v2 store + v1 policy) -> MIGRATION_REQUIRED, untouched.
    v1_root = trusted_tmp / "v1-unmigrated"
    rt_v1 = open_runtime(
        v1_root,
        adapters,
        handlers=(),
        kinds=KindRegistry(()),
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    v1_store_id = rt_v1.store.store_id
    rt_v1.close()
    v1_tls = _provision_tls(v1_store_id, trusted_tmp / "v1-tls", clock, adapters)
    v1_cfg = DaemonConfig(
        version=1,
        data_root=v1_root,
        expected_store_id=v1_store_id,
        cert_path=v1_tls.cert_path,
        key_path=v1_tls.key_path,
    )
    v1_lock_before = (v1_root / "writer.lock").read_bytes()
    v1_snap_before = digest_data_root(v1_root)
    _expect_brain_error(ErrorCode.MIGRATION_REQUIRED, lambda: serve(v1_cfg, os_=adapters, clock=clock))
    assert (v1_root / "writer.lock").read_bytes() == v1_lock_before
    assert digest_data_root(v1_root) == v1_snap_before

    mixed_root, _, mixed_cfg = _instantiate_case(trusted_tmp, "mixed-schema", _daemon_template)
    mixed_pol_db = mixed_root / "policy" / "policy.db"
    with contextlib.closing(sqlite3.connect(mixed_pol_db)) as raw_pol, raw_pol:
        raw_pol.execute("PRAGMA journal_mode=DELETE")
        raw_pol.execute("UPDATE meta SET value = '2' WHERE key IN ('schema_version', 'min_reader_version')")
    adapters.permissions.secure_file(mixed_pol_db)
    mixed_lock_before = (mixed_root / "writer.lock").read_bytes()
    mixed_snap_before = digest_data_root(mixed_root)
    _expect_brain_error(ErrorCode.MIGRATION_REQUIRED, lambda: serve(mixed_cfg, os_=adapters, clock=clock))
    assert (mixed_root / "writer.lock").read_bytes() == mixed_lock_before
    assert digest_data_root(mixed_root) == mixed_snap_before

    # 6. Future unsupported schema version -> UNSUPPORTED_VERSION without modifying DBs or bumping epoch.
    fut_root, _, fut_cfg = _instantiate_case(trusted_tmp, "future-schema", _daemon_template)
    fut_store_db = fut_root / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(fut_store_db)) as raw_db, raw_db:
        raw_db.execute("PRAGMA journal_mode=DELETE")
        raw_db.execute("UPDATE meta SET value = '99' WHERE key IN ('schema_version', 'min_reader_version')")
    adapters.permissions.secure_file(fut_store_db)
    fut_lock_before = (fut_root / "writer.lock").read_bytes()
    fut_snap_before = digest_data_root(fut_root)
    _expect_brain_error(ErrorCode.UNSUPPORTED_VERSION, lambda: serve(fut_cfg, os_=adapters, clock=clock))
    assert (fut_root / "writer.lock").read_bytes() == fut_lock_before
    assert digest_data_root(fut_root) == fut_snap_before


def test_endpoint_unsafe_entries_refused_before_write(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Symlinks/junctions, non-regular entries & loose ACLs at endpoint/stage fail closed under lease."""
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    adapters = os_adapters(clock=clock)

    # 1. Fake symlink on endpoint.json & uppercase ENDPOINT.JSON.STAGE-FAKE -> UNSAFE_PATH before bump.
    for idx, entry_name in enumerate((ENDPOINT_NAME, "ENDPOINT.JSON.STAGE-FAKE")):
        case_root, _, cfg = _instantiate_case(trusted_tmp, f"fake-link-{idx}", _daemon_template)
        target = case_root / entry_name
        target.write_bytes(b"untouched")
        if sys.platform != "win32":
            os.chmod(target, 0o600)
        lock_before = (case_root / "writer.lock").read_bytes()
        with monkeypatch.context() as mp:
            fake_link(mp, target)
            _expect_brain_error(ErrorCode.UNSAFE_PATH, functools.partial(serve, cfg, os_=adapters, clock=clock))
        assert (case_root / "writer.lock").read_bytes() == lock_before
        assert target.read_bytes() == b"untouched"

    # 2. Real OS reparse point (Windows junction / POSIX symlink) at endpoint.json and stage-* -> UNSAFE_PATH.
    outside_dir = trusted_tmp / "outside-target"
    outside_dir.mkdir()
    outside_marker = outside_dir / "sentinel.txt"
    outside_marker.write_bytes(b"keep-safe")
    for idx, entry_name in enumerate((ENDPOINT_NAME, "ENDPOINT.JSON.STAGE-REPARSE")):
        case_root, _, cfg = _instantiate_case(trusted_tmp, f"reparse-{idx}", _daemon_template)
        bad_entry = case_root / entry_name
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(outside_dir), str(bad_entry))
        else:
            os.symlink(outside_dir, bad_entry)
        lock_before = (case_root / "writer.lock").read_bytes()
        _expect_brain_error(ErrorCode.UNSAFE_PATH, functools.partial(serve, cfg, os_=adapters, clock=clock))
        assert (case_root / "writer.lock").read_bytes() == lock_before
        assert outside_marker.read_bytes() == b"keep-safe"

    # 3. Directory (non-regular file) at endpoint.json & ENDPOINT.JSON.STAGE-DIR -> INVALID_INPUT before bump.
    for idx, entry_name in enumerate((ENDPOINT_NAME, "ENDPOINT.JSON.STAGE-DIR")):
        case_root, _, cfg = _instantiate_case(trusted_tmp, f"nonreg-{idx}", _daemon_template)
        bad_dir = case_root / entry_name
        bad_dir.mkdir()
        if sys.platform != "win32":
            os.chmod(bad_dir, 0o700)
        lock_before = (case_root / "writer.lock").read_bytes()
        _expect_brain_error(ErrorCode.INVALID_INPUT, functools.partial(serve, cfg, os_=adapters, clock=clock))
        assert (case_root / "writer.lock").read_bytes() == lock_before

    # 4. Loose ACL / permissions on endpoint.json & ENDPOINT.JSON.STAGE-LOOSE -> INSECURE_PERMISSIONS before bump.
    for idx, entry_name in enumerate((ENDPOINT_NAME, "ENDPOINT.JSON.STAGE-LOOSE")):
        case_root, _, cfg = _instantiate_case(trusted_tmp, f"loose-{idx}", _daemon_template)
        loose_file = case_root / entry_name
        loose_file.write_bytes(b"loose")
        _loosen_permissions(loose_file)
        lock_before = (case_root / "writer.lock").read_bytes()
        _expect_brain_error(ErrorCode.INSECURE_PERMISSIONS, functools.partial(serve, cfg, os_=adapters, clock=clock))
        assert (case_root / "writer.lock").read_bytes() == lock_before

    # 5. Direct helper invariants: lease required, remove_own_endpoint preserves foreign epoch/instance,
    #    and competing serve while winner holds lock with a stage file fails with WRITER_HELD (no unlocked scan).
    race_root, _, race_cfg = _instantiate_case(trusted_tmp, "stage-under-lock", _daemon_template)
    droot = DataRoot.at(race_root)
    with acquire_writer(droot, adapters) as held_lease:
        assert check_endpoint_entries_under_lease(droot, held_lease, adapters) == ()
        ep_own = Endpoint(
            version=1,
            host="127.0.0.1",
            port=54321,
            store_id=_daemon_template.store_id,
            writer_epoch=held_lease.epoch,
            instance_id="inst-own-1",
        )
        publish_endpoint(droot, held_lease, ep_own, adapters)
        assert droot.endpoint_path.read_bytes() == ep_own.encode_canonical()

        # Foreign instance_id with same epoch must NOT remove ep_own's descriptor.
        ep_other = dataclasses.replace(ep_own, instance_id="inst-other-2")
        assert remove_own_endpoint(droot, held_lease, ep_other, adapters) is False
        assert droot.endpoint_path.read_bytes() == ep_own.encode_canonical()

        # Transient loose stage file while winner holds writer.lock -> contender gets WRITER_HELD!
        transient_stage = race_root / "endpoint.json.stage-inflight"
        transient_stage.write_bytes(b"partial")
        _loosen_permissions(transient_stage)
        _expect_brain_error(ErrorCode.WRITER_HELD, lambda: serve(race_cfg, os_=adapters, clock=clock))
        transient_stage.unlink()

        assert remove_own_endpoint(droot, held_lease, ep_own, adapters) is True
        assert not droot.endpoint_path.exists()

    # Unheld lease is rejected with INTEGRITY_FAILURE.
    unheld = acquire_writer_unbumped(droot, adapters)
    unheld.release()
    _expect_brain_error(
        ErrorCode.INTEGRITY_FAILURE,
        lambda: check_endpoint_entries_under_lease(droot, unheld, adapters),
    )


def test_recovery_failure_never_publishes_ready(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """TLS expiry, mismatched key, missing credentials, recovery errors & sync failures never emit Ready."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)

    # 1. Expired TLS cert at initial verification -> INVALID_INPUT, zero bound listeners.
    r1, _, cfg1 = _instantiate_case(trusted_tmp, "fail-tls-expired", _daemon_template)
    del r1
    exp_clock = FakeClock(_daemon_template.tls.not_after)
    bound_1: list[BoundLoopbackListener] = []
    loop_1 = create_daemon_owner_loop(
        os_=os_adapters(clock=exp_clock),
        clock=exp_clock,
        on_listener_bound=bound_1.append,
    )
    _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_1.start(cfg1))
    assert bound_1 == [] and loop_1.ready is None

    # 2. Cert expires right before socket bind (after_tls_verify advances clock to not_after) -> never binds.
    r2, _, cfg2 = _instantiate_case(trusted_tmp, "fail-prebind-tls", _daemon_template)
    prebind_clock = FakeClock(base_now)
    bound_2: list[BoundLoopbackListener] = []
    loop_2 = create_daemon_owner_loop(
        os_=os_adapters(clock=prebind_clock),
        clock=prebind_clock,
        hooks=DaemonTestHooks(after_tls_verify=lambda: prebind_clock.set(_daemon_template.tls.not_after)),
        on_listener_bound=bound_2.append,
    )
    _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_2.start(cfg2))
    assert bound_2 == [] and loop_2.ready is None and not (r2 / ENDPOINT_NAME).exists()

    # 3. Mismatched cert/key pair -> INVALID_INPUT, never binds.
    _, _, cfg3_base = _instantiate_case(trusted_tmp, "fail-mismatch-key", _daemon_template)
    other_clock = FakeClock(base_now)
    other_adapters = os_adapters(clock=other_clock)
    other_tls = _provision_tls(_daemon_template.store_id, trusted_tmp / "other-key-tls", other_clock, other_adapters)
    cfg3 = dataclasses.replace(cfg3_base, key_path=other_tls.key_path)
    bound_3: list[BoundLoopbackListener] = []
    loop_3 = create_daemon_owner_loop(
        os_=other_adapters,
        clock=other_clock,
        on_listener_bound=bound_3.append,
    )
    _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_3.start(cfg3))
    assert bound_3 == [] and loop_3.ready is None

    # 4. Store with zero active credentials -> fails closed before bind and releases writer.lock.
    nocred_root = trusted_tmp / "fail-no-creds"
    nc_clock = FakeClock(base_now)
    nc_adapters = os_adapters(clock=nc_clock)
    rt_nc = open_kernel_job_runtime(nocred_root, nc_adapters)
    nc_store_id = rt_nc.store.store_id
    rt_nc.close()
    nc_tls = _provision_tls(nc_store_id, trusted_tmp / "nc-tls", nc_clock, nc_adapters)
    nc_cfg = DaemonConfig(
        version=1,
        data_root=nocred_root,
        expected_store_id=nc_store_id,
        cert_path=nc_tls.cert_path,
        key_path=nc_tls.key_path,
    )
    bound_4: list[BoundLoopbackListener] = []
    loop_4 = create_daemon_owner_loop(os_=nc_adapters, clock=nc_clock, on_listener_bound=bound_4.append)
    with pytest.raises(BrainError) as nc_err:
        loop_4.start(nc_cfg)
    assert nc_err.value.code in {ErrorCode.POLICY_UNAVAILABLE, ErrorCode.UNAUTHENTICATED}
    assert bound_4 == [] and loop_4.ready is None
    with acquire_writer(DataRoot.at(nocred_root), nc_adapters):
        pass

    # 5. Injected failure in before_job_recover -> never binds, preserves prior stale endpoint, releases lock.
    r5, _, cfg5 = _instantiate_case(trusted_tmp, "fail-recover", _daemon_template)
    stale_bytes = Endpoint(
        version=1,
        host="127.0.0.1",
        port=40111,
        store_id=_daemon_template.store_id,
        writer_epoch=1,
        instance_id="prior-crashed-inst",
    ).encode_canonical()
    (r5 / ENDPOINT_NAME).write_bytes(stale_bytes)
    if sys.platform != "win32":
        os.chmod(r5 / ENDPOINT_NAME, 0o600)
    rec_clock = FakeClock(base_now)
    rec_adapters = os_adapters(clock=rec_clock)
    bound_5: list[BoundLoopbackListener] = []

    def _boom_recover(_rt: Runtime) -> None:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    loop_5 = create_daemon_owner_loop(
        os_=rec_adapters,
        clock=rec_clock,
        hooks=DaemonTestHooks(before_job_recover=_boom_recover),
        on_listener_bound=bound_5.append,
    )
    _expect_brain_error(ErrorCode.INTEGRITY_FAILURE, lambda: loop_5.start(cfg5))
    assert bound_5 == [] and loop_5.ready is None
    assert (r5 / ENDPOINT_NAME).read_bytes() == stale_bytes
    with acquire_writer(DataRoot.at(r5), rec_adapters):
        pass

    # 6. Publisher failure AFTER atomic rename replaced endpoint.json -> Ready never emitted, listener closed,
    #    failed instance's endpoint cleaned up under lease, and writer.lock released.
    r6, _, cfg6 = _instantiate_case(trusted_tmp, "fail-publish-sync", _daemon_template)
    pub_clock = FakeClock(base_now)
    real_adapters = os_adapters(clock=pub_clock)

    class _FailAfterReplacePublisher:
        def flush_file(self, path: Path) -> None:
            real_adapters.publisher.flush_file(path)

        def write_new(self, path: Path, data: bytes) -> None:
            real_adapters.publisher.write_new(path, data)

        def publish(self, staging: Path, final: Path) -> None:
            if final.name == ENDPOINT_NAME:
                os.replace(staging, final)
                raise BrainError(ErrorCode.IO_ERROR, "I/O error")
            real_adapters.publisher.publish(staging, final)

        def rename_dir(self, src: Path, dst: Path) -> None:
            real_adapters.publisher.rename_dir(src, dst)

        def sync_directory(self, directory: Path) -> None:
            real_adapters.publisher.sync_directory(directory)

        def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
            return real_adapters.publisher.durability(directory, env)

    failing_adapters = dataclasses.replace(real_adapters, publisher=_FailAfterReplacePublisher())
    bound_6: list[BoundLoopbackListener] = []
    loop_6 = create_daemon_owner_loop(
        os_=failing_adapters,
        clock=pub_clock,
        on_listener_bound=bound_6.append,
    )
    _expect_brain_error(ErrorCode.IO_ERROR, lambda: loop_6.start(cfg6))
    assert loop_6.ready is None
    assert bound_6 and all(b.sock.fileno() == -1 for b in bound_6)
    assert not (r6 / ENDPOINT_NAME).exists()

    ready_seen_6: list[Ready] = []
    _expect_brain_error(
        ErrorCode.IO_ERROR,
        lambda: serve(
            cfg6,
            os_=failing_adapters,
            clock=pub_clock,
            on_ready=lambda r, _l: ready_seen_6.append(r),
        ),
    )
    assert ready_seen_6 == []
    assert not (r6 / ENDPOINT_NAME).exists()
    with acquire_writer(DataRoot.at(r6), real_adapters):
        pass

    # 7. Final post-publish UTC cert expiry check -> fails closed, removes own endpoint, closes listener & lock.
    r7, _, cfg7 = _instantiate_case(trusted_tmp, "fail-final-tls", _daemon_template)
    fin_clock = FakeClock(base_now)
    fin_adapters = os_adapters(clock=fin_clock)
    bound_7: list[BoundLoopbackListener] = []
    final_hook_hit: list[Endpoint] = []

    def _expire_after_publish(ep: Endpoint) -> None:
        final_hook_hit.append(ep)
        fin_clock.set(_daemon_template.tls.not_after)

    loop_7 = create_daemon_owner_loop(
        os_=fin_adapters,
        clock=fin_clock,
        hooks=DaemonTestHooks(after_endpoint_publish_before_final_tls_check=_expire_after_publish),
        on_listener_bound=bound_7.append,
    )
    _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_7.start(cfg7))
    assert len(final_hook_hit) == 1
    assert loop_7.ready is None
    assert bound_7 and all(b.sock.fileno() == -1 for b in bound_7)
    assert not (r7 / ENDPOINT_NAME).exists()
    with acquire_writer(DataRoot.at(r7), fin_adapters):
        pass


class _LegacyV1ProviderProjection:
    """Historical ``f82b5a3`` v1 ``provider_invocations`` projection writing ``settled/0`` on incomplete usage."""

    name = "provider_invocations"
    handler_version = 1
    kinds = frozenset({"provider.reserved", "provider.settled", "provider.unknown"})

    def __init__(self, delegate: ProjectionHandler) -> None:
        self._delegate = delegate

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        self._delegate.create_tables(db, prefix)

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        if entry.kind == "provider.settled":
            complete = entry.meta["complete"]
            assert type(complete) is bool
            cur = db.execute(
                f"UPDATE {prefix}state SET state = 'settled', usage_digest = ?, usage_complete = ?, sequence = ? "
                "WHERE invocation_id = ? AND state = ?",
                (
                    str(entry.meta["usage_digest"]),
                    1 if complete else 0,
                    entry.sequence,
                    str(entry.meta["invocation_id"]),
                    str(entry.meta["prior_state"]),
                ),
            )
            assert cur.rowcount == 1
            return
        self._delegate.apply(db, prefix, entry, policy)


def _legacy_v1_store_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    prod_handlers, prod_kinds = kernel_store_extensions()
    legacy_settled_kind = EntryKind(
        "provider.settled",
        1,
        {
            "invocation_id": FieldType.UUID,
            "prior_state": FieldType.ENUM,
            "usage_digest": FieldType.DIGEST,
            "complete": FieldType.BOOL,
        },
        {"prior_state": frozenset({"reserved", "outcome_unknown"})},
    )
    v1_kinds = KindRegistry(
        [
            legacy_settled_kind if name == "provider.settled" else prod_kinds.get(name)
            for name in sorted(prod_kinds.kinds())
        ]
    )
    v1_handlers = tuple(
        _LegacyV1ProviderProjection(handler) if handler.name == "provider_invocations" else handler
        for handler in prod_handlers
    )
    return v1_handlers, v1_kinds


def test_legacy_projection_and_pending_attempt_recovered_before_ready(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Startup rebuilds legacy v1 settled/0 rows, recovers unknown-before-requeue & pending send attempts pre-bind."""
    clock = FakeClock(_daemon_template.base_time)
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "legacy-recovery-data"
    v1_handlers, v1_kinds = _legacy_v1_store_extensions()

    # Epoch 1: write real v1 provider.settled(complete=False) and v1 provider.settled(complete=True) history.
    rt1 = open_runtime(
        root,
        adapters,
        handlers=v1_handlers,
        kinds=v1_kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt1.store.store_id
    try:
        cred = seed_principal_and_credential(rt1.policy, owner_id="dan")
        service1, store1 = kernel_job_service(rt1, clock)
        job_hist = enqueue_job(service1, store1, owner_id="dan", payload=b"v1-history").job_id
        lease1 = service1.lease_next(rt1.lease.epoch, clock.now())
        assert lease1 is not None
        service1.start(lease1)
        inv_v1_inc = service1.reserve_invocation(lease1, RESERVE)
        inv_v1_cmp = service1.reserve_invocation(lease1, RESERVE)

        inc_blob = usage_descriptor(inv_v1_inc, UsageRecord(None, False))
        cmp_blob = usage_descriptor(inv_v1_cmp, UsageRecord("0.1", True))
        store1.stage_blob(inc_blob)
        store1.stage_blob(cmp_blob)

        def _append_v1_entries(tx: KernelTx) -> None:
            inc_dig = tx.hold_blob(inc_blob, holder_id=inv_v1_inc)
            tx.append_record(
                KernelRecord(
                    "provider.settled",
                    {
                        "invocation_id": inv_v1_inc,
                        "prior_state": "reserved",
                        "usage_digest": inc_dig,
                        "complete": False,
                    },
                )
            )
            cmp_dig = tx.hold_blob(cmp_blob, holder_id=inv_v1_cmp)
            tx.append_record(
                KernelRecord(
                    "provider.settled",
                    {
                        "invocation_id": inv_v1_cmp,
                        "prior_state": "reserved",
                        "usage_digest": cmp_dig,
                        "complete": True,
                    },
                )
            )

        store1.transact(_append_v1_entries)
        service1.complete(lease1, JobOutcome.success())
    finally:
        rt1.close()

    # Epoch 2: crash state with stale settled/0 projection untouched + reserved invocation + leased/running jobs
    # + pending artifact_send_attempt.
    clock.advance(dt.timedelta(minutes=1))
    rt2 = reopen_kernel_job_runtime(root, store_id, adapters)
    try:
        service2, store2 = kernel_job_service(rt2, clock)
        job_retry = enqueue_job(service2, store2, owner_id="dan", payload=b"crashed-attempt-1").job_id
        lease_retry = service2.lease_next(rt2.lease.epoch, clock.now())
        assert lease_retry is not None and lease_retry.job_id == job_retry
        service2.start(lease_retry)
        inv_crashed = service2.reserve_invocation(lease_retry, RESERVE)

        job_dead = enqueue_job(service2, store2, owner_id="dan", payload=b"crashed-attempt-3").job_id
        for expected_attempt in (1, 2):
            clock.advance(dt.timedelta(seconds=10))
            dl_lease = service2.lease_next(rt2.lease.epoch, clock.now())
            assert dl_lease is not None and (dl_lease.job_id, dl_lease.attempt) == (job_dead, expected_attempt)
            service2.start(dl_lease)
            service2.complete(dl_lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))
        clock.advance(dt.timedelta(seconds=10))
        lease_dead_3 = service2.lease_next(rt2.lease.epoch, clock.now())
        assert lease_dead_3 is not None and (lease_dead_3.job_id, lease_dead_3.attempt) == (job_dead, 3)
        service2.start(lease_dead_3)

        send_store = KernelSendAttemptStore(rt2.store, rt2.policy, writer_epoch=rt2.lease.epoch)
        pending_attempt = send_store.record_pending_attempt(
            ArtifactSendSpec(
                logical_result_id=new_id(),
                principal_id=cred.principal.principal_id,
                task_id="task-pending-1",
                artifact_id="art-pending-1",
                revision=1,
                resource_digests=(ResourceDigest(name="L1.md", digest=digest_bytes(b"pending-skill")),),
            )
        )
    finally:
        rt2.close()

    tls = _provision_tls(store_id, trusted_tmp / "legacy-tls", clock, adapters)
    cfg = DaemonConfig(
        version=1,
        data_root=root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
    )

    stage_order: list[str] = []
    bound_listeners: list[BoundLoopbackListener] = []
    endpoint_path = DataRoot.at(root).endpoint_path

    def _query_inv(rt: Runtime, inv_id: str) -> tuple[str, int | None]:
        with rt.store.transaction() as txn:
            row = txn.db.execute(
                "SELECT state, usage_complete FROM p_provider_invocations_state WHERE invocation_id = ?",
                (inv_id,),
            ).fetchone()
        assert row is not None
        return str(row[0]), (None if row[1] is None else int(row[1]))

    def _query_job(rt: Runtime, jid: str) -> tuple[str, int]:
        with rt.store.transaction() as txn:
            row = txn.db.execute(
                "SELECT state, attempt FROM p_jobs_state WHERE job_id = ?",
                (jid,),
            ).fetchone()
        assert row is not None
        return str(row[0]), int(row[1])

    def _after_open_before_rebuild(rt: Runtime) -> None:
        assert bound_listeners == [] and not endpoint_path.exists()
        assert _query_inv(rt, inv_v1_inc) == ("settled", 0)
        stage_order.append("after_open_before_rebuild")

    def _before_job_recover(rt: Runtime) -> None:
        assert bound_listeners == [] and not endpoint_path.exists()
        assert _query_inv(rt, inv_v1_inc) == ("outcome_unknown", 0)
        assert _query_inv(rt, inv_v1_cmp) == ("settled", 1)
        assert _query_inv(rt, inv_crashed) == ("reserved", None)
        stage_order.append("before_job_recover")

    def _before_bind(rt: Runtime) -> None:
        assert bound_listeners == [] and not endpoint_path.exists()
        assert _query_inv(rt, inv_v1_inc) == ("outcome_unknown", 0)
        assert _query_inv(rt, inv_crashed) == ("outcome_unknown", None)
        assert _query_job(rt, job_retry) == ("queued", 2)
        assert _query_job(rt, job_dead) == ("dead_letter", 3)
        with rt.store.transaction() as txn:
            recovered_send = read_send_attempt_row(txn.db, pending_attempt.send_attempt_id)
            ack_count = int(txn.db.execute("SELECT COUNT(*) FROM artifact_read_ack").fetchone()[0])
        assert recovered_send is not None and recovered_send.state is SendAttemptState.UNKNOWN
        assert ack_count == 0
        stage_order.append("before_bind")

    mono = _FakeMonotonicClock()
    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        hooks=DaemonTestHooks(
            after_open_before_rebuild=_after_open_before_rebuild,
            before_job_recover=_before_job_recover,
            before_bind=_before_bind,
        ),
        on_listener_bound=bound_listeners.append,
    )
    try:
        ready = loop.start(cfg)
        assert stage_order == ["after_open_before_rebuild", "before_job_recover", "before_bind"]
        assert ready.endpoint.writer_epoch == 3
        assert endpoint_path.exists()

        # Verify recovered job & accounting views via live get_job before and after first complete usage.
        dl_ns = mono.now + TOTAL_REQUEST_BUDGET_NS
        hist_env = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_hist}, token=cred.token),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert hist_env["ok"] is True
        hist_data = cast(dict[str, JsonValue], hist_env["data"])
        assert hist_data["accounting_status"] == AccountingStatus.OUTCOME_UNKNOWN.value

        retry_env = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_retry}, token=cred.token),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert retry_env["ok"] is True
        retry_data = cast(dict[str, JsonValue], retry_env["data"])
        assert retry_data["state"] == JobState.QUEUED.value and retry_data["attempt"] == 2
        assert retry_data["accounting_status"] == AccountingStatus.OUTCOME_UNKNOWN.value

        dead_env = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_dead}, token=cred.token),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert dead_env["ok"] is True
        dead_data = cast(dict[str, JsonValue], dead_env["data"])
        assert dead_data["state"] == JobState.DEAD_LETTER.value and dead_data["attempt"] == 3

        # Reconcile legacy incomplete v1 invocation once with first complete=True usage ("0.42").
        settled_rec = loop.apply_worker_command(WorkerUsage(inv_v1_inc, UsageRecord("0.42", True))).result(
            timeout=BOUND_WAIT_S
        )
        assert getattr(settled_rec, "state", None) is InvocationState.SETTLED

        hist_after = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_hist}, token=cred.token),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert hist_after["ok"] is True
        assert cast(dict[str, JsonValue], hist_after["data"])["accounting_status"] == AccountingStatus.SETTLED.value

        # Second conflicting known settle on inv_v1_inc AND any overwrite of locked v1 complete=True fail closed.
        _expect_brain_error(
            ErrorCode.IDEMPOTENCY_CONFLICT,
            lambda: loop.apply_worker_command(WorkerUsage(inv_v1_inc, UsageRecord("0.99", True))).result(
                timeout=BOUND_WAIT_S
            ),
        )
        _expect_brain_error(
            ErrorCode.IDEMPOTENCY_CONFLICT,
            lambda: loop.apply_worker_command(WorkerUsage(inv_v1_cmp, UsageRecord("0.25", True))).result(
                timeout=BOUND_WAIT_S
            ),
        )
    finally:
        with contextlib.suppress(BrainError):
            loop.stop()

    # Negative control A: unsupported handler_version in ledger history fails closed in Store.open pre-bind.
    corrupt_hist_root = trusted_tmp / "corrupt-history"
    _clone_owner_only_tree(root, corrupt_hist_root)
    corrupt_hist_db = corrupt_hist_root / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(corrupt_hist_db)) as raw_db, raw_db:
        raw_db.execute("PRAGMA journal_mode=DELETE")
        raw_db.execute(
            "UPDATE p_provider_invocations_state SET state = 'settled', usage_complete = 0 WHERE invocation_id = ?",
            (inv_v1_inc,),
        )
        raw_db.execute("UPDATE ledger SET handler_version = 99 WHERE kind = 'provider.settled'")
    adapters.permissions.secure_file(corrupt_hist_db)
    corrupt_hist_cfg = dataclasses.replace(cfg, data_root=corrupt_hist_root)
    corrupt_hist_bound: list[BoundLoopbackListener] = []
    corrupt_hist_loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        on_listener_bound=corrupt_hist_bound.append,
    )
    with pytest.raises(BrainError) as corrupt_hist_err:
        corrupt_hist_loop.start(corrupt_hist_cfg)
    assert corrupt_hist_err.value.code in {ErrorCode.UNSUPPORTED_VERSION, ErrorCode.INTEGRITY_FAILURE}
    assert corrupt_hist_bound == [] and not (corrupt_hist_root / ENDPOINT_NAME).exists()

    # Negative control B: Store.open succeeds, legacy (settled, usage_complete=0) row triggers
    # store.rebuild_projections(), and corrupt ledger.meta blob fails closed with INTEGRITY_FAILURE pre-bind!
    corrupt_rebuild_root = trusted_tmp / "corrupt-rebuild-meta"
    _clone_owner_only_tree(root, corrupt_rebuild_root)
    corrupt_rebuild_db = corrupt_rebuild_root / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(corrupt_rebuild_db)) as raw_db, raw_db:
        raw_db.execute("PRAGMA journal_mode=DELETE")
        raw_db.execute(
            "UPDATE p_provider_invocations_state SET state = 'settled', usage_complete = 0 WHERE invocation_id = ?",
            (inv_v1_inc,),
        )
        raw_db.execute("UPDATE ledger SET meta = ? WHERE kind = 'provider.settled'", (b"{}",))
    adapters.permissions.secure_file(corrupt_rebuild_db)
    corrupt_rebuild_cfg = dataclasses.replace(cfg, data_root=corrupt_rebuild_root)
    corrupt_rebuild_bound: list[BoundLoopbackListener] = []
    rebuild_stages: list[str] = []
    corrupt_rebuild_loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        hooks=DaemonTestHooks(
            after_open_before_rebuild=lambda _rt: rebuild_stages.append("opened"),
            before_job_recover=lambda _rt: rebuild_stages.append("recovered"),
        ),
        on_listener_bound=corrupt_rebuild_bound.append,
    )
    _expect_brain_error(ErrorCode.INTEGRITY_FAILURE, lambda: corrupt_rebuild_loop.start(corrupt_rebuild_cfg))
    assert rebuild_stages == ["opened"]
    assert corrupt_rebuild_bound == [] and not (corrupt_rebuild_root / ENDPOINT_NAME).exists()
    with acquire_writer(DataRoot.at(corrupt_rebuild_root), adapters):
        pass


# ===========================================================================
# Group 2 (6a.2) · Owner coordination, AuthGate & shallow health
# ===========================================================================


def test_shallow_health_bypasses_blocked_write_queue(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Shallow ``get_health`` succeeds from RAM while write #1 blocks in COMMIT and 32 queue slots are full."""
    _, _, cfg = _instantiate_case(trusted_tmp, "shallow-health-bypass", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)

    # ToolCommand repr/str privacy invariant: neither token nor raw arguments ever appear.
    canary_token = _daemon_template.cred_a.token
    canary_arg = "top-secret-raw-argument-4411"
    probe_cmd = ToolCommand("submit_episode", {"secret": canary_arg}, token=canary_token)
    assert canary_token not in repr(probe_cmd) and canary_arg not in repr(probe_cmd)
    assert canary_token not in str(probe_cmd) and canary_arg not in str(probe_cmd)

    domain = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-write-block-0001"})
    domain.allow_apply_finish.clear()

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain,
    )
    try:
        ready = loop.start(cfg)
        dl_ns = mono.now + TOTAL_REQUEST_BUDGET_NS

        # 1. Block write #1 inside its active SQLite COMMIT transaction.
        fut_block = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-write-block-0001"),
                token=canary_token,
                selected_scope=scope_a,
            ),
            dl_ns,
        )
        assert domain.apply_entered.wait(timeout=BOUND_WAIT_S)
        assert not fut_block.done()

        # 2. Fill all 32 bounded owner queue slots (#2..#33).
        queued_futs: list[Future[CallResult]] = []
        for slot in range(DAEMON_QUEUE_DEPTH):
            queued_futs.append(
                loop.submit(
                    ToolCommand(
                        "submit_episode",
                        _episode_args(ws_a, f"idem-fill-slot-{slot:04d}"),
                        token=canary_token,
                        selected_scope=scope_a,
                    ),
                    dl_ns,
                )
            )
        assert all(not f.done() for f in queued_futs)

        # 3. Slot #34 is refused pre-queue with store_busy.
        overflow = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-overflow-slot-0034"),
                token=canary_token,
                selected_scope=scope_a,
            ),
            dl_ns,
        ).result(timeout=1.0)
        assert overflow == {"ok": False, "error": {"code": "store_busy", "message": "store busy"}}

        # 4. Shallow get_health bypasses the blocked owner thread & full queue via RAM AuthGate!
        health_reply = loop.submit_reply(
            ToolCommand("get_health", {"schema_version": "2.0"}, token=canary_token),
            dl_ns,
        ).result(timeout=1.0)
        assert health_reply.envelope == {
            "ok": True,
            "data": {
                "ready": True,
                "store_id": _daemon_template.store_id,
                "writer_epoch": ready.endpoint.writer_epoch,
                "schema_version": 4,
                "policy_schema_version": 3,
                "degraded_codes": [],
            },
        }
        assert health_reply.grant_stamp is not None
        assert health_reply.grant_stamp.credential_id == _daemon_template.cred_a.credential_id
        assert health_reply.send_completion is None
        assert set(health_reply.envelope) == {"ok", "data"}

        # Shallow health rejects idempotency_key and non-None selected_scope per contract.
        bad_idem = loop.submit(
            ToolCommand(
                "get_health",
                {"schema_version": "2.0", "deep": False, "idempotency_key": "idem-forbidden-health-1"},
                token=canary_token,
            ),
            dl_ns,
        ).result(timeout=1.0)
        assert bad_idem == {
            "ok": False,
            "error": {"code": "invalid_input", "message": "shallow health forbids idempotency_key"},
        }

        scoped_health = loop.submit(
            ToolCommand(
                "get_health",
                {"schema_version": "2.0"},
                token=canary_token,
                selected_scope=scope_a,
            ),
            dl_ns,
        ).result(timeout=1.0)
        assert scoped_health["ok"] is False

        # Release COMMIT and drain all 33 writes cleanly.
        domain.allow_apply_finish.set()
        assert fut_block.result(timeout=BOUND_WAIT_S)["ok"] is True
        for qf in queued_futs:
            assert qf.result(timeout=BOUND_WAIT_S)["ok"] is True
    finally:
        domain.allow_apply_finish.set()
        with contextlib.suppress(BrainError):
            loop.stop()


def test_tls_expiring_health_uses_clock_and_no_io(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Shallow health computes TLS expiry from UTC clock + cached metadata with zero cert/SQLite I/O."""
    _, _, cfg = _instantiate_case(trusted_tmp, "tls-health-clock", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    domain = _DaemonTestDomain(ws_a=ws_a)

    sql_count = [0]
    arm_sql = [False]

    def _capture_sql_trace(rt: Runtime) -> None:
        def _trace(_sql: str) -> None:
            if arm_sql[0]:
                sql_count[0] += 1

        with rt.store.transaction() as txn:
            txn.db.set_trace_callback(_trace)

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain,
        hooks=DaemonTestHooks(before_bind=_capture_sql_trace),
    )
    try:
        ready = loop.start(cfg)
        not_after = ready.tls_not_after
        tok_a = _daemon_template.cred_a.token
        tok_b = _daemon_template.cred_b.token

        # Arm SQLite statement counter + forbid cert file reads during shallow health & TLS-expired gate.
        arm_sql[0] = True
        from superbrain.adapters.os import tls_material

        tls_reads = [0]
        orig_read_tls = tls_material._read_owner_only_file

        def _spy_read_tls(path: Path, os_: OsAdapters) -> bytes:
            tls_reads[0] += 1
            return orig_read_tls(path, os_)

        monkeypatch.setattr(tls_material, "_read_owner_only_file", _spy_read_tls)

        def _shallow(token: str = tok_a) -> CallResult:
            return loop.submit(
                ToolCommand("get_health", {"schema_version": "2.0"}, token=token),
                mono.now + TOTAL_REQUEST_BUDGET_NS,
            ).result(timeout=1.0)

        # 1. > 30 days remaining -> ready=True, degraded_codes=[].
        clock.set(not_after - dt.timedelta(days=30, seconds=1))
        h_clean = _shallow()
        assert h_clean["ok"] is True
        d_clean = cast(dict[str, JsonValue], h_clean["data"])
        assert d_clean["ready"] is True and d_clean["degraded_codes"] == []

        # 2. Exact 30d boundary and < 30d -> ready=True, degraded_codes=["tls_expiring"].
        for delta in (dt.timedelta(days=30), dt.timedelta(seconds=1)):
            clock.set(not_after - delta)
            h_exp = _shallow()
            assert h_exp["ok"] is True
            d_exp = cast(dict[str, JsonValue], h_exp["data"])
            assert d_exp["ready"] is True and d_exp["degraded_codes"] == ["tls_expiring"]

        # 3. Exact 0 remaining and past expiry -> ready=False, "tls_expired", and non-shallow admission blocked!
        for delta in (dt.timedelta(0), dt.timedelta(seconds=5)):
            clock.set(not_after + delta)
            h_dead = _shallow()
            assert h_dead["ok"] is True
            d_dead = cast(dict[str, JsonValue], h_dead["data"])
            assert d_dead["ready"] is False and d_dead["degraded_codes"] == ["tls_expired"]

            blocked_call = loop.submit(
                ToolCommand(
                    "submit_episode",
                    _episode_args(ws_a, "idem-blocked-by-expired-tls"),
                    token=tok_a,
                    selected_scope=scope_a,
                ),
                mono.now + TOTAL_REQUEST_BUDGET_NS,
            ).result(timeout=1.0)
            assert blocked_call == {
                "ok": False,
                "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
            }
        assert tls_reads[0] == 0 and sql_count[0] == 0
        arm_sql[0] = False

        # 4. C4 clock regression -> idempotency_clock_untrusted surfaces in RAM shallow health.
        t_high = not_after - dt.timedelta(days=60)
        clock.set(t_high)
        ok_write = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-c4-high-watermark"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert ok_write["ok"] is True

        clock.set(t_high - dt.timedelta(minutes=5))
        _ = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-c4-regressed-call"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)

        h_untrusted = _shallow()
        assert h_untrusted["ok"] is True
        d_untrusted = cast(dict[str, JsonValue], h_untrusted["data"])
        assert d_untrusted["ready"] is False
        assert "idempotency_clock_untrusted" in cast(list[JsonValue], d_untrusted["degraded_codes"])

        # 5. Bad token, revoked credential, and invalidated AuthGate.
        assert _shallow("sbk_cred-bad_notavalidbase64secret")["ok"] is False
        assert cast(dict[str, JsonValue], _shallow("bad-token")["error"])["code"] == "unauthenticated"

        rev_auth = make_bootstrap_auth(
            store_id=_daemon_template.store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=_daemon_template.cred_b.credential_id,
            trust_generation=1,
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        loop.revoke_credential(_daemon_template.cred_b.credential_id, rev_auth).result(timeout=BOUND_WAIT_S)
        assert cast(dict[str, JsonValue], _shallow(tok_b)["error"])["code"] == "unauthenticated"
        assert _shallow(tok_a)["ok"] is True

        loop.auth_gate.invalidate()
        assert _shallow(tok_a) == {
            "ok": False,
            "error": {"code": "policy_unavailable", "message": "policy unavailable"},
        }
    finally:
        with contextlib.suppress(BrainError):
            loop.stop()


def test_get_job_uses_owner_scope(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Production ``OwnerLoop`` serves ``get_job`` with strict owner/scope ACLs, zero payload leak & empty worker."""
    data_root, _, cfg = _instantiate_case(trusted_tmp, "prod-get-job", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    ws_b = _daemon_template.ws_b

    assert dict(PRODUCTION_JOB_HANDLERS) == {}

    secret_global = b"secret-global-job-payload-9911"
    secret_scoped = b"secret-scoped-job-payload-9922"
    expected_ref = ObjectRef(kind="improvement_report", id=new_id(), revision=1, digest=digest_bytes(b"rep-1"))

    rt_seed = reopen_kernel_job_runtime(data_root, _daemon_template.store_id, adapters)
    try:
        service, store = kernel_job_service(rt_seed, clock)
        global_job_id = enqueue_job(service, store, owner_id="dan", payload=secret_global).job_id

        scoped_spec = JobSpec(
            kind="fixture.work",
            owner_id="dan",
            payload=secret_scoped,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
        )
        store.stage_blob(secret_scoped)
        scoped_job_id = store.transact(lambda tx: service.enqueue(tx, scoped_spec)).job_id

        l_first = service.lease_next(rt_seed.lease.epoch, clock.now())
        assert l_first is not None and l_first.job_id == global_job_id
        service.cancel(global_job_id, _daemon_template.dan, selected_scope=None)

        l_scoped = service.lease_next(rt_seed.lease.epoch, clock.now())
        assert l_scoped is not None and l_scoped.job_id == scoped_job_id
        service.start(l_scoped)
        inv_id = service.reserve_invocation(l_scoped, RESERVE)
        service.settle_usage(inv_id, UsageRecord("0.25", True))
        service.complete(l_scoped, JobOutcome.success((expected_ref,)))

        due_global_id = enqueue_job(service, store, owner_id="dan", payload=secret_global).job_id
    finally:
        rt_seed.close()

    # Start real production OwnerLoop (domain=None, job_handlers=None).
    loop = create_daemon_owner_loop(os_=adapters, clock=clock, monotonic_clock=mono)
    try:
        loop.start(cfg)
        dl_ns = mono.now + TOTAL_REQUEST_BUDGET_NS
        tok_dan = _daemon_template.cred_a.token
        tok_bob = _daemon_template.cred_bob.token
        tok_other_m = _daemon_template.cred_other_machine.token

        # 1. Due queued job stays QUEUED at attempt=1 (production empty registry never leases/fails it).
        res_global = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": due_global_id}, token=tok_dan),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert res_global == {
            "ok": True,
            "data": {
                "job_id": due_global_id,
                "state": "queued",
                "attempt": 1,
                "result_refs": [],
                "accounting_status": "none",
            },
        }
        assert secret_global.decode("ascii") not in canonical_json(res_global).decode("utf-8")

        # Other owner cannot read Dan's global job.
        res_bob_global = loop.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": due_global_id}, token=tok_bob),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert res_bob_global == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # 2. Scoped job requires exact matching Scope(repo_id, checkout_id) and machine/principal grants.
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        res_scoped_ok = loop.submit(
            ToolCommand(
                "get_job",
                {"schema_version": "2.0", "job_id": scoped_job_id},
                token=tok_dan,
                selected_scope=scope_a,
            ),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert res_scoped_ok == {
            "ok": True,
            "data": {
                "job_id": scoped_job_id,
                "state": "succeeded",
                "attempt": 1,
                "result_refs": [expected_ref.to_dict()],
                "accounting_status": "settled",
            },
        }
        assert secret_scoped.decode("ascii") not in canonical_json(res_scoped_ok).decode("utf-8")

        for bad_tok, bad_scope in (
            (tok_dan, None),
            (tok_dan, scope_b),
            (tok_other_m, scope_a),
            (tok_bob, scope_a),
        ):
            denied = loop.submit(
                ToolCommand(
                    "get_job",
                    {"schema_version": "2.0", "job_id": scoped_job_id},
                    token=bad_tok,
                    selected_scope=bad_scope,
                ),
                dl_ns,
            ).result(timeout=BOUND_WAIT_S)
            assert denied == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # 3. Deep health and all 6 business tools return capability_unavailable after auth/validation.
        unsupported_calls: tuple[tuple[str, dict[str, JsonValue], Scope | None], ...] = (
            ("get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": "idem-deep-health-0001"}, None),
            (
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws_a.repo_id,
                    "checkout_id": ws_a.checkout_id,
                    "description": "task",
                    "idempotency_key": "idem-cap-prep-0001",
                },
                scope_a,
            ),
            (
                "search_knowledge",
                {"schema_version": "2.0", "workspace_id": ws_a.repo_id, "query": "bug"},
                scope_a,
            ),
            ("get_artifact", _artifact_args(ws_a, "idem-cap-art-0001"), scope_a),
            ("submit_episode", _episode_args(ws_a, "idem-cap-ep-0001"), scope_a),
            (
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws_a.repo_id,
                    "delivery_id": "deliv-1",
                    "outcome": "success",
                    "idempotency_key": "idem-cap-out-0001",
                },
                scope_a,
            ),
            (
                "request_improvement",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws_a.repo_id,
                    "task_id": "task-1",
                    "idempotency_key": "idem-cap-imp-0001",
                },
                scope_a,
            ),
        )
        for tool_name, tool_args, tool_scope in unsupported_calls:
            cap_res = loop.submit(
                ToolCommand(tool_name, tool_args, token=tok_dan, selected_scope=tool_scope),
                dl_ns,
            ).result(timeout=BOUND_WAIT_S)
            assert cap_res == {
                "ok": False,
                "error": {"code": "capability_unavailable", "message": "capability unavailable"},
            }
    finally:
        with contextlib.suppress(BrainError):
            loop.stop()


def test_auth_invalidation_fences_release_and_queued_call(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Policy transitions & owner authority errors invalidate AuthGate; cred_A revocation fences queued A, keeps B."""
    _, _, cfg = _instantiate_case(trusted_tmp, "auth-invalidation", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    domain = _DaemonTestDomain(ws_a=ws_a)

    observed_invalidated_before_publish: list[bool] = []
    loop_holder: list[OwnerLoop] = []

    def _before_publish(_view: RequestAuthView) -> None:
        if loop_holder and loop_holder[0].ready is not None:
            observed_invalidated_before_publish.append(loop_holder[0].auth_gate.current() is None)

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain,
        hooks=DaemonTestHooks(before_auth_gate_publish=_before_publish),
    )
    loop_holder.append(loop)
    blocker_entered = threading.Event()
    release_blocker = threading.Event()
    release_blocker.set()
    try:
        ready = loop.start(cfg)
        dl_ns = mono.now + TOTAL_REQUEST_BUDGET_NS
        tok_a = _daemon_template.cred_a.token
        tok_b = _daemon_template.cred_b.token

        # 1. Initial authenticated call mints grant_stamp bound to exact (cred_a, view.version, identity).
        rep_1 = loop.submit_reply(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-auth-init-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert rep_1.envelope["ok"] is True
        assert set(rep_1.envelope) == {"ok", "data"}
        stamp_1 = rep_1.grant_stamp
        assert isinstance(stamp_1, AuthGrantStamp)
        assert stamp_1.credential_id == _daemon_template.cred_a.credential_id
        assert stamp_1.identity == ready.identity
        assert loop.auth_gate.authorize_stamp(stamp_1) is True
        assert loop.auth_gate.authorize_release(stamp_1.credential_id, stamp_1.generation) is True

        # 2. register_workspace invalidates AuthGate BEFORE publish and bumps process-local generation
        #    even though PolicyStore trust_generation remains unchanged!
        extra_reg = build_registration(
            owner_id="dan",
            principal_id=_daemon_template.dan.principal_id,
            machine_id=_daemon_template.dan.machine_id,
            alias="ws-extra",
            raw_path=str(_daemon_template.checkout_extra_dir),
            raw_remote=REMOTE_EXTRA,
            provider_egress_enabled=False,
        )
        ws_auth = make_bootstrap_auth(
            store_id=_daemon_template.store_id,
            owner_id="dan",
            action="workspace_register",
            subject_id=extra_reg.subject_id,
            trust_generation=stamp_1.trust_generation,
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        loop.register_workspace(extra_reg, ws_auth).result(timeout=BOUND_WAIT_S)
        assert observed_invalidated_before_publish == [True]
        view_after_ws = loop.auth_gate.current()
        assert view_after_ws is not None
        assert view_after_ws.auth.trust_generation == stamp_1.trust_generation
        assert view_after_ws.version > stamp_1.generation
        assert loop.auth_gate.authorize_stamp(stamp_1) is False
        assert loop.auth_gate.authorize_release(stamp_1.credential_id, stamp_1.generation) is False

        # 3. Queue call A (cred_a) and call B (cred_b, same principal!) at view v2, revoke cred_a -> v3
        #    before owner executes queued A & B: A fails unauthenticated, B succeeds with v3 stamp!
        v2_version = view_after_ws.version
        release_blocker.clear()

        def _hold_owner() -> None:
            blocker_entered.set()
            assert release_blocker.wait(timeout=BOUND_WAIT_S)

        hold_fut = loop.run_owner_action(_hold_owner)
        assert blocker_entered.wait(timeout=BOUND_WAIT_S)

        rev_auth = make_bootstrap_auth(
            store_id=_daemon_template.store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=_daemon_template.cred_a.credential_id,
            trust_generation=view_after_ws.auth.trust_generation,
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        rev_fut = loop.revoke_credential(_daemon_template.cred_a.credential_id, rev_auth)

        # AuthGate is still at v2 while owner is held -> both tok_a and tok_b pass RAM pre-queue admission!
        queued_a = loop.submit_reply(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-queued-cred-a"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            dl_ns,
        )
        queued_b = loop.submit_reply(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-queued-cred-b"),
                token=tok_b,
                selected_scope=scope_a,
            ),
            dl_ns,
        )

        release_blocker.set()
        hold_fut.result(timeout=BOUND_WAIT_S)
        rev_fut.result(timeout=BOUND_WAIT_S)

        out_a = queued_a.result(timeout=BOUND_WAIT_S)
        out_b = queued_b.result(timeout=BOUND_WAIT_S)
        assert out_a.envelope == {"ok": False, "error": {"code": "unauthenticated", "message": "unauthenticated"}}
        assert out_a.grant_stamp is None

        assert out_b.envelope["ok"] is True
        assert out_b.grant_stamp is not None
        assert out_b.grant_stamp.credential_id == _daemon_template.cred_b.credential_id
        assert out_b.grant_stamp.generation > v2_version
        assert loop.auth_gate.authorize_stamp(out_b.grant_stamp) is True

        # 4. Authority error inside an owner call invalidates AuthGate immediately.
        stamp_before_err = out_b.grant_stamp
        domain.owner_error_once.append(BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch"))
        err_rep = loop.submit_reply(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-owner-auth-err"),
                token=tok_b,
                selected_scope=scope_a,
            ),
            dl_ns,
        ).result(timeout=BOUND_WAIT_S)
        assert err_rep.envelope == {
            "ok": False,
            "error": {"code": "identity_mismatch", "message": "principal identity mismatch"},
        }
        assert err_rep.grant_stamp is None
        assert loop.auth_gate.current() is None
        assert loop.auth_gate.authorize_stamp(stamp_before_err) is False
    finally:
        release_blocker.set()
        with contextlib.suppress(BrainError):
            loop.stop()


def test_late_auth_publish_cannot_reopen_stopped_gate(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Stopping ``OwnerLoop`` seals ``AuthGate`` terminally so an in-flight publish cannot reopen it."""
    _, _, cfg = _instantiate_case(trusted_tmp, "late-auth-publish", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)

    arm_pause = threading.Event()
    publish_paused = threading.Event()
    allow_publish = threading.Event()
    captured_views: list[RequestAuthView] = []

    def _pause_before_publish(view: RequestAuthView) -> None:
        captured_views.append(view)
        if arm_pause.is_set():
            publish_paused.set()
            allow_publish.wait(timeout=BOUND_WAIT_S)

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        hooks=DaemonTestHooks(before_auth_gate_publish=_pause_before_publish),
    )
    try:
        loop.start(cfg)
        gate: AuthGate = loop.auth_gate
        initial_view = gate.current()
        assert initial_view is not None

        arm_pause.set()
        extra_reg = build_registration(
            owner_id="dan",
            principal_id=_daemon_template.dan.principal_id,
            machine_id=_daemon_template.dan.machine_id,
            alias="ws-late-pub",
            raw_path=str(_daemon_template.checkout_extra_dir),
            raw_remote=REMOTE_EXTRA,
            provider_egress_enabled=False,
        )
        ws_auth = make_bootstrap_auth(
            store_id=_daemon_template.store_id,
            owner_id="dan",
            action="workspace_register",
            subject_id=extra_reg.subject_id,
            trust_generation=initial_view.auth.trust_generation,
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        reg_fut = loop.register_workspace(extra_reg, ws_auth)
        assert publish_paused.wait(timeout=BOUND_WAIT_S)

        # Stop with short grace closes AuthGate terminally under mutex before allow_publish releases!
        report = loop.stop(grace_s=0.02)
        assert report.state in {ShutdownState.OVERRUN, ShutdownState.STOPPED}
        assert gate.closed is True
        assert gate.current() is None

        # Release the paused owner publisher and wait for any pending future settlement.
        allow_publish.set()
        with contextlib.suppress(BrainError):
            reg_fut.result(timeout=BOUND_WAIT_S)

        assert gate.closed is True
        assert gate.current() is None
        assert gate.current_with_health() == (None, None, True)
        assert gate.authorize_release(_daemon_template.cred_a.credential_id, initial_view.version) is False

        # Direct publish / publish_view attempts on a closed gate fail closed and leave current() None.
        _expect_brain_error(ErrorCode.DAEMON_UNAVAILABLE, lambda: gate.publish_view(captured_views[-1]))
        assert gate.current() is None

        post_stop = loop.submit(
            ToolCommand("get_health", {"schema_version": "2.0"}, token=_daemon_template.cred_a.token),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=1.0)
        assert post_stop == {
            "ok": False,
            "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
        }
    finally:
        allow_publish.set()
        with contextlib.suppress(BrainError):
            loop.stop()


def test_owner_cutoff_settles_once_while_commit_blocked(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """1,475 ms commit cutoff settles once (arbiter OR late owner finish under state lock) & cleans send attempt."""
    data_root, _, cfg = _instantiate_case(trusted_tmp, "owner-cutoff", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    tok_a = _daemon_template.cred_a.token

    handler_cutoff_offset_ns = TOTAL_REQUEST_BUDGET_NS - HANDLER_RESERVE_NS  # 1,300 ms
    cutoff_offset_ns = TOTAL_REQUEST_BUDGET_NS - RESPONSE_RESERVE_NS  # 1,475 ms
    pre_commit_advance_keys: dict[str, int] = {}
    late_finish_keys: dict[str, int] = {}

    def _before_enter_commit(_res: Reservation | None) -> None:
        if "active" in pre_commit_advance_keys:
            mono.set(pre_commit_advance_keys.pop("active"))

    def _on_apply(idem_key: str, _res_uuid: str) -> None:
        if idem_key in late_finish_keys:
            mono.set(late_finish_keys[idem_key])

    domain = _DaemonTestDomain(
        ws_a=ws_a,
        pause_idem_keys={"idem-cutoff-blocked-0001"},
        on_apply_hook=_on_apply,
    )
    domain.allow_apply_finish.clear()

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain,
        hooks=DaemonTestHooks(before_enter_commit=_before_enter_commit),
    )
    expected_pending_send_ids: set[str] = set()
    try:
        loop.start(cfg)

        # Subcase 0: Pre-commit 1,300 ms handler cutoff inside before_enter_commit -> enter_commit refuses,
        # Future settles once with deadline_exceeded, _apply never executes, and scope_key is released!
        t_pre = mono.now
        pre_commit_advance_keys["active"] = t_pre + handler_cutoff_offset_ns
        callbacks_pre: list[OwnerReply] = []
        fut_pre = loop.submit_reply(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-precommit-0000"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            t_pre + TOTAL_REQUEST_BUDGET_NS,
        )
        fut_pre.add_done_callback(lambda f: callbacks_pre.append(f.result()))
        rep_pre = fut_pre.result(timeout=BOUND_WAIT_S)
        assert rep_pre.envelope == {
            "ok": False,
            "error": {"code": "deadline_exceeded", "message": "deadline exceeded"},
        }
        assert rep_pre.grant_stamp is None and rep_pre.send_completion is None
        assert len(callbacks_pre) == 1
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert "idem-cutoff-precommit-0000" not in domain.executed_keys

        retry_pre = loop.submit_reply(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-precommit-0000"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert retry_pre.envelope["ok"] is True
        assert retry_pre.send_completion is not None
        expected_pending_send_ids.add(retry_pre.send_completion.send_attempt_id)

        # Subcase A: Owner blocked inside COMMITTING past 1,475 ms -> external arbiter settles Future once
        # with commit_outcome_unknown; retry gets in_progress until commit finishes, then replays once!
        t0 = mono.advance(10_000_000)
        pre_commit_advance_keys["active"] = t0 + 1_290_000_000  # 1,290 ms (< 1,300 ms handler cutoff)
        late_finish_keys["idem-cutoff-blocked-0001"] = t0 + cutoff_offset_ns  # exact 1,475 ms in COMMITTING

        callbacks_a: list[OwnerReply] = []
        fut_a = loop.submit_reply(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-blocked-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            t0 + TOTAL_REQUEST_BUDGET_NS,
        )
        fut_a.add_done_callback(lambda f: callbacks_a.append(f.result()))
        assert domain.apply_entered.wait(timeout=BOUND_WAIT_S)

        rep_a = fut_a.result(timeout=BOUND_WAIT_S)
        assert rep_a.envelope == {
            "ok": False,
            "error": {"code": "commit_outcome_unknown", "message": "commit outcome unknown"},
        }
        assert rep_a.grant_stamp is None and rep_a.send_completion is None
        assert len(callbacks_a) == 1

        # Same idempotency_key while owner transaction is still blocked -> in_progress (reservation retained!).
        t_retry = mono.now
        in_prog = loop.submit(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-blocked-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            t_retry + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=1.0)
        assert in_prog == {
            "ok": False,
            "error": {"code": "in_progress", "message": "operation in progress"},
        }

        # Release blocked commit, fence owner completion, and verify replay returns the single committed result!
        domain.allow_apply_finish.set()
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        replay_a = loop.submit_reply(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-blocked-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert replay_a.envelope["ok"] is True
        assert replay_a.send_completion is not None
        expected_pending_send_ids.add(replay_a.send_completion.send_attempt_id)
        assert domain.executed_keys.count("idem-cutoff-blocked-0001") == 1

        # Subcase B: Timer thread held below cutoff while owner finishes at exact 1,475 ms tick ->
        # owner checks monotonic clock under state lock and CANNOT win late!
        t2 = mono.advance(10_000_000)
        late_finish_keys["idem-cutoff-late-owner-0002"] = t2 + cutoff_offset_ns

        rep_b = loop.submit_reply(
            ToolCommand(
                "get_artifact",
                _artifact_args(ws_a, "idem-cutoff-late-owner-0002"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            t2 + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert rep_b.envelope == {
            "ok": False,
            "error": {"code": "commit_outcome_unknown", "message": "commit outcome unknown"},
        }
        assert rep_b.grant_stamp is None and rep_b.send_completion is None
    finally:
        domain.allow_apply_finish.set()
        with contextlib.suppress(BrainError):
            loop.stop()

    # Inspect durable artifact_send_attempt rows: zero orphaned PENDING attempts from cutoff-losing calls,
    # except the explicit retries (retry_pre & replay_a) which won settlement for 6b flush!
    rt_check = reopen_kernel_job_runtime(data_root, _daemon_template.store_id, adapters)
    try:
        with rt_check.store.transaction() as txn:
            rows = txn.db.execute("SELECT id, state FROM artifact_send_attempt").fetchall()
        states_by_id = {str(r[0]): str(r[1]) for r in rows}
        for sid, st in states_by_id.items():
            if sid in expected_pending_send_ids:
                assert st == SendAttemptState.PENDING.value
            else:
                assert st == SendAttemptState.UNKNOWN.value
    finally:
        rt_check.close()


def test_reserve_enqueue_race_settles_once_on_stop_or_full(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Pause between reserve and queue append: full+expiry race and stop race settle once with zero key leak."""
    data_root, _, cfg = _instantiate_case(trusted_tmp, "reserve-enqueue-race", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    tok_a = _daemon_template.cred_a.token

    pause_next_reserve = threading.Event()
    paused_in_hook = threading.Event()
    release_hook = threading.Event()
    release_hook.set()
    captured_res: list[Reservation] = []

    def _after_reserve_before_enqueue(_res: Reservation) -> None:
        if pause_next_reserve.is_set():
            pause_next_reserve.clear()
            captured_res.append(_res)
            paused_in_hook.set()
            release_hook.wait(timeout=BOUND_WAIT_S)

    domain = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-hold-owner-0000"})
    domain.allow_apply_finish.clear()

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain,
        hooks=DaemonTestHooks(after_reserve_before_enqueue=_after_reserve_before_enqueue),
    )
    try:
        loop.start(cfg)
        t0 = mono.now

        # Hold owner thread on request #0 so the 32-slot queue can be filled deterministically.
        fut_hold = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-hold-owner-0000"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            t0 + 10 * TOTAL_REQUEST_BUDGET_NS,
        )
        assert domain.apply_entered.wait(timeout=BOUND_WAIT_S)

        # Subcase 1: Pause r_full between reserve and enqueue, fill all 32 slots, expire r_full's handler
        # budget, wait for the external arbiter to settle r_full with deadline_exceeded, and THEN release
        # into STORE_BUSY rollback -> settles once, never executes, and does not leak scope_key!
        release_hook.clear()
        paused_in_hook.clear()
        captured_res.clear()
        pause_next_reserve.set()

        race_full_holder: list[Future[CallResult]] = []
        race_full_cbs: list[CallResult] = []
        sub_full_errors: list[BaseException] = []

        def _submit_r_full() -> None:
            try:
                f = loop.submit(
                    ToolCommand(
                        "submit_episode",
                        _episode_args(ws_a, "idem-race-full-0001"),
                        token=tok_a,
                        selected_scope=scope_a,
                    ),
                    t0 + TOTAL_REQUEST_BUDGET_NS,
                )
                f.add_done_callback(lambda done_f: race_full_cbs.append(done_f.result()))
                race_full_holder.append(f)
            except BaseException as exc:  # noqa: BLE001
                sub_full_errors.append(exc)

        t_sub_full = threading.Thread(target=_submit_r_full, daemon=True)
        t_sub_full.start()
        assert paused_in_hook.wait(timeout=BOUND_WAIT_S)
        assert len(captured_res) == 1
        paused_res = captured_res[0]

        fill_futs = [
            loop.submit(
                ToolCommand(
                    "submit_episode",
                    _episode_args(ws_a, f"idem-race-fill-{i:04d}"),
                    token=tok_a,
                    selected_scope=scope_a,
                ),
                t0 + 10 * TOTAL_REQUEST_BUDGET_NS,
            )
            for i in range(DAEMON_QUEUE_DEPTH)
        ]

        # Advance monotonic clock to exact 1,300 ms handler cutoff and wait for arbiter settlement BEFORE release!
        mono.set(t0 + TOTAL_REQUEST_BUDGET_NS - HANDLER_RESERVE_NS)
        settled_by_arbiter = paused_res.wait_response(timeout=BOUND_WAIT_S)
        assert settled_by_arbiter == {
            "ok": False,
            "error": {"code": "deadline_exceeded", "message": "deadline exceeded"},
        }

        release_hook.set()
        t_sub_full.join(timeout=BOUND_WAIT_S)
        assert not t_sub_full.is_alive()
        assert sub_full_errors == []
        assert len(race_full_holder) == 1
        res_full = race_full_holder[0].result(timeout=BOUND_WAIT_S)
        assert res_full == {
            "ok": False,
            "error": {"code": "deadline_exceeded", "message": "deadline exceeded"},
        }
        assert len(race_full_cbs) == 1

        # Drain #0 and the 32 fillers, then prove "idem-race-full-0001" was NOT executed and is NOT leaked!
        domain.allow_apply_finish.set()
        assert fut_hold.result(timeout=BOUND_WAIT_S)["ok"] is True
        for ff in fill_futs:
            assert ff.result(timeout=BOUND_WAIT_S)["ok"] is True
        assert "idem-race-full-0001" not in domain.executed_keys

        retry_after_full = loop.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-race-full-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert retry_after_full["ok"] is True

        # Subcase 2: Pause r_stop between reserve and enqueue, call OwnerLoop.stop(), then release ->
        # stop wins before enqueue, rolls back reservation, and settles Future once with daemon_unavailable!
        release_hook.clear()
        paused_in_hook.clear()
        pause_next_reserve.set()
        race_stop_holder: list[Future[CallResult]] = []
        race_stop_cbs: list[CallResult] = []

        def _submit_r_stop() -> None:
            f = loop.submit(
                ToolCommand(
                    "submit_episode",
                    _episode_args(ws_a, "idem-race-stop-0002"),
                    token=tok_a,
                    selected_scope=scope_a,
                ),
                mono.now + TOTAL_REQUEST_BUDGET_NS,
            )
            f.add_done_callback(lambda done_f: race_stop_cbs.append(done_f.result()))
            race_stop_holder.append(f)

        t_sub_stop = threading.Thread(target=_submit_r_stop, daemon=True)
        t_sub_stop.start()
        assert paused_in_hook.wait(timeout=BOUND_WAIT_S)

        stop_holder: list[ShutdownState] = []
        t_stopper = threading.Thread(target=lambda: stop_holder.append(loop.stop(grace_s=2.0).state), daemon=True)
        t_stopper.start()

        # Wait with bounded deadline until stop() clears ready and closes AuthGate, then release r_stop!
        _wait_until(
            lambda: loop.ready is None and loop.auth_gate.closed,
            desc="OwnerLoop.stop() to clear ready and close AuthGate",
        )
        release_hook.set()

        t_sub_stop.join(timeout=BOUND_WAIT_S)
        t_stopper.join(timeout=BOUND_WAIT_S)
        assert len(race_stop_holder) == 1
        res_stop = race_stop_holder[0].result(timeout=BOUND_WAIT_S)
        assert res_stop == {
            "ok": False,
            "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
        }
        assert len(race_stop_cbs) == 1
        assert "idem-race-stop-0002" not in domain.executed_keys
        assert stop_holder == [ShutdownState.STOPPED]
    finally:
        release_hook.set()
        domain.allow_apply_finish.set()
        with contextlib.suppress(BrainError):
            loop.stop()

    # Confirm zero durable commit for idem-race-stop-0002 on reopen.
    rt_verify = reopen_kernel_job_runtime(data_root, _daemon_template.store_id, adapters)
    try:
        with rt_verify.store.transaction() as txn:
            count = int(txn.db.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])
        # 1 hold + 32 fillers + 1 retry_after_full = 34 (idem-race-stop-0002 was never committed).
        assert count == 1 + DAEMON_QUEUE_DEPTH + 1
    finally:
        rt_verify.close()


# ===========================================================================
# Group 3 (6a.3) · Shutdown & worker handoff
# ===========================================================================


def test_shutdown_keeps_lock_until_handles_close(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Clean & overrun shutdowns validate grace_s, hold writer.lock until DB handles close, & fence slow worker."""
    # Part 1: Clean drain + invalid grace_s rejection + lock held at before_runtime_close.
    clean_root, _, clean_cfg = _instantiate_case(trusted_tmp, "shutdown-clean", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    tok_a = _daemon_template.cred_a.token

    domain_clean = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-drain-clean-0001"})
    domain_clean.allow_apply_finish.clear()
    bound_clean: list[BoundLoopbackListener] = []
    close_checks: list[bool] = []

    def _before_close_clean(rt: Runtime) -> None:
        assert bound_clean and bound_clean[0].sock.fileno() == -1
        assert not (clean_root / ENDPOINT_NAME).exists()
        assert not rt.store.closed and not rt.policy.closed and rt.lease.held
        _expect_brain_error(ErrorCode.WRITER_HELD, lambda: acquire_writer(DataRoot.at(clean_root), adapters))
        close_checks.append(True)

    loop_clean = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        domain=domain_clean,
        hooks=DaemonTestHooks(before_runtime_close=_before_close_clean),
        on_listener_bound=bound_clean.append,
    )
    try:
        loop_clean.start(clean_cfg)

        # Reject boolean, negative, NaN, and infinite grace_s with INVALID_INPUT without stopping!
        bad_graces: tuple[object, ...] = (True, False, -0.01, math.nan, math.inf, -math.inf)
        for bad_grace in bad_graces:
            _expect_brain_error(
                ErrorCode.INVALID_INPUT,
                functools.partial(loop_clean.stop, grace_s=cast(float, bad_grace)),
            )
        assert loop_clean.ready is not None

        drain_fut = loop_clean.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-drain-clean-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + 10 * TOTAL_REQUEST_BUDGET_NS,
        )
        assert domain_clean.apply_entered.wait(timeout=BOUND_WAIT_S)

        stop_rep_holder: list[ShutdownState] = []
        stop_removed_holder: list[bool] = []

        def _do_clean_stop() -> None:
            rep = loop_clean.stop(grace_s=3.0)
            stop_rep_holder.append(rep.state)
            stop_removed_holder.append(rep.endpoint_removed)

        t_stop = threading.Thread(target=_do_clean_stop, daemon=True)
        t_stop.start()
        _wait_until(lambda: loop_clean.ready is None, desc="OwnerLoop.stop() to clear ready")

        # Post-stop submit is immediately refused while in-flight commit drains to completion.
        refused = loop_clean.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-refused-during-stop"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=1.0)
        assert refused["ok"] is False
        assert cast(dict[str, JsonValue], refused["error"])["code"] == "daemon_unavailable"

        domain_clean.allow_apply_finish.set()
        assert drain_fut.result(timeout=BOUND_WAIT_S)["ok"] is True
        t_stop.join(timeout=BOUND_WAIT_S)
        assert stop_rep_holder == [ShutdownState.STOPPED]
        assert stop_removed_holder == [True]
        assert close_checks == [True]
    finally:
        domain_clean.allow_apply_finish.set()
        with contextlib.suppress(BrainError):
            loop_clean.stop()

    rt_reopen = reopen_kernel_job_runtime(clean_root, _daemon_template.store_id, adapters)
    try:
        with rt_reopen.store.transaction() as txn:
            assert int(txn.db.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]) == 1
    finally:
        rt_reopen.close()

    # Part 2: Overrun shutdown + foreground serve() lifecycle retention + slow worker durable recovery.
    over_root, _, over_cfg = _instantiate_case(trusted_tmp, "shutdown-overrun", _daemon_template)
    rt_seed = reopen_kernel_job_runtime(over_root, _daemon_template.store_id, adapters)
    try:
        svc_seed, st_seed = kernel_job_service(rt_seed, clock)
        slow_job_id = enqueue_job(svc_seed, st_seed, owner_id="dan", kind="slow.work", payload=b"slow").job_id
    finally:
        rt_seed.close()

    worker_entered = threading.Event()
    worker_saw_cancel = threading.Event()
    release_worker = threading.Event()

    def _slow_job_handler(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        worker_entered.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            worker_saw_cancel.set()
        release_worker.wait(timeout=BOUND_WAIT_S)
        return ()

    domain_over = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-overrun-commit-0001"})
    domain_over.allow_apply_finish.clear()
    stop_ev = threading.Event()
    ready_ev = threading.Event()
    loop_over_ref: list[OwnerLoop] = []
    serve_rc: list[int] = []
    serve_done = threading.Event()

    def _on_ready_over(_r: Ready, lp: OwnerLoop) -> None:
        loop_over_ref.append(lp)
        ready_ev.set()

    def _run_foreground_serve() -> None:
        try:
            rc = serve(
                over_cfg,
                os_=adapters,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=0.05,
                on_ready=_on_ready_over,
                domain=domain_over,
                job_handlers={"slow.work": _slow_job_handler},
            )
            serve_rc.append(rc)
        finally:
            serve_done.set()

    t_serve = threading.Thread(target=_run_foreground_serve, daemon=True)
    t_serve.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S)
        assert worker_entered.wait(timeout=BOUND_WAIT_S)
        lp_over = loop_over_ref[0]

        fut_committing = lp_over.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-overrun-commit-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + 10 * TOTAL_REQUEST_BUDGET_NS,
        )
        assert domain_over.apply_entered.wait(timeout=BOUND_WAIT_S)

        fut_queued = lp_over.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-overrun-queued-0002"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            mono.now + 10 * TOTAL_REQUEST_BUDGET_NS,
        )

        # Trigger stop with 50 ms grace while commit & slow worker are still blocked!
        stop_ev.set()
        assert worker_saw_cancel.wait(timeout=BOUND_WAIT_S)
        queued_out = fut_queued.result(timeout=BOUND_WAIT_S)
        assert queued_out["ok"] is False

        # Foreground serve() MUST wait for owner cleanup & keep writer.lock held while commit unwinds!
        assert not serve_done.wait(timeout=0.08)
        assert t_serve.is_alive()
        _expect_brain_error(ErrorCode.WRITER_HELD, lambda: acquire_writer(DataRoot.at(over_root), adapters))

        # Unblock commit first, let owner close Runtime, then release slow worker after fence!
        domain_over.allow_apply_finish.set()
        _ = fut_committing.result(timeout=BOUND_WAIT_S)
        assert serve_done.wait(timeout=BOUND_WAIT_S)
        assert serve_rc and serve_rc[0] != 0
        release_worker.set()
    finally:
        domain_over.allow_apply_finish.set()
        release_worker.set()
        stop_ev.set()
        t_serve.join(timeout=BOUND_WAIT_S)

    # Reopen in next epoch: committed transaction survived AND slow_job recovers to QUEUED attempt 2!
    rt_after = reopen_kernel_job_runtime(over_root, _daemon_template.store_id, adapters)
    try:
        with rt_after.store.transaction() as txn:
            assert int(txn.db.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]) == 1
        svc_after, _ = kernel_job_service(rt_after, clock)
        rec = svc_after.recover(rt_after.lease.epoch)
        assert rec.jobs_requeued == 1
        view_slow = svc_after.get_job(slow_job_id, _daemon_template.dan, selected_scope=None)
        assert (view_slow.state, view_slow.attempt) == (JobState.QUEUED, 2)
    finally:
        rt_after.close()


def test_shutdown_close_failure_retains_lease(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """``Runtime.close`` failure reports ``CLOSE_FAILED``, returns non-zero in ``serve``, and retains lease."""
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    mono = _FakeMonotonicClock()
    adapters = os_adapters(clock=clock, monotonic=mono)

    # 1. Direct OwnerLoop.stop() -> ShutdownState.CLOSE_FAILED with writer.lock retained.
    r1, _, cfg1 = _instantiate_case(trusted_tmp, "close-fail-loop", _daemon_template)
    held_rt_1: list[tuple[Runtime, Callable[[], None]]] = []

    def _inject_close_fail_1(rt: Runtime) -> None:
        real_close = rt.store.close
        held_rt_1.append((rt, real_close))

        def _boom() -> None:
            raise BrainError(ErrorCode.IO_ERROR, "I/O error")

        rt.store.close = _boom  # type: ignore[method-assign]

    loop_1 = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono,
        hooks=DaemonTestHooks(before_runtime_close=_inject_close_fail_1),
    )
    try:
        loop_1.start(cfg1)
        rep = loop_1.stop(grace_s=2.0)
        assert rep.state is ShutdownState.CLOSE_FAILED
        assert rep.error_code is ErrorCode.IO_ERROR
        assert held_rt_1 and held_rt_1[0][0].lease.held is True
        _expect_brain_error(ErrorCode.WRITER_HELD, lambda: acquire_writer(DataRoot.at(r1), adapters))
    finally:
        for rt_obj, orig_close in held_rt_1:
            rt_obj.store.close = orig_close  # type: ignore[method-assign]
            with contextlib.suppress(BrainError):
                rt_obj.close()

    # 2. Foreground serve() -> returns non-zero WITHOUT double-releasing AdmittedWriter in any finally block!
    r2, _, cfg2 = _instantiate_case(trusted_tmp, "close-fail-serve", _daemon_template)
    held_rt_2: list[tuple[Runtime, Callable[[], None]]] = []

    def _inject_close_fail_2(rt: Runtime) -> None:
        real_close = rt.store.close
        held_rt_2.append((rt, real_close))

        def _boom() -> None:
            raise BrainError(ErrorCode.IO_ERROR, "I/O error")

        rt.store.close = _boom  # type: ignore[method-assign]

    stop_ev = threading.Event()
    try:
        rc = serve(
            cfg2,
            os_=adapters,
            clock=clock,
            monotonic_clock=mono,
            stop_event=stop_ev,
            on_ready=lambda _r, _lp: stop_ev.set(),
            hooks=DaemonTestHooks(before_runtime_close=_inject_close_fail_2),
        )
        assert rc != 0
        assert held_rt_2 and held_rt_2[0][0].lease.held is True
        _expect_brain_error(ErrorCode.WRITER_HELD, lambda: acquire_writer(DataRoot.at(r2), adapters))
    finally:
        for rt_obj, orig_close in held_rt_2:
            rt_obj.store.close = orig_close  # type: ignore[method-assign]
            with contextlib.suppress(BrainError):
                rt_obj.close()
    assert prepare_data_root(r2, adapters) == DataRoot.at(r2)


def test_startup_prepublish_tls_naive_clock_and_post_rebuild_verification(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Startup rechecks UTC cert expiry before publish, rejects naive clocks, and verifies legacy rebuild completion."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)

    # Subcase A: Pre-publish UTC validity recheck catches expiry BEFORE staging/publishing endpoint.json.
    root_a, _, cfg_a = _instantiate_case(trusted_tmp, "b1-prepublish-tls", _daemon_template)
    clock_a = FakeClock(base_now)
    real_adapters_a = os_adapters(clock=clock_a)
    endpoint_pub_ops: list[tuple[str, str]] = []

    def _is_endpoint_target(path: Path) -> bool:
        norm = os.path.normcase(path.name)
        return norm == ENDPOINT_NAME or norm.startswith(ENDPOINT_STAGE_PREFIX)

    class _RecordingEndpointPublisher:
        def flush_file(self, path: Path) -> None:
            real_adapters_a.publisher.flush_file(path)

        def write_new(self, path: Path, data: bytes) -> None:
            if _is_endpoint_target(path):
                endpoint_pub_ops.append(("write_new", path.name))
            real_adapters_a.publisher.write_new(path, data)

        def publish(self, staging: Path, final: Path) -> None:
            if _is_endpoint_target(staging) or _is_endpoint_target(final):
                endpoint_pub_ops.append(("publish", final.name))
            real_adapters_a.publisher.publish(staging, final)

        def rename_dir(self, src: Path, dst: Path) -> None:
            real_adapters_a.publisher.rename_dir(src, dst)

        def sync_directory(self, directory: Path) -> None:
            real_adapters_a.publisher.sync_directory(directory)

        def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
            return real_adapters_a.publisher.durability(directory, env)

    rec_adapters_a = dataclasses.replace(real_adapters_a, publisher=_RecordingEndpointPublisher())
    bound_a: list[BoundLoopbackListener] = []
    hook_seen_a: list[Endpoint] = []

    def _expire_before_publish(ep: Endpoint) -> None:
        hook_seen_a.append(ep)
        clock_a.set(_daemon_template.tls.not_after)

    loop_a = create_daemon_owner_loop(
        os_=rec_adapters_a,
        clock=clock_a,
        hooks=DaemonTestHooks(before_endpoint_publish=_expire_before_publish),
        on_listener_bound=bound_a.append,
    )
    _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_a.start(cfg_a))
    assert len(hook_seen_a) == 1
    assert endpoint_pub_ops == []
    assert loop_a.ready is None
    assert not (root_a / ENDPOINT_NAME).exists()
    assert bound_a and all(b.sock.fileno() == -1 for b in bound_a)
    with acquire_writer(DataRoot.at(root_a), real_adapters_a):
        pass

    # Subcase B: Naive clock (tzinfo=None, +10d well inside cert window regardless of host TZ) fails closed.
    root_b, _, cfg_b = _instantiate_case(trusted_tmp, "b1-naive-clock", _daemon_template)
    real_adapters_b = os_adapters(clock=FakeClock(base_now))
    before_bind_hit: list[bool] = []

    class _SwitchableNaiveClock:
        def __init__(self, initial: dt.datetime) -> None:
            self._current = initial
            self._naive = False

        def switch_to_naive(self) -> None:
            self._naive = True

        def now(self) -> dt.datetime:
            if self._naive:
                return (self._current + dt.timedelta(days=10)).replace(tzinfo=None)
            return self._current

    naive_clock = _SwitchableNaiveClock(base_now)

    def _flip_naive(_rt: Runtime) -> None:
        before_bind_hit.append(True)
        naive_clock.switch_to_naive()

    bound_b: list[BoundLoopbackListener] = []
    loop_b = create_daemon_owner_loop(
        os_=real_adapters_b,
        clock=naive_clock,
        hooks=DaemonTestHooks(before_bind=_flip_naive),
        on_listener_bound=bound_b.append,
    )
    try:
        _expect_brain_error(ErrorCode.INVALID_INPUT, lambda: loop_b.start(cfg_b))
        assert before_bind_hit == [True]
        assert bound_b == []
        assert loop_b.ready is None
        assert not (root_b / ENDPOINT_NAME).exists()
    finally:
        with contextlib.suppress(BrainError):
            loop_b.stop()
    with acquire_writer(DataRoot.at(root_b), real_adapters_b):
        pass

    # Subcase C: Post-rebuild verification fails closed with INTEGRITY_FAILURE if legacy settled/0 rows remain.
    root_c, _, cfg_c = _instantiate_case(trusted_tmp, "b1-post-rebuild-legacy", _daemon_template)
    clock_c = FakeClock(base_now)
    real_adapters_c = os_adapters(clock=clock_c)
    rt_seed = reopen_kernel_job_runtime(root_c, _daemon_template.store_id, real_adapters_c)
    try:
        svc_seed, st_seed = kernel_job_service(rt_seed, clock_c)
        enqueue_job(svc_seed, st_seed, owner_id="dan", payload=b"b1-legacy-seed")
        lease_seed = svc_seed.lease_next(rt_seed.lease.epoch, clock_c.now())
        assert lease_seed is not None
        svc_seed.start(lease_seed)
        inv_seed = svc_seed.reserve_invocation(lease_seed, RESERVE)
        svc_seed.settle_usage(inv_seed, UsageRecord(None, False))
        svc_seed.complete(lease_seed, JobOutcome.success())
    finally:
        rt_seed.close()

    db_c = root_c / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(db_c)) as raw_db, raw_db:
        raw_db.execute("PRAGMA journal_mode=DELETE")
        raw_db.execute(
            "UPDATE p_provider_invocations_state SET state = 'settled', usage_complete = 0 WHERE invocation_id = ?",
            (inv_seed,),
        )
    real_adapters_c.permissions.secure_file(db_c)

    noop_installed: list[bool] = []
    recover_reached: list[bool] = []
    bound_c: list[BoundLoopbackListener] = []

    def _noop_rebuild(rt: Runtime) -> None:
        noop_installed.append(True)
        rt.store.rebuild_projections = lambda: 0  # type: ignore[method-assign]

    def _on_before_recover(_rt: Runtime) -> None:
        recover_reached.append(True)

    loop_c = create_daemon_owner_loop(
        os_=real_adapters_c,
        clock=clock_c,
        hooks=DaemonTestHooks(
            after_open_before_rebuild=_noop_rebuild,
            before_job_recover=_on_before_recover,
        ),
        on_listener_bound=bound_c.append,
    )
    try:
        _expect_brain_error(ErrorCode.INTEGRITY_FAILURE, lambda: loop_c.start(cfg_c))
        assert noop_installed == [True]
        assert recover_reached == []
        assert bound_c == []
        assert loop_c.ready is None
        assert not (root_c / ENDPOINT_NAME).exists()
    finally:
        with contextlib.suppress(BrainError):
            loop_c.stop()
    with acquire_writer(DataRoot.at(root_c), real_adapters_c):
        pass


def test_owner_live_authority_divergence_invalidates_gate_and_withholds_stamp(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """Owner live-policy divergence from stale RAM ``AuthGate`` withholds ``grant_stamp`` and invalidates gate."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)

    # Subcase A: Live PolicyStore workspace mutation without AuthGate republish -> grant_stamp=None & gate cleared.
    root_a, _, cfg_a = _instantiate_case(trusted_tmp, "b2-stale-stamp", _daemon_template)
    clock_a = FakeClock(base_now)
    mono_a = _FakeMonotonicClock()
    adapters_a = os_adapters(clock=clock_a, monotonic=mono_a)

    rt_seed_a = reopen_kernel_job_runtime(root_a, _daemon_template.store_id, adapters_a)
    try:
        svc_a, st_a = kernel_job_service(rt_seed_a, clock_a)
        job_a_id = enqueue_job(svc_a, st_a, owner_id="dan", payload=b"b2-job-a").job_id
    finally:
        rt_seed_a.close()

    rt_box_a: list[Runtime] = []
    loop_a = create_daemon_owner_loop(
        os_=adapters_a,
        clock=clock_a,
        monotonic_clock=mono_a,
        hooks=DaemonTestHooks(before_bind=rt_box_a.append),
    )
    try:
        loop_a.start(cfg_a)
        rt_a = rt_box_a[0]
        initial_view_a = loop_a.auth_gate.current()
        assert initial_view_a is not None
        dl_a = mono_a.now + TOTAL_REQUEST_BUDGET_NS

        rep_ok = loop_a.submit_reply(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_a_id}, token=_daemon_template.cred_a.token),
            dl_a,
        ).result(timeout=BOUND_WAIT_S)
        assert rep_ok.envelope["ok"] is True
        assert rep_ok.grant_stamp is not None

        div_dir = trusted_tmp / "b2-div-chk"
        div_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            os.chmod(div_dir, 0o700)

        def _mutate_live_policy_only() -> None:
            reg = build_registration(
                owner_id="dan",
                principal_id=_daemon_template.dan.principal_id,
                machine_id=_daemon_template.dan.machine_id,
                alias="ws-divergent",
                raw_path=str(div_dir),
                raw_remote=REMOTE_EXTRA,
                provider_egress_enabled=False,
            )
            proof = make_bootstrap_auth(
                store_id=rt_a.policy.store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg.subject_id,
                trust_generation=rt_a.policy.trust_generation(),
                expires_at=clock_a.now() + dt.timedelta(hours=1),
            )
            rt_a.policy.register_authorized_workspace(reg, proof)
            rt_a.store.reconcile_policy()

        loop_a.run_owner_action(_mutate_live_policy_only).result(timeout=BOUND_WAIT_S)
        assert loop_a.auth_gate.current() == initial_view_a

        rep_div = loop_a.submit_reply(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_a_id}, token=_daemon_template.cred_a.token),
            dl_a,
        ).result(timeout=BOUND_WAIT_S)
        assert rep_div.envelope["ok"] is True
        assert rep_div.grant_stamp is None
        assert loop_a.auth_gate.current() is None
        assert loop_a.auth_gate.authorize_stamp(rep_ok.grant_stamp) is False
    finally:
        with contextlib.suppress(BrainError):
            loop_a.stop()

    # Subcase B: Direct PolicyStore credential revocation detected on unauthenticated owner call clears stale AuthGate.
    root_b, _, cfg_b = _instantiate_case(trusted_tmp, "b2-revoked-divergent", _daemon_template)
    clock_b = FakeClock(base_now)
    mono_b = _FakeMonotonicClock()
    adapters_b = os_adapters(clock=clock_b, monotonic=mono_b)

    rt_seed_b = reopen_kernel_job_runtime(root_b, _daemon_template.store_id, adapters_b)
    try:
        svc_b, st_b = kernel_job_service(rt_seed_b, clock_b)
        job_b_id = enqueue_job(svc_b, st_b, owner_id="dan", payload=b"b2-job-b").job_id
    finally:
        rt_seed_b.close()

    rt_box_b: list[Runtime] = []
    loop_b = create_daemon_owner_loop(
        os_=adapters_b,
        clock=clock_b,
        monotonic_clock=mono_b,
        hooks=DaemonTestHooks(before_bind=rt_box_b.append),
    )
    try:
        loop_b.start(cfg_b)
        rt_b = rt_box_b[0]
        initial_view_b = loop_b.auth_gate.current()
        assert initial_view_b is not None
        dl_b = mono_b.now + TOTAL_REQUEST_BUDGET_NS

        def _revoke_live_policy_only() -> None:
            proof = make_bootstrap_auth(
                store_id=rt_b.policy.store_id,
                owner_id="dan",
                action="credential_revoke",
                subject_id=_daemon_template.cred_a.credential_id,
                trust_generation=rt_b.policy.trust_generation(),
                expires_at=clock_b.now() + dt.timedelta(hours=1),
            )
            rt_b.policy.record_authorized_revocation(_daemon_template.cred_a.credential_id, proof)
            rt_b.store.reconcile_policy()

        loop_b.run_owner_action(_revoke_live_policy_only).result(timeout=BOUND_WAIT_S)
        assert loop_b.auth_gate.current() == initial_view_b

        rep_unauth = loop_b.submit_reply(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": job_b_id}, token=_daemon_template.cred_a.token),
            dl_b,
        ).result(timeout=BOUND_WAIT_S)
        assert rep_unauth.envelope == {"ok": False, "error": {"code": "unauthenticated", "message": "unauthenticated"}}
        assert rep_unauth.grant_stamp is None
        assert loop_b.auth_gate.current() is None

        health_b = loop_b.submit(
            ToolCommand("get_health", {"schema_version": "2.0"}, token=_daemon_template.cred_b.token),
            dl_b,
        ).result(timeout=1.0)
        assert health_b["ok"] is False
        assert cast(dict[str, JsonValue], health_b["error"])["code"] == "policy_unavailable"
    finally:
        with contextlib.suppress(BrainError):
            loop_b.stop()


def test_shutdown_report_metrics_and_shared_concurrent_stop_cutoff(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """``ShutdownReport`` tracks drained/cancelled/worker metrics and concurrent ``stop()`` calls share one cutoff."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)
    ws_a = _daemon_template.ws_a
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    tok_a = _daemon_template.cred_a.token

    # Subcase A: Drain count when queued work finishes inside stop() grace window.
    _, _, cfg_a = _instantiate_case(trusted_tmp, "b3-drain-metrics", _daemon_template)
    clock_a = FakeClock(base_now)
    adapters_a = os_adapters(clock=clock_a)
    first_at_pre_commit = threading.Event()
    release_pre_commit = threading.Event()
    pause_once = [True]

    def _pause_first_pre_commit(_res: Reservation | None) -> None:
        if pause_once:
            pause_once.pop()
            first_at_pre_commit.set()
            assert release_pre_commit.wait(timeout=BOUND_WAIT_S)

    domain_a = _DaemonTestDomain(ws_a=ws_a)
    loop_a = create_daemon_owner_loop(
        os_=adapters_a,
        clock=clock_a,
        domain=domain_a,
        hooks=DaemonTestHooks(before_enter_commit=_pause_first_pre_commit),
    )
    try:
        loop_a.start(cfg_a)
        fut_a1 = loop_a.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-drain-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_a.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )
        assert first_at_pre_commit.wait(timeout=BOUND_WAIT_S)

        fut_a2 = loop_a.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-drain-0002"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_a.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )

        rep_a_box: list[ShutdownReport] = []
        t_stop_a = threading.Thread(target=lambda: rep_a_box.append(loop_a.stop(grace_s=2.0)), daemon=True)
        t_stop_a.start()
        _wait_until(lambda: loop_a.ready is None, desc="stop_a clears ready")
        release_pre_commit.set()

        assert fut_a1.result(timeout=BOUND_WAIT_S)["ok"] is True
        assert fut_a2.result(timeout=BOUND_WAIT_S)["ok"] is True
        t_stop_a.join(timeout=BOUND_WAIT_S)
        assert len(rep_a_box) == 1
        rep_a = rep_a_box[0]
        assert rep_a.state is ShutdownState.STOPPED
        assert rep_a.drained_requests >= 1
        assert rep_a.cancelled_requests == 0
        assert rep_a.worker_drained is True
    finally:
        release_pre_commit.set()
        with contextlib.suppress(BrainError):
            loop_a.stop()

    # Subcase B1: Concurrent stop(grace_s=0.0) shares first stopper's 0.40s cutoff instead of imposing 0.0s.
    _, _, cfg_b1 = _instantiate_case(trusted_tmp, "b3-shared-cutoff", _daemon_template)
    clock_b1 = FakeClock(base_now)
    adapters_b1 = os_adapters(clock=clock_b1)
    domain_b1 = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-b3-shared-0001"})
    domain_b1.allow_apply_finish.clear()
    loop_b1 = create_daemon_owner_loop(
        os_=adapters_b1,
        clock=clock_b1,
        domain=domain_b1,
    )
    try:
        loop_b1.start(cfg_b1)
        fut_commit_b1 = loop_b1.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-shared-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_b1.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )
        assert domain_b1.apply_entered.wait(timeout=BOUND_WAIT_S)

        fut_queued_b1 = loop_b1.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-shared-0002"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_b1.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )

        rep_1_box: list[ShutdownReport] = []
        rep_2_box: list[ShutdownReport] = []
        stop_2_done = threading.Event()

        def _run_stopper_1() -> None:
            rep_1_box.append(loop_b1.stop(grace_s=0.40))

        def _run_stopper_2() -> None:
            try:
                rep_2_box.append(loop_b1.stop(grace_s=0.0))
            finally:
                stop_2_done.set()

        t_stop_1 = threading.Thread(target=_run_stopper_1, daemon=True)
        t_stop_1.start()
        _wait_until(lambda: loop_b1.ready is None, desc="stopper_1 locks stop cutoff")

        t_stop_2 = threading.Thread(target=_run_stopper_2, daemon=True)
        t_stop_2.start()

        def _stopper_2_entered_stop() -> bool:
            if stop_2_done.is_set() or not t_stop_2.is_alive():
                return True
            ident = t_stop_2.ident
            if ident is None:
                return False
            frame = sys._current_frames().get(ident)
            while frame is not None:
                if frame.f_code.co_name == "stop":
                    return True
                frame = frame.f_back
            return False

        _wait_until(_stopper_2_entered_stop, desc="stopper_2 entered stop()")
        domain_b1.allow_apply_finish.set()

        t_stop_1.join(timeout=BOUND_WAIT_S)
        t_stop_2.join(timeout=BOUND_WAIT_S)
        assert fut_commit_b1.result(timeout=BOUND_WAIT_S)["ok"] is True
        assert fut_queued_b1.result(timeout=BOUND_WAIT_S)["ok"] is True
        assert len(rep_1_box) == 1 and rep_1_box[0].state is ShutdownState.STOPPED
        assert len(rep_2_box) == 1 and rep_2_box[0].state is ShutdownState.STOPPED
    finally:
        domain_b1.allow_apply_finish.set()
        with contextlib.suppress(BrainError):
            loop_b1.stop()

    # Subcase B2: Overrun ShutdownReport accurately reports worker_drained=False and cancelled_requests >= 1.
    root_b2, _, cfg_b2 = _instantiate_case(trusted_tmp, "b3-overrun-metrics", _daemon_template)
    clock_b2 = FakeClock(base_now)
    adapters_b2 = os_adapters(clock=clock_b2)
    rt_seed_b2 = reopen_kernel_job_runtime(root_b2, _daemon_template.store_id, adapters_b2)
    try:
        svc_b2, st_b2 = kernel_job_service(rt_seed_b2, clock_b2)
        enqueue_job(svc_b2, st_b2, owner_id="dan", kind="slow.work", payload=b"b3-slow")
    finally:
        rt_seed_b2.close()

    worker_entered = threading.Event()
    worker_saw_cancel = threading.Event()
    release_worker = threading.Event()

    def _slow_job_handler(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        worker_entered.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            worker_saw_cancel.set()
        release_worker.wait(timeout=BOUND_WAIT_S)
        return ()

    domain_b2 = _DaemonTestDomain(ws_a=ws_a, pause_idem_keys={"idem-b3-over-0001"})
    domain_b2.allow_apply_finish.clear()
    loop_b2 = create_daemon_owner_loop(
        os_=adapters_b2,
        clock=clock_b2,
        domain=domain_b2,
        job_handlers={"slow.work": _slow_job_handler},
    )
    try:
        loop_b2.start(cfg_b2)
        assert worker_entered.wait(timeout=BOUND_WAIT_S)

        fut_commit_b2 = loop_b2.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-over-0001"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_b2.monotonic.monotonic_ns() + 10 * TOTAL_REQUEST_BUDGET_NS,
        )
        assert domain_b2.apply_entered.wait(timeout=BOUND_WAIT_S)

        fut_queued_b2 = loop_b2.submit(
            ToolCommand(
                "submit_episode",
                _episode_args(ws_a, "idem-b3-over-0002"),
                token=tok_a,
                selected_scope=scope_a,
            ),
            adapters_b2.monotonic.monotonic_ns() + 10 * TOTAL_REQUEST_BUDGET_NS,
        )

        rep_over = loop_b2.stop(grace_s=0.05)
        assert worker_saw_cancel.wait(timeout=BOUND_WAIT_S)
        assert fut_queued_b2.result(timeout=BOUND_WAIT_S)["ok"] is False
        assert rep_over.state is ShutdownState.OVERRUN
        assert rep_over.worker_drained is False
        assert rep_over.cancelled_requests >= 1
        domain_b2.allow_apply_finish.set()
        _ = fut_commit_b2.result(timeout=BOUND_WAIT_S)
    finally:
        domain_b2.allow_apply_finish.set()
        release_worker.set()
        closed_rep = loop_b2.wait_closed(timeout=BOUND_WAIT_S)
        assert closed_rep is not None and closed_rep.endpoint_removed is True


def test_shutdown_interrupted_handler_does_not_commit_succeeded_and_requeues_next_epoch(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
) -> None:
    """CL-T5-A1: Shutdown-aborted handler returning ``()`` stays ``RUNNING`` for next-epoch ``recover()``."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)
    root_a1, _, cfg_a1 = _instantiate_case(trusted_tmp, "cl-t5-a1-shutdown", _daemon_template)
    clock_a1 = FakeClock(base_now)
    mono_a1 = _FakeMonotonicClock()
    adapters_a1 = os_adapters(clock=clock_a1, monotonic=mono_a1)

    control_payload = b"a1-control-empty"
    aborted_payload = b"a1-aborted-on-stop"

    rt_seed = reopen_kernel_job_runtime(root_a1, _daemon_template.store_id, adapters_a1)
    try:
        svc_seed, st_seed = kernel_job_service(rt_seed, clock_a1)
        control_job_id = enqueue_job(svc_seed, st_seed, owner_id="dan", payload=control_payload).job_id
        clock_a1.advance(dt.timedelta(milliseconds=1))
        aborted_job_id = enqueue_job(svc_seed, st_seed, owner_id="dan", payload=aborted_payload).job_id
    finally:
        rt_seed.close()

    control_finished = threading.Event()
    aborted_entered = threading.Event()
    observed_cancelled: list[bool] = []

    def _a1_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        if spec.payload == control_payload:
            control_finished.set()
            return ()
        aborted_entered.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            observed_cancelled.append(True)
        return ()

    loop_a1 = create_daemon_owner_loop(
        os_=adapters_a1,
        clock=clock_a1,
        monotonic_clock=mono_a1,
        job_handlers={FIXTURE_JOB_KIND: _a1_handler},
    )
    try:
        ready_a1 = loop_a1.start(cfg_a1)
        epoch_daemon = ready_a1.identity.writer_epoch
        assert aborted_entered.wait(timeout=BOUND_WAIT_S), "aborted_job never entered running"
        assert control_finished.is_set(), "control_job must complete before aborted_job enters on single worker"

        rep_a1 = loop_a1.stop(grace_s=3.0)
        assert rep_a1.state is ShutdownState.STOPPED
        assert rep_a1.worker_drained is True
        assert observed_cancelled == [True]
    finally:
        with contextlib.suppress(BrainError):
            loop_a1.stop()

    clock_a1.advance(dt.timedelta(seconds=2))
    rt_next = reopen_kernel_job_runtime(root_a1, _daemon_template.store_id, adapters_a1)
    try:
        assert rt_next.lease.epoch == epoch_daemon + 1
        svc_next, st_next = kernel_job_service(rt_next, clock_a1)

        ctrl_pre = st_next.transact(lambda tx: tx.read_job(control_job_id))
        abort_pre = st_next.transact(lambda tx: tx.read_job(aborted_job_id))
        assert ctrl_pre is not None and abort_pre is not None
        assert (ctrl_pre.state, ctrl_pre.attempt, ctrl_pre.result_digest) == (JobState.SUCCEEDED, 1, None)
        ctrl_view = svc_next.get_job(control_job_id, _daemon_template.dan, selected_scope=None)
        assert (ctrl_view.state, ctrl_view.attempt, ctrl_view.result_refs) == (JobState.SUCCEEDED, 1, ())
        assert (abort_pre.state, abort_pre.attempt) == (JobState.RUNNING, 1)

        counts = svc_next.recover(rt_next.lease.epoch)
        assert counts == RecoveryCounts(invocations_unknown=0, jobs_requeued=1, jobs_dead_lettered=0)

        ctrl_post = st_next.transact(lambda tx: tx.read_job(control_job_id))
        abort_post = st_next.transact(lambda tx: tx.read_job(aborted_job_id))
        assert ctrl_post is not None and abort_post is not None
        assert (ctrl_post.state, ctrl_post.attempt) == (JobState.SUCCEEDED, 1)
        assert (abort_post.state, abort_post.attempt) == (JobState.QUEUED, 2)

        # Companion S1=A check: WorkerUsage published during close() settles while WorkerCompleted is suppressed.
        lease_a2 = svc_next.lease_next(rt_next.lease.epoch, clock_a1.now())
        assert lease_a2 is not None and (lease_a2.job_id, lease_a2.attempt) == (aborted_job_id, 2)
        svc_next.start(lease_a2)
        inv_a2 = svc_next.reserve_invocation(lease_a2, RESERVE)

        usage_entered = threading.Event()

        def _usage_on_cancel(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
            usage_entered.set()
            assert ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled()
            ctx.report_usage(ctx.invocation_ids[0], UsageRecord("0.25", complete=True))
            return ()

        executor_u = JobExecutor({FIXTURE_JOB_KIND: _usage_on_cancel}, mono_a1.monotonic_ns)
        executor_u.start()
        try:
            executor_u.submit(
                WorkItem(
                    lease=lease_a2,
                    spec=svc_next.job_spec(lease_a2),
                    deadline_ns=mono_a1.now + TOTAL_REQUEST_BUDGET_NS,
                    invocation_ids=(inv_a2,),
                )
            )
            assert usage_entered.wait(timeout=BOUND_WAIT_S)
            assert executor_u.close(BOUND_WAIT_S) is True
            cmd_usage = executor_u.next_command(BOUND_WAIT_S)
            assert cmd_usage == WorkerUsage(inv_a2, UsageRecord("0.25", complete=True))
            assert executor_u.next_command(0.01) is None

            svc_next.apply_command(cmd_usage)
            view_a2 = svc_next.get_job(aborted_job_id, _daemon_template.dan, selected_scope=None)
            assert (view_a2.state, view_a2.attempt, view_a2.accounting_status) == (
                JobState.RUNNING,
                2,
                AccountingStatus.SETTLED,
            )
        finally:
            executor_u.close(BOUND_WAIT_S)
    finally:
        rt_next.close()


def test_quarantined_or_tombstoned_queued_job_fails_fenced_and_next_valid_job_runs(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CL-T5-B1: Policy-blocked leased jobs fail fenced with ``INVALID_PAYLOAD`` without blocking valid jobs."""
    base_now = _daemon_template.base_time + dt.timedelta(minutes=5)
    tok_a = _daemon_template.cred_a.token

    root_1, _, cfg_1 = _instantiate_case(trusted_tmp, "cl-t5-b1", _daemon_template)
    clock_1 = FakeClock(base_now)
    mono_1 = _FakeMonotonicClock()
    adapters_1 = os_adapters(clock=clock_1, monotonic=mono_1)

    quarantined_payload = b"b1-quarantined-payload"
    quarantined_digest = digest_bytes(quarantined_payload)
    valid_payload_1 = b"b1-valid-control"
    tombstoned_payload = b"b1-tombstoned-payload"
    tombstoned_digest = digest_bytes(tombstoned_payload)
    valid_payload_2 = b"b1-valid-after-tombstone"
    corrupt_payload = b"b1-missing-cas-blob"
    corrupt_hex = digest_bytes(corrupt_payload).removeprefix("sha256:")

    # Seed Subcase 1 while store is offline: quarantined payload digest while queued + valid control job.
    rt_seed_1 = reopen_kernel_job_runtime(root_1, _daemon_template.store_id, adapters_1)
    try:
        svc_1, st_1 = kernel_job_service(rt_seed_1, clock_1)
        quarantined_job_id = enqueue_job(svc_1, st_1, owner_id="dan", payload=quarantined_payload).job_id
        clock_1.advance(dt.timedelta(milliseconds=1))
        valid_job_1_id = enqueue_job(svc_1, st_1, owner_id="dan", payload=valid_payload_1).job_id
        rt_seed_1.policy.record_intent(IntentKind.QUARANTINE, {"digest": quarantined_digest})
        assert rt_seed_1.policy.is_quarantined(quarantined_digest) is True
    finally:
        rt_seed_1.close()

    entered_ids: list[str] = []
    valid_1_entered = threading.Event()
    valid_2_entered = threading.Event()

    def _b1_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        entered_ids.append(ctx.lease.job_id)
        if spec.payload == valid_payload_1:
            valid_1_entered.set()
        elif spec.payload == valid_payload_2:
            valid_2_entered.set()
        return (ObjectRef(kind="fixture_result", id=ctx.lease.job_id, revision=1, digest=digest_bytes(spec.payload)),)

    rt_box: list[Runtime] = []
    loop_1 = create_daemon_owner_loop(
        os_=adapters_1,
        clock=clock_1,
        monotonic_clock=mono_1,
        job_handlers={FIXTURE_JOB_KIND: _b1_handler},
        hooks=DaemonTestHooks(before_bind=rt_box.append),
    )
    tombstoned_ids: list[str] = []
    valid_2_ids: list[str] = []
    corrupt_ids: list[str] = []
    pol_job_ids: list[str] = []
    try:
        loop_1.start(cfg_1)
        rt_live = rt_box[0]
        dl_1 = mono_1.now + TOTAL_REQUEST_BUDGET_NS

        # Subcase 1: Quarantined payload digest while queued -> FAILED(INVALID_PAYLOAD), valid_job_1 succeeds.
        assert valid_1_entered.wait(timeout=BOUND_WAIT_S)

        def _job_succeeded(jid: str) -> Callable[[], bool]:
            def _pred() -> bool:
                res = loop_1.submit(
                    ToolCommand("get_job", {"schema_version": "2.0", "job_id": jid}, token=tok_a),
                    dl_1,
                ).result(timeout=BOUND_WAIT_S)
                return res.get("ok") is True and cast(dict[str, JsonValue], res["data"]).get("state") == "succeeded"

            return _pred

        _wait_until(_job_succeeded(valid_job_1_id), desc="valid_job_1 succeeded")
        assert entered_ids == [valid_job_1_id]

        res_q = loop_1.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": quarantined_job_id}, token=tok_a),
            dl_1,
        ).result(timeout=BOUND_WAIT_S)
        assert res_q == {
            "ok": True,
            "data": {
                "job_id": quarantined_job_id,
                "state": "failed",
                "attempt": 1,
                "result_refs": [],
                "accounting_status": "none",
            },
        }

        # Subcase 2: Live TOMBSTONE("event", job_id) before reconcile while OwnerLoop is already running.
        def _enqueue_and_tombstone_live() -> None:
            svc_live, st_live = kernel_job_service(rt_live, clock_1)
            clock_1.advance(dt.timedelta(milliseconds=1))
            t_id = enqueue_job(svc_live, st_live, owner_id="dan", payload=tombstoned_payload).job_id
            clock_1.advance(dt.timedelta(milliseconds=1))
            v_id = enqueue_job(svc_live, st_live, owner_id="dan", payload=valid_payload_2).job_id
            rt_live.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": t_id})
            assert rt_live.policy.is_tombstoned("event", t_id) is True
            tombstoned_ids.append(t_id)
            valid_2_ids.append(v_id)

        loop_1.run_owner_action(_enqueue_and_tombstone_live).result(timeout=BOUND_WAIT_S)
        tombstoned_job_id = tombstoned_ids[0]
        valid_job_2_id = valid_2_ids[0]

        assert valid_2_entered.wait(timeout=BOUND_WAIT_S)
        _wait_until(_job_succeeded(valid_job_2_id), desc="valid_job_2 succeeded")
        assert entered_ids == [valid_job_1_id, valid_job_2_id]

        res_t = loop_1.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": tombstoned_job_id}, token=tok_a),
            dl_1,
        ).result(timeout=BOUND_WAIT_S)
        assert res_t == {
            "ok": True,
            "data": {
                "job_id": tombstoned_job_id,
                "state": "failed",
                "attempt": 1,
                "result_refs": [],
                "accounting_status": "none",
            },
        }

        def _verify_live_holds_unreleased() -> None:
            with rt_live.store.transaction() as txn:
                assert held_digests(txn.db, "event", quarantined_job_id) == [quarantined_digest]
                assert held_digests(txn.db, "event", tombstoned_job_id) == [tombstoned_digest]

        loop_1.run_owner_action(_verify_live_holds_unreleased).result(timeout=BOUND_WAIT_S)

        # Subcase 3a: Missing CAS blob without policy restriction raises INTEGRITY_FAILURE, NOT INVALID_PAYLOAD.
        def _enqueue_and_unlink_cas() -> None:
            svc_live, st_live = kernel_job_service(rt_live, clock_1)
            clock_1.advance(dt.timedelta(milliseconds=1))
            c_id = enqueue_job(svc_live, st_live, owner_id="dan", payload=corrupt_payload).job_id
            cas_blob_file = root_1 / "store" / "cas" / corrupt_hex[:2] / corrupt_hex
            assert cas_blob_file.is_file()
            cas_blob_file.unlink()
            corrupt_ids.append(c_id)

        loop_1.run_owner_action(_enqueue_and_unlink_cas).result(timeout=BOUND_WAIT_S)
        loop_1.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        corrupt_job_id = corrupt_ids[0]
        res_3a = loop_1.submit(
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": corrupt_job_id}, token=tok_a),
            dl_1,
        ).result(timeout=BOUND_WAIT_S)
        assert res_3a["ok"] is True
        assert cast(dict[str, JsonValue], res_3a["data"])["state"] == "leased"
        assert entered_ids == [valid_job_1_id, valid_job_2_id]

        # Subcase 3b: POLICY_UNAVAILABLE during owner claim invalidates AuthGate and does NOT mark INVALID_PAYLOAD.
        assert loop_1.auth_gate.current() is not None

        def _raise_pol_unavailable(*_args: object, **_kwargs: object) -> bool:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

        def _enqueue_and_break_policy() -> None:
            svc_live, st_live = kernel_job_service(rt_live, clock_1)
            clock_1.advance(dt.timedelta(milliseconds=1))
            p_id = enqueue_job(svc_live, st_live, owner_id="dan", payload=b"b1-policy-down").job_id
            pol_job_ids.append(p_id)
            monkeypatch.setattr(rt_live.policy, "is_tombstoned", _raise_pol_unavailable)
            monkeypatch.setattr(rt_live.policy, "is_quarantined", _raise_pol_unavailable)

        loop_1.run_owner_action(_enqueue_and_break_policy).result(timeout=BOUND_WAIT_S)
        _wait_until(lambda: loop_1.auth_gate.current() is None, desc="AuthGate invalidated on POLICY_UNAVAILABLE")
        assert entered_ids == [valid_job_1_id, valid_job_2_id]

        rep_1 = loop_1.stop(grace_s=3.0)
        assert rep_1.state is ShutdownState.STOPPED
    finally:
        with contextlib.suppress(BrainError):
            loop_1.stop()
        monkeypatch.undo()

    rt_v1 = reopen_kernel_job_runtime(root_1, _daemon_template.store_id, adapters_1)
    try:
        svc_v1, st_v1 = kernel_job_service(rt_v1, clock_1)

        def _read_v1(jid: str) -> JobRecord:
            row = st_v1.transact(lambda tx: tx.read_job(jid))
            assert row is not None
            return row

        for blocked_id in (quarantined_job_id, tombstoned_ids[0]):
            b_row = _read_v1(blocked_id)
            assert (b_row.state, b_row.attempt, b_row.reason, b_row.result_digest) == (
                JobState.FAILED,
                1,
                JobErrorCode.INVALID_PAYLOAD,
                None,
            )
            terminals = [
                e for e in rt_v1.store.entries() if e.kind == "job.terminal" and e.meta.get("job_id") == blocked_id
            ]
            assert len(terminals) == 1
            assert (
                terminals[0].meta["prior_state"],
                terminals[0].meta["state"],
                terminals[0].meta["reason"],
                terminals[0].actor,
            ) == ("leased", "failed", "invalid_payload", "system:kernel")

        # Spec §5.6: QUARANTINE preserves CAS hold across reopen; TOMBSTONE is reconciled on Store.open() by policy.
        with rt_v1.store.transaction() as txn:
            assert held_digests(txn.db, "event", quarantined_job_id) == [quarantined_digest]
            assert held_digests(txn.db, "event", tombstoned_ids[0]) == []
        assert [
            e
            for e in rt_v1.store.entries()
            if e.kind == "cas.release" and e.meta.get("holder_id") == quarantined_job_id
        ] == []
        assert [
            (e.actor, e.meta.get("reason"))
            for e in rt_v1.store.entries()
            if e.kind == "cas.release" and e.meta.get("holder_id") == tombstoned_ids[0]
        ] == [("system:cas", "tombstoned")]
        assert [
            e.actor
            for e in rt_v1.store.entries()
            if e.kind == "policy.tombstone" and e.meta.get("holder_id") == tombstoned_ids[0]
        ] == ["system:policy"]

        for negative_id in (corrupt_ids[0], pol_job_ids[0]):
            n_row = _read_v1(negative_id)
            assert (n_row.state, n_row.attempt, n_row.reason) == (JobState.LEASED, 1, None)
            assert [
                e for e in rt_v1.store.entries() if e.kind == "job.terminal" and e.meta.get("job_id") == negative_id
            ] == []

        # Only the 2 negative-control leased jobs are requeued; policy-blocked FAILED jobs are never requeued.
        assert svc_v1.recover(rt_v1.lease.epoch) == RecoveryCounts(
            invocations_unknown=0, jobs_requeued=2, jobs_dead_lettered=0
        )
        for blocked_id in (quarantined_job_id, tombstoned_ids[0]):
            b_after = _read_v1(blocked_id)
            assert (b_after.state, b_after.attempt) == (JobState.FAILED, 1)
    finally:
        rt_v1.close()



