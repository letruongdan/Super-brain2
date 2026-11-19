"""Test support fixtures and harness for SP1 Increment 2 Task 6b (Loopback TLS Transport).

Provides clean, fast, deterministic fixtures for real admitted (store=4, policy=3) roots,
active credentials, session-scoped TLS material, and teardown-safe LoopbackServer lifecycles.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import os
import shutil
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid
import warnings
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api._loopback_server import (
    LoopbackServer,
)
from superbrain.cli_api.loopback import (
    LoopbackClient,
    LoopbackTarget,
)
from superbrain.composition.daemon_entry import (
    BoundLoopbackListener,
    DaemonTestHooks,
    create_daemon_owner_loop,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
    DaemonConfig,
    ObjectRef,
    OwnerReply,
    Principal,
    Ready,
    ResourceDigest,
    Scope,
    StoredResult,
    TlsMaterial,
    ToolCommand,
    WorkspaceBinding,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobHandler
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
)
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)


def make_trusted_test_dir(label: str) -> Path:
    """Create a secure directory trusted by Windows DACL permission guards."""
    if sys.platform == "win32":
        base = Path(os.environ["LOCALAPPDATA"]) / "superbrain-tests" / f"{label}-{uuid.uuid4()}"
        base.mkdir(parents=True)
        os_adapters().permissions.secure_directory(base)
        return base
    base = Path(os.environ.get("TMPDIR", "/tmp")) / f"{label}-{uuid.uuid4()}"
    base.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(base)
    return base


def clone_owner_only_tree(src: Path, dst: Path) -> None:
    """Clone ``src`` into ``dst`` with owner-only permissions."""
    dst.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        dst.chmod(0o700)
    for cur_dir, dirnames, filenames in os.walk(src):
        rel = Path(cur_dir).relative_to(src)
        target_base = dst / rel if rel != Path(".") else dst
        for dname in dirnames:
            sub = target_base / dname
            sub.mkdir(exist_ok=True)
            if sys.platform != "win32":
                sub.chmod(0o700)
        for fname in filenames:
            sfile = Path(cur_dir) / fname
            tfile = target_base / fname
            shutil.copyfile(sfile, tfile)
            if sys.platform != "win32":
                tfile.chmod(0o600)


def write_daemon_config_file(
    config_path: Path,
    *,
    data_root: Path,
    expected_store_id: str,
    cert_path: Path,
    key_path: Path,
    os_: OsAdapters | None = None,
) -> DaemonConfig:
    """Write and secure a canonical DaemonConfig JSON file."""
    adapters = os_ if os_ is not None else os_adapters()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        config_path.parent.chmod(0o700)
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


def register_workspace_direct(
    rt: Runtime,
    clock: FakeClock,
    principal: Principal,
    *,
    alias: str,
    checkout_dir: Path,
    remote: str = "https://github.example/dan/repo-transport-a.git",
) -> WorkspaceBinding:
    """Directly register an authorized workspace and grant repo permissions."""
    checkout_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        checkout_dir.chmod(0o700)
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
    seed_repo_grant(
        rt.policy,
        principal_id=principal.principal_id,
        repo_id=binding.repo_id,
        owner_id=principal.owner_id,
    )
    rt.store.reconcile_policy()
    return binding


def read_raw_http_response(sock: ssl.SSLSocket | socket.socket, timeout: float = 2.0) -> bytes:
    """Read a complete HTTP/1.1 response from sock until Content-Length is satisfied or EOF."""
    sock.settimeout(timeout)
    resp = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp.extend(chunk)
            if b"\r\n\r\n" in resp:
                header_end = resp.index(b"\r\n\r\n")
                headers = resp[:header_end].decode("iso-8859-1")
                cl = 0
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        cl = int(line.split(":", 1)[1].strip())
                if len(resp) >= header_end + 4 + cl:
                    break
        except (TimeoutError, OSError):
            break
    return bytes(resp)


@dataclasses.dataclass
class TransportTestDomain(KernelToolDomain):
    """Test-only KernelToolDomain with real SQLite blob storage and artifact send descriptors."""

    ws_a: WorkspaceBinding | None = None
    pause_idem_keys: set[str] = dataclasses.field(default_factory=set)
    apply_entered: threading.Event = dataclasses.field(default_factory=threading.Event)
    allow_apply_finish: threading.Event = dataclasses.field(default_factory=threading.Event)
    on_apply_hook: Callable[[str, str], None] | None = None
    executed_keys: list[str] = dataclasses.field(default_factory=list)
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.allow_apply_finish.set()

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if deep:
            return False
        return tool in {"get_health", "get_artifact", "prepare_task", "submit_episode", "get_job"}

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: dt.datetime) -> PreparedEffect:
        del ctx, now
        idem_key = str(call.arguments.get("idempotency_key", ""))
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
                "schema": "transport-test-domain-v1",
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
                if not self.allow_apply_finish.wait(timeout=15.0):
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
            return {
                "task_id": "task-prep-1",
                "delivery_id": result.result_id,
                "assignment_id": result.assignment_id,
                "skills": [],
            }
        return {
            "episode_id": result.result_id,
            "evidence_ids": [],
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


class FakeMonotonicClock:
    """Thread-safe controllable nanosecond monotonic clock."""

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

    def advance_ns(self, delta_ns: int) -> int:
        return self.advance(delta_ns)

    def advance_ms(self, delta_ms: int) -> int:
        return self.advance(delta_ms * 1_000_000)

    def monotonic_ns(self) -> int:
        with self._lock:
            return self._now_ns


@dataclasses.dataclass(frozen=True)
class TransportTemplate:
    """Pre-migrated store root + provisioned TLS material for fast test cloning."""

    base_dir: Path
    root: Path
    store_id: str
    cred: SeededCredential
    tls: TlsMaterial
    base_time: dt.datetime
    dan: Principal | None = None
    cred_b: SeededCredential | None = None
    bob: Principal | None = None
    cred_bob: SeededCredential | None = None
    ws_a: WorkspaceBinding | None = None
    ws_b: WorkspaceBinding | None = None
    global_job_id: str | None = None
    scoped_job_id: str | None = None
    config_path: Path | None = None


def create_transport_template(base_label: str = "t6b3-template") -> TransportTemplate:
    """Initialize a template admitted root with v2 migrations, seeded credentials, workspaces & jobs."""
    base_dir = make_trusted_test_dir(base_label)
    base_time = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=10)
    clock = FakeClock(base_time)
    adapters = os_adapters(clock=clock)
    root = base_dir / "template-data"

    rt = open_kernel_job_runtime(root, adapters, role="transport-tpl", use_template=False)
    store_id = rt.store.store_id
    try:
        cred = seed_principal_and_credential(
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
        cred_bob = seed_principal_and_credential(
            rt.policy,
            owner_id="bob",
            harness_id="claude-code",
            machine_id="m-2",
        )
        ws_a = register_workspace_direct(
            rt,
            clock,
            cred.principal,
            alias="ws-a",
            checkout_dir=base_dir / "chk-a",
            remote="https://github.example/dan/repo-transport-a.git",
        )
        ws_b = register_workspace_direct(
            rt,
            clock,
            cred.principal,
            alias="ws-b",
            checkout_dir=base_dir / "chk-b",
            remote="https://github.example/dan/repo-transport-b.git",
        )
        # Seed global job and scoped job
        service, staged_store = kernel_job_service(rt, clock)
        global_job = enqueue_job(service, staged_store, owner_id="dan", payload=b"global job payload")
        scoped_job = enqueue_job(
            service,
            staged_store,
            owner_id="dan",
            payload=b"scoped job payload",
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
        )
    finally:
        rt.close()

    tls_auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=2),
        destination=base_dir / "tls",
    )
    tls = create_store_tls(store_id, base_dir / "tls", tls_auth, clock, adapters)
    config_path = base_dir / "daemon-config.json"
    write_daemon_config_file(
        config_path,
        data_root=root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
        os_=adapters,
    )
    return TransportTemplate(
        base_dir=base_dir,
        root=root,
        store_id=store_id,
        cred=cred,
        tls=tls,
        base_time=base_time,
        dan=cred.principal,
        cred_b=cred_b,
        bob=cred_bob.principal,
        cred_bob=cred_bob,
        ws_a=ws_a,
        ws_b=ws_b,
        global_job_id=global_job.job_id,
        scoped_job_id=scoped_job.job_id,
        config_path=config_path,
    )


class TransportHarness:
    """Running LoopbackServer + OwnerLoop harness with inspection helpers."""

    def __init__(
        self,
        base_dir: Path,
        data_root: Path,
        store_id: str,
        cred: SeededCredential,
        tls: TlsMaterial,
        config: DaemonConfig,
        loop: OwnerLoop,
        ready: Ready,
        server: LoopbackServer,
        bound: BoundLoopbackListener,
        stop_event: threading.Event,
        mono_clock: FakeMonotonicClock,
        clock: FakeClock,
        domain: KernelToolDomain | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.data_root = data_root
        self.store_id = store_id
        self.cred = cred
        self.tls = tls
        self.config = config
        self.loop = loop
        self.ready = ready
        self.server = server
        self.bound = bound
        self.stop_event = stop_event
        self.mono_clock = mono_clock
        self.clock = clock
        self.domain = domain

        self._submit_lock = threading.Lock()
        self.submitted_commands: list[ToolCommand] = []

    @property
    def submit_count(self) -> int:
        with self._submit_lock:
            return len(self.submitted_commands)

    def record_submit(self, cmd: ToolCommand) -> None:
        with self._submit_lock:
            self.submitted_commands.append(cmd)

    def ledger_sequence(self) -> int:
        """Inspect the current highest ledger sequence number in SQLite."""
        db_path = self.data_root / "store" / "brain.db"
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            row = conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM ledger").fetchone()
            return int(row[0]) if row is not None else 0

    def idempotency_count(self) -> int:
        """Inspect the current idempotency record count in SQLite."""
        db_path = self.data_root / "store" / "brain.db"
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            row = conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()
            return int(row[0]) if row is not None else 0

    def count_send_attempts(self, state: str | None = None) -> int:
        """Count rows in SQLite artifact_send_attempt table, optionally filtered by state."""
        db_path = self.data_root / "store" / "brain.db"
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            if state is not None:
                row = conn.execute("SELECT COUNT(*) FROM artifact_send_attempt WHERE state = ?", (state,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM artifact_send_attempt").fetchone()
            return int(row[0]) if row is not None else 0

    def count_read_acks(self) -> int:
        """Count rows in SQLite artifact_read_ack table."""
        db_path = self.data_root / "store" / "brain.db"
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            row = conn.execute("SELECT COUNT(*) FROM artifact_read_ack").fetchone()
            return int(row[0]) if row is not None else 0

    def get_send_attempt_state(self, attempt_id: str) -> str | None:
        """Query state of a specific artifact_send_attempt row."""
        db_path = self.data_root / "store" / "brain.db"
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            row = conn.execute("SELECT state FROM artifact_send_attempt WHERE id = ?", (attempt_id,)).fetchone()
            return str(row[0]) if row is not None else None

    def make_target(self) -> LoopbackTarget:
        """Build a LoopbackTarget configured for this server."""
        return LoopbackTarget(
            endpoint=self.ready.endpoint,
            expected_store_id=self.store_id,
            ca_pem=self.tls.ca_cert_path.read_text(encoding="utf-8"),
            leaf_cert_sha256=self.ready.leaf_cert_sha256,
        )

    def open_client(self, monotonic_ns: Callable[[], int] | None = None) -> LoopbackClient:
        """Create a LoopbackClient wired with this harness monotonic clock."""
        mono = monotonic_ns if monotonic_ns is not None else self.mono_clock.monotonic_ns
        return LoopbackClient(monotonic_ns=mono)

    def open_raw_tls_socket(self, timeout: float = 2.0) -> ssl.SSLSocket:
        """Open a raw TLS client connection to this listener."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=self.tls.ca_cert_path.read_text(encoding="utf-8"))
        ctx.check_hostname = True
        raw_sock = socket.create_connection(
            (self.ready.endpoint.host, self.ready.endpoint.port),
            timeout=timeout,
        )
        return ctx.wrap_socket(raw_sock, server_hostname="127.0.0.1")

    def send_raw_http(
        self,
        tls_sock: ssl.SSLSocket,
        request_bytes: bytes,
        read_timeout: float = 2.0,
    ) -> bytes:
        """Write request bytes to a TLS socket and read response until end-of-frame or close."""
        tls_sock.settimeout(read_timeout)
        tls_sock.sendall(request_bytes)
        return read_raw_http_response(tls_sock, timeout=read_timeout)


@contextlib.contextmanager
def open_test_loopback_transport(
    template: TransportTemplate,
    name: str = "case",
    domain: KernelToolDomain | None = None,
    hooks: DaemonTestHooks | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
) -> Iterator[TransportHarness]:
    """Teardown-safe context manager running OwnerLoop + LoopbackServer on real sockets."""
    case_dir = make_trusted_test_dir(f"t6b3-{name}")
    data_root = case_dir / "data"
    clone_owner_only_tree(template.root, data_root)

    cfg = DaemonConfig(
        version=1,
        data_root=data_root,
        expected_store_id=template.store_id,
        cert_path=template.tls.cert_path,
        key_path=template.tls.key_path,
    )

    clock = FakeClock(template.base_time)
    adapters = os_adapters(clock=clock)
    mono_clock = FakeMonotonicClock(1_000_000_000)

    bound_listeners: list[BoundLoopbackListener] = []
    effective_hooks = hooks if hooks is not None else DaemonTestHooks()
    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono_clock,
        domain=domain,
        job_handlers=job_handlers,
        hooks=effective_hooks,
        on_listener_bound=bound_listeners.append,
    )

    loop_started = False
    server_started = False
    stop_event = threading.Event()
    server: LoopbackServer | None = None
    harness: TransportHarness | None = None

    try:
        ready = loop.start(cfg)
        loop_started = True
        assert len(bound_listeners) == 1
        bound = bound_listeners[0]

        # Construct LoopbackServer on the bound loopback listener
        server = LoopbackServer(
            listener=bound.sock,
            ssl_context=bound.ssl_context,
            ready=ready,
            owner=loop,
            monotonic_ns=mono_clock.monotonic_ns,
            stop_event=stop_event,
        )

        harness = TransportHarness(
            base_dir=case_dir,
            data_root=data_root,
            store_id=template.store_id,
            cred=template.cred,
            tls=template.tls,
            config=cfg,
            loop=loop,
            ready=ready,
            server=server,
            bound=bound,
            stop_event=stop_event,
            mono_clock=mono_clock,
            clock=clock,
            domain=domain,
        )

        # Spy on loop.submit_reply to track admission to OwnerLoop
        orig_submit_reply = loop.submit_reply

        def spied_submit_reply(command: ToolCommand, dl_ns: int) -> Future[OwnerReply]:
            assert harness is not None
            harness.record_submit(command)
            return orig_submit_reply(command, dl_ns)

        loop.submit_reply = spied_submit_reply  # type: ignore[method-assign,assignment]

        # Start LoopbackServer
        server.start()
        server_started = True

        yield harness
    finally:
        # CRITICAL TEARDOWN SAFETY:
        # If server.start() fails (e.g. BrainError(CAPABILITY_UNAVAILABLE) on Pin B RED!),
        # or when the test completes, always cleanly quiesce and stop loop + server so
        # SQLite handles, writer.lock, and bound listener sockets never leak!
        if server is not None and server_started:
            stop_deadline = time.perf_counter() + 2.0
            server.quiesce(stop_deadline)
        if loop_started:
            loop.stop(grace_s=2.0)
        if server is not None and server_started:
            stop_deadline = time.perf_counter() + 2.0
            server.finish(stop_deadline)
        try:
            shutil.rmtree(case_dir, ignore_errors=True)
        except OSError as err:
            warnings.warn(f"could not remove transport test dir {case_dir}: {err}", stacklevel=1)
