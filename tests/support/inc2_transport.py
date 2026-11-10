"""Test support fixtures and harness for SP1 Increment 2 Task 6b.3 (Loopback TLS Transport).

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
from collections.abc import Iterator
from concurrent.futures import Future
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api._loopback_server import (
    LoopbackServer,
)
from superbrain.cli_api.loopback import (
    LoopbackTarget,
)
from superbrain.composition.daemon_entry import (
    BoundLoopbackListener,
    create_daemon_owner_loop,
)
from superbrain.core.kernel import (
    DaemonConfig,
    OwnerReply,
    Ready,
    TlsMaterial,
    ToolCommand,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
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
            tfile.write_bytes(sfile.read_bytes())
            if sys.platform != "win32":
                tfile.chmod(0o600)


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


def create_transport_template(base_label: str = "t6b3-template") -> TransportTemplate:
    """Initialize a template admitted root with v2 migrations and seeded credential."""
    base_dir = make_trusted_test_dir(base_label)
    base_time = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=10)
    clock = FakeClock(base_time)
    adapters = os_adapters(clock=clock)
    root = base_dir / "template-data"

    rt = open_kernel_job_runtime(root, adapters)
    store_id = rt.store.store_id
    try:
        cred = seed_principal_and_credential(
            rt.policy,
            owner_id="dan",
            harness_id="claude-code",
            machine_id="m-1",
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
    return TransportTemplate(
        base_dir=base_dir,
        root=root,
        store_id=store_id,
        cred=cred,
        tls=tls,
        base_time=base_time,
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
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            row = conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM ledger").fetchone()
            return int(row[0]) if row is not None else 0

    def idempotency_count(self) -> int:
        """Inspect the current idempotency record count in SQLite."""
        db_path = self.data_root / "store" / "brain.db"
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            row = conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()
            return int(row[0]) if row is not None else 0

    def make_target(self) -> LoopbackTarget:
        """Build a LoopbackTarget configured for this server."""
        return LoopbackTarget(
            endpoint=self.ready.endpoint,
            expected_store_id=self.store_id,
            ca_pem=self.tls.ca_cert_path.read_text(encoding="utf-8"),
            leaf_cert_sha256=self.ready.leaf_cert_sha256,
        )

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
        response = bytearray()
        while True:
            try:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\r\n\r\n" in response:
                    header_end = response.find(b"\r\n\r\n")
                    headers = response[:header_end].decode("iso-8859-1")
                    content_length = 0
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":", 1)[1].strip())
                    if len(response) >= header_end + 4 + content_length:
                        break
            except (TimeoutError, OSError):
                break
        return bytes(response)


@contextlib.contextmanager
def open_test_loopback_transport(
    template: TransportTemplate,
    name: str = "case",
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
    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono_clock,
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
