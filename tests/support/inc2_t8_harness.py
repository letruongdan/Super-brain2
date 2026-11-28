"""In-process daemon with the durable fixture domain on an existing data root (SP1 increment 2, Task 8.2).

``fixture_daemon`` runs the real ``create_daemon_owner_loop`` + ``LoopbackServer`` (as ``open_test_loopback_transport``
does) but on a data root the caller owns, so a test can stop it and open the same root again (restart recovery).
The store opens with the fixture projections (``use_fixture_store_extensions`` through ``monkeypatch``) and the domain
is a ``FixtureDomainProxy`` bound in ``before_job_recover``. Clocks are the harness fakes: ``FakeClock`` for wall time
and ``FakeMonotonicClock`` shared by the daemon and the domain. The installed-shim timing test supplies a real
monotonic clock so the response budget can be measured from receipt to flush and receipt by the parent.

``SendAttemptTracker`` attaches deterministic ``threading.Event`` barriers to ``OwnerLoop.finalize_send_attempt`` and
``OwnerLoop.interrupt_send_attempt`` completions so receipt tests never poll with ``time.sleep``.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import Future
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.composition import daemon_entry
from superbrain.composition.daemon_entry import BoundLoopbackListener, DaemonTestHooks, create_daemon_owner_loop
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendAttempt,
    DaemonConfig,
    OwnerReply,
    SendAttemptCompletion,
    ToolCommand,
    WorkspaceBinding,
)
from superbrain.ports.clock import MonotonicClock
from superbrain.ports.kernel import SnapshotObserver
from superbrain.workers.executor import JobHandler
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_client_profile_file, write_credential_file
from tests.support.inc2_kernel_domain import fixture_store_extensions
from tests.support.inc2_t8_domain import FixtureDomainProxy, fixture_hooks
from tests.support.inc2_transport import FakeMonotonicClock, TransportHarness, TransportTemplate, clone_owner_only_tree


class SendAttemptTracker:
    """Deterministic ``threading.Event`` barrier per ``send_attempt_id`` settled on ``OwnerLoop``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}

    def _event_for(self, attempt_id: str) -> threading.Event:
        with self._lock:
            ev = self._events.get(attempt_id)
            if ev is None:
                ev = threading.Event()
                self._events[attempt_id] = ev
            return ev

    def mark_settled(self, attempt_id: str) -> None:
        self._event_for(attempt_id).set()

    def wait_settled(self, attempt_id: str, *, timeout: float = 5.0) -> None:
        assert self._event_for(attempt_id).wait(timeout=timeout), f"send attempt {attempt_id} did not settle"


def clone_template_root(template: TransportTemplate, data_root: Path) -> Path:
    clone_owner_only_tree(template.root, data_root)
    return data_root


@contextlib.contextmanager
def fixture_daemon(
    monkeypatch: pytest.MonkeyPatch,
    template: TransportTemplate,
    data_root: Path,
    *,
    observer: SnapshotObserver | None = None,
    hooks: DaemonTestHooks | None = None,
    clock: FakeClock | None = None,
    daemon_clock: MonotonicClock | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
) -> Iterator[tuple[TransportHarness, FixtureDomainProxy, SendAttemptTracker]]:
    monkeypatch.setattr(daemon_entry, "kernel_store_extensions", fixture_store_extensions)
    cfg = DaemonConfig(
        version=1,
        data_root=data_root,
        expected_store_id=template.store_id,
        cert_path=template.tls.cert_path,
        key_path=template.tls.key_path,
    )
    wall = clock if clock is not None else FakeClock(template.base_time)
    mono = FakeMonotonicClock(1_000_000_000)
    active_clock = mono if daemon_clock is None else daemon_clock
    proxy = FixtureDomainProxy()
    tracker = SendAttemptTracker()
    bound: list[BoundLoopbackListener] = []
    loop = create_daemon_owner_loop(
        os_=os_adapters(clock=wall),
        clock=wall,
        monotonic_clock=active_clock,
        domain=proxy,
        hooks=fixture_hooks(proxy, monotonic_ns=active_clock.monotonic_ns, observer=observer, base=hooks),
        on_listener_bound=bound.append,
        job_handlers=job_handlers,
    )
    stop_event = threading.Event()
    server: LoopbackServer | None = None
    started = False
    ready = loop.start(cfg)
    try:
        assert len(bound) == 1
        server = LoopbackServer(
            listener=bound[0].sock,
            ssl_context=bound[0].ssl_context,
            ready=ready,
            owner=loop,
            monotonic_ns=active_clock.monotonic_ns,
            stop_event=stop_event,
        )
        harness = TransportHarness(
            base_dir=data_root.parent,
            data_root=data_root,
            store_id=template.store_id,
            cred=template.cred,
            tls=template.tls,
            config=cfg,
            loop=loop,
            ready=ready,
            server=server,
            bound=bound[0],
            stop_event=stop_event,
            mono_clock=mono,
            clock=wall,
            domain=proxy,
        )
        orig_submit = loop.submit_reply
        orig_finalize = loop.finalize_send_attempt
        orig_interrupt = loop.interrupt_send_attempt

        def spied(command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
            harness.record_submit(command)
            return orig_submit(command, deadline_ns)

        def tracked_finalize(completion: SendAttemptCompletion) -> Future[ArtifactSendAttempt]:
            fut = orig_finalize(completion)
            fut.add_done_callback(lambda _f: tracker.mark_settled(completion.send_attempt_id))
            return fut

        def tracked_interrupt(send_attempt_id: str) -> Future[ArtifactSendAttempt]:
            fut = orig_interrupt(send_attempt_id)
            fut.add_done_callback(lambda _f: tracker.mark_settled(send_attempt_id))
            return fut

        loop.submit_reply = spied  # type: ignore[method-assign]
        loop.finalize_send_attempt = tracked_finalize  # type: ignore[method-assign]
        loop.interrupt_send_attempt = tracked_interrupt  # type: ignore[method-assign]
        server.start()
        started = True
        loop.wait_doctor_settled(timeout=5.0)
        yield harness, proxy, tracker
    finally:
        if server is not None and started:
            server.quiesce(time.perf_counter() + 2.0)
        loop.stop(grace_s=2.0)
        if server is not None and started:
            server.finish(time.perf_counter() + 2.0)


def store_rows(data_root: Path, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Read-only query of the committed main store (the daemon may be running)."""
    db_path = data_root / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]


def count(data_root: Path, table: str, where: str = "", params: tuple[Any, ...] = ()) -> int:
    (row,) = store_rows(data_root, f"SELECT COUNT(*) FROM {table} {where}", params)
    return int(row[0])


def shim_profile(
    h: TransportHarness,
    binding: WorkspaceBinding,
    name: str,
    token: str,
    *,
    workspace: Mapping[str, JsonValue] | None = None,
) -> Path:
    client = h.base_dir / f"client-{name}"
    cred = write_credential_file(client / "credential.txt", token)
    ws = (
        workspace
        if workspace is not None
        else {
            "alias": binding.alias,
            "checkout_path": str(binding.checkout_path),
            "expected_workspace_id": binding.repo_id,
            "expected_checkout_id": binding.checkout_id,
        }
    )
    profile, _ = write_client_profile_file(
        client / "profile.json",
        endpoint_path=h.data_root / "endpoint.json",
        expected_store_id=h.store_id,
        ca_file=h.tls.ca_cert_path,
        leaf_cert_sha256=h.ready.leaf_cert_sha256,
        credential_file=cred,
        workspace=ws,
    )
    return profile
