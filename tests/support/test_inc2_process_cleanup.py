"""T9-R05 regressions for process identity and failed Win32 launch ownership."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.kernel import ENDPOINT_VERSION, Endpoint
from tests.support import inc2_child, inc2_cli
from tests.support.inc2_fixture import SampleTlsMaterial

_PYTHON = str(getattr(sys, "_base_executable", sys.executable))


@pytest.mark.parametrize("launcher_exits", [False, True])
def test_posix_cleanup_cannot_signal_unowned_inner_process(
    launcher_exits: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reported inner PID belongs to a real process that this controller never launched.
    # This also models an original inner PID being reused after the hello record.
    with subprocess.Popen([_PYTHON, "-c", "import time; time.sleep(20)"]) as unrelated:
        try:
            hello = json.dumps({"event": "hello", "pid": unrelated.pid})
            command = f"print({hello!r}, flush=True)"
            if not launcher_exits:
                command += "; import sys; sys.stdin.readline()"
            with inc2_child.Inc2ChildProcess([_PYTHON, "-c", command]) as child:
                child.wait_hello(timeout=5)
                assert child.inner_pid == unrelated.pid
                assert child.launcher_pid != unrelated.pid
                if launcher_exits:
                    assert child._proc.wait(timeout=5) == 0
                else:
                    assert child._proc.poll() is None

                sent_signals: list[tuple[int, int]] = []

                def observe_kill(pid: int, signum: int) -> None:
                    sent_signals.append((pid, signum))

                with monkeypatch.context() as mp:
                    if sys.platform == "win32":
                        # Exercise only the POSIX close path on Windows. Popen keeps using
                        # its real OS implementation for its own launcher.
                        mp.setattr(inc2_child, "sys", SimpleNamespace(platform="linux"))
                        mp.setattr(inc2_child, "signal", SimpleNamespace(SIGKILL=9), raising=False)
                    mp.setattr(inc2_child, "os", SimpleNamespace(kill=observe_kill))
                    child.close(timeout=5)

                assert all(pid != unrelated.pid for pid, _ in sent_signals)
                assert unrelated.poll() is None
                assert child._proc.poll() is not None
                assert child.cleanup_unverified
        finally:
            if unrelated.poll() is None:
                unrelated.kill()
                unrelated.wait(timeout=5)


def test_posix_cleanup_verifies_its_direct_child(monkeypatch: pytest.MonkeyPatch) -> None:
    command = (
        "import json, os, sys; "
        "print(json.dumps({'event':'hello','pid':os.getpid()}), flush=True); sys.stdin.readline()"
    )
    with inc2_child.Inc2ChildProcess([_PYTHON, "-c", command]) as child:
        child.wait_hello(timeout=5)
        assert child.inner_pid == child.launcher_pid
        assert child._proc.poll() is None
        with monkeypatch.context() as mp:
            if sys.platform == "win32":
                mp.setattr(inc2_child, "sys", SimpleNamespace(platform="linux"))
            child.close(timeout=5)
        assert child._proc.poll() is not None
        assert not child.cleanup_unverified


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 Job Object setup")
@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("popen", "injected Popen failure"),
        ("assign", "Failed to assign process"),
        ("resume", "Failed to resume process"),
    ],
)
def test_win32_failed_child_setup_releases_owned_resources(
    fault: str, message: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs: list[inc2_cli._Win32ProcessJob] = []
    children: list[subprocess.Popen[Any]] = []
    faults_reached: list[str] = []
    create_job = inc2_cli._Win32ProcessJob.__init__
    popen = subprocess.Popen
    spawn_failure = OSError(message)

    def remember_job(job: inc2_cli._Win32ProcessJob, *, kill_on_close: bool = False) -> None:
        create_job(job, kill_on_close=kill_on_close)
        assert job.handle is not None
        jobs.append(job)

    def capture_child(*args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        if fault == "popen":
            faults_reached.append(fault)
            raise spawn_failure
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    def fail_assign(_job: inc2_cli._Win32ProcessJob, _handle: int | None) -> bool:
        faults_reached.append(fault)
        return False

    def fail_resume(_handle: int | None) -> bool:
        faults_reached.append(fault)
        return False

    monkeypatch.setattr(inc2_cli._Win32ProcessJob, "__init__", remember_job)
    monkeypatch.setattr(subprocess, "Popen", capture_child)
    if fault == "assign":
        monkeypatch.setattr(inc2_cli._Win32ProcessJob, "assign_process", fail_assign)
    if fault == "resume":
        monkeypatch.setattr(inc2_cli, "_win32_resume_process", fail_resume)
    try:
        error_type = OSError if fault == "popen" else RuntimeError
        with pytest.raises(error_type, match=message) as raised:
            inc2_child.Inc2ChildProcess([_PYTHON, "-c", "raise AssertionError('never execute')"])
        assert faults_reached == [fault]
        assert len(jobs) == 1
        assert len(children) == (0 if fault == "popen" else 1)
        if fault == "popen":
            assert raised.value is spawn_failure

        open_pipes = [
            name
            for child in children
            for name, pipe in (("stdin", child.stdin), ("stdout", child.stdout), ("stderr", child.stderr))
            if pipe is not None and not pipe.closed
        ]
        assert all(child.returncode is not None for child in children), "suspended child was not waited for"
        assert (jobs[0].handle, open_pipes) == (None, [])
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for pipe in (child.stdin, child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
        for job in jobs:
            job.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 Job Object setup")
def test_win32_second_pump_start_failure_rolls_back_child(monkeypatch: pytest.MonkeyPatch) -> None:
    jobs: list[inc2_cli._Win32ProcessJob] = []
    children: list[subprocess.Popen[Any]] = []
    readers: list[threading.Thread] = []
    create_job = inc2_cli._Win32ProcessJob.__init__
    popen = subprocess.Popen
    start_thread = threading.Thread.start
    start_failure = RuntimeError("injected second pump start failure")

    def remember_job(job: inc2_cli._Win32ProcessJob, *, kill_on_close: bool = False) -> None:
        create_job(job, kill_on_close=kill_on_close)
        jobs.append(job)

    def capture_child(*args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    def start_first_pump(thread: threading.Thread) -> None:
        if thread.name == "inc2-child-stderr-pump":
            raise start_failure
        start_thread(thread)
        if thread.name == "inc2-child-ctrl-pump":
            readers.append(thread)

    monkeypatch.setattr(inc2_cli._Win32ProcessJob, "__init__", remember_job)
    monkeypatch.setattr(subprocess, "Popen", capture_child)
    monkeypatch.setattr(threading.Thread, "start", start_first_pump)
    try:
        with pytest.raises(RuntimeError, match="injected second pump start failure") as raised:
            inc2_child.Inc2ChildProcess([_PYTHON, "-c", "import time; time.sleep(20)"])
        assert raised.value is start_failure
        assert len(jobs) == len(children) == len(readers) == 1
        child, job, reader = children[0], jobs[0], readers[0]
        assert (child.returncode is not None, job.handle is None, reader.is_alive()) == (True, True, False)
        assert all(pipe is not None and pipe.closed for pipe in (child.stdin, child.stdout, child.stderr))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        for child in children:
            for pipe in (child.stdin, child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
        for job in jobs:
            job.close()


def test_installed_serve_process_wait_ready_requires_tls_handshake_acceptance(
    trusted_tmp: Path,
    inc2_tls_material: SampleTlsMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """wait_ready must not return as soon as endpoint.json exists if the TLS listener is not accepting."""
    ep_path = trusted_tmp / "endpoint.json"
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_sock.bind(("127.0.0.1", 0))
    closed_port = int(probe_sock.getsockname()[1])
    probe_sock.close()

    ep = Endpoint(
        version=ENDPOINT_VERSION,
        host="127.0.0.1",
        port=closed_port,
        store_id="store-wait-ready-probe",
        writer_epoch=1,
        instance_id="inst-wait-ready-probe",
    )
    ep_path.write_bytes(ep.encode_canonical())
    adapters = os_adapters()
    adapters.permissions.secure_file(ep_path)

    fake_proc = SimpleNamespace(poll=lambda: None)
    dummy = object.__new__(inc2_cli.InstalledServeProcess)
    dummy._proc = cast(subprocess.Popen[Any], fake_proc)
    dummy._endpoint_path = ep_path
    dummy._descendant_identities = []
    dummy._proc_ticks = None
    dummy._job = None
    dummy._job_handle = None
    dummy.cleanup_unverified = False

    # 1. With endpoint.json published on a non-accepting port, wait_ready must NOT return early.
    with pytest.raises(AssertionError, match="TLS"):
        inc2_cli.InstalledServeProcess.wait_ready(dummy, timeout=0.2)

    # 2. Once a real TLS listener binds and accepts, wait_ready returns the verified Endpoint.
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(
        certfile=str(inc2_tls_material.leaf_cert_path),
        keyfile=str(inc2_tls_material.leaf_key_path),
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.2)
    live_port = int(listener.getsockname()[1])
    live_ep = Endpoint(
        version=ENDPOINT_VERSION,
        host="127.0.0.1",
        port=live_port,
        store_id="store-wait-ready-probe",
        writer_epoch=1,
        instance_id="inst-wait-ready-probe",
    )
    ep_path.write_bytes(live_ep.encode_canonical())
    adapters.permissions.secure_file(ep_path)

    stop_accept = threading.Event()
    accept_errors: list[BaseException] = []

    def _accept_once() -> None:
        while not stop_accept.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with server_ctx.wrap_socket(conn, server_side=True):
                    return
            except OSError as err:
                accept_errors.append(err)
                return

    thread = threading.Thread(target=_accept_once, daemon=True)
    thread.start()
    monkeypatch.setattr(dummy, "snapshot_descendant_pids", lambda: ())
    try:
        returned = inc2_cli.InstalledServeProcess.wait_ready(dummy, timeout=2.0)
        assert returned == live_ep
        assert accept_errors == []
    finally:
        stop_accept.set()
        listener.close()
        thread.join(timeout=2.0)
