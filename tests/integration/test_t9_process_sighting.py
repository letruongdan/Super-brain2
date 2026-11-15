"""OS process identity must be retained with a real live FD sighting.

Scheduling seam: the real inode-holder scan completes, then the actual client
exits before the caller regains control. No PID, FD, inode or clock is faked.
"""
from __future__ import annotations

import contextlib
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from superbrain.cli_api import _loopback_server
from tests.support import inc2_native_owner as owner

LINUX_ONLY = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real Linux proc/FD identity')


def _closure_fn(fn: Any, name: str) -> Any:
    for cell in fn.__closure__ or ():
        value = cell.cell_contents
        if callable(value) and getattr(value, '__name__', '') == name:
            return value
    raise LookupError(name)


def _conn_state() -> dict[str, Any]:
    return {
        'lock': threading.Lock(),
        'conn_started_ns': time.monotonic_ns(),
        'conn_started_seq': next(owner._ORDER_SEQ),
        'closed_event': threading.Event(),
        'worker_entered_event': threading.Event(),
        'closing': False,
        'closing_ns': None,
        'closing_seq': None,
        'closing_at': None,
        'closed_at': None,
        'closed_ns': None,
        'closed_seq': None,
        'raw_sock': None,
        'ssl_sock': None,
    }


def _safe_hooks() -> tuple[dict[str, Any], Any, Any]:
    hooks = owner._install_loopback_server_hooks(
        eq=queue.Queue(), daemon_pid=os.getpid(), daemon_started_at=owner.process_started_at_for_pid(os.getpid())
    )
    tap = _loopback_server.LoopbackServer._conn_worker
    safe = _closure_fn(_closure_fn(tap, '_submit_lookup'), '_safe_client_identity')
    close = _closure_fn(tap, '_mark_conn_closing')
    return hooks, safe, close


@LINUX_ONLY
@pytest.mark.parametrize('exit_after_scan', [False, True], ids=['alive_positive', 'exit_after_live_sighting'])
def test_unique_live_child_retains_identity_after_scan(
    monkeypatch: pytest.MonkeyPatch, exit_after_scan: bool
) -> None:
    hooks, safe, mark_closing = _safe_hooks()
    proc = None
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listen_port = listener.getsockname()[1]
            conn = _conn_state()
            proc = subprocess.Popen(
                [sys.executable, '-I', '-u', '-c',
                 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); '
                 'print(s.getsockname()[1],flush=True); sys.stdin.buffer.read(); s.close()', str(listen_port)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            accepted, _ = listener.accept()
            with accepted:
                assert proc.stdout is not None and proc.stdin is not None
                client_port = int(proc.stdout.readline())
                expected_started = owner.process_started_at_for_pid(proc.pid)
                original_scan = owner._socket_inode_holders
                actual_holders: list[set[int]] = []

                def scan_then_resume(inode: int, **kwargs: Any) -> set[int]:
                    found = original_scan(inode, **kwargs)
                    actual_holders.append(found)
                    assert found == {proc.pid}, 'real kernel FD scan must identify only the actual child'
                    if exit_after_scan:
                        # Resume the caller only after the real client exited and closing was recorded.
                        assert proc.stdin is not None
                        proc.stdin.close()
                        assert proc.wait(timeout=3) == 0
                        assert not os.path.exists(f'/proc/{proc.pid}/stat')
                        mark_closing(conn)
                    return found

                monkeypatch.setattr(owner, '_socket_inode_holders', scan_then_resume)
                result = safe(client_port, listen_port, conn)
                assert actual_holders == [{proc.pid}]
                assert result[0:2] == (proc.pid, expected_started), (
                    'an immutable OS process identity captured with a unique live FD sighting '
                    'must survive caller resumption after that process exits'
                )
                assert result[2] is not None and result[3] is not None
                if exit_after_scan:
                    assert result[3] <= conn['closing_ns']
    finally:
        if proc is not None:
            with contextlib.suppress(OSError):
                if proc.stdin is not None:
                    proc.stdin.close()
            proc.wait(timeout=3)
        hooks['uninstall']()


@LINUX_ONLY
def test_shared_real_client_fd_stays_ambiguous() -> None:
    hooks, safe, _close = _safe_hooks()
    proc = None
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            conn = _conn_state()
            with socket.create_connection(listener.getsockname()) as client:
                accepted, _ = listener.accept()
                with accepted:
                    proc = subprocess.Popen(
                        [sys.executable, '-I', '-u', '-c',
                         'import os,sys; os.fstat(int(sys.argv[1])); '
                         'print("ready",flush=True); sys.stdin.buffer.read()',
                         str(client.fileno())],
                        pass_fds=(client.fileno(),), stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    assert proc.stdout is not None and proc.stdout.readline() == b'ready\n'
                    assert safe(client.getsockname()[1], listener.getsockname()[1], conn) == (None, None, None, None)
    finally:
        if proc is not None:
            assert proc.stdin is not None
            proc.stdin.close()
            assert proc.wait(timeout=3) == 0
        hooks['uninstall']()


@LINUX_ONLY
@pytest.mark.parametrize('identity_fault', ['unknown', 'changed_after_fd_match'])
def test_real_fd_with_unknown_or_changed_process_identity_is_refused(
    monkeypatch: pytest.MonkeyPatch, identity_fault: str
) -> None:
    """Fault only the OS creation-time boundary; real PID/FD/tuple are unchanged.

    The changed-time fault models PID reuse across the FD read. It can only
    produce a refusal, never positive/native evidence containing an invented ID.
    """
    hooks, safe, _close = _safe_hooks()
    proc = None
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            conn = _conn_state()
            proc = subprocess.Popen(
                [sys.executable, '-I', '-u', '-c',
                 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); '
                 'print(s.getsockname()[1],flush=True); sys.stdin.buffer.read(); s.close()',
                 str(listener.getsockname()[1])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            accepted, _ = listener.accept()
            with accepted:
                assert proc.stdout is not None
                client_port = int(proc.stdout.readline())
                inode = owner._parse_proc_net_tcp_inode(
                    owner._LINUX_PROC_ROOT.joinpath('net/tcp').read_text(),
                    client_port=client_port, listen_port=listener.getsockname()[1], ipv6=False,
                )
                assert inode is not None
                target = f'socket:[{inode}]'
                original_readlink = os.readlink
                original_started = owner.process_started_at_for_pid
                matched = False

                def readlink_and_switch(path: Any, *args: Any, **kwargs: Any) -> str:
                    nonlocal matched
                    result = original_readlink(path, *args, **kwargs)
                    if result == target:
                        matched = True
                    return cast(str, result)

                def creation_time(pid: int) -> str:
                    if pid == proc.pid:
                        if identity_fault == 'unknown':
                            raise OSError('creation_time_unavailable')
                        if matched:
                            # Static negative-fault value; must never become accepted observation.
                            return '2099-01-01T00:00:00.000000Z'
                    return original_started(pid)

                monkeypatch.setattr(os, 'readlink', readlink_and_switch)
                monkeypatch.setattr(owner, 'process_started_at_for_pid', creation_time)
                assert safe(client_port, listener.getsockname()[1], conn) == (None, None, None, None), (
                    'unknown or changing process creation identity must never label a live socket'
                )
    finally:
        if proc is not None:
            assert proc.stdin is not None
            proc.stdin.close()
            assert proc.wait(timeout=3) == 0
        hooks['uninstall']()


@pytest.mark.parametrize('post_row_identity', ['current', 'reused'])
def test_unbracketed_fallback_pid_does_not_mint_process_identity(
    monkeypatch: pytest.MonkeyPatch, post_row_identity: str
) -> None:
    """Real OS positive twin, then a negative unbracketed collector edge fault.

    The subprocess/lsof boundary is faulted only after the actual OS has proved
    the tuple/PID and the same live connection passed the immutable-identity path.
    An available identity read after a row cannot repair its missing provenance.
    """
    actual_started = owner.process_started_at_for_pid(os.getpid())
    hooks, safe, _close = _safe_hooks()
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with socket.create_connection(listener.getsockname()) as client:
                accepted, _peer = listener.accept()
                with accepted:
                    client_port, listen_port = client.getsockname()[1], listener.getsockname()[1]
                    # The connection is held open throughout, so a missing short
                    # socket or a PID guessed from the payload cannot satisfy this.
                    assert owner._lookup_loopback_client_pid(client_port, listen_port) == os.getpid()
                    live = safe(client_port, listen_port, _conn_state())
                    assert live[0:2] == (os.getpid(), actual_started)
                    assert live[2] is not None and live[3] is not None

                    lsof_row = f'p{os.getpid()}\nn127.0.0.1:{client_port}->127.0.0.1:{listen_port}\n'
                    monkeypatch.setattr(owner, 'sys', SimpleNamespace(platform='darwin'))
                    monkeypatch.setattr(owner, '_libproc_client_holders', lambda *_args: None)

                    def lsof(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
                        return subprocess.CompletedProcess(['lsof'], 0, stdout=lsof_row, stderr='')

                    monkeypatch.setattr(subprocess, 'run', lsof)
                    post_row_started = (
                        actual_started if post_row_identity == 'current' else '2099-01-01T00:00:00.000000Z'
                    )
                    monkeypatch.setattr(owner, 'process_started_at_for_pid', lambda _pid: post_row_started)
                    assert safe(client_port, listen_port, _conn_state()) == (None, None, None, None), (
                        'an unbracketed PID row has no immutable process-identity evidence'
                    )
    finally:
        hooks['uninstall']()


@pytest.mark.skipif(
    not sys.platform.startswith(('linux', 'darwin')),
    reason='actual Linux or macOS socket holder with unavailable exact creation metadata',
)
def test_live_holder_with_unavailable_kernel_start_cannot_use_ps_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact TCP match does not authorize a whole-second process lifetime."""
    pid = os.getpid()
    started = owner.process_started_at_for_pid(pid)
    hooks, safe, _close = _safe_hooks()
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(2)
            with socket.create_connection(listener.getsockname(), timeout=2) as client:
                accepted, _peer = listener.accept()
                with accepted:
                    peer_port, listen_port = client.getsockname()[1], listener.getsockname()[1]
                    live = safe(peer_port, listen_port, _conn_state())
                    assert live[0:2] == (pid, started)
                    assert live[2] is not None and live[3] is not None

                    if sys.platform.startswith('linux'):
                        creation_file = Path(f'/proc/{pid}/stat')
                        original_exists = Path.exists
                        original_read_text = Path.read_text

                        def exists(path: Path, *args: Any, **kwargs: Any) -> bool:
                            return path != creation_file and original_exists(path, *args, **kwargs)

                        def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
                            if path == creation_file:
                                raise FileNotFoundError('creation metadata was unavailable')
                            return original_read_text(path, *args, **kwargs)

                        monkeypatch.setattr(Path, 'exists', exists)
                        monkeypatch.setattr(Path, 'read_text', read_text)
                    else:
                        monkeypatch.setattr(owner, '_libproc_started_at', lambda _pid: None)
                    original_run = subprocess.run

                    def tempting_ps(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
                        if cmd == ['ps', '-o', 'lstart=', '-p', str(pid)]:
                            return subprocess.CompletedProcess(
                                cmd, 0, stdout='Wed Jan 01 00:00:00 2025\n', stderr=''
                            )
                        return original_run(cmd, **kwargs)

                    monkeypatch.setattr(subprocess, 'run', tempting_ps)
                    assert safe(peer_port, listen_port, _conn_state()) == (None, None, None, None), (
                        'available socket ownership does not turn a coarse ps time into exact creation evidence'
                    )
    finally:
        hooks['uninstall']()
