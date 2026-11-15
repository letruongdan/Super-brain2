"""The Linux observer must find an actual live holder before sampling identity."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.integration.test_t9_process_sighting import _conn_state, _safe_hooks
from tests.support import inc2_native_owner as owner


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real Linux procfs and child TCP socket')
def test_unrelated_process_creation_reads_cannot_cost_the_live_fd_sighting(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deterministic scheduling seam models slow creation reads for nonholders.

    The TCP socket, fd walk, inode, process and expected start are real. Only
    the scheduling of a creation-time read competes with the client's close.
    A second lookup on the same still-live connection must bind its true owner.
    """
    hooks, safe, mark_closing = _safe_hooks()
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(3)
            listen_port = listener.getsockname()[1]
            proc = subprocess.Popen(
                [sys.executable, '-I', '-u', '-c',
                 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); '
                 'print(s.getsockname()[1],flush=True); sys.stdin.buffer.read(); s.close()', str(listen_port)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                assert proc.stdin is not None and proc.stdout is not None
                accepted, _ = listener.accept()
                with accepted:
                    client_port = int(proc.stdout.readline())
                    expected_started = owner.process_started_at_for_pid(proc.pid)
                    control = safe(client_port, listen_port, _conn_state())
                    assert control[:2] == (proc.pid, expected_started), 'live child positive control did not bind'
                    conn = _conn_state()
                    unrelated_stat_reads: list[int] = []
                    proc_path = Path('/proc')
                    real_read_text = Path.read_text
                    real_open = os.open
                    real_readlink = os.readlink

                    def advance_close_on_unrelated_stat(path: Path) -> None:
                        physical = path.resolve()
                        if physical.name != 'stat' or physical.parent.parent != proc_path:
                            return
                        if not physical.parent.name.isdecimal() or int(physical.parent.name) == proc.pid:
                            return
                        unrelated_stat_reads.append(int(physical.parent.name))
                        if len(unrelated_stat_reads) == 1:
                            # Advancing the competing real close here removes wall-time
                            # guesses and reproduces the fd disappearing before sighting.
                            assert proc.stdin is not None
                            proc.stdin.close()
                            assert proc.wait(timeout=3) == 0
                            mark_closing(conn)

                    def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
                        if path.name == 'stat':
                            advance_close_on_unrelated_stat(path)
                        return real_read_text(path, *args, **kwargs)

                    def open_file(path: Any, *args: Any, **kwargs: Any) -> int:
                        if isinstance(path, (str, bytes, os.PathLike)):
                            candidate = Path(os.fsdecode(path))
                            if candidate.name == 'stat':
                                base_fd = kwargs.get('dir_fd')
                                if base_fd is not None and not candidate.is_absolute():
                                    candidate = Path(real_readlink(f'/proc/self/fd/{base_fd}')) / candidate
                                advance_close_on_unrelated_stat(candidate)
                        return real_open(path, *args, **kwargs)

                    with monkeypatch.context() as patch:
                        patch.setattr(Path, 'read_text', read_text)
                        patch.setattr(os, 'open', open_file)
                        result = safe(client_port, listen_port, conn)
                    assert result[:2] == (proc.pid, expected_started), (
                        'speculative nonholder creation read lost real live FD sighting', unrelated_stat_reads, result
                    )
                    assert result[2] is not None and result[3] is not None
                    assert not unrelated_stat_reads, 'lifetime metadata is relevant only to a matching holder'
            finally:
                if proc.stdin is not None and not proc.stdin.closed:
                    proc.stdin.close()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
    finally:
        hooks['uninstall']()
