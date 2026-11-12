"""Test-only wheel owner driver and same-daemon verifier for Task 9 integration tests.

Runs the real production owner composition (``owner_entry._explicit_owner_adapters`` + ``daemon_entry.serve``)
inside the installed wheel interpreter (enforced under ``python -I`` when launched as a subprocess), tapping
``LoopbackServer._release_owner_reply`` and ``write_json_response`` without performing disk I/O inside
``AuthGate`` locks, request deadlines, or SQLite transactions.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import queue
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import Ready
    from tests.support.inc2_fixture import InstalledEnv
    from tests.support.inc2_native import (
        NativeConnectionProbe,
        OwnerCallObservation,
        ProcessIdentity,
        SocketObservation,
    )

__all__ = [
    "ObservedWheelOwner",
    "load_owner_observations",
    "process_started_at_for_pid",
    "run_observed_owner",
    "spawn_observed_wheel_owner",
    "verify_same_daemon",
]


@dataclass(frozen=True)
class ObservedWheelOwner:
    process_identity: ProcessIdentity
    endpoint_port: int
    store_id: str
    writer_epoch: int
    instance_id: str
    module_file: str
    schema_sha256: str
    evidence_dir: Path


def _utc_now_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def process_started_at_for_pid(pid: int) -> str:
    """Return canonical UTC RFC3339 process creation timestamp for ``pid``."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        close_handle = False
        if pid == os.getpid():
            handle = kernel32.GetCurrentProcess()
        else:
            handle = kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                raise OSError(ctypes.get_last_error(), "OpenProcess failed")
            close_handle = True
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
            ticks_100ns = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
            dt = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks_100ns // 10)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        finally:
            if close_handle:
                kernel32.CloseHandle(handle)

    proc_stat = Path(f"/proc/{pid}/stat")
    sys_stat = Path("/proc/stat")
    if proc_stat.exists() and sys_stat.exists():
        btime_s = 0.0
        for line in sys_stat.read_text(encoding="ascii").splitlines():
            if line.startswith("btime "):
                btime_s = float(line.split()[1])
                break
        start_ticks = int(proc_stat.read_text(encoding="ascii").rpartition(")")[2].split()[19])
        hz = os.sysconf("SC_CLK_TCK")
        dt = datetime.fromtimestamp(btime_s + (start_ticks / float(hz)), tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    out = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, check=True)
    raw = " ".join(out.stdout.split())
    parsed = datetime.strptime(raw, "%a %b %d %H:%M:%S %Y").astimezone(UTC)
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_LINUX_PROC_ROOT = Path("/proc")


def _parse_proc_net_tcp_inode(text: str, *, client_port: int, listen_port: int, ipv6: bool = False) -> int | None:
    """Return socket inode for loopback ``127.0.0.1:client_port -> 127.0.0.1:listen_port`` from ``/proc/net/tcp*``."""
    addr_hex = "0000000000000000FFFF00000100007F" if ipv6 else "0100007F"
    local_target = f"{addr_hex}:{client_port:04X}"
    remote_target = f"{addr_hex}:{listen_port:04X}"
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        if parts[1].upper() == local_target and parts[2].upper() == remote_target and parts[3].upper() != "0A":
            try:
                inode = int(parts[9])
            except ValueError:
                continue
            if inode > 0:
                return inode
    return None


def _find_pid_by_socket_inode(inode: int, *, proc_root: Path | None = None) -> int | None:
    """Locate the owning PID whose ``/proc/<pid>/fd/*`` references ``socket:[inode]``."""
    root = _LINUX_PROC_ROOT if proc_root is None else proc_root
    target = f"socket:[{inode}]"
    try:
        entries = list(root.iterdir())
    except OSError:
        return None
    for pid_dir in entries:
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            fd_entries = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd_path in fd_entries:
            try:
                if os.readlink(fd_path) == target:
                    return int(pid_dir.name)
            except OSError:
                continue
    return None


def _parse_lsof_client_pid(output: str, *, client_port: int, listen_port: int) -> int | None:
    """Parse ``lsof -nP -F pn`` output and return the PID owning ``127.0.0.1:client_port->127.0.0.1:listen_port``."""
    target_name = f"127.0.0.1:{client_port}->127.0.0.1:{listen_port}"
    current_pid: int | None = None
    for raw_line in output.splitlines():
        if raw_line.startswith("p"):
            try:
                current_pid = int(raw_line[1:])
            except ValueError:
                current_pid = None
        elif raw_line.startswith("n") and current_pid is not None:
            if raw_line[1:].strip() == target_name:
                return current_pid
    return None


def _lookup_loopback_client_pid(client_port: int, listen_port: int) -> int | None:
    if client_port <= 0 or listen_port <= 0:
        return None
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
        buf = (ctypes.c_ubyte * (size.value + 4096))()
        size2 = wintypes.DWORD(len(buf))
        if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size2), False, 2, 5, 0) != 0:
            return None
        num = ctypes.c_uint32.from_buffer(buf, 0).value
        for idx in range(num):
            base = 4 + idx * 24
            _state, laddr, lport_net, raddr, rport_net, pid = (
                ctypes.c_uint32.from_buffer(buf, base + offset * 4).value for offset in range(6)
            )
            if socket.inet_ntoa(struct.pack("<I", laddr)) != "127.0.0.1":
                continue
            if socket.inet_ntoa(struct.pack("<I", raddr)) != "127.0.0.1":
                continue
            if socket.ntohs(lport_net & 0xFFFF) == client_port and socket.ntohs(rport_net & 0xFFFF) == listen_port:
                if pid > 0:
                    return int(pid)
        return None
    if sys.platform.startswith("linux"):
        for name, is_v6 in (("tcp", False), ("tcp6", True)):
            try:
                text = (_LINUX_PROC_ROOT / "net" / name).read_text(encoding="ascii", errors="replace")
            except OSError:
                continue
            inode = _parse_proc_net_tcp_inode(text, client_port=client_port, listen_port=listen_port, ipv6=is_v6)
            if inode is not None:
                pid = _find_pid_by_socket_inode(inode)
                if pid is not None:
                    return pid
        return None
    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                ["lsof", "-nP", "-F", "pn", f"-iTCP@127.0.0.1:{client_port}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 and not proc.stdout:
            return None
        return _parse_lsof_client_pid(proc.stdout, client_port=client_port, listen_port=listen_port)
    return None


def _run_event_writer(evidence_dir: Path, event_queue: queue.SimpleQueue[dict[str, JsonValue] | None]) -> None:
    events_path = evidence_dir / "owner-events.jsonl"
    ready_path = evidence_dir / "owner-ready.json"
    from superbrain.core.canonical import canonical_json

    with events_path.open("ab") as events_fh:
        while True:
            item = event_queue.get()
            if item is None:
                break
            kind = item.get("event")
            if kind == "ready":
                tmp = evidence_dir / f".ready-{os.getpid()}.tmp"
                tmp.write_bytes(canonical_json(item) + b"\n")
                os.replace(tmp, ready_path)
            else:
                events_fh.write(canonical_json(item) + b"\n")
                events_fh.flush()


def _install_loopback_server_hooks(
    *,
    eq: Any,
    daemon_pid: int,
    daemon_started_at: str,
    store_id: str | None = None,
    instance_id: str | None = None,
    initial_ready: bool = True,
) -> dict[str, Any]:
    from superbrain.application._auth_gate import AuthGate
    from superbrain.cli_api import _loopback_server
    from superbrain.core.canonical import digest_bytes
    from superbrain.core.wire import encode_envelope

    hook_lock = threading.Lock()
    pending_cmds: dict[int, tuple[str, dict[str, JsonValue] | None, str, str, str, int, str, int]] = {}
    flush_by_thread: dict[int, tuple[int | None, str | None]] = {}
    stamp_result_by_tid: dict[int, bool] = {}
    ready_seen = initial_ready

    loopback_mod: Any = _loopback_server
    auth_gate_cls: Any = AuthGate
    orig_read_cmd = loopback_mod.read_admitted_tool_command
    orig_write_json = loopback_mod.write_json_response
    orig_release = _loopback_server.LoopbackServer._release_owner_reply
    orig_conn_worker = _loopback_server.LoopbackServer._conn_worker
    orig_authorize_stamp = AuthGate.authorize_stamp

    def _resolve_principal_and_cred(
        gate: Any,
        grant_stamp: Any,
        raw_token: str,
    ) -> tuple[str | None, str | None]:
        view = gate.current()
        credential_id: str | None = grant_stamp.credential_id if grant_stamp is not None else None
        if credential_id is None and "." in raw_token:
            credential_id = raw_token.split(".", 1)[0]
        cred = (
            view.auth.credentials.get(credential_id)
            if (credential_id is not None and view is not None)
            else None
        )
        principal_id = cred.principal.principal_id if cred is not None else None
        return principal_id, credential_id

    def _emit_owner_call(
        *,
        gate: Any,
        principal_id: str | None,
        credential_id: str | None,
        tool_name: str,
        ready_val: bool,
        auth_matched: bool,
        response_flushed_ok: bool,
        resp_digest: str | None,
        listen_host: str,
        listen_port: int,
        peer_host: str,
        peer_port: int,
        client_pid: int | None,
        client_started_at: str | None,
        req_started_at: str,
        ended_at: str,
        selected_scope: dict[str, JsonValue] | None,
    ) -> None:
        ident = gate.identity
        eq.put_nowait(
            {
                "event": "owner_call",
                "daemon_pid": daemon_pid,
                "daemon_started_at": daemon_started_at,
                "store_id": ident.store_id if ident is not None else (store_id or ""),
                "writer_epoch": ident.writer_epoch if ident is not None else 0,
                "instance_id": ident.instance_id if ident is not None else (instance_id or ""),
                "principal_id": principal_id or "<unknown>",
                "credential_id": credential_id or "<unknown>",
                "tool_name": tool_name,
                "ready": ready_val,
                "auth_stamp_matched": auth_matched,
                "response_flushed_ok": response_flushed_ok,
                "response_digest": resp_digest,
                "listen_host": listen_host,
                "listen_port": listen_port,
                "client_host": peer_host,
                "client_port": peer_port,
                "client_pid": client_pid,
                "client_started_at": client_started_at,
                "started_at": req_started_at,
                "ended_at": ended_at,
                "selected_scope": selected_scope,
            }
        )

    def _tap_read_cmd(
        ssl_sock: Any,
        reader: Any,
        ready: Any,
        *,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> Any:
        tid = threading.get_ident()
        with hook_lock:
            flush_by_thread.pop(tid, None)
            stamp_result_by_tid.pop(tid, None)
        cmd = orig_read_cmd(ssl_sock, reader, ready, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        if cmd is not None:
            scope_dict = cmd.selected_scope.to_dict() if cmd.selected_scope is not None else None
            listen_host = "127.0.0.1"
            listen_port = 0
            peer_host = "127.0.0.1"
            peer_port = 0
            with contextlib.suppress(OSError):
                lhost, lport = ssl_sock.getsockname()[:2]
                phost, pport = ssl_sock.getpeername()[:2]
                listen_host, listen_port = str(lhost), int(lport)
                peer_host, peer_port = str(phost), int(pport)
            with hook_lock:
                pending_cmds[tid] = (
                    str(cmd.tool),
                    scope_dict,
                    _utc_now_z(),
                    str(cmd.token),
                    listen_host,
                    listen_port,
                    peer_host,
                    peer_port,
                )
        return cmd

    def _tap_write_json(
        ssl_sock: Any,
        *,
        status: int,
        body: bytes,
        close_conn: bool,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> None:
        orig_write_json(
            ssl_sock,
            status=status,
            body=body,
            close_conn=close_conn,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        tid = threading.get_ident()
        with hook_lock:
            flush_by_thread[tid] = (int(status), digest_bytes(body))

    def _tap_authorize_stamp(gate_self: Any, stamp: Any) -> bool:
        res = bool(orig_authorize_stamp(gate_self, stamp))
        with hook_lock:
            stamp_result_by_tid[threading.get_ident()] = res
        return res

    def _tap_conn_worker(self: Any, conn_id: Any, raw_sock: Any, accept_ns: int) -> None:
        tid = threading.get_ident()
        try:
            orig_conn_worker(self, conn_id, raw_sock, accept_ns)
        finally:
            with hook_lock:
                cmd_info = pending_cmds.pop(tid, None)
                flushed_status, flushed_digest = flush_by_thread.pop(tid, (None, None))
                stamp_result_by_tid.pop(tid, None)
            if cmd_info is not None:
                (
                    tool_name,
                    selected_scope,
                    req_started_at,
                    raw_token,
                    listen_host,
                    listen_port,
                    peer_host,
                    peer_port,
                ) = cmd_info
                gate = self._owner.auth_gate
                principal_id, credential_id = _resolve_principal_and_cred(gate, None, raw_token)
                _emit_owner_call(
                    gate=gate,
                    principal_id=principal_id,
                    credential_id=credential_id,
                    tool_name=tool_name,
                    ready_val=False,
                    auth_matched=False,
                    response_flushed_ok=bool(flushed_status == 200 and flushed_digest is not None),
                    resp_digest=flushed_digest,
                    listen_host=listen_host,
                    listen_port=listen_port,
                    peer_host=peer_host,
                    peer_port=peer_port,
                    client_pid=None,
                    client_started_at=None,
                    req_started_at=req_started_at,
                    ended_at=_utc_now_z(),
                    selected_scope=selected_scope,
                )

    def _tap_release(self: Any, ssl_sock: Any, reply: Any, tool_deadline_ns: int) -> None:
        tid = threading.get_ident()
        with hook_lock:
            cmd_info = pending_cmds.pop(tid, None)
        tool_name = cmd_info[0] if cmd_info is not None else None
        selected_scope = cmd_info[1] if cmd_info is not None else None
        req_started_at = cmd_info[2] if cmd_info is not None else _utc_now_z()
        raw_token = cmd_info[3] if cmd_info is not None else ""

        listen_host = cmd_info[4] if cmd_info is not None else "127.0.0.1"
        listen_port = cmd_info[5] if cmd_info is not None else 0
        peer_host = cmd_info[6] if cmd_info is not None else "127.0.0.1"
        peer_port = cmd_info[7] if cmd_info is not None else 0
        with contextlib.suppress(OSError):
            lhost, lport = ssl_sock.getsockname()[:2]
            phost, pport = ssl_sock.getpeername()[:2]
            listen_host, listen_port = str(lhost), int(lport)
            peer_host, peer_port = str(phost), int(pport)

        client_pid: int | None = None
        client_started_at: str | None = None
        if peer_port > 0 and listen_port > 0:
            client_pid = _lookup_loopback_client_pid(peer_port, listen_port)
            if client_pid is not None:
                with contextlib.suppress(OSError):
                    client_started_at = process_started_at_for_pid(client_pid)

        gate = self._owner.auth_gate
        grant_stamp = reply.grant_stamp
        principal_id, credential_id = _resolve_principal_and_cred(gate, grant_stamp, raw_token)

        expected_env_digest = digest_bytes(encode_envelope(reply.envelope))
        try:
            orig_release(self, ssl_sock, reply, tool_deadline_ns)
        finally:
            with hook_lock:
                flushed_status, flushed_digest = flush_by_thread.pop(tid, (None, None))
                stamp_result = stamp_result_by_tid.pop(tid, None)

            ended_at = _utc_now_z()
            env_ok = reply.envelope.get("ok") is True
            if env_ok:
                if stamp_result is not None:
                    auth_matched = bool(
                        stamp_result and flushed_status == 200 and flushed_digest == expected_env_digest
                    )
                else:
                    auth_matched = bool(
                        grant_stamp is not None and flushed_status == 200 and flushed_digest == expected_env_digest
                    )
                response_flushed_ok = bool(
                    auth_matched and flushed_status == 200 and flushed_digest == expected_env_digest
                )
            else:
                auth_matched = False
                response_flushed_ok = bool(flushed_status is not None and flushed_digest == expected_env_digest)

            if env_ok and not auth_matched:
                ready_val = False
            elif tool_name == "get_health" and auth_matched and isinstance(reply.envelope.get("data"), dict):
                ready_val = bool(reply.envelope["data"].get("ready") is True)
            else:
                ready_val = ready_seen

            if tool_name is not None:
                _emit_owner_call(
                    gate=gate,
                    principal_id=principal_id,
                    credential_id=credential_id,
                    tool_name=tool_name,
                    ready_val=ready_val,
                    auth_matched=auth_matched,
                    response_flushed_ok=response_flushed_ok,
                    resp_digest=flushed_digest,
                    listen_host=listen_host,
                    listen_port=listen_port,
                    peer_host=peer_host,
                    peer_port=peer_port,
                    client_pid=client_pid,
                    client_started_at=client_started_at,
                    req_started_at=req_started_at,
                    ended_at=ended_at,
                    selected_scope=selected_scope,
                )

    def _set_ready(value: bool) -> None:
        nonlocal ready_seen
        ready_seen = value

    def _pending_count() -> int:
        with hook_lock:
            return len(pending_cmds)

    loopback_mod.read_admitted_tool_command = _tap_read_cmd
    loopback_mod.write_json_response = _tap_write_json
    loopback_mod.LoopbackServer._release_owner_reply = _tap_release
    loopback_mod.LoopbackServer._conn_worker = _tap_conn_worker
    auth_gate_cls.authorize_stamp = _tap_authorize_stamp

    def _uninstall() -> None:
        loopback_mod.read_admitted_tool_command = orig_read_cmd
        loopback_mod.write_json_response = orig_write_json
        loopback_mod.LoopbackServer._release_owner_reply = orig_release
        loopback_mod.LoopbackServer._conn_worker = orig_conn_worker
        auth_gate_cls.authorize_stamp = orig_authorize_stamp

    return {
        "uninstall": _uninstall,
        "pending_count": _pending_count,
        "set_ready": _set_ready,
    }


def run_observed_owner(config_path: Path, evidence_dir: Path, stop: threading.Event) -> int:
    """Run the production owner loop via ``_explicit_owner_adapters`` and record sanitized call observations."""
    if not isinstance(config_path, Path) or not config_path.is_absolute():
        raise ValueError("absolute config_path required")
    if not isinstance(evidence_dir, Path) or not evidence_dir.is_absolute():
        raise ValueError("absolute evidence_dir required")

    import superbrain
    from superbrain.composition import daemon_entry, owner_entry
    from superbrain.core.wire import load_catalog

    evidence_dir.mkdir(parents=True, exist_ok=True)
    daemon_pid = os.getpid()
    daemon_started_at = process_started_at_for_pid(daemon_pid)
    module_file = str(Path(superbrain.__file__).resolve()) if superbrain.__file__ else ""
    schema_sha256 = load_catalog().schema_sha256

    cfg, adapters, scratch_base = owner_entry._explicit_owner_adapters(config_path)
    event_queue: queue.SimpleQueue[dict[str, JsonValue] | None] = queue.SimpleQueue()
    writer_thread = threading.Thread(
        target=_run_event_writer,
        args=(evidence_dir, event_queue),
        daemon=True,
    )
    writer_thread.start()

    hook_state = _install_loopback_server_hooks(
        eq=event_queue,
        daemon_pid=daemon_pid,
        daemon_started_at=daemon_started_at,
        initial_ready=False,
    )

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        hook_state["set_ready"](True)
        shutil.rmtree(scratch_base, ignore_errors=True)
        event_queue.put_nowait(
            {
                "event": "ready",
                "daemon_pid": daemon_pid,
                "daemon_started_at": daemon_started_at,
                "port": ready.endpoint.port,
                "store_id": ready.identity.store_id,
                "writer_epoch": ready.identity.writer_epoch,
                "instance_id": ready.identity.instance_id,
                "module_file": module_file,
                "schema_sha256": schema_sha256,
            }
        )

    try:
        return int(daemon_entry.serve(cfg, os_=adapters, stop_event=stop, on_ready=_on_ready))
    finally:
        hook_state["uninstall"]()
        shutil.rmtree(scratch_base, ignore_errors=True)
        event_queue.put_nowait(None)
        writer_thread.join(timeout=5.0)


def load_owner_observations(
    evidence_dir: Path,
) -> tuple[dict[str, Any] | None, tuple[OwnerCallObservation, ...], tuple[SocketObservation, ...]]:
    """Read ready metadata, owner call observations, and loopback socket observations from ``evidence_dir``."""
    from tests.support.inc2_native import OwnerCallObservation, ProcessIdentity, SocketObservation

    ready_path = evidence_dir / "owner-ready.json"
    ready_meta: dict[str, Any] | None = None
    if ready_path.is_file():
        ready_meta = cast(dict[str, Any], json.loads(ready_path.read_bytes()))

    events_path = evidence_dir / "owner-events.jsonl"
    owners: list[OwnerCallObservation] = []
    sockets: list[SocketObservation] = []
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = cast(dict[str, Any], json.loads(line))
            if row.get("event") != "owner_call":
                continue
            client_pid = row.get("client_pid")
            client_started = row.get("client_started_at")
            client_proc = (
                ProcessIdentity(pid=client_pid, started_at=client_started)
                if isinstance(client_pid, int) and isinstance(client_started, str)
                else None
            )
            client_host_raw = row.get("client_host")
            client_port_raw = row.get("client_port")
            daemon_proc = ProcessIdentity(pid=int(row["daemon_pid"]), started_at=str(row["daemon_started_at"]))
            owners.append(
                OwnerCallObservation(
                    daemon_process=daemon_proc,
                    store_id=str(row["store_id"]),
                    writer_epoch=int(row["writer_epoch"]),
                    instance_id=str(row["instance_id"]),
                    principal_id=str(row["principal_id"]),
                    credential_id=str(row["credential_id"]),
                    tool_name=str(row["tool_name"]),
                    ready=bool(row["ready"]),
                    auth_stamp_matched=bool(row["auth_stamp_matched"]),
                    response_flushed_ok=bool(row["response_flushed_ok"]),
                    response_digest=cast(str | None, row["response_digest"]),
                    listen_host=str(row["listen_host"]),
                    listen_port=int(row["listen_port"]),
                    started_at=str(row["started_at"]),
                    ended_at=str(row["ended_at"]),
                    call_id=None,
                    selected_scope=cast(dict[str, Any] | None, row["selected_scope"]),
                    client_host=str(client_host_raw) if isinstance(client_host_raw, str) else None,
                    client_port=int(client_port_raw) if isinstance(client_port_raw, int) else None,
                    client_process=client_proc,
                )
            )
            if isinstance(client_pid, int) and isinstance(client_started, str):
                sockets.append(
                    SocketObservation(
                        client_process=ProcessIdentity(pid=client_pid, started_at=client_started),
                        daemon_process=daemon_proc,
                        local_addr=str(row["client_host"]),
                        local_port=int(row["client_port"]),
                        remote_addr=str(row["listen_host"]),
                        remote_port=int(row["listen_port"]),
                        store_id=str(row["store_id"]),
                        writer_epoch=int(row["writer_epoch"]),
                        instance_id=str(row["instance_id"]),
                    )
                )
    return ready_meta, tuple(owners), tuple(sockets)


@contextmanager
def spawn_observed_wheel_owner(
    env: InstalledEnv,
    config_path: Path,
    evidence_dir: Path,
    *,
    cwd: Path,
) -> Iterator[ObservedWheelOwner]:
    """Spawn ``inc2_native_owner.py`` under ``env.venv_python -I`` and wait until ready."""
    from tests.support.inc2_cli import clean_installed_subprocess_env
    from tests.support.inc2_native import ProcessIdentity

    evidence_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(env.venv_python),
        "-I",
        str(Path(__file__).resolve()),
        "--config",
        str(config_path),
        "--evidence-dir",
        str(evidence_dir),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=clean_installed_subprocess_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    ready_file = evidence_dir / "owner-ready.json"
    deadline = time.monotonic() + 15.0
    ready_data: dict[str, Any] | None = None
    try:
        while time.monotonic() < deadline:
            if ready_file.is_file():
                try:
                    raw = ready_file.read_bytes()
                    if raw:
                        ready_data = cast(dict[str, Any], json.loads(raw))
                        break
                except (OSError, ValueError):
                    pass
            rc = proc.poll()
            if rc is not None:
                out_b, err_b = proc.communicate(timeout=5.0)
                raise RuntimeError(
                    f"observed wheel owner exited early (rc={rc}): "
                    f"out={out_b.decode('utf-8', 'replace')!r} err={err_b.decode('utf-8', 'replace')!r}"
                )
            time.sleep(0.02)
        if ready_data is None:
            raise TimeoutError("observed wheel owner never wrote owner-ready.json")

        owner = ObservedWheelOwner(
            process_identity=ProcessIdentity(
                pid=int(ready_data["daemon_pid"]),
                started_at=str(ready_data["daemon_started_at"]),
            ),
            endpoint_port=int(ready_data["port"]),
            store_id=str(ready_data["store_id"]),
            writer_epoch=int(ready_data["writer_epoch"]),
            instance_id=str(ready_data["instance_id"]),
            module_file=str(ready_data["module_file"]),
            schema_sha256=str(ready_data["schema_sha256"]),
            evidence_dir=evidence_dir,
        )
        yield owner
    finally:
        with contextlib.suppress(OSError):
            if proc.stdin is not None:
                proc.stdin.close()
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5.0)
        if proc.stdout is not None:
            with contextlib.suppress(OSError):
                proc.stdout.read()
        if proc.stderr is not None:
            with contextlib.suppress(OSError):
                proc.stderr.read()


def verify_same_daemon(first: NativeConnectionProbe, second: NativeConnectionProbe) -> bool:
    """True iff both passed probes link distinct principals on one live daemon, store, epoch, and runtime."""
    from tests.support.inc2_native import ProbeValidationError, _all_passed_fields_present, _validate_probe_invariants

    for item in (first, second):
        try:
            _validate_probe_invariants(item)
        except ProbeValidationError:
            return False
        if item.status != "passed" or item.reason_code is not None or not _all_passed_fields_present(item):
            return False
        assert item.terminal_facts is not None and item.path_check is not None
        if not (
            item.terminal_facts.ready
            and item.terminal_facts.ok
            and item.terminal_facts.auth_granted
            and item.terminal_facts.response_flushed
            and item.terminal_facts.response_digest is not None
        ):
            return False
        if not (
            item.path_check.physical_root_ok
            and item.path_check.ancestors_ok
            and item.path_check.symlink_or_reparse_rejected
        ):
            return False

    assert first.daemon_process is not None and second.daemon_process is not None
    assert first.binding is not None and second.binding is not None
    assert first.token_context is not None and second.token_context is not None
    if (
        first.kind != second.kind
        or first.os != second.os
        or first.source_commit != second.source_commit
        or first.config_digest != second.config_digest
        or first.binding.environment != second.binding.environment
    ):
        return False
    if first.binding.principal_id == second.binding.principal_id:
        return False
    if first.token_context.credential_id == second.token_context.credential_id:
        return False

    return (
        first.daemon_process == second.daemon_process
        and first.binding.store_id == second.binding.store_id
        and first.binding.writer_epoch == second.binding.writer_epoch
        and first.binding.instance_id == second.binding.instance_id
    )


def _wheel_child_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--evidence-dir", required=True)
    ns = parser.parse_args(argv)
    stop = threading.Event()

    def _watch_stdin() -> None:
        try:
            while sys.stdin.buffer.read(1):
                pass
        except OSError:
            pass
        finally:
            stop.set()

    for sig_name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if isinstance(sig, signal.Signals):
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, lambda _s, _f: stop.set())

    threading.Thread(target=_watch_stdin, daemon=True).start()
    return run_observed_owner(Path(ns.config), Path(ns.evidence_dir), stop)


def _child_bootstrap() -> int:
    import superbrain

    if superbrain.__file__ is None:
        sys.stderr.write("wheel_check_failed_no_file\n")
        return 3
    mod_path = Path(superbrain.__file__).resolve()
    venv_path = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix or not mod_path.is_relative_to(venv_path):
        sys.stderr.write("wheel_check_failed_outside_venv\n")
        return 3

    from superbrain.core.wire import load_catalog

    _ = load_catalog().schema_sha256
    repo_root = str(Path(__file__).resolve().parents[2])
    if repo_root not in sys.path:
        sys.path.append(repo_root)

    from tests.support.inc2_native_owner import _wheel_child_main as entry

    return entry(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(_child_bootstrap())
