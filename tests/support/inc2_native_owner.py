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


def run_observed_owner(config_path: Path, evidence_dir: Path, stop: threading.Event) -> int:
    """Run the production owner loop via ``_explicit_owner_adapters`` and record sanitized call observations."""
    if not isinstance(config_path, Path) or not config_path.is_absolute():
        raise ValueError("absolute config_path required")
    if not isinstance(evidence_dir, Path) or not evidence_dir.is_absolute():
        raise ValueError("absolute evidence_dir required")

    import superbrain
    from superbrain.cli_api import _loopback_server
    from superbrain.composition import daemon_entry, owner_entry
    from superbrain.core.canonical import canonical_json, digest_bytes
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

    hook_lock = threading.Lock()
    pending_cmds: dict[int, tuple[str, dict[str, JsonValue] | None, str]] = {}
    flush_by_thread: dict[int, tuple[bool, str | None]] = {}
    ready_seen = False

    loopback_mod: Any = _loopback_server
    orig_read_cmd = loopback_mod.read_admitted_tool_command
    orig_write_json = loopback_mod.write_json_response
    orig_release = _loopback_server.LoopbackServer._release_owner_reply

    def _tap_read_cmd(
        ssl_sock: Any,
        reader: Any,
        ready: Ready,
        *,
        deadline_ns: int,
        monotonic_ns: Any,
    ) -> Any:
        cmd = orig_read_cmd(ssl_sock, reader, ready, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        if cmd is not None:
            scope_dict = cmd.selected_scope.to_dict() if cmd.selected_scope is not None else None
            with hook_lock:
                pending_cmds[id(ssl_sock)] = (str(cmd.tool), scope_dict, _utc_now_z())
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
            flush_by_thread[tid] = (status == 200, digest_bytes(body))

    def _tap_release(self: Any, ssl_sock: Any, reply: Any, tool_deadline_ns: int) -> None:
        with hook_lock:
            cmd_info = pending_cmds.pop(id(ssl_sock), None)
        tool_name = cmd_info[0] if cmd_info is not None else None
        selected_scope = cmd_info[1] if cmd_info is not None else None
        req_started_at = cmd_info[2] if cmd_info is not None else _utc_now_z()

        listen_host = "127.0.0.1"
        listen_port = 0
        peer_host = "127.0.0.1"
        peer_port = 0
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
        view = gate.current()
        grant_stamp = reply.grant_stamp
        stamp_ok = (
            grant_stamp is not None
            and view is not None
            and grant_stamp.identity == gate.identity
            and grant_stamp.generation == view.version
            and grant_stamp.trust_generation == view.auth.trust_generation
        )
        cred = (
            view.auth.credentials.get(grant_stamp.credential_id)
            if (grant_stamp is not None and view is not None)
            else None
        )
        cred_active = cred is not None and not cred.revoked
        principal_id = cred.principal.principal_id if cred is not None else None
        credential_id = grant_stamp.credential_id if grant_stamp is not None else None
        auth_matched = bool(stamp_ok and cred_active)

        tid = threading.get_ident()
        try:
            orig_release(self, ssl_sock, reply, tool_deadline_ns)
        finally:
            with hook_lock:
                flushed_status_ok, flushed_digest = flush_by_thread.pop(tid, (False, None))

        ended_at = _utc_now_z()
        env_ok = reply.envelope.get("ok") is True
        resp_digest = flushed_digest if flushed_digest is not None else digest_bytes(canonical_json(reply.envelope))
        ready_val = ready_seen
        if tool_name == "get_health" and isinstance(reply.envelope.get("data"), dict):
            ready_val = bool(reply.envelope["data"].get("ready") is True)

        if principal_id is not None and credential_id is not None and tool_name is not None:
            ident = gate.identity
            event_queue.put_nowait(
                {
                    "event": "owner_call",
                    "daemon_pid": daemon_pid,
                    "daemon_started_at": daemon_started_at,
                    "store_id": ident.store_id,
                    "writer_epoch": ident.writer_epoch,
                    "instance_id": ident.instance_id,
                    "principal_id": principal_id,
                    "credential_id": credential_id,
                    "tool_name": tool_name,
                    "ready": ready_val,
                    "auth_stamp_matched": auth_matched,
                    "response_flushed_ok": bool(flushed_status_ok and env_ok),
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

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        nonlocal ready_seen
        ready_seen = True
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

    loopback_mod.read_admitted_tool_command = _tap_read_cmd
    loopback_mod.write_json_response = _tap_write_json
    loopback_mod.LoopbackServer._release_owner_reply = _tap_release
    try:
        return int(daemon_entry.serve(cfg, os_=adapters, stop_event=stop, on_ready=_on_ready))
    finally:
        loopback_mod.read_admitted_tool_command = orig_read_cmd
        loopback_mod.write_json_response = orig_write_json
        loopback_mod.LoopbackServer._release_owner_reply = orig_release
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
                )
            )
            client_pid = row.get("client_pid")
            client_started = row.get("client_started_at")
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
    """True iff both passed probes belong to the same live daemon instance, epoch, and process identity."""
    from tests.support.inc2_native import ProbeValidationError, _all_passed_fields_present, _validate_probe_invariants

    for item in (first, second):
        try:
            _validate_probe_invariants(item)
        except ProbeValidationError:
            return False
        if item.status != "passed" or item.reason_code is not None or not _all_passed_fields_present(item):
            return False
        assert item.terminal_facts is not None
        if not (
            item.terminal_facts.ready
            and item.terminal_facts.ok
            and item.terminal_facts.auth_granted
            and item.terminal_facts.response_flushed
        ):
            return False

    assert first.daemon_process is not None and second.daemon_process is not None
    assert first.binding is not None and second.binding is not None
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
