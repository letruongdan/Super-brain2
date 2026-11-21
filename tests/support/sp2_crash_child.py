"""Wheel-side child driver for SP2-2 outbox and capture-ingest crash cases.

Run as ``<wheel venv python> -I sp2_crash_child.py <mode> <abs_target_path> <abs_payload_json>``.
Modes:
- ``outbox-enqueue``: opens ``OutboxSpool`` at ``abs_target_path`` and enqueues an event payload.
- ``capture-serve``: starts ``daemon_entry.serve_config_path`` for ``abs_target_path`` with the capture
  producer binding from ``abs_payload_json`` published to ``auth_gate`` prior to ``READY``.
- ``session-bind``: binds a ``session_id`` into ``PolicyStore`` and projects ``SessionStore`` at ``abs_target_path``.
- ``continuity-worker``: schedules/executes one ``continuity.refresh`` 3-phase cycle at ``abs_target_path``.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

_MODES = ("outbox-enqueue", "capture-serve", "session-bind", "continuity-worker")


class _StaticClock:
    def __init__(self, moment: dt.datetime) -> None:
        self._now = moment.astimezone(dt.UTC)

    def now(self) -> dt.datetime:
        return self._now


class _StaticMono:
    def __init__(self, start_ns: int = 1_000_000_000) -> None:
        self._now_ns = start_ns

    def monotonic_ns(self) -> int:
        return self._now_ns


def _mark(tag: str, value: str) -> None:
    sys.stderr.write(f"{tag} {value}\n")
    sys.stderr.flush()


def _process_start() -> str:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, *[ctypes.POINTER(wintypes.FILETIME)] * 4]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), *(ctypes.byref(t) for t in times)):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
        return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
    stat_path = Path("/proc/self/stat")
    if stat_path.exists():
        return stat_path.read_text(encoding="ascii").rpartition(")")[2].split()[19]
    import subprocess

    out = subprocess.run(["ps", "-o", "lstart=", "-p", str(os.getpid())], capture_output=True, text=True, check=True)
    return "_".join(out.stdout.split())


def _run_outbox_enqueue(outbox_dir: Path, payload: dict[str, Any]) -> int:
    from superbrain.ports.capture import CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    rec = CaptureEventRecord.from_dict(payload["event"])
    spool = OutboxSpool(outbox_dir)
    eid = spool.enqueue_event(rec)
    sys.stdout.write(json.dumps({"entry_id": eid}) + "\n")
    sys.stdout.flush()
    return 0


def _run_capture_serve(config_path: Path, payload: dict[str, Any]) -> int:
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.composition.daemon_entry import serve_config_path
    from superbrain.composition.owner_entry import _explicit_owner_adapters
    from superbrain.core.kernel import (
        CAPABILITY_CAPTURE_PRODUCER,
        CaptureProducerBinding,
        Ready,
    )

    _cfg, adapters, scratch_base = _explicit_owner_adapters(config_path)
    cred_id = str(payload["credential_id"])
    binding = CaptureProducerBinding(
        producer_stream=str(payload["producer_stream"]),
        repo_id=str(payload["repo_id"]),
        checkout_id=str(payload["checkout_id"]),
    )

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        shutil.rmtree(scratch_base, ignore_errors=True)

        def _publish() -> None:
            session: Any = loop._session
            assert session is not None
            rt = session._rt
            snap = rt.policy.snapshot()
            cap_rec = replace(
                snap.credentials[cred_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=binding,
            )
            new_snap = replace(snap, credentials={**snap.credentials, cred_id: cap_rec})
            session.auth_gate.publish(new_snap)

        loop.run_owner_action(_publish).result(timeout=5.0)
        _mark("READY", ready.endpoint.encode_canonical().decode("utf-8"))

    try:
        return serve_config_path(config_path, os_=adapters, on_ready=_on_ready)
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)


def _run_session_bind(data_root: Path, payload: dict[str, Any]) -> int:
    from superbrain.adapters.os import os_adapters
    from superbrain.composition.kernel_projections import kernel_store_extensions
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease

    moment = dt.datetime.fromisoformat(str(payload["now_iso"]))
    from superbrain.storage.sessions import SessionStore

    clock = _StaticClock(moment)
    adapters = os_adapters(clock=clock)
    handlers, kinds = kernel_store_extensions()
    rt = open_runtime_under_lease(
        admit_existing_pair(data_root, str(payload["store_id"]), adapters, purpose="serve"),
        handlers=handlers,
        kinds=kinds,
    )
    try:
        ss = SessionStore(rt.store, rt.policy)
        rec = ss.bind_session(
            principal_id=str(payload["principal_id"]),
            repo_id=str(payload["repo_id"]),
            checkout_id=str(payload["checkout_id"]),
            harness_id=str(payload.get("harness_id", "claude-code")),
            raw_session_id=str(payload["raw_session_id"]),
            now=clock.now(),
        )
        sys.stdout.write(json.dumps({"session_ref": rec.session_ref}) + "\n")
        sys.stdout.flush()
    finally:
        rt.close()
    return 0


def _run_continuity_worker(data_root: Path, payload: dict[str, Any]) -> int:
    from superbrain.adapters.os import os_adapters
    from superbrain.application.jobs import JobService
    from superbrain.composition.kernel_projections import kernel_store_extensions
    from superbrain.storage.idempotency import StagedKernelStore
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
    from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor

    moment = dt.datetime.fromisoformat(str(payload["now_iso"]))
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = _StaticClock(moment)
    mono = _StaticMono()
    adapters = os_adapters(clock=clock, monotonic=mono)
    handlers, kinds = kernel_store_extensions()
    rt = open_runtime_under_lease(
        admit_existing_pair(data_root, str(payload["store_id"]), adapters, purpose="serve"),
        handlers=handlers,
        kinds=kinds,
    )
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        kstore = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
        svc = JobService(kstore, kstore, rt.policy, clock, writer_epoch=rt.lease.epoch)
        if payload.get("recover_stale"):
            svc.recover(rt.lease.epoch)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        if payload.get("enqueue"):
            coord.enqueue_if_due(task_id=str(payload["task_id"]), now=clock.now())
        coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now())
        handoff = SessionStore(rt.store, rt.policy).read_task_handoff(str(payload["task_id"]))
        sys.stdout.write(json.dumps({"observed_ref": handoff.observed_ref if handoff else None}) + "\n")
        sys.stdout.flush()
    finally:
        executor.close(5.0)
        rt.close()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in _MODES:
        _mark("DRIVER_ERROR", "usage")
        return 2
    mode, target_raw, payload_raw = argv[1], argv[2], argv[3]
    target_path = Path(target_raw)
    payload_path = Path(payload_raw)
    if not target_path.is_absolute() or not payload_path.is_absolute():
        _mark("DRIVER_ERROR", "paths must be absolute")
        return 2

    import superbrain

    if superbrain.__file__ is None:
        _mark("DRIVER_ERROR", "superbrain.__file__ is None")
        return 3
    module = Path(superbrain.__file__).resolve()
    venv = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix or not module.is_relative_to(venv):
        _mark("DRIVER_ERROR", f"superbrain not from wheel venv: {module} (prefix {venv})")
        return 3
    sys.path.append(str(Path(__file__).resolve().parents[2]))

    from superbrain.composition import owner_entry
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.wire import load_catalog

    _mark("PPID", str(os.getppid()))
    _mark("MODULE", str(module))
    _mark("SCHEMA", load_catalog().schema_sha256)
    _mark("ENTERED", f"{os.getpid()} {_process_start()}")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    try:
        if mode == "outbox-enqueue":
            return _run_outbox_enqueue(target_path, payload)
        if mode == "session-bind":
            return _run_session_bind(target_path, payload)
        if mode == "continuity-worker":
            return _run_continuity_worker(target_path, payload)
        return _run_capture_serve(target_path, payload)
    except BrainError as err:
        owner_entry._write_stderr(err.code.value)
        return 1
    except OSError:
        owner_entry._write_stderr(ErrorCode.IO_ERROR.value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
