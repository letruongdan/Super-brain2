"""Wheel-side child driver for SP2-2 outbox and capture-ingest crash cases.

Run as ``<wheel venv python> -I sp2_crash_child.py <mode> <abs_target_path> <abs_payload_json>``.
Modes:
- ``outbox-enqueue``: opens ``OutboxSpool`` at ``abs_target_path`` and enqueues an event payload.
- ``capture-serve``: starts ``daemon_entry.serve_config_path`` for ``abs_target_path`` with the capture
  producer binding from ``abs_payload_json`` published to ``auth_gate`` prior to ``READY``.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

_MODES = ("outbox-enqueue", "capture-serve")


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
        return _run_capture_serve(target_path, payload)
    except BrainError as err:
        owner_entry._write_stderr(err.code.value)
        return 1
    except OSError:
        owner_entry._write_stderr(ErrorCode.IO_ERROR.value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
