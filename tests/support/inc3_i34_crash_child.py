"""Wheel-side owner driver for the SP1 increment 3 restore step-7 crash case (I3-4).

Run as ``<wheel venv python> -I inc3_i34_crash_child.py <mode> <abs_config_path> <abs_payload_path>``.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

_MODES = ("restore-store", "serve-recover")


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
    stat = Path("/proc/self/stat")
    if stat.exists():
        return stat.read_text(encoding="ascii").rpartition(")")[2].split()[19]
    import subprocess

    out = subprocess.run(["ps", "-o", "lstart=", "-p", str(os.getpid())], capture_output=True, text=True, check=True)
    return "_".join(out.stdout.split())


def _adapters_for(config_path: Path, clock: Any) -> tuple[Any, Any, Path]:
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import read_daemon_config
    from superbrain.core.ids import new_id

    base = os_adapters(clock=clock)
    cfg = read_daemon_config(config_path, base)
    scratch_base = cfg.data_root.parent / f".{cfg.data_root.name}.admit-{new_id()}"
    adapters = dataclasses.replace(
        base,
        traits=dataclasses.replace(base.traits, default_scratch_base=scratch_base),
    )
    return cfg, adapters, scratch_base


def _run_restore_store(config_path: Path, payload: dict[str, Any]) -> int:
    from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
    from superbrain.storage.layout import verify_existing_data_root
    from superbrain.storage.policy_store import PolicyStore
    from superbrain.storage.restore import restore_store
    from superbrain.storage.swap import recover_interrupted_swaps
    from superbrain.storage.writer import acquire_writer
    from tests.support.clock import FakeClock

    now = dt.datetime.fromisoformat(str(payload["now_iso"]))
    clock = FakeClock(now)
    cfg, adapters, scratch_base = _adapters_for(config_path, clock)
    root = verify_existing_data_root(cfg.data_root, adapters)
    lease = acquire_writer(root, adapters)
    policy: PolicyStore | None = None
    try:
        recover_interrupted_swaps(root, lease, adapters)
        policy = PolicyStore.open(root, lease, adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        report = restore_store(
            root,
            lease,
            adapters,
            Path(str(payload["backup_dir"])),
            policy,
            now,
            migrations=KERNEL_STORE_MIGRATIONS,
        )
        out = {"new_epoch": report.new_epoch, "replaced_dir": str(report.replaced_dir)}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
        return 0
    finally:
        if policy is not None and not policy.closed:
            policy.close()
        lease.release()
        shutil.rmtree(scratch_base, ignore_errors=True)


def _run_serve_recover(config_path: Path, payload: dict[str, Any]) -> int:
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.composition.daemon_entry import serve
    from superbrain.core.kernel import Ready
    from tests.support.clock import FakeClock

    clock = FakeClock(dt.datetime.fromisoformat(str(payload["now_iso"])))
    cfg, adapters, scratch_base = _adapters_for(config_path, clock)

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        shutil.rmtree(scratch_base, ignore_errors=True)
        _mark("READY", ready.endpoint.encode_canonical().decode("utf-8"))

    try:
        return serve(cfg, os_=adapters, clock=clock, on_ready=_on_ready)
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in _MODES or not Path(argv[2]).is_absolute() or not Path(argv[3]).is_absolute():
        _mark("DRIVER_ERROR", "usage")
        return 2

    import superbrain

    if superbrain.__file__ is None:
        _mark("DRIVER_ERROR", "superbrain.__file__ is None")
        return 3
    module = Path(superbrain.__file__).resolve()
    venv = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix or not module.is_relative_to(venv):
        _mark("DRIVER_ERROR", f"superbrain not from the wheel venv: {module} (prefix {venv})")
        return 3
    sys.path.append(str(Path(__file__).resolve().parents[2]))

    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.wire import load_catalog

    mode, config_path, payload_path = argv[1], Path(argv[2]), Path(argv[3])
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    _mark("PPID", str(os.getppid()))
    _mark("MODULE", str(module))
    _mark("SCHEMA", load_catalog().schema_sha256)
    _mark("ENTERED", f"{os.getpid()} {_process_start()}")
    try:
        if mode == "restore-store":
            return _run_restore_store(config_path, payload)
        return _run_serve_recover(config_path, payload)
    except BrainError as err:
        sys.stderr.write(f"{err.code.value}\n")
        sys.stderr.flush()
        return 1
    except OSError:
        sys.stderr.write(f"{ErrorCode.IO_ERROR.value}\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
