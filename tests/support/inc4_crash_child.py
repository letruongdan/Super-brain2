"""Wheel-side owner driver for SP1 increment 4 ``brain doctor --fix`` crash cases (I4-4).

Run as ``<wheel venv python> -I inc4_crash_child.py <mode> <abs_config_path> <abs_payload_path>``.
``-I`` keeps the checkout and ``PYTHONPATH`` off ``sys.path`` so ``superbrain`` must import from the
installed wheel before adding the repository root for ``tests.support`` helpers.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_MODES = ("doctor-fix-offline",)


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


def _run_doctor_fix_offline(config_path: Path, payload: dict[str, Any]) -> int:
    import threading

    import superbrain.composition.daemon_entry as daemon_entry
    import superbrain.composition.doctor_entry as doctor_entry
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import read_daemon_config
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.core.kernel import Ready

    adapters = os_adapters()
    cfg = read_daemon_config(config_path, adapters)
    stop_event = threading.Event()
    fix_rc_box: list[int] = []

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        def _runner() -> None:
            try:
                args = ["doctor", "--fix"]
                profile_raw = payload.get("profile_path")
                if isinstance(profile_raw, str) and profile_raw:
                    args.extend(["--profile", profile_raw])
                else:
                    args.extend(["--config", str(config_path)])
                checkout_raw = payload.get("checkout_root")
                if isinstance(checkout_raw, str) and checkout_raw:
                    args.extend(["--checkout", checkout_raw])
                args.append("--json")
                rc = int(doctor_entry.main(args))
                fix_rc_box.append(rc)
            finally:
                stop_event.set()

        t = threading.Thread(target=_runner, daemon=True)
        t.start()

    rc = daemon_entry.serve(cfg, os_=adapters, stop_event=stop_event, on_ready=_on_ready)
    if fix_rc_box:
        return fix_rc_box[0]
    return rc


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
    raw_payload = json.loads(payload_path.read_text(encoding="utf-8"))
    if not isinstance(raw_payload, dict):
        _mark("DRIVER_ERROR", "payload must be a JSON object")
        return 2

    _mark("PPID", str(os.getppid()))
    _mark("MODULE", str(module))
    _mark("SCHEMA", load_catalog().schema_sha256)
    _mark("ENTERED", f"{os.getpid()} {_process_start()}")
    try:
        if mode == "doctor-fix-offline":
            return _run_doctor_fix_offline(config_path, raw_payload)
        _mark("DRIVER_ERROR", f"unknown mode: {mode}")
        return 2
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
