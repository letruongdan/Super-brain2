"""Wheel-side owner driver for the SP1 increment 2 Task 8 crash cases.

Run as ``<wheel venv python> -I inc2_t8_child.py <serve|serve-fixture|migrate> <absolute DaemonConfig path>``.
``-I`` keeps the checkout and ``PYTHONPATH`` off ``sys.path``, so ``superbrain`` is imported from the installed wheel;
the driver checks that ``superbrain.__file__`` lies inside the running venv before it adds the repository (test
support) path.

Channels: stdout carries only what the owner CLI prints (``migrate`` envelope, nothing for ``serve``). Control markers
go to stderr, one per line, next to the owner's own static error code and ``CRASHPOINT_HIT``:

- ``PPID <pid>``: the parent PID (on Windows the venv ``python.exe`` redirector is a separate launcher process).
- ``MODULE <abs path>``: resolved ``superbrain.__file__`` recorded before adding the test-support path.
- ``SCHEMA <sha256>``: the digest of the packaged ``mcp-tools-v2.json`` catalog the wheel loaded.
- ``ENTERED <pid> <start>``: this interpreter's real PID and process start time, printed before the owner operation.
- ``READY <endpoint canonical JSON>``: ``serve`` modes only, from ``on_ready`` after the endpoint was published.

``serve`` uses the owner CLI's composition (``owner_entry._explicit_owner_adapters`` +
``daemon_entry.serve_config_path``) with an ``on_ready`` that also prints ``READY``; ``migrate`` calls
``owner_entry.main`` exactly as ``brain migrate`` does. ``serve-fixture`` is ``serve`` with the durable test domain of
``tests/support/inc2_t8_domain.py``: the store opens with the fixture projections and a ``FixtureDomainProxy`` is bound
on the owner thread in ``before_job_recover``. Fault injection stays the product's own ``SUPERBRAIN_CRASHPOINT``
environment hook; the driver adds none.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

_MODES = ("serve", "serve-fixture", "migrate", "serve-jobs", "job-operation", "revoke-fixture")


def _mark(tag: str, value: str) -> None:
    sys.stderr.write(f"{tag} {value}\n")
    sys.stderr.flush()


def _process_start() -> str:
    """The OS start time of this process: FILETIME on Windows, boot ticks on Linux, ``ps`` lstart elsewhere."""
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


def _serve(config_path: Path, *, mode: str, args: Sequence[str]) -> int:
    import shutil

    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.composition.daemon_entry import serve_config_path
    from superbrain.composition.owner_entry import _explicit_owner_adapters
    from superbrain.core.kernel import Ready

    cfg, adapters, scratch_base = _explicit_owner_adapters(config_path)
    stop = threading.Event()

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        shutil.rmtree(scratch_base, ignore_errors=True)
        loop.wait_doctor_settled(timeout=5.0)
        if mode == "revoke-fixture":
            from tests.support.inc2_t8_job_child import revoke_on_owner

            revoke_on_owner(loop, cfg, args, _mark)
            stop.set()
        else:
            _mark("READY", ready.endpoint.encode_canonical().decode("utf-8"))

    try:
        if mode == "serve-jobs":
            from tests.support.inc2_t8_job_child import serve_claim

            return serve_claim(config_path, adapters, _mark)
        if mode == "job-operation":
            from tests.support.inc2_t8_job_child import operate_job

            return operate_job(cfg, adapters, args, _mark)
        if mode == "serve":
            return serve_config_path(config_path, os_=adapters, on_ready=_on_ready)

        from tests.support.inc2_t8_domain import FixtureDomainProxy, fixture_hooks, use_fixture_store_extensions

        use_fixture_store_extensions()
        proxy = FixtureDomainProxy()
        hooks = fixture_hooks(proxy, monotonic_ns=adapters.monotonic.monotonic_ns)
        # No job handlers: the template's queued jobs must not be claimed while a request-path crash
        # oracle compares durable state (job claiming is covered by ``serve-jobs``).
        return serve_config_path(
            config_path,
            os_=adapters,
            on_ready=_on_ready,
            stop_event=stop,
            domain=proxy,
            hooks=hooks,
            job_handlers={},
        )
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in _MODES or not Path(argv[2]).is_absolute():
        _mark("DRIVER_ERROR", "usage")
        return 2
    if len(argv) != 3 and argv[1] not in {"job-operation", "revoke-fixture"}:
        _mark("DRIVER_ERROR", "unexpected operation arguments")
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
    sys.path.append(str(Path(__file__).resolve().parents[2]))  # test support path, only after the wheel check

    from superbrain.composition import owner_entry
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.wire import load_catalog

    mode, config_path = argv[1], Path(argv[2])
    _mark("PPID", str(os.getppid()))
    _mark("MODULE", str(module))
    _mark("SCHEMA", load_catalog().schema_sha256)
    _mark("ENTERED", f"{os.getpid()} {_process_start()}")
    if mode == "migrate":
        return owner_entry.main(["migrate", "--offline", "--config", str(config_path)])
    try:  # the same mapping as owner_entry.main
        return _serve(config_path, mode=mode, args=argv[3:])
    except BrainError as err:
        owner_entry._write_stderr(err.code.value)
        return 1
    except OSError:
        owner_entry._write_stderr(ErrorCode.IO_ERROR.value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
