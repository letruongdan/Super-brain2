"""Wheel-side owner driver for the SP1 increment 3 ApplyJournal crash cases (I3-3).

Run as ``<wheel venv python> -I inc3_crash_child.py <mode> <abs_config_path> <abs_payload_path>``.
``-I`` keeps the checkout and ``PYTHONPATH`` off ``sys.path`` so ``superbrain`` must import from the
installed wheel before adding the repository root for ``tests.support`` helpers.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

_MODES = ("apply", "rollback-applied", "rollback-interrupted", "serve-recover", "serve-recover-twice")


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


def _parse_approval(raw: dict[str, Any]) -> Any:
    from superbrain.core._kernel_approval import (
        ApprovalAction,
        ApprovalMessage,
        RecoveryScope,
        RiskLevel,
        TargetFile,
    )
    from superbrain.core._kernel_base import ResourceDigest

    return ApprovalMessage(
        store_id=str(raw["store_id"]),
        owner_id=str(raw["owner_id"]),
        trust_generation=int(raw["trust_generation"]),
        action=ApprovalAction(str(raw["action"])),
        subject_id=str(raw["subject_id"]),
        subject_revision=int(raw["subject_revision"]),
        resource_digests=tuple(ResourceDigest(str(name), str(digest)) for name, digest in raw["resource_digests"]),
        target_files=tuple(
            TargetFile(
                root_path=str(tf["root_path"]),
                normalized_rel_path=str(tf["normalized_rel_path"]),
                parent_physical_id=str(tf["parent_physical_id"]),
                target_physical_id=tf["target_physical_id"],
                original_digest=tf["original_digest"],
                original_present=bool(tf["original_present"]),
            )
            for tf in raw["target_files"]
        ),
        risk_level=RiskLevel(str(raw["risk_level"])),
        risk_policy_version=int(raw["risk_policy_version"]),
        recovery_scope=RecoveryScope(str(raw["recovery_scope"])),
        nonce=str(raw["nonce"]),
        expires_at=dt.datetime.fromisoformat(str(raw["expires_at"])),
    )


def _adapters_for(config_path: Path, clock: Any | None) -> tuple[Any, Any, Path]:
    import dataclasses

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


def _run_journal_op(config_path: Path, mode: str, payload: dict[str, Any]) -> int:
    from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
    from superbrain.application.review_apply import ReviewApplyService
    from superbrain.composition.kernel_projections import kernel_store_extensions
    from superbrain.core._kernel_approval import ApprovalChannel
    from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
    from tests.support.clock import FakeClock

    clock = FakeClock(dt.datetime.fromisoformat(str(payload["now_iso"])))
    cfg, adapters, scratch_base = _adapters_for(config_path, clock)
    rt = None
    try:
        admitted = admit_existing_pair(cfg.data_root, cfg.expected_store_id, adapters, purpose="serve")
        handlers, kinds = kernel_store_extensions()
        rt = open_runtime_under_lease(admitted, handlers=handlers, kinds=kinds)
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, adapters),
            PolicyApplyAuthority(rt.policy),
            adapters,
            data_root=rt.root.root,
            home_dir=Path(str(payload["home_dir"])),
            config_merger=SharedConfigMergerAdapter(),
        )
        if mode == "apply":
            msg = _parse_approval(payload["approval"])
            journal = svc.apply_proposal(
                str(payload["proposal_id"]),
                approval=msg,
                signer_id=payload.get("signer_id"),
                channel=ApprovalChannel(str(payload["channel"])),
            )
        elif mode == "rollback-applied":
            msg = _parse_approval(payload["approval"])
            plan = svc.plan_rollback_targets(str(payload["proposal_id"]))
            journal = svc.rollback_applied_proposal(
                str(payload["proposal_id"]),
                approval=msg,
                signer_id=payload.get("signer_id"),
                channel=ApprovalChannel(str(payload["channel"])),
                plan=plan,
            )
        else:
            journal = svc.rollback_interrupted_journal(str(payload["journal_id"]))
        sys.stdout.write(json.dumps({"journal_id": journal.journal_id, "status": journal.status.value}) + "\n")
        sys.stdout.flush()
        return 0
    finally:
        if rt is not None:
            rt.close()
        shutil.rmtree(scratch_base, ignore_errors=True)


def _run_serve_recover(config_path: Path, payload: dict[str, Any]) -> int:
    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.composition.daemon_entry import serve
    from superbrain.core.kernel import Ready
    from tests.support.clock import FakeClock

    now_iso = payload.get("now_iso")
    clock = FakeClock(dt.datetime.fromisoformat(str(now_iso))) if now_iso else None
    cfg, adapters, scratch_base = _adapters_for(config_path, clock)

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        shutil.rmtree(scratch_base, ignore_errors=True)
        _mark("READY", ready.endpoint.encode_canonical().decode("utf-8"))

    try:
        return serve(cfg, os_=adapters, clock=clock, on_ready=_on_ready)
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)


def _rows(db_path: Path, scratch: Path, sql: str) -> list[tuple[object, ...]]:
    import contextlib

    from superbrain.storage.sqlite import open_readonly

    scratch.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(open_readonly(db_path, scratch_dir=scratch)) as db:
        return [tuple(r) for r in db.execute(sql)]


def raw_i33_policy(data_root: Path, scratch: Path) -> dict[str, list[tuple[object, ...]]]:
    from superbrain.storage.layout import DataRoot

    db = DataRoot.at(data_root).policy_db
    return {
        "grants": _rows(
            db,
            scratch,
            "SELECT grant_id, journal_id, recovery_scope, trust_generation, state, end_reason "
            "FROM recovery_grant ORDER BY rowid",
        ),
        "turns": _rows(
            db,
            scratch,
            "SELECT turn_id, journal_id, approval_id, direction, state FROM apply_turn_intent ORDER BY rowid",
        ),
    }


def raw_i33_store(data_root: Path, scratch: Path) -> dict[str, list[tuple[object, ...]]]:
    from superbrain.storage.layout import DataRoot

    db = DataRoot.at(data_root).store_db
    return {
        "proposals": _rows(
            db,
            scratch,
            "SELECT proposal_id, status, active_journal_id FROM p_proposals_proposals ORDER BY proposal_id",
        ),
        "journals": _rows(
            db,
            scratch,
            "SELECT journal_id, proposal_id, direction, status, grant_id FROM p_proposals_journals ORDER BY sequence",
        ),
        "manifests": _rows(
            db,
            scratch,
            "SELECT proposal_id, target_key_digest, slice_digest FROM p_proposals_manifests ORDER BY sequence",
        ),
    }


def _run_serve_recover_twice(config_path: Path, payload: dict[str, Any]) -> int:
    """Recover twice in one process: each ``serve`` stops cleanly from ``on_ready``; the second must change nothing."""
    import threading

    from superbrain.application.owner_loop import OwnerLoop
    from superbrain.composition.daemon_entry import serve
    from superbrain.core.kernel import Ready
    from tests.support.clock import FakeClock
    from tests.support.inc2_cli import is_writer_lock_held

    clock = FakeClock(dt.datetime.fromisoformat(str(payload["now_iso"])))
    cfg, adapters, scratch_base = _adapters_for(config_path, clock)
    ro_scratch, watched = Path(str(payload["ro_scratch"])), [Path(p) for p in payload["watch_files"]]

    def _state() -> tuple[object, ...]:
        files = [p.read_bytes() if p.exists() else None for p in watched]
        return (raw_i33_policy(cfg.data_root, ro_scratch), raw_i33_store(cfg.data_root, ro_scratch), files)

    def _recover(tag: str) -> int:
        stop = threading.Event()

        def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
            shutil.rmtree(scratch_base, ignore_errors=True)
            _mark(tag, ready.endpoint.encode_canonical().decode("utf-8"))
            stop.set()

        try:
            rc = serve(cfg, os_=adapters, clock=clock, stop_event=stop, on_ready=_on_ready)
        finally:
            shutil.rmtree(scratch_base, ignore_errors=True)
        if rc == 0 and is_writer_lock_held(cfg.data_root) is not False:
            _mark("DRIVER_ERROR", f"writer lock still held after {tag}")
            return 4
        return rc

    rc = _recover("READY_1")
    if rc != 0:
        return rc
    after_first = _state()
    rc = _recover("READY_2")
    if rc == 0 and _state() != after_first:
        _mark("DRIVER_ERROR", "second recovery changed policy/store/files state")
        return 5
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
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    _mark("PPID", str(os.getppid()))
    _mark("MODULE", str(module))
    _mark("SCHEMA", load_catalog().schema_sha256)
    _mark("ENTERED", f"{os.getpid()} {_process_start()}")
    try:
        if mode == "serve-recover":
            return _run_serve_recover(config_path, payload)
        if mode == "serve-recover-twice":
            return _run_serve_recover_twice(config_path, payload)
        return _run_journal_op(config_path, mode, payload)
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
