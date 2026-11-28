"""Spec 7.1: past the hook's hard cap the hook exits successfully **and records a CaptureGap**.

The cap is the harness's view: it is counted from process entry, and the fallback gap must be durable before the
watchdog ends the process. These tests shrink the cap so the stall is deterministic.
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.composition import hook_entry
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OUTBOX_RECORD_GAP, CaptureEventRecord
from superbrain.storage.outbox import OutboxSpool

_CAP_NS = 1_200_000_000  # room for a real (macOS F_FULLFSYNC) gap write after the simulated slow one
_SLOW_GAP_WRITE_S = 0.2


def _event_stdin() -> bytes:
    rec = CaptureEventRecord(
        event_id="ev-hook-deadline-1", producer_stream="stream-hook-deadline", sequence=1, harness_id="claude-code",
        kind="command_result", recorded_at="2026-11-28T10:00:00Z", payload={"cmd": "pytest"},
    )
    return json.dumps(rec.to_dict()).encode("utf-8")


class _StallingSpool(OutboxSpool):
    """The event write stalls until its deadline (slow disk) and fails like the real deadline check does; the gap
    write is slow too."""

    def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
        assert deadline_ns is not None
        time.sleep(max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9))
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def enqueue_fallback_gap(self, **kwargs: Any) -> Any:
        time.sleep(_SLOW_GAP_WRITE_S)  # a slow fsync: the gap needs real room, and must still land before the watchdog
        return super().enqueue_fallback_gap(**kwargs)


def _run_main(
    monkeypatch: pytest.MonkeyPatch, outbox: Path, *, start_ns: int | None = None, slow_log_s: float = 0.0
) -> dict[str, Any]:
    perms = os_adapters().permissions
    seen: dict[str, Any] = {"exit_called": False, "gap_at_exit": None}

    def _gaps() -> list[Any]:
        spool = OutboxSpool(outbox, permissions=perms)
        return [e for e in spool.read_pending(limit=10) if e.record_kind == OUTBOX_RECORD_GAP]

    def _fake_exit(code: int) -> None:
        seen["exit_called"] = True
        seen["gap_at_exit"] = _gaps()  # what a killed process would leave behind
        raise SystemExit(code)

    monkeypatch.setattr(hook_entry, "HOOK_HARD_CAP_NS", _CAP_NS)
    monkeypatch.setattr(hook_entry, "_hard_exit", _fake_exit)
    monkeypatch.setattr(hook_entry, "_make_spool", lambda d, _f: _StallingSpool(d, permissions=perms))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(_event_stdin())))
    argv = ["--outbox", str(outbox), "--harness", "claude-code"]
    if slow_log_s:
        real_log = hook_entry._write_static_log

        def _slow_log(*args: Any, **kwargs: Any) -> None:
            time.sleep(slow_log_s)  # a contended or slow diagnostic log; the outbox itself is healthy
            real_log(*args, **kwargs)

        monkeypatch.setattr(hook_entry, "_write_static_log", _slow_log)
        argv += ["--log", str(outbox.parent / "hook.log")]
    t0 = time.monotonic_ns()
    try:
        rc = hook_entry.main(argv) if start_ns is None else hook_entry.main(argv, start_ns=start_ns)
    except SystemExit as stop:
        rc = int(stop.code or 0)
    seen["rc"] = rc
    seen["elapsed_ns"] = time.monotonic_ns() - t0
    seen["gaps_after"] = _gaps()
    return seen


def test_stalled_outbox_write_leaves_a_durable_capture_gap_before_the_hook_ends(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _run_main(monkeypatch, trusted_tmp / "outbox")
    assert seen["rc"] == 0
    # a watchdog exit kills the process: the gap must already be durable at that moment, not written afterwards
    gaps = seen["gap_at_exit"] if seen["exit_called"] else seen["gaps_after"]
    assert gaps is not None and len(gaps) == 1, seen
    assert gaps[0].sequence == 1
    assert seen["elapsed_ns"] < _CAP_NS


def test_the_hard_cap_counts_from_process_entry(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # interpreter start and imports already used almost all of the cap before main() ran
    started = time.monotonic_ns() - (_CAP_NS - 100_000_000)
    seen = _run_main(monkeypatch, trusted_tmp / "outbox", start_ns=started)
    assert seen["rc"] == 0
    total_ns = time.monotonic_ns() - started
    assert total_ns < _CAP_NS + 50_000_000, total_ns  # the harness sees the cap, not cap + startup


def test_a_slow_diagnostic_log_cannot_spend_the_capture_gap_reserve(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _run_main(monkeypatch, trusted_tmp / "outbox", slow_log_s=0.35)
    assert seen["rc"] == 0
    gaps = seen["gap_at_exit"] if seen["exit_called"] else seen["gaps_after"]
    assert gaps is not None and len(gaps) == 1, seen  # the gap is written before the log, not after it
