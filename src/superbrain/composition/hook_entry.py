"""Thin fail-open, bounded capture hook entrypoint (target < 100 ms warm, 2 s hard cap, always exits 0)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.domain.capture.envelope import normalize_capture_record
from superbrain.domain.capture.privacy_gate import CapturePrivacyGate
from superbrain.ports.capture import (
    HOOK_HARD_CAP_NS,
    CaptureEventRecord,
    ProducerCaptureGap,
)
from superbrain.storage.outbox import OutboxSpool

_MAX_STDIN_BYTES = 2 * 1024 * 1024


def _write_static_log(log_path: Path | None, *, phase: str, code: str) -> None:
    if log_path is None:
        return
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"phase={phase} error.code={code}\n")
    except OSError:
        pass


def _make_spool(outbox_dir: Path, spool_factory: Callable[[Path], OutboxSpool] | None) -> OutboxSpool:
    if spool_factory is not None:
        return spool_factory(outbox_dir)
    return OutboxSpool(outbox_dir, file_lock=OUTBOX_FILE_LOCK)


def run_hook(
    raw_bytes: bytes,
    *,
    outbox_dir: Path,
    log_path: Path | None = None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    spool_factory: Callable[[Path], OutboxSpool] | None = None,
    cap_ns: int = HOOK_HARD_CAP_NS,
    default_harness_id: str | None = None,
    raw_session_id: str | None = None,
) -> int:
    """Validate, privacy-filter, and durably enqueue a capture record; always returns ``0``."""
    start_ns = int(monotonic_ns())
    deadline_ns = start_ns + cap_ns
    normalized: CaptureEventRecord | ProducerCaptureGap | None = None
    try:
        if not isinstance(raw_bytes, bytes) or len(raw_bytes) > _MAX_STDIN_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if int(monotonic_ns()) >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        try:
            text = raw_bytes.decode("utf-8", errors="strict")
            parsed: JsonValue = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        normalized = normalize_capture_record(parsed, default_harness_id=default_harness_id)
        if int(monotonic_ns()) >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        if isinstance(normalized, ProducerCaptureGap):
            spool = _make_spool(outbox_dir, spool_factory)
            spool.enqueue_gap(normalized, deadline_ns=deadline_ns)
            return 0

        gate = CapturePrivacyGate(PrivacyFilter(monotonic_ns=monotonic_ns), monotonic_ns=monotonic_ns)
        sanitized = gate.sanitize_event(
            normalized,
            raw_session_id=raw_session_id,
            deadline_ns=deadline_ns,
        )
        spool = _make_spool(outbox_dir, spool_factory)
        spool.enqueue_event(sanitized, deadline_ns=deadline_ns)
        return 0
    except BrainError as err:
        _write_static_log(log_path, phase="hook", code=err.code.value)
        if err.code in (ErrorCode.DEADLINE_EXCEEDED, ErrorCode.STORAGE_FULL) and isinstance(
            normalized, CaptureEventRecord
        ):
            reason = "hook_timeout" if err.code is ErrorCode.DEADLINE_EXCEEDED else "outbox_full"
            duration_ms = max(0, (int(monotonic_ns()) - start_ns) // 1_000_000)
            gap = ProducerCaptureGap(
                gap_id=f"gap-{new_id()}",
                producer_stream=normalized.producer_stream,
                sequence=normalized.sequence,
                reason=reason,
                recorded_at=normalized.recorded_at,
                estimated_count=1,
                duration_ms=duration_ms,
            )
            try:
                spool = _make_spool(outbox_dir, spool_factory)
                spool.enqueue_gap(gap)
            except BrainError as gap_err:
                _write_static_log(log_path, phase="hook_gap", code=gap_err.code.value)
            except Exception:  # noqa: BLE001
                _write_static_log(log_path, phase="hook_gap", code=ErrorCode.IO_ERROR.value)
        return 0
    except Exception:  # noqa: BLE001
        _write_static_log(log_path, phase="hook", code=ErrorCode.INTEGRITY_FAILURE.value)
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for ``python -I -m superbrain.composition.hook_entry``."""
    parser = argparse.ArgumentParser(description="Bounded Super-brain2 capture hook entry point")
    parser.add_argument("--outbox", required=True, type=Path, help="Local outbox spool directory")
    parser.add_argument("--log", default=None, type=Path, help="Optional static diagnostic log file")
    parser.add_argument("--harness", default=None, help="Default harness_id when omitted by stdin payload")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        raw_bytes = sys.stdin.buffer.read(_MAX_STDIN_BYTES + 1)
    except OSError:
        _write_static_log(args.log, phase="hook_stdin", code=ErrorCode.IO_ERROR.value)
        return 0
    return run_hook(
        raw_bytes,
        outbox_dir=args.outbox,
        log_path=args.log,
        default_harness_id=args.harness,
    )


if __name__ == "__main__":
    raise SystemExit(main())
