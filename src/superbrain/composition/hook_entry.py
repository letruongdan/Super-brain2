"""Thin fail-open, bounded capture hook entrypoint (target < 100 ms warm, 2 s hard cap, always exits 0)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from superbrain.adapters.os import os_adapters
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
    default_outbox_dir_renamer,
)
from superbrain.storage._outbox_io import (
    _O_BINARY,
    _O_NOFOLLOW,
    ensure_dir_tree_atomic,
    ensure_secure_regular_file_atomic,
    reject_links_upward,
    thread_lock_for,
    write_all_fd,
)
from superbrain.storage.outbox import OutboxSpool

_MAX_STDIN_BYTES = 2 * 1024 * 1024


def _write_static_log(log_path: Path | None, *, phase: str, code: str) -> None:
    if log_path is None:
        return
    try:
        resolved = log_path if log_path.is_absolute() else log_path.absolute()
        reject_links_upward(resolved)
        perms = os_adapters().permissions
        renamer = default_outbox_dir_renamer()
        with thread_lock_for(resolved):
            ensure_dir_tree_atomic(resolved.parent, perms, renamer, verify_existing=False)
            ensure_secure_regular_file_atomic(resolved, perms)
            fd = os.open(resolved, os.O_WRONLY | os.O_APPEND | _O_BINARY | _O_NOFOLLOW, 0o600)
            try:
                write_all_fd(fd, f"phase={phase} error.code={code}\n".encode())
            finally:
                os.close(fd)
    except (OSError, BrainError):
        pass


def _make_spool(outbox_dir: Path, spool_factory: Callable[[Path], OutboxSpool] | None) -> OutboxSpool:
    if spool_factory is not None:
        return spool_factory(outbox_dir)
    return OutboxSpool(outbox_dir, permissions=os_adapters().permissions, file_lock=OUTBOX_FILE_LOCK)


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
    if type(cap_ns) is not int or cap_ns <= 0:
        _write_static_log(log_path, phase="hook", code=ErrorCode.INVALID_INPUT.value)
        return 0
    hard_deadline_ns = start_ns + cap_ns
    reserve_ns = min(max(1, cap_ns // 10), 50_000_000)
    work_deadline_ns = start_ns + max(1, cap_ns - reserve_ns)
    normalized: CaptureEventRecord | ProducerCaptureGap | None = None
    try:
        if not isinstance(raw_bytes, bytes) or len(raw_bytes) > _MAX_STDIN_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if int(monotonic_ns()) >= work_deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        try:
            text = raw_bytes.decode("utf-8", errors="strict")
            parsed: JsonValue = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        normalized = normalize_capture_record(parsed, default_harness_id=default_harness_id)
        if int(monotonic_ns()) >= work_deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        gate = CapturePrivacyGate(PrivacyFilter(monotonic_ns=monotonic_ns), monotonic_ns=monotonic_ns)
        if isinstance(normalized, ProducerCaptureGap):
            validated_gap = gate.validate_gap(
                normalized,
                raw_session_id=raw_session_id,
                deadline_ns=work_deadline_ns,
            )
            spool = _make_spool(outbox_dir, spool_factory)
            spool.enqueue_gap(validated_gap, deadline_ns=work_deadline_ns)
            return 0

        sanitized = gate.sanitize_event(
            normalized,
            raw_session_id=raw_session_id,
            deadline_ns=work_deadline_ns,
        )
        spool = _make_spool(outbox_dir, spool_factory)
        spool.enqueue_event(sanitized, deadline_ns=work_deadline_ns)
        return 0
    except BrainError as err:
        _write_static_log(log_path, phase="hook", code=err.code.value)
        raw_ok = raw_session_id is None or (
            isinstance(raw_session_id, str)
            and isinstance(normalized, CaptureEventRecord)
            and raw_session_id not in normalized.producer_stream
        )
        cur_ns = int(monotonic_ns())
        if (
            err.code in (ErrorCode.DEADLINE_EXCEEDED, ErrorCode.STORAGE_FULL)
            and isinstance(normalized, CaptureEventRecord)
            and raw_ok
            and cur_ns < hard_deadline_ns
        ):
            reason = "hook_timeout" if err.code is ErrorCode.DEADLINE_EXCEEDED else "outbox_full"
            duration_ms = max(0, (cur_ns - start_ns) // 1_000_000)
            gap = ProducerCaptureGap(
                gap_id=f"gap-{new_id()}",
                producer_stream=normalized.producer_stream,
                sequence=normalized.sequence,
                reason=reason,
                recorded_at=normalized.recorded_at,
                estimated_count=1,
                duration_ms=duration_ms,
            )
            gap_deadline_ns = min(hard_deadline_ns, cur_ns + reserve_ns)
            try:
                spool = _make_spool(outbox_dir, spool_factory)
                spool.enqueue_gap(gap, deadline_ns=gap_deadline_ns)
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
