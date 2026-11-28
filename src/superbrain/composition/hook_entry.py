"""Thin fail-open, bounded capture hook entrypoint (target < 100 ms warm, 2 s hard cap, always exits 0)."""

# ruff: noqa: E402 - the process-entry timestamp must precede the imports whose time it counts
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time

_PROCESS_T0_NS = time.monotonic_ns()  # as close to process entry as Python allows: the cap is the harness's view
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import HOOK_HARD_CAP_NS, CaptureEventRecord, ProducerCaptureGap

if TYPE_CHECKING:
    from superbrain.storage.outbox import OutboxSpool

_MAX_STDIN_BYTES = 2 * 1024 * 1024


def _write_static_log(
    log_path: Path | None,
    *,
    phase: str,
    code: str,
    timeout_s: float = 0.25,
) -> None:
    if log_path is None:
        return
    try:
        from superbrain.adapters.os.physical_fs import atomic_append_no_follow
        from superbrain.ports.capture import default_outbox_dir_renamer
        from superbrain.storage._outbox_io import (
            FOREIGN_STAGE_MARKER,
            ensure_dir_tree_atomic,
            ensure_secure_regular_file_atomic,
            reject_links_upward,
            thread_lock_for,
        )

        resolved = log_path if log_path.is_absolute() else log_path.absolute()
        reject_links_upward(resolved)
        perms = os_adapters().permissions
        renamer = default_outbox_dir_renamer()
        with thread_lock_for(resolved):
            # The log may sit inside a spool; its stages must not look like spool stages to a sweep.
            ensure_dir_tree_atomic(resolved.parent, perms, renamer, verify_existing=False,
                                   stage_marker=FOREIGN_STAGE_MARKER)
            ensure_secure_regular_file_atomic(resolved, perms, stage_marker=FOREIGN_STAGE_MARKER)
            atomic_append_no_follow(resolved, f"phase={phase} error.code={code}\n".encode(), timeout_s=timeout_s)
    except (OSError, BrainError):
        pass


def _make_spool(outbox_dir: Path, spool_factory: Callable[[Path], OutboxSpool] | None) -> OutboxSpool:
    if spool_factory is not None:
        return spool_factory(outbox_dir)
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

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
    checkout_root: Path | None = None,
    profile_path: Path | None = None,
    producer_stream: str | None = None,
    sequence: int | None = None,
) -> int:
    """Validate, privacy-filter, and durably enqueue a capture record; always returns ``0``."""
    start_ns = int(monotonic_ns())
    if type(cap_ns) is not int or cap_ns <= 0:
        _write_static_log(log_path, phase="hook", code=ErrorCode.INVALID_INPUT.value)
        return 0
    hard_deadline_ns = start_ns + cap_ns
    # the fallback CaptureGap needs room for its own durable write once the work deadline passes (spec 7.1)
    reserve_ns = max(1, min(cap_ns // 2, _GAP_RESERVE_NS))
    work_deadline_ns = start_ns + max(1, cap_ns - reserve_ns)
    normalized: CaptureEventRecord | ProducerCaptureGap | None = None
    slot_known = False  # True once ``normalized.sequence`` is the slot the spool assigned or the producer chose
    slot_dedup_key: str | None = None
    effective_raw_sid = raw_session_id
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
        is_native = isinstance(parsed, dict) and (
            checkout_root is not None
            or profile_path is not None
            or any(k in parsed for k in ("hook_event_name", "event_type", "transcript_path"))
            or ("cwd" in parsed and any(k in parsed for k in ("event_name", "type", "event")))
        )
        if is_native:
            assert isinstance(parsed, dict)
            from superbrain.composition._hook_adapter_bridge import prepare_native_hook

            prep = prepare_native_hook(
                parsed,
                os_=os_adapters(),
                default_harness_id=default_harness_id,
                checkout_root=checkout_root,
                profile_path=profile_path,
                producer_stream=producer_stream,
                sequence=sequence,
                raw_session_id=raw_session_id,
            )
            effective_raw_sid = prep.raw_session_id
            if prep.build_record is None:
                _write_static_log(log_path, phase="hook_adapter", code=prep.skip_code or "unavailable")
                return 0
            slot_dedup_key = prep.dedup_key
            if int(monotonic_ns()) >= work_deadline_ns:
                normalized = prep.build_record(
                    prep.explicit_sequence if prep.explicit_sequence is not None else 1,
                    prep.explicit_event_id or f"ev-{new_id()}",
                    prep.fallback_recorded_at,
                )
                slot_known = prep.explicit_sequence is not None
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            from superbrain.application.privacy import PrivacyFilter
            from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

            gate = CapturePrivacyGate(PrivacyFilter(monotonic_ns=monotonic_ns), monotonic_ns=monotonic_ns)
            if parsed.get("record_kind") == "capture_gap":
                gap_rec = prep.build_record(
                    prep.explicit_sequence if prep.explicit_sequence is not None else 1,
                    prep.explicit_event_id or f"gap-{new_id()}",
                    prep.fallback_recorded_at,
                )
                assert isinstance(gap_rec, ProducerCaptureGap)
                normalized = gap_rec
                validated_gap = gate.validate_gap(
                    gap_rec,
                    raw_session_id=effective_raw_sid,
                    deadline_ns=work_deadline_ns,
                )
                spool = _make_spool(outbox_dir, spool_factory)
                spool.enqueue_gap(validated_gap, deadline_ns=work_deadline_ns)
                return 0

            def _build_sanitized(seq_val: int, ev_id_val: str, rec_at_val: str) -> CaptureEventRecord:
                nonlocal normalized, slot_known
                assert prep.build_record is not None
                built = prep.build_record(seq_val, ev_id_val, rec_at_val)
                assert isinstance(built, CaptureEventRecord)
                normalized = built
                slot_known = True
                return gate.sanitize_event(
                    built,
                    raw_session_id=effective_raw_sid,
                    deadline_ns=work_deadline_ns,
                )

            spool = _make_spool(outbox_dir, spool_factory)
            spool.enqueue_hook_event(
                producer_stream=prep.producer_stream,
                build_event=_build_sanitized,
                explicit_sequence=prep.explicit_sequence,
                explicit_event_id=prep.explicit_event_id,
                dedup_key=prep.dedup_key,
                fallback_recorded_at=prep.fallback_recorded_at,
                deadline_ns=work_deadline_ns,
            )
            return 0

        from superbrain.application.privacy import PrivacyFilter
        from superbrain.domain.capture.envelope import normalize_capture_record
        from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

        gate = CapturePrivacyGate(PrivacyFilter(monotonic_ns=monotonic_ns), monotonic_ns=monotonic_ns)
        normalized = normalize_capture_record(parsed, default_harness_id=default_harness_id)
        slot_known = True
        if int(monotonic_ns()) >= work_deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        if isinstance(normalized, ProducerCaptureGap):
            validated_gap = gate.validate_gap(
                normalized,
                raw_session_id=effective_raw_sid,
                deadline_ns=work_deadline_ns,
            )
            spool = _make_spool(outbox_dir, spool_factory)
            spool.enqueue_gap(validated_gap, deadline_ns=work_deadline_ns)
            return 0

        sanitized = gate.sanitize_event(
            normalized,
            raw_session_id=effective_raw_sid,
            deadline_ns=work_deadline_ns,
        )
        spool = _make_spool(outbox_dir, spool_factory)
        spool.enqueue_event(sanitized, deadline_ns=work_deadline_ns)
        return 0
    except BrainError as err:
        _write_static_log(log_path, phase="hook", code=err.code.value)
        raw_ok = effective_raw_sid is None or (
            isinstance(effective_raw_sid, str)
            and isinstance(normalized, CaptureEventRecord)
            and effective_raw_sid not in normalized.producer_stream
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
            event: CaptureEventRecord = normalized
            try:
                spool = _make_spool(outbox_dir, spool_factory)
                # One spool lock covers the slot decision, its reservation and the gap write.
                written = spool.enqueue_fallback_gap(
                    producer_stream=event.producer_stream, sequence=event.sequence if slot_known else None,
                    dedup_key=slot_dedup_key, reason=reason, recorded_at=event.recorded_at, duration_ms=duration_ms,
                    deadline_ns=hard_deadline_ns,
                )
                if written is None:
                    _write_static_log(log_path, phase="hook_gap", code=ErrorCode.IDEMPOTENCY_CONFLICT.value)
            except BrainError as gap_err:
                _write_static_log(log_path, phase="hook_gap", code=gap_err.code.value)
            except Exception:  # noqa: BLE001
                _write_static_log(log_path, phase="hook_gap", code=ErrorCode.IO_ERROR.value)
        return 0
    except Exception:  # noqa: BLE001
        _write_static_log(log_path, phase="hook", code=ErrorCode.INTEGRITY_FAILURE.value)
        return 0


def main(argv: Sequence[str] | None = None, *, start_ns: int | None = None) -> int:
    """CLI entry point for ``python -I -m superbrain.composition.hook_entry``.

    ``start_ns`` is the process entry time; the hard cap counts from it so the harness never waits longer.
    """
    start_ns = time.monotonic_ns() if start_ns is None else start_ns
    parser = argparse.ArgumentParser(description="Bounded Super-brain2 capture hook entry point")
    parser.add_argument("--outbox", required=True, type=Path, help="Local outbox spool directory")
    parser.add_argument("--log", default=None, type=Path, help="Optional static diagnostic log file")
    parser.add_argument("--harness", default=None, help="Default harness_id when omitted by stdin payload")
    parser.add_argument("--checkout", default=None, type=Path, help="Pinned checkout root for adapter verification")
    parser.add_argument("--profile", default=None, type=Path, help="Pinned harness ClientProfile JSON path")
    parser.add_argument("--producer-stream", default=None, help="Optional default producer_stream")
    parser.add_argument("--sequence", default=None, type=int, help="Optional sequence number when omitted")
    args = parser.parse_args(list(argv) if argv is not None else None)
    done = threading.Event()

    def _body() -> None:
        # The whole hook (stdin, filter, durable write) runs here so the watchdog bounds every step.
        try:
            try:
                raw_bytes = sys.stdin.buffer.read(_MAX_STDIN_BYTES + 1)
            except OSError:
                _write_static_log(args.log, phase="hook_stdin", code=ErrorCode.IO_ERROR.value)
                return
            # run_hook (and its fallback gap) must finish before the watchdog stops waiting for it
            remaining_ns = HOOK_HARD_CAP_NS - _WATCHDOG_EXIT_RESERVE_NS - (time.monotonic_ns() - start_ns)
            if remaining_ns <= 0:
                _write_static_log(args.log, phase="hook_stdin", code=ErrorCode.DEADLINE_EXCEEDED.value)
                return
            run_hook(
                raw_bytes,
                outbox_dir=args.outbox,
                log_path=args.log,
                default_harness_id=args.harness,
                checkout_root=args.checkout,
                profile_path=args.profile,
                producer_stream=args.producer_stream,
                sequence=args.sequence,
                cap_ns=remaining_ns,
            )
        finally:
            done.set()

    threading.Thread(target=_body, name="superbrain-hook", daemon=True).start()
    hard_deadline_ns = start_ns + HOOK_HARD_CAP_NS
    log_deadline_ns = hard_deadline_ns - _WATCHDOG_EXIT_RESERVE_NS
    if done.wait(max(0.0, (log_deadline_ns - time.monotonic_ns()) / 1e9)):
        return 0
    # Input never ended or I/O stalled: no identity is safe to record. The static log gets only what is left of
    # the reserve on its own thread, then the process leaves at the cap whether or not the log finished; an
    # interrupted outbox write is an ordinary crash.
    logged = threading.Event()

    def _log() -> None:
        _write_static_log(args.log, phase="hook_watchdog", code=ErrorCode.DEADLINE_EXCEEDED.value, timeout_s=0.05)
        logged.set()

    threading.Thread(target=_log, name="superbrain-hook-log", daemon=True).start()
    logged.wait(max(0.0, (hard_deadline_ns - _WATCHDOG_EXIT_MARGIN_NS - time.monotonic_ns()) / 1e9))
    _hard_exit(0)
    return 0


_WATCHDOG_EXIT_RESERVE_NS = 150_000_000
"""Part of the hard cap kept for the timeout log and process exit."""
_WATCHDOG_EXIT_MARGIN_NS = 20_000_000
_GAP_RESERVE_NS = 300_000_000
"""Part of the hook budget kept for the fallback CaptureGap write after the work deadline."""


def _hard_exit(code: int) -> None:
    os._exit(code)


if __name__ == "__main__":
    raise SystemExit(main(start_ns=_PROCESS_T0_NS))
