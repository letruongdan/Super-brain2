"""Native host payloads as the hosts really send them (observed in the 2026-11-28 real-host smoke): Claude Code and
Codex always pass a ``transcript_path`` under the user's host data directory, outside the checkout. The hook event is
captured; the transcript outside the checkout is never read."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.composition.hook_entry import run_hook
from superbrain.storage.outbox import OutboxSpool


def _setup(tmp: Path, harness: str) -> tuple[Path, Path, Path, Path]:
    perms = os_adapters().permissions
    chk = tmp / f"{harness}-checkout"
    host_home = tmp / f"{harness}-host-home"
    prof_dir = tmp / f"{harness}-profile"
    for d in (chk, host_home, prof_dir):
        d.mkdir()
        perms.secure_directory(d)
    transcript = host_home / "session.jsonl"
    transcript.write_bytes(b'{"type":"user","message":"SECRET_HOST_TRANSCRIPT"}\n')
    prof = prof_dir / "profile.json"
    prof.write_bytes(json.dumps({
        "version": 1, "endpoint_path": str(prof_dir / "endpoint.json"), "expected_store_id": "s",
        "ca_file": str(prof_dir / "ca.pem"), "leaf_cert_sha256": "0" * 64, "credential_file": str(prof_dir / "c"),
        "workspace": {"alias": "w", "expected_workspace_id": "repo-native", "expected_checkout_id": "chk-native",
                      "checkout_path": str(chk)},
    }).encode())
    perms.secure_file(prof)
    return chk, transcript, prof, tmp / f"{harness}-outbox"


@pytest.mark.parametrize("harness", ["claude-code", "codex"])
def test_real_shaped_payload_with_host_transcript_is_captured_without_reading_it(
    trusted_tmp: Path, harness: str
) -> None:
    chk, transcript, prof, outbox = _setup(trusted_tmp, harness)
    payload: dict[str, Any] = {
        "session_id": "11111111-2222-3333-4444-555555555555", "transcript_path": str(transcript), "cwd": str(chk),
        "permission_mode": "default", "hook_event_name": "PostToolUse", "tool_name": "Read",
        "tool_input": {"file_path": str(chk / "README.md")}, "tool_response": {"type": "text", "file": "ok"},
        "tool_use_id": "toolu_real_shape_1",
    }
    if harness == "codex":
        payload.update(turn_id="turn-1", model="gpt-5")
    assert run_hook(json.dumps(payload).encode(), outbox_dir=outbox, default_harness_id=harness,
                    checkout_root=chk, profile_path=prof,
                    spool_factory=lambda d: OutboxSpool(d, permissions=os_adapters().permissions)) == 0
    entries = OutboxSpool(outbox, permissions=os_adapters().permissions).read_pending(limit=5)
    assert [e.record_kind for e in entries] == ["event"]
    assert "SECRET_HOST_TRANSCRIPT" not in entries[0].payload_json
    # neither the host's transcript location nor its session id leaves with the event
    assert "transcript_path" not in entries[0].payload_json and transcript.parent.name not in entries[0].payload_json
    assert "11111111-2222-3333-4444-555555555555" not in entries[0].payload_json


def test_a_timed_out_native_event_keeps_its_explicit_event_id_through_the_fallback_gap(trusted_tmp: Path) -> None:
    """The hook reserves the slot with the producer's event_id, so retrying that notification later lands on it."""
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord

    chk, _transcript, prof, outbox = _setup(trusted_tmp, "claude-code")
    perms = os_adapters().permissions
    payload: dict[str, Any] = {
        "session_id": "sess-explicit", "cwd": str(chk), "hook_event_name": "PostToolUse", "tool_name": "Read",
        "tool_input": {"file_path": str(chk / "README.md")}, "tool_response": {"type": "text"},
        "event_id": "ev-native-explicit-1",
    }

    class _TimesOutBeforeBinding(OutboxSpool):
        def enqueue_hook_event(self, **kwargs: Any) -> CaptureEventRecord:
            kwargs["build_event"](1, kwargs["explicit_event_id"], kwargs["fallback_recorded_at"])
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def _hook(factory: Any) -> int:
        return run_hook(json.dumps(payload).encode(), outbox_dir=outbox, default_harness_id="claude-code",
                        checkout_root=chk, profile_path=prof, spool_factory=factory)

    assert _hook(lambda d: _TimesOutBeforeBinding(d, permissions=perms)) == 0
    spool = OutboxSpool(outbox, permissions=perms)
    [gap] = spool.read_pending(limit=5)
    assert (gap.record_kind, gap.sequence) == ("capture_gap", 1)
    spool.apply_ack(CaptureBatchAck(producer_stream=gap.producer_stream, repo_id="r", checkout_id="c",
                                    committed_event_sequences=(), contiguous_event_acked_through=0,
                                    acked_producer_gap_sequences=(1,), accepted_count=1, deduped_count=0))
    assert _hook(lambda d: OutboxSpool(d, permissions=perms)) == 0  # the retry of the same notification
    [event] = spool.read_pending(limit=5)
    assert (event.record_kind, event.sequence, event.entry_id) == ("event", 1, "ev-native-explicit-1")
