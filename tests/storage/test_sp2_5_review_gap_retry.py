import json
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.composition.hook_entry import run_hook
from superbrain.storage.outbox import OutboxSpool


def test_retry_reuses_gap_slot_reserved_for_native_notification(trusted_tmp: Path) -> None:
    checkout = trusted_tmp / "checkout"
    checkout.mkdir()
    perms = os_adapters().permissions
    perms.secure_directory(checkout)
    box = trusted_tmp / "outbox"
    stream = "review-stream"
    payload = json.dumps({
        "cwd": str(checkout), "hook_event_name": "PostToolUse",
        "session_id": "synthetic-review", "tool_use_id": "synthetic-tool-1",
        "tool_name": "Read", "tool_input": {"file_path": "README.md"},
        "tool_response": {"content": "synthetic example"},
    }).encode()

    def hook(expire: bool) -> int:
        clock_reads = 0
        def mono() -> int:
            nonlocal clock_reads
            clock_reads += 1
            return 1_960_000_000 if expire and clock_reads >= 3 else 0

        return run_hook(
            payload, outbox_dir=box, monotonic_ns=mono, default_harness_id="claude-code",
            checkout_root=checkout, producer_stream=stream,
            spool_factory=lambda path: OutboxSpool(path, permissions=perms, monotonic_ns=mono),
        )

    assert hook(True) == 0
    assert [(x.record_kind, x.sequence) for x in OutboxSpool(box).read_pending()] == [("capture_gap", 1)]
    assert hook(False) == 0
    pending = [(x.record_kind, x.sequence) for x in OutboxSpool(box).read_pending()]
    assert pending == [("capture_gap", 1), ("event", 1)], pending
