import json
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.composition.hook_entry import run_hook
from superbrain.ports.capture import CaptureBatchAck
from superbrain.storage.outbox import OutboxSpool


def test_fallback_retry_after_gap_ack_cannot_create_new_gap_identity(trusted_tmp: Path) -> None:
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

    def hook() -> int:
        clock_reads = 0
        def mono() -> int:
            nonlocal clock_reads
            clock_reads += 1
            return 1_960_000_000 if clock_reads >= 3 else 0

        return run_hook(
            payload, outbox_dir=box, monotonic_ns=mono, default_harness_id="claude-code",
            checkout_root=checkout, producer_stream=stream, sequence=1,
            spool_factory=lambda path: OutboxSpool(path, permissions=perms, monotonic_ns=mono),
        )

    assert hook() == 0
    spool = OutboxSpool(box)
    [first] = spool.read_pending()
    assert (first.record_kind, first.sequence) == ("capture_gap", 1)
    ack = CaptureBatchAck(
        producer_stream=stream, repo_id="review-repo", checkout_id="review-checkout",
        committed_event_sequences=(), contiguous_event_acked_through=0,
        acked_producer_gap_sequences=(1,), accepted_count=1, deduped_count=0,
    )
    assert spool.apply_ack(ack) == 1
    assert OutboxSpool(box).read_pending() == []
    assert hook() == 0
    pending = OutboxSpool(box).read_pending()
    print("first", (first.sequence, first.entry_id), "after retry", [(r.sequence, r.entry_id) for r in pending])
    assert not pending or [(r.sequence, r.entry_id, r.payload_digest) for r in pending] == [
        (first.sequence, first.entry_id, first.payload_digest)
    ]

