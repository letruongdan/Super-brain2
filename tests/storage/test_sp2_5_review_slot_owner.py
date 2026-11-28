import pytest

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.outbox import OutboxSpool
from tests.storage.test_outbox_durability_and_limits import _mk_event


def test_direct_event_cannot_take_slot_reserved_by_pending_hook(trusted_tmp, monkeypatch):
    path = trusted_tmp / "outbox"
    stream = "review-stream"
    spool = OutboxSpool(path)
    key = digest_bytes(b"synthetic pending observation")

    def enqueue_owner(target):
        return target.enqueue_hook_event(
            producer_stream=stream,
            build_event=lambda seq, event_id, at: _mk_event(seq, event_id=event_id, stream=stream),
            dedup_key=key,
            fallback_recorded_at="2026-11-28T00:00:00Z",
        )

    def stop_before_publish(*a, **kw):
        raise BrainError(ErrorCode.IO_ERROR, "simulated failure before frame publish")

    with monkeypatch.context() as patch:
        patch.setattr(spool, "_atomic_publish_frame", stop_before_publish)
        with pytest.raises(BrainError) as stopped:
            enqueue_owner(spool)
        assert stopped.value.code is ErrorCode.IO_ERROR
    reopened = OutboxSpool(path)
    assert reopened.read_pending() == []
    try:
        result = reopened.enqueue_event(_mk_event(1, event_id="distinct-normalized-event", stream=stream))
    except BrainError as rejected:
        assert rejected.code is ErrorCode.IDEMPOTENCY_CONFLICT
        assert enqueue_owner(reopened).sequence == 1
        return
    assert result == "distinct-normalized-event"
    assert [(x.sequence, x.entry_id) for x in reopened.read_pending()] == [(1, result)]
    with pytest.raises(BrainError) as owner_conflict:
        enqueue_owner(reopened)
    assert owner_conflict.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    pytest.fail("the unrelated event occupied slot 1 and the reserved owner could no longer publish")
