"""State-transition oracles for slot ownership (audit 2026-11-28 group A): one notification keeps one slot through
fallback gap, gap ACK, late event, crash and restart; every write path checks the slot owner."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureBatchAck
from superbrain.storage.outbox import OutboxSpool
from tests.storage.test_outbox_r10_ack_durability import (
    _enqueue_hook,
    _legacy_probe_script,
    _mk_event,
    _repo_root_with_36bf08d9,
    _stream_dir,
)

_AT = "2026-11-28T08:00:00Z"


def _gap_ack(stream: str, *seqs: int) -> CaptureBatchAck:
    return CaptureBatchAck(producer_stream=stream, repo_id="r", checkout_id="c", committed_event_sequences=(),
                           contiguous_event_acked_through=0, acked_producer_gap_sequences=seqs,
                           accepted_count=len(seqs), deduped_count=0)


def _ev_ack(stream: str, *seqs: int) -> CaptureBatchAck:
    return CaptureBatchAck(producer_stream=stream, repo_id="r", checkout_id="c", committed_event_sequences=seqs,
                           contiguous_event_acked_through=0, acked_producer_gap_sequences=(),
                           accepted_count=len(seqs), deduped_count=0)


def _fallback(spool: OutboxSpool, stream: str, dk: str | None, *, seq: int | None = None, reason: str = "hook_timeout",
              at: str = _AT, duration: int = 5) -> str | None:
    return spool.enqueue_fallback_gap(producer_stream=stream, sequence=seq, dedup_key=dk, reason=reason,
                                      recorded_at=at, duration_ms=duration)


def _frames(spool: OutboxSpool, stream: str) -> list[tuple[str, int, str, str]]:
    return [(e.record_kind, e.sequence, e.entry_id, e.payload_digest)
            for e in spool.read_pending(limit=50, producer_stream=stream)]


def _kinds(spool: OutboxSpool, stream: str) -> list[tuple[str, int]]:
    return [(k, s) for k, s, _i, _d in _frames(spool, stream)]


def test_slot_reserved_by_fallback_gap_survives_ack_retry_and_late_event(trusted_tmp: Path) -> None:
    """Fresh -> gap reserved -> repeat -> gap ACKed -> repeated timeout (other clock, other reason) -> late event ->
    event ACK -> no further gap; another notification takes the next slot."""
    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-1"
    spool = OutboxSpool(root, permissions=perms)
    stream, dk = "s-slot-1", digest_bytes(b"slot-1-notification")
    assert _fallback(spool, stream, dk, duration=5) is not None
    [first] = _frames(spool, stream)
    assert first[:2] == ("capture_gap", 1)
    _fallback(OutboxSpool(root, permissions=perms), stream, dk, duration=99, reason="outbox_full")
    assert _frames(spool, stream) == [first]
    assert spool.apply_ack(_gap_ack(stream, 1)) == 1
    _fallback(OutboxSpool(root, permissions=perms), stream, dk, duration=1234, reason="outbox_full",
              at="2026-11-28T09:00:00Z")
    assert _frames(spool, stream) in ([], [first])
    spool.apply_ack(_gap_ack(stream, 1))
    rec = _enqueue_hook(OutboxSpool(root, permissions=perms), stream=stream, dk=dk)
    assert rec.sequence == 1
    assert _kinds(spool, stream) == [("event", 1)]
    assert spool.apply_ack(_ev_ack(stream, 1)) == 1
    assert _fallback(OutboxSpool(root, permissions=perms), stream, dk) is None
    assert _frames(spool, stream) == []
    assert _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"slot-1-other")).sequence == 2


def test_slot_reservation_is_durable_before_the_gap_and_survives_a_crash(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crash after the reservation is written and before the gap frame is published: restart keeps the slot."""
    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-2"
    stream, dk = "s-slot-2", digest_bytes(b"slot-2-notification")
    spool = OutboxSpool(root, permissions=perms)

    def _crash(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "simulated crash before gap publication")

    with monkeypatch.context() as mp:
        mp.setattr(spool, "_atomic_publish_frame", _crash)
        with pytest.raises(BrainError):
            _fallback(spool, stream, dk, duration=7)
    assert _frames(OutboxSpool(root, permissions=perms), stream) == []
    with pytest.raises(BrainError) as taken:
        OutboxSpool(root, permissions=perms).enqueue_event(_mk_event(stream, 1, event_id="ev-unrelated"))
    assert taken.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    _fallback(OutboxSpool(root, permissions=perms), stream, dk, duration=999)
    [gap] = OutboxSpool(root, permissions=perms).read_pending(limit=5, producer_stream=stream)
    assert (gap.record_kind, gap.sequence) == ("capture_gap", 1)
    assert json.loads(gap.payload_json)["duration_ms"] == 7
    assert _enqueue_hook(OutboxSpool(root, permissions=perms), stream=stream, dk=dk).sequence == 1


def test_fallback_without_free_binding_capacity_still_records_the_gap(trusted_tmp: Path) -> None:
    """At the binding cap the fallback cannot reserve a slot; it still writes the gap (no silent loss)."""
    perms = os_adapters().permissions
    spool = OutboxSpool(trusted_tmp / "outbox-slot-3", permissions=perms, max_binding_keys=1)
    stream = "s-slot-3"
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"slot-3-a"))
    assert _fallback(spool, stream, digest_bytes(b"slot-3-b")) is not None
    assert _kinds(spool, stream) == [("event", 1), ("capture_gap", 2)]
    sdir = _stream_dir(spool.root, stream)
    rows = [r for f in (sdir / ".bindings").glob("*.json") for r in json.loads(f.read_text("utf-8"))["entries"]]
    assert len(rows) == 1  # the cap is kept: no reservation beyond it


def test_direct_event_respects_slot_owner_and_owner_may_complete(trusted_tmp: Path) -> None:
    """A direct event may publish only into a slot nobody reserved; the reserving notification still completes."""
    perms = os_adapters().permissions
    spool = OutboxSpool(trusted_tmp / "outbox-slot-4", permissions=perms)
    stream, dk = "s-slot-4", digest_bytes(b"slot-4-notification")
    _fallback(spool, stream, dk)
    with pytest.raises(BrainError) as taken:
        spool.enqueue_event(_mk_event(stream, 1, event_id="ev-someone-else"))
    assert taken.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    assert spool.enqueue_event(_mk_event(stream, 2, event_id="ev-free-slot")) == "ev-free-slot"
    assert _enqueue_hook(spool, stream=stream, dk=dk).sequence == 1


@pytest.mark.parametrize("legacy_commit", ["36bf08d9", "4e33772"])
def test_legacy_binary_refuses_after_a_slot_reservation(trusted_tmp: Path, legacy_commit: str) -> None:
    """A gap-stamped reservation is written behind a fence no earlier binary accepts: 36bf08d9 (pre-v4) and 4e33772
    (v4, five-field binding rows) both refuse before mutating a byte."""
    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-5"
    spool = OutboxSpool(root, permissions=perms)
    stream_a, stream_b = "s-slot-5-a", "s-slot-5-b"
    _enqueue_hook(spool, stream=stream_b, dk=digest_bytes(b"slot-5-b"))
    _fallback(spool, stream_a, digest_bytes(b"slot-5-a"))
    assert (root / "streams" / ".v4_fence").exists()
    sdir = _stream_dir(root, stream_a)
    buckets = [json.loads(f.read_text("utf-8")) for f in (sdir / ".bindings").glob("*.json")]
    assert any(len(r) == 6 for b in buckets for r in b["entries"])
    # a bucket holding a gap stamp is schema 4 and the fence is 5: no earlier reader accepts either
    assert all(b["schema_version"] == 4 for b in buckets if any(len(r) == 6 for r in b["entries"]))
    assert json.loads((root / "streams" / ".v4_fence").read_text("utf-8")) == {"schema_version": 5}
    repo_root = _repo_root_with_36bf08d9()
    if repo_root is None:
        pytest.skip("the legacy commits are not reachable from this checkout")
    legacy = trusted_tmp / f"legacy-src-slot-5-{legacy_commit}"
    legacy.mkdir()
    tar_bytes = subprocess.check_output(["git", "-C", str(repo_root), "archive", "--format=tar", legacy_commit, "src"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(legacy, filter="data")
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}
    script = _legacy_probe_script(legacy / "src", [(str(root), stream_a, stream_b)])
    proc = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout.strip().splitlines()[-1])[str(root)]
    assert all(v.startswith("refused:") for v in res.values()), res
    after = {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}
    assert after == before


def test_fallback_without_stable_identity_uses_a_free_slot(trusted_tmp: Path) -> None:
    """No dedup key and no sequence: the gap takes the next free slot and reserves nothing (documented limit)."""
    perms = os_adapters().permissions
    spool = OutboxSpool(trusted_tmp / "outbox-slot-6", permissions=perms)
    stream = "s-slot-6"
    spool.enqueue_event(_mk_event(stream, 1))
    assert _fallback(spool, stream, None) is not None
    assert _kinds(spool, stream) == [("event", 1), ("capture_gap", 2)]
    assert not (_stream_dir(spool.root, stream) / ".bindings").exists()


def test_pinned_writers_cannot_take_a_slot_reserved_for_another_notification(trusted_tmp: Path) -> None:
    """A producer-chosen sequence that another notification reserved is refused on the hook and fallback paths, and a
    notification cannot move its own reservation to a different pinned sequence."""
    perms = os_adapters().permissions
    spool = OutboxSpool(trusted_tmp / "outbox-slot-7", permissions=perms)
    stream, k1, k2 = "s-slot-7", digest_bytes(b"slot-7-k1"), digest_bytes(b"slot-7-k2")
    _fallback(spool, stream, k1)
    with pytest.raises(BrainError) as hook_taken:
        _enqueue_hook(spool, stream=stream, dk=k2, explicit_seq=1)
    assert hook_taken.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    with pytest.raises(BrainError) as gap_taken:
        _fallback(spool, stream, k2, seq=1)
    assert gap_taken.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    with pytest.raises(BrainError) as moved:
        _fallback(spool, stream, k1, seq=2)
    assert moved.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    assert _kinds(spool, stream) == [("capture_gap", 1)]


def test_fallback_gap_identity_follows_the_slot_and_the_reservation(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gap id is the slot's (same after an ACK even without a dedup key), and a gap standing in for a hook that
    reserved its slot but never published carries the reservation's recorded_at."""
    perms = os_adapters().permissions
    spool = OutboxSpool(trusted_tmp / "outbox-slot-8", permissions=perms)
    stream = "s-slot-8"
    first = _fallback(spool, stream, None, seq=3)
    spool.apply_ack(_gap_ack(stream, 3))
    assert _fallback(spool, stream, None, seq=3) == first

    dk = digest_bytes(b"slot-8-hook")

    def _stop(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "simulated failure before frame publish")

    with monkeypatch.context() as mp:
        mp.setattr(spool, "_atomic_publish_frame", _stop)
        with pytest.raises(BrainError):
            _enqueue_hook(spool, stream=stream, dk=dk)
    _fallback(OutboxSpool(spool.root, permissions=perms), stream, dk, at="2026-11-28T23:59:59Z")
    gaps = [e for e in spool.read_pending(limit=10, producer_stream=stream)
            if e.record_kind == "capture_gap" and e.sequence != 3]
    assert len(gaps) == 1
    assert json.loads(gaps[0].payload_json)["recorded_at"] == "2026-11-27T08:00:00Z"


def test_fallback_binding_keeps_the_producers_explicit_event_id(trusted_tmp: Path) -> None:
    """A notification with an explicit event_id that times out before its binding is written keeps that id: the
    retry with the original event_id lands on the reserved slot, before and after the gap ACK; another id cannot."""
    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-explicit-id"
    spool = OutboxSpool(root, permissions=perms)
    stream, dk, ev_id = "s-slot-explicit", digest_bytes(b"slot-explicit"), "ev-producer-chosen-1"
    assert spool.enqueue_fallback_gap(producer_stream=stream, sequence=None, dedup_key=dk, reason="hook_timeout",
                                      recorded_at=_AT, duration_ms=5, event_id=ev_id) is not None

    def _retry(event_id: str) -> Any:
        return OutboxSpool(root, permissions=perms).enqueue_hook_event(
            producer_stream=stream, build_event=lambda seq, eid, ts: _mk_event(stream, seq, event_id=eid),
            explicit_event_id=event_id, dedup_key=dk, fallback_recorded_at=_AT,
        )

    with pytest.raises(BrainError) as other:
        _retry("ev-someone-else")
    assert other.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    with pytest.raises(BrainError) as other_gap:  # a fallback naming another id for the same notification
        spool.enqueue_fallback_gap(producer_stream=stream, sequence=None, dedup_key=dk, reason="hook_timeout",
                                   recorded_at=_AT, duration_ms=5, event_id="ev-someone-else")
    assert other_gap.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    spool.apply_ack(_gap_ack(stream, 1))
    rec = _retry(ev_id)
    assert (rec.sequence, rec.event_id) == (1, ev_id)


def test_fallback_adopts_a_pending_gap_an_earlier_binary_wrote_for_the_slot(trusted_tmp: Path) -> None:
    """Upgrade: 4e33772 bound the notification, timed out and published a gap with a random id at that slot. The new
    fallback keeps that gap's identity instead of publishing a second one the daemon would reject as a conflict."""
    from superbrain.ports.capture import ProducerCaptureGap

    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-legacy-gap"
    stream, dk = "s-slot-legacy-gap", digest_bytes(b"slot-legacy-gap")

    class _FailsBeforePublish(OutboxSpool):
        def _atomic_publish_frame(self, *args: Any, **kwargs: Any) -> None:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "timed out before the frame")

    with pytest.raises(BrainError):
        _enqueue_hook(_FailsBeforePublish(root, permissions=perms), stream=stream, dk=dk)
    spool = OutboxSpool(root, permissions=perms)
    legacy_gap = ProducerCaptureGap(gap_id="gap-legacy-random-1", producer_stream=stream, sequence=1,
                                    reason="hook_timeout", recorded_at=_AT, estimated_count=1, duration_ms=7)
    spool.enqueue_gap(legacy_gap)
    before = _frames(spool, stream)
    assert [(k, s, i) for k, s, i, _d in before] == [("capture_gap", 1, "gap-legacy-random-1")]
    _fallback(OutboxSpool(root, permissions=perms), stream, dk, duration=42, reason="outbox_full")
    assert _frames(spool, stream) == before  # no second gap at the slot
    spool.apply_ack(_gap_ack(stream, 1))
    _fallback(OutboxSpool(root, permissions=perms), stream, dk, duration=43)
    after_ack = _frames(spool, stream)
    assert after_ack == [] or [(k, s, i) for k, s, i, _d in after_ack] == [("capture_gap", 1, "gap-legacy-random-1")]


def test_adopting_a_pending_gap_runs_the_replay_durability_barrier(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A visible gap frame whose directory sync may have failed is only reported after the same barrier a replay
    through enqueue_gap runs (stream metadata synced)."""
    from superbrain.ports.capture import ProducerCaptureGap
    from superbrain.storage import _outbox_seq

    perms = os_adapters().permissions
    root = trusted_tmp / "outbox-slot-adopt-barrier"
    stream = "s-slot-adopt-barrier"
    spool = OutboxSpool(root, permissions=perms)
    spool.enqueue_gap(ProducerCaptureGap(gap_id="gap-legacy-random-9", producer_stream=stream, sequence=1,
                                         reason="hook_timeout", recorded_at=_AT, estimated_count=1, duration_ms=1))
    synced: list[Path] = []
    real_sync = _outbox_seq.sync_stream_metadata
    def _spy(stream_dir: Path) -> None:
        synced.append(Path(stream_dir))
        real_sync(stream_dir)

    monkeypatch.setattr(_outbox_seq, "sync_stream_metadata", _spy)
    assert _fallback(OutboxSpool(root, permissions=perms), stream, None, seq=1) == "gap-legacy-random-9"
    assert synced, "the adopted gap was reported without the replay barrier"
