"""R8 storage regression tests for sharded hook cursor migration, crash recovery, and limits."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import (
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxPermissionsPort,
    ProducerCaptureGap,
)
from superbrain.storage import _outbox_bindings, _outbox_seq
from superbrain.storage import outbox as outbox_mod
from superbrain.storage._outbox_bindings import bucket_name_for_key
from superbrain.storage._outbox_io import _STREAMS_DIR, stream_dir_key
from superbrain.storage.outbox import OutboxSpool

_REC_AT = "2026-11-27T08:00:00Z"


def _mk_event(
    stream: str,
    seq: int,
    *,
    event_id: str | None = None,
    note: str = "ok",
    recorded_at: str = _REC_AT,
) -> CaptureEventRecord:
    return CaptureEventRecord(
        event_id=event_id or f"ev-{stream}-{seq}",
        producer_stream=stream,
        sequence=seq,
        harness_id="claude-code",
        kind="command_result",
        recorded_at=recorded_at,
        payload={"seq": seq, "note": note},
    )


def _record_digest(rec: CaptureEventRecord) -> str:
    return digest_bytes(canonical_json(rec.to_dict()))


def _stream_dir(outbox_root: Path, stream: str) -> Path:
    return outbox_root / _STREAMS_DIR / stream_dir_key(stream)


def _write_cursor_json(
    outbox_root: Path,
    stream: str,
    obj: dict[str, Any],
    perms: OutboxPermissionsPort,
) -> Path:
    streams_dir = outbox_root / _STREAMS_DIR
    sdir = streams_dir / stream_dir_key(stream)
    streams_dir.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(streams_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(sdir)
    cursor_path = sdir / ".seq_cursor.json"
    cursor_path.write_bytes(canonical_json(obj))
    perms.secure_file(cursor_path)
    return cursor_path


def _enqueue_hook(
    spool: OutboxSpool,
    *,
    stream: str,
    dk: str,
    note: str = "ok",
    explicit_seq: int | None = None,
    explicit_ev_id: str | None = None,
    recorded_at: str = _REC_AT,
) -> CaptureEventRecord:
    return spool.enqueue_hook_event(
        producer_stream=stream,
        build_event=lambda seq, ev_id, ts: _mk_event(stream, seq, event_id=ev_id, note=note, recorded_at=ts),
        explicit_sequence=explicit_seq,
        explicit_event_id=explicit_ev_id,
        dedup_key=dk,
        fallback_recorded_at=recorded_at,
    )


def _same_bucket_key(target_dk: str) -> str:
    target_bucket = bucket_name_for_key(target_dk)
    for i in range(10_000):
        cand = digest_bytes(f"r8-same-bucket-{i}".encode())
        if cand != target_dk and bucket_name_for_key(cand) == target_bucket:
            return cand
    raise AssertionError(f"failed to find bucket sibling for {target_bucket}")


def test_r8_finding1_legacy_v1_v2_cursor_survives_gap_event_ack_and_backfills_digest(
    trusted_tmp: Path,
) -> None:
    """Legacy v1/v2 cursors migrate cleanly across gap/event/ack and backfill missing digests."""
    os_ = os_adapters()
    perms = os_.permissions

    # --- Part A: v2 cursor upgraded via enqueue_gap (stream 1) & enqueue_event (stream 2) ---
    outbox_a = trusted_tmp / "outbox-r8-v2"
    spool_a = OutboxSpool(outbox_a, permissions=perms)

    for idx, trigger in enumerate(("gap", "event"), start=1):
        stream = f"stream-r8-v2-{trigger}"
        dk1 = digest_bytes(f"r8-v2-{idx}-k1".encode())
        dk2 = digest_bytes(f"r8-v2-{idx}-k2".encode())
        dk3 = digest_bytes(f"r8-v2-{idx}-k3".encode())
        ev1 = _mk_event(stream, 1, event_id=f"ev-v2-{idx}-1", note="n1")
        ev2 = _mk_event(stream, 2, event_id=f"ev-v2-{idx}-2", note="n2")
        ev3 = _mk_event(stream, 3, event_id=f"ev-v2-{idx}-3", note="n3")

        # Publish frame 3 safely via enqueue_event before laying down legacy v2 cursor.
        spool_a.enqueue_event(ev3)
        _write_cursor_json(
            outbox_a,
            stream,
            {
                "schema_version": 2,
                "next_seq": 4,
                "recent": [
                    [dk1, 1, ev1.event_id, _REC_AT, "acked", _record_digest(ev1)],
                    [dk2, 2, ev2.event_id, _REC_AT, "bound", _record_digest(ev2)],
                    [dk3, 3, ev3.event_id, _REC_AT, "published", _record_digest(ev3)],
                ],
            },
            perms,
        )

        if trigger == "gap":
            spool_a.enqueue_gap(
                ProducerCaptureGap(
                    gap_id=f"gap-v2-{idx}-4",
                    producer_stream=stream,
                    sequence=4,
                    reason="hook_timeout",
                    recorded_at=_REC_AT,
                    estimated_count=1,
                    duration_ms=100,
                )
            )
        else:
            spool_a.enqueue_event(_mk_event(stream, 4, event_id=f"ev-v2-{idx}-4", note="n4"))

        reopened = OutboxSpool(outbox_a, permissions=perms)
        cur_data = json.loads((_stream_dir(outbox_a, stream) / ".seq_cursor.json").read_text(encoding="utf-8"))
        assert cur_data["schema_version"] == 3
        assert cur_data["binding_count"] == 3
        assert cur_data["acked_ranges"] == [[1, 1]]

        # Retry ACKed key 1 -> returns (ev1, 1) without publishing a new frame for seq 1.
        r1 = _enqueue_hook(reopened, stream=stream, dk=dk1, note="n1")
        assert (r1.event_id, r1.sequence) == (ev1.event_id, 1)
        assert {e.sequence for e in reopened.read_pending(limit=10, producer_stream=stream)} == {3, 4}

        # Retry bound key 2 -> returns (ev2, 2) and publishes frame seq 2.
        r2 = _enqueue_hook(reopened, stream=stream, dk=dk2, note="n2")
        assert (r2.event_id, r2.sequence) == (ev2.event_id, 2)
        assert {e.sequence for e in reopened.read_pending(limit=10, producer_stream=stream)} == {2, 3, 4}

        # Tampered payload for key 1 must fail closed with IDEMPOTENCY_CONFLICT.
        with pytest.raises(BrainError) as conflict_v2:
            _enqueue_hook(reopened, stream=stream, dk=dk1, note="tampered-v2")
        assert conflict_v2.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

        # Brand-new key receives sequence == 5.
        r5 = _enqueue_hook(reopened, stream=stream, dk=digest_bytes(f"r8-v2-{idx}-new5".encode()), note="n5")
        assert r5.sequence == 5

    # --- Part B: v1 cursor upgraded via enqueue_gap + apply_ack + payload_digest backfill ---
    outbox_b = trusted_tmp / "outbox-r8-v1"
    spool_b = OutboxSpool(outbox_b, permissions=perms)
    stream_b = "stream-r8-v1"
    dk_v1_1 = digest_bytes(b"r8-v1-k1")
    dk_v1_2 = digest_bytes(b"r8-v1-k2")
    ev_v1_1 = _mk_event(stream_b, 1, event_id="ev-v1-1", note="v1-orig-1")
    ev_v1_2 = _mk_event(stream_b, 2, event_id="ev-v1-2", note="v1-orig-2")

    spool_b.enqueue_event(ev_v1_2)
    _write_cursor_json(
        outbox_b,
        stream_b,
        {
            "schema_version": 1,
            "next_seq": 3,
            "recent": [
                [dk_v1_1, 1, ev_v1_1.event_id, _REC_AT],
                [dk_v1_2, 2, ev_v1_2.event_id, _REC_AT],
            ],
        },
        perms,
    )
    spool_b.enqueue_gap(
        ProducerCaptureGap(
            gap_id="gap-v1-3",
            producer_stream=stream_b,
            sequence=3,
            reason="hook_timeout",
            recorded_at=_REC_AT,
            estimated_count=1,
            duration_ms=50,
        )
    )
    evicted_v1 = spool_b.apply_ack(
        CaptureBatchAck(
            producer_stream=stream_b,
            repo_id="repo-r8",
            checkout_id="chk-r8",
            committed_event_sequences=(1,),
            contiguous_event_acked_through=1,
            acked_producer_gap_sequences=(3,),
            accepted_count=1,
            deduped_count=0,
            policy_disabled=False,
        )
    )
    assert evicted_v1 == 1

    reopened_b = OutboxSpool(outbox_b, permissions=perms)
    # Key 1 retry (already ACKed): returns (ev_v1_1, 1), leaves pending=[2], and backfills payload_digest.
    rb1 = _enqueue_hook(reopened_b, stream=stream_b, dk=dk_v1_1, note="v1-orig-1")
    assert (rb1.event_id, rb1.sequence) == (ev_v1_1.event_id, 1)
    assert [e.sequence for e in reopened_b.read_pending(limit=10, producer_stream=stream_b)] == [2]
    with pytest.raises(BrainError) as conflict_v1_1:
        _enqueue_hook(reopened_b, stream=stream_b, dk=dk_v1_1, note="v1-tampered-1")
    assert conflict_v1_1.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

    # Key 2 retry (matched pre-existing frame seq 2): returns (ev_v1_2, 2) and backfills payload_digest.
    rb2 = _enqueue_hook(reopened_b, stream=stream_b, dk=dk_v1_2, note="v1-orig-2")
    assert (rb2.event_id, rb2.sequence) == (ev_v1_2.event_id, 2)
    with pytest.raises(BrainError) as conflict_v1_2:
        _enqueue_hook(reopened_b, stream=stream_b, dk=dk_v1_2, note="v1-tampered-2")
    assert conflict_v1_2.value.code is ErrorCode.IDEMPOTENCY_CONFLICT


def test_r8_finding2_interrupted_migration_and_frame_reconcile_preserve_binding_count_cap(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interrupted v2->v3 migration & frame-reconcile cursor crash preserve binding_count cap."""
    os_ = os_adapters()
    perms = os_.permissions

    # --- Part A: Interrupted v2 -> v3 migration with duplicate row + DEADLINE_EXCEEDED ---
    outbox_a = trusted_tmp / "outbox-r8-int-mig"
    stream_a = "stream-r8-int-mig"
    spool_a: OutboxSpool = cast(Any, OutboxSpool)(outbox_a, permissions=perms, max_binding_keys=6)

    keys_a = [digest_bytes(f"r8-mig-{i}".encode()) for i in range(1, 7)]
    evs_a = [_mk_event(stream_a, i, event_id=f"ev-mig-{i}", note=f"m{i}") for i in range(1, 7)]
    recent_v2: list[list[Any]] = [
        [keys_a[i], i + 1, evs_a[i].event_id, _REC_AT, "acked", _record_digest(evs_a[i])]
        for i in range(6)
    ]
    # Duplicate identical row (7 rows total, 6 unique keys).
    recent_v2.append(list(recent_v2[0]))

    cursor_path_a = _write_cursor_json(
        outbox_a,
        stream_a,
        {"schema_version": 2, "next_seq": 7, "recent": recent_v2},
        perms,
    )

    real_upsert = _outbox_bindings.upsert_binding
    calls = [0]

    def _fail_4th_upsert(*args: Any, **kwargs: Any) -> bool:
        calls[0] += 1
        if calls[0] == 4:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated deadline mid-migration")
        return real_upsert(*args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_seq, "upsert_binding", _fail_4th_upsert)
        with pytest.raises(BrainError) as mig_err:
            _enqueue_hook(spool_a, stream=stream_a, dk=keys_a[0], note="m1")
        assert mig_err.value.code is ErrorCode.DEADLINE_EXCEEDED

    assert json.loads(cursor_path_a.read_text(encoding="utf-8"))["schema_version"] == 2

    retry_a1 = _enqueue_hook(spool_a, stream=stream_a, dk=keys_a[0], note="m1")
    assert (retry_a1.event_id, retry_a1.sequence) == (evs_a[0].event_id, 1)
    cur_after_a = json.loads(cursor_path_a.read_text(encoding="utf-8"))
    assert cur_after_a["schema_version"] == 3
    assert cur_after_a["binding_count"] == 6

    with pytest.raises(BrainError) as full_a:
        _enqueue_hook(spool_a, stream=stream_a, dk=digest_bytes(b"r8-mig-7"), note="m7")
    assert full_a.value.code is ErrorCode.STORAGE_FULL

    # --- Part B: Crash inside reconcile_matched_hook_frame_cursor before clearing pending_binding ---
    outbox_b = trusted_tmp / "outbox-r8-reconcile"
    stream_b = "stream-r8-reconcile"
    spool_b: OutboxSpool = cast(Any, OutboxSpool)(outbox_b, permissions=perms, max_binding_keys=1)

    dk_b1 = digest_bytes(b"r8-rec-k1")
    ev_b1 = _mk_event(stream_b, 1, event_id="ev-rec-1", note="rec1")
    spool_b.enqueue_event(ev_b1)

    orig_write_cursor = _outbox_seq.write_stream_cursor

    def _crash_post_bucket(sdir: Path, cursor: Any, p: Any) -> None:
        if cursor.pending_binding is None:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated crash clearing pending_binding")
        orig_write_cursor(sdir, cursor, p)

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_seq, "write_stream_cursor", _crash_post_bucket)
        mp.setattr(outbox_mod, "write_stream_cursor", _crash_post_bucket)
        with pytest.raises(BrainError) as rec_err:
            _enqueue_hook(
                spool_b,
                stream=stream_b,
                dk=dk_b1,
                note="rec1",
                explicit_seq=1,
                explicit_ev_id=ev_b1.event_id,
            )
        assert rec_err.value.code is ErrorCode.DEADLINE_EXCEEDED

    spool_b_re: OutboxSpool = cast(Any, OutboxSpool)(outbox_b, permissions=perms, max_binding_keys=1)
    rb1 = _enqueue_hook(
        spool_b_re,
        stream=stream_b,
        dk=dk_b1,
        note="rec1",
        explicit_seq=1,
        explicit_ev_id=ev_b1.event_id,
    )
    assert (rb1.event_id, rb1.sequence) == (ev_b1.event_id, 1)
    cur_b = json.loads((_stream_dir(outbox_b, stream_b) / ".seq_cursor.json").read_text(encoding="utf-8"))
    assert cur_b["binding_count"] == 1

    with pytest.raises(BrainError) as full_b:
        _enqueue_hook(spool_b_re, stream=stream_b, dk=digest_bytes(b"r8-rec-k2"), note="rec2")
    assert full_b.value.code is ErrorCode.STORAGE_FULL


def test_r8_finding3_bucket_storage_full_does_not_wedge_cursor_and_rejects_link_sdir(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bucket _MAX_BUCKET_BYTES failure leaves .seq_cursor.json unwedged; link sdir fails closed."""
    os_ = os_adapters()
    perms = os_.permissions

    # --- Part A: Bucket _MAX_BUCKET_BYTES STORAGE_FULL does not wedge .seq_cursor.json ---
    outbox_a = trusted_tmp / "outbox-r8-bucket"
    stream_a = "stream-r8-bucket"
    spool_a = OutboxSpool(outbox_a, permissions=perms)

    monkeypatch.setattr(_outbox_bindings, "_MAX_BUCKET_BYTES", 420)

    dk_a = digest_bytes(b"r8-bucket-key-a")
    ev_a = _enqueue_hook(spool_a, stream=stream_a, dk=dk_a, note="bucket-a")
    assert ev_a.sequence == 1

    cursor_path_a = _stream_dir(outbox_a, stream_a) / ".seq_cursor.json"
    before_bytes = cursor_path_a.read_bytes()
    before_obj = json.loads(before_bytes.decode("utf-8"))
    assert before_obj["binding_count"] == 1
    assert before_obj["pending_binding"] is None

    dk_b = _same_bucket_key(dk_a)
    with pytest.raises(BrainError) as bucket_err:
        _enqueue_hook(spool_a, stream=stream_a, dk=dk_b, note="bucket-b")
    assert bucket_err.value.code is ErrorCode.STORAGE_FULL

    assert cursor_path_a.read_bytes() == before_bytes

    ra = _enqueue_hook(spool_a, stream=stream_a, dk=dk_a, note="bucket-a")
    assert (ra.event_id, ra.sequence) == (ev_a.event_id, 1)

    evicted = spool_a.apply_ack(
        CaptureBatchAck(
            producer_stream=stream_a,
            repo_id="repo-r8",
            checkout_id="chk-r8",
            committed_event_sequences=(1,),
            contiguous_event_acked_through=1,
            acked_producer_gap_sequences=(),
            accepted_count=1,
            deduped_count=0,
            policy_disabled=False,
        )
    )
    assert evicted == 1
    assert spool_a.read_pending(limit=10, producer_stream=stream_a) == []

    # --- Part B: Link/junction sdir fails closed with UNSAFE_PATH before reading .seq_cursor.json ---
    outbox_b = trusted_tmp / "outbox-r8-link-sdir"
    stream_b = "stream-r8-link-sdir"
    ext_dir = trusted_tmp / "external-sdir-target"
    ext_dir.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(ext_dir)
    ext_cursor = ext_dir / ".seq_cursor.json"
    ext_cursor.write_bytes(
        canonical_json(
            {
                "schema_version": 3,
                "next_seq": 99,
                "binding_count": 0,
                "acked_ranges": [],
                "pending_binding": None,
            }
        )
    )
    perms.secure_file(ext_cursor)

    outbox_b.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(outbox_b)
    streams_dir_b = outbox_b / _STREAMS_DIR
    streams_dir_b.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(streams_dir_b)

    link_sdir = _stream_dir(outbox_b, stream_b)
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(ext_dir), str(link_sdir))
    else:
        os.symlink(ext_dir, link_sdir)

    spool_b = OutboxSpool(outbox_b, permissions=perms)
    with pytest.raises(BrainError) as link_err:
        _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(b"r8-link-k1"), note="link")
    assert link_err.value.code is ErrorCode.UNSAFE_PATH
