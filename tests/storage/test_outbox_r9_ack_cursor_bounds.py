"""R9 storage regression tests for bounded v4 ack bitset paging, cursor limits, and v3 upgrade."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

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
from superbrain.storage._outbox_bindings import HookBindingRecord
from superbrain.storage._outbox_io import _STREAMS_DIR, stream_dir_key
from superbrain.storage._outbox_seq import StreamSeqCursor, read_stream_cursor, write_stream_cursor
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


def _stream_dir(outbox_root: Path, stream: str) -> Path:
    return outbox_root / _STREAMS_DIR / stream_dir_key(stream)


def _write_cursor_json(
    outbox_root: Path,
    stream: str,
    obj: dict[str, Any],
    perms: OutboxPermissionsPort,
) -> tuple[Path, bytes]:
    streams_dir = outbox_root / _STREAMS_DIR
    sdir = streams_dir / stream_dir_key(stream)
    streams_dir.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(streams_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(sdir)
    cursor_path = sdir / ".seq_cursor.json"
    raw = canonical_json(obj)
    cursor_path.write_bytes(raw)
    perms.secure_file(cursor_path)
    return cursor_path, raw


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


def _ack(
    stream: str,
    *,
    committed: tuple[int, ...] = (),
    contiguous: int = 0,
    repo_id: str = "repo-r9",
    checkout_id: str = "chk-r9",
) -> CaptureBatchAck:
    return CaptureBatchAck(
        producer_stream=stream,
        repo_id=repo_id,
        checkout_id=checkout_id,
        committed_event_sequences=committed,
        contiguous_event_acked_through=contiguous,
        acked_producer_gap_sequences=(),
        accepted_count=len(committed),
        deduped_count=0,
        policy_disabled=False,
    )


def test_r9_p1_sparse_ack_boundary_v3_upgrade_retry_and_new_enqueue(trusted_tmp: Path) -> None:
    """Near-256KiB v3 cursor upgrades to bounded v4 on apply_ack and preserves retries and new seqs."""
    perms = os_adapters().permissions
    outbox = trusted_tmp / "outbox-r9-p1"
    stream = "stream-r9-p1"
    spool = OutboxSpool(outbox, permissions=perms)

    dk_1 = digest_bytes(b"r9-p1-k1")
    dk_mid = digest_bytes(b"r9-p1-kmid")
    dk_47434 = digest_bytes(b"r9-p1-k47434")

    _enqueue_hook(spool, stream=stream, dk=dk_1, note="n1")
    assert spool.apply_ack(_ack(stream, committed=(1,))) == 1

    ev_mid = _enqueue_hook(spool, stream=stream, dk=dk_mid, note="nmid", explicit_seq=37433)
    assert ev_mid.sequence == 37433
    assert spool.apply_ack(_ack(stream, committed=(37433,))) == 1

    ev_47434 = _enqueue_hook(spool, stream=stream, dk=dk_47434, note="n47434", explicit_seq=47434)
    assert ev_47434.sequence == 47434
    assert [e.sequence for e in spool.read_pending(limit=10, producer_stream=stream)] == [47434]

    # Replace .seq_cursor.json with a valid v3 cursor packed right under _MAX_CURSOR_BYTES (262,144).
    sparse_ranges = [[i, i] for i in range(1, 39022, 2)]
    cursor_path, v3_raw = _write_cursor_json(
        outbox,
        stream,
        {
            "schema_version": 3,
            "next_seq": 47435,
            "binding_count": 3,
            "acked_ranges": sparse_ranges,
            "pending_binding": None,
        },
        perms,
    )
    assert 262_000 < len(v3_raw) <= 262_144

    evicted = spool.apply_ack(_ack(stream, committed=(47434,)))
    assert evicted == 1
    assert spool.read_pending(limit=10, producer_stream=stream) == []

    cursor_bytes = cursor_path.read_bytes()
    assert len(cursor_bytes) <= 1024
    assert json.loads(cursor_bytes.decode("utf-8"))["schema_version"] == 4

    spool2 = OutboxSpool(outbox, permissions=perms)
    sdir = _stream_dir(outbox, stream)
    cur = read_stream_cursor(sdir, perms)
    assert cur.is_event_acked(47434) is True
    assert cur.is_event_acked(1) is True
    assert cur.is_event_acked(37433) is True
    assert cur.is_event_acked(2) is False
    assert cur.is_event_acked(47433) is False

    r_47434 = _enqueue_hook(spool2, stream=stream, dk=dk_47434, note="n47434")
    assert (r_47434.event_id, r_47434.sequence) == (ev_47434.event_id, 47434)
    r_mid = _enqueue_hook(spool2, stream=stream, dk=dk_mid, note="nmid")
    assert (r_mid.event_id, r_mid.sequence) == (ev_mid.event_id, 37433)
    assert spool2.read_pending(limit=10, producer_stream=stream) == []

    with pytest.raises(BrainError) as conflict_err:
        _enqueue_hook(spool2, stream=stream, dk=dk_47434, note="tampered-47434")
    assert conflict_err.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

    ev_new = _enqueue_hook(spool2, stream=stream, dk=digest_bytes(b"r9-p1-knew"), note="nnew")
    assert ev_new.sequence == 47435
    assert [e.sequence for e in spool2.read_pending(limit=10, producer_stream=stream)] == [47435]


def test_r9_p1_v3_boundary_upgrade_via_pending_binding_and_gap_and_ack_page_cap(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Near-limit v3 upgrade on hook/gap, watermark compaction, page cap, writer bounds, and link safety."""
    perms = os_adapters().permissions

    # --- Case A: v3 cursor near 262,144 bytes upgraded via enqueue_hook_event ---
    outbox_a = trusted_tmp / "outbox-r9-case-a"
    stream_a = "stream-r9-case-a"
    spool_a = OutboxSpool(outbox_a, permissions=perms)
    cursor_a, raw_a = _write_cursor_json(
        outbox_a,
        stream_a,
        {
            "schema_version": 3,
            "next_seq": 47435,
            "binding_count": 0,
            "acked_ranges": [[i, i] for i in range(1, 39006, 2)],
            "pending_binding": None,
        },
        perms,
    )
    assert 262_000 < len(raw_a) <= 262_144

    ev_a = _enqueue_hook(spool_a, stream=stream_a, dk=digest_bytes(b"r9-case-a-k1"), note="case-a")
    assert ev_a.sequence == 47435
    assert len(cursor_a.read_bytes()) <= 1024
    assert json.loads(cursor_a.read_text(encoding="utf-8"))["schema_version"] == 4

    reopened_a = OutboxSpool(outbox_a, permissions=perms)
    cur_a = read_stream_cursor(_stream_dir(outbox_a, stream_a), perms)
    assert cur_a.is_event_acked(1) is True
    assert cur_a.is_event_acked(37419) is True
    assert cur_a.is_event_acked(2) is False
    assert [e.sequence for e in reopened_a.read_pending(limit=10, producer_stream=stream_a)] == [47435]

    # --- Case B: v3 cursor at ~262,139 bytes upgraded via enqueue_gap ---
    outbox_b = trusted_tmp / "outbox-r9-case-b"
    stream_b = "stream-r9-case-b"
    spool_b = OutboxSpool(outbox_b, permissions=perms)
    cursor_b, raw_b = _write_cursor_json(
        outbox_b,
        stream_b,
        {
            "schema_version": 3,
            "next_seq": 47435,
            "binding_count": 0,
            "acked_ranges": [[i, i] for i in range(1, 39022, 2)],
            "pending_binding": None,
        },
        perms,
    )
    assert 262_000 < len(raw_b) <= 262_144

    spool_b.enqueue_gap(
        ProducerCaptureGap(
            gap_id="gap-r9-50000",
            producer_stream=stream_b,
            sequence=50000,
            reason="hook_timeout",
            recorded_at=_REC_AT,
            estimated_count=1,
            duration_ms=100,
        )
    )
    assert len(cursor_b.read_bytes()) <= 1024
    assert json.loads(cursor_b.read_text(encoding="utf-8"))["schema_version"] == 4

    OutboxSpool(outbox_b, permissions=perms)
    cur_b = read_stream_cursor(_stream_dir(outbox_b, stream_b), perms)
    assert cur_b.next_seq == 50001
    assert cur_b.is_event_acked(1) is True
    assert cur_b.is_event_acked(37433) is True
    assert cur_b.is_event_acked(2) is False

    # --- Case C1: Watermark compaction & .acks pruning ---
    outbox_c1 = trusted_tmp / "outbox-r9-compact"
    stream_c1 = "stream-r9-compact"
    spool_c1 = OutboxSpool(outbox_c1, permissions=perms)
    for seq in (1, 2, 3):
        _enqueue_hook(spool_c1, stream=stream_c1, dk=digest_bytes(f"r9-c1-{seq}".encode()), note=f"c1-{seq}")

    spool_c1.apply_ack(_ack(stream_c1, committed=(1,), contiguous=0))
    spool_c1.apply_ack(_ack(stream_c1, committed=(3,), contiguous=0))

    sdir_c1 = _stream_dir(outbox_c1, stream_c1)
    acks_dir_c1 = sdir_c1 / ".acks"
    assert acks_dir_c1.is_dir()
    assert (acks_dir_c1 / "p0000000000000000.json").is_file()

    spool_c1.apply_ack(_ack(stream_c1, committed=(2,), contiguous=0))
    c1_obj = json.loads((sdir_c1 / ".seq_cursor.json").read_text(encoding="utf-8"))
    assert c1_obj["contiguous_acked_through"] == 3
    assert not (acks_dir_c1 / "p0000000000000000.json").exists()
    if acks_dir_c1.exists():
        assert list(acks_dir_c1.glob("*.json")) == []

    cur_c1 = read_stream_cursor(sdir_c1, perms)
    assert cur_c1.is_event_acked(1) is True
    assert cur_c1.is_event_acked(2) is True
    assert cur_c1.is_event_acked(3) is True
    assert cur_c1.is_event_acked(4) is False

    # --- Case C2: Page cap fail-closed ---
    outbox_c2 = trusted_tmp / "outbox-r9-pagecap"
    stream_c2 = "stream-r9-pagecap"
    spool_c2 = OutboxSpool(outbox_c2, permissions=perms)
    _enqueue_hook(spool_c2, stream=stream_c2, dk=digest_bytes(b"r9-c2-10000"), note="c2", explicit_seq=10_000)
    sdir_c2 = _stream_dir(outbox_c2, stream_c2)
    cursor_c2 = sdir_c2 / ".seq_cursor.json"

    with monkeypatch.context() as mp:
        mp.setattr("superbrain.storage._outbox_acks._MAX_ACK_PAGES", 2)
        spool_c2.apply_ack(_ack(stream_c2, committed=(2,), contiguous=0))
        spool_c2.apply_ack(_ack(stream_c2, committed=(5_000,), contiguous=0))

        before_c2_bytes = cursor_c2.read_bytes()
        assert [e.sequence for e in spool_c2.read_pending(limit=10, producer_stream=stream_c2)] == [10_000]

        with pytest.raises(BrainError) as cap_err:
            spool_c2.apply_ack(_ack(stream_c2, committed=(10_000,), contiguous=0))
        assert cap_err.value.code is ErrorCode.STORAGE_FULL

        assert cursor_c2.read_bytes() == before_c2_bytes
        assert [e.sequence for e in spool_c2.read_pending(limit=10, producer_stream=stream_c2)] == [10_000]

    # --- Case C3: Writer cursor byte cap + legacy range guard ---
    outbox_w = trusted_tmp / "outbox-r9-writer"
    sdir_x = _stream_dir(outbox_w, "stream-r9-writer")
    (outbox_w / _STREAMS_DIR).mkdir(parents=True, exist_ok=True)
    perms.secure_directory(outbox_w / _STREAMS_DIR)
    sdir_x.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(sdir_x)

    write_stream_cursor(sdir_x, StreamSeqCursor(1), perms)
    baseline_bytes = (sdir_x / ".seq_cursor.json").read_bytes()

    with pytest.raises(BrainError) as legacy_err:
        write_stream_cursor(sdir_x, StreamSeqCursor(1, acked_ranges=((1, 1),)), perms)
    assert legacy_err.value.code is ErrorCode.INTEGRITY_FAILURE
    assert (sdir_x / ".seq_cursor.json").read_bytes() == baseline_bytes

    oversized_pb = HookBindingRecord(
        key=digest_bytes(b"r9-oversized-pb"),
        sequence=1,
        event_id="ev-" + ("x" * 263_000),
        recorded_at=_REC_AT,
        payload_digest=digest_bytes(b"pb"),
    )
    with pytest.raises(BrainError) as size_err:
        write_stream_cursor(sdir_x, StreamSeqCursor(2, pending_binding=oversized_pb), perms)
    assert size_err.value.code is ErrorCode.STORAGE_FULL
    assert (sdir_x / ".seq_cursor.json").read_bytes() == baseline_bytes

    # --- Case C4: .acks link safety ---
    outbox_link = trusted_tmp / "outbox-r9-acks-link"
    stream_link = "stream-r9-acks-link"
    spool_link = OutboxSpool(outbox_link, permissions=perms)
    _enqueue_hook(spool_link, stream=stream_link, dk=digest_bytes(b"r9-link-k1"), note="link")
    sdir_link = _stream_dir(outbox_link, stream_link)

    ext_acks = trusted_tmp / "external-acks-target"
    ext_acks.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(ext_acks)
    acks_link = sdir_link / ".acks"
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(ext_acks), str(acks_link))
    else:
        os.symlink(ext_acks, acks_link)

    with pytest.raises(BrainError) as ack_link_err:
        spool_link.apply_ack(_ack(stream_link, committed=(2,), contiguous=0))
    assert ack_link_err.value.code is ErrorCode.UNSAFE_PATH

    with pytest.raises(BrainError) as read_link_err:
        read_stream_cursor(sdir_link, perms)
    assert read_link_err.value.code is ErrorCode.UNSAFE_PATH
