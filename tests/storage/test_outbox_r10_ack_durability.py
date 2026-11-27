"""R10 storage regression tests for v4 ack durability, page-cap recovery, fences, and deadlines."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord, OutboxPermissionsPort, ProducerCaptureGap
from superbrain.storage import _outbox_acks, _outbox_seq
from superbrain.storage._outbox_io import _STREAMS_DIR, replace_file_resilient, stream_dir_key
from superbrain.storage._outbox_seq import read_stream_cursor
from superbrain.storage.outbox import OutboxSpool

_REC_AT = "2026-11-27T08:00:00Z"


def _mk_event(stream: str, seq: int, *, event_id: str | None = None, note: str = "ok") -> CaptureEventRecord:
    return CaptureEventRecord(
        event_id=event_id or f"ev-{stream}-{seq}",
        producer_stream=stream,
        sequence=seq,
        harness_id="claude-code",
        kind="command_result",
        recorded_at=_REC_AT,
        payload={"seq": seq, "note": note},
    )


def _mk_gap(stream: str, seq: int, *, gap_id: str = "gap-r10") -> ProducerCaptureGap:
    return ProducerCaptureGap(
        gap_id=gap_id,
        producer_stream=stream,
        sequence=seq,
        reason="hook_timeout",
        recorded_at=_REC_AT,
        estimated_count=1,
        duration_ms=50,
    )


def _stream_dir(outbox_root: Path, stream: str) -> Path:
    return outbox_root / _STREAMS_DIR / stream_dir_key(stream)


def _write_cursor_json(
    outbox_root: Path, stream: str, obj: dict[str, Any], perms: OutboxPermissionsPort
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
    deadline_ns: int | None = None,
) -> CaptureEventRecord:
    return spool.enqueue_hook_event(
        producer_stream=stream,
        build_event=lambda seq, ev_id, _ts: _mk_event(stream, seq, event_id=ev_id, note=note),
        explicit_sequence=explicit_seq,
        dedup_key=dk,
        fallback_recorded_at=_REC_AT,
        deadline_ns=deadline_ns,
    )


def _ack(stream: str, *, committed: tuple[int, ...] = (), contiguous: int = 0) -> CaptureBatchAck:
    return CaptureBatchAck(
        producer_stream=stream,
        repo_id="repo-r10",
        checkout_id="chk-r10",
        committed_event_sequences=committed,
        contiguous_event_acked_through=contiguous,
        acked_producer_gap_sequences=(),
        accepted_count=len(committed),
        deduped_count=0,
        policy_disabled=False,
    )


def _setup_v4_two_pages(
    outbox: Path, stream: str, perms: OutboxPermissionsPort
) -> tuple[OutboxSpool, Path, Path, Path]:
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(f"{stream}-k1".encode()), note="n1", explicit_seq=1)
    spool.apply_ack(_ack(stream, committed=(2, 5_000)))
    sdir = _stream_dir(outbox, stream)
    return spool, sdir, sdir / ".acks", sdir / ".seq_cursor.json"


def _invoke_stream_op(spool: OutboxSpool, *, op: str, stream: str, seq: int, tag: str) -> None:
    if op == "gap":
        spool.enqueue_gap(_mk_gap(stream, seq, gap_id=f"gap-{tag}"))
    elif op == "event":
        spool.enqueue_event(_mk_event(stream, seq, event_id=f"ev-{tag}"))
    elif op == "hook":
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(f"hook-{tag}".encode()))
    else:
        spool.apply_ack(_ack(stream, committed=(seq,)))


def test_r10_f1_crash_between_page_write_and_cursor_commit_preserves_acks(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 1: Crash before cursor commit or before prune never loses committed ACKs."""
    perms = os_adapters().permissions

    # Part A: Crash after .acks page write and BEFORE .seq_cursor.json replace
    outbox_a, stream_a = trusted_tmp / "outbox-r10-f1a", "stream-r10-f1a"
    spool_a = OutboxSpool(outbox_a, permissions=perms)
    keys_a = [digest_bytes(f"r10-f1a-k{i}".encode()) for i in range(1, 6)]
    evs_a = [_enqueue_hook(spool_a, stream=stream_a, dk=keys_a[i - 1], note=f"n{i}") for i in range(1, 6)]
    assert spool_a.apply_ack(_ack(stream_a, committed=(2, 3, 5))) == 3

    def _crash_before_cursor(*_args: Any, **_kwargs: Any) -> None:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated crash before cursor replace")

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_seq, "_persist_cursor_payload", _crash_before_cursor)
        with pytest.raises(BrainError) as err_a:
            spool_a.apply_ack(_ack(stream_a, committed=(1,)))
        assert err_a.value.code is ErrorCode.DEADLINE_EXCEEDED

    sdir_a = _stream_dir(outbox_a, stream_a)
    spool_a2 = OutboxSpool(outbox_a, permissions=perms)
    cur_a = read_stream_cursor(sdir_a, perms)
    assert all(cur_a.is_event_acked(s) for s in (2, 3, 5))
    assert cur_a.is_event_acked(1) is False and cur_a.is_event_acked(4) is False

    retry_2 = _enqueue_hook(spool_a2, stream=stream_a, dk=keys_a[1], note="n2")
    assert (retry_2.event_id, retry_2.sequence) == (evs_a[1].event_id, 2)
    assert [e.sequence for e in spool_a2.read_pending(limit=10, producer_stream=stream_a)] == [1, 4]

    assert spool_a2.apply_ack(_ack(stream_a, committed=(1,))) == 1
    cur_a_done = read_stream_cursor(sdir_a, perms)
    assert cur_a_done.contiguous_acked_through == 3
    assert cur_a_done.is_event_acked(5) is True and cur_a_done.is_event_acked(4) is False

    # Part B: Crash AFTER cursor commit and BEFORE pruning old pages
    outbox_b, stream_b = trusted_tmp / "outbox-r10-f1b", "stream-r10-f1b"
    spool_b = OutboxSpool(outbox_b, permissions=perms)
    for i in range(1, 6):
        _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(f"r10-f1b-k{i}".encode()), note=f"b{i}")
    assert spool_b.apply_ack(_ack(stream_b, committed=(2, 3, 5))) == 3

    orig_persist = _outbox_seq._persist_cursor_payload

    def _crash_after_cursor(stream_dir: Path, payload: bytes, p: OutboxPermissionsPort) -> None:
        orig_persist(stream_dir, payload, p)
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated crash after cursor commit before prune")

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_seq, "_persist_cursor_payload", _crash_after_cursor)
        with pytest.raises(BrainError) as err_b:
            spool_b.apply_ack(_ack(stream_b, committed=(1,)))
        assert err_b.value.code is ErrorCode.DEADLINE_EXCEEDED

    sdir_b = _stream_dir(outbox_b, stream_b)
    spool_b2 = OutboxSpool(outbox_b, permissions=perms)
    cur_b = read_stream_cursor(sdir_b, perms)
    assert cur_b.contiguous_acked_through == 3
    assert all(cur_b.is_event_acked(s) for s in (1, 2, 3, 5)) and cur_b.is_event_acked(4) is False

    assert spool_b2.apply_ack(_ack(stream_b, committed=(4,))) == 1
    cur_b_done = read_stream_cursor(sdir_b, perms)
    assert cur_b_done.contiguous_acked_through == 5
    acks_b = sdir_b / ".acks"
    assert not acks_b.exists() or list(acks_b.glob("*.json")) == []


def test_r10_f2_recovery_at_max_ack_pages_during_transitional_page_swap(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 2: Transitional extra page at _MAX_ACK_PAGES recovers cleanly; true overflow fails closed."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f2", "stream-r10-f2"
    spool = OutboxSpool(outbox, permissions=perms)

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_acks, "_MAX_ACK_PAGES", 4)
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f2-k1"), explicit_seq=1)
        spool.apply_ack(_ack(stream, committed=tuple(range(2, 4097)) + (5_000, 9_000, 13_000)))
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f2-k17000"), explicit_seq=17_000)

        sdir = _stream_dir(outbox, stream)
        acks_dir, cursor_path = sdir / ".acks", sdir / ".seq_cursor.json"
        assert len(list(acks_dir.glob("*.json"))) == 4

        def _crash_before_cursor(*_args: Any, **_kwargs: Any) -> None:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated crash before cursor replace")

        with monkeypatch.context() as crash_mp:
            crash_mp.setattr(_outbox_seq, "_persist_cursor_payload", _crash_before_cursor)
            with pytest.raises(BrainError) as crash_err:
                spool.apply_ack(_ack(stream, committed=(1, 17_000)))
            assert crash_err.value.code is ErrorCode.DEADLINE_EXCEEDED

        assert len(list(acks_dir.glob("*.json"))) == 5
        spool2 = OutboxSpool(outbox, permissions=perms)
        cur_mid = read_stream_cursor(sdir, perms)
        assert cur_mid.is_event_acked(5_000) is True
        assert [e.sequence for e in spool2.read_pending(limit=10, producer_stream=stream)] == [1, 17_000]

        assert spool2.apply_ack(_ack(stream, committed=(1, 17_000))) == 2
        cur_done = read_stream_cursor(sdir, perms)
        assert cur_done.contiguous_acked_through == 4096
        assert all(cur_done.is_event_acked(s) for s in (1, 4096, 5_000, 9_000, 13_000, 17_000))
        assert cur_done.is_event_acked(4097) is False
        assert len(list(acks_dir.glob("*.json"))) == 4
        assert list(acks_dir.glob("p0000000000000000*.json")) == []

        _enqueue_hook(spool2, stream=stream, dk=digest_bytes(b"r10-f2-k21000"), explicit_seq=21_000)
        before_cursor = cursor_path.read_bytes()
        before_acks = {p.name: p.read_bytes() for p in sorted(acks_dir.iterdir())}
        with pytest.raises(BrainError) as full_err:
            spool2.apply_ack(_ack(stream, committed=(21_000,)))
        assert full_err.value.code is ErrorCode.STORAGE_FULL
        assert cursor_path.read_bytes() == before_cursor
        assert {p.name: p.read_bytes() for p in sorted(acks_dir.iterdir())} == before_acks


def test_r10_f3_v3_upgrade_storage_full_leaves_bindings_and_frames_untouched(trusted_tmp: Path) -> None:
    """Finding 3: v3 upgrade failing with STORAGE_FULL must not mutate .bindings or publish frames."""
    perms = os_adapters().permissions
    sparse_1025 = [[i * 4096 + 1, i * 4096 + 1] for i in range(1, 1026)]
    pb_row = [digest_bytes(b"r10-f3-pb"), 1, "ev-r10-f3-pb", _REC_AT, digest_bytes(b"pb-payload")]

    for op_name in ("hook", "ack", "gap", "event"):
        outbox, stream = trusted_tmp / f"outbox-r10-f3-{op_name}", f"stream-r10-f3-{op_name}"
        spool = OutboxSpool(outbox, permissions=perms)
        v3_obj: dict[str, Any] = {
            "schema_version": 3, "next_seq": 4_300_000, "binding_count": 0,
            "acked_ranges": sparse_1025, "pending_binding": pb_row,
        }
        cursor_path, v3_raw = _write_cursor_json(outbox, stream, v3_obj, perms)
        assert len(v3_raw) < 262_144
        sdir = _stream_dir(outbox, stream)

        with pytest.raises(BrainError) as err:
            seq = 4_300_000 if op_name == "ack" else 4_300_001
            _invoke_stream_op(spool, op=op_name, stream=stream, seq=seq, tag=f"f3-{op_name}")
        assert err.value.code is ErrorCode.STORAGE_FULL
        assert cursor_path.read_bytes() == v3_raw
        assert not (sdir / ".bindings").exists()
        acks_dir = sdir / ".acks"
        assert not acks_dir.exists() or list(acks_dir.glob("*.json")) == []
        assert list(sdir.glob("*.frame")) == []
        assert spool.read_pending(limit=10, producer_stream=stream) == []


def test_r10_f4_missing_tampered_extra_ack_pages_and_orphan_acks_fail_closed(trusted_tmp: Path) -> None:
    """Finding 4: Missing/tampered/extra-field .acks pages, missing .acks, or orphan .acks fail closed."""
    perms = os_adapters().permissions

    # (a) Deleting page 1 -> INTEGRITY_FAILURE across read/hook/ack/gap
    spool_a, sdir_a, acks_a, _cur_a = _setup_v4_two_pages(trusted_tmp / "outbox-r10-f4a", "stream-f4a", perms)
    p1_files = sorted(acks_a.glob("p0000000000000001*.json"))
    assert len(p1_files) == 1
    p1_files[0].unlink()
    with pytest.raises(BrainError) as e_read:
        read_stream_cursor(sdir_a, perms)
    assert e_read.value.code is ErrorCode.INTEGRITY_FAILURE
    for op_name in ("hook", "ack", "gap"):
        with pytest.raises(BrainError) as e_op:
            _invoke_stream_op(spool_a, op=op_name, stream="stream-f4a", seq=6_000, tag=f"f4a-{op_name}")
        assert e_op.value.code is ErrorCode.INTEGRITY_FAILURE

    # (b) Mutating one hex char in page 0's bitmap_hex -> INTEGRITY_FAILURE
    _sb, sdir_b, acks_b, _cb = _setup_v4_two_pages(trusted_tmp / "outbox-r10-f4b", "stream-f4b", perms)
    p0_b = sorted(acks_b.glob("p0000000000000000*.json"))[0]
    obj_b = json.loads(p0_b.read_text(encoding="utf-8"))
    obj_b["bitmap_hex"] = obj_b["bitmap_hex"][:-1] + ("a" if obj_b["bitmap_hex"][-1] != "a" else "b")
    p0_b.write_bytes(canonical_json(obj_b))
    perms.secure_file(p0_b)
    with pytest.raises(BrainError) as e_tamper:
        read_stream_cursor(sdir_b, perms)
    assert e_tamper.value.code is ErrorCode.INTEGRITY_FAILURE

    # (c) Unexpected JSON key "extra": 1 in page 0 -> INTEGRITY_FAILURE
    _sc, sdir_c, acks_c, _cc = _setup_v4_two_pages(trusted_tmp / "outbox-r10-f4c", "stream-f4c", perms)
    p0_c = sorted(acks_c.glob("p0000000000000000*.json"))[0]
    obj_c = json.loads(p0_c.read_text(encoding="utf-8"))
    obj_c["extra"] = 1
    p0_c.write_bytes(canonical_json(obj_c))
    perms.secure_file(p0_c)
    with pytest.raises(BrainError) as e_extra:
        read_stream_cursor(sdir_c, perms)
    assert e_extra.value.code is ErrorCode.INTEGRITY_FAILURE

    # (d) Deleting .acks directory when v4 cursor expects pages -> INTEGRITY_FAILURE
    _sd, sdir_d, acks_d, _cd = _setup_v4_two_pages(trusted_tmp / "outbox-r10-f4d", "stream-f4d", perms)
    shutil.rmtree(acks_d)
    with pytest.raises(BrainError) as e_no_acks:
        read_stream_cursor(sdir_d, perms)
    assert e_no_acks.value.code is ErrorCode.INTEGRITY_FAILURE

    # (e) Deleting .seq_cursor.json while .acks retains page files -> INTEGRITY_FAILURE
    _se, sdir_e, _acks_e, cur_e = _setup_v4_two_pages(trusted_tmp / "outbox-r10-f4e", "stream-f4e", perms)
    cur_e.unlink()
    with pytest.raises(BrainError) as e_orphan:
        read_stream_cursor(sdir_e, perms)
    assert e_orphan.value.code is ErrorCode.INTEGRITY_FAILURE


def test_r10_f5_version_fence_blocks_legacy_writers_and_future_versions_pre_publication(
    trusted_tmp: Path,
) -> None:
    """Finding 5: streams/ regular fence exists for v4 and future cursor/fence v5 fails pre-publication."""
    perms = os_adapters().permissions

    # (a) v4 sparse ACKs create regular non-directory fence file in streams/ without breaking v4 reads
    outbox_a, stream_a = trusted_tmp / "outbox-r10-f5a", "stream-r10-f5a"
    spool_a = OutboxSpool(outbox_a, permissions=perms)
    _enqueue_hook(spool_a, stream=stream_a, dk=digest_bytes(b"r10-f5a-k1"), explicit_seq=1)
    spool_a.apply_ack(_ack(stream_a, committed=(2,)))
    streams_dir_a = outbox_a / _STREAMS_DIR
    fence_files = [
        p for p in streams_dir_a.iterdir() if p.is_file() and not p.name.endswith(".part") and ".init-" not in p.name
    ]
    assert len(fence_files) >= 1
    assert [e.sequence for e in spool_a.read_pending(limit=10, producer_stream=stream_a)] == [1]
    assert fence_files[0].is_file()
    fence_name, fence_raw = fence_files[0].name, fence_files[0].read_bytes()

    # (b1) Future cursor version 5 rejects gap/event/hook/ack with zero frames written
    v5_cur: dict[str, Any] = {
        "schema_version": 5, "next_seq": 2, "binding_count": 0,
        "contiguous_acked_through": 0, "pending_binding": None,
    }
    for op_name in ("gap", "event", "hook", "ack"):
        outbox, stream = trusted_tmp / f"outbox-r10-f5-cur-{op_name}", f"stream-r10-f5-cur-{op_name}"
        spool = OutboxSpool(outbox, permissions=perms)
        _write_cursor_json(outbox, stream, v5_cur, perms)
        sdir = _stream_dir(outbox, stream)
        with pytest.raises(BrainError) as err:
            _invoke_stream_op(spool, op=op_name, stream=stream, seq=2, tag=f"f5c-{op_name}")
        assert err.value.code is ErrorCode.INTEGRITY_FAILURE
        assert list(sdir.glob("*.frame")) == []

    # (b2) Future fence version 5 in streams/ rejects gap/event/hook/ack with zero frames written
    fence_obj = json.loads(fence_raw.decode("utf-8"))
    assert isinstance(fence_obj, dict)
    version_keys = [k for k, v in fence_obj.items() if type(v) is int and "version" in k]
    assert version_keys
    for k in version_keys:
        fence_obj[k] = 5
    future_fence_raw = canonical_json(fence_obj)

    for op_name in ("gap", "event", "hook", "ack"):
        outbox, stream = trusted_tmp / f"outbox-r10-f5-fence-{op_name}", f"stream-r10-f5-fence-{op_name}"
        spool = OutboxSpool(outbox, permissions=perms)
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(f"f5f-init-{op_name}".encode()), explicit_seq=1)
        assert spool.apply_ack(_ack(stream, committed=(1,))) == 1
        sdir = _stream_dir(outbox, stream)
        assert list(sdir.glob("*.frame")) == []
        fence_path = outbox / _STREAMS_DIR / fence_name
        fence_path.write_bytes(future_fence_raw)
        perms.secure_file(fence_path)
        with pytest.raises(BrainError) as err:
            _invoke_stream_op(spool, op=op_name, stream=stream, seq=2, tag=f"f5f-{op_name}")
        assert err.value.code is ErrorCode.INTEGRITY_FAILURE
        assert list(sdir.glob("*.frame")) == []


def test_r10_f6_recovery_write_ack_pages_checks_deadline_between_pages(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 6: Recovery with pre-existing .acks checks deadline between page writes."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f6", "stream-r10-f6"
    setup_spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(setup_spool, stream=stream, dk=digest_bytes(b"r10-f6-init"), explicit_seq=1)
    setup_spool.apply_ack(_ack(stream, committed=(2,)))
    setup_spool.apply_ack(_ack(stream, committed=(1,)))

    sdir = _stream_dir(outbox, stream)
    acks_dir = sdir / ".acks"
    if not acks_dir.exists():
        acks_dir.mkdir()
        perms.secure_directory(acks_dir)

    v3_obj: dict[str, Any] = {
        "schema_version": 3, "next_seq": 13_001, "binding_count": 0,
        "acked_ranges": [[5_000, 5_000], [9_000, 9_000], [13_000, 13_000]], "pending_binding": None,
    }
    cursor_path, v3_raw = _write_cursor_json(outbox, stream, v3_obj, perms)

    now, writes = [100], [0]
    spool = OutboxSpool(outbox, monotonic_ns=lambda: now[0], permissions=perms)
    orig_replace = replace_file_resilient

    def _expire_after_first_page(src: Path, dst: Path) -> None:
        orig_replace(src, dst)
        writes[0] += 1
        if writes[0] == 1:
            now[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_acks, "replace_file_resilient", _expire_after_first_page)
        with pytest.raises(BrainError) as err:
            _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f6-new"), deadline_ns=1_000)
        assert err.value.code is ErrorCode.DEADLINE_EXCEEDED

    assert len(list(acks_dir.glob("*.json"))) <= 1
    assert cursor_path.read_bytes() == v3_raw

    now[0] = 100
    ev = _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f6-new"), deadline_ns=10_000_000)
    assert ev.sequence == 13_001
    assert json.loads(cursor_path.read_text(encoding="utf-8"))["schema_version"] == 4
    cur = read_stream_cursor(sdir, perms)
    assert all(cur.is_event_acked(s) for s in (5_000, 9_000, 13_000))
    assert cur.is_event_acked(4_999) is False


def test_r10_f7_interrupted_v4_fence_part_recovers_cleanly(trusted_tmp: Path) -> None:
    """Crash leaving streams/.v4_fence-*.part must sweep cleanly on reopen rather than bricking outbox."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f7", "stream-r10-f7"
    spool = OutboxSpool(outbox, permissions=perms)
    spool.enqueue_event(_mk_event(stream, 1))

    staged = outbox / _STREAMS_DIR / (".v4_fence-" + ("a" * 32) + ".part")
    staged.write_bytes(b'{"schema_version":4}')
    perms.secure_file(staged)

    reopened = OutboxSpool(outbox, permissions=perms)
    assert staged.exists()
    assert [e.sequence for e in reopened.read_pending(limit=10, producer_stream=stream)] == [1]
    assert not staged.exists()

    staged2 = outbox / _STREAMS_DIR / (".v4_fence-" + ("b" * 32) + ".part")
    staged2.write_bytes(b'{"schema_version":4}')
    perms.secure_file(staged2)
    assert reopened.apply_ack(_ack(stream, committed=(1,))) == 1
    assert not staged2.exists()
    ev = _enqueue_hook(reopened, stream=stream, dk=digest_bytes(b"r10-f7-hook"), explicit_seq=2)
    assert ev.sequence == 2


def test_r10_f8_read_pending_verifies_cursor_acks_and_v4_fence(trusted_tmp: Path) -> None:
    """read_pending() and read_pending(producer_stream=...) must fail closed on missing acks/orphan/future fence."""
    perms = os_adapters().permissions

    outbox_a, stream_a = trusted_tmp / "outbox-r10-f8-missing", "stream-r10-f8-missing"
    spool_a = OutboxSpool(outbox_a, permissions=perms)
    _enqueue_hook(spool_a, stream=stream_a, dk=digest_bytes(b"r10-f8-a"))
    spool_a.apply_ack(_ack(stream_a, committed=(5_000,)))
    page_file = next((_stream_dir(outbox_a, stream_a) / ".acks").glob("*.json"))
    page_file.unlink()
    for filtered in (None, stream_a):
        with pytest.raises(BrainError) as err:
            spool_a.read_pending(limit=10, producer_stream=filtered)
        assert err.value.code is ErrorCode.INTEGRITY_FAILURE

    outbox_b, stream_b = trusted_tmp / "outbox-r10-f8-fence", "stream-r10-f8-fence"
    spool_b = OutboxSpool(outbox_b, permissions=perms)
    _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(b"r10-f8-b"))
    spool_b.apply_ack(_ack(stream_b, committed=(5_000,)))
    fence = next((outbox_b / _STREAMS_DIR).glob(".*fence*"))
    fence.write_bytes(canonical_json({"schema_version": 5}))
    perms.secure_file(fence)
    for filtered in (None, stream_b):
        with pytest.raises(BrainError) as err_f:
            spool_b.read_pending(limit=10, producer_stream=filtered)
        assert err_f.value.code is ErrorCode.INTEGRITY_FAILURE

    outbox_c, stream_c = trusted_tmp / "outbox-r10-f8-orphan", "stream-r10-f8-orphan"
    spool_c = OutboxSpool(outbox_c, permissions=perms)
    _enqueue_hook(spool_c, stream=stream_c, dk=digest_bytes(b"r10-f8-c"))
    spool_c.apply_ack(_ack(stream_c, committed=(5_000,)))
    (_stream_dir(outbox_c, stream_c) / ".seq_cursor.json").unlink()
    for filtered in (None, stream_c):
        with pytest.raises(BrainError) as err_o:
            spool_c.read_pending(limit=10, producer_stream=filtered)
        assert err_o.value.code is ErrorCode.INTEGRITY_FAILURE


def test_r10_f9_write_ack_pages_skips_replace_after_fsync_deadline(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If deadline expires during fsync, write_ack_pages must clean temp file and publish zero pages."""
    perms = os_adapters().permissions
    now = [0]
    outbox, stream = trusted_tmp / "outbox-r10-f9", "stream-r10-f9"
    spool = OutboxSpool(outbox, permissions=perms, monotonic_ns=lambda: now[0])
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f9-init"))
    spool.apply_ack(_ack(stream, committed=(5_000,)))
    sdir = _stream_dir(outbox, stream)
    cur_path = sdir / ".seq_cursor.json"
    initial_cur = cur_path.read_bytes()
    before_files = {p.name for p in (sdir / ".acks").iterdir()}

    real_fsync = os.fsync

    def _expire_during_fsync(fd: int) -> None:
        real_fsync(fd)
        now[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(os, "fsync", _expire_during_fsync)
        with pytest.raises(BrainError) as err:
            spool.apply_ack(_ack(stream, committed=(9_000,)), deadline_ns=1_000)
        assert err.value.code is ErrorCode.DEADLINE_EXCEEDED

    after_files = {p.name for p in (sdir / ".acks").iterdir()}
    assert cur_path.read_bytes() == initial_cur
    assert after_files == before_files


def test_r10_f10_recovery_capacity_overflow_is_pure_preflight(trusted_tmp: Path) -> None:
    """v3 cursor recovery fitting at 1024 pages must still reject an overflowing apply_ack with zero disk writes."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f10", "stream-r10-f10"
    spool = OutboxSpool(outbox, permissions=perms)
    ranges = [[i * 4096 + 1, i * 4096 + 1] for i in range(1, 1025)]
    pending = [digest_bytes(b"r10-f10-pending"), 1, "ev-f10-pending", _REC_AT, digest_bytes(b"payload-f10")]
    cur_obj: dict[str, Any] = {
        "schema_version": 3, "next_seq": 4_300_000, "binding_count": 0,
        "acked_ranges": ranges, "pending_binding": pending,
    }
    cur_path, initial_bytes = _write_cursor_json(outbox, stream, cur_obj, perms)
    with pytest.raises(BrainError) as err:
        spool.apply_ack(_ack(stream, committed=(1025 * 4096 + 1,)))
    assert err.value.code is ErrorCode.STORAGE_FULL
    sdir = _stream_dir(outbox, stream)
    assert cur_path.read_bytes() == initial_bytes
    assert not (sdir / ".bindings").exists()
    assert not (sdir / ".acks").exists()
