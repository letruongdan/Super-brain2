"""R10 storage regression tests for v4 ack durability, page-cap recovery, fences, and deadlines."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord, OutboxPermissionsPort, ProducerCaptureGap
from superbrain.storage import _outbox_acks, _outbox_bindings, _outbox_seq
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


def _snapshot_tree_bytes(directory: Path) -> dict[str, bytes]:
    if not directory.exists():
        return {}
    return {
        p.relative_to(directory).as_posix(): p.read_bytes()
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def _repo_root_with_36bf08d9() -> Path | None:
    cur = Path(__file__).resolve().parent
    while cur != cur.parent:
        if (cur / ".git").exists():
            chk = subprocess.run(
                ["git", "-C", str(cur), "cat-file", "-e", "36bf08d9^{commit}"],
                capture_output=True,
                check=False,
            )
            if chk.returncode == 0:
                return cur
        cur = cur.parent
    return None


def test_r10_f11_legacy_binary_blocked_before_sibling_cursor_recovery(trusted_tmp: Path) -> None:
    """Upgrading stream A to v4 fences all existing sibling cursors so legacy 36bf08d9 mutates zero bytes on B."""
    perms = os_adapters().permissions
    outbox = trusted_tmp / "outbox-r10-f11"
    stream_a, stream_b = "stream-r10-f11-a", "stream-r10-f11-b"
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream_a, dk=digest_bytes(b"r10-f11-a1"), explicit_seq=1)

    pending_b = [digest_bytes(b"r10-f11-b-pending"), 1, "ev-f11-b1", _REC_AT, digest_bytes(b"payload-f11-b")]
    cur_b_obj: dict[str, Any] = {
        "schema_version": 3, "next_seq": 2, "binding_count": 0, "acked_ranges": [], "pending_binding": pending_b,
    }
    cur_b_path, _ = _write_cursor_json(outbox, stream_b, cur_b_obj, perms)
    cur_a_obj: dict[str, Any] = {
        "schema_version": 3, "next_seq": 2, "binding_count": 1, "acked_ranges": [], "pending_binding": None,
    }
    _write_cursor_json(outbox, stream_a, cur_a_obj, perms)

    spool.apply_ack(_ack(stream_a, committed=(1,)))
    cur_b_after = json.loads(cur_b_path.read_text(encoding="utf-8"))
    assert cur_b_after["schema_version"] == 4
    assert cur_b_after["pending_binding"] is None

    repo_root = _repo_root_with_36bf08d9()
    if repo_root is None:
        return
    legacy_root = trusted_tmp / "legacy-src-36bf08d9"
    legacy_root.mkdir(parents=True)
    tar_bytes = subprocess.check_output(["git", "-C", str(repo_root), "archive", "--format=tar", "36bf08d9", "src"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(legacy_root, filter="data")
    sdir_b = _stream_dir(outbox, stream_b)
    snap_before = _snapshot_tree_bytes(sdir_b)
    probe_script = (
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(legacy_root / 'src')!r})\n"
        "from superbrain.adapters.os import os_adapters\n"
        "from superbrain.core.canonical import digest_bytes\n"
        "from superbrain.core.errors import BrainError, ErrorCode\n"
        "from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap\n"
        "from superbrain.storage.outbox import OutboxSpool\n"
        f"spool = OutboxSpool(Path({str(outbox)!r}), permissions=os_adapters().permissions)\n"
        "try:\n"
        "    spool.enqueue_hook_event(\n"
        f"        producer_stream={stream_b!r},\n"
        "        build_event=lambda s, e, r: CaptureEventRecord(\n"
        f"            event_id=e, producer_stream={stream_b!r}, sequence=s, harness_id='claude-code',\n"
        "            kind='command_result', recorded_at=r, payload={'n': 'legacy'},\n"
        "        ),\n"
        "        dedup_key=digest_bytes(b'r10-f11-legacy-b2'),\n"
        f"        fallback_recorded_at={_REC_AT!r},\n"
        "    )\n"
        "    raise AssertionError('expected INTEGRITY_FAILURE')\n"
        "except BrainError as err:\n"
        "    assert err.code is ErrorCode.INTEGRITY_FAILURE, err\n"
    )
    proc = subprocess.run([sys.executable, "-I", "-c", probe_script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert _snapshot_tree_bytes(sdir_b) == snap_before


def test_r10_f12_cursor_frame_fence_and_eviction_honor_cutoff(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deadline expiration during fsync or busy-replace stops frame/cursor publication and frame eviction."""
    perms = os_adapters().permissions
    real_fsync = os.fsync

    # (a) Frame fsync expiration -> no frame published on direct enqueue_gap
    now_a = [0]
    spool_a = OutboxSpool(trusted_tmp / "outbox-r10-f12-frame", permissions=perms, monotonic_ns=lambda: now_a[0])

    def _expire_on_fsync_a(fd: int) -> None:
        real_fsync(fd)
        now_a[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(os, "fsync", _expire_on_fsync_a)
        with pytest.raises(BrainError) as err_a:
            spool_a.enqueue_gap(_mk_gap("s-f12-a", 1), deadline_ns=1_000)
        assert err_a.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert spool_a.read_pending(limit=10, producer_stream="s-f12-a") == []

    # (b) Cursor fsync expiration during apply_ack -> cursor untouched, frames kept
    now_b, hit_b = [0], [0]
    outbox_b, stream_b = trusted_tmp / "outbox-r10-f12-cur", "s-f12-b"
    spool_b = OutboxSpool(outbox_b, permissions=perms, monotonic_ns=lambda: now_b[0])
    spool_b.enqueue_event(_mk_event(stream_b, 1))
    cur_b_init: dict[str, Any] = {
        "schema_version": 4, "next_seq": 2, "binding_count": 0,
        "contiguous_acked_through": 0, "acked_pages": [], "pending_binding": None,
    }
    cur_b = _write_cursor_json(outbox_b, stream_b, cur_b_init, perms)[0]
    cur_before = cur_b.read_bytes()

    def _expire_on_first_fsync_b(fd: int) -> None:
        real_fsync(fd)
        hit_b[0] += 1
        if hit_b[0] == 1:
            now_b[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(os, "fsync", _expire_on_first_fsync_b)
        with pytest.raises(BrainError) as err_b:
            spool_b.apply_ack(_ack(stream_b, committed=(1,)), deadline_ns=1_000)
        assert err_b.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert cur_b.read_bytes() == cur_before
    assert [e.sequence for e in spool_b.read_pending(limit=10, producer_stream=stream_b)] == [1]

    # (c) replace_file_resilient sharing violation retry honors active deadline
    now_c, calls_c = [0], [0]
    orig_replace = os.replace
    spool_c = OutboxSpool(trusted_tmp / "outbox-r10-f12-retry", permissions=perms, monotonic_ns=lambda: now_c[0])
    (trusted_tmp / "outbox-r10-f12-retry").mkdir(parents=True, exist_ok=True)
    perms.secure_directory(trusted_tmp / "outbox-r10-f12-retry")

    def _busy_then_expire(src: Path | str, dst: Path | str) -> None:
        calls_c[0] += 1
        if calls_c[0] == 1:
            now_c[0] = 2_000
            err = OSError("sharing violation")
            err.winerror = 32
            raise err
        orig_replace(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _busy_then_expire)
        mp.setattr(time, "sleep", lambda _d: None)
        with pytest.raises(BrainError) as err_c:
            spool_c.enqueue_gap(_mk_gap("s-f12-c", 1), deadline_ns=1_000)
        assert err_c.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert calls_c[0] == 1

    # (d) apply_ack eviction loop stops before remaining unlinks once deadline expires
    now_d = [0]
    outbox_d, stream_d = trusted_tmp / "outbox-r10-f12-evict", "s-f12-d"
    spool_d = OutboxSpool(outbox_d, permissions=perms, monotonic_ns=lambda: now_d[0])
    spool_d.enqueue_event(_mk_event(stream_d, 1))
    spool_d.enqueue_event(_mk_event(stream_d, 2))
    orig_decode = OutboxSpool._decode_frame_file
    dec_count = [0]

    def _expire_on_second_decode(self: OutboxSpool, path: Path) -> Any:
        dec_count[0] += 1
        if dec_count[0] == 2:
            now_d[0] = 2_000
        return orig_decode(self, path)

    with monkeypatch.context() as mp:
        mp.setattr(OutboxSpool, "_decode_frame_file", _expire_on_second_decode)
        with pytest.raises(BrainError) as err_d:
            spool_d.apply_ack(_ack(stream_d, committed=(1, 2)), deadline_ns=1_000)
        assert err_d.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert [e.sequence for e in spool_d.read_pending(limit=10, producer_stream=stream_d)] == [2]


def test_r10_f13_direct_enqueue_matched_retry_fails_on_missing_ack_page(trusted_tmp: Path) -> None:
    """Matched direct enqueue_gap/enqueue_event retry must fail closed if a committed .acks page is missing."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f13", "stream-r10-f13"
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f13-hook"))
    spool.apply_ack(_ack(stream, committed=(5_000,)))

    gap = _mk_gap(stream, 1, gap_id="gap-r10-f13")
    ev = _mk_event(stream, 2, event_id="ev-r10-f13")
    spool.enqueue_gap(gap)
    spool.enqueue_event(ev)

    next((_stream_dir(outbox, stream) / ".acks").glob("*.json")).unlink()
    with pytest.raises(BrainError) as err_gap:
        spool.enqueue_gap(gap)
    assert err_gap.value.code is ErrorCode.INTEGRITY_FAILURE
    with pytest.raises(BrainError) as err_ev:
        spool.enqueue_event(ev)
    assert err_ev.value.code is ErrorCode.INTEGRITY_FAILURE


def test_r10_f14_hook_binding_cap_and_byte_cap_preflight_before_recovery(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """enqueue_hook_event hitting max_binding_keys after interrupted pending_binding must leave disk unchanged."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r10-f14", "stream-r10-f14"
    spool = cast(Any, OutboxSpool)(outbox, permissions=perms, max_binding_keys=1)

    def _fail_bucket(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "simulated bucket crash")

    outbox_mod_ref = sys.modules["superbrain.storage.outbox"]
    with monkeypatch.context() as mp:
        mp.setattr(outbox_mod_ref, "write_prepared_binding_bucket", _fail_bucket)
        mp.setattr(_outbox_bindings, "write_prepared_binding_bucket", _fail_bucket)
        with pytest.raises(BrainError) as err_init:
            _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f14-k1"), explicit_seq=1)
        assert err_init.value.code is ErrorCode.IO_ERROR
    del outbox_mod_ref

    sdir = _stream_dir(outbox, stream)
    cur_path = sdir / ".seq_cursor.json"
    initial_cursor = cur_path.read_bytes()
    assert not (sdir / ".bindings").exists()

    with pytest.raises(BrainError) as err_cap:
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f14-k2"))
    assert err_cap.value.code is ErrorCode.STORAGE_FULL
    assert cur_path.read_bytes() == initial_cursor
    assert not (sdir / ".bindings").exists()

    retried = _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r10-f14-k1"), explicit_seq=1)
    assert retried.sequence == 1


# --- R11 regressions (Codex review sp2-5-remediation-r11) ------------------------------------------------------


def _same_bucket_keys(tag: str) -> tuple[str, str]:
    seen: dict[str, str] = {}
    for i in range(4096):
        key = digest_bytes(f"{tag}-{i}".encode())
        bucket = key[7:9]
        if bucket in seen:
            return seen[bucket], key
        seen[bucket] = key
    raise AssertionError("no two keys share a bucket")


def _bucket_keys(sdir: Path, key: str) -> set[str]:
    path = sdir / ".bindings" / f"{key[7:9]}.json"
    if not path.exists():
        return set()
    return {row[0] for row in json.loads(path.read_text(encoding="utf-8"))["entries"]}


def test_r10_f15_recovered_pending_binding_survives_new_key_in_same_bucket(trusted_tmp: Path) -> None:
    """R11-1: a bucket published after recovery keeps every committed binding and matches ``binding_count``."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r11-f15", "stream-r11-f15"
    spool = cast(Any, OutboxSpool)(outbox, permissions=perms, max_binding_keys=2)
    k1, k2 = _same_bucket_keys("r11-f15")

    def _fail_bucket(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "simulated crash before bucket write")

    outbox_mod = sys.modules["superbrain.storage.outbox"]
    orig_write = outbox_mod.write_prepared_binding_bucket
    outbox_mod.write_prepared_binding_bucket = _fail_bucket
    try:
        with pytest.raises(BrainError) as err_k1:
            _enqueue_hook(spool, stream=stream, dk=k1, note="k1", explicit_seq=1)
        assert err_k1.value.code is ErrorCode.IO_ERROR
    finally:
        outbox_mod.write_prepared_binding_bucket = orig_write
    sdir = _stream_dir(outbox, stream)
    assert json.loads((sdir / ".seq_cursor.json").read_text(encoding="utf-8"))["pending_binding"][0] == k1

    rec_k2 = _enqueue_hook(spool, stream=stream, dk=k2, note="k2")
    assert rec_k2.sequence == 2
    assert _bucket_keys(sdir, k1) == {k1, k2}
    cursor = json.loads((sdir / ".seq_cursor.json").read_text(encoding="utf-8"))
    assert cursor["binding_count"] == 2
    assert cursor["pending_binding"] is None

    retried = _enqueue_hook(spool, stream=stream, dk=k1, note="k1", explicit_seq=1)
    assert retried.sequence == 1
    assert _bucket_keys(sdir, k1) == {k1, k2}


def _has_v4_artifact(outbox: Path) -> bool:
    streams = outbox / _STREAMS_DIR
    if (streams / ".v4_fence").exists():
        return True
    for cur in streams.glob("*/.seq_cursor.json"):
        if json.loads(cur.read_text(encoding="utf-8")).get("schema_version") == 4:
            return True
    return any(streams.glob("*/.acks/*.json"))


def _legacy_probe_script(legacy_src: Path, cases: list[tuple[str, str, str]]) -> str:
    return (
        "import json, sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(legacy_src)!r})\n"
        "from superbrain.adapters.os import os_adapters\n"
        "from superbrain.core.canonical import digest_bytes\n"
        "from superbrain.core.errors import BrainError\n"
        "from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord, ProducerCaptureGap\n"
        "from superbrain.storage.outbox import OutboxSpool\n"
        f"cases = {cases!r}\n"
        "out = {}\n"
        "def ev(stream, seq, eid):\n"
        "    return CaptureEventRecord(event_id=eid, producer_stream=stream, sequence=seq, harness_id='claude-code',\n"
        f"        kind='command_result', recorded_at={_REC_AT!r}, payload={{'n': 'legacy'}})\n"
        "def ack(stream):\n"
        "    return CaptureBatchAck(producer_stream=stream, repo_id='r', checkout_id='c',\n"
        "        committed_event_sequences=(1,), contiguous_event_acked_through=0, acked_producer_gap_sequences=(),\n"
        "        accepted_count=1, deduped_count=0, policy_disabled=False)\n"
        "for root, sa, sb in cases:\n"
        "    spool = OutboxSpool(Path(root), permissions=os_adapters().permissions)\n"
        "    ops = {\n"
        "        'apply_ack_a': lambda: spool.apply_ack(ack(sa)),\n"
        "        'apply_ack_b': lambda: spool.apply_ack(ack(sb)),\n"
        "        'hook_b': lambda: spool.enqueue_hook_event(producer_stream=sb,\n"
        "            build_event=lambda s, e, r: ev(sb, s, e), dedup_key=digest_bytes(b'legacy-hook-b'),\n"
        f"            fallback_recorded_at={_REC_AT!r}),\n"
        "        'hook_a': lambda: spool.enqueue_hook_event(producer_stream=sa,\n"
        "            build_event=lambda s, e, r: ev(sa, s, e), dedup_key=digest_bytes(b'legacy-hook-a'),\n"
        f"            fallback_recorded_at={_REC_AT!r}),\n"
        "        'event_a': lambda: spool.enqueue_event(ev(sa, 9, 'ev-legacy-a9')),\n"
        "        'gap_b': lambda: spool.enqueue_gap(ProducerCaptureGap(gap_id='gap-legacy-b9', producer_stream=sb,\n"
        f"            sequence=9, reason='hook_timeout', recorded_at={_REC_AT!r}, estimated_count=1, duration_ms=1)),\n"
        "    }\n"
        "    res = {}\n"
        "    for name, op in ops.items():\n"
        "        try:\n"
        "            op()\n"
        "            res[name] = 'ok'\n"
        "        except BrainError as err:\n"
        "            res[name] = 'refused:' + err.code.value\n"
        "    out[root] = res\n"
        "print(json.dumps(out))\n"
    )


def _seed_r11_f16_outbox(outbox: Path, stream_a: str, stream_b: str, perms: OutboxPermissionsPort) -> OutboxSpool:
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream_a, dk=digest_bytes(b"r11-f16-a1"), explicit_seq=1)
    pending_a = [digest_bytes(b"r11-f16-a-pending"), 2, "ev-f16-a2", _REC_AT, digest_bytes(b"payload-f16-a2")]
    pending_b = [digest_bytes(b"r11-f16-b-pending"), 1, "ev-f16-b1", _REC_AT, digest_bytes(b"payload-f16-b1")]
    # Sparse acked range + pending binding: the target's own recovery commits v4 directly, so the fence is published
    # while the target cursor on disk still carries its pending binding.
    _write_cursor_json(outbox, stream_a, {"schema_version": 3, "next_seq": 4, "binding_count": 1,
        "acked_ranges": [[3, 3]], "pending_binding": pending_a}, perms)
    _write_cursor_json(outbox, stream_b, {"schema_version": 3, "next_seq": 2, "binding_count": 0,
        "acked_ranges": [], "pending_binding": pending_b}, perms)
    return spool


def test_r10_f16_v4_migration_interrupted_at_any_step_never_admits_legacy_writes(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R11-2: once any v4 artifact is durable, every legacy 36bf08d9 write path refuses before mutating."""
    perms = os_adapters().permissions
    stream_a, stream_b = "stream-r11-f16-a", "stream-r11-f16-b"
    sdir_names = {stream_dir_key(stream_a)}
    outbox_io_mod = sys.modules["superbrain.storage._outbox_io"]

    def _boom(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.IO_ERROR, "simulated interruption")

    orig_recover = _outbox_seq.recover_stream_cursor
    orig_write_cursor = _outbox_seq.write_stream_cursor

    def _recover_sibling_boom(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("skip_fence"):
            raise BrainError(ErrorCode.IO_ERROR, "simulated interruption in sibling upgrade")
        return orig_recover(*args, **kwargs)

    def _target_v4_cursor_boom(stream_dir: Path, cursor: Any, p: Any) -> None:
        if stream_dir.name in sdir_names and cursor.schema_v4:
            raise BrainError(ErrorCode.IO_ERROR, "simulated interruption at target v4 cursor")
        orig_write_cursor(stream_dir, cursor, p)

    interrupts: dict[str, tuple[Any, str, Any]] = {
        "fence": (outbox_io_mod, "ensure_v4_fence", _boom),
        "sibling": (_outbox_seq, "recover_stream_cursor", _recover_sibling_boom),
        "pages": (_outbox_acks, "write_ack_pages", _boom),
        "target_cursor": (_outbox_seq, "write_stream_cursor", _target_v4_cursor_boom),
    }
    roots: dict[str, Path] = {}
    for name, (mod, attr, fake) in interrupts.items():
        outbox = trusted_tmp / f"outbox-r11-f16-{name}"
        spool = _seed_r11_f16_outbox(outbox, stream_a, stream_b, perms)
        with monkeypatch.context() as mp:
            mp.setattr(mod, attr, fake)
            with pytest.raises(BrainError):
                spool.apply_ack(_ack(stream_a, committed=(1, 5_000)))
        roots[name] = outbox
    completed = trusted_tmp / "outbox-r11-f16-completed"
    spool_done = _seed_r11_f16_outbox(completed, stream_a, stream_b, perms)
    spool_done.apply_ack(_ack(stream_a, committed=(1, 5_000)))
    roots["completed"] = completed
    assert _has_v4_artifact(completed)

    repo_root = _repo_root_with_36bf08d9()
    if repo_root is None:
        return
    legacy_root = trusted_tmp / "legacy-src-36bf08d9-f16"
    legacy_root.mkdir(parents=True)
    tar_bytes = subprocess.check_output(["git", "-C", str(repo_root), "archive", "--format=tar", "36bf08d9", "src"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(legacy_root, filter="data")
    guarded = {name: root for name, root in roots.items() if _has_v4_artifact(root)}
    assert "completed" in guarded
    before = {name: _snapshot_tree_bytes(root) for name, root in guarded.items()}
    script = _legacy_probe_script(legacy_root / "src", [(str(r), stream_a, stream_b) for r in guarded.values()])
    proc = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    results = json.loads(proc.stdout.strip().splitlines()[-1])
    for name, root in guarded.items():
        res = results[str(root)]
        assert all(v.startswith("refused:") for v in res.values()), (name, res)
        assert _snapshot_tree_bytes(root) == before[name], name


def test_r10_f17_directory_sync_io_error_stops_before_cursor_publication(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R11-3: a real I/O error syncing ``.acks`` or the cursor dir stops before the next publication step."""
    import errno

    from superbrain.adapters.os import durable

    perms = os_adapters().permissions
    real_fsync_dir = durable._fsync_directory

    def _seed(name: str) -> tuple[OutboxSpool, str, Path]:
        outbox, stream = trusted_tmp / f"outbox-r11-f17-{name}", f"stream-r11-f17-{name}"
        spool = OutboxSpool(outbox, permissions=perms)
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(f"r11-f17-{name}".encode()), explicit_seq=1)
        return spool, stream, _stream_dir(outbox, stream)

    # (a) EIO syncing .acks: no cursor change, frame kept.
    spool_a, stream_a, sdir_a = _seed("acks")
    cur_a = (sdir_a / ".seq_cursor.json").read_bytes()

    def _eio_on_acks(path: Path, **kw: Any) -> bool:
        if Path(path).name == ".acks":
            raise OSError(errno.EIO, "injected EIO")
        return bool(real_fsync_dir(path, **kw))

    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_on_acks)
        with pytest.raises(BrainError) as err_a:
            spool_a.apply_ack(_ack(stream_a, committed=(1, 5_000)))
        assert err_a.value.code is ErrorCode.IO_ERROR
    assert (sdir_a / ".seq_cursor.json").read_bytes() == cur_a
    assert [e.sequence for e in spool_a.read_pending(limit=10, producer_stream=stream_a)] == [1]

    # (b) EIO syncing the cursor directory: frames are not evicted.
    spool_b, stream_b, sdir_b = _seed("cursor")

    def _eio_on_stream_dir(path: Path, **kw: Any) -> bool:
        if Path(path) == sdir_b:
            raise OSError(errno.EIO, "injected EIO")
        return bool(real_fsync_dir(path, **kw))

    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_on_stream_dir)
        with pytest.raises(BrainError) as err_b:
            spool_b.apply_ack(_ack(stream_b, committed=(1, 5_000)))
        assert err_b.value.code is ErrorCode.IO_ERROR
    assert [e.sequence for e in spool_b.read_pending(limit=10, producer_stream=stream_b)] == [1]

    # (c) Positive twin: a filesystem that cannot fsync directories (unsupported) still completes.
    spool_c, stream_c, _sdir_c = _seed("unsupported")
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", lambda _p, **_kw: False)
        assert spool_c.apply_ack(_ack(stream_c, committed=(1, 5_000))) == 1



def test_r10_f18_enqueue_never_reports_failure_after_frame_publication(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R11-4: a frame published before the deadline is never followed by a ``CaptureGap`` for the same slot."""
    from superbrain.composition.hook_entry import run_hook

    perms = os_adapters().permissions
    io_mod = sys.modules["superbrain.storage._outbox_io"]
    real_replace = io_mod.replace_file_resilient

    # (a) run_hook direct path: deadline hits right after the event frame is published.
    outbox_a, stream_a = trusted_tmp / "outbox-r11-f18-run", "stream-r11-f18-run"
    now = [0]
    seed = OutboxSpool(outbox_a, permissions=perms)
    _enqueue_hook(seed, stream=stream_a, dk=digest_bytes(b"r11-f18-seed"), explicit_seq=1)

    def _expire_after_frame(src: Path, dst: Path) -> None:
        real_replace(src, dst)
        if str(dst).endswith(".frame"):
            now[0] = 1_960_000_000

    raw = json.dumps({
        "event_id": "ev-r11-f18-2", "producer_stream": stream_a, "sequence": 2, "harness_id": "claude-code",
        "kind": "tool_post", "recorded_at": "2026-11-27T08:00:00Z", "payload": {"tool": "Read", "seq": 2},
    }).encode()
    with monkeypatch.context() as mp:
        mp.setattr(io_mod, "replace_file_resilient", _expire_after_frame)
        rc = run_hook(
            raw, outbox_dir=outbox_a, monotonic_ns=lambda: now[0],
            spool_factory=lambda d: OutboxSpool(d, permissions=perms, monotonic_ns=lambda: now[0]),
        )
    assert rc == 0
    entries = OutboxSpool(outbox_a, permissions=perms).read_pending(limit=10, producer_stream=stream_a)
    assert [(e.record_kind, e.sequence) for e in entries] == [("event", 1), ("event", 2)]

    # (b) Spool hook path: the post-publication cursor update cannot turn a published event into an error.
    outbox_b, stream_b = trusted_tmp / "outbox-r11-f18-hook", "stream-r11-f18-hook"
    clock = [0]
    spool_b = OutboxSpool(outbox_b, permissions=perms, monotonic_ns=lambda: clock[0])

    def _expire_after_frame_b(src: Path, dst: Path) -> None:
        real_replace(src, dst)
        if str(dst).endswith(".frame"):
            clock[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(io_mod, "replace_file_resilient", _expire_after_frame_b)
        rec = _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(b"r11-f18-hook"), deadline_ns=1_000)
    assert rec.sequence == 1
    assert [e.sequence for e in spool_b.read_pending(limit=10, producer_stream=stream_b)] == [1]

    # (c) Retry of the same key while its frame is already published: upkeep that hits the deadline is deferred,
    # never reported as a failure that the hook would turn into a CaptureGap.
    clock[0] = 0
    upkeep_calls = [0]

    def _expire_before_first_upkeep_write(src: Path, dst: Path) -> None:
        upkeep_calls[0] += 1
        if upkeep_calls[0] == 1:
            clock[0] = 2_000
        real_replace(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(io_mod, "replace_file_resilient", _expire_before_first_upkeep_write)
        retried = _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(b"r11-f18-hook"), deadline_ns=1_000)
    assert retried.sequence == 1
    assert upkeep_calls[0] >= 1
    assert [(e.record_kind, e.sequence) for e in spool_b.read_pending(limit=10, producer_stream=stream_b)] == [
        ("event", 1)
    ]
    clock[0] = 0
    _enqueue_hook(spool_b, stream=stream_b, dk=digest_bytes(b"r11-f18-hook-2"))
    cursor_b = json.loads((_stream_dir(outbox_b, stream_b) / ".seq_cursor.json").read_text(encoding="utf-8"))
    assert cursor_b["pending_binding"] is None


def test_r10_f19_ack_cleanup_and_busy_backoff_check_the_cutoff(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R11-5: every unlink and every retry wait checks the remaining budget right before it happens."""
    perms = os_adapters().permissions
    io_mod = sys.modules["superbrain.storage._outbox_io"]

    # (a) Deadline expires while syncing the committed cursor: the superseded ACK page is not deleted.
    now_a = [0]
    outbox_a, stream_a = trusted_tmp / "outbox-r11-f19-prune", "stream-r11-f19-prune"
    _spool_seed, sdir_a, acks_a, cur_path = _setup_v4_two_pages(outbox_a, stream_a, perms)
    pages_before = {p.name for p in acks_a.glob("*.json")}
    cur_before = cur_path.read_bytes()
    spool_a = OutboxSpool(outbox_a, permissions=perms, monotonic_ns=lambda: now_a[0])
    real_sync = io_mod.sync_dir

    def _expire_after_cursor_commit(directory: Path) -> None:
        real_sync(directory)
        if Path(directory) == sdir_a and cur_path.read_bytes() != cur_before:
            now_a[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(io_mod, "sync_dir", _expire_after_cursor_commit)
        with pytest.raises(BrainError) as err_a:
            spool_a.apply_ack(_ack(stream_a, committed=(5_001,)), deadline_ns=1_000)
        assert err_a.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert cur_path.read_bytes() != cur_before
    assert pages_before <= {p.name for p in acks_a.glob("*.json")}

    # (b) A busy replace that ends past the cutoff does not sleep before failing.
    now_b: list[int] = [0]
    sleeps_b: list[float] = []
    spool_b = OutboxSpool(trusted_tmp / "outbox-r11-f19-busy", permissions=perms, monotonic_ns=lambda: now_b[0])
    orig_replace = os.replace
    calls_b = [0]

    def _busy_and_expire(src: Path | str, dst: Path | str) -> None:
        calls_b[0] += 1
        if calls_b[0] == 1:
            now_b[0] = 2_000
            err = OSError("sharing violation")
            err.winerror = 32
            raise err
        orig_replace(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _busy_and_expire)
        mp.setattr(time, "sleep", sleeps_b.append)
        with pytest.raises(BrainError) as err_b:
            spool_b.enqueue_gap(_mk_gap("s-r11-f19-b", 1), deadline_ns=1_000)
        assert err_b.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert sleeps_b == []

    # (c) A busy replace with 3 ms left waits at most the remaining budget.
    now_c: list[int] = [0]
    sleeps_c: list[float] = []
    spool_c = OutboxSpool(trusted_tmp / "outbox-r11-f19-bound", permissions=perms, monotonic_ns=lambda: now_c[0])
    calls_c = [0]

    def _busy_near_deadline(src: Path | str, dst: Path | str) -> None:
        calls_c[0] += 1
        if calls_c[0] == 1:
            now_c[0] = 1_000_000_000 - 3_000_000
            err = OSError("sharing violation")
            err.winerror = 32
            raise err
        orig_replace(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _busy_near_deadline)
        mp.setattr(time, "sleep", sleeps_c.append)
        spool_c.enqueue_gap(_mk_gap("s-r11-f19-c", 1), deadline_ns=1_000_000_000)
    assert sleeps_c, sleeps_c
    assert max(sleeps_c) <= 0.003 + 1e-9, sleeps_c
