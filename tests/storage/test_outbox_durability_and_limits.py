"""SP2-2 local OutboxSpool durability, limits, separated ACK eviction, and f83271d oracles."""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from tests.support.fs import fake_link
from tests.support.platform import posix_only


def _mk_event(seq: int, *, event_id: str | None = None, stream: str = "stream-a", note: str = "hello") -> Any:
    from superbrain.ports.capture import CaptureEventRecord

    return CaptureEventRecord(
        event_id=event_id or f"ev-{stream}-{seq}",
        producer_stream=stream,
        sequence=seq,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={"seq": seq, "note": note, "items": ["a", "b"]},
        session_ref="sha256:" + ("a" * 64),
        source_metadata={"host_version": "2.1.325"},
    )


def _mk_gap(seq: int, *, gap_id: str | None = None, stream: str = "stream-a", reason: str = "hook_timeout") -> Any:
    from superbrain.ports.capture import ProducerCaptureGap

    return ProducerCaptureGap(
        gap_id=gap_id or f"gap-{stream}-{seq}",
        producer_stream=stream,
        sequence=seq,
        reason=reason,
        recorded_at="2026-11-21T12:00:02Z",
        estimated_count=1,
        duration_ms=2000,
    )


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "PYTHONPATH",
        "PYTHONHOME",
        "SUPERBRAIN_CRASHPOINT",
        "SUPERBRAIN_PAUSEPOINT",
    ):
        env.pop(key, None)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def test_outbox_never_imports_sqlite3_or_faults_at_import(trusted_tmp: Path) -> None:
    spool_dir = trusted_tmp / "no-sqlite-spool"
    script = (
        "import json, sys; from pathlib import Path; "
        "from superbrain.storage.outbox import OutboxSpool; "
        "from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord, OUTBOX_RECORD_EVENT; "
        "has_faults_on_import = 'superbrain.core.faults' in sys.modules; "
        "spool = OutboxSpool(Path(sys.argv[1])); "
        "ev = CaptureEventRecord('ev-1','s1',1,'claude-code','tool_post','2026-11-21T12:00:00Z',{'k':'v'}); "
        "eid = spool.enqueue_event(ev); "
        "pending = spool.read_pending(limit=10); "
        "ack = CaptureBatchAck('s1','r1','c1',(1,),1,(),1,0); "
        "evicted = spool.apply_ack(ack); "
        "print(json.dumps({'eid': eid, 'n': len(pending), 'evicted': evicted, "
        "'bytes': spool.total_bytes(), 'has_sqlite': 'sqlite3' in sys.modules, "
        "'has_faults_on_import': has_faults_on_import}))"
    )
    res = subprocess.run(
        [sys.executable, "-I", "-c", script, str(spool_dir)],
        env=_clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=15.0,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["eid"] == "ev-1"
    assert data["n"] == 1 and data["evicted"] == 1 and data["bytes"] == 0
    assert data["has_sqlite"] is False
    assert data["has_faults_on_import"] is False


def test_outbox_owner_only_permissions_and_symlink_refusal(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    secured_calls: list[tuple[str, Path]] = []

    class _SpyPerms:
        def secure_directory(self, path: Path) -> None:
            secured_calls.append(("dir", path))
            os_.permissions.secure_directory(path)

        def secure_file(self, path: Path) -> None:
            secured_calls.append(("file", path))
            os_.permissions.secure_file(path)

        def problems(self, path: Path) -> Any:
            return os_.permissions.problems(path)

    spool_dir = trusted_tmp / "perm-spool"
    spool = OutboxSpool(spool_dir, permissions=_SpyPerms())
    spool.enqueue_event(_mk_event(1))
    assert any(kind == "dir" for kind, _p in secured_calls)
    assert any(kind == "file" for kind, _p in secured_calls)
    assert os_.permissions.problems(spool_dir) == []

    # Linked root or linked file inside spool is refused with UNSAFE_PATH.
    linked_root = trusted_tmp / "linked-spool"
    linked_root.mkdir()
    os_.permissions.secure_directory(linked_root)
    fake_link(monkeypatch, linked_root)
    with pytest.raises(BrainError) as exc:
        OutboxSpool(linked_root)
    assert exc.value.code is ErrorCode.UNSAFE_PATH


@posix_only
def test_outbox_posix_modes_are_0700_and_0600(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "posix-spool"
    spool = OutboxSpool(spool_dir)
    spool.enqueue_event(_mk_event(1))
    assert stat.S_IMODE(spool_dir.stat().st_mode) == 0o700
    for item in spool_dir.rglob("*"):
        if item.is_dir():
            assert stat.S_IMODE(item.stat().st_mode) == 0o700
        elif item.is_file():
            assert stat.S_IMODE(item.stat().st_mode) == 0o600


def test_reopen_retry_and_conflict(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "retry-spool"
    ev1 = _mk_event(1, event_id="ev-retry-1", note="original")
    s1 = OutboxSpool(spool_dir)
    assert s1.enqueue_event(ev1) == "ev-retry-1"
    # Identical retry in-process and across reopen returns same entry_id without duplicating.
    assert s1.enqueue_event(ev1) == "ev-retry-1"
    s2 = OutboxSpool(spool_dir)
    assert s2.enqueue_event(ev1) == "ev-retry-1"
    assert len(s2.read_pending(limit=10)) == 1

    # Different payload for same entry_id -> IDEMPOTENCY_CONFLICT
    conflict_same_id = _mk_event(1, event_id="ev-retry-1", note="mutated")
    with pytest.raises(BrainError) as exc1:
        s2.enqueue_event(conflict_same_id)
    assert exc1.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

    # Different payload / entry_id for same (record_kind, producer_stream, sequence) -> IDEMPOTENCY_CONFLICT
    conflict_same_seq = _mk_event(1, event_id="ev-other-id", note="mutated-seq")
    with pytest.raises(BrainError) as exc2:
        s2.enqueue_event(conflict_same_seq)
    assert exc2.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    assert json.loads(s2.read_pending(limit=10)[0].payload_json)["payload"]["note"] == "original"


def test_ack_is_durable_and_unknown_sequences_are_safe(trusted_tmp: Path) -> None:
    from superbrain.ports.capture import CaptureBatchAck
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "ack-spool"
    spool = OutboxSpool(spool_dir)
    spool.enqueue_event(_mk_event(1))
    spool.enqueue_event(_mk_event(2))

    # Unknown sequence / wrong stream evicts 0 entries cleanly.
    noop_ack = CaptureBatchAck("other-stream", "r1", "c1", (1, 99), 99, (), 0, 0)
    assert spool.apply_ack(noop_ack) == 0
    assert len(spool.read_pending(limit=10)) == 2

    ack1 = CaptureBatchAck("stream-a", "r1", "c1", (1,), 1, (), 1, 0)
    assert spool.apply_ack(ack1) == 1
    reopened = OutboxSpool(spool_dir)
    remaining = reopened.read_pending(limit=10)
    assert [e.sequence for e in remaining] == [2]
    assert reopened.apply_ack(ack1) == 0


def test_enqueue_and_read_pending_are_detached_from_caller_mutation(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "detach-spool"
    spool = OutboxSpool(spool_dir)
    ev = _mk_event(1, note="immutable-copy")
    spool.enqueue_event(ev)
    ev.payload["note"] = "mutated-after-enqueue"

    pending = spool.read_pending(limit=10)
    assert len(pending) == 1
    assert json.loads(pending[0].payload_json)["payload"]["note"] == "immutable-copy"
    pending.clear()

    reopened = OutboxSpool(spool_dir)
    assert len(reopened.read_pending(limit=10)) == 1


def test_read_pending_is_bounded_and_keeps_insertion_order(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool = OutboxSpool(trusted_tmp / "order-spool")
    for seq in (3, 1, 2):
        spool.enqueue_event(_mk_event(seq, stream="stream-a"))
    spool.enqueue_event(_mk_event(1, stream="stream-b"))

    top2 = spool.read_pending(limit=2, producer_stream="stream-a")
    assert len(top2) == 2
    assert [e.sequence for e in top2] == [3, 1]
    all_b = spool.read_pending(limit=10, producer_stream="stream-b")
    assert [(e.producer_stream, e.sequence) for e in all_b] == [("stream-b", 1)]


@pytest.mark.parametrize("bad_limit", [0, -1, 1025, True, False, 1.5, "2", None])
def test_read_pending_rejects_invalid_limits(trusted_tmp: Path, bad_limit: Any) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool = OutboxSpool(trusted_tmp / "limit-spool")
    with pytest.raises(BrainError) as exc:
        spool.read_pending(limit=bad_limit)
    assert exc.value.code is ErrorCode.INVALID_INPUT

    # Exact boundaries 1 and 1024 succeed.
    assert spool.read_pending(limit=1) == []
    assert spool.read_pending(limit=1024) == []


@pytest.mark.parametrize(
    "bad_record",
    [
        None,
        "string",
        123,
        [],
        {"event_id": "x"},
    ],
)
def test_enqueue_rejects_non_record_objects(trusted_tmp: Path, bad_record: Any) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool = OutboxSpool(trusted_tmp / "bad-rec-spool")
    with pytest.raises(BrainError) as exc:
        spool.enqueue_event(bad_record)
    assert exc.value.code is ErrorCode.INVALID_INPUT


def test_enqueue_survives_immediate_os_exit_after_commit(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "exit-spool"
    child_code = (
        "import os, sys; from pathlib import Path; "
        "from superbrain.ports.capture import CaptureEventRecord; "
        "from superbrain.storage.outbox import OutboxSpool; "
        "s = OutboxSpool(Path(sys.argv[1])); "
        "s.enqueue_event(CaptureEventRecord('ev-exit-1','s1',1,'claude-code','tool_post',"
        "'2026-11-21T12:00:00Z',{'ok':'durable'})); "
        "os._exit(0)"
    )
    res = subprocess.run(
        [sys.executable, "-I", "-c", child_code, str(spool_dir)],
        env=_clean_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    pending = OutboxSpool(spool_dir).read_pending(limit=10)
    assert len(pending) == 1 and pending[0].entry_id == "ev-exit-1"


def test_two_concurrent_writers_preserve_idempotent_and_distinct_events(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "concurrent-spool"
    same_ev = _mk_event(1, event_id="ev-conc-1", stream="s-conc", note="same")

    def _worker(worker_seq: int) -> tuple[str, str]:
        spool = OutboxSpool(spool_dir)
        eid_same = spool.enqueue_event(same_ev)
        eid_own = spool.enqueue_event(_mk_event(worker_seq, event_id=f"ev-conc-{worker_seq}", stream="s-conc"))
        return eid_same, eid_own

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_worker, 2)
        f2 = pool.submit(_worker, 3)
        r1 = f1.result(timeout=15.0)
        r2 = f2.result(timeout=15.0)

    assert r1[0] == "ev-conc-1" and r2[0] == "ev-conc-1"
    entries = OutboxSpool(spool_dir).read_pending(limit=10)
    assert sorted(e.sequence for e in entries) == [1, 2, 3]


def test_outbox_100mb_default_smaller_cap_enospc_and_space_reclaim(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.ports.capture import DEFAULT_OUTBOX_MAX_BYTES, CaptureBatchAck
    from superbrain.storage.outbox import OutboxSpool

    assert DEFAULT_OUTBOX_MAX_BYTES == 104_857_600

    spool = OutboxSpool(trusted_tmp / "cap-spool", max_bytes=1200)
    spool.enqueue_event(_mk_event(1, note="A" * 100))
    bytes_one = spool.total_bytes()
    assert 0 < bytes_one <= 1200

    # Overflow max_bytes -> STORAGE_FULL, existing pending intact.
    with pytest.raises(BrainError) as exc_cap:
        spool.enqueue_event(_mk_event(2, note="B" * 1500))
    assert exc_cap.value.code is ErrorCode.STORAGE_FULL
    assert [e.sequence for e in spool.read_pending(limit=10)] == [1]

    # ENOSPC during write/flush -> STORAGE_FULL, existing durable items intact.
    def _fail_enospc(fd: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", _fail_enospc)
    with pytest.raises(BrainError) as exc_enospc:
        spool.enqueue_event(_mk_event(2, note="small"))
    assert exc_enospc.value.code is ErrorCode.STORAGE_FULL
    monkeypatch.undo()
    assert [e.sequence for e in spool.read_pending(limit=10)] == [1]

    # apply_ack reclaims bytes so subsequent bounded enqueue succeeds.
    assert spool.apply_ack(CaptureBatchAck("stream-a", "r1", "c1", (1,), 1, (), 1, 0)) == 1
    assert spool.total_bytes() == 0
    spool.enqueue_event(_mk_event(2, note="C" * 100))
    assert [e.sequence for e in spool.read_pending(limit=10)] == [2]


def test_outbox_separated_ack_eviction_preserves_holes_and_distinguishes_gaps(trusted_tmp: Path) -> None:
    from superbrain.ports.capture import OUTBOX_RECORD_EVENT, OUTBOX_RECORD_GAP, CaptureBatchAck
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "sep-ack-spool"
    spool = OutboxSpool(spool_dir)
    spool.enqueue_event(_mk_event(1))
    spool.enqueue_event(_mk_event(2))
    spool.enqueue_event(_mk_event(3))
    spool.enqueue_gap(_mk_gap(4))

    # Hole at 2: daemon commits 1, 3 -> contiguous=1. Gap ACK at 2 MUST NEVER delete Event 2!
    # Gap ACK at 4 deletes CaptureGap(4) cleanly.
    ack_hole = CaptureBatchAck(
        producer_stream="stream-a",
        repo_id="r1",
        checkout_id="c1",
        committed_event_sequences=(1, 3),
        contiguous_event_acked_through=1,
        acked_producer_gap_sequences=(2, 4),
        accepted_count=3,
        deduped_count=0,
    )
    evicted = spool.apply_ack(ack_hole)
    assert evicted == 3

    reopened = OutboxSpool(spool_dir)
    rem = reopened.read_pending(limit=10)
    assert [(e.record_kind, e.sequence) for e in rem] == [(OUTBOX_RECORD_EVENT, 2)]

    # Event 4 on another stream or same seq must never be evicted by a gap ACK at seq 4.
    reopened.enqueue_event(_mk_event(4, stream="stream-b"))
    reopened.enqueue_gap(_mk_gap(4, stream="stream-b"))
    assert reopened.apply_ack(CaptureBatchAck("stream-b", "r1", "c1", (), 0, (4,), 1, 0)) == 1
    rem_b = reopened.read_pending(limit=10, producer_stream="stream-b")
    assert [(e.record_kind, e.sequence) for e in rem_b] == [(OUTBOX_RECORD_EVENT, 4)]

    # Late Event 2 commit finally evicts Event 2.
    assert reopened.apply_ack(CaptureBatchAck("stream-a", "r1", "c1", (2,), 3, (), 1, 0)) == 1
    assert reopened.read_pending(limit=10, producer_stream="stream-a") == []
    # Sanity check OUTBOX_RECORD_GAP constant unused lint safety.
    assert OUTBOX_RECORD_GAP == "capture_gap"


def test_outbox_discards_torn_staging_and_eof_tail_but_rejects_middle_corruption(trusted_tmp: Path) -> None:
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "torn-spool"
    spool = OutboxSpool(spool_dir)
    spool.enqueue_event(_mk_event(1, note="frame-1-ok"))
    spool.enqueue_event(_mk_event(2, note="frame-2-ok"))

    # Stage leftover .part file + append truncated EOF tail bytes to the active spool data file.
    leftover_part = spool_dir / "pending.part"
    leftover_part.write_bytes(b'{"partial": true')
    os_adapters().permissions.secure_file(leftover_part)

    data_files = sorted(
        p
        for p in spool_dir.rglob("*")
        if p.is_file() and not p.name.endswith(".part") and b"frame-1-ok" in p.read_bytes()
    )
    assert data_files
    target_file = data_files[0]
    tail_candidates = sorted(
        p
        for p in spool_dir.rglob("*")
        if p.is_file() and not p.name.endswith(".part") and b"frame-2-ok" in p.read_bytes()
    )
    assert tail_candidates
    tail_file = tail_candidates[-1]
    original_bytes = tail_file.read_bytes()
    tail_file.write_bytes(original_bytes + b'{"record_kind":"event","broken":')

    reopened = OutboxSpool(spool_dir)
    entries = reopened.read_pending(limit=10)
    assert [e.sequence for e in entries] == [1, 2]
    assert not leftover_part.exists()

    # Corrupting a byte inside the first frame's body/digest (not the tail) must fail closed.
    raw = target_file.read_bytes()
    idx = raw.find(b"frame-1-ok")
    assert idx > 0
    corrupted = raw[:idx] + b"CORRUPTED!" + raw[idx + 10 :]
    target_file.write_bytes(corrupted)
    with pytest.raises(BrainError) as exc_mid:
        OutboxSpool(spool_dir).read_pending(limit=10)
    assert exc_mid.value.code is ErrorCode.INTEGRITY_FAILURE
