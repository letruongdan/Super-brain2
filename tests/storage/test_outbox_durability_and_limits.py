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
        "from superbrain.adapters.os import os_adapters; "
        "from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK; "
        "spool = OutboxSpool(Path(sys.argv[1]), permissions=os_adapters().permissions, file_lock=OUTBOX_FILE_LOCK); "
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
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    spool_dir = trusted_tmp / "exit-spool"
    child_code = (
        "import os, sys; from pathlib import Path; "
        "from superbrain.ports.capture import CaptureEventRecord; "
        "from superbrain.storage.outbox import OutboxSpool; "
        "assert 'superbrain.core.faults' not in sys.modules; "
        "from superbrain.adapters.os import os_adapters; "
        "from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK; "
        "s = OutboxSpool(Path(sys.argv[1]), permissions=os_adapters().permissions, file_lock=OUTBOX_FILE_LOCK); "
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
    pending = OutboxSpool(
        spool_dir, permissions=os_adapters().permissions, file_lock=OUTBOX_FILE_LOCK
    ).read_pending(limit=10)
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


def test_outbox_init_does_not_sweep_part_unlocked_and_read_pending_sweeps_under_lock(
    trusted_tmp: Path,
) -> None:
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    spool_dir = trusted_tmp / "init-no-sweep-spool"
    s1 = OutboxSpool(spool_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    s1.enqueue_event(_mk_event(1, note="kept-event-1"))

    root_part = spool_dir / "pending.part"
    root_part.write_bytes(b'{"partial": true')
    os_.permissions.secure_file(root_part)

    stream_dirs = [p for p in (spool_dir / "streams").iterdir() if p.is_dir()]
    assert stream_dirs
    stream_part = stream_dirs[0] / "orphan.part"
    stream_part.write_bytes(b'{"orphan": true')
    os_.permissions.secure_file(stream_part)

    class _SpyLock:
        def __init__(self) -> None:
            self.acquires = 0
            self.unlocks = 0
            self.parts_present_on_first_lock: list[bool] = []

        def try_lock_fd(self, fd: int) -> bool:
            ok = bool(OUTBOX_FILE_LOCK.try_lock_fd(fd))
            if ok:
                if self.acquires == 0:
                    self.parts_present_on_first_lock = [root_part.exists(), stream_part.exists()]
                self.acquires += 1
            return ok

        def unlock_fd(self, fd: int) -> None:
            self.unlocks += 1
            OUTBOX_FILE_LOCK.unlock_fd(fd)

    spy = _SpyLock()
    reopened = OutboxSpool(spool_dir, permissions=os_.permissions, file_lock=spy)
    assert spy.acquires == 0
    assert root_part.exists() is True
    assert stream_part.exists() is True

    entries = reopened.read_pending(limit=10)
    assert spy.acquires >= 1
    assert spy.unlocks == spy.acquires
    assert spy.parts_present_on_first_lock == [True, True]
    assert not root_part.exists()
    assert not stream_part.exists()
    assert [e.sequence for e in entries] == [1]


def test_outbox_fails_closed_without_os_adapters_in_clean_process(trusted_tmp: Path) -> None:
    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from superbrain.core.errors import BrainError, ErrorCode\n"
        "from superbrain.ports.capture import CaptureEventRecord\n"
        "from superbrain.storage.outbox import OutboxSpool\n"
        "class _StubPerms:\n"
        "    def secure_directory(self, path: Path) -> None: pass\n"
        "    def secure_file(self, path: Path) -> None: pass\n"
        "    def problems(self, path: Path) -> list[object]: return []\n"
        "class _StubLock:\n"
        "    def try_lock_fd(self, fd: int) -> bool: return True\n"
        "    def unlock_fd(self, fd: int) -> None: pass\n"
        "ev = CaptureEventRecord('ev-fc-1','s1',1,'claude-code','tool_post','2026-11-21T12:00:00Z',{'k':'v'})\n"
        "allowed = {ErrorCode.CAPABILITY_UNAVAILABLE.value, ErrorCode.INSECURE_PERMISSIONS.value}\n"
        "results = {}\n"
        "for label, kwargs in [\n"
        "    ('no_adapters', {}),\n"
        "    ('no_lock', {'permissions': _StubPerms()}),\n"
        "    ('no_perms', {'file_lock': _StubLock()}),\n"
        "]:\n"
        "    try:\n"
        "        s = OutboxSpool(Path(sys.argv[1]) / label, **kwargs)\n"
        "        s.enqueue_event(ev)\n"
        "        results[label] = 'UNEXPECTED_SUCCESS'\n"
        "    except BrainError as exc:\n"
        "        results[label] = exc.code.value\n"
        "print(json.dumps({'results': results, 'os_imported': 'superbrain.adapters.os' in sys.modules, "
        "'allowed': sorted(allowed)}))"
    )
    res = subprocess.run(
        [sys.executable, "-I", "-c", script, str(trusted_tmp / "clean-fail-closed")],
        env=_clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=15.0,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["os_imported"] is False
    allowed = set(data["allowed"])
    for key in ("no_adapters", "no_lock", "no_perms"):
        assert data["results"][key] in allowed, f"{key} failed with {data['results'][key]!r} instead of {allowed}"


def test_outbox_rejects_preexisting_insecure_directory_and_symlinked_stream_frame(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    bad_dir = trusted_tmp / "pre-insecure-outbox"
    bad_dir.mkdir()
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(bad_dir, "S-1-1-0", 0x120089, flags=0x3)
    else:
        os.chmod(bad_dir, 0o755)
    assert os_.permissions.problems(bad_dir)

    with pytest.raises(BrainError) as exc_perm:
        s_bad = OutboxSpool(bad_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
        s_bad.read_pending(limit=10)
    assert exc_perm.value.code is ErrorCode.INSECURE_PERMISSIONS

    # Symlinked .frame under filtered read_pending(producer_stream=...) must fail closed with UNSAFE_PATH.
    good_dir = trusted_tmp / "symlink-frame-outbox"
    spool = OutboxSpool(good_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    spool.enqueue_event(_mk_event(1, stream="stream-link-f3", note="frame-link-bait"))
    frame_files = sorted(p for p in good_dir.rglob("*.frame") if p.is_file())
    assert len(frame_files) == 1
    fake_link(monkeypatch, frame_files[0])
    with pytest.raises(BrainError) as exc_link:
        OutboxSpool(good_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
            limit=10, producer_stream="stream-link-f3"
        )
    assert exc_link.value.code is ErrorCode.UNSAFE_PATH


def test_outbox_frames_use_pure_lf_fail_closed_on_newlineless_frame_and_repair_atomically(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    lf_dir = trusted_tmp / "pure-lf-spool"
    s_lf = OutboxSpool(lf_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    s_lf.enqueue_event(_mk_event(1, note="pure-lf-spool-1"))
    s_lf.enqueue_gap(_mk_gap(2))

    hook_lf_dir = trusted_tmp / "pure-lf-hook"
    hook_ev = json.dumps(
        {
            "event_id": "evt-hook-lf-1",
            "producer_stream": "hook-lf-stream",
            "sequence": 1,
            "harness_id": "claude-code",
            "kind": "tool_post",
            "recorded_at": "2026-11-21T12:00:00Z",
            "payload": {"note": "pure-lf-hook-1"},
        }
    ).encode()
    res_hook = subprocess.run(
        [sys.executable, "-I", "-m", "superbrain.composition.hook_entry", "--outbox", str(hook_lf_dir)],
        input=hook_ev,
        env=_clean_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res_hook.returncode == 0, res_hook.stderr.decode(errors="replace")

    for base in (lf_dir, hook_lf_dir):
        frames = sorted(p for p in base.rglob("*.frame") if p.is_file())
        assert frames
        for frame in frames:
            raw = frame.read_bytes()
            assert b"\r\n" not in raw, f"CRLF detected in outbox frame {frame}"
            assert raw.endswith(b"\n")

    # Empty or newline-less .frame files fail closed with INTEGRITY_FAILURE without unlinking evidence.
    for label, corrupt_bytes in (("empty", b""), ("no_nl", b'{"no":"newline"}')):
        corrupt_dir = trusted_tmp / f"corrupt-{label}"
        cs = OutboxSpool(corrupt_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
        cs.enqueue_event(_mk_event(1, note=f"corrupt-{label}"))
        c_frames = sorted(p for p in corrupt_dir.rglob("*.frame") if p.is_file())
        assert len(c_frames) == 1
        c_frame = c_frames[0]
        c_frame.write_bytes(corrupt_bytes)
        with pytest.raises(BrainError) as exc_nl:
            OutboxSpool(corrupt_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(limit=10)
        assert exc_nl.value.code is ErrorCode.INTEGRITY_FAILURE
        assert c_frame.exists() is True
        assert c_frame.read_bytes() == corrupt_bytes

    # Torn EOF suffix repair uses atomic .part + os.replace; os.replace failure leaves committed bytes intact.
    repair_dir = trusted_tmp / "atomic-repair-spool"
    rs = OutboxSpool(repair_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    rs.enqueue_event(_mk_event(1, note="atomic-ok-1"))
    rs.enqueue_event(_mk_event(2, note="atomic-ok-2"))
    tail_candidates = sorted(
        p for p in repair_dir.rglob("*.frame") if p.is_file() and b"atomic-ok-2" in p.read_bytes()
    )
    assert tail_candidates
    tail_file = tail_candidates[-1]
    committed_bytes = tail_file.read_bytes()
    torn_bytes = committed_bytes + b'{"record_kind":"event","torn":'
    tail_file.write_bytes(torn_bytes)

    replace_calls: list[tuple[Any, Any]] = []

    def _failing_replace(src: Any, dst: Any) -> None:
        replace_calls.append((src, dst))
        raise OSError(errno.EIO, "simulated replace crash")

    monkeypatch.setattr(os, "replace", _failing_replace)
    with pytest.raises(BrainError) as exc_rep:
        OutboxSpool(repair_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(limit=10)
    assert exc_rep.value.code is ErrorCode.IO_ERROR
    assert len(replace_calls) == 1
    assert tail_file.read_bytes().startswith(committed_bytes)

    monkeypatch.undo()
    repaired_entries = OutboxSpool(
        repair_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK
    ).read_pending(limit=10)
    assert [e.sequence for e in repaired_entries] == [1, 2]
    assert tail_file.read_bytes() == committed_bytes
    assert list(repair_dir.rglob("*.part")) == []


def test_outbox_and_hook_log_handle_concurrent_cold_creation_under_loose_parent_while_refusing_preexisting_insecure(
    trusted_tmp: Path,
) -> None:
    import threading

    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.composition.hook_entry import run_hook
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    loose_parent = trusted_tmp / "loose-parent-r2"
    loose_parent.mkdir()
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(loose_parent, "S-1-1-0", 0x120089, flags=0x3)
    else:
        os.chmod(loose_parent, 0o755)
    assert os_.permissions.problems(loose_parent)

    # Deterministic pipe-synchronized two-process TOCTOU cold races on dir and lockfile hardening.
    def _run_pipe_cold_race(mode: str, target_dir: Path, stream: str) -> None:
        proc_a_script = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "if os.name == 'posix': os.umask(0o022)\n"
            "import superbrain.adapters.os\n"
            "from superbrain.adapters.os import os_adapters\n"
            "from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK\n"
            "from superbrain.ports.capture import CaptureEventRecord, default_outbox_permissions\n"
            "from superbrain.storage.outbox import OutboxSpool\n"
            "inner = default_outbox_permissions() or os_adapters().permissions\n"
            "pause_mode = sys.argv[2]\n"
            "class _PausePerms:\n"
            "    def __init__(self) -> None:\n"
            "        self._paused = False\n"
            "    def _maybe_pause(self, kind: str) -> None:\n"
            "        if kind == pause_mode and not self._paused:\n"
            "            self._paused = True\n"
            "            sys.stdout.write('READY\\n')\n"
            "            sys.stdout.flush()\n"
            "            assert sys.stdin.readline().strip() == 'CONTINUE'\n"
            "    def secure_directory(self, path: Path) -> None:\n"
            "        self._maybe_pause('dir')\n"
            "        inner.secure_directory(path)\n"
            "    def secure_file(self, path: Path) -> None:\n"
            "        self._maybe_pause('file')\n"
            "        inner.secure_file(path)\n"
            "    def problems(self, path: Path):\n"
            "        return inner.problems(path)\n"
            "    def object_problems(self, path: Path):\n"
            "        return inner.object_problems(path)\n"
            "s = OutboxSpool(Path(sys.argv[1]), permissions=_PausePerms(), file_lock=OUTBOX_FILE_LOCK)\n"
            "s.enqueue_event(CaptureEventRecord('ev-race-a', sys.argv[3], 1, 'claude-code', 'tool_post', "
            "'2026-11-21T12:00:00Z', {'race': 'a'}))\n"
        )
        proc_b_script = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "if os.name == 'posix': os.umask(0o022)\n"
            "import superbrain.adapters.os\n"
            "from superbrain.adapters.os import os_adapters\n"
            "from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK\n"
            "from superbrain.ports.capture import CaptureEventRecord, default_outbox_permissions\n"
            "from superbrain.storage.outbox import OutboxSpool\n"
            "inner = default_outbox_permissions() or os_adapters().permissions\n"
            "s = OutboxSpool(Path(sys.argv[1]), permissions=inner, file_lock=OUTBOX_FILE_LOCK)\n"
            "s.enqueue_event(CaptureEventRecord('ev-race-b', sys.argv[2], 2, 'claude-code', 'tool_post', "
            "'2026-11-21T12:00:01Z', {'race': 'b'}))\n"
        )
        proc_a = subprocess.Popen(
            [sys.executable, "-I", "-c", proc_a_script, str(target_dir), mode, stream],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_clean_env(),
        )
        try:
            assert proc_a.stdout is not None and proc_a.stdin is not None
            ready = proc_a.stdout.readline().strip()
            assert ready == "READY", (
                f"proc_a failed before READY ({mode}): rc={proc_a.poll()} "
                f"stderr={proc_a.stderr.read() if proc_a.stderr else ''}"
            )
            res_b = subprocess.run(
                [sys.executable, "-I", "-c", proc_b_script, str(target_dir), stream],
                input="",
                text=True,
                env=_clean_env(),
                capture_output=True,
                check=False,
                timeout=10.0,
            )
            assert res_b.returncode == 0, f"proc_b failed during {mode} pause: {res_b.stderr}"
            proc_a.stdin.write("CONTINUE\n")
            proc_a.stdin.flush()
            proc_a.stdin.close()
            rc_a = proc_a.wait(timeout=10.0)
            err_a = proc_a.stderr.read() if proc_a.stderr is not None else ""
            assert rc_a == 0, f"proc_a failed ({mode}): {err_a}"
        finally:
            for pipe in (proc_a.stdin, proc_a.stdout, proc_a.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
            if proc_a.poll() is None:
                proc_a.terminate()
                try:
                    proc_a.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    proc_a.kill()
                    proc_a.wait(timeout=5.0)

    dir_target = loose_parent / "pipe-race-dir"
    _run_pipe_cold_race("dir", dir_target, "pipe-dir-stream")
    dir_entries = OutboxSpool(dir_target, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
        limit=10, producer_stream="pipe-dir-stream"
    )
    assert sorted(e.sequence for e in dir_entries) == [1, 2]
    assert os_.permissions.problems(dir_target) == []

    lock_target = loose_parent / "pipe-race-lock"
    _run_pipe_cold_race("file", lock_target, "pipe-lock-stream")
    lock_entries = OutboxSpool(lock_target, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
        limit=10, producer_stream="pipe-lock-stream"
    )
    assert sorted(e.sequence for e in lock_entries) == [1, 2]
    assert os_.permissions.problems(lock_target) == []
    assert os_.permissions.object_problems(lock_target / ".spool.lock") == []

    # Multi-thread concurrent OutboxSpool cold creation (zero PrivacyFilter skew) across 6 trials.
    for spool_trial in range(6):
        spool_cold = loose_parent / f"cold-spool-direct-{spool_trial}"
        spool_barrier = threading.Barrier(12)

        def _spool_worker(
            idx: int,
            b: threading.Barrier = spool_barrier,
            sd: Path = spool_cold,
        ) -> str:
            b.wait(timeout=10.0)
            s = OutboxSpool(sd, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
            return s.enqueue_event(_mk_event(idx + 1, stream="cold-direct-r2", note=f"w-{idx}"))

        with ThreadPoolExecutor(max_workers=12) as pool:
            eids = [f.result(timeout=15.0) for f in [pool.submit(_spool_worker, i) for i in range(12)]]
        assert len(eids) == 12
        pending_direct = OutboxSpool(
            spool_cold, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK
        ).read_pending(limit=50, producer_stream="cold-direct-r2")
        assert sorted(e.sequence for e in pending_direct) == list(range(1, 13))
        assert os_.permissions.problems(spool_cold) == []

    # Concurrent cold failing-hook log creation (verifies every log line lands and log ACL is strict).
    for log_trial in range(4):
        log_cold_dir = loose_parent / f"cold-log-dir-{log_trial}"
        log_cold = log_cold_dir / "nested" / "cold-fail.log"
        log_barrier = threading.Barrier(8)

        def _log_worker(
            b: threading.Barrier = log_barrier,
            ob: Path = loose_parent / f"cold-log-ob-{log_trial}",
            lp: Path = log_cold,
        ) -> int:
            b.wait(timeout=10.0)
            return run_hook(b"not json", outbox_dir=ob, log_path=lp)

        with ThreadPoolExecutor(max_workers=8) as pool:
            log_rcs = [f.result(timeout=15.0) for f in [pool.submit(_log_worker) for _ in range(8)]]
        assert log_rcs == [0] * 8
        assert log_cold.is_file()
        log_lines = [ln for ln in log_cold.read_text(encoding="utf-8").splitlines() if ln]
        assert len(log_lines) == 8, f"lost static log lines under concurrent cold creation: {log_lines}"
        assert all("invalid_input" in ln for ln in log_lines)
        assert os_.permissions.problems(log_cold_dir) == []
        assert os_.permissions.object_problems(log_cold) == []

    # Multi-thread concurrent cold run_hook creation across 4 trials (6 valid writers + 2 failing log writers).
    for trial in range(4):
        cold_outbox = loose_parent / f"cold-outbox-{trial}"
        cold_log = loose_parent / f"cold-{trial}.log"
        barrier = threading.Barrier(8)

        def _thread_worker(
            idx: int,
            b: threading.Barrier = barrier,
            ob: Path = cold_outbox,
            lp: Path = cold_log,
            t: int = trial,
        ) -> int:
            b.wait(timeout=10.0)
            if idx < 6:
                seq = idx + 1
                raw = json.dumps(
                    {
                        "event_id": f"ev-cold-{t}-{seq}",
                        "producer_stream": "cold-r2-stream",
                        "sequence": seq,
                        "harness_id": "claude-code",
                        "kind": "tool_post",
                        "recorded_at": "2026-11-21T12:00:00Z",
                        "payload": {"worker": seq},
                    }
                ).encode()
            elif idx == 6:
                raw = b"not json"
            else:
                raw = json.dumps(
                    {
                        "event_id": f"ev-cold-bad-{t}",
                        "producer_stream": "cold-r2-stream",
                        "sequence": 99,
                        "harness_id": "claude-code",
                        "kind": "tool_post",
                        "recorded_at": "2026-11-21T12:00:00Z",
                        "payload": {"note": "<private>UNCLOSED_R2_BAIT"},
                    }
                ).encode()
            return run_hook(raw, outbox_dir=ob, log_path=lp)

        with ThreadPoolExecutor(max_workers=8) as pool:
            rcs = [f.result(timeout=15.0) for f in [pool.submit(_thread_worker, i) for i in range(8)]]
        assert rcs == [0] * 8
        pending = OutboxSpool(cold_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
            limit=100, producer_stream="cold-r2-stream"
        )
        assert sorted(e.sequence for e in pending) == [1, 2, 3, 4, 5, 6]
        assert cold_log.is_file()
        log_text = cold_log.read_text(encoding="utf-8")
        assert log_text.count("invalid_input") == 2
        assert "insecure_permissions" not in log_text
        assert "UNCLOSED_R2_BAIT" not in log_text
        assert os_.permissions.problems(cold_outbox) == []
        assert os_.permissions.object_problems(cold_log) == []

    # Cross-process concurrent cold creation via synchronized python -I hook_entry processes.
    proc_outbox = loose_parent / "cold-outbox-proc"
    proc_log = loose_parent / "cold-proc.log"
    proc_cmd = (
        "import os, sys; "
        "os.umask(0o022) if os.name == 'posix' else None; "
        "from superbrain.composition.hook_entry import main; "
        "sys.stdout.write('READY\\n'); sys.stdout.flush(); "
        "assert sys.stdin.buffer.readline() == b'GO\\n'; "
        "sys.exit(main(sys.argv[1:]))"
    )
    proc_payloads: list[bytes] = []
    for idx in range(6):
        if idx < 4:
            seq = idx + 1
            proc_payloads.append(
                json.dumps(
                    {
                        "event_id": f"ev-proc-{seq}",
                        "producer_stream": "cold-r2-proc",
                        "sequence": seq,
                        "harness_id": "claude-code",
                        "kind": "tool_post",
                        "recorded_at": "2026-11-21T12:00:00Z",
                        "payload": {"proc": seq},
                    }
                ).encode()
            )
        else:
            proc_payloads.append(b"{corrupt")

    procs: list[subprocess.Popen[bytes]] = []
    try:
        for _ in range(6):
            p = subprocess.Popen(
                [sys.executable, "-I", "-c", proc_cmd, "--outbox", str(proc_outbox), "--log", str(proc_log)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_clean_env(),
            )
            procs.append(p)
        for p in procs:
            assert p.stdout is not None
            assert p.stdout.readline().strip() == b"READY"
        for p, payload in zip(procs, proc_payloads, strict=True):
            assert p.stdin is not None
            p.stdin.write(b"GO\n" + payload)
            p.stdin.flush()
            p.stdin.close()
        proc_rcs = [p.wait(timeout=15.0) for p in procs]
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5.0)
    assert proc_rcs == [0] * 6
    proc_pending = OutboxSpool(proc_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
        limit=100, producer_stream="cold-r2-proc"
    )
    assert sorted(e.sequence for e in proc_pending) == [1, 2, 3, 4]
    assert proc_log.is_file()
    proc_log_text = proc_log.read_text(encoding="utf-8")
    assert proc_log_text.count("invalid_input") == 2
    assert "insecure_permissions" not in proc_log_text
    assert os_.permissions.problems(proc_outbox) == []
    assert os_.permissions.object_problems(proc_log) == []

    # Negative twins: pre-existing insecure outbox dir or log file under loose parent must fail closed.
    pre_bad_outbox = loose_parent / "preexisting-insecure-outbox"
    pre_bad_outbox.mkdir()
    if sys.platform != "win32":
        os.chmod(pre_bad_outbox, 0o755)
    assert os_.permissions.problems(pre_bad_outbox)
    with pytest.raises(BrainError) as exc_pre_dir:
        OutboxSpool(pre_bad_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(limit=10)
    assert exc_pre_dir.value.code is ErrorCode.INSECURE_PERMISSIONS

    good_diag_log = trusted_tmp / "pre-dir-diag.log"
    valid_bytes = json.dumps(
        {
            "event_id": "ev-pre-bad-dir",
            "producer_stream": "cold-r2-stream",
            "sequence": 1,
            "harness_id": "claude-code",
            "kind": "tool_post",
            "recorded_at": "2026-11-21T12:00:00Z",
            "payload": {"k": "v"},
        }
    ).encode()
    assert run_hook(valid_bytes, outbox_dir=pre_bad_outbox, log_path=good_diag_log) == 0
    assert "insecure_permissions" in good_diag_log.read_text(encoding="utf-8")

    pre_bad_log = loose_parent / "preexisting-insecure.log"
    pre_bad_log.write_bytes(b"preexisting-sentinel\n")
    if sys.platform != "win32":
        os.chmod(pre_bad_log, 0o644)
    assert os_.permissions.object_problems(pre_bad_log)
    assert run_hook(b"not-json", outbox_dir=trusted_tmp / "outbox-for-bad-log", log_path=pre_bad_log) == 0
    assert pre_bad_log.read_bytes() == b"preexisting-sentinel\n"
