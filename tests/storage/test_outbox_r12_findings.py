"""Regression oracles for Codex review R12 findings on the outbox spool (R12-1, R12-2, R12-3, R12-5..R12-7)."""

from __future__ import annotations

import errno
import io
import json
import os
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.outbox import OutboxSpool
from tests.storage.test_outbox_r10_ack_durability import (
    _ack,
    _enqueue_hook,
    _has_v4_artifact,
    _legacy_probe_script,
    _mk_event,
    _mk_gap,
    _repo_root_with_36bf08d9,
    _seed_r11_f16_outbox,
    _stream_dir,
)

_OUTBOX_MOD = sys.modules["superbrain.storage.outbox"]


def _pending(spool: OutboxSpool, stream: str) -> list[tuple[str, int]]:
    return [(e.record_kind, e.sequence) for e in spool.read_pending(limit=50, producer_stream=stream)]


def test_r12_1_hook_initializes_new_stream_after_v4_fence(trusted_tmp: Path) -> None:
    """R12-1: once the outbox is v4-fenced, a hook can still open a stream that never existed."""
    perms = os_adapters().permissions
    outbox = trusted_tmp / "outbox-r12-1"
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream="s-r12-1-a", dk=digest_bytes(b"r12-1-a"), explicit_seq=1)
    spool.apply_ack(_ack("s-r12-1-a", committed=(1, 5_000)))
    assert (outbox / "streams" / ".v4_fence").exists()

    rec_b = _enqueue_hook(spool, stream="s-r12-1-b", dk=digest_bytes(b"r12-1-b"))
    assert rec_b.sequence == 1
    rec_c = spool.enqueue_hook_event(
        producer_stream="s-r12-1-c", build_event=lambda s, e, _r: _mk_event("s-r12-1-c", s, event_id=e),
        fallback_recorded_at="2026-11-27T08:00:00Z",
    )
    assert rec_c.sequence == 1
    spool.enqueue_event(_mk_event("s-r12-1-d", 1))
    restarted = OutboxSpool(outbox, permissions=perms)
    rec_d = _enqueue_hook(restarted, stream="s-r12-1-d", dk=digest_bytes(b"r12-1-d"))
    assert rec_d.sequence == 2
    for stream, want in (("s-r12-1-b", [("event", 1)]), ("s-r12-1-c", [("event", 1)]),
                         ("s-r12-1-d", [("event", 1), ("event", 2)])):
        assert _pending(restarted, stream) == want, stream
        cursor = json.loads((_stream_dir(outbox, stream) / ".seq_cursor.json").read_text(encoding="utf-8"))
        assert cursor["schema_version"] == 4, stream


def _committed_view(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.name.endswith(".part")
    }


def test_r12_2_legacy_binary_refusal_never_changes_committed_state(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R12-2: with staging left at every level, each legacy 36bf08d9 entry point refuses a v4 outbox and leaves
    every committed file (frames, cursors, buckets, ACK pages, fence) byte-identical; only uncommitted ``.part``
    staging, which the current binary's own sweep also discards, may be removed."""
    perms = os_adapters().permissions
    stream_a, stream_b = "stream-r12-2-a", "stream-r12-2-b"
    roots: dict[str, Path] = {}
    done = trusted_tmp / "outbox-r12-2-completed"
    _seed_r11_f16_outbox(done, stream_a, stream_b, perms).apply_ack(_ack(stream_a, committed=(1, 5_000)))
    roots["completed"] = done
    sibling = trusted_tmp / "outbox-r12-2-sibling"
    spool_s = _seed_r11_f16_outbox(sibling, stream_a, stream_b, perms)
    from superbrain.storage import _outbox_seq

    orig_recover = _outbox_seq.recover_stream_cursor

    def _sibling_boom(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("skip_fence"):
            raise BrainError(ErrorCode.IO_ERROR, "interrupted before sibling upgrade")
        return orig_recover(*args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(_outbox_seq, "recover_stream_cursor", _sibling_boom)
        with pytest.raises(BrainError):
            spool_s.apply_ack(_ack(stream_a, committed=(1, 5_000)))
    roots["sibling_not_upgraded"] = sibling
    for root in roots.values():
        assert _has_v4_artifact(root)
        sa, sb = _stream_dir(root, stream_a), _stream_dir(root, stream_b)
        staged = [root / "root-stage.part", sa / "x_event_00000000000000000009.part", sb / ".cursor-x.part"]
        if (sa / ".bindings").is_dir():
            staged.append(sa / ".bindings" / "aa.json.x.part")
        if (sa / ".acks").is_dir():
            staged.append(sa / ".acks" / "page.x.part")
        for path in staged:
            path.write_bytes(b"staging")
            perms.secure_file(path)

    repo_root = _repo_root_with_36bf08d9()
    if repo_root is None:
        pytest.skip("36bf08d9 is not reachable from this checkout")
    legacy_root = trusted_tmp / "legacy-src-36bf08d9-r12-2"
    legacy_root.mkdir(parents=True)
    tar_bytes = subprocess.check_output(["git", "-C", str(repo_root), "archive", "--format=tar", "36bf08d9", "src"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(legacy_root, filter="data")
    before = {name: _committed_view(root) for name, root in roots.items()}
    script = _legacy_probe_script(legacy_root / "src", [(str(r), stream_a, stream_b) for r in roots.values()])
    script = script.replace(
        "    res = {}\n",
        "    ops['read_pending'] = lambda: spool.read_pending(limit=10)\n"
        "    ops['total_bytes'] = lambda: spool.total_bytes()\n"
        "    res = {}\n",
    )
    proc = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    results = json.loads(proc.stdout.strip().splitlines()[-1])
    for name, root in roots.items():
        res = results[str(root)]
        assert len(res) == 8, (name, res)
        assert all(v.startswith("refused:") for v in res.values()), (name, res)
        assert _committed_view(root) == before[name], name


def _seed_acked_once(trusted_tmp: Path, name: str) -> tuple[OutboxSpool, str, Path]:
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / f"outbox-r12-3-{name}", f"stream-r12-3-{name}"
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(f"r12-3-{name}".encode()), explicit_seq=1)
    return spool, stream, _stream_dir(outbox, stream)


def test_r12_3_ack_retry_reestablishes_metadata_durability(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R12-3: a retried ACK syncs again every directory its eviction depends on before deleting a frame."""
    from superbrain.adapters.os import durable

    real_fsync_dir = durable._fsync_directory

    def _eio_for(target: Path, *, once_exists: Path | None = None) -> Any:
        def _fake(path: Path, **kw: Any) -> bool:
            if Path(path) == target and (once_exists is None or once_exists.exists()):
                raise OSError(errno.EIO, "injected EIO")
            return bool(real_fsync_dir(path, **kw))
        return _fake

    # (a) streams/ sync fails after the fence was replaced; the retry must not trust the fence without a sync.
    spool_a, stream_a, sdir_a = _seed_acked_once(trusted_tmp, "fence")
    streams_a = sdir_a.parent
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_for(streams_a, once_exists=streams_a / ".v4_fence"))
        for _attempt in range(2):
            with pytest.raises(BrainError) as err_a:
                spool_a.apply_ack(_ack(stream_a, committed=(1, 5_000)))
            assert err_a.value.code is ErrorCode.IO_ERROR
            assert (streams_a / ".v4_fence").exists()
            assert _pending(spool_a, stream_a) == [("event", 1)]
    assert spool_a.apply_ack(_ack(stream_a, committed=(1, 5_000))) == 1

    # (b) cursor directory sync keeps failing; the retry sees the new cursor but must not evict before a sync.
    spool_b, stream_b, sdir_b = _seed_acked_once(trusted_tmp, "cursor")
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_for(sdir_b))
        for _attempt in range(2):
            with pytest.raises(BrainError) as err_b:
                spool_b.apply_ack(_ack(stream_b, committed=(1, 5_000)))
            assert err_b.value.code is ErrorCode.IO_ERROR
            assert _pending(spool_b, stream_b) == [("event", 1)]
    assert spool_b.apply_ack(_ack(stream_b, committed=(1, 5_000))) == 1


def _raw_event(stream: str, seq: int) -> bytes:
    return json.dumps({
        "event_id": f"ev-{stream}-{seq}", "producer_stream": stream, "sequence": seq, "harness_id": "claude-code",
        "kind": "tool_post", "recorded_at": "2026-11-27T08:00:00Z", "payload": {"tool": "Read", "seq": seq},
    }).encode()


def test_r12_5_capture_result_separates_published_lost_and_integrity(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R12-5: no CaptureGap is written for a sequence that already holds a published or acknowledged event,
    a gap is still written for a sequence that has none, and an integrity failure after publication is reported."""
    from superbrain.composition.hook_entry import run_hook
    from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

    perms = os_adapters().permissions
    real_sanitize = CapturePrivacyGate.sanitize_event

    def _deadline_in_sanitize(self: Any, *a: Any, **kw: Any) -> Any:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def _hook(outbox: Path, raw: bytes) -> None:
        assert run_hook(raw, outbox_dir=outbox, spool_factory=lambda d: OutboxSpool(d, permissions=perms)) == 0

    outbox = trusted_tmp / "outbox-r12-5"
    stream = "stream-r12-5"
    spool = OutboxSpool(outbox, permissions=perms)
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r12-5-cursor"), explicit_seq=1)  # stream keeps a cursor
    _hook(outbox, _raw_event(stream, 2))
    with monkeypatch.context() as mp:
        mp.setattr(CapturePrivacyGate, "sanitize_event", _deadline_in_sanitize)
        _hook(outbox, _raw_event(stream, 2))  # published, not yet acknowledged
        spool.apply_ack(_ack(stream, committed=(1,), contiguous=1))
        _hook(outbox, _raw_event(stream, 1))  # acknowledged and evicted
        _hook(outbox, _raw_event(stream, 3))  # positive twin: no event at 3, the gap is real
    assert CapturePrivacyGate.sanitize_event is real_sanitize
    assert _pending(spool, stream) == [("event", 2), ("capture_gap", 3)]

    # Integrity failure while clearing pending state after publication is reported, never turned into success.
    outbox_h, stream_h = trusted_tmp / "outbox-r12-5-hook", "stream-r12-5-hook"
    spool_h = OutboxSpool(outbox_h, permissions=perms)
    real_write = _OUTBOX_MOD.write_stream_cursor
    calls = [0]

    def _corrupt_second_write(*args: Any, **kwargs: Any) -> None:
        calls[0] += 1
        if calls[0] == 2:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "cursor corrupt")
        real_write(*args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(_OUTBOX_MOD, "write_stream_cursor", _corrupt_second_write)
        with pytest.raises(BrainError) as err_h:
            _enqueue_hook(spool_h, stream=stream_h, dk=digest_bytes(b"r12-5-hook"))
    assert err_h.value.code is ErrorCode.INTEGRITY_FAILURE
    assert calls[0] == 2

    outbox_d = trusted_tmp / "outbox-r12-5-direct"
    spool_d = OutboxSpool(outbox_d, permissions=perms)

    def _corrupt_bump(*_a: Any, **_kw: Any) -> None:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "cursor corrupt")

    spool_d.enqueue_event(_mk_event("s-r12-5-d", 1))
    with monkeypatch.context() as mp:
        mp.setattr(_OUTBOX_MOD, "commit_bumped_cursor", _corrupt_bump)
        with pytest.raises(BrainError) as err_d:
            spool_d.enqueue_event(_mk_event("s-r12-5-d", 2))
    assert err_d.value.code is ErrorCode.INTEGRITY_FAILURE


class _BusyLock:
    def __init__(self, on_try: Any) -> None:
        self._on_try = on_try

    def try_lock_fd(self, fd: int) -> bool:
        return bool(self._on_try())

    def unlock_fd(self, fd: int) -> None:
        return None


def test_r12_6_lock_waits_and_staging_cleanup_honor_cutoff(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R12-6: lock waits are bounded by the remaining budget and failed staging is left to a later sweep."""
    perms = os_adapters().permissions

    # (a) The file lock stays busy until the cutoff passes: no sleep after expiry.
    now_a = [0]
    sleeps_a: list[float] = []

    def _busy_then_expire() -> bool:
        now_a[0] = 2_000
        return False

    spool_a = OutboxSpool(trusted_tmp / "outbox-r12-6-lock", permissions=perms, file_lock=_BusyLock(_busy_then_expire),
                          monotonic_ns=lambda: now_a[0])
    with monkeypatch.context() as mp:
        mp.setattr(time, "sleep", sleeps_a.append)
        with pytest.raises(BrainError) as err_a:
            spool_a.enqueue_gap(_mk_gap("s-r12-6-a", 1), deadline_ns=1_000)
    assert err_a.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert sleeps_a == []

    # (b) With 1 ms left a busy file lock waits at most that long.
    now_b = [0]
    sleeps_b: list[float] = []
    tries = [0]

    def _busy_near_deadline() -> bool:
        tries[0] += 1
        if tries[0] == 1:
            now_b[0] = 1_000_000_000 - 1_000_000
            return False
        return True

    spool_b = OutboxSpool(trusted_tmp / "outbox-r12-6-bound", permissions=perms,
                          file_lock=_BusyLock(_busy_near_deadline), monotonic_ns=lambda: now_b[0])
    with monkeypatch.context() as mp:
        mp.setattr(time, "sleep", sleeps_b.append)
        spool_b.enqueue_gap(_mk_gap("s-r12-6-b", 1), deadline_ns=1_000_000_000)
    assert sleeps_b and max(sleeps_b) <= 0.001 + 1e-9, sleeps_b

    # (c) The in-process lock is held elsewhere: the wait ends at the cutoff, not when the holder releases.
    outbox_c = trusted_tmp / "outbox-r12-6-thread"
    spool_c = OutboxSpool(outbox_c, permissions=perms)
    spool_c.enqueue_gap(_mk_gap("s-r12-6-c", 1))
    held, release = threading.Event(), threading.Event()

    def _holder() -> None:
        with spool_c._thread_lock:
            held.set()
            release.wait(5)

    th = threading.Thread(target=_holder)
    th.start()
    try:
        assert held.wait(5)
        start = time.monotonic()
        with pytest.raises(BrainError) as err_c:
            spool_c.enqueue_gap(_mk_gap("s-r12-6-c", 2), deadline_ns=time.monotonic_ns() + 50_000_000)
        elapsed = time.monotonic() - start
    finally:
        release.set()
        th.join(5)
    assert err_c.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert elapsed < 1.0, elapsed

    # (d) The frame fsync spends the budget: the error stands and the staging file waits for the next sweep.
    now_d = [0]
    outbox_d, stream_d = trusted_tmp / "outbox-r12-6-stage", "s-r12-6-d"
    spool_d = OutboxSpool(outbox_d, permissions=perms, monotonic_ns=lambda: now_d[0])
    spool_d.enqueue_event(_mk_event(stream_d, 1))
    sdir_d = _stream_dir(outbox_d, stream_d)
    real_fsync = os.fsync

    def _fsync_spends_budget(fd: int) -> None:
        real_fsync(fd)
        if any(sdir_d.glob("*_event_*.part")):
            now_d[0] = 2_000

    with monkeypatch.context() as mp:
        mp.setattr(os, "fsync", _fsync_spends_budget)
        with pytest.raises(BrainError) as err_d:
            spool_d.enqueue_event(_mk_event(stream_d, 2), deadline_ns=1_000)
    assert err_d.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert list(sdir_d.glob("*_event_*.part"))
    now_d[0] = 0
    assert _pending(spool_d, stream_d) == [("event", 1)]
    assert not list(sdir_d.glob("*.part"))


def test_r12_7_capacity_refusal_leaves_outbox_untouched(trusted_tmp: Path) -> None:
    """R12-7: a hook refused for the binding cap changes nothing on disk, staging included."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r12-7", "stream-r12-7"
    spool = OutboxSpool(outbox, permissions=perms, max_binding_keys=1)
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r12-7-k1"), explicit_seq=1)
    sdir = _stream_dir(outbox, stream)
    bucket = next((sdir / ".bindings").glob("*.json"))
    row = json.loads(bucket.read_text(encoding="utf-8"))["entries"][0]
    cur_path = sdir / ".seq_cursor.json"
    cur = json.loads(cur_path.read_text(encoding="utf-8"))
    cur["pending_binding"] = row
    cur_path.write_bytes(canonical_json(cur))
    for stage in (sdir / ".bindings" / f"{bucket.name}.r12-7.part", sdir / "x_event_00000000000000000009.part",
                  outbox / "root-r12-7.part", sdir.parent / ".v4_fence-r12-7.part"):
        stage.write_bytes(b"staging")
        perms.secure_file(stage)
    before = {p.relative_to(outbox).as_posix(): p.read_bytes() for p in sorted(outbox.rglob("*")) if p.is_file()}
    with pytest.raises(BrainError) as err:
        _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"r12-7-k2"))
    assert err.value.code is ErrorCode.STORAGE_FULL
    after = {p.relative_to(outbox).as_posix(): p.read_bytes() for p in sorted(outbox.rglob("*")) if p.is_file()}
    assert after == before
