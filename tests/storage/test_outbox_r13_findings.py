"""Regression oracles for Codex review R13 findings on the outbox spool (R13-1..R13-5)."""

from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureEventRecord
from superbrain.storage.outbox import OutboxSpool
from tests.storage.test_outbox_r10_ack_durability import _ack, _enqueue_hook, _mk_event, _mk_gap, _stream_dir
from tests.storage.test_outbox_r12_findings import _pending, _raw_event

_REC_AT = "2026-11-28T08:00:00Z"


def _eio_for(target: Path) -> Any:
    from superbrain.adapters.os import durable

    real = durable._fsync_directory

    def _fake(path: Path, **kw: Any) -> bool:
        if Path(path) == target:
            raise OSError(errno.EIO, "injected EIO")
        return bool(real(path, **kw))

    return _fake


def test_r13_1_replay_and_sibling_upgrade_resync_metadata(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R13-1: a replayed enqueue and the pre-fence upgrade of a sibling stream confirm directory durability before
    they report success, clear a pending binding or evict."""
    from superbrain.adapters.os import durable

    perms = os_adapters().permissions
    # (a) direct replay of an already published frame
    outbox_a = trusted_tmp / "outbox-r13-1-direct"
    OutboxSpool(outbox_a, permissions=perms).enqueue_event(_mk_event("s-r13-1-d", 1))
    sdir_a = _stream_dir(outbox_a, "s-r13-1-d")
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_for(sdir_a))
        with pytest.raises(BrainError) as err_a:
            OutboxSpool(outbox_a, permissions=perms).enqueue_event(_mk_event("s-r13-1-d", 1))
        assert err_a.value.code is ErrorCode.IO_ERROR
    assert OutboxSpool(outbox_a, permissions=perms).enqueue_event(_mk_event("s-r13-1-d", 1)) == "ev-s-r13-1-d-1"

    # (b) hook replay of an already published frame
    outbox_b = trusted_tmp / "outbox-r13-1-hook"
    _enqueue_hook(OutboxSpool(outbox_b, permissions=perms), stream="s-r13-1-h", dk=digest_bytes(b"r13-1-h"))
    sdir_b = _stream_dir(outbox_b, "s-r13-1-h")
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_for(sdir_b))
        with pytest.raises(BrainError) as err_b:
            _enqueue_hook(OutboxSpool(outbox_b, permissions=perms), stream="s-r13-1-h", dk=digest_bytes(b"r13-1-h"))
        assert err_b.value.code is ErrorCode.IO_ERROR
    assert _enqueue_hook(OutboxSpool(outbox_b, permissions=perms), stream="s-r13-1-h",
                         dk=digest_bytes(b"r13-1-h")).sequence == 1

    # (c) sibling B stopped with a pending binding whose bucket directory never synced; A's first v4 ACK must not
    # clear B's pending binding or evict A while B's bindings directory still fails to sync.
    outbox_c = trusted_tmp / "outbox-r13-1-sibling"
    spool_c = OutboxSpool(outbox_c, permissions=perms)
    _enqueue_hook(spool_c, stream="s-r13-1-a", dk=digest_bytes(b"r13-1-a"), explicit_seq=1)
    sdir_bb = _stream_dir(outbox_c, "s-r13-1-b")
    with monkeypatch.context() as mp:
        mp.setattr(durable, "_fsync_directory", _eio_for(sdir_bb / ".bindings"))
        with pytest.raises(BrainError):
            _enqueue_hook(spool_c, stream="s-r13-1-b", dk=digest_bytes(b"r13-1-b"))
        assert json.loads((sdir_bb / ".seq_cursor.json").read_text(encoding="utf-8"))["pending_binding"] is not None
        with pytest.raises(BrainError) as err_c:
            spool_c.apply_ack(_ack("s-r13-1-a", committed=(1, 5_000)))
        assert err_c.value.code is ErrorCode.IO_ERROR
        assert json.loads((sdir_bb / ".seq_cursor.json").read_text(encoding="utf-8"))["pending_binding"] is not None
        assert _pending(spool_c, "s-r13-1-a") == [("event", 1)]
    assert spool_c.apply_ack(_ack("s-r13-1-a", committed=(1, 5_000))) == 1


def _native_prep(stream: str, dk: str) -> Any:
    from superbrain.composition._hook_adapter_bridge import PreparedNativeHook

    def _build(seq: int, ev_id: str, rec_at: str) -> CaptureEventRecord:
        return CaptureEventRecord(event_id=ev_id, producer_stream=stream, sequence=seq, harness_id="claude-code",
                                  kind="tool_post", recorded_at=rec_at, payload={"tool": "Read", "k": dk[:12]})

    return PreparedNativeHook(producer_stream=stream, raw_session_id=None, explicit_sequence=None,
                              explicit_event_id=None, dedup_key=dk, fallback_recorded_at=_REC_AT, skip_code=None,
                              build_record=_build)


def test_r13_2_fallback_gap_uses_the_real_slot_atomically(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R13-2: the hook fallback decides and writes its gap for the slot that event actually owns, under one spool
    lock, and a stream that only received direct events still remembers an acknowledged slot."""
    from superbrain.composition import _hook_adapter_bridge
    from superbrain.composition.hook_entry import run_hook
    from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r13-2-native", "stream-r13-2-native"
    native = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Read"}).encode()
    clock: dict[str, int | None] = {"calls": 0, "expire_at": None}

    def _mono() -> int:
        clock["calls"] = int(clock["calls"] or 0) + 1
        exp = clock["expire_at"]
        return 1_960_000_000 if exp is not None and int(clock["calls"] or 0) >= exp else 0

    def _factory(d: Path) -> OutboxSpool:
        return OutboxSpool(d, permissions=perms, monotonic_ns=_mono)

    def _native_hook(dk: str, *, expire: bool) -> None:
        clock["calls"], clock["expire_at"] = 0, (3 if expire else None)
        with monkeypatch.context() as mp:
            mp.setattr(_hook_adapter_bridge, "prepare_native_hook", lambda *_a, **_k: _native_prep(stream, dk))
            assert run_hook(native, outbox_dir=outbox, monotonic_ns=_mono, spool_factory=_factory) == 0

    k1, k2 = digest_bytes(b"r13-2-k1"), digest_bytes(b"r13-2-k2")
    _native_hook(k1, expire=False)
    spool = OutboxSpool(outbox, permissions=perms)
    assert _pending(spool, stream) == [("event", 1)]
    _native_hook(k2, expire=True)   # budget gone before K2 got a slot: its gap takes the next slot
    _native_hook(k1, expire=True)   # K1 already owns published slot 1: no gap
    assert _pending(spool, stream) == [("event", 1), ("capture_gap", 2)]

    # The slot check and the gap write happen under the same spool lock.
    held: list[bool] = []

    class _Probe(OutboxSpool):
        def enqueue_gap(self, gap: Any, *, deadline_ns: int | None = None) -> str:
            held.append(bool(self._thread_lock._is_owned()))  # type: ignore[attr-defined]
            return super().enqueue_gap(gap, deadline_ns=deadline_ns)

    def _deadline_in_sanitize(self: Any, *a: Any, **kw: Any) -> Any:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    outbox_p = trusted_tmp / "outbox-r13-2-atomic"
    with monkeypatch.context() as mp:
        mp.setattr(CapturePrivacyGate, "sanitize_event", _deadline_in_sanitize)
        assert run_hook(_raw_event("s-r13-2-p", 5), outbox_dir=outbox_p,
                        spool_factory=lambda d: _Probe(d, permissions=perms)) == 0
    assert held == [True]
    assert _pending(OutboxSpool(outbox_p, permissions=perms), "s-r13-2-p") == [("capture_gap", 5)]

    # A direct-only stream: the acknowledged and evicted event 2 still blocks a later fallback gap at 2.
    outbox_d, stream_d = trusted_tmp / "outbox-r13-2-direct", "s-r13-2-d"
    for seq in (1, 2):
        assert run_hook(_raw_event(stream_d, seq), outbox_dir=outbox_d,
                        spool_factory=lambda d: OutboxSpool(d, permissions=perms)) == 0
    spool_d = OutboxSpool(outbox_d, permissions=perms)
    assert spool_d.apply_ack(_ack(stream_d, committed=(2,))) == 1
    with monkeypatch.context() as mp:
        mp.setattr(CapturePrivacyGate, "sanitize_event", _deadline_in_sanitize)
        assert run_hook(_raw_event(stream_d, 2), outbox_dir=outbox_d,
                        spool_factory=lambda d: OutboxSpool(d, permissions=perms)) == 0
    assert _pending(spool_d, stream_d) == [("event", 1)]


def test_r13_3_lock_bootstrap_and_tail_repair_honor_cutoff(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R13-3: the lock-file bootstrap and the frame tail repair do not delete anything once the cutoff passed."""
    perms = os_adapters().permissions
    # (a) the cutoff passes while the lock file's stage is being secured: the stage waits for the next sweep.
    now = [0]
    outbox_a = trusted_tmp / "outbox-r13-3-lock"
    outbox_a.mkdir()
    perms.secure_directory(outbox_a)
    real_secure = perms.secure_file

    class _Perms:
        def __getattr__(self, name: str) -> Any:
            return getattr(perms, name)

        def secure_file(self, path: Path) -> None:
            real_secure(path)
            if ".spool.lock" in Path(path).name and Path(path).name != ".spool.lock":
                now[0] = 2_000

    spool_a = OutboxSpool(outbox_a, permissions=_Perms(), monotonic_ns=lambda: now[0])
    with pytest.raises(BrainError) as err_a:
        spool_a.enqueue_gap(_mk_gap("s-r13-3-a", 1), deadline_ns=1_000)
    assert err_a.value.code is ErrorCode.DEADLINE_EXCEEDED
    stages = [p.name for p in outbox_a.iterdir() if ".spool.lock" in p.name and p.name != ".spool.lock"]
    assert stages, list(outbox_a.iterdir())
    now[0] = 0
    OutboxSpool(outbox_a, permissions=perms).read_pending(limit=1)
    assert not [p for p in outbox_a.iterdir() if p.name in stages]

    # (b) a frame with a torn tail is repaired during an ACK; the cutoff passes right after parsing: no unlink.
    now_b = [0]
    outbox_b, stream_b = trusted_tmp / "outbox-r13-3-tail", "s-r13-3-b"
    spool_b = OutboxSpool(outbox_b, permissions=perms, monotonic_ns=lambda: now_b[0])
    spool_b.enqueue_event(_mk_event(stream_b, 1))
    sdir_b = _stream_dir(outbox_b, stream_b)
    frame = next(sdir_b.glob("*.frame"))
    with frame.open("ab") as fh:
        fh.write(b"torn-tail")
    planted = frame.with_name(frame.name + ".part")
    io_mod = sys.modules["superbrain.storage._outbox_io"]
    real_parse = io_mod.parse_verified_outbox_frame

    def _parse_then_expire(raw: bytes) -> Any:
        out = real_parse(raw)
        # staging that appears after the operation's sweep, right before the repair would reuse its name
        planted.write_bytes(b"staging")
        perms.secure_file(planted)
        now_b[0] = 2_000
        return out

    with monkeypatch.context() as mp:
        mp.setattr(io_mod, "parse_verified_outbox_frame", _parse_then_expire)
        with pytest.raises(BrainError) as err_b:
            spool_b.apply_ack(_ack(stream_b, committed=(1,)), deadline_ns=1_000)
        assert err_b.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert planted.read_bytes() == b"staging"  # neither deleted nor overwritten by the repair's own staging


def test_r13_4_sweep_removes_only_spool_owned_stages(trusted_tmp: Path) -> None:
    """R13-4: a sweep removes creation stages the spool itself names, never a foreign ``.init-`` directory."""
    perms = os_adapters().permissions
    outbox, stream = trusted_tmp / "outbox-r13-4", "s-r13-4"
    spool = OutboxSpool(outbox, permissions=perms)
    spool.enqueue_event(_mk_event(stream, 1))
    sdir = _stream_dir(outbox, stream)
    foreign = sdir / ".diagnostics.init-1234-5678-abcd"
    foreign.mkdir()
    perms.secure_directory(foreign)
    (foreign / "log.txt").write_text("in progress", encoding="utf-8")
    perms.secure_file(foreign / "log.txt")
    from superbrain.storage import _outbox_io

    owned = sdir / f".acks{getattr(_outbox_io, '_SPOOL_STAGE_MARKER', '.sbstage-')}1-2-dead"
    owned.mkdir()
    perms.secure_directory(owned)
    assert spool.total_bytes() > 0
    spool.read_pending(limit=1)
    assert (foreign / "log.txt").read_text(encoding="utf-8") == "in progress"
    assert not owned.exists()


def test_r13_5_capacity_refusal_on_missing_root_creates_nothing(trusted_tmp: Path) -> None:
    """R13-5: a request refused for capacity on a spool that does not exist yet leaves no root and no lock."""
    perms = os_adapters().permissions
    for name, op in (
        ("event", lambda s: s.enqueue_event(_mk_event("s-r13-5", 1))),
        ("gap", lambda s: s.enqueue_gap(_mk_gap("s-r13-5", 1))),
        ("hook", lambda s: _enqueue_hook(s, stream="s-r13-5", dk=digest_bytes(b"r13-5"))),
    ):
        root = trusted_tmp / f"outbox-r13-5-{name}"
        with pytest.raises(BrainError) as err:
            op(OutboxSpool(root, permissions=perms, max_bytes=1))
        assert err.value.code is ErrorCode.STORAGE_FULL, name
        assert not os.path.lexists(root), name
