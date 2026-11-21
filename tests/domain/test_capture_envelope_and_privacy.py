"""SP2-2 domain, privacy-gate, pure outbox rules, and hook_entry subprocess oracles."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import FilterPolicy


def _clean_hook_env() -> dict[str, str]:
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


def _base_event_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "event_id": "evt-0001",
        "producer_stream": "claude-hook-chk-a",
        "sequence": 1,
        "harness_id": "claude-code",
        "kind": "tool_post",
        "recorded_at": "2026-11-21T12:00:00Z",
        "payload": {"tool": "Read", "summary": "read README.md"},
        "session_ref": "sha256:" + ("a" * 64),
        "source_metadata": {"host_version": "2.1.325", "config_digest": "sha256:" + ("b" * 64)},
    }
    data.update(overrides)
    return data


def _base_gap_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "record_kind": "capture_gap",
        "gap_id": "gap-0001",
        "producer_stream": "claude-hook-chk-a",
        "sequence": 2,
        "reason": "hook_timeout",
        "recorded_at": "2026-11-21T12:00:05Z",
        "estimated_count": 1,
        "duration_ms": 2000,
    }
    data.update(overrides)
    return data


def test_capture_port_constants_and_record_round_trips() -> None:
    from superbrain.ports.capture import (
        CAPTURE_GAP_REASONS,
        DEFAULT_OUTBOX_MAX_BYTES,
        HOOK_HARD_CAP_NS,
        HOOK_TARGET_BUDGET_NS,
        MAX_CAPTURE_BATCH_EVENTS,
        OUTBOX_RECORD_EVENT,
        OUTBOX_RECORD_GAP,
        CaptureBatchAck,
        CaptureEventRecord,
        CaptureHealthSnapshot,
        OutboxEntry,
        ProducerCaptureGap,
    )

    assert DEFAULT_OUTBOX_MAX_BYTES == 104_857_600
    assert HOOK_TARGET_BUDGET_NS == 100_000_000
    assert HOOK_HARD_CAP_NS == 2_000_000_000
    assert MAX_CAPTURE_BATCH_EVENTS == 1024
    assert OUTBOX_RECORD_EVENT == "event"
    assert OUTBOX_RECORD_GAP == "capture_gap"
    assert "hook_timeout" in CAPTURE_GAP_REASONS

    ev = CaptureEventRecord(
        event_id="evt-rt-1",
        producer_stream="stream-1",
        sequence=1,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={"ok": True},
        session_ref="sha256:" + ("1" * 64),
        source_metadata={"host_version": "2.1.325"},
    )
    assert CaptureEventRecord.from_dict(ev.to_dict()) == ev

    gap = ProducerCaptureGap(
        gap_id="gap-rt-1",
        producer_stream="stream-1",
        sequence=2,
        reason="hook_timeout",
        recorded_at="2026-11-21T12:00:01Z",
        estimated_count=1,
        duration_ms=2000,
    )
    assert ProducerCaptureGap.from_dict(gap.to_dict()) == gap

    entry = OutboxEntry(
        record_kind=OUTBOX_RECORD_EVENT,
        producer_stream="stream-1",
        sequence=1,
        entry_id="evt-rt-1",
        payload_json='{"event_id":"evt-rt-1"}',
        payload_digest="sha256:" + ("2" * 64),
        byte_size=24,
    )
    assert entry.sequence == 1

    ack = CaptureBatchAck(
        producer_stream="stream-1",
        repo_id="repo-a",
        checkout_id="chk-a",
        committed_event_sequences=(1, 3),
        contiguous_event_acked_through=1,
        acked_producer_gap_sequences=(4,),
        accepted_count=2,
        deduped_count=1,
        policy_disabled=False,
    )
    assert CaptureBatchAck.from_dict(ack.to_dict()) == ack
    assert ack.allows_eviction(OUTBOX_RECORD_EVENT, 1) is True
    assert ack.allows_eviction(OUTBOX_RECORD_EVENT, 2) is False
    assert ack.allows_eviction(OUTBOX_RECORD_EVENT, 3) is True
    assert ack.allows_eviction(OUTBOX_RECORD_EVENT, 4) is False
    assert ack.allows_eviction(OUTBOX_RECORD_GAP, 4) is True
    assert ack.allows_eviction(OUTBOX_RECORD_GAP, 1) is False

    assert CaptureHealthSnapshot(total_events=5, open_gaps=0, closed_gaps=0, producer_gaps=0).has_gaps is False
    assert CaptureHealthSnapshot(total_events=5, open_gaps=1, closed_gaps=0, producer_gaps=0).has_gaps is True
    assert CaptureHealthSnapshot(total_events=5, open_gaps=0, closed_gaps=1, producer_gaps=0).has_gaps is True
    assert CaptureHealthSnapshot(total_events=5, open_gaps=0, closed_gaps=0, producer_gaps=1).has_gaps is True


def test_normalize_capture_record_valid_event_gap_and_invalid_rejections() -> None:
    from superbrain.domain.capture.envelope import normalize_capture_record
    from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap

    ev = normalize_capture_record(_base_event_dict())
    assert isinstance(ev, CaptureEventRecord)
    assert ev.sequence == 1 and ev.harness_id == "claude-code"

    ev_default_harness = normalize_capture_record(
        {k: v for k, v in _base_event_dict().items() if k != "harness_id"},
        default_harness_id="codex",
    )
    assert isinstance(ev_default_harness, CaptureEventRecord)
    assert ev_default_harness.harness_id == "codex"

    gap = normalize_capture_record(_base_gap_dict())
    assert isinstance(gap, ProducerCaptureGap)
    assert gap.reason == "hook_timeout" and gap.sequence == 2

    invalid_cases: list[Any] = [
        "not-a-dict",
        [],
        _base_event_dict(sequence=0),
        _base_event_dict(sequence=-3),
        _base_event_dict(sequence=True),
        _base_event_dict(recorded_at="not-a-timestamp"),
        _base_event_dict(event_id=""),
        _base_event_dict(producer_stream=""),
        _base_event_dict(payload={"x": float("nan")}),
        _base_event_dict(record_kind="unknown_kind"),
        _base_gap_dict(reason="invented_reason_xyz"),
        {k: v for k, v in _base_event_dict().items() if k != "kind"},
    ]
    for bad in invalid_cases:
        with pytest.raises(BrainError) as exc:
            normalize_capture_record(bad)
        assert exc.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "forbidden_key",
    ["source", "source_verification", "exposure_evidence", "session_id", "raw_session_id"],
)
def test_normalize_capture_record_rejects_client_supplied_authority_and_session_keys(forbidden_key: str) -> None:
    from superbrain.domain.capture.envelope import normalize_capture_record

    top_bad = _base_event_dict(**{forbidden_key: "forged-value"})
    with pytest.raises(BrainError) as exc_top:
        normalize_capture_record(top_bad)
    assert exc_top.value.code is ErrorCode.INVALID_INPUT

    nested_bad = _base_event_dict(payload={"nested": {forbidden_key: "forged-value"}})
    with pytest.raises(BrainError) as exc_nested:
        normalize_capture_record(nested_bad)
    assert exc_nested.value.code is ErrorCode.INVALID_INPUT

    meta_bad = _base_event_dict(source_metadata={forbidden_key: "forged-value"})
    with pytest.raises(BrainError) as exc_meta:
        normalize_capture_record(meta_bad)
    assert exc_meta.value.code is ErrorCode.INVALID_INPUT


def test_capture_privacy_gate_sanitizes_bait_and_fails_closed_without_secret_leaks() -> None:
    from superbrain.application.privacy import PrivacyFilter

    now_ns = 1_000_000_000

    from superbrain.domain.capture.envelope import normalize_capture_record
    from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

    def mono() -> int:
        return now_ns

    gate = CapturePrivacyGate(PrivacyFilter(monotonic_ns=mono), monotonic_ns=mono)

    raw_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----"
    raw_pat = "github_pat_" + ("A1b2C3d4" * 5)
    raw_sk = "sk-" + ("XyZ987654" * 4)
    raw_bearer = "Bearer " + ("toksecret" * 4)
    raw_pwd = "password=UltraSecretPassword!1234"
    raw_private = "<private>do-not-persist-private-tag-bait</private>"
    raw_path = "/home/alice/.ssh/id_rsa"
    raw_entropy = "K9mP3qR8vT2xW7zB4nJ6cL1fD5gH0yQ"
    raw_session = "raw-sess-bait-secret-7788"

    dirty_rec = normalize_capture_record(
        _base_event_dict(
            payload={
                "public": "keep-this-benign-label",
                "priv": f"before {raw_private} after",
                "pem": raw_pem,
                "nested_list": [raw_bearer, raw_pat, {"deep": raw_sk, "pwd": raw_pwd, "path": raw_path}],
                "password": "dropped-by-sensitive-key",
                "entropy": raw_entropy,
            }
        )
    )
    cleaned = gate.sanitize_event(
        dirty_rec,
        policy=FilterPolicy(),
        raw_session_id=raw_session,
        deadline_ns=now_ns + 5_000_000_000,
    )
    serialized = json.dumps(cleaned.to_dict(), sort_keys=True)
    assert "keep-this-benign-label" in serialized
    for bait in (
        "do-not-persist-private-tag-bait",
        "MIIEvQIBADAN",
        raw_pat,
        raw_sk,
        "toksecret" * 4,
        "UltraSecretPassword!1234",
        "dropped-by-sensitive-key",
        raw_path,
        raw_entropy,
    ):
        assert bait not in serialized, f"bait secret leaked after CapturePrivacyGate: {bait!r}"

    # Unclosed <private> tag -> fail closed with INVALID_INPUT and zero secret leak in error message
    ambiguous_secret = "UNCLOSED_SECRET_BAIT_9911"
    ambiguous = normalize_capture_record(_base_event_dict(payload={"msg": f"<private>{ambiguous_secret}"}))
    with pytest.raises(BrainError) as exc_amb:
        gate.sanitize_event(ambiguous, policy=FilterPolicy(), raw_session_id=raw_session)
    assert exc_amb.value.code is ErrorCode.INVALID_INPUT
    assert ambiguous_secret not in str(exc_amb.value)

    # Raw session_id inside nested value or key or event_id -> refused without echoing raw_session
    for sess_raw in (
        _base_event_dict(payload={"note": f"prefix {raw_session} suffix"}),
        _base_event_dict(payload={"nested": [{raw_session: "val"}]}),
        _base_event_dict(event_id=f"ev-{raw_session}"),
    ):
        sess_rec = normalize_capture_record(sess_raw)
        with pytest.raises(BrainError) as exc_sess:
            gate.sanitize_event(sess_rec, policy=FilterPolicy(), raw_session_id=raw_session)
        assert exc_sess.value.code is ErrorCode.INVALID_INPUT
        assert raw_session not in str(exc_sess.value)

    # Expired deadline -> DEADLINE_EXCEEDED without leaking text
    expired_rec = normalize_capture_record(_base_event_dict(payload={"msg": "EXPIRED_SECRET_TEXT_42"}))
    with pytest.raises(BrainError) as exc_dl:
        gate.sanitize_event(expired_rec, policy=FilterPolicy(), deadline_ns=now_ns)
    assert exc_dl.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert "EXPIRED_SECRET_TEXT_42" not in str(exc_dl.value)


def test_outbox_rules_contiguous_watermark_separated_eviction_and_batch_partition() -> None:
    from superbrain.domain.capture.outbox_rules import (
        compute_contiguous_event_acked_through,
        partition_pending_for_batch,
        should_evict_outbox_entry,
    )
    from superbrain.ports.capture import (
        OUTBOX_RECORD_EVENT,
        OUTBOX_RECORD_GAP,
        CaptureBatchAck,
        OutboxEntry,
    )

    assert compute_contiguous_event_acked_through(()) == 0
    assert compute_contiguous_event_acked_through((1, 3)) == 1
    assert compute_contiguous_event_acked_through((2, 3)) == 0
    assert compute_contiguous_event_acked_through((3, 1, 2)) == 3
    assert compute_contiguous_event_acked_through((5, 2, 1, 3)) == 3

    ack_hole = CaptureBatchAck(
        producer_stream="s1",
        repo_id="r1",
        checkout_id="c1",
        committed_event_sequences=(1, 3),
        contiguous_event_acked_through=1,
        acked_producer_gap_sequences=(2, 4),
        accepted_count=2,
        deduped_count=0,
    )
    # Closed/producer gap at seq 2 or 4 must NEVER evict an Event entry at seq 2 or 4.
    assert should_evict_outbox_entry(OUTBOX_RECORD_EVENT, 1, ack_hole) is True
    assert should_evict_outbox_entry(OUTBOX_RECORD_EVENT, 2, ack_hole) is False
    assert should_evict_outbox_entry(OUTBOX_RECORD_EVENT, 3, ack_hole) is True
    assert should_evict_outbox_entry(OUTBOX_RECORD_EVENT, 4, ack_hole) is False
    # Producer gap only evicts via acked_producer_gap_sequences.
    assert should_evict_outbox_entry(OUTBOX_RECORD_GAP, 1, ack_hole) is False
    assert should_evict_outbox_entry(OUTBOX_RECORD_GAP, 2, ack_hole) is True
    assert should_evict_outbox_entry(OUTBOX_RECORD_GAP, 4, ack_hole) is True

    entries = [
        OutboxEntry(OUTBOX_RECORD_EVENT, "s1", seq, f"id-{seq}", "{}", "sha256:" + ("3" * 64), 2)
        for seq in range(1, 6)
    ]
    batches = partition_pending_for_batch(entries, max_events=2)
    assert [len(batch) for batch in batches] == [2, 2, 1]
    assert [e.sequence for b in batches for e in b] == [1, 2, 3, 4, 5]


def test_hook_entry_subprocess_enqueues_sanitized_stays_within_budget_and_imports_minimal(
    trusted_tmp: Path,
) -> None:
    outbox_dir = trusted_tmp / "outbox"
    log_path = trusted_tmp / "hook.log"
    secret = "github_pat_" + ("Z9y8X7w6" * 5)
    payload = _base_event_dict(
        payload={"note": "normal hook capture", "token": secret, "ok_text": "kept"},
    )
    raw_bytes = json.dumps(payload).encode()

    t0_ns = time.monotonic_ns()
    res = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "superbrain.composition.hook_entry",
            "--outbox",
            str(outbox_dir),
            "--log",
            str(log_path),
        ],
        input=raw_bytes,
        env=_clean_hook_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    cold_ns = time.monotonic_ns() - t0_ns
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    assert cold_ns < 2_000_000_000, f"cold hook subprocess exceeded 2s hard cap: {cold_ns} ns"

    from superbrain.storage.outbox import OutboxSpool

    spool = OutboxSpool(outbox_dir)
    pending = spool.read_pending(limit=10)
    assert len(pending) == 1
    assert secret not in pending[0].payload_json
    assert "kept" in pending[0].payload_json

    # Negative subprocess check: raw session_id rejection exits 0, writes 0 bytes to outbox, logs 0 raw bytes.
    raw_session = "raw-sess-subproc-8899"
    sess_outbox = trusted_tmp / "outbox-raw-sess"
    sess_log = trusted_tmp / "hook-raw-sess.log"
    sess_input = json.dumps(
        _base_event_dict(
            event_id="evt-sess-neg-1",
            session_id=raw_session,
            payload={"note": f"prefix {raw_session} suffix"},
        )
    ).encode()
    res_sess = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "superbrain.composition.hook_entry",
            "--outbox",
            str(sess_outbox),
            "--log",
            str(sess_log),
        ],
        input=sess_input,
        env=_clean_hook_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res_sess.returncode == 0
    assert raw_session.encode() not in res_sess.stdout + res_sess.stderr
    if sess_outbox.exists():
        assert OutboxSpool(sess_outbox).read_pending(limit=10) == []
        assert sum(p.stat().st_size for p in sess_outbox.rglob("*") if p.is_file()) == 0
    assert sess_log.is_file()
    sess_log_text = sess_log.read_text(encoding="utf-8")
    assert "invalid_input" in sess_log_text
    assert raw_session not in sess_log_text

    # Isolated warm check in python -I: 0 sqlite3/socket/faults imported AND warm run_hook < 100 ms.
    probe_script = (
        "import json, sys, time; from pathlib import Path; "
        "from superbrain.composition.hook_entry import run_hook; "
        "from superbrain.ports.capture import HOOK_TARGET_BUDGET_NS; "
        "raw = json.dumps({'event_id':'warm-1','producer_stream':'s-warm','sequence':1,"
        "'harness_id':'claude-code','kind':'tool_post','recorded_at':'2026-11-21T12:00:00Z',"
        "'payload':{'ok':'warm'}}).encode(); "
        "outbox = Path(sys.argv[1]); "
        "run_hook(raw, outbox_dir=outbox); "
        "raw2 = json.dumps({'event_id':'warm-2','producer_stream':'s-warm','sequence':2,"
        "'harness_id':'claude-code','kind':'tool_post','recorded_at':'2026-11-21T12:00:01Z',"
        "'payload':{'ok':'warm2'}}).encode(); "
        "t0 = time.monotonic_ns(); "
        "rc = run_hook(raw2, outbox_dir=outbox); "
        "elapsed = time.monotonic_ns() - t0; "
        "forbidden = [m for m in ('sqlite3', 'socket', 'superbrain.core.faults') if m in sys.modules]; "
        "print(json.dumps({"
        "'rc': rc, 'elapsed_ns': elapsed, 'budget_ns': HOOK_TARGET_BUDGET_NS, 'forbidden': forbidden"
        "}))"
    )
    warm_outbox = trusted_tmp / "warm-outbox"
    probe = subprocess.run(
        [sys.executable, "-I", "-c", probe_script, str(warm_outbox)],
        env=_clean_hook_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=15.0,
    )
    assert probe.returncode == 0, probe.stderr
    info = json.loads(probe.stdout)
    assert info["rc"] == 0
    assert info["forbidden"] == [], f"forbidden modules imported by hook_entry: {info['forbidden']}"
    assert info["elapsed_ns"] < info["budget_ns"], info


def test_hook_entry_privacy_rejection_exits_zero_with_zero_leaks_and_static_log(trusted_tmp: Path) -> None:
    outbox_dir = trusted_tmp / "outbox-rej"
    log_path = trusted_tmp / "hook-rej.log"
    secret_bait = "UNCLOSED_SECRET_NEVER_WRITE_999"
    bad_payload = json.dumps(
        _base_event_dict(event_id="evt-rej-1", payload={"broken": f"<private>{secret_bait}"})
    ).encode()

    res = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "superbrain.composition.hook_entry",
            "--outbox",
            str(outbox_dir),
            "--log",
            str(log_path),
        ],
        input=bad_payload,
        env=_clean_hook_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res.returncode == 0
    assert secret_bait.encode() not in res.stdout + res.stderr

    from superbrain.storage.outbox import OutboxSpool

    if outbox_dir.exists():
        assert OutboxSpool(outbox_dir).read_pending(limit=10) == []
        for fpath in outbox_dir.rglob("*"):
            if fpath.is_file():
                assert secret_bait.encode() not in fpath.read_bytes()

    assert log_path.is_file()
    log_text = log_path.read_text(encoding="utf-8")
    assert secret_bait not in log_text
    assert "invalid_input" in log_text


def test_hook_entry_timeout_writes_hook_timeout_gap_and_exits_zero(trusted_tmp: Path) -> None:
    from superbrain.composition.hook_entry import run_hook
    from superbrain.ports.capture import (
        HOOK_HARD_CAP_NS,
        OUTBOX_RECORD_GAP,
        CaptureEventRecord,
        ProducerCaptureGap,
    )
    from superbrain.storage.outbox import OutboxSpool

    outbox_dir = trusted_tmp / "outbox-timeout"
    log_path = trusted_tmp / "hook-timeout.log"
    raw_secret_note = "TIMEOUT_RAW_PAYLOAD_MUST_NOT_LEAK"
    raw_bytes = json.dumps(
        _base_event_dict(event_id="evt-to-1", payload={"note": raw_secret_note})
    ).encode()

    now = [10_000_000_000]

    def fake_mono() -> int:
        return now[0]

    class _StallingSpool(OutboxSpool):
        def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
            # Simulate stalling disk I/O past HOOK_HARD_CAP_NS (no real sleep in gate).
            now[0] += HOOK_HARD_CAP_NS + 50_000_000
            return str(super().enqueue_event(record, deadline_ns=deadline_ns))

    def _factory(path: Path) -> OutboxSpool:
        return _StallingSpool(path, monotonic_ns=fake_mono)

    rc = run_hook(
        raw_bytes,
        outbox_dir=outbox_dir,
        log_path=log_path,
        monotonic_ns=fake_mono,
        spool_factory=_factory,
    )
    assert rc == 0

    reopened = OutboxSpool(outbox_dir)
    entries = reopened.read_pending(limit=10)
    assert len(entries) == 1
    assert entries[0].record_kind == OUTBOX_RECORD_GAP
    gap_obj = json.loads(entries[0].payload_json)
    assert gap_obj["reason"] == "hook_timeout"
    assert gap_obj["producer_stream"] == "claude-hook-chk-a"
    assert gap_obj["sequence"] == 1
    assert raw_secret_note not in entries[0].payload_json

    assert log_path.is_file()
    log_text = log_path.read_text(encoding="utf-8")
    assert raw_secret_note not in log_text
    assert "deadline_exceeded" in log_text

    # Unwritable outbox during timeout still fails soft with rc == 0 (never blocks harness).
    class _BrokenSpool(OutboxSpool):
        def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
            now[0] += HOOK_HARD_CAP_NS + 50_000_000
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
            raise BrainError(ErrorCode.IO_ERROR, "disk unwritable")

    def broken_factory(p: Path) -> OutboxSpool:
        return _BrokenSpool(p, monotonic_ns=fake_mono)
    rc_broken = run_hook(
        raw_bytes,
        outbox_dir=trusted_tmp / "outbox-broken",
        log_path=log_path,
        monotonic_ns=fake_mono,
        spool_factory=broken_factory,
    )
    assert rc_broken == 0
