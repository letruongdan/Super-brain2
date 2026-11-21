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

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    spool = OutboxSpool(outbox_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
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
        assert OutboxSpool(
            sess_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK
        ).read_pending(limit=10) == []
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

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.storage.outbox import OutboxSpool

    if outbox_dir.exists():
        assert OutboxSpool(
            outbox_dir, permissions=os_adapters().permissions, file_lock=OUTBOX_FILE_LOCK
        ).read_pending(limit=10) == []
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

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK

    os_ = os_adapters()

    class _StallingSpool(OutboxSpool):
        def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
            # Simulate I/O stalling past work_deadline_ns inside HOOK_HARD_CAP_NS (no real sleep).
            now[0] += HOOK_HARD_CAP_NS - 40_000_000
            return str(super().enqueue_event(record, deadline_ns=deadline_ns))

    def _factory(path: Path) -> OutboxSpool:
        return _StallingSpool(
            path, monotonic_ns=fake_mono, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK
        )

    rc = run_hook(
        raw_bytes,
        outbox_dir=outbox_dir,
        log_path=log_path,
        monotonic_ns=fake_mono,
        spool_factory=_factory,
    )
    assert rc == 0

    reopened = OutboxSpool(outbox_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
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
            now[0] += HOOK_HARD_CAP_NS - 40_000_000
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
            raise BrainError(ErrorCode.IO_ERROR, "disk unwritable")

    def broken_factory(p: Path) -> OutboxSpool:
        return _BrokenSpool(p, monotonic_ns=fake_mono, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    rc_broken = run_hook(
        raw_bytes,
        outbox_dir=trusted_tmp / "outbox-broken",
        log_path=log_path,
        monotonic_ns=fake_mono,
        spool_factory=broken_factory,
    )
    assert rc_broken == 0


def test_capture_privacy_gate_preserves_payload_and_metadata_with_manual_submission_disabled() -> None:
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.domain.capture.privacy_gate import CapturePrivacyGate
    from superbrain.ports.capture import CaptureEventRecord

    gate = CapturePrivacyGate(PrivacyFilter())
    secret_pat = "github_pat_" + ("Z9y8X7w6" * 5)
    raw = CaptureEventRecord(
        event_id="evt-caponly-unit-1",
        producer_stream="claude-hook-chk-a",
        sequence=1,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={
            "tool": "Read",
            "summary": "read <private>SECRET_TAG_F1</private> docs",
            "path": "README.md",
            "token": secret_pat,
        },
        session_ref="sha256:" + ("a" * 64),
        source_metadata={"host_version": "2.1.325", "config_digest": "sha256:" + ("c" * 64)},
    )
    sanitized = gate.sanitize_event(raw, policy=FilterPolicy(manual_submission=False))
    serialized = json.dumps(sanitized.to_dict(), sort_keys=True)
    assert sanitized.payload["tool"] == "Read"
    assert sanitized.payload["path"] == "README.md"
    assert "read" in str(sanitized.payload["summary"])
    assert "SECRET_TAG_F1" not in serialized
    assert secret_pat not in serialized
    assert dict(sanitized.source_metadata) == {
        "host_version": "2.1.325",
        "config_digest": "sha256:" + ("c" * 64),
    }


def test_hook_entry_secures_outbox_and_log_even_under_loose_parent_acls(trusted_tmp: Path) -> None:
    from superbrain.adapters.os import os_adapters
    from tests.support.winacl import grant

    os_ = os_adapters()
    loose_parent = trusted_tmp / "loose-parent-f3"
    loose_parent.mkdir()
    if sys.platform == "win32":
        grant(loose_parent, "S-1-1-0", 0x120089, flags=0x3)
    else:
        os.chmod(loose_parent, 0o755)
    assert os_.permissions.problems(loose_parent), "precondition: loose parent must have insecure ACL/mode"

    outbox_dir = loose_parent / "outbox"
    log_path = loose_parent / "hook.log"
    hook_cmd = (
        "import os, sys; "
        "os.umask(0o022) if os.name == 'posix' else None; "
        "from superbrain.composition.hook_entry import main; "
        "sys.exit(main(sys.argv[1:]))"
    )
    ev_bytes = json.dumps(_base_event_dict(event_id="evt-acl-f3")).encode()
    res_ok = subprocess.run(
        [sys.executable, "-I", "-c", hook_cmd, "--outbox", str(outbox_dir), "--log", str(log_path)],
        input=ev_bytes,
        env=_clean_hook_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res_ok.returncode == 0, res_ok.stderr.decode(errors="replace")

    res_log = subprocess.run(
        [sys.executable, "-I", "-c", hook_cmd, "--outbox", str(outbox_dir), "--log", str(log_path)],
        input=b"not valid json",
        env=_clean_hook_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert res_log.returncode == 0, res_log.stderr.decode(errors="replace")
    assert log_path.is_file()
    assert os_.permissions.problems(outbox_dir) == []
    assert os_.permissions.object_problems(log_path) == []


def test_hook_entry_bounded_under_spool_lock_contention_and_refuses_gap_raw_session_leak(
    trusted_tmp: Path,
) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.composition.hook_entry import run_hook
    from superbrain.ports.capture import CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    outbox_dir = trusted_tmp / "contended-outbox"
    spool = OutboxSpool(outbox_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    spool.enqueue_event(
        CaptureEventRecord(
            event_id="evt-pre-lock-1",
            producer_stream="s-lock-test",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-21T12:00:00Z",
            payload={"ok": "init"},
        )
    )
    lock_file = outbox_dir / ".spool.lock"
    assert lock_file.is_file()

    holder_code = (
        "import os, sys, time; "
        "from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK; "
        "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600); "
        "locked = OUTBOX_FILE_LOCK.try_lock_fd(fd); "
        "assert locked; "
        "sys.stdout.write('LOCKED\\n'); sys.stdout.flush(); "
        "time.sleep(2.5); "
        "OUTBOX_FILE_LOCK.unlock_fd(fd); os.close(fd)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", holder_code, str(lock_file)],
        env=_clean_hook_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        ready_line = proc.stdout.readline().strip()
        assert ready_line == "LOCKED", proc.stderr.read() if proc.stderr is not None else ""

        log_path = trusted_tmp / "contended-hook.log"
        raw_bytes = json.dumps(
            _base_event_dict(event_id="evt-locked-2", producer_stream="s-lock-test", sequence=2)
        ).encode()
        t0 = time.monotonic()
        rc = run_hook(raw_bytes, outbox_dir=outbox_dir, log_path=log_path, cap_ns=200_000_000)
        elapsed = time.monotonic() - t0
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5.0)

    assert rc == 0
    assert elapsed < 1.0, f"run_hook exceeded bounded cap under lock contention: {elapsed:.3f}s"
    assert log_path.is_file()
    assert "deadline_exceeded" in log_path.read_text(encoding="utf-8")

    # ProducerCaptureGap refusing raw_session_id leaks in gap_id and producer_stream
    raw_sess = "raw-sess-gap-bait-4421"
    for idx, gap_override in enumerate(
        (
            {"gap_id": f"gap-{raw_sess}-0", "producer_stream": "gap-clean-stream"},
            {"gap_id": "gap-clean-1", "producer_stream": f"stream-{raw_sess}-1"},
        )
    ):
        g_outbox = trusted_tmp / f"gap-neg-outbox-{idx}"
        g_log = trusted_tmp / f"gap-neg-{idx}.log"
        g_bytes = json.dumps(_base_gap_dict(**gap_override)).encode()
        g_rc = run_hook(g_bytes, outbox_dir=g_outbox, log_path=g_log, raw_session_id=raw_sess)
        assert g_rc == 0
        if g_outbox.exists():
            assert (
                OutboxSpool(g_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(limit=10)
                == []
            )
            for p in g_outbox.rglob("*"):
                if p.is_file():
                    assert raw_sess.encode() not in p.read_bytes()
        assert g_log.is_file()
        g_log_text = g_log.read_text(encoding="utf-8")
        assert "invalid_input" in g_log_text
        assert raw_sess not in g_log_text

    # Clean ProducerCaptureGap with raw_session_id passed still succeeds.
    good_outbox = trusted_tmp / "gap-pos-outbox"
    good_bytes = json.dumps(_base_gap_dict(gap_id="gap-clean-ok", producer_stream="gap-clean-stream")).encode()
    assert run_hook(good_bytes, outbox_dir=good_outbox, raw_session_id=raw_sess) == 0
    assert (
        len(
            OutboxSpool(good_outbox, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(limit=10)
        )
        == 1
    )


def _sized_event_dict(seq: int, target_bytes: int, *, stream: str = "s-f7-size") -> dict[str, Any]:
    from superbrain.core.canonical import canonical_json

    chunk = 50_000
    payload: dict[str, Any] = {}
    i = 0
    while True:
        sample = _base_event_dict(event_id=f"ev-sz-{seq}", producer_stream=stream, sequence=seq, payload=payload)
        cur = len(canonical_json(sample))
        rem = target_bytes - cur
        if rem <= 12:
            break
        take = min(chunk, max(1, rem - 10))
        payload[f"k{i:03d}"] = "x" * take
        i += 1
    return _base_event_dict(event_id=f"ev-sz-{seq}", producer_stream=stream, sequence=seq, payload=payload)


def test_outbox_wire_batch_limit_oversized_record_and_int64_sequence_bounds(trusted_tmp: Path) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.cli_api._loopback_wire import encode_capture_batch
    from superbrain.core._json_parse import MAX_WIRE_BODY_BYTES
    from superbrain.core.canonical import canonical_json
    from superbrain.core.kernel import CaptureBatchCommand
    from superbrain.domain.capture.envelope import normalize_capture_record
    from superbrain.domain.capture.outbox_rules import DEFAULT_MAX_WIRE_BATCH_BYTES, partition_pending_for_batch
    from superbrain.ports.capture import CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    assert DEFAULT_MAX_WIRE_BATCH_BYTES <= MAX_WIRE_BODY_BYTES - 4096

    # 1_046_000 B single record rejected cleanly; 950_000 B succeeds and encodes within MAX_WIRE_BODY_BYTES.
    big_dict = _sized_event_dict(1, 1_046_000)
    big_bytes = len(canonical_json(big_dict))
    assert 1_045_000 <= big_bytes < MAX_WIRE_BODY_BYTES

    with pytest.raises(BrainError) as exc_big:
        rec_big = normalize_capture_record(big_dict)
        assert isinstance(rec_big, CaptureEventRecord)
        big_spool = OutboxSpool(trusted_tmp / "big-spool", permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
        big_spool.enqueue_event(rec_big)
        for batch in partition_pending_for_batch(big_spool.read_pending(limit=10)):
            encode_capture_batch(
                CaptureBatchCommand(
                    "s-f7-size", "r1", "c1", tuple(json.loads(e.payload_json) for e in batch), "tok"
                )
            )
    assert exc_big.value.code is ErrorCode.INVALID_INPUT

    ok_dict = _sized_event_dict(2, 950_000)
    rec_ok = normalize_capture_record(ok_dict)
    assert isinstance(rec_ok, CaptureEventRecord)
    ok_spool = OutboxSpool(trusted_tmp / "ok-spool", permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    ok_spool.enqueue_event(rec_ok)
    ok_batches = partition_pending_for_batch(ok_spool.read_pending(limit=10))
    assert len(ok_batches) == 1
    encoded_ok = encode_capture_batch(
        CaptureBatchCommand(
            "s-f7-size", "r1", "c1", tuple(json.loads(e.payload_json) for e in ok_batches[0]), "tok"
        )
    )
    assert len(encoded_ok) <= MAX_WIRE_BODY_BYTES

    # 7 x 200 KB entries split cleanly across >= 2 batches using default partition_pending_for_batch args.
    chunk_spool = OutboxSpool(trusted_tmp / "chunk-spool", permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    for seq in range(1, 8):
        rec = normalize_capture_record(_sized_event_dict(seq, 200_000, stream="s-f7-200k"))
        assert isinstance(rec, CaptureEventRecord)
        chunk_spool.enqueue_event(rec)
    batches = partition_pending_for_batch(chunk_spool.read_pending(limit=20, producer_stream="s-f7-200k"))
    assert len(batches) >= 2
    seen_seqs: list[int] = []
    for batch in batches:
        assert sum(e.byte_size for e in batch) <= DEFAULT_MAX_WIRE_BATCH_BYTES
        enc = encode_capture_batch(
            CaptureBatchCommand(
                "s-f7-200k", "r1", "c1", tuple(json.loads(e.payload_json) for e in batch), "tok"
            )
        )
        assert len(enc) <= MAX_WIRE_BODY_BYTES
        seen_seqs.extend(e.sequence for e in batch)
    assert seen_seqs == [1, 2, 3, 4, 5, 6, 7]

    # Signed int64 sequence boundary enforcement (F6 domain boundary)
    max_i64 = (2**63) - 1
    ok_i64 = normalize_capture_record(_base_event_dict(sequence=max_i64))
    assert isinstance(ok_i64, CaptureEventRecord) and ok_i64.sequence == max_i64
    for bad_seq_raw in (
        _base_event_dict(sequence=2**63),
        _base_event_dict(sequence=10**20),
        _base_gap_dict(sequence=10**20),
    ):
        with pytest.raises(BrainError) as exc_seq:
            normalize_capture_record(bad_seq_raw)
        assert exc_seq.value.code is ErrorCode.INVALID_INPUT


def _seed_outbox_frames(
    spool_dir: Path,
    perms: Any,
    counts_by_stream: list[tuple[str, int]],
) -> None:
    import hashlib
    import zlib

    from superbrain.core.canonical import canonical_json, digest_bytes
    from superbrain.ports.capture import OUTBOX_RECORD_EVENT, CaptureEventRecord

    streams_root = spool_dir / "streams"
    streams_root.mkdir(parents=True, exist_ok=True)
    perms.secure_directory(spool_dir)
    perms.secure_directory(streams_root)

    order = 0
    first_frame: Path | None = None
    for stream, count in counts_by_stream:
        sdir = streams_root / hashlib.sha256(stream.encode("utf-8")).hexdigest()[:24]
        sdir.mkdir(exist_ok=True)
        perms.secure_directory(sdir)
        for seq in range(1, count + 1):
            order += 1
            rec = CaptureEventRecord(
                event_id=f"ev-{stream}-{seq}",
                producer_stream=stream,
                sequence=seq,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at="2026-11-21T12:00:00Z",
                payload={"tool": "Read", "seq": seq},
            )
            payload_bytes = canonical_json(rec.to_dict())
            payload_json = payload_bytes.decode("utf-8")
            payload_digest = digest_bytes(payload_bytes)
            core = {
                "byte_size": len(payload_bytes),
                "entry_id": rec.event_id,
                "payload_digest": payload_digest,
                "payload_json": payload_json,
                "producer_stream": stream,
                "record_kind": OUTBOX_RECORD_EVENT,
                "sequence": seq,
            }
            core["frame_crc32"] = f"{zlib.crc32(canonical_json(core)) & 0xFFFFFFFF:08x}"
            frame_bytes = canonical_json(core) + b"\n"
            fpath = sdir / f"{order:016d}_{OUTBOX_RECORD_EVENT}_{seq:020d}.frame"
            fpath.write_bytes(frame_bytes)
            if sys.platform != "win32":
                os.chmod(fpath, 0o600)
            elif first_frame is None:
                first_frame = fpath
    if first_frame is not None:
        assert perms.object_problems(first_frame) == []


def test_hook_entry_backlog_stays_within_budget_and_preserves_idempotency(trusted_tmp: Path) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.composition.hook_entry import run_hook
    from superbrain.ports.capture import HOOK_HARD_CAP_NS, CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()

    # Stage 1: 500 frames across 2 streams
    dir_500 = trusted_tmp / "backlog-500"
    log_500 = trusted_tmp / "backlog-500.log"
    _seed_outbox_frames(dir_500, os_.permissions, [("stream-r1-500-a", 250), ("stream-r1-500-b", 250)])
    ev_251_bytes = json.dumps(
        _base_event_dict(
            event_id="ev-stream-r1-500-a-251",
            producer_stream="stream-r1-500-a",
            sequence=251,
            payload={"tool": "Read", "seq": 251},
        )
    ).encode()
    t0_500 = time.monotonic()
    rc_500 = run_hook(ev_251_bytes, outbox_dir=dir_500, log_path=log_500, cap_ns=HOOK_HARD_CAP_NS)
    elapsed_500 = time.monotonic() - t0_500
    assert rc_500 == 0
    assert elapsed_500 < 0.5, f"run_hook on 500-frame backlog took {elapsed_500:.3f}s"
    if log_500.exists():
        assert "deadline_exceeded" not in log_500.read_text(encoding="utf-8")

    # Stage 2: 2,000 frames across 2 streams -> seq 1001 on stream-a (2,001st frame overall)
    dir_2k = trusted_tmp / "backlog-2000"
    log_2k = trusted_tmp / "backlog-2000.log"
    _seed_outbox_frames(dir_2k, os_.permissions, [("stream-r1-a", 1000), ("stream-r1-b", 1000)])
    ev_next_bytes = json.dumps(
        _base_event_dict(
            event_id="ev-stream-r1-a-1001",
            producer_stream="stream-r1-a",
            sequence=1001,
            payload={"tool": "Read", "seq": 1001},
        )
    ).encode()
    t0_2k = time.monotonic()
    rc_2k = run_hook(ev_next_bytes, outbox_dir=dir_2k, log_path=log_2k, cap_ns=HOOK_HARD_CAP_NS)
    elapsed_2k = time.monotonic() - t0_2k
    assert rc_2k == 0
    assert elapsed_2k < 0.5, f"run_hook on 2000-frame backlog took {elapsed_2k:.3f}s"
    if log_2k.exists():
        assert "deadline_exceeded" not in log_2k.read_text(encoding="utf-8")

    spool_2k = OutboxSpool(dir_2k, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
    pending_a = spool_2k.read_pending(limit=1024, producer_stream="stream-r1-a")
    assert len(pending_a) == 1001
    assert any(e.sequence == 1001 and e.entry_id == "ev-stream-r1-a-1001" for e in pending_a)

    # Duplicate & conflicting sequence detection must still hold under 2,000+ frames.
    dup_rec = CaptureEventRecord(
        event_id="ev-stream-r1-a-1000",
        producer_stream="stream-r1-a",
        sequence=1000,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={"tool": "Read", "seq": 1000},
    )
    assert spool_2k.enqueue_event(dup_rec) == "ev-stream-r1-a-1000"

    conflict_rec = CaptureEventRecord(
        event_id="ev-stream-r1-a-1000",
        producer_stream="stream-r1-a",
        sequence=1000,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:00Z",
        payload={"tool": "Write", "seq": 1000, "mutated": True},
    )
    with pytest.raises(BrainError) as exc_conf:
        spool_2k.enqueue_event(conflict_rec)
    assert exc_conf.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

    conflict_bytes = json.dumps(
        _base_event_dict(
            event_id="ev-stream-r1-a-1000",
            producer_stream="stream-r1-a",
            sequence=1000,
            payload={"tool": "Write", "mutated": True},
        )
    ).encode()
    assert run_hook(conflict_bytes, outbox_dir=dir_2k, log_path=log_2k, cap_ns=HOOK_HARD_CAP_NS) == 0
    assert "idempotency_conflict" in log_2k.read_text(encoding="utf-8")


def test_hook_entry_clamps_fallback_gap_deadline_and_outbox_propagates_deadline(trusted_tmp: Path) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.composition.hook_entry import run_hook
    from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()

    # Part A: Fallback gap_deadline_ns in run_hook must be clamped to <= start_ns + cap_ns.
    def _run_clamp_case(remaining_before_gap_ns: int) -> None:
        start_ns = 1_000_000_000
        cap_ns = 100_000_000
        hard_ceiling_ns = start_ns + cap_ns
        now = [start_ns]
        observed_gap_deadlines: list[int | None] = []
        hook_dir = trusted_tmp / f"clamp-dir-{remaining_before_gap_ns}"
        hook_log = trusted_tmp / f"clamp-{remaining_before_gap_ns}.log"

        def _fake_mono() -> int:
            return now[0]

        class _ClampProbeSpool(OutboxSpool):
            def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
                now[0] = hard_ceiling_ns - remaining_before_gap_ns
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

            def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
                observed_gap_deadlines.append(deadline_ns)
                if int(self._monotonic_ns()) >= (deadline_ns or 0):
                    raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
                return gap.gap_id

        def _clamp_factory(path: Path) -> OutboxSpool:
            return _ClampProbeSpool(
                path, monotonic_ns=_fake_mono, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK
            )

        raw_ev = json.dumps(_base_event_dict(event_id="evt-clamp-1", sequence=1)).encode()
        rc = run_hook(
            raw_ev,
            outbox_dir=hook_dir,
            log_path=hook_log,
            monotonic_ns=_fake_mono,
            spool_factory=_clamp_factory,
            cap_ns=cap_ns,
        )
        assert rc == 0
        assert hook_log.is_file() and "deadline_exceeded" in hook_log.read_text(encoding="utf-8")
        if remaining_before_gap_ns > 0:
            assert observed_gap_deadlines, "expected bounded fallback enqueue_gap when budget remains"
        for g_deadline in observed_gap_deadlines:
            assert g_deadline is not None
            assert g_deadline <= hard_ceiling_ns, (
                f"fallback gap deadline {g_deadline} overshot hard cap {hard_ceiling_ns}"
            )

    for rem_ns in (3_000_000, -5_000_000):
        _run_clamp_case(rem_ns)

    # Part B: OutboxSpool.enqueue_event propagates deadline_ns into scan/permission/pre-commit work.
    dl_dir = trusted_tmp / "deadline-scan-dir"
    _seed_outbox_frames(dl_dir, os_.permissions, [("stream-dl", 10)])
    scan_now = [0]

    class _SlowPerms:
        def secure_directory(self, path: Path) -> None:
            os_.permissions.secure_directory(path)

        def secure_file(self, path: Path) -> None:
            scan_now[0] += 40_000_000
            os_.permissions.secure_file(path)

        def problems(self, path: Path) -> Any:
            scan_now[0] += 40_000_000
            return os_.permissions.problems(path)

        def object_problems(self, path: Path) -> Any:
            scan_now[0] += 40_000_000
            return os_.permissions.object_problems(path)

    dl_spool = OutboxSpool(
        dl_dir,
        monotonic_ns=lambda: scan_now[0],
        permissions=_SlowPerms(),
        file_lock=OUTBOX_FILE_LOCK,
    )
    deadline_start = scan_now[0]
    ev11 = CaptureEventRecord(
        event_id="ev-dl-11",
        producer_stream="stream-dl",
        sequence=11,
        harness_id="claude-code",
        kind="tool_post",
        recorded_at="2026-11-21T12:00:11Z",
        payload={"tool": "Read", "seq": 11},
    )
    with pytest.raises(BrainError) as exc_dl:
        dl_spool.enqueue_event(ev11, deadline_ns=deadline_start + 100_000_000)
    assert exc_dl.value.code is ErrorCode.DEADLINE_EXCEEDED
    committed = OutboxSpool(dl_dir, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK).read_pending(
        limit=20, producer_stream="stream-dl"
    )
    assert [e.sequence for e in committed] == list(range(1, 11))
