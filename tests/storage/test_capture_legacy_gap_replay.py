"""Owner-approved upgrade rule (2026-11-28): a fallback gap whose id is derived from its slot, replayed onto a
producer gap an earlier binary committed with a random id at the same (producer_stream, sequence, repo_id,
checkout_id), is a dedup. The stored gap stays, the sequence is acknowledged as a gap, and Events keep their own
conflict check. Without it the hook (which cannot recover a random id after the old frame was ACKed and deleted)
would poison the stream's drain with IDEMPOTENCY_CONFLICT."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    CaptureBatchAck,
    CaptureEventRecord,
    ProducerCaptureGap,
    StagedCaptureEvent,
    fallback_gap_id,
)
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.runtime import Runtime
from tests.storage.test_outbox_r10_ack_durability import _repo_root_with_36bf08d9
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime

_STREAM, _REPO, _CHK, _PRINCIPAL = "stream-legacy-gap", "repo-legacy-gap", "chk-legacy-gap", "principal-legacy-gap"
_AT = "2026-11-28T08:00:00Z"
_NOW = datetime(2026, 11, 28, 9, 0, tzinfo=UTC)


def _gap(gap_id: str, seq: int = 1, reason: str = "hook_timeout") -> ProducerCaptureGap:
    return ProducerCaptureGap(gap_id=gap_id, producer_stream=_STREAM, sequence=seq, reason=reason, recorded_at=_AT,
                              estimated_count=1, duration_ms=5)


def _event(seq: int, note: str = "ok") -> StagedCaptureEvent:
    payload: dict[str, JsonValue] = {"cmd": "pytest", "note": note}
    body = canonical_json(payload)
    return StagedCaptureEvent(
        record=CaptureEventRecord(event_id=f"ev-legacy-gap-{seq}", producer_stream=_STREAM, sequence=seq,
                                  harness_id="claude-code", kind="tool_post", recorded_at=_AT, payload=payload),
        payload_bytes=body, payload_digest=digest_bytes(body), source="unknown", source_verification="unverified",
    )


def _commit(
    rt: Runtime, *, events: tuple[StagedCaptureEvent, ...] = (), gaps: tuple[ProducerCaptureGap, ...] = (),
    checkout_id: str = _CHK,
) -> CaptureBatchAck:
    return KernelCaptureStore(rt.store).commit_staged_batch(
        producer_stream=_STREAM, repo_id=_REPO, checkout_id=checkout_id, principal_id=_PRINCIPAL,
        events=events, gaps=gaps, now=_NOW,
    )


def _stored_gap(rt: Runtime, seq: int) -> tuple[str, str]:
    row = rt.store._db.execute(
        "SELECT gap_id, checkout_id FROM capture_gaps WHERE producer_stream = ? AND sequence = ? "
        "AND gap_origin = 'producer'", (_STREAM, seq),
    ).fetchone()
    return str(row[0]), str(row[1])


_LEGACY_SCRIPT = """
import json, sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from superbrain.adapters.os import os_adapters
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.ports.capture import ProducerCaptureGap
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
root, store_id, stream, repo, chk, principal, gap_id, at = sys.argv[2:10]
os_ = os_adapters()
handlers, kinds = kernel_store_extensions()
rt = open_runtime_under_lease(admit_existing_pair(Path(root), store_id, os_, purpose="serve"),
                              handlers=handlers, kinds=kinds)
try:
    gap = ProducerCaptureGap(gap_id=gap_id, producer_stream=stream, sequence=1, reason="hook_timeout",
                             recorded_at=at, estimated_count=1, duration_ms=5)
    ack = KernelCaptureStore(rt.store).commit_staged_batch(
        producer_stream=stream, repo_id=repo, checkout_id=chk, principal_id=principal, events=(), gaps=(gap,),
        now=datetime(2026, 11, 28, 9, 0, tzinfo=timezone.utc))
    print(json.dumps(list(ack.acked_producer_gap_sequences)))
finally:
    rt.close()
"""


def _legacy_commit_gap(tmp: Path, root: Path, store_id: str, gap_id: str) -> list[int]:
    repo_root = _repo_root_with_36bf08d9()
    if repo_root is None:
        pytest.skip("4e33772 is not reachable from this checkout")
    legacy = tmp / "legacy-src-4e33772"
    legacy.mkdir()
    tar_bytes = subprocess.check_output(["git", "-C", str(repo_root), "archive", "--format=tar", "4e33772", "src"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(legacy, filter="data")
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _LEGACY_SCRIPT, str(legacy / "src"), str(root), store_id, _STREAM, _REPO, _CHK,
         _PRINCIPAL, gap_id, _AT],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return list(json.loads(proc.stdout.strip().splitlines()[-1]))


def test_upgrade_replays_a_slot_derived_gap_onto_an_acked_legacy_gap(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    root = trusted_tmp / "store"
    rt = open_kernel_job_runtime(root, os_)
    store_id = rt.store.store_id
    rt.close()
    # the earlier binary (4e33772, from git) commits a random gap id into the same DB and acknowledges it
    assert _legacy_commit_gap(trusted_tmp, root, store_id, "gap-legacy-random-1") == [1]
    new_gap = _gap(fallback_gap_id(_STREAM, 1), reason="outbox_full")
    for _restart in range(2):  # upgraded daemon on the same DB, then once more after a restart
        rt = reopen_kernel_job_runtime(root, store_id, os_)
        try:
            ack = _commit(rt, events=(_event(2),), gaps=(new_gap,))
            assert ack.acked_producer_gap_sequences == (1,)
            assert ack.committed_event_sequences == (2,)
            assert _stored_gap(rt, 1) == ("gap-legacy-random-1", _CHK)  # the stored gap is kept as it was
        finally:
            rt.close()
    rt = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        assert 1 in _commit(rt, events=(_event(1),)).committed_event_sequences  # a late Event still lands
        with pytest.raises(BrainError) as other_content:
            _commit(rt, events=(_event(2, note="different"),))
        assert other_content.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    finally:
        rt.close()


@pytest.mark.parametrize("variant", ["random-id", "other-checkout"])
def test_other_gap_mismatches_at_a_committed_slot_stay_conflicts(trusted_tmp: Path, variant: str) -> None:
    rt = open_kernel_job_runtime(trusted_tmp / "store", os_adapters())
    try:
        _commit(rt, gaps=(_gap("gap-legacy-random-1"),))
        with pytest.raises(BrainError) as err:
            if variant == "random-id":  # not a slot-derived fallback: identity mismatch is still a conflict
                _commit(rt, gaps=(_gap("gap-another-random-2"),))
            else:  # slot-derived, but another checkout's scope
                _commit(rt, gaps=(_gap(fallback_gap_id(_STREAM, 1)),), checkout_id="chk-someone-else")
        assert err.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
    finally:
        rt.close()
