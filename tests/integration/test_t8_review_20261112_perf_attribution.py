"""T8-E01: every accepted measurement belongs to its own response write.

Run the actual child taps through the sealed r5 scripted harness. The transport
and clock stand-ins expose the cut between flush and sample publication, and
the two worker threads retain the real threading.local behavior.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.integration import test_t8_closure_perf_probe_r5 as fixture


class _AfterFlushClock(fixture._Clock):
    def __init__(self) -> None:
        super().__init__()
        self.callback: Callable[[], None] | None = None
        self.called = False

    def __call__(self) -> int:
        self.value += 1
        timestamp = self.value
        if self.value == 1010 and self.callback is not None:
            self.called = True
            self.callback()
        return timestamp


def test_e01_request_starting_after_flush_cannot_replace_the_flushed_requests_sample(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    original_run = fixture._Harness.run
    monkeypatch.setattr(fixture, "_Clock", _AfterFlushClock)

    def run(harness: Any, domain: Any, steps: list[tuple[str, str]]) -> None:
        from superbrain.cli_api import _loopback_server

        transport: Any = _loopback_server

        def start_b_after_a_flushed() -> None:
            harness.workers["w2"].submit(
                transport.read_admitted_tool_command, deadline_ns=fixture.DEADLINE["req-B"], key="req-B",
            ).result()
            harness._bracket(
                "req-B", domain.prepare_mutation, SimpleNamespace(arguments={"idempotency_key": "req-B"}),
                None, now=None,
            )

        harness.clock.callback = start_b_after_a_flushed
        original_run(harness, domain, steps)

    monkeypatch.setattr(fixture._Harness, "run", run)
    harness, samples = fixture._drive(monkeypatch, capsys, tmp_path, fixture._full("req-A"))
    assert isinstance(harness.clock, _AfterFlushClock)
    assert harness.clock.called, "the controlled post-flush interleaving must execute"
    assert len(samples) == 1, "one response write must preserve exactly one sample"
    sample = samples[0]
    assert sample["idempotency_key"] == "req-A", "the first response belongs to request A"
    assert sample["t0_read_ns"] == fixture.DEADLINE["req-A"] - fixture.T0_OFFSET
    if sample["status"] == "ok":
        assert not fixture._foreign(sample, harness), "an accepted sample contains foreign spans"


def _same_key_run(harness: Any, domain: Any, steps: list[tuple[str, str]]) -> None:
    """Keep A/B as call identities while both actual tool calls use the same logical retry key."""
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.cli_api import _loopback_server
    from superbrain.storage.idempotency import KernelIdempotencyStore

    transport: Any = _loopback_server
    store_cls: Any = KernelIdempotencyStore
    for step, request in steps:
        pool = harness.workers["w1" if request == "req-A" else "w2"]
        if step == "read":
            pool.submit(
                transport.read_admitted_tool_command, deadline_ns=fixture.DEADLINE[request], key="req-A",
            ).result()
        elif step == "prepare":
            harness._bracket(
                request, domain.prepare_mutation, SimpleNamespace(arguments={"idempotency_key": "req-A"}),
                None, now=None,
            )
        elif step == "observe":
            harness._bracket(request, harness.observer.observe, None, 0)
        elif step == "filter":
            harness._bracket(request, PrivacyFilter.apply, PrivacyFilter(), {"k": request}, None)
        elif step == "commit":
            harness._bracket(request, store_cls.commit_prepared_effect, object(), request=request)
        elif step == "write":
            harness._bracket(
                request, fixture._run_on, pool, transport.write_json_response, body=json.dumps({"ok": True}),
            )
        else:
            raise AssertionError(step)
    for executor in harness.workers.values():
        executor.shutdown()


def test_e01_overlapping_same_key_calls_never_emit_an_accepted_mixed_sample(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    monkeypatch.setattr(fixture._Harness, "run", _same_key_run)
    steps = fixture._full("req-A")[:-1] + fixture._full("req-B")[:-1] + [("write", "req-A"), ("write", "req-B")]
    _, samples = fixture._drive(monkeypatch, capsys, tmp_path, steps)
    assert len(samples) == 2, "both attempted response writes must retain a sample"
    assert [sample["idempotency_key"] for sample in samples] == ["req-A", "req-A"]
    assert all(sample["status"] != "ok" for sample in samples), (
        "a reused idempotency key must not hide overlapping requests",
        samples,
    )


def test_e01_sequential_same_key_calls_keep_both_request_identities_and_clean_samples(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    monkeypatch.setattr(fixture._Harness, "run", _same_key_run)
    harness, samples = fixture._drive(
        monkeypatch, capsys, tmp_path, fixture._full("req-A") + fixture._full("req-B"),
    )
    assert len(samples) == 2
    for request, sample in zip(("req-A", "req-B"), samples, strict=True):
        assert sample["status"] == "ok" and sample["idempotency_key"] == "req-A"
        assert sample["t0_read_ns"] == fixture.DEADLINE[request] - fixture.T0_OFFSET
        assert sample["redacted_count"] == fixture.REDACTED_COUNT[request]
        for name, timestamp in sample.items():
            if name.endswith("_ns") and name not in fixture.NOT_SPANS:
                assert any(low < timestamp <= high for low, high in harness.brackets[request]), (request, name)
