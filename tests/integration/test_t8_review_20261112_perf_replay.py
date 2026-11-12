"""T8-E01 siblings: replay and atomic per-read registration preserve sample identity."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from scripts import perf_probe
from tests.integration import test_t8_closure_perf_probe_r5 as fixture
from tests.integration.test_t8_review_20261112_perf_attribution import _same_key_run

OWNER_SPANS = frozenset({
    "admission_done_ns", "filter_start_ns", "filter_end_ns", "commit_start_ns", "commit_end_ns",
    "observer_start_ns", "observer_end_ns",
})


def test_e01_cached_same_key_replay_never_reuses_the_previous_calls_owner_spans(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    monkeypatch.setattr(fixture._Harness, "run", _same_key_run)
    steps = fixture._full("req-A") + [("read", "req-B"), ("write", "req-B")]
    _, samples = fixture._drive(monkeypatch, capsys, tmp_path, steps)
    assert len(samples) == 2
    fresh, replay = samples
    assert fresh["status"] == "ok" and fresh["idempotency_key"] == "req-A"
    assert replay["idempotency_key"] == "req-A", "both calls deliberately use one logical retry key"
    assert replay["status"] != "ok", "a replay without owner phase measurements must not be accepted as a fresh probe"
    assert replay["t0_read_ns"] == fixture.DEADLINE["req-B"] - fixture.T0_OFFSET
    assert not (OWNER_SPANS & replay.keys()), "the replay has no prepare/filter/commit/observer taps"


class _BeforeAcquireLock:
    """Inject an independent completion before the next critical section begins."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.hook: Callable[[], None] | None = None
        self.called = False

    def __enter__(self) -> Self:
        hook, self.hook = self.hook, None
        if hook is not None:
            self.called = True
            hook()
        self.lock.acquire()
        return self

    def __exit__(self, *args: Any) -> None:
        self.lock.release()


def test_e01_read_registration_cannot_pick_up_an_intervening_same_key_calls_row(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    lock = _BeforeAcquireLock()
    threading_api = SimpleNamespace(**vars(threading))
    threading_api.Lock = lambda: lock
    monkeypatch.setattr(perf_probe, "threading", threading_api)
    original_run = fixture._Harness.run

    def run(harness: Any, domain: Any, steps: list[tuple[str, str]]) -> None:
        from superbrain.application.privacy import PrivacyFilter
        from superbrain.cli_api import _loopback_server
        from superbrain.storage.idempotency import KernelIdempotencyStore

        transport: Any = _loopback_server
        store_cls: Any = KernelIdempotencyStore

        def complete_b_before_a_registers() -> None:
            pool = harness.workers["w2"]
            pool.submit(
                transport.read_admitted_tool_command, deadline_ns=fixture.DEADLINE["req-B"], key="req-A",
            ).result()
            harness._bracket(
                "req-B", domain.prepare_mutation, SimpleNamespace(arguments={"idempotency_key": "req-A"}),
                None, now=None,
            )
            harness._bracket("req-B", harness.observer.observe, None, 0)
            harness._bracket("req-B", PrivacyFilter.apply, PrivacyFilter(), {"k": "req-B"}, None)
            harness._bracket("req-B", store_cls.commit_prepared_effect, object(), request="req-B")
            harness._bracket(
                "req-B", fixture._run_on, pool, transport.write_json_response, body=json.dumps({"ok": True}),
            )

        lock.hook = complete_b_before_a_registers
        original_run(harness, domain, steps)

    monkeypatch.setattr(fixture._Harness, "run", run)
    harness, samples = fixture._drive(monkeypatch, capsys, tmp_path, fixture._full("req-A"))
    assert lock.called, "the controlled read-registration interleaving must execute"
    assert len(samples) == 2, "each response write retains its own record"
    for request, sample in zip(("req-B", "req-A"), samples, strict=True):
        assert sample["idempotency_key"] == "req-A"
        assert sample["t0_read_ns"] == fixture.DEADLINE[request] - fixture.T0_OFFSET, (
            "a read attempt picked up the other attempt's same-key row",
            request,
            sample,
        )
        if sample["status"] == "ok":
            assert sample["redacted_count"] == fixture.REDACTED_COUNT[request]
            for name, stamp in sample.items():
                if name.endswith("_ns") and name not in fixture.NOT_SPANS:
                    assert any(low < stamp <= high for low, high in harness.brackets[request]), (request, name)


def test_e01_fresh_sequential_same_key_requests_still_have_complete_measured_spans(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    monkeypatch.setattr(fixture._Harness, "run", _same_key_run)
    harness, samples = fixture._drive(
        monkeypatch, capsys, tmp_path, fixture._full("req-A") + fixture._full("req-B"),
    )
    assert len(samples) == 2
    for request, sample in zip(("req-A", "req-B"), samples, strict=True):
        assert sample["status"] == "ok" and sample["idempotency_key"] == "req-A"
        assert OWNER_SPANS <= sample.keys(), "the fresh positive twin must exercise the measured phases"
        assert sample["t0_read_ns"] == fixture.DEADLINE[request] - fixture.T0_OFFSET
        assert sample["redacted_count"] == fixture.REDACTED_COUNT[request]
        for name, stamp in sample.items():
            if name.endswith("_ns") and name not in fixture.NOT_SPANS:
                assert any(low < stamp <= high for low, high in harness.brackets[request]), (request, name)
