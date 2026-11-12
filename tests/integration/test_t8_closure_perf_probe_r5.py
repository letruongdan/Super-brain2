"""Closure round C r5 oracle (review F3): an ``ok`` perf sample carries only spans of its own request.

Requirement: ``scripts/perf_probe.py`` ``child()`` emits ``status == "ok"`` only when every span in the sample
(admission, filter, commit, observer, response write) and every filter-derived value was recorded by that sample's
own request, whatever the interleaving of overlapping requests. A non-``ok`` status is acceptable when requests
overlap (it blocks the verdict).

The taps installed by ``child()`` run unchanged; the daemon, transport read/write, domain ``prepare_mutation``, the
filter/commit originals and the clock are scripted. Owner-thread taps (prepare, filter, commit, observer) run on the
test thread; reads and writes run on two dedicated worker threads so ``threading.local`` behaves as in the server.
Every tap call is bracketed by the scripted clock, so each timestamp in a sample is attributable to one request.
"""

from __future__ import annotations

import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import perf_probe

T0_OFFSET = 1_500_000_000
DEADLINE = {"req-A": 10_000_000_000, "req-B": 20_000_000_000}
REDACTED_COUNT = {"req-A": 11, "req-B": 22}
NOT_SPANS = frozenset({"t0_read_ns", "elapsed_ns"})


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000

    def __call__(self) -> int:
        self.value += 1
        return self.value


def _run_on(pool: ThreadPoolExecutor, fn: Any, **kwargs: Any) -> None:
    pool.submit(fn, **kwargs).result()


class _Harness:
    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.workers = {name: ThreadPoolExecutor(max_workers=1) for name in ("w1", "w2")}
        self.brackets: dict[str, list[tuple[int, int]]] = {"req-A": [], "req-B": []}
        self.observer: Any = None
        self.ok_response = {"req-A": True, "req-B": True}

    def _bracket(self, key: str, action: Any, *args: Any, **kwargs: Any) -> None:
        before = self.clock.value
        action(*args, **kwargs)
        self.brackets[key].append((before, self.clock.value))

    def run(self, domain: Any, steps: list[tuple[str, str]]) -> None:
        from superbrain.application.privacy import PrivacyFilter
        from superbrain.cli_api import _loopback_server
        from superbrain.storage.idempotency import KernelIdempotencyStore

        transport: Any = _loopback_server
        store_cls: Any = KernelIdempotencyStore
        worker_of = {"req-A": "w1", "req-B": "w2"}
        for step, key in steps:
            pool = self.workers[worker_of[key]]
            if step == "read":
                pool.submit(transport.read_admitted_tool_command, deadline_ns=DEADLINE[key], key=key).result()
            elif step == "prepare":
                call = SimpleNamespace(arguments={"idempotency_key": key})
                self._bracket(key, domain.prepare_mutation, call, None, now=None)
            elif step == "filter":
                filter_api: Any = PrivacyFilter.apply
                self._bracket(key, filter_api, PrivacyFilter(), {"k": key}, None)
            elif step == "commit":
                self._bracket(key, store_cls.commit_prepared_effect, object(), request=key)
            elif step == "observe":
                self._bracket(key, self.observer.observe, None, 0)
            elif step == "write":
                body = {"ok": True} if self.ok_response[key] else {"ok": False, "error": {"code": "deadline_exceeded"}}
                self._bracket(key, _run_on, pool, transport.write_json_response, body=json.dumps(body))
            else:
                raise AssertionError(step)
        for executor in self.workers.values():
            executor.shutdown()


def _drive(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
           steps: list[tuple[str, str]], ok_response: dict[str, bool] | None = None,
           ) -> tuple[_Harness, list[dict[str, Any]]]:
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.cli_api import _loopback_server
    from superbrain.composition import daemon_entry as daemon_module
    from superbrain.composition import owner_entry
    from superbrain.storage.idempotency import KernelIdempotencyStore
    from tests.support import inc2_t8_domain, inc2_t8_privacy

    transport: Any = _loopback_server
    daemon_entry: Any = daemon_module
    clock = _Clock()
    harness = _Harness(clock)
    if ok_response:
        harness.ok_response.update(ok_response)

    def fake_filter(self: Any, value: Any, policy: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(redacted_count=REDACTED_COUNT[value["k"]], stripped_keys_count=0, value={})

    # Originals captured by child() are these fakes; monkeypatch restores the real ones afterwards.
    monkeypatch.setattr(PrivacyFilter, "apply", fake_filter)
    monkeypatch.setattr(KernelIdempotencyStore, "commit_prepared_effect", lambda self, **kwargs: (None, False))
    monkeypatch.setattr(daemon_entry, "kernel_store_extensions", daemon_entry.kernel_store_extensions)
    monkeypatch.setattr(transport, "read_admitted_tool_command",
                        lambda *, deadline_ns, key: SimpleNamespace(arguments={"idempotency_key": key}))
    monkeypatch.setattr(transport, "write_json_response", lambda **kwargs: None)
    monkeypatch.setattr(inc2_t8_privacy.PrivacyDomainProxy, "prepare_mutation", lambda self, call, ctx, *, now: None)

    def fake_hooks(*args: Any, observer: Any = None, **kwargs: Any) -> None:
        harness.observer = observer

    monkeypatch.setattr(inc2_t8_domain, "fixture_hooks", fake_hooks)
    monkeypatch.setattr(owner_entry, "_explicit_owner_adapters", lambda config: (None, None, tmp_path / "scratch"))
    monkeypatch.setattr(perf_probe, "time", SimpleNamespace(perf_counter_ns=clock))
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    def fake_serve(config: Path, *, os_: Any, domain: Any, hooks: Any, stop_event: Any, on_ready: Any) -> int:
        harness.run(domain, steps)
        return 0

    monkeypatch.setattr(daemon_entry, "serve_config_path", fake_serve)
    capsys.readouterr()
    assert perf_probe.child(tmp_path / "config.json") == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    return harness, [event for event in events if event.get("event") == "sample"]


def _foreign(event: dict[str, Any], harness: _Harness) -> list[str]:
    """Fields of ``event`` not recorded by its own request (empty when the sample is clean)."""
    key = event.get("idempotency_key")
    if key not in DEADLINE:
        return ["idempotency_key"]
    problems: list[str] = []
    if event.get("t0_read_ns") != DEADLINE[key] - T0_OFFSET:
        problems.append("t0_read_ns")
    for name, value in event.items():
        if name.endswith("_ns") and name not in NOT_SPANS and isinstance(value, int):
            if not any(low < value <= high for low, high in harness.brackets[key]):
                problems.append(name)
    if "redacted_count" in event and event["redacted_count"] != REDACTED_COUNT[key]:
        problems.append("redacted_count")
    return problems


def _assert_no_ok_sample_with_foreign_span(harness: _Harness, samples: list[dict[str, Any]]) -> None:
    assert samples, "every response write emits a sample record"
    for event in samples:
        if event.get("status") != "ok":
            continue
        key = event.get("idempotency_key")
        assert key in DEADLINE and harness.ok_response[key], f"ok sample for a request whose response failed: {event}"
        foreign = _foreign(event, harness)
        assert not foreign, f"ok sample {key} carries foreign fields {foreign}: {event}"


def _full(key: str) -> list[tuple[str, str]]:
    return [("read", key), ("prepare", key), ("observe", key), ("filter", key), ("commit", key), ("write", key)]


def test_r5_positive_control_sequential_requests_give_clean_ok_samples(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    harness, samples = _drive(monkeypatch, capsys, tmp_path, _full("req-A") + _full("req-B"))
    assert [s["status"] for s in samples] == ["ok", "ok"]
    assert [s["idempotency_key"] for s in samples] == ["req-A", "req-B"]
    for event in samples:
        assert not _foreign(event, harness), event
        for span in ("admission_done_ns", "filter_start_ns", "filter_end_ns", "commit_start_ns", "commit_end_ns",
                     "observer_start_ns", "observer_end_ns", "response_write_start_ns", "response_flushed_ns"):
            assert span in event, f"positive control must record {span}"


INTERLEAVINGS: dict[str, list[tuple[str, str]]] = {
    # Reviewer F3: B's write would pair B's response with A's late commit.
    "late_commit": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("commit", "req-B"), ("commit", "req-A"), ("write", "req-A"), ("write", "req-B"),
    ],
    "late_commit_b_writes_first": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("commit", "req-B"), ("commit", "req-A"), ("write", "req-B"), ("write", "req-A"),
    ],
    "late_filter_into_record_without_filter": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("filter", "req-A"), ("write", "req-B"), ("write", "req-A"),
    ],
    "late_filter_overwrites_own_filter": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"), ("filter", "req-B"),
        ("filter", "req-A"), ("write", "req-B"), ("write", "req-A"),
    ],
    "late_observer": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("observe", "req-B"), ("observe", "req-A"), ("write", "req-B"), ("write", "req-A"),
    ],
    "late_observer_into_record_without_observer": [
        ("read", "req-A"), ("prepare", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("observe", "req-A"), ("write", "req-B"), ("write", "req-A"),
    ],
    "a_prepare_after_b_write": [
        ("read", "req-A"), ("read", "req-B"), ("prepare", "req-B"), ("commit", "req-B"), ("write", "req-B"),
        ("prepare", "req-A"), ("commit", "req-A"), ("write", "req-A"),
    ],
    "all_spans_interleaved": [
        ("read", "req-A"), ("prepare", "req-A"), ("observe", "req-A"), ("read", "req-B"), ("prepare", "req-B"),
        ("observe", "req-B"), ("filter", "req-A"), ("filter", "req-B"), ("commit", "req-A"), ("commit", "req-B"),
        ("write", "req-B"), ("write", "req-A"),
    ],
}


@pytest.mark.parametrize("name", sorted(INTERLEAVINGS))
def test_r5_no_ok_sample_carries_a_span_of_another_request(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, name: str,
) -> None:
    harness, samples = _drive(monkeypatch, capsys, tmp_path, INTERLEAVINGS[name])
    assert len(samples) == 2
    _assert_no_ok_sample_with_foreign_span(harness, samples)


def test_r5_failed_response_never_yields_an_ok_sample_under_overlap(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    harness, samples = _drive(monkeypatch, capsys, tmp_path, INTERLEAVINGS["late_commit"], {"req-B": False})
    _assert_no_ok_sample_with_foreign_span(harness, samples)
