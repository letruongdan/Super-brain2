"""C-07 closure oracle: a perf-probe sample never mixes spans of different requests.

Requirement: ``scripts/perf_probe.py`` ``child()`` accepts a sample only when every span in it belongs to the same
request (``idempotency_key``). When a response write happens while the recorded spans belong to another request
(overlapping/pipelined requests on different HTTP worker threads), the emitted sample must carry a non-``ok``
status (which blocks the probe verdict), never an ``ok`` status that pairs one request's response with another
request's spans.

The real taps installed by ``child()`` are driven deterministically: the daemon (``serve_config_path``), the
transport read/write, the domain ``prepare_mutation`` and the clock are replaced by scripted fakes, and the taps
themselves (the code under test) run unchanged.
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


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000

    def __call__(self) -> int:
        self.value += 1
        return self.value


class _Scenario:
    """Scripted daemon: runs request steps on named worker threads (one OS thread per worker)."""

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.workers = {name: ThreadPoolExecutor(max_workers=1) for name in ("w1", "w2")}
        self.deadline = {"req-A": 10_000_000_000, "req-B": 20_000_000_000}
        self.admission: dict[str, tuple[int, int]] = {}
        self.writes: list[str] = []
        self.steps: list[tuple[str, str, str]] = []

    def run(self, domain: Any) -> None:
        from superbrain.cli_api import _loopback_server

        transport: Any = _loopback_server
        for step, key, worker in self.steps:
            if step == "read":
                self.workers[worker].submit(
                    transport.read_admitted_tool_command, deadline_ns=self.deadline[key], key=key,
                ).result()
            elif step == "prepare":
                before = self.clock.value
                domain.prepare_mutation(SimpleNamespace(arguments={"idempotency_key": key}), None, now=None)
                self.admission[key] = (before, self.clock.value)
            else:
                body = {"ok": True} if step == "write_ok" else {"ok": False, "error": {"code": "deadline_exceeded"}}
                self.workers[worker].submit(transport.write_json_response, body=json.dumps(body)).result()
                self.writes.append(key)
        for pool in self.workers.values():
            pool.shutdown()


def _drive(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
           steps: list[tuple[str, str, str]]) -> tuple[_Scenario, list[dict[str, Any]]]:
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.cli_api import _loopback_server
    from superbrain.composition import daemon_entry as daemon_module
    from superbrain.composition import owner_entry
    from superbrain.storage.idempotency import KernelIdempotencyStore
    from tests.support import inc2_t8_domain, inc2_t8_privacy

    transport: Any = _loopback_server
    daemon_entry: Any = daemon_module
    clock = _Clock()
    scenario = _Scenario(clock)
    scenario.steps = steps

    # child() overwrites these globals without restoring them: pre-register them so monkeypatch restores them.
    monkeypatch.setattr(PrivacyFilter, "apply", PrivacyFilter.apply)
    monkeypatch.setattr(KernelIdempotencyStore, "commit_prepared_effect", KernelIdempotencyStore.commit_prepared_effect)
    monkeypatch.setattr(daemon_entry, "kernel_store_extensions", daemon_entry.kernel_store_extensions)

    def fake_read(*, deadline_ns: int, key: str) -> Any:
        return SimpleNamespace(arguments={"idempotency_key": key})

    monkeypatch.setattr(transport, "read_admitted_tool_command", fake_read)
    monkeypatch.setattr(transport, "write_json_response", lambda **kwargs: None)
    monkeypatch.setattr(inc2_t8_privacy.PrivacyDomainProxy, "prepare_mutation", lambda self, call, ctx, *, now: None)
    monkeypatch.setattr(inc2_t8_domain, "fixture_hooks", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner_entry, "_explicit_owner_adapters", lambda config: (None, None, tmp_path / "scratch"))
    monkeypatch.setattr(perf_probe, "time", SimpleNamespace(perf_counter_ns=clock))
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    def fake_serve(config: Path, *, os_: Any, domain: Any, hooks: Any, stop_event: Any, on_ready: Any) -> int:
        scenario.run(domain)
        return 0

    monkeypatch.setattr(daemon_entry, "serve_config_path", fake_serve)
    capsys.readouterr()
    assert perf_probe.child(tmp_path / "config.json") == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    return scenario, [event for event in events if event.get("event") == "sample"]


def _belongs(event: dict[str, Any], key: str, scenario: _Scenario) -> bool:
    low, high = scenario.admission[key]
    return (
        event.get("idempotency_key") == key
        and event.get("t0_read_ns") == scenario.deadline[key] - T0_OFFSET
        and low < int(event["admission_done_ns"]) <= high
    )


def test_c07_positive_control_sequential_requests_give_ok_samples_with_own_spans(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    scenario, samples = _drive(monkeypatch, capsys, tmp_path, [
        ("read", "req-A", "w1"), ("prepare", "req-A", "-"), ("write_ok", "req-A", "w1"),
        ("read", "req-B", "w2"), ("prepare", "req-B", "-"), ("write_ok", "req-B", "w2"),
    ])
    assert len(samples) == 2
    assert samples[0]["status"] == "ok" and _belongs(samples[0], "req-A", scenario)
    assert samples[1]["status"] == "ok" and _belongs(samples[1], "req-B", scenario)


def test_c07_overlapping_requests_never_emit_an_ok_sample_with_another_requests_spans(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    # A is admitted, then B is admitted on another worker before A's response is written; B's response fails.
    scenario, samples = _drive(monkeypatch, capsys, tmp_path, [
        ("read", "req-A", "w1"), ("prepare", "req-A", "-"),
        ("read", "req-B", "w2"), ("prepare", "req-B", "-"),
        ("write_ok", "req-A", "w1"), ("write_error", "req-B", "w2"),
    ])
    assert samples, "each response write must still emit a sample record"
    responses_ok = {"req-A": True, "req-B": False}
    for event in samples:
        if event.get("status") != "ok":
            continue  # a non-ok sample blocks the verdict: acceptable for a mixed/ambiguous measurement
        key = event.get("idempotency_key")
        assert key in responses_ok, f"ok sample without a known request: {event!r}"
        assert responses_ok[key], f"ok sample for {key} whose own response was an error: {event!r}"
        assert _belongs(event, key, scenario), f"ok sample for {key} carries another request's spans: {event!r}"
