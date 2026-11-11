"""Fast performance evidence oracles. The full benchmark runs only through this module's CLI."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import runpy
import sys
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from scripts import perf_gate
from scripts.gate import SourceIdentity
from superbrain.application.privacy import PrivacyFilter
from superbrain.cli_api._http_frames import MAX_BODY_BYTES
from superbrain.cli_api._loopback_wire import encode_call
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy, Scope, ToolCommand
from superbrain.core.wire import MAX_WIRE_BODY_BYTES, MCP_PROTOCOL_VERSION, load_catalog

SOURCE = SourceIdentity("a" * 40, True, "sha256:" + "b" * 64, "sha256:" + "c" * 64, "sha256:" + "d" * 64)
WHEEL = "sha256:" + "e" * 64
SCHEMA = "sha256:" + "f" * 64
POSITIVE = "ordinary safe prose"
WARM_SPANS = (
    "t0_read_ns",
    "admission_done_ns",
    "filter_start_ns",
    "filter_end_ns",
    "observer_start_ns",
    "observer_end_ns",
    "commit_start_ns",
    "commit_end_ns",
    "response_write_start_ns",
    "response_flushed_ns",
)


def warm_sample(index: int, *, elapsed_ms: int = 20) -> dict[str, JsonValue]:
    begin = 10_000_000_000 + index * 2_000_000_000
    row: dict[str, JsonValue] = {
        name: begin + offset * 1_000_000 for offset, name in enumerate(WARM_SPANS[:-1])
    }
    row.update(
        idempotency_key=f"perf-{index}",
        status="ok",
        delivery_verified=True,
        response_flushed_ns=begin + elapsed_ms * 1_000_000,
        elapsed_ns=elapsed_ms * 1_000_000,
    )
    return row


def warm_inputs() -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    return [warm_sample(i) for i in range(-10, 0)], [warm_sample(i) for i in range(200)]


def privacy_sample(kib: int) -> dict[str, JsonValue]:
    return {
        "status": "ok",
        "elapsed_ns": kib * 50_000,
        "filter_bytes": kib * 1024,
        "filter_ran": True,
        "rejected_before_filter": False,
        "redacted_count": 3,
        "stripped_keys_count": 1,
        "positive_control_preserved": True,
    }


def privacy_inputs() -> tuple[dict[int, list[dict[str, JsonValue]]], list[dict[str, JsonValue]]]:
    sizes = {kib: [privacy_sample(kib) for _ in range(30)] for kib in (256, 512, 768, 1024)}
    wire = [{**privacy_sample(1023), "wire_bytes": 1_048_320}]
    return sizes, wire


def cold_sample(index: int) -> dict[str, JsonValue]:
    started = 1_000_000_000 + index * 100_000_000
    return {
        "pid": 5000 + index,
        "status": "ok",
        "started_ns": started,
        "first_frame_ns": started + 30_000_000,
        "elapsed_ns": 30_000_000,
        "valid_initialize_frame": True,
        "first_frame": {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "superbrain", "version": "2.0"},
            },
        },
    }


def cold_inputs() -> dict[str, list[dict[str, JsonValue]]]:
    return {
        "brain-mcp": [cold_sample(i) for i in range(20)],
        "brain mcp": [cold_sample(i + 20) for i in range(20)],
    }


def build_receipt(**changes: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "start": SOURCE,
        "end": SOURCE,
        "wheel_digest": WHEEL,
        "schema_sha256": SCHEMA,
        "interpreter": {
            "version": "3.14.3",
            "implementation": "cpython",
            "executable": sys.executable,
        },
        "host": {"system": sys.platform, "platform": sys.platform, "node": "fixture-host", "cpu": "fixture-cpu"},
        "command": ["python", "-m", __name__],
        "warm_prepare": {"accepted": True},
        "privacy_local": {"accepted": True},
        "cold_client": {"accepted": True},
    }
    kwargs.update(changes)
    return perf_gate.build_perf_receipt(**kwargs)


def assert_refused(probe: dict[str, Any]) -> None:
    assert probe["accepted"] is False
    assert probe.get("reasons"), "a refused probe must explain which measurement was invalid"


@pytest.mark.parametrize(
    ("values", "pct", "expected"),
    [([9.0], 50, 9.0), ([3.0, 1.0, 2.0], 50, 2.0), (list(map(float, range(1, 21))), 95, 19.0)],
)
def test_nearest_rank_percentile(values: list[float], pct: int, expected: float) -> None:
    assert perf_gate.nearest_rank_percentile(values, pct) == expected


@pytest.mark.parametrize(
    ("values", "pct"),
    [([], 95), ([math.nan], 95), ([math.inf], 95), ([True], 95), ([1.0], 0), ([1.0], 101), ([1.0], True)],
)
def test_percentile_rejects_invalid_measurements(values: list[float], pct: int) -> None:
    with pytest.raises((TypeError, ValueError)):
        perf_gate.nearest_rank_percentile(values, pct)


def test_warm_probe_keeps_all_samples_and_uses_the_nearest_rank_boundary() -> None:
    warmup, samples = warm_inputs()
    for index in range(189, 200):
        samples[index] = warm_sample(index, elapsed_ms=1600)
    refused = perf_gate.evaluate_warm_prepare_probe(warmup, samples)
    assert_refused(refused)
    assert refused["samples"] == samples
    assert refused["p95_ms"] == 1600.0
    samples[189] = warm_sample(189)
    passed = perf_gate.evaluate_warm_prepare_probe(warmup, samples)
    assert passed["accepted"] is True
    assert passed["warmup"] == warmup and passed["samples"] == samples
    assert passed["p50_ms"] == passed["p95_ms"] == 20.0
    assert passed["p99_ms"] == 1600.0


@pytest.mark.parametrize("defect", ["warmup", "missing", "key", "failed", "flush", "elapsed", "order"])
def test_warm_probe_refuses_incomplete_replay_and_incorrect_timing(defect: str) -> None:
    warmup, samples = warm_inputs()
    if defect == "warmup":
        warmup.pop()
    elif defect == "missing":
        samples.pop()
    elif defect == "key":
        samples[1]["idempotency_key"] = samples[0]["idempotency_key"]
    elif defect == "failed":
        samples[0]["status"] = "deadline_exceeded"
        samples[0]["delivery_verified"] = False
    elif defect == "flush":
        del samples[0]["response_flushed_ns"]
    elif defect == "elapsed":
        samples[0]["elapsed_ns"] = 8_000_000
    else:
        samples[0]["observer_start_ns"] = samples[0]["t0_read_ns"]
    probe = perf_gate.evaluate_warm_prepare_probe(warmup, samples)
    assert_refused(probe)
    assert probe["samples"] == samples and probe["warmup"] == warmup
    if defect == "key":
        reasons = probe["reasons"]
        assert isinstance(reasons, list)
        assert any("key" in str(reason).lower() or "replay" in str(reason).lower() for reason in reasons)
    assert build_receipt(warm_prepare=probe)["accepted"] is False


def test_privacy_probe_reports_each_size_and_growth_with_wire_control() -> None:
    sizes, wire = privacy_inputs()
    probe = perf_gate.evaluate_privacy_probe(sizes, wire)
    assert probe["accepted"] is True
    buckets = probe["sizes"]
    assert isinstance(buckets, dict)
    for kib in (256, 512, 768, 1024):
        bucket = buckets[str(kib)]
        assert isinstance(bucket, dict)
        assert bucket["samples"] == sizes[kib]
        assert bucket["p50_ms"] == pytest.approx(kib * 0.05)
        assert bucket["p95_ms"] == pytest.approx(kib * 0.05)
        assert bucket["ms_per_kib"] == pytest.approx(0.05)
    assert probe["growth_ratio_1024_256"] == pytest.approx(1.0)
    assert probe["wire_samples"] == wire


@pytest.mark.parametrize(
    "defect", ["bucket", "count", "failed", "parser", "filter", "redaction", "control", "slow", "wire"]
)
def test_privacy_probe_keeps_failure_and_refuses_an_unexercised_or_slow_filter(defect: str) -> None:
    sizes, wire = privacy_inputs()
    if defect == "bucket":
        del sizes[1024]
    elif defect == "count":
        sizes[1024].pop()
    elif defect == "failed":
        sizes[1024][0]["status"] = "invalid_input"
    elif defect == "parser":
        sizes[1024][0]["rejected_before_filter"] = True
    elif defect == "filter":
        sizes[1024][0]["filter_ran"] = False
    elif defect == "redaction":
        sizes[1024][0]["redacted_count"] = 0
    elif defect == "control":
        sizes[1024][0]["positive_control_preserved"] = False
    elif defect == "slow":
        for row in sizes[1024]:
            row["elapsed_ns"] = 100_000_001
    else:
        wire[0]["filter_ran"] = False
    probe = perf_gate.evaluate_privacy_probe(sizes, wire)
    assert_refused(probe)
    buckets = probe["sizes"]
    assert isinstance(buckets, dict)
    for kib, rows in sizes.items():
        bucket = buckets[str(kib)]
        assert isinstance(bucket, dict)
        assert bucket["samples"] == rows
    assert probe["wire_samples"] == wire
    assert build_receipt(privacy_local=probe)["accepted"] is False


def test_cold_probe_records_both_real_entrypoint_samples_without_a_latency_cap() -> None:
    spawns = cold_inputs()
    for rows in spawns.values():
        for row in rows:
            row["elapsed_ns"] = 5_000_000_000
            row["first_frame_ns"] = int(str(row["started_ns"])) + 5_000_000_000
    probe = perf_gate.evaluate_cold_client_probe(spawns)
    assert probe["accepted"] is True
    groups = probe["entrypoints"]
    assert isinstance(groups, dict)
    for name, rows in spawns.items():
        group = groups[name]
        assert isinstance(group, dict)
        assert group["samples"] == rows
        assert group["p50_ms"] == group["p95_ms"] == 5000.0


@pytest.mark.parametrize("defect", ["missing", "failed", "wrong-method", "wrong-version", "error", "flag"])
def test_cold_probe_rejects_wrong_first_frame_and_keeps_failed_spawn(defect: str) -> None:
    spawns = cold_inputs()
    if defect == "missing":
        spawns["brain mcp"].pop()
    elif defect == "failed":
        spawns["brain-mcp"][0]["status"] = "transport_error"
    elif defect == "wrong-method":
        spawns["brain-mcp"][0]["first_frame"] = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    elif defect == "wrong-version":
        frame = spawns["brain-mcp"][0]["first_frame"]
        assert isinstance(frame, dict) and isinstance(frame["result"], dict)
        frame["result"]["protocolVersion"] = "unaccepted-version"
    elif defect == "error":
        spawns["brain-mcp"][0]["first_frame"] = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603}}
    else:
        spawns["brain-mcp"][0]["valid_initialize_frame"] = False
    probe = perf_gate.evaluate_cold_client_probe(spawns)
    assert_refused(probe)
    groups = probe["entrypoints"]
    assert isinstance(groups, dict)
    for name, rows in spawns.items():
        group = groups[name]
        assert isinstance(group, dict)
        assert group["samples"] == rows
    assert build_receipt(cold_client=probe)["accepted"] is False


def string_leaves(value: JsonValue) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from string_leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from string_leaves(item)


def has_positive(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return value.get("positive_control") == POSITIVE or any(has_positive(item) for item in value.values())
    return isinstance(value, list) and any(has_positive(item) for item in value)


@pytest.mark.parametrize("kib", [256, 512, 768, 1024])
def test_adversarial_corpus_reaches_the_actual_filter_at_the_requested_size(kib: int) -> None:
    payload, reported = perf_gate.build_privacy_corpus_sample(kib, 0)
    raw = canonical_json(payload)
    assert reported == len(raw) == kib * 1024
    assert payload == perf_gate.build_privacy_corpus_sample(kib, 0)[0]
    text = list(string_leaves(payload))
    assert max(len(item.encode("utf-8")) for item in text) <= 65536
    assert any("://" in item and "@" in item for item in text)
    assert any("<private>" in item for item in text)
    assert any(len(item) >= 24 for item in text)
    result = PrivacyFilter().apply(payload, FilterPolicy())
    assert result.redacted_count > 0 and result.stripped_keys_count > 0
    assert has_positive(result.value)


def test_unclosed_private_tail_is_rejected_by_the_filter_after_a_bounded_valid_prefix() -> None:
    payload, reported = perf_gate.build_unclosed_private_tail_sample(256)
    assert reported == len(canonical_json(payload)) and reported >= 255 * 1024
    assert any("<private>" in item and "</private>" not in item for item in string_leaves(payload))
    with pytest.raises(BrainError) as caught:
        PrivacyFilter().apply(payload, FilterPolicy())
    assert caught.value.code is ErrorCode.INVALID_INPUT


def test_wire_corpus_is_schema_valid_and_fits_both_complete_envelopes() -> None:
    args, filter_bytes, wire_bytes = perf_gate.build_wire_privacy_sample()
    assert filter_bytes == len(canonical_json(args))
    catalog = load_catalog()
    tool = catalog.tools["submit_episode"]
    jsonschema.Draft202012Validator(tool.input_schema).validate(args)
    mcp: dict[str, JsonValue] = {
        "jsonrpc": "2.0", "id": "perf-wire", "method": "tools/call",
        "params": {"name": "submit_episode", "arguments": args},
    }
    http = encode_call(ToolCommand(
        "submit_episode", args, token="fixture-token",
        selected_scope=Scope("repo-perf", "checkout-perf"), correlation_id="perf-wire",
    ))
    assert wire_bytes == len(canonical_json(mcp)) <= MAX_WIRE_BODY_BYTES
    assert len(http) <= MAX_BODY_BYTES
    assert max(wire_bytes, len(http)) >= MAX_BODY_BYTES - 256
    result = PrivacyFilter().apply(args, FilterPolicy())
    assert result.redacted_count > 0 and result.stripped_keys_count > 0
    assert has_positive(result.value)


@pytest.mark.parametrize(
    "field",
    [
        "commit", "tree_clean", "tracked_digest", "lock_digest", "config_digest",
        "start", "end", "wheel", "schema", "interpreter",
    ],
)
def test_perf_receipt_rejects_source_drift_and_missing_provenance(field: str) -> None:
    changed: dict[str, Any] = {}
    if field in {"start", "end"}:
        changed[field] = None
    elif field == "tree_clean":
        changed["start"] = changed["end"] = replace(SOURCE, tree_clean=False)
    elif field in {"commit", "tracked_digest", "lock_digest", "config_digest"}:
        altered: dict[str, Any] = {field: "changed"}
        changed["end"] = replace(SOURCE, **altered)
    else:
        changed[{"wheel": "wheel_digest", "schema": "schema_sha256", "interpreter": "interpreter"}[field]] = None
    assert_refused(build_receipt(**changed))


def test_perf_receipt_is_source_bound_digestible_and_named_for_the_observed_runtime() -> None:
    receipt = build_receipt()
    assert receipt["accepted"] is True
    raw = copy.deepcopy(receipt)
    claimed = raw.pop("receipt_digest")
    assert claimed == digest_bytes(canonical_json(raw))
    name = perf_gate.perf_receipt_name(receipt)
    assert name.startswith("perf-" + SOURCE.commit[:12]) and "3.14.3" in name and name.endswith(".json")
    assert build_receipt(extra_reasons=["measured sample lost"])["accepted"] is False


def test_benchmark_writes_unique_attempt_and_terminal_receipt_for_fake_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(perf_gate, "source_identity", lambda repo: SOURCE, raising=False)
    measured = perf_gate.ProbeMeasurements(
        WHEEL, SCHEMA, {"version": "3.14.3", "implementation": "cpython", "executable": sys.executable},
        {"accepted": True, "samples": [{"status": "ok", "idempotency_key": "measurement-marker"}]},
        {"accepted": True}, {"accepted": True},
    )
    monkeypatch.setattr(perf_gate, "_measure", lambda repo, attempt: measured)
    outputs = []
    for _ in range(2):
        receipt, path = perf_gate.run_benchmark(tmp_path, evidence_dir=tmp_path / "evidence")
        assert path.is_file(), "a benchmark attempt must retain its terminal evidence"
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved == receipt and receipt["accepted"] is True
        claimed = saved.pop("receipt_digest")
        assert claimed == digest_bytes(canonical_json(saved))
        evidence = receipt["evidence"]
        assert isinstance(evidence, dict) and isinstance(evidence["manifest"], dict)
        assert evidence["manifest"]
        for relative, digest in evidence["manifest"].items():
            content = (path.parent / relative).read_bytes()
            assert digest == "sha256:" + hashlib.sha256(content).hexdigest()
        assert "measurement-marker" in json.dumps(receipt)
        outputs.append(path)
    assert outputs[0].parent != outputs[1].parent


@pytest.mark.parametrize("accepted", [True, False])
def test_benchmark_cli_returns_the_terminal_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, accepted: bool
) -> None:
    monkeypatch.setattr(perf_gate, "run_benchmark", lambda *args, **kwargs: (
        {"accepted": accepted}, tmp_path / "perf-fixture.json",
    ))
    assert perf_gate.main(["--evidence-dir", str(tmp_path)]) == (0 if accepted else 1)


def test_module_entrypoint_delegates_to_benchmark_main(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(perf_gate, "main", lambda: 37)
    with pytest.raises(SystemExit) as caught:
        runpy.run_path(str(Path(__file__)), run_name="__main__")
    assert caught.value.code == 37


def test_benchmark_cli_rejects_relative_evidence_directory() -> None:
    assert perf_gate.main(["--evidence-dir", "relative"]) == 2


if __name__ == "__main__":
    raise SystemExit(perf_gate.main())
