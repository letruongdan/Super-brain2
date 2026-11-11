"""Explicit Task 8 benchmark and source-bound performance evidence."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from scripts.gate import SourceIdentity, source_identity
from superbrain.cli_api._loopback_wire import encode_call
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import SHA256_DIGEST_RE, FilterPolicy, Scope, ToolCommand
from superbrain.core.wire import MCP_PROTOCOL_VERSION

WARMUP_CALLS = 10
WARM_PREPARE_SAMPLES = 200
WARM_PREPARE_P95_BUDGET_MS = 1500.0
PRIVACY_SIZES_KIB = (256, 512, 768, 1024)
PRIVACY_SAMPLES_PER_SIZE = 30
PRIVACY_LOCAL_P95_BUDGET_MS = 100.0
COLD_CLIENT_SPAWNS = 20
POSITIVE_CONTROL = "ordinary safe prose"
WARM_SPANS = (
    "t0_read_ns", "admission_done_ns", "filter_start_ns", "filter_end_ns",
    "observer_start_ns", "observer_end_ns", "commit_start_ns", "commit_end_ns",
    "response_write_start_ns", "response_flushed_ns",
)


@dataclass(frozen=True)
class ProbeMeasurements:
    wheel_digest: str | None
    schema_sha256: str | None
    interpreter: Mapping[str, JsonValue] | None
    warm_prepare: Mapping[str, JsonValue]
    privacy_local: Mapping[str, JsonValue]
    cold_client: Mapping[str, JsonValue]


def nearest_rank_percentile(values: Sequence[float], pct: int) -> float:
    if type(pct) is not int or not 1 <= pct <= 100 or not values:
        raise ValueError("percentile needs samples and an integer rank from 1 to 100")
    if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("samples must be finite nonnegative numbers")
    return float(sorted(values)[math.ceil(len(values) * pct / 100) - 1])


def _corpus(size: int, sample_index: int) -> dict[str, JsonValue]:
    # Escaped quotes contribute to the JSON size. The filter also counts node overhead.
    # Retain this margin so a canonical 1 MiB input genuinely reaches all filter passes.
    block = (
        f'safe "quoted" prose {sample_index} '
        "https://probe-user:probe-pass@example.invalid/path "
        "<private>synthetic private text</private> "
        "Ab9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV "
    )
    chunks: list[JsonValue] = []
    body: dict[str, JsonValue] = {
        "nested": {
            "details": {"apiKey": "synthetic-canary", "positive_control": POSITIVE_CONTROL},
            "chunks": chunks,
        },
        "padding": "",
    }
    base_size = len(canonical_json(body))
    while size - base_size > 8:
        left = size - base_size
        low, high = 0, min(65536, left - 3)
        while low < high:
            mid = (low + high + 1) // 2
            text = block * (mid // len(block)) + "x" * (mid % len(block))
            cost = len(canonical_json(text)) + (1 if chunks else 0)
            if cost <= left:
                low = mid
            else:
                high = mid - 1
        if low == 0:
            break
        text = block * (low // len(block)) + "x" * (low % len(block))
        chunks.append(text)
        base_size = len(canonical_json(body))
    body["padding"] = "x" * (size - len(canonical_json(body)))
    return body


def build_privacy_corpus_sample(
    size_kib: int, sample_index: int, *, policy: FilterPolicy | None = None
) -> tuple[dict[str, JsonValue], int]:
    if size_kib not in PRIVACY_SIZES_KIB or type(sample_index) is not int or sample_index < 0:
        raise ValueError("unsupported corpus size or sample index")
    payload = _corpus(size_kib * 1024, sample_index)
    return payload, len(canonical_json(payload))


def build_unclosed_private_tail_sample(size_kib: int) -> tuple[dict[str, JsonValue], int]:
    payload, _ = build_privacy_corpus_sample(size_kib, 0)
    payload["unclosed"] = "<private>synthetic unterminated tail"
    return payload, len(canonical_json(payload))


def build_wire_privacy_sample(
    *, tool_name: str = "submit_episode", policy: FilterPolicy | None = None
) -> tuple[dict[str, JsonValue], int, int]:
    if tool_name != "submit_episode":
        raise ValueError("wire corpus exercises the evidence ingress")
    args: dict[str, JsonValue] = {
        "schema_version": "2.0", "task_id": "task-perf", "session_id": "session-perf",
        "evidence": [{"kind": "fixture", "data": {}}], "idempotency_key": "perf-wire-sample00",
    }
    mcp: dict[str, JsonValue] = {
        "jsonrpc": "2.0", "id": "perf-wire", "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }
    http = encode_call(ToolCommand(
        tool_name, args, token="fixture-token", selected_scope=Scope("repo-perf", "checkout-perf"),
        correlation_id="perf-wire",
    ))
    # Keep room for the real workspace UUIDs and the shim-generated correlation ID.
    room = 1024 * 1024 - max(len(canonical_json(mcp)), len(http)) - 128
    data = _corpus(room + 2, 0)
    args["evidence"] = [{"kind": "fixture", "data": data}]
    return args, len(canonical_json(args)), len(canonical_json(mcp))


def _statistics(samples: Sequence[Mapping[str, JsonValue]], reasons: list[str]) -> dict[str, JsonValue]:
    values: list[float] = []
    for index, sample in enumerate(samples):
        elapsed = sample.get("elapsed_ns")
        if (
            isinstance(elapsed, bool) or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed) or elapsed < 0
        ):
            reasons.append(f"sample {index} has invalid elapsed time")
        else:
            values.append(float(elapsed) / 1_000_000)
    return {
        f"p{pct}_ms": nearest_rank_percentile(values, pct) if values else None
        for pct in (50, 95, 99)
    }


def _preserved(samples: Sequence[Mapping[str, JsonValue]]) -> list[JsonValue]:
    return [dict(s) for s in samples]


def evaluate_warm_prepare_probe(
    warmup: Sequence[Mapping[str, JsonValue]],
    samples: Sequence[Mapping[str, JsonValue]],
    *,
    expected_count: int = WARM_PREPARE_SAMPLES,
    p95_budget_ms: float = WARM_PREPARE_P95_BUDGET_MS,
) -> dict[str, JsonValue]:
    reasons: list[str] = []
    if len(warmup) < WARMUP_CALLS or len(samples) < expected_count:
        reasons.append("missing warmup or measured prepare samples")
    seen: set[str] = set()
    for index, sample in enumerate((*warmup, *samples)):
        key = sample.get("idempotency_key")
        if not isinstance(key, str) or not key or key in seen:
            reasons.append(f"sample {index} has a missing or replayed idempotency key")
        elif isinstance(key, str):
            seen.add(key)
        if sample.get("status") != "ok" or sample.get("delivery_verified") is not True:
            reasons.append(f"sample {index} did not verify a successful delivery")
        spans = [sample.get(name) for name in WARM_SPANS]
        if any(type(stamp) is not int for stamp in spans):
            reasons.append(f"sample {index} has missing or invalid phase timestamps")
            continue
        stamps = [int(str(stamp)) for stamp in spans]
        if stamps != sorted(stamps) or sample.get("elapsed_ns") != stamps[-1] - stamps[0]:
            reasons.append(f"sample {index} did not measure ordered phases through complete flush")
    stats = _statistics(samples, reasons)
    p95 = stats["p95_ms"]
    if isinstance(p95, (int, float)) and p95 > p95_budget_ms:
        reasons.append("warm prepare p95 exceeds its budget")
    return {
        "accepted": not reasons, "reasons": list(reasons), "warmup": _preserved(warmup),
        "samples": _preserved(samples), **stats,
    }


def evaluate_privacy_probe(
    size_buckets: Mapping[int, Sequence[Mapping[str, JsonValue]]],
    wire_samples: Sequence[Mapping[str, JsonValue]],
    *,
    expected_per_size: int = PRIVACY_SAMPLES_PER_SIZE,
    local_p95_budget_ms: float = PRIVACY_LOCAL_P95_BUDGET_MS,
) -> dict[str, JsonValue]:
    reasons: list[str] = []
    buckets: dict[str, JsonValue] = {}
    for kib in PRIVACY_SIZES_KIB:
        samples = size_buckets.get(kib, ())
        if len(samples) < expected_per_size:
            reasons.append(f"privacy {kib} KiB has missing samples")
        for index, sample in enumerate(samples):
            if not _privacy_sample_valid(sample) or sample.get("filter_bytes") != kib * 1024:
                reasons.append(f"privacy {kib} KiB sample {index} did not exercise the valid corpus")
        stats = _statistics(samples, reasons)
        p95 = stats["p95_ms"]
        if isinstance(p95, (int, float)) and p95 > local_p95_budget_ms:
            reasons.append(f"privacy {kib} KiB p95 exceeds the local budget")
        buckets[str(kib)] = {
            "samples": _preserved(samples), **stats,
            "ms_per_kib": p95 / kib if isinstance(p95, (int, float)) else None,
        }
    if not wire_samples:
        reasons.append("missing wire privacy samples")
    for index, sample in enumerate(wire_samples):
        size = sample.get("wire_bytes")
        if not _privacy_sample_valid(sample) or type(size) is not int or not 0 < size <= 1024 * 1024:
            reasons.append(f"wire privacy sample {index} did not exercise the real filter")
    first = buckets["256"]
    last = buckets["1024"]
    assert isinstance(first, dict) and isinstance(last, dict)
    a, b = first["ms_per_kib"], last["ms_per_kib"]
    growth = b / a if isinstance(a, (int, float)) and a > 0 and isinstance(b, (int, float)) else None
    return {
        "accepted": not reasons, "reasons": list(reasons), "sizes": buckets,
        "wire_samples": _preserved(wire_samples), "growth_ratio_1024_256": growth,
    }


def _privacy_sample_valid(sample: Mapping[str, JsonValue]) -> bool:
    redacted, stripped = sample.get("redacted_count"), sample.get("stripped_keys_count")
    return (
        sample.get("status") == "ok" and sample.get("filter_ran") is True
        and sample.get("rejected_before_filter") is False
        and type(redacted) is int and redacted > 0 and type(stripped) is int and stripped > 0
        and sample.get("positive_control_preserved") is True
    )


def valid_initialize_frame(frame: JsonValue) -> bool:
    if not isinstance(frame, dict) or frame.get("jsonrpc") != "2.0" or frame.get("id") != 1:
        return False
    if set(frame) != {"jsonrpc", "id", "result"} or not isinstance(frame["result"], dict):
        return False
    result = frame["result"]
    capabilities, server = result.get("capabilities"), result.get("serverInfo")
    return (
        result.get("protocolVersion") == MCP_PROTOCOL_VERSION
        and isinstance(capabilities, dict) and isinstance(capabilities.get("tools"), dict)
        and isinstance(server, dict) and isinstance(server.get("name"), str) and bool(server["name"])
        and isinstance(server.get("version"), str) and bool(server["version"])
    )


def evaluate_cold_client_probe(
    spawns_by_entrypoint: Mapping[str, Sequence[Mapping[str, JsonValue]]],
    *,
    expected_spawns: int = COLD_CLIENT_SPAWNS,
) -> dict[str, JsonValue]:
    reasons: list[str] = []
    groups: dict[str, JsonValue] = {}
    identities: set[tuple[int, int]] = set()
    for name in ("brain-mcp", "brain mcp"):
        samples = spawns_by_entrypoint.get(name, ())
        if len(samples) < expected_spawns:
            reasons.append(f"cold {name} has missing process samples")
        for index, sample in enumerate(samples):
            pid, started, frame_time = sample.get("pid"), sample.get("started_ns"), sample.get("first_frame_ns")
            if type(pid) is not int or pid < 1 or type(started) is not int or type(frame_time) is not int:
                reasons.append(f"cold {name} sample {index} has invalid process/timing identity")
            else:
                identity = (pid, started)
                if identity in identities or frame_time < started or sample.get("elapsed_ns") != frame_time - started:
                    reasons.append(f"cold {name} sample {index} reused a spawn or has invalid timing")
                identities.add(identity)
            if (
                sample.get("status") != "ok" or sample.get("valid_initialize_frame") is not True
                or not valid_initialize_frame(sample.get("first_frame"))
            ):
                reasons.append(f"cold {name} sample {index} did not return a valid initialize frame")
        groups[name] = {"samples": _preserved(samples), **_statistics(samples, reasons)}
    return {"accepted": not reasons, "reasons": list(reasons), "entrypoints": groups}


def build_perf_receipt(
    *,
    start: SourceIdentity | None,
    end: SourceIdentity | None,
    wheel_digest: str | None,
    schema_sha256: str | None,
    interpreter: Mapping[str, JsonValue] | None,
    host: Mapping[str, JsonValue],
    command: Sequence[str],
    warm_prepare: Mapping[str, JsonValue],
    privacy_local: Mapping[str, JsonValue],
    cold_client: Mapping[str, JsonValue],
    extra_reasons: Sequence[str] = (),
) -> dict[str, JsonValue]:
    reasons = list(extra_reasons)
    if start is None or end is None or start != end or not start.tree_clean or not end.tree_clean:
        reasons.append("source identity is missing, dirty or changed during the benchmark")
    for name, value in (("wheel", wheel_digest), ("schema", schema_sha256)):
        if not isinstance(value, str) or SHA256_DIGEST_RE.fullmatch(value) is None:
            reasons.append(f"missing or invalid {name} digest")
    if not interpreter or not all(isinstance(interpreter.get(k), str) and interpreter[k] for k in (
        "version", "implementation", "executable",
    )):
        reasons.append("missing observed interpreter provenance")
    for name, probe in (("warm_prepare", warm_prepare), ("privacy_local", privacy_local), ("cold_client", cold_client)):
        if probe.get("accepted") is not True:
            reasons.append(f"probe {name} was not accepted")
    receipt: dict[str, JsonValue] = {
        "accepted": not reasons, "reasons": list(reasons),
        "start": asdict(start) if start is not None else None, "end": asdict(end) if end is not None else None,
        "wheel_digest": wheel_digest, "schema_sha256": schema_sha256,
        "interpreter": dict(interpreter) if interpreter is not None else None, "host": dict(host),
        "command": list(command), "warm_prepare": dict(warm_prepare), "privacy_local": dict(privacy_local),
        "cold_client": dict(cold_client),
    }
    receipt["receipt_digest"] = digest_bytes(canonical_json(receipt))
    return receipt


def perf_receipt_name(receipt: Mapping[str, JsonValue]) -> str:
    start, runtime, host = receipt.get("start"), receipt.get("interpreter"), receipt.get("host")
    commit = str(start["commit"])[:12] if isinstance(start, dict) else "unverified"
    version = str(runtime.get("version", "unknown")).split()[0] if isinstance(runtime, dict) else "unknown"
    impl = str(runtime.get("implementation", "unknown")) if isinstance(runtime, dict) else "unknown"
    os_name = str(host.get("platform", "unknown")) if isinstance(host, dict) else "unknown"
    return f"perf-{commit}-{impl}{version}-{os_name}.json"


def _measure(repo: Path, attempt: Path) -> ProbeMeasurements:
    from scripts.perf_probe import measure

    return measure(repo, attempt)


def run_benchmark(repo: Path, *, evidence_dir: Path) -> tuple[dict[str, JsonValue], Path]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    attempt = evidence_dir / f"attempt-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}"
    attempt.mkdir()
    reasons: list[str] = []
    start = end = None
    measured = ProbeMeasurements(None, None, None, {}, {}, {})
    try:
        start = source_identity(repo)
        if start.tree_clean:
            measured = _measure(repo, attempt)
        else:
            reasons.append("source is dirty before measurement")
    except Exception as error:  # noqa: BLE001 - keep a refused benchmark receipt
        reasons.append(f"benchmark measurement failed: {type(error).__name__}")
    try:
        end = source_identity(repo)
    except (OSError, RuntimeError) as error:
        reasons.append(f"source identity failed at end: {type(error).__name__}")
    raw = canonical_json(asdict(measured))
    (attempt / "measurements.json").write_bytes(raw)
    receipt = build_perf_receipt(
        start=start, end=end, wheel_digest=measured.wheel_digest, schema_sha256=measured.schema_sha256,
        interpreter=measured.interpreter,
        host={"node": platform.node(), "cpu": platform.processor(), "machine": platform.machine(),
              "system": platform.system(), "platform": sys.platform},
        command=[
            sys.executable, "-m", "tests.integration.test_kernel_performance", "--evidence-dir", str(evidence_dir),
        ],
        warm_prepare=measured.warm_prepare, privacy_local=measured.privacy_local, cold_client=measured.cold_client,
        extra_reasons=reasons,
    )
    del receipt["receipt_digest"]
    receipt["evidence"] = {"attempt_dir": str(attempt), "manifest": {"measurements.json": digest_bytes(raw)}}
    receipt["receipt_digest"] = digest_bytes(canonical_json(receipt))
    path = attempt / perf_receipt_name(receipt)
    tmp = attempt / ".receipt.tmp"
    tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return receipt, path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure the explicit Task 8 performance probes.")
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args(argv)
    evidence = Path(args.evidence_dir)
    if not evidence.is_absolute():
        print("benchmark refused: --evidence-dir must be absolute", file=sys.stderr)
        return 2
    try:
        receipt, path = run_benchmark(Path(__file__).resolve().parents[1], evidence_dir=evidence)
    except OSError as error:
        print(f"benchmark evidence failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(f"benchmark {'ACCEPTED' if receipt['accepted'] else 'NOT ACCEPTED'} -> {path}")
    return 0 if receipt["accepted"] is True else 1
