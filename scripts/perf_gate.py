"""Task 8.6 interface fixture for independent pre-implementation testing."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.gate import SourceIdentity
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy

WARMUP_CALLS = 10
WARM_PREPARE_SAMPLES = 200
WARM_PREPARE_P95_BUDGET_MS = 1500.0
PRIVACY_SIZES_KIB = (256, 512, 768, 1024)
PRIVACY_SAMPLES_PER_SIZE = 30
PRIVACY_LOCAL_P95_BUDGET_MS = 100.0
COLD_CLIENT_SPAWNS = 20


@dataclass(frozen=True)
class ProbeMeasurements:
    wheel_digest: str | None
    schema_sha256: str | None
    interpreter: Mapping[str, JsonValue] | None
    warm_prepare: Mapping[str, JsonValue]
    privacy_local: Mapping[str, JsonValue]
    cold_client: Mapping[str, JsonValue]


def nearest_rank_percentile(values: Sequence[float], pct: int) -> float:
    return 0.0


def build_privacy_corpus_sample(
    size_kib: int, sample_index: int, *, policy: FilterPolicy | None = None
) -> tuple[dict[str, JsonValue], int]:
    return {}, 0


def build_unclosed_private_tail_sample(size_kib: int) -> tuple[dict[str, JsonValue], int]:
    return {}, 0


def build_wire_privacy_sample(
    *, tool_name: str = "submit_episode", policy: FilterPolicy | None = None
) -> tuple[dict[str, JsonValue], int, int]:
    return {}, 0, 0


def evaluate_warm_prepare_probe(
    warmup: Sequence[Mapping[str, JsonValue]],
    samples: Sequence[Mapping[str, JsonValue]],
    *,
    expected_count: int = WARM_PREPARE_SAMPLES,
    p95_budget_ms: float = WARM_PREPARE_P95_BUDGET_MS,
) -> dict[str, JsonValue]:
    return {"accepted": False, "warmup": [dict(s) for s in warmup], "samples": [dict(s) for s in samples]}


def evaluate_privacy_probe(
    size_buckets: Mapping[int, Sequence[Mapping[str, JsonValue]]],
    wire_samples: Sequence[Mapping[str, JsonValue]],
    *,
    expected_per_size: int = PRIVACY_SAMPLES_PER_SIZE,
    local_p95_budget_ms: float = PRIVACY_LOCAL_P95_BUDGET_MS,
) -> dict[str, JsonValue]:
    return {"accepted": False, "sizes": {}, "wire_samples": [dict(s) for s in wire_samples]}


def evaluate_cold_client_probe(
    spawns_by_entrypoint: Mapping[str, Sequence[Mapping[str, JsonValue]]],
    *,
    expected_spawns: int = COLD_CLIENT_SPAWNS,
) -> dict[str, JsonValue]:
    return {"accepted": False, "entrypoints": {}}


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
    return {"accepted": False, "reasons": list(extra_reasons)}


def perf_receipt_name(receipt: Mapping[str, JsonValue]) -> str:
    return "perf-unverified.json"


def _measure(repo: Path, attempt: Path) -> ProbeMeasurements:
    return ProbeMeasurements(None, None, None, {}, {}, {})


def run_benchmark(repo: Path, *, evidence_dir: Path) -> tuple[dict[str, JsonValue], Path]:
    return {"accepted": False}, evidence_dir / "perf-unverified.json"


def main(argv: Sequence[str] | None = None) -> int:
    return 2
