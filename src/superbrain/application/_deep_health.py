"""Application-layer SP2-5 ``get_health(deep=true)`` preparation and stored-result rendering."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from superbrain.application.dispatch import PreparedEffect
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPTURE_GAPS_PRESENT_CODE,
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    ObjectRef,
    StoredResult,
)
from superbrain.ports.kernel import KernelTx


@dataclass(frozen=True)
class DeepHealthProbeResult:
    """Read-only SP2 diagnostic summary surfaced by ``get_health(deep=true)``."""

    store_id: str
    writer_epoch: int
    store_schema_version: int
    policy_schema_version: int
    clock_untrusted: bool
    has_open_gaps: bool
    outbox_pending: int
    active_sessions: int
    layer2_degraded: bool
    layer2_drifted: bool
    probe_errors: tuple[str, ...] = ()


def build_deep_health_payload(probe: DeepHealthProbeResult) -> dict[str, JsonValue]:
    """Render a strict ``GetHealthResult`` payload from ``DeepHealthProbeResult``."""
    degraded: list[JsonValue] = []
    if probe.clock_untrusted:
        degraded.append(IDEMPOTENCY_CLOCK_UNTRUSTED_CODE)
    if probe.has_open_gaps:
        degraded.append(CAPTURE_GAPS_PRESENT_CODE)
    if probe.outbox_pending > 0:
        degraded.append("capture_outbox_pending")
    if probe.layer2_drifted:
        degraded.append("layer2_drifted")
    if probe.layer2_degraded:
        degraded.append("layer2_unverified")
        degraded.append("terminal_channel_ineligible")
    if probe.probe_errors:
        degraded.append("sp2_probe_error")
    return {
        "ready": (not probe.clock_untrusted) and (not probe.probe_errors),
        "store_id": probe.store_id,
        "writer_epoch": probe.writer_epoch,
        "schema_version": probe.store_schema_version,
        "policy_schema_version": probe.policy_schema_version,
        "degraded_codes": degraded,
        "doctor_run_id": new_id(),
        "age_s": 0,
        "job_id": None,
    }


def prepare_deep_health_effect(probe_fn: Callable[[], DeepHealthProbeResult]) -> PreparedEffect:
    """Build a read-only ``PreparedEffect`` holding only the ``GetHealthResult`` CAS blob."""
    probe = probe_fn()
    payload = build_deep_health_payload(probe)
    blob = canonical_json(payload)
    res_id = new_id()
    ref = ObjectRef(kind="health_result", id=res_id, revision=1, digest=digest_bytes(blob))

    def _apply(tx: KernelTx) -> StoredResult:
        tx.hold_blob(blob, holder_id=res_id)
        return StoredResult(result_id=res_id, assignment_id=None, refs=(ref,))

    return PreparedEffect(blobs=(blob,), apply=_apply)


def render_deep_health_stored(result: StoredResult, read_blob: Callable[[str], bytes]) -> dict[str, JsonValue]:
    """Read back the committed ``GetHealthResult`` JSON object from CAS."""
    if not result.refs:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "health result missing ref")
    raw = read_blob(result.refs[0].digest)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "malformed stored deep health result")
    return dict(parsed)


__all__ = [
    "DeepHealthProbeResult",
    "build_deep_health_payload",
    "prepare_deep_health_effect",
    "render_deep_health_stored",
]
