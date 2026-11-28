"""Capture continuity port contracts shared across domain, storage, application, and composition."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from superbrain.core._json_parse import MAX_WIRE_BODY_BYTES
from superbrain.core._kernel_base import (
    is_strict_int,
    require_non_negative_int,
    require_object_kind,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._kernel_workspace import FilterPolicy, SafePayload
from superbrain.core.canonical import canonical_json, digest_bytes, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

DEFAULT_OUTBOX_MAX_BYTES = 104_857_600
"""Default per-outbox disk cap (100 MiB = 104,857,600 bytes)."""
MAX_CAPTURE_SEQUENCE = (1 << 63) - 1
"""Maximum valid capture sequence fitting signed 64-bit SQLite storage."""
CAPTURE_WIRE_OVERHEAD_RESERVE_BYTES = 4096
"""Reserved bytes below ``MAX_WIRE_BODY_BYTES`` for loopback batch envelope metadata."""
MAX_CAPTURE_ENTRY_BYTES = MAX_WIRE_BODY_BYTES - CAPTURE_WIRE_OVERHEAD_RESERVE_BYTES
"""Maximum canonical serialized bytes for any single capture record."""
HOOK_TARGET_BUDGET_NS = 100_000_000
"""Warm hook target latency budget (100 ms)."""
HOOK_HARD_CAP_NS = 2_000_000_000
"""Hard wall/monotonic cap for a single hook execution (2 s)."""
MAX_CAPTURE_BATCH_EVENTS = 1024
"""Maximum entries allowed in a single capture ingest batch."""
OUTBOX_RECORD_EVENT = "event"
OUTBOX_RECORD_GAP = "capture_gap"

CAPTURE_GAP_REASONS: frozenset[str] = frozenset(
    {
        "hook_timeout",
        "outbox_full",
        "privacy_rejected",
        "corrupted_tail",
        "daemon_rejected",
        "policy_disabled",
        "dropped",
    }
)

EVENT_SOURCES: frozenset[str] = frozenset({"tool_observed", "unknown"})
EVENT_SOURCE_VERIFICATIONS: frozenset[str] = frozenset({"verified_host", "unverified", "unavailable"})

FORBIDDEN_CLIENT_CAPTURE_KEYS: frozenset[str] = frozenset(
    {"source", "source_verification", "exposure_evidence", "session_id", "raw_session_id"}
)

_ISO_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")

_EVENT_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "record_kind", "event_id", "producer_stream", "sequence", "harness_id",
        "kind", "recorded_at", "payload", "session_ref", "source_metadata",
    }
)
_GAP_ALLOWED_KEYS: frozenset[str] = frozenset(
    {"record_kind", "gap_id", "producer_stream", "sequence", "reason", "recorded_at", "estimated_count", "duration_ms"}
)


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def require_capture_sequence(value: object) -> int:
    """Validate a capture sequence within ``1..MAX_CAPTURE_SEQUENCE`` (signed 64-bit SQLite range)."""
    seq = require_positive_int(value)
    if seq > MAX_CAPTURE_SEQUENCE:
        raise _invalid()
    return seq


def require_iso_utc_timestamp(value: object) -> str:
    """Validate an ISO-8601 UTC timestamp terminating in ``Z`` (with optional 1..6 fractional digits)."""
    if not isinstance(value, str) or _ISO_UTC_RE.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as err:
        raise _invalid() from err
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise _invalid()
    _ = parsed.astimezone(UTC)
    return value


def assert_no_forbidden_capture_keys(value: object) -> None:
    """Fail closed if any client-supplied mapping contains forged authority or raw session keys."""
    stack: list[object] = [value]
    while stack:
        cur = stack.pop()
        if isinstance(cur, Mapping):
            for key, item in cur.items():
                if not isinstance(key, str):
                    raise _invalid()
                if key in FORBIDDEN_CLIENT_CAPTURE_KEYS:
                    raise _invalid()
                stack.append(item)
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)


def _clone_json(value: object) -> JsonValue:
    """Deep-copy pure JSON containers into fresh mutable Python values."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, JsonValue] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise _invalid()
            out[k] = _clone_json(v)
        return out
    if isinstance(value, list):
        return [_clone_json(item) for item in value]
    raise _invalid()


def freeze_json_mapping(raw: object) -> dict[str, JsonValue]:
    """Validate and deeply detach a JSON object mapping into a fresh mutable ``dict``."""
    if not isinstance(raw, Mapping):
        raise _invalid()
    cloned_raw: dict[str, JsonValue] = {}
    for k, v in raw.items():
        if not isinstance(k, str):
            raise _invalid()
        cloned_raw[k] = _clone_json(v)
    validate_json(cloned_raw)
    assert_no_forbidden_capture_keys(cloned_raw)
    return cloned_raw


def clone_json_mapping(raw: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Produce a fresh deep-copied mutable dict from a validated JSON mapping."""
    out: dict[str, JsonValue] = {}
    for k, v in raw.items():
        out[k] = _clone_json(v)
    return out


class CapturePrivacyFilterPort(Protocol):
    """Port implemented by ``application.privacy.PrivacyFilter`` for D6 capture payload sanitization."""

    def apply(
        self,
        payload: JsonValue,
        policy: FilterPolicy,
        *,
        deadline_ns: int | None = None,
    ) -> SafePayload: ...


class OutboxPermissionsPort(Protocol):
    """Minimal permission adapter protocol for ``storage.outbox.OutboxSpool``."""

    def secure_directory(self, path: Path) -> None: ...

    def secure_file(self, path: Path) -> None: ...

    def problems(self, path: Path) -> Sequence[object]: ...


class OutboxFileLockPort(Protocol):
    """Non-blocking kernel file-lock adapter protocol for ``storage.outbox.OutboxSpool``."""

    def try_lock_fd(self, fd: int) -> bool: ...

    def unlock_fd(self, fd: int) -> None: ...


OutboxDirRenamer = Callable[[Path, Path], None]
OutboxDirSync = Callable[[Path], None]

_DEFAULT_OUTBOX_FILE_LOCK: OutboxFileLockPort | None = None
_DEFAULT_OUTBOX_PERMISSIONS: OutboxPermissionsPort | None = None
_DEFAULT_OUTBOX_DIR_RENAMER: OutboxDirRenamer | None = None
_DEFAULT_OUTBOX_DIR_SYNC: OutboxDirSync | None = None


def register_outbox_file_lock(adapter: OutboxFileLockPort) -> None:
    """Register the process-wide OS file-lock adapter used by ``OutboxSpool`` by default."""
    global _DEFAULT_OUTBOX_FILE_LOCK
    _DEFAULT_OUTBOX_FILE_LOCK = adapter


def default_outbox_file_lock() -> OutboxFileLockPort | None:
    """Return the registered OS file-lock adapter, or ``None`` if OS adapters have not loaded."""
    return _DEFAULT_OUTBOX_FILE_LOCK


def register_outbox_permissions(adapter: OutboxPermissionsPort) -> None:
    """Register the process-wide OS permission adapter used by ``OutboxSpool`` by default."""
    global _DEFAULT_OUTBOX_PERMISSIONS
    _DEFAULT_OUTBOX_PERMISSIONS = adapter


def default_outbox_permissions() -> OutboxPermissionsPort | None:
    """Return the registered OS permission adapter, or ``None`` if OS adapters have not loaded."""
    return _DEFAULT_OUTBOX_PERMISSIONS


def register_outbox_dir_renamer(renamer: OutboxDirRenamer) -> None:
    """Register the process-wide atomic no-replace directory rename helper."""
    global _DEFAULT_OUTBOX_DIR_RENAMER
    _DEFAULT_OUTBOX_DIR_RENAMER = renamer


def default_outbox_dir_renamer() -> OutboxDirRenamer | None:
    """Return the registered atomic directory renamer, or ``None`` if OS adapters have not loaded."""
    return _DEFAULT_OUTBOX_DIR_RENAMER


def register_outbox_dir_sync(sync_fn: OutboxDirSync) -> None:
    """Register the process-wide OS directory-fsync helper used by ``OutboxSpool``."""
    global _DEFAULT_OUTBOX_DIR_SYNC
    _DEFAULT_OUTBOX_DIR_SYNC = sync_fn


def default_outbox_dir_sync() -> OutboxDirSync | None:
    """Return the registered directory-fsync helper, or ``None`` if OS adapters have not loaded."""
    return _DEFAULT_OUTBOX_DIR_SYNC


@dataclass(frozen=True)
class StagedCaptureEvent:
    """Privacy-filtered event paired with canonical payload digest/bytes and server attribution."""

    record: CaptureEventRecord
    payload_bytes: bytes
    payload_digest: str
    source: str
    source_verification: str

    def __post_init__(self) -> None:
        if not isinstance(self.record, CaptureEventRecord):
            raise _invalid()
        if type(self.payload_bytes) is not bytes:
            raise _invalid()
        require_sha256_digest(self.payload_digest)
        if self.source not in EVENT_SOURCES:
            raise _invalid()
        if self.source_verification not in EVENT_SOURCE_VERIFICATIONS:
            raise _invalid()


def compute_contiguous_event_acked_through(committed_sequences: Iterable[int]) -> int:
    """Return the highest ``k >= 0`` such that ``1..k`` are all in ``committed_sequences``."""
    present = {require_positive_int(seq) for seq in committed_sequences}
    high = 0
    while (high + 1) in present:
        high += 1
    return high


class CaptureStorePort(Protocol):
    """Port implemented by ``storage.capture_events.KernelCaptureStore``."""

    def commit_staged_batch(
        self,
        *,
        producer_stream: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        events: Sequence[StagedCaptureEvent],
        gaps: Sequence[ProducerCaptureGap],
        now: datetime,
        on_event_committed_in_tx: Callable[[Any, StagedCaptureEvent], None] | None = None,
    ) -> CaptureBatchAck: ...

    def mark_daemon_gap_closed(
        self,
        *,
        producer_stream: str,
        sequence: int,
        now: datetime,
        repo_id: str | None = None,
        checkout_id: str | None = None,
    ) -> None: ...

    def read_capture_health(self) -> CaptureHealthSnapshot: ...

    def has_gaps(self) -> bool: ...


def _enforce_capture_entry_size(record_dict: Mapping[str, JsonValue]) -> None:
    if len(canonical_json(record_dict)) > MAX_CAPTURE_ENTRY_BYTES:
        raise _invalid()


@dataclass(frozen=True)
class CaptureEventRecord:
    """Normalized untrusted hook/transcript capture event envelope (before host attribution)."""

    event_id: str
    producer_stream: str
    sequence: int
    harness_id: str
    kind: str
    recorded_at: str
    payload: dict[str, JsonValue]
    session_ref: str | None = None
    source_metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_opaque_id(self.event_id, label="event_id")
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_capture_sequence(self.sequence)
        require_opaque_id(self.harness_id, label="harness_id")
        require_object_kind(self.kind)
        require_iso_utc_timestamp(self.recorded_at)
        if self.session_ref is not None:
            require_sha256_digest(self.session_ref)
        object.__setattr__(self, "payload", freeze_json_mapping(self.payload))
        object.__setattr__(self, "source_metadata", freeze_json_mapping(self.source_metadata))
        _enforce_capture_entry_size(self.to_dict())

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "record_kind": OUTBOX_RECORD_EVENT, "event_id": self.event_id,
            "producer_stream": self.producer_stream, "sequence": self.sequence,
            "harness_id": self.harness_id, "kind": self.kind, "recorded_at": self.recorded_at,
            "payload": clone_json_mapping(self.payload), "session_ref": self.session_ref,
            "source_metadata": clone_json_mapping(self.source_metadata),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> CaptureEventRecord:
        if not isinstance(raw, Mapping):
            raise _invalid()
        assert_no_forbidden_capture_keys(raw)
        if not set(raw) <= _EVENT_ALLOWED_KEYS:
            raise _invalid()
        record_kind = raw.get("record_kind")
        if record_kind is not None and record_kind != OUTBOX_RECORD_EVENT:
            raise _invalid()
        required = ("event_id", "producer_stream", "sequence", "harness_id", "kind", "recorded_at", "payload")
        if any(key not in raw for key in required):
            raise _invalid()
        event_id, producer_stream, sequence = raw["event_id"], raw["producer_stream"], raw["sequence"]
        harness_id, kind, recorded_at, payload = raw["harness_id"], raw["kind"], raw["recorded_at"], raw["payload"]
        session_ref, source_metadata = raw.get("session_ref"), raw.get("source_metadata")
        if (
            not isinstance(event_id, str) or not isinstance(producer_stream, str)
            or not is_strict_int(sequence) or not isinstance(harness_id, str)
            or not isinstance(kind, str) or not isinstance(recorded_at, str)
            or not isinstance(payload, Mapping)
        ):
            raise _invalid()
        assert isinstance(sequence, int)
        if session_ref is not None and not isinstance(session_ref, str):
            raise _invalid()
        if source_metadata is None:
            resolved_meta: dict[str, JsonValue] = {}
        elif isinstance(source_metadata, Mapping):
            resolved_meta = clone_json_mapping(source_metadata)
        else:
            raise _invalid()
        return cls(
            event_id=event_id, producer_stream=producer_stream, sequence=sequence,
            harness_id=harness_id, kind=kind, recorded_at=recorded_at,
            payload=clone_json_mapping(payload), session_ref=session_ref, source_metadata=resolved_meta,
        )


@dataclass(frozen=True)
class ProducerCaptureGap:
    """Explicit capture discontinuity emitted at the producer boundary (timeout, spool full, drop)."""

    gap_id: str
    producer_stream: str
    sequence: int
    reason: str
    recorded_at: str
    estimated_count: int = 1
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.gap_id, label="gap_id")
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_capture_sequence(self.sequence)
        if not isinstance(self.reason, str) or self.reason not in CAPTURE_GAP_REASONS:
            raise _invalid()
        require_iso_utc_timestamp(self.recorded_at)
        require_positive_int(self.estimated_count)
        if self.duration_ms is not None:
            require_non_negative_int(self.duration_ms)
        _enforce_capture_entry_size(self.to_dict())

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "record_kind": OUTBOX_RECORD_GAP, "gap_id": self.gap_id,
            "producer_stream": self.producer_stream, "sequence": self.sequence,
            "reason": self.reason, "recorded_at": self.recorded_at,
            "estimated_count": self.estimated_count, "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> ProducerCaptureGap:
        if not isinstance(raw, Mapping):
            raise _invalid()
        assert_no_forbidden_capture_keys(raw)
        if not set(raw) <= _GAP_ALLOWED_KEYS:
            raise _invalid()
        record_kind = raw.get("record_kind")
        if record_kind is not None and record_kind != OUTBOX_RECORD_GAP:
            raise _invalid()
        required = ("gap_id", "producer_stream", "sequence", "reason", "recorded_at")
        if any(key not in raw for key in required):
            raise _invalid()
        gap_id, producer_stream, sequence = raw["gap_id"], raw["producer_stream"], raw["sequence"]
        reason, recorded_at = raw["reason"], raw["recorded_at"]
        estimated_count, duration_ms = raw.get("estimated_count", 1), raw.get("duration_ms")
        if (
            not isinstance(gap_id, str) or not isinstance(producer_stream, str)
            or not is_strict_int(sequence) or not isinstance(reason, str)
            or not isinstance(recorded_at, str) or not is_strict_int(estimated_count)
        ):
            raise _invalid()
        assert isinstance(sequence, int) and isinstance(estimated_count, int)
        if duration_ms is not None and not is_strict_int(duration_ms):
            raise _invalid()
        assert duration_ms is None or isinstance(duration_ms, int)
        return cls(
            gap_id=gap_id, producer_stream=producer_stream, sequence=sequence,
            reason=reason, recorded_at=recorded_at, estimated_count=estimated_count, duration_ms=duration_ms,
        )


@dataclass(frozen=True)
class OutboxEntry:
    """Materialized durable spool frame metadata returned by ``OutboxSpool.read_pending``."""

    record_kind: str
    producer_stream: str
    sequence: int
    entry_id: str
    payload_json: str
    payload_digest: str
    byte_size: int

    def __post_init__(self) -> None:
        if self.record_kind not in (OUTBOX_RECORD_EVENT, OUTBOX_RECORD_GAP):
            raise _invalid()
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_capture_sequence(self.sequence)
        require_opaque_id(self.entry_id, label="entry_id")
        if not isinstance(self.payload_json, str) or not self.payload_json:
            raise _invalid()
        require_sha256_digest(self.payload_digest)
        require_positive_int(self.byte_size)
        if self.byte_size > MAX_CAPTURE_ENTRY_BYTES:
            raise _invalid()


def _req_str_field(raw: Mapping[str, JsonValue], key: str) -> str:
    val = raw[key]
    if not isinstance(val, str):
        raise _invalid()
    return val


def _req_int_field(raw: Mapping[str, JsonValue], key: str) -> int:
    val = raw[key]
    if not is_strict_int(val):
        raise _invalid()
    assert isinstance(val, int)
    return val


@dataclass(frozen=True)
class CaptureBatchAck:
    """Separated post-COMMIT acknowledgment for ``POST /v2/capture/events``."""

    producer_stream: str
    repo_id: str
    checkout_id: str
    committed_event_sequences: tuple[int, ...]
    contiguous_event_acked_through: int
    acked_producer_gap_sequences: tuple[int, ...]
    accepted_count: int
    deduped_count: int
    policy_disabled: bool = False

    def __post_init__(self) -> None:
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")
        if isinstance(self.committed_event_sequences, (str, bytes)) or not isinstance(
            self.committed_event_sequences, Sequence
        ):
            raise _invalid()
        ev_seqs = tuple(require_capture_sequence(seq) for seq in self.committed_event_sequences)
        object.__setattr__(self, "committed_event_sequences", ev_seqs)
        require_non_negative_int(self.contiguous_event_acked_through)
        if self.contiguous_event_acked_through > MAX_CAPTURE_SEQUENCE:
            raise _invalid()
        if isinstance(self.acked_producer_gap_sequences, (str, bytes)) or not isinstance(
            self.acked_producer_gap_sequences, Sequence
        ):
            raise _invalid()
        gap_seqs = tuple(require_capture_sequence(seq) for seq in self.acked_producer_gap_sequences)
        object.__setattr__(self, "acked_producer_gap_sequences", gap_seqs)
        require_non_negative_int(self.accepted_count)
        require_non_negative_int(self.deduped_count)
        if not isinstance(self.policy_disabled, bool):
            raise _invalid()

    def allows_eviction(self, record_kind: str, sequence: int) -> bool:
        """Whether an outbox entry of ``record_kind`` at ``sequence`` may be evicted by this ACK."""
        if record_kind not in (OUTBOX_RECORD_EVENT, OUTBOX_RECORD_GAP):
            raise _invalid()
        require_capture_sequence(sequence)
        if self.policy_disabled:
            return False
        if record_kind == OUTBOX_RECORD_EVENT:
            return sequence <= self.contiguous_event_acked_through or sequence in self.committed_event_sequences
        return sequence in self.acked_producer_gap_sequences

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "producer_stream": self.producer_stream, "repo_id": self.repo_id, "checkout_id": self.checkout_id,
            "committed_event_sequences": list(self.committed_event_sequences),
            "contiguous_event_acked_through": self.contiguous_event_acked_through,
            "acked_producer_gap_sequences": list(self.acked_producer_gap_sequences),
            "accepted_count": self.accepted_count, "deduped_count": self.deduped_count,
            "policy_disabled": self.policy_disabled,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> CaptureBatchAck:
        expected = {"producer_stream", "repo_id", "checkout_id", "committed_event_sequences",
            "contiguous_event_acked_through", "acked_producer_gap_sequences", "accepted_count", "deduped_count",
            "policy_disabled"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise _invalid()
        ev_raw, gap_raw = raw["committed_event_sequences"], raw["acked_producer_gap_sequences"]
        pd = raw["policy_disabled"]
        if not isinstance(ev_raw, list) or not isinstance(gap_raw, list) or not isinstance(pd, bool):
            raise _invalid()
        return cls(
            producer_stream=_req_str_field(raw, "producer_stream"), repo_id=_req_str_field(raw, "repo_id"),
            checkout_id=_req_str_field(raw, "checkout_id"),
            committed_event_sequences=tuple(require_capture_sequence(x) for x in ev_raw),
            contiguous_event_acked_through=_req_int_field(raw, "contiguous_event_acked_through"),
            acked_producer_gap_sequences=tuple(require_capture_sequence(x) for x in gap_raw),
            accepted_count=_req_int_field(raw, "accepted_count"), deduped_count=_req_int_field(raw, "deduped_count"),
            policy_disabled=pd,
        )


@dataclass(frozen=True)
class CaptureHealthSnapshot:
    """Durable store v6 capture continuity health summary."""

    total_events: int
    open_gaps: int
    closed_gaps: int
    producer_gaps: int

    def __post_init__(self) -> None:
        for val in (self.total_events, self.open_gaps, self.closed_gaps, self.producer_gaps):
            require_non_negative_int(val)

    @property
    def has_gaps(self) -> bool:
        return (self.open_gaps + self.closed_gaps + self.producer_gaps) > 0

    def to_dict(self) -> dict[str, JsonValue]:
        return {"total_events": self.total_events, "open_gaps": self.open_gaps, "closed_gaps": self.closed_gaps,
            "producer_gaps": self.producer_gaps, "has_gaps": self.has_gaps}


def fallback_gap_id(producer_stream: str, sequence: int) -> str:
    """Gap id derived from the slot, so every fallback for one slot names the same gap (hook/daemon contract)."""
    slot = (producer_stream + "\n" + str(sequence)).encode()
    return "gap-" + digest_bytes(slot)[7:39]


__all__ = [
    "CAPTURE_GAP_REASONS", "CAPTURE_WIRE_OVERHEAD_RESERVE_BYTES", "DEFAULT_OUTBOX_MAX_BYTES",
    "EVENT_SOURCES", "EVENT_SOURCE_VERIFICATIONS", "FORBIDDEN_CLIENT_CAPTURE_KEYS", "HOOK_HARD_CAP_NS",
    "HOOK_TARGET_BUDGET_NS", "MAX_CAPTURE_BATCH_EVENTS", "MAX_CAPTURE_ENTRY_BYTES", "MAX_CAPTURE_SEQUENCE",
    "OUTBOX_RECORD_EVENT", "OUTBOX_RECORD_GAP", "CaptureBatchAck", "CaptureEventRecord", "CaptureHealthSnapshot",
    "CapturePrivacyFilterPort", "CaptureStorePort", "OutboxDirRenamer", "OutboxDirSync", "OutboxEntry",
    "OutboxFileLockPort", "OutboxPermissionsPort", "ProducerCaptureGap", "StagedCaptureEvent",
    "assert_no_forbidden_capture_keys", "clone_json_mapping", "compute_contiguous_event_acked_through",
    "default_outbox_dir_renamer", "fallback_gap_id", "default_outbox_dir_sync", "default_outbox_file_lock",
    "default_outbox_permissions", "freeze_json_mapping", "register_outbox_dir_renamer", "register_outbox_dir_sync",
    "register_outbox_file_lock", "register_outbox_permissions", "require_capture_sequence", "require_iso_utc_timestamp",
]
