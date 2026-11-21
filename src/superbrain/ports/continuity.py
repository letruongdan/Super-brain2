"""Domain-neutral session, segment, exposure, checkpoint, and continuity worker ports (SP2-3)."""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from superbrain.core._kernel_base import (
    ObjectRef,
    is_strict_int,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import CaptureEventRecord, require_iso_utc_timestamp

CONTINUITY_REFRESH_JOB_KIND = "continuity.refresh"
WORKER_EVENT_THRESHOLD = 20
WORKER_MAX_AGE_S = 60
SESSION_ACTIVE_IDLE_S = 300
SESSION_UNKNOWN_CHECKPOINT_IDLE_S = 1800
SESSION_HMAC_KEY_BYTES = 32
EVENT_KINDS_ENDING_SESSION: frozenset[str] = frozenset({"session_end", "session_ended"})
EVENT_KINDS_RESUMING_SESSION: frozenset[str] = frozenset({"session_resumed"})


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _require_text(value: object, *, label: str, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise _invalid()
    return value


def _require_digest_or_unknown(value: object) -> str:
    if value == "unknown":
        return "unknown"
    require_sha256_digest(value)
    assert isinstance(value, str)
    return value


class ExposureEvidence(StrEnum):
    """Source item exposure classification per SessionSegment (spec §7.2)."""

    SENT_TO_RECIPIENT = "sent_to_recipient"
    LOCAL_ONLY = "local_only"
    UNKNOWN = "unknown"


class SessionState(StrEnum):
    """Session liveness states (spec §7.3 & SP2-3)."""

    ACTIVE = "active"
    IN_PROGRESS_UNKNOWN = "in_progress_unknown"
    ENDED = "ended"


@dataclass(frozen=True)
class RecipientProfile:
    """Verified or partial recipient identity tuple defining a ``SessionSegment``."""

    harness_id: str
    provider_endpoint_digest: str
    model_config_digest: str
    account_digest: str

    def __post_init__(self) -> None:
        if self.harness_id != "unknown":
            require_opaque_id(self.harness_id, label="harness_id")
        _require_digest_or_unknown(self.provider_endpoint_digest)
        _require_digest_or_unknown(self.model_config_digest)
        _require_digest_or_unknown(self.account_digest)

    @property
    def is_complete(self) -> bool:
        return "unknown" not in (
            self.harness_id,
            self.provider_endpoint_digest,
            self.model_config_digest,
            self.account_digest,
        )

    def segment_key(self) -> tuple[str, str, str, str]:
        return (
            self.harness_id,
            self.provider_endpoint_digest,
            self.model_config_digest,
            self.account_digest,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "account_digest": self.account_digest,
            "harness_id": self.harness_id,
            "model_config_digest": self.model_config_digest,
            "provider_endpoint_digest": self.provider_endpoint_digest,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> RecipientProfile:
        expected = {"harness_id", "provider_endpoint_digest", "model_config_digest", "account_digest"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise _invalid()
        return cls(
            harness_id=str(raw["harness_id"]),
            provider_endpoint_digest=str(raw["provider_endpoint_digest"]),
            model_config_digest=str(raw["model_config_digest"]),
            account_digest=str(raw["account_digest"]),
        )


@dataclass(frozen=True)
class SessionSegmentRecord:
    """One contiguous recipient profile window under a ``session_ref``."""

    segment_id: str
    session_ref: str
    segment_index: int
    profile: RecipientProfile
    opened_at: str

    def __post_init__(self) -> None:
        require_opaque_id(self.segment_id, label="segment_id")
        require_sha256_digest(self.session_ref)
        require_positive_int(self.segment_index)
        if not isinstance(self.profile, RecipientProfile):
            raise _invalid()
        require_iso_utc_timestamp(self.opened_at)


@dataclass(frozen=True)
class SessionRecord:
    """Dual-store projected session record (never contains raw ``session_id``)."""

    session_ref: str
    repo_id: str
    checkout_id: str
    principal_id: str
    harness_id: str
    state: SessionState
    last_event_at: str
    active_segment_id: str | None = None
    ended_at: str | None = None

    def __post_init__(self) -> None:
        require_sha256_digest(self.session_ref)
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.harness_id, label="harness_id")
        if not isinstance(self.state, SessionState):
            raise _invalid()
        require_iso_utc_timestamp(self.last_event_at)
        if self.active_segment_id is not None:
            require_opaque_id(self.active_segment_id, label="active_segment_id")
        if self.ended_at is not None:
            require_iso_utc_timestamp(self.ended_at)


@dataclass(frozen=True)
class SessionBindingRecord:
    """Policy store append-only binding row for one ``session_ref``."""

    session_ref: str
    principal_id: str
    repo_id: str | None = None
    checkout_id: str | None = None
    harness_id: str | None = None
    bound_at: str = ""

    def __post_init__(self) -> None:
        require_sha256_digest(self.session_ref)
        require_opaque_id(self.principal_id, label="principal_id")
        if self.repo_id is not None:
            require_opaque_id(self.repo_id, label="repo_id")
        if self.checkout_id is not None:
            require_opaque_id(self.checkout_id, label="checkout_id")
        if self.harness_id is not None:
            require_opaque_id(self.harness_id, label="harness_id")
        if self.bound_at:
            require_iso_utc_timestamp(self.bound_at)


@dataclass(frozen=True)
class ModelExchangeProof:
    """Verified adapter proof linking an item digest to a completed model exchange."""

    item_digest: str
    segment_id: str
    completed_model_call_id: str
    completed: bool
    recipient_profile: RecipientProfile

    def __post_init__(self) -> None:
        require_sha256_digest(self.item_digest)
        require_opaque_id(self.segment_id, label="segment_id")
        require_opaque_id(self.completed_model_call_id, label="completed_model_call_id")
        if type(self.completed) is not bool or not isinstance(self.recipient_profile, RecipientProfile):
            raise _invalid()


@dataclass(frozen=True)
class LongRunningCheckpoint:
    """Structured checkpoint metadata for long-running external processes (spec §7.3)."""

    command: str
    cwd: str
    source_revision: str
    pid: int | None
    started_at: str
    log_or_receipt_path: str | None
    next_action: str

    def __post_init__(self) -> None:
        _require_text(self.command, label="command")
        _require_text(self.cwd, label="cwd")
        _require_text(self.source_revision, label="source_revision", max_len=256)
        _require_text(self.next_action, label="next_action")
        if self.pid is not None:
            require_positive_int(self.pid)
        if not self.started_at:
            raise _invalid()
        require_iso_utc_timestamp(self.started_at)
        if self.log_or_receipt_path is not None:
            _require_text(self.log_or_receipt_path, label="log_or_receipt_path")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "command": self.command,
            "cwd": self.cwd,
            "log_or_receipt_path": self.log_or_receipt_path,
            "next_action": self.next_action,
            "pid": self.pid,
            "source_revision": self.source_revision,
            "started_at": self.started_at,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> LongRunningCheckpoint:
        expected = {
            "command",
            "cwd",
            "source_revision",
            "pid",
            "started_at",
            "log_or_receipt_path",
            "next_action",
        }
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise _invalid()
        raw_pid = raw["pid"]
        if raw_pid is not None and (not is_strict_int(raw_pid) or not isinstance(raw_pid, int)):
            raise _invalid()
        pid_val: int | None = raw_pid
        raw_log = raw["log_or_receipt_path"]
        if raw_log is not None and not isinstance(raw_log, str):
            raise _invalid()
        return cls(
            command=str(raw["command"]),
            cwd=str(raw["cwd"]),
            source_revision=str(raw["source_revision"]),
            pid=pid_val,
            started_at=str(raw["started_at"]),
            log_or_receipt_path=raw_log,
            next_action=str(raw["next_action"]),
        )


@dataclass(frozen=True)
class LivenessDecision:
    """Result of pure session liveness classification."""

    state: SessionState
    active_takeover_warning: bool
    requires_acknowledge_active: bool
    should_create_unknown_checkpoint: bool


@dataclass(frozen=True)
class TestRunSignal:
    """Structured test command execution signal extracted by deterministic worker rules."""

    command: str
    exit_code: int
    recorded_at: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {"command": self.command, "exit_code": self.exit_code, "recorded_at": self.recorded_at}


@dataclass(frozen=True)
class ErrorSignatureSignal:
    """Repeated or distinct error signature detected from events."""

    signature: str
    count: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {"count": self.count, "signature": self.signature}


@dataclass(frozen=True)
class ObservedSummary:
    """Deterministic worker observation bundle (staged outside SQLite before owner commit)."""

    latest_high_seq: int
    last_event_at: str | None
    test_runs: tuple[TestRunSignal, ...]
    error_signatures: tuple[ErrorSignatureSignal, ...]
    modified_files: tuple[str, ...]
    user_corrections: tuple[str, ...]
    long_running: LongRunningCheckpoint | None
    item_count: int
    source_events: tuple[tuple[str, int, str, str], ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "error_signatures": [e.to_dict() for e in self.error_signatures],
            "item_count": self.item_count,
            "last_event_at": self.last_event_at,
            "latest_high_seq": self.latest_high_seq,
            "long_running": self.long_running.to_dict() if self.long_running is not None else None,
            "modified_files": list(self.modified_files),
            "source_events": [list(item) for item in self.source_events],
            "test_runs": [t.to_dict() for t in self.test_runs],
            "user_corrections": list(self.user_corrections),
        }


@dataclass(frozen=True)
class TaskHandoffRecord:
    """Live SP2-3 task handoff metadata & dual-ref revision state."""

    task_id: str
    artifact_id: str
    repo_id: str
    checkout_id: str
    current_revision: int
    current_revision_epoch: int
    handoff_revision: int
    writer_generation: int
    agent_ref: str | None
    observed_ref: str | None
    task_state: str
    task_state_source: str
    holder_principal: str | None = None
    holder_session_ref: str | None = None
    agent_updated_at: str | None = None
    observed_through: str | None = None


@dataclass(frozen=True)
class ContinuityWorkerState:
    """Per-task continuity refresh scheduling state in ``continuity_refresh_state``."""

    task_id: str
    owner_id: str
    repo_id: str
    checkout_id: str
    pending_event_count: int
    first_pending_event_at: str | None
    observed_through: str | None
    dirty_flag: bool
    active_job_id: str | None
    pending_job_id: str | None


@dataclass(frozen=True)
class ContinuityEventRow:
    """Minimal stored event snapshot exported by ``ContinuityStorePort`` for refresh extraction."""

    producer_stream: str
    sequence: int
    record: CaptureEventRecord
    payload_digest: str


@dataclass(frozen=True)
class ContinuityCommitOutcome:
    """Result returned by Phase 3 owner commit when ``continuity.refresh`` commits."""

    task_id: str
    job_id: str
    observed_ref: str
    current_revision: int
    handoff_revision: int
    dirty_followup_job_id: str | None = None


def compute_hmac_session_ref(hmac_key: bytes, raw_session_id: str) -> str:
    """Compute ``sha256:<hex>`` HMAC of ``raw_session_id`` without leaking input in errors."""
    if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) != SESSION_HMAC_KEY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid session key")
    if not isinstance(raw_session_id, str) or not raw_session_id:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid session identifier")
    digest = hmac.new(bytes(hmac_key), raw_session_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256:{digest}"


def _require_aware_utc_dt(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "timezone-aware datetime required")
    return value.astimezone(UTC)


def decide_session_liveness(
    *,
    recorded_state: SessionState,
    last_event_at: datetime,
    now: datetime,
    checkpoint_exists: bool = False,
    has_end_event: bool = False,
    has_resumed_after_end: bool = False,
    process_killed: bool = False,
) -> LivenessDecision:
    """Classify session liveness per spec §7.3 (`ended` never returns to `active` without resume)."""
    if not isinstance(recorded_state, SessionState) or not all(
        type(x) is bool for x in (checkpoint_exists, has_end_event, has_resumed_after_end, process_killed)
    ):
        raise _invalid()
    last_dt = _require_aware_utc_dt(last_event_at)
    now_dt = _require_aware_utc_dt(now)
    if recorded_state is SessionState.ENDED or has_end_event:
        if has_resumed_after_end:
            return LivenessDecision(SessionState.ACTIVE, True, True, False)
        return LivenessDecision(SessionState.ENDED, False, False, False)
    if process_killed:
        return LivenessDecision(SessionState.IN_PROGRESS_UNKNOWN, False, False, not checkpoint_exists)
    idle_delta = now_dt - last_dt
    if idle_delta <= timedelta(seconds=SESSION_ACTIVE_IDLE_S):
        return LivenessDecision(SessionState.ACTIVE, True, True, False)
    if idle_delta <= timedelta(seconds=SESSION_UNKNOWN_CHECKPOINT_IDLE_S):
        return LivenessDecision(SessionState.IN_PROGRESS_UNKNOWN, False, False, False)
    return LivenessDecision(SessionState.IN_PROGRESS_UNKNOWN, False, False, not checkpoint_exists)


def monotonic_watermark(prev_high: int, event_seq: int) -> int:
    """Return monotonic producer high watermark ``max(prev_high, event_seq)``."""
    prev_val = require_non_negative_int(prev_high)
    seq_val = require_non_negative_int(event_seq)
    return seq_val if seq_val > prev_val else prev_val


class ContinuityStorePort(Protocol):
    """Storage boundary consumed by ``ContinuityWorkerCoordinator`` in ``application``."""

    def read_task_handoff(self, task_id: str) -> TaskHandoffRecord | None: ...
    def get_continuity_worker_state(self, task_id: str) -> ContinuityWorkerState | None: ...
    def build_refresh_job_payload(self, task_id: str) -> tuple[bytes, int, int] | None: ...
    def reserve_pending_job(self, task_id: str, job_id: str, *, now: datetime) -> None: ...
    def mark_job_running(self, task_id: str, job_id: str, *, now: datetime) -> None: ...
    def check_automatic_capture_enabled(self, repo_id: str) -> bool: ...
    def read_task_owner(self, task_id: str) -> tuple[str, str, str]: ...
    def read_events_for_streams(
        self, task_id: str, stream_watermarks: Mapping[str, int]
    ) -> tuple[ContinuityEventRow, ...]: ...
    def apply_agent_handoff_patch(
        self,
        *,
        task_id: str,
        repo_id: str,
        checkout_id: str,
        session_ref: str | None = None,
        base_revision: int,
        agent_ref: str,
        now: datetime,
    ) -> TaskHandoffRecord: ...
    def check_manual_submission_enabled(self, repo_id: str) -> bool: ...
    def has_restricted_blobs_for_events(self, events: Sequence[tuple[str, int, str, str]]) -> bool: ...
    def clear_inflight_job_on_skip(self, task_id: str, job_id: str, *, now: datetime) -> None: ...
    def apply_worker_commit_in_tx(
        self,
        tx: object,
        *,
        task_id: str,
        job_id: str,
        observed_digest: str,
        observed_summary: Mapping[str, JsonValue],
        now: datetime,
        dirty_followup_fn: Callable[[object], str | None] | None = None,
    ) -> ContinuityCommitOutcome: ...


ContinuityStoreFactory = Callable[[object, object], ContinuityStorePort]
_STORE_FACTORY: list[ContinuityStoreFactory] = []


def register_continuity_store_factory(factory: ContinuityStoreFactory) -> None:
    """Register the concrete ``SessionStore`` constructor from ``storage.sessions`` cleanly."""
    _STORE_FACTORY.clear()
    _STORE_FACTORY.append(factory)


def default_continuity_store_factory() -> ContinuityStoreFactory | None:
    """Return the registered ``SessionStore`` factory if ``storage.sessions`` has loaded."""
    return _STORE_FACTORY[-1] if _STORE_FACTORY else None


_STAGE_LOCK = threading.Lock()
_STAGE_CALLBACKS: dict[tuple[str, int, str], tuple[bytes, int]] = {}


def stage_worker_observed_output(job_id: str, attempt: int, obs_digest: str, obs_bytes: bytes) -> None:
    """Ephemerally retain worker-computed bytes outside SQLite for owner-side CAS staging."""
    with _STAGE_LOCK:
        _STAGE_CALLBACKS[(job_id, attempt, obs_digest)] = (obs_bytes, len(obs_bytes))


def pop_worker_observed_output(job_id: str, attempt: int, ref: ObjectRef) -> bytes | None:
    """Retrieve and consume worker-computed bytes matching ``ref.digest`` on owner thread."""
    with _STAGE_LOCK:
        found = _STAGE_CALLBACKS.pop((job_id, attempt, ref.digest), None)
    if found is None:
        return None
    return found[0]


__all__ = [
    "CONTINUITY_REFRESH_JOB_KIND",
    "EVENT_KINDS_ENDING_SESSION",
    "EVENT_KINDS_RESUMING_SESSION",
    "SESSION_ACTIVE_IDLE_S",
    "SESSION_HMAC_KEY_BYTES",
    "SESSION_UNKNOWN_CHECKPOINT_IDLE_S",
    "WORKER_EVENT_THRESHOLD",
    "WORKER_MAX_AGE_S",
    "ContinuityCommitOutcome",
    "ContinuityEventRow",
    "ContinuityStoreFactory",
    "ContinuityStorePort",
    "ContinuityWorkerState",
    "ErrorSignatureSignal",
    "ExposureEvidence",
    "LivenessDecision",
    "LongRunningCheckpoint",
    "ModelExchangeProof",
    "ObservedSummary",
    "RecipientProfile",
    "SessionBindingRecord",
    "SessionRecord",
    "SessionSegmentRecord",
    "SessionState",
    "TaskHandoffRecord",
    "TestRunSignal",
    "compute_hmac_session_ref",
    "decide_session_liveness",
    "default_continuity_store_factory",
    "monotonic_watermark",
    "pop_worker_observed_output",
    "register_continuity_store_factory",
    "stage_worker_observed_output",
]
