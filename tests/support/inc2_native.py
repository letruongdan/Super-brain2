"""Receipt schema and cross-channel verifier for Task 9 native and wheel connection probes.

Schema version: ``sp1-i2-native-connection-v1``.
Does not import dev-only dependencies so installed-wheel drivers may import it under ``python -I``.
"""

from __future__ import annotations

import hmac
import math
import os
import re
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope, is_strict_int, require_opaque_id, require_sha256_digest
from superbrain.core.wire import parse_json
from tests.support.inc2_lifecycle import ShimLaunchObservation, workspace_transition_matches

NATIVE_CONNECTION_SCHEMA_VERSION = "sp1-i2-native-connection-v1"

_ALLOWED_KINDS = frozenset({"native", "fixture"})
_ALLOWED_STATUSES = frozenset({"passed", "failed", "not_run"})
_ALLOWED_HOSTS = frozenset({"claude-code", "codex-desktop", "codex-cli"})
_ALLOWED_HOST_MODES = frozenset(
    {
        "claude_cli_mcp_isolated",
        "codex_desktop_gui",
        "codex_cli_exec",
        "wheel_mcp_pipe",
        "fixture_mcp_stdio",
    }
)
_NATIVE_HOST_TO_MODE = {
    "claude-code": "claude_cli_mcp_isolated",
    "codex-desktop": "codex_desktop_gui",
    "codex-cli": "codex_cli_exec",
}
_FIXTURE_HOST_MODES = frozenset({"wheel_mcp_pipe", "fixture_mcp_stdio"})
_KNOWN_V2_TOOLS = frozenset(
    {
        "prepare_task",
        "search_knowledge",
        "get_artifact",
        "submit_episode",
        "record_outcome",
        "request_improvement",
        "get_job",
        "get_health",
    }
)
_WORKSPACE_REQUIRED_TOOLS = frozenset(
    {
        "prepare_task",
        "search_knowledge",
        "get_artifact",
        "submit_episode",
        "record_outcome",
        "request_improvement",
    }
)
_GLOBAL_SCOPELESS_TOOLS = frozenset({"get_health"})
_D8_NATIVE_ACTIVE_TOOLS = frozenset({"get_health", "get_job"})
_ALLOWED_TERMINAL_STATUSES = frozenset(
    {
        "ok",
        "error",
        "deadline_exceeded",
        "in_progress",
        "commit_outcome_unknown",
        "policy_unavailable",
        "daemon_unavailable",
        "invalid_request",
    }
)
_ALLOWED_OBSERVATION_STATUSES = frozenset({"ok", "observation_incomplete"})
_REQUIRED_ARTIFACT_LABELS = frozenset(
    {
        "config",
        "profile",
        "schema",
        "shim_build",
        "evidence_index",
        "owner_ready",
        "owner_events",
        "host_calls",
        "socket_observations",
    }
)
_INDEXED_ARTIFACT_LABELS = frozenset(
    {
        "config",
        "profile",
        "schema",
        "shim_build",
        "owner_ready",
        "owner_events",
        "host_calls",
        "socket_observations",
    }
)
_COMMIT_HEX_RE = re.compile(r"^[0-9a-f]{40}$")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BEARER_TOKEN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{20,}",
    re.IGNORECASE,
)
_URI_CREDS_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^/:@\s]+:[^/@\s]+@", re.IGNORECASE)
_PROBE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "status",
        "reason_code",
        "task_id",
        "run_id",
        "observer_id",
        "observed_call_id",
        "observation_channel",
        "host",
        "host_mode",
        "host_version",
        "host_pid",
        "os",
        "source_commit",
        "shim_build_digest",
        "config_digest",
        "profile_digest",
        "schema_digest",
        "host_process",
        "shim_launcher_process",
        "shim_worker_process",
        "daemon_process",
        "filtered_command",
        "timespan",
        "token_context",
        "path_check",
        "binding",
        "terminal_facts",
    }
)

__all__ = [
    "NATIVE_CONNECTION_SCHEMA_VERSION",
    "BindingSummary",
    "EvidenceIndex",
    "HostCallObservation",
    "HostTokenContext",
    "NativeConnectionProbe",
    "ObservationSet",
    "ObserverRegistration",
    "OwnerCallObservation",
    "OwnerReadyObservation",
    "PathCheckResult",
    "ProbeValidationError",
    "ProcessIdentity",
    "SocketObservation",
    "TerminalToolFacts",
    "TimespanRecord",
    "encode_native_probe",
    "parse_evidence_index",
    "parse_host_calls_jsonl",
    "parse_native_probe",
    "parse_owner_events_jsonl",
    "parse_owner_ready",
    "parse_socket_observations_jsonl",
    "verify_native_connection",
]


class ProbeValidationError(ValueError):
    """Static validation error carrying no untrusted input values or secrets."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    started_at: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {"pid": self.pid, "started_at": self.started_at}


@dataclass(frozen=True)
class TimespanRecord:
    started_at: str
    ended_at: str
    duration_ms: float

    def to_dict(self) -> dict[str, JsonValue]:
        return {"started_at": self.started_at, "ended_at": self.ended_at, "duration_ms": self.duration_ms}


@dataclass(frozen=True)
class HostTokenContext:
    credential_id: str
    uid_or_sid: str
    sandbox_state: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "credential_id": self.credential_id,
            "uid_or_sid": self.uid_or_sid,
            "sandbox_state": self.sandbox_state,
        }


@dataclass(frozen=True)
class PathCheckResult:
    physical_root_ok: bool
    ancestors_ok: bool
    symlink_or_reparse_rejected: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "physical_root_ok": self.physical_root_ok,
            "ancestors_ok": self.ancestors_ok,
            "symlink_or_reparse_rejected": self.symlink_or_reparse_rejected,
        }


@dataclass(frozen=True)
class BindingSummary:
    store_id: str
    writer_epoch: int
    instance_id: str
    principal_id: str
    environment: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "store_id": self.store_id,
            "writer_epoch": self.writer_epoch,
            "instance_id": self.instance_id,
            "principal_id": self.principal_id,
            "environment": self.environment,
        }


@dataclass(frozen=True)
class TerminalToolFacts:
    ready: bool
    tool_name: str
    ok: bool
    status: str
    auth_granted: bool
    response_flushed: bool
    response_digest: str | None = None
    observed_scope: Mapping[str, JsonValue] | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "ready": self.ready,
            "tool_name": self.tool_name,
            "ok": self.ok,
            "status": self.status,
            "auth_granted": self.auth_granted,
            "response_flushed": self.response_flushed,
            "response_digest": self.response_digest,
            "observed_scope": dict(self.observed_scope) if self.observed_scope is not None else None,
        }


@dataclass(frozen=True)
class NativeConnectionProbe:
    schema_version: str
    kind: Literal["native", "fixture"]
    status: Literal["passed", "failed", "not_run"]
    reason_code: str | None
    task_id: str
    observed_call_id: str | None
    observation_channel: str | None
    host: str
    host_version: str | None
    host_pid: int | None
    os: str
    source_commit: str
    shim_build_digest: str | None
    config_digest: str | None
    profile_digest: str | None
    schema_digest: str | None
    host_process: ProcessIdentity | None
    shim_launcher_process: ProcessIdentity | None
    shim_worker_process: ProcessIdentity | None
    daemon_process: ProcessIdentity | None
    filtered_command: tuple[str, ...] | None
    timespan: TimespanRecord | None
    token_context: HostTokenContext | None
    path_check: PathCheckResult | None
    binding: BindingSummary | None
    terminal_facts: TerminalToolFacts | None
    run_id: str | None = None
    observer_id: str | None = None
    host_mode: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "status": self.status,
            "reason_code": self.reason_code,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "observer_id": self.observer_id,
            "observed_call_id": self.observed_call_id,
            "observation_channel": self.observation_channel,
            "host": self.host,
            "host_mode": self.host_mode,
            "host_version": self.host_version,
            "host_pid": self.host_pid,
            "os": self.os,
            "source_commit": self.source_commit,
            "shim_build_digest": self.shim_build_digest,
            "config_digest": self.config_digest,
            "profile_digest": self.profile_digest,
            "schema_digest": self.schema_digest,
            "host_process": self.host_process.to_dict() if self.host_process is not None else None,
            "shim_launcher_process": (
                self.shim_launcher_process.to_dict() if self.shim_launcher_process is not None else None
            ),
            "shim_worker_process": self.shim_worker_process.to_dict() if self.shim_worker_process is not None else None,
            "daemon_process": self.daemon_process.to_dict() if self.daemon_process is not None else None,
            "filtered_command": list(self.filtered_command) if self.filtered_command is not None else None,
            "timespan": self.timespan.to_dict() if self.timespan is not None else None,
            "token_context": self.token_context.to_dict() if self.token_context is not None else None,
            "path_check": self.path_check.to_dict() if self.path_check is not None else None,
            "binding": self.binding.to_dict() if self.binding is not None else None,
            "terminal_facts": self.terminal_facts.to_dict() if self.terminal_facts is not None else None,
        }


@dataclass(frozen=True)
class HostCallObservation:
    call_id: str
    channel: str
    host_process: ProcessIdentity
    shim_launcher_process: ProcessIdentity
    shim_worker_process: ProcessIdentity
    tool_name: str
    terminal_ok: bool
    response_digest: str | None
    started_at: str
    ended_at: str


@dataclass(frozen=True)
class OwnerCallObservation:
    daemon_process: ProcessIdentity
    store_id: str
    writer_epoch: int
    instance_id: str
    principal_id: str
    credential_id: str
    tool_name: str
    ready: bool
    auth_stamp_matched: bool
    response_flushed_ok: bool
    response_digest: str | None
    listen_host: str
    listen_port: int
    started_at: str
    ended_at: str
    call_id: str | None = None
    selected_scope: Mapping[str, JsonValue] | None = None
    client_host: str | None = None
    client_port: int | None = None
    client_process: ProcessIdentity | None = None
    connection_id: str | None = None
    observation_status: str = "ok"


@dataclass(frozen=True)
class SocketObservation:
    client_process: ProcessIdentity | None
    daemon_process: ProcessIdentity
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    store_id: str
    writer_epoch: int
    instance_id: str
    connection_id: str
    started_at: str
    ended_at: str
    observed_at: str | None = None
    observation_status: str = "ok"


@dataclass(frozen=True)
class EvidenceIndex:
    schema_version: str
    task_id: str
    run_id: str
    observer_id: str
    source_commit: str
    host: str
    host_mode: str
    host_version: str
    artifacts: Mapping[str, str]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "observer_id": self.observer_id,
            "source_commit": self.source_commit,
            "host": self.host,
            "host_mode": self.host_mode,
            "host_version": self.host_version,
            "artifacts": {k: v for k, v in self.artifacts.items()},
        }


@dataclass(frozen=True)
class OwnerReadyObservation:
    event: Literal["ready"]
    daemon_pid: int
    daemon_started_at: str
    port: int
    store_id: str
    writer_epoch: int
    instance_id: str
    module_file: str
    schema_sha256: str
    config_digest: str


@dataclass(frozen=True)
class ObserverRegistration:
    evidence_root: Path
    task_id: str
    expected_kind: Literal["native", "fixture"]
    registered_observer_id: str
    registered_channel: str
    expected_host: str
    expected_os: str
    expected_source_commit: str
    expected_shim_build_digest: str
    expected_config_path: Path
    expected_config_digest: str
    expected_profile_path: Path
    expected_profile_digest: str
    expected_schema_digest: str
    expected_store_id: str
    expected_environment: str
    registered_host_versions: tuple[str, ...] = ()
    active: bool = True
    run_id: str = ""
    expected_host_mode: str = ""


@dataclass(frozen=True)
class ObservationSet:
    artifact_paths: Mapping[str, Path]
    host_calls: tuple[HostCallObservation, ...]
    owner_events: tuple[OwnerCallObservation, ...]
    socket_observations: tuple[SocketObservation, ...]
    prior_lifecycle: ShimLaunchObservation | None = None
    current_lifecycle: ShimLaunchObservation | None = None
    expected_scope: Scope | None = None
    expected_profile_digest: str | None = None
    expected_first_scope: Scope | None = None
    expected_alias: str | None = None


def _reject_if_secret_str(value: str) -> None:
    lowered = value.lower()
    if (
        _BEARER_TOKEN_RE.search(value) is not None
        or "bearer " in lowered
        or "-----begin " in lowered
        or "<private>" in lowered
        or "</private>" in lowered
        or _URI_CREDS_RE.search(value) is not None
    ):
        raise ProbeValidationError("probe_secret_rejected")


def _scan_no_secrets(value: object) -> None:
    if isinstance(value, str):
        _reject_if_secret_str(value)
    elif isinstance(value, list | tuple):
        for item in value:
            _scan_no_secrets(item)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProbeValidationError("probe_invalid_key")
            _reject_if_secret_str(key)
            _scan_no_secrets(item)


def _req_str(val: object) -> str:
    if not isinstance(val, str) or not val or "\x00" in val:
        raise ProbeValidationError("probe_invalid_string")
    _reject_if_secret_str(val)
    return val


def _opt_str(val: object) -> str | None:
    return None if val is None else _req_str(val)


def _req_pos_int(val: object) -> int:
    if not is_strict_int(val):
        raise ProbeValidationError("probe_invalid_int")
    assert isinstance(val, int)
    if val < 1:
        raise ProbeValidationError("probe_invalid_int")
    return val


def _opt_pos_int(val: object) -> int | None:
    return None if val is None else _req_pos_int(val)


def _req_port(val: object) -> int:
    port = _req_pos_int(val)
    if port > 65535:
        raise ProbeValidationError("probe_invalid_port")
    return port


def _opt_port(val: object) -> int | None:
    return None if val is None else _req_port(val)


def _req_bool(val: object) -> bool:
    if type(val) is not bool:
        raise ProbeValidationError("probe_invalid_bool")
    return val


def _validate_host_mode_alignment(kind: str, host: str, host_mode: str) -> bool:
    if host not in _ALLOWED_HOSTS or host_mode not in _ALLOWED_HOST_MODES:
        return False
    if kind == "native":
        return _NATIVE_HOST_TO_MODE.get(host) == host_mode
    if kind == "fixture":
        return host_mode in _FIXTURE_HOST_MODES
    return False


def _req_utc_iso(val: object) -> datetime:
    text = _req_str(val)
    if not text.endswith("Z"):
        raise ProbeValidationError("probe_invalid_timestamp")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as err:
        raise ProbeValidationError("probe_invalid_timestamp") from err
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise ProbeValidationError("probe_invalid_timestamp")
    return dt


def _req_digest_opt(val: object) -> str | None:
    if val is None:
        return None
    text = _req_str(val)
    try:
        return require_sha256_digest(text)
    except BrainError as err:
        raise ProbeValidationError("probe_invalid_digest") from err


def _req_opaque(val: object) -> str:
    text = _req_str(val)
    try:
        return require_opaque_id(text)
    except BrainError as err:
        raise ProbeValidationError("probe_invalid_identifier") from err


def _req_uuid7(val: object) -> str:
    text = _req_str(val)
    try:
        parsed = uuid.UUID(text)
    except ValueError as err:
        raise ProbeValidationError("probe_invalid_uuid7") from err
    if str(parsed) != text or parsed.version != 7:
        raise ProbeValidationError("probe_invalid_uuid7")
    return text


def _req_dict(val: object, expected_keys: frozenset[str]) -> dict[str, JsonValue]:
    if not isinstance(val, dict) or set(val) != expected_keys:
        raise ProbeValidationError("probe_field_mismatch")
    return val


def _parse_process_identity(raw: object) -> ProcessIdentity | None:
    if raw is None:
        return None
    obj = _req_dict(raw, frozenset({"pid", "started_at"}))
    pid = _req_pos_int(obj["pid"])
    _req_utc_iso(obj["started_at"])
    return ProcessIdentity(pid=pid, started_at=_req_str(obj["started_at"]))


def _parse_timespan(raw: object) -> TimespanRecord | None:
    if raw is None:
        return None
    obj = _req_dict(raw, frozenset({"started_at", "ended_at", "duration_ms"}))
    start_dt = _req_utc_iso(obj["started_at"])
    end_dt = _req_utc_iso(obj["ended_at"])
    if end_dt < start_dt:
        raise ProbeValidationError("probe_invalid_timespan")
    dur = obj["duration_ms"]
    if isinstance(dur, bool) or not isinstance(dur, (int, float)) or not math.isfinite(dur) or dur < 0:
        raise ProbeValidationError("probe_invalid_duration")
    return TimespanRecord(
        started_at=_req_str(obj["started_at"]),
        ended_at=_req_str(obj["ended_at"]),
        duration_ms=float(dur),
    )


def _parse_token_context(raw: object) -> HostTokenContext | None:
    if raw is None:
        return None
    obj = _req_dict(raw, frozenset({"credential_id", "uid_or_sid", "sandbox_state"}))
    return HostTokenContext(
        credential_id=_req_uuid7(obj["credential_id"]),
        uid_or_sid=_req_str(obj["uid_or_sid"]),
        sandbox_state=_req_str(obj["sandbox_state"]),
    )


def _parse_path_check(raw: object) -> PathCheckResult | None:
    if raw is None:
        return None
    obj = _req_dict(raw, frozenset({"physical_root_ok", "ancestors_ok", "symlink_or_reparse_rejected"}))
    return PathCheckResult(
        physical_root_ok=_req_bool(obj["physical_root_ok"]),
        ancestors_ok=_req_bool(obj["ancestors_ok"]),
        symlink_or_reparse_rejected=_req_bool(obj["symlink_or_reparse_rejected"]),
    )


def _parse_binding(raw: object) -> BindingSummary | None:
    if raw is None:
        return None
    obj = _req_dict(raw, frozenset({"store_id", "writer_epoch", "instance_id", "principal_id", "environment"}))
    env = _req_str(obj["environment"])
    if _SAFE_TOKEN_RE.fullmatch(env) is None:
        raise ProbeValidationError("probe_invalid_environment")
    return BindingSummary(
        store_id=_req_opaque(obj["store_id"]),
        writer_epoch=_req_pos_int(obj["writer_epoch"]),
        instance_id=_req_opaque(obj["instance_id"]),
        principal_id=_req_opaque(obj["principal_id"]),
        environment=env,
    )


def _validate_terminal_tool_scope(tool_name: str, *, ok: bool, scope: Mapping[str, JsonValue] | None) -> None:
    if tool_name in _WORKSPACE_REQUIRED_TOOLS and scope is None:
        raise ProbeValidationError("probe_missing_required_scope")
    if tool_name in _GLOBAL_SCOPELESS_TOOLS and ok and scope is not None:
        raise ProbeValidationError("probe_unexpected_scope_for_global_tool")


def _parse_terminal_facts(raw: object) -> TerminalToolFacts | None:
    if raw is None:
        return None
    obj = _req_dict(
        raw,
        frozenset(
            {
                "ready",
                "tool_name",
                "ok",
                "status",
                "auth_granted",
                "response_flushed",
                "response_digest",
                "observed_scope",
            }
        ),
    )
    tool_name = _req_opaque(obj["tool_name"])
    if tool_name not in _KNOWN_V2_TOOLS:
        raise ProbeValidationError("probe_unknown_tool")
    ok_val = _req_bool(obj["ok"])
    status_val = _req_str(obj["status"])
    if status_val not in _ALLOWED_TERMINAL_STATUSES:
        raise ProbeValidationError("probe_invalid_terminal_status")
    ready_val = _req_bool(obj["ready"])
    auth_granted_val = _req_bool(obj["auth_granted"])
    flushed_val = _req_bool(obj["response_flushed"])
    resp_digest = _req_digest_opt(obj["response_digest"])

    if ok_val and status_val != "ok":
        raise ProbeValidationError("probe_inconsistent_terminal_status")
    if not ok_val and status_val == "ok":
        raise ProbeValidationError("probe_inconsistent_terminal_status")
    if ok_val and (not auth_granted_val or not flushed_val or resp_digest is None):
        raise ProbeValidationError("probe_inconsistent_ok_facts")

    obs_scope_raw = obj["observed_scope"]
    obs_scope: dict[str, JsonValue] | None = None
    if obs_scope_raw is not None:
        scope_obj = _req_dict(obs_scope_raw, frozenset({"repo_id", "checkout_id"}))
        obs_scope = {
            "repo_id": _req_opaque(scope_obj["repo_id"]),
            "checkout_id": _req_opaque(scope_obj["checkout_id"]),
        }
    _validate_terminal_tool_scope(tool_name, ok=ok_val, scope=obs_scope)

    return TerminalToolFacts(
        ready=ready_val,
        tool_name=tool_name,
        ok=ok_val,
        status=status_val,
        auth_granted=auth_granted_val,
        response_flushed=flushed_val,
        response_digest=resp_digest,
        observed_scope=obs_scope,
    )


def _validate_probe_invariants(probe: NativeConnectionProbe) -> None:
    _scan_no_secrets(probe.to_dict())
    if probe.schema_version != NATIVE_CONNECTION_SCHEMA_VERSION:
        raise ProbeValidationError("probe_invalid_schema_version")
    if probe.kind not in _ALLOWED_KINDS or probe.status not in _ALLOWED_STATUSES:
        raise ProbeValidationError("probe_invalid_kind_or_status")
    if probe.status == "passed":
        if probe.reason_code is not None:
            raise ProbeValidationError("probe_passed_must_not_have_reason")
    else:
        if probe.reason_code is None or _REASON_CODE_RE.fullmatch(probe.reason_code) is None:
            raise ProbeValidationError("probe_invalid_reason_code")
    _req_opaque(probe.task_id)
    if probe.run_id is not None:
        _req_opaque(probe.run_id)
    if probe.observer_id is not None:
        _req_opaque(probe.observer_id)
    _req_str(probe.host)
    if probe.host not in _ALLOWED_HOSTS:
        raise ProbeValidationError("probe_invalid_host")
    if probe.host_mode is not None and not _validate_host_mode_alignment(probe.kind, probe.host, probe.host_mode):
        raise ProbeValidationError("probe_invalid_host_mode")
    _req_str(probe.os)
    if _COMMIT_HEX_RE.fullmatch(probe.source_commit) is None:
        raise ProbeValidationError("probe_invalid_commit")
    if probe.host_pid is not None and probe.host_process is not None and probe.host_pid != probe.host_process.pid:
        raise ProbeValidationError("probe_host_pid_mismatch")
    if probe.terminal_facts is not None:
        tf = probe.terminal_facts
        if tf.tool_name not in _KNOWN_V2_TOOLS or tf.status not in _ALLOWED_TERMINAL_STATUSES:
            raise ProbeValidationError("probe_invalid_terminal_status")
        if tf.ok and (
            tf.status != "ok"
            or not tf.auth_granted
            or not tf.response_flushed
            or tf.response_digest is None
        ):
            raise ProbeValidationError("probe_inconsistent_terminal_status")
        if not tf.ok and tf.status == "ok":
            raise ProbeValidationError("probe_inconsistent_terminal_status")
        _validate_terminal_tool_scope(tf.tool_name, ok=tf.ok, scope=tf.observed_scope)
        if probe.kind == "native" and tf.ok and tf.tool_name not in _D8_NATIVE_ACTIVE_TOOLS:
            raise ProbeValidationError("probe_tool_outside_d8_scope")


def encode_native_probe(probe: NativeConnectionProbe) -> bytes:
    """Serialize ``probe`` to canonical UTF-8 JSON bytes after checking secret redaction."""
    _validate_probe_invariants(probe)
    return canonical_json(probe.to_dict())


def parse_native_probe(raw: bytes) -> NativeConnectionProbe:
    """Parse and strictly validate a ``sp1-i2-native-connection-v1`` receipt payload."""
    if type(raw) is not bytes:
        raise ProbeValidationError("probe_invalid_bytes")
    try:
        parsed = parse_json(raw)
    except (BrainError, ValueError) as err:
        raise ProbeValidationError("probe_malformed_json") from err
    if not isinstance(parsed, dict) or set(parsed) != _PROBE_KEYS:
        raise ProbeValidationError("probe_field_mismatch")
    _scan_no_secrets(parsed)

    raw_kind = _req_str(parsed["kind"])
    raw_status = _req_str(parsed["status"])
    if raw_kind not in _ALLOWED_KINDS or raw_status not in _ALLOWED_STATUSES:
        raise ProbeValidationError("probe_invalid_kind_or_status")

    raw_cmd = parsed["filtered_command"]
    filtered_cmd: tuple[str, ...] | None = None
    if raw_cmd is not None:
        if not isinstance(raw_cmd, list):
            raise ProbeValidationError("probe_invalid_command")
        filtered_cmd = tuple(_req_str(item) for item in raw_cmd)

    probe = NativeConnectionProbe(
        schema_version=_req_str(parsed["schema_version"]),
        kind=cast(Literal["native", "fixture"], raw_kind),
        status=cast(Literal["passed", "failed", "not_run"], raw_status),
        reason_code=_opt_str(parsed["reason_code"]),
        task_id=_req_opaque(parsed["task_id"]),
        observed_call_id=_opt_str(parsed["observed_call_id"]),
        observation_channel=_opt_str(parsed["observation_channel"]),
        host=_req_str(parsed["host"]),
        host_version=_opt_str(parsed["host_version"]),
        host_pid=_opt_pos_int(parsed["host_pid"]),
        os=_req_str(parsed["os"]),
        source_commit=_req_str(parsed["source_commit"]),
        shim_build_digest=_req_digest_opt(parsed["shim_build_digest"]),
        config_digest=_req_digest_opt(parsed["config_digest"]),
        profile_digest=_req_digest_opt(parsed["profile_digest"]),
        schema_digest=_req_digest_opt(parsed["schema_digest"]),
        host_process=_parse_process_identity(parsed["host_process"]),
        shim_launcher_process=_parse_process_identity(parsed["shim_launcher_process"]),
        shim_worker_process=_parse_process_identity(parsed["shim_worker_process"]),
        daemon_process=_parse_process_identity(parsed["daemon_process"]),
        filtered_command=filtered_cmd,
        timespan=_parse_timespan(parsed["timespan"]),
        token_context=_parse_token_context(parsed["token_context"]),
        path_check=_parse_path_check(parsed["path_check"]),
        binding=_parse_binding(parsed["binding"]),
        terminal_facts=_parse_terminal_facts(parsed["terminal_facts"]),
        run_id=_req_opaque(parsed["run_id"]) if parsed["run_id"] is not None else None,
        observer_id=_req_opaque(parsed["observer_id"]) if parsed["observer_id"] is not None else None,
        host_mode=_opt_str(parsed["host_mode"]),
    )
    _validate_probe_invariants(probe)
    return probe


_EVIDENCE_INDEX_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "run_id",
        "observer_id",
        "source_commit",
        "host",
        "host_mode",
        "host_version",
        "artifacts",
    }
)
_OWNER_READY_KEYS = frozenset(
    {
        "event",
        "daemon_pid",
        "daemon_started_at",
        "port",
        "store_id",
        "writer_epoch",
        "instance_id",
        "module_file",
        "schema_sha256",
        "config_digest",
    }
)
_HOST_CALL_KEYS = frozenset(
    {
        "call_id",
        "channel",
        "host_process",
        "shim_launcher_process",
        "shim_worker_process",
        "tool_name",
        "terminal_ok",
        "response_digest",
        "started_at",
        "ended_at",
    }
)
_OWNER_EVENT_KEYS = frozenset(
    {
        "event",
        "connection_id",
        "observation_status",
        "daemon_pid",
        "daemon_started_at",
        "store_id",
        "writer_epoch",
        "instance_id",
        "principal_id",
        "credential_id",
        "tool_name",
        "ready",
        "auth_stamp_matched",
        "response_flushed_ok",
        "response_digest",
        "listen_host",
        "listen_port",
        "client_host",
        "client_port",
        "client_pid",
        "client_started_at",
        "started_at",
        "ended_at",
        "call_id",
        "selected_scope",
    }
)
_SOCKET_OBS_KEYS = frozenset(
    {
        "event",
        "connection_id",
        "observation_status",
        "client_pid",
        "client_started_at",
        "daemon_pid",
        "daemon_started_at",
        "local_addr",
        "local_port",
        "remote_addr",
        "remote_port",
        "store_id",
        "writer_epoch",
        "instance_id",
        "started_at",
        "observed_at",
        "ended_at",
    }
)


def _req_opaque_or_unknown(val: object) -> str:
    text = _req_str(val)
    if text == "<unknown>":
        return text
    return _req_opaque(text)


def _parse_json_object_strict(raw: bytes, expected_keys: frozenset[str]) -> dict[str, JsonValue]:
    if type(raw) is not bytes:
        raise ProbeValidationError("probe_invalid_bytes")
    try:
        parsed = parse_json(raw)
    except (BrainError, ValueError) as err:
        raise ProbeValidationError("probe_malformed_json") from err
    obj = _req_dict(parsed, expected_keys)
    _scan_no_secrets(obj)
    return obj


def _split_nonempty_jsonl_lines(raw: bytes) -> list[bytes]:
    if type(raw) is not bytes:
        raise ProbeValidationError("probe_invalid_bytes")
    if not raw:
        return []
    lines: list[bytes] = []
    for raw_line in raw.splitlines():
        if not raw_line.strip():
            raise ProbeValidationError("probe_blank_jsonl_line")
        lines.append(raw_line)
    return lines


def parse_evidence_index(raw: bytes) -> EvidenceIndex:
    """Parse and strictly validate a coordinator ``evidence-index.json`` manifest."""
    obj = _parse_json_object_strict(raw, _EVIDENCE_INDEX_KEYS)
    if _req_str(obj["schema_version"]) != NATIVE_CONNECTION_SCHEMA_VERSION:
        raise ProbeValidationError("probe_invalid_schema_version")
    commit = _req_str(obj["source_commit"])
    if _COMMIT_HEX_RE.fullmatch(commit) is None:
        raise ProbeValidationError("probe_invalid_commit")
    host = _req_str(obj["host"])
    if host not in _ALLOWED_HOSTS:
        raise ProbeValidationError("probe_invalid_host")
    host_mode = _req_str(obj["host_mode"])
    if host_mode not in _ALLOWED_HOST_MODES:
        raise ProbeValidationError("probe_invalid_host_mode")
    arts_obj = _req_dict(obj["artifacts"], _INDEXED_ARTIFACT_LABELS)
    artifacts: dict[str, str] = {}
    for label, digest_val in arts_obj.items():
        digest_str = _req_digest_opt(digest_val)
        if digest_str is None:
            raise ProbeValidationError("probe_invalid_digest")
        artifacts[label] = digest_str
    return EvidenceIndex(
        schema_version=NATIVE_CONNECTION_SCHEMA_VERSION,
        task_id=_req_opaque(obj["task_id"]),
        run_id=_req_opaque(obj["run_id"]),
        observer_id=_req_opaque(obj["observer_id"]),
        source_commit=commit,
        host=host,
        host_mode=host_mode,
        host_version=_req_str(obj["host_version"]),
        artifacts=artifacts,
    )


def parse_owner_ready(raw: bytes) -> OwnerReadyObservation:
    """Parse and strictly validate ``owner-ready.json`` emitted by ``inc2_native_owner``."""
    obj = _parse_json_object_strict(raw, _OWNER_READY_KEYS)
    if _req_str(obj["event"]) != "ready":
        raise ProbeValidationError("probe_invalid_event")
    _req_utc_iso(obj["daemon_started_at"])
    raw_schema_sha = _req_str(obj["schema_sha256"])
    schema_norm = raw_schema_sha if raw_schema_sha.startswith("sha256:") else f"sha256:{raw_schema_sha}"
    schema_sha = _req_digest_opt(schema_norm)
    cfg_digest = _req_digest_opt(obj["config_digest"])
    if schema_sha is None or cfg_digest is None:
        raise ProbeValidationError("probe_invalid_digest")
    return OwnerReadyObservation(
        event="ready",
        daemon_pid=_req_pos_int(obj["daemon_pid"]),
        daemon_started_at=_req_str(obj["daemon_started_at"]),
        port=_req_port(obj["port"]),
        store_id=_req_opaque(obj["store_id"]),
        writer_epoch=_req_pos_int(obj["writer_epoch"]),
        instance_id=_req_opaque(obj["instance_id"]),
        module_file=_req_str(obj["module_file"]),
        schema_sha256=raw_schema_sha,
        config_digest=cfg_digest,
    )


def parse_host_calls_jsonl(raw: bytes) -> tuple[HostCallObservation, ...]:
    """Parse and strictly validate JSONL records from ``host-calls.jsonl``."""
    out: list[HostCallObservation] = []
    for line in _split_nonempty_jsonl_lines(raw):
        obj = _parse_json_object_strict(line, _HOST_CALL_KEYS)
        host_proc = _parse_process_identity(obj["host_process"])
        launcher_proc = _parse_process_identity(obj["shim_launcher_process"])
        worker_proc = _parse_process_identity(obj["shim_worker_process"])
        if host_proc is None or launcher_proc is None or worker_proc is None:
            raise ProbeValidationError("probe_missing_process")
        start_dt = _req_utc_iso(obj["started_at"])
        end_dt = _req_utc_iso(obj["ended_at"])
        if end_dt < start_dt:
            raise ProbeValidationError("probe_invalid_timespan")
        tool_name = _req_opaque(obj["tool_name"])
        if tool_name not in _KNOWN_V2_TOOLS:
            raise ProbeValidationError("probe_unknown_tool")
        term_ok = _req_bool(obj["terminal_ok"])
        resp_digest = _req_digest_opt(obj["response_digest"])
        if term_ok and resp_digest is None:
            raise ProbeValidationError("probe_inconsistent_ok_facts")
        out.append(
            HostCallObservation(
                call_id=_req_opaque(obj["call_id"]),
                channel=_req_str(obj["channel"]),
                host_process=host_proc,
                shim_launcher_process=launcher_proc,
                shim_worker_process=worker_proc,
                tool_name=tool_name,
                terminal_ok=term_ok,
                response_digest=resp_digest,
                started_at=_req_str(obj["started_at"]),
                ended_at=_req_str(obj["ended_at"]),
            )
        )
    return tuple(out)


def parse_owner_events_jsonl(raw: bytes) -> tuple[OwnerCallObservation, ...]:
    """Parse and strictly validate JSONL records from ``owner-events.jsonl``."""
    out: list[OwnerCallObservation] = []
    for line in _split_nonempty_jsonl_lines(raw):
        obj = _parse_json_object_strict(line, _OWNER_EVENT_KEYS)
        if _req_str(obj["event"]) != "owner_call":
            raise ProbeValidationError("probe_invalid_event")
        obs_status = _req_str(obj["observation_status"])
        if obs_status not in _ALLOWED_OBSERVATION_STATUSES:
            raise ProbeValidationError("probe_invalid_observation_status")
        _req_utc_iso(obj["daemon_started_at"])
        daemon_proc = ProcessIdentity(
            pid=_req_pos_int(obj["daemon_pid"]),
            started_at=_req_str(obj["daemon_started_at"]),
        )
        start_dt = _req_utc_iso(obj["started_at"])
        end_dt = _req_utc_iso(obj["ended_at"])
        if end_dt < start_dt:
            raise ProbeValidationError("probe_invalid_timespan")

        client_pid_raw = obj["client_pid"]
        client_started_raw = obj["client_started_at"]
        client_proc: ProcessIdentity | None = None
        if client_pid_raw is not None or client_started_raw is not None:
            if client_pid_raw is None or client_started_raw is None:
                raise ProbeValidationError("probe_incomplete_client_identity")
            _req_utc_iso(client_started_raw)
            client_proc = ProcessIdentity(
                pid=_req_pos_int(client_pid_raw),
                started_at=_req_str(client_started_raw),
            )

        selected_scope_raw = obj["selected_scope"]
        selected_scope: dict[str, JsonValue] | None = None
        if selected_scope_raw is not None:
            scope_obj = _req_dict(selected_scope_raw, frozenset({"repo_id", "checkout_id"}))
            selected_scope = {
                "repo_id": _req_opaque(scope_obj["repo_id"]),
                "checkout_id": _req_opaque(scope_obj["checkout_id"]),
            }

        tool_name = _req_opaque(obj["tool_name"])
        if tool_name not in _KNOWN_V2_TOOLS:
            raise ProbeValidationError("probe_unknown_tool")
        ready_val = _req_bool(obj["ready"])
        auth_matched = _req_bool(obj["auth_stamp_matched"])
        response_flushed_ok = _req_bool(obj["response_flushed_ok"])
        resp_digest = _req_digest_opt(obj["response_digest"])
        if auth_matched and (not response_flushed_ok or resp_digest is None):
            raise ProbeValidationError("probe_inconsistent_ok_facts")
        if ready_val and not auth_matched:
            raise ProbeValidationError("probe_inconsistent_terminal_status")
        _validate_terminal_tool_scope(tool_name, ok=(auth_matched and response_flushed_ok), scope=selected_scope)

        conn_id_raw = obj["connection_id"]
        call_id_raw = obj["call_id"]
        out.append(
            OwnerCallObservation(
                daemon_process=daemon_proc,
                store_id=_req_opaque(obj["store_id"]),
                writer_epoch=_req_pos_int(obj["writer_epoch"]),
                instance_id=_req_opaque(obj["instance_id"]),
                principal_id=_req_opaque_or_unknown(obj["principal_id"]),
                credential_id=_req_opaque_or_unknown(obj["credential_id"]),
                tool_name=tool_name,
                ready=ready_val,
                auth_stamp_matched=auth_matched,
                response_flushed_ok=response_flushed_ok,
                response_digest=resp_digest,
                listen_host=_req_str(obj["listen_host"]),
                listen_port=_req_port(obj["listen_port"]),
                started_at=_req_str(obj["started_at"]),
                ended_at=_req_str(obj["ended_at"]),
                call_id=_req_opaque(call_id_raw) if call_id_raw is not None else None,
                selected_scope=selected_scope,
                client_host=_opt_str(obj["client_host"]),
                client_port=_opt_port(obj["client_port"]),
                client_process=client_proc,
                connection_id=_req_opaque(conn_id_raw) if conn_id_raw is not None else None,
                observation_status=obs_status,
            )
        )
    return tuple(out)


def parse_socket_observations_jsonl(raw: bytes) -> tuple[SocketObservation, ...]:
    """Parse and strictly validate JSONL records from ``socket-observations.jsonl``."""
    out: list[SocketObservation] = []
    for line in _split_nonempty_jsonl_lines(raw):
        obj = _parse_json_object_strict(line, _SOCKET_OBS_KEYS)
        if _req_str(obj["event"]) != "socket_observation":
            raise ProbeValidationError("probe_invalid_event")
        obs_status = _req_str(obj["observation_status"])
        if obs_status not in _ALLOWED_OBSERVATION_STATUSES:
            raise ProbeValidationError("probe_invalid_observation_status")
        _req_utc_iso(obj["daemon_started_at"])
        start_dt = _req_utc_iso(obj["started_at"])
        end_dt = _req_utc_iso(obj["ended_at"])
        if end_dt < start_dt:
            raise ProbeValidationError("probe_invalid_timespan")

        client_pid_raw = obj["client_pid"]
        client_started_raw = obj["client_started_at"]
        observed_raw = obj["observed_at"]
        client_proc: ProcessIdentity | None = None
        client_start_dt: datetime | None = None
        if client_pid_raw is not None or client_started_raw is not None:
            if client_pid_raw is None or client_started_raw is None:
                raise ProbeValidationError("probe_incomplete_client_identity")
            client_start_dt = _req_utc_iso(client_started_raw)
            client_proc = ProcessIdentity(
                pid=_req_pos_int(client_pid_raw),
                started_at=_req_str(client_started_raw),
            )
        observed_dt: datetime | None = None
        observed_str: str | None = None
        if observed_raw is not None:
            observed_dt = _req_utc_iso(observed_raw)
            observed_str = _req_str(observed_raw)
            if observed_dt < start_dt or observed_dt > end_dt:
                raise ProbeValidationError("probe_invalid_timespan")
            if client_start_dt is not None and client_start_dt > observed_dt:
                raise ProbeValidationError("probe_invalid_timespan")

        if obs_status == "ok" and (client_proc is None or observed_dt is None):
            raise ProbeValidationError("probe_incomplete_client_identity")

        out.append(
            SocketObservation(
                client_process=client_proc,
                daemon_process=ProcessIdentity(
                    pid=_req_pos_int(obj["daemon_pid"]),
                    started_at=_req_str(obj["daemon_started_at"]),
                ),
                local_addr=_req_str(obj["local_addr"]),
                local_port=_req_port(obj["local_port"]),
                remote_addr=_req_str(obj["remote_addr"]),
                remote_port=_req_port(obj["remote_port"]),
                store_id=_req_opaque(obj["store_id"]),
                writer_epoch=_req_pos_int(obj["writer_epoch"]),
                instance_id=_req_opaque(obj["instance_id"]),
                connection_id=_req_opaque(obj["connection_id"]),
                started_at=_req_str(obj["started_at"]),
                observed_at=observed_str,
                ended_at=_req_str(obj["ended_at"]),
                observation_status=obs_status,
            )
        )
    return tuple(out)


def _is_link_or_reparse(info: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attrs = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attrs & reparse)


def _check_physical_path(path: Path, *, root: Path | None, expect_dir: bool = False) -> bool:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts or "\x00" in os.fspath(path):
        return False
    lexical = Path(os.path.abspath(path))
    if root is not None:
        if not root.is_absolute() or ".." in root.parts:
            return False
        root_lex = Path(os.path.abspath(root))
        try:
            lexical.relative_to(root_lex)
        except ValueError:
            return False
    for part in (*reversed(lexical.parents), lexical):
        try:
            st = part.lstat()
        except OSError:
            return False
        if _is_link_or_reparse(st):
            return False
        if part == lexical:
            if expect_dir and not stat.S_ISDIR(st.st_mode):
                return False
            if not expect_dir and not stat.S_ISREG(st.st_mode):
                return False
        elif not stat.S_ISDIR(st.st_mode):
            return False
    if root is not None:
        try:
            lexical.resolve().relative_to(Path(os.path.abspath(root)).resolve())
        except (OSError, ValueError):
            return False
    return True


def _read_physical_artifact(path: Path, *, evidence_root: Path | None) -> tuple[bytes, str] | None:
    if not _check_physical_path(path, root=evidence_root, expect_dir=False):
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return raw, digest_bytes(raw)


def _all_passed_fields_present(probe: NativeConnectionProbe) -> bool:
    required = (
        probe.run_id,
        probe.observer_id,
        probe.observed_call_id,
        probe.observation_channel,
        probe.host_mode,
        probe.host_version,
        probe.host_pid,
        probe.shim_build_digest,
        probe.config_digest,
        probe.profile_digest,
        probe.schema_digest,
        probe.host_process,
        probe.shim_launcher_process,
        probe.shim_worker_process,
        probe.daemon_process,
        probe.filtered_command,
        probe.timespan,
        probe.token_context,
        probe.path_check,
        probe.binding,
        probe.terminal_facts,
    )
    if not all(item is not None for item in required):
        return False
    assert probe.terminal_facts is not None
    if probe.terminal_facts.response_digest is None:
        return False
    try:
        require_sha256_digest(probe.terminal_facts.response_digest)
    except BrainError:
        return False
    return True


_CALL_OVERLAP_SLACK = timedelta(milliseconds=5)
_PROCESS_START_SLACK = timedelta(seconds=2)


def _parse_utc_dt(raw: str) -> datetime | None:
    if not isinstance(raw, str) or not raw.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _same_physical_file(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _load_verified_artifacts(
    probe: NativeConnectionProbe, registration: ObserverRegistration, observations: ObservationSet
) -> OwnerReadyObservation | None:
    ev_root = registration.evidence_root
    if not _check_physical_path(ev_root, root=None, expect_dir=True):
        return None
    if not _REQUIRED_ARTIFACT_LABELS.issubset(observations.artifact_paths.keys()):
        return None
    if not _check_physical_path(registration.expected_config_path, root=None, expect_dir=False):
        return None
    if not _check_physical_path(registration.expected_profile_path, root=None, expect_dir=False):
        return None
    if not _same_physical_file(observations.artifact_paths["config"], registration.expected_config_path):
        return None
    if not _same_physical_file(observations.artifact_paths["profile"], registration.expected_profile_path):
        return None

    artifact_bytes: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    for label, path in observations.artifact_paths.items():
        loaded = _read_physical_artifact(path, evidence_root=ev_root)
        if loaded is None:
            return None
        raw, actual_digest = loaded
        artifact_bytes[label] = raw
        digests[label] = actual_digest

    if not hmac.compare_digest(digests["config"], registration.expected_config_digest):
        return None
    if not hmac.compare_digest(digests["config"], probe.config_digest or ""):
        return None
    if not hmac.compare_digest(digests["profile"], registration.expected_profile_digest):
        return None
    if not hmac.compare_digest(digests["profile"], probe.profile_digest or ""):
        return None
    if not hmac.compare_digest(digests["schema"], registration.expected_schema_digest):
        return None
    if not hmac.compare_digest(probe.schema_digest or "", registration.expected_schema_digest):
        return None
    if not hmac.compare_digest(digests["shim_build"], registration.expected_shim_build_digest):
        return None
    if not hmac.compare_digest(probe.shim_build_digest or "", registration.expected_shim_build_digest):
        return None

    try:
        idx = parse_evidence_index(artifact_bytes["evidence_index"])
        owner_ready = parse_owner_ready(artifact_bytes["owner_ready"])
        disk_host_calls = parse_host_calls_jsonl(artifact_bytes["host_calls"])
        disk_owner_events = parse_owner_events_jsonl(artifact_bytes["owner_events"])
        disk_socks = parse_socket_observations_jsonl(artifact_bytes["socket_observations"])
    except ProbeValidationError:
        return None

    if (
        idx.task_id != registration.task_id
        or idx.run_id != registration.run_id
        or idx.observer_id != registration.registered_observer_id
        or idx.source_commit != registration.expected_source_commit
        or idx.host != registration.expected_host
        or idx.host_mode != registration.expected_host_mode
        or idx.host_version != probe.host_version
    ):
        return None
    for label in _INDEXED_ARTIFACT_LABELS:
        idx_digest = idx.artifacts.get(label)
        if idx_digest is None or not hmac.compare_digest(idx_digest, digests[label]):
            return None

    assert probe.daemon_process is not None and probe.binding is not None
    if not hmac.compare_digest(owner_ready.config_digest, digests["config"]):
        return None
    owner_schema_norm = (
        owner_ready.schema_sha256
        if owner_ready.schema_sha256.startswith("sha256:")
        else f"sha256:{owner_ready.schema_sha256}"
    )
    if not hmac.compare_digest(owner_schema_norm, digests["schema"]):
        return None
    if (
        owner_ready.daemon_pid != probe.daemon_process.pid
        or owner_ready.daemon_started_at != probe.daemon_process.started_at
        or owner_ready.store_id != probe.binding.store_id
        or owner_ready.writer_epoch != probe.binding.writer_epoch
        or owner_ready.instance_id != probe.binding.instance_id
    ):
        return None

    if (
        disk_host_calls != observations.host_calls
        or disk_owner_events != observations.owner_events
        or disk_socks != observations.socket_observations
    ):
        return None
    return owner_ready


def _verify_artifacts(
    probe: NativeConnectionProbe, registration: ObserverRegistration, observations: ObservationSet
) -> bool:
    return _load_verified_artifacts(probe, registration, observations) is not None


def verify_native_connection(
    probe: NativeConnectionProbe,
    *,
    registration: ObserverRegistration,
    observations: ObservationSet,
    require_native: bool = True,
) -> bool:
    """Verify ``probe`` against coordinator registration and independent multi-channel observations."""
    try:
        _validate_probe_invariants(probe)
        _req_opaque(registration.registered_observer_id)
        _req_opaque(registration.run_id)
        if not registration.registered_host_versions:
            return False
        for ver in registration.registered_host_versions:
            _req_str(ver)
        if not _validate_host_mode_alignment(
            registration.expected_kind, registration.expected_host, registration.expected_host_mode
        ):
            return False
    except ProbeValidationError:
        return False

    if not registration.active or probe.status != "passed" or probe.reason_code is not None:
        return False
    if require_native and probe.kind != "native":
        return False
    if probe.kind != registration.expected_kind:
        return False
    if not _all_passed_fields_present(probe):
        return False

    assert probe.run_id is not None
    assert probe.observer_id is not None
    assert probe.host_mode is not None
    assert probe.observed_call_id is not None
    assert probe.observation_channel is not None
    assert probe.host_process is not None
    assert probe.shim_launcher_process is not None
    assert probe.shim_worker_process is not None
    assert probe.daemon_process is not None
    assert probe.token_context is not None
    assert probe.path_check is not None
    assert probe.binding is not None
    assert probe.terminal_facts is not None

    if (
        probe.task_id != registration.task_id
        or probe.run_id != registration.run_id
        or probe.observer_id != registration.registered_observer_id
        or probe.observation_channel != registration.registered_channel
        or probe.host != registration.expected_host
        or probe.host_mode != registration.expected_host_mode
        or probe.os != registration.expected_os
        or probe.source_commit != registration.expected_source_commit
    ):
        return False
    if probe.host_version not in registration.registered_host_versions:
        return False
    if probe.binding.store_id != registration.expected_store_id:
        return False
    if probe.binding.environment != registration.expected_environment:
        return False
    if not (
        probe.path_check.physical_root_ok
        and probe.path_check.ancestors_ok
        and probe.path_check.symlink_or_reparse_rejected
    ):
        return False
    if not (
        probe.terminal_facts.ready
        and probe.terminal_facts.ok
        and probe.terminal_facts.status == "ok"
        and probe.terminal_facts.auth_granted
        and probe.terminal_facts.response_flushed
        and probe.terminal_facts.response_digest is not None
    ):
        return False
    owner_ready = _load_verified_artifacts(probe, registration, observations)
    if owner_ready is None:
        return False

    if probe.binding.writer_epoch < 1:
        return False

    assert (
        probe.host_process is not None
        and probe.shim_launcher_process is not None
        and probe.shim_worker_process is not None
        and probe.daemon_process is not None
        and probe.timespan is not None
        and probe.terminal_facts is not None
        and probe.binding is not None
        and probe.token_context is not None
    )
    binding = probe.binding
    token_ctx = probe.token_context
    term_facts = probe.terminal_facts
    worker_proc = probe.shim_worker_process
    daemon_proc = probe.daemon_process
    host_started = _parse_utc_dt(probe.host_process.started_at)
    launcher_started = _parse_utc_dt(probe.shim_launcher_process.started_at)
    worker_started = _parse_utc_dt(probe.shim_worker_process.started_at)
    daemon_started = _parse_utc_dt(probe.daemon_process.started_at)
    call_start = _parse_utc_dt(probe.timespan.started_at)
    call_end = _parse_utc_dt(probe.timespan.ended_at)
    if (
        host_started is None
        or launcher_started is None
        or worker_started is None
        or daemon_started is None
        or call_start is None
        or call_end is None
        or call_start > call_end
        or probe.timespan.duration_ms < 0.0
    ):
        return False
    if not (host_started <= launcher_started <= worker_started):
        return False
    if host_started > call_start + _PROCESS_START_SLACK or worker_started > call_end:
        return False
    if daemon_started > call_end:
        return False

    matching_host_calls = [hc for hc in observations.host_calls if hc.call_id == probe.observed_call_id]
    if len(matching_host_calls) != 1:
        return False
    hc = matching_host_calls[0]
    hc_start = _parse_utc_dt(hc.started_at)
    hc_end = _parse_utc_dt(hc.ended_at)
    if hc_start is None or hc_end is None or hc_start > hc_end:
        return False
    if (
        abs((call_start - hc_start).total_seconds()) > 5.0
        or abs((call_end - hc_end).total_seconds()) > 5.0
        or worker_started > hc_end
        or host_started > hc_start + _PROCESS_START_SLACK
    ):
        return False
    if (
        hc.channel != probe.observation_channel
        or hc.host_process != probe.host_process
        or hc.shim_launcher_process != probe.shim_launcher_process
        or hc.shim_worker_process != probe.shim_worker_process
        or not hc.terminal_ok
        or hc.tool_name != probe.terminal_facts.tool_name
        or hc.response_digest != probe.terminal_facts.response_digest
    ):
        return False

    sock_by_conn: dict[str, SocketObservation] = {}
    sock_intervals_by_tuple: dict[tuple[str, int, str, int], list[tuple[str, datetime, datetime]]] = {}
    for so in observations.socket_observations:
        if not so.connection_id or so.connection_id in sock_by_conn:
            return False
        if so.observation_status not in _ALLOWED_OBSERVATION_STATUSES:
            return False
        so_s = _parse_utc_dt(so.started_at)
        so_e = _parse_utc_dt(so.ended_at)
        if so_s is None or so_e is None or so_s > so_e:
            return False
        sock_tuple = (so.local_addr, so.local_port, so.remote_addr, so.remote_port)
        for prev_conn, prev_s, prev_e in sock_intervals_by_tuple.get(sock_tuple, ()):
            if prev_conn != so.connection_id and prev_s <= so_e and so_s <= prev_e:
                return False
        sock_intervals_by_tuple.setdefault(sock_tuple, []).append((so.connection_id, so_s, so_e))
        sock_by_conn[so.connection_id] = so

    worker_socks_all = [
        so for so in observations.socket_observations if so.client_process == probe.shim_worker_process
    ]
    worker_socks: list[SocketObservation] = []
    for so in worker_socks_all:
        so_start = _parse_utc_dt(so.started_at)
        so_end = _parse_utc_dt(so.ended_at)
        so_obs = _parse_utc_dt(so.observed_at) if so.observed_at is not None else None
        if so_start is None or so_end is None or so_obs is None or not (so_start <= so_obs <= so_end):
            return False
        if worker_started > so_obs or daemon_started > so_start + _PROCESS_START_SLACK or daemon_started > so_obs:
            return False
        if not (
            so.observation_status == "ok"
            and so.daemon_process == probe.daemon_process
            and so.local_addr == "127.0.0.1"
            and 1 <= so.local_port <= 65535
            and so.remote_addr == "127.0.0.1"
            and so.remote_port == owner_ready.port
            and so.store_id == probe.binding.store_id
            and so.writer_epoch == probe.binding.writer_epoch
            and so.instance_id == probe.binding.instance_id
        ):
            return False
        worker_socks.append(so)
    if not worker_socks or len(worker_socks) != len(worker_socks_all):
        return False

    worker_tuples = {(so.local_addr, so.local_port, so.remote_addr, so.remote_port) for so in worker_socks}
    for so in observations.socket_observations:
        if (so.local_addr, so.local_port, so.remote_addr, so.remote_port) in worker_tuples and (
            so.client_process != probe.shim_worker_process
            or so.daemon_process != probe.daemon_process
            or so.store_id != probe.binding.store_id
            or so.writer_epoch != probe.binding.writer_epoch
            or so.instance_id != probe.binding.instance_id
        ):
            return False
    worker_sock_by_conn = {so.connection_id: so for so in worker_socks}

    seen_owner_conns: set[str] = set()
    for oc in observations.owner_events:
        if oc.connection_id is not None:
            if oc.connection_id in seen_owner_conns:
                return False
            seen_owner_conns.add(oc.connection_id)

    probe_scope = dict(probe.terminal_facts.observed_scope) if probe.terminal_facts.observed_scope is not None else None

    def _oc_times_ok(oc: OwnerCallObservation, so: SocketObservation) -> bool:
        oc_start = _parse_utc_dt(oc.started_at)
        oc_end = _parse_utc_dt(oc.ended_at)
        so_start = _parse_utc_dt(so.started_at)
        so_end = _parse_utc_dt(so.ended_at)
        if oc_start is None or oc_end is None or oc_start > oc_end or so_start is None or so_end is None:
            return False
        if not (so_start <= oc_start <= oc_end <= so_end):
            return False
        if daemon_started > oc_start + _PROCESS_START_SLACK or daemon_started > oc_end:
            return False
        if worker_started > oc_end:
            return False
        if oc_start > hc_end + _CALL_OVERLAP_SLACK or hc_start > oc_end + _CALL_OVERLAP_SLACK:
            return False
        if oc_start > call_end + _CALL_OVERLAP_SLACK or call_start > oc_end + _CALL_OVERLAP_SLACK:
            return False
        return True

    def _oc_scope_matches(oc: OwnerCallObservation) -> bool:
        if probe_scope is None:
            return oc.selected_scope is None
        return oc.selected_scope is not None and dict(oc.selected_scope) == probe_scope

    def _oc_relates_to_call(oc: OwnerCallObservation) -> bool:
        if oc.call_id is not None:
            return oc.call_id == probe.observed_call_id
        oc_start = _parse_utc_dt(oc.started_at)
        oc_end = _parse_utc_dt(oc.ended_at)
        if oc_start is None or oc_end is None or oc_end < hc_start or oc_start > hc_end:
            return False
        if oc.connection_id is not None and oc.connection_id in sock_by_conn:
            so = sock_by_conn[oc.connection_id]
            so_start = _parse_utc_dt(so.started_at)
            so_end = _parse_utc_dt(so.ended_at)
            if so_start is None or so_end is None or so_end < hc_start or so_start > hc_end:
                return False
        if oc.client_process is not None and oc.client_process != worker_proc:
            return False
        if oc.connection_id is not None and oc.connection_id in worker_sock_by_conn:
            return True
        if oc.client_process == worker_proc:
            return True
        return (
            oc.daemon_process == daemon_proc
            and oc.store_id == binding.store_id
            and oc.principal_id == binding.principal_id
            and oc.credential_id == token_ctx.credential_id
            and oc.tool_name == term_facts.tool_name
        )

    related_owner = [oc for oc in observations.owner_events if _oc_relates_to_call(oc)]
    matching_owner: list[OwnerCallObservation] = []
    for oc in related_owner:
        if (
            oc.observation_status != "ok"
            or oc.connection_id is None
            or oc.client_host != "127.0.0.1"
            or oc.client_port is None
            or not (1 <= oc.client_port <= 65535)
            or not (1 <= oc.listen_port <= 65535)
            or oc.client_process != probe.shim_worker_process
        ):
            return False
        worker_so = worker_sock_by_conn.get(oc.connection_id)
        if worker_so is None:
            return False
        if (
            worker_so.local_port != oc.client_port
            or worker_so.remote_port != oc.listen_port
            or worker_so.remote_port != owner_ready.port
            or worker_so.local_addr != oc.client_host
            or worker_so.remote_addr != oc.listen_host
        ):
            return False
        if not (
            oc.daemon_process == probe.daemon_process
            and oc.store_id == probe.binding.store_id
            and oc.writer_epoch == probe.binding.writer_epoch
            and oc.instance_id == probe.binding.instance_id
            and oc.principal_id == probe.binding.principal_id
            and oc.credential_id == probe.token_context.credential_id
            and oc.tool_name == probe.terminal_facts.tool_name
            and oc.ready
            and oc.auth_stamp_matched
            and oc.response_flushed_ok
            and oc.response_digest == probe.terminal_facts.response_digest
            and oc.listen_host == "127.0.0.1"
            and _oc_scope_matches(oc)
            and _oc_times_ok(oc, worker_so)
        ):
            return False
        matching_owner.append(oc)

    if len(matching_owner) != 1:
        return False

    if observations.prior_lifecycle is not None or observations.current_lifecycle is not None:
        if (
            observations.prior_lifecycle is None
            or observations.current_lifecycle is None
            or observations.expected_scope is None
            or observations.expected_profile_digest is None
        ):
            return False
        if not workspace_transition_matches(
            observations.prior_lifecycle,
            observations.current_lifecycle,
            expected_scope=observations.expected_scope,
            expected_profile_digest=observations.expected_profile_digest,
            expected_first_scope=observations.expected_first_scope,
            expected_alias=observations.expected_alias,
        ):
            return False
        curr_lc = observations.current_lifecycle
        if (
            curr_lc.pid != probe.shim_worker_process.pid
            or curr_lc.started_at != probe.shim_worker_process.started_at
            or curr_lc.profile_digest != probe.profile_digest
            or observations.expected_profile_digest != registration.expected_profile_digest
        ):
            return False
        if probe_scope is None:
            return False
        repo_id = probe_scope.get("repo_id")
        checkout_id = probe_scope.get("checkout_id")
        if not isinstance(repo_id, str) or not isinstance(checkout_id, str):
            return False
        if curr_lc.observed_scope != Scope(repo_id, checkout_id):
            return False

    if probe.kind == "native" and term_facts.tool_name not in _D8_NATIVE_ACTIVE_TOOLS:
        return False

    return True
