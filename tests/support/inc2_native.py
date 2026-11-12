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
        "observed_call_id",
        "observation_channel",
        "host",
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
    "HostCallObservation",
    "HostTokenContext",
    "NativeConnectionProbe",
    "ObservationSet",
    "ObserverRegistration",
    "OwnerCallObservation",
    "PathCheckResult",
    "ProbeValidationError",
    "ProcessIdentity",
    "SocketObservation",
    "TerminalToolFacts",
    "TimespanRecord",
    "encode_native_probe",
    "parse_native_probe",
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

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "status": self.status,
            "reason_code": self.reason_code,
            "task_id": self.task_id,
            "observed_call_id": self.observed_call_id,
            "observation_channel": self.observation_channel,
            "host": self.host,
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


@dataclass(frozen=True)
class SocketObservation:
    client_process: ProcessIdentity
    daemon_process: ProcessIdentity
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    store_id: str
    writer_epoch: int
    instance_id: str


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


def _req_bool(val: object) -> bool:
    if type(val) is not bool:
        raise ProbeValidationError("probe_invalid_bool")
    return val


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
    obs_scope = obj["observed_scope"]
    if obs_scope is not None and not isinstance(obs_scope, dict):
        raise ProbeValidationError("probe_invalid_scope")
    return TerminalToolFacts(
        ready=_req_bool(obj["ready"]),
        tool_name=_req_opaque(obj["tool_name"]),
        ok=_req_bool(obj["ok"]),
        status=_req_str(obj["status"]),
        auth_granted=_req_bool(obj["auth_granted"]),
        response_flushed=_req_bool(obj["response_flushed"]),
        response_digest=_req_digest_opt(obj["response_digest"]),
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
    _req_str(probe.host)
    _req_str(probe.os)
    if _COMMIT_HEX_RE.fullmatch(probe.source_commit) is None:
        raise ProbeValidationError("probe_invalid_commit")
    if probe.host_pid is not None and probe.host_process is not None and probe.host_pid != probe.host_process.pid:
        raise ProbeValidationError("probe_host_pid_mismatch")


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
    )
    _validate_probe_invariants(probe)
    return probe


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


def _digest_physical_file(path: Path, *, evidence_root: Path | None) -> str | None:
    if not _check_physical_path(path, root=evidence_root, expect_dir=False):
        return None
    try:
        return digest_bytes(path.read_bytes())
    except OSError:
        return None


def _all_passed_fields_present(probe: NativeConnectionProbe) -> bool:
    required = (
        probe.observed_call_id,
        probe.observation_channel,
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
    return all(item is not None for item in required)


def _verify_artifacts(
    probe: NativeConnectionProbe, registration: ObserverRegistration, observations: ObservationSet
) -> bool:
    ev_root = registration.evidence_root
    if not _check_physical_path(ev_root, root=None, expect_dir=True):
        return False
    if "config" not in observations.artifact_paths or "profile" not in observations.artifact_paths:
        return False

    digests: dict[str, str] = {}
    for label, path in observations.artifact_paths.items():
        actual_digest = _digest_physical_file(path, evidence_root=ev_root)
        if actual_digest is None:
            return False
        digests[label] = actual_digest

    cfg_disk = _digest_physical_file(registration.expected_config_path, evidence_root=None)
    prof_disk = _digest_physical_file(registration.expected_profile_path, evidence_root=None)
    if cfg_disk is None or prof_disk is None:
        return False
    if os.path.abspath(observations.artifact_paths["config"]) != os.path.abspath(registration.expected_config_path):
        return False
    if os.path.abspath(observations.artifact_paths["profile"]) != os.path.abspath(registration.expected_profile_path):
        return False
    if not hmac.compare_digest(digests["config"], registration.expected_config_digest):
        return False
    if not hmac.compare_digest(digests["config"], probe.config_digest or ""):
        return False
    if not hmac.compare_digest(digests["profile"], registration.expected_profile_digest):
        return False
    if not hmac.compare_digest(digests["profile"], probe.profile_digest or ""):
        return False
    if "schema" in digests and not hmac.compare_digest(digests["schema"], registration.expected_schema_digest):
        return False
    if not hmac.compare_digest(probe.schema_digest or "", registration.expected_schema_digest):
        return False
    if "shim_build" in digests and not hmac.compare_digest(
        digests["shim_build"], registration.expected_shim_build_digest
    ):
        return False
    return hmac.compare_digest(probe.shim_build_digest or "", registration.expected_shim_build_digest)


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
        or probe.observation_channel != registration.registered_channel
        or probe.host != registration.expected_host
        or probe.os != registration.expected_os
        or probe.source_commit != registration.expected_source_commit
    ):
        return False
    if registration.registered_host_versions and probe.host_version not in registration.registered_host_versions:
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
        and probe.terminal_facts.auth_granted
        and probe.terminal_facts.response_flushed
    ):
        return False
    if not _verify_artifacts(probe, registration, observations):
        return False

    matching_host_calls = [hc for hc in observations.host_calls if hc.call_id == probe.observed_call_id]
    if len(matching_host_calls) != 1:
        return False
    hc = matching_host_calls[0]
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

    probe_scope = dict(probe.terminal_facts.observed_scope) if probe.terminal_facts.observed_scope is not None else None
    matching_owner = [
        oc
        for oc in observations.owner_events
        if (
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
            and (oc.call_id is None or oc.call_id == probe.observed_call_id)
            and oc.listen_host == "127.0.0.1"
            and (
                probe_scope is None
                or (oc.selected_scope is not None and dict(oc.selected_scope) == probe_scope)
            )
        )
    ]
    if not matching_owner:
        return False

    matched_ports = {oc.listen_port for oc in matching_owner}
    matching_sock = [
        so
        for so in observations.socket_observations
        if (
            so.client_process == probe.shim_worker_process
            and so.daemon_process == probe.daemon_process
            and so.local_addr == "127.0.0.1"
            and so.remote_addr == "127.0.0.1"
            and so.remote_port in matched_ports
            and so.store_id == probe.binding.store_id
            and so.writer_epoch == probe.binding.writer_epoch
            and so.instance_id == probe.binding.instance_id
        )
    ]
    if not matching_sock:
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

    return True
