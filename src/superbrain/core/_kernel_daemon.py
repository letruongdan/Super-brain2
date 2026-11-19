"""Pure Task 6a kernel daemon lifecycle, endpoint, command, auth-stamp, health, and shutdown value types."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from superbrain.core._json_parse import parse_json
from superbrain.core._kernel_base import (
    Identity,
    Scope,
    is_strict_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core._kernel_dispatch import CallResult
from superbrain.core._kernel_send_attempts import SendAttemptCompletion
from superbrain.core.canonical import canonical_json, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

ENDPOINT_VERSION = 1
ENDPOINT_HOST = "127.0.0.1"
ENDPOINT_CONTRACT = "mcp-tools-v2"
DAEMON_QUEUE_DEPTH = 32
DAEMON_LISTEN_BACKLOG = 32
DEFAULT_SHUTDOWN_GRACE_S = 5.0
TLS_EXPIRING_WINDOW = timedelta(days=30)
TLS_EXPIRING_CODE = "tls_expiring"
TLS_EXPIRED_CODE = "tls_expired"

_ENDPOINT_FIELDS: frozenset[str] = frozenset(
    {
        "version",
        "host",
        "port",
        "store_id",
        "writer_epoch",
        "instance_id",
        "contract",
    }
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_utc_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


@dataclass(frozen=True)
class Endpoint:
    """Published loopback endpoint descriptor (7 pinned fields in canonical JSON)."""

    version: int
    host: str
    port: int
    store_id: str
    writer_epoch: int
    instance_id: str
    contract: str = ENDPOINT_CONTRACT

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or isinstance(self.port, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not is_strict_int(self.version) or self.version != ENDPOINT_VERSION:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.host, str) or self.host != ENDPOINT_HOST:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(self.port) or not (1 <= self.port <= 65535):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.writer_epoch)
        require_opaque_id(self.instance_id, label="instance_id")
        if not isinstance(self.contract, str) or self.contract != ENDPOINT_CONTRACT:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    @property
    def identity(self) -> Identity:
        return Identity(
            store_id=self.store_id,
            writer_epoch=self.writer_epoch,
            instance_id=self.instance_id,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "store_id": self.store_id,
            "writer_epoch": self.writer_epoch,
            "instance_id": self.instance_id,
            "contract": self.contract,
        }

    def encode_canonical(self) -> bytes:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> Endpoint:
        if not isinstance(raw, Mapping) or set(raw) != _ENDPOINT_FIELDS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        raw_version = raw["version"]
        raw_host = raw["host"]
        raw_port = raw["port"]
        raw_store_id = raw["store_id"]
        raw_epoch = raw["writer_epoch"]
        raw_instance_id = raw["instance_id"]
        raw_contract = raw["contract"]
        if isinstance(raw_version, bool) or isinstance(raw_port, bool) or isinstance(raw_epoch, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if (
            not isinstance(raw_version, int)
            or not isinstance(raw_host, str)
            or not isinstance(raw_port, int)
            or not isinstance(raw_store_id, str)
            or not isinstance(raw_epoch, int)
            or not isinstance(raw_instance_id, str)
            or not isinstance(raw_contract, str)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return cls(
            version=raw_version,
            host=raw_host,
            port=raw_port,
            store_id=raw_store_id,
            writer_epoch=raw_epoch,
            instance_id=raw_instance_id,
            contract=raw_contract,
        )

    @classmethod
    def from_canonical(cls, raw: bytes) -> Endpoint:
        if type(raw) is not bytes:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        parsed = parse_json(raw)
        if not isinstance(parsed, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return cls.from_dict(parsed)


@dataclass(frozen=True)
class ToolCommand:
    """Decoded pre-normalization tool submission to ``OwnerLoop.submit``.

    ``token`` and ``arguments`` are omitted from ``__repr__`` so bearer secrets and raw
    unredacted inputs never enter logs or tracebacks.
    """

    tool: str
    arguments: JsonValue | Mapping[str, JsonValue]
    token: str
    selected_scope: Scope | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if self.selected_scope is not None and not isinstance(self.selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    def __repr__(self) -> str:
        return (
            f"ToolCommand(tool={self.tool!r}, "
            f"selected_scope={self.selected_scope!r}, "
            f"correlation_id={self.correlation_id!r})"
        )


@dataclass(frozen=True)
class CaptureBatchCommand:
    """Decoded internal ``POST /v2/capture/events`` submission for bounded capture ingestion.

    ``token`` and ``events`` are omitted from ``__repr__`` so bearer secrets and raw
    unredacted payloads never enter logs or tracebacks.
    """

    producer_stream: str
    repo_id: str
    checkout_id: str
    events: tuple[Mapping[str, JsonValue], ...]
    token: str
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")
        if (
            not isinstance(self.events, tuple)
            or not self.events
            or len(self.events) > 1024
            or not all(isinstance(ev, Mapping) for ev in self.events)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.token, str) or not self.token:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.correlation_id is not None:
            if not isinstance(self.correlation_id, str):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            try:
                encoded = self.correlation_id.encode("utf-8", errors="strict")
            except UnicodeEncodeError as err:
                raise BrainError(ErrorCode.INVALID_INPUT, "unpaired surrogate") from err
            if not (1 <= len(encoded) <= 128):
                raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
        for ev in self.events:
            validate_json(dict(ev))

    def __repr__(self) -> str:
        return (
            f"CaptureBatchCommand(producer_stream={self.producer_stream!r}, "
            f"repo_id={self.repo_id!r}, "
            f"checkout_id={self.checkout_id!r}, "
            f"correlation_id={self.correlation_id!r})"
        )


@dataclass(frozen=True)
class AuthGrantStamp:
    """Internal Task 6b release-grant stamp bound to the exact owner auth view used at live-auth/render."""

    credential_id: str
    generation: int
    trust_generation: int
    identity: Identity

    def __post_init__(self) -> None:
        require_opaque_id(self.credential_id, label="credential_id")
        require_positive_int(self.generation)
        if isinstance(self.trust_generation, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not is_strict_int(self.trust_generation) or self.trust_generation < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class OwnerReply:
    """Internal Task 6b handoff result keeping private grant/send metadata off the public wire envelope."""

    envelope: CallResult
    grant_stamp: AuthGrantStamp | None = None
    send_completion: SendAttemptCompletion | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ok = self.envelope.get("ok")
        if not isinstance(ok, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        expected_keys = {"ok", "data"} if ok else {"ok", "error"}
        if set(self.envelope) != expected_keys:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        validate_json(self.envelope)
        if self.grant_stamp is not None and not isinstance(self.grant_stamp, AuthGrantStamp):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.send_completion is not None and not isinstance(self.send_completion, SendAttemptCompletion):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class ShallowHealthMeta:
    """Immutable RAM metadata published alongside ``RequestAuthView`` for zero-I/O shallow ``get_health``."""

    store_id: str
    writer_epoch: int
    instance_id: str
    schema_version: int
    policy_schema_version: int
    tls_not_after: datetime
    idempotency_clock_untrusted: bool = False

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.writer_epoch)
        require_opaque_id(self.instance_id, label="instance_id")
        require_positive_int(self.schema_version)
        require_positive_int(self.policy_schema_version)
        _require_utc_datetime(self.tls_not_after)
        if not isinstance(self.idempotency_clock_untrusted, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class Ready:
    """Internal startup completion descriptor emitted after recovery, bind, and durable endpoint publication."""

    endpoint: Endpoint
    identity: Identity
    tls_not_after: datetime
    leaf_cert_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, Endpoint) or not isinstance(self.identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.endpoint.identity != self.identity:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_utc_datetime(self.tls_not_after)
        if not isinstance(self.leaf_cert_sha256, str) or not _HEX64_RE.fullmatch(self.leaf_cert_sha256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


class ShutdownState(StrEnum):
    STOPPED = "stopped"
    OVERRUN = "overrun"
    CLOSE_FAILED = "close_failed"


@dataclass(frozen=True)
class ShutdownReport:
    """Internal shutdown outcome returned by ``OwnerLoop.stop``."""

    state: ShutdownState
    drained_requests: int = 0
    cancelled_requests: int = 0
    worker_drained: bool = True
    endpoint_removed: bool = False
    error_code: ErrorCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ShutdownState):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if isinstance(self.drained_requests, bool) or isinstance(self.cancelled_requests, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not is_strict_int(self.drained_requests) or self.drained_requests < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(self.cancelled_requests) or self.cancelled_requests < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.worker_drained, bool) or not isinstance(self.endpoint_removed, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.error_code is not None and not isinstance(self.error_code, ErrorCode):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
