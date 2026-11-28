"""NativeHostReceipt builder, canonical config digest, and Layer-2 verification/invalidation (SP2-5, §11.3)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.harness._common import compute_checkout_config_digest
from superbrain.adapters.harness_config.bootstrap_templates import AUTHORITY_ASK_COMMANDS
from superbrain.core._kernel_approval import Layer2State
from superbrain.core._kernel_base import OPAQUE_ID_RE, require_opaque_id, require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import require_iso_utc_timestamp
from superbrain.ports.os import OsAdapters

NATIVE_HOST_RECEIPT_SCHEMA_VERSION = "sp2-layer2-native-host-receipt-v1"


def _invalid(msg: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, msg)


@dataclass(frozen=True)
class AuthorityCommandProbeResult:
    """Observed host Layer-2 behavior for one AUTHORITY_ASK_COMMANDS pattern."""

    command_pattern: str
    prompted_user: bool
    blocked_without_approval: bool

    def __post_init__(self) -> None:
        if not isinstance(self.command_pattern, str) or not self.command_pattern.strip():
            raise _invalid("invalid command_pattern")
        if type(self.prompted_user) is not bool or type(self.blocked_without_approval) is not bool:
            raise _invalid("invalid probe booleans")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "command_pattern": self.command_pattern,
            "prompted_user": self.prompted_user,
            "blocked_without_approval": self.blocked_without_approval,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> AuthorityCommandProbeResult:
        expected = {"command_pattern", "prompted_user", "blocked_without_approval"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise _invalid("malformed probe entry")
        return cls(
            command_pattern=str(raw["command_pattern"]),
            prompted_user=bool(raw["prompted_user"]) if type(raw["prompted_user"]) is bool else _raise_bad_bool(),
            blocked_without_approval=(
                bool(raw["blocked_without_approval"])
                if type(raw["blocked_without_approval"]) is bool
                else _raise_bad_bool()
            ),
        )


def _raise_bad_bool() -> bool:
    raise _invalid("expected boolean")


@dataclass(frozen=True)
class NativeHostReceipt:
    """Secret-free receipt binding ``(harness_id, host_version, config_digest)`` to 11 ask-command probes."""

    schema_version: str
    receipt_id: str
    harness_id: str
    host_version: str
    config_digest: str
    probe_mode: str
    command_probes: tuple[AuthorityCommandProbeResult, ...]
    observed_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        require_opaque_id(self.receipt_id, label="receipt_id")
        for tok in (self.harness_id, self.host_version):
            if not isinstance(tok, str) or not OPAQUE_ID_RE.fullmatch(tok):
                raise _invalid("invalid receipt identifier")
        require_sha256_digest(self.config_digest)
        if not isinstance(self.probe_mode, str) or not self.probe_mode.strip():
            raise _invalid("invalid probe_mode")
        require_iso_utc_timestamp(self.observed_at)
        require_sha256_digest(self.receipt_digest)

    def _unsigned_body(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "harness_id": self.harness_id,
            "host_version": self.host_version,
            "config_digest": self.config_digest,
            "probe_mode": self.probe_mode,
            "command_probes": [p.to_dict() for p in self.command_probes],
            "observed_at": self.observed_at,
        }

    def compute_digest(self) -> str:
        return digest_bytes(canonical_json(self._unsigned_body()))

    @classmethod
    def build(
        cls,
        *,
        receipt_id: str,
        harness_id: str,
        host_version: str,
        config_digest: str,
        probe_mode: str,
        command_probes: tuple[AuthorityCommandProbeResult, ...],
        observed_at: str,
    ) -> NativeHostReceipt:
        unsigned = {
            "schema_version": NATIVE_HOST_RECEIPT_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "harness_id": harness_id,
            "host_version": host_version,
            "config_digest": config_digest,
            "probe_mode": probe_mode,
            "command_probes": [p.to_dict() for p in command_probes],
            "observed_at": observed_at,
        }
        return cls(
            schema_version=NATIVE_HOST_RECEIPT_SCHEMA_VERSION,
            receipt_id=receipt_id,
            harness_id=harness_id,
            host_version=host_version,
            config_digest=config_digest,
            probe_mode=probe_mode,
            command_probes=command_probes,
            observed_at=observed_at,
            receipt_digest=digest_bytes(canonical_json(unsigned)),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {**self._unsigned_body(), "receipt_digest": self.receipt_digest}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> NativeHostReceipt:
        expected = {
            "schema_version",
            "receipt_id",
            "harness_id",
            "host_version",
            "config_digest",
            "probe_mode",
            "command_probes",
            "observed_at",
            "receipt_digest",
        }
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise _invalid("malformed NativeHostReceipt")
        raw_probes = raw["command_probes"]
        if not isinstance(raw_probes, list):
            raise _invalid("command_probes must be list")
        probes = tuple(
            AuthorityCommandProbeResult.from_dict(item)
            for item in raw_probes
            if isinstance(item, Mapping)
        )
        if len(probes) != len(raw_probes):
            raise _invalid("malformed probe entry in list")
        return cls(
            schema_version=str(raw["schema_version"]),
            receipt_id=str(raw["receipt_id"]),
            harness_id=str(raw["harness_id"]),
            host_version=str(raw["host_version"]),
            config_digest=str(raw["config_digest"]),
            probe_mode=str(raw["probe_mode"]),
            command_probes=probes,
            observed_at=str(raw["observed_at"]),
            receipt_digest=str(raw["receipt_digest"]),
        )


@dataclass(frozen=True)
class Layer2ReceiptVerdict:
    """Outcome of verifying a ``NativeHostReceipt`` against live host version & checkout config."""

    state: Layer2State
    reason: str
    missing_commands: tuple[str, ...] = ()


def compute_harness_config_digest(harness_id: str, checkout_root: Path, os_: OsAdapters) -> str | None:
    """Compute checkout-scoped canonical ``config_digest`` for ``claude-code`` or ``codex``."""
    cfg_dig, _, _, _ = compute_checkout_config_digest(
        harness_id=harness_id, checkout_root=checkout_root, os_=os_
    )
    return cfg_dig


def verify_native_host_receipt(
    receipt: NativeHostReceipt | None,
    *,
    current_host_version: str | None,
    current_config_digest: str | None,
    expected_harness_id: str | None = None,
) -> Layer2ReceiptVerdict:
    """Verify receipt integrity, 11-command coverage, and exact ``(host_version, config_digest)`` match."""
    if receipt is None:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "receipt_missing")
    if receipt.schema_version != NATIVE_HOST_RECEIPT_SCHEMA_VERSION:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "schema_version_mismatch")
    if receipt.compute_digest() != receipt.receipt_digest:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "invalid_receipt_digest")
    if expected_harness_id is not None and receipt.harness_id != expected_harness_id:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "harness_mismatch")
    if current_host_version is None or receipt.host_version != current_host_version:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "host_version_changed")
    if current_config_digest is None or receipt.config_digest != current_config_digest:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "config_digest_changed")

    by_cmd: dict[str, AuthorityCommandProbeResult] = {}
    for p in receipt.command_probes:
        if p.command_pattern in by_cmd:
            return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "duplicate_command_probe")
        by_cmd[p.command_pattern] = p

    missing = tuple(cmd for cmd in AUTHORITY_ASK_COMMANDS if cmd not in by_cmd)
    if missing:
        return Layer2ReceiptVerdict(Layer2State.UNKNOWN, "missing_authority_commands", missing_commands=missing)

    for cmd in AUTHORITY_ASK_COMMANDS:
        probe = by_cmd[cmd]
        if not probe.prompted_user or not probe.blocked_without_approval:
            return Layer2ReceiptVerdict(Layer2State.UNSUPPORTED, "authority_command_not_blocked")

    return Layer2ReceiptVerdict(Layer2State.VERIFIED, "verified")


__all__ = [
    "NATIVE_HOST_RECEIPT_SCHEMA_VERSION",
    "AuthorityCommandProbeResult",
    "Layer2ReceiptVerdict",
    "NativeHostReceipt",
    "compute_harness_config_digest",
    "verify_native_host_receipt",
]
