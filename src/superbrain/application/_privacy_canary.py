"""In-memory privacy canary self-check & bounded byte/text rescanning (spec 14.2, D6, I4-1)."""

from __future__ import annotations

import json
import re
from typing import cast

from superbrain.application._privacy_rules import (
    _AUTH_HEADER,
    _AUTH_SCHEME,
    _FIXED_TOKENS,
    _KEY_VALUE_SECRET,
    _PEM_BEGIN,
)
from superbrain.application._privacy_scan import _PRIVATE_MARK
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy
from superbrain.ports.doctor import PrivacyCanaryProbeResult, PrivacyScannerPort

_CONTROL_CLEANUP_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_NO_ENTROPY_POLICY = FilterPolicy(entropy_min_length=4096)
_FS_PATH_TOKEN_RE = re.compile(
    r"(?:[A-Za-z]:[\\/][^\s\"'<>@:|?*]+[\\/][^\s\"'<>@:|?*]+"
    r"|(?<![A-Za-z0-9+.-]:)/(?!/)[^\s\"'<>@]+/[^\s\"'<>@]+)"
)

_CANARY_CHANNELS: tuple[tuple[str, str, JsonValue], ...] = (
    (
        "hook",
        "ghp_CanaryHookToken9876543210abcdef",
        {"event": "hook", "stdout": "Authorization: token ghp_CanaryHookToken9876543210abcdef"},
    ),
    (
        "direct_tool",
        "sk-CanaryDirectToolSecretKey12345678",
        {"tool": "prepare_task", "text": "use api_key=sk-CanaryDirectToolSecretKey12345678 cleanly"},
    ),
    (
        "nested_object",
        "AKIAIOSFODNN7CANARY9",
        {"outer": {"inner": [{"aws_access_key_id": "AKIAIOSFODNN7CANARY9"}]}},
    ),
    (
        "error_log",
        "CanaryErrorLogBearer99887766",
        {"level": "ERROR", "message": "HTTP call failed header Authorization: Bearer CanaryErrorLogBearer99887766"},
    ),
    (
        "trace",
        "canary_trace_password_554433",
        {"span": "db.connect", "dsn": "postgres://svc:canary_trace_password_554433@localhost/app"},
    ),
    (
        "outbox",
        "xoxb-CanaryOutboxSlackToken-11223344",
        {"outbox_batch": [{"payload": "notify token xoxb-CanaryOutboxSlackToken-11223344"}]},
    ),
    (
        "derived_content",
        "canary_private_derived_body_77",
        {"summary": "Notes <private>canary_private_derived_body_77</private> preserved context"},
    ),
)


def _reject_nonfinite(tok: str) -> object:
    raise ValueError(f"non-finite JSON constant: {tok}")


def _mask_fs_paths(value: JsonValue) -> JsonValue:
    """Mask verified-safe filesystem path tokens before Shannon-entropy scoring only."""
    if isinstance(value, str):
        return _FS_PATH_TOKEN_RE.sub(" ", value)
    if isinstance(value, list):
        return [_mask_fs_paths(elem) for elem in value]
    if isinstance(value, dict):
        return {k: _mask_fs_paths(v) for k, v in value.items()}
    return value


class KernelPrivacyScanner(PrivacyScannerPort):
    """Privacy scanner backed by the real kernel ``PrivacyFilter`` with strictly zero disk writes."""

    def __init__(self, filter_: PrivacyFilter | None = None) -> None:
        self._filter = filter_ if filter_ is not None else PrivacyFilter()

    def check_canary_channels(self) -> tuple[PrivacyCanaryProbeResult, ...]:
        policy = FilterPolicy()
        results: list[PrivacyCanaryProbeResult] = []
        for channel, canary_secret, payload in _CANARY_CHANNELS:
            try:
                outcome = self._filter.apply(payload, policy)
                encoded = canonical_json(outcome.value).decode("utf-8", errors="replace")
                leaked = canary_secret in encoded or (outcome.redacted_count < 1 and outcome.stripped_keys_count < 1)
                if leaked:
                    results.append(
                        PrivacyCanaryProbeResult(
                            channel=channel,
                            passed=False,
                            detail="canary passed filter unredacted",
                        )
                    )
                else:
                    results.append(
                        PrivacyCanaryProbeResult(
                            channel=channel,
                            passed=True,
                            detail=(
                                f"blocked/redacted (redacted={outcome.redacted_count}, "
                                f"stripped={outcome.stripped_keys_count})"
                            ),
                        )
                    )
            except BrainError:
                results.append(
                    PrivacyCanaryProbeResult(
                        channel=channel,
                        passed=True,
                        detail="rejected by filter",
                    )
                )
        return tuple(results)

    def _apply_two_stage(self, payload: JsonValue, rules: list[str]) -> None:
        """Run all deterministic rules unmasked, then entropy scoring with safe OS paths masked."""
        try:
            deterministic = self._filter.apply(payload, _NO_ENTROPY_POLICY)
            if (deterministic.redacted_count > 0 or deterministic.stripped_keys_count > 0) and (
                "privacy_filter_redacted" not in rules
            ):
                rules.append("privacy_filter_redacted")
            entropy_safe = self._filter.apply(_mask_fs_paths(payload), FilterPolicy())
            if (entropy_safe.redacted_count > 0 or entropy_safe.stripped_keys_count > 0) and (
                "privacy_filter_redacted" not in rules
            ):
                rules.append("privacy_filter_redacted")
        except BrainError:
            if "privacy_filter_rejected" not in rules:
                rules.append("privacy_filter_rejected")

    def scan_bytes(self, data: bytes) -> tuple[str, ...]:
        if not data:
            return ()
        decoded = data.decode("utf-8", errors="replace")
        sanitized = _CONTROL_CLEANUP_RE.sub(" ", decoded)
        rules: list[str] = []

        if _PRIVATE_MARK.search(sanitized) is not None:
            rules.append("private_marker")
        if _PEM_BEGIN.search(sanitized) is not None:
            rules.append("pem_private_key")
        if _AUTH_HEADER.search(sanitized) is not None:
            rules.append("auth_header")
        if _AUTH_SCHEME.search(sanitized) is not None:
            rules.append("auth_scheme")
        if _KEY_VALUE_SECRET.search(sanitized) is not None:
            rules.append("key_value_secret")
        if any(pat.search(sanitized) is not None for pat in _FIXED_TOKENS):
            rules.append("fixed_token_prefix")

        try:
            loaded = json.loads(decoded, parse_constant=_reject_nonfinite)
            if isinstance(loaded, (dict, list)):
                self._apply_two_stage(cast(JsonValue, loaded), rules)
                return tuple(rules)
        except ValueError:
            pass

        chunk_size = 32 * 1024
        for offset in range(0, len(sanitized), chunk_size):
            chunk = sanitized[offset : offset + chunk_size]
            self._apply_two_stage({"content": chunk}, rules)

        return tuple(rules)
