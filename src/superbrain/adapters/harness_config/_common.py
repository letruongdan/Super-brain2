"""Shared validation helpers for harness config mergers."""

from __future__ import annotations

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

__all__ = ["check_clean_text", "digest_json_value", "invalid_config", "revision_conflict"]


def invalid_config(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def revision_conflict(message: str = "revision conflict") -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, message)


def check_clean_text(text: str | None) -> str:
    """Validate optional config file text, rejecting UTF-8 BOM and NUL bytes."""
    if text is None:
        return ""
    if not isinstance(text, str):
        raise invalid_config()
    if text.startswith("\ufeff") or "\x00" in text:
        raise invalid_config()
    return text


def digest_json_value(value: JsonValue) -> str:
    """Compute canonical SHA-256 digest of a JSON-compatible slice value."""
    return digest_bytes(canonical_json(value))
