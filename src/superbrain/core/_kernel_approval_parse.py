"""Strict base64url, SSH key-line, and dict-parsing helpers for ``superbrain.core._kernel_approval``."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping

from superbrain.core._kernel_base import is_strict_int
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

MAX_PUBLIC_KEY_CHARS = 4096
MAX_PASSKEY_CREDENTIAL_ID_BYTES = 1024
MAX_PASSKEY_COSE_KEY_BYTES = 4096

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_SSH_KEY_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9@.\-]{0,127}$")


def invalid_input(message: str = "invalid input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def strict_b64url_decode(value: object, *, max_decoded_bytes: int | None = None) -> bytes:
    """Strictly decode URL-safe base64 (validates alphabet, padding, and optional decoded byte cap)."""
    if not isinstance(value, str) or not value or not value.isascii():
        raise invalid_input()
    if max_decoded_bytes is not None and len(value) > ((max_decoded_bytes + 2) // 3) * 4 + 4:
        raise invalid_input()
    if _B64URL_RE.fullmatch(value) is None:
        raise invalid_input()
    if "=" in value:
        if len(value) % 4 != 0:
            raise invalid_input()
        padded = value
    else:
        if len(value) % 4 == 1:
            raise invalid_input()
        padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError) as err:
        raise invalid_input() from err
    if not raw:
        raise invalid_input()
    if max_decoded_bytes is not None and len(raw) > max_decoded_bytes:
        raise invalid_input()
    return raw


def parse_ssh_public_key(line: str) -> tuple[str, str]:
    """``(key_type, base64_blob)`` of an OpenSSH public key line (a trailing comment is ignored)."""
    if not isinstance(line, str) or not line or len(line) > MAX_PUBLIC_KEY_CHARS:
        raise invalid_input()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in line):
        raise invalid_input()
    parts = line.split()
    if len(parts) < 2:
        raise invalid_input()
    key_type, blob = parts[0], parts[1]
    if _SSH_KEY_TYPE_RE.fullmatch(key_type) is None:
        raise invalid_input()
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as err:
        raise invalid_input() from err
    if len(raw) < 4:
        raise invalid_input()
    key_type_bytes = key_type.encode("ascii")
    declared = int.from_bytes(raw[:4], "big")
    if declared != len(key_type_bytes) or raw[4 : 4 + declared] != key_type_bytes:
        raise invalid_input()
    return key_type, blob


def text_field(value: object) -> str:
    if not isinstance(value, str):
        raise invalid_input()
    return value


def int_field(value: object) -> int:
    if not is_strict_int(value):
        raise invalid_input()
    assert isinstance(value, int)
    return value


def mapping_field(value: object) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise invalid_input()
    return value
