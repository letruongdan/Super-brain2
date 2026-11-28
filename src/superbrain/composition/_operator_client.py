"""Shared loopback client loading and operator request helpers for CLI composition modules."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import (
    read_client_ca,
    read_client_credential,
    read_client_endpoint,
    read_client_profile,
)
from superbrain.core.client_profile import ClientProfile
from superbrain.core.errors import BrainError, ErrorCode, safe_wire_message
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.os import OsAdapters

if TYPE_CHECKING:
    from superbrain.cli_api.loopback import LoopbackTarget

__all__ = [
    "OperatorEndpointClient",
    "call_operator_from_profile",
    "call_operator_target",
    "load_operator_client",
    "write_error_code",
    "write_json_error",
]


def call_operator_target(
    target: LoopbackTarget,
    token: str,
    path: str,
    body: Mapping[str, object],
    *,
    os_: OsAdapters | None = None,
) -> dict[str, JsonValue]:
    """Issue a pinned loopback operator request against ``target`` using bearer ``token``."""
    from superbrain.cli_api.loopback import LoopbackClient

    adapters = os_ if os_ is not None else os_adapters()
    client = LoopbackClient(monotonic_ns=adapters.monotonic.monotonic_ns)
    return client.call_operator(target, path, json.dumps(body).encode("utf-8"), token)


class OperatorEndpointClient:
    """Bound loopback operator caller backed by a validated client profile."""

    def __init__(self, profile_path: Path, os_: OsAdapters | None = None) -> None:
        from superbrain.cli_api.loopback import LoopbackTarget

        self._adapters = os_ if os_ is not None else os_adapters()
        if not os.path.lexists(profile_path):
            raise BrainError(ErrorCode.NOT_FOUND, "profile not found")
        profile: ClientProfile = read_client_profile(profile_path, self._adapters)
        ca_pem = read_client_ca(profile.ca_file, self._adapters)
        token = read_client_credential(profile.credential_file, self._adapters)
        endpoint = read_client_endpoint(profile.endpoint_path, self._adapters)
        self._target = LoopbackTarget(
            endpoint=endpoint,
            expected_store_id=profile.expected_store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=profile.leaf_cert_sha256,
        )
        self._token = token

    def call(self, path: str, body: Mapping[str, object]) -> dict[str, JsonValue]:
        return call_operator_target(self._target, self._token, path, body, os_=self._adapters)


def load_operator_client(profile_path: Path, *, os_: OsAdapters | None = None) -> OperatorEndpointClient:
    """Load an ``OperatorEndpointClient`` from ``profile_path``."""
    return OperatorEndpointClient(profile_path, os_=os_)


def call_operator_from_profile(
    profile_path: Path,
    path: str,
    body: Mapping[str, object],
    *,
    os_: OsAdapters | None = None,
) -> dict[str, JsonValue]:
    """Load ``profile_path`` and issue a single operator call to ``path``."""
    return OperatorEndpointClient(profile_path, os_=os_).call(path, body)


def write_error_code(code: ErrorCode | str) -> None:
    val = code.value if isinstance(code, ErrorCode) else str(code)
    try:
        sys.stderr.write(f"{val}\n")
        sys.stderr.flush()
    except OSError:
        pass


def write_json_error(code: ErrorCode, message: str | None = None) -> None:
    payload = json.dumps(
        {"ok": False, "error": {"code": code.value, "message": safe_wire_message(code, message)}},
        sort_keys=True,
    )
    try:
        sys.stdout.write(payload + "\n")
        sys.stdout.flush()
    except OSError:
        pass
