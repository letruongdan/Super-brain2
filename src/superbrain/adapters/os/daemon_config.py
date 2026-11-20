"""Strict owner-only loaders for ``DaemonConfig`` and client profile/trust files (D1, D2, D3)."""

from __future__ import annotations

import contextlib
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from superbrain.adapters.os.durable import map_os_error
from superbrain.core.client_profile import (
    CLIENT_PROFILE_VERSION,
    ClientProfile,
    WorkspaceProfile,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DaemonConfig,
    Endpoint,
    parse_bearer_token,
    require_opaque_id,
    require_workspace_alias,
)
from superbrain.core.wire import parse_json
from superbrain.ports.os import NoReplacePublisher, OsAdapters

MAX_DAEMON_CONFIG_BYTES = 65_536
MAX_CLIENT_PROFILE_BYTES = 65_536
MAX_CLIENT_ENDPOINT_BYTES = 65_536
MAX_CLIENT_CA_BYTES = 65_536
MAX_CLIENT_CREDENTIAL_BYTES = 256

_EXPECTED_FIELDS: frozenset[str] = frozenset({"version", "data_root", "expected_store_id", "cert_path", "key_path"})
_PROFILE_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {
        "version",
        "endpoint_path",
        "expected_store_id",
        "ca_file",
        "leaf_cert_sha256",
        "credential_file",
    }
)
_PROFILE_OPTIONAL_FIELDS: frozenset[str] = frozenset({"workspace"})
_WORKSPACE_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"alias", "checkout_path", "expected_workspace_id", "expected_checkout_id"}
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _missing_error(code: ErrorCode) -> BrainError:
    if code == ErrorCode.DAEMON_UNAVAILABLE:
        return BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
    return BrainError(ErrorCode.NOT_FOUND, "not found")


def _read_checked_file_bytes(
    path: Path,
    os_: OsAdapters,
    *,
    max_bytes: int,
    missing_code: ErrorCode = ErrorCode.NOT_FOUND,
) -> bytes:
    if not isinstance(path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw_str = os.fspath(path)
    if not raw_str or "\x00" in raw_str:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_unsafe_path(raw_str)
    if ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not path.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_links(path)
    ancestor_problems = os_.permissions.check_ancestors(path)
    if ancestor_problems:
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    try:
        pre_st = path.lstat()
    except FileNotFoundError as err:
        raise _missing_error(missing_code) from err
    except OSError as err:
        raise map_os_error(err, "inspecting owner file") from err
    if stat.S_ISLNK(pre_st.st_mode):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not stat.S_ISREG(pre_st.st_mode):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if pre_st.st_size > max_bytes:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    if os_.permissions.object_problems(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as err:
        raise _missing_error(missing_code) from err
    except OSError as err:
        raise map_os_error(err, "opening owner file") from err
    try:
        open_fst = os.fstat(fd)
        if not stat.S_ISREG(open_fst.st_mode):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        if not os.path.samestat(pre_st, open_fst):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 8192):
            total += len(chunk)
            if total > max_bytes:
                raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
            chunks.append(chunk)
        try:
            post_st = path.lstat()
        except OSError as err:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path") from err
        if not os.path.samestat(open_fst, post_st):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        if os_.permissions.object_problems(path):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        return b"".join(chunks)
    except OSError as err:
        raise map_os_error(err, "reading owner file") from err
    finally:
        os.close(fd)


def _require_config_abs_path(raw: object, os_: OsAdapters) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_unsafe_path(raw)
    parsed = Path(raw)
    if ".." in parsed.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not parsed.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return parsed


def read_daemon_config(path: Path, os_: OsAdapters) -> DaemonConfig:
    """Validate path safety/permissions/bounds and parse ``DaemonConfig`` without reading cert/key files."""
    raw = _read_checked_file_bytes(path, os_, max_bytes=MAX_DAEMON_CONFIG_BYTES)
    parsed = parse_json(raw)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    extra = set(parsed) - _EXPECTED_FIELDS
    if extra:
        raise BrainError(ErrorCode.INVALID_INPUT, "unknown field")
    missing = _EXPECTED_FIELDS - set(parsed)
    if missing:
        raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")

    raw_version = parsed["version"]
    if isinstance(raw_version, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if type(raw_version) is not int or raw_version != 1:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    return DaemonConfig(
        version=1,
        data_root=_require_config_abs_path(parsed["data_root"], os_),
        expected_store_id=require_opaque_id(parsed["expected_store_id"], label="expected_store_id"),
        cert_path=_require_config_abs_path(parsed["cert_path"], os_),
        key_path=_require_config_abs_path(parsed["key_path"], os_),
    )


def read_owner_json_object(path: Path, os_: OsAdapters) -> dict[str, Any]:
    """Strictly read an owner-only JSON object file (same path, permission and size rules as the daemon config)."""
    parsed = parse_json(_read_checked_file_bytes(path, os_, max_bytes=MAX_DAEMON_CONFIG_BYTES))
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return parsed


def read_client_profile(path: Path, os_: OsAdapters) -> Any:
    """Validate owner-only ``ClientProfile`` file and parse its typed fields without opening trust/endpoint targets."""
    raw = _read_checked_file_bytes(path, os_, max_bytes=MAX_CLIENT_PROFILE_BYTES)
    parsed = parse_json(raw)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    allowed = _PROFILE_REQUIRED_FIELDS | _PROFILE_OPTIONAL_FIELDS
    if set(parsed) - allowed:
        raise BrainError(ErrorCode.INVALID_INPUT, "unknown field")
    if _PROFILE_REQUIRED_FIELDS - set(parsed):
        raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")

    raw_version = parsed["version"]
    if isinstance(raw_version, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if type(raw_version) is not int or raw_version != CLIENT_PROFILE_VERSION:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    raw_pin = parsed["leaf_cert_sha256"]
    if not isinstance(raw_pin, str) or not _HEX64_RE.fullmatch(raw_pin):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    ws_profile: WorkspaceProfile | None = None
    if "workspace" in parsed:
        raw_ws = parsed["workspace"]
        if not isinstance(raw_ws, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if set(raw_ws) - _WORKSPACE_REQUIRED_FIELDS:
            raise BrainError(ErrorCode.INVALID_INPUT, "unknown field")
        if _WORKSPACE_REQUIRED_FIELDS - set(raw_ws):
            raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")
        ws_profile = WorkspaceProfile(
            alias=require_workspace_alias(raw_ws["alias"]),
            checkout_path=_require_config_abs_path(raw_ws["checkout_path"], os_),
            expected_workspace_id=require_opaque_id(
                raw_ws["expected_workspace_id"],
                label="expected_workspace_id",
            ),
            expected_checkout_id=require_opaque_id(
                raw_ws["expected_checkout_id"],
                label="expected_checkout_id",
            ),
        )

    return ClientProfile(
        version=CLIENT_PROFILE_VERSION,
        endpoint_path=_require_config_abs_path(parsed["endpoint_path"], os_),
        expected_store_id=require_opaque_id(parsed["expected_store_id"], label="expected_store_id"),
        ca_file=_require_config_abs_path(parsed["ca_file"], os_),
        leaf_cert_sha256=raw_pin,
        credential_file=_require_config_abs_path(parsed["credential_file"], os_),
        workspace=ws_profile,
    )


def read_client_endpoint(path: Path, os_: OsAdapters) -> Endpoint:
    """Read and validate the owner-only daemon ``endpoint.json`` descriptor."""
    raw = _read_checked_file_bytes(
        path,
        os_,
        max_bytes=MAX_CLIENT_ENDPOINT_BYTES,
        missing_code=ErrorCode.DAEMON_UNAVAILABLE,
    )
    return Endpoint.from_canonical(raw)


def read_client_ca(path: Path, os_: OsAdapters) -> str:
    """Read and validate the owner-only PEM CA certificate file."""
    raw = _read_checked_file_bytes(path, os_, max_bytes=MAX_CLIENT_CA_BYTES)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err
    if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return text


def read_client_credential(path: Path, os_: OsAdapters) -> str:
    """Read and validate the owner-only bearer credential file (allowing one trailing LF or CRLF)."""
    raw = _read_checked_file_bytes(path, os_, max_bytes=MAX_CLIENT_CREDENTIAL_BYTES)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err
    if text.endswith("\r\n"):
        token = text[:-2]
    elif text.endswith("\n"):
        token = text[:-1]
    else:
        token = text
    parse_bearer_token(token)
    return token

def _validate_publish_target(target: Path, os_: OsAdapters) -> None:
    if not isinstance(target, Path) or not target.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw_str = os.fspath(target)
    if not raw_str or "\x00" in raw_str:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_unsafe_path(raw_str)
    if ".." in target.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    os_.paths.reject_links(target)


def publish_new_owner_file(
    path: Path,
    data: bytes,
    os_: OsAdapters,
    *,
    stage_path: Path | None = None,
    before_stage: Callable[[Path], None] | None = None,
) -> None:
    """Crash-safely create a NEW owner-only file: stage, secure, flush, then publish without replacing anything.

    No byte ever lands on ``path`` before it is complete and flushed; a pre-existing ``path`` (user file) is refused
    with ``INVALID_INPUT`` and never replaced. A hard kill leaves at most a ``.<name>.stage-<uuid7>`` sibling
    (or ``stage_path`` when specified). When ``before_stage`` is provided, it runs before a single byte is written.
    """
    _validate_publish_target(path, os_)
    if os_.permissions.check_ancestors(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if os.path.lexists(path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if stage_path is not None:
        _validate_publish_target(stage_path, os_)
        if stage_path == path or stage_path.parent != path.parent:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        stage = stage_path
    else:
        stage = path.parent / f".{path.name}.stage-{new_id()}"
    if os.path.lexists(stage):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if before_stage is not None:
        before_stage(stage)
    created_stage = False
    try:
        os_.publisher.write_new(stage, data)
        created_stage = True
        os_.permissions.secure_file(stage)
        os_.publisher.flush_file(stage)
        cast(NoReplacePublisher, os_.publisher).publish_no_replace(stage, path)
        os_.permissions.secure_file(path)
        os_.publisher.sync_directory(path.parent)
    except FileExistsError as err:
        if created_stage:
            _discard_stage(stage)
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
    except Exception:
        if created_stage:
            _discard_stage(stage)
        raise


def _discard_stage(stage: Path) -> None:
    """Best-effort unlink of our own staging file on a handled error (a hard kill leaves it for the verified sweep)."""
    with contextlib.suppress(OSError):
        stage.unlink()
