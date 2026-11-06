"""Strict owner-only loader for ``DaemonConfig`` JSON files (Decision D1)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from superbrain.adapters.os.durable import map_os_error
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DaemonConfig, require_opaque_id
from superbrain.core.wire import parse_json
from superbrain.ports.os import OsAdapters

MAX_DAEMON_CONFIG_BYTES = 65_536
_EXPECTED_FIELDS: frozenset[str] = frozenset(
    {"version", "data_root", "expected_store_id", "cert_path", "key_path"}
)


def _read_checked_config_bytes(path: Path, os_: OsAdapters) -> bytes:
    os_.paths.reject_unsafe_path(str(path))
    if not path.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_links(path)
    ancestor_problems = os_.permissions.check_ancestors(path)
    if ancestor_problems:
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    try:
        st = path.lstat()
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise map_os_error(err, "inspecting daemon config") from err
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if st.st_size > MAX_DAEMON_CONFIG_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    if os_.permissions.object_problems(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise map_os_error(err, "opening daemon config") from err
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 8192):
            total += len(chunk)
            if total > MAX_DAEMON_CONFIG_BYTES:
                raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as err:
        raise map_os_error(err, "reading daemon config") from err
    finally:
        os.close(fd)


def _require_config_abs_path(raw: object, os_: OsAdapters) -> Path:
    if not isinstance(raw, str) or not raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_unsafe_path(raw)
    parsed = Path(raw)
    if not parsed.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return parsed


def read_daemon_config(path: Path, os_: OsAdapters) -> DaemonConfig:
    """Validate path safety/permissions/bounds and parse ``DaemonConfig`` without reading cert/key files."""
    raw = _read_checked_config_bytes(path, os_)
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
