"""Workspace identity adapters: canonical remote locators and physical checkout identity (Task 3, D3).

Pure string canonicalization for locators: nothing here fetches a URL, runs ``git`` or any project program, hook or
config. Checkout identity is the canonical physical path in the file system's own case (``realpath``), keyed with the
machine by the policy registry; the file ID (device + index) only confirms that the caller's spelling and the
resolved path name the same directory, and never carries identity across a move or a reused index. Error messages are
static and never echo the caller's input. The real snapshot observer is gated to SP2/SP5 and is not shipped here.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

from superbrain.adapters.os.permissions import owned_by_current_user
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import TrustedLocator, WorkspaceRegistration

_MAX_LOCATOR = 2048
_FORBIDDEN_IN_PATH = re.compile(r"[\x00-\x20\x7f%\"'<>`|^{}]")
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f%\\\"'<>`|^{}]")
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~+-]{1,255}")
_SCP_RE = re.compile(r"(?:[A-Za-z0-9._-]{1,64}@)?([A-Za-z0-9.-]{2,253}):(?!//)(.+)")
_WIN_DRIVE_RE = re.compile(r"([A-Za-z]):[\\/](.*)")
_DEFAULT_PORTS = {"https": 443, "ssh": 22}


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _segments(path: str, *, allow_empty: bool = False) -> list[str]:
    parts = [part for part in re.split(r"[/\\]+", path) if part]
    if not parts and not allow_empty:
        raise _invalid()
    for part in parts:
        if part in {".", ".."} or _SEGMENT_RE.fullmatch(part) is None:
            raise _invalid()
    if parts and parts[-1].lower().endswith(".git") and len(parts[-1]) > 4:
        parts[-1] = parts[-1][:-4]
    return parts


def _host_port(netloc: str, scheme: str) -> str:
    hostport = netloc.rpartition("@")[2]  # userinfo is dropped before anything else
    host, sep, port = hostport.partition(":")
    host = host.lower()
    if not host or _HOST_RE.fullmatch(host) is None:
        raise _invalid()
    if sep:
        if not port.isascii() or not port.isdigit() or not (1 <= len(port) <= 5) or not (1 <= int(port) <= 65535):
            raise _invalid()
        if int(port) != _DEFAULT_PORTS[scheme]:
            return f"{host}:{int(port)}"
    return host


def _locator(scheme: str, canonical: str) -> TrustedLocator:
    return TrustedLocator(scheme=scheme, canonical_locator=canonical, locator_digest=digest_bytes(canonical.encode()))


def _file_locator(drive: str | None, path: str) -> TrustedLocator:
    parts = _segments(path)
    prefix = f"/{drive.upper()}:" if drive is not None else ""
    return _locator("file", f"file://{prefix}/{'/'.join(parts)}")


def canonical_remote_locator(raw: object) -> TrustedLocator:
    """Canonical locator and ``locator_digest`` for a restricted HTTPS, SSH or local Git path shape.

    Userinfo, query and fragment are stripped, scheme and host lowercased, default ports and a trailing ``.git``
    removed. Anything else (other schemes, UNC/device/ADS paths, traversal, whitespace) is ``INVALID_INPUT``.
    """
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_LOCATOR:
        raise _invalid()
    if raw.startswith(("\\\\", "//")):
        raise _invalid()
    drive = _WIN_DRIVE_RE.fullmatch(raw)
    if drive is not None:
        if ":" in drive.group(2) or _FORBIDDEN_IN_PATH.search(drive.group(2)):
            raise _invalid()
        return _file_locator(drive.group(1), drive.group(2))
    if _FORBIDDEN_CHARS.search(raw) or "::" in raw:
        raise _invalid()
    lowered = raw.lower()
    for scheme in ("https", "ssh", "file"):
        if lowered.startswith(f"{scheme}://"):
            parts = urlsplit(raw)
            if scheme == "file":
                if parts.netloc or parts.query or parts.fragment:
                    raise _invalid()
                win = re.fullmatch(r"/([A-Za-z]):/(.*)", parts.path)
                if win is not None:
                    return _file_locator(win.group(1), win.group(2))
                return _file_locator(None, parts.path)
            host = _host_port(parts.netloc, scheme)
            return _locator(scheme, f"{scheme}://{host}/{'/'.join(_segments(parts.path))}")
    if "://" in raw:
        raise _invalid()
    if raw.startswith("/"):
        return _file_locator(None, raw)
    scp = _SCP_RE.fullmatch(raw)
    if scp is not None:
        host = scp.group(1).lower()
        if _HOST_RE.fullmatch(host) is None or "@" in scp.group(2) or ":" in scp.group(2):
            raise _invalid()
        return _locator("ssh", f"ssh://{host}/{'/'.join(_segments(scp.group(2)))}")
    raise _invalid()


@dataclass(frozen=True)
class PhysicalCheckout:
    checkout_path: str
    """The resolved real path, in the file system's own case."""
    path_identity: str
    """``path:<canonical physical path>``: equal for every spelling or link that reaches the same location."""


def _reject_unsafe_spelling(raw: str) -> None:
    if raw.startswith(("\\\\", "//")):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if sys.platform == "win32":
        drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
        if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")


def _is_absolute(raw: str) -> bool:
    if sys.platform == "win32":
        pure = PureWindowsPath(raw)
        return bool(pure.drive) and bool(pure.root)
    return raw.startswith("/")


def physical_checkout(raw_path: object) -> PhysicalCheckout:
    """Resolve an owner-supplied checkout path to its physical identity (links/junctions followed by the OS).

    Relative, UNC, device and alternate-data-stream spellings are refused; the directory must exist and be owned
    by the current user.
    """
    if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path or len(raw_path) > 4096:
        raise _invalid()
    _reject_unsafe_spelling(raw_path)
    if not _is_absolute(raw_path):
        raise _invalid()
    resolved: str | None = None
    same_directory = False
    is_directory = False
    try:
        resolved = os.path.realpath(raw_path, strict=True)
        resolved_stat = os.stat(resolved)
        same_directory = os.path.samestat(os.stat(raw_path), resolved_stat)  # confirmation only, never identity
        is_directory = stat.S_ISDIR(resolved_stat.st_mode)
    except (OSError, ValueError):
        resolved = None
    if resolved is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    _reject_unsafe_spelling(resolved)
    if not is_directory:
        raise _invalid()
    if not same_directory:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not owned_by_current_user(Path(resolved)):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    return PhysicalCheckout(checkout_path=resolved, path_identity=f"path:{resolved}")


def build_registration(
    *,
    owner_id: str,
    principal_id: str,
    machine_id: str,
    alias: str,
    raw_path: str,
    raw_remote: str | None = None,
    provider_egress_enabled: bool = False,
) -> WorkspaceRegistration:
    """The owner/adapter side of an authorized registration: physical identity plus canonical locator."""
    physical = physical_checkout(raw_path)
    return WorkspaceRegistration(
        owner_id=owner_id,
        principal_id=principal_id,
        machine_id=machine_id,
        alias=alias,
        checkout_path=physical.checkout_path,
        path_identity=physical.path_identity,
        locator=canonical_remote_locator(raw_remote) if raw_remote is not None else None,
        provider_egress_enabled=provider_egress_enabled,
    )
