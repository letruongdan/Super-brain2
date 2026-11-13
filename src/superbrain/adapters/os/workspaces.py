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
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

from superbrain.adapters.os.permissions import owned_by_current_user
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import TrustedLocator, WorkspaceRegistration
from superbrain.ports.os import OsAdapters

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


def _fold(name: str) -> str:
    """Name key under case- and normalization-insensitive comparison (APFS keeps bytes, compares folded)."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())


def _same_real_entry(entry: Path, target: Path) -> bool:
    """``entry`` is a non-link directory entry for the same object as ``target`` (a link never names a component)."""
    try:
        return not stat.S_ISLNK(os.lstat(entry).st_mode) and os.path.samefile(entry, target)
    except OSError:
        return False


def _on_disk_spelling(resolved: str) -> str:
    """Spell each component as its parent lists it: one identity on case-insensitive POSIX file systems (APFS)."""
    parts = Path(resolved).parts
    current = Path(parts[0])
    for name in parts[1:]:
        try:
            entries = os.listdir(current)
        except OSError:
            entries = [name]  # unlistable ancestor: keep the resolved spelling (exact on case-sensitive systems)
        if name not in entries:
            key = _fold(name)
            same = [e for e in entries if _fold(e) == key and _same_real_entry(current / e, current / name)]
            if len(same) == 1:
                name = same[0]
        current = current / name
    return str(current)


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
        if sys.platform != "win32":  # Windows realpath already returns the on-disk case
            resolved = _on_disk_spelling(resolved)
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


def _validate_dir_spelling(path: Path, os_: OsAdapters) -> str:
    if not isinstance(path, Path):
        raise _invalid()
    raw = os.fspath(path)
    if not raw or "\x00" in raw or len(raw) > 4096:
        raise _invalid()
    os_.paths.reject_unsafe_path(raw)
    _reject_unsafe_spelling(raw)
    if ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not path.is_absolute() or not _is_absolute(raw):
        raise _invalid()
    return raw


def _is_within_checkout(chk_real: Path, cwd_real: Path) -> bool:
    return cwd_real == chk_real or chk_real in cwd_real.parents


def verify_launch_checkout(checkout_path: Path, launch_cwd: Path, os_: OsAdapters) -> None:
    """Verify that ``launch_cwd`` is an owner-only, link-free directory inside ``checkout_path``."""
    raw_chk = _validate_dir_spelling(checkout_path, os_)
    raw_cwd = _validate_dir_spelling(launch_cwd, os_)

    os_.paths.reject_links(checkout_path)
    if os_.permissions.check_ancestors(checkout_path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    phys_chk = physical_checkout(raw_chk)
    if os_.permissions.object_problems(checkout_path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    os_.paths.reject_links(launch_cwd)
    try:
        cwd_st = launch_cwd.lstat()
    except OSError as err:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch") from err
    if stat.S_ISLNK(cwd_st.st_mode):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not stat.S_ISDIR(cwd_st.st_mode):
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if os_.permissions.check_ancestors(launch_cwd):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if os_.permissions.object_problems(launch_cwd):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    phys_cwd = physical_checkout(raw_cwd)

    chk_real = Path(phys_chk.checkout_path)
    cwd_real = Path(phys_cwd.checkout_path)
    if not _is_within_checkout(chk_real, cwd_real):
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
