"""Workspace identity adapters: canonical remote locators, physical checkout identity and a bounded directory
snapshot observer (Task 3, D3).

Pure string canonicalization for locators: nothing here fetches a URL, runs ``git`` or any project program, hook or
config. Physical identity comes from the file system (``realpath`` + ``stat`` device/file index), never from a
lowercased spelling. Error messages are static and never echo the caller's input.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    TrustedLocator,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.ports.clock import Clock

_MAX_LOCATOR = 2048
_FORBIDDEN_IN_PATH = re.compile(r"[\x00-\x20\x7f%\"'<>`|^{}]")
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f%\\\"'<>`|^{}]")
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~+-]{1,255}")
_SCP_RE = re.compile(r"(?:[A-Za-z0-9._-]{1,64}@)?([A-Za-z0-9.-]{2,253}):(?!//)(.+)")
_WIN_DRIVE_RE = re.compile(r"([A-Za-z]):[\\/](.*)")
_DEFAULT_PORTS = {"https": 443, "ssh": 22}
_CHUNK = 1 << 20


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _segments(path: str, *, allow_empty: bool = False) -> list[str]:
    parts = [part for part in re.split(r"[/\\]+", path) if part]
    if not parts and not allow_empty:
        raise _invalid()
    for part in parts:
        if part in {".", ".."} or _SEGMENT_RE.fullmatch(part) is None:
            raise _invalid()
    if parts and parts[-1].endswith(".git") and len(parts[-1]) > 4:
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
    """``fsid:<device>:<file index>`` of the directory: equal for every spelling or link that reaches it."""


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


def _check_owner(path: str, st: os.stat_result) -> None:
    if sys.platform == "win32":
        from superbrain.adapters.os import permissions

        if permissions._owner_sid(Path(path)) != permissions._current_user_sid():
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    elif st.st_uid != os.geteuid():
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


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
    try:
        resolved = os.path.realpath(raw_path, strict=True)
        st = os.stat(resolved)
    except (OSError, ValueError):
        resolved = None
    if resolved is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    _reject_unsafe_spelling(resolved)
    if not stat.S_ISDIR(st.st_mode):
        raise _invalid()
    if not st.st_ino:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    _check_owner(resolved, st)
    return PhysicalCheckout(checkout_path=resolved, path_identity=f"fsid:{st.st_dev:x}:{st.st_ino:x}")


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


class _Budget(Exception):
    pass


class _Limit(Exception):
    pass


class DirectorySnapshotObserver:
    """Bounded content snapshot of an approved checkout directory (fixture-grade, not activated in production).

    Every regular file is hashed from its bytes on every observation: size and mtime are never trusted as proof of
    unchanged content. Links are recorded by name and never followed; ``.git`` is skipped; nothing is executed.
    """

    def __init__(
        self,
        *,
        clock: Clock,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        max_files: int = 20_000,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        self._clock = clock
        self._monotonic_ns = monotonic_ns
        self._max_files = max_files
        self._max_bytes = max_bytes

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        if self._monotonic_ns() >= deadline_ns:
            return SnapshotObservation(SnapshotStatus.DEADLINE, None)
        status: SnapshotStatus | None = None
        records: list[list[str]] = []
        try:
            physical = physical_checkout(binding.checkout_path)
            if physical.checkout_path != binding.checkout_path:
                status = SnapshotStatus.UNAVAILABLE
            else:
                self._walk(physical.checkout_path, deadline_ns, records)
        except _Budget:
            status = SnapshotStatus.DEADLINE
        except (_Limit, OSError, BrainError):
            status = SnapshotStatus.UNAVAILABLE
        if status is not None:
            return SnapshotObservation(status, None)
        if self._monotonic_ns() > deadline_ns:
            return SnapshotObservation(SnapshotStatus.DEADLINE, None)
        observed_at = self._clock.now().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        descriptor = SnapshotDescriptor(
            kind="directory",
            tree_or_head_digest=digest_bytes(canonical_json(sorted(records))),
            dirty=False,
            dirty_digest=None,
            observed_at=observed_at,
        )
        return SnapshotObservation(SnapshotStatus.AVAILABLE, descriptor)

    def _walk(self, root: str, deadline_ns: int, records: list[list[str]]) -> None:
        files = total = 0
        pending: list[tuple[str, str]] = [(root, "")]
        while pending:
            directory, rel = pending.pop()
            with os.scandir(directory) as entries:
                listing = sorted(entries, key=lambda e: e.name)
            for entry in listing:
                self._tick(deadline_ns)
                name = f"{rel}/{entry.name}" if rel else entry.name
                info = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                    records.append(["link", name, ""])
                elif stat.S_ISDIR(info.st_mode):
                    if entry.name != ".git":
                        pending.append((entry.path, name))
                elif stat.S_ISREG(info.st_mode):
                    files += 1
                    if files > self._max_files:
                        raise _Limit
                    digest, size = self._hash(entry.path, deadline_ns)
                    total += size
                    if total > self._max_bytes:
                        raise _Limit
                    records.append(["file", name, digest])

    def _tick(self, deadline_ns: int) -> None:
        if self._monotonic_ns() >= deadline_ns:
            raise _Budget

    def _hash(self, path: str, deadline_ns: int) -> tuple[str, int]:
        hasher = hashlib.sha256()
        size = 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            while chunk := os.read(fd, _CHUNK):
                self._tick(deadline_ns)
                hasher.update(chunk)
                size += len(chunk)
                if size > self._max_bytes:
                    raise _Limit
        finally:
            os.close(fd)
        return "sha256:" + hasher.hexdigest(), size
