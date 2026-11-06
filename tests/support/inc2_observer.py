"""Test-only bounded directory snapshot observer (fixture for Task 3 observer tests).

The real observer is gated to SP2/SP5 (secure bounded reading review); this fixture lives under ``tests/support``
and is never shipped. Every regular file is hashed from its bytes on every observation: size and mtime are never
trusted as proof of unchanged content. Links are recorded by name and never followed; ``.git`` is skipped.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable
from datetime import UTC

from superbrain.adapters.os.workspaces import physical_checkout
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError
from superbrain.core.kernel import SnapshotDescriptor, SnapshotObservation, SnapshotStatus, WorkspaceBinding
from superbrain.ports.clock import Clock

_CHUNK = 1 << 20


class _Budget(Exception):
    pass


class _Limit(Exception):
    pass


class DirectorySnapshotObserver:
    """Bounded content snapshot of an approved checkout directory (test fixture only)."""

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
