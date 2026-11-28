"""Deadline-bound rename, directory-sync and unlink primitives shared by the outbox storage modules."""

from __future__ import annotations

import errno
import os
import time
from collections.abc import Callable
from contextvars import ContextVar, Token
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import default_outbox_dir_sync

_BUSY_REPLACE_WINERRORS = frozenset({5, 32})
_BUSY_REPLACE_DELAYS = (0.01, 0.02, 0.05, 0.1, 0.2)
# A directory handle the OS cannot open or fsync: entry durability is then the filesystem's own mechanism.
_DIR_OPEN_UNSUPPORTED = frozenset({errno.EACCES, errno.EPERM, errno.EISDIR, errno.EINVAL})
_DIR_FSYNC_UNSUPPORTED = frozenset(
    {errno.EINVAL, errno.EBADF, errno.ENOSYS, getattr(errno, "ENOTSUP", errno.EINVAL),
     getattr(errno, "EOPNOTSUPP", errno.EINVAL)}
)
_ACTIVE_DEADLINE_CHECK: ContextVar[Callable[[], None] | None] = ContextVar("_outbox_deadline_check", default=None)
_ACTIVE_DEADLINE_REMAINING: ContextVar[Callable[[], int] | None] = ContextVar(
    "_outbox_deadline_remaining", default=None
)


def push_deadline_check(fn: Callable[[], None] | None) -> Token[Callable[[], None] | None]:
    """Bind ``fn`` as the active deadline callback for nested outbox I/O."""
    return _ACTIVE_DEADLINE_CHECK.set(fn)


def reset_deadline_check(tok: Token[Callable[[], None] | None]) -> None:
    """Restore the previous active deadline callback."""
    _ACTIVE_DEADLINE_CHECK.reset(tok)


def push_deadline_remaining(fn: Callable[[], int] | None) -> Token[Callable[[], int] | None]:
    """Bind ``fn`` (nanoseconds left before the deadline) for waits inside nested outbox I/O."""
    return _ACTIVE_DEADLINE_REMAINING.set(fn)


def reset_deadline_remaining(tok: Token[Callable[[], int] | None]) -> None:
    """Restore the previous remaining-budget callback."""
    _ACTIVE_DEADLINE_REMAINING.reset(tok)


def active_deadline_check() -> Callable[[], None] | None:
    """Return active bound deadline callback, if any."""
    return _ACTIVE_DEADLINE_CHECK.get()


def unlink_before_deadline(path: Path, check_deadline: Callable[[], None] | None = None) -> None:
    """Delete ``path`` only while the deadline (explicit or active) still has budget."""
    dl = check_deadline or _ACTIVE_DEADLINE_CHECK.get()
    if dl is not None:
        dl()
    path.unlink(missing_ok=True)


def staging_cleanup_allowed(check_deadline: Callable[[], None] | None = None) -> bool:
    """True while the deadline still has budget; past the cutoff a failed step leaves its staging to the next sweep
    and the step's own error is kept."""
    dl = check_deadline or _ACTIVE_DEADLINE_CHECK.get()
    if dl is None:
        return True
    try:
        dl()
    except BrainError:
        return False
    return True


def wait_within_budget(wait: float) -> None:
    """Sleep ``wait`` seconds after checking the deadline, never longer than the remaining budget."""
    dl = _ACTIVE_DEADLINE_CHECK.get()
    if dl is not None:
        dl()
    remaining = _ACTIVE_DEADLINE_REMAINING.get()
    time.sleep(wait if remaining is None else min(wait, max(0, remaining()) / 1e9))


def replace_file_resilient(src: Path, dst: Path) -> None:
    """Replace ``dst`` with ``src``; the deadline is checked before every attempt and every busy wait, and a wait
    never outlasts the remaining budget."""
    for delay in (*_BUSY_REPLACE_DELAYS, None):
        dl = _ACTIVE_DEADLINE_CHECK.get()
        if dl is not None:
            dl()
        try:
            os.replace(src, dst)
            return
        except OSError as err:
            if delay is None or getattr(err, "winerror", None) not in _BUSY_REPLACE_WINERRORS:
                raise
            wait = delay
        wait_within_budget(wait)


def _fallback_sync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError as err:
        if err.errno in _DIR_OPEN_UNSUPPORTED:
            return
        raise
    try:
        os.fsync(fd)
    except OSError as err:
        if err.errno not in _DIR_FSYNC_UNSUPPORTED:
            raise
    finally:
        os.close(fd)


def sync_existing_dirs(*directories: Path) -> None:
    """Sync every directory that exists, so entries an earlier attempt could not confirm are durable before use."""
    for directory in directories:
        if os.path.isdir(directory):
            sync_dir(directory)


def sync_dir(directory: Path) -> None:
    """Persist directory entries; an OS that cannot sync directories is accepted, a real I/O error is raised so
    the caller stops before its next publication step."""
    try:
        registered = default_outbox_dir_sync()
        if registered is not None:
            registered(directory)
        else:
            _fallback_sync_dir(directory)
    except OSError as err:
        raise raise_storage_error(err, "cannot sync outbox directory") from err


_ENOSPC_WINERROR = 112


def raise_storage_error(err: OSError, message: str) -> BrainError:
    """One mapping for every outbox write: a full disk is STORAGE_FULL (the hook then records an outbox_full gap)."""
    winerr = getattr(err, "winerror", None)
    if err.errno in (errno.ENOSPC, errno.EDQUOT) or winerr == _ENOSPC_WINERROR:
        return BrainError(ErrorCode.STORAGE_FULL, "storage full")
    if getattr(errno, "ELOOP", None) is not None and err.errno == errno.ELOOP:
        return BrainError(ErrorCode.UNSAFE_PATH, f"symlink detected in outbox: {err}")
    return BrainError(ErrorCode.IO_ERROR, f"{message}: {err}")
