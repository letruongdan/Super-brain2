"""Shared walk-entry classification and transient not-found helpers across layers."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Literal

MAX_TRANSIENT_WALK_ATTEMPTS = 4
_REPARSE_POINT = 0x400
_NOT_FOUND_WINERRORS = frozenset({2, 3})  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
_NOT_FOUND_ERRNOS = frozenset({errno.ENOENT})

WalkEntryState = Literal["vanished", "recreated", "recreated_link", "fail_closed"]


def same_walk_path(path: Path, root: Path) -> bool:
    """Whether ``path`` refers to ``root`` itself (walk roots never count as transient children)."""
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(root))


def stat_reparse_or_link(st: os.stat_result) -> bool:
    """Whether ``st`` represents a POSIX symlink or Windows reparse point/junction."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def is_not_found_error(err: BaseException) -> bool:
    """Whether an exception (including ``pywintypes.error``) represents not-found (winerror 2/3 or ENOENT)."""
    if isinstance(err, FileNotFoundError):
        return True
    if isinstance(err, OSError):
        winerror = getattr(err, "winerror", None)
        return (winerror in _NOT_FOUND_WINERRORS) or (err.errno in _NOT_FOUND_ERRNOS)
    if type(err).__module__.startswith("pywintypes"):
        winerror = getattr(err, "winerror", None)
        if isinstance(winerror, int):
            return winerror in _NOT_FOUND_WINERRORS
        args = getattr(err, "args", ())
        if args and isinstance(args[0], int):
            return args[0] in _NOT_FOUND_WINERRORS
    return False


def is_not_found_cause(exc: BaseException | None) -> bool:
    """Whether ``exc`` or any exception in its ``__cause__``/``__context__`` chain is a not-found error."""
    seen: set[int] = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if is_not_found_error(cur):
            return True
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return False


def classify_below_root_failure(
    path: Path, root: Path, exc: BaseException | None = None
) -> WalkEntryState:
    """Classify an inspection, scan, or repair failure on ``path`` during a walk anchored at ``root``.

    Walk roots and denied lookups always fail closed; links/reparse points fail as ``recreated_link``; confirmed
    missing entries return ``vanished``; recreated non-link entries after a not-found error return ``recreated``.
    """
    if same_walk_path(path, root):
        return "fail_closed"
    try:
        st = os.lstat(path)
        if stat_reparse_or_link(st) or path.is_symlink():
            return "recreated_link"
    except FileNotFoundError:
        return "vanished"
    except OSError:
        return "fail_closed"
    if is_not_found_cause(exc):
        return "recreated"
    return "fail_closed"
