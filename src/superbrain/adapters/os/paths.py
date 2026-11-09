"""Path-safety adapter and default data-root resolution."""

import os
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from superbrain.core.errors import BrainError, ErrorCode

_REPARSE_POINT = 0x400
_APP_DIR = "ensemble-brain"
_ORIG_IS_SYMLINK = Path.is_symlink
_ORIG_PATH_LSTAT = Path.lstat


def _is_link_str(raw: str) -> bool:
    try:
        st = os.lstat(raw)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect path for links: {err}") from err
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _is_link(path: Path) -> bool:
    # Checked without resolving, so a link is detected before it is ever followed.
    if Path.is_symlink is _ORIG_IS_SYMLINK and Path.lstat is _ORIG_PATH_LSTAT:
        return _is_link_str(os.fspath(path))
    try:
        if Path.is_symlink is not _ORIG_IS_SYMLINK and path.is_symlink():
            return True
        st = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        # ENOTDIR: a parent is not a directory, so the path cannot exist.
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect path for links: {err}") from err
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def is_link(path: Path) -> bool:
    """Whether ``path`` itself (not its parents) is a symlink or a reparse point such as a junction; never followed."""
    return _is_link(path)


def _fast_abs_str(raw: str) -> str:
    if sys.platform == "win32":
        if len(raw) >= 3 and raw[0].isalpha() and raw[1] == ":" and raw[2] in ("\\", "/") and ".." not in raw:
            return os.path.normpath(raw)
        return str(Path(raw).absolute())
    if raw.startswith("/") and ".." not in raw:
        return os.path.normpath(raw)
    return str(Path(raw).absolute())


class OsPathSafety:
    def reject_unsafe_path(self, raw: str) -> None:
        if sys.platform != "win32":
            return
        # Device/extended prefixes (\?\, \.\) and UNC (\server\...) all start with two separators.
        if raw.startswith(("\\\\", "//")):
            raise BrainError(ErrorCode.UNSAFE_PATH, "extended, device and UNC paths are not allowed")
        drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
        if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
            raise BrainError(ErrorCode.UNSAFE_PATH, "':' is only allowed after a drive letter")

    def reject_links(self, path: Path, *, entries: Sequence[Path] = ()) -> None:
        if Path.is_symlink is _ORIG_IS_SYMLINK and Path.lstat is _ORIG_PATH_LSTAT:
            cur = _fast_abs_str(os.fspath(path))
            seen_str: set[str] = set()
            while cur not in seen_str:
                seen_str.add(cur)
                if _is_link_str(cur):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "path must not contain symlink or reparse points")
                parent = os.path.dirname(cur)
                if parent == cur:
                    break
                cur = parent
            for entry in entries:
                ecur = _fast_abs_str(os.fspath(entry))
                if ecur in seen_str:
                    continue
                seen_str.add(ecur)
                if _is_link_str(ecur):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "path must not contain symlink or reparse points")
            return

        supplied = Path(path).absolute()
        seen: set[Path] = set()
        for candidate in (supplied, *supplied.parents, *(Path(e).absolute() for e in entries)):
            if candidate in seen:
                continue
            seen.add(candidate)
            if _is_link(candidate):
                raise BrainError(ErrorCode.UNSAFE_PATH, "path must not contain symlink or reparse points")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise BrainError(ErrorCode.INVALID_INPUT, f"environment variable {name} is not set")
    return value


def default_data_root(env: Mapping[str, str], platform: str) -> PurePath:
    """Pure path in the flavor of ``platform``; callers wrap it in ``Path`` for the running host."""
    home = env.get("SUPERBRAIN_HOME")
    pure: PurePath
    if home:
        pure = PureWindowsPath(home) if platform == "win32" else PurePosixPath(home)
    elif platform == "win32":
        pure = PureWindowsPath(_required(env, "LOCALAPPDATA")) / _APP_DIR
    elif platform == "darwin":
        pure = PurePosixPath(_required(env, "HOME")) / "Library" / "Application Support" / _APP_DIR
    else:
        xdg = env.get("XDG_DATA_HOME")
        base = PurePosixPath(xdg) if xdg else PurePosixPath(_required(env, "HOME")) / ".local" / "share"
        pure = base / _APP_DIR
    return pure
