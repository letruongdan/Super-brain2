"""Path-safety adapter and default data-root resolution."""

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from superbrain.core.errors import BrainError, ErrorCode

_REPARSE_POINT = 0x400
_APP_DIR = "ensemble-brain"


def _is_link(path: Path) -> bool:
    # Checked without resolving, so a link is detected before it is ever followed.
    try:
        if path.is_symlink():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except (FileNotFoundError, NotADirectoryError):
        # ENOTDIR: a parent is not a directory, so the path cannot exist.
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect path for links: {err}") from err
    return bool(attributes & _REPARSE_POINT)


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
        supplied = Path(path).absolute()
        for candidate in (supplied, *supplied.parents, *(Path(e).absolute() for e in entries)):
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
