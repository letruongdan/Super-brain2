"""OS-specific executable lookup, subprocess spawn flags, and Windows Appx host probing."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from superbrain.core._kernel_base import OPAQUE_ID_RE

__all__ = [
    "find_host_executable",
    "probe_windows_codex_appx_version",
    "run_host_version_command",
]

_REPARSE_POINT = 0x400
_APPX_CODEX_RE = re.compile(r"^OpenAI\.Codex_([0-9]+(?:\.[0-9A-Za-z.-]+)+)_", re.IGNORECASE)
_APPX_REGISTRY_KEY = (
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
)


def _is_link_or_non_regular(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
    except OSError:
        return True
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return True
    return not stat.S_ISREG(st.st_mode)


def find_host_executable(name: str) -> Path | None:
    """Locate ``name`` strictly in absolute directories of ``PATH`` (never CWD or symlinks)."""
    raw_path = os.environ.get("PATH", "")
    if not raw_path:
        return None
    if sys.platform == "win32":
        raw_exts = [
            ext.strip()
            for ext in os.environ.get("PATHEXT", ".EXE;.CMD;.BAT;.COM").split(os.pathsep)
            if ext.strip()
        ]
        exts: tuple[str, ...] = tuple(raw_exts) or (".EXE", ".CMD", ".BAT")
    else:
        exts = ("",)
    for raw_dir in raw_path.split(os.pathsep):
        if not raw_dir or "\x00" in raw_dir:
            continue
        directory = Path(raw_dir)
        if not directory.is_absolute() or ".." in directory.parts:
            continue
        for ext in exts:
            candidate = directory / f"{name}{ext}"
            if _is_link_or_non_regular(candidate):
                continue
            if os.access(candidate, os.X_OK):
                return candidate
    return None


def probe_windows_codex_appx_version() -> str | None:
    """Inspect HKCU AppModel package keys on Windows for installed MSIX ``OpenAI.Codex`` version."""
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _APPX_REGISTRY_KEY) as key:
            idx = 0
            while True:
                try:
                    subkey = winreg.EnumKey(key, idx)
                except OSError:
                    break
                idx += 1
                match = _APPX_CODEX_RE.match(subkey)
                if match is not None:
                    token = match.group(1)
                    if OPAQUE_ID_RE.fullmatch(token):
                        return token
    except OSError:
        return None
    return None


def run_host_version_command(exe: Path, *, timeout_s: float = 2.0) -> str | None:
    """Run ``<exe> --version`` safely with OS window-suppression flags and return stdout on ``rc=0``."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            [str(exe), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout
