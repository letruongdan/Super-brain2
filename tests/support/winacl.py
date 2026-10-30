"""Windows ACL helpers for tests (pywin32 stays out of the test bodies)."""

import sys
from pathlib import Path

import pytest


def grant(path: Path, sid_string: str, access_mask: int) -> None:
    """Add an access-allowed ACE for ``sid_string`` to the existing DACL of ``path``."""
    assert sys.platform == "win32"
    import win32security

    sid = win32security.ConvertStringSidToSid(sid_string)
    sd = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION_DS, access_mask, sid)
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION, None, None, dacl, None
    )


def fake_owner(monkeypatch: pytest.MonkeyPatch, path: Path, sid_string: str) -> None:
    """Make the adapter report ``sid_string`` as owner of exactly ``path``."""
    if sys.platform != "win32":
        raise AssertionError("Windows-only helper")
    from superbrain.adapters.os import permissions

    original = permissions._owner_sid
    target = path.absolute()

    def owner_sid(candidate: Path) -> str:
        if candidate.absolute() == target:
            return sid_string
        return str(original(candidate))

    monkeypatch.setattr(permissions, "_owner_sid", owner_sid)
