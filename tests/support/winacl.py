"""Windows ACL helpers for tests (pywin32 stays out of the test bodies)."""

import sys
from pathlib import Path

import pytest


def grant(path: Path, sid_string: str, access_mask: int, flags: int = 0) -> None:
    """Add an access-allowed ACE for ``sid_string`` to the existing DACL of ``path``."""
    assert sys.platform == "win32"
    import win32security

    sid = win32security.ConvertStringSidToSid(sid_string)
    sd = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, flags, access_mask, sid)
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


def fake_unsupported_ace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every DACL read raise ``NotImplementedError`` from ``GetAce``, like a callback ACE does in pywin32."""
    if sys.platform != "win32":
        raise AssertionError("Windows-only helper")
    import win32security

    from superbrain.adapters.os import permissions

    original = permissions._security_descriptor

    class _Dacl:
        def GetAceCount(self) -> int:  # noqa: N802 (mirrors the pywin32 API)
            return 1

        def GetAce(self, index: int) -> object:  # noqa: N802
            raise NotImplementedError("unsupported ACE type 9")

    class _Descriptor:
        def GetSecurityDescriptorDacl(self) -> _Dacl:  # noqa: N802
            return _Dacl()

    def descriptor(path: Path, info: int) -> object:
        if info == win32security.DACL_SECURITY_INFORMATION:
            return _Descriptor()
        return original(path, info)

    monkeypatch.setattr(permissions, "_security_descriptor", descriptor)


def security_sddl(path: Path) -> str:
    """Owner and DACL of ``path`` as an SDDL string, for "unchanged" comparisons."""
    assert sys.platform == "win32"
    import win32security

    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info)
    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, info)
    return str(sddl)
