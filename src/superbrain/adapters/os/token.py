"""Facts about the current process token (spec 4.3 owner policy: the acceptance environment is checked for real).

Windows only: whether the token is an AppContainer token (``TokenIsAppContainer``) and its mandatory integrity
level. Elsewhere there is no such token and both are ``None``. A query that fails raises ``OSError``.
"""

import sys

INTEGRITY_LEVELS = ("untrusted", "low", "medium", "high", "system")


def integrity_level_name(rid: int) -> str:
    """The name of a mandatory-label RID (``S-1-16-<rid>``): below 0x1000 untrusted, then low, medium (including
    medium-plus 0x2100), high, and system (0x4000 and above, protected process included)."""
    for bound, name in zip((0x1000, 0x2000, 0x3000, 0x4000), INTEGRITY_LEVELS, strict=False):
        if rid < bound:
            return name
    return "system"


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    from typing import Any

    import pywintypes
    import win32api
    import win32con
    import win32security

    _TOKEN_IS_APP_CONTAINER = 29  # TOKEN_INFORMATION_CLASS; pywin32 does not decode it

    def _open_token() -> Any:
        try:
            return win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        except pywintypes.error as err:
            raise OSError(f"OpenProcessToken failed: {err}") from err

    def is_app_container() -> bool | None:
        token = _open_token()
        value = wintypes.DWORD()
        returned = wintypes.DWORD()
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        ok = advapi32.GetTokenInformation(
            int(token), _TOKEN_IS_APP_CONTAINER, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(returned)
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return value.value != 0

    def integrity_level() -> str | None:
        try:
            sid, _attributes = win32security.GetTokenInformation(_open_token(), win32security.TokenIntegrityLevel)
            rid = int(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1))
        except pywintypes.error as err:
            raise OSError(f"cannot read the token integrity level: {err}") from err
        return integrity_level_name(rid)

else:

    def is_app_container() -> bool | None:
        return None

    def integrity_level() -> str | None:
        return None
