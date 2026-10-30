"""Owner-only permission adapters (POSIX modes, Windows DACLs)."""

import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import PermissionProblem

_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_INHERIT_ONLY_ACE = 0x08
_NOT_FOUND_ERRORS = (2, 3)  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND


def _inspect_error(path: Path, err: BaseException) -> BrainError:
    return BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot inspect permissions of {path}: {err}")


def _tree(root: Path) -> Iterator[Path]:
    """``root`` and everything below it, without following links; unreadable directories raise."""

    def fail(err: OSError) -> None:
        raise _inspect_error(Path(err.filename or root), err)

    yield root
    if root.is_symlink() or not root.is_dir():
        return
    for directory, dirnames, filenames in os.walk(root, onerror=fail):
        for name in (*dirnames, *filenames):
            yield Path(directory) / name


def _ancestors(path: Path) -> list[Path]:
    return list(Path(os.path.abspath(path)).parents)


if sys.platform != "win32":

    class PosixPermissionGuard:
        def secure_directory(self, path: Path) -> None:
            self._chmod(path, 0o700)

        def secure_file(self, path: Path) -> None:
            self._chmod(path, 0o600)

        @staticmethod
        def _chmod(path: Path, mode: int) -> None:
            try:
                os.chmod(path, mode)
            except OSError as err:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot restrict {path}: {err}") from err

        def problems(self, root: Path) -> list[PermissionProblem]:
            return [problem for path in _tree(root) for problem in self.object_problems(path)]

        def object_problems(self, path: Path) -> list[PermissionProblem]:
            try:
                st = path.lstat()
            except OSError as err:
                raise _inspect_error(path, err) from err
            if stat.S_ISLNK(st.st_mode):
                return []
            if st.st_mode & 0o077:
                mode = stat.S_IMODE(st.st_mode)
                return [PermissionProblem(path, f"mode {mode:04o} grants group/other access")]
            if st.st_uid != os.geteuid():
                return [PermissionProblem(path, f"owned by uid {st.st_uid}, not the current user")]
            return []

        def check_ancestors(self, path: Path) -> list[PermissionProblem]:
            found: list[PermissionProblem] = []
            euid = os.geteuid()
            for ancestor in _ancestors(path):
                try:
                    st = ancestor.stat()
                except FileNotFoundError:
                    continue
                except OSError as err:
                    raise _inspect_error(ancestor, err) from err
                if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
                    found.append(PermissionProblem(ancestor, "writable by group/other without the sticky bit"))
                elif st.st_uid not in (0, euid):
                    reason = f"owned by uid {st.st_uid}, neither root nor the current user"
                    found.append(PermissionProblem(ancestor, reason))
            return found


if sys.platform == "win32":
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32security

    def _current_user_sid() -> str:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return str(win32security.ConvertSidToStringSid(sid))


    def _security_descriptor(path: Path, info: int) -> Any:
        try:
            return win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info)
        except pywintypes.error as err:
            if err.winerror in _NOT_FOUND_ERRORS:
                raise FileNotFoundError(str(path)) from err
            raise _inspect_error(path, err) from err


    def _owner_sid(path: Path) -> str:
        """Owner SID string of ``path``; kept small and module-level so tests can substitute it."""
        sd = _security_descriptor(path, win32security.OWNER_SECURITY_INFORMATION)
        return str(win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()))


    def _allowed_aces(path: Path) -> list[tuple[int, int, str]] | None:
        """(ace flags, access mask, sid) of every access-allowed ACE, or ``None`` for a NULL DACL."""
        sd = _security_descriptor(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return None
        aces: list[tuple[int, int, str]] = []
        try:
            for index in range(dacl.GetAceCount()):
                (ace_type, flags), mask, sid = dacl.GetAce(index)[:3]
                if ace_type == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE:
                    aces.append((flags, mask, str(win32security.ConvertSidToStringSid(sid))))
        except (NotImplementedError, pywintypes.error, OSError) as err:
            # e.g. conditional/callback ACEs, which pywin32 cannot decode
            raise _inspect_error(path, err) from err
        return aces


    class WindowsPermissionGuard:
        def secure_directory(self, path: Path) -> None:
            self._secure(path, ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE)

        def secure_file(self, path: Path) -> None:
            self._secure(path, 0)

        @staticmethod
        def _secure(path: Path, inherit_flags: int) -> None:
            try:
                user = win32security.ConvertStringSidToSid(_current_user_sid())
                system = win32security.ConvertStringSidToSid(_SYSTEM_SID)
                dacl = win32security.ACL()
                for sid in (user, system):
                    dacl.AddAccessAllowedAceEx(
                        win32security.ACL_REVISION_DS, inherit_flags, ntsecuritycon.FILE_ALL_ACCESS, sid
                    )
                win32security.SetNamedSecurityInfo(
                    str(path),
                    win32security.SE_FILE_OBJECT,
                    win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION
                    | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                    user,
                    None,
                    dacl,
                    None,
                )
            except pywintypes.error as err:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot restrict {path}: {err}") from err

        def problems(self, root: Path) -> list[PermissionProblem]:
            user = _current_user_sid()
            return [problem for path in _tree(root) for problem in self._object_problems(path, user)]

        def object_problems(self, path: Path) -> list[PermissionProblem]:
            return self._object_problems(path, _current_user_sid())

        def _object_problems(self, path: Path, user: str) -> list[PermissionProblem]:
            if path.is_symlink():
                return []
            reason = self._entry_problem(path, user, {user, _SYSTEM_SID})
            return [PermissionProblem(path, reason)] if reason else []

        @staticmethod
        def _entry_problem(path: Path, user: str, allowed: set[str]) -> str | None:
            try:
                owner = _owner_sid(path)
                aces = _allowed_aces(path)
            except FileNotFoundError as err:
                raise _inspect_error(path, err) from err
            if owner != user:
                return f"owned by {owner}, not the current user"
            if aces is None:
                return "NULL DACL grants everyone access"
            for _flags, _mask, sid in aces:
                if sid not in allowed:
                    return f"ACE grants access to {sid}"
            return None

        def check_ancestors(self, path: Path) -> list[PermissionProblem]:
            # Rights that let a holder rename/delete the ancestor or its entries, or rewrite its DACL or owner.
            # DELETE on the ancestor itself suffices to rename it away (given add-subdirectory elsewhere).
            takeover = (
                ntsecuritycon.DELETE
                | ntsecuritycon.FILE_DELETE_CHILD
                | ntsecuritycon.WRITE_DAC
                | ntsecuritycon.WRITE_OWNER
                | ntsecuritycon.GENERIC_ALL
            )
            found: list[PermissionProblem] = []
            trusted = {_current_user_sid(), _SYSTEM_SID, _ADMINISTRATORS_SID, _TRUSTED_INSTALLER_SID}
            for ancestor in _ancestors(path):
                try:
                    owner = _owner_sid(ancestor)
                    aces = _allowed_aces(ancestor)
                except FileNotFoundError:
                    continue
                if owner not in trusted:
                    found.append(PermissionProblem(ancestor, f"owned by {owner}, who can rewrite its DACL"))
                elif aces is None:
                    found.append(PermissionProblem(ancestor, "NULL DACL grants everyone full access"))
                else:
                    for flags, mask, sid in aces:
                        if sid not in trusted and not flags & _INHERIT_ONLY_ACE and mask & takeover:
                            found.append(
                                PermissionProblem(ancestor, f"ACE grants takeover rights to {sid} (mask {mask:#x})")
                            )
                            break
            return found
