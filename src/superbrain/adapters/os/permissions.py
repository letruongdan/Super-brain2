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
_ORIG_PATH_IS_SYMLINK = Path.is_symlink
_REPARSE_POINT = 0x400


def _is_reparse_or_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _inspect_error(path: Path, err: BaseException) -> BrainError:
    return BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot inspect permissions of {path}: {err}")


def vanished_below(path: Path, root: Path) -> bool:
    """``path`` lies strictly below a walk's ``root`` and no longer exists: it was removed after it was listed.

    A removed entry grants nobody access, so a permission walk skips it; the walk's own root never counts. Only
    "not found" counts as removed: an entry that cannot be looked up for any other reason is still checked.
    """
    if os.path.abspath(path) == os.path.abspath(root):
        return False
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _tree(root: Path) -> Iterator[Path]:
    """``root`` and everything below it, without following links; unreadable directories raise."""

    def fail(err: OSError) -> None:
        failed = Path(err.filename or root)
        if isinstance(err, FileNotFoundError) and vanished_below(failed, root):
            return
        raise _inspect_error(failed, err)

    yield root
    try:
        root_st = root.lstat()
    except OSError:
        root_st = None
    if root.is_symlink() or (root_st is not None and _is_reparse_or_link(root_st)) or not root.is_dir():
        return
    for directory, dirnames, filenames in os.walk(root, onerror=fail):
        kept_dirs: list[str] = []
        for dname in dirnames:
            cand = Path(directory) / dname
            try:
                if cand.is_symlink() or _is_reparse_or_link(cand.lstat()):
                    continue
            except OSError:
                continue
            kept_dirs.append(dname)
        dirnames[:] = kept_dirs
        for name in (*dirnames, *filenames):
            yield Path(directory) / name


def _non_symlink_tree(root: Path) -> Iterator[Path]:
    """Yield non-symlink paths under ``root`` via ``scandir`` when ``Path.is_symlink`` is unpatched."""
    if Path.is_symlink is not _ORIG_PATH_IS_SYMLINK:
        for path in _tree(root):
            try:
                st = path.lstat()
            except OSError:
                st = None
            if not path.is_symlink() and (st is None or not _is_reparse_or_link(st)):
                yield path
        return
    try:
        st = os.lstat(root)
    except FileNotFoundError as err:
        raise _inspect_error(root, err) from err
    except OSError as err:
        raise _inspect_error(root, err) from err
    if _is_reparse_or_link(st):
        return
    yield root
    if not stat.S_ISDIR(st.st_mode):
        return
    stack: list[str] = [os.fspath(root)]
    while stack:
        current = stack.pop()
        children: list[str] = []
        subdirs: list[str] = []
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entry.is_symlink():
                        continue
                    try:
                        est = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # removed after it was listed
                    except OSError as err:
                        raise _inspect_error(Path(entry.path), err) from err
                    if _is_reparse_or_link(est):
                        continue
                    children.append(entry.path)
                    if stat.S_ISDIR(est.st_mode):
                        subdirs.append(entry.path)
        except OSError as err:
            failed = Path(err.filename or current)
            if isinstance(err, FileNotFoundError) and vanished_below(failed, root):
                continue
            raise _inspect_error(failed, err) from err
        for child in children:
            yield Path(child)
        stack.extend(reversed(subdirs))


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
            found: list[PermissionProblem] = []
            for path in _tree(root):
                try:
                    found.extend(self.object_problems(path))
                except BrainError:
                    if not vanished_below(path, root):
                        raise
            return found

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

    def owned_by_current_user(path: Path) -> bool:
        """Whether ``path`` (links followed) is owned by the current user."""
        try:
            return os.stat(path).st_uid == os.geteuid()
        except OSError as err:
            raise _inspect_error(path, err) from err


if sys.platform == "win32":
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32security

    _USER_SID_CACHE: list[str] = []
    _SECURE_PYSID_CACHE: dict[str, tuple[Any, Any]] = {}
    _KNOWN_PYSIDS: list[tuple[Any, str]] = [
        (win32security.ConvertStringSidToSid(_SYSTEM_SID), _SYSTEM_SID),
        (win32security.ConvertStringSidToSid(_ADMINISTRATORS_SID), _ADMINISTRATORS_SID),
        (win32security.ConvertStringSidToSid(_TRUSTED_INSTALLER_SID), _TRUSTED_INSTALLER_SID),
    ]

    def _current_user_sid() -> str:
        if _USER_SID_CACHE:
            return _USER_SID_CACHE[0]
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            user_sid = str(win32security.ConvertSidToStringSid(sid))
        finally:
            win32api.CloseHandle(token)
        _USER_SID_CACHE.append(user_sid)
        _KNOWN_PYSIDS.insert(0, (win32security.ConvertStringSidToSid(user_sid), user_sid))
        return user_sid

    def _sid_str(sid: Any) -> str:
        for known_pysid, known_str in _KNOWN_PYSIDS:
            if sid == known_pysid:
                return known_str
        return str(win32security.ConvertSidToStringSid(sid))

    def _security_descriptor(path: Path, info: int) -> Any:
        try:
            return win32security.GetNamedSecurityInfo(os.fspath(path), win32security.SE_FILE_OBJECT, info)
        except pywintypes.error as err:
            if err.winerror in _NOT_FOUND_ERRORS:
                raise FileNotFoundError(str(path)) from err
            raise _inspect_error(path, err) from err

    def _owner_sid(path: Path) -> str:
        """Owner SID string of ``path``; kept small and module-level so tests can substitute it."""
        sd = _security_descriptor(path, win32security.OWNER_SECURITY_INFORMATION)
        return _sid_str(sd.GetSecurityDescriptorOwner())

    def owned_by_current_user(path: Path) -> bool:
        """Whether ``path`` is owned by the current user's SID."""
        try:
            return _owner_sid(path) == _current_user_sid()
        except FileNotFoundError as err:
            raise _inspect_error(path, err) from err

    def _decode_allowed_aces(path: Path, sd: Any) -> list[tuple[int, int, str]] | None:
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return None
        aces: list[tuple[int, int, str]] = []
        try:
            for index in range(dacl.GetAceCount()):
                (ace_type, flags), mask, sid = dacl.GetAce(index)[:3]
                if ace_type == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE:
                    aces.append((flags, mask, _sid_str(sid)))
        except (NotImplementedError, pywintypes.error, OSError) as err:
            # e.g. conditional/callback ACEs, which pywin32 cannot decode
            raise _inspect_error(path, err) from err
        return aces

    def _allowed_aces(path: Path) -> list[tuple[int, int, str]] | None:
        """(ace flags, access mask, sid) of every access-allowed ACE, or ``None`` for a NULL DACL."""
        sd = _security_descriptor(path, win32security.DACL_SECURITY_INFORMATION)
        return _decode_allowed_aces(path, sd)

    _ORIG_OWNER_SID = _owner_sid
    _ORIG_SECURITY_DESCRIPTOR = _security_descriptor
    _ORIG_ALLOWED_ACES = _allowed_aces

    def _owner_and_allowed_aces(path: Path) -> tuple[str, list[tuple[int, int, str]] | None]:
        if (
            _owner_sid is _ORIG_OWNER_SID
            and _security_descriptor is _ORIG_SECURITY_DESCRIPTOR
            and _allowed_aces is _ORIG_ALLOWED_ACES
        ):
            sd = _security_descriptor(
                path,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = _sid_str(sd.GetSecurityDescriptorOwner())
            return owner, _decode_allowed_aces(path, sd)
        return _owner_sid(path), _allowed_aces(path)

    class WindowsPermissionGuard:
        def secure_directory(self, path: Path) -> None:
            self._secure(path, ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE)

        def secure_file(self, path: Path) -> None:
            self._secure(path, 0)

        @staticmethod
        def _secure(path: Path, inherit_flags: int) -> None:
            try:
                user_sid = _current_user_sid()
                cached_sids = _SECURE_PYSID_CACHE.get(user_sid)
                if cached_sids is None:
                    user = win32security.ConvertStringSidToSid(user_sid)
                    system = win32security.ConvertStringSidToSid(_SYSTEM_SID)
                    if _USER_SID_CACHE and user_sid == _USER_SID_CACHE[0]:
                        _SECURE_PYSID_CACHE[user_sid] = (user, system)
                else:
                    user, system = cached_sids
                dacl = win32security.ACL()
                for sid in (user, system):
                    dacl.AddAccessAllowedAceEx(
                        win32security.ACL_REVISION_DS, inherit_flags, ntsecuritycon.FILE_ALL_ACCESS, sid
                    )
                win32security.SetNamedSecurityInfo(
                    os.fspath(path),
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
            allowed = {user, _SYSTEM_SID}
            found: list[PermissionProblem] = []
            for path in _non_symlink_tree(root):
                try:
                    reason = self._entry_problem(path, user, allowed)
                except BrainError:
                    if vanished_below(path, root):
                        continue
                    raise
                if reason:
                    found.append(PermissionProblem(path, reason))
            return found

        def object_problems(self, path: Path) -> list[PermissionProblem]:
            user = _current_user_sid()
            return self._object_problems(path, user)

        def _object_problems(self, path: Path, user: str) -> list[PermissionProblem]:
            if Path.is_symlink is _ORIG_PATH_IS_SYMLINK:
                try:
                    if stat.S_ISLNK(os.lstat(path).st_mode):
                        return []
                except OSError:
                    pass
            elif path.is_symlink():
                return []
            reason = self._entry_problem(path, user, {user, _SYSTEM_SID})
            return [PermissionProblem(path, reason)] if reason else []

        @staticmethod
        def _entry_problem(path: Path, user: str, allowed: set[str]) -> str | None:
            try:
                owner, aces = _owner_and_allowed_aces(path)
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
                    owner, aces = _owner_and_allowed_aces(ancestor)
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
