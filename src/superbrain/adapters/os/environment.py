"""Facts about the environment a process runs in, and their assessment (spec 4.3 owner policy of 2026-10-31).

"Môi trường nghiệm thu phải được kiểm tra trên thực tế: token của tiến trình, đường dẫn vật lý và ACL thật của data
root cùng các thư mục cha." The probe reads the process token (AppContainer flag, integrity level), resolves each
configured path to its physical path and runs the same ancestor check as ``prepare_data_root`` on it, with the
trusted set of spec 5.9 unchanged. An existing path is checked itself too (``check_root``): the data root with the
owner-only rule ``prepare_data_root`` applies, any other role (a shared parent such as the test trusted root or
``/tmp``) with the ancestor rule. ``assess`` turns the facts into problems; nothing is allow-listed.
"""

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from superbrain.adapters.os import os_adapters, token
from superbrain.adapters.os.paths import is_link
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue

_LOW_INTEGRITY = ("untrusted", "low")
DATA_ROOT_ROLE = "default_data_root"
"""The role whose existing path must itself be owner-only; every other role is a shared parent."""


@dataclass(frozen=True)
class RootFacts:
    """Configured-path existence, including dangling links; ``None`` when unsafe syntax prevents inspection."""

    exists: bool | None
    problems: tuple[str, ...] = ()


class EnvironmentProbe(Protocol):
    def app_container(self) -> bool | None:
        """Windows ``TokenIsAppContainer``; ``None`` where not applicable or unknown."""
        ...

    def integrity_level(self) -> str | None:
        """``untrusted``, ``low``, ``medium``, ``high``, ``system``, or ``None`` if unavailable."""
        ...

    def resolve(self, path: Path) -> Path:
        """The physical path of ``path``; may raise ``OSError``."""
        ...

    def check_ancestors(self, path: Path) -> list[str]:
        """``PermissionGuard.check_ancestors`` problems of ``path``, as text."""
        ...

    def check_root(self, path: Path, role: str) -> RootFacts:
        """Existence and admission problems of the CONFIGURED (unresolved) path, kept independent."""
        ...


class OsEnvironmentProbe:
    """The real process token, physical paths and ancestor ACLs of the running OS."""

    def app_container(self) -> bool | None:
        return token.is_app_container()

    def integrity_level(self) -> str | None:
        return token.integrity_level()

    def resolve(self, path: Path) -> Path:
        return path.resolve()

    def check_ancestors(self, path: Path) -> list[str]:
        try:
            problems = os_adapters().permissions.check_ancestors(path)
        except BrainError as err:
            return [f"{path}: the ancestors could not be checked: {err}"]
        return [f"{problem.path}: {problem.reason}" for problem in problems]

    def check_root(self, path: Path, role: str) -> RootFacts:
        """Admit configured syntax before inspecting ``path``, and never resolve a rejected path.

        The data root: no link at the path or above it (``reject_links``, as ``prepare_data_root``), a directory,
        owner-only (``object_problems``). Any other role (a shared parent such as ``/tmp``, whose own ancestors may
        legitimately be links): the path itself is no link, a directory, and passes the ancestor rule (no takeover
        right for an untrusted account; on POSIX group/world-writable only with the sticky bit), not owner-only.
        Missing paths require their nearest existing ancestor to be a directory; nothing is created here."""
        exists: bool | None = None
        guard = os_adapters().permissions
        try:
            os_adapters().paths.reject_unsafe_path(str(path))
            exists = os.path.lexists(path)
            if role == DATA_ROOT_ROLE:
                os_adapters().paths.reject_links(path)
            elif is_link(path):
                return RootFacts(exists, (f"{path}: is a link or reparse point",))
            if not exists:
                parent = path.parent
                while not os.path.lexists(parent):
                    parent = parent.parent
                if not parent.is_dir():
                    return RootFacts(False, (f"{path}: existing ancestor {parent} is not a directory",))
                return RootFacts(False)
            if not path.is_dir():
                return RootFacts(True, (f"{path}: not a directory",))
            if role == DATA_ROOT_ROLE:
                found = guard.object_problems(path)
            else:
                itself = Path(os.path.abspath(path))
                found = [p for p in guard.check_ancestors(itself / "child") if p.path == itself]
        except (BrainError, OSError) as err:
            return RootFacts(exists, (f"{path}: {err}",))
        return RootFacts(exists, tuple(f"{problem.path}: {problem.reason}" for problem in found))


@dataclass(frozen=True)
class PathFacts:
    role: str
    configured: str
    resolved: str | None
    ancestor_problems: tuple[str, ...]
    error: str | None = None
    exists: bool | None = None
    root_problems: tuple[str, ...] = ()


@dataclass(frozen=True)
class EnvironmentFacts:
    platform: str
    app_container: bool | None
    integrity_level: str | None
    paths: tuple[PathFacts, ...]
    probe_error: str | None = None


def collect(probe: EnvironmentProbe, paths: Mapping[str, Path], platform: str) -> EnvironmentFacts:
    """Check configured paths first, then collect physical-path ancestor and token facts for admitted paths.

    Resolution and token-query ``OSError`` instances are recorded; other probe failures reach the gate's
    fail-closed preflight boundary.
    """
    found: list[PathFacts] = []
    for role, configured in paths.items():
        itself = probe.check_root(configured, role)
        if itself.problems:
            found.append(
                PathFacts(
                    role,
                    str(configured),
                    None,
                    (),
                    "configured path failed admission",
                    exists=itself.exists,
                    root_problems=itself.problems,
                )
            )
            continue
        try:
            resolved = probe.resolve(configured)
        except OSError as err:
            found.append(PathFacts(role, str(configured), None, (), f"{type(err).__name__}: {err}"))
            continue
        ancestors = tuple(probe.check_ancestors(resolved))
        found.append(
            PathFacts(
                role,
                str(configured),
                str(resolved),
                ancestors,
                exists=itself.exists,
                root_problems=itself.problems,
            )
        )
    failures: list[str] = []
    app_container: bool | None = None
    integrity: str | None = None
    try:
        app_container = probe.app_container()
    except OSError as err:
        failures.append(f"AppContainer query: {err}")
    try:
        integrity = probe.integrity_level()
    except OSError as err:
        failures.append(f"integrity level query: {err}")
    return EnvironmentFacts(platform, app_container, integrity, tuple(found), "; ".join(failures) or None)


def assess(facts: EnvironmentFacts, *, required: Sequence[str]) -> dict[str, JsonValue]:
    """The facts as JSON, every problem found (each ``required`` role must be present), and ``accepted``."""
    problems: list[str] = []
    if facts.app_container is True:
        problems.append("the process token is an AppContainer (sandboxed) token")
    elif facts.app_container is None and facts.platform == "win32":
        problems.append("whether the process token is an AppContainer token is unknown")
    if facts.integrity_level in _LOW_INTEGRITY:
        problems.append(f"the process token runs at integrity level {facts.integrity_level}")
    if facts.probe_error is not None:
        problems.append(f"the environment preflight could not query the token: {facts.probe_error}")
    roles = [p.role for p in facts.paths]
    problems.extend(f"{role}: missing from the environment facts" for role in required if role not in roles)
    paths: dict[str, JsonValue] = {}
    for p in facts.paths:
        if p.resolved is None:
            problems.append(f"{p.role}: {p.configured} was not resolved to a physical path: {p.error}")
        problems.extend(f"{p.role}: ancestor not trusted: {problem}" for problem in p.ancestor_problems)
        subject = p.resolved or p.configured
        problems.extend(f"{p.role}: {subject} itself is not acceptable: {problem}" for problem in p.root_problems)
        paths[p.role] = {
            "configured": p.configured,
            "resolved": p.resolved,
            "ancestor_problems": list(p.ancestor_problems),
            "error": p.error,
            "exists": p.exists,
            "root_problems": list(p.root_problems),
        }
    return {
        "platform": facts.platform,
        "app_container": facts.app_container,
        "integrity_level": facts.integrity_level,
        "paths": paths,
        "problems": list(problems),
        "accepted": not problems,
    }
