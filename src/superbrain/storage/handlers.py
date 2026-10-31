"""Projection handlers and entry kinds a store is opened with: defaults, registry checks and history checks.

``check_history`` is the no-downgrade rule of spec 5.8 at open: live projection tables are no proof that the
handlers given now can handle what the ledger already holds.
"""

import re
import sqlite3
from collections.abc import Sequence

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import HolderProjection
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import CORE_KINDS, KindRegistry
from superbrain.storage.ledger import ProjectionHandler

_HANDLER_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


def with_defaults(
    handlers: Sequence[ProjectionHandler], kinds: KindRegistry
) -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """``handlers`` plus ``HolderProjection`` and ``kinds`` plus ``CORE_KINDS``, each added only if absent.

    A caller kind named like a core kind must be that core kind; a caller handler named ``cas_holders`` that is no
    ``HolderProjection`` is left in place, so the duplicate-name check refuses it.
    """
    extra_kinds = []
    for core in CORE_KINDS:
        if core.kind not in kinds.kinds():
            extra_kinds.append(core)
        elif kinds.get(core.kind) != core:
            raise BrainError(ErrorCode.INVALID_INPUT, f"core entry kind {core.kind!r} cannot be redefined")
    merged_kinds = KindRegistry([*(kinds.get(name) for name in sorted(kinds.kinds())), *extra_kinds])
    if any(isinstance(handler, HolderProjection) for handler in handlers):
        return tuple(handlers), merged_kinds
    return (HolderProjection(), *handlers), merged_kinds


def check_handlers(handlers: Sequence[ProjectionHandler], kinds: KindRegistry) -> None:
    names = [handler.name for handler in handlers]
    for name in names:
        if not isinstance(name, str) or _HANDLER_NAME.fullmatch(name) is None:
            raise BrainError(ErrorCode.INVALID_INPUT, f"projection handler name {name!r} is not a valid identifier")
    if len(set(names)) != len(names):
        raise BrainError(ErrorCode.INVALID_INPUT, "projection handler names must be unique")
    for a in names:
        for b in names:
            if a != b and f"{b}_".startswith(f"{a}_"):
                raise BrainError(ErrorCode.INVALID_INPUT, f"projection handlers {a!r} and {b!r} share a table prefix")
    registered = kinds.kinds()
    for handler in handlers:
        unknown = sorted(handler.kinds - registered)
        if unknown:
            raise BrainError(ErrorCode.INVALID_INPUT, f"projection {handler.name} handles unregistered kinds {unknown}")
        for kind in sorted(handler.kinds):
            if kinds.get(kind).handler_version > handler.handler_version:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION, f"projection {handler.name} is older than entry kind {kind}"
                )


def check_history(db: sqlite3.Connection, handlers: Sequence[ProjectionHandler]) -> dict[str, int]:
    """Refuse handlers older than the ledger's history, before anything is written (spec 5.8: no downgrade).

    For every kind the ledger holds entries of, every handler of that kind must support the highest
    ``handler_version`` recorded, whether or not its live tables already exist; otherwise ``UNSUPPORTED_VERSION``.
    Returns that highest version per kind, so writes can refuse an older entry kind (``Txn``); a kind registered
    without a handler can still be opened and read.
    """
    try:
        rows = db.execute("SELECT kind, MAX(handler_version) FROM ledger GROUP BY kind ORDER BY kind").fetchall()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read the handler versions of the ledger", exc) from exc
    history: dict[str, int] = {}
    for kind, needed in rows:
        if not isinstance(kind, str) or type(needed) is not int:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the ledger holds a malformed kind or handler_version")
        for handler in handlers:
            if kind in handler.kinds and handler.handler_version < needed:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"the ledger holds {kind} entries of handler version {needed}, "
                    f"projection {handler.name} is version {handler.handler_version}",
                )
        history[kind] = needed
    return history
