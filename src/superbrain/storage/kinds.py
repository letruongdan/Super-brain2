"""Typed ledger entry kinds (spec 5.4).

The ledger holds metadata only. Every entry kind registers a schema of typed fields; there is no free-text type,
so nothing but ids, digests, numbers, timestamps, booleans and enum values can reach the ledger. ``actor`` and
``owner_id`` follow identifier patterns and ``refs`` are unique content digests.

A ``reserved`` kind can only be written through the internal helper that checks its invariant
(``Txn.hold``/``Txn.release`` for ``cas.*``, ``Store.reconcile_policy`` for ``policy.*``).
"""

import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import RetentionClass as RetentionClass

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ACTOR = re.compile(r"(?:(?:user|system):[a-z0-9][a-z0-9._:-]{0,63}|principal:[A-Za-z0-9][A-Za-z0-9._-]{0,127})")
_OWNER_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_KIND_NAME = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
_TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,6})?Z")
# INT is SQLite's signed 64-bit range, so every value a handler stores fits a column.
_INT_MIN, _INT_MAX = -(2**63), 2**63 - 1


class FieldType(StrEnum):
    UUID = "uuid"
    DIGEST = "digest"
    INT = "int"
    TIMESTAMP = "timestamp"
    BOOL = "bool"
    ENUM = "enum"
    OPAQUE_ID = "opaque_id"


def _invalid(message: str) -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


@dataclass(frozen=True)
class EntryKind:
    """Every field in ``fields`` must be present; a field in ``nullable`` may hold ``null``."""

    kind: str
    handler_version: int
    fields: Mapping[str, FieldType]
    enums: Mapping[str, frozenset[str]]
    nullable: frozenset[str] = frozenset()
    reserved: bool = False

    def __post_init__(self) -> None:
        if not _KIND_NAME.fullmatch(self.kind):
            raise _invalid(f"entry kind name {self.kind!r} is not dotted lowercase")
        if type(self.handler_version) is not int or self.handler_version < 1:
            raise _invalid(f"{self.kind}: handler_version must be a positive integer")
        enum_fields = {name for name, ftype in self.fields.items() if ftype is FieldType.ENUM}
        if set(self.enums) != enum_fields:
            raise _invalid(f"{self.kind}: enums must list exactly the ENUM fields")
        if not self.nullable <= set(self.fields):
            raise _invalid(f"{self.kind}: nullable names fields that do not exist")


def _check_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _check_timestamp(value: object) -> bool:
    """Exactly ``YYYY-MM-DDTHH:MM:SS[.f{1,6}]Z`` naming a real instant: one spelling, so timestamps compare."""
    if type(value) is not str:
        return False
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return False
    return True


def _check_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _matches(ftype: FieldType, value: object, allowed: frozenset[str]) -> bool:
    if ftype is FieldType.UUID:
        return _check_uuid(value)
    if ftype is FieldType.DIGEST:
        return _check_digest(value)
    if ftype is FieldType.INT:
        return type(value) is int and _INT_MIN <= value <= _INT_MAX
    if ftype is FieldType.TIMESTAMP:
        return _check_timestamp(value)
    if ftype is FieldType.BOOL:
        return type(value) is bool
    if ftype is FieldType.ENUM:
        return type(value) is str and value in allowed
    if ftype is FieldType.OPAQUE_ID:
        return type(value) is str and _OPAQUE_ID.fullmatch(value) is not None
    raise AssertionError(f"unhandled field type {ftype!r}")


class KindRegistry:
    def __init__(self, kinds: Iterable[EntryKind]) -> None:
        self._kinds: dict[str, EntryKind] = {}
        for kind in kinds:
            if kind.kind in self._kinds:
                raise _invalid(f"entry kind {kind.kind!r} is registered twice")
            self._kinds[kind.kind] = kind

    def get(self, kind: str) -> EntryKind:
        found = self._kinds.get(kind)
        if found is None:
            raise _invalid(f"unknown entry kind {kind!r}")
        return found

    def kinds(self) -> frozenset[str]:
        return frozenset(self._kinds)

    def validate(self, kind: str, meta: Mapping[str, JsonValue]) -> None:
        """Require ``meta`` to hold exactly the kind's fields, each a flat value of its declared type."""
        spec = self.get(kind)
        if not isinstance(meta, Mapping):
            raise _invalid(f"{kind}: meta must be an object")
        if set(meta) != set(spec.fields):
            extra = sorted(str(k) for k in set(meta) - set(spec.fields))
            missing = sorted(set(spec.fields) - set(meta))
            raise _invalid(f"{kind}: meta keys do not match the schema (extra {extra}, missing {missing})")
        for name, ftype in spec.fields.items():
            value = meta[name]
            if value is None and name in spec.nullable:
                continue
            if not _matches(ftype, value, spec.enums.get(name, frozenset())):
                raise _invalid(f"{kind}: field {name!r} is not a valid {ftype.value}")


def validate_envelope(actor: str, owner_id: str | None, refs: Sequence[str]) -> tuple[str, ...]:
    """Check the fields every entry carries; return ``refs`` as a tuple."""
    if type(actor) is not str or _ACTOR.fullmatch(actor) is None:
        raise _invalid("actor is not a valid actor identifier")
    if owner_id is not None and (type(owner_id) is not str or _OWNER_ID.fullmatch(owner_id) is None):
        raise _invalid("owner_id is not a valid owner identifier")
    if isinstance(refs, (str, bytes)) or not isinstance(refs, Sequence):
        raise _invalid("refs must be a sequence of digests")
    checked = tuple(refs)
    if not all(_check_digest(ref) for ref in checked):
        raise _invalid("every ref must be a sha256 digest")
    if len(set(checked)) != len(checked):
        raise _invalid("refs must not repeat a digest")
    return checked


def is_uuid(value: object) -> bool:
    """``value`` is a UUID in canonical lowercase hyphenated form."""
    return _check_uuid(value)


_HOLDER_KINDS = frozenset({"event", "evidence", "artifact", "lesson", "proposal", "receipt"})

CORE_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "cas.hold",
        1,
        {
            "digest": FieldType.DIGEST,
            "holder_kind": FieldType.ENUM,
            "holder_id": FieldType.UUID,
            "retention": FieldType.ENUM,
            "expires_at": FieldType.TIMESTAMP,
        },
        {"holder_kind": _HOLDER_KINDS, "retention": frozenset(v.value for v in RetentionClass)},
        nullable=frozenset({"expires_at"}),
        reserved=True,
    ),
    EntryKind(
        "cas.release",
        1,
        {
            "digest": FieldType.DIGEST,
            "holder_kind": FieldType.ENUM,
            "holder_id": FieldType.UUID,
            "reason": FieldType.ENUM,
        },
        {
            "holder_kind": _HOLDER_KINDS,
            "reason": frozenset({"expired", "tombstoned", "superseded", "deleted_by_owner"}),
        },
        reserved=True,
    ),
    EntryKind(
        "policy.quarantine",
        1,
        {"digest": FieldType.DIGEST, "intent_id": FieldType.UUID},
        {},
        reserved=True,
    ),
    EntryKind(
        "policy.tombstone",
        1,
        {"holder_kind": FieldType.ENUM, "holder_id": FieldType.UUID, "intent_id": FieldType.UUID},
        {"holder_kind": _HOLDER_KINDS},
        reserved=True,
    ),
)
