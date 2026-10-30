from collections.abc import Callable, Mapping

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry, validate_envelope

D = "sha256:" + "ab" * 32
U = "0192f3a4-5b6c-7d8e-9f01-23456789abcd"
TS = "2026-10-30T12:00:00Z"
HOLD: dict[str, JsonValue] = {"digest": D, "holder_kind": "lesson", "holder_id": U, "retention": "durable"}

ALL_TYPES = EntryKind(
    "demo.all",
    1,
    {
        "u": FieldType.UUID,
        "d": FieldType.DIGEST,
        "i": FieldType.INT,
        "t": FieldType.TIMESTAMP,
        "b": FieldType.BOOL,
        "e": FieldType.ENUM,
    },
    {"e": frozenset({"x", "y"})},
)
VALID_ALL: dict[str, JsonValue] = {"u": U, "d": D, "i": 3, "t": TS, "b": True, "e": "x"}


def invalid(code: ErrorCode = ErrorCode.INVALID_INPUT) -> "pytest.RaisesExc[BrainError]":
    return pytest.raises(BrainError, check=lambda e: e.code == code)


def test_nullable_field_accepts_null_but_must_be_present() -> None:
    registry = KindRegistry(CORE_KINDS)
    registry.validate("cas.hold", {**HOLD, "expires_at": None})
    registry.validate("cas.hold", {**HOLD, "expires_at": TS})
    with invalid():
        registry.validate("cas.hold", HOLD)


def test_free_text_payload_is_rejected_by_schema() -> None:
    with invalid():
        KindRegistry(CORE_KINDS).validate(
            "cas.release", {"digest": D, "holder_kind": "event", "holder_id": U, "reason": "tiny-secret-7f3a"}
        )


def test_core_kinds_match_the_brief() -> None:
    kinds = {k.kind: k for k in CORE_KINDS}
    assert set(kinds) == {"cas.hold", "cas.release", "policy.quarantine", "policy.tombstone"}
    assert all(k.reserved and k.handler_version == 1 for k in CORE_KINDS)
    holder_kinds = frozenset({"event", "evidence", "artifact", "lesson", "proposal", "receipt"})
    hold, release = kinds["cas.hold"], kinds["cas.release"]
    assert dict(hold.fields) == {
        "digest": FieldType.DIGEST,
        "holder_kind": FieldType.ENUM,
        "holder_id": FieldType.UUID,
        "retention": FieldType.ENUM,
        "expires_at": FieldType.TIMESTAMP,
    }
    assert hold.nullable == frozenset({"expires_at"})
    retention = frozenset({"event_payload", "evidence", "durable"})
    assert dict(hold.enums) == {"holder_kind": holder_kinds, "retention": retention}
    assert dict(release.fields) == {
        "digest": FieldType.DIGEST,
        "holder_kind": FieldType.ENUM,
        "holder_id": FieldType.UUID,
        "reason": FieldType.ENUM,
    }
    assert dict(release.enums) == {
        "holder_kind": holder_kinds,
        "reason": frozenset({"expired", "tombstoned", "superseded", "deleted_by_owner"}),
    }
    assert dict(kinds["policy.quarantine"].fields) == {"digest": FieldType.DIGEST, "intent_id": FieldType.UUID}
    assert dict(kinds["policy.tombstone"].fields) == {
        "holder_kind": FieldType.ENUM,
        "holder_id": FieldType.UUID,
        "intent_id": FieldType.UUID,
    }
    assert dict(kinds["policy.tombstone"].enums) == {"holder_kind": holder_kinds}


def test_every_field_type_accepts_its_values() -> None:
    registry = KindRegistry([ALL_TYPES])
    registry.validate("demo.all", VALID_ALL)
    registry.validate("demo.all", {**VALID_ALL, "t": "2026-10-30T12:00:00.123456Z", "b": False, "i": -5})
    registry.validate("demo.all", {**VALID_ALL, "t": "2024-02-29T23:59:59.5Z"})


@pytest.mark.parametrize("n", [-(2**63), 2**63 - 1, 0])
def test_int_accepts_the_signed_64_bit_range(n: int) -> None:
    KindRegistry([ALL_TYPES]).validate("demo.all", {**VALID_ALL, "i": n})


@pytest.mark.parametrize(
    "n",
    [-(2**63) - 1, 2**63, 2**70, 10**5000, -(10**5000)],
    ids=["min-1", "max+1", "2**70", "10**5000", "-10**5000"],
)
def test_int_outside_the_signed_64_bit_range_is_rejected(n: int) -> None:
    with invalid():
        KindRegistry([ALL_TYPES]).validate("demo.all", {**VALID_ALL, "i": n})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("u", U.upper()),
        ("u", U.replace("-", "")),
        ("u", "{" + U + "}"),
        ("u", "not-a-uuid"),
        ("u", 1),
        ("d", "sha256:" + "AB" * 32),
        ("d", "sha256:" + "ab" * 31),
        ("d", D + "\n"),
        ("d", "md5:" + "ab" * 16),
        ("i", True),
        ("i", 1.0),
        ("i", "1"),
        ("t", "2026-10-30T12:00:00+00:00"),
        ("t", "2026-10-30T12:00:00"),
        ("t", "2026-10-30T12:00:00+01:00Z"),
        ("t", "yesterday Z"),
        ("t", "2026-13-30T12:00:00Z"),
        ("t", "2026-02-30T12:00:00Z"),
        ("t", "2026-10-30 12:00:00Z"),
        ("t", "20261030T120000Z"),
        ("t", "2026-W44-5T12:00:00Z"),
        ("t", "2026-10-30T12Z"),
        ("t", "2026-10-30T12:00Z"),
        ("t", "2026-10-30T12:00:00,5Z"),
        ("t", "2026-10-30T24:00:00Z"),
        ("t", "2026-10-30T12:00:00.1234567Z"),
        ("t", "2026-10-30T12:00:00.Z"),
        ("t", "2026-10-30T12:00:00z"),
        ("t", "2026-10-30T12:00:00Z\n"),
        ("t", "2026-10-30T12:00:00ZZ"),
        ("t", "2026-10-30T12:00:0٠Z"),
        ("t", 0),
        ("b", 1),
        ("b", "true"),
        ("e", "z"),
        ("e", "X"),
        ("e", ["x"]),
        ("e", None),
    ],
)
def test_wrong_value_for_field_type_is_rejected(name: str, value: JsonValue) -> None:
    with invalid():
        KindRegistry([ALL_TYPES]).validate("demo.all", {**VALID_ALL, name: value})


@pytest.mark.parametrize(
    "meta",
    [{**VALID_ALL, "extra": 1}, {k: v for k, v in VALID_ALL.items() if k != "u"}, {**VALID_ALL, "i": {"n": 1}}],
)
def test_meta_keys_must_match_schema_exactly(meta: Mapping[str, JsonValue]) -> None:
    with invalid():
        KindRegistry([ALL_TYPES]).validate("demo.all", meta)


def test_meta_must_be_a_mapping() -> None:
    with invalid():
        KindRegistry([ALL_TYPES]).validate("demo.all", [("u", U)])  # type: ignore[arg-type]


def test_unknown_kind_is_invalid_input() -> None:
    with invalid():
        KindRegistry(CORE_KINDS).get("demo.unknown")
    with invalid():
        KindRegistry(CORE_KINDS).validate("demo.unknown", {})


def test_registry_refuses_duplicate_kinds() -> None:
    with invalid():
        KindRegistry([ALL_TYPES, ALL_TYPES])


@pytest.mark.parametrize(
    "kind",
    [
        lambda: EntryKind("demo.x", 1, {"e": FieldType.ENUM}, {}),
        lambda: EntryKind("demo.x", 1, {"i": FieldType.INT}, {"i": frozenset({"a"})}),
        lambda: EntryKind("demo.x", 1, {"i": FieldType.INT}, {}, nullable=frozenset({"j"})),
        lambda: EntryKind("demo.x", 0, {"i": FieldType.INT}, {}),
        lambda: EntryKind("Demo X", 1, {"i": FieldType.INT}, {}),
    ],
)
def test_entry_kind_definition_must_be_consistent(kind: Callable[[], EntryKind]) -> None:
    with invalid():
        kind()


@pytest.mark.parametrize("actor", ["user:cli", "system:gc", "principal:agent.7", "user:a:b-c_d", "user:" + "a" * 64])
def test_valid_actor_is_accepted(actor: str) -> None:
    assert validate_envelope(actor, "dan", [D]) == (D,)


@pytest.mark.parametrize(
    "actor",
    ["cli", "user:", "user:CLI", "robot:x", "user:x\n", "user:-x", "user:" + "a" * 65, "user:tiny secret", 7],
)
def test_actor_outside_pattern_is_rejected(actor: str) -> None:
    with invalid():
        validate_envelope(actor, "dan", ())


@pytest.mark.parametrize("owner_id", [None, "dan", "a", "team.x-1_2", "a" * 64])
def test_valid_owner_id_is_accepted(owner_id: str | None) -> None:
    assert validate_envelope("user:cli", owner_id, ()) == ()


@pytest.mark.parametrize("owner_id", ["", "Dan", "-x", "a" * 65, "dan\n", "d:n", 1])
def test_owner_id_outside_pattern_is_rejected(owner_id: str) -> None:
    with invalid():
        validate_envelope("user:cli", owner_id, ())


@pytest.mark.parametrize("refs", [["tiny-secret-7f3a"], [D, D], ["sha256:XYZ"], D, [1]])
def test_refs_must_be_a_sequence_of_unique_digests(refs: list[str]) -> None:
    with invalid():
        validate_envelope("user:cli", "dan", refs)
