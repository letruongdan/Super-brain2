"""Caller identity normalization, direct ref scope authorization, and policy intent classification."""

from __future__ import annotations

import copy
from collections.abc import Mapping

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DirectRefRecord,
    ObjectRef,
    Principal,
    Scope,
    require_object_kind,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.ports.kernel import KernelPolicyPort
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage.kernel_schema import KERNEL_POLICY_KINDS
from superbrain.storage.kinds import CORE_KINDS, KindRegistry

_CALLER_IDENTITY_FIELDS: tuple[str, ...] = ("owner_id", "principal_id", "harness_id", "machine_id")

_WORKSPACE_REGISTER_V2_FIELDS: tuple[str, ...] = (
    "subject_id",
    "repo_id",
    "checkout_id",
    "principal_id",
    "machine_id",
    "alias",
    "locator_digest",
)
_WORKSPACE_REGISTER_LEGACY_V1_FIELDS: tuple[str, ...] = (
    "repo_id",
    "checkout_id",
    "principal_id",
    "machine_id",
    "alias",
    "locator_digest",
)

_INTENT_PAYLOAD_FIELDS: dict[IntentKind, tuple[str, ...]] = {
    IntentKind.TOMBSTONE: ("holder_kind", "holder_id"),
    IntentKind.QUARANTINE: ("digest",),
    IntentKind.CREDENTIAL_REVOKE: ("principal_id", "credential_id", "owner_id"),
    IntentKind.WORKSPACE_REGISTER: _WORKSPACE_REGISTER_V2_FIELDS,
}

_INTENT_EFFECT_KIND: dict[IntentKind, str] = {
    IntentKind.TOMBSTONE: "policy.tombstone",
    IntentKind.QUARANTINE: "policy.quarantine",
    IntentKind.CREDENTIAL_REVOKE: "policy.credential_revoke",
    IntentKind.WORKSPACE_REGISTER: "policy.workspace_register",
}

_POLICY_EFFECT_REGISTRY = KindRegistry((*CORE_KINDS, *KERNEL_POLICY_KINDS))


def validate_policy_intent_payload(
    kind: object,
    payload: object,
    intent_id: str,
    *,
    allow_legacy_v1: bool = False,
) -> dict[str, JsonValue]:
    """Validate ``payload`` for ``kind`` against its reserved ``policy.*`` ledger schema."""
    if not isinstance(kind, IntentKind) or kind not in _INTENT_PAYLOAD_FIELDS:
        raise BrainError(ErrorCode.INVALID_INPUT, f"{kind!r} is not an IntentKind")
    if not isinstance(payload, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, f"a {kind} payload must be an object")
    if kind is IntentKind.WORKSPACE_REGISTER:
        payload_keys = set(payload)
        if payload_keys == set(_WORKSPACE_REGISTER_V2_FIELDS):
            if payload["subject_id"] is None:
                raise BrainError(
                    ErrorCode.INVALID_INPUT,
                    "policy.workspace_register: field 'subject_id' is not a valid digest",
                )
            checked_v2: dict[str, JsonValue] = {
                name: payload[name] for name in _WORKSPACE_REGISTER_V2_FIELDS
            }
            _POLICY_EFFECT_REGISTRY.validate(_INTENT_EFFECT_KIND[kind], {**checked_v2, "intent_id": intent_id})
            return checked_v2
        if allow_legacy_v1 and payload_keys == set(_WORKSPACE_REGISTER_LEGACY_V1_FIELDS):
            checked_6: dict[str, JsonValue] = {
                name: payload[name] for name in _WORKSPACE_REGISTER_LEGACY_V1_FIELDS
            }
            _POLICY_EFFECT_REGISTRY.validate(
                _INTENT_EFFECT_KIND[kind],
                {**checked_6, "subject_id": None, "intent_id": intent_id},
            )
            return checked_6
        raise BrainError(
            ErrorCode.INVALID_INPUT,
            f"a {kind} payload takes exactly {list(_WORKSPACE_REGISTER_V2_FIELDS)}",
        )
    fields = _INTENT_PAYLOAD_FIELDS[kind]
    if set(payload) != set(fields):
        raise BrainError(ErrorCode.INVALID_INPUT, f"a {kind} payload takes exactly {list(fields)}")
    checked: dict[str, JsonValue] = {name: payload[name] for name in fields}
    _POLICY_EFFECT_REGISTRY.validate(_INTENT_EFFECT_KIND[kind], {**checked, "intent_id": intent_id})
    return checked


def classify_reconcile_intent(
    intent: Intent,
) -> tuple[str, dict[str, JsonValue], tuple[str, str] | None]:
    """Exhaustively classify ``intent`` for ``Store.reconcile_policy``.

    Returns ``(effect_ledger_kind, validated_meta, tombstone_holder_or_none)``.
    Any unknown or malformed intent kind/payload fails closed with ``INTEGRITY_FAILURE``.
    """
    if type(intent.kind) is not IntentKind or intent.kind not in _INTENT_EFFECT_KIND:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unknown policy intent kind {intent.kind!r}")
    try:
        checked = validate_policy_intent_payload(
            intent.kind, intent.payload, intent.intent_id, allow_legacy_v1=True
        )
    except BrainError as exc:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE, f"policy intent {intent.intent_id!r} has invalid payload: {exc}"
        ) from exc
    if intent.kind is IntentKind.WORKSPACE_REGISTER:
        ws_meta: dict[str, JsonValue] = {
            **checked,
            "subject_id": checked.get("subject_id"),
            "intent_id": intent.intent_id,
        }
        return ("policy.workspace_register", ws_meta, None)
    meta: dict[str, JsonValue] = {**checked, "intent_id": intent.intent_id}
    if intent.kind is IntentKind.TOMBSTONE:
        return ("policy.tombstone", meta, (str(meta["holder_kind"]), str(meta["holder_id"])))
    if intent.kind is IntentKind.QUARANTINE:
        return ("policy.quarantine", meta, None)
    if intent.kind is IntentKind.CREDENTIAL_REVOKE:
        return ("policy.credential_revoke", meta, None)
    raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unhandled policy intent kind {intent.kind!r}")


def verify_caller_identity(
    principal: Principal, declared: Mapping[str, JsonValue]
) -> dict[str, JsonValue]:
    """Verify optional caller-supplied identity fields against ``principal`` and strip matching ones."""
    if not isinstance(principal, Principal) or not isinstance(declared, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for field_name in _CALLER_IDENTITY_FIELDS:
        if field_name in declared:
            supplied = declared[field_name]
            if not isinstance(supplied, str) or not supplied:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if supplied != getattr(principal, field_name):
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
    return {
        key: copy.deepcopy(value)
        for key, value in declared.items()
        if key not in _CALLER_IDENTITY_FIELDS
    }


def _coerce_ref_record(record_meta: DirectRefRecord | Mapping[str, JsonValue]) -> DirectRefRecord:
    if isinstance(record_meta, DirectRefRecord):
        return record_meta
    if not isinstance(record_meta, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw_repo = record_meta.get("repo_id")
    raw_checkout = record_meta.get("checkout_id")
    return DirectRefRecord(
        kind=require_object_kind(record_meta.get("kind")),
        id=require_opaque_id(record_meta.get("id"), label="id"),
        revision=require_positive_int(record_meta.get("revision")),
        digest=require_sha256_digest(record_meta.get("digest")),
        owner_id=require_opaque_id(record_meta.get("owner_id"), label="owner_id"),
        repo_id=require_opaque_id(raw_repo, label="repo_id") if raw_repo is not None else None,
        checkout_id=require_opaque_id(raw_checkout, label="checkout_id") if raw_checkout is not None else None,
    )


def authorize_direct_ref(
    principal: Principal,
    selected_scope: Scope | None,
    ref: ObjectRef,
    record_meta: DirectRefRecord | Mapping[str, JsonValue] | None,
    policy: KernelPolicyPort,
    *,
    claimed_owner_id: str | None = None,
    expected_kind: str | None = None,
) -> DirectRefRecord:
    """Authorize direct object reference lookup across artifact, job, and context refs.

    * Policy unavailable/closed/corrupt -> ``POLICY_UNAVAILABLE``
    * Mismatched ``claimed_owner_id`` -> ``IDENTITY_MISMATCH``
    * Missing record, wrong kind/revision/digest, cross-owner/repo/checkout, or missing grant -> ``NOT_FOUND``
    """
    if not isinstance(principal, Principal) or not isinstance(ref, ObjectRef):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if selected_scope is not None and not isinstance(selected_scope, Scope):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    # Probe live policy availability first so closed/unreadable policy never degrades to NOT_FOUND.
    caller_active = policy.allows(principal, None, action="get_job")

    if claimed_owner_id is not None:
        require_opaque_id(claimed_owner_id, label="owner_id")
        if claimed_owner_id != principal.owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")

    if record_meta is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    rec = _coerce_ref_record(record_meta)

    if expected_kind is not None and ref.kind != expected_kind:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if (ref.kind, ref.id, ref.revision, ref.digest) != (rec.kind, rec.id, rec.revision, rec.digest):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if rec.owner_id != principal.owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    if rec.repo_id is None:
        if not caller_active:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return rec

    if selected_scope is None or selected_scope.repo_id != rec.repo_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if rec.checkout_id is not None and selected_scope.checkout_id != rec.checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    effective_scope = Scope(
        repo_id=rec.repo_id,
        checkout_id=rec.checkout_id if rec.checkout_id is not None else selected_scope.checkout_id,
    )
    if not policy.allows(principal, effective_scope, action="get_artifact"):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return rec
