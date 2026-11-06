"""Internal policy v2 write-side authorized mutation helpers backing ``PolicyStore``."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from datetime import datetime

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    BootstrapAuthorization,
    TrustedLocator,
    WorkspaceBinding,
    WorkspaceRegistration,
    is_trusted_bootstrap_issuer,
)
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage._policy_authority import (
    ensure_v2_tables,
    require_stored_bool_int,
    require_stored_opaque_id,
    require_stored_str,
    require_stored_uuid,
)
from superbrain.storage.identity import validate_policy_intent_payload
from superbrain.storage.kinds import is_uuid
from superbrain.storage.ledger import utc_timestamp

_STORAGE_ERROR_CODES: frozenset[ErrorCode] = frozenset(
    {ErrorCode.INTEGRITY_FAILURE, ErrorCode.IO_ERROR, ErrorCode.STORE_BUSY}
)


@contextlib.contextmanager
def _map_db_failure() -> Iterator[None]:
    try:
        yield
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    except BrainError as err:
        if err.code in _STORAGE_ERROR_CODES:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from err
        raise


def _check_ingress_auth(
    auth: BootstrapAuthorization,
    *,
    store_id: str,
    expected_action: str,
    expected_subject_id: str,
    trust_generation: int,
    now: datetime,
) -> None:
    if not isinstance(auth, BootstrapAuthorization):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if auth.store_id != store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if auth.trust_generation != trust_generation:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    if not is_trusted_bootstrap_issuer(auth.issuer_id):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if auth.action != expected_action:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if auth.subject_id != expected_subject_id:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if auth.expires_at <= now:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _verify_existing_repo_policy(
    db: sqlite3.Connection, *, repo_id: str, expected_owner_id: str, expected_egress: bool
) -> None:
    repo_row = db.execute(
        "SELECT owner_id, provider_egress_enabled FROM repo_policy WHERE repo_id = ?",
        (repo_id,),
    ).fetchone()
    if repo_row is None:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    stored_owner = require_stored_opaque_id(repo_row[0])
    stored_egress = require_stored_bool_int(repo_row[1])
    if stored_owner != expected_owner_id or stored_egress != expected_egress:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")


def _verify_locator_row(
    loc_row: tuple[object, ...],
    *,
    expected_owner_id: str,
    expected_repo_id: str | None,
    loc: TrustedLocator,
) -> str:
    loc_owner = require_stored_opaque_id(loc_row[0])
    loc_repo = require_stored_opaque_id(loc_row[1])
    loc_scheme = require_stored_str(loc_row[2])
    loc_canonical = require_stored_str(loc_row[3])
    if (
        loc_owner != expected_owner_id
        or (expected_repo_id is not None and loc_repo != expected_repo_id)
        or loc_scheme != loc.scheme
        or loc_canonical != loc.canonical_locator
    ):
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    return loc_repo


def record_policy_authorized_revocation(
    db: sqlite3.Connection,
    immediate: Callable[[], AbstractContextManager[sqlite3.Connection]],
    decode_intent: Callable[[tuple[object, ...]], Intent],
    *,
    credential_id: str,
    authorization: BootstrapAuthorization,
    store_id: str,
    trust_generation: int,
    now: datetime,
) -> Intent:
    ensure_v2_tables(db)
    if not is_uuid(credential_id):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _check_ingress_auth(
        authorization,
        store_id=store_id,
        expected_action="credential_revoke",
        expected_subject_id=credential_id,
        trust_generation=trust_generation,
        now=now,
    )

    with _map_db_failure():
        existing_intent_row = db.execute(
            "SELECT intent_id, kind, payload, created_at FROM intents WHERE intent_id = ?",
            (authorization.intent_id,),
        ).fetchone()

        cred_row = db.execute(
            "SELECT c.principal_id, p.owner_id FROM credential AS c "
            "LEFT JOIN principal AS p ON p.id = c.principal_id WHERE c.id = ?",
            (credential_id,),
        ).fetchone()
        if cred_row is None:
            if existing_intent_row is not None:
                decode_intent(tuple(existing_intent_row))
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if cred_row[1] is None:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        principal_id = require_stored_uuid(cred_row[0])
        cred_owner_id = require_stored_opaque_id(cred_row[1])
        if authorization.owner_id != cred_owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        expected_payload: dict[str, JsonValue] = {
            "principal_id": principal_id,
            "credential_id": credential_id,
            "owner_id": cred_owner_id,
        }
        checked = validate_policy_intent_payload(
            IntentKind.CREDENTIAL_REVOKE, expected_payload, authorization.intent_id
        )

        if existing_intent_row is not None:
            existing_intent = decode_intent(tuple(existing_intent_row))
            if existing_intent.kind is IntentKind.CREDENTIAL_REVOKE and dict(existing_intent.payload) == checked:
                return existing_intent
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

        created_at = utc_timestamp(now)
        intent = Intent(
            intent_id=authorization.intent_id,
            kind=IntentKind.CREDENTIAL_REVOKE,
            payload=checked,
            created_at=created_at,
        )
        with immediate() as txn_db:
            txn_db.execute(
                "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (intent.intent_id, IntentKind.CREDENTIAL_REVOKE.value, canonical_json(checked), created_at),
            )
            txn_db.execute(
                "UPDATE credential SET revoked_intent_id = COALESCE(revoked_intent_id, ?) WHERE id = ?",
                (intent.intent_id, credential_id),
            )
    crashpoint("policy.after_intent_commit")
    return intent


def register_policy_authorized_workspace(
    db: sqlite3.Connection,
    immediate: Callable[[], AbstractContextManager[sqlite3.Connection]],
    decode_intent: Callable[[tuple[object, ...]], Intent],
    *,
    registration: WorkspaceRegistration,
    authorization: BootstrapAuthorization,
    store_id: str,
    trust_generation: int,
    now: datetime,
) -> WorkspaceBinding:
    ensure_v2_tables(db)
    if not isinstance(registration, WorkspaceRegistration):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if isinstance(authorization, BootstrapAuthorization) and authorization.owner_id != registration.owner_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    _check_ingress_auth(
        authorization,
        store_id=store_id,
        expected_action="workspace_register",
        expected_subject_id=registration.subject_id,
        trust_generation=trust_generation,
        now=now,
    )

    loc = registration.locator
    loc_digest = loc.locator_digest if loc is not None else None

    with _map_db_failure():
        p_row = db.execute(
            "SELECT owner_id, machine_id FROM principal WHERE id = ?",
            (registration.principal_id,),
        ).fetchone()
        if p_row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        stored_p_owner = require_stored_opaque_id(p_row[0])
        stored_p_machine = require_stored_opaque_id(p_row[1])
        if stored_p_owner != registration.owner_id or stored_p_machine != registration.machine_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        existing_intent_row = db.execute(
            "SELECT intent_id, kind, payload, created_at FROM intents WHERE intent_id = ?",
            (authorization.intent_id,),
        ).fetchone()
        if existing_intent_row is not None:
            existing_intent = decode_intent(tuple(existing_intent_row))
            if existing_intent.kind is not IntentKind.WORKSPACE_REGISTER:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            chk_id = require_stored_opaque_id(existing_intent.payload["checkout_id"])
            repo_id = require_stored_opaque_id(existing_intent.payload["repo_id"])
            chk_row = db.execute(
                "SELECT owner_id, repo_id, machine_id, alias, checkout_path, path_identity "
                "FROM workspace_checkout WHERE checkout_id = ?",
                (chk_id,),
            ).fetchone()
            if (
                chk_row is None
                or require_stored_opaque_id(chk_row[0]) != registration.owner_id
                or require_stored_opaque_id(chk_row[1]) != repo_id
                or require_stored_opaque_id(chk_row[2]) != registration.machine_id
                or require_stored_str(chk_row[3]) != registration.alias
                or require_stored_str(chk_row[4]) != registration.checkout_path
                or require_stored_str(chk_row[5]) != registration.path_identity
                or require_stored_str(existing_intent.payload["principal_id"]) != registration.principal_id
                or existing_intent.payload["locator_digest"] != loc_digest
            ):
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            _verify_existing_repo_policy(
                db,
                repo_id=repo_id,
                expected_owner_id=registration.owner_id,
                expected_egress=registration.provider_egress_enabled,
            )
            if loc is not None:
                loc_row = db.execute(
                    "SELECT owner_id, repo_id, scheme, canonical_locator "
                    "FROM workspace_repo_locator WHERE locator_digest = ?",
                    (loc.locator_digest,),
                ).fetchone()
                if loc_row is None:
                    raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
                _verify_locator_row(
                    loc_row,
                    expected_owner_id=registration.owner_id,
                    expected_repo_id=repo_id,
                    loc=loc,
                )
            return WorkspaceBinding(
                owner_id=registration.owner_id,
                repo_id=repo_id,
                checkout_id=chk_id,
                machine_id=registration.machine_id,
                alias=registration.alias,
                checkout_path=registration.checkout_path,
                locator_digest=loc_digest,
            )

        created_at = utc_timestamp(now)
        with immediate() as txn_db:
            alias_row = txn_db.execute(
                "SELECT checkout_id, path_identity FROM workspace_checkout "
                "WHERE owner_id = ? AND machine_id = ? AND alias = ?",
                (registration.owner_id, registration.machine_id, registration.alias),
            ).fetchone()
            if alias_row is not None and require_stored_str(alias_row[1]) != registration.path_identity:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

            path_row = txn_db.execute(
                "SELECT checkout_id, repo_id, alias FROM workspace_checkout "
                "WHERE owner_id = ? AND machine_id = ? AND path_identity = ?",
                (registration.owner_id, registration.machine_id, registration.path_identity),
            ).fetchone()
            if path_row is not None:
                if require_stored_str(path_row[2]) != registration.alias:
                    raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
                checkout_id = require_stored_opaque_id(path_row[0])
                repo_id = require_stored_opaque_id(path_row[1])
                _verify_existing_repo_policy(
                    txn_db,
                    repo_id=repo_id,
                    expected_owner_id=registration.owner_id,
                    expected_egress=registration.provider_egress_enabled,
                )
                if loc is not None:
                    loc_row = txn_db.execute(
                        "SELECT owner_id, repo_id, scheme, canonical_locator "
                        "FROM workspace_repo_locator WHERE locator_digest = ?",
                        (loc.locator_digest,),
                    ).fetchone()
                    if loc_row is not None:
                        _verify_locator_row(
                            loc_row,
                            expected_owner_id=registration.owner_id,
                            expected_repo_id=repo_id,
                            loc=loc,
                        )
                    else:
                        txn_db.execute(
                            "INSERT INTO workspace_repo_locator "
                            "(locator_digest, owner_id, repo_id, scheme, canonical_locator, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                loc.locator_digest,
                                registration.owner_id,
                                repo_id,
                                loc.scheme,
                                loc.canonical_locator,
                                created_at,
                            ),
                        )
                txn_db.execute(
                    "UPDATE workspace_checkout SET checkout_path = ?, registered_intent_id = ? "
                    "WHERE checkout_id = ?",
                    (registration.checkout_path, authorization.intent_id, checkout_id),
                )
            else:
                if loc is not None:
                    loc_row = txn_db.execute(
                        "SELECT owner_id, repo_id, scheme, canonical_locator "
                        "FROM workspace_repo_locator WHERE locator_digest = ?",
                        (loc.locator_digest,),
                    ).fetchone()
                    if loc_row is not None:
                        repo_id = _verify_locator_row(
                            loc_row,
                            expected_owner_id=registration.owner_id,
                            expected_repo_id=None,
                            loc=loc,
                        )
                        _verify_existing_repo_policy(
                            txn_db,
                            repo_id=repo_id,
                            expected_owner_id=registration.owner_id,
                            expected_egress=registration.provider_egress_enabled,
                        )
                    else:
                        repo_id = new_id()
                        txn_db.execute(
                            "INSERT INTO repo_policy (repo_id, owner_id, provider_egress_enabled, updated_at) "
                            "VALUES (?, ?, ?, ?)",
                            (
                                repo_id,
                                registration.owner_id,
                                1 if registration.provider_egress_enabled else 0,
                                created_at,
                            ),
                        )
                        txn_db.execute(
                            "INSERT INTO workspace_repo_locator "
                            "(locator_digest, owner_id, repo_id, scheme, canonical_locator, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                loc.locator_digest,
                                registration.owner_id,
                                repo_id,
                                loc.scheme,
                                loc.canonical_locator,
                                created_at,
                            ),
                        )
                else:
                    repo_id = new_id()
                    txn_db.execute(
                        "INSERT INTO repo_policy (repo_id, owner_id, provider_egress_enabled, updated_at) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            repo_id,
                            registration.owner_id,
                            1 if registration.provider_egress_enabled else 0,
                            created_at,
                        ),
                    )
                checkout_id = new_id()
                txn_db.execute(
                    "INSERT INTO workspace_checkout "
                    "(checkout_id, owner_id, repo_id, machine_id, alias, checkout_path, path_identity, "
                    "registered_intent_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        checkout_id,
                        registration.owner_id,
                        repo_id,
                        registration.machine_id,
                        registration.alias,
                        registration.checkout_path,
                        registration.path_identity,
                        authorization.intent_id,
                        created_at,
                    ),
                )

            txn_db.execute(
                "INSERT OR IGNORE INTO repo_grant (principal_id, repo_id, granted_intent_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (registration.principal_id, repo_id, authorization.intent_id, created_at),
            )
            payload: dict[str, JsonValue] = {
                "repo_id": repo_id,
                "checkout_id": checkout_id,
                "principal_id": registration.principal_id,
                "machine_id": registration.machine_id,
                "alias": registration.alias,
                "locator_digest": loc_digest,
            }
            checked = validate_policy_intent_payload(
                IntentKind.WORKSPACE_REGISTER, payload, authorization.intent_id
            )
            txn_db.execute(
                "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (authorization.intent_id, IntentKind.WORKSPACE_REGISTER.value, canonical_json(checked), created_at),
            )
    crashpoint("policy.after_intent_commit")
    return WorkspaceBinding(
        owner_id=registration.owner_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        machine_id=registration.machine_id,
        alias=registration.alias,
        checkout_path=registration.checkout_path,
        locator_digest=loc_digest,
    )
