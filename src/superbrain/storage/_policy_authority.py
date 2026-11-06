"""Internal policy v2 authority implementation backing ``PolicyStore``'s ``KernelPolicyPort`` methods."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    AuthSnapshot,
    BootstrapAuthorization,
    CredentialRecord,
    Principal,
    RepoPolicy,
    Scope,
    WorkspaceBinding,
    WorkspaceRegistration,
    is_trusted_bootstrap_issuer,
    parse_bearer_token,
    verify_secret_digest,
)
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage.identity import validate_policy_intent_payload
from superbrain.storage.kernel_schema import POLICY_V2_TABLES
from superbrain.storage.kinds import is_uuid
from superbrain.storage.ledger import utc_timestamp

_GLOBAL_SCOPELESS_ACTIONS: frozenset[str] = frozenset({"get_health", "get_job", "global_read"})


def _ensure_v2_tables(db: sqlite3.Connection) -> None:
    try:
        tables = {
            str(row[0])
            for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if not POLICY_V2_TABLES <= tables:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")


def resolve_policy_credential(db: sqlite3.Connection, token: str) -> Principal:
    _ensure_v2_tables(db)
    cred_id, candidate_digest = parse_bearer_token(token)
    try:
        row = db.execute(
            "SELECT c.secret_digest, c.revoked_intent_id, p.id, p.owner_id, p.harness_id, p.machine_id "
            "FROM credential AS c JOIN principal AS p ON p.id = c.principal_id WHERE c.id = ?",
            (cred_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if row is None or row[1] is not None:
        verify_secret_digest(candidate_digest, None)
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    secret_digest, _, principal_id, owner_id, harness_id, machine_id = row
    if not isinstance(secret_digest, str) or not verify_secret_digest(candidate_digest, secret_digest):
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    return Principal(
        principal_id=str(principal_id),
        owner_id=str(owner_id),
        harness_id=str(harness_id),
        machine_id=str(machine_id),
    )


def policy_allows(
    db: sqlite3.Connection, principal: Principal, scope: Scope | None, *, action: str
) -> bool:
    _ensure_v2_tables(db)
    if not isinstance(principal, Principal) or not isinstance(action, str) or not action:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    try:
        p_row = db.execute(
            "SELECT 1 FROM principal WHERE id = ? AND owner_id = ? AND harness_id = ? AND machine_id = ?",
            (principal.principal_id, principal.owner_id, principal.harness_id, principal.machine_id),
        ).fetchone()
        if p_row is None:
            return False
        active_cred = db.execute(
            "SELECT 1 FROM credential WHERE principal_id = ? AND revoked_intent_id IS NULL LIMIT 1",
            (principal.principal_id,),
        ).fetchone()
        if active_cred is None:
            return False
        if scope is None:
            return action in _GLOBAL_SCOPELESS_ACTIONS
        repo_row = db.execute(
            "SELECT owner_id FROM repo_policy WHERE repo_id = ?",
            (scope.repo_id,),
        ).fetchone()
        if repo_row is None or str(repo_row[0]) != principal.owner_id:
            return False
        grant_row = db.execute(
            "SELECT 1 FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
            (principal.principal_id, scope.repo_id),
        ).fetchone()
        if grant_row is None:
            return False
        if scope.checkout_id is not None:
            chk_row = db.execute(
                "SELECT 1 FROM workspace_checkout "
                "WHERE checkout_id = ? AND owner_id = ? AND repo_id = ? AND machine_id = ?",
                (scope.checkout_id, principal.owner_id, scope.repo_id, principal.machine_id),
            ).fetchone()
            if chk_row is None:
                return False
        return True
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc


def build_policy_snapshot(
    db: sqlite3.Connection, *, store_id: str, trust_generation: int
) -> AuthSnapshot:
    _ensure_v2_tables(db)
    try:
        principals: dict[str, Principal] = {}
        for pid, owner_id, harness_id, machine_id in db.execute(
            "SELECT id, owner_id, harness_id, machine_id FROM principal ORDER BY id"
        ).fetchall():
            p = Principal(
                principal_id=str(pid),
                owner_id=str(owner_id),
                harness_id=str(harness_id),
                machine_id=str(machine_id),
            )
            principals[p.principal_id] = p

        credentials: dict[str, CredentialRecord] = {}
        for cid, pid, secret_digest, revoked_intent_id in db.execute(
            "SELECT id, principal_id, secret_digest, revoked_intent_id FROM credential ORDER BY id"
        ).fetchall():
            principal_obj = principals.get(str(pid))
            if principal_obj is None:
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            credentials[str(cid)] = CredentialRecord(
                credential_id=str(cid),
                principal=principal_obj,
                secret_digest=str(secret_digest),
                revoked=revoked_intent_id is not None,
            )

        repo_policies: dict[str, RepoPolicy] = {}
        for repo_id, owner_id, egress in db.execute(
            "SELECT repo_id, owner_id, provider_egress_enabled FROM repo_policy ORDER BY repo_id"
        ).fetchall():
            repo_policies[str(repo_id)] = RepoPolicy(
                repo_id=str(repo_id),
                owner_id=str(owner_id),
                provider_egress_enabled=bool(egress),
            )

        grants = frozenset(
            (str(pid), str(rid))
            for pid, rid in db.execute("SELECT principal_id, repo_id FROM repo_grant").fetchall()
        )

        intent_locators: dict[str, str | None] = {}
        for intent_id, raw_payload in db.execute(
            "SELECT intent_id, payload FROM intents WHERE kind = ?",
            (IntentKind.WORKSPACE_REGISTER.value,),
        ).fetchall():
            decoded = json.loads(bytes(raw_payload))
            loc = decoded.get("locator_digest") if isinstance(decoded, dict) else None
            intent_locators[str(intent_id)] = str(loc) if isinstance(loc, str) else None

        checkouts: dict[str, WorkspaceBinding] = {}
        for chk_id, owner_id, repo_id, machine_id, alias, chk_path, reg_intent_id in db.execute(
            "SELECT checkout_id, owner_id, repo_id, machine_id, alias, checkout_path, registered_intent_id "
            "FROM workspace_checkout ORDER BY checkout_id"
        ).fetchall():
            checkouts[str(chk_id)] = WorkspaceBinding(
                owner_id=str(owner_id),
                repo_id=str(repo_id),
                checkout_id=str(chk_id),
                machine_id=str(machine_id),
                alias=str(alias),
                checkout_path=str(chk_path),
                locator_digest=intent_locators.get(str(reg_intent_id)),
            )
    except BrainError as err:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from err
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc

    return AuthSnapshot(
        store_id=store_id,
        trust_generation=trust_generation,
        credentials=credentials,
        principals=principals,
        repo_policies=repo_policies,
        grants=grants,
        checkouts=checkouts,
    )


def read_policy_request_digest_key(db: sqlite3.Connection) -> tuple[str, bytes]:
    _ensure_v2_tables(db)
    try:
        rows = db.execute(
            "SELECT id, key_bytes FROM request_digest_key WHERE active = 1 ORDER BY rowid DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if len(rows) != 1:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    key_id, key_bytes = rows[0]
    if not isinstance(key_id, str) or not key_id or not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return key_id, key_bytes


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


def record_policy_authorized_revocation(
    db: sqlite3.Connection,
    immediate: Callable[[], AbstractContextManager[sqlite3.Connection]],
    decode_intent: Callable[[ tuple[object, ...] ], Intent],
    *,
    credential_id: str,
    authorization: BootstrapAuthorization,
    store_id: str,
    trust_generation: int,
    now: datetime,
) -> Intent:
    _ensure_v2_tables(db)
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

    existing_intent_row = db.execute(
        "SELECT intent_id, kind, payload, created_at FROM intents WHERE intent_id = ?",
        (authorization.intent_id,),
    ).fetchone()

    cred_row = db.execute(
        "SELECT c.principal_id, p.owner_id FROM credential AS c "
        "JOIN principal AS p ON p.id = c.principal_id WHERE c.id = ?",
        (credential_id,),
    ).fetchone()
    if cred_row is None:
        if existing_intent_row is not None:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    principal_id, cred_owner_id = str(cred_row[0]), str(cred_row[1])
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
    decode_intent: Callable[[ tuple[object, ...] ], Intent],
    *,
    registration: WorkspaceRegistration,
    authorization: BootstrapAuthorization,
    store_id: str,
    trust_generation: int,
    now: datetime,
) -> WorkspaceBinding:
    _ensure_v2_tables(db)
    if not isinstance(registration, WorkspaceRegistration):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if isinstance(authorization, BootstrapAuthorization) and authorization.owner_id != registration.owner_id:
        if authorization.store_id != store_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    _check_ingress_auth(
        authorization,
        store_id=store_id,
        expected_action="workspace_register",
        expected_subject_id=registration.subject_id,
        trust_generation=trust_generation,
        now=now,
    )

    p_row = db.execute(
        "SELECT owner_id, machine_id FROM principal WHERE id = ?",
        (registration.principal_id,),
    ).fetchone()
    if p_row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if str(p_row[0]) != registration.owner_id or str(p_row[1]) != registration.machine_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

    loc = registration.locator
    loc_digest = loc.locator_digest if loc is not None else None

    existing_intent_row = db.execute(
        "SELECT intent_id, kind, payload, created_at FROM intents WHERE intent_id = ?",
        (authorization.intent_id,),
    ).fetchone()
    if existing_intent_row is not None:
        existing_intent = decode_intent(tuple(existing_intent_row))
        if existing_intent.kind is not IntentKind.WORKSPACE_REGISTER:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        chk_id = str(existing_intent.payload["checkout_id"])
        repo_id = str(existing_intent.payload["repo_id"])
        chk_row = db.execute(
            "SELECT owner_id, repo_id, machine_id, alias, checkout_path, path_identity "
            "FROM workspace_checkout WHERE checkout_id = ?",
            (chk_id,),
        ).fetchone()
        if (
            chk_row is None
            or str(chk_row[0]) != registration.owner_id
            or str(chk_row[1]) != repo_id
            or str(chk_row[2]) != registration.machine_id
            or str(chk_row[3]) != registration.alias
            or str(chk_row[4]) != registration.checkout_path
            or str(chk_row[5]) != registration.path_identity
            or str(existing_intent.payload["principal_id"]) != registration.principal_id
            or existing_intent.payload["locator_digest"] != loc_digest
        ):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
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
        if alias_row is not None and str(alias_row[1]) != registration.path_identity:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

        path_row = txn_db.execute(
            "SELECT checkout_id, repo_id, alias FROM workspace_checkout "
            "WHERE owner_id = ? AND machine_id = ? AND path_identity = ?",
            (registration.owner_id, registration.machine_id, registration.path_identity),
        ).fetchone()
        if path_row is not None:
            if str(path_row[2]) != registration.alias:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            checkout_id = str(path_row[0])
            repo_id = str(path_row[1])
            if loc is not None:
                loc_row = txn_db.execute(
                    "SELECT owner_id, repo_id FROM workspace_repo_locator WHERE locator_digest = ?",
                    (loc.locator_digest,),
                ).fetchone()
                if loc_row is not None and (str(loc_row[0]) != registration.owner_id or str(loc_row[1]) != repo_id):
                    raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
                if loc_row is None:
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
                "UPDATE repo_policy SET provider_egress_enabled = ?, updated_at = ? WHERE repo_id = ?",
                (1 if registration.provider_egress_enabled else 0, created_at, repo_id),
            )
            txn_db.execute(
                "UPDATE workspace_checkout SET checkout_path = ?, registered_intent_id = ? WHERE checkout_id = ?",
                (registration.checkout_path, authorization.intent_id, checkout_id),
            )
        else:
            if loc is not None:
                loc_row = txn_db.execute(
                    "SELECT owner_id, repo_id FROM workspace_repo_locator WHERE locator_digest = ?",
                    (loc.locator_digest,),
                ).fetchone()
                if loc_row is not None:
                    if str(loc_row[0]) != registration.owner_id:
                        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
                    repo_id = str(loc_row[1])
                else:
                    repo_id = new_id()
                    txn_db.execute(
                        "INSERT INTO repo_policy (repo_id, owner_id, provider_egress_enabled, updated_at) "
                        "VALUES (?, ?, ?, ?)",
                        (repo_id, registration.owner_id, 1 if registration.provider_egress_enabled else 0, created_at),
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
                    (repo_id, registration.owner_id, 1 if registration.provider_egress_enabled else 0, created_at),
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
