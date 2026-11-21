"""Internal policy v2 read-side authority and stored-row validation backing ``PolicyStore``."""

from __future__ import annotations

import json
import sqlite3

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    GLOBAL_SCOPELESS_ACTIONS,
    OPAQUE_ID_RE,
    SHA256_DIGEST_RE,
    AuthSnapshot,
    CredentialRecord,
    Principal,
    RepoPolicy,
    Scope,
    WorkspaceBinding,
    parse_bearer_token,
    require_opaque_id,
    verify_secret_digest,
)
from superbrain.ports.policy import IntentKind
from superbrain.storage.identity import validate_policy_intent_payload
from superbrain.storage.kernel_schema import (
    KERNEL_POLICY_MIGRATIONS,
    POLICY_V2_TABLES,
    POLICY_V4_TABLES,
    POLICY_V5_TABLES,
)
from superbrain.storage.kinds import is_uuid
from superbrain.storage.schema import code_version

_POLICY_V1_TABLES: frozenset[str] = frozenset({"meta", "intents", "tombstones", "quarantine", "trust"})
_REQUIRED_POLICY_TABLES: frozenset[str] = _POLICY_V1_TABLES | POLICY_V2_TABLES
_MAX_VERSION_DIGITS = 18


def _parse_policy_version(raw: str | None) -> int:
    if raw is None or not (1 <= len(raw) <= _MAX_VERSION_DIGITS) or not (raw.isascii() and raw.isdigit()):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    try:
        return int(raw)
    except ValueError as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc


def ensure_v2_tables(
    db: sqlite3.Connection,
    *,
    expected_store_id: str | None = None,
    expected_schema_version: int | None = None,
) -> None:
    target_sv = code_version(KERNEL_POLICY_MIGRATIONS) if expected_schema_version is None else expected_schema_version
    if type(target_sv) is not int or target_sv < 2:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    try:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            if isinstance(row[0], str)
        }
        if (
            not _REQUIRED_POLICY_TABLES <= tables
            or (target_sv >= 4 and not POLICY_V4_TABLES <= tables)
            or (target_sv >= 5 and not POLICY_V5_TABLES <= tables)
        ):
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

        raw_meta = db.execute("SELECT key, value FROM meta").fetchall()
        if any(not isinstance(r[0], str) or not isinstance(r[1], str) for r in raw_meta):
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        meta_rows = {str(r[0]): str(r[1]) for r in raw_meta}
        sv = _parse_policy_version(meta_rows.get("schema_version"))
        mrv = _parse_policy_version(meta_rows.get("min_reader_version"))
        raw_sid = meta_rows.get("store_id")
        if sv != target_sv or mrv < 1 or mrv > sv or raw_sid is None or not raw_sid:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        if expected_store_id is not None and raw_sid != expected_store_id:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

        trust_rows = db.execute("SELECT id, generation FROM trust").fetchall()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if (
        len(trust_rows) != 1
        or type(trust_rows[0][0]) is not int
        or trust_rows[0][0] != 1
        or type(trust_rows[0][1]) is not int
        or trust_rows[0][1] < 1
    ):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")


def require_stored_str(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return value


def require_stored_uuid(value: object) -> str:
    if not isinstance(value, str) or not is_uuid(value):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return value


def require_stored_opaque_id(value: object) -> str:
    if not isinstance(value, str) or not OPAQUE_ID_RE.fullmatch(value):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return value


def require_stored_digest(value: object) -> str:
    if not isinstance(value, str) or not SHA256_DIGEST_RE.fullmatch(value):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return value


def require_stored_optional_uuid(value: object) -> str | None:
    if value is None:
        return None
    return require_stored_uuid(value)


def require_stored_bool_int(value: object) -> bool:
    if type(value) is not int or value not in (0, 1):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return value == 1


def decode_stored_principal(
    principal_id: object, owner_id: object, harness_id: object, machine_id: object
) -> Principal:
    pid = require_stored_str(principal_id)
    oid = require_stored_str(owner_id)
    hid = require_stored_str(harness_id)
    mid = require_stored_str(machine_id)
    try:
        return Principal(principal_id=pid, owner_id=oid, harness_id=hid, machine_id=mid)
    except BrainError as err:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from err


def resolve_policy_credential(
    db: sqlite3.Connection,
    token: str,
    *,
    expected_store_id: str | None = None,
    expected_schema_version: int | None = None,
) -> Principal:
    ensure_v2_tables(
        db,
        expected_store_id=expected_store_id,
        expected_schema_version=expected_schema_version,
    )
    cred_id, candidate_digest = parse_bearer_token(token)
    try:
        row = db.execute(
            "SELECT c.secret_digest, c.revoked_intent_id, p.id, p.owner_id, p.harness_id, p.machine_id "
            "FROM credential AS c LEFT JOIN principal AS p ON p.id = c.principal_id WHERE c.id = ?",
            (cred_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if row is None:
        verify_secret_digest(candidate_digest, None)
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")

    raw_digest, raw_revoked, p_id, owner_id, harness_id, machine_id = row
    secret_digest = require_stored_digest(raw_digest)
    revoked_intent_id = require_stored_optional_uuid(raw_revoked)
    principal = decode_stored_principal(p_id, owner_id, harness_id, machine_id)

    if revoked_intent_id is not None:
        verify_secret_digest(candidate_digest, None)
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    if not verify_secret_digest(candidate_digest, secret_digest):
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    return principal


def policy_allows(
    db: sqlite3.Connection,
    principal: Principal,
    scope: Scope | None,
    *,
    action: str,
    expected_store_id: str | None = None,
    expected_schema_version: int | None = None,
) -> bool:
    ensure_v2_tables(
        db,
        expected_store_id=expected_store_id,
        expected_schema_version=expected_schema_version,
    )
    if (
        not isinstance(principal, Principal)
        or (scope is not None and not isinstance(scope, Scope))
        or not isinstance(action, str)
        or not action
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    try:
        p_row = db.execute(
            "SELECT id, owner_id, harness_id, machine_id FROM principal WHERE id = ?",
            (principal.principal_id,),
        ).fetchone()
        if p_row is None:
            return False
        stored_principal = decode_stored_principal(p_row[0], p_row[1], p_row[2], p_row[3])
        if stored_principal != principal:
            return False

        cred_rows = db.execute(
            "SELECT id, secret_digest, revoked_intent_id FROM credential WHERE principal_id = ?",
            (principal.principal_id,),
        ).fetchall()
        has_active_cred = False
        for cid, s_digest, rev_id in cred_rows:
            require_stored_uuid(cid)
            require_stored_digest(s_digest)
            if require_stored_optional_uuid(rev_id) is None:
                has_active_cred = True
        if not has_active_cred:
            return False

        if scope is None:
            return action in GLOBAL_SCOPELESS_ACTIONS

        repo_row = db.execute(
            "SELECT owner_id, provider_egress_enabled FROM repo_policy WHERE repo_id = ?",
            (scope.repo_id,),
        ).fetchone()
        if repo_row is None:
            return False
        repo_owner = require_stored_opaque_id(repo_row[0])
        require_stored_bool_int(repo_row[1])
        if repo_owner != principal.owner_id:
            return False

        grant_row = db.execute(
            "SELECT granted_intent_id FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
            (principal.principal_id, scope.repo_id),
        ).fetchone()
        if grant_row is None:
            return False
        require_stored_uuid(grant_row[0])

        if scope.checkout_id is not None:
            chk_row = db.execute(
                "SELECT owner_id, repo_id, machine_id, alias, checkout_path "
                "FROM workspace_checkout WHERE checkout_id = ?",
                (scope.checkout_id,),
            ).fetchone()
            if chk_row is None:
                return False
            try:
                binding = WorkspaceBinding(
                    owner_id=require_stored_str(chk_row[0]),
                    repo_id=require_stored_str(chk_row[1]),
                    checkout_id=scope.checkout_id,
                    machine_id=require_stored_str(chk_row[2]),
                    alias=require_stored_str(chk_row[3]),
                    checkout_path=require_stored_str(chk_row[4]),
                )
            except BrainError as err:
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from err
            if (
                binding.owner_id != principal.owner_id
                or binding.repo_id != scope.repo_id
                or binding.machine_id != principal.machine_id
            ):
                return False
        return True
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc


def build_policy_snapshot(
    db: sqlite3.Connection,
    *,
    store_id: str,
    trust_generation: int,
    expected_schema_version: int | None = None,
) -> AuthSnapshot:
    ensure_v2_tables(
        db,
        expected_store_id=store_id,
        expected_schema_version=expected_schema_version,
    )
    try:
        principals: dict[str, Principal] = {}
        for pid, owner_id, harness_id, machine_id in db.execute(
            "SELECT id, owner_id, harness_id, machine_id FROM principal ORDER BY id"
        ).fetchall():
            p = decode_stored_principal(pid, owner_id, harness_id, machine_id)
            principals[p.principal_id] = p

        credentials: dict[str, CredentialRecord] = {}
        for cid, pid, secret_digest, revoked_intent_id in db.execute(
            "SELECT id, principal_id, secret_digest, revoked_intent_id FROM credential ORDER BY id"
        ).fetchall():
            cred_id = require_stored_uuid(cid)
            principal_id = require_stored_opaque_id(pid)
            principal_obj = principals.get(principal_id)
            if principal_obj is None:
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            credentials[cred_id] = CredentialRecord(
                credential_id=cred_id,
                principal=principal_obj,
                secret_digest=require_stored_digest(secret_digest),
                revoked=require_stored_optional_uuid(revoked_intent_id) is not None,
            )

        repo_policies: dict[str, RepoPolicy] = {}
        target_sv = (
            code_version(KERNEL_POLICY_MIGRATIONS) if expected_schema_version is None else expected_schema_version
        )
        if target_sv >= 4:
            for repo_id, owner_id, egress, auto_cap, manual_sub, idx_en, post_rev in db.execute(
                "SELECT repo_id, owner_id, provider_egress_enabled, automatic_capture_enabled, "
                "manual_submission_enabled, indexing_enabled, post_session_review_enabled "
                "FROM repo_policy ORDER BY repo_id"
            ).fetchall():
                rid = require_stored_opaque_id(repo_id)
                repo_policies[rid] = RepoPolicy(
                    repo_id=rid,
                    owner_id=require_stored_opaque_id(owner_id),
                    provider_egress_enabled=require_stored_bool_int(egress),
                    automatic_capture_enabled=require_stored_bool_int(auto_cap),
                    manual_submission_enabled=require_stored_bool_int(manual_sub),
                    indexing_enabled=require_stored_bool_int(idx_en),
                    post_session_review_enabled=require_stored_bool_int(post_rev),
                )
        else:
            for repo_id, owner_id, egress in db.execute(
                "SELECT repo_id, owner_id, provider_egress_enabled FROM repo_policy ORDER BY repo_id"
            ).fetchall():
                rid = require_stored_opaque_id(repo_id)
                repo_policies[rid] = RepoPolicy(
                    repo_id=rid,
                    owner_id=require_stored_opaque_id(owner_id),
                    provider_egress_enabled=require_stored_bool_int(egress),
                )

        grant_pairs: set[tuple[str, str]] = set()
        for pid, rid, granted_intent_id in db.execute(
            "SELECT principal_id, repo_id, granted_intent_id FROM repo_grant"
        ).fetchall():
            g_pid = require_stored_opaque_id(pid)
            g_rid = require_stored_opaque_id(rid)
            require_stored_uuid(granted_intent_id)
            if g_pid not in principals or g_rid not in repo_policies:
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            grant_pairs.add((g_pid, g_rid))

        intent_locators: dict[str, str | None] = {}
        for raw_intent_id, raw_payload in db.execute(
            "SELECT intent_id, payload FROM intents WHERE kind = ?",
            (IntentKind.WORKSPACE_REGISTER.value,),
        ).fetchall():
            iid = require_stored_uuid(raw_intent_id)
            if not isinstance(raw_payload, bytes):
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            checked = validate_policy_intent_payload(
                IntentKind.WORKSPACE_REGISTER,
                json.loads(raw_payload),
                iid,
                allow_legacy_v1=True,
            )
            loc = checked.get("locator_digest")
            intent_locators[iid] = loc if isinstance(loc, str) else None

        checkouts: dict[str, WorkspaceBinding] = {}
        for chk_id, owner_id, repo_id, machine_id, alias, chk_path, reg_intent_id in db.execute(
            "SELECT checkout_id, owner_id, repo_id, machine_id, alias, checkout_path, registered_intent_id "
            "FROM workspace_checkout ORDER BY checkout_id"
        ).fetchall():
            cid_str = require_stored_opaque_id(chk_id)
            rid_str = require_stored_opaque_id(repo_id)
            iid_str = require_stored_uuid(reg_intent_id)
            if rid_str not in repo_policies:
                raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            checkouts[cid_str] = WorkspaceBinding(
                owner_id=require_stored_opaque_id(owner_id),
                repo_id=rid_str,
                checkout_id=cid_str,
                machine_id=require_stored_opaque_id(machine_id),
                alias=require_stored_str(alias),
                checkout_path=require_stored_str(chk_path),
                locator_digest=intent_locators.get(iid_str),
            )

        return AuthSnapshot(
            store_id=store_id,
            trust_generation=trust_generation,
            credentials=credentials,
            principals=principals,
            repo_policies=repo_policies,
            grants=frozenset(grant_pairs),
            checkouts=checkouts,
        )
    except BrainError as err:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from err
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc


def read_policy_request_digest_key(
    db: sqlite3.Connection,
    *,
    expected_store_id: str | None = None,
    expected_schema_version: int | None = None,
) -> tuple[str, bytes]:
    ensure_v2_tables(
        db,
        expected_store_id=expected_store_id,
        expected_schema_version=expected_schema_version,
    )
    try:
        rows = db.execute(
            "SELECT id, key_bytes FROM request_digest_key WHERE active = 1 ORDER BY rowid DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if len(rows) != 1:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    key_id, key_bytes = rows[0]
    checked_id = require_stored_opaque_id(key_id)
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return checked_id, key_bytes


def read_policy_request_digest_key_by_id(
    db: sqlite3.Connection,
    key_id: str,
    *,
    expected_store_id: str | None = None,
    expected_schema_version: int | None = None,
) -> bytes | None:
    require_opaque_id(key_id, label="key_id")
    ensure_v2_tables(
        db,
        expected_store_id=expected_store_id,
        expected_schema_version=expected_schema_version,
    )
    try:
        row = db.execute(
            "SELECT id, key_bytes, active FROM request_digest_key WHERE id = ?",
            (key_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc
    if row is None:
        return None
    stored_id, key_bytes, active = row
    checked_id = require_stored_opaque_id(stored_id)
    if checked_id != key_id:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    if type(active) is not int or active not in (0, 1):
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    if type(key_bytes) is not bytes or len(key_bytes) != 32:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    return key_bytes
