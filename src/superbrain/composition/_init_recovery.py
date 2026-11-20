"""Durable state and recovery helpers for ``brain init`` (F3).

Ownership evidence of an interrupted init is two-tiered: the non-secret ``meta['init_bootstrap_state']`` row in
``policy.db`` and, for crashes *before* that row exists (or before ``policy.db`` itself exists), the owner-only
``<config_dir>/.init-bootstrap.json`` pre-marker written before any data-root byte.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from superbrain.adapters.os.daemon_config import (
    publish_new_owner_file,
    read_client_ca,
    read_client_credential,
    read_daemon_config,
    read_owner_json_object,
)
from superbrain.adapters.os.tls_material import create_store_tls, verify_server_tls_files
from superbrain.core._kernel_approval import CLI_HARNESS_ID, SignerEnrollment
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import BootstrapAuthorization, DaemonConfig, parse_bearer_token
from superbrain.ports.os import OsAdapters
from superbrain.storage._policy_approvals import store_owner
from superbrain.storage.layout import DataRoot, verify_existing_data_root
from superbrain.storage.runtime import Runtime, _preadmission_scratch
from superbrain.storage.schema import read_schema_info
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.writer import acquire_writer_unbumped

__all__ = [
    "INIT_BOOTSTRAP_STATE_KEY", "INIT_MARKER_NAME", "InitBootstrapState", "compute_init_request_digest",
    "has_existing_data_artifacts", "prepare_init_recovery", "recover_or_provision_tls", "remove_init_marker",
    "require_matching_marker", "sweep_config_stage_files", "write_init_bootstrap_state", "write_init_marker",
]

INIT_BOOTSTRAP_STATE_KEY = "init_bootstrap_state"
INIT_MARKER_NAME = ".init-bootstrap.json"
_TLS_KNOWN_NAMES = frozenset({"ca.pem", "ca.key", "server.pem", "server.key"})
_UUID7 = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
# Staging siblings of ``publish_new_owner_file`` (a hard kill may leave one); nothing else is ever swept.
_CONFIG_STAGE_RE = re.compile(rf"\.(?:\.init-bootstrap\.json|daemon\.json|cli\.credential)\.stage-{_UUID7}")
_TLS_STAGE_RE = re.compile(rf"\.(?:ca\.pem|ca\.key|server\.pem|server\.key)\.stage-{_UUID7}")
_BOOTSTRAP_ISSUER = "owner:local-bootstrap"
_BOOTSTRAP_TTL = timedelta(minutes=10)
_FRESH_ONLY_ROWS = (
    "workspace_checkout", "approval_receipt_meta", "recovery_grant", "apply_turn_intent",
)


@dataclass(frozen=True)
class InitBootstrapState:
    status: str
    request_digest: str
    config_dir: str
    cli_credential_id: str = ""
    tls_leaf_cert_sha256: str = ""


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def compute_init_request_digest(*, owner_id: str, machine_id: str, signer: SignerEnrollment, config_dir: Path) -> str:
    """Compute canonical SHA-256 digest of the non-secret ``InitRequest`` identity."""
    return digest_bytes(canonical_json({
        "owner_id": owner_id, "machine_id": machine_id, "signer_channel": signer.channel.value,
        "signer_key_digest": signer.key_digest, "signer_credential_id": signer.credential_id,
        "config_dir": os.path.abspath(config_dir),
    }))


def has_existing_data_artifacts(data_root: Path) -> bool:
    """Return True if ``data_root`` contains any store/policy/lock artifacts."""
    root = DataRoot.at(data_root)
    existing = (
        root.lock_path, root.policy_db, root.store_db, root.policy_dir, root.store_dir, root.cas_dir, root.backups_dir
    )
    if any(os.path.lexists(path) for path in existing):
        return True
    if os.path.lexists(data_root) and data_root.is_dir():
        return any(entry.name.startswith(("policy.", "store.")) for entry in data_root.iterdir())
    return False


def write_init_bootstrap_state(
    rt: Runtime,
    *,
    status: str,
    request_digest: str,
    config_dir: Path,
    cli_credential_id: str,
    tls_leaf_cert_sha256: str = "",
) -> None:
    """Persist non-secret ``init_bootstrap_state`` into ``policy.db`` ``meta`` table."""
    payload = json.dumps(
        {
            "status": status,
            "request_digest": request_digest,
            "config_dir": os.path.abspath(config_dir),
            "cli_credential_id": cli_credential_id,
            "tls_leaf_cert_sha256": tls_leaf_cert_sha256,
        },
        sort_keys=True,
    )
    with rt.policy._authority_tx() as db:
        db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (INIT_BOOTSTRAP_STATE_KEY, payload))


def _parse_state(raw: object) -> InitBootstrapState:
    if not isinstance(raw, str):
        raise _invalid()
    try:
        parsed: Any = json.loads(raw)
    except ValueError as err:
        raise _invalid() from err
    if not isinstance(parsed, dict):
        raise _invalid()
    required = [parsed.get(k) for k in ("status", "request_digest", "config_dir")]
    optional = [parsed.get(k, "") for k in ("cli_credential_id", "tls_leaf_cert_sha256")]
    if not all(isinstance(v, str) and v for v in required) or not all(isinstance(v, str) for v in optional):
        raise _invalid()
    return InitBootstrapState(str(required[0]), str(required[1]), str(required[2]), str(optional[0]), str(optional[1]))


def _marker_body(*, request_digest: str, data_root: Path, config_dir: Path, owner_id: str) -> dict[str, object]:
    return {
        "version": 1, "status": "in_progress", "request_digest": request_digest,
        "data_root": os.path.abspath(data_root), "config_dir": os.path.abspath(config_dir), "owner_id": owner_id,
    }


def write_init_marker(
    *, request_digest: str, data_root: Path, config_dir: Path, owner_id: str, os_: OsAdapters
) -> None:
    """Durably write the owner-only, non-secret pre-marker BEFORE any data-root byte is created."""
    path = config_dir / INIT_MARKER_NAME
    body = _marker_body(request_digest=request_digest, data_root=data_root, config_dir=config_dir, owner_id=owner_id)
    publish_new_owner_file(path, canonical_json(body) + b"\n", os_)



def _verified_stages(directory: Path, pattern: re.Pattern[str], os_: OsAdapters) -> list[Path]:
    """Our own staging files in ``directory`` (never links/foreign names); unsafe ones refuse the init."""
    if not os.path.lexists(directory) or not directory.is_dir():
        return []
    found: list[Path] = []
    for entry in directory.iterdir():
        if not pattern.fullmatch(entry.name):
            continue
        os_.paths.reject_links(entry)
        if not entry.is_file():
            raise _invalid()
        if os_.permissions.object_problems(entry):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        found.append(entry)
    return found


def _sweep_stages(directory: Path, pattern: re.Pattern[str], os_: OsAdapters) -> None:
    stages = _verified_stages(directory, pattern, os_)
    for stage in stages:
        stage.unlink()
    if stages:
        os_.publisher.sync_directory(directory)


def sweep_config_stage_files(config_dir: Path, os_: OsAdapters) -> None:
    """Remove verified leftover init staging files (marker/``daemon.json``/``cli.credential``) of a killed init."""
    _sweep_stages(config_dir, _CONFIG_STAGE_RE, os_)


def remove_init_marker(config_dir: Path, os_: OsAdapters) -> None:
    """Remove the pre-marker (if any) once ownership is carried by the completed ``meta`` row."""
    path = config_dir / INIT_MARKER_NAME
    if os.path.lexists(path):
        path.unlink()
        os_.publisher.sync_directory(config_dir)


def _marker_matches(
    config_dir: Path, *, request_digest: str, data_root: Path, owner_id: str, os_: OsAdapters
) -> bool | None:
    """``None`` when no marker exists; otherwise whether it is exactly this request's marker."""
    path = config_dir / INIT_MARKER_NAME
    if not os.path.lexists(path):
        return None
    try:
        raw = read_owner_json_object(path, os_)
    except BrainError as err:
        if err.code in (ErrorCode.INVALID_INPUT, ErrorCode.NOT_FOUND):
            return False
        raise
    want = _marker_body(request_digest=request_digest, data_root=data_root, config_dir=config_dir, owner_id=owner_id)
    return bool(raw == want)


def require_matching_marker(
    config_dir: Path, *, request_digest: str, data_root: Path, owner_id: str, os_: OsAdapters, must_exist: bool
) -> bool:
    """Refuse a foreign/mismatching marker; return whether a matching one exists."""
    state = _marker_matches(config_dir, request_digest=request_digest, data_root=data_root, owner_id=owner_id, os_=os_)
    if state is False or (state is None and must_exist):
        raise _invalid()
    return state is True


def _validate_recovery_config_dir(
    *, data_root: Path, config_dir: Path, store_id: str, expected_cred_id: str, os_: OsAdapters
) -> None:
    if not os.path.lexists(config_dir):
        return
    os_.paths.reject_links(config_dir)
    if not config_dir.is_dir():
        raise _invalid()
    if os_.permissions.object_problems(config_dir):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    tls_dir = config_dir / "tls"
    if os.path.lexists(tls_dir):
        os_.paths.reject_links(tls_dir)
        if not tls_dir.is_dir():
            raise _invalid()
        if os_.permissions.object_problems(tls_dir):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        for entry in tls_dir.iterdir():
            if entry.name not in _TLS_KNOWN_NAMES and not _TLS_STAGE_RE.fullmatch(entry.name):
                raise _invalid()
            os_.paths.reject_links(entry)
            if not entry.is_file():
                raise _invalid()
            if os_.permissions.object_problems(entry):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    _verified_stages(config_dir, _CONFIG_STAGE_RE, os_)
    daemon_cfg = config_dir / "daemon.json"
    if os.path.lexists(daemon_cfg):
        cfg = read_daemon_config(daemon_cfg, os_)
        if (
            os.path.abspath(cfg.data_root) != os.path.abspath(data_root)
            or cfg.expected_store_id != store_id
            or os.path.abspath(cfg.cert_path) != os.path.abspath(tls_dir / "server.pem")
            or os.path.abspath(cfg.key_path) != os.path.abspath(tls_dir / "server.key")
        ):
            raise _invalid()

    cli_cred = config_dir / "cli.credential"
    if os.path.lexists(cli_cred):
        cid, _ = parse_bearer_token(read_client_credential(cli_cred, os_))
        if not expected_cred_id or cid != expected_cred_id:
            raise _invalid()


def _count(db: sqlite3.Connection, sql: str, params: tuple[object, ...] = ()) -> int:
    row = db.execute(sql, params).fetchone()
    return int(row[0]) if row is not None else 0


def _check_premeta_policy(db: sqlite3.Connection, owner_id: str, signer: SignerEnrollment) -> None:
    if store_owner(db) not in (None, owner_id):
        raise _invalid()
    signers = db.execute("SELECT owner_id, channel, key_digest, revoked_at FROM signer").fetchall()
    if len(signers) > 1 or any(
        (str(s[0]), str(s[1]), str(s[2])) != (owner_id, signer.channel.value, signer.key_digest) or s[3] is not None
        for s in signers
    ):
        raise _invalid()
    if _count(db, "SELECT COUNT(*) FROM principal WHERE harness_id <> ?", (CLI_HARNESS_ID,)) != 0:
        raise _invalid()
    if any(_count(db, f"SELECT COUNT(*) FROM {table}") != 0 for table in _FRESH_ONLY_ROWS):
        raise _invalid()


def _dir_is_empty(path: Path) -> bool:
    if not os.path.lexists(path):
        return True
    if not path.is_dir():
        return False
    with os.scandir(path) as entries:
        return next(iter(entries), None) is None


def _verify_premeta_root(verified: DataRoot, owner_id: str, signer: SignerEnrollment, os_: OsAdapters) -> None:
    """Read-only proof that a ``meta``-less root holds nothing but the init's own fresh bootstrap state."""
    if not _dir_is_empty(verified.cas_dir) or not _dir_is_empty(verified.backups_dir):
        raise _invalid()
    with _preadmission_scratch(verified.root, os_, None) as scratch_dir:
        try:
            if os.path.lexists(verified.policy_db):
                if read_schema_info(verified.policy_db) is None:
                    raise _invalid()
                pdb = open_readonly(verified.policy_db, scratch_dir=scratch_dir)
                try:
                    _check_premeta_policy(pdb, owner_id, signer)
                finally:
                    pdb.close()
            if os.path.lexists(verified.store_db):
                sdb = open_readonly(verified.store_db, scratch_dir=scratch_dir)
                try:
                    if _count(sdb, "SELECT COUNT(*) FROM ledger WHERE kind NOT LIKE 'policy%'") != 0:
                        raise _invalid()
                finally:
                    sdb.close()
        except sqlite3.Error as exc:
            raise _invalid() from exc


def _require_unstarted_config(config_dir: Path) -> None:
    if any(os.path.lexists(config_dir / name) for name in ("daemon.json", "cli.credential", "tls")):
        raise _invalid()


def prepare_init_recovery(
    *, data_root: Path, config_dir: Path, owner_id: str, request_digest: str, signer: SignerEnrollment, os_: OsAdapters
) -> tuple[str | None, InitBootstrapState]:
    """Read-only verification of an interrupted ``init_store`` root; raises ``INVALID_INPUT`` if unsafe/completed.

    Returns ``(store_id, state)`` when ``meta['init_bootstrap_state']`` proves an ``in_progress`` init of this exact
    request, or ``(None, state)`` when only the pre-marker proves ownership (crash before the ``meta`` row existed).
    A completed store, a legacy/user-owned store and any mismatch refuse without touching a byte.
    """
    root = DataRoot.at(data_root)
    try:
        verified = verify_existing_data_root(data_root, os_)
    except BrainError as err:
        if err.code is ErrorCode.NOT_FOUND:
            raise _invalid() from err
        raise
    with acquire_writer_unbumped(verified, os_):
        row = None
        info = None
        existing_owner: str | None = None
        if os.path.lexists(root.policy_db):
            info = read_schema_info(verified.policy_db)
            if info is None:
                raise _invalid()
            with _preadmission_scratch(verified.root, os_, None) as scratch_dir:
                ro_db = open_readonly(verified.policy_db, scratch_dir=scratch_dir)
                try:
                    try:
                        row = ro_db.execute(
                            "SELECT value FROM meta WHERE key = ?", (INIT_BOOTSTRAP_STATE_KEY,)
                        ).fetchone()
                        existing_owner = store_owner(ro_db)
                    except sqlite3.Error as exc:
                        raise _invalid() from exc
                finally:
                    ro_db.close()
        if row is None:
            require_matching_marker(
                config_dir, request_digest=request_digest, data_root=data_root, owner_id=owner_id, os_=os_,
                must_exist=True,
            )
            _require_unstarted_config(config_dir)
            _verified_stages(config_dir, _CONFIG_STAGE_RE, os_)
            _verify_premeta_root(verified, owner_id, signer, os_)
            return None, InitBootstrapState("in_progress", request_digest, os.path.abspath(config_dir))
        if existing_owner != owner_id or info is None or not os.path.lexists(root.store_db):
            raise _invalid()
        state = _parse_state(row[0])
        if (
            state.status != "in_progress"
            or state.request_digest != request_digest
            or state.config_dir != os.path.abspath(config_dir)
        ):
            raise _invalid()
        require_matching_marker(
            config_dir, request_digest=request_digest, data_root=data_root, owner_id=owner_id, os_=os_,
            must_exist=False,
        )
        _validate_recovery_config_dir(
            data_root=data_root,
            config_dir=config_dir,
            store_id=info.store_id,
            expected_cred_id=state.cli_credential_id,
            os_=os_,
        )
        return info.store_id, state


def _verify_complete_tls(tls_dir: Path, data_root: Path, store_id: str, os_: OsAdapters) -> bool:
    ca_pem_path, ca_key_path = tls_dir / "ca.pem", tls_dir / "ca.key"
    server_pem, server_key = tls_dir / "server.pem", tls_dir / "server.key"
    try:
        cfg = DaemonConfig(
            version=1, data_root=data_root, expected_store_id=store_id, cert_path=server_pem, key_path=server_key
        )
        verify_server_tls_files(cfg, os_.clock, os_)
        ca_cert = x509.load_pem_x509_certificate(read_client_ca(ca_pem_path, os_).encode("utf-8"))
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        der, spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if ca_cert.public_key().public_bytes(der, spki) != ca_key.public_key().public_bytes(der, spki):
            return False
        leaf_cert = x509.load_pem_x509_certificate(server_pem.read_bytes())
        pub = ca_cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or leaf_cert.signature_hash_algorithm is None:
            return False
        pub.verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes, ec.ECDSA(leaf_cert.signature_hash_algorithm))
        return True
    except (BrainError, InvalidSignature, ValueError, TypeError, OSError):
        return False


def recover_or_provision_tls(
    *, store_id: str, owner_id: str, generation: int, data_root: Path, tls_dir: Path, os_: OsAdapters
) -> tuple[Path, Path, str]:
    """Reuse complete valid TLS files or clean incomplete known TLS files and provision fresh TLS.

    Returns ``(cert_path, key_path, leaf_cert_sha256)``; the pin is the SHA-256 of the DER leaf certificate.
    """
    known = [tls_dir / name for name in ("ca.pem", "ca.key", "server.pem", "server.key")]
    existing = [p for p in known if os.path.lexists(p)]
    if len(existing) == 4:
        if not _verify_complete_tls(tls_dir, data_root, store_id, os_):
            raise _invalid()
        server_pem = tls_dir / "server.pem"
        leaf = x509.load_pem_x509_certificate(server_pem.read_bytes())
        sha = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
        _sweep_stages(tls_dir, _TLS_STAGE_RE, os_)
        return server_pem, tls_dir / "server.key", sha
    if existing:
        for path in existing:
            path.unlink()
        os_.publisher.sync_directory(tls_dir)
    _sweep_stages(tls_dir, _TLS_STAGE_RE, os_)
    auth = BootstrapAuthorization(
        intent_id=new_id(), store_id=store_id, owner_id=owner_id, action="provision_tls", subject_id=store_id,
        trust_generation=generation, expires_at=os_.clock.now() + _BOOTSTRAP_TTL, issuer_id=_BOOTSTRAP_ISSUER,
        destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, auth, os_.clock, os_)
    return tls.cert_path, tls.key_path, tls.leaf_cert_sha256
