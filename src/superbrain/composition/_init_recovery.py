"""Durable state and recovery helpers for ``brain init`` (F3)."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from superbrain.adapters.os.daemon_config import read_client_ca, read_client_credential, read_daemon_config
from superbrain.adapters.os.tls_material import create_store_tls, verify_server_tls_files
from superbrain.core._kernel_approval import SignerEnrollment
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
    "INIT_BOOTSTRAP_STATE_KEY", "InitBootstrapState", "compute_init_request_digest",
    "has_existing_data_artifacts", "prepare_init_recovery", "recover_or_provision_tls", "write_init_bootstrap_state",
]

INIT_BOOTSTRAP_STATE_KEY = "init_bootstrap_state"
_TLS_KNOWN_NAMES = frozenset({"ca.pem", "ca.key", "server.pem", "server.key"})
_BOOTSTRAP_ISSUER = "owner:local-bootstrap"
_BOOTSTRAP_TTL = timedelta(minutes=10)


@dataclass(frozen=True)
class InitBootstrapState:
    status: str
    request_digest: str
    config_dir: str
    cli_credential_id: str


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
    rt: Runtime, *, status: str, request_digest: str, config_dir: Path, cli_credential_id: str
) -> None:
    """Persist non-secret ``init_bootstrap_state`` into ``policy.db`` ``meta`` table."""
    payload = json.dumps(
        {
            "status": status,
            "request_digest": request_digest,
            "config_dir": os.path.abspath(config_dir),
            "cli_credential_id": cli_credential_id,
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
    keys = ("status", "request_digest", "config_dir", "cli_credential_id")
    vals = [parsed.get(k) for k in keys]
    if not all(isinstance(v, str) and v for v in vals):
        raise _invalid()
    return InitBootstrapState(str(vals[0]), str(vals[1]), str(vals[2]), str(vals[3]))


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
            if entry.name not in _TLS_KNOWN_NAMES:
                raise _invalid()
            os_.paths.reject_links(entry)
            if not entry.is_file():
                raise _invalid()
            if os_.permissions.object_problems(entry):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

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
        if cid != expected_cred_id:
            raise _invalid()


def prepare_init_recovery(
    *, data_root: Path, config_dir: Path, owner_id: str, request_digest: str, os_: OsAdapters
) -> tuple[str, InitBootstrapState]:
    """Read-only verification of an interrupted ``init_store`` root; raises ``INVALID_INPUT`` if unsafe/completed."""
    root = DataRoot.at(data_root)
    if not os.path.lexists(root.policy_db) or not os.path.lexists(root.store_db):
        raise _invalid()
    verified = verify_existing_data_root(data_root, os_)
    with acquire_writer_unbumped(verified, os_):
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
        if row is None or existing_owner != owner_id:
            raise _invalid()
        state = _parse_state(row[0])
        if (
            state.status != "in_progress"
            or state.request_digest != request_digest
            or state.config_dir != os.path.abspath(config_dir)
        ):
            raise _invalid()
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
) -> tuple[Path, Path]:
    """Reuse complete valid TLS files or clean incomplete known TLS files and provision fresh TLS."""
    known = [tls_dir / name for name in ("ca.pem", "ca.key", "server.pem", "server.key")]
    existing = [p for p in known if os.path.lexists(p)]
    if len(existing) == 4:
        if not _verify_complete_tls(tls_dir, data_root, store_id, os_):
            raise _invalid()
        return tls_dir / "server.pem", tls_dir / "server.key"
    if existing:
        for path in existing:
            path.unlink()
        os_.publisher.sync_directory(tls_dir)
    auth = BootstrapAuthorization(
        intent_id=new_id(), store_id=store_id, owner_id=owner_id, action="provision_tls", subject_id=store_id,
        trust_generation=generation, expires_at=os_.clock.now() + _BOOTSTRAP_TTL, issuer_id=_BOOTSTRAP_ISSUER,
        destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, auth, os_.clock, os_)
    return tls.cert_path, tls.key_path
