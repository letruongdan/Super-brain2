"""Per-store private CA and loopback ``127.0.0.1`` TLS material provisioning and verification (Decision D2)."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.durable import map_os_error
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    BootstrapAuthorization,
    DaemonConfig,
    TlsMaterial,
    VerifiedServerTls,
    is_trusted_bootstrap_issuer,
    require_opaque_id,
)
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters

_LOOPBACK_IPV4 = ipaddress.IPv4Address("127.0.0.1")
_CA_VALIDITY_DAYS = 10 * 365
_LEAF_VALIDITY_DAYS = 365
_MAX_TLS_FILE_BYTES = 65_536


def _read_owner_only_file(path: Path, os_: OsAdapters) -> bytes:
    os_.paths.reject_unsafe_path(str(path))
    if not path.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    os_.paths.reject_links(path)
    if os_.permissions.check_ancestors(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    try:
        st = path.lstat()
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise map_os_error(err, "inspecting TLS file") from err
    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_TLS_FILE_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if os_.permissions.object_problems(path):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    try:
        return path.read_bytes()
    except OSError as err:
        raise map_os_error(err, "reading TLS file") from err


def create_store_tls(
    store_id: str,
    destination: Path,
    authorization: BootstrapAuthorization,
    clock: Clock,
    os_: OsAdapters | None = None,
) -> TlsMaterial:
    """Provision a per-store ECDSA P-256 Root CA and ``127.0.0.1`` server leaf certificate under ``destination``."""
    require_opaque_id(store_id, label="store_id")
    adapters = os_ if os_ is not None else os_adapters(clock=clock)
    adapters.paths.reject_unsafe_path(str(destination))
    if not destination.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    dest = Path(os.path.abspath(destination))

    if not isinstance(authorization, BootstrapAuthorization):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if authorization.store_id != store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if (
        authorization.action != "provision_tls"
        or authorization.subject_id != store_id
        or not is_trusted_bootstrap_issuer(authorization.issuer_id)
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if authorization.destination is not None and Path(os.path.abspath(authorization.destination)) != dest:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    now = clock.now().astimezone(dt.UTC)
    if authorization.expires_at <= now:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    ca_cert_path = dest / "ca.pem"
    ca_key_path = dest / "ca.key"
    cert_path = dest / "server.pem"
    key_path = dest / "server.key"
    target_files = (ca_cert_path, ca_key_path, cert_path, key_path)

    adapters.paths.reject_links(dest, entries=[p for p in target_files if os.path.lexists(p)])
    if adapters.permissions.check_ancestors(dest):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    if os.path.lexists(dest):
        if not dest.is_dir():
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if adapters.permissions.object_problems(dest):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        if any(os.path.lexists(p) for p in target_files):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    else:
        try:
            dest.mkdir(mode=0o700)
        except FileExistsError as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        except OSError as err:
            raise map_os_error(err, "creating TLS directory") from err
        adapters.permissions.secure_directory(dest)
        adapters.publisher.sync_directory(dest.parent)

    ca_not_after = now + dt.timedelta(days=_CA_VALIDITY_DAYS)
    leaf_not_after = now + dt.timedelta(days=_LEAF_VALIDITY_DAYS)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "superbrain-store-ca"),
            x509.NameAttribute(NameOID.USER_ID, store_id),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(ca_not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
            x509.NameAttribute(NameOID.USER_ID, store_id),
        ]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(leaf_not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(_LOOPBACK_IPV4)]),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    for path, content in (
        (ca_cert_path, ca_pem),
        (ca_key_path, ca_key_pem),
        (cert_path, leaf_pem),
        (key_path, leaf_key_pem),
    ):
        try:
            adapters.publisher.write_new(path, content)
        except FileExistsError as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        adapters.permissions.secure_file(path)
    adapters.publisher.sync_directory(dest)

    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    leaf_sha256 = hashlib.sha256(leaf_der).hexdigest()
    return TlsMaterial(
        store_id=store_id,
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        cert_path=cert_path,
        key_path=key_path,
        leaf_cert_sha256=leaf_sha256,
        not_before=leaf_cert.not_valid_before_utc,
        not_after=leaf_cert.not_valid_after_utc,
    )


def verify_server_tls_files(
    config: DaemonConfig,
    clock: Clock,
    os_: OsAdapters,
) -> VerifiedServerTls:
    """Verify server cert/key permissions, matching public key, ``127.0.0.1`` IP SAN, ``store_id``, and validity."""
    cert_bytes = _read_owner_only_file(config.cert_path, os_)
    key_bytes = _read_owner_only_file(config.key_path, os_)

    try:
        leaf_cert = x509.load_pem_x509_certificate(cert_bytes)
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except (ValueError, TypeError) as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err

    cert_spki = leaf_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_spki != key_spki:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    try:
        bc = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err

    if bc.ca or ExtendedKeyUsageOID.SERVER_AUTH not in list(eku):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if _LOOPBACK_IPV4 not in san.get_values_for_type(x509.IPAddress):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    uid_attrs = leaf_cert.subject.get_attributes_for_oid(NameOID.USER_ID)
    if len(uid_attrs) != 1 or not isinstance(uid_attrs[0].value, str):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if uid_attrs[0].value != config.expected_store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

    now = clock.now().astimezone(dt.UTC)
    if not (leaf_cert.not_valid_before_utc <= now < leaf_cert.not_valid_after_utc):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    leaf_sha256 = hashlib.sha256(leaf_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return VerifiedServerTls(
        store_id=config.expected_store_id,
        cert_path=config.cert_path,
        key_path=config.key_path,
        leaf_cert_sha256=leaf_sha256,
        not_before=leaf_cert.not_valid_before_utc,
        not_after=leaf_cert.not_valid_after_utc,
    )
