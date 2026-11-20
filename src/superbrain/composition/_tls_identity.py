"""Pinned daemon TLS/endpoint identity checks for client profiles (re-review F1, spec D2/D3).

A harness profile is only trusted when its endpoint path, leaf-certificate pin and CA actually belong to the
daemon of *this* store, not merely when it parses.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from superbrain.core.client_profile import ClientProfile
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.layout import ENDPOINT_NAME

__all__ = ["ExpectedDaemonIdentity", "resolve_expected_identity", "verify_profile_tls_identity"]

_MAX_CERT_BYTES = 65_536
_INIT_BOOTSTRAP_STATE_KEY = "init_bootstrap_state"


def _mismatch() -> BrainError:
    return BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")


@dataclass(frozen=True)
class ExpectedDaemonIdentity:
    endpoint_path: Path
    leaf_cert_sha256: str
    server_cert_path: Path


def _fallback_from_policy(policy: object) -> tuple[Path | None, str | None, Path | None]:
    data_root = getattr(policy, "data_root", None)
    meta_value: Callable[[str], str | None] | None = getattr(policy, "meta_value", None)
    endpoint = Path(data_root) / ENDPOINT_NAME if isinstance(data_root, Path) else None
    sha: str | None = None
    cert: Path | None = None
    raw = meta_value(_INIT_BOOTSTRAP_STATE_KEY) if callable(meta_value) else None
    if isinstance(raw, str):
        try:
            state: Any = json.loads(raw)
        except ValueError:
            state = None
        if isinstance(state, dict):
            pin, cfg = state.get("tls_leaf_cert_sha256"), state.get("config_dir")
            if isinstance(pin, str) and pin:
                sha = pin
            if isinstance(cfg, str) and cfg and os.path.isabs(cfg):
                cert = Path(cfg) / "tls" / "server.pem"
    return endpoint, sha, cert


def resolve_expected_identity(
    policy: object,
    *,
    endpoint_path: Path | None,
    leaf_cert_sha256: str | None,
    server_cert_path: Path | None,
) -> ExpectedDaemonIdentity:
    """Explicit daemon identity wins; otherwise fall back to the store's own init record; else fail closed."""
    fb_endpoint, fb_sha, fb_cert = _fallback_from_policy(policy)
    endpoint = endpoint_path if endpoint_path is not None else fb_endpoint
    sha = leaf_cert_sha256 if leaf_cert_sha256 is not None else fb_sha
    cert = server_cert_path if server_cert_path is not None else fb_cert
    if endpoint is None or not sha or cert is None:
        raise _mismatch()
    return ExpectedDaemonIdentity(endpoint_path=endpoint, leaf_cert_sha256=sha, server_cert_path=cert)


def _same_endpoint(actual: Path, expected: Path) -> bool:
    if actual.name != expected.name:
        return False
    if os.path.normcase(os.path.realpath(actual.parent)) != os.path.normcase(os.path.realpath(expected.parent)):
        return False
    if os.path.lexists(actual) and os.path.lexists(expected):
        try:
            return os.path.samefile(actual, expected)
        except OSError:
            return False
    return True


def _load_server_cert(path: Path) -> x509.Certificate:
    try:
        if os.path.islink(path) or path.stat().st_size > _MAX_CERT_BYTES:
            raise _mismatch()
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as err:
        raise _mismatch() from err


def verify_profile_tls_identity(profile: ClientProfile, expected: ExpectedDaemonIdentity, ca_pem: str) -> None:
    """Raise ``IDENTITY_MISMATCH`` unless endpoint, pin and CA all match the expected daemon."""
    if not _same_endpoint(profile.endpoint_path, expected.endpoint_path):
        raise _mismatch()
    if not hmac.compare_digest(profile.leaf_cert_sha256.lower(), expected.leaf_cert_sha256.lower()):
        raise _mismatch()
    leaf = _load_server_cert(expected.server_cert_path)
    der = leaf.public_bytes(serialization.Encoding.DER)
    if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), expected.leaf_cert_sha256.lower()):
        raise _mismatch()
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
        leaf.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature) as err:
        raise _mismatch() from err
