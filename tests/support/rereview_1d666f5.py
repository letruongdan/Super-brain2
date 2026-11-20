"""Shared oracle helpers for the SP1-I3 ``1d666f5`` re-review (F1 TLS identity, F2 rule scope).

Requirement sources: Plan I3 line 215 (§7.4 / §14.2), spec rev 22 D3,
``docs/reviews/2026-11-20-sp1-increment3-rereview-1d666f5.md``.
"""

from __future__ import annotations

import base64
import hashlib
import ssl
import struct
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition.init_entry import InitRequest, init_store
from superbrain.core._kernel_approval import ApprovalChannel, SignerEnrollment
from superbrain.core.kernel import WorkspaceBinding
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters
from tests.support.kernel_auth import make_bootstrap_auth


def ssh_enrollment(tag: str, owner_id: str = "dan") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    key = f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} {tag}@devbox"
    return SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=key)


def ws_dict(ws: WorkspaceBinding, checkout: Path | None = None) -> dict[str, str]:
    co = checkout if checkout is not None else ws.checkout_path
    return {
        "alias": ws.alias, "checkout_path": str(co),
        "expected_workspace_id": ws.repo_id, "expected_checkout_id": ws.checkout_id,
    }


def prop_id(out: Mapping[str, Any]) -> str:
    assert isinstance((prop_obj := out["proposal"]), Mapping)
    return str(prop_obj["proposal_id"])

def leaf_sha(server_pem: Path) -> str:
    """The TLS pin: SHA-256 of the DER leaf certificate."""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(server_pem.read_text("utf-8"))).hexdigest()


def flip_last_hex_char(digest: str) -> str:
    return digest[:-1] + ("0" if digest[-1] != "0" else "1")


def daemon_identity(data_root: Path, cfg_dir: Path) -> dict[str, Any]:
    """Explicit daemon TLS/endpoint identity kwargs of the init store (the ones a live daemon would pass)."""
    cert = cfg_dir / "tls" / "server.pem"
    return {
        "expected_endpoint_path": data_root / "endpoint.json",
        "expected_leaf_cert_sha256": leaf_sha(cert),
        "server_cert_path": cert,
    }


def foreign_ca_file(base: Path, os_: OsAdapters, *, owner_id: str, machine_id: str, signer: SignerEnrollment) -> Path:
    """A valid PEM CA of a *different* initialized store."""
    req = InitRequest(
        data_root=base / "foreign-data", config_dir=base / "foreign-cfg", owner_id=owner_id, machine_id=machine_id,
        signer=signer,
    )
    init_store(req, os_)
    return req.config_dir / "tls" / "ca.pem"


def rotated_tls(store_id: str, tls_dir: Path, owner_id: str, clock: Clock, os_: OsAdapters) -> tuple[Path, Path, str]:
    """A daemon-rotated per-store TLS bundle: ``(server_cert, ca_file, pin)``."""
    auth = make_bootstrap_auth(
        store_id=store_id, owner_id=owner_id, action="provision_tls", subject_id=store_id,
        expires_at=clock.now() + timedelta(hours=1), destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, auth, clock, os_)
    return tls.cert_path, tls_dir / "ca.pem", leaf_sha(tls.cert_path)


def assert_f2_rule_scope(rule_text: str) -> None:
    """F2: the takeover edit gate is scoped to open-handoff takeover; ``not_stored_policy`` has both branches."""
    low = " ".join(rule_text.lower().split())
    assert "never edit any checkout file" not in low
    gate = [s for s in low.split(". ") if "writer_status=holder" in s]
    assert gate, "missing stored+holder takeover ACK gate"
    for sentence in gate:
        assert "open handoff" in sentence and any(w in sentence for w in ("takeover", "taking over", "take over"))
    at = low.index("not_stored_policy")
    clause = low[at : at + 500]
    assert "taking over an open handoff" in clause, "branch (i) takeover not stated"
    assert "do not edit" in clause and ("notify" in clause or "ask" in clause), "branch (i) must block + notify/ask"
    assert any(p in clause for p in ("not taking over", "without taking over", "no open handoff", "ordinary")), (
        "branch (ii) ordinary work not stated"
    )
    assert "proceed" in clause or "continue" in clause, "branch (ii) must proceed normally"
    assert "policy" in clause and "manual_submission" in low


__all__ = [
    "assert_f2_rule_scope", "daemon_identity", "flip_last_hex_char", "foreign_ca_file", "leaf_sha", "prop_id",
    "rotated_tls", "ssh_enrollment", "ws_dict",
]
