"""Principal identity, direct ref authorization, bearer credentials, and per-store TLS tests (Task 2)."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from superbrain.adapters.os.tls_material import create_store_tls, verify_server_tls_files
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DaemonConfig,
    DirectRefRecord,
    ObjectRef,
    Scope,
    TrustedLocator,
    WorkspaceRegistration,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.identity import authorize_direct_ref, verify_caller_identity
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.runtime import open_runtime
from tests.support.clock import FakeClock
from tests.support.kernel_auth import (
    generate_bearer_token,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)


def _loosen_file(path: Path) -> None:
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(path, "S-1-1-0", 0x120089)
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)


def test_wrong_owner_and_cross_scope_ref_are_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    rt = open_runtime(
        trusted_tmp / "identity-root",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        expiry = clock.now() + dt.timedelta(hours=1)

        alice_box1 = seed_principal_and_credential(
            rt.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
        )
        alice_box2 = seed_principal_and_credential(
            rt.policy, owner_id="alice", harness_id="claude-code", machine_id="box-2"
        )
        bob_box1 = seed_principal_and_credential(
            rt.policy, owner_id="bob", harness_id="claude-code", machine_id="box-1"
        )

        # Register two checkouts on repo-a (same remote locator) for alice_box1, and a separate repo-b for alice_box1.
        loc_a = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/alice/repo-a.git",
            locator_digest=digest_bytes(b"https://example.invalid/alice/repo-a.git"),
        )
        reg_chk1 = WorkspaceRegistration(
            owner_id="alice",
            principal_id=alice_box1.principal.principal_id,
            machine_id="box-1",
            alias="repo-a-main",
            checkout_path=str(trusted_tmp / "alice-chk1"),
            path_identity="alice:box-1:chk1",
            locator=loc_a,
        )
        bind_chk1 = rt.policy.register_authorized_workspace(
            reg_chk1,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="alice",
                action="workspace_register",
                subject_id=reg_chk1.subject_id,
                trust_generation=gen,
                expires_at=expiry,
            ),
        )

        reg_chk2 = WorkspaceRegistration(
            owner_id="alice",
            principal_id=alice_box1.principal.principal_id,
            machine_id="box-1",
            alias="repo-a-wt2",
            checkout_path=str(trusted_tmp / "alice-chk2"),
            path_identity="alice:box-1:chk2",
            locator=loc_a,
        )
        bind_chk2 = rt.policy.register_authorized_workspace(
            reg_chk2,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="alice",
                action="workspace_register",
                subject_id=reg_chk2.subject_id,
                trust_generation=gen,
                expires_at=expiry,
            ),
        )
        assert bind_chk1.repo_id == bind_chk2.repo_id
        assert bind_chk1.checkout_id != bind_chk2.checkout_id

        # Repo-b granted to alice_box1 only; bob_box1 has his own repo.
        repo_b_id = new_id()
        seed_repo_grant(rt.policy, principal_id=alice_box1.principal.principal_id, repo_id=repo_b_id, owner_id="alice")
        bob_repo_id = new_id()
        seed_repo_grant(rt.policy, principal_id=bob_box1.principal.principal_id, repo_id=bob_repo_id, owner_id="bob")

        # 1. Payload caller identity normalization vs mismatch.
        normalized = verify_caller_identity(
            alice_box1.principal,
            {
                "owner_id": "alice",
                "principal_id": alice_box1.principal.principal_id,
                "harness_id": "claude-code",
                "machine_id": "box-1",
                "query": "safe-query",
            },
        )
        assert normalized == {"query": "safe-query"}

        for bad_field, bad_val in (
            ("owner_id", "bob"),
            ("principal_id", bob_box1.principal.principal_id),
            ("harness_id", "other-harness"),
            ("machine_id", "box-2"),
        ):
            with pytest.raises(BrainError) as exc_id:
                verify_caller_identity(alice_box1.principal, {bad_field: bad_val, "query": "x"})
            assert exc_id.value.code is ErrorCode.IDENTITY_MISMATCH

        # 2. Direct refs across artifact, workspace job, owner-global job, and context.
        scope_chk1 = Scope(repo_id=bind_chk1.repo_id, checkout_id=bind_chk1.checkout_id)
        scope_chk2 = Scope(repo_id=bind_chk2.repo_id, checkout_id=bind_chk2.checkout_id)

        artifact_ref = ObjectRef(kind="artifact", id=new_id(), revision=2, digest=digest_bytes(b"art-v2"))
        artifact_rec = DirectRefRecord(
            kind="artifact",
            id=artifact_ref.id,
            revision=2,
            digest=artifact_ref.digest,
            owner_id="alice",
            repo_id=bind_chk1.repo_id,
            checkout_id=bind_chk1.checkout_id,
        )
        context_ref = ObjectRef(kind="context", id=new_id(), revision=1, digest=digest_bytes(b"ctx-v1"))
        context_rec = DirectRefRecord(
            kind="context",
            id=context_ref.id,
            revision=1,
            digest=context_ref.digest,
            owner_id="alice",
            repo_id=bind_chk1.repo_id,
            checkout_id=bind_chk1.checkout_id,
        )
        ws_job_ref = ObjectRef(kind="job", id=new_id(), revision=1, digest=digest_bytes(b"ws-job"))
        ws_job_rec = DirectRefRecord(
            kind="job",
            id=ws_job_ref.id,
            revision=1,
            digest=ws_job_ref.digest,
            owner_id="alice",
            repo_id=bind_chk1.repo_id,
            checkout_id=bind_chk1.checkout_id,
        )
        global_job_ref = ObjectRef(kind="job", id=new_id(), revision=1, digest=digest_bytes(b"global-job"))
        global_job_rec = DirectRefRecord(
            kind="job",
            id=global_job_ref.id,
            revision=1,
            digest=global_job_ref.digest,
            owner_id="alice",
            repo_id=None,
            checkout_id=None,
        )

        # Authorized lookups succeed.
        assert (
            authorize_direct_ref(alice_box1.principal, scope_chk1, artifact_ref, artifact_rec, rt.policy)
            == artifact_rec
        )
        assert (
            authorize_direct_ref(alice_box1.principal, scope_chk1, context_ref, context_rec, rt.policy)
            == context_rec
        )
        assert authorize_direct_ref(alice_box1.principal, scope_chk1, ws_job_ref, ws_job_rec, rt.policy) == ws_job_rec
        assert (
            authorize_direct_ref(alice_box1.principal, None, global_job_ref, global_job_rec, rt.policy)
            == global_job_rec
        )

        # Wrong claimed owner -> IDENTITY_MISMATCH.
        with pytest.raises(BrainError) as exc_claim:
            authorize_direct_ref(
                alice_box1.principal,
                scope_chk1,
                artifact_ref,
                artifact_rec,
                rt.policy,
                claimed_owner_id="bob",
            )
        assert exc_claim.value.code is ErrorCode.IDENTITY_MISMATCH

        # Cross-owner lookup (Bob querying Alice's artifact / context / workspace job / global job) -> NOT_FOUND.
        bob_scope = Scope(repo_id=bob_repo_id, checkout_id=None)
        for ref, rec, sc in (
            (artifact_ref, artifact_rec, bob_scope),
            (context_ref, context_rec, bob_scope),
            (ws_job_ref, ws_job_rec, bob_scope),
            (global_job_ref, global_job_rec, None),
        ):
            with pytest.raises(BrainError) as exc_xowner:
                authorize_direct_ref(bob_box1.principal, sc, ref, rec, rt.policy)
            assert exc_xowner.value.code is ErrorCode.NOT_FOUND

        # Cross-repo, cross-checkout, missing scope on workspace ref, missing grant, wrong machine -> NOT_FOUND.
        repo_b_scope = Scope(repo_id=repo_b_id, checkout_id=None)
        for caller, sel_scope in (
            (alice_box1.principal, repo_b_scope),  # wrong repo
            (alice_box1.principal, scope_chk2),  # wrong checkout in same repo
            (alice_box1.principal, None),  # workspace ref without selected_scope
            (alice_box2.principal, scope_chk1),  # missing repo_grant & wrong machine_id
        ):
            for ref, rec in ((artifact_ref, artifact_rec), (context_ref, context_rec), (ws_job_ref, ws_job_rec)):
                with pytest.raises(BrainError) as exc_scope:
                    authorize_direct_ref(caller, sel_scope, ref, rec, rt.policy)
                assert exc_scope.value.code is ErrorCode.NOT_FOUND

        # Even if alice_box2 gets a repo_grant on repo_a, checkout chk1 is bound to machine box-1 -> NOT_FOUND!
        seed_repo_grant(
            rt.policy, principal_id=alice_box2.principal.principal_id, repo_id=bind_chk1.repo_id, owner_id="alice"
        )
        with pytest.raises(BrainError) as exc_machine:
            authorize_direct_ref(alice_box2.principal, scope_chk1, artifact_ref, artifact_rec, rt.policy)
        assert exc_machine.value.code is ErrorCode.NOT_FOUND

        # Wrong kind, wrong revision, wrong digest, or missing record -> NOT_FOUND.
        wrong_kind_ref = ObjectRef(kind="context", id=artifact_ref.id, revision=2, digest=artifact_ref.digest)
        wrong_rev_ref = ObjectRef(kind="artifact", id=artifact_ref.id, revision=1, digest=artifact_ref.digest)
        wrong_dig_ref = ObjectRef(kind="artifact", id=artifact_ref.id, revision=2, digest=digest_bytes(b"tampered"))
        bad_ref_cases: list[tuple[ObjectRef, DirectRefRecord | None]] = [
            (wrong_kind_ref, artifact_rec),
            (wrong_rev_ref, artifact_rec),
            (wrong_dig_ref, artifact_rec),
            (artifact_ref, None),
        ]
        for bad_ref, maybe_rec in bad_ref_cases:
            with pytest.raises(BrainError) as exc_bad_ref:
                authorize_direct_ref(alice_box1.principal, scope_chk1, bad_ref, maybe_rec, rt.policy)
            assert exc_bad_ref.value.code is ErrorCode.NOT_FOUND
    finally:
        rt.close()

    # Closed policy -> POLICY_UNAVAILABLE on authorize_direct_ref (never falls back to default allow or NOT_FOUND).
    with pytest.raises(BrainError) as exc_unavail:
        authorize_direct_ref(alice_box1.principal, scope_chk1, artifact_ref, artifact_rec, rt.policy)
    assert exc_unavail.value.code is ErrorCode.POLICY_UNAVAILABLE


def test_bearer_credential_resolution_snapshot_and_digest_key(
    trusted_tmp: Path, os_: OsAdapters
) -> None:
    rt1 = open_runtime(
        trusted_tmp / "store-one",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    rt2 = open_runtime(
        trusted_tmp / "store-two",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        # Empty production store has zero active credentials and refuses any bearer token.
        empty_snap = rt1.policy.snapshot()
        assert len(empty_snap.credentials) == 0
        _, random_tok, _, _ = generate_bearer_token()
        with pytest.raises(BrainError) as exc_empty:
            rt1.policy.resolve_credential(random_tok)
        assert exc_empty.value.code is ErrorCode.UNAUTHENTICATED

        # Seeded credential resolves via both live PolicyStore and immutable AuthSnapshot.
        seeded = seed_principal_and_credential(
            rt1.policy, owner_id="dan", harness_id="antigravity", machine_id="win-box"
        )
        assert rt1.policy.resolve_credential(seeded.token) == seeded.principal
        snap = rt1.policy.snapshot()
        assert snap.resolve_credential(seeded.token) == seeded.principal

        # Raw secret never appears in policy.db or WAL bytes on disk!
        rt1.policy._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        raw_policy_bytes = rt1.root.policy_db.read_bytes()
        assert seeded.raw_secret_b64.encode("ascii") not in raw_policy_bytes
        assert seeded.secret_digest.encode("ascii") in raw_policy_bytes

        # Malformed / wrong-secret / padded / UUIDv4 / uppercase tokens -> UNAUTHENTICATED.
        _, _, _, other_b64 = generate_bearer_token()
        v4_id = str(uuid.uuid4())
        malformed_tokens = [
            "",
            "not-a-token",
            f"Bearer {seeded.token}",
            f"{seeded.credential_id}.{seeded.raw_secret_b64}=",  # '=' padding forbidden
            f"{seeded.credential_id}.short",
            f"{seeded.credential_id.upper()}.{seeded.raw_secret_b64}",
            f"{v4_id}.{seeded.raw_secret_b64}",  # UUIDv4 instead of UUIDv7
            f"{seeded.credential_id}.{other_b64}",  # wrong secret
            f"{new_id()}.{seeded.raw_secret_b64}",  # unknown credential_id
        ]
        for bad_tok in malformed_tokens:
            with pytest.raises(BrainError) as exc_bad:
                rt1.policy.resolve_credential(bad_tok)
            assert exc_bad.value.code is ErrorCode.UNAUTHENTICATED

        # Unique 32-byte request_digest_key per store.
        k1_id, k1_bytes = rt1.policy.request_digest_key()
        k2_id, k2_bytes = rt2.policy.request_digest_key()
        assert len(k1_bytes) == 32 and len(k2_bytes) == 32
        assert k1_id != k2_id
        assert k1_bytes != k2_bytes
    finally:
        rt1.close()
        rt2.close()

    # Closed PolicyStore raises POLICY_UNAVAILABLE on KernelPolicyPort methods, while keeping AssertionError on I1 APIs.
    for fn in (
        lambda: rt1.policy.resolve_credential(seeded.token),
        lambda: rt1.policy.allows(seeded.principal, None, action="get_health"),
        rt1.policy.snapshot,
        rt1.policy.request_digest_key,
    ):
        with pytest.raises(BrainError) as exc_closed:
            fn()
        assert exc_closed.value.code is ErrorCode.POLICY_UNAVAILABLE
    with pytest.raises(AssertionError, match="policy store closed"):
        _ = rt1.policy.store_id


def test_tls_material_is_per_store_and_owner_only(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    expiry = clock.now() + dt.timedelta(hours=1)
    dest_a = trusted_tmp / "tls-store-a"
    dest_b = trusted_tmp / "tls-store-b"

    mat_a = create_store_tls(
        "store-alpha",
        dest_a,
        make_bootstrap_auth(
            store_id="store-alpha",
            action="provision_tls",
            subject_id="store-alpha",
            expires_at=expiry,
            destination=dest_a,
        ),
        clock,
        os_,
    )
    mat_b = create_store_tls(
        "store-beta",
        dest_b,
        make_bootstrap_auth(
            store_id="store-beta",
            action="provision_tls",
            subject_id="store-beta",
            expires_at=expiry,
            destination=dest_b,
        ),
        clock,
        os_,
    )

    assert mat_a.store_id == "store-alpha" and mat_b.store_id == "store-beta"
    assert mat_a.leaf_cert_sha256 != mat_b.leaf_cert_sha256
    assert mat_a.ca_cert_path.read_bytes() != mat_b.ca_cert_path.read_bytes()
    assert mat_a.ca_key_path != mat_a.ca_cert_path
    assert b"PRIVATE KEY" not in mat_a.ca_cert_path.read_bytes()
    assert b"PRIVATE KEY" not in repr(mat_a).encode("utf-8")

    # Every directory and file created in both TLS directories is strictly owner-only.
    assert os_.permissions.problems(dest_a) == []
    assert os_.permissions.problems(dest_b) == []


def test_cert_expiry_and_ip_san(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    store_id = "store-" + ("x" * 90)  # >64 chars to exercise full 128-char opaque_id X.509 binding!
    dest = trusted_tmp / "tls-san"
    mat = create_store_tls(
        store_id,
        dest,
        make_bootstrap_auth(
            store_id=store_id,
            action="provision_tls",
            subject_id=store_id,
            expires_at=clock.now() + dt.timedelta(minutes=30),
            destination=dest,
        ),
        clock,
        os_,
    )

    ca_cert = x509.load_pem_x509_certificate(mat.ca_cert_path.read_bytes())
    leaf_cert = x509.load_pem_x509_certificate(mat.cert_path.read_bytes())

    ca_bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert ca_bc.ca is True and ca_bc.path_length == 0
    assert ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc == dt.timedelta(days=3650)

    leaf_bc = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert leaf_bc.ca is False
    eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in list(eku)
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.IPv4Address("127.0.0.1")]
    assert leaf_cert.not_valid_after_utc - leaf_cert.not_valid_before_utc == dt.timedelta(days=365)
    assert hashlib.sha256(leaf_cert.public_bytes(serialization.Encoding.DER)).hexdigest() == mat.leaf_cert_sha256

    cfg = DaemonConfig(
        version=1,
        data_root=trusted_tmp / "data",
        expected_store_id=store_id,
        cert_path=mat.cert_path,
        key_path=mat.key_path,
    )
    verified = verify_server_tls_files(cfg, clock, os_)
    assert verified.leaf_cert_sha256 == mat.leaf_cert_sha256
    assert verified.store_id == store_id

    # Wrong expected_store_id refused with IDENTITY_MISMATCH.
    wrong_cfg = DaemonConfig(
        version=1,
        data_root=cfg.data_root,
        expected_store_id="different-store",
        cert_path=mat.cert_path,
        key_path=mat.key_path,
    )
    with pytest.raises(BrainError) as exc_store:
        verify_server_tls_files(wrong_cfg, clock, os_)
    assert exc_store.value.code is ErrorCode.IDENTITY_MISMATCH

    # Expired cert refused when clock advances past 365 days.
    expired_clock = FakeClock(clock.now() + dt.timedelta(days=366))
    with pytest.raises(BrainError) as exc_exp:
        verify_server_tls_files(cfg, expired_clock, os_)
    assert exc_exp.value.code is ErrorCode.INVALID_INPUT

    # Loose private key permissions refused with INSECURE_PERMISSIONS.
    _loosen_file(mat.key_path)
    with pytest.raises(BrainError) as exc_perm:
        verify_server_tls_files(cfg, clock, os_)
    assert exc_perm.value.code is ErrorCode.INSECURE_PERMISSIONS

    # Missing private key refused with NOT_FOUND.
    mat.key_path.unlink()
    with pytest.raises(BrainError) as exc_missing:
        verify_server_tls_files(cfg, clock, os_)
    assert exc_missing.value.code is ErrorCode.NOT_FOUND


def test_unauthorized_or_existing_key_is_not_overwritten(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    dest = trusted_tmp / "tls-guard"
    now = clock.now()

    # Unauthorized proofs (wrong action, wrong store_id, untrusted issuer, expired, wrong destination) create nothing.
    bad_auths = [
        make_bootstrap_auth(
            store_id="store-1",
            action="credential_revoke",
            subject_id="store-1",
            expires_at=now + dt.timedelta(hours=1),
            destination=dest,
        ),
        make_bootstrap_auth(
            store_id="other-store",
            action="provision_tls",
            subject_id="store-1",
            expires_at=now + dt.timedelta(hours=1),
            destination=dest,
        ),
        make_bootstrap_auth(
            store_id="store-1",
            action="provision_tls",
            subject_id="store-1",
            expires_at=now + dt.timedelta(hours=1),
            issuer_id="principal:mcp-agent",
            destination=dest,
        ),
        make_bootstrap_auth(
            store_id="store-1",
            action="provision_tls",
            subject_id="store-1",
            expires_at=now - dt.timedelta(seconds=1),
            destination=dest,
        ),
        make_bootstrap_auth(
            store_id="store-1",
            action="provision_tls",
            subject_id="store-1",
            expires_at=now + dt.timedelta(hours=1),
            destination=trusted_tmp / "wrong-dest",
        ),
    ]
    for auth in bad_auths:
        with pytest.raises(BrainError):
            create_store_tls("store-1", dest, auth, clock, os_)
        assert not dest.exists()

    # First valid provisioning succeeds; a second attempt refuses without overwriting any existing key/cert bytes!
    valid_auth = make_bootstrap_auth(
        store_id="store-1",
        action="provision_tls",
        subject_id="store-1",
        expires_at=now + dt.timedelta(hours=1),
        destination=dest,
    )
    mat = create_store_tls("store-1", dest, valid_auth, clock, os_)
    original_key = mat.key_path.read_bytes()
    original_ca_key = mat.ca_key_path.read_bytes()
    original_cert = mat.cert_path.read_bytes()

    with pytest.raises(BrainError) as exc_exists:
        create_store_tls(
            "store-1",
            dest,
            make_bootstrap_auth(
                store_id="store-1",
                action="provision_tls",
                subject_id="store-1",
                expires_at=now + dt.timedelta(hours=1),
                destination=dest,
            ),
            clock,
            os_,
        )
    assert exc_exists.value.code is ErrorCode.INVALID_INPUT
    assert mat.key_path.read_bytes() == original_key
    assert mat.ca_key_path.read_bytes() == original_ca_key
    assert mat.cert_path.read_bytes() == original_cert


def test_corrupt_policy_db_raises_policy_unavailable_across_kernel_port(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    rt = open_runtime(
        trusted_tmp / "corrupt-policy",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        expiry = clock.now() + dt.timedelta(hours=1)
        seeded = seed_principal_and_credential(
            rt.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
        )

        # 1. Corrupt credential.secret_digest (non-ASCII, non-sha256 format, non-text) -> POLICY_UNAVAILABLE
        # across resolve_credential, allows, and snapshot (never UnicodeEncodeError or UNAUTHENTICATED).
        for bad_digest in ("sha256:\U0001f4a5corrupt", "not-a-sha256-digest", 12345):
            with rt.policy._immediate() as db:
                db.execute(
                    "UPDATE credential SET secret_digest = ? WHERE id = ?",
                    (bad_digest, seeded.credential_id),
                )
            for call in (
                lambda: rt.policy.resolve_credential(seeded.token),
                lambda: rt.policy.allows(seeded.principal, None, action="get_health"),
                rt.policy.snapshot,
            ):
                with pytest.raises(BrainError) as exc_digest:
                    call()
                assert exc_digest.value.code is ErrorCode.POLICY_UNAVAILABLE

        # Restore valid secret_digest, then corrupt principal.owner_id -> POLICY_UNAVAILABLE (never INVALID_INPUT).
        with rt.policy._immediate() as db:
            db.execute(
                "UPDATE credential SET secret_digest = ? WHERE id = ?",
                (seeded.secret_digest, seeded.credential_id),
            )
            db.execute(
                "UPDATE principal SET owner_id = ? WHERE id = ?",
                ("bad owner with spaces", seeded.principal.principal_id),
            )
        for call in (
            lambda: rt.policy.resolve_credential(seeded.token),
            rt.policy.snapshot,
        ):
            with pytest.raises(BrainError) as exc_principal:
                call()
            assert exc_principal.value.code is ErrorCode.POLICY_UNAVAILABLE

        # Restore principal.owner_id, then corrupt stored intents row for an incoming intent_id -> POLICY_UNAVAILABLE
        # on record_authorized_revocation and register_authorized_workspace (never INTEGRITY_FAILURE).
        bad_intent_id = new_id()
        with rt.policy._immediate() as db:
            db.execute(
                "UPDATE principal SET owner_id = ? WHERE id = ?",
                ("alice", seeded.principal.principal_id),
            )
            db.execute(
                "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (bad_intent_id, "credential_revoke", b"{corrupt-json", "2026-11-05T00:00:00Z"),
            )
        reg = WorkspaceRegistration(
            owner_id="alice",
            principal_id=seeded.principal.principal_id,
            machine_id="box-1",
            alias="repo-corrupt",
            checkout_path=str(trusted_tmp / "repo-corrupt"),
            path_identity="alice:box-1:corrupt",
        )
        with pytest.raises(BrainError) as exc_corrupt_rev:
            rt.policy.record_authorized_revocation(
                seeded.credential_id,
                make_bootstrap_auth(
                    intent_id=bad_intent_id,
                    store_id=store_id,
                    owner_id="alice",
                    action="credential_revoke",
                    subject_id=seeded.credential_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            )
        assert exc_corrupt_rev.value.code is ErrorCode.POLICY_UNAVAILABLE

        with pytest.raises(BrainError) as exc_corrupt_ws:
            rt.policy.register_authorized_workspace(
                reg,
                make_bootstrap_auth(
                    intent_id=bad_intent_id,
                    store_id=store_id,
                    owner_id="alice",
                    action="workspace_register",
                    subject_id=reg.subject_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            )
        assert exc_corrupt_ws.value.code is ErrorCode.POLICY_UNAVAILABLE

        # 2. Missing/corrupt trust row -> POLICY_UNAVAILABLE on snapshot, revocation, and workspace registration.
        with rt.policy._immediate() as db:
            db.execute("DELETE FROM intents WHERE intent_id = ?", (bad_intent_id,))
            db.execute("DELETE FROM trust")
        for mut_call in (
            rt.policy.snapshot,
            lambda: rt.policy.record_authorized_revocation(
                seeded.credential_id,
                make_bootstrap_auth(
                    store_id=store_id,
                    owner_id="alice",
                    action="credential_revoke",
                    subject_id=seeded.credential_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            ),
            lambda: rt.policy.register_authorized_workspace(
                reg,
                make_bootstrap_auth(
                    store_id=store_id,
                    owner_id="alice",
                    action="workspace_register",
                    subject_id=reg.subject_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            ),
        ):
            with pytest.raises(BrainError) as exc_trust:
                mut_call()
            assert exc_trust.value.code is ErrorCode.POLICY_UNAVAILABLE

        # 3. SQLite error during pre-transaction reads (e.g. dropped intents table while v2 tables remain) ->
        # POLICY_UNAVAILABLE rather than raw sqlite3.OperationalError!
        with rt.policy._immediate() as db:
            db.execute("INSERT INTO trust (id, generation) VALUES (1, ?)", (gen,))
            db.execute("DROP TABLE intents")
        for mut_call in (
            rt.policy.snapshot,
            lambda: rt.policy.record_authorized_revocation(
                seeded.credential_id,
                make_bootstrap_auth(
                    store_id=store_id,
                    owner_id="alice",
                    action="credential_revoke",
                    subject_id=seeded.credential_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            ),
            lambda: rt.policy.register_authorized_workspace(
                reg,
                make_bootstrap_auth(
                    store_id=store_id,
                    owner_id="alice",
                    action="workspace_register",
                    subject_id=reg.subject_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            ),
        ):
            with pytest.raises(BrainError) as exc_sql:
                mut_call()
            assert exc_sql.value.code is ErrorCode.POLICY_UNAVAILABLE
    finally:
        rt.close()


def test_missing_or_corrupt_trust_authority_fails_closed_across_all_kernel_policy_methods(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    from collections.abc import Callable

    def verify_corrupt_case(case_name: str, sql_stmt: str) -> None:
        rt = open_runtime(
            trusted_tmp / f"trust-authority-{case_name}",
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            store_id = rt.policy.store_id
            gen = rt.policy.trust_generation()
            expiry = clock.now() + dt.timedelta(hours=1)
            seeded = seed_principal_and_credential(
                rt.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
            )
            reg_initial = WorkspaceRegistration(
                owner_id="alice",
                principal_id=seeded.principal.principal_id,
                machine_id="box-1",
                alias="repo-healthy",
                checkout_path=str(trusted_tmp / f"{case_name}-chk1"),
                path_identity=f"alice:box-1:{case_name}:chk1",
                locator=TrustedLocator(
                    scheme="https",
                    canonical_locator=f"https://example.invalid/alice/{case_name}.git",
                    locator_digest=digest_bytes(f"https://example.invalid/alice/{case_name}.git".encode()),
                ),
            )
            binding = rt.policy.register_authorized_workspace(
                reg_initial,
                make_bootstrap_auth(
                    store_id=store_id,
                    owner_id="alice",
                    action="workspace_register",
                    subject_id=reg_initial.subject_id,
                    trust_generation=gen,
                    expires_at=expiry,
                ),
            )
            ws_scope = Scope(repo_id=binding.repo_id, checkout_id=binding.checkout_id)

            # Baseline pre-corruption checks: all read methods + snapshot succeed.
            assert rt.policy.resolve_credential(seeded.token) == seeded.principal
            assert rt.policy.allows(seeded.principal, None, action="get_health") is True
            assert rt.policy.allows(seeded.principal, ws_scope, action="get_artifact") is True
            key_id, key_bytes = rt.policy.request_digest_key()
            assert key_id and len(key_bytes) == 32
            assert rt.policy.snapshot().trust_generation == gen

            # Corrupt authority state in policy.db.
            rt.policy._db.execute("PRAGMA ignore_check_constraints = ON")
            try:
                with rt.policy._immediate() as db:
                    db.execute(sql_stmt)
            finally:
                rt.policy._db.execute("PRAGMA ignore_check_constraints = OFF")

            reg_after = WorkspaceRegistration(
                owner_id="alice",
                principal_id=seeded.principal.principal_id,
                machine_id="box-1",
                alias="repo-after-corrupt",
                checkout_path=str(trusted_tmp / f"{case_name}-chk2"),
                path_identity=f"alice:box-1:{case_name}:chk2",
            )
            port_calls: tuple[tuple[str, Callable[[], object]], ...] = (
                ("resolve_credential", lambda: rt.policy.resolve_credential(seeded.token)),
                ("allows_global", lambda: rt.policy.allows(seeded.principal, None, action="get_health")),
                ("allows_scoped", lambda: rt.policy.allows(seeded.principal, ws_scope, action="get_artifact")),
                ("request_digest_key", rt.policy.request_digest_key),
                ("snapshot", rt.policy.snapshot),
                (
                    "record_authorized_revocation",
                    lambda: rt.policy.record_authorized_revocation(
                        seeded.credential_id,
                        make_bootstrap_auth(
                            store_id=store_id,
                            owner_id="alice",
                            action="credential_revoke",
                            subject_id=seeded.credential_id,
                            trust_generation=gen,
                            expires_at=expiry,
                        ),
                    ),
                ),
                (
                    "register_authorized_workspace",
                    lambda: rt.policy.register_authorized_workspace(
                        reg_after,
                        make_bootstrap_auth(
                            store_id=store_id,
                            owner_id="alice",
                            action="workspace_register",
                            subject_id=reg_after.subject_id,
                            trust_generation=gen,
                            expires_at=expiry,
                        ),
                    ),
                ),
            )
            for method_label, fn in port_calls:
                with pytest.raises(BrainError, match=".") as exc_info:
                    fn()
                assert exc_info.value.code is ErrorCode.POLICY_UNAVAILABLE, (
                    f"{case_name}: expected POLICY_UNAVAILABLE from {method_label}, got {exc_info.value.code}"
                )
        finally:
            rt.close()

    def verify_first_read_after_trust_loss(first_read_name: str) -> None:
        rt_first = open_runtime(
            trusted_tmp / f"trust-first-read-{first_read_name}",
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            f_store_id = rt_first.policy.store_id
            f_gen = rt_first.policy.trust_generation()
            f_exp = clock.now() + dt.timedelta(hours=1)
            f_seeded = seed_principal_and_credential(
                rt_first.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
            )
            f_reg = WorkspaceRegistration(
                owner_id="alice",
                principal_id=f_seeded.principal.principal_id,
                machine_id="box-1",
                alias="repo-first",
                checkout_path=str(trusted_tmp / f"first-{first_read_name}-chk"),
                path_identity=f"alice:box-1:first:{first_read_name}",
            )
            f_bind = rt_first.policy.register_authorized_workspace(
                f_reg,
                make_bootstrap_auth(
                    store_id=f_store_id,
                    owner_id="alice",
                    action="workspace_register",
                    subject_id=f_reg.subject_id,
                    trust_generation=f_gen,
                    expires_at=f_exp,
                ),
            )
            f_scope = Scope(repo_id=f_bind.repo_id, checkout_id=f_bind.checkout_id)

            with rt_first.policy._immediate() as db:
                db.execute("DELETE FROM trust")

            first_calls: dict[str, Callable[[], object]] = {
                "resolve_credential": lambda: rt_first.policy.resolve_credential(f_seeded.token),
                "allows_global": lambda: rt_first.policy.allows(f_seeded.principal, None, action="get_health"),
                "allows_scoped": lambda: rt_first.policy.allows(f_seeded.principal, f_scope, action="get_artifact"),
                "request_digest_key": rt_first.policy.request_digest_key,
            }
            with pytest.raises(BrainError) as exc_first:
                first_calls[first_read_name]()
            assert exc_first.value.code is ErrorCode.POLICY_UNAVAILABLE
        finally:
            rt_first.close()

    for case_name, sql_stmt in (
        ("missing-trust-row", "DELETE FROM trust"),
        ("zero-trust-generation", "UPDATE trust SET generation = 0 WHERE id = 1"),
        ("non-int-trust-generation", "UPDATE trust SET generation = 'corrupt' WHERE id = 1"),
        ("dropped-trust-table", "DROP TABLE trust"),
        ("dropped-intents-table", "DROP TABLE intents"),
    ):
        verify_corrupt_case(case_name, sql_stmt)

    # Also verify each read-side method fails closed as the very first call after DELETE FROM trust
    # (preventing any cross-method error latch from masking a missing per-method authority check).
    for first_read_name in ("resolve_credential", "allows_global", "allows_scoped", "request_digest_key"):
        verify_first_read_after_trust_loss(first_read_name)


def test_overlong_and_unsupported_policy_version_metadata_fails_closed_without_writes(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    import sqlite3
    from collections.abc import Callable, Mapping

    from superbrain.ports.policy import IntentKind
    from superbrain.storage.runtime import admit_existing_pair
    from superbrain.storage.schema import Migration, read_schema_info

    authority_tables: tuple[str, ...] = (
        "intents",
        "credential",
        "repo_policy",
        "repo_grant",
        "workspace_repo_locator",
        "workspace_checkout",
    )

    def _snapshot_authority_rows(db: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in authority_tables}

    def verify_live_meta_case(case_name: str, meta_updates: Mapping[str, str]) -> None:
        rt = open_runtime(
            trusted_tmp / f"policy-meta-{case_name}",
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            store_id = rt.policy.store_id
            gen = rt.policy.trust_generation()
            expiry = clock.now() + dt.timedelta(hours=1)
            seeded = seed_principal_and_credential(
                rt.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
            )
            reg_init = WorkspaceRegistration(
                owner_id="alice",
                principal_id=seeded.principal.principal_id,
                machine_id="box-1",
                alias="repo-init",
                checkout_path=str(trusted_tmp / f"{case_name}-chk-init"),
                path_identity=f"alice:box-1:{case_name}:init",
                locator=TrustedLocator(
                    scheme="https",
                    canonical_locator=f"https://example.invalid/alice/{case_name}.git",
                    locator_digest=digest_bytes(f"https://example.invalid/alice/{case_name}.git".encode()),
                ),
            )
            i_init = new_id()
            auth_init = make_bootstrap_auth(
                intent_id=i_init,
                store_id=store_id,
                owner_id="alice",
                action="workspace_register",
                subject_id=reg_init.subject_id,
                trust_generation=gen,
                expires_at=expiry,
            )
            binding = rt.policy.register_authorized_workspace(reg_init, auth_init)
            ws_scope = Scope(repo_id=binding.repo_id, checkout_id=binding.checkout_id)

            with rt.policy._immediate() as db:
                for m_key, m_val in meta_updates.items():
                    db.execute("UPDATE meta SET value = ? WHERE key = ?", (m_val, m_key))

            rows_before = _snapshot_authority_rows(rt.policy._db)

            reg_fresh = WorkspaceRegistration(
                owner_id="alice",
                principal_id=seeded.principal.principal_id,
                machine_id="box-1",
                alias="repo-fresh",
                checkout_path=str(trusted_tmp / f"{case_name}-chk-fresh"),
                path_identity=f"alice:box-1:{case_name}:fresh",
            )
            port_calls: tuple[tuple[str, Callable[[], object]], ...] = (
                ("resolve_credential", lambda: rt.policy.resolve_credential(seeded.token)),
                ("allows_global", lambda: rt.policy.allows(seeded.principal, None, action="get_health")),
                ("allows_scoped", lambda: rt.policy.allows(seeded.principal, ws_scope, action="get_artifact")),
                ("request_digest_key", rt.policy.request_digest_key),
                ("snapshot", rt.policy.snapshot),
                (
                    "register_authorized_workspace_fresh",
                    lambda: rt.policy.register_authorized_workspace(
                        reg_fresh,
                        make_bootstrap_auth(
                            store_id=store_id,
                            owner_id="alice",
                            action="workspace_register",
                            subject_id=reg_fresh.subject_id,
                            trust_generation=gen,
                            expires_at=expiry,
                        ),
                    ),
                ),
                (
                    "register_authorized_workspace_replay",
                    lambda: rt.policy.register_authorized_workspace(reg_init, auth_init),
                ),
                (
                    "record_authorized_revocation",
                    lambda: rt.policy.record_authorized_revocation(
                        seeded.credential_id,
                        make_bootstrap_auth(
                            store_id=store_id,
                            owner_id="alice",
                            action="credential_revoke",
                            subject_id=seeded.credential_id,
                            trust_generation=gen,
                            expires_at=expiry,
                        ),
                    ),
                ),
            )
            for method_label, fn in port_calls:
                with pytest.raises(BrainError, match=".") as exc_info:
                    fn()
                assert exc_info.value.code is ErrorCode.POLICY_UNAVAILABLE, (
                    f"{case_name}: expected POLICY_UNAVAILABLE from {method_label}, got {exc_info.value.code}"
                )

            assert _snapshot_authority_rows(rt.policy._db) == rows_before
        finally:
            rt.close()

    for live_case_name, live_meta in (
        ("overlong-schema", {"schema_version": "9" * 5000}),
        ("overlong-reader", {"min_reader_version": "9" * 5000}),
        ("future-schema-and-reader", {"schema_version": "99", "min_reader_version": "99"}),
        ("future-schema-compat-reader", {"schema_version": "99", "min_reader_version": "2"}),
        ("reader-exceeds-schema", {"schema_version": "2", "min_reader_version": "99"}),
        ("downgraded-v1-meta", {"schema_version": "1", "min_reader_version": "1"}),
        ("zero-reader-meta", {"schema_version": "2", "min_reader_version": "0"}),
        ("zero-schema-meta", {"schema_version": "0", "min_reader_version": "0"}),
        ("non-digit-schema", {"schema_version": "v2"}),
    ):
        verify_live_meta_case(live_case_name, live_meta)

    # Closed DB pre-admission / read_schema_info with overlong decimal metadata raises INTEGRITY_FAILURE
    # (never raw ValueError).
    for meta_key in ("schema_version", "min_reader_version"):
        closed_root = trusted_tmp / f"closed-overlong-{meta_key}"
        rt_closed = open_runtime(
            closed_root,
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            closed_store_id = rt_closed.policy.store_id
            policy_db_path = rt_closed.root.policy_db
            with rt_closed.policy._immediate() as db_closed:
                db_closed.execute("UPDATE meta SET value = ? WHERE key = ?", ("9" * 5000, meta_key))
        finally:
            rt_closed.close()

        with pytest.raises(BrainError) as exc_rsi:
            read_schema_info(policy_db_path)
        assert exc_rsi.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_admit_serve:
            admit_existing_pair(closed_root, closed_store_id, os_, purpose="serve")
        assert exc_admit_serve.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_admit_mig:
            admit_existing_pair(closed_root, closed_store_id, os_, purpose="migrate")
        assert exc_admit_mig.value.code is ErrorCode.INTEGRITY_FAILURE

    # Non-hardcoded future policy tuple compatibility: injected v3 policy migration allows all 6
    # KernelPolicyPort methods to succeed at schema_version == 3, while still rejecting out-of-band version drift.
    v3_policy_migrations = (
        *KERNEL_POLICY_MIGRATIONS,
        Migration(to_version=3, min_reader_version=2, apply=lambda db: None),
    )
    rt_v3 = open_runtime(
        trusted_tmp / "policy-v3-compat",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=v3_policy_migrations,
    )
    try:
        v3_info = read_schema_info(rt_v3.root.policy_db)
        assert v3_info is not None and v3_info.schema_version == 3 and v3_info.min_reader_version == 2

        v3_store_id = rt_v3.policy.store_id
        v3_gen = rt_v3.policy.trust_generation()
        v3_exp = clock.now() + dt.timedelta(hours=1)
        seeded_v3 = seed_principal_and_credential(
            rt_v3.policy, owner_id="alice", harness_id="claude-code", machine_id="box-1"
        )
        reg_v3 = WorkspaceRegistration(
            owner_id="alice",
            principal_id=seeded_v3.principal.principal_id,
            machine_id="box-1",
            alias="repo-v3",
            checkout_path=str(trusted_tmp / "v3-chk"),
            path_identity="alice:box-1:v3:chk",
        )
        bind_v3 = rt_v3.policy.register_authorized_workspace(
            reg_v3,
            make_bootstrap_auth(
                store_id=v3_store_id,
                owner_id="alice",
                action="workspace_register",
                subject_id=reg_v3.subject_id,
                trust_generation=v3_gen,
                expires_at=v3_exp,
            ),
        )
        scope_v3 = Scope(repo_id=bind_v3.repo_id, checkout_id=bind_v3.checkout_id)
        assert rt_v3.policy.resolve_credential(seeded_v3.token) == seeded_v3.principal
        assert rt_v3.policy.allows(seeded_v3.principal, None, action="get_health") is True
        assert rt_v3.policy.allows(seeded_v3.principal, scope_v3, action="get_artifact") is True
        v3_key_id, v3_key_bytes = rt_v3.policy.request_digest_key()
        assert v3_key_id and len(v3_key_bytes) == 32
        assert bind_v3.checkout_id in rt_v3.policy.snapshot().checkouts

        rev_v3 = rt_v3.policy.record_authorized_revocation(
            seeded_v3.credential_id,
            make_bootstrap_auth(
                store_id=v3_store_id,
                owner_id="alice",
                action="credential_revoke",
                subject_id=seeded_v3.credential_id,
                trust_generation=v3_gen,
                expires_at=v3_exp,
            ),
        )
        assert rev_v3.kind is IntentKind.CREDENTIAL_REVOKE

        # Drift above v3 on the open v3 handle still fails closed with POLICY_UNAVAILABLE.
        with rt_v3.policy._immediate() as db_v3:
            db_v3.execute("UPDATE meta SET value = '4' WHERE key = 'schema_version'")
        with pytest.raises(BrainError) as exc_v3_drift:
            rt_v3.policy.snapshot()
        assert exc_v3_drift.value.code is ErrorCode.POLICY_UNAVAILABLE
    finally:
        rt_v3.close()
