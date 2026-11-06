"""Credential revocation, authorized workspace registration, store restore durability, and reconcile tests (Task 2)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import cast

import pytest

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import Scope, TrustedLocator, WorkspaceRegistration
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage.backup import create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_store
from superbrain.storage.runtime import admit_existing_pair, open_runtime, open_runtime_under_lease
from tests.storage.conftest import StaticPolicy, StoreFactory, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential


def test_revoked_credential_stays_revoked_after_store_restore(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "revoke-restore"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1")

        reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=seeded.principal.principal_id,
            machine_id="dev-1",
            alias="super-brain2",
            checkout_path=str(trusted_tmp / "ws"),
            path_identity="dan:dev-1:ws",
            locator=TrustedLocator(
                scheme="https",
                canonical_locator="https://example.invalid/dan/super-brain2.git",
                locator_digest=digest_bytes(b"https://example.invalid/dan/super-brain2.git"),
            ),
        )
        binding = rt.policy.register_authorized_workspace(
            reg,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg.subject_id,
                trust_generation=gen,
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        assert rt.store.reconcile_policy() == 1
        scope = Scope(repo_id=binding.repo_id, checkout_id=binding.checkout_id)
        assert rt.policy.resolve_credential(seeded.token) == seeded.principal
        assert rt.policy.allows(seeded.principal, scope, action="prepare_task") is True

        # Take a verified store backup BEFORE revoking the credential.
        clock.advance(dt.timedelta(seconds=5))
        pre_revoke_backup = create_store_backup(rt.store, os_, clock.now())

        # Commit authorized credential_revoke in policy2, then kill/close BEFORE Store.reconcile_policy runs!
        clock.advance(dt.timedelta(seconds=5))
        revoke_intent = rt.policy.record_authorized_revocation(
            seeded.credential_id,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="dan",
                action="credential_revoke",
                subject_id=seeded.credential_id,
                trust_generation=gen,
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        # Credential is immediately blocked in policy even before store reconcile.
        with pytest.raises(BrainError) as exc_immediate:
            rt.policy.resolve_credential(seeded.token)
        assert exc_immediate.value.code is ErrorCode.UNAUTHENTICATED
    finally:
        rt.close()

    # Restore the older pre-revocation store backup while policy2 retains the committed revocation.
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root_path, os_) as (mroot, mlease):
        pol = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(
                mroot,
                mlease,
                os_,
                pre_revoke_backup,
                pol,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol.close()

    # Reopen TWICE under admitted writer lease; credential stays refused and restored store has exact 1 ledger effect!
    for reopen_round in (1, 2):
        clock.advance(dt.timedelta(seconds=5))
        admitted = admit_existing_pair(root_path, store_id, os_, purpose="serve")
        reopened = open_runtime_under_lease(admitted)
        try:
            with pytest.raises(BrainError) as exc_revoked:
                reopened.policy.resolve_credential(seeded.token)
            assert exc_revoked.value.code is ErrorCode.UNAUTHENTICATED
            assert reopened.policy.allows(seeded.principal, scope, action="prepare_task") is False
            assert reopened.policy.allows(seeded.principal, None, action="get_health") is False

            revoke_entries = [
                entry
                for entry in reopened.store.entries()
                if entry.kind == "policy.credential_revoke" and entry.meta.get("intent_id") == revoke_intent.intent_id
            ]
            assert len(revoke_entries) == 1, f"round {reopen_round}: expected 1 revoke entry, got {revoke_entries}"
            assert revoke_entries[0].meta == {
                "intent_id": revoke_intent.intent_id,
                "principal_id": seeded.principal.principal_id,
                "credential_id": seeded.credential_id,
                "owner_id": "dan",
            }
        finally:
            reopened.close()


def test_unknown_intent_kind_is_typed_integrity_failure(
    trusted_tmp: Path, os_: OsAdapters, store_factory: StoreFactory
) -> None:
    # 1. Corrupt/unknown intent kind persisted in policy.db fails closed with INTEGRITY_FAILURE.
    root_path = trusted_tmp / "unknown-intent"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    bad_intent_id = new_id()
    with rt.policy._immediate() as db:
        db.execute(
            "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
            (bad_intent_id, "unknown_future_intent", b"{}", "2026-11-05T00:00:00Z"),
        )
    with pytest.raises(BrainError) as exc_pol:
        rt.policy.intents()
    assert exc_pol.value.code is ErrorCode.INTEGRITY_FAILURE
    rt.close()

    # Reopening runtime also fails closed with INTEGRITY_FAILURE during Store.open reconcile_policy.
    with pytest.raises(BrainError) as exc_reopen:
        admit = admit_existing_pair(root_path, rt.policy._store_id, os_, purpose="serve")
        open_runtime_under_lease(admit)
    assert exc_reopen.value.code is ErrorCode.INTEGRITY_FAILURE

    # 2. Forged/unknown IntentKind returned by PolicySource in Store.reconcile_policy raises INTEGRITY_FAILURE
    # and rolls back applied_intents cleanly.
    fake_policy = StaticPolicy()
    store = store_factory(policy=fake_policy)
    forged_id = new_id()
    fake_policy.queued_intents.append(
        Intent(
            intent_id=forged_id,
            kind=cast(IntentKind, "unhandled_intent_kind"),
            payload={},
            created_at="2026-11-05T00:00:00Z",
        )
    )
    with pytest.raises(BrainError) as exc_reconcile:
        store.reconcile_policy()
    assert exc_reconcile.value.code is ErrorCode.INTEGRITY_FAILURE
    applied_rows = store._db.execute("SELECT intent_id FROM applied_intents").fetchall()
    assert applied_rows == []


def test_direct_record_intent_bypass_is_refused(trusted_tmp: Path, os_: OsAdapters) -> None:
    rt = open_runtime(
        trusted_tmp / "bypass-guard",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        for forbidden_kind, sample_payload in (
            (
                IntentKind.CREDENTIAL_REVOKE,
                {
                    "principal_id": new_id(),
                    "credential_id": new_id(),
                    "owner_id": "dan",
                },
            ),
            (
                IntentKind.WORKSPACE_REGISTER,
                {
                    "repo_id": new_id(),
                    "checkout_id": new_id(),
                    "principal_id": new_id(),
                    "machine_id": "box-1",
                    "alias": "repo",
                    "locator_digest": None,
                },
            ),
        ):
            with pytest.raises(BrainError) as exc_bypass:
                rt.policy.record_intent(forbidden_kind, sample_payload)
            assert exc_bypass.value.code is ErrorCode.INVALID_INPUT
        assert rt.policy.intents() == []
    finally:
        rt.close()


def test_authorized_intents_validation_idempotency_conflict_and_retained_replay(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "auth-intents"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        now = clock.now()
        valid_exp = now + dt.timedelta(minutes=15)

        cred_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1")

        # 1. Foreign store_id, wrong owner_id, stale trust_generation, expired proof, untrusted issuer, wrong subject.
        rev_cases: list[tuple[dict[str, object], ErrorCode]] = [
            ({"store_id": "foreign-store"}, ErrorCode.IDENTITY_MISMATCH),
            ({"owner_id": "other-owner"}, ErrorCode.IDENTITY_MISMATCH),
            ({"trust_generation": gen + 1}, ErrorCode.REVISION_CONFLICT),
            ({"expires_at": now - dt.timedelta(seconds=1)}, ErrorCode.INVALID_INPUT),
            ({"issuer_id": "principal:agent"}, ErrorCode.INVALID_INPUT),
            ({"action": "workspace_register"}, ErrorCode.INVALID_INPUT),
            ({"subject_id": cred_b.credential_id}, ErrorCode.INVALID_INPUT),
        ]
        for overrides, expected_code in rev_cases:
            base_kwargs: dict[str, object] = {
                "store_id": store_id,
                "owner_id": "dan",
                "action": "credential_revoke",
                "subject_id": cred_a.credential_id,
                "trust_generation": gen,
                "expires_at": valid_exp,
            }
            base_kwargs.update(overrides)
            bad_auth = make_bootstrap_auth(**base_kwargs)  # type: ignore[arg-type]
            with pytest.raises(BrainError) as exc_bad:
                rt.policy.record_authorized_revocation(cred_a.credential_id, bad_auth)
            assert exc_bad.value.code is expected_code
        assert rt.policy.intents() == []
        assert rt.policy.resolve_credential(cred_a.token) == cred_a.principal

        # 2. Workspace registration idempotency + reused intent_id conflict + shared repo_id across checkouts.
        shared_loc = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/shared-repo.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/shared-repo.git"),
        )
        reg_1 = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred_a.principal.principal_id,
            machine_id="m1",
            alias="wt-one",
            checkout_path=str(trusted_tmp / "wt-one"),
            path_identity="dan:m1:wt-one",
            locator=shared_loc,
        )
        ws_intent_id = new_id()
        ws_auth_1 = make_bootstrap_auth(
            intent_id=ws_intent_id,
            store_id=store_id,
            owner_id="dan",
            action="workspace_register",
            subject_id=reg_1.subject_id,
            trust_generation=gen,
            expires_at=valid_exp,
        )
        bind_1 = rt.policy.register_authorized_workspace(reg_1, ws_auth_1)
        # Duplicate operation with same intent_id + identical subject returns exact same IDs without minting new ones.
        bind_1_dup = rt.policy.register_authorized_workspace(reg_1, ws_auth_1)
        assert bind_1_dup == bind_1
        assert len(rt.policy.intents()) == 1

        # Reusing the same intent_id with a different registration subject refuses with REVISION_CONFLICT.
        reg_2 = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred_a.principal.principal_id,
            machine_id="m1",
            alias="wt-two",
            checkout_path=str(trusted_tmp / "wt-two"),
            path_identity="dan:m1:wt-two",
            locator=shared_loc,
        )
        with pytest.raises(BrainError) as exc_reuse_ws:
            rt.policy.register_authorized_workspace(
                reg_2,
                make_bootstrap_auth(
                    intent_id=ws_intent_id,
                    store_id=store_id,
                    owner_id="dan",
                    action="workspace_register",
                    subject_id=reg_2.subject_id,
                    trust_generation=gen,
                    expires_at=valid_exp,
                ),
            )
        assert exc_reuse_ws.value.code is ErrorCode.REVISION_CONFLICT

        # Registering wt-two with its own intent_id shares repo_id (same remote locator) with a distinct checkout_id.
        bind_2 = rt.policy.register_authorized_workspace(
            reg_2,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg_2.subject_id,
                trust_generation=gen,
                expires_at=valid_exp,
            ),
        )
        assert bind_2.repo_id == bind_1.repo_id
        assert bind_2.checkout_id != bind_1.checkout_id

        # 3. Revocation idempotency + reused intent_id conflict.
        rev_intent_id = new_id()
        rev_auth_a = make_bootstrap_auth(
            intent_id=rev_intent_id,
            store_id=store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=cred_a.credential_id,
            trust_generation=gen,
            expires_at=valid_exp,
        )
        rev_1 = rt.policy.record_authorized_revocation(cred_a.credential_id, rev_auth_a)
        rev_1_dup = rt.policy.record_authorized_revocation(cred_a.credential_id, rev_auth_a)
        assert rev_1_dup == rev_1

        with pytest.raises(BrainError) as exc_reuse_rev:
            rt.policy.record_authorized_revocation(
                cred_b.credential_id,
                make_bootstrap_auth(
                    intent_id=rev_intent_id,
                    store_id=store_id,
                    owner_id="dan",
                    action="credential_revoke",
                    subject_id=cred_b.credential_id,
                    trust_generation=gen,
                    expires_at=valid_exp,
                ),
            )
        assert exc_reuse_rev.value.code is ErrorCode.REVISION_CONFLICT

        # 4. Retained intent replay after ingress proof expiry (40 days later):
        # Store.reconcile_policy() replays all 3 intents without demanding unexpired proof, without writing policy.db,
        # and without minting new IDs/grants!
        clock.advance(dt.timedelta(days=40))
        rt.policy._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        policy_hashes_before = digest_tree(rt.root.policy_dir)
        snapshot_before = rt.policy.snapshot()

        applied_count = rt.store.reconcile_policy()
        assert applied_count == 3
        assert digest_tree(rt.root.policy_dir) == policy_hashes_before
        assert rt.policy.snapshot() == snapshot_before

        ws_entries = [e for e in rt.store.entries() if e.kind == "policy.workspace_register"]
        rev_entries = [e for e in rt.store.entries() if e.kind == "policy.credential_revoke"]
        assert len(ws_entries) == 2
        assert {str(e.meta["checkout_id"]) for e in ws_entries} == {bind_1.checkout_id, bind_2.checkout_id}
        assert {str(e.meta["repo_id"]) for e in ws_entries} == {bind_1.repo_id}
        assert len(rev_entries) == 1
        assert rev_entries[0].meta["credential_id"] == cred_a.credential_id
    finally:
        rt.close()


def test_workspace_register_enforces_egress_and_locator_consistency(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    rt = open_runtime(
        trusted_tmp / "ws-consistency",
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        valid_exp = clock.now() + dt.timedelta(minutes=30)
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")

        loc_https = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/repo-one.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/repo-one.git"),
        )
        reg_base = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred.principal.principal_id,
            machine_id="m1",
            alias="wt-one",
            checkout_path=str(trusted_tmp / "wt-one"),
            path_identity="dan:m1:wt-one",
            locator=loc_https,
            provider_egress_enabled=False,
        )
        intent_1 = new_id()
        bind_1 = rt.policy.register_authorized_workspace(
            reg_base,
            make_bootstrap_auth(
                intent_id=intent_1,
                store_id=store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg_base.subject_id,
                trust_generation=gen,
                expires_at=valid_exp,
            ),
        )
        assert rt.policy.snapshot().repo_policies[bind_1.repo_id].provider_egress_enabled is False

        # 1. Reusing intent_1 with modified provider_egress_enabled raises REVISION_CONFLICT.
        reg_egress_flip = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred.principal.principal_id,
            machine_id="m1",
            alias="wt-one",
            checkout_path=str(trusted_tmp / "wt-one"),
            path_identity="dan:m1:wt-one",
            locator=loc_https,
            provider_egress_enabled=True,
        )
        with pytest.raises(BrainError) as exc_reuse_egress:
            rt.policy.register_authorized_workspace(
                reg_egress_flip,
                make_bootstrap_auth(
                    intent_id=intent_1,
                    store_id=store_id,
                    owner_id="dan",
                    action="workspace_register",
                    subject_id=reg_egress_flip.subject_id,
                    trust_generation=gen,
                    expires_at=valid_exp,
                ),
            )
        assert exc_reuse_egress.value.code is ErrorCode.REVISION_CONFLICT

        # 2. Reusing intent_1 with same locator_digest but modified scheme/canonical_locator raises REVISION_CONFLICT.
        for bad_loc in (
            TrustedLocator(
                scheme="ssh",
                canonical_locator=loc_https.canonical_locator,
                locator_digest=loc_https.locator_digest,
            ),
            TrustedLocator(
                scheme="https",
                canonical_locator="https://example.invalid/dan/spoofed.git",
                locator_digest=loc_https.locator_digest,
            ),
        ):
            reg_loc_spoof = WorkspaceRegistration(
                owner_id="dan",
                principal_id=cred.principal.principal_id,
                machine_id="m1",
                alias="wt-one",
                checkout_path=str(trusted_tmp / "wt-one"),
                path_identity="dan:m1:wt-one",
                locator=bad_loc,
                provider_egress_enabled=False,
            )
            with pytest.raises(BrainError) as exc_reuse_loc:
                rt.policy.register_authorized_workspace(
                    reg_loc_spoof,
                    make_bootstrap_auth(
                        intent_id=intent_1,
                        store_id=store_id,
                        owner_id="dan",
                        action="workspace_register",
                        subject_id=reg_loc_spoof.subject_id,
                        trust_generation=gen,
                        expires_at=valid_exp,
                    ),
                )
            assert exc_reuse_loc.value.code is ErrorCode.REVISION_CONFLICT

        # 3. Registering a second checkout on an existing locator_digest with mismatched scheme/canonical_locator
        # or conflicting provider_egress_enabled raises REVISION_CONFLICT and preserves repo_policy!
        for bad_reg in (
            WorkspaceRegistration(
                owner_id="dan",
                principal_id=cred.principal.principal_id,
                machine_id="m1",
                alias="wt-two",
                checkout_path=str(trusted_tmp / "wt-two"),
                path_identity="dan:m1:wt-two",
                locator=TrustedLocator(
                    scheme="ssh",
                    canonical_locator="ssh://example.invalid/dan/repo-one.git",
                    locator_digest=loc_https.locator_digest,
                ),
                provider_egress_enabled=False,
            ),
            WorkspaceRegistration(
                owner_id="dan",
                principal_id=cred.principal.principal_id,
                machine_id="m1",
                alias="wt-two",
                checkout_path=str(trusted_tmp / "wt-two"),
                path_identity="dan:m1:wt-two",
                locator=loc_https,
                provider_egress_enabled=True,
            ),
            # Re-registering existing path_identity with new intent_id but conflicting provider_egress_enabled:
            reg_egress_flip,
        ):
            with pytest.raises(BrainError) as exc_conflict:
                rt.policy.register_authorized_workspace(
                    bad_reg,
                    make_bootstrap_auth(
                        store_id=store_id,
                        owner_id="dan",
                        action="workspace_register",
                        subject_id=bad_reg.subject_id,
                        trust_generation=gen,
                        expires_at=valid_exp,
                    ),
                )
            assert exc_conflict.value.code is ErrorCode.REVISION_CONFLICT

        assert rt.policy.snapshot().repo_policies[bind_1.repo_id].provider_egress_enabled is False
    finally:
        rt.close()
