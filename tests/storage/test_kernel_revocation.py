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


def test_workspace_register_replay_binds_immutable_original_subject_after_move(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    import dataclasses
    import json

    from superbrain.core.canonical import canonical_json

    root_path = trusted_tmp / "ws-replay-after-move"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        valid_exp = clock.now() + dt.timedelta(minutes=30)
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1")
        cred_other = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="dev-1")

        loc = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/checkout.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/checkout.git"),
        )
        r1 = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred.principal.principal_id,
            machine_id="dev-1",
            alias="checkout",
            checkout_path=str(trusted_tmp / "old"),
            path_identity="same-physical-checkout",
            locator=loc,
            provider_egress_enabled=False,
        )
        r2 = dataclasses.replace(r1, checkout_path=str(trusted_tmp / "new"))
        assert r1.subject_id != r2.subject_id

        i1 = new_id()
        i2 = new_id()

        b1 = rt.policy.register_authorized_workspace(
            r1,
            make_bootstrap_auth(
                intent_id=i1,
                store_id=store_id,
                owner_id=r1.owner_id,
                action="workspace_register",
                subject_id=r1.subject_id,
                trust_generation=gen,
                expires_at=valid_exp,
            ),
        )
        assert b1.checkout_path == str(trusted_tmp / "old")
        assert rt.policy.snapshot().checkouts[b1.checkout_id].checkout_path == str(trusted_tmp / "old")

        b2 = rt.policy.register_authorized_workspace(
            r2,
            make_bootstrap_auth(
                intent_id=i2,
                store_id=store_id,
                owner_id=r2.owner_id,
                action="workspace_register",
                subject_id=r2.subject_id,
                trust_generation=gen,
                expires_at=valid_exp,
            ),
        )
        assert b2.repo_id == b1.repo_id
        assert b2.checkout_id == b1.checkout_id
        assert b2.checkout_path == str(trusted_tmp / "new")
        assert rt.policy.snapshot().checkouts[b1.checkout_id].checkout_path == str(trusted_tmp / "new")

        # Replaying original (r1, i1) after i2 moved checkout_path succeeds idempotently returning b1
        # AND does NOT roll back the live checkout_path updated by i2.
        b1_replay = rt.policy.register_authorized_workspace(
            r1,
            make_bootstrap_auth(
                intent_id=i1,
                store_id=store_id,
                owner_id=r1.owner_id,
                action="workspace_register",
                subject_id=r1.subject_id,
                trust_generation=gen,
                expires_at=valid_exp,
            ),
        )
        assert b1_replay == b1
        intents = rt.policy.intents()
        assert len(intents) == 2
        intents_by_id = {it.intent_id: it for it in intents}
        assert intents_by_id[i1].payload.get("subject_id") == r1.subject_id
        assert intents_by_id[i2].payload.get("subject_id") == r2.subject_id
        assert rt.policy.snapshot().checkouts[b1.checkout_id].checkout_path == str(trusted_tmp / "new")

        # Reusing i1 with r2's subject (matching live workspace_checkout, differing from i1's original subject)
        # MUST fail closed with REVISION_CONFLICT.
        with pytest.raises(BrainError) as exc_r2_on_i1:
            rt.policy.register_authorized_workspace(
                r2,
                make_bootstrap_auth(
                    intent_id=i1,
                    store_id=store_id,
                    owner_id=r2.owner_id,
                    action="workspace_register",
                    subject_id=r2.subject_id,
                    trust_generation=gen,
                    expires_at=valid_exp,
                ),
            )
        assert exc_r2_on_i1.value.code is ErrorCode.REVISION_CONFLICT

        # Reusing i1 with any modified registration field still raises REVISION_CONFLICT.
        other_loc = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/other.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/other.git"),
        )
        for modified_reg in (
            dataclasses.replace(r1, provider_egress_enabled=True),
            dataclasses.replace(r1, locator=other_loc),
            dataclasses.replace(r1, locator=None),
            dataclasses.replace(r1, alias="checkout-renamed"),
            dataclasses.replace(r1, path_identity="different-physical-checkout"),
            dataclasses.replace(r1, principal_id=cred_other.principal.principal_id),
            dataclasses.replace(r1, machine_id="dev-2"),
        ):
            assert modified_reg.subject_id != r1.subject_id
            with pytest.raises(BrainError) as exc_mod:
                rt.policy.register_authorized_workspace(
                    modified_reg,
                    make_bootstrap_auth(
                        intent_id=i1,
                        store_id=store_id,
                        owner_id=modified_reg.owner_id,
                        action="workspace_register",
                        subject_id=modified_reg.subject_id,
                        trust_generation=gen,
                        expires_at=valid_exp,
                    ),
                )
            assert exc_mod.value.code is ErrorCode.REVISION_CONFLICT

        assert rt.store.reconcile_policy() == 2
    finally:
        rt.close()

    # Reopen under admitted writer lease and verify durable original-subject binding persists.
    admitted = admit_existing_pair(root_path, store_id, os_, purpose="serve")
    reopened = open_runtime_under_lease(admitted)
    try:
        reopened_exp = clock.now() + dt.timedelta(minutes=30)
        assert reopened.policy.snapshot().checkouts[b1.checkout_id].checkout_path == str(trusted_tmp / "new")
        assert (
            reopened.policy.register_authorized_workspace(
                r1,
                make_bootstrap_auth(
                    intent_id=i1,
                    store_id=store_id,
                    owner_id=r1.owner_id,
                    action="workspace_register",
                    subject_id=r1.subject_id,
                    trust_generation=gen,
                    expires_at=reopened_exp,
                ),
            )
            == b1
        )
        with pytest.raises(BrainError) as exc_reopen_conflict:
            reopened.policy.register_authorized_workspace(
                r2,
                make_bootstrap_auth(
                    intent_id=i1,
                    store_id=store_id,
                    owner_id=r2.owner_id,
                    action="workspace_register",
                    subject_id=r2.subject_id,
                    trust_generation=gen,
                    expires_at=reopened_exp,
                ),
            )
        assert exc_reopen_conflict.value.code is ErrorCode.REVISION_CONFLICT
    finally:
        reopened.close()

    # Classified legacy v1 6-key workspace_register row ("subject_id" absent from intents.payload):
    # intents(), snapshot(), and reconcile_policy() succeed without fabricating a digest, while duplicate
    # replay under the same intent_id fails closed with REVISION_CONFLICT even when workspace_checkout matches.
    from collections.abc import Callable

    from superbrain.core.jsonvalue import JsonValue

    legacy_root = trusted_tmp / "ws-missing-subject-proof"
    rt_legacy = open_runtime(
        legacy_root,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        leg_store_id = rt_legacy.policy.store_id
        leg_gen = rt_legacy.policy.trust_generation()
        leg_exp = clock.now() + dt.timedelta(minutes=30)
        leg_cred = seed_principal_and_credential(
            rt_legacy.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1"
        )
        r_leg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=leg_cred.principal.principal_id,
            machine_id="dev-1",
            alias="legacy-ws",
            checkout_path=str(trusted_tmp / "legacy-ws"),
            path_identity="legacy-physical-checkout",
        )
        leg_intent_id = new_id()
        leg_auth = make_bootstrap_auth(
            intent_id=leg_intent_id,
            store_id=leg_store_id,
            owner_id="dan",
            action="workspace_register",
            subject_id=r_leg.subject_id,
            trust_generation=leg_gen,
            expires_at=leg_exp,
        )
        b_leg = rt_legacy.policy.register_authorized_workspace(r_leg, leg_auth)

        with rt_legacy.policy._immediate() as db:
            row = db.execute("SELECT payload FROM intents WHERE intent_id = ?", (leg_intent_id,)).fetchone()
            assert row is not None
            raw_bytes = bytes(row[0]) if isinstance(row[0], (bytes, bytearray, memoryview)) else str(row[0]).encode()
            decoded_payload = json.loads(raw_bytes.decode("utf-8"))
            assert isinstance(decoded_payload, dict)
            decoded_payload.pop("subject_id", None)
            assert set(decoded_payload) == {
                "repo_id",
                "checkout_id",
                "principal_id",
                "machine_id",
                "alias",
                "locator_digest",
            }
            db.execute(
                "UPDATE intents SET payload = ? WHERE intent_id = ?",
                (canonical_json(decoded_payload), leg_intent_id),
            )

        leg_intents = rt_legacy.policy.intents()
        assert len(leg_intents) == 1
        assert leg_intents[0].intent_id == leg_intent_id
        assert leg_intents[0].kind is IntentKind.WORKSPACE_REGISTER
        assert "subject_id" not in leg_intents[0].payload
        assert dict(leg_intents[0].payload) == decoded_payload

        leg_snap = rt_legacy.policy.snapshot()
        assert leg_snap.checkouts[b_leg.checkout_id].checkout_path == str(trusted_tmp / "legacy-ws")
        assert rt_legacy.store.reconcile_policy() == 1
        leg_entries = [
            e
            for e in rt_legacy.store.entries()
            if e.kind == "policy.workspace_register" and e.meta.get("intent_id") == leg_intent_id
        ]
        assert len(leg_entries) == 1
        assert leg_entries[0].handler_version == 2
        assert leg_entries[0].meta["subject_id"] is None

        with pytest.raises(BrainError) as exc_missing_subj_replay:
            rt_legacy.policy.register_authorized_workspace(r_leg, leg_auth)
        assert exc_missing_subj_replay.value.code is ErrorCode.REVISION_CONFLICT
        assert len(rt_legacy.policy.intents()) == 1
        assert "subject_id" not in rt_legacy.policy.intents()[0].payload
    finally:
        rt_legacy.close()

    # Genuinely corrupt workspace_register payloads in intents still fail closed:
    # POLICY_UNAVAILABLE on KernelPolicyPort (register_authorized_workspace, snapshot) and
    # INTEGRITY_FAILURE on PolicySource.intents() / Store.reconcile_policy().
    def verify_corrupt_ws_payload(case_label: str, mutate_fn: Callable[[dict[str, JsonValue]], None]) -> None:
        rt_bad = open_runtime(
            trusted_tmp / f"ws-corrupt-payload-{case_label}",
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            bad_store_id = rt_bad.policy.store_id
            bad_gen = rt_bad.policy.trust_generation()
            bad_exp = clock.now() + dt.timedelta(minutes=30)
            bad_cred = seed_principal_and_credential(
                rt_bad.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1"
            )
            r_bad = WorkspaceRegistration(
                owner_id="dan",
                principal_id=bad_cred.principal.principal_id,
                machine_id="dev-1",
                alias="corrupt-ws",
                checkout_path=str(trusted_tmp / f"corrupt-ws-{case_label}"),
                path_identity=f"corrupt-physical-{case_label}",
            )
            bad_intent_id = new_id()
            bad_auth = make_bootstrap_auth(
                intent_id=bad_intent_id,
                store_id=bad_store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=r_bad.subject_id,
                trust_generation=bad_gen,
                expires_at=bad_exp,
            )
            rt_bad.policy.register_authorized_workspace(r_bad, bad_auth)

            with rt_bad.policy._immediate() as db:
                bad_row = db.execute("SELECT payload FROM intents WHERE intent_id = ?", (bad_intent_id,)).fetchone()
                assert bad_row is not None
                bad_raw = (
                    bytes(bad_row[0])
                    if isinstance(bad_row[0], (bytes, bytearray, memoryview))
                    else str(bad_row[0]).encode()
                )
                bad_payload = json.loads(bad_raw.decode("utf-8"))
                assert isinstance(bad_payload, dict)
                mutate_fn(bad_payload)
                db.execute(
                    "UPDATE intents SET payload = ? WHERE intent_id = ?",
                    (canonical_json(bad_payload), bad_intent_id),
                )

            with pytest.raises(BrainError) as exc_bad_reg:
                rt_bad.policy.register_authorized_workspace(r_bad, bad_auth)
            assert exc_bad_reg.value.code is ErrorCode.POLICY_UNAVAILABLE

            with pytest.raises(BrainError) as exc_bad_snap:
                rt_bad.policy.snapshot()
            assert exc_bad_snap.value.code is ErrorCode.POLICY_UNAVAILABLE

            with pytest.raises(BrainError) as exc_bad_intents:
                rt_bad.policy.intents()
            assert exc_bad_intents.value.code is ErrorCode.INTEGRITY_FAILURE

            with pytest.raises(BrainError) as exc_bad_reconcile:
                rt_bad.store.reconcile_policy()
            assert exc_bad_reconcile.value.code is ErrorCode.INTEGRITY_FAILURE
        finally:
            rt_bad.close()

    def _set_null_subject(p: dict[str, JsonValue]) -> None:
        p["subject_id"] = None

    def _set_bad_subject(p: dict[str, JsonValue]) -> None:
        p["subject_id"] = "not-a-digest"

    def _drop_subject_and_repo(p: dict[str, JsonValue]) -> None:
        p.pop("subject_id", None)
        p.pop("repo_id", None)

    def _add_extra_key(p: dict[str, JsonValue]) -> None:
        p["unexpected_field"] = "bad"

    for corrupt_label, mutator in (
        ("null-subject-7key", _set_null_subject),
        ("bad-subject-7key", _set_bad_subject),
        ("missing-repo-id-5key", _drop_subject_and_repo),
        ("extra-key-8key", _add_extra_key),
    ):
        verify_corrupt_ws_payload(corrupt_label, mutator)


def test_opaque_principal_id_revocation_blocks_credential_and_survives_restore(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "opaque-principal-revoke"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.policy.store_id
        gen = rt.policy.trust_generation()
        cred = seed_principal_and_credential(
            rt.policy,
            owner_id="dan",
            harness_id="claude-code",
            machine_id="dev-1",
            principal_id="principal-review",
        )
        assert cred.principal.principal_id == "principal-review"
        assert rt.policy.resolve_credential(cred.token) == cred.principal
        assert rt.policy.allows(cred.principal, None, action="get_health") is True
        assert rt.policy.snapshot().resolve_credential(cred.token) == cred.principal

        clock.advance(dt.timedelta(seconds=5))
        pre_revoke_backup = create_store_backup(rt.store, os_, clock.now())

        clock.advance(dt.timedelta(seconds=5))
        rev_auth = make_bootstrap_auth(
            store_id=store_id,
            owner_id="dan",
            action="credential_revoke",
            subject_id=cred.credential_id,
            trust_generation=gen,
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        rev_intent = rt.policy.record_authorized_revocation(cred.credential_id, rev_auth)
        assert rev_intent.kind is IntentKind.CREDENTIAL_REVOKE
        assert rev_intent.payload["principal_id"] == "principal-review"
        assert rev_intent.payload["credential_id"] == cred.credential_id
        assert len(rt.policy.intents()) == 1

        # Idempotent duplicate replay returns exact same Intent.
        assert rt.policy.record_authorized_revocation(cred.credential_id, rev_auth) == rev_intent
        assert len(rt.policy.intents()) == 1

        with pytest.raises(BrainError) as exc_immediate:
            rt.policy.resolve_credential(cred.token)
        assert exc_immediate.value.code is ErrorCode.UNAUTHENTICATED
        assert rt.policy.allows(cred.principal, None, action="get_health") is False
    finally:
        rt.close()

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

    clock.advance(dt.timedelta(seconds=5))
    admitted = admit_existing_pair(root_path, store_id, os_, purpose="serve")
    reopened = open_runtime_under_lease(admitted)
    try:
        with pytest.raises(BrainError) as exc_after_restore:
            reopened.policy.resolve_credential(cred.token)
        assert exc_after_restore.value.code is ErrorCode.UNAUTHENTICATED
        assert reopened.policy.allows(cred.principal, None, action="get_health") is False

        revoke_entries = [
            entry
            for entry in reopened.store.entries()
            if entry.kind == "policy.credential_revoke" and entry.meta.get("intent_id") == rev_intent.intent_id
        ]
        assert len(revoke_entries) == 1
        assert revoke_entries[0].meta["principal_id"] == "principal-review"
        assert revoke_entries[0].meta["credential_id"] == cred.credential_id
    finally:
        reopened.close()

    # Genuinely corrupt stored principal_id values in credential still fail closed with POLICY_UNAVAILABLE.
    for idx, corrupt_principal_id in enumerate(("bad principal id", "", "p" * 129, 12345)):
        rt_bad = open_runtime(
            trusted_tmp / f"corrupt-cred-principal-{idx}",
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            bad_store_id = rt_bad.policy.store_id
            bad_gen = rt_bad.policy.trust_generation()
            seeded_bad = seed_principal_and_credential(
                rt_bad.policy,
                owner_id="dan",
                harness_id="claude-code",
                machine_id="dev-1",
                principal_id="valid-principal",
            )
            rt_bad.policy._db.execute("PRAGMA foreign_keys = OFF")
            with rt_bad.policy._immediate() as db:
                db.execute(
                    "UPDATE credential SET principal_id = ? WHERE id = ?",
                    (corrupt_principal_id, seeded_bad.credential_id),
                )
            with pytest.raises(BrainError) as exc_corrupt:
                rt_bad.policy.record_authorized_revocation(
                    seeded_bad.credential_id,
                    make_bootstrap_auth(
                        store_id=bad_store_id,
                        owner_id="dan",
                        action="credential_revoke",
                        subject_id=seeded_bad.credential_id,
                        trust_generation=bad_gen,
                        expires_at=clock.now() + dt.timedelta(hours=1),
                    ),
                )
            assert exc_corrupt.value.code is ErrorCode.POLICY_UNAVAILABLE
        finally:
            rt_bad.close()


def test_cross_revision_v1_workspace_register_root_reopens_reconciles_and_blocks_unproven_replay(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    import dataclasses
    import sqlite3

    from superbrain.composition.migrate_entry import migrate_offline
    from superbrain.core.canonical import canonical_json
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import DaemonConfig
    from superbrain.ports.policy import PolicyView
    from superbrain.storage.kernel_schema import KERNEL_POLICY_KINDS
    from superbrain.storage.ledger import LedgerEntry

    def _snapshot_policy_rows(db: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in (
                "intents",
                "repo_policy",
                "repo_grant",
                "workspace_repo_locator",
                "workspace_checkout",
            )
        }

    class _WsRegisterProjection:
        name = "ws_reg_compat"
        kinds = frozenset({"policy.workspace_register"})

        def __init__(self, version: int) -> None:
            self.handler_version = version

        def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
            db.execute(f"CREATE TABLE {prefix}count (k INTEGER PRIMARY KEY CHECK (k = 1), seen INTEGER NOT NULL)")
            db.execute(f"INSERT INTO {prefix}count (k, seen) VALUES (1, 0)")

        def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
            _ = (entry, policy)
            db.execute(f"UPDATE {prefix}count SET seen = seen + 1 WHERE k = 1")

    # --- Root A: already-reconciled v1 (store=2, policy=2) root with 6-key intent + handler_version=1 ledger row ---
    root_a = trusted_tmp / "v1-reconciled-root-a"
    rt_seed_a = open_runtime(
        root_a,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id_a = rt_seed_a.policy.store_id
        gen_a = rt_seed_a.policy.trust_generation()
        cred_a = seed_principal_and_credential(
            rt_seed_a.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1"
        )
        loc_a = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/v1-root-a.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/v1-root-a.git"),
        )
        old_path_a = str(trusted_tmp / "v1-a-old")
        reg_a = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred_a.principal.principal_id,
            machine_id="dev-1",
            alias="v1-ws-a",
            checkout_path=old_path_a,
            path_identity="dan:dev-1:v1-a",
            locator=loc_a,
            provider_egress_enabled=False,
        )
        i_old_a = new_id()
        bind_a = rt_seed_a.policy.register_authorized_workspace(
            reg_a,
            make_bootstrap_auth(
                intent_id=i_old_a,
                store_id=store_id_a,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg_a.subject_id,
                trust_generation=gen_a,
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        assert rt_seed_a.store.reconcile_policy() == 1

        v1_payload_a: dict[str, JsonValue] = {
            "repo_id": bind_a.repo_id,
            "checkout_id": bind_a.checkout_id,
            "principal_id": cred_a.principal.principal_id,
            "machine_id": "dev-1",
            "alias": "v1-ws-a",
            "locator_digest": loc_a.locator_digest,
        }
        with rt_seed_a.policy._immediate() as db_pol:
            db_pol.execute(
                "UPDATE intents SET payload = ? WHERE intent_id = ?",
                (canonical_json(v1_payload_a), i_old_a),
            )
            assert db_pol.execute("SELECT value FROM meta WHERE key = 'store_published'").fetchone() == ("1",)

        with rt_seed_a.store.transaction() as txn_a:
            applied_seq_row = txn_a.db.execute(
                "SELECT applied_sequence FROM applied_intents WHERE intent_id = ?",
                (i_old_a,),
            ).fetchone()
            assert applied_seq_row is not None
            cur = txn_a.db.execute(
                "UPDATE ledger SET schema_version = 2, handler_version = 1, meta = ? "
                "WHERE kind = 'policy.workspace_register'",
                (canonical_json({"intent_id": i_old_a, **v1_payload_a}),),
            )
            assert cur.rowcount == 1
    finally:
        rt_seed_a.close()

    # Ordinary serve admission + open_runtime_under_lease succeeds BEFORE migrate_offline().
    clock.advance(dt.timedelta(seconds=5))
    admitted_a = admit_existing_pair(root_a, store_id_a, os_, purpose="serve")
    rt_a = open_runtime_under_lease(admitted_a)
    try:
        ws_kinds = [k for k in KERNEL_POLICY_KINDS if k.kind == "policy.workspace_register"]
        assert len(ws_kinds) == 1
        assert ws_kinds[0].handler_version == 2
        assert ws_kinds[0].nullable == frozenset({"locator_digest", "subject_id"})

        assert rt_a.policy.store_id == store_id_a and rt_a.store.store_id == store_id_a
        assert rt_a.policy.resolve_credential(cred_a.token) == cred_a.principal
        scope_a = Scope(repo_id=bind_a.repo_id, checkout_id=bind_a.checkout_id)
        assert rt_a.policy.allows(cred_a.principal, scope_a, action="prepare_task") is True

        snap_a = rt_a.policy.snapshot()
        assert snap_a.checkouts[bind_a.checkout_id].repo_id == bind_a.repo_id
        assert snap_a.checkouts[bind_a.checkout_id].checkout_path == old_path_a
        assert snap_a.checkouts[bind_a.checkout_id].locator_digest == loc_a.locator_digest
        assert (cred_a.principal.principal_id, bind_a.repo_id) in snap_a.grants

        intents_a = rt_a.policy.intents()
        assert len(intents_a) == 1 and intents_a[0].intent_id == i_old_a
        assert "subject_id" not in intents_a[0].payload
        assert dict(intents_a[0].payload) == v1_payload_a

        entries_a = [e for e in rt_a.store.entries() if e.kind == "policy.workspace_register"]
        assert len(entries_a) == 1
        assert entries_a[0].handler_version == 1
        assert "subject_id" not in entries_a[0].meta
        assert entries_a[0].meta["intent_id"] == i_old_a
        assert rt_a.store.rebuild_projections() == len(list(rt_a.store.entries()))

        # Duplicate replay of legacy 6-key intent i_old_a fails closed with REVISION_CONFLICT and mutates zero rows.
        before_replay_rows = _snapshot_policy_rows(rt_a.policy._db)
        with pytest.raises(BrainError) as exc_replay_a:
            rt_a.policy.register_authorized_workspace(
                reg_a,
                make_bootstrap_auth(
                    intent_id=i_old_a,
                    store_id=store_id_a,
                    owner_id="dan",
                    action="workspace_register",
                    subject_id=reg_a.subject_id,
                    trust_generation=rt_a.policy.trust_generation(),
                    expires_at=clock.now() + dt.timedelta(hours=1),
                ),
            )
        assert exc_replay_a.value.code is ErrorCode.REVISION_CONFLICT
        assert _snapshot_policy_rows(rt_a.policy._db) == before_replay_rows
    finally:
        rt_a.close()

    # Offline migrate succeeds cleanly; reopen preserves exact repo_id, checkout_id, locator_digest, and grants.
    clock.advance(dt.timedelta(seconds=5))
    mig_a = migrate_offline(
        DaemonConfig(1, root_a, store_id_a, trusted_tmp / "c.pem", trusted_tmp / "c.key"),
        os_,
    )
    assert mig_a.store_id == store_id_a

    clock.advance(dt.timedelta(seconds=5))
    admitted_a2 = admit_existing_pair(root_a, store_id_a, os_, purpose="serve")
    rt_a2 = open_runtime_under_lease(admitted_a2, handlers=(_WsRegisterProjection(2),))
    try:
        snap_a2 = rt_a2.policy.snapshot()
        assert snap_a2.checkouts[bind_a.checkout_id].repo_id == bind_a.repo_id
        assert snap_a2.checkouts[bind_a.checkout_id].locator_digest == loc_a.locator_digest
        assert (cred_a.principal.principal_id, bind_a.repo_id) in snap_a2.grants

        # Registering the same physical checkout under a NEW intent_id moves checkout_path, preserves repo_id &
        # checkout_id, writes a 7-key v2 intent, and reconciles a handler_version=2 ledger entry.
        new_path_a = str(trusted_tmp / "v1-a-new")
        reg_new = dataclasses.replace(reg_a, checkout_path=new_path_a)
        i_new = new_id()
        bind_new = rt_a2.policy.register_authorized_workspace(
            reg_new,
            make_bootstrap_auth(
                intent_id=i_new,
                store_id=store_id_a,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg_new.subject_id,
                trust_generation=rt_a2.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        assert bind_new.repo_id == bind_a.repo_id
        assert bind_new.checkout_id == bind_a.checkout_id
        assert bind_new.checkout_path == new_path_a

        intents_by_id = {it.intent_id: it for it in rt_a2.policy.intents()}
        assert len(intents_by_id) == 2
        assert "subject_id" not in intents_by_id[i_old_a].payload
        assert set(intents_by_id[i_new].payload) == {
            "subject_id",
            "repo_id",
            "checkout_id",
            "principal_id",
            "machine_id",
            "alias",
            "locator_digest",
        }
        assert intents_by_id[i_new].payload["subject_id"] == reg_new.subject_id

        assert rt_a2.store.reconcile_policy() == 1
        ws_entries_after = [e for e in rt_a2.store.entries() if e.kind == "policy.workspace_register"]
        assert len(ws_entries_after) == 2
        assert ws_entries_after[0].handler_version == 1
        assert ws_entries_after[1].handler_version == 2
        assert ws_entries_after[1].meta["intent_id"] == i_new
        assert ws_entries_after[1].meta["subject_id"] == reg_new.subject_id
        assert rt_a2.store.rebuild_projections() == len(list(rt_a2.store.entries()))
    finally:
        rt_a2.close()

    # Spec §5.8 no-downgrade: opening/rebuilding Store on root_a with a v1 ProjectionHandler for
    # "policy.workspace_register" refuses with UNSUPPORTED_VERSION once handler_version=2 entries exist.
    clock.advance(dt.timedelta(seconds=5))
    with pytest.raises(BrainError) as exc_downgrade:
        admitted_dg = admit_existing_pair(root_a, store_id_a, os_, purpose="serve")
        open_runtime_under_lease(admitted_dg, handlers=(_WsRegisterProjection(1),))
    assert exc_downgrade.value.code is ErrorCode.UNSUPPORTED_VERSION

    # --- Root B: unreconciled v1 (store=2, policy=2) root + restore_store reconciliation ---
    root_b = trusted_tmp / "v1-unreconciled-root-b"
    rt_seed_b = open_runtime(
        root_b,
        os_,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id_b = rt_seed_b.policy.store_id
        gen_b = rt_seed_b.policy.trust_generation()
        cred_b = seed_principal_and_credential(
            rt_seed_b.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-1"
        )
        clock.advance(dt.timedelta(seconds=5))
        pre_reg_backup = create_store_backup(rt_seed_b.store, os_, clock.now())

        clock.advance(dt.timedelta(seconds=5))
        loc_b = TrustedLocator(
            scheme="https",
            canonical_locator="https://example.invalid/dan/v1-root-b.git",
            locator_digest=digest_bytes(b"https://example.invalid/dan/v1-root-b.git"),
        )
        reg_b = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred_b.principal.principal_id,
            machine_id="dev-1",
            alias="v1-ws-b",
            checkout_path=str(trusted_tmp / "v1-b-path"),
            path_identity="dan:dev-1:v1-b",
            locator=loc_b,
        )
        i_old_b = new_id()
        bind_b = rt_seed_b.policy.register_authorized_workspace(
            reg_b,
            make_bootstrap_auth(
                intent_id=i_old_b,
                store_id=store_id_b,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg_b.subject_id,
                trust_generation=gen_b,
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        v1_payload_b: dict[str, JsonValue] = {
            "repo_id": bind_b.repo_id,
            "checkout_id": bind_b.checkout_id,
            "principal_id": cred_b.principal.principal_id,
            "machine_id": "dev-1",
            "alias": "v1-ws-b",
            "locator_digest": loc_b.locator_digest,
        }
        with rt_seed_b.policy._immediate() as db_pol_b:
            db_pol_b.execute(
                "UPDATE intents SET payload = ? WHERE intent_id = ?",
                (canonical_json(v1_payload_b), i_old_b),
            )
        assert list(rt_seed_b.store.entries()) == []
    finally:
        rt_seed_b.close()

    clock.advance(dt.timedelta(seconds=5))
    admitted_b = admit_existing_pair(root_b, store_id_b, os_, purpose="serve")
    rt_b = open_runtime_under_lease(admitted_b)
    try:
        ws_entries_b = [e for e in rt_b.store.entries() if e.kind == "policy.workspace_register"]
        assert len(ws_entries_b) == 1
        assert ws_entries_b[0].handler_version == 2
        assert ws_entries_b[0].meta["intent_id"] == i_old_b
        assert ws_entries_b[0].meta["subject_id"] is None
        assert ws_entries_b[0].meta["repo_id"] == bind_b.repo_id
        assert ws_entries_b[0].meta["checkout_id"] == bind_b.checkout_id

        with pytest.raises(BrainError) as exc_replay_b:
            rt_b.policy.register_authorized_workspace(
                reg_b,
                make_bootstrap_auth(
                    intent_id=i_old_b,
                    store_id=store_id_b,
                    owner_id="dan",
                    action="workspace_register",
                    subject_id=reg_b.subject_id,
                    trust_generation=rt_b.policy.trust_generation(),
                    expires_at=clock.now() + dt.timedelta(hours=1),
                ),
            )
        assert exc_replay_b.value.code is ErrorCode.REVISION_CONFLICT
    finally:
        rt_b.close()

    # Restore pre-registration store backup while policy.db retains the 6-key v1 intent, then reopen and reconcile.
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root_b, os_) as (mroot_b, mlease_b):
        pol_b = PolicyStore.open(mroot_b, mlease_b, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(
                mroot_b,
                mlease_b,
                os_,
                pre_reg_backup,
                pol_b,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol_b.close()

    clock.advance(dt.timedelta(seconds=5))
    admitted_b2 = admit_existing_pair(root_b, store_id_b, os_, purpose="serve")
    rt_b2 = open_runtime_under_lease(admitted_b2)
    try:
        ws_entries_b2 = [e for e in rt_b2.store.entries() if e.kind == "policy.workspace_register"]
        assert len(ws_entries_b2) == 1
        assert ws_entries_b2[0].handler_version == 2
        assert ws_entries_b2[0].meta["intent_id"] == i_old_b
        assert ws_entries_b2[0].meta["subject_id"] is None
        assert ws_entries_b2[0].meta["repo_id"] == bind_b.repo_id
        assert ws_entries_b2[0].meta["checkout_id"] == bind_b.checkout_id

        snap_b2 = rt_b2.policy.snapshot()
        assert snap_b2.checkouts[bind_b.checkout_id].repo_id == bind_b.repo_id
        assert snap_b2.checkouts[bind_b.checkout_id].locator_digest == loc_b.locator_digest
        assert (cred_b.principal.principal_id, bind_b.repo_id) in snap_b2.grants
        assert rt_b2.policy.resolve_credential(cred_b.token) == cred_b.principal
        assert (
            rt_b2.policy.allows(
                cred_b.principal,
                Scope(repo_id=bind_b.repo_id, checkout_id=bind_b.checkout_id),
                action="prepare_task",
            )
            is True
        )
    finally:
        rt_b2.close()
