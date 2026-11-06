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

    # Fail-closed check: a workspace_register row in intents lacking "subject_id" in its payload
    # (even when workspace_checkout has a matching live row) NEVER infers subject_id from workspace_checkout.
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
        rt_legacy.policy.register_authorized_workspace(r_leg, leg_auth)

        with rt_legacy.policy._immediate() as db:
            row = db.execute("SELECT payload FROM intents WHERE intent_id = ?", (leg_intent_id,)).fetchone()
            assert row is not None
            raw_bytes = bytes(row[0]) if isinstance(row[0], (bytes, bytearray, memoryview)) else str(row[0]).encode()
            decoded_payload = json.loads(raw_bytes.decode("utf-8"))
            assert isinstance(decoded_payload, dict)
            decoded_payload.pop("subject_id", None)
            db.execute(
                "UPDATE intents SET payload = ? WHERE intent_id = ?",
                (canonical_json(decoded_payload), leg_intent_id),
            )

        with pytest.raises(BrainError) as exc_missing_subj_replay:
            rt_legacy.policy.register_authorized_workspace(r_leg, leg_auth)
        assert exc_missing_subj_replay.value.code is ErrorCode.POLICY_UNAVAILABLE

        with pytest.raises(BrainError) as exc_missing_subj_intents:
            rt_legacy.policy.intents()
        assert exc_missing_subj_intents.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_missing_subj_reconcile:
            rt_legacy.store.reconcile_policy()
        assert exc_missing_subj_reconcile.value.code is ErrorCode.INTEGRITY_FAILURE
    finally:
        rt_legacy.close()


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
