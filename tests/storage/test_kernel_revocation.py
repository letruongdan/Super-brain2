"""Credential revocation, authorized workspace registration, store restore durability, and reconcile tests (Task 2)."""

from __future__ import annotations

import atexit
import datetime as dt
import shutil
import subprocess
import tempfile
import zipfile
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
from tests.support.bounded_worker import BoundedJsonWorker
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import open_cloned_runtime
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential


def test_revoked_credential_stays_revoked_after_store_restore(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "revoke-restore"
    rt = open_cloned_runtime(
        root_path,
        os_,
        role="krev-cur",
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
    rt = open_cloned_runtime(
        root_path,
        os_,
        role="krev-cur",
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
    rt = open_cloned_runtime(
        trusted_tmp / "bypass-guard",
        os_,
        role="krev-cur",
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
    rt = open_cloned_runtime(
        root_path,
        os_,
        role="krev-cur",
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
    rt = open_cloned_runtime(
        trusted_tmp / "ws-consistency",
        os_,
        role="krev-cur",
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
    rt = open_cloned_runtime(
        root_path,
        os_,
        role="krev-cur",
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
    rt_legacy = open_cloned_runtime(
        legacy_root,
        os_,
        role="krev-cur-b",
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
    rt = open_cloned_runtime(
        root_path,
        os_,
        role="krev-cur",
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
    from superbrain.storage.schema import SchemaInfo, code_version, read_schema_info

    v2_policy_migrations = KERNEL_POLICY_MIGRATIONS[:2]
    v2_store_migrations = KERNEL_STORE_MIGRATIONS[:2]
    assert code_version(v2_policy_migrations) == 2
    assert code_version(v2_store_migrations) == 2

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
    rt_seed_a = open_cloned_runtime(
        root_a,
        os_,
        role="krev-v2-a",
        store_migrations=v2_store_migrations,
        policy_migrations=v2_policy_migrations,
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

    pol_info_a = read_schema_info(root_a / "policy" / "policy.db")
    str_info_a = read_schema_info(root_a / "store" / "brain.db")
    assert pol_info_a is not None and pol_info_a.schema_version == 2 and pol_info_a.min_reader_version == 2
    assert str_info_a is not None and str_info_a.schema_version == 2 and str_info_a.min_reader_version == 2

    # Before migrate_offline(), serve admission and open_runtime refuse with MIGRATION_REQUIRED and zero mutations.
    clock.advance(dt.timedelta(seconds=5))
    snap_root_a = digest_tree(root_a)
    with pytest.raises(BrainError) as exc_admit_pre_a:
        unexpected_admit_a = admit_existing_pair(root_a, store_id_a, os_, purpose="serve")
        unexpected_admit_a.release()
    assert exc_admit_pre_a.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(root_a) == snap_root_a

    snap_pol_pre_a = digest_tree(root_a / "policy")
    snap_str_pre_a = digest_tree(root_a / "store")
    with pytest.raises(BrainError) as exc_open_pre_a:
        unexpected_rt_a = open_runtime(
            root_a,
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        unexpected_rt_a.close()
    assert exc_open_pre_a.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(root_a / "policy") == snap_pol_pre_a
    assert digest_tree(root_a / "store") == snap_str_pre_a

    # Offline migrate upgrades policy 2 -> 3 and store 2 -> 4.
    clock.advance(dt.timedelta(seconds=5))
    mig_a = migrate_offline(
        DaemonConfig(1, root_a, store_id_a, trusted_tmp / "c.pem", trusted_tmp / "c.key"),
        os_,
    )
    assert mig_a.store_id == store_id_a
    assert not mig_a.noop
    assert mig_a.policy_report.status == "migrated"
    assert mig_a.policy_report.from_version == 2
    assert mig_a.policy_report.to_version == 3
    assert mig_a.store_report.status == "migrated"
    assert mig_a.store_report.from_version == 2
    assert mig_a.store_report.to_version == 4
    assert code_version(KERNEL_POLICY_MIGRATIONS) == 3
    assert code_version(KERNEL_STORE_MIGRATIONS) == 4
    assert read_schema_info(root_a / "policy" / "policy.db") == SchemaInfo(3, 3, store_id_a)
    assert read_schema_info(root_a / "store" / "brain.db") == SchemaInfo(4, 4, store_id_a)

    # Post-migration serve admission + open_runtime_under_lease preserves retained 6-key intent and handler_version=1.
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
    rt_seed_b = open_cloned_runtime(
        root_b,
        os_,
        role="krev-v2-b",
        store_migrations=v2_store_migrations,
        policy_migrations=v2_policy_migrations,
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

    pol_info_b = read_schema_info(root_b / "policy" / "policy.db")
    str_info_b = read_schema_info(root_b / "store" / "brain.db")
    assert pol_info_b is not None and pol_info_b.schema_version == 2 and pol_info_b.min_reader_version == 2
    assert str_info_b is not None and str_info_b.schema_version == 2 and str_info_b.min_reader_version == 2

    # Before migrate_offline(), Root B also refuses serve admission and open_runtime with zero DB/CAS mutations.
    clock.advance(dt.timedelta(seconds=5))
    snap_root_b = digest_tree(root_b)
    with pytest.raises(BrainError) as exc_admit_pre_b:
        unexpected_admit_b = admit_existing_pair(root_b, store_id_b, os_, purpose="serve")
        unexpected_admit_b.release()
    assert exc_admit_pre_b.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(root_b) == snap_root_b

    snap_pol_pre_b = digest_tree(root_b / "policy")
    snap_str_pre_b = digest_tree(root_b / "store")
    with pytest.raises(BrainError) as exc_open_pre_b:
        unexpected_rt_b = open_runtime(
            root_b,
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        unexpected_rt_b.close()
    assert exc_open_pre_b.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(root_b / "policy") == snap_pol_pre_b
    assert digest_tree(root_b / "store") == snap_str_pre_b

    clock.advance(dt.timedelta(seconds=5))
    mig_b = migrate_offline(
        DaemonConfig(1, root_b, store_id_b, trusted_tmp / "cb.pem", trusted_tmp / "cb.key"),
        os_,
    )
    assert mig_b.store_id == store_id_b
    assert not mig_b.noop
    assert mig_b.policy_report.status == "migrated"
    assert mig_b.policy_report.from_version == 2
    assert mig_b.policy_report.to_version == 3
    assert mig_b.store_report.status == "migrated"
    assert mig_b.store_report.from_version == 2
    assert mig_b.store_report.to_version == 4
    assert read_schema_info(root_b / "policy" / "policy.db") == SchemaInfo(3, 3, store_id_b)
    assert read_schema_info(root_b / "store" / "brain.db") == SchemaInfo(4, 4, store_id_b)

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
    assert read_schema_info(root_b / "store" / "brain.db") == SchemaInfo(4, 4, store_id_b)

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


_HIST_V2_COMMIT = "6a67b384c16c5a405f2a26b3ecb4b67e4ab26652"
_HIST_V2_SRC_CACHE: dict[tuple[Path, str], tuple[Path | None, bool]] = {}


def _ensure_historical_v2_src(
    repo_root: Path,
    os_: OsAdapters,
    hist_commit: str = _HIST_V2_COMMIT,
) -> tuple[Path | None, bool]:
    """Return ``(hist_src, non_shallow)`` with a cached read-only ``src/`` tree for ``hist_commit``."""
    key = (repo_root.resolve(), hist_commit)
    if key in _HIST_V2_SRC_CACHE:
        cached_src, cached_non_shallow = _HIST_V2_SRC_CACHE[key]
        if cached_src is None or (cached_src / "superbrain" / "__init__.py").is_file():
            return cached_src, cached_non_shallow

    shallow_proc = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    non_shallow = shallow_proc.returncode == 0 and shallow_proc.stdout.strip() == "false"
    has_hist_commit = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{hist_commit}^{{commit}}"],
            cwd=repo_root,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )
    if non_shallow:
        assert has_hist_commit, f"non-shallow repository must contain historical commit {hist_commit}"

    if not has_hist_commit:
        _HIST_V2_SRC_CACHE[key] = (None, non_shallow)
        return None, non_shallow

    hist_base = Path(tempfile.mkdtemp(prefix="sb2-hist-6a67b38-"))
    atexit.register(shutil.rmtree, hist_base, ignore_errors=True)
    try:
        hist_zip = hist_base / "hist.zip"
        arch_proc = subprocess.run(
            ["git", "archive", "--format=zip", f"--output={hist_zip}", hist_commit, "src"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        assert arch_proc.returncode == 0, arch_proc.stderr
        hist_dir = hist_base / "tree"
        hist_dir.mkdir()
        os_.permissions.secure_directory(hist_dir)
        with zipfile.ZipFile(hist_zip) as zf:
            for member in zf.infolist():
                member_path = Path(member.filename)
                member_parts = member_path.parts
                assert (
                    bool(member_parts)
                    and member_parts[0] == "src"
                    and ".." not in member_parts
                    and not member_path.is_absolute()
                    and not member_path.drive
                ), f"unsafe zip entry: {member.filename}"
            zf.extractall(hist_dir)
        hist_zip.unlink(missing_ok=True)
        hist_src = hist_dir / "src"
        assert (hist_src / "superbrain" / "__init__.py").is_file()
        _HIST_V2_SRC_CACHE[key] = (hist_src, non_shallow)
        return hist_src, non_shallow
    except BaseException:
        shutil.rmtree(hist_base, ignore_errors=True)
        raise


def test_historical_v2_writer_is_fenced_before_policy_mutation_across_migrate_and_restore(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    import os
    import shutil
    import sys
    from typing import Literal

    from superbrain.composition.migrate_entry import migrate_offline
    from superbrain.core.kernel import DaemonConfig
    from superbrain.storage.backup import create_policy_backup
    from superbrain.storage.restore import restore_policy
    from superbrain.storage.schema import (
        POLICY_MIGRATIONS,
        STORE_MIGRATIONS,
        SchemaInfo,
        code_version,
        read_schema_info,
    )
    from superbrain.storage.sqlite import open_readonly
    from superbrain.storage.swap import READY
    from tests.support.inc2_transport import clone_owner_only_tree

    def _read_policy_state(policy_db: Path) -> dict[str, object]:
        db = open_readonly(policy_db)
        try:
            gen_row = db.execute("SELECT generation FROM trust WHERE id = 1").fetchone()
            assert gen_row is not None and type(gen_row[0]) is int
            meta_rows = dict(db.execute("SELECT key, value FROM meta").fetchall())
            intents_rows = db.execute("SELECT intent_id, kind, payload FROM intents ORDER BY rowid").fetchall()
            checkouts_rows = db.execute(
                "SELECT checkout_id, repo_id, checkout_path, alias FROM workspace_checkout ORDER BY checkout_id"
            ).fetchall()
            grants_rows = db.execute(
                "SELECT principal_id, repo_id, granted_intent_id FROM repo_grant ORDER BY principal_id, repo_id"
            ).fetchall()
            creds_rows = db.execute("SELECT id, principal_id, revoked_intent_id FROM credential ORDER BY id").fetchall()
            return {
                "trust_generation": gen_row[0],
                "meta": meta_rows,
                "intents": intents_rows,
                "checkouts": checkouts_rows,
                "grants": grants_rows,
                "credentials": creds_rows,
            }
        finally:
            db.close()

    repo_root = Path(__file__).resolve().parents[2]
    hist_src, non_shallow = _ensure_historical_v2_src(repo_root, os_)
    part_a_ran = hist_src is not None
    if hist_src is not None:

        driver_path = trusted_tmp / "hist_6a67b38_driver.py"
        driver_code = (
            "import datetime as dt\n"
            "import json\n"
            "import sys\n"
            "from pathlib import Path\n"
            "\n"
            "hist_src = Path(sys.argv[1]).resolve()\n"
            "repo_root = Path(sys.argv[2]).resolve()\n"
            "repo_src = (repo_root / 'src').resolve()\n"
            "sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != repo_src]\n"
            "sys.path[:0] = [str(hist_src), str(repo_root)]\n"
            "\n"
            "import superbrain\n"
            "from superbrain.adapters.os import os_adapters\n"
            "from superbrain.composition.migrate_entry import migrate_offline\n"
            "from superbrain.core.errors import BrainError\n"
            "from superbrain.core.kernel import DaemonConfig, WorkspaceRegistration\n"
            "from superbrain.storage.backup import create_policy_backup, create_store_backup\n"
            "from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS\n"
            "from superbrain.storage.runtime import admit_existing_pair, open_runtime\n"
            "from superbrain.storage.schema import code_version\n"
            "from tests.support.clock import FakeClock\n"
            "from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential\n"
            "\n"
            "def _dispatch(req: dict[str, object]) -> dict[str, object]:\n"
            "    assert Path(superbrain.__file__).resolve().is_relative_to(hist_src)\n"
            "    assert code_version(KERNEL_STORE_MIGRATIONS) == 2\n"
            "    assert code_version(KERNEL_POLICY_MIGRATIONS) == 2\n"
            "    mode = req['mode']\n"
            "    root = Path(str(req['root']))\n"
            "    base = Path(str(req['base']))\n"
            "    if mode == 'create_pending':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 8, 0, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        rt = open_runtime(\n"
            "            root,\n"
            "            adapters,\n"
            "            store_migrations=KERNEL_STORE_MIGRATIONS,\n"
            "            policy_migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "        )\n"
            "        try:\n"
            "            cred = seed_principal_and_credential(\n"
            "                rt.policy, owner_id='dan', harness_id='claude-code', machine_id='dev-hist-1'\n"
            "            )\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            s_bak = create_store_backup(rt.store, adapters, clock.now())\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            p_bak = create_policy_backup(rt.policy, adapters, clock.now())\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            reg = WorkspaceRegistration(\n"
            "                owner_id='dan',\n"
            "                principal_id=cred.principal.principal_id,\n"
            "                machine_id=cred.principal.machine_id,\n"
            "                alias='checkout',\n"
            "                checkout_path=str(base / 'old'),\n"
            "                path_identity='same-inode',\n"
            "            )\n"
            "            auth = make_bootstrap_auth(\n"
            "                store_id=rt.policy.store_id,\n"
            "                owner_id='dan',\n"
            "                action='workspace_register',\n"
            "                subject_id=reg.subject_id,\n"
            "                trust_generation=rt.policy.trust_generation(),\n"
            "                expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "            )\n"
            "            binding = rt.policy.register_authorized_workspace(reg, auth)\n"
            "            intents = rt.policy.intents()\n"
            "            ws_entries = [e for e in rt.store.entries() if e.kind == 'policy.workspace_register']\n"
            "            return {\n"
            "                'store_id': rt.policy.store_id,\n"
            "                'principal_id': cred.principal.principal_id,\n"
            "                'machine_id': cred.principal.machine_id,\n"
            "                'credential_id': cred.credential_id,\n"
            "                'token': cred.token,\n"
            "                'repo_id': binding.repo_id,\n"
            "                'checkout_id': binding.checkout_id,\n"
            "                'intent_id': auth.intent_id,\n"
            "                'store_backup': str(s_bak),\n"
            "                'policy_backup': str(p_bak),\n"
            "                'intents_count': len(intents),\n"
            "                'intent_has_subject': 'subject_id' in intents[0].payload,\n"
            "                'ledger_workspace_entries': len(ws_entries),\n"
            "            }\n"
            "        finally:\n"
            "            rt.close()\n"
            "    if mode == 'probe_preadmission':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 0, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        sid = str(req['store_id'])\n"
            "        out: dict[str, object] = {}\n"
            "        for p_label, p_val in (('admit_serve', 'serve'), ('admit_migrate', 'migrate')):\n"
            "            try:\n"
            "                adm = admit_existing_pair(root, sid, adapters, purpose=p_val)\n"
            "                try:\n"
            "                    out[p_label] = 'accepted'\n"
            "                finally:\n"
            "                    adm.release()\n"
            "            except BrainError as err:\n"
            "                out[p_label] = err.code.value\n"
            "        try:\n"
            "            migrate_offline(DaemonConfig(1, root, sid, base / 'c.pem', base / 'c.key'), adapters)\n"
            "        except BrainError as err:\n"
            "            out['migrate_offline'] = err.code.value\n"
            "        else:\n"
            "            out['migrate_offline'] = 'accepted'\n"
            "        return out\n"
            "    if mode == 'probe_open_and_mutate':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 30, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        stage_reached = 'open_runtime'\n"
            "        error_code: str | None = None\n"
            "        try:\n"
            "            rt = open_runtime(\n"
            "                root,\n"
            "                adapters,\n"
            "                store_migrations=KERNEL_STORE_MIGRATIONS,\n"
            "                policy_migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "            )\n"
            "            try:\n"
            "                stage_reached = 'register_authorized_workspace'\n"
            "                reg = WorkspaceRegistration(\n"
            "                    owner_id='dan',\n"
            "                    principal_id=str(req['principal_id']),\n"
            "                    machine_id=str(req['machine_id']),\n"
            "                    alias='checkout',\n"
            "                    checkout_path=str(base / 'new'),\n"
            "                    path_identity='same-inode',\n"
            "                )\n"
            "                rt.policy.register_authorized_workspace(\n"
            "                    reg,\n"
            "                    make_bootstrap_auth(\n"
            "                        store_id=rt.policy.store_id,\n"
            "                        owner_id='dan',\n"
            "                        action='workspace_register',\n"
            "                        subject_id=reg.subject_id,\n"
            "                        trust_generation=rt.policy.trust_generation(),\n"
            "                        expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "                    ),\n"
            "                )\n"
            "                stage_reached = 'record_authorized_revocation'\n"
            "                rt.policy.record_authorized_revocation(\n"
            "                    str(req['credential_id']),\n"
            "                    make_bootstrap_auth(\n"
            "                        store_id=rt.policy.store_id,\n"
            "                        owner_id='dan',\n"
            "                        action='credential_revoke',\n"
            "                        subject_id=str(req['credential_id']),\n"
            "                        trust_generation=rt.policy.trust_generation(),\n"
            "                        expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "                    ),\n"
            "                )\n"
            "                stage_reached = 'reconcile_policy'\n"
            "                rt.store.reconcile_policy()\n"
            "                stage_reached = 'completed'\n"
            "            finally:\n"
            "                rt.close()\n"
            "        except BrainError as err:\n"
            "            error_code = err.code.value\n"
            "        return {'stage_reached': stage_reached, 'error_code': error_code}\n"
            "    raise AssertionError(f'unknown mode: {mode}')\n"
            "\n"
            "for raw_line in sys.stdin:\n"
            "    if not raw_line.strip():\n"
            "        continue\n"
            "    resp = _dispatch(json.loads(raw_line))\n"
            "    print(json.dumps(resp), flush=True)\n"
        )
        driver_path.write_text(driver_code, encoding="utf-8")
        os_.permissions.secure_file(driver_path)

        hist_worker = BoundedJsonWorker(
            [sys.executable, str(driver_path), str(hist_src), str(repo_root)],
            cwd=repo_root,
            stderr_path=trusted_tmp / "hist_6a67b38_worker.stderr.log",
            label="historical worker",
        )
        _close_hist_worker = hist_worker.close
        _run_hist_child = hist_worker.request

        try:
            part_a_base = trusted_tmp / "part-a-6a67b38"
            part_a_base.mkdir()
            os_.permissions.secure_directory(part_a_base)

            def _assert_hist_6a67b38_fenced(
                target_root: Path,
                target_store_id: str,
                target_principal_id: str,
                target_machine_id: str,
                target_credential_id: str,
                stage_label: str,
            ) -> None:
                root_before = digest_tree(target_root)
                preadm_res = _run_hist_child(
                    {
                        "mode": "probe_preadmission",
                        "root": str(target_root),
                        "base": str(part_a_base),
                        "store_id": target_store_id,
                    }
                )
                assert preadm_res == {
                    "admit_serve": ErrorCode.UNSUPPORTED_VERSION.value,
                    "admit_migrate": ErrorCode.UNSUPPORTED_VERSION.value,
                    "migrate_offline": ErrorCode.UNSUPPORTED_VERSION.value,
                }, f"{stage_label}: unexpected pre-admission result {preadm_res}"
                assert digest_tree(target_root) == root_before, (
                    f"{stage_label}: root changed during pre-admission refusal"
                )

                pol_before = digest_tree(target_root / "policy")
                str_before = digest_tree(target_root / "store")
                pol_state_before = _read_policy_state(target_root / "policy" / "policy.db")
                mut_res = _run_hist_child(
                    {
                        "mode": "probe_open_and_mutate",
                        "root": str(target_root),
                        "base": str(part_a_base),
                        "principal_id": target_principal_id,
                        "machine_id": target_machine_id,
                        "credential_id": target_credential_id,
                    }
                )
                assert mut_res == {
                    "stage_reached": "open_runtime",
                    "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
                }, f"{stage_label}: historical writer was not fenced at open_runtime: {mut_res}"
                assert digest_tree(target_root / "policy") == pol_before, f"{stage_label}: policy/ bytes changed"
                assert digest_tree(target_root / "store") == str_before, f"{stage_label}: store/ bytes changed"
                assert _read_policy_state(target_root / "policy" / "policy.db") == pol_state_before

            # 0a. Direct probe_downgrade_writer reproduction: 6a67b38 creates pending 6-key workspace_register,
            # Current Code runs migrate_offline + serve reconcile, then 6a67b38 default open_runtime attempts
            # register_authorized_workspace + record_authorized_revocation -> MUST fail at open_runtime with
            # UNSUPPORTED_VERSION before any policy authority mutation executes!
            root_probe = part_a_base / "probe-downgrade-root"
            probe_created = _run_hist_child(
                {
                    "mode": "create_pending",
                    "root": str(root_probe),
                    "base": str(part_a_base),
                }
            )
            probe_store_id = str(probe_created["store_id"])
            clock.advance(dt.timedelta(seconds=5))
            migrate_offline(
                DaemonConfig(1, root_probe, probe_store_id, part_a_base / "c.pem", part_a_base / "c.key"),
                os_,
            )
            adm_probe = admit_existing_pair(root_probe, probe_store_id, os_, purpose="serve")
            rt_probe = open_runtime_under_lease(adm_probe)
            rt_probe.close()

            pol_probe_before = digest_tree(root_probe / "policy")
            str_probe_before = digest_tree(root_probe / "store")
            state_probe_before = _read_policy_state(root_probe / "policy" / "policy.db")
            probe_mut_res = _run_hist_child(
                {
                    "mode": "probe_open_and_mutate",
                    "root": str(root_probe),
                    "base": str(part_a_base),
                    "principal_id": str(probe_created["principal_id"]),
                    "machine_id": str(probe_created["machine_id"]),
                    "credential_id": str(probe_created["credential_id"]),
                }
            )
            assert probe_mut_res == {
                "stage_reached": "open_runtime",
                "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
            }, f"historical 6a67b38 writer mutated policy before fence: {probe_mut_res}"
            assert digest_tree(root_probe / "policy") == pol_probe_before
            assert digest_tree(root_probe / "store") == str_probe_before
            assert _read_policy_state(root_probe / "policy" / "policy.db") == state_probe_before

            # 0b. Root created directly by Current Code (with 7-key intent) and reconciled at handler_version=2 MUST
            # also fence 6a67b38 with UNSUPPORTED_VERSION (never INTEGRITY_FAILURE) before PolicyStore opens.
            root_cur_created = part_a_base / "current-created-root"
            rt_cur_init = open_cloned_runtime(
                root_cur_created,
                os_,
                role="krev-cur",
                store_migrations=KERNEL_STORE_MIGRATIONS,
                policy_migrations=KERNEL_POLICY_MIGRATIONS,
            )
            try:
                cur_store_id = rt_cur_init.policy.store_id
                cur_cred = seed_principal_and_credential(
                    rt_cur_init.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-cur-1"
                )
                cur_reg = WorkspaceRegistration(
                    owner_id="dan",
                    principal_id=cur_cred.principal.principal_id,
                    machine_id=cur_cred.principal.machine_id,
                    alias="checkout",
                    checkout_path=str(part_a_base / "old"),
                    path_identity="same-inode",
                )
                rt_cur_init.policy.register_authorized_workspace(
                    cur_reg,
                    make_bootstrap_auth(
                        store_id=cur_store_id,
                        owner_id="dan",
                        action="workspace_register",
                        subject_id=cur_reg.subject_id,
                        trust_generation=rt_cur_init.policy.trust_generation(),
                        expires_at=clock.now() + dt.timedelta(minutes=30),
                    ),
                )
                assert rt_cur_init.store.reconcile_policy() == 1
            finally:
                rt_cur_init.close()

            pol_cur_before = digest_tree(root_cur_created / "policy")
            str_cur_before = digest_tree(root_cur_created / "store")
            state_cur_before = _read_policy_state(root_cur_created / "policy" / "policy.db")
            cur_mut_res = _run_hist_child(
                {
                    "mode": "probe_open_and_mutate",
                    "root": str(root_cur_created),
                    "base": str(part_a_base),
                    "principal_id": cur_cred.principal.principal_id,
                    "machine_id": cur_cred.principal.machine_id,
                    "credential_id": cur_cred.credential_id,
                }
            )
            assert cur_mut_res == {
                "stage_reached": "open_runtime",
                "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
            }, f"historical 6a67b38 writer mutated policy before fence: {cur_mut_res}"
            assert digest_tree(root_cur_created / "policy") == pol_cur_before
            assert digest_tree(root_cur_created / "store") == str_cur_before
            assert _read_policy_state(root_cur_created / "policy" / "policy.db") == state_cur_before
            _assert_hist_6a67b38_fenced(
                root_cur_created,
                cur_store_id,
                cur_cred.principal.principal_id,
                cur_cred.principal.machine_id,
                cur_cred.credential_id,
                "step0-current-created-root",
            )

            # 1. 6a67b38 child creates (store=2, policy=2) root, takes v2 backups, commits 6-key workspace_register
            # intent (old checkout path), and closes before reconcile_policy().
            root_hist = part_a_base / "store-root"

            created = _run_hist_child(
                {
                    "mode": "create_pending",
                    "root": str(root_hist),
                    "base": str(part_a_base),
                }
            )
            assert created["intents_count"] == 1
            assert created["intent_has_subject"] is False
            assert created["ledger_workspace_entries"] == 0
            hist_store_id = str(created["store_id"])
            hist_principal_id = str(created["principal_id"])
            hist_machine_id = str(created["machine_id"])
            hist_credential_id = str(created["credential_id"])
            hist_token = str(created["token"])
            hist_repo_id = str(created["repo_id"])
            hist_checkout_id = str(created["checkout_id"])
            hist_store_backup = Path(str(created["store_backup"]))
            hist_policy_backup = Path(str(created["policy_backup"]))

            # 2. Current Code verifies admit_existing_pair(..., purpose="serve") raises MIGRATION_REQUIRED with
            # digest_tree(root) unchanged, runs migrate_offline (policy: 2 -> 3), and opens + reconciles.
            snap_pre_mig = digest_tree(root_hist)
            with pytest.raises(BrainError) as exc_pre_mig:
                unexpected_adm = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                unexpected_adm.release()
            assert exc_pre_mig.value.code is ErrorCode.MIGRATION_REQUIRED
            assert digest_tree(root_hist) == snap_pre_mig

            snap_pol_pre_mig = digest_tree(root_hist / "policy")
            snap_str_pre_mig = digest_tree(root_hist / "store")
            with pytest.raises(BrainError) as exc_open_pre_mig:
                unexpected_rt_hist = open_runtime(
                    root_hist,
                    os_,
                    store_migrations=KERNEL_STORE_MIGRATIONS,
                    policy_migrations=KERNEL_POLICY_MIGRATIONS,
                )
                unexpected_rt_hist.close()
            assert exc_open_pre_mig.value.code is ErrorCode.MIGRATION_REQUIRED
            assert digest_tree(root_hist / "policy") == snap_pol_pre_mig
            assert digest_tree(root_hist / "store") == snap_str_pre_mig

            clock.advance(dt.timedelta(minutes=1))
            mig_hist = migrate_offline(
                DaemonConfig(1, root_hist, hist_store_id, part_a_base / "c.pem", part_a_base / "c.key"),
                os_,
            )
            assert not mig_hist.noop
            assert mig_hist.policy_report.status == "migrated"
            assert mig_hist.policy_report.from_version == 2
            assert mig_hist.policy_report.to_version == 3
            assert mig_hist.policy_report.backup is not None
            maint_v2_policy_backup = mig_hist.policy_report.backup
            assert mig_hist.store_report.status == "migrated"
            assert mig_hist.store_report.from_version == 2
            assert mig_hist.store_report.to_version == 4
            assert mig_hist.store_report.backup is not None
            assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(3, 3, hist_store_id)
            assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)

            clock.advance(dt.timedelta(seconds=5))
            adm_cur = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
            rt_cur = open_runtime_under_lease(adm_cur)
            try:
                ws_reconciled = [e for e in rt_cur.store.entries() if e.kind == "policy.workspace_register"]
                assert len(ws_reconciled) == 1
                assert ws_reconciled[0].handler_version == 2
                assert ws_reconciled[0].meta["subject_id"] is None
                assert rt_cur.policy.snapshot().checkouts[hist_checkout_id].checkout_path == str(part_a_base / "old")
                assert rt_cur.policy.resolve_credential(hist_token).principal_id == hist_principal_id
            finally:
                rt_cur.close()

            def _assert_root_hist_fenced(stage_label: str) -> None:
                _assert_hist_6a67b38_fenced(
                    root_hist,
                    hist_store_id,
                    hist_principal_id,
                    hist_machine_id,
                    hist_credential_id,
                    stage_label,
                )

            # 3. 6a67b38 child refuses admit_existing_pair (serve & migrate), migrate_offline, and default open_runtime
            # BEFORE any policy mutation executes; intents, checkout_path, grants, bindings, and generation stay intact.
            state_step3 = _read_policy_state(root_hist / "policy" / "policy.db")
            intents_step3 = state_step3["intents"]
            checkouts_step3 = state_step3["checkouts"]
            grants_step3 = state_step3["grants"]
            creds_step3 = state_step3["credentials"]
            assert isinstance(intents_step3, list) and len(intents_step3) == 1
            assert checkouts_step3 == [(hist_checkout_id, hist_repo_id, str(part_a_base / "old"), "checkout")]
            assert isinstance(grants_step3, list) and len(grants_step3) == 1
            assert creds_step3 == [(hist_credential_id, hist_principal_id, None)]
            _assert_root_hist_fenced("step3-after-migrate-and-reconcile")
            assert _read_policy_state(root_hist / "policy" / "policy.db") == state_step3

            # 4. Current Code runs restore_store (restoring the 6a67b38 v2 store backup): 6a67b38 child STILL fails with
            # UNSUPPORTED_VERSION and unchanged policy/ + store/ hashes; Current Code reopens and re-reconciles cleanly.
            clock.advance(dt.timedelta(minutes=1))
            with maintenance_lease(root_hist, os_) as (mroot_h, mlease_h):
                pol_h = PolicyStore.open(mroot_h, mlease_h, os_, migrations=KERNEL_POLICY_MIGRATIONS)
                try:
                    restore_store(
                        mroot_h,
                        mlease_h,
                        os_,
                        hist_store_backup,
                        pol_h,
                        clock.now(),
                        migrations=KERNEL_STORE_MIGRATIONS,
                    )
                finally:
                    pol_h.close()
            assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)

            _assert_root_hist_fenced("step4-after-restore-store")

            clock.advance(dt.timedelta(seconds=5))
            adm_after_srestore = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
            rt_after_srestore = open_runtime_under_lease(adm_after_srestore)
            try:
                ws_entries_srestore = [
                    e for e in rt_after_srestore.store.entries() if e.kind == "policy.workspace_register"
                ]
                assert len(ws_entries_srestore) == 1
                assert ws_entries_srestore[0].handler_version == 2
                assert ws_entries_srestore[0].meta["subject_id"] is None
                assert rt_after_srestore.policy.snapshot().checkouts[hist_checkout_id].checkout_path == str(
                    part_a_base / "old"
                )
            finally:
                rt_after_srestore.close()

            # 5. Current Code runs restore_policy for BOTH the v2 maintenance policy backup created by migrate_offline
            # AND the 6a67b38 v2 policy backup under migrations=KERNEL_POLICY_MIGRATIONS: restored policy.db has
            # schema_version == 3 and min_reader_version == 3, monotonic trust.generation, meta.store_published == '1',
            # Current Code reopens cleanly, and 6a67b38 child STILL fails with UNSUPPORTED_VERSION before any mutation.
            for bak_label, bak_path in (
                ("migrate-maint-v2-policy-backup", maint_v2_policy_backup),
                ("hist-6a67b38-v2-policy-backup", hist_policy_backup),
            ):
                prev_state = _read_policy_state(root_hist / "policy" / "policy.db")
                prev_gen = prev_state["trust_generation"]
                assert isinstance(prev_gen, int)

                clock.advance(dt.timedelta(minutes=1))
                with maintenance_lease(root_hist, os_) as (mroot_p, mlease_p):
                    rep_p = restore_policy(
                        mroot_p,
                        mlease_p,
                        os_,
                        bak_path,
                        store_id=hist_store_id,
                        now=clock.now(),
                        migrations=KERNEL_POLICY_MIGRATIONS,
                    )

                restored_info = read_schema_info(root_hist / "policy" / "policy.db")
                assert (
                    restored_info is not None
                    and restored_info.schema_version == 3
                    and restored_info.min_reader_version == 3
                )
                post_state = _read_policy_state(root_hist / "policy" / "policy.db")
                post_gen = post_state["trust_generation"]
                post_meta = post_state["meta"]
                assert isinstance(post_gen, int) and rep_p.trust_generation == post_gen and post_gen > prev_gen
                assert isinstance(post_meta, dict) and post_meta.get("store_published") == "1"

                _assert_root_hist_fenced(f"step5-{bak_label}-before-serve")

                clock.advance(dt.timedelta(seconds=5))
                adm_post_p = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                rt_post_p = open_runtime_under_lease(adm_post_p)
                try:
                    assert rt_post_p.policy.trust_generation() == post_gen
                    assert rt_post_p.policy.resolve_credential(hist_token).principal_id == hist_principal_id
                    assert rt_post_p.store.reconcile_policy() == 0
                finally:
                    rt_post_p.close()

                _assert_root_hist_fenced(f"step5-{bak_label}-after-serve")
        finally:
            _close_hist_worker()

    if non_shallow:
        assert part_a_ran is True

    # --- Part B: Shallow-Clone-Safe In-Process Historical-v2 Tuple & Recovery Fence Checks ---
    v2_policy = KERNEL_POLICY_MIGRATIONS[:2]
    v2_store = KERNEL_STORE_MIGRATIONS[:2]
    assert code_version(v2_policy) == 2
    assert code_version(v2_store) == 2
    assert code_version(KERNEL_POLICY_MIGRATIONS) == 3
    assert code_version(KERNEL_STORE_MIGRATIONS) == 4

    # B1 & B2: Create a root at v1, take v1 policy backup, upgrade to (store=2, policy=2), take v2 policy backup,
    # then upgrade via migrate_offline to (store=4, policy=3).
    b1_root = trusted_tmp / "part-b-upgraded-root"
    rt_b1_v1 = open_cloned_runtime(
        b1_root,
        os_,
        role="krev-v1",
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    try:
        b1_store_id = rt_b1_v1.policy.store_id
        clock.advance(dt.timedelta(seconds=5))
        b1_v1_pol_backup = create_policy_backup(rt_b1_v1.policy, os_, clock.now())
    finally:
        rt_b1_v1.close()

    clock.advance(dt.timedelta(seconds=5))
    mig_b1_to_v2 = migrate_offline(
        DaemonConfig(1, b1_root, b1_store_id, trusted_tmp / "b1.pem", trusted_tmp / "b1.key"),
        os_,
        policy_migrations=v2_policy,
        store_migrations=v2_store,
    )
    assert not mig_b1_to_v2.noop
    assert mig_b1_to_v2.policy_report.to_version == 2 and mig_b1_to_v2.store_report.to_version == 2

    rt_b1_v2 = open_runtime(b1_root, os_, store_migrations=v2_store, policy_migrations=v2_policy)
    try:
        b1_cred = seed_principal_and_credential(
            rt_b1_v2.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-b1"
        )
        clock.advance(dt.timedelta(seconds=5))
        b1_v2_pol_backup = create_policy_backup(rt_b1_v2.policy, os_, clock.now())
    finally:
        rt_b1_v2.close()

    saved_v2_policy_bytes = (b1_root / "policy" / "policy.db").read_bytes()
    v2_tpl = trusted_tmp / "part-b-v2-template"
    clone_owner_only_tree(b1_root, v2_tpl)

    clock.advance(dt.timedelta(seconds=5))
    mig_b1_to_v3 = migrate_offline(
        DaemonConfig(1, b1_root, b1_store_id, trusted_tmp / "b1.pem", trusted_tmp / "b1.key"),
        os_,
    )
    assert not mig_b1_to_v3.noop
    assert mig_b1_to_v3.policy_report.from_version == 2 and mig_b1_to_v3.policy_report.to_version == 3
    assert mig_b1_to_v3.store_report.status == "migrated"
    assert mig_b1_to_v3.store_report.from_version == 2 and mig_b1_to_v3.store_report.to_version == 4
    assert read_schema_info(b1_root / "store" / "brain.db") == SchemaInfo(4, 4, b1_store_id)

    # Clean up prior policy.replaced-* / store.replaced-* from setup so stage-creation checks start clean.
    for leftover in list(b1_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)

    v3_tpl = trusted_tmp / "part-b-v3-template"
    clone_owner_only_tree(b1_root, v3_tpl)

    # B1. Against upgraded (store=2, policy=3) root, admit_existing_pair, open_runtime, and PolicyStore.open
    # with v2_policy all raise UNSUPPORTED_VERSION before any mutation.
    b1_root_snap = digest_tree(b1_root)
    purposes: tuple[Literal["serve", "migrate"], ...] = ("serve", "migrate")
    for purpose in purposes:
        with pytest.raises(BrainError) as exc_b1_adm:
            adm_b1 = admit_existing_pair(
                b1_root,
                b1_store_id,
                os_,
                purpose=purpose,
                store_migrations=v2_store,
                policy_migrations=v2_policy,
            )
            adm_b1.release()
        assert exc_b1_adm.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(b1_root) == b1_root_snap

    b1_pol_snap = digest_tree(b1_root / "policy")
    b1_str_snap = digest_tree(b1_root / "store")
    with pytest.raises(BrainError) as exc_b1_open:
        rt_b1_bad = open_runtime(b1_root, os_, store_migrations=v2_store, policy_migrations=v2_policy)
        rt_b1_bad.close()
    assert exc_b1_open.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(b1_root / "policy") == b1_pol_snap
    assert digest_tree(b1_root / "store") == b1_str_snap

    with maintenance_lease(b1_root, os_) as (mroot_b1, mlease_b1):
        with pytest.raises(BrainError) as exc_b1_pol_open:
            pol_b1_bad = PolicyStore.open(mroot_b1, mlease_b1, os_, migrations=v2_policy)
            pol_b1_bad.close()
        assert exc_b1_pol_open.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(b1_root / "policy") == b1_pol_snap
    assert digest_tree(b1_root / "store") == b1_str_snap

    # B2. restore_policy with migrations=v2_policy or migrations=POLICY_MIGRATIONS against live v3 policy.db
    # raises UNSUPPORTED_VERSION before staging anything (no policy.* directories created).
    assert not any(name.startswith("policy.") for name in os.listdir(b1_root))
    for bad_bak, bad_migs in ((b1_v2_pol_backup, v2_policy), (b1_v1_pol_backup, POLICY_MIGRATIONS)):
        clock.advance(dt.timedelta(seconds=5))
        with maintenance_lease(b1_root, os_) as (mroot_b2, mlease_b2):
            with pytest.raises(BrainError) as exc_b2_restore:
                restore_policy(
                    mroot_b2,
                    mlease_b2,
                    os_,
                    bad_bak,
                    store_id=b1_store_id,
                    now=clock.now(),
                    migrations=bad_migs,
                )
            assert exc_b2_restore.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(b1_root / "policy") == b1_pol_snap
        assert digest_tree(b1_root / "store") == b1_str_snap
        assert not any(name.startswith("policy.") for name in os.listdir(b1_root))

    # Also verify restoring the v1 policy backup under KERNEL_POLICY_MIGRATIONS upgrades staged policy.db to v3.
    prev_b1_gen = _read_policy_state(b1_root / "policy" / "policy.db")["trust_generation"]
    assert isinstance(prev_b1_gen, int)
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(b1_root, os_) as (mroot_b2_ok, mlease_b2_ok):
        rep_b2_v1 = restore_policy(
            mroot_b2_ok,
            mlease_b2_ok,
            os_,
            b1_v1_pol_backup,
            store_id=b1_store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    b2_v1_info = read_schema_info(b1_root / "policy" / "policy.db")
    assert b2_v1_info is not None and b2_v1_info.schema_version == 3 and b2_v1_info.min_reader_version == 3
    assert rep_b2_v1.trust_generation is not None and rep_b2_v1.trust_generation > prev_b1_gen
    b2_v1_meta = _read_policy_state(b1_root / "policy" / "policy.db")["meta"]
    assert isinstance(b2_v1_meta, dict) and b2_v1_meta.get("store_published") == "1"
    adm_b2_v1 = admit_existing_pair(b1_root, b1_store_id, os_, purpose="serve")
    rt_b2_v1 = open_runtime_under_lease(adm_b2_v1)
    try:
        key_id_v1_up, key_bytes_v1_up = rt_b2_v1.policy.request_digest_key()
        assert key_id_v1_up and len(key_bytes_v1_up) == 32
    finally:
        rt_b2_v1.close()
    _ = b1_cred

    # B3. Even if live policy.db is at v2 while live store.db holds policy.workspace_register at handler_version=2,
    # restore_policy with v2_policy or POLICY_MIGRATIONS raises UNSUPPORTED_VERSION before staging anything.
    b3_root = trusted_tmp / "part-b3-store-hv2"
    clone_owner_only_tree(v3_tpl, b3_root)
    b3_store_id = b1_store_id
    b3_v1_pol_backup = b3_root / b1_v1_pol_backup.relative_to(b1_root)
    b3_v2_pol_backup = b3_root / b1_v2_pol_backup.relative_to(b1_root)
    adm_b3 = admit_existing_pair(b3_root, b3_store_id, os_, purpose="serve")
    rt_b3_v3 = open_runtime_under_lease(adm_b3)
    try:
        b3_cred = seed_principal_and_credential(
            rt_b3_v3.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-b3"
        )
        b3_reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=b3_cred.principal.principal_id,
            machine_id="dev-b3",
            alias="b3-ws",
            checkout_path=str(trusted_tmp / "b3-ws"),
            path_identity="dan:dev-b3:ws",
        )
        rt_b3_v3.policy.register_authorized_workspace(
            b3_reg,
            make_bootstrap_auth(
                store_id=b3_store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=b3_reg.subject_id,
                trust_generation=rt_b3_v3.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(minutes=30),
            ),
        )
        assert rt_b3_v3.store.reconcile_policy() == 1
        assert [e.handler_version for e in rt_b3_v3.store.entries() if e.kind == "policy.workspace_register"] == [2]
    finally:
        rt_b3_v3.close()

    for leftover in list(b3_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)
    for companion in ("policy.db-wal", "policy.db-shm"):
        (b3_root / "policy" / companion).unlink(missing_ok=True)
    (b3_root / "policy" / "policy.db").write_bytes(saved_v2_policy_bytes)
    os_.permissions.secure_file(b3_root / "policy" / "policy.db")
    b3_live_pol_info = read_schema_info(b3_root / "policy" / "policy.db")
    assert b3_live_pol_info is not None and b3_live_pol_info.schema_version == 2

    b3_pol_snap = digest_tree(b3_root / "policy")
    b3_str_snap = digest_tree(b3_root / "store")
    assert not any(name.startswith("policy.") for name in os.listdir(b3_root))
    for bad_b3_bak, bad_b3_migs in ((b3_v2_pol_backup, v2_policy), (b3_v1_pol_backup, POLICY_MIGRATIONS)):
        clock.advance(dt.timedelta(seconds=5))
        with maintenance_lease(b3_root, os_) as (mroot_b3, mlease_b3):
            with pytest.raises(BrainError) as exc_b3_restore:
                restore_policy(
                    mroot_b3,
                    mlease_b3,
                    os_,
                    bad_b3_bak,
                    store_id=b3_store_id,
                    now=clock.now(),
                    migrations=bad_b3_migs,
                )
            assert exc_b3_restore.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(b3_root / "policy") == b3_pol_snap
        assert digest_tree(b3_root / "store") == b3_str_snap
        assert not any(name.startswith("policy.") for name in os.listdir(b3_root))

    # B4a. Interrupted migration stage policy.migrating/READY with v3 policy.db alongside v2 live policy/
    # fences admit_existing_pair(..., policy_migrations=v2_policy) with UNSUPPORTED_VERSION and unchanged root bytes.
    b4a_root = trusted_tmp / "part-b4a-after-stage"
    clone_owner_only_tree(v2_tpl, b4a_root)
    b4a_store_id = b1_store_id

    clock.advance(dt.timedelta(seconds=5))
    mig_b4a = migrate_offline(
        DaemonConfig(1, b4a_root, b4a_store_id, trusted_tmp / "b4a.pem", trusted_tmp / "b4a.key"),
        os_,
    )
    assert mig_b4a.policy_report.replaced_dir is not None
    (b4a_root / "policy").rename(b4a_root / "policy.migrating")
    mig_b4a.policy_report.replaced_dir.rename(b4a_root / "policy")
    assert (b4a_root / "policy.migrating" / READY).is_file()
    assert read_schema_info(b4a_root / "policy" / "policy.db") is not None
    b4a_snap = digest_tree(b4a_root)
    for purpose in purposes:
        with pytest.raises(BrainError) as exc_b4a:
            adm_b4a = admit_existing_pair(
                b4a_root,
                b4a_store_id,
                os_,
                purpose=purpose,
                store_migrations=v2_store,
                policy_migrations=v2_policy,
            )
            adm_b4a.release()
        assert exc_b4a.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(b4a_root) == b4a_snap

    # B4b. Interrupted migration between_renames (policy/ moved aside, policy.migrating/READY holds v3):
    # admit_existing_pair refuses untouched, and open_runtime(..., policy_migrations=v2_policy) promotes v3 and
    # fails PolicyStore.open with UNSUPPORTED_VERSION before any authority mutation.
    b4b_root = trusted_tmp / "part-b4b-between-renames"
    clone_owner_only_tree(v2_tpl, b4b_root)
    b4b_store_id = b1_store_id

    clock.advance(dt.timedelta(seconds=5))
    mig_b4b = migrate_offline(
        DaemonConfig(1, b4b_root, b4b_store_id, trusted_tmp / "b4b.pem", trusted_tmp / "b4b.key"),
        os_,
    )
    assert mig_b4b.policy_report.replaced_dir is not None
    (b4b_root / "policy").rename(b4b_root / "policy.migrating")
    assert not (b4b_root / "policy").exists()
    assert (b4b_root / "policy.migrating" / READY).is_file()

    b4b_snap = digest_tree(b4b_root)
    with pytest.raises(BrainError) as exc_b4b_adm:
        adm_b4b = admit_existing_pair(
            b4b_root,
            b4b_store_id,
            os_,
            purpose="serve",
            store_migrations=v2_store,
            policy_migrations=v2_policy,
        )
        adm_b4b.release()
    assert exc_b4b_adm.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(b4b_root) == b4b_snap

    b4b_stage_hashes = digest_tree(b4b_root / "policy.migrating")
    b4b_store_hashes = digest_tree(b4b_root / "store")
    with pytest.raises(BrainError) as exc_b4b_open:
        rt_b4b_bad = open_runtime(b4b_root, os_, store_migrations=v2_store, policy_migrations=v2_policy)
        rt_b4b_bad.close()
    assert exc_b4b_open.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert not (b4b_root / "policy.migrating").exists()
    promoted_info = read_schema_info(b4b_root / "policy" / "policy.db")
    assert promoted_info is not None and promoted_info.schema_version == 3 and promoted_info.min_reader_version == 3
    assert digest_tree(b4b_root / "policy") == b4b_stage_hashes
    assert digest_tree(b4b_root / "store") == b4b_store_hashes


def test_historical_restore_policy_cannot_strip_main_store_fence_before_authority_mutation(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    import os
    import shutil
    import sqlite3
    import sys
    from typing import Literal

    from superbrain.composition.migrate_entry import migrate_offline
    from superbrain.core.kernel import DaemonConfig
    from superbrain.storage.backup import create_policy_backup, create_store_backup
    from superbrain.storage.cas import RetentionClass
    from superbrain.storage.restore import restore_policy
    from superbrain.storage.schema import (
        POLICY_MIGRATIONS,
        STORE_MIGRATIONS,
        SchemaInfo,
        code_version,
        ensure_readable,
        read_schema_info,
    )
    from superbrain.storage.sqlite import open_readonly
    from tests.support.inc2_transport import clone_owner_only_tree

    def _norm_blob(val: object) -> bytes:
        if isinstance(val, (bytes, bytearray, memoryview)):
            return bytes(val)
        return str(val).encode("utf-8")

    def _norm_row(row: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(bytes(v) if isinstance(v, (bytes, bytearray, memoryview)) else v for v in row)

    def _read_full_policy_state(policy_db: Path) -> dict[str, object]:
        db = open_readonly(policy_db)
        try:
            trust_rows = db.execute("SELECT id, generation FROM trust ORDER BY id").fetchall()
            assert len(trust_rows) == 1 and trust_rows[0][0] == 1 and type(trust_rows[0][1]) is int
            meta_rows = dict(db.execute("SELECT key, value FROM meta").fetchall())
            intents_rows = [
                (r[0], r[1], _norm_blob(r[2]), r[3])
                for r in db.execute(
                    "SELECT intent_id, kind, payload, created_at FROM intents ORDER BY rowid"
                ).fetchall()
            ]
            checkouts_rows = db.execute(
                "SELECT checkout_id, repo_id, checkout_path, alias FROM workspace_checkout ORDER BY checkout_id"
            ).fetchall()
            checkouts_all = [_norm_row(r) for r in db.execute("SELECT * FROM workspace_checkout ORDER BY rowid")]
            locators_all = [_norm_row(r) for r in db.execute("SELECT * FROM workspace_repo_locator ORDER BY rowid")]
            repo_policies_all = [_norm_row(r) for r in db.execute("SELECT * FROM repo_policy ORDER BY rowid")]
            grants_rows = db.execute(
                "SELECT principal_id, repo_id, granted_intent_id FROM repo_grant ORDER BY principal_id, repo_id"
            ).fetchall()
            creds_rows = [
                (r[0], r[1], _norm_blob(r[2]), r[3])
                for r in db.execute(
                    "SELECT id, principal_id, secret_digest, revoked_intent_id FROM credential ORDER BY id"
                ).fetchall()
            ]
            principals_rows = db.execute(
                "SELECT id, owner_id, harness_id, machine_id FROM principal ORDER BY id"
            ).fetchall()
            digest_key_rows = [
                (r[0], _norm_blob(r[1]))
                for r in db.execute("SELECT id, key_bytes FROM request_digest_key ORDER BY id").fetchall()
            ]
            tombstones_all = [_norm_row(r) for r in db.execute("SELECT * FROM tombstones ORDER BY rowid")]
            quarantine_all = [_norm_row(r) for r in db.execute("SELECT * FROM quarantine ORDER BY rowid")]
            return {
                "trust_generation": trust_rows[0][1],
                "meta": meta_rows,
                "intents": intents_rows,
                "checkouts": checkouts_rows,
                "checkouts_all": checkouts_all,
                "locators_all": locators_all,
                "repo_policies_all": repo_policies_all,
                "grants": grants_rows,
                "credentials": creds_rows,
                "principals": principals_rows,
                "request_digest_key": digest_key_rows,
                "tombstones": tombstones_all,
                "quarantine": quarantine_all,
            }
        finally:
            db.close()

    def _read_store_ws_ledger_versions(store_db: Path) -> list[int]:
        db = open_readonly(store_db)
        try:
            rows = db.execute(
                "SELECT handler_version FROM ledger WHERE kind = 'policy.workspace_register' ORDER BY sequence"
            ).fetchall()
            return [int(r[0]) for r in rows]
        finally:
            db.close()

    repo_root = Path(__file__).resolve().parents[2]
    hist_src, non_shallow = _ensure_historical_v2_src(repo_root, os_)
    part_a_ran = hist_src is not None
    if hist_src is not None:

        driver_path = trusted_tmp / "hist_r4_6a67b38_driver.py"
        driver_code = (
            "import datetime as dt\n"
            "import json\n"
            "import sys\n"
            "from pathlib import Path\n"
            "\n"
            "hist_src = Path(sys.argv[1]).resolve()\n"
            "repo_root = Path(sys.argv[2]).resolve()\n"
            "repo_src = (repo_root / 'src').resolve()\n"
            "sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != repo_src]\n"
            "sys.path[:0] = [str(hist_src), str(repo_root)]\n"
            "\n"
            "import superbrain\n"
            "from superbrain.adapters.os import os_adapters\n"
            "from superbrain.composition.migrate_entry import migrate_offline\n"
            "from superbrain.core.errors import BrainError\n"
            "from superbrain.core.kernel import DaemonConfig, WorkspaceRegistration\n"
            "from superbrain.storage.backup import create_policy_backup, create_store_backup\n"
            "from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS\n"
            "from superbrain.storage.layout import prepare_data_root\n"
            "from superbrain.storage.restore import restore_policy\n"
            "from superbrain.storage.runtime import admit_existing_pair, open_runtime\n"
            "from superbrain.storage.schema import code_version\n"
            "from superbrain.storage.writer import acquire_writer\n"
            "from tests.support.clock import FakeClock\n"
            "from tests.support.fs import digest_tree\n"
            "from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential\n"
            "\n"
            "def _dispatch(req: dict[str, object]) -> dict[str, object]:\n"
            "    assert Path(superbrain.__file__).resolve().is_relative_to(hist_src)\n"
            "    assert Path(restore_policy.__code__.co_filename).resolve().is_relative_to(hist_src)\n"
            "    assert Path(open_runtime.__code__.co_filename).resolve().is_relative_to(hist_src)\n"
            "    assert code_version(KERNEL_STORE_MIGRATIONS) == 2\n"
            "    assert code_version(KERNEL_POLICY_MIGRATIONS) == 2\n"
            "    mode = req['mode']\n"
            "    root = Path(str(req['root']))\n"
            "    base = Path(str(req['base']))\n"
            "    if mode == 'create_pending':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 8, 0, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        rt = open_runtime(\n"
            "            root,\n"
            "            adapters,\n"
            "            store_migrations=KERNEL_STORE_MIGRATIONS,\n"
            "            policy_migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "        )\n"
            "        try:\n"
            "            cred = seed_principal_and_credential(\n"
            "                rt.policy, owner_id='dan', harness_id='claude-code', machine_id='dev-hist-r4'\n"
            "            )\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            s_bak = create_store_backup(rt.store, adapters, clock.now())\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            reg = WorkspaceRegistration(\n"
            "                owner_id='dan',\n"
            "                principal_id=cred.principal.principal_id,\n"
            "                machine_id=cred.principal.machine_id,\n"
            "                alias='checkout',\n"
            "                checkout_path=str(base / 'old'),\n"
            "                path_identity='same-physical-checkout',\n"
            "            )\n"
            "            auth = make_bootstrap_auth(\n"
            "                store_id=rt.policy.store_id,\n"
            "                owner_id='dan',\n"
            "                action='workspace_register',\n"
            "                subject_id=reg.subject_id,\n"
            "                trust_generation=rt.policy.trust_generation(),\n"
            "                expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "            )\n"
            "            binding = rt.policy.register_authorized_workspace(reg, auth)\n"
            "            clock.advance(dt.timedelta(seconds=5))\n"
            "            p_bak = create_policy_backup(rt.policy, adapters, clock.now())\n"
            "            intents = rt.policy.intents()\n"
            "            ws_entries = [e for e in rt.store.entries() if e.kind == 'policy.workspace_register']\n"
            "            return {\n"
            "                'store_id': rt.policy.store_id,\n"
            "                'principal_id': cred.principal.principal_id,\n"
            "                'machine_id': cred.principal.machine_id,\n"
            "                'credential_id': cred.credential_id,\n"
            "                'token': cred.token,\n"
            "                'repo_id': binding.repo_id,\n"
            "                'checkout_id': binding.checkout_id,\n"
            "                'intent_id': auth.intent_id,\n"
            "                'store_backup': str(s_bak),\n"
            "                'policy_backup': str(p_bak),\n"
            "                'intents_count': len(intents),\n"
            "                'intent_has_subject': 'subject_id' in intents[0].payload,\n"
            "                'ledger_workspace_entries': len(ws_entries),\n"
            "            }\n"
            "        finally:\n"
            "            rt.close()\n"
            "    if mode == 'hist_restore_policy':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 0, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        droot = prepare_data_root(root, adapters)\n"
            "        lease = acquire_writer(droot, adapters)\n"
            "        try:\n"
            "            rep = restore_policy(\n"
            "                droot,\n"
            "                lease,\n"
            "                adapters,\n"
            "                Path(str(req['backup'])),\n"
            "                store_id=str(req['store_id']),\n"
            "                now=clock.now(),\n"
            "                migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "            )\n"
            "        finally:\n"
            "            lease.release()\n"
            "        return {'status': 'accepted', 'trust_generation': rep.trust_generation}\n"
            "    if mode == 'probe_preadmission':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 15, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        sid = str(req['store_id'])\n"
            "        out: dict[str, object] = {}\n"
            "        for p_label, p_val in (('admit_serve', 'serve'), ('admit_migrate', 'migrate')):\n"
            "            snap_before = digest_tree(root)\n"
            "            try:\n"
            "                adm = admit_existing_pair(root, sid, adapters, purpose=p_val)\n"
            "                try:\n"
            "                    out[p_label] = 'accepted'\n"
            "                finally:\n"
            "                    adm.release()\n"
            "            except BrainError as err:\n"
            "                out[p_label] = err.code.value\n"
            "            out[f'{p_label}_unchanged'] = digest_tree(root) == snap_before\n"
            "        snap_before_mig = digest_tree(root)\n"
            "        try:\n"
            "            migrate_offline(DaemonConfig(1, root, sid, base / 'c.pem', base / 'c.key'), adapters)\n"
            "            out['migrate_offline'] = 'accepted'\n"
            "        except BrainError as err:\n"
            "            out['migrate_offline'] = err.code.value\n"
            "        out['migrate_offline_unchanged'] = digest_tree(root) == snap_before_mig\n"
            "        return out\n"
            "    if mode == 'probe_open_and_register_ws':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 30, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        stage_reached = 'open_runtime'\n"
            "        error_code: str | None = None\n"
            "        before_intents: int | None = None\n"
            "        after_intents: int | None = None\n"
            "        live_path_changed = False\n"
            "        try:\n"
            "            rt = open_runtime(\n"
            "                root,\n"
            "                adapters,\n"
            "                store_migrations=KERNEL_STORE_MIGRATIONS,\n"
            "                policy_migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "            )\n"
            "            try:\n"
            "                before_intents = len(rt.policy.intents())\n"
            "                stage_reached = 'register_authorized_workspace'\n"
            "                reg = WorkspaceRegistration(\n"
            "                    owner_id='dan',\n"
            "                    principal_id=str(req['principal_id']),\n"
            "                    machine_id=str(req['machine_id']),\n"
            "                    alias='checkout',\n"
            "                    checkout_path=str(base / 'new'),\n"
            "                    path_identity='same-physical-checkout',\n"
            "                )\n"
            "                rt.policy.register_authorized_workspace(\n"
            "                    reg,\n"
            "                    make_bootstrap_auth(\n"
            "                        store_id=rt.policy.store_id,\n"
            "                        owner_id='dan',\n"
            "                        action='workspace_register',\n"
            "                        subject_id=reg.subject_id,\n"
            "                        trust_generation=rt.policy.trust_generation(),\n"
            "                        expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "                    ),\n"
            "                )\n"
            "                after_intents = len(rt.policy.intents())\n"
            "                first_chk = next(iter(rt.policy.snapshot().checkouts.values()))\n"
            "                live_path_changed = first_chk.checkout_path == reg.checkout_path\n"
            "                stage_reached = 'reconcile_policy'\n"
            "                rt.store.reconcile_policy()\n"
            "                stage_reached = 'completed'\n"
            "            finally:\n"
            "                rt.close()\n"
            "        except BrainError as err:\n"
            "            error_code = err.code.value\n"
            "        return {\n"
            "            'stage_reached': stage_reached,\n"
            "            'error_code': error_code,\n"
            "            'before_intents': before_intents,\n"
            "            'after_intents': after_intents,\n"
            "            'live_path_changed': live_path_changed,\n"
            "        }\n"
            "    if mode == 'probe_open_and_revoke':\n"
            "        clock = FakeClock(dt.datetime(2026, 11, 6, 9, 45, tzinfo=dt.UTC))\n"
            "        adapters = os_adapters(clock)\n"
            "        stage_reached = 'open_runtime'\n"
            "        error_code_rev: str | None = None\n"
            "        before_intents_rev: int | None = None\n"
            "        after_intents_rev: int | None = None\n"
            "        credential_revoked = False\n"
            "        try:\n"
            "            rt = open_runtime(\n"
            "                root,\n"
            "                adapters,\n"
            "                store_migrations=KERNEL_STORE_MIGRATIONS,\n"
            "                policy_migrations=KERNEL_POLICY_MIGRATIONS,\n"
            "            )\n"
            "            try:\n"
            "                before_intents_rev = len(rt.policy.intents())\n"
            "                stage_reached = 'record_authorized_revocation'\n"
            "                rt.policy.record_authorized_revocation(\n"
            "                    str(req['credential_id']),\n"
            "                    make_bootstrap_auth(\n"
            "                        store_id=rt.policy.store_id,\n"
            "                        owner_id='dan',\n"
            "                        action='credential_revoke',\n"
            "                        subject_id=str(req['credential_id']),\n"
            "                        trust_generation=rt.policy.trust_generation(),\n"
            "                        expires_at=clock.now() + dt.timedelta(minutes=5),\n"
            "                    ),\n"
            "                )\n"
            "                after_intents_rev = len(rt.policy.intents())\n"
            "                credential_revoked = True\n"
            "                stage_reached = 'reconcile_policy'\n"
            "                rt.store.reconcile_policy()\n"
            "                stage_reached = 'completed'\n"
            "            finally:\n"
            "                rt.close()\n"
            "        except BrainError as err:\n"
            "            error_code_rev = err.code.value\n"
            "        return {\n"
            "            'stage_reached': stage_reached,\n"
            "            'error_code': error_code_rev,\n"
            "            'before_intents': before_intents_rev,\n"
            "            'after_intents': after_intents_rev,\n"
            "            'credential_revoked': credential_revoked,\n"
            "        }\n"
            "    raise AssertionError(f'unknown mode: {mode}')\n"
            "\n"
            "for raw_line in sys.stdin:\n"
            "    if not raw_line.strip():\n"
            "        continue\n"
            "    resp = _dispatch(json.loads(raw_line))\n"
            "    print(json.dumps(resp), flush=True)\n"
        )
        driver_path.write_text(driver_code, encoding="utf-8")
        os_.permissions.secure_file(driver_path)

        r4_worker = BoundedJsonWorker(
            [sys.executable, str(driver_path), str(hist_src), str(repo_root)],
            cwd=repo_root,
            stderr_path=trusted_tmp / "hist_r4_6a67b38_worker.stderr.log",
            label="historical r4 worker",
        )
        _close_r4_worker = r4_worker.close
        _run_r4_child = r4_worker.request

        try:
            part_a_base = trusted_tmp / "part-a-r4-6a67b38"
            part_a_base.mkdir()
            os_.permissions.secure_directory(part_a_base)
            root_hist = part_a_base / "store"

            # (a) 6a67b38 child creates (store=2, policy=2) root, commits pending 6-key workspace_register (intents==1,
            # checkout_path == old), takes valid v2 policy & store backups, and closes before Store.reconcile_policy().
            created = _run_r4_child(
                {
                    "mode": "create_pending",
                    "root": str(root_hist),
                    "base": str(part_a_base),
                }
            )
            assert created["intents_count"] == 1
            assert created["intent_has_subject"] is False
            assert created["ledger_workspace_entries"] == 0
            hist_store_id = str(created["store_id"])
            hist_principal_id = str(created["principal_id"])
            hist_machine_id = str(created["machine_id"])
            hist_credential_id = str(created["credential_id"])
            hist_token = str(created["token"])
            hist_repo_id = str(created["repo_id"])
            hist_checkout_id = str(created["checkout_id"])
            hist_intent_id = str(created["intent_id"])
            hist_store_backup = Path(str(created["store_backup"]))
            hist_policy_backup = Path(str(created["policy_backup"]))
            assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(2, 2, hist_store_id)
            assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(2, 2, hist_store_id)

            # (b) Current Code refuses admit_existing_pair("serve") and open_runtime on (2, 2) with MIGRATION_REQUIRED
            # and zero mutations, runs migrate_offline upgrading BOTH policy (2 -> 3) and store (2 -> 3), opens runtime
            # under lease, and reconciles handler_version == 2 (subject_id is None).
            snap_pre_mig = digest_tree(root_hist)
            with pytest.raises(BrainError) as exc_pre_admit:
                bad_adm = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                bad_adm.release()
            assert exc_pre_admit.value.code is ErrorCode.MIGRATION_REQUIRED
            assert digest_tree(root_hist) == snap_pre_mig

            snap_pol_pre = digest_tree(root_hist / "policy")
            snap_str_pre = digest_tree(root_hist / "store")
            with pytest.raises(BrainError) as exc_pre_open:
                bad_rt = open_runtime(
                    root_hist,
                    os_,
                    store_migrations=KERNEL_STORE_MIGRATIONS,
                    policy_migrations=KERNEL_POLICY_MIGRATIONS,
                )
                bad_rt.close()
            assert exc_pre_open.value.code is ErrorCode.MIGRATION_REQUIRED
            assert digest_tree(root_hist / "policy") == snap_pol_pre
            assert digest_tree(root_hist / "store") == snap_str_pre

            clock.advance(dt.timedelta(minutes=1))
            mig_initial = migrate_offline(
                DaemonConfig(1, root_hist, hist_store_id, part_a_base / "server.pem", part_a_base / "server.key"),
                os_,
            )
            assert not mig_initial.noop
            assert mig_initial.policy_report.status == "migrated"
            assert mig_initial.policy_report.from_version == 2 and mig_initial.policy_report.to_version == 3
            assert mig_initial.policy_report.backup is not None
            maint_v2_policy_backup = mig_initial.policy_report.backup
            assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(3, 3, hist_store_id)

            clock.advance(dt.timedelta(seconds=5))
            adm_reconcile = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
            rt_reconcile = open_runtime_under_lease(adm_reconcile)
            try:
                ws_reconciled = [e for e in rt_reconcile.store.entries() if e.kind == "policy.workspace_register"]
                assert len(ws_reconciled) == 1
                assert ws_reconciled[0].handler_version == 2
                assert ws_reconciled[0].meta["intent_id"] == hist_intent_id
                assert ws_reconciled[0].meta["subject_id"] is None
                assert rt_reconcile.policy.snapshot().checkouts[hist_checkout_id].checkout_path == str(
                    part_a_base / "old"
                )
                assert rt_reconcile.policy.resolve_credential(hist_token).principal_id == hist_principal_id
            finally:
                rt_reconcile.close()

            # (c) Before historical restore_policy, 6a67b38 open_runtime fails at open_runtime with UNSUPPORTED_VERSION.
            pol_before_c = digest_tree(root_hist / "policy")
            str_before_c = digest_tree(root_hist / "store")
            state_before_c = _read_full_policy_state(root_hist / "policy" / "policy.db")
            res_before_restore = _run_r4_child(
                {
                    "mode": "probe_open_and_register_ws",
                    "root": str(root_hist),
                    "base": str(part_a_base),
                    "principal_id": hist_principal_id,
                    "machine_id": hist_machine_id,
                }
            )
            assert res_before_restore == {
                "stage_reached": "open_runtime",
                "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
                "before_intents": None,
                "after_intents": None,
                "live_path_changed": False,
            }
            assert digest_tree(root_hist / "policy") == pol_before_c
            assert digest_tree(root_hist / "store") == str_before_c
            assert _read_full_policy_state(root_hist / "policy" / "policy.db") == state_before_c

            def _assert_hist_preadmission_fenced(label: str) -> None:
                root_snap_pre = digest_tree(root_hist)
                preadm = _run_r4_child(
                    {
                        "mode": "probe_preadmission",
                        "root": str(root_hist),
                        "base": str(part_a_base),
                        "store_id": hist_store_id,
                    }
                )
                assert preadm == {
                    "admit_serve": ErrorCode.UNSUPPORTED_VERSION.value,
                    "admit_serve_unchanged": True,
                    "admit_migrate": ErrorCode.UNSUPPORTED_VERSION.value,
                    "admit_migrate_unchanged": True,
                    "migrate_offline": ErrorCode.UNSUPPORTED_VERSION.value,
                    "migrate_offline_unchanged": True,
                }, f"{label}: unexpected pre-admission result {preadm}"
                assert digest_tree(root_hist) == root_snap_pre, (
                    f"{label}: root bytes mutated during pre-admission refusal"
                )

            def _assert_hist_open_mutations_fenced(
                label: str,
                expected_ledger_versions: list[int],
            ) -> None:
                store_snap = digest_tree(root_hist / "store")
                pol_state_expected = _read_full_policy_state(root_hist / "policy" / "policy.db")
                intents_list = pol_state_expected["intents"]
                assert isinstance(intents_list, list) and len(intents_list) == 1
                assert intents_list[0][0] == hist_intent_id
                assert pol_state_expected["checkouts"] == [
                    (hist_checkout_id, hist_repo_id, str(part_a_base / "old"), "checkout")
                ]
                creds_list = pol_state_expected["credentials"]
                assert isinstance(creds_list, list) and len(creds_list) == 1
                assert creds_list[0][0] == hist_credential_id and creds_list[0][3] is None
                assert pol_state_expected["principals"] == [(hist_principal_id, "dan", "claude-code", hist_machine_id)]
                grants_list = pol_state_expected["grants"]
                assert isinstance(grants_list, list) and len(grants_list) == 1
                dk_list = pol_state_expected["request_digest_key"]
                assert isinstance(dk_list, list) and len(dk_list) == 1 and len(dk_list[0][1]) == 32

                ws_res = _run_r4_child(
                    {
                        "mode": "probe_open_and_register_ws",
                        "root": str(root_hist),
                        "base": str(part_a_base),
                        "principal_id": hist_principal_id,
                        "machine_id": hist_machine_id,
                    }
                )
                assert ws_res == {
                    "stage_reached": "open_runtime",
                    "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
                    "before_intents": None,
                    "after_intents": None,
                    "live_path_changed": False,
                }, f"{label}: historical 6a67b38 restore_policy stripped fence and mutated policy: {ws_res}"
                assert digest_tree(root_hist / "store") == store_snap, (
                    f"{label}: store/ bytes changed on ws open_runtime"
                )
                assert _read_store_ws_ledger_versions(root_hist / "store" / "brain.db") == expected_ledger_versions
                assert _read_full_policy_state(root_hist / "policy" / "policy.db") == pol_state_expected

                rev_res = _run_r4_child(
                    {
                        "mode": "probe_open_and_revoke",
                        "root": str(root_hist),
                        "base": str(part_a_base),
                        "credential_id": hist_credential_id,
                    }
                )
                assert rev_res == {
                    "stage_reached": "open_runtime",
                    "error_code": ErrorCode.UNSUPPORTED_VERSION.value,
                    "before_intents": None,
                    "after_intents": None,
                    "credential_revoked": False,
                }, f"{label}: historical 6a67b38 restore_policy allowed revocation mutation: {rev_res}"
                assert digest_tree(root_hist / "store") == store_snap, (
                    f"{label}: store/ bytes changed on rev open_runtime"
                )
                assert _read_store_ws_ledger_versions(root_hist / "store" / "brain.db") == expected_ledger_versions
                assert _read_full_policy_state(root_hist / "policy" / "policy.db") == pol_state_expected

            # (d), (e), (f) Execute 6a67b38's restore_policy for BOTH 6a67b38's v2 policy backup AND migrate_offline's
            # v2 maintenance policy backup, verify 6a67b38 runtime & admission are fenced at (policy=2, store=3) before
            # authority mutation, and verify Current Code recovers (policy=2, store=3) -> (policy=3, store=3) cleanly.
            for pass_idx, (bak_label, v2_pol_bak) in enumerate(
                (
                    ("hist-6a67b38-v2-policy-backup", hist_policy_backup),
                    ("migrate-maint-v2-policy-backup", maint_v2_policy_backup),
                )
            ):
                hist_restore_res = _run_r4_child(
                    {
                        "mode": "hist_restore_policy",
                        "root": str(root_hist),
                        "base": str(part_a_base),
                        "backup": str(v2_pol_bak),
                        "store_id": hist_store_id,
                    }
                )
                assert hist_restore_res["status"] == "accepted"
                assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(2, 2, hist_store_id)

                if pass_idx == 0:
                    # Pass 0 reproduces probe_historical_restore.py directly first, then checks pre-admission & v4.
                    _assert_hist_open_mutations_fenced(f"step-e-{bak_label}", expected_ledger_versions=[2])
                    assert mig_initial.store_report.status == "migrated"
                    assert mig_initial.store_report.from_version == 2 and mig_initial.store_report.to_version == 4
                    assert mig_initial.store_report.backup is not None
                    assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)
                    _assert_hist_preadmission_fenced(f"step-e-{bak_label}-preadm")
                else:
                    # Pass 1 runs pre-admission checks first (on fresh DELETE-mode restored policy.db) then open_runtime
                    assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)
                    _assert_hist_preadmission_fenced(f"step-e-{bak_label}-preadm")
                    _assert_hist_open_mutations_fenced(f"step-e-{bak_label}", expected_ledger_versions=[2])

                # (f) Current Code refuses (policy=2, store=4) before migration with MIGRATION_REQUIRED & zero mutations
                # then upgrades (policy=2, store=4) -> (policy=3, store=4) via migrate_offline.
                snap_mixed_root = digest_tree(root_hist)
                with pytest.raises(BrainError) as exc_cur_admit:
                    bad_cur_adm = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                    bad_cur_adm.release()
                assert exc_cur_admit.value.code is ErrorCode.MIGRATION_REQUIRED
                assert digest_tree(root_hist) == snap_mixed_root

                snap_mixed_pol = digest_tree(root_hist / "policy")
                snap_mixed_str = digest_tree(root_hist / "store")
                with pytest.raises(BrainError) as exc_cur_open:
                    bad_cur_rt = open_runtime(
                        root_hist,
                        os_,
                        store_migrations=KERNEL_STORE_MIGRATIONS,
                        policy_migrations=KERNEL_POLICY_MIGRATIONS,
                    )
                    bad_cur_rt.close()
                assert exc_cur_open.value.code is ErrorCode.MIGRATION_REQUIRED
                assert digest_tree(root_hist / "policy") == snap_mixed_pol
                assert digest_tree(root_hist / "store") == snap_mixed_str

                clock.advance(dt.timedelta(minutes=1))
                mig_recover = migrate_offline(
                    DaemonConfig(1, root_hist, hist_store_id, part_a_base / "server.pem", part_a_base / "server.key"),
                    os_,
                )
                assert not mig_recover.noop
                assert mig_recover.policy_report.status == "migrated"
                assert mig_recover.policy_report.from_version == 2 and mig_recover.policy_report.to_version == 3
                assert mig_recover.store_report.status == "skipped"
                assert mig_recover.store_report.from_version == 4 and mig_recover.store_report.to_version == 4
                assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(3, 3, hist_store_id)
                assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)

                clock.advance(dt.timedelta(seconds=5))
                adm_recovered = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                rt_recovered = open_runtime_under_lease(adm_recovered)
                try:
                    assert rt_recovered.policy.store_id == hist_store_id
                    assert rt_recovered.store.store_id == hist_store_id
                    assert rt_recovered.policy.resolve_credential(hist_token).principal_id == hist_principal_id
                    snap_rec = rt_recovered.policy.snapshot()
                    assert snap_rec.checkouts[hist_checkout_id].repo_id == hist_repo_id
                    assert snap_rec.checkouts[hist_checkout_id].checkout_path == str(part_a_base / "old")
                    assert (hist_principal_id, hist_repo_id) in snap_rec.grants
                    assert rt_recovered.store.reconcile_policy() == 0
                    ws_rec_entries = [e for e in rt_recovered.store.entries() if e.kind == "policy.workspace_register"]
                    assert [e.handler_version for e in ws_rec_entries] == [2]

                    # Unproven replay of retained 6-key intent_id refuses with REVISION_CONFLICT and zero mutations.
                    pol_state_pre_replay = _read_full_policy_state(root_hist / "policy" / "policy.db")
                    reg_replay_6key = WorkspaceRegistration(
                        owner_id="dan",
                        principal_id=hist_principal_id,
                        machine_id=hist_machine_id,
                        alias="checkout",
                        checkout_path=str(part_a_base / "old"),
                        path_identity="same-physical-checkout",
                    )
                    with pytest.raises(BrainError) as exc_unproven:
                        rt_recovered.policy.register_authorized_workspace(
                            reg_replay_6key,
                            make_bootstrap_auth(
                                intent_id=hist_intent_id,
                                store_id=hist_store_id,
                                owner_id="dan",
                                action="workspace_register",
                                subject_id=reg_replay_6key.subject_id,
                                trust_generation=rt_recovered.policy.trust_generation(),
                                expires_at=clock.now() + dt.timedelta(hours=1),
                            ),
                        )
                    assert exc_unproven.value.code is ErrorCode.REVISION_CONFLICT
                    assert _read_full_policy_state(root_hist / "policy" / "policy.db") == pol_state_pre_replay

                    if pass_idx == 1:
                        # Fresh 7-key v2 workspace_register succeeds, keeping repo_id & checkout_id and appending row.
                        reg_fresh_v2 = WorkspaceRegistration(
                            owner_id="dan",
                            principal_id=hist_principal_id,
                            machine_id=hist_machine_id,
                            alias="checkout",
                            checkout_path=str(part_a_base / "recovered-new"),
                            path_identity="same-physical-checkout",
                        )
                        fresh_intent_id = new_id()
                        bind_fresh = rt_recovered.policy.register_authorized_workspace(
                            reg_fresh_v2,
                            make_bootstrap_auth(
                                intent_id=fresh_intent_id,
                                store_id=hist_store_id,
                                owner_id="dan",
                                action="workspace_register",
                                subject_id=reg_fresh_v2.subject_id,
                                trust_generation=rt_recovered.policy.trust_generation(),
                                expires_at=clock.now() + dt.timedelta(hours=1),
                            ),
                        )
                        assert bind_fresh.repo_id == hist_repo_id
                        assert bind_fresh.checkout_id == hist_checkout_id
                        assert rt_recovered.store.reconcile_policy() == 1
                        ws_after_fresh = [
                            e for e in rt_recovered.store.entries() if e.kind == "policy.workspace_register"
                        ]
                        assert [e.handler_version for e in ws_after_fresh] == [2, 2]
                        assert ws_after_fresh[1].meta["intent_id"] == fresh_intent_id
                        assert ws_after_fresh[1].meta["subject_id"] == reg_fresh_v2.subject_id
                finally:
                    rt_recovered.close()

            # (g) Current Code restore_store of older v2 store backup (and v2 store_full maintenance backup) upgrades
            # staged brain.db to (4, 4), so even if 6a67b38 subsequently executes 6a67b38's restore_policy (v2 backup),
            # 6a67b38 admit_existing_pair, migrate_offline, and open_runtime STILL fail with UNSUPPORTED_VERSION before
            # any authority mutation!
            assert mig_initial.store_report.backup is not None
            maint_v2_store_full_backup = mig_initial.store_report.backup
            for s_bak_label, s_bak_path in (
                ("hist-6a67b38-v2-store-backup", hist_store_backup),
                ("migrate-maint-v2-store-full-backup", maint_v2_store_full_backup),
            ):
                clock.advance(dt.timedelta(minutes=1))
                with maintenance_lease(root_hist, os_) as (mroot_g, mlease_g):
                    pol_g = PolicyStore.open(mroot_g, mlease_g, os_, migrations=KERNEL_POLICY_MIGRATIONS)
                    try:
                        restore_store(
                            mroot_g,
                            mlease_g,
                            os_,
                            s_bak_path,
                            pol_g,
                            clock.now(),
                            migrations=KERNEL_STORE_MIGRATIONS,
                        )
                    finally:
                        pol_g.close()
                assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)

                hist_restore_after_s = _run_r4_child(
                    {
                        "mode": "hist_restore_policy",
                        "root": str(root_hist),
                        "base": str(part_a_base),
                        "backup": str(hist_policy_backup),
                        "store_id": hist_store_id,
                    }
                )
                assert hist_restore_after_s["status"] == "accepted"
                assert read_schema_info(root_hist / "policy" / "policy.db") == SchemaInfo(2, 2, hist_store_id)
                assert read_schema_info(root_hist / "store" / "brain.db") == SchemaInfo(4, 4, hist_store_id)

                _assert_hist_preadmission_fenced(f"step-g-{s_bak_label}-preadm")
                _assert_hist_open_mutations_fenced(f"step-g-{s_bak_label}", expected_ledger_versions=[])

                clock.advance(dt.timedelta(minutes=1))
                mig_g_rec = migrate_offline(
                    DaemonConfig(1, root_hist, hist_store_id, part_a_base / "server.pem", part_a_base / "server.key"),
                    os_,
                )
                assert mig_g_rec.policy_report.status == "migrated" and mig_g_rec.policy_report.to_version == 3
                assert mig_g_rec.store_report.status == "skipped" and mig_g_rec.store_report.to_version == 4
                adm_g = admit_existing_pair(root_hist, hist_store_id, os_, purpose="serve")
                rt_g = open_runtime_under_lease(adm_g)
                try:
                    assert [
                        e.handler_version for e in rt_g.store.entries() if e.kind == "policy.workspace_register"
                    ] == [2]
                finally:
                    rt_g.close()
        finally:
            _close_r4_worker()

    if non_shallow:
        assert part_a_ran is True

    # --- Part B: Unconditional Shallow-Clone-Safe In-Process Checks ---
    v2_policy = KERNEL_POLICY_MIGRATIONS[:2]
    v2_store = KERNEL_STORE_MIGRATIONS[:2]
    v3_store = KERNEL_STORE_MIGRATIONS[:3]
    assert code_version(v2_policy) == 2
    assert code_version(v2_store) == 2
    assert code_version(v3_store) == 3
    assert code_version(KERNEL_POLICY_MIGRATIONS) == 3
    assert code_version(KERNEL_STORE_MIGRATIONS) == 4

    # B1. Build (store=4, policy=3) root from v1 -> v2 -> (4, 3) with v1/v2/v4 backups and handler_version=2 history.
    pb_root = trusted_tmp / "part-b-r4-root"
    rt_pb_v1 = open_cloned_runtime(
        pb_root,
        os_,
        role="krev-v1",
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    try:
        pb_store_id = rt_pb_v1.policy.store_id
        pb_blob_digest = rt_pb_v1.store.store_content(b"pb-v1-blob", "evidence", new_id(), RetentionClass.DURABLE, None)
        clock.advance(dt.timedelta(seconds=5))
        pb_v1_store_backup = create_store_backup(rt_pb_v1.store, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        pb_v1_pol_backup = create_policy_backup(rt_pb_v1.policy, os_, clock.now())
    finally:
        rt_pb_v1.close()

    clock.advance(dt.timedelta(seconds=5))
    mig_pb_v2 = migrate_offline(
        DaemonConfig(1, pb_root, pb_store_id, trusted_tmp / "pb.pem", trusted_tmp / "pb.key"),
        os_,
        policy_migrations=v2_policy,
        store_migrations=v2_store,
    )
    assert mig_pb_v2.store_report.backup is not None
    pb_v1_store_full_backup = mig_pb_v2.store_report.backup

    rt_pb_v2 = open_runtime(pb_root, os_, store_migrations=v2_store, policy_migrations=v2_policy)
    try:
        pb_cred = seed_principal_and_credential(
            rt_pb_v2.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-pb"
        )
        clock.advance(dt.timedelta(seconds=5))
        pb_v2_store_backup = create_store_backup(rt_pb_v2.store, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        pb_v2_pol_backup = create_policy_backup(rt_pb_v2.policy, os_, clock.now())
    finally:
        rt_pb_v2.close()

    saved_pb_pol_v2 = (pb_root / "policy" / "policy.db").read_bytes()
    v2_pb_tpl = trusted_tmp / "part-b-pb-v2-tpl"
    clone_owner_only_tree(pb_root, v2_pb_tpl)

    clock.advance(dt.timedelta(seconds=5))
    mig_pb_v3 = migrate_offline(
        DaemonConfig(1, pb_root, pb_store_id, trusted_tmp / "pb.pem", trusted_tmp / "pb.key"),
        os_,
    )
    assert mig_pb_v3.policy_report.to_version == 3 and mig_pb_v3.store_report.to_version == 4
    assert mig_pb_v3.store_report.backup is not None
    pb_v2_store_full_backup = mig_pb_v3.store_report.backup

    adm_pb = admit_existing_pair(pb_root, pb_store_id, os_, purpose="serve")
    rt_pb_v3 = open_runtime_under_lease(adm_pb)
    try:
        pb_reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=pb_cred.principal.principal_id,
            machine_id="dev-pb",
            alias="pb-ws",
            checkout_path=str(trusted_tmp / "pb-ws"),
            path_identity="dan:dev-pb:ws",
        )
        rt_pb_v3.policy.register_authorized_workspace(
            pb_reg,
            make_bootstrap_auth(
                store_id=pb_store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=pb_reg.subject_id,
                trust_generation=rt_pb_v3.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(minutes=30),
            ),
        )
        assert rt_pb_v3.store.reconcile_policy() == 1
        clock.advance(dt.timedelta(seconds=5))
        pb_v3_store_backup = create_store_backup(rt_pb_v3.store, os_, clock.now())
    finally:
        rt_pb_v3.close()

    for leftover in list(pb_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)

    # Verify restore_policy with v2_policy or POLICY_MIGRATIONS fails with UNSUPPORTED_VERSION on (store=3, policy=3).
    pb_pol_snap = digest_tree(pb_root / "policy")
    pb_str_snap = digest_tree(pb_root / "store")
    for bad_pol_bak, bad_pol_migs in ((pb_v2_pol_backup, v2_policy), (pb_v1_pol_backup, POLICY_MIGRATIONS)):
        clock.advance(dt.timedelta(seconds=5))
        with maintenance_lease(pb_root, os_) as (mroot_pb, mlease_pb):
            with pytest.raises(BrainError) as exc_pb_rpol:
                restore_policy(
                    mroot_pb,
                    mlease_pb,
                    os_,
                    bad_pol_bak,
                    store_id=pb_store_id,
                    now=clock.now(),
                    migrations=bad_pol_migs,
                )
            assert exc_pb_rpol.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(pb_root / "policy") == pb_pol_snap
        assert digest_tree(pb_root / "store") == pb_str_snap
        assert not any(name.startswith("policy.") for name in os.listdir(pb_root))

    # B2. Verify restore_store with older migrations (v2_store / STORE_MIGRATIONS) fails with UNSUPPORTED_VERSION
    # before staging when open policy is v3 OR live store.db is v3 OR live store.db has handler_version >= 2.
    with maintenance_lease(pb_root, os_) as (mroot_pb_s, mlease_pb_s):
        pol_pb_v3 = PolicyStore.open(mroot_pb_s, mlease_pb_s, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            for bad_s_bak, bad_s_migs in ((pb_v2_store_backup, v2_store), (pb_v1_store_backup, STORE_MIGRATIONS)):
                clock.advance(dt.timedelta(seconds=5))
                with pytest.raises(BrainError) as exc_pb_rstore:
                    restore_store(
                        mroot_pb_s,
                        mlease_pb_s,
                        os_,
                        bad_s_bak,
                        pol_pb_v3,
                        clock.now(),
                        migrations=bad_s_migs,
                    )
                assert exc_pb_rstore.value.code is ErrorCode.UNSUPPORTED_VERSION
                assert digest_tree(pb_root / "store") == pb_str_snap
                assert not any(name.startswith("store.") for name in os.listdir(pb_root))
        finally:
            pol_pb_v3.close()

    # Case B2b: open policy is v3 while live store.db is v2 -> restore_store(..., migrations=v2_store) refuses.
    p3s2_root = trusted_tmp / "part-b-p3-s2"
    clone_owner_only_tree(v2_pb_tpl, p3s2_root)
    p3s2_sid = pb_store_id
    p3s2_v2_sbak = p3s2_root / pb_v2_store_backup.relative_to(pb_root)
    clock.advance(dt.timedelta(seconds=5))
    migrate_offline(
        DaemonConfig(1, p3s2_root, p3s2_sid, trusted_tmp / "p3s2.pem", trusted_tmp / "p3s2.key"),
        os_,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
        store_migrations=v2_store,
    )
    for leftover in list(p3s2_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)
    p3s2_store_snap = digest_tree(p3s2_root / "store")
    with maintenance_lease(p3s2_root, os_) as (mr_p3s2, ml_p3s2):
        pol_p3s2 = PolicyStore.open(mr_p3s2, ml_p3s2, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            with pytest.raises(BrainError) as exc_p3s2:
                restore_store(
                    mr_p3s2,
                    ml_p3s2,
                    os_,
                    p3s2_v2_sbak,
                    pol_p3s2,
                    clock.now(),
                    migrations=v2_store,
                )
            assert exc_p3s2.value.code is ErrorCode.UNSUPPORTED_VERSION
            assert digest_tree(p3s2_root / "store") == p3s2_store_snap
            assert not any(name.startswith("store.") for name in os.listdir(p3s2_root))
        finally:
            pol_p3s2.close()

    # Case B2c: open policy is v2 while live store.db has (2, 2) meta + handler_version=2 ledger row -> refuses.
    hv2_root = trusted_tmp / "part-b-hv2-only"
    clone_owner_only_tree(v2_pb_tpl, hv2_root)
    hv2_sid = pb_store_id
    hv2_v2_sbak = hv2_root / pb_v2_store_backup.relative_to(pb_root)
    clock.advance(dt.timedelta(seconds=5))
    migrate_offline(DaemonConfig(1, hv2_root, hv2_sid, trusted_tmp / "hv2.pem", trusted_tmp / "hv2.key"), os_)
    adm_hv2 = admit_existing_pair(hv2_root, hv2_sid, os_, purpose="serve")
    rt_hv2 = open_runtime_under_lease(adm_hv2)
    try:
        hv2_cred = seed_principal_and_credential(
            rt_hv2.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-hv2"
        )
        hv2_reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=hv2_cred.principal.principal_id,
            machine_id="dev-hv2",
            alias="hv2-ws",
            checkout_path=str(trusted_tmp / "hv2-ws"),
            path_identity="dan:dev-hv2:ws",
        )
        rt_hv2.policy.register_authorized_workspace(
            hv2_reg,
            make_bootstrap_auth(
                store_id=hv2_sid,
                owner_id="dan",
                action="workspace_register",
                subject_id=hv2_reg.subject_id,
                trust_generation=rt_hv2.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(minutes=30),
            ),
        )
        assert rt_hv2.store.reconcile_policy() == 1
    finally:
        rt_hv2.close()
    for leftover in list(hv2_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)
    for companion in ("policy.db-wal", "policy.db-shm"):
        (hv2_root / "policy" / companion).unlink(missing_ok=True)
    (hv2_root / "policy" / "policy.db").write_bytes(saved_pb_pol_v2)
    os_.permissions.secure_file(hv2_root / "policy" / "policy.db")
    hv2_conn = sqlite3.connect(hv2_root / "store" / "brain.db")
    try:
        hv2_conn.execute("PRAGMA journal_mode=DELETE")
        hv2_conn.execute("UPDATE meta SET value = '2' WHERE key IN ('schema_version', 'min_reader_version')")
        hv2_conn.commit()
    finally:
        hv2_conn.close()
    os_.permissions.secure_file(hv2_root / "store" / "brain.db")
    hv2_store_snap = digest_tree(hv2_root / "store")
    with maintenance_lease(hv2_root, os_) as (mr_hv2, ml_hv2):
        pol_hv2 = PolicyStore.open(mr_hv2, ml_hv2, os_, migrations=v2_policy)
        try:
            with pytest.raises(BrainError) as exc_hv2:
                restore_store(
                    mr_hv2,
                    ml_hv2,
                    os_,
                    hv2_v2_sbak,
                    pol_hv2,
                    clock.now(),
                    migrations=v2_store,
                )
            assert exc_hv2.value.code is ErrorCode.UNSUPPORTED_VERSION
            assert digest_tree(hv2_root / "store") == hv2_store_snap
            assert not any(name.startswith("store.") for name in os.listdir(hv2_root))
        finally:
            pol_hv2.close()

    # B3. Verify restore_store under KERNEL_STORE_MIGRATIONS upgrades v1/v2 (store & store_full) backups to (4, 4)
    # and keeps exact snapshot bytes when manifest.schema_version == code_version(KERNEL_STORE_MIGRATIONS) (v4).
    for up_bak in (pb_v2_store_backup, pb_v2_store_full_backup, pb_v1_store_full_backup, pb_v1_store_backup):
        clock.advance(dt.timedelta(seconds=5))
        with maintenance_lease(pb_root, os_) as (mr_up, ml_up):
            pol_up = PolicyStore.open(mr_up, ml_up, os_, migrations=KERNEL_POLICY_MIGRATIONS)
            try:
                restore_store(
                    mr_up,
                    ml_up,
                    os_,
                    up_bak,
                    pol_up,
                    clock.now(),
                    migrations=KERNEL_STORE_MIGRATIONS,
                )
            finally:
                pol_up.close()
        assert read_schema_info(pb_root / "store" / "brain.db") == SchemaInfo(4, 4, pb_store_id)

    adm_pb_after_v1 = admit_existing_pair(pb_root, pb_store_id, os_, purpose="serve")
    rt_pb_after_v1 = open_runtime_under_lease(adm_pb_after_v1)
    try:
        assert rt_pb_after_v1.store.cas.read(pb_blob_digest) == b"pb-v1-blob"
        assert [e.handler_version for e in rt_pb_after_v1.store.entries() if e.kind == "policy.workspace_register"] == [
            2
        ]
    finally:
        rt_pb_after_v1.close()

    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(pb_root, os_) as (mr_v3, ml_v3):
        pol_v3_exact = PolicyStore.open(mr_v3, ml_v3, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(
                mr_v3,
                ml_v3,
                os_,
                pb_v3_store_backup,
                pol_v3_exact,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol_v3_exact.close()
    assert (pb_root / "store" / "brain.db").read_bytes() == (pb_v3_store_backup / "brain.db").read_bytes()

    # B4. Simulate a (policy=2, store=3) pair (migrating only store 2 -> 3 while leaving policy at 2):
    # verify v2 tuples fail restore_store, ensure_readable, admit_existing_pair("serve"|"migrate"), migrate_offline,
    # and open_runtime with UNSUPPORTED_VERSION before returning Runtime (zero policy logical mutations), while
    # Current Code migrate_offline upgrades (policy=2, store=3) -> (policy=3, store=3) cleanly!
    sim_root = trusted_tmp / "part-b-sim-p2-s3"
    rt_sim_v2 = open_cloned_runtime(
        sim_root,
        os_,
        role="krev-v2-a",
        store_migrations=v2_store,
        policy_migrations=v2_policy,
    )
    try:
        sim_sid = rt_sim_v2.policy.store_id
        sim_cred = seed_principal_and_credential(
            rt_sim_v2.policy, owner_id="dan", harness_id="claude-code", machine_id="dev-sim"
        )
        clock.advance(dt.timedelta(seconds=5))
        sim_v2_sbak = create_store_backup(rt_sim_v2.store, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        sim_reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=sim_cred.principal.principal_id,
            machine_id="dev-sim",
            alias="sim-ws",
            checkout_path=str(trusted_tmp / "sim-old"),
            path_identity="dan:dev-sim:ws",
        )
        sim_bind = rt_sim_v2.policy.register_authorized_workspace(
            sim_reg,
            make_bootstrap_auth(
                store_id=sim_sid,
                owner_id="dan",
                action="workspace_register",
                subject_id=sim_reg.subject_id,
                trust_generation=rt_sim_v2.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(minutes=30),
            ),
        )
    finally:
        rt_sim_v2.close()

    clock.advance(dt.timedelta(seconds=5))
    mig_sim_store_only = migrate_offline(
        DaemonConfig(1, sim_root, sim_sid, trusted_tmp / "sim.pem", trusted_tmp / "sim.key"),
        os_,
        policy_migrations=v2_policy,
        store_migrations=v3_store,
    )
    assert mig_sim_store_only.policy_report.status == "skipped" and mig_sim_store_only.policy_report.to_version == 2
    assert mig_sim_store_only.store_report.status == "migrated" and mig_sim_store_only.store_report.to_version == 3
    for leftover in list(sim_root.iterdir()):
        if leftover.name.startswith(("policy.replaced-", "store.replaced-")):
            shutil.rmtree(leftover)

    sim_pol_info = read_schema_info(sim_root / "policy" / "policy.db")
    sim_str_info = read_schema_info(sim_root / "store" / "brain.db")
    assert sim_pol_info == SchemaInfo(2, 2, sim_sid)
    assert sim_str_info == SchemaInfo(3, 3, sim_sid)

    with pytest.raises(BrainError) as exc_sim_read:
        ensure_readable(sim_str_info, v2_store)
    assert exc_sim_read.value.code is ErrorCode.UNSUPPORTED_VERSION

    # Even with open v2 PolicyStore, restore_store with migrations=v2_store refuses against live v3 store.db!
    sim_store_snap_0 = digest_tree(sim_root / "store")
    with maintenance_lease(sim_root, os_) as (mr_sim, ml_sim):
        pol_sim_v2 = PolicyStore.open(mr_sim, ml_sim, os_, migrations=v2_policy)
        try:
            with pytest.raises(BrainError) as exc_sim_rstore:
                restore_store(
                    mr_sim,
                    ml_sim,
                    os_,
                    sim_v2_sbak,
                    pol_sim_v2,
                    clock.now(),
                    migrations=v2_store,
                )
            assert exc_sim_rstore.value.code is ErrorCode.UNSUPPORTED_VERSION
            assert digest_tree(sim_root / "store") == sim_store_snap_0
            assert not any(name.startswith("store.") for name in os.listdir(sim_root))
        finally:
            pol_sim_v2.close()

    sim_root_snap = digest_tree(sim_root)
    sim_purposes: tuple[Literal["serve", "migrate"], ...] = ("serve", "migrate")
    for sim_purpose in sim_purposes:
        with pytest.raises(BrainError) as exc_sim_adm:
            bad_sim_adm = admit_existing_pair(
                sim_root,
                sim_sid,
                os_,
                purpose=sim_purpose,
                store_migrations=v2_store,
                policy_migrations=v2_policy,
            )
            bad_sim_adm.release()
        assert exc_sim_adm.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(sim_root) == sim_root_snap

    with pytest.raises(BrainError) as exc_sim_mig:
        migrate_offline(
            DaemonConfig(1, sim_root, sim_sid, trusted_tmp / "sim.pem", trusted_tmp / "sim.key"),
            os_,
            policy_migrations=v2_policy,
            store_migrations=v2_store,
        )
    assert exc_sim_mig.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(sim_root) == sim_root_snap

    sim_store_snap = digest_tree(sim_root / "store")
    sim_pol_state_before = _read_full_policy_state(sim_root / "policy" / "policy.db")
    with pytest.raises(BrainError) as exc_sim_open:
        bad_sim_rt = open_runtime(sim_root, os_, store_migrations=v2_store, policy_migrations=v2_policy)
        bad_sim_rt.close()
    assert exc_sim_open.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(sim_root / "store") == sim_store_snap
    assert _read_full_policy_state(sim_root / "policy" / "policy.db") == sim_pol_state_before

    # Current Code refuses mixed (policy=2, store=3) before migrate, then upgrades cleanly to (3, 3).
    sim_mixed_snap = digest_tree(sim_root)
    with pytest.raises(BrainError) as exc_sim_cur_adm:
        bad_sim_cur = admit_existing_pair(sim_root, sim_sid, os_, purpose="serve")
        bad_sim_cur.release()
    assert exc_sim_cur_adm.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(sim_root) == sim_mixed_snap

    sim_mixed_pol = digest_tree(sim_root / "policy")
    sim_mixed_str = digest_tree(sim_root / "store")
    with pytest.raises(BrainError) as exc_sim_cur_open:
        bad_sim_cur_rt = open_runtime(
            sim_root,
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        bad_sim_cur_rt.close()
    assert exc_sim_cur_open.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(sim_root / "policy") == sim_mixed_pol
    assert digest_tree(sim_root / "store") == sim_mixed_str

    clock.advance(dt.timedelta(seconds=5))
    mig_sim_up = migrate_offline(
        DaemonConfig(1, sim_root, sim_sid, trusted_tmp / "sim.pem", trusted_tmp / "sim.key"),
        os_,
    )
    assert not mig_sim_up.noop
    assert mig_sim_up.policy_report.status == "migrated"
    assert mig_sim_up.policy_report.from_version == 2 and mig_sim_up.policy_report.to_version == 3
    assert mig_sim_up.store_report.status == "migrated"
    assert mig_sim_up.store_report.from_version == 3 and mig_sim_up.store_report.to_version == 4
    assert read_schema_info(sim_root / "policy" / "policy.db") == SchemaInfo(3, 3, sim_sid)
    assert read_schema_info(sim_root / "store" / "brain.db") == SchemaInfo(4, 4, sim_sid)

    adm_sim_ok = admit_existing_pair(sim_root, sim_sid, os_, purpose="serve")
    rt_sim_ok = open_runtime_under_lease(adm_sim_ok)
    try:
        assert rt_sim_ok.policy.resolve_credential(sim_cred.token).principal_id == sim_cred.principal.principal_id
        assert rt_sim_ok.policy.snapshot().checkouts[sim_bind.checkout_id].repo_id == sim_bind.repo_id
        assert [e.handler_version for e in rt_sim_ok.store.entries() if e.kind == "policy.workspace_register"] == [2]
    finally:
        rt_sim_ok.close()
