"""Task 4a: store4 DDL, transactional idempotency, 30-day expiry, C4 clock watermark, C2 CAS staging, and C3 replay."""

from __future__ import annotations

import datetime as dt
import os
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.idempotency import (
    compute_idempotency_key_hash,
    compute_request_hmac,
)
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    IDEMPOTENCY_CLOCK_HWM_META_KEY,
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    AccountingStatus,
    CallContext,
    DaemonConfig,
    IdempotencyRow,
    Identity,
    JobState,
    ObjectRef,
    Principal,
    PrivateRequestAuth,
    RepoFlags,
    RequestAuthView,
    Scope,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    StagedBlob,
    StoredResult,
    WorkspaceBinding,
    field_path_digest,
)
from superbrain.core.wire import (
    DEFAULT_CONTEXT_BUDGET_TOKENS,
    normalize_call,
    parse_json,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.cas import blob_digests
from superbrain.storage.idempotency import StrictKernelTx
from superbrain.storage.kernel_schema import (
    KERNEL_POLICY_MIGRATIONS,
    KERNEL_STORE_MIGRATIONS,
    STORE_V4_MIGRATION,
)
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import Runtime, admit_existing_pair, open_runtime, open_runtime_under_lease
from superbrain.storage.schema import SchemaInfo, code_version, read_schema_info
from superbrain.storage.store import Store
from superbrain.storage.workspaces import StoreKernelTx
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FixtureDeliveryRefSpec,
    FixtureKernelDomain,
    FixtureResourceSpec,
    fixture_store_extensions,
    validate_response_envelope,
)
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

MS = 1_000_000
REMOTE_A = "https://github.example/dan/repo-alpha.git"
REMOTE_B = "https://github.example/dan/repo-beta.git"
REMOTE_C = "https://github.example/dan/repo-gamma.git"
TREE_A = "sha256:" + "a" * 64
TREE_B = "sha256:" + "b" * 64
TREE_C = "sha256:" + "c" * 64


class Mono:
    def __init__(self, start: int = 10_000 * MS) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now

    def monotonic_ns(self) -> int:
        return self.now

    def advance(self, ns: int) -> None:
        self.now += ns


@dataclass
class FakeObserver:
    descriptor: SnapshotDescriptor | None = None
    status: SnapshotStatus = SnapshotStatus.AVAILABLE
    calls: list[tuple[WorkspaceBinding, int]] = field(default_factory=list)

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        self.calls.append((binding, deadline_ns))
        if self.status is SnapshotStatus.AVAILABLE:
            return SnapshotObservation(SnapshotStatus.AVAILABLE, self.descriptor)
        return SnapshotObservation(self.status, None)


def _desc(tree: str = TREE_A, *, dirty_digest: str | None = None) -> SnapshotDescriptor:
    return SnapshotDescriptor(
        kind="git",
        tree_or_head_digest=tree,
        dirty=dirty_digest is not None,
        dirty_digest=dirty_digest,
        observed_at="2026-11-01T00:00:00.000000Z",
    )


def _open_fixture_runtime(root: Path, os_: OsAdapters) -> Runtime:
    handlers, kinds = fixture_store_extensions()
    return open_runtime(
        root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def _reopen_fixture_runtime(root: Path, store_id: str, os_: OsAdapters) -> Runtime:
    handlers, kinds = fixture_store_extensions()
    admitted = admit_existing_pair(
        root,
        store_id,
        os_,
        purpose="serve",
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    return open_runtime_under_lease(
        admitted,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def _register_ws(
    rt: Runtime,
    clock: FakeClock,
    seeded: SeededCredential,
    *,
    alias: str,
    checkout_dir: Path,
    remote: str | None = REMOTE_A,
    egress: bool = False,
) -> WorkspaceBinding:
    checkout_dir.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias=alias,
        raw_path=str(checkout_dir),
        raw_remote=remote,
        provider_egress_enabled=egress,
    )
    binding = rt.policy.register_authorized_workspace(
        reg,
        make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=seeded.principal.owner_id,
            action="workspace_register",
            subject_id=reg.subject_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        ),
    )
    rt.store.reconcile_policy()
    return binding


def _auth_for(seeded: SeededCredential) -> PrivateRequestAuth:
    return PrivateRequestAuth(
        credential_id=seeded.credential_id,
        principal=seeded.principal,
        token=seeded.token,
    )


def _ctx_for(
    rt: Runtime,
    principal: Principal,
    mono: Mono,
    *,
    selected_scope: Scope | None,
    instance_id: str = "inst-test-01",
    budget_ms: int = 1_500,
) -> CallContext:
    return CallContext(
        principal=principal,
        identity=Identity(
            store_id=rt.store.store_id,
            writer_epoch=rt.lease.epoch,
            instance_id=instance_id,
        ),
        deadline_ns=mono() + budget_ms * MS,
        selected_scope=selected_scope,
    )


def _make_bridge(
    rt: Runtime,
    clock: FakeClock,
    mono: Mono,
    *,
    observer: FakeObserver | None = None,
    delivery_plan: Callable[[WorkspaceBinding, str], Sequence[FixtureDeliveryRefSpec]] | None = None,
    on_commit_completed: Callable[[StoredResult], None] | None = None,
) -> tuple[KernelBridge, FixtureKernelDomain]:
    domain = FixtureKernelDomain(
        store=rt.store,
        policy=rt.policy,
        clock=clock,
        observer=observer,
        monotonic_ns=mono,
        delivery_plan=delivery_plan,
    )
    bridge = KernelBridge(
        store=rt.store,
        policy=rt.policy,
        clock=clock,
        writer_epoch=rt.lease.epoch,
        domain=domain,
        on_commit_completed=on_commit_completed,
    )
    return bridge, domain


def _expect_ok(tool: str, res: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is True, f"expected ok=True for {tool}, got {checked}"
    data = checked["data"]
    assert isinstance(data, dict)
    return data


def _expect_err(tool: str, res: Mapping[str, JsonValue], code: ErrorCode) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is False, f"expected error {code.value} for {tool}, got {checked}"
    err = checked["error"]
    assert isinstance(err, dict)
    assert err["code"] == code.value
    return err


def _count_rows(store: Store, table: str) -> int:
    with store.transaction() as txn:
        row = txn.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


# --- 1. Durable idempotency row & single delivery/assignment/result -------------------------------------------------


def test_concurrent_retry_one_delivery_assignment_and_result(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk-main")
        scope = Scope(binding.repo_id, binding.checkout_id)
        obs = FakeObserver(descriptor=_desc(TREE_A))
        bridge, domain = _make_bridge(rt, clock, mono, observer=obs)

        # Also verify production bridge (domain=None) refuses prepare_task as capability_unavailable without rows.
        prod_bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch)
        call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "implement durable idempotent delivery",
                "idempotency_key": "idem_concurrent_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        prod_res = prod_bridge.dispatch(
            call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
        )
        _expect_err("prepare_task", prod_res, ErrorCode.CAPABILITY_UNAVAILABLE)
        assert _count_rows(rt.store, "idempotency") == 0

        first = _expect_ok(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)),
        )
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1
        assert len(obs.calls) == 1
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
        assert _count_rows(rt.store, "p_task_lineage_bindings") == 1

        # Durable retries (before and after advancing wall clock within 30d, and across reopen) keep identical IDs.
        clock.advance(dt.timedelta(minutes=5))
        second = _expect_ok(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)),
        )
        assert second == first
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1
        assert len(obs.calls) == 1

        # Changed normalized payload under the same live key -> IDEMPOTENCY_CONFLICT and no extra rows.
        changed_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-main",
                "description": "different description under same key",
                "idempotency_key": "idem_concurrent_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                changed_call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.IDEMPOTENCY_CONFLICT,
        )
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
        store_id = rt.store.store_id
    finally:
        rt.close()

    rt2 = _reopen_fixture_runtime(trusted_tmp / "root", store_id, os_)
    try:
        obs2 = FakeObserver(descriptor=_desc(TREE_B))
        bridge2, domain2 = _make_bridge(rt2, clock, mono, observer=obs2)
        replayed = _expect_ok(
            "prepare_task",
            bridge2.dispatch(call, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)),
        )
        assert replayed == first
        assert domain2.prepare_calls == 0
        assert domain2.apply_calls == 0
        assert len(obs2.calls) == 0

        # --- 4b reservation half: pause before commit AND inside commit + lost response -> single committed result ---
        paused_before_commit = threading.Event()
        release_before_commit = threading.Event()
        paused_in_commit = threading.Event()
        release_in_commit = threading.Event()
        lose_response_once = True

        def _before_enter_commit(_res: object) -> None:
            paused_before_commit.set()
            assert release_before_commit.wait(timeout=10.0)

        def _on_completed(_stored: StoredResult) -> None:
            nonlocal lose_response_once
            if lose_response_once:
                lose_response_once = False
                raise RuntimeError("simulated lost transport response after durable SQLite commit")

        obs_res = FakeObserver(descriptor=_desc(TREE_C))
        dom_res = FixtureKernelDomain(
            store=rt2.store,
            policy=rt2.policy,
            clock=clock,
            observer=obs_res,
            monotonic_ns=mono,
        )

        def _pause_in_apply(_tx: object) -> None:
            paused_in_commit.set()
            assert release_in_commit.wait(timeout=10.0)

        dom_res.before_apply_hook = _pause_in_apply
        bridge_res = KernelBridge(
            store=rt2.store,
            policy=rt2.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt2.lease.epoch,
            domain=dom_res,
            before_enter_commit=_before_enter_commit,
            on_commit_completed=_on_completed,
        )
        bridge_res.publish_auth_view()

        res_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_hint": "ws-main",
            "description": "4b concurrent reservation + lost response check",
            "idempotency_key": "idem_concurrent_4b_0002",
        }
        sub_first = bridge_res.submit_request(
            "prepare_task",
            res_args,
            token=seeded.token,
            selected_scope=scope,
        )

        # Spawn concurrent retries from request threads while main (owner) thread executes sub_first across barriers!
        pre_commit_outcomes: list[tuple[Mapping[str, JsonValue], Mapping[str, JsonValue]]] = []
        in_commit_outcomes: list[tuple[Mapping[str, JsonValue], Mapping[str, JsonValue]]] = []

        def _concurrent_probes() -> None:
            assert paused_before_commit.wait(timeout=5.0)
            dup_pre = bridge_res.call_tool(
                "prepare_task", dict(res_args), token=seeded.token, selected_scope=scope, timeout=2.0
            )
            conf_pre = bridge_res.call_tool(
                "prepare_task",
                {**res_args, "description": "changed while paused before enter_commit"},
                token=seeded.token,
                selected_scope=scope,
                timeout=2.0,
            )
            pre_commit_outcomes.append((dup_pre, conf_pre))
            release_before_commit.set()

            assert paused_in_commit.wait(timeout=5.0)
            dup_mid = bridge_res.call_tool(
                "prepare_task", dict(res_args), token=seeded.token, selected_scope=scope, timeout=2.0
            )
            conf_mid = bridge_res.call_tool(
                "prepare_task",
                {**res_args, "description": "changed while paused inside SQLite commit"},
                token=seeded.token,
                selected_scope=scope,
                timeout=2.0,
            )
            in_commit_outcomes.append((dup_mid, conf_mid))
            release_in_commit.set()

        probe_thread = threading.Thread(target=_concurrent_probes, daemon=True)
        probe_thread.start()
        assert bridge_res.process_next_queued(block=False) is True
        probe_thread.join(timeout=10.0)
        assert not probe_thread.is_alive()

        assert len(pre_commit_outcomes) == 1
        _expect_err("prepare_task", pre_commit_outcomes[0][0], ErrorCode.IN_PROGRESS)
        _expect_err("prepare_task", pre_commit_outcomes[0][1], ErrorCode.IDEMPOTENCY_CONFLICT)

        assert len(in_commit_outcomes) == 1
        _expect_err("prepare_task", in_commit_outcomes[0][0], ErrorCode.IN_PROGRESS)
        _expect_err("prepare_task", in_commit_outcomes[0][1], ErrorCode.IDEMPOTENCY_CONFLICT)

        # First caller received COMMIT_OUTCOME_UNKNOWN due to lost post-commit completion callback,
        # yet durable commit succeeded once and reservation cleared!
        _expect_err("prepare_task", sub_first.wait(timeout=2.0), ErrorCode.COMMIT_OUTCOME_UNKNOWN)
        assert bridge_res.reservations.active_count() == 0
        assert dom_res.prepare_calls == 1
        assert dom_res.apply_calls == 1
        assert _count_rows(rt2.store, "idempotency") == 2
        assert _count_rows(rt2.store, "p_fixture_domain_deliveries") == 2

        dom_res.before_apply_hook = None
        sub_retry = bridge_res.submit_request(
            "prepare_task",
            dict(res_args),
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge_res.process_next_queued(block=False) is True
        recovered = _expect_ok("prepare_task", sub_retry.wait(timeout=2.0))
        assert recovered["delivery_id"] != first["delivery_id"]
        assert isinstance(recovered["assignment_id"], str)
        assert dom_res.prepare_calls == 1
        assert dom_res.apply_calls == 1
        assert _count_rows(rt2.store, "idempotency") == 2
        assert _count_rows(rt2.store, "p_fixture_domain_deliveries") == 2
    finally:
        rt2.close()


# --- 2. Raw normalized HMAC detects changed raw secret even when safe payloads match --------------------------------


def test_same_key_changed_raw_secret_conflicts_after_redaction(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        binding = _register_ws(rt, clock, seeded, alias="ws-sec", checkout_dir=trusted_tmp / "chk-sec")
        scope = Scope(binding.repo_id, binding.checkout_id)
        bridge, domain = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))

        # Both descriptions redact to identical "[redacted]" under PrivacyFilter, yet raw normalized args differ.
        call_secret_1 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-sec",
                "description": "deploy with <private>alpha-secret-one</private> config",
                "idempotency_key": "idem_raw_secret_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        call_secret_2 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-sec",
                "description": "deploy with <private>bravo-secret-two</private> config",
                "idempotency_key": "idem_raw_secret_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_secret_1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                call_secret_2, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.IDEMPOTENCY_CONFLICT,
        )
        assert domain.apply_calls == 1
    finally:
        rt.close()


# --- 3. Per-store HMAC secret & fail-closed missing/corrupt key ID --------------------------------------------------


def test_request_hmac_is_different_per_store_and_unknown_key_fails_closed(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt_a = _open_fixture_runtime(trusted_tmp / "root-a", os_)
    rt_b = _open_fixture_runtime(trusted_tmp / "root-b", os_)
    try:
        cred_a = seed_principal_and_credential(rt_a.policy, principal_id="princ-same")
        cred_b = seed_principal_and_credential(rt_b.policy, principal_id="princ-same")
        ws_a = _register_ws(rt_a, clock, cred_a, alias="ws-x", checkout_dir=trusted_tmp / "chk-ax")
        ws_b = _register_ws(rt_b, clock, cred_b, alias="ws-x", checkout_dir=trusted_tmp / "chk-bx")

        key_id_a, key_bytes_a = rt_a.policy.request_digest_key()
        key_id_b, key_bytes_b = rt_b.policy.request_digest_key()
        assert key_id_a != key_id_b
        assert key_bytes_a != key_bytes_b
        assert rt_a.policy.request_digest_key_by_id(key_id_a) == key_bytes_a
        assert rt_a.policy.request_digest_key_by_id("missing-key-id") is None

        # Identical normalized call produces distinct HMACs under the two stores, while lookup key_hash is unkeyed.
        sample_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-x",
                "description": "same logical request",
                "idempotency_key": "idem_per_store_0001",
            },
            cred_a.principal,
            selected_scope=None,
        )
        hmac_a = compute_request_hmac(key_bytes_a, sample_call)
        hmac_b = compute_request_hmac(key_bytes_b, sample_call)
        assert hmac_a != hmac_b
        assert compute_idempotency_key_hash(
            cred_a.principal.principal_id, "prepare_task", "idem_per_store_0001"
        ) == compute_idempotency_key_hash(cred_b.principal.principal_id, "prepare_task", "idem_per_store_0001")

        # Retained inactive key (active=0) still resolves via request_digest_key_by_id without minting a new key.
        retained_id = new_id()
        retained_secret = b"\x5a" * 32
        with rt_a.policy._immediate() as pdb:
            pdb.execute(
                "INSERT INTO request_digest_key (id, key_bytes, active, created_at) VALUES (?, ?, 0, ?)",
                (retained_id, retained_secret, utc_timestamp(clock.now())),
            )
        assert rt_a.policy.request_digest_key_by_id(retained_id) == retained_secret

        # Commit a row in root-a, then remove its key_id from policy to simulate missing key authority.
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        bridge_a, domain_a = _make_bridge(rt_a, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))
        call_a = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-x",
                "description": "initial commit",
                "idempotency_key": "idem_per_store_0001",
            },
            cred_a.principal,
            selected_scope=scope_a,
        )
        _expect_ok(
            "prepare_task",
            bridge_a.dispatch(
                call_a, _ctx_for(rt_a, cred_a.principal, mono, selected_scope=scope_a), auth=_auth_for(cred_a)
            ),
        )
        _ = ws_b

        missing_id = new_id()
        with rt_a.store.transaction() as stxn:
            stxn.db.execute("UPDATE idempotency SET request_digest_key_id = ?", (missing_id,))

        # Fails closed with POLICY_UNAVAILABLE on live replay, on expired replacement, AND on prune_expired!
        _expect_err(
            "prepare_task",
            bridge_a.dispatch(
                call_a, _ctx_for(rt_a, cred_a.principal, mono, selected_scope=scope_a), auth=_auth_for(cred_a)
            ),
            ErrorCode.POLICY_UNAVAILABLE,
        )
        clock.advance(dt.timedelta(days=31))
        _expect_err(
            "prepare_task",
            bridge_a.dispatch(
                call_a, _ctx_for(rt_a, cred_a.principal, mono, selected_scope=scope_a), auth=_auth_for(cred_a)
            ),
            ErrorCode.POLICY_UNAVAILABLE,
        )
        with pytest.raises(BrainError) as prune_exc:
            bridge_a.prune_expired(clock.now(), limit=10)
        assert prune_exc.value.code is ErrorCode.POLICY_UNAVAILABLE
        assert _count_rows(rt_a.store, "idempotency") == 1
        assert domain_a.apply_calls == 1

        # Corrupt stored key_bytes (<32 bytes) also fails closed with POLICY_UNAVAILABLE.
        corrupt_id = new_id()
        with rt_a.policy._immediate() as pdb:
            pdb.execute("PRAGMA ignore_check_constraints = ON")
            try:
                pdb.execute(
                    "INSERT INTO request_digest_key (id, key_bytes, active, created_at) VALUES (?, ?, 0, ?)",
                    (corrupt_id, b"short", utc_timestamp(clock.now())),
                )
            finally:
                pdb.execute("PRAGMA ignore_check_constraints = OFF")
        with pytest.raises(BrainError) as corrupt_exc:
            rt_a.policy.request_digest_key_by_id(corrupt_id)
        assert corrupt_exc.value.code is ErrorCode.POLICY_UNAVAILABLE
    finally:
        rt_b.close()
        rt_a.close()


# --- 4. Replay live recheck: credential revocation, principal isolation, quarantine, lost grant, out of scope -------


def test_replay_rechecks_revocation_quarantine_scope(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        cred_a1 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude", machine_id="m1")
        # Issue a second active credential for the SAME principal, and a credential for a DIFFERENT principal.
        cred_a2 = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude", machine_id="m1")
        assert cred_a1.principal == cred_a2.principal
        assert cred_a1.credential_id != cred_a2.credential_id
        other_princ = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1")

        ws_alpha = _register_ws(
            rt, clock, cred_a1, alias="ws-alpha", checkout_dir=trusted_tmp / "chk-alpha", remote=REMOTE_A
        )
        ws_alpha_2 = _register_ws(
            rt, clock, cred_a1, alias="ws-alpha-2", checkout_dir=trusted_tmp / "chk-alpha-2", remote=REMOTE_A
        )
        ws_beta = _register_ws(
            rt, clock, cred_a1, alias="ws-beta", checkout_dir=trusted_tmp / "chk-beta", remote=REMOTE_B
        )
        _ = _register_ws(
            rt, clock, other_princ, alias="ws-other", checkout_dir=trusted_tmp / "chk-other", remote=REMOTE_A
        )

        skill_ok_ref = ObjectRef(kind="skill", id="skill-keep", revision=1, digest=digest_bytes(b"skill-keep"))
        skill_quar_ref = ObjectRef(kind="skill", id="skill-quar", revision=1, digest=digest_bytes(b"skill-quar"))
        lesson_beta_ref = ObjectRef(kind="lesson", id="lesson-beta", revision=2, digest=digest_bytes(b"lesson-beta"))
        ctx_other_chk_ref = ObjectRef(kind="context", id="ctx-chk2", revision=1, digest=digest_bytes(b"ctx-chk2"))
        gate_snap_dep_ref = ObjectRef(kind="gate", id="gate-snap", revision=1, digest=digest_bytes(b"gate-snap"))

        def plan(binding: WorkspaceBinding, _task_id: str) -> Sequence[FixtureDeliveryRefSpec]:
            return (
                FixtureDeliveryRefSpec(
                    slot="skills",
                    ref=skill_ok_ref,
                    owner_id=binding.owner_id,
                    repo_id=ws_alpha.repo_id,
                    checkout_id=ws_alpha.checkout_id,
                ),
                FixtureDeliveryRefSpec(
                    slot="skills",
                    ref=skill_quar_ref,
                    owner_id=binding.owner_id,
                    repo_id=ws_alpha.repo_id,
                    checkout_id=ws_alpha.checkout_id,
                ),
                FixtureDeliveryRefSpec(
                    slot="lessons",
                    ref=lesson_beta_ref,
                    owner_id=binding.owner_id,
                    repo_id=ws_beta.repo_id,
                    checkout_id=None,
                ),
                FixtureDeliveryRefSpec(
                    slot="context",
                    ref=ctx_other_chk_ref,
                    owner_id=binding.owner_id,
                    repo_id=ws_alpha.repo_id,
                    checkout_id=ws_alpha_2.checkout_id,
                ),
                FixtureDeliveryRefSpec(
                    slot="finishing_gates",
                    ref=gate_snap_dep_ref,
                    owner_id=binding.owner_id,
                    repo_id=ws_alpha.repo_id,
                    checkout_id=ws_alpha.checkout_id,
                    snapshot_dependent=True,
                ),
            )

        scope_alpha = Scope(ws_alpha.repo_id, ws_alpha.checkout_id)
        bridge, domain = _make_bridge(
            rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)), delivery_plan=plan
        )

        # Seed an artifact in ws_alpha as well to verify GetArtifactResult redaction on replay.
        art_blob = b"# Active Skill Guide\nStep 1: verify invariants.\n"
        art_ref = domain.seed_artifact(
            bridge,
            artifact_id="art-guide-1",
            revision=1,
            owner_id="dan",
            repo_id=ws_alpha.repo_id,
            checkout_id=ws_alpha.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=art_blob, encoding="utf-8", level="L1"),),
        )
        _ = art_ref

        render_current_calls = 0
        orig_render_current = bridge._dispatcher.render_current

        def spy_render_current(
            result: StoredResult, principal: Principal, *, selected_scope: Scope | None
        ) -> JsonValue:
            nonlocal render_current_calls
            render_current_calls += 1
            return orig_render_current(result, principal, selected_scope=selected_scope)

        bridge._dispatcher.render_current = spy_render_current  # type: ignore[method-assign]

        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_alpha.repo_id,
                "checkout_id": ws_alpha.checkout_id,
                "description": "prepare with multi-repo refs",
                "idempotency_key": "idem_recheck_prep_01",
            },
            cred_a1.principal,
            selected_scope=scope_alpha,
        )
        initial = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call, _ctx_for(rt, cred_a1.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a1)
            ),
        )
        assert render_current_calls == 1
        # Initially: skill-keep & skill-quar & lesson-beta are ok; ctx-chk2 is already out of scope for chk-alpha!
        assert initial["skills"] == [
            {"kind": "skill", "id": "skill-keep", "revision": 1, "digest": skill_ok_ref.digest, "status": "ok"},
            {"kind": "skill", "id": "skill-quar", "revision": 1, "digest": skill_quar_ref.digest, "status": "ok"},
        ]
        assert initial["lessons"] == [
            {"kind": "lesson", "id": "lesson-beta", "revision": 2, "digest": lesson_beta_ref.digest, "status": "ok"}
        ]
        assert initial["context"] == [{"id": "ctx-chk2", "status": "redacted", "reason": "access_restricted"}]

        art_call = normalize_call(
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": ws_alpha.repo_id,
                "task_id": str(initial["task_id"]),
                "artifact_id": "art-guide-1",
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem_recheck_art_01",
            },
            cred_a1.principal,
            selected_scope=scope_alpha,
        )
        art_initial = _expect_ok(
            "get_artifact",
            bridge.dispatch(
                art_call, _ctx_for(rt, cred_a1.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a1)
            ),
        )
        assert art_initial["status"] == "ok"

        # 1) Revoke cred_a1 while cred_a2 stays active: cred_a1 MUST fail with UNAUTHENTICATED before any read!
        rt.policy.record_authorized_revocation(
            cred_a1.credential_id,
            make_bootstrap_auth(
                store_id=rt.policy.store_id,
                owner_id="dan",
                action="credential_revoke",
                subject_id=cred_a1.credential_id,
                trust_generation=rt.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                prep_call, _ctx_for(rt, cred_a1.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a1)
            ),
            ErrorCode.UNAUTHENTICATED,
        )

        # 2) Different principal under the same owner never reads cred_a1's row.
        other_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-other",
                "description": "other principal same key string",
                "idempotency_key": "idem_recheck_prep_01",
            },
            other_princ.principal,
            selected_scope=None,
        )
        other_data = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                other_call, _ctx_for(rt, other_princ.principal, mono, selected_scope=None), auth=_auth_for(other_princ)
            ),
        )
        assert other_data["delivery_id"] != initial["delivery_id"]
        assert other_data["assignment_id"] != initial["assignment_id"]

        # 3) Quarantine skill-quar + art_blob, and remove principal's repo_grant on ws_beta.
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": skill_quar_ref.digest})
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(art_blob)})
        with rt.policy._immediate() as pdb:
            pdb.execute(
                "DELETE FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
                (cred_a2.principal.principal_id, ws_beta.repo_id),
            )

        # Replay via active cred_a2: same delivery_id & assignment_id, while quarantined & grant-lost refs redact!
        rc_before_replay = render_current_calls
        replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call, _ctx_for(rt, cred_a2.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a2)
            ),
        )
        assert render_current_calls == rc_before_replay + 1
        assert replayed["delivery_id"] == initial["delivery_id"]
        assert replayed["assignment_id"] == initial["assignment_id"]
        assert replayed["skills"] == [
            {"kind": "skill", "id": "skill-keep", "revision": 1, "digest": skill_ok_ref.digest, "status": "ok"},
            {"id": "skill-quar", "status": "redacted", "reason": "access_restricted"},
        ]
        assert replayed["lessons"] == [{"id": "lesson-beta", "status": "redacted", "reason": "access_restricted"}]
        assert replayed["context"] == [{"id": "ctx-chk2", "status": "redacted", "reason": "access_restricted"}]
        assert replayed["finishing_gates"] == [
            {"kind": "gate", "id": "gate-snap", "revision": 1, "digest": gate_snap_dep_ref.digest, "status": "ok"}
        ]

        # Direct render_current on authorized scope_alpha returns the redacted items; cross-checkout selected_scope
        # on chk-alpha's recorded Delivery or Artifact receipt MUST refuse with NOT_FOUND per D3!
        with rt.store.transaction() as stxn:
            row = stxn.db.execute(
                "SELECT result_id, assignment_id, refs_json FROM idempotency WHERE principal_id = ? AND tool = ?",
                (cred_a2.principal.principal_id, "prepare_task"),
            ).fetchone()
            art_row = stxn.db.execute(
                "SELECT result_id, assignment_id, refs_json FROM idempotency WHERE principal_id = ? AND tool = ?",
                (cred_a2.principal.principal_id, "get_artifact"),
            ).fetchone()
        assert row is not None and art_row is not None
        stored = StoredResult(
            result_id=str(row[0]),
            assignment_id=None if row[1] is None else str(row[1]),
            refs=StoredResult.decode_refs_json(str(row[2])),
        )
        art_stored = StoredResult(
            result_id=str(art_row[0]),
            assignment_id=None if art_row[1] is None else str(art_row[1]),
            refs=StoredResult.decode_refs_json(str(art_row[2])),
        )
        rendered_same_scope = bridge.render_current(stored, cred_a2.principal, selected_scope=scope_alpha)
        assert isinstance(rendered_same_scope, dict)
        assert rendered_same_scope["skills"] == replayed["skills"]
        assert rendered_same_scope["lessons"] == replayed["lessons"]
        assert rendered_same_scope["context"] == replayed["context"]

        other_chk_scope = Scope(ws_alpha.repo_id, ws_alpha_2.checkout_id)
        with pytest.raises(BrainError) as other_deliv_exc:
            bridge.render_current(stored, cred_a2.principal, selected_scope=other_chk_scope)
        assert other_deliv_exc.value.code is ErrorCode.NOT_FOUND

        with pytest.raises(BrainError) as other_art_exc:
            bridge.render_current(art_stored, cred_a2.principal, selected_scope=other_chk_scope)
        assert other_art_exc.value.code is ErrorCode.NOT_FOUND

        # Replaying get_artifact after blob quarantine preserves result identity & returns schema-valid redacted result.
        art_replayed = _expect_ok(
            "get_artifact",
            bridge.dispatch(
                art_call, _ctx_for(rt, cred_a2.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a2)
            ),
        )
        assert art_replayed == {
            "artifact_id": "art-guide-1",
            "revision": 1,
            "level": "L1",
            "status": "redacted",
            "reason": "access_restricted",
            "resources": [],
        }

        # Quarantining the recorded snapshot descriptor after commit preserves the StoredResult's historical
        # snapshot provenance (C1:67) while omitting snapshot_dependent content under current policy (C1:56)!
        assert initial["source_snapshot_id"] is not None
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": _desc(TREE_A).descriptor_digest})
        snap_quar_replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call, _ctx_for(rt, cred_a2.principal, mono, selected_scope=scope_alpha), auth=_auth_for(cred_a2)
            ),
        )
        assert snap_quar_replayed["delivery_id"] == initial["delivery_id"]
        assert snap_quar_replayed["assignment_id"] == initial["assignment_id"]
        assert snap_quar_replayed["source_snapshot_id"] == initial["source_snapshot_id"]
        assert snap_quar_replayed["snapshot_status"] == "available"
        assert snap_quar_replayed["degraded_codes"] == []
        assert snap_quar_replayed["finishing_gates"] == []
        assert snap_quar_replayed["skills"] == replayed["skills"]

        rendered_snap_quar = bridge.render_current(stored, cred_a2.principal, selected_scope=scope_alpha)
        assert isinstance(rendered_snap_quar, dict)
        for field_name in (
            "delivery_id",
            "assignment_id",
            "source_snapshot_id",
            "snapshot_status",
            "degraded_codes",
            "finishing_gates",
            "skills",
        ):
            assert rendered_snap_quar[field_name] == snap_quar_replayed[field_name]
    finally:
        rt.close()


# --- 5. Exact 30-day expiry from original commit, failed replacement rollback, watermark & pruning ------------------


def test_expiry_is_30_days_from_original_commit(trusted_tmp: Path) -> None:
    t0 = dt.datetime(2026, 11, 1, 0, 0, 0, 0, tzinfo=dt.UTC)
    clock = FakeClock(t0)
    os_ = os_adapters(clock=clock)
    mono = Mono()

    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-exp", checkout_dir=trusted_tmp / "chk-exp")
        scope = Scope(ws.repo_id, ws.checkout_id)
        obs = FakeObserver(descriptor=_desc(TREE_A))
        bridge, domain = _make_bridge(rt, clock, mono, observer=obs)

        call_v1 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "original commit at Nov 1",
                "idempotency_key": "idem_ttl_30d_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        first = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_v1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )

        def read_row_and_hwm(s: Store) -> tuple[str, str, str | None]:
            with s.transaction() as txn:
                r = txn.db.execute(
                    "SELECT result_id, committed_at FROM idempotency WHERE tool = 'prepare_task'"
                ).fetchone()
                m = txn.db.execute("SELECT value FROM meta WHERE key = ?", (IDEMPOTENCY_CLOCK_HWM_META_KEY,)).fetchone()
            assert r is not None
            return str(r[0]), str(r[1]), (None if m is None else str(m[0]))

        orig_result_id, orig_committed_at, hwm_1 = read_row_and_hwm(rt.store)
        assert orig_committed_at == "2026-11-01T00:00:00.000000Z"
        assert hwm_1 == "2026-11-01T00:00:00.000000Z"

        # Replay at Nov 20 advances operational watermark, NEVER committed_at or business IDs!
        clock.set(dt.datetime(2026, 11, 20, 0, 0, 0, 0, tzinfo=dt.UTC))
        replay_nov20 = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_v1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert replay_nov20 == first
        res_nov20, comm_nov20, hwm_nov20 = read_row_and_hwm(rt.store)
        assert res_nov20 == orig_result_id
        assert comm_nov20 == "2026-11-01T00:00:00.000000Z"
        assert hwm_nov20 == "2026-11-20T00:00:00.000000Z"

        # One microsecond before 30 days (2026-11-30T23:59:59.999999Z) is STILL LIVE -> replay (no extension!).
        clock.set(dt.datetime(2026, 11, 30, 23, 59, 59, 999999, tzinfo=dt.UTC))
        replay_last_us = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_v1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert replay_last_us == first
        assert domain.apply_calls == 1
        _, comm_last_us, hwm_last_us = read_row_and_hwm(rt.store)
        assert comm_last_us == "2026-11-01T00:00:00.000000Z"
        assert hwm_last_us == "2026-11-30T23:59:59.999999Z"

        # Exact cutoff 2026-12-01T00:00:00.000000Z: inject failure during replacement -> rollback keeps old row!
        clock.set(dt.datetime(2026, 12, 1, 0, 0, 0, 0, tzinfo=dt.UTC))
        obs.descriptor = _desc(TREE_B)

        def fail_inside_tx(_tx: object) -> None:
            raise BrainError(ErrorCode.IO_ERROR, "I/O error")

        domain.before_apply_hook = fail_inside_tx
        call_v2 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "new payload allowed after 30d expiry",
                "idempotency_key": "idem_ttl_30d_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                call_v2, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.IO_ERROR,
        )
        res_after_fail, comm_after_fail, hwm_after_fail = read_row_and_hwm(rt.store)
        assert res_after_fail == orig_result_id
        assert comm_after_fail == "2026-11-01T00:00:00.000000Z"
        assert hwm_after_fail == "2026-11-30T23:59:59.999999Z"

        # Clear failure hook at exact same cutoff -> atomic replacement commits new result & new delivery!
        domain.before_apply_hook = None
        replaced = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_v2, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert replaced["delivery_id"] != first["delivery_id"]
        assert replaced["assignment_id"] != first["assignment_id"]
        assert replaced["source_snapshot_id"] != first["source_snapshot_id"]
        new_res_id, new_comm, new_hwm = read_row_and_hwm(rt.store)
        assert new_res_id != orig_result_id
        assert new_comm == "2026-12-01T00:00:00.000000Z"
        assert new_hwm == "2026-12-01T00:00:00.000000Z"
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 2

        # prune_expired bounds validation (1..100 strict int) and non-cascade of business results/holds/attempts/acks.
        for bad_limit in (0, -1, 101, True, False):
            with pytest.raises(BrainError) as bad_lim_exc:
                bridge.prune_expired(clock.now(), limit=bad_limit)
            assert bad_lim_exc.value.code is ErrorCode.INVALID_INPUT

        # Seed 3 extra keys, plus operational rows in artifact_send_attempt & artifact_read_ack.
        for idx in range(3):
            extra_call = normalize_call(
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "workspace_hint": "ws-exp",
                    "description": f"extra-{idx}",
                    "idempotency_key": f"idem_extra_prune_{idx:04d}",
                },
                seeded.principal,
                selected_scope=scope,
            )
            _expect_ok(
                "prepare_task",
                bridge.dispatch(
                    extra_call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
                ),
            )
        attempt_id = new_id()
        ack_id = new_id()
        with rt.store.transaction() as stxn:
            stxn.db.execute(
                "INSERT INTO artifact_send_attempt VALUES (?, ?, ?, ?, ?, ?, ?, 'served_only')",
                (attempt_id, new_res_id, seeded.principal.principal_id, str(replaced["task_id"]), "art-1", 1, "[]"),
            )
            stxn.db.execute(
                "INSERT INTO artifact_read_ack VALUES (?, ?, ?, ?, ?, ?)",
                (ack_id, attempt_id, seeded.principal.principal_id, str(replaced["task_id"]), 1, "[]"),
            )
        holders_before = _count_rows(rt.store, "p_cas_holders_")
        deliveries_before = _count_rows(rt.store, "p_fixture_domain_deliveries")
        assert _count_rows(rt.store, "idempotency") == 4

        # Before 30d from Dec 1 -> 0 pruned.
        clock.set(dt.datetime(2026, 12, 30, 23, 59, 59, 999999, tzinfo=dt.UTC))
        assert bridge.prune_expired(clock.now(), limit=2) == 0

        # At 2026-12-31T00:00:00Z -> bounded prune deletes 2, then remaining 2, leaving deliveries/holds/attempts/acks!
        clock.set(dt.datetime(2026, 12, 31, 0, 0, 0, 0, tzinfo=dt.UTC))
        assert bridge.prune_expired(clock.now(), limit=2) == 2
        assert _count_rows(rt.store, "idempotency") == 2
        assert bridge.prune_expired(clock.now(), limit=100) == 2
        assert _count_rows(rt.store, "idempotency") == 0
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == deliveries_before
        assert _count_rows(rt.store, "p_cas_holders_") == holders_before
        assert _count_rows(rt.store, "artifact_send_attempt") == 1
        assert _count_rows(rt.store, "artifact_read_ack") == 1

        # Concurrent reuse hitting commit_prepared_effect's raced-live-row branch
        # (same-HMAC replay & changed-HMAC conflict):
        race_completions: list[str] = []
        obs.descriptor = _desc(TREE_A)
        race_bridge, race_domain = _make_bridge(
            rt,
            clock,
            mono,
            observer=obs,
            on_commit_completed=lambda sr: race_completions.append(sr.result_id),
        )
        # Seed initial row at 2027-01-01T00:00:00Z, then advance 30 days to 2027-01-31T00:00:00Z so it is expired.
        clock.set(dt.datetime(2027, 1, 1, 0, 0, 0, 0, tzinfo=dt.UTC))
        call_race_seed = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "seed before concurrent reuse",
                "idempotency_key": "idem_ttl_race_reuse_01",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            race_bridge.dispatch(
                call_race_seed, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert race_domain.apply_calls == 1
        assert len(race_completions) == 1

        # Case 1 (same-HMAC raced reuse at 2027-01-31T00:00:00Z): both callers pass lookup_for_owner seeing the expired
        # row; winner commits replacement right before loser enters commit_prepared_effect -> loser replays winner's row
        # (was_raced_replay=True) with ZERO extra apply_calls and ZERO extra on_commit_completed callbacks!
        clock.set(dt.datetime(2027, 1, 31, 0, 0, 0, 0, tzinfo=dt.UTC))
        obs.descriptor = _desc(TREE_B)
        call_race_same = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "winner replacement payload v1",
                "idempotency_key": "idem_ttl_race_reuse_01",
            },
            seeded.principal,
            selected_scope=scope,
        )
        orig_commit_fn = race_bridge._dispatcher._idempotency.commit_prepared_effect
        winner_same_result: dict[str, JsonValue] | None = None
        inject_same_once = True

        def raced_same_commit(**kwargs: object) -> tuple[StoredResult, bool]:
            nonlocal inject_same_once, winner_same_result
            if inject_same_once:
                inject_same_once = False
                winner_same_result = _expect_ok(
                    "prepare_task",
                    race_bridge.dispatch(
                        call_race_same,
                        _ctx_for(rt, seeded.principal, mono, selected_scope=scope),
                        auth=_auth_for(seeded),
                    ),
                )
            return orig_commit_fn(**kwargs)  # type: ignore[arg-type]

        race_bridge._dispatcher._idempotency.commit_prepared_effect = raced_same_commit  # type: ignore[method-assign]
        try:
            loser_same_result = _expect_ok(
                "prepare_task",
                race_bridge.dispatch(
                    call_race_same, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
                ),
            )
        finally:
            race_bridge._dispatcher._idempotency.commit_prepared_effect = orig_commit_fn  # type: ignore[method-assign]

        assert winner_same_result is not None
        assert loser_same_result == winner_same_result
        assert race_domain.apply_calls == 2  # 1 seed + 1 winner (loser did NOT run apply!)
        assert len(race_completions) == 2  # loser hit was_raced_replay=True -> no duplicate completion signal!

        # Case 2 (changed-HMAC raced reuse after another 30d at 2027-03-02T00:00:00Z): winner commits replacement first,
        # loser enters commit_prepared_effect with different normalized arguments -> IDEMPOTENCY_CONFLICT & zero writes!
        clock.set(dt.datetime(2027, 3, 2, 0, 0, 0, 0, tzinfo=dt.UTC))
        obs.descriptor = _desc(TREE_C)
        call_race_winner_2 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "winner replacement payload v2",
                "idempotency_key": "idem_ttl_race_reuse_01",
            },
            seeded.principal,
            selected_scope=scope,
        )
        call_race_loser_conflict = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-exp",
                "description": "conflicting loser payload v2",
                "idempotency_key": "idem_ttl_race_reuse_01",
            },
            seeded.principal,
            selected_scope=scope,
        )
        winner_2_result: dict[str, JsonValue] | None = None
        inject_conflict_once = True

        def raced_conflict_commit(**kwargs: object) -> tuple[StoredResult, bool]:
            nonlocal inject_conflict_once, winner_2_result
            if inject_conflict_once:
                inject_conflict_once = False
                winner_2_result = _expect_ok(
                    "prepare_task",
                    race_bridge.dispatch(
                        call_race_winner_2,
                        _ctx_for(rt, seeded.principal, mono, selected_scope=scope),
                        auth=_auth_for(seeded),
                    ),
                )
            return orig_commit_fn(**kwargs)  # type: ignore[arg-type]

        race_bridge._dispatcher._idempotency.commit_prepared_effect = raced_conflict_commit  # type: ignore[method-assign]
        try:
            _expect_err(
                "prepare_task",
                race_bridge.dispatch(
                    call_race_loser_conflict,
                    _ctx_for(rt, seeded.principal, mono, selected_scope=scope),
                    auth=_auth_for(seeded),
                ),
                ErrorCode.IDEMPOTENCY_CONFLICT,
            )
        finally:
            race_bridge._dispatcher._idempotency.commit_prepared_effect = orig_commit_fn  # type: ignore[method-assign]

        assert winner_2_result is not None
        assert race_domain.apply_calls == 3  # only winner_2 ran apply; conflicting loser wrote nothing!
        assert len(race_completions) == 3
    finally:
        rt.close()


# --- 6. Retry after working-tree change or alias repointing keeps original binding & snapshot -----------------------


def test_retry_after_tree_changes_keeps_original_snapshot(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws_1 = _register_ws(rt, clock, seeded, alias="ws-hint", checkout_dir=trusted_tmp / "chk-1", remote=REMOTE_A)
        ws_2 = _register_ws(rt, clock, seeded, alias="ws-other-2", checkout_dir=trusted_tmp / "chk-2", remote=REMOTE_B)
        obs = FakeObserver(descriptor=_desc(TREE_A))
        bridge, domain = _make_bridge(rt, clock, mono, observer=obs)

        call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-hint",
                "description": "capture snapshot before tree edits",
                "idempotency_key": "idem_tree_change_0001",
            },
            seeded.principal,
            selected_scope=None,
        )
        first = _expect_ok(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)),
        )
        assert first["checkout_id"] == ws_1.checkout_id
        assert first["snapshot_status"] == "available"
        assert first["source_snapshot_id"] is not None

        # Mutate observer tree AND repoint alias "ws-hint" -> ws_2 in policy!
        obs.descriptor = _desc(TREE_C, dirty_digest=TREE_B)
        with rt.policy._immediate() as pdb:
            pdb.execute("UPDATE workspace_checkout SET alias = 'ws-old-1' WHERE checkout_id = ?", (ws_1.checkout_id,))
            pdb.execute("UPDATE workspace_checkout SET alias = 'ws-hint' WHERE checkout_id = ?", (ws_2.checkout_id,))

        replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)),
        )
        assert replayed == first
        assert len(obs.calls) == 1
        assert domain.prepare_calls == 1
        assert domain.apply_calls == 1

        # Revoking repo_grant on recorded ws_1.repo_id (even while "ws-hint" points to still-granted ws_2!)
        # MUST fail closed with NOT_FOUND on selected_scope=None replay — never returning ungranted ws_1's Delivery!
        with rt.policy._immediate() as pdb:
            pdb.execute(
                "DELETE FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
                (seeded.principal.principal_id, ws_1.repo_id),
            )
        _expect_err(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)),
            ErrorCode.NOT_FOUND,
        )
    finally:
        rt.close()


# --- 7. Request canonicalization & credential rotation under same principal -----------------------------------------


def test_request_canonicalization_and_credential_rotation_replay(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        cred_1 = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, cred_1, alias="ws-canon", checkout_dir=trusted_tmp / "chk-canon")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))

        # Raw JSON 1: unsorted keys, extra whitespace, omitted default context_budget_tokens, optional principal fields,
        # and correlation_id="corr-1".
        raw_1 = (
            b'{\n  "idempotency_key" : "idem_canon_00001" ,\n'
            b'  "description": "canonicalize request",\n'
            b'  "workspace_hint": "ws-canon",\n'
            b'  "owner_id": "' + cred_1.principal.owner_id.encode("utf-8") + b'",\n'
            b'  "principal_id": "' + cred_1.principal.principal_id.encode("utf-8") + b'",\n'
            b'  "schema_version": "2.0"\n}'
        )
        # Raw JSON 2: compact, different key order, explicit default context_budget_tokens=4000, no optional identity
        # fields, different correlation_id="corr-2".
        raw_2 = (
            b'{"schema_version":"2.0","context_budget_tokens":'
            + str(DEFAULT_CONTEXT_BUDGET_TOKENS).encode("ascii")
            + b',"workspace_hint":"ws-canon","description":"canonicalize request","idempotency_key":"idem_canon_00001"}'
        )

        call_1 = normalize_call(
            "prepare_task",
            parse_json(raw_1),
            cred_1.principal,
            selected_scope=scope,
            correlation_id="corr-1",
        )
        call_2 = normalize_call(
            "prepare_task",
            parse_json(raw_2),
            cred_1.principal,
            selected_scope=scope,
            correlation_id="corr-2",
        )
        _, key_bytes = rt.policy.request_digest_key()
        assert compute_request_hmac(key_bytes, call_1) == compute_request_hmac(key_bytes, call_2)

        first = _expect_ok(
            "prepare_task",
            bridge.dispatch(call_1, _ctx_for(rt, cred_1.principal, mono, selected_scope=scope), auth=_auth_for(cred_1)),
        )

        # Rotate credential: issue cred_2 for the same principal and revoke cred_1.
        cred_2 = seed_principal_and_credential(rt.policy)
        assert cred_2.principal == cred_1.principal
        rt.policy.record_authorized_revocation(
            cred_1.credential_id,
            make_bootstrap_auth(
                store_id=rt.policy.store_id,
                owner_id=cred_1.principal.owner_id,
                action="credential_revoke",
                subject_id=cred_1.credential_id,
                trust_generation=rt.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )

        replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(call_2, _ctx_for(rt, cred_2.principal, mono, selected_scope=scope), auth=_auth_for(cred_2)),
        )
        assert replayed == first
        assert domain.apply_calls == 1
    finally:
        rt.close()


# --- 8. store3 -> store4 offline migration, min_reader=4 fence, and backup/restore ----------------------------------


def test_store3_to_store4_migration_min_reader_fence_and_backup_restore(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    assert STORE_V4_MIGRATION.to_version == 4
    assert STORE_V4_MIGRATION.min_reader_version == 4
    assert code_version(KERNEL_STORE_MIGRATIONS) == 4

    v3_store_migrations = KERNEL_STORE_MIGRATIONS[:3]
    assert code_version(v3_store_migrations) == 3

    # Create a (store=3, policy=3) root and populate workspace data.
    root = trusted_tmp / "mig-root"
    handlers, kinds = fixture_store_extensions()
    rt_v3 = open_runtime(
        root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=v3_store_migrations,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        seeded = seed_principal_and_credential(rt_v3.policy)
        ws = _register_ws(rt_v3, clock, seeded, alias="ws-mig", checkout_dir=trusted_tmp / "chk-mig")
        store_id = rt_v3.store.store_id
    finally:
        rt_v3.close()

    assert read_schema_info(root / "store" / "brain.db") == SchemaInfo(3, 3, store_id)

    # Serve admission before offline migration refuses mixed (store=3, policy=3) against target (4, 3).
    with pytest.raises(BrainError) as mixed_exc:
        admit_existing_pair(root, store_id, os_, purpose="serve")
    assert mixed_exc.value.code is ErrorCode.MIGRATION_REQUIRED

    # Offline migrate upgrades store 3 -> 4 (policy 3 noop).
    cert_f = trusted_tmp / "leaf.pem"
    key_f = trusted_tmp / "leaf.key"
    cert_f.write_bytes(b"cert")
    key_f.write_bytes(b"key")
    cfg = DaemonConfig(
        version=1,
        data_root=root,
        expected_store_id=store_id,
        cert_path=cert_f,
        key_path=key_f,
    )
    mig_report = migrate_offline(cfg, os_)
    assert mig_report.policy_report.status == "skipped"
    assert mig_report.store_report.status == "migrated"
    assert mig_report.store_report.from_version == 3
    assert mig_report.store_report.to_version == 4
    assert read_schema_info(root / "store" / "brain.db") == SchemaInfo(4, 4, store_id)

    # A v3 reader refuses a store4 root (min_reader_version=4 -> UNSUPPORTED_VERSION).
    with pytest.raises(BrainError) as down_exc:
        admit_existing_pair(
            root,
            store_id,
            os_,
            purpose="serve",
            store_migrations=v3_store_migrations,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
    assert down_exc.value.code is ErrorCode.UNSUPPORTED_VERSION

    # Open store4, take a policy backup BEFORE adding a new request key, commit an idempotent row, backup & restore.
    rt_v4 = _reopen_fixture_runtime(root, store_id, os_)
    try:
        clock.advance(dt.timedelta(seconds=5))
        pol_backup_old = create_policy_backup(rt_v4.policy, os_, clock.now())

        # Rotate to a second active key in policy so pol_backup_old lacks key_2!
        key_2_id = new_id()
        key_2_bytes = b"\x33" * 32
        with rt_v4.policy._immediate() as pdb:
            pdb.execute("UPDATE request_digest_key SET active = 0 WHERE active = 1")
            pdb.execute(
                "INSERT INTO request_digest_key (id, key_bytes, active, created_at) VALUES (?, ?, 1, ?)",
                (key_2_id, key_2_bytes, utc_timestamp(clock.now())),
            )

        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, _ = _make_bridge(rt_v4, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))
        call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-mig",
                "description": "row committed on store4",
                "idempotency_key": "idem_store4_backup_01",
            },
            seeded.principal,
            selected_scope=scope,
        )
        committed = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call, _ctx_for(rt_v4, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        clock.advance(dt.timedelta(seconds=5))
        store_backup_v4 = create_store_backup(rt_v4.store, os_, clock.now())
    finally:
        rt_v4.close()

    # Restore store4 backup into root while policy still holds key_2 -> row replays cleanly!
    from superbrain.storage.policy_store import PolicyStore

    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root, os_) as (mroot, lease):
        policy_only = PolicyStore.open(mroot, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(
                mroot, lease, os_, store_backup_v4, policy_only, clock.now(), migrations=KERNEL_STORE_MIGRATIONS
            )
        finally:
            policy_only.close()

    rt_restored = _reopen_fixture_runtime(root, store_id, os_)
    try:
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge_r, dom_r = _make_bridge(rt_restored, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_B)))
        replayed = _expect_ok(
            "prepare_task",
            bridge_r.dispatch(
                call, _ctx_for(rt_restored, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert replayed == committed
        assert dom_r.apply_calls == 0
    finally:
        rt_restored.close()

    # Now restore the older policy backup lacking key_2 -> replay fails closed with POLICY_UNAVAILABLE!
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root, os_) as (mroot, lease):
        restore_policy(
            mroot, lease, os_, pol_backup_old, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )

    rt_missing_key = _reopen_fixture_runtime(root, store_id, os_)
    try:
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge_mk, _ = _make_bridge(rt_missing_key, clock, mono)
        _expect_err(
            "prepare_task",
            bridge_mk.dispatch(
                call, _ctx_for(rt_missing_key, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.POLICY_UNAVAILABLE,
        )
    finally:
        rt_missing_key.close()


# --- 9. Canary privacy scan across commit, rollback, retry, and repr -----------------------------------------------


def test_canary_privacy_scan_across_commit_rollback_and_retry(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    data_root = trusted_tmp / "canary-root"
    rt = _open_fixture_runtime(data_root, os_)
    raw_idem_ok = "idem_CANARY_KEY_OK_991122"
    raw_idem_fail = "idem_CANARY_KEY_FAIL_883344"
    canary_desc_ok = "task <private>CANARY_PRIV_BLOCK_774411</private> notes"
    canary_desc_fail = "task <private>CANARY_ROLLBACK_SECRET_665500</private> notes"
    canary_stripped_seg = "api_secret"
    try:
        seeded = seed_principal_and_credential(rt.policy)
        raw_token = seeded.token
        raw_secret_part = seeded.raw_secret_b64
        ws = _register_ws(rt, clock, seeded, alias="ws-can", checkout_dir=trusted_tmp / "chk-can")
        scope = Scope(ws.repo_id, ws.checkout_id)

        auth = _auth_for(seeded)
        assert raw_token not in repr(auth)
        assert raw_secret_part not in repr(auth)

        # Also verify RequestAuthView repr hides key_bytes.
        view_canary_bytes = b"CANARY_HMAC_KEY_BYTES_32_SECRET!"
        assert len(view_canary_bytes) == 32
        view = RequestAuthView(
            version=1,
            auth=rt.policy.snapshot(),
            active_request_key_id="key-canary-test",
            active_request_key_bytes=view_canary_bytes,
        )
        assert "CANARY_HMAC_KEY_BYTES" not in repr(view)

        bad_path_ref = ObjectRef(kind="context", id="ctx-sec", revision=1, digest=digest_bytes(b"ctx-sec"))

        def plan(binding: WorkspaceBinding, _tid: str) -> Sequence[FixtureDeliveryRefSpec]:
            return (
                FixtureDeliveryRefSpec(
                    slot="context",
                    ref=bad_path_ref,
                    owner_id=binding.owner_id,
                    repo_id=binding.repo_id,
                    checkout_id=binding.checkout_id,
                    custom_field_path=("context", canary_stripped_seg, "CANARY_STRIPPED_PATH_551199"),
                ),
            )

        bridge, domain = _make_bridge(
            rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)), delivery_plan=plan
        )

        # 1) Commit + replay
        call_ok = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-can",
                "description": canary_desc_ok,
                "idempotency_key": raw_idem_ok,
            },
            seeded.principal,
            selected_scope=scope,
        )
        res_ok = bridge.dispatch(call_ok, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=auth)
        _expect_ok("prepare_task", res_ok)
        _expect_ok(
            "prepare_task",
            bridge.dispatch(call_ok, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=auth),
        )

        # 2) Pre-commit rollback
        def abort_tx(_tx: object) -> None:
            raise BrainError(ErrorCode.IO_ERROR, "I/O error")

        domain.before_apply_hook = abort_tx
        call_fail = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-can",
                "description": canary_desc_fail,
                "idempotency_key": raw_idem_fail,
            },
            seeded.principal,
            selected_scope=scope,
        )
        res_fail = bridge.dispatch(call_fail, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=auth)
        _expect_err("prepare_task", res_fail, ErrorCode.IO_ERROR)
    finally:
        rt.close()

    canaries = (
        raw_idem_ok.encode("utf-8"),
        raw_idem_fail.encode("utf-8"),
        b"CANARY_PRIV_BLOCK_774411",
        b"CANARY_ROLLBACK_SECRET_665500",
        b"CANARY_STRIPPED_PATH_551199",
        raw_token.encode("utf-8"),
        raw_secret_part.encode("utf-8"),
    )
    scanned_files = 0
    for root_dir, _dirs, files in os.walk(data_root):
        for fname in files:
            fpath = Path(root_dir) / fname
            content = fpath.read_bytes()
            scanned_files += 1
            for needle in canaries:
                assert needle not in content, f"canary {needle!r} leaked into {fpath}"
    assert scanned_files >= 2


# --- 10. Existing task_id with new key or expired key creates a new logical Delivery (C1) --------------------------


def test_existing_task_with_new_key_or_expired_key_creates_new_logical_delivery(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    root = trusted_tmp / "c1-root"
    rt = _open_fixture_runtime(root, os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws_a = _register_ws(rt, clock, seeded, alias="ws-a", checkout_dir=trusted_tmp / "chk-a", remote=REMOTE_A)
        ws_b = _register_ws(rt, clock, seeded, alias="ws-b", checkout_dir=trusted_tmp / "chk-b", remote=REMOTE_B)
        ws_c = _register_ws(rt, clock, seeded, alias="ws-c", checkout_dir=trusted_tmp / "chk-c", remote=REMOTE_C)
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        ref_1 = ObjectRef(kind="lesson", id="les-1", revision=1, digest=digest_bytes(b"les-1"))
        ref_snap_dep = ObjectRef(kind="context", id="ctx-snap", revision=1, digest=digest_bytes(b"ctx-snap"))
        ref_gate_c = ObjectRef(kind="gate", id="gate-c-snap", revision=1, digest=digest_bytes(b"gate-c-snap"))
        ref_2 = ObjectRef(kind="skill", id="sk-2", revision=1, digest=digest_bytes(b"sk-2"))

        current_specs: list[FixtureDeliveryRefSpec] = [
            FixtureDeliveryRefSpec(
                slot="lessons",
                ref=ref_1,
                owner_id="dan",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                unknown_source=True,  # Marks task + field unknown on Delivery 1!
            ),
            FixtureDeliveryRefSpec(
                slot="context",
                ref=ref_snap_dep,
                owner_id="dan",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                snapshot_dependent=True,
            ),
        ]

        obs = FakeObserver(descriptor=_desc(TREE_A), status=SnapshotStatus.AVAILABLE)
        bridge, _domain = _make_bridge(rt, clock, mono, observer=obs, delivery_plan=lambda _b, _t: tuple(current_specs))

        # Delivery 1 on task-shared-01: snapshot AVAILABLE, unknown_source=True on lessons[0].
        call_k1 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": "task-shared-01",
                "description": "first operation on task",
                "idempotency_key": "idem_task_op_0001",
            },
            seeded.principal,
            selected_scope=scope_a,
        )
        d1 = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_k1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert d1["snapshot_status"] == "available"
        assert d1["source_snapshot_id"] is not None
        assert len(cast(list[object], d1["context"])) == 1

        # Trying to bind existing task-shared-01 to ws_b with a new key MUST fail with NOT_FOUND.
        wrong_ws_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_b.repo_id,
                "checkout_id": ws_b.checkout_id,
                "task_id": "task-shared-01",
                "description": "attempt scope move",
                "idempotency_key": "idem_task_move_0002",
            },
            seeded.principal,
            selected_scope=scope_b,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                wrong_ws_call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_b), auth=_auth_for(seeded)
            ),
            ErrorCode.NOT_FOUND,
        )

        # Delivery 2 on SAME task-shared-01 with a NEW idempotency key when observer is UNAVAILABLE:
        # Must NOT hit Task 3's load_delivery(task_id) shortcut; creates a new Delivery ID & assignment ID,
        # omits snapshot-dependent context, and retains prior unknown/source constraints!
        obs.status = SnapshotStatus.UNAVAILABLE
        obs.descriptor = None
        current_specs[:] = [
            FixtureDeliveryRefSpec(
                slot="skills",
                ref=ref_2,
                owner_id="dan",
                repo_id=ws_b.repo_id,
                checkout_id=None,
                unknown_source=False,
            ),
            FixtureDeliveryRefSpec(
                slot="context",
                ref=ref_snap_dep,
                owner_id="dan",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                snapshot_dependent=True,
            ),
            FixtureDeliveryRefSpec(
                slot="finishing_gates",
                ref=ref_gate_c,
                owner_id="dan",
                repo_id=ws_c.repo_id,
                checkout_id=None,
                snapshot_dependent=True,
            ),
        ]
        call_k2 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": "task-shared-01",
                "description": "second operation on same task with new key",
                "idempotency_key": "idem_task_op_0002",
            },
            seeded.principal,
            selected_scope=scope_a,
        )
        clock.advance(dt.timedelta(hours=1))
        d2 = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_k2, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert d2["task_id"] == "task-shared-01"
        assert d2["delivery_id"] != d1["delivery_id"]
        assert d2["assignment_id"] != d1["assignment_id"]
        assert d2["snapshot_status"] == "unavailable"
        assert d2["source_snapshot_id"] is None
        assert d2["context"] == []
        assert d2["finishing_gates"] == []

        # Omitted snapshot_dependent cross-repo source (ws_c) MUST NOT pollute p_task_lineage_sources on unavailable d2!
        with rt.store.transaction() as stxn:
            d2_task_repos = {
                str(r[0])
                for r in stxn.db.execute(
                    "SELECT repo_id FROM p_task_lineage_sources WHERE task_id = 'task-shared-01'"
                ).fetchall()
            }
        assert ws_b.repo_id in d2_task_repos
        assert ws_c.repo_id not in d2_task_repos

        # Replaying k1 STILL returns d1's AVAILABLE snapshot & delivery_id (never task's latest unavailable status!).
        d1_replay = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_k1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert d1_replay == d1

        # Delivery 3 on SAME task-shared-01 via EXPIRED key k1 after 30 days with TREE_B snapshot
        # (while k2 committed 1 hour later remains live at 29d 23h):
        clock.advance(dt.timedelta(days=29, hours=23))
        obs.status = SnapshotStatus.AVAILABLE
        obs.descriptor = _desc(TREE_B)
        d3 = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_k1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert d3["delivery_id"] not in {d1["delivery_id"], d2["delivery_id"]}
        assert d3["source_snapshot_id"] not in {None, d1["source_snapshot_id"]}

        # Verify monotonic task & field lineage constraints (sticky unknown + accumulated sources) and shadow rebuild!
        with rt.store.transaction() as stxn:
            unk_row = stxn.db.execute(
                "SELECT 1 FROM p_task_lineage_unknown WHERE task_id = 'task-shared-01'"
            ).fetchone()
            lessons_digest = field_path_digest(("lessons", 0))
            f_unk_row = stxn.db.execute(
                "SELECT 1 FROM p_field_lineage_unknown WHERE task_id = 'task-shared-01' AND field_path_digest = ?",
                (lessons_digest,),
            ).fetchone()
            d3_task_repos = {
                str(r[0])
                for r in stxn.db.execute(
                    "SELECT repo_id FROM p_task_lineage_sources WHERE task_id = 'task-shared-01'"
                ).fetchall()
            }
        assert unk_row is not None
        assert f_unk_row is not None
        assert ws_c.repo_id in d3_task_repos

        rt.store.rebuild_projections()
        d2_after_rebuild = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_k2, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert d2_after_rebuild == d2

        # Backup & restore preserves all per-result records and each logical result's exact snapshot status.
        clock.advance(dt.timedelta(seconds=5))
        bkp = create_store_backup(rt.store, os_, clock.now())
        store_id = rt.store.store_id
    finally:
        rt.close()

    from superbrain.storage.policy_store import PolicyStore

    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root, os_) as (mroot, lease):
        pol_only = PolicyStore.open(mroot, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(mroot, lease, os_, bkp, pol_only, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol_only.close()

    rt_after = _reopen_fixture_runtime(root, store_id, os_)
    try:
        bridge_after, dom_after = _make_bridge(rt_after, clock, mono)
        assert (
            _expect_ok(
                "prepare_task",
                bridge_after.dispatch(
                    call_k2, _ctx_for(rt_after, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
                ),
            )
            == d2
        )
        assert (
            _expect_ok(
                "prepare_task",
                bridge_after.dispatch(
                    call_k1, _ctx_for(rt_after, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
                ),
            )
            == d3
        )
        assert dom_after.apply_calls == 0
    finally:
        rt_after.close()


# --- 11. CAS blobs staged outside SQLite transaction & strict hold_blob rejects undeclared/missing blobs -----------


def test_cas_is_staged_before_transaction_and_only_declared_blobs_can_be_held(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "c2-root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-c2", checkout_dir=trusted_tmp / "chk-c2")
        scope = Scope(ws.repo_id, ws.checkout_id)

        in_tx_states: list[bool] = []
        orig_put = rt.store.cas.put

        def recording_put(data: bytes) -> str:
            in_tx_states.append(rt.store._db.in_transaction)
            return orig_put(data)

        rt.store.cas.put = recording_put  # type: ignore[method-assign]

        stripped_ref = ObjectRef(kind="context", id="ctx-stripped", revision=1, digest=digest_bytes(b"stripped"))
        kept_ref = ObjectRef(kind="skill", id="sk-kept", revision=1, digest=digest_bytes(b"kept"))

        def plan(binding: WorkspaceBinding, _tid: str) -> Sequence[FixtureDeliveryRefSpec]:
            return (
                FixtureDeliveryRefSpec(
                    slot="skills",
                    ref=kept_ref,
                    owner_id=binding.owner_id,
                    repo_id=binding.repo_id,
                    checkout_id=binding.checkout_id,
                ),
                FixtureDeliveryRefSpec(
                    slot="context",
                    ref=stripped_ref,
                    owner_id=binding.owner_id,
                    repo_id=binding.repo_id,
                    checkout_id=binding.checkout_id,
                    custom_field_path=("context", "client_secret", "never_stage"),
                ),
            )

        bridge, domain = _make_bridge(
            rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)), delivery_plan=plan
        )
        call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c2",
                "description": "stage blobs outside transaction",
                "idempotency_key": "idem_c2_stage_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            bridge.dispatch(call, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)),
        )
        assert in_tx_states and all(state is False for state in in_tx_states)

        # Stripped path descriptor was NEVER staged into CAS, not even as an unheld orphan!
        from superbrain.core.kernel import field_path_descriptor

        stripped_blob_digest = digest_bytes(field_path_descriptor(("context", "client_secret", "never_stage")))
        assert stripped_blob_digest not in blob_digests(rt.root.cas_dir, os_)

        # Undeclared blob inside strict hold_blob fails with INTEGRITY_FAILURE without calling cas.put!
        put_calls_during_tx = 0

        def forbid_put_in_tx(data: bytes) -> str:
            nonlocal put_calls_during_tx
            if rt.store._db.in_transaction:
                put_calls_during_tx += 1
            return orig_put(data)

        rt.store.cas.put = forbid_put_in_tx  # type: ignore[method-assign]

        def hold_undeclared(tx: object) -> None:
            from superbrain.ports.kernel import KernelTx

            cast(KernelTx, tx).hold_blob(b"undeclared-bytes", holder_id=new_id())

        domain.before_apply_hook = hold_undeclared
        call_undecl = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c2",
                "description": "attempt undeclared hold",
                "idempotency_key": "idem_c2_stage_0002",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                call_undecl, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )
        assert put_calls_during_tx == 0
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1

        # Missing blob on disk even if listed in StagedBlob bundle also fails with INTEGRITY_FAILURE.
        missing_bytes = b"declared-but-missing-on-disk"
        fake_staged = StagedBlob(
            store_id=rt.store.store_id,
            digest=digest_bytes(missing_bytes),
            size_bytes=len(missing_bytes),
        )
        with pytest.raises(BrainError) as miss_exc, rt.store.transaction() as stxn:
            strict_tx = StrictKernelTx(
                stxn,
                rt.store.cas,
                rt.policy,
                store_id=rt.store.store_id,
                staged_blobs=(fake_staged,),
            )
            strict_tx.hold_blob(missing_bytes, holder_id=new_id())
        assert miss_exc.value.code is ErrorCode.INTEGRITY_FAILURE

        # Stage failure / cancellation on 2nd blob BEFORE SQLite transaction opens (C2, task-4-brief.md:85, 188):
        # leaves zero new idempotency rows, zero new holds, zero new ledger/projection rows, and only safe unheld
        # orphan bytes in CAS; clean retry executes the full transaction and holds the blobs!
        domain.before_apply_hook = None
        new_obs_desc = _desc(TREE_C)
        obs_stage_fail = FakeObserver(descriptor=new_obs_desc)
        stage_fail_plan = lambda binding, _tid: (  # noqa: E731
            FixtureDeliveryRefSpec(
                slot="lessons",
                ref=kept_ref,
                owner_id=binding.owner_id,
                repo_id=binding.repo_id,
                checkout_id=binding.checkout_id,
                custom_field_path=("lessons", "safe_stage_orphan_check"),
            ),
        )
        bridge_sf, domain_sf = _make_bridge(rt, clock, mono, observer=obs_stage_fail, delivery_plan=stage_fail_plan)
        idem_before_sf = _count_rows(rt.store, "idempotency")
        holds_before_sf = _count_rows(rt.store, "p_cas_holders_")
        ledger_before_sf = _count_rows(rt.store, "ledger")
        deliv_before_sf = _count_rows(rt.store, "p_fixture_domain_deliveries")

        stage_calls = 0

        def fail_on_second_stage(data: bytes) -> str:
            nonlocal stage_calls
            assert not rt.store._db.in_transaction
            stage_calls += 1
            if stage_calls == 2:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            return orig_put(data)

        rt.store.cas.put = fail_on_second_stage  # type: ignore[method-assign]
        call_sf = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c2",
                "description": "stage cancel after first safe blob",
                "idempotency_key": "idem_c2_stage_fail_03",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge_sf.dispatch(
                call_sf, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.DEADLINE_EXCEEDED,
        )
        assert stage_calls == 2
        assert domain_sf.apply_calls == 0
        assert _count_rows(rt.store, "idempotency") == idem_before_sf
        assert _count_rows(rt.store, "p_cas_holders_") == holds_before_sf
        assert _count_rows(rt.store, "ledger") == ledger_before_sf
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == deliv_before_sf
        assert new_obs_desc.descriptor_digest in rt.store.cas.orphans()

        # Restore CAS publisher and retry with the exact same key -> full transaction runs and holds the blobs!
        rt.store.cas.put = orig_put  # type: ignore[method-assign]
        sf_ok = _expect_ok(
            "prepare_task",
            bridge_sf.dispatch(
                call_sf, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert sf_ok["snapshot_status"] == "available"
        assert domain_sf.apply_calls == 1
        assert _count_rows(rt.store, "idempotency") == idem_before_sf + 1
        assert new_obs_desc.descriptor_digest not in rt.store.cas.orphans()

        # Direct StoreKernelTx.read_idempotency / save_idempotency delegation check.
        direct_kh = compute_idempotency_key_hash(seeded.principal.principal_id, "prepare_task", "idem_direct_ktx_0001")
        active_kid, active_kbytes = rt.policy.request_digest_key()
        direct_row = IdempotencyRow(
            principal_id=seeded.principal.principal_id,
            tool="prepare_task",
            key_hash=direct_kh,
            request_digest_key_id=active_kid,
            request_digest=compute_request_hmac(active_kbytes, call_sf),
            result_id="direct-res-1",
            assignment_id=None,
            refs=(kept_ref,),
            committed_at=utc_timestamp(clock.now()),
        )
        with rt.store.transaction() as stxn:
            base_ktx = StoreKernelTx(stxn, rt.store.cas, rt.policy)
            assert base_ktx.read_idempotency(seeded.principal.principal_id, "prepare_task", direct_kh) is None
            base_ktx.save_idempotency(direct_row)
            assert base_ktx.read_idempotency(seeded.principal.principal_id, "prepare_task", direct_kh) == direct_row
    finally:
        rt.close()


# --- 12. C4 clock regression & missing watermark with retained rows refuse without writes --------------------------


def test_clock_regression_refuses_handling_and_pruning_without_writes(trusted_tmp: Path) -> None:
    t_commit = dt.datetime(2026, 11, 1, 0, 0, 0, 0, tzinfo=dt.UTC)
    clock = FakeClock(t_commit)
    os_ = os_adapters(clock=clock)
    mono = Mono()
    root = trusted_tmp / "c4-root"

    rt = _open_fixture_runtime(root, os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-c4", checkout_dir=trusted_tmp / "chk-c4")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))

        call_1 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c4",
                "description": "commit at Nov 1",
                "idempotency_key": "idem_c4_clock_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        orig = _expect_ok(
            "prepare_task",
            bridge.dispatch(call_1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)),
        )

        # Advance watermark to 2026-11-20T00:00:00Z via replay.
        clock.set(dt.datetime(2026, 11, 20, 0, 0, 0, 0, tzinfo=dt.UTC))
        assert (
            _expect_ok(
                "prepare_task",
                bridge.dispatch(
                    call_1, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
                ),
            )
            == orig
        )
        store_id = rt.store.store_id
    finally:
        rt.close()

    # Reopen (restart!) with regressed wall clock at 2026-11-19T00:00:00Z -> refuses replay, new key, and prune!
    clock.set(dt.datetime(2026, 11, 19, 0, 0, 0, 0, tzinfo=dt.UTC))
    rt2 = _reopen_fixture_runtime(root, store_id, os_)
    try:
        bridge2, domain2 = _make_bridge(rt2, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_B)))
        assert bridge2.clock_untrusted() is False

        # Same-key replay refused with INTEGRITY_FAILURE + static wire message + zero writes.
        err_replay = _expect_err(
            "prepare_task",
            bridge2.dispatch(
                call_1, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )
        assert err_replay["message"] == "integrity failure"
        assert bridge2.clock_untrusted() is True

        # Shallow get_health remains available (read-only) and exposes idempotency_clock_untrusted!
        health_call = normalize_call("get_health", {"schema_version": "2.0"}, seeded.principal, selected_scope=None)
        health_data = _expect_ok(
            "get_health",
            bridge2.dispatch(
                health_call, _ctx_for(rt2, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)
            ),
        )
        assert IDEMPOTENCY_CLOCK_UNTRUSTED_CODE in cast(list[str], health_data["degraded_codes"])

        # New key ALSO refused with zero writes.
        call_new = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c4",
                "description": "new key while regressed",
                "idempotency_key": "idem_c4_clock_0002",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge2.dispatch(
                call_new, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )

        # Prune ALSO refused with zero writes.
        with pytest.raises(BrainError) as prune_exc:
            bridge2.prune_expired(clock.now(), limit=10)
        assert prune_exc.value.code is ErrorCode.INTEGRITY_FAILURE
        assert _count_rows(rt2.store, "idempotency") == 1
        assert domain2.apply_calls == 0

        # Once clock catches up to 2026-11-20T00:00:00Z, normal TTL resumes and untrusted flag clears!
        clock.set(dt.datetime(2026, 11, 20, 0, 0, 0, 0, tzinfo=dt.UTC))
        recovered = _expect_ok(
            "prepare_task",
            bridge2.dispatch(
                call_1, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert recovered == orig
        assert bridge2.clock_untrusted() is False

        # Advance HWM past 30 days (to 2026-12-10T00:00:00Z) via a second key while call_1 (Nov 1) stays retained;
        # then regress clock to 2026-12-05T00:00:00Z (< HWM Dec 10, while >= Dec 1 30d expiry cutoff for call_1):
        # reusing expired call_1 MUST still be refused with INTEGRITY_FAILURE and zero writes (row NOT replaced!).
        clock.set(dt.datetime(2026, 12, 10, 0, 0, 0, 0, tzinfo=dt.UTC))
        call_hwm_dec10 = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c4",
                "description": "advance hwm to Dec 10",
                "idempotency_key": "idem_c4_clock_dec10_03",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            bridge2.dispatch(
                call_hwm_dec10, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert domain2.apply_calls == 1

        clock.set(dt.datetime(2026, 12, 5, 0, 0, 0, 0, tzinfo=dt.UTC))
        call_1_replacement = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c4",
                "description": "attempt expired replacement while regressed below Dec 10 HWM",
                "idempotency_key": "idem_c4_clock_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge2.dispatch(
                call_1_replacement, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )
        assert bridge2.clock_untrusted() is True
        assert domain2.apply_calls == 1
        with rt2.store.transaction() as stxn:
            call_1_comm = stxn.db.execute(
                "SELECT committed_at FROM idempotency WHERE key_hash = ?",
                (compute_idempotency_key_hash(seeded.principal.principal_id, "prepare_task", "idem_c4_clock_0001"),),
            ).fetchone()
        assert call_1_comm == ("2026-11-01T00:00:00.000000Z",)

        # Catch clock back up to 2026-12-15T00:00:00Z, then corrupt a mid-range row's committed_at so it sorts
        # lexicographically between MIN ("2026-11-01...") and MAX ("2026-12-10..."): validate_c4_clock catches it!
        clock.set(dt.datetime(2026, 12, 15, 0, 0, 0, 0, tzinfo=dt.UTC))
        call_mid = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-c4",
                "description": "seed third row for mid-range corruption check",
                "idempotency_key": "idem_c4_clock_mid_0004",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            bridge2.dispatch(
                call_mid, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert bridge2.clock_untrusted() is False
        mid_kh = compute_idempotency_key_hash(seeded.principal.principal_id, "prepare_task", "idem_c4_clock_dec10_03")
        with rt2.store.transaction() as stxn:
            stxn.db.execute(
                "UPDATE idempotency SET committed_at = '2026-11-15T99:99:99.000000Z' WHERE key_hash = ?",
                (mid_kh,),
            )
        _expect_err(
            "prepare_task",
            bridge2.dispatch(
                call_mid, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )
        assert bridge2.clock_untrusted() is True
        # Restore valid timestamp before testing missing-watermark refusal.
        with rt2.store.transaction() as stxn:
            stxn.db.execute(
                "UPDATE idempotency SET committed_at = '2026-12-10T00:00:00.000000Z' WHERE key_hash = ?",
                (mid_kh,),
            )

        # Missing watermark while retained idempotency rows exist -> INTEGRITY_FAILURE + clock_untrusted!
        with rt2.store.transaction() as stxn:
            stxn.db.execute("DELETE FROM meta WHERE key = ?", (IDEMPOTENCY_CLOCK_HWM_META_KEY,))
        _expect_err(
            "prepare_task",
            bridge2.dispatch(
                call_1, _ctx_for(rt2, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.INTEGRITY_FAILURE,
        )
        assert bridge2.clock_untrusted() is True
    finally:
        rt2.close()


# --- 13. Lost commit completion vs definitive pre-commit rollback --------------------------------------------------


def test_committed_result_survives_lost_commit_completion(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "lost-root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-lost", checkout_dir=trusted_tmp / "chk-lost")
        scope = Scope(ws.repo_id, ws.checkout_id)

        raise_after_commit = True

        def completion_hook(_res: StoredResult) -> None:
            if raise_after_commit:
                raise RuntimeError("simulated lost commit completion signal")

        obs = FakeObserver(descriptor=_desc(TREE_A))
        bridge, domain = _make_bridge(rt, clock, mono, observer=obs, on_commit_completed=completion_hook)

        call_lost = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-lost",
                "description": "commit succeeds then completion raises",
                "idempotency_key": "idem_lost_commit_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        first_res = bridge.dispatch(
            call_lost, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
        )
        _expect_err("prepare_task", first_res, ErrorCode.COMMIT_OUTCOME_UNKNOWN)
        assert domain.apply_calls == 1
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1

        # Retry with the same key returns the committed durable result and NEVER executes a second effect!
        raise_after_commit = False
        obs.descriptor = _desc(TREE_B)
        recovered = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_lost, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert domain.apply_calls == 1
        assert len(obs.calls) == 1
        assert recovered["snapshot_status"] == "available"

        # Compare with definitive pre-commit rollback: leaves no row, so retry executes once cleanly.
        def abort_before_commit(_tx: object) -> None:
            raise BrainError(ErrorCode.STORAGE_FULL, "storage full")

        domain.before_apply_hook = abort_before_commit
        call_rb = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": "ws-lost",
                "description": "definitive rollback before commit",
                "idempotency_key": "idem_definitive_rb_0002",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                call_rb, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
            ErrorCode.STORAGE_FULL,
        )
        assert _count_rows(rt.store, "idempotency") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1

        domain.before_apply_hook = None
        after_rb = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_rb, _ctx_for(rt, seeded.principal, mono, selected_scope=scope), auth=_auth_for(seeded)
            ),
        )
        assert after_rb["delivery_id"] != recovered["delivery_id"]
        assert _count_rows(rt.store, "idempotency") == 2
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 2
    finally:
        rt.close()


# --- 14. Plan line 234: same repo, other checkout refused for record_outcome & get_artifact -------------------------


def test_same_repo_other_checkout_outcome_and_artifact_are_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "scope-root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        # Same remote -> same repo_id, two distinct checkouts A and B both granted to seeded.principal.
        ws_a = _register_ws(rt, clock, seeded, alias="ws-chk-a", checkout_dir=trusted_tmp / "chk-a", remote=REMOTE_A)
        ws_b = _register_ws(rt, clock, seeded, alias="ws-chk-b", checkout_dir=trusted_tmp / "chk-b", remote=REMOTE_A)
        assert ws_a.repo_id == ws_b.repo_id
        assert ws_a.checkout_id != ws_b.checkout_id

        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)
        bridge, domain = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))

        domain.seed_artifact(
            bridge,
            artifact_id="art-chk-a",
            revision=1,
            owner_id=seeded.principal.owner_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=b"checkout A artifact", level="L1"),),
        )

        prep_a = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "task in checkout A",
                "idempotency_key": "idem_scope_prep_a_01",
            },
            seeded.principal,
            selected_scope=scope_a,
        )
        deliv_a = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_a, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )

        # Profile B (selected_scope = checkout B) trying to read task/artifact from checkout A -> NOT_FOUND, 0 writes!
        art_from_b = normalize_call(
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "task_id": str(deliv_a["task_id"]),
                "artifact_id": "art-chk-a",
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem_scope_art_b_01",
            },
            seeded.principal,
            selected_scope=scope_b,
        )
        _expect_err(
            "get_artifact",
            bridge.dispatch(
                art_from_b, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_b), auth=_auth_for(seeded)
            ),
            ErrorCode.NOT_FOUND,
        )

        # Profile B trying to record_outcome on Delivery from checkout A -> NOT_FOUND, 0 writes!
        out_from_b = normalize_call(
            "record_outcome",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "delivery_id": str(deliv_a["delivery_id"]),
                "outcome": "success",
                "idempotency_key": "idem_scope_out_b_01",
            },
            seeded.principal,
            selected_scope=scope_b,
        )
        _expect_err(
            "record_outcome",
            bridge.dispatch(
                out_from_b, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_b), auth=_auth_for(seeded)
            ),
            ErrorCode.NOT_FOUND,
        )
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 0
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == 0
        assert _count_rows(rt.store, "idempotency") == 1
    finally:
        rt.close()


# --- 15. Plan line 234 & 149: profile switch with same key & unchanged outcome args conflicts ----------------------


def test_profile_switch_same_key_conflicts_even_when_outcome_args_are_unchanged(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "switch-root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws_a = _register_ws(rt, clock, seeded, alias="ws-sw-a", checkout_dir=trusted_tmp / "chk-sw-a", remote=REMOTE_A)
        ws_b = _register_ws(rt, clock, seeded, alias="ws-sw-b", checkout_dir=trusted_tmp / "chk-sw-b", remote=REMOTE_A)
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        bridge, domain = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))
        # Exercise Plan line 149: manual_submission=False strips applied_refs/read_acks to ID/status only!
        domain.repo_flags_overrides[ws_a.repo_id] = RepoFlags(manual_submission=False)

        prep_a = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "delivery for outcome",
                "idempotency_key": "idem_switch_prep_01",
            },
            seeded.principal,
            selected_scope=scope_a,
        )
        deliv_a = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_a, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )

        outcome_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws_a.repo_id,
            "delivery_id": str(deliv_a["delivery_id"]),
            "outcome": "success",
            "applied_refs": [
                {
                    "kind": "skill",
                    "id": "sk-1",
                    "revision": 1,
                    "digest": digest_bytes(b"sk-1"),
                }
            ],
            "idempotency_key": "idem_switch_outcome_01",
        }
        call_scope_a = normalize_call("record_outcome", outcome_args, seeded.principal, selected_scope=scope_a)
        out_data = _expect_ok(
            "record_outcome",
            bridge.dispatch(
                call_scope_a, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert out_data["status"] == "declared"

        # Verify manual_submission=False dropped applied_refs before persistence.
        with rt.store.transaction() as stxn:
            cnt_row = stxn.db.execute("SELECT applied_ref_count FROM p_fixture_domain_outcomes").fetchone()
        assert cnt_row == (0,)

        # Same principal, same tool, same idempotency_key, identical outcome_args, but switched selected_scope -> B:
        # Lookup hits (principal_id, "record_outcome", key_hash) and HMAC conflicts on selected_scope!
        call_scope_b = normalize_call("record_outcome", outcome_args, seeded.principal, selected_scope=scope_b)
        _expect_err(
            "record_outcome",
            bridge.dispatch(
                call_scope_b, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_b), auth=_auth_for(seeded)
            ),
            ErrorCode.IDEMPOTENCY_CONFLICT,
        )
    finally:
        rt.close()


# --- 16. Plan line 234: get_job scope classification (workspace-scoped vs owner-global) & read-only non-caching -----


def test_missing_scope_is_refused_for_workspace_job_and_global_job_is_authorized(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "job-root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude", machine_id="m1")
        foreign = seed_principal_and_credential(rt.policy, owner_id="alice", harness_id="claude", machine_id="m2")
        ws_a = _register_ws(
            rt, clock, seeded, alias="ws-job-a", checkout_dir=trusted_tmp / "chk-job-a", remote=REMOTE_A
        )
        ws_b = _register_ws(
            rt, clock, seeded, alias="ws-job-b", checkout_dir=trusted_tmp / "chk-job-b", remote=REMOTE_A
        )
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        bridge, domain = _make_bridge(rt, clock, mono)
        domain.seed_job(
            job_id="job-ws-scoped-01",
            owner_id="dan",
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            state=JobState.RUNNING,
            attempt=2,
            accounting_status=AccountingStatus.RESERVED,
        )
        domain.seed_job(
            job_id="job-owner-global-01",
            owner_id="dan",
            repo_id=None,
            checkout_id=None,
            state=JobState.SUCCEEDED,
            attempt=1,
            accounting_status=AccountingStatus.SETTLED,
        )

        # 1) Workspace-scoped job without selected_scope -> NOT_FOUND; wrong checkout -> NOT_FOUND; scope_a -> OK!
        ws_job_none = normalize_call(
            "get_job", {"schema_version": "2.0", "job_id": "job-ws-scoped-01"}, seeded.principal, selected_scope=None
        )
        _expect_err(
            "get_job",
            bridge.dispatch(
                ws_job_none, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)
            ),
            ErrorCode.NOT_FOUND,
        )
        ws_job_b = normalize_call(
            "get_job", {"schema_version": "2.0", "job_id": "job-ws-scoped-01"}, seeded.principal, selected_scope=scope_b
        )
        _expect_err(
            "get_job",
            bridge.dispatch(
                ws_job_b, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_b), auth=_auth_for(seeded)
            ),
            ErrorCode.NOT_FOUND,
        )
        ws_job_a = normalize_call(
            "get_job", {"schema_version": "2.0", "job_id": "job-ws-scoped-01"}, seeded.principal, selected_scope=scope_a
        )
        ws_job_ok = _expect_ok(
            "get_job",
            bridge.dispatch(
                ws_job_a, _ctx_for(rt, seeded.principal, mono, selected_scope=scope_a), auth=_auth_for(seeded)
            ),
        )
        assert ws_job_ok["state"] == "running"
        assert ws_job_ok["attempt"] == 2

        # 2) Owner-global job WITHOUT selected_scope is authorized for owner "dan", refused for foreign owner "alice"!
        glob_call = normalize_call(
            "get_job", {"schema_version": "2.0", "job_id": "job-owner-global-01"}, seeded.principal, selected_scope=None
        )
        glob_ok = _expect_ok(
            "get_job",
            bridge.dispatch(
                glob_call, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)
            ),
        )
        assert glob_ok["state"] == "succeeded"

        foreign_call = normalize_call(
            "get_job",
            {"schema_version": "2.0", "job_id": "job-owner-global-01"},
            foreign.principal,
            selected_scope=None,
        )
        _expect_err(
            "get_job",
            bridge.dispatch(
                foreign_call, _ctx_for(rt, foreign.principal, mono, selected_scope=None), auth=_auth_for(foreign)
            ),
            ErrorCode.NOT_FOUND,
        )

        # 3) Read-only calls & deep=True capability_unavailable NEVER write idempotency rows or C4 watermark!
        deep_health = normalize_call(
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_deep_unavail_01"},
            seeded.principal,
            selected_scope=None,
        )
        _expect_err(
            "get_health",
            bridge.dispatch(
                deep_health, _ctx_for(rt, seeded.principal, mono, selected_scope=None), auth=_auth_for(seeded)
            ),
            ErrorCode.CAPABILITY_UNAVAILABLE,
        )
        assert _count_rows(rt.store, "idempotency") == 0
    finally:
        rt.close()
