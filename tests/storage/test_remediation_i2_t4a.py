"""Requirement-derived regressions for SP1-I2 Task 4a remediation (I2-T4A-R01 and I2-T4A-R02).

Requirement sources:
- ``docs/reviews/2026-11-07-sp1-increment2-task4a-0-task4a-review.md`` (I2-T4A-R01, I2-T4A-R02)
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-4-brief.md`` (C1:56, C1:67, C3:89-90, line 136)
- ``schemas/mcp-tools-v2.json`` (``PrepareTaskResult``, ``DeliveryItem``, ``ErrorEnvelope``)
- Spec §5.2/§5.4/§5.5 (admitted single-root runtime & held ``WriterLease`` binding)
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from superbrain.adapters.os.workspaces import build_registration
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CallContext,
    Identity,
    ObjectRef,
    Principal,
    PrivateRequestAuth,
    Scope,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    StoredResult,
    WorkspaceBinding,
)
from superbrain.core.wire import normalize_call
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.runtime import Runtime, admit_existing_pair, open_runtime, open_runtime_under_lease
from superbrain.storage.store import Store
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FixtureDeliveryRefSpec,
    FixtureKernelDomain,
    fixture_store_extensions,
    validate_response_envelope,
)
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

MS = 1_000_000
REMOTE_A = "https://github.example/dan/repo-r01-alpha.git"
TREE_A = "sha256:" + "a" * 64


class Mono:
    def __init__(self, start: int = 10_000 * MS) -> None:
        self.now = start

    def __call__(self) -> int:
        return self.now


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


def _desc(tree: str = TREE_A) -> SnapshotDescriptor:
    return SnapshotDescriptor(
        kind="git",
        tree_or_head_digest=tree,
        dirty=False,
        dirty_digest=None,
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


def _clone_closed_data_root(src: Path, dst: Path, os_: OsAdapters) -> None:
    """Copy a closed data root inside ``trusted_tmp`` and apply owner-only permissions on every copied entry."""
    shutil.copytree(src, dst)
    os_.permissions.secure_directory(dst)
    for cur_dir, dirnames, filenames in os.walk(dst):
        cur_path = Path(cur_dir)
        for dirname in dirnames:
            os_.permissions.secure_directory(cur_path / dirname)
        for filename in filenames:
            os_.permissions.secure_file(cur_path / filename)
    assert os_.permissions.problems(dst) == []


def _register_ws(
    rt: Runtime,
    clock: FakeClock,
    seeded: SeededCredential,
    *,
    alias: str,
    checkout_dir: Path,
    remote: str | None = REMOTE_A,
) -> WorkspaceBinding:
    checkout_dir.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias=alias,
        raw_path=str(checkout_dir),
        raw_remote=remote,
        provider_egress_enabled=False,
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
    store_id: str,
    writer_epoch: int,
    principal: Principal,
    mono: Mono,
    *,
    selected_scope: Scope | None,
) -> CallContext:
    return CallContext(
        principal=principal,
        identity=Identity(
            store_id=store_id,
            writer_epoch=writer_epoch,
            instance_id="inst-remediation-t4a",
        ),
        deadline_ns=mono() + 1_500 * MS,
        selected_scope=selected_scope,
    )


def _make_bridge(
    rt: Runtime,
    clock: FakeClock,
    mono: Mono,
    *,
    observer: FakeObserver | None = None,
    delivery_plan: Callable[[WorkspaceBinding, str], Sequence[FixtureDeliveryRefSpec]] | None = None,
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
    )
    return bridge, domain


def _expect_ok(tool: str, res: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is True, f"expected ok=True for {tool}, got {checked}"
    data = checked["data"]
    assert isinstance(data, dict)
    return data


def _expect_err(tool: str, res: Mapping[str, JsonValue], allowed_codes: set[ErrorCode]) -> dict[str, JsonValue]:
    checked = validate_response_envelope(tool, res)
    assert checked["ok"] is False, f"expected error {[c.value for c in allowed_codes]} for {tool}, got {checked}"
    err = checked["error"]
    assert isinstance(err, dict)
    assert err["code"] in {c.value for c in allowed_codes}
    return err


def _load_stored_result(store: Store, *, principal_id: str, tool: str) -> StoredResult:
    with store.transaction() as stxn:
        row = stxn.db.execute(
            "SELECT result_id, assignment_id, refs_json FROM idempotency WHERE principal_id = ? AND tool = ?",
            (principal_id, tool),
        ).fetchone()
    assert row is not None
    return StoredResult(
        result_id=str(row[0]),
        assignment_id=None if row[1] is None else str(row[1]),
        refs=StoredResult.decode_refs_json(str(row[2])),
    )


def _read_delivery_snapshot_row(store: Store, delivery_id: str) -> tuple[str | None, str]:
    with store.transaction() as stxn:
        row = stxn.db.execute(
            "SELECT source_snapshot_id, snapshot_status FROM p_fixture_domain_deliveries WHERE delivery_id = ?",
            (delivery_id,),
        ).fetchone()
    assert row is not None
    return (None if row[0] is None else str(row[0])), str(row[1])


# =====================================================================================================================
# I2-T4A-R01: Admitted DataRoot + live WriterLease pair binding at composition boundary
# =====================================================================================================================


def test_r01_cross_root_clone_same_store_id_diverged_policy_is_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R01-A: Cloned roots sharing ``store_id`` with diverged policy cannot be cross-wired in ``KernelBridge``."""
    mono = Mono()
    root_a = trusted_tmp / "root-a"
    root_b = trusted_tmp / "root-b"

    rt_seed = _open_fixture_runtime(root_a, os_)
    try:
        cred_revoked = seed_principal_and_credential(
            rt_seed.policy, owner_id="dan", harness_id="claude", machine_id="m1"
        )
        cred_active = seed_principal_and_credential(
            rt_seed.policy, owner_id="dan", harness_id="claude", machine_id="m1"
        )
        assert cred_revoked.principal == cred_active.principal
        assert cred_revoked.credential_id != cred_active.credential_id
        ws = _register_ws(rt_seed, clock, cred_active, alias="ws-r01", checkout_dir=trusted_tmp / "chk-r01")
        store_id = rt_seed.store.store_id
    finally:
        rt_seed.close()

    _clone_closed_data_root(root_a, root_b, os_)

    rt_a = _reopen_fixture_runtime(root_a, store_id, os_)
    rt_b = _reopen_fixture_runtime(root_b, store_id, os_)
    try:
        assert rt_a.root != rt_b.root
        assert rt_a.store.store_id == rt_b.policy.store_id == store_id
        assert rt_b.store.store_id == rt_a.policy.store_id == store_id

        quar_skill_ref = ObjectRef(
            kind="skill",
            id="skill-r01-quar",
            revision=1,
            digest=digest_bytes(b"r01-quarantined-skill"),
        )
        # Diverge policy in root_a only; root_b retains pre-revoke / pre-quarantine policy.
        rt_a.policy.record_authorized_revocation(
            cred_revoked.credential_id,
            make_bootstrap_auth(
                store_id=rt_a.policy.store_id,
                owner_id="dan",
                action="credential_revoke",
                subject_id=cred_revoked.credential_id,
                trust_generation=rt_a.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        rt_a.policy.record_intent(IntentKind.QUARANTINE, {"digest": quar_skill_ref.digest})
        rt_a.store.reconcile_policy()
        assert rt_a.policy.is_quarantined(quar_skill_ref.digest) is True
        assert rt_b.policy.is_quarantined(quar_skill_ref.digest) is False

        scope = Scope(ws.repo_id, ws.checkout_id)
        plan = lambda binding, _tid: (  # noqa: E731
            FixtureDeliveryRefSpec(
                slot="skills",
                ref=quar_skill_ref,
                owner_id=binding.owner_id,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
            ),
        )
        valid_bridge, _ = _make_bridge(
            rt_a, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)), delivery_plan=plan
        )

        health_call = normalize_call(
            "get_health", {"schema_version": "2.0"}, cred_active.principal, selected_scope=None
        )
        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "control check on admitted root_a pair",
                "idempotency_key": "idem_r01_control_0001",
            },
            cred_active.principal,
            selected_scope=scope,
        )

        # Valid same-root bridge rejects cred_revoked on both get_health and prepare_task, and serves cred_active.
        _expect_err(
            "get_health",
            valid_bridge.dispatch(
                health_call,
                _ctx_for(store_id, rt_a.lease.epoch, cred_revoked.principal, mono, selected_scope=None),
                auth=_auth_for(cred_revoked),
            ),
            {ErrorCode.UNAUTHENTICATED},
        )
        _expect_err(
            "prepare_task",
            valid_bridge.dispatch(
                prep_call,
                _ctx_for(store_id, rt_a.lease.epoch, cred_revoked.principal, mono, selected_scope=scope),
                auth=_auth_for(cred_revoked),
            ),
            {ErrorCode.UNAUTHENTICATED},
        )
        _expect_ok(
            "get_health",
            valid_bridge.dispatch(
                health_call,
                _ctx_for(store_id, rt_a.lease.epoch, cred_active.principal, mono, selected_scope=None),
                auth=_auth_for(cred_active),
            ),
        )
        active_prep = _expect_ok(
            "prepare_task",
            valid_bridge.dispatch(
                prep_call,
                _ctx_for(store_id, rt_a.lease.epoch, cred_active.principal, mono, selected_scope=scope),
                auth=_auth_for(cred_active),
            ),
        )
        assert active_prep["skills"] == [{"id": "skill-r01-quar", "status": "redacted", "reason": "access_restricted"}]

        # Cross-root (rt_a.store, rt_b.policy) and (rt_b.store, rt_a.policy) MUST fail closed at construction!
        with pytest.raises(BrainError) as exc_ab:
            KernelBridge(
                store=rt_a.store,
                policy=rt_b.policy,
                clock=clock,
                writer_epoch=rt_a.lease.epoch,
            )
        assert exc_ab.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_ba:
            KernelBridge(
                store=rt_b.store,
                policy=rt_a.policy,
                clock=clock,
                writer_epoch=rt_b.lease.epoch,
            )
        assert exc_ba.value.code is ErrorCode.INTEGRITY_FAILURE

        # Sibling Store+PolicyStore consumer / _make_bridge-style pairing with mismatched roots MUST also fail closed!
        with pytest.raises(BrainError) as exc_domain_pair:
            crossed_domain = FixtureKernelDomain(
                store=rt_a.store,
                policy=rt_b.policy,
                clock=clock,
                monotonic_ns=mono,
            )
            KernelBridge(
                store=rt_a.store,
                policy=rt_a.policy,
                clock=clock,
                writer_epoch=rt_a.lease.epoch,
                domain=crossed_domain,
            )
        assert exc_domain_pair.value.code is ErrorCode.INTEGRITY_FAILURE
    finally:
        rt_b.close()
        rt_a.close()


def test_r01_mismatched_writer_epoch_on_same_root_is_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R01-B: ``KernelBridge`` refuses ``writer_epoch != lease.epoch`` on the same admitted root."""
    root = trusted_tmp / "root-epoch"
    rt_first = _open_fixture_runtime(root, os_)
    store_id = rt_first.store.store_id
    rt_first.close()

    rt = _reopen_fixture_runtime(root, store_id, os_)
    try:
        assert rt.lease.epoch >= 2
        _ = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch)

        with pytest.raises(BrainError) as exc_future:
            KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch + 1)
        assert exc_future.value.code is ErrorCode.INTEGRITY_FAILURE

        with pytest.raises(BrainError) as exc_stale:
            KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch - 1)
        assert exc_stale.value.code is ErrorCode.INTEGRITY_FAILURE
    finally:
        rt.close()


@pytest.mark.parametrize("mode", ["policy_closed", "store_closed", "runtime_closed"])
def test_r01_closed_handle_or_released_lease_before_construction_is_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, mode: str
) -> None:
    """Case R01-C (pre-construction): Closed ``Store``/``PolicyStore`` or released ``WriterLease`` fails closed."""
    rt = _open_fixture_runtime(trusted_tmp / f"root-pre-{mode}", os_)
    try:
        epoch = rt.lease.epoch
        if mode == "policy_closed":
            rt.policy.close()
        elif mode == "store_closed":
            rt.store.close()
        else:
            rt.close()

        with pytest.raises(BrainError) as exc_info:
            KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=epoch)
        assert exc_info.value.code in {ErrorCode.INTEGRITY_FAILURE, ErrorCode.POLICY_UNAVAILABLE}
    finally:
        rt.close()


@pytest.mark.parametrize("mode", ["policy_closed", "store_closed", "runtime_closed", "epoch_bumped"])
def test_r01_closing_handle_or_releasing_lease_after_construction_fails_closed(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, mode: str
) -> None:
    """Case R01-C (post-construction): Closing a handle, releasing the lease, or advancing epoch fails closed."""
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / f"root-post-{mode}", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-post", checkout_dir=trusted_tmp / f"chk-post-{mode}")
        scope = Scope(ws.repo_id, ws.checkout_id)
        store_id = rt.store.store_id
        initial_epoch = rt.lease.epoch

        bridge, _ = _make_bridge(rt, clock, mono, observer=FakeObserver(descriptor=_desc(TREE_A)))
        bridge.publish_auth_view()
        assert bridge.auth_state.current() is not None

        seed_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "seed stored result before handle invalidation",
                "idempotency_key": "idem_r01c_seed_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        _expect_ok(
            "prepare_task",
            bridge.dispatch(
                seed_call,
                _ctx_for(store_id, initial_epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        stored = _load_stored_result(rt.store, principal_id=seeded.principal.principal_id, tool="prepare_task")

        if mode == "policy_closed":
            rt.policy.close()
        elif mode == "store_closed":
            rt.store.close()
        elif mode == "runtime_closed":
            rt.close()
        else:
            rt.lease.bump_epoch()

        allowed = {ErrorCode.POLICY_UNAVAILABLE, ErrorCode.INTEGRITY_FAILURE}

        # Operations fail closed even before publish_auth_view() is called again.
        health_call = normalize_call("get_health", {"schema_version": "2.0"}, seeded.principal, selected_scope=None)
        _expect_err(
            "get_health",
            bridge.dispatch(
                health_call,
                _ctx_for(store_id, initial_epoch, seeded.principal, mono, selected_scope=None),
                auth=_auth_for(seeded),
            ),
            allowed,
        )
        _expect_err(
            "prepare_task",
            bridge.dispatch(
                seed_call,
                _ctx_for(store_id, initial_epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
            allowed,
        )

        with pytest.raises(BrainError) as render_exc:
            bridge.render_current(stored, seeded.principal, selected_scope=scope)
        assert render_exc.value.code in allowed

        with pytest.raises(BrainError) as stage_exc:
            bridge.stage_blob(b"safe")
        assert stage_exc.value.code in allowed

        with pytest.raises(BrainError) as prune_exc:
            bridge.prune_expired(clock.now())
        assert prune_exc.value.code in allowed

        # Failed publish_auth_view() raises BrainError AND clears auth_state.current() so stale RAM auth cannot linger!
        with pytest.raises(BrainError) as pub_exc:
            bridge.publish_auth_view()
        assert pub_exc.value.code in allowed
        assert bridge.auth_state.current() is None
    finally:
        rt.close()


# =====================================================================================================================
# I2-T4A-R02: Live replay preserves StoredResult snapshot provenance while omitting unreadable snapshot_dependent items
# =====================================================================================================================


def _build_r02_plan(
    ws: WorkspaceBinding,
    *,
    skill_ok_ref: ObjectRef,
    lesson_indep_ref: ObjectRef,
    ctx_snap_dep_ref: ObjectRef,
    gate_snap_dep_ref: ObjectRef,
) -> Callable[[WorkspaceBinding, str], Sequence[FixtureDeliveryRefSpec]]:
    def plan(binding: WorkspaceBinding, _task_id: str) -> Sequence[FixtureDeliveryRefSpec]:
        return (
            FixtureDeliveryRefSpec(
                slot="skills",
                ref=skill_ok_ref,
                owner_id=binding.owner_id,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                snapshot_dependent=False,
            ),
            FixtureDeliveryRefSpec(
                slot="lessons",
                ref=lesson_indep_ref,
                owner_id=binding.owner_id,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                snapshot_dependent=False,
            ),
            FixtureDeliveryRefSpec(
                slot="context",
                ref=ctx_snap_dep_ref,
                owner_id=binding.owner_id,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                snapshot_dependent=True,
            ),
            FixtureDeliveryRefSpec(
                slot="finishing_gates",
                ref=gate_snap_dep_ref,
                owner_id=binding.owner_id,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                snapshot_dependent=True,
            ),
        )

    return plan


def test_r02_replay_after_snapshot_quarantine_preserves_provenance_and_omits_snapshot_dependent(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R02-A: Quarantining snapshot descriptor keeps ``available/<snap_id>`` while omitting dependent items."""
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "r02-quar", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-r02a", checkout_dir=trusted_tmp / "chk-r02a")
        scope = Scope(ws.repo_id, ws.checkout_id)

        skill_ok_ref = ObjectRef(kind="skill", id="skill-r02a", revision=1, digest=digest_bytes(b"skill-r02a"))
        lesson_quar_ref = ObjectRef(kind="lesson", id="lesson-r02a", revision=1, digest=digest_bytes(b"lesson-r02a"))
        ctx_dep_ref = ObjectRef(kind="context", id="ctx-r02a", revision=1, digest=digest_bytes(b"ctx-r02a"))
        gate_dep_ref = ObjectRef(kind="gate", id="gate-r02a", revision=1, digest=digest_bytes(b"gate-r02a"))

        snap_desc = _desc(TREE_A)
        obs = FakeObserver(descriptor=snap_desc)
        bridge, domain = _make_bridge(
            rt,
            clock,
            mono,
            observer=obs,
            delivery_plan=_build_r02_plan(
                ws,
                skill_ok_ref=skill_ok_ref,
                lesson_indep_ref=lesson_quar_ref,
                ctx_snap_dep_ref=ctx_dep_ref,
                gate_snap_dep_ref=gate_dep_ref,
            ),
        )

        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "commit available snapshot before quarantine",
                "idempotency_key": "idem_r02a_quar_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        initial = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        snap_id = initial["source_snapshot_id"]
        assert isinstance(snap_id, str)
        assert initial["snapshot_status"] == "available"
        assert initial["degraded_codes"] == []
        assert initial["skills"] == [
            {"kind": "skill", "id": "skill-r02a", "revision": 1, "digest": skill_ok_ref.digest, "status": "ok"}
        ]
        assert initial["lessons"] == [
            {"kind": "lesson", "id": "lesson-r02a", "revision": 1, "digest": lesson_quar_ref.digest, "status": "ok"}
        ]
        assert initial["context"] == [
            {"kind": "context", "id": "ctx-r02a", "revision": 1, "digest": ctx_dep_ref.digest, "status": "ok"}
        ]
        assert initial["finishing_gates"] == [
            {"kind": "gate", "id": "gate-r02a", "revision": 1, "digest": gate_dep_ref.digest, "status": "ok"}
        ]
        assert len(obs.calls) == 1
        assert domain.apply_calls == 1

        stored = _load_stored_result(rt.store, principal_id=seeded.principal.principal_id, tool="prepare_task")

        # Quarantine snapshot descriptor AND non-snapshot_dependent lesson_quar_ref; check both immediate policy view
        # and reconciled store state.
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": snap_desc.descriptor_digest})
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": lesson_quar_ref.digest})

        for phase in ("immediate", "reconciled"):
            if phase == "reconciled":
                rt.store.reconcile_policy()
            replayed = _expect_ok(
                "prepare_task",
                bridge.dispatch(
                    prep_call,
                    _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                    auth=_auth_for(seeded),
                ),
            )
            assert replayed["delivery_id"] == initial["delivery_id"]
            assert replayed["assignment_id"] == initial["assignment_id"]
            assert replayed["source_snapshot_id"] == snap_id
            assert replayed["snapshot_status"] == "available"
            assert replayed["degraded_codes"] == []
            assert replayed["context"] == []
            assert replayed["finishing_gates"] == []
            assert replayed["skills"] == initial["skills"]
            assert replayed["lessons"] == [{"id": "lesson-r02a", "status": "redacted", "reason": "access_restricted"}]
            assert len(obs.calls) == 1
            assert domain.apply_calls == 1
            assert _read_delivery_snapshot_row(rt.store, str(initial["delivery_id"])) == (snap_id, "available")

            rendered = bridge.render_current(stored, seeded.principal, selected_scope=scope)
            assert rendered == replayed
    finally:
        rt.close()


def test_r02_replay_after_snapshot_tombstone_preserves_provenance_and_omits_snapshot_dependent(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R02-B: Tombstoning snapshot holder keeps ``available/<snap_id>`` while omitting dependent items."""
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "r02-tomb", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-r02b", checkout_dir=trusted_tmp / "chk-r02b")
        scope = Scope(ws.repo_id, ws.checkout_id)

        skill_ok_ref = ObjectRef(kind="skill", id="skill-r02b", revision=1, digest=digest_bytes(b"skill-r02b"))
        lesson_ok_ref = ObjectRef(kind="lesson", id="lesson-r02b", revision=1, digest=digest_bytes(b"lesson-r02b"))
        ctx_dep_ref = ObjectRef(kind="context", id="ctx-r02b", revision=1, digest=digest_bytes(b"ctx-r02b"))
        gate_dep_ref = ObjectRef(kind="gate", id="gate-r02b", revision=1, digest=digest_bytes(b"gate-r02b"))

        obs = FakeObserver(descriptor=_desc(TREE_A))
        bridge, domain = _make_bridge(
            rt,
            clock,
            mono,
            observer=obs,
            delivery_plan=_build_r02_plan(
                ws,
                skill_ok_ref=skill_ok_ref,
                lesson_indep_ref=lesson_ok_ref,
                ctx_snap_dep_ref=ctx_dep_ref,
                gate_snap_dep_ref=gate_dep_ref,
            ),
        )

        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "commit available snapshot before tombstone",
                "idempotency_key": "idem_r02b_tomb_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        initial = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        snap_id = initial["source_snapshot_id"]
        assert isinstance(snap_id, str)
        assert initial["snapshot_status"] == "available"
        assert initial["degraded_codes"] == []
        stored = _load_stored_result(rt.store, principal_id=seeded.principal.principal_id, tool="prepare_task")

        rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": snap_id})

        for phase in ("immediate", "reconciled"):
            if phase == "reconciled":
                rt.store.reconcile_policy()
            replayed = _expect_ok(
                "prepare_task",
                bridge.dispatch(
                    prep_call,
                    _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                    auth=_auth_for(seeded),
                ),
            )
            assert replayed["delivery_id"] == initial["delivery_id"]
            assert replayed["assignment_id"] == initial["assignment_id"]
            assert replayed["source_snapshot_id"] == snap_id
            assert replayed["snapshot_status"] == "available"
            assert replayed["degraded_codes"] == []
            assert replayed["context"] == []
            assert replayed["finishing_gates"] == []
            assert replayed["skills"] == initial["skills"]
            assert replayed["lessons"] == initial["lessons"]
            assert len(obs.calls) == 1
            assert domain.apply_calls == 1
            assert _read_delivery_snapshot_row(rt.store, str(initial["delivery_id"])) == (snap_id, "available")

            rendered = bridge.render_current(stored, seeded.principal, selected_scope=scope)
            assert rendered == replayed
    finally:
        rt.close()


def test_r02_replay_after_snapshot_blob_missing_preserves_provenance_and_omits_snapshot_dependent(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R02-B2: Missing CAS snapshot descriptor blob keeps ``available/<snap_id>`` while omitting dependent refs."""
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "r02-missing-blob", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-r02-blob", checkout_dir=trusted_tmp / "chk-r02-blob")
        scope = Scope(ws.repo_id, ws.checkout_id)

        skill_ok_ref = ObjectRef(kind="skill", id="skill-r02m", revision=1, digest=digest_bytes(b"skill-r02m"))
        lesson_ok_ref = ObjectRef(kind="lesson", id="lesson-r02m", revision=1, digest=digest_bytes(b"lesson-r02m"))
        ctx_dep_ref = ObjectRef(kind="context", id="ctx-r02m", revision=1, digest=digest_bytes(b"ctx-r02m"))
        gate_dep_ref = ObjectRef(kind="gate", id="gate-r02m", revision=1, digest=digest_bytes(b"gate-r02m"))

        snap_desc = _desc(TREE_A)
        obs = FakeObserver(descriptor=snap_desc)
        bridge, domain = _make_bridge(
            rt,
            clock,
            mono,
            observer=obs,
            delivery_plan=_build_r02_plan(
                ws,
                skill_ok_ref=skill_ok_ref,
                lesson_indep_ref=lesson_ok_ref,
                ctx_snap_dep_ref=ctx_dep_ref,
                gate_snap_dep_ref=gate_dep_ref,
            ),
        )

        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "commit available snapshot before CAS blob loss",
                "idempotency_key": "idem_r02m_blob_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        initial = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        snap_id = initial["source_snapshot_id"]
        assert isinstance(snap_id, str)
        stored = _load_stored_result(rt.store, principal_id=seeded.principal.principal_id, tool="prepare_task")

        hex_digest = snap_desc.descriptor_digest.removeprefix("sha256:")
        blob_path = rt.root.cas_dir / hex_digest[:2] / hex_digest
        assert blob_path.is_file()
        blob_path.unlink()

        replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                prep_call,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        assert replayed["delivery_id"] == initial["delivery_id"]
        assert replayed["assignment_id"] == initial["assignment_id"]
        assert replayed["source_snapshot_id"] == snap_id
        assert replayed["snapshot_status"] == "available"
        assert replayed["degraded_codes"] == []
        assert replayed["context"] == []
        assert replayed["finishing_gates"] == []
        assert replayed["skills"] == initial["skills"]
        assert replayed["lessons"] == initial["lessons"]
        assert len(obs.calls) == 1
        assert domain.apply_calls == 1

        rendered = bridge.render_current(stored, seeded.principal, selected_scope=scope)
        assert rendered == replayed
    finally:
        rt.close()


def test_r02_new_key_commits_unavailable_delivery_while_live_replay_keeps_available_provenance(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """Case R02-C: New key on same task commits ``unavailable`` while first live key replays ``available/<snap_id>``."""
    mono = Mono()
    rt = _open_fixture_runtime(trusted_tmp / "r02-new-key", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-r02c", checkout_dir=trusted_tmp / "chk-r02c")
        scope = Scope(ws.repo_id, ws.checkout_id)

        skill_ok_ref = ObjectRef(kind="skill", id="skill-r02c", revision=1, digest=digest_bytes(b"skill-r02c"))
        lesson_ok_ref = ObjectRef(kind="lesson", id="lesson-r02c", revision=1, digest=digest_bytes(b"lesson-r02c"))
        ctx_dep_ref = ObjectRef(kind="context", id="ctx-r02c", revision=1, digest=digest_bytes(b"ctx-r02c"))
        gate_dep_ref = ObjectRef(kind="gate", id="gate-r02c", revision=1, digest=digest_bytes(b"gate-r02c"))

        snap_desc = _desc(TREE_A)
        obs = FakeObserver(descriptor=snap_desc, status=SnapshotStatus.AVAILABLE)
        bridge, domain = _make_bridge(
            rt,
            clock,
            mono,
            observer=obs,
            delivery_plan=_build_r02_plan(
                ws,
                skill_ok_ref=skill_ok_ref,
                lesson_indep_ref=lesson_ok_ref,
                ctx_snap_dep_ref=ctx_dep_ref,
                gate_snap_dep_ref=gate_dep_ref,
            ),
        )

        call_first = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "task_id": "task-r02c-shared",
                "description": "first logical operation on task-r02c-shared",
                "idempotency_key": "idem_r02c_first_0001",
            },
            seeded.principal,
            selected_scope=scope,
        )
        initial = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_first,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        snap_id = initial["source_snapshot_id"]
        assert isinstance(snap_id, str)
        assert initial["snapshot_status"] == "available"
        assert initial["degraded_codes"] == []

        # Quarantine first snapshot's descriptor AND make observer report UNAVAILABLE for the new key on the same task.
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": snap_desc.descriptor_digest})
        rt.store.reconcile_policy()
        obs.status = SnapshotStatus.UNAVAILABLE
        obs.descriptor = None

        clock.advance(dt.timedelta(minutes=10))
        call_second = normalize_call(
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "task_id": "task-r02c-shared",
                "description": "second logical operation with new idempotency key",
                "idempotency_key": "idem_r02c_second_0002",
            },
            seeded.principal,
            selected_scope=scope,
        )
        second = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_second,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        assert second["task_id"] == "task-r02c-shared"
        assert second["delivery_id"] != initial["delivery_id"]
        assert second["source_snapshot_id"] is None
        assert second["snapshot_status"] == "unavailable"
        assert second["degraded_codes"] == ["snapshot_unavailable"]
        assert second["context"] == []
        assert second["finishing_gates"] == []
        assert second["skills"] == initial["skills"]
        assert len(obs.calls) == 2
        assert domain.apply_calls == 2

        # Replaying the FIRST live idempotency_key afterward STILL returns the first result's available/<snap_id>,
        # while omitting snapshot_dependent items because snap_desc is quarantined!
        first_replayed = _expect_ok(
            "prepare_task",
            bridge.dispatch(
                call_first,
                _ctx_for(rt.store.store_id, rt.lease.epoch, seeded.principal, mono, selected_scope=scope),
                auth=_auth_for(seeded),
            ),
        )
        assert first_replayed["delivery_id"] == initial["delivery_id"]
        assert first_replayed["assignment_id"] == initial["assignment_id"]
        assert first_replayed["source_snapshot_id"] == snap_id
        assert first_replayed["snapshot_status"] == "available"
        assert first_replayed["degraded_codes"] == []
        assert first_replayed["context"] == []
        assert first_replayed["finishing_gates"] == []
        assert first_replayed["skills"] == initial["skills"]
        assert len(obs.calls) == 2
        assert domain.apply_calls == 2
    finally:
        rt.close()
