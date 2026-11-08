"""Task 4c: durable artifact send attempts vs client-declared ReadAcks (C5)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.workspaces import build_registration
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CallResult,
    ReadAckInput,
    ResourceDigest,
    Scope,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    StoredResult,
    WorkspaceBinding,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import is_uuid
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.store import Store
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FixtureKernelDomain,
    FixtureResourceSpec,
    fixture_store_extensions,
    validate_response_envelope,
)
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)

MS = 1_000_000
REMOTE_A = "https://github.example/dan/repo-send-a.git"
REMOTE_B = "https://github.example/dan/repo-send-b.git"
TREE_A = "sha256:" + "a" * 64
CLOCK_START = dt.datetime(2026, 11, 1, 0, 0, 0, 0, tzinfo=dt.UTC)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(CLOCK_START)


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock)


@dataclass
class FakeMonotonicClock:
    now_ns: int = 1_000 * MS

    def monotonic_ns(self) -> int:
        return self.now_ns

    def advance(self, delta_ns: int) -> int:
        self.now_ns += delta_ns
        return self.now_ns


@dataclass
class RecordingObserver:
    descriptor: SnapshotDescriptor | None
    calls: list[tuple[WorkspaceBinding, int]] = field(default_factory=list)

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        self.calls.append((binding, deadline_ns))
        if self.descriptor is None:
            return SnapshotObservation(SnapshotStatus.UNAVAILABLE, None)
        return SnapshotObservation(SnapshotStatus.AVAILABLE, self.descriptor)


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
    proof = make_bootstrap_auth(
        store_id=rt.policy.store_id,
        owner_id=seeded.principal.owner_id,
        action="workspace_register",
        subject_id=reg.subject_id,
        trust_generation=rt.policy.trust_generation(),
        expires_at=clock.now() + dt.timedelta(hours=1),
    )
    binding = rt.policy.register_authorized_workspace(reg, proof)
    rt.store.reconcile_policy()
    return binding


def _make_bridge_and_domain(
    rt: Runtime,
    clock: FakeClock,
    mono: FakeMonotonicClock,
    *,
    writer_epoch: int | None = None,
    instance_id: str | None = None,
    recover_pending_on_init: bool = True,
) -> tuple[KernelBridge, FixtureKernelDomain]:
    domain = FixtureKernelDomain(
        store=rt.store,
        policy=rt.policy,
        clock=clock,
        observer=RecordingObserver(descriptor=_desc()),
        monotonic_ns=mono.monotonic_ns,
    )
    epoch = rt.lease.epoch if writer_epoch is None else writer_epoch
    if recover_pending_on_init:
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=epoch,
            instance_id=instance_id,
            domain=domain,
        )
    else:
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=epoch,
            instance_id=instance_id,
            domain=domain,
            recover_pending_on_init=False,
        )
    bridge.publish_auth_view()
    return bridge, domain


def _run_tool(
    bridge: KernelBridge,
    tool: str,
    arguments: Mapping[str, JsonValue],
    *,
    token: str,
    selected_scope: Scope | None,
) -> CallResult:
    sub = bridge.submit_request(
        tool,
        arguments,
        token=token,
        selected_scope=selected_scope,
    )
    if not sub.done():
        assert bridge.process_next_queued(block=False) is True
    return sub.wait(timeout=2.0)


def _expect_ok(tool: str, envelope: CallResult) -> dict[str, JsonValue]:
    validate_response_envelope(tool, envelope)
    assert envelope.get("ok") is True, f"expected ok=True for {tool}, got {envelope}"
    data = envelope["data"]
    assert isinstance(data, dict)
    return data


def _expect_err(tool: str, envelope: CallResult, code: ErrorCode) -> dict[str, JsonValue]:
    validate_response_envelope(tool, envelope)
    assert envelope.get("ok") is False, f"expected error {code.value} for {tool}, got {envelope}"
    err = envelope["error"]
    assert isinstance(err, dict)
    assert err["code"] == code.value
    return err


def _count_rows(store: Store, table: str) -> int:
    with store.transaction() as txn:
        row = txn.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


def _prepare_task_on(
    bridge: KernelBridge,
    *,
    token: str,
    scope: Scope,
    hint: str = "ws-main",
    idem_key: str,
) -> tuple[str, str]:
    data = _expect_ok(
        "prepare_task",
        _run_tool(
            bridge,
            "prepare_task",
            {
                "schema_version": "2.0",
                "workspace_hint": hint,
                "description": f"task for {idem_key}",
                "idempotency_key": idem_key,
            },
            token=token,
            selected_scope=scope,
        ),
    )
    return str(data["task_id"]), str(data["delivery_id"])


# --- 1. Replay keeps logical result while minting a new send attempt / served_receipt_id ------------------------------


def test_replay_keeps_result_but_creates_new_send_attempt(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        res_l1 = b"# Skill L1\nApply deterministic kernel rules.\n"
        res_rules = b"rule-1: verify digest set\n"
        domain.seed_artifact(
            bridge,
            artifact_id="art-replay-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(
                FixtureResourceSpec(name="L1.md", content=res_l1, level="L1"),
                FixtureResourceSpec(name="rules.txt", content=res_rules, level="L1"),
            ),
        )
        task_id, _delivery_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_rep_01")

        art_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "task_id": task_id,
            "artifact_id": "art-replay-1",
            "revision": 1,
            "level": "L1",
            "idempotency_key": "idem_art_replay_01",
        }
        first = _expect_ok(
            "get_artifact",
            _run_tool(bridge, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        assert "served_receipt_id" in first
        receipt_1 = str(first["served_receipt_id"])
        assert is_uuid(receipt_1)
        assert domain.apply_calls == 2  # 1 prepare_task + 1 get_artifact
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == 1
        assert _count_rows(rt.store, "artifact_send_attempt") == 1

        with rt.store.transaction() as stxn:
            row_1 = stxn.db.execute(
                "SELECT id, logical_result_id, principal_id, task_id, artifact_id, revision, state "
                "FROM artifact_send_attempt WHERE id = ?",
                (receipt_1,),
            ).fetchone()
        assert row_1 is not None
        assert row_1[0] == receipt_1
        assert row_1[6] == "pending"  # Must remain pending until explicit flush finalization!
        logical_result_id = str(row_1[1])

        # Finalize first send attempt to served_only.
        comp_1 = bridge.build_send_completion(receipt_1)
        finalized_1 = bridge.finalize_send_attempt(comp_1)
        assert finalized_1.send_attempt_id == receipt_1
        assert str(finalized_1.state) == "served_only"

        # Replay exact same get_artifact idempotency_key -> same logical result, brand-new send attempt & receipt ID!
        second = _expect_ok(
            "get_artifact",
            _run_tool(bridge, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        assert "served_receipt_id" in second
        receipt_2 = str(second["served_receipt_id"])
        assert is_uuid(receipt_2)
        assert receipt_2 != receipt_1
        assert {k: v for k, v in second.items() if k != "served_receipt_id"} == {
            k: v for k, v in first.items() if k != "served_receipt_id"
        }
        assert domain.apply_calls == 2  # Replay did NOT re-execute business mutation!
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == 1
        assert _count_rows(rt.store, "artifact_send_attempt") == 2

        with rt.store.transaction() as stxn:
            rows = stxn.db.execute(
                "SELECT id, logical_result_id, state FROM artifact_send_attempt ORDER BY rowid"
            ).fetchall()
        assert rows == [
            (receipt_1, logical_result_id, "served_only"),
            (receipt_2, logical_result_id, "pending"),
        ]

        # Pure render_current NEVER inserts a send attempt or attaches served_receipt_id (4c:248).
        with rt.store.transaction() as stxn:
            refs_json_row = stxn.db.execute(
                "SELECT refs_json FROM idempotency WHERE result_id = ?",
                (logical_result_id,),
            ).fetchone()
        assert refs_json_row is not None
        pure_rendered = bridge.render_current(
            StoredResult(
                result_id=logical_result_id,
                assignment_id=None,
                refs=StoredResult.decode_refs_json(str(refs_json_row[0])),
            ),
            seeded.principal,
            selected_scope=scope,
        )
        assert isinstance(pure_rendered, dict)
        assert "served_receipt_id" not in pure_rendered
        assert _count_rows(rt.store, "artifact_send_attempt") == 2
        assert _count_rows(rt.store, "artifact_read_ack") == 0
    finally:
        rt.close()


# --- 2. Partial/interrupted flush records unknown and has no ackable served receipt ----------------------------------


def test_partial_flush_has_no_served_receipt(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        content = b"partial flush resource bytes"
        res_digest = digest_bytes(content)
        domain.seed_artifact(
            bridge,
            artifact_id="art-partial-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=content, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_part_1")

        art_ok = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-partial-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_part_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in art_ok
        receipt_id = str(art_ok["served_receipt_id"])
        comp = bridge.build_send_completion(receipt_id)

        # Simulate dropped client connection mid-flush -> pending transitions to unknown (idempotent on repeat).
        interrupted = bridge.interrupt_send_attempt(receipt_id)
        assert str(interrupted.state) == "unknown"
        assert str(bridge.interrupt_send_attempt(receipt_id).state) == "unknown"

        # Unknown attempt MUST NEVER upgrade to served_only even if a late completion callback arrives!
        from superbrain.core.errors import BrainError

        with pytest.raises(BrainError) as exc_late:
            bridge.finalize_send_attempt(comp)
        assert exc_late.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.INTEGRITY_FAILURE}

        # Client attempting ReadAck against interrupted/unknown receipt gets NOT_FOUND and commits nothing!
        ack = ReadAckInput(
            served_receipt_id=receipt_id,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        err = _expect_err(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack.to_dict()],
                    "idempotency_key": "idem_out_part_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.NOT_FOUND,
        )
        assert err["message"] == "not found"
        assert _count_rows(rt.store, "artifact_read_ack") == 0
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 0
    finally:
        rt.close()


# --- 3. Authorized ReadAck while send attempt is still pending returns IN_PROGRESS -----------------------------------


def test_ack_for_pending_attempt_is_in_progress(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        content = b"pending flush bytes"
        res_digest = digest_bytes(content)
        domain.seed_artifact(
            bridge,
            artifact_id="art-pend-1",
            revision=2,
            kind="lesson",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="lesson.md", content=content, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_pend_1")

        art_ok = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-pend-1",
                    "revision": 2,
                    "level": "L1",
                    "idempotency_key": "idem_art_pend_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in art_ok
        receipt_id = str(art_ok["served_receipt_id"])

        ack = ReadAckInput(
            served_receipt_id=receipt_id,
            task_id=task_id,
            revision=2,
            resource_digests=(ResourceDigest(name="lesson.md", digest=res_digest),),
        )
        outcome_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "delivery_id": delivery_id,
            "outcome": "success",
            "read_acks": [ack.to_dict()],
            "idempotency_key": "idem_out_pend_01",
        }

        # Before finalize_send_attempt -> authorized pending attempt MUST return IN_PROGRESS and commit nothing!
        err = _expect_err(
            "record_outcome",
            _run_tool(bridge, "record_outcome", outcome_args, token=seeded.token, selected_scope=scope),
            ErrorCode.IN_PROGRESS,
        )
        assert err["message"] == "operation in progress"
        assert _count_rows(rt.store, "artifact_read_ack") == 0
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 0
        assert _count_rows(rt.store, "idempotency") == 2  # only prepare_task + get_artifact

        # Once flush finalizes pending -> served_only, retrying the exact same record_outcome succeeds!
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_id))
        out_ok = _expect_ok(
            "record_outcome",
            _run_tool(bridge, "record_outcome", outcome_args, token=seeded.token, selected_scope=scope),
        )
        assert out_ok["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 1
    finally:
        rt.close()


# --- 4. Wrong principal/task/scope -> NOT_FOUND (even on pending!); wrong rev/digest set -> INVALID_INPUT ------------


def test_wrong_principal_revision_or_digest_ack_is_refused(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        dan_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="box-1")
        dan_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude", machine_id="box-1")
        ws = _register_ws(rt, clock, dan_a, alias="ws-main", checkout_dir=trusted_tmp / "chk", remote=REMOTE_A)
        # Grant dan_b on the exact same repo & checkout!
        seed_repo_grant(rt.policy, principal_id=dan_b.principal.principal_id, repo_id=ws.repo_id, owner_id="dan")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        bytes_alpha = b"resource alpha"
        bytes_beta = b"resource beta"
        dig_alpha = digest_bytes(bytes_alpha)
        dig_beta = digest_bytes(bytes_beta)
        domain.seed_artifact(
            bridge,
            artifact_id="art-multi-1",
            revision=3,
            kind="skill",
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(
                FixtureResourceSpec(name="alpha.md", content=bytes_alpha, level="L1"),
                FixtureResourceSpec(name="beta.md", content=bytes_beta, level="L1"),
            ),
        )

        task_a1, deliv_a1 = _prepare_task_on(bridge, token=dan_a.token, scope=scope, idem_key="idem_prep_dan_a1_01")
        task_a2, deliv_a2 = _prepare_task_on(bridge, token=dan_a.token, scope=scope, idem_key="idem_prep_dan_a2_01")
        task_b1, deliv_b1 = _prepare_task_on(bridge, token=dan_b.token, scope=scope, idem_key="idem_prep_dan_b1_01")

        # Create one pending attempt and one served_only attempt for dan_a on task_a1.
        art_pend = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_a1,
                    "artifact_id": "art-multi-1",
                    "revision": 3,
                    "level": "L1",
                    "idempotency_key": "idem_art_a1_pend",
                },
                token=dan_a.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in art_pend
        receipt_pend_a1 = str(art_pend["served_receipt_id"])

        art_served = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_a1,
                    "artifact_id": "art-multi-1",
                    "revision": 3,
                    "level": "L1",
                    "idempotency_key": "idem_art_a1_served",
                },
                token=dan_a.token,
                selected_scope=scope,
            ),
        )
        receipt_served_a1 = str(art_served["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_served_a1))

        # 1) Wrong principal (dan_b) referencing dan_a's PENDING or SERVED receipt MUST get NOT_FOUND
        #    (even on deliv_a1 + task_a1 or mismatched rev/digests — never leaking IN_PROGRESS or INVALID_INPUT)!
        for target_deliv, target_tid in ((deliv_b1, task_b1), (deliv_a1, task_a1)):
            for target_receipt in (receipt_pend_a1, receipt_served_a1):
                wrong_princ_err = _expect_err(
                    "record_outcome",
                    _run_tool(
                        bridge,
                        "record_outcome",
                        {
                            "schema_version": "2.0",
                            "workspace_id": ws.repo_id,
                            "delivery_id": target_deliv,
                            "outcome": "success",
                            "read_acks": [
                                {
                                    "served_receipt_id": target_receipt,
                                    "task_id": target_tid,
                                    "revision": 999,
                                    "resource_digests": [{"name": "alpha.md", "digest": "sha256:" + "0" * 64}],
                                }
                            ],
                            "idempotency_key": f"idem_wp_{target_deliv[:6]}_{target_receipt[:8]}",
                        },
                        token=dan_b.token,
                        selected_scope=scope,
                    ),
                    ErrorCode.NOT_FOUND,
                )
                assert wrong_princ_err["message"] == "not found"

        # 1b) Absent/unknown receipt ID (UUID or opaque ID) -> NOT_FOUND!
        for missing_id in (new_id(), "nonexistent-receipt-01"):
            missing_err = _expect_err(
                "record_outcome",
                _run_tool(
                    bridge,
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "workspace_id": ws.repo_id,
                        "delivery_id": deliv_a1,
                        "outcome": "success",
                        "read_acks": [
                            {
                                "served_receipt_id": missing_id,
                                "task_id": task_a1,
                                "revision": 3,
                                "resource_digests": [
                                    {"name": "alpha.md", "digest": dig_alpha},
                                    {"name": "beta.md", "digest": dig_beta},
                                ],
                            }
                        ],
                        "idempotency_key": f"idem_miss_rcpt_{missing_id[:8]}",
                    },
                    token=dan_a.token,
                    selected_scope=scope,
                ),
                ErrorCode.NOT_FOUND,
            )
            assert missing_err["message"] == "not found"

        # 2) Same principal (dan_a) on wrong task (deliv_a2 / task_a2) referencing task_a1's PENDING or SERVED receipt
        #    MUST get NOT_FOUND (never leaking IN_PROGRESS)!
        for ack_tid in (task_a1, task_a2):
            wrong_task_err = _expect_err(
                "record_outcome",
                _run_tool(
                    bridge,
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "workspace_id": ws.repo_id,
                        "delivery_id": deliv_a2,
                        "outcome": "success",
                        "read_acks": [
                            {
                                "served_receipt_id": receipt_pend_a1,
                                "task_id": ack_tid,
                                "revision": 3,
                                "resource_digests": [
                                    {"name": "alpha.md", "digest": dig_alpha},
                                    {"name": "beta.md", "digest": dig_beta},
                                ],
                            }
                        ],
                        "idempotency_key": f"idem_wrong_t_{ack_tid[:8]}",
                    },
                    token=dan_a.token,
                    selected_scope=scope,
                ),
                ErrorCode.NOT_FOUND,
            )
            assert wrong_task_err["message"] == "not found"

        # 3) Authorized principal & task on SERVED receipt with wrong revision, subset, superset, or wrong digest
        #    -> INVALID_INPUT with static message and ZERO raw digest/name echo!
        tampered_digest = "sha256:" + "e" * 64
        bad_ack_cases: list[tuple[str, int, list[dict[str, JsonValue]]]] = [
            (
                "wrong_rev",
                2,
                [{"name": "alpha.md", "digest": dig_alpha}, {"name": "beta.md", "digest": dig_beta}],
            ),
            (
                "subset",
                3,
                [{"name": "alpha.md", "digest": dig_alpha}],
            ),
            (
                "superset",
                3,
                [
                    {"name": "alpha.md", "digest": dig_alpha},
                    {"name": "beta.md", "digest": dig_beta},
                    {"name": "extra.md", "digest": dig_alpha},
                ],
            ),
            (
                "bad_dig",
                3,
                [{"name": "alpha.md", "digest": dig_alpha}, {"name": "beta.md", "digest": tampered_digest}],
            ),
        ]
        for label, rev, dig_list in bad_ack_cases:
            bad_env = _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": deliv_a1,
                    "outcome": "success",
                    "read_acks": [
                        {
                            "served_receipt_id": receipt_served_a1,
                            "task_id": task_a1,
                            "revision": rev,
                            "resource_digests": cast(JsonValue, dig_list),
                        }
                    ],
                    "idempotency_key": f"idem_bad_ack_{label}",
                },
                token=dan_a.token,
                selected_scope=scope,
            )
            bad_err = _expect_err("record_outcome", bad_env, ErrorCode.INVALID_INPUT)
            assert bad_err["message"] == "invalid input"
            serialized_err = canonical_json(bad_env).decode("utf-8")
            assert tampered_digest not in serialized_err
            assert dig_alpha not in serialized_err
            assert "beta.md" not in serialized_err

        assert _count_rows(rt.store, "artifact_read_ack") == 0

        # 4) Reordered identical (resource_name, digest) set IS accepted cleanly!
        ok_reordered = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": deliv_a1,
                    "outcome": "success",
                    "read_acks": [
                        {
                            "served_receipt_id": receipt_served_a1,
                            "task_id": task_a1,
                            "revision": 3,
                            "resource_digests": [
                                {"name": "beta.md", "digest": dig_beta},
                                {"name": "alpha.md", "digest": dig_alpha},
                            ],
                        }
                    ],
                    "idempotency_key": "idem_reordered_ok_01",
                },
                token=dan_a.token,
                selected_scope=scope,
            ),
        )
        assert ok_reordered["status"] == "declared"
        assert _count_rows(rt.store, "artifact_read_ack") == 1
    finally:
        rt.close()


# --- 5. HTTP flush is daemon->shim served_only only; failed stdio / dup finalize / revoke never auto-ack -------------


def test_failed_stdio_does_not_generate_automatic_ack(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    from superbrain.core.errors import BrainError

    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        content = b"daemon to shim bytes"
        domain.seed_artifact(
            bridge,
            artifact_id="art-stdio-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=content, level="L1"),),
        )
        task_id, _deliv_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_stdio_1")

        art_1 = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-stdio-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_stdio_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in art_1
        receipt_1 = str(art_1["served_receipt_id"])
        comp_1 = bridge.build_send_completion(receipt_1)

        # Daemon flushes HTTP response to shim, then shim fails writing stdout to host -> NO ReadAck exists!
        fin_a = bridge.finalize_send_attempt(comp_1)
        fin_b = bridge.finalize_send_attempt(comp_1)  # Duplicate completion callback is idempotent!
        assert str(fin_a.state) == "served_only"
        assert str(fin_b.state) == "served_only"
        assert _count_rows(rt.store, "artifact_read_ack") == 0

        # Cannot downgrade historical served_only to unknown after flush completed!
        with pytest.raises(BrainError):
            bridge.interrupt_send_attempt(receipt_1)

        # Fence checks on a second pending attempt: stale epoch, wrong instance, wrong store, or tampered subject fail!
        art_2 = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-stdio-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_stdio_02",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        receipt_2 = str(art_2["served_receipt_id"])
        comp_2 = bridge.build_send_completion(receipt_2)

        for bad_comp in (
            replace(comp_2, identity=replace(comp_2.identity, writer_epoch=comp_2.identity.writer_epoch + 1)),
            replace(comp_2, identity=replace(comp_2.identity, instance_id=new_id())),
            replace(comp_2, identity=replace(comp_2.identity, store_id=new_id())),
            replace(comp_2, logical_result_id=new_id()),
            replace(comp_2, principal_id=new_id()),
            replace(comp_2, artifact_id="art-other-999"),
            replace(comp_2, revision=99),
            replace(comp_2, task_id=new_id()),
            replace(comp_2, resource_digests=(ResourceDigest(name="L1.md", digest="sha256:" + "0" * 64),)),
        ):
            with pytest.raises(BrainError):
                bridge.finalize_send_attempt(bad_comp)

        with rt.store.transaction() as stxn:
            state_2 = stxn.db.execute("SELECT state FROM artifact_send_attempt WHERE id = ?", (receipt_2,)).fetchone()
        assert state_2 == ("pending",)

        # Valid finalize + subsequent credential revoke keeps historical served_only and never creates ReadAck (C5:113)!
        assert str(bridge.finalize_send_attempt(comp_2).state) == "served_only"
        revoke_proof = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=seeded.principal.owner_id,
            action="credential_revoke",
            subject_id=seeded.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        )
        bridge.revoke_credential(seeded.credential_id, revoke_proof)
        assert _count_rows(rt.store, "artifact_read_ack") == 0
        with rt.store.transaction() as stxn:
            states = stxn.db.execute("SELECT id, state FROM artifact_send_attempt ORDER BY rowid").fetchall()
        assert states == [(receipt_1, "served_only"), (receipt_2, "served_only")]
    finally:
        rt.close()


# --- 6. Matching ReadAck is client declaration only; prune_expired keeps send/ack history; 4b cutoff safe ------------


def test_matching_ack_is_client_declaration_only(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        content = b"declared lesson content"
        res_digest = digest_bytes(content)
        domain.seed_artifact(
            bridge,
            artifact_id="art-decl-1",
            revision=1,
            kind="lesson",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=content, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_decl_1")

        art_ok = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-decl-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_decl_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in art_ok
        receipt_id = str(art_ok["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_id))

        ack = ReadAckInput(
            served_receipt_id=receipt_id,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        out_ok = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack.to_dict()],
                    "idempotency_key": "idem_out_decl_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert set(out_ok) == {"outcome_id", "status"}
        assert out_ok["status"] == "declared"

        # served_only NEVER mutates into read_ack; artifact_read_ack has its own distinct UUIDv7!
        with rt.store.transaction() as stxn:
            attempt_row = stxn.db.execute(
                "SELECT state FROM artifact_send_attempt WHERE id = ?", (receipt_id,)
            ).fetchone()
            ack_row = stxn.db.execute(
                "SELECT id, served_receipt_id, principal_id, task_id, revision FROM artifact_read_ack"
            ).fetchone()
        assert attempt_row == ("served_only",)
        assert ack_row is not None
        assert is_uuid(str(ack_row[0])) and str(ack_row[0]) != receipt_id
        assert ack_row[1:] == (receipt_id, seeded.principal.principal_id, task_id, 1)

        # 4b 1,475 ms cutoff race: if waiter timed out to COMMIT_OUTCOME_UNKNOWN during commit, owner finish must NOT
        # leave behind a finalizable 'pending' send attempt!
        def _advance_past_cutoff(_tx: KernelTx) -> None:
            mono.advance(1_475 * MS)
            bridge.arbitrate_deadlines()

        domain.before_apply_hook = _advance_past_cutoff
        sub_cutoff = bridge.submit_request(
            "get_artifact",
            {
                "schema_version": "2.0",
                "workspace_id": ws.repo_id,
                "task_id": task_id,
                "artifact_id": "art-decl-1",
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem_art_cutoff_02",
            },
            token=seeded.token,
            selected_scope=scope,
        )
        assert bridge.process_next_queued(block=False) is True
        domain.before_apply_hook = None
        _expect_err("get_artifact", sub_cutoff.wait(timeout=2.0), ErrorCode.COMMIT_OUTCOME_UNKNOWN)
        with rt.store.transaction() as stxn:
            pending_after_cutoff = stxn.db.execute(
                "SELECT COUNT(*) FROM artifact_send_attempt WHERE state = 'pending'"
            ).fetchone()
        assert pending_after_cutoff == (0,)

        # Idempotency pruning after 30 days removes ONLY idempotency rows — never results, holds, attempts, or ReadAcks!
        clock.advance(dt.timedelta(days=31))
        pruned = bridge.prune_expired(clock.now())
        assert pruned == 4
        assert _count_rows(rt.store, "idempotency") == 0
        assert _count_rows(rt.store, "artifact_send_attempt") >= 1
        assert _count_rows(rt.store, "artifact_read_ack") == 1
        assert _count_rows(rt.store, "p_fixture_domain_deliveries") == 1
        assert _count_rows(rt.store, "p_fixture_domain_artifact_results") == 2
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 1
        assert rt.store.cas.holders(res_digest)
    finally:
        rt.close()


# --- 7. served_receipt_id == artifact_send_attempt.id across reopen; recovery turns pending -> unknown ---------------


def test_reserved_receipt_id_is_attempt_id_across_reopen_and_pending_finalize(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    from superbrain.core.errors import BrainError

    mono = FakeMonotonicClock()
    root = trusted_tmp / "reopen-root"
    content = b"reopen durability bytes"
    res_digest = digest_bytes(content)

    # Epoch 1: reserve receipt_1 as pending, then close WITHOUT finalizing.
    rt_1 = _open_fixture_runtime(root, os_)
    try:
        seeded = seed_principal_and_credential(rt_1.policy)
        ws = _register_ws(rt_1, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge_1, domain_1 = _make_bridge_and_domain(rt_1, clock, mono)
        domain_1.seed_artifact(
            bridge_1,
            artifact_id="art-reopen-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=content, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(bridge_1, token=seeded.token, scope=scope, idem_key="idem_prep_reop_1")

        art_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "task_id": task_id,
            "artifact_id": "art-reopen-1",
            "revision": 1,
            "level": "L1",
            "idempotency_key": "idem_art_reop_01",
        }
        ok_1 = _expect_ok(
            "get_artifact",
            _run_tool(bridge_1, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        assert "served_receipt_id" in ok_1
        receipt_1 = str(ok_1["served_receipt_id"])
        with rt_1.store.transaction() as stxn:
            pk_rows = stxn.db.execute("SELECT id, state FROM artifact_send_attempt").fetchall()
        assert pk_rows == [(receipt_1, "pending")]
    finally:
        rt_1.close()

    # Epoch 2 (recover_pending_on_init=False): brand-new KernelBridge instance with empty RAM STILL resolves receipt_1
    # as 'pending' (IN_PROGRESS) from SQLite PK and can finalize it to 'served_only'!
    rt_2 = _open_fixture_runtime(root, os_)
    try:
        bridge_2, _ = _make_bridge_and_domain(rt_2, clock, mono, recover_pending_on_init=False)
        ack_1 = ReadAckInput(
            served_receipt_id=receipt_1,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        _expect_err(
            "record_outcome",
            _run_tool(
                bridge_2,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack_1.to_dict()],
                    "idempotency_key": "idem_out_reop_pend",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.IN_PROGRESS,
        )
        bridge_2.finalize_send_attempt(bridge_2.build_send_completion(receipt_1))

        # Also create receipt_2 via replay and leave it 'pending' to exercise crash/startup recovery on next reopen!
        ok_2 = _expect_ok(
            "get_artifact",
            _run_tool(bridge_2, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        receipt_2 = str(ok_2["served_receipt_id"])
        assert receipt_2 != receipt_1
    finally:
        rt_2.close()

    # Epoch 3 (default startup recovery recover_pending_on_init=True):
    # - receipt_1 stays 'served_only' and resolves ReadAck across reopen without any RAM map!
    # - receipt_2 transitions 'pending' -> 'unknown' on startup; neither ReadAck, finalize, nor replay upgrades it!
    rt_3 = _open_fixture_runtime(root, os_)
    try:
        bridge_3, _ = _make_bridge_and_domain(rt_3, clock, mono)
        with rt_3.store.transaction() as stxn:
            rows_after_recovery = stxn.db.execute(
                "SELECT id, state FROM artifact_send_attempt ORDER BY rowid"
            ).fetchall()
        assert rows_after_recovery == [(receipt_1, "served_only"), (receipt_2, "unknown")]
        assert _count_rows(rt_3.store, "artifact_read_ack") == 0

        # receipt_1 (served_only) succeeds across reopen:
        _expect_ok(
            "record_outcome",
            _run_tool(
                bridge_3,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack_1.to_dict()],
                    "idempotency_key": "idem_out_reop_served",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert _count_rows(rt_3.store, "artifact_read_ack") == 1

        # receipt_2 (unknown) is refused by both ReadAck (NOT_FOUND) and finalize_send_attempt!
        ack_2 = ReadAckInput(
            served_receipt_id=receipt_2,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="L1.md", digest=res_digest),),
        )
        _expect_err(
            "record_outcome",
            _run_tool(
                bridge_3,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack_2.to_dict()],
                    "idempotency_key": "idem_out_reop_unknown",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.NOT_FOUND,
        )
        with pytest.raises(BrainError):
            bridge_3.finalize_send_attempt(bridge_3.build_send_completion(receipt_2))

        # Replaying get_artifact mints receipt_3 while receipt_2 stays 'unknown'!
        ok_3 = _expect_ok(
            "get_artifact",
            _run_tool(bridge_3, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        receipt_3 = str(ok_3["served_receipt_id"])
        assert receipt_3 not in {receipt_1, receipt_2}
        with rt_3.store.transaction() as stxn:
            final_rows = stxn.db.execute("SELECT id, state FROM artifact_send_attempt ORDER BY rowid").fetchall()
        assert final_rows == [
            (receipt_1, "served_only"),
            (receipt_2, "unknown"),
            (receipt_3, "pending"),
        ]
    finally:
        rt_3.close()


# --- 8. Error or redacted get_artifact emits NO served_receipt_id and inserts NO artifact_send_attempt ---------------


def test_redacted_or_error_response_has_no_new_content_receipt(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        secret_res = b"quarantinable artifact bytes"
        res_digest = digest_bytes(secret_res)
        domain.seed_artifact(
            bridge,
            artifact_id="art-redact-1",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="L1.md", content=secret_res, level="L1"),),
        )
        task_id, _deliv_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_redact_01")

        # 1) Typed error response -> zero send attempts, schema-valid error envelope.
        _expect_err(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-missing-999",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_missing_01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.NOT_FOUND,
        )
        assert _count_rows(rt.store, "artifact_send_attempt") == 0

        # 2) Initial permitted get_artifact -> 1 send attempt (finalized to served_only).
        art_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "workspace_id": ws.repo_id,
            "task_id": task_id,
            "artifact_id": "art-redact-1",
            "revision": 1,
            "level": "L1",
            "idempotency_key": "idem_art_redact_01",
        }
        ok_initial = _expect_ok(
            "get_artifact",
            _run_tool(bridge, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        assert "served_receipt_id" in ok_initial
        receipt_1 = str(ok_initial["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_1))
        assert _count_rows(rt.store, "artifact_send_attempt") == 1

        with rt.store.transaction() as stxn:
            orig_id_row = stxn.db.execute(
                "SELECT result_id FROM idempotency WHERE principal_id = ? AND tool = 'get_artifact'",
                (seeded.principal.principal_id,),
            ).fetchone()
        assert orig_id_row is not None
        orig_result_id = str(orig_id_row[0])

        # 3) Quarantine resource blob -> replay AND fresh-key get_artifact both render status='redacted' WITHOUT
        #    served_receipt_id, validate against GetArtifactRedactedResult, and insert ZERO new send attempts!
        bridge.record_policy_intent(IntentKind.QUARANTINE, {"digest": res_digest})

        redacted_replay = _expect_ok(
            "get_artifact",
            _run_tool(bridge, "get_artifact", art_args, token=seeded.token, selected_scope=scope),
        )
        assert redacted_replay == {
            "artifact_id": "art-redact-1",
            "revision": 1,
            "level": "L1",
            "status": "redacted",
            "reason": "access_restricted",
            "resources": [],
        }
        assert "served_receipt_id" not in redacted_replay
        assert _count_rows(rt.store, "artifact_send_attempt") == 1

        redacted_fresh = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {**art_args, "idempotency_key": "idem_art_redact_02"},
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert redacted_fresh["status"] == "redacted"
        assert "served_receipt_id" not in redacted_fresh
        assert _count_rows(rt.store, "artifact_send_attempt") == 1

        # Original result identity & prior send history remain intact!
        with rt.store.transaction() as stxn:
            kept_row = stxn.db.execute("SELECT id, logical_result_id, state FROM artifact_send_attempt").fetchone()
        assert kept_row == (receipt_1, orig_result_id, "served_only")
    finally:
        rt.close()


# --- 9. Repeated identical ReadAck reuses ack_id (same batch & cross-outcome key); batch failure rolls back ----------


def test_repeated_identical_read_ack_reuses_ack_id(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> None:
    mono = FakeMonotonicClock()
    rt = _open_fixture_runtime(trusted_tmp / "root", os_)
    try:
        seeded = seed_principal_and_credential(rt.policy)
        ws = _register_ws(rt, clock, seeded, alias="ws-main", checkout_dir=trusted_tmp / "chk")
        scope = Scope(ws.repo_id, ws.checkout_id)
        bridge, domain = _make_bridge_and_domain(rt, clock, mono)

        bytes_a = b"artifact A content"
        bytes_b = b"artifact B content"
        dig_a = digest_bytes(bytes_a)
        dig_b = digest_bytes(bytes_b)
        domain.seed_artifact(
            bridge,
            artifact_id="art-dup-a",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="a.md", content=bytes_a, level="L1"),),
        )
        domain.seed_artifact(
            bridge,
            artifact_id="art-dup-b",
            revision=1,
            kind="skill",
            owner_id=seeded.principal.owner_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            resources=(FixtureResourceSpec(name="b.md", content=bytes_b, level="L1"),),
        )
        task_id, delivery_id = _prepare_task_on(bridge, token=seeded.token, scope=scope, idem_key="idem_prep_dupack_01")

        ok_a = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-dup-a",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_dupack_a01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert "served_receipt_id" in ok_a
        receipt_a = str(ok_a["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_a))

        ok_b = _expect_ok(
            "get_artifact",
            _run_tool(
                bridge,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": task_id,
                    "artifact_id": "art-dup-b",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_art_dupack_b01",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        receipt_b = str(ok_b["served_receipt_id"])
        bridge.finalize_send_attempt(bridge.build_send_completion(receipt_b))

        ack_a = ReadAckInput(
            served_receipt_id=receipt_a,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="a.md", digest=dig_a),),
        )

        # 1) Duplicate identical ReadAckInput in a single record_outcome call -> 1 row in artifact_read_ack!
        out_1 = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "unknown",
                    "read_acks": [ack_a.to_dict(), ack_a.to_dict()],
                    "idempotency_key": "idem_out_dup_call_1",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert _count_rows(rt.store, "artifact_read_ack") == 1
        with rt.store.transaction() as stxn:
            ack_row_1 = stxn.db.execute("SELECT id, served_receipt_id FROM artifact_read_ack").fetchone()
        assert ack_row_1 is not None
        ack_id_a = str(ack_row_1[0])
        assert is_uuid(ack_id_a) and ack_id_a != receipt_a
        assert ack_row_1[1] == receipt_a

        # 2) Different outcome idempotency_key referencing the same served_receipt_id reuses ack_id_a without dup row!
        out_2 = _expect_ok(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "success",
                    "read_acks": [ack_a.to_dict()],
                    "idempotency_key": "idem_out_dup_call_2",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
        )
        assert out_2["outcome_id"] != out_1["outcome_id"]
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 2
        assert _count_rows(rt.store, "artifact_read_ack") == 1
        with rt.store.transaction() as stxn:
            ack_row_2 = stxn.db.execute("SELECT id FROM artifact_read_ack").fetchone()
        assert ack_row_2 == (ack_id_a,)

        # 3) Atomic rollback: valid ack_b + invalid second item in one transaction rolls back ack_b AND outcome!
        ack_b_valid = ReadAckInput(
            served_receipt_id=receipt_b,
            task_id=task_id,
            revision=1,
            resource_digests=(ResourceDigest(name="b.md", digest=dig_b),),
        )
        ack_b_bad = ReadAckInput(
            served_receipt_id=receipt_b,
            task_id=task_id,
            revision=2,
            resource_digests=(ResourceDigest(name="b.md", digest=dig_b),),
        )
        _expect_err(
            "record_outcome",
            _run_tool(
                bridge,
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "delivery_id": delivery_id,
                    "outcome": "failure",
                    "read_acks": [ack_b_valid.to_dict(), ack_b_bad.to_dict()],
                    "idempotency_key": "idem_out_batch_rb_3",
                },
                token=seeded.token,
                selected_scope=scope,
            ),
            ErrorCode.INVALID_INPUT,
        )
        assert _count_rows(rt.store, "artifact_read_ack") == 1
        assert _count_rows(rt.store, "p_fixture_domain_outcomes") == 2
    finally:
        rt.close()
