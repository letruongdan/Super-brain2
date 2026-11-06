"""Independent regressions for Task 3 review findings I2-T3-R01, R02 and R04 through a real Store and policy.

Oracle sources (requirements, not current output):

- R01 — Task 3 plan ("field path digest thay raw JSON pointer trong ledger ... field path descriptor safe ở CAS"),
  D6 ("Khóa JSON nhạy cảm khiến cả subtree bị loại trước canonical safe payload"; privacy before the first durable
  write) and spec 14.2 ("Filter lỗi thì không lưu payload gốc"). A key the filter strips must not reach CAS, the
  ledger or any projection by another route, e.g. as a ``DeliveryItem.path``. Distinct fields keep distinct
  identities, so two secret paths may not collapse onto one shared sentinel identity.
- R02 — spec 14.2: "Nội dung tạo trong task kế thừa lineage của task tại thời điểm tạo. Một trường gửi đi ... mang
  lineage hiện tại của task, không chỉ repo." and "Phục vụ sang task mới chuyển cả lineage"; eligibility checks the
  current ``provider_egress`` of every lineage source. In the D6 handoff fixture (repo A -> T1 in B -> T2 in C), a
  field derived inside T2 carries A+B+C. With C's egress disabled the field is not eligible, before and after
  rebuild. A field's own recorded provenance is immutable: it never loses its own sources.
- R04 — Task 3 plan ("descriptor safe ở CAS có holder"; explicit snapshot "phải đúng checkout, readable ... sai/
  quarantine không được bỏ qua để fallback") and D6 (snapshot.observed with its held descriptor). Once the exact
  hold ``(event, snapshot_id, descriptor_digest)`` is released, that snapshot is closed: explicit admission is
  refused, dedupe never returns it (a new snapshot and hold are written), and the restriction port treats it as
  restricted. Blob presence or another holder is no proof, and the same holds after rebuild.

Every canary below is a fake test value.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Mapping
from functools import partial
from pathlib import Path

import pytest

from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.lineage import (
    admit_source_snapshot,
    evaluate_egress_eligibility,
    prepare_labeled_delivery,
    register_snapshot,
)
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DeliveryItem,
    FieldLineage,
    FilterPolicy,
    LabeledDelivery,
    LineageRef,
    LineageSet,
    ObjectRef,
    Principal,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    TaskBinding,
    WorkspaceBinding,
    WorkspaceSelector,
    binding_lineage_ref,
    field_path_digest,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.workspaces import KernelWorkspaceStore, StoreSourceRestrictions
from tests.support.clock import FakeClock
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

MS = 1_000_000
CANARY_1 = "sk-" + "A" * 24
CANARY_2 = "sk-" + "B" * 24
TREE_1 = "sha256:" + "1" * 64
TREE_3 = "sha256:" + "3" * 64


# --- helpers ------------------------------------------------------------------------------------------------------


class _Mono:
    def __init__(self) -> None:
        self.now = 50_000 * MS

    def __call__(self) -> int:
        return self.now


class _Observer:
    def __init__(self, descriptor: SnapshotDescriptor) -> None:
        self.descriptor = descriptor

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        return SnapshotObservation(SnapshotStatus.AVAILABLE, self.descriptor)


def _desc(tree: str) -> SnapshotDescriptor:
    return SnapshotDescriptor(
        kind="git", tree_or_head_digest=tree, dirty=False, dirty_digest=None, observed_at="2026-11-07T01:02:03.000000Z"
    )


def _open(root: Path, os_: OsAdapters) -> Runtime:
    handlers, kinds = kernel_store_extensions()
    return open_runtime(
        root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def _register(
    rt: Runtime, clock: FakeClock, seeded: SeededCredential, *, alias: str, checkout: Path, remote: str, egress: bool
) -> WorkspaceBinding:
    checkout.mkdir(parents=True, exist_ok=True)
    reg = build_registration(
        owner_id=seeded.principal.owner_id,
        principal_id=seeded.principal.principal_id,
        machine_id=seeded.principal.machine_id,
        alias=alias,
        raw_path=str(checkout),
        raw_remote=remote,
        provider_egress_enabled=egress,
    )
    return rt.policy.register_authorized_workspace(
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


def _prepare(
    rt: Runtime,
    principal: Principal,
    alias: str,
    task_id: str,
    *,
    payload: JsonValue = None,
    items: tuple[DeliveryItem, ...] = (),
    served: tuple[LineageRef, ...] = (),
    observer: _Observer | None = None,
    snapshot_id: str | None = None,
) -> LabeledDelivery:
    mono = _Mono()
    start = mono()
    return prepare_labeled_delivery(
        store=KernelWorkspaceStore(rt.store, rt.policy),
        policy=rt.policy,
        principal=principal,
        selector=WorkspaceSelector(workspace_hint=alias, source_snapshot_id=snapshot_id),
        task_id=task_id,
        payload=payload if payload is not None else {"schema_version": "2.0", "description": "fix the login bug"},
        filter_policy=FilterPolicy(),
        items=items,
        served_sources=served,
        observer=observer,
        monotonic_ns=mono,
        local_phase_start_ns=start,
        total_deadline_ns=start + 1_500 * MS,
    )


def _artifact(binding: WorkspaceBinding, ident: str) -> LineageRef:
    return LineageRef(
        owner_id=binding.owner_id,
        repo_id=binding.repo_id,
        source=ObjectRef(kind="artifact", id=ident, revision=1, digest=digest_bytes(ident.encode())),
    )


def _snapshot_ref(binding: WorkspaceBinding, snapshot_id: str, digest: str) -> LineageRef:
    return LineageRef(
        owner_id=binding.owner_id,
        repo_id=binding.repo_id,
        source=ObjectRef(kind="source_snapshot", id=snapshot_id, revision=1, digest=digest),
    )


def _read_task_lineage(task_id: str, tx: KernelTx) -> tuple[LineageSet, bool]:
    return tx.read_task_lineage(task_id)


def _read_field_lineage(task_id: str, tx: KernelTx) -> Mapping[str, FieldLineage]:
    return tx.read_field_lineage(task_id)


def _read_task_binding(task_id: str, tx: KernelTx) -> TaskBinding | None:
    return tx.read_task_binding(task_id)


def _files_containing(root: Path, needle: bytes) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and needle in p.read_bytes())


@pytest.fixture
def kroot(trusted_tmp: Path) -> Path:
    return trusted_tmp / "kroot"


@pytest.fixture
def kernel(kroot: Path, os_: OsAdapters) -> Iterator[Runtime]:
    rt = _open(kroot, os_)
    try:
        yield rt
    finally:
        rt.close()


@pytest.fixture
def dan(kernel: Runtime) -> SeededCredential:
    return seed_principal_and_credential(kernel.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")


# --- I2-T3-R01: a key stripped by the filter never reaches CAS, ledger or projections -----------------------------


def test_filter_stripped_key_used_as_item_path_is_never_persisted(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "r01root"
    rt = _open(root, os_)
    task_id = "r01-task"
    committed: LabeledDelivery | None = None
    try:
        dan = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        binding = _register(
            rt, clock, dan, alias="r01", checkout=trusted_tmp / "r01", remote="https://r.example/o/r01.git", egress=True
        )
        bref = binding_lineage_ref(binding)
        clean_src, s1, s2 = _artifact(binding, "clean"), _artifact(binding, "sec-1"), _artifact(binding, "sec-2")
        items = (
            DeliveryItem(("description",), frozenset({bref, clean_src})),
            DeliveryItem((CANARY_1,), frozenset({bref, s1})),
            DeliveryItem((CANARY_2,), frozenset({bref, s2})),
        )
        payload: JsonValue = {
            "schema_version": "2.0",
            "description": "fix the login bug",
            CANARY_1: "ordinary value",
            CANARY_2: "another ordinary value",
        }
        try:
            committed = _prepare(rt, dan.principal, "r01", task_id, payload=payload, items=items)
        except BrainError as err:  # refusing the whole delivery is an acceptable privacy-first outcome
            assert err.code is ErrorCode.INVALID_INPUT, err.code
        kstore = KernelWorkspaceStore(rt.store, rt.policy)
        if committed is None:
            assert kstore.transact(lambda tx: tx.read_task_binding(task_id)) is None
        else:
            assert committed.safe_payload is not None
            assert committed.safe_payload.stripped_keys_count == 2
            for _round in ("live", "rebuilt"):
                fields = kstore.transact(lambda tx: tx.read_field_lineage(task_id))
                clean_digest = field_path_digest(("description",))
                assert clean_digest in fields
                # Both secret items dropped (1 identity) or both kept under distinct safe identities (3).
                # Two identities would mean the secret items collapsed onto one shared identity.
                assert len(fields) in (1, 3), sorted(fields)
                rt.store.rebuild_projections()
        ledger_text = "\n".join(repr((e.kind, dict(e.meta), tuple(e.refs))) for e in rt.store.entries())
        assert CANARY_1 not in ledger_text and CANARY_2 not in ledger_text
    finally:
        rt.close()
    for canary in (CANARY_1, CANARY_2):
        assert _files_containing(root, canary.encode("utf-8")) == [], canary  # CAS blobs, DB/WAL, projections


# --- I2-T3-R02: a field derived inside a task inherits the task's whole current lineage ---------------------------


def test_derived_field_inherits_handoff_lineage_and_follows_disabled_egress(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    repo_a = _register(
        kernel, clock, dan, alias="ra", checkout=trusted_tmp / "ra", remote="https://h.example/o/a.git", egress=True
    )
    _register(
        kernel, clock, dan, alias="rb", checkout=trusted_tmp / "rb", remote="https://h.example/o/b.git", egress=True
    )
    repo_c = _register(
        kernel, clock, dan, alias="rc", checkout=trusted_tmp / "rc", remote="https://h.example/o/c.git", egress=False
    )
    repo_d = _register(
        kernel, clock, dan, alias="rd", checkout=trusted_tmp / "rd", remote="https://h.example/o/d.git", egress=True
    )
    src_a = _artifact(repo_a, "art-a")
    _prepare(
        kernel,
        dan.principal,
        "rb",
        "T1",
        items=(DeliveryItem(("handoff",), frozenset({src_a})),),
        served=(src_a,),
    )
    kernel.store.rebuild_projections()
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    t1_lineage, t1_unknown = kstore.transact(lambda tx: tx.read_task_lineage("T1"))
    derived = DeliveryItem(("derived",), t1_lineage, unknown_source=t1_unknown)
    _prepare(kernel, dan.principal, "rc", "T2", items=(derived,))  # C: provider_egress disabled
    _prepare(kernel, dan.principal, "rd", "T3", items=(derived,))  # D: control with egress enabled
    restrictions = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": src_a.__eq__})
    derived_digest = field_path_digest(("derived",))
    for stage in ("committed", "rebuilt"):
        handoff = kstore.transact(lambda tx: tx.read_field_lineage("T1"))[field_path_digest(("handoff",))]
        assert src_a in handoff.sources, stage  # an item's own provenance is never lost
        for task_id, repo, eligible in (("T2", repo_c, False), ("T3", repo_d, True)):
            task_lineage, _ = kstore.transact(partial(_read_task_lineage, task_id))
            field = kstore.transact(partial(_read_field_lineage, task_id))[derived_digest]
            assert binding_lineage_ref(repo) in task_lineage, (stage, task_id)
            assert evaluate_egress_eligibility(field, kernel.policy, restrictions=restrictions) is eligible, (
                stage,
                task_id,
                sorted(r.repo_id for r in field.sources),
            )
            assert t1_lineage <= field.sources, (stage, task_id)  # its own derivation sources stay
            assert task_lineage <= field.sources, (stage, task_id, sorted(r.repo_id for r in field.sources))
        kernel.store.rebuild_projections()


# --- I2-T3-R04: a snapshot whose exact hold was released is closed -------------------------------------------------


def _holder_ids(kernel: Runtime, digest: str) -> set[tuple[str, str]]:
    return {(kind, holder) for kind, holder, _retention in kernel.store.cas.holders(digest)}


def _released_snapshot(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, *, shared: bool
) -> tuple[WorkspaceBinding, str, str, WorkspaceBinding | None, str | None]:
    """Register a snapshot, then release its exact hold with a valid ``Txn.release``; the blob stays in CAS.

    ``shared``: the same descriptor content is also held by a snapshot of another checkout and by an unrelated
    holder, so the blob keeps other holders after the release.
    """
    binding = _register(
        kernel, clock, dan, alias="rel", checkout=trusted_tmp / "rel", remote="https://s.example/o/r.git", egress=True
    )
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    digest = _desc(TREE_1).descriptor_digest
    sid = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
    other: WorkspaceBinding | None = None
    keeper: str | None = None
    if shared:
        other = _register(
            kernel,
            clock,
            dan,
            alias="rel2",
            checkout=trusted_tmp / "rel2",
            remote="https://s.example/o/r.git",
            egress=True,
        )
        keeper = kstore.transact(lambda tx: register_snapshot(tx, other, _desc(TREE_1)))
        assert keeper != sid
        with kernel.store.transaction() as txn:
            txn.hold(digest, "event", new_id(), RetentionClass.DURABLE, None)
    assert ("event", sid) in _holder_ids(kernel, digest)
    with kernel.store.transaction() as txn:
        txn.release(digest, "event", sid, "superseded")
    assert ("event", sid) not in _holder_ids(kernel, digest)
    assert (len(_holder_ids(kernel, digest)) > 0) is shared
    assert kernel.store.cas.blob_intact(digest)  # the bytes are still in CAS: presence is not proof
    return binding, sid, digest, other, keeper


@pytest.mark.parametrize("shared", [False, True], ids=["sole-holder", "other-holders"])
def test_released_snapshot_is_refused_at_explicit_admission(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, shared: bool
) -> None:
    binding, sid, _digest, other, keeper = _released_snapshot(kernel, dan, clock, trusted_tmp, shared=shared)
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    for label in ("after release", "after rebuild"):
        with pytest.raises(BrainError) as exc:
            kstore.transact(lambda tx: admit_source_snapshot(tx, binding, sid))
        assert exc.value.code is ErrorCode.NOT_FOUND, label
        task_id = f"rel-explicit-{label[6:]}"
        with pytest.raises(BrainError) as exc:
            _prepare(kernel, dan.principal, "rel", task_id, snapshot_id=sid)
        assert exc.value.code is ErrorCode.NOT_FOUND, label
        assert kstore.transact(partial(_read_task_binding, task_id)) is None, label
        if other is not None and keeper is not None:  # the still-held twin stays admissible
            assert kstore.transact(lambda tx: admit_source_snapshot(tx, other, keeper)).snapshot_id == keeper
        kernel.store.rebuild_projections()


@pytest.mark.parametrize("shared", [False, True], ids=["sole-holder", "other-holders"])
def test_released_snapshot_is_never_deduped_and_a_new_snapshot_and_hold_are_written(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, shared: bool
) -> None:
    binding, sid, digest, _other, _keeper = _released_snapshot(kernel, dan, clock, trusted_tmp, shared=shared)
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    for label in ("after release", "after rebuild"):
        fresh = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
        assert fresh != sid, label  # never resurrects the closed identity
        assert ("event", fresh) in _holder_ids(kernel, digest), label
        observed = [e for e in kernel.store.entries() if e.kind == "snapshot.observed"]
        assert any(e.meta.get("snapshot_id") == fresh for e in observed), label
        kernel.store.rebuild_projections()
    delivery = _prepare(kernel, dan.principal, "rel", "rel-observed", observer=_Observer(_desc(TREE_1)))
    assert delivery.binding.source_snapshot_id not in (None, sid)


@pytest.mark.parametrize("shared", [False, True], ids=["sole-holder", "other-holders"])
def test_released_snapshot_is_restricted_by_the_restriction_port(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, shared: bool
) -> None:
    binding, sid, digest, other, keeper = _released_snapshot(kernel, dan, clock, trusted_tmp, shared=shared)
    for label in ("after release", "after rebuild"):
        restrictions = StoreSourceRestrictions(kernel.store, kernel.policy)
        assert restrictions.is_restricted(_snapshot_ref(binding, sid, digest)) is True, label
        assert (
            evaluate_egress_eligibility(
                frozenset({_snapshot_ref(binding, sid, digest)}), kernel.policy, restrictions=restrictions
            )
            is False
        ), label
        if other is not None and keeper is not None:  # the still-held twin stays unrestricted
            assert restrictions.is_restricted(_snapshot_ref(other, keeper, digest)) is False, label
        kernel.store.rebuild_projections()


def test_release_of_one_descriptor_leaves_other_snapshots_admissible(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    """Guard: closing one snapshot never restricts an unrelated, still-held snapshot of the same checkout."""
    binding = _register(
        kernel, clock, dan, alias="g", checkout=trusted_tmp / "g", remote="https://s.example/o/g.git", egress=True
    )
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    released = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
    kept = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_3)))
    with kernel.store.transaction() as txn:
        txn.release(_desc(TREE_1).descriptor_digest, "event", released, "superseded")
    assert kstore.transact(lambda tx: admit_source_snapshot(tx, binding, kept)).snapshot_id == kept
    assert kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_3))) == kept
