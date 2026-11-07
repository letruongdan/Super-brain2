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
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import pytest

from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.lineage import (
    admit_source_snapshot,
    evaluate_egress_eligibility,
    prepare_labeled_delivery,
    record_field_lineage,
    record_task_lineage,
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
    LineagedField,
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
from superbrain.ports.kernel import KernelTx, SourceRestrictionPort
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


def _record_field(path: tuple[str | int, ...], sources: LineageSet, tx: KernelTx) -> FieldLineage:
    return record_field_lineage(tx, "r01d-task", path, sources, unknown=False)


def test_direct_record_field_lineage_refuses_filter_stripped_path_before_any_write(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """I2-T3-R01 at the shared boundary: ``record_field_lineage`` itself, not only ``prepare_labeled_delivery``.

    Same requirement as the R01 regression above (Task 3 plan: safe field-path descriptor in CAS; D6 privacy before
    the first durable write): a path naming a key the privacy filter strips is refused (``INVALID_INPUT``) and leaves
    nothing in CAS, the ledger or projections; a clean path still records.
    """
    root = trusted_tmp / "r01direct"
    rt = _open(root, os_)
    try:
        dan = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
        binding = _register(
            rt, clock, dan, alias="r01d", checkout=trusted_tmp / "r01d", remote="https://r.example/o/d.git", egress=True
        )
        sources = frozenset({binding_lineage_ref(binding)})
        kstore = KernelWorkspaceStore(rt.store, rt.policy)
        before = len(list(rt.store.entries()))
        secret_paths: tuple[tuple[str | int, ...], ...] = ((CANARY_1,), ("outer", CANARY_1), ("items", 0, CANARY_1))
        for path in secret_paths:
            with pytest.raises(BrainError) as exc:
                kstore.transact(partial(_record_field, path, sources))
            assert exc.value.code is ErrorCode.INVALID_INPUT, path
        assert len(list(rt.store.entries())) == before
        assert kstore.transact(partial(_read_field_lineage, "r01d-task")) == {}
        recorded = kstore.transact(partial(_record_field, ("description",), sources))
        assert recorded.field_path_digest == field_path_digest(("description",))
        assert kstore.transact(partial(_read_field_lineage, "r01d-task"))[recorded.field_path_digest].sources == sources
        ledger_text = "\n".join(repr((e.kind, dict(e.meta), tuple(e.refs))) for e in rt.store.entries())
        assert CANARY_1 not in ledger_text
    finally:
        rt.close()
    assert _files_containing(root, CANARY_1.encode("utf-8")) == []  # CAS blobs, DB/WAL, projections


def _rehold_under_other_digest(kernel: Runtime, binding: WorkspaceBinding, *, other_holder: bool) -> tuple[str, str]:
    """Register a snapshot, release its exact hold, then hold the SAME snapshot ID under a DIFFERENT digest.

    I2-T3-R04 invariant: only the exact current hold ``(event, snapshot_id, descriptor_digest)`` proves a snapshot
    readable. A hold of that snapshot ID on another blob is not that hold.
    """
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    digest = _desc(TREE_1).descriptor_digest
    sid = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
    wrong = kernel.store.cas.put(b"unrelated blob held under the snapshot id")
    assert wrong != digest
    with kernel.store.transaction() as txn:
        txn.release(digest, "event", sid, "superseded")
        txn.hold(wrong, "event", sid, RetentionClass.DURABLE, None)
        if other_holder:
            txn.hold(digest, "event", new_id(), RetentionClass.DURABLE, None)
    assert ("event", sid) not in _holder_ids(kernel, digest)
    assert ("event", sid) in _holder_ids(kernel, wrong)
    assert kernel.store.cas.blob_intact(digest)
    return sid, digest


@pytest.mark.parametrize("other_holder", [False, True], ids=["wrong-digest-only", "wrong-digest-plus-other-holder"])
def test_hold_of_the_snapshot_id_on_another_digest_is_not_the_exact_hold(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, other_holder: bool
) -> None:
    binding = _register(
        kernel, clock, dan, alias="xd", checkout=trusted_tmp / "xd", remote="https://s.example/o/x.git", egress=True
    )
    sid, digest = _rehold_under_other_digest(kernel, binding, other_holder=other_holder)
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    for label in ("live", "after rebuild"):
        with pytest.raises(BrainError) as exc:
            kstore.transact(lambda tx: admit_source_snapshot(tx, binding, sid))
        assert exc.value.code is ErrorCode.NOT_FOUND, label
        restrictions = StoreSourceRestrictions(kernel.store, kernel.policy)
        assert restrictions.is_restricted(_snapshot_ref(binding, sid, digest)) is True, label
        fresh = kstore.transact(lambda tx: register_snapshot(tx, binding, _desc(TREE_1)))
        assert fresh != sid, label
        assert ("event", fresh) in _holder_ids(kernel, digest), label
        kernel.store.rebuild_projections()


# --- I2-T3-R02 reopened (7278dc8): duplicate field paths and initial == committed == replay == rebuilt ------------


@dataclass(frozen=True)
class _DeliveryBoundaryView:
    items: tuple[FieldLineage, ...]
    task_lineage: LineageSet
    task_unknown: bool
    field_eligibility: tuple[tuple[str, bool], ...]
    task_eligible: bool


def _delivery_view(
    delivery: LabeledDelivery, rt: Runtime, restrictions: SourceRestrictionPort
) -> _DeliveryBoundaryView:
    return _DeliveryBoundaryView(
        items=delivery.items,
        task_lineage=delivery.task_lineage,
        task_unknown=delivery.task_unknown,
        field_eligibility=tuple(
            (f.field_path_digest, evaluate_egress_eligibility(f, rt.policy, restrictions=restrictions))
            for f in delivery.items
        ),
        task_eligible=evaluate_egress_eligibility(
            LineagedField(value=None, sources=delivery.task_lineage, unknown_source=delivery.task_unknown),
            rt.policy,
            restrictions=restrictions,
        ),
    )


def _projected_view(
    kstore: KernelWorkspaceStore, rt: Runtime, task_id: str, restrictions: SourceRestrictionPort
) -> _DeliveryBoundaryView:
    fields = kstore.transact(partial(_read_field_lineage, task_id))
    task_lineage, task_unknown = kstore.transact(partial(_read_task_lineage, task_id))
    items = tuple(fields[d] for d in sorted(fields))
    return _DeliveryBoundaryView(
        items=items,
        task_lineage=task_lineage,
        task_unknown=task_unknown,
        field_eligibility=tuple(
            (f.field_path_digest, evaluate_egress_eligibility(f, rt.policy, restrictions=restrictions))
            for f in items
        ),
        task_eligible=evaluate_egress_eligibility(
            LineagedField(value=None, sources=task_lineage, unknown_source=task_unknown),
            rt.policy,
            restrictions=restrictions,
        ),
    )


def _assert_structural_uniqueness(delivery: LabeledDelivery) -> None:
    digests = [f.field_path_digest for f in delivery.items]
    assert len(digests) == len(set(digests)), digests
    assert len(delivery.omitted_items) == len(set(delivery.omitted_items)), delivery.omitted_items
    assert set(digests).isdisjoint(delivery.omitted_items), (digests, delivery.omitted_items)


def _prepare_and_check_boundaries(
    rt: Runtime,
    principal: Principal,
    alias: str,
    task_id: str,
    *,
    items: tuple[DeliveryItem, ...],
    restrictions: SourceRestrictionPort,
    observer: _Observer | None = None,
    served: tuple[LineageRef, ...] = (),
) -> tuple[LabeledDelivery, _DeliveryBoundaryView]:
    kstore = KernelWorkspaceStore(rt.store, rt.policy)
    initial = _prepare(rt, principal, alias, task_id, items=items, served=served, observer=observer)
    assert initial.replayed is False
    initial_view = _delivery_view(initial, rt, restrictions)
    committed_view = _projected_view(kstore, rt, task_id, restrictions)
    replay = _prepare(rt, principal, alias, task_id, items=items, served=served, observer=observer)
    assert replay.replayed is True
    replay_view = _delivery_view(replay, rt, restrictions)
    rt.store.rebuild_projections()
    rebuilt_view = _projected_view(kstore, rt, task_id, restrictions)
    rebuilt_replay = _prepare(rt, principal, alias, task_id, items=items, served=served, observer=observer)
    assert rebuilt_replay.replayed is True
    rebuilt_replay_view = _delivery_view(rebuilt_replay, rt, restrictions)

    assert initial_view == committed_view
    assert replay_view == committed_view
    assert rebuilt_view == committed_view
    assert rebuilt_replay_view == committed_view
    for candidate in (initial, replay, rebuilt_replay):
        _assert_structural_uniqueness(candidate)
    return initial, initial_view


@pytest.mark.parametrize("path", [("same",), ("nested", 0, "same")], ids=["top-level", "nested"])
def test_duplicate_field_path_unknown_source_aggregates_monotonically_in_both_orders(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, path: tuple[str | int, ...]
) -> None:
    repo = _register(
        kernel,
        clock,
        dan,
        alias="dupu",
        checkout=trusted_tmp / "dupu",
        remote="https://h.example/o/du.git",
        egress=True,
    )
    src_a = _artifact(repo, "art-known-a")
    src_b = _artifact(repo, "art-known-b")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_a, src_b}.__contains__}
    )
    known_item = DeliveryItem(path, frozenset({src_a}), unknown_source=False)
    unknown_item = DeliveryItem(path, frozenset({src_b}), unknown_source=True)
    target_digest = field_path_digest(path)

    init_ft, view_ft = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupu", "dup-unk-ft", items=(known_item, unknown_item), restrictions=restrictions
    )
    init_tf, view_tf = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupu", "dup-unk-tf", items=(unknown_item, known_item), restrictions=restrictions
    )
    assert len(init_ft.items) == 1 and len(init_tf.items) == 1
    assert view_ft == view_tf
    (field,) = view_ft.items
    assert field.field_path_digest == target_digest
    assert {binding_lineage_ref(repo), src_a, src_b} <= field.sources
    assert field.unknown_source is True
    assert view_ft.task_unknown is True
    assert view_ft.field_eligibility == ((target_digest, False),)
    assert view_ft.task_eligible is False


def test_duplicate_field_path_empty_unproven_sources_marks_unknown_in_both_orders(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    repo = _register(
        kernel,
        clock,
        dan,
        alias="dupe",
        checkout=trusted_tmp / "dupe",
        remote="https://h.example/o/de.git",
        egress=True,
    )
    src_allow = _artifact(repo, "art-allow")
    restrictions = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": src_allow.__eq__})
    path = ("unproven_dup",)
    target_digest = field_path_digest(path)
    empty_item = DeliveryItem(path, frozenset(), unknown_source=False)
    known_item = DeliveryItem(path, frozenset({src_allow}), unknown_source=False)

    init_ek, view_ek = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupe", "dup-emp-ek", items=(empty_item, known_item), restrictions=restrictions
    )
    init_ke, view_ke = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupe", "dup-emp-ke", items=(known_item, empty_item), restrictions=restrictions
    )
    assert len(init_ek.items) == 1 and len(init_ke.items) == 1
    assert view_ek == view_ke
    (field,) = view_ek.items
    assert field.field_path_digest == target_digest
    assert {binding_lineage_ref(repo), src_allow} <= field.sources
    assert field.unknown_source is True
    assert view_ek.task_unknown is True
    assert view_ek.field_eligibility == ((target_digest, False),)
    assert view_ek.task_eligible is False


def test_duplicate_field_path_merges_multi_repo_provenance_and_denies_disabled_egress(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    repo_task = _register(
        kernel,
        clock,
        dan,
        alias="dupt",
        checkout=trusted_tmp / "dupt",
        remote="https://h.example/o/dt.git",
        egress=True,
    )
    repo_allow = _register(
        kernel,
        clock,
        dan,
        alias="dupa",
        checkout=trusted_tmp / "dupa",
        remote="https://h.example/o/da.git",
        egress=True,
    )
    repo_deny = _register(
        kernel,
        clock,
        dan,
        alias="dupd",
        checkout=trusted_tmp / "dupd",
        remote="https://h.example/o/dd.git",
        egress=False,
    )
    src_allow = _artifact(repo_allow, "art-allow")
    src_deny = _artifact(repo_deny, "art-deny")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_allow, src_deny}.__contains__}
    )
    assert restrictions.is_restricted(src_allow) is False
    assert restrictions.is_restricted(src_deny) is False

    _ctrl_init, ctrl_view = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "dupt",
        "dup-repo-ctrl",
        items=(DeliveryItem(("control_ok",), frozenset({src_allow}), unknown_source=False),),
        restrictions=restrictions,
    )
    assert ctrl_view.field_eligibility == ((field_path_digest(("control_ok",)), True),)
    assert ctrl_view.task_eligible is True

    path = ("multi_repo",)
    target_digest = field_path_digest(path)
    allow_item = DeliveryItem(path, frozenset({src_allow}), unknown_source=False)
    deny_item = DeliveryItem(path, frozenset({src_deny}), unknown_source=False)

    init_ad, view_ad = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupt", "dup-repo-ad", items=(allow_item, deny_item), restrictions=restrictions
    )
    init_da, view_da = _prepare_and_check_boundaries(
        kernel, dan.principal, "dupt", "dup-repo-da", items=(deny_item, allow_item), restrictions=restrictions
    )
    assert len(init_ad.items) == 1 and len(init_da.items) == 1
    assert view_ad == view_da
    (field,) = view_ad.items
    expected_sources = frozenset({binding_lineage_ref(repo_task), src_allow, src_deny})
    assert field.sources == expected_sources
    assert view_ad.task_lineage == expected_sources
    assert field.unknown_source is False
    assert view_ad.task_unknown is False
    assert view_ad.field_eligibility == ((target_digest, False),)
    assert view_ad.task_eligible is False


def test_duplicate_snapshot_dependent_path_omits_once_and_preserves_s1a_sibling(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path
) -> None:
    repo = _register(
        kernel,
        clock,
        dan,
        alias="snapa",
        checkout=trusted_tmp / "snapa",
        remote="https://h.example/o/sa.git",
        egress=True,
    )
    src_1 = _artifact(repo, "art-s1")
    src_2 = _artifact(repo, "art-s2")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_1, src_2}.__contains__}
    )
    snap_digest = field_path_digest(("snap_only",))
    kept_digest = field_path_digest(("kept_known",))
    items = (
        DeliveryItem(("snap_only",), frozenset({src_1}), unknown_source=False, snapshot_dependent=True),
        DeliveryItem(("kept_known",), frozenset({src_1}), unknown_source=False, snapshot_dependent=False),
        DeliveryItem(("snap_only",), frozenset({src_2}), unknown_source=False, snapshot_dependent=True),
    )

    initial, view = _prepare_and_check_boundaries(
        kernel, dan.principal, "snapa", "dup-snap-only", items=items, restrictions=restrictions, observer=None
    )
    assert initial.binding.snapshot_status is SnapshotStatus.UNAVAILABLE
    assert initial.omitted_items == (snap_digest,)
    assert [f.field_path_digest for f in view.items] == [kept_digest]
    (kept_field,) = view.items
    assert kept_field.unknown_source is False
    assert view.task_unknown is False
    assert view.field_eligibility == ((kept_digest, True),)
    assert view.task_eligible is True


@pytest.mark.parametrize("restriction_kind", ["unknown-source", "disabled-egress-repo"])
def test_mixed_snapshot_dependent_duplicate_path_omits_unit_when_unavailable_and_aggregates_when_available(
    kernel: Runtime,
    dan: SeededCredential,
    clock: FakeClock,
    trusted_tmp: Path,
    restriction_kind: str,
) -> None:
    repo_allow = _register(
        kernel,
        clock,
        dan,
        alias="snapm",
        checkout=trusted_tmp / "snapm",
        remote="https://h.example/o/sm.git",
        egress=True,
    )
    repo_deny = _register(
        kernel,
        clock,
        dan,
        alias="snapd",
        checkout=trusted_tmp / "snapd",
        remote="https://h.example/o/sd.git",
        egress=False,
    )
    src_allow = _artifact(repo_allow, "art-allow")
    src_deny = _artifact(repo_deny, "art-deny")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_allow, src_deny}.__contains__}
    )
    mixed_digest = field_path_digest(("mixed_snap",))
    base_item = DeliveryItem(("mixed_snap",), frozenset({src_allow}), unknown_source=False, snapshot_dependent=False)
    if restriction_kind == "unknown-source":
        snap_item = DeliveryItem(("mixed_snap",), frozenset({src_allow}), unknown_source=True, snapshot_dependent=True)
    else:
        snap_item = DeliveryItem(("mixed_snap",), frozenset({src_deny}), unknown_source=False, snapshot_dependent=True)

    unavail_1, uview_1 = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "snapm",
        f"mixed-unavail-1-{restriction_kind}",
        items=(base_item, snap_item),
        restrictions=restrictions,
        observer=None,
    )
    unavail_2, uview_2 = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "snapm",
        f"mixed-unavail-2-{restriction_kind}",
        items=(snap_item, base_item),
        restrictions=restrictions,
        observer=None,
    )
    assert unavail_1.omitted_items == (mixed_digest,)
    assert unavail_2.omitted_items == (mixed_digest,)
    assert uview_1.items == () and uview_2.items == ()
    assert uview_1 == uview_2

    obs = _Observer(_desc(TREE_1))
    avail_1, aview_1 = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "snapm",
        f"mixed-avail-1-{restriction_kind}",
        items=(base_item, snap_item),
        restrictions=restrictions,
        observer=obs,
    )
    avail_2, aview_2 = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "snapm",
        f"mixed-avail-2-{restriction_kind}",
        items=(snap_item, base_item),
        restrictions=restrictions,
        observer=obs,
    )
    assert avail_1.omitted_items == () and avail_2.omitted_items == ()
    assert len(avail_1.items) == 1 and len(avail_2.items) == 1
    assert aview_1 == aview_2
    (field,) = aview_1.items
    assert field.field_path_digest == mixed_digest
    assert src_allow in field.sources
    if restriction_kind == "unknown-source":
        assert field.unknown_source is True
        assert aview_1.task_unknown is True
    else:
        assert src_deny in field.sources
        assert field.unknown_source is False
        assert aview_1.task_unknown is False
    assert aview_1.field_eligibility == ((mixed_digest, False),)
    assert aview_1.task_eligible is False


@pytest.mark.parametrize("pre_state", ["pre-task-deny-source", "pre-task-unknown", "pre-field-lineage"])
def test_preexisting_task_or_field_lineage_is_reflected_in_initial_labeled_delivery(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, pre_state: str
) -> None:
    repo_allow = _register(
        kernel,
        clock,
        dan,
        alias="prea",
        checkout=trusted_tmp / "prea",
        remote="https://h.example/o/pa.git",
        egress=True,
    )
    repo_deny = _register(
        kernel,
        clock,
        dan,
        alias="pred",
        checkout=trusted_tmp / "pred",
        remote="https://h.example/o/pd.git",
        egress=False,
    )
    src_allow = _artifact(repo_allow, "art-pre-allow")
    src_deny = _artifact(repo_deny, "art-pre-deny")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_allow, src_deny}.__contains__}
    )
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    task_id = f"pre-task-{pre_state}"
    derived_digest = field_path_digest(("derived",))
    prior_digest = field_path_digest(("prior",))

    if pre_state == "pre-task-deny-source":
        kstore.transact(lambda tx: record_task_lineage(tx, task_id, frozenset({src_deny}), unknown=False))
    elif pre_state == "pre-task-unknown":
        kstore.transact(lambda tx: record_task_lineage(tx, task_id, frozenset({src_allow}), unknown=True))
    else:
        assert pre_state == "pre-field-lineage"

        def _seed_fields(tx: KernelTx) -> None:
            record_field_lineage(tx, task_id, ("prior",), frozenset({src_deny}), unknown=False)
            record_field_lineage(tx, task_id, ("derived",), frozenset({src_deny}), unknown=True)

        kstore.transact(_seed_fields)

    initial, view = _prepare_and_check_boundaries(
        kernel,
        dan.principal,
        "prea",
        task_id,
        items=(DeliveryItem(("derived",), frozenset({src_allow}), unknown_source=False),),
        restrictions=restrictions,
    )
    by_digest = {f.field_path_digest: f for f in initial.items}
    assert derived_digest in by_digest
    if pre_state == "pre-task-deny-source":
        assert src_deny in view.task_lineage
        assert src_deny in by_digest[derived_digest].sources
        assert view.field_eligibility == ((derived_digest, False),)
        assert view.task_eligible is False
    elif pre_state == "pre-task-unknown":
        assert view.task_unknown is True
        assert view.task_eligible is False
    else:
        assert set(by_digest) == {prior_digest, derived_digest}
        assert src_deny in by_digest[prior_digest].sources
        assert {binding_lineage_ref(repo_allow), src_allow, src_deny} <= by_digest[derived_digest].sources
        assert by_digest[derived_digest].unknown_source is True
        assert dict(view.field_eligibility) == {prior_digest: False, derived_digest: False}
        assert src_deny in view.task_lineage
        assert view.task_unknown is True
        assert view.task_eligible is False


# --- I2-T3-R02 reopened round 2 (8277603): pre-existing field lineage constraints ----------------------------------


def _seed_prior_field(
    task_id: str, path: tuple[str | int, ...], sources: LineageSet, unknown: bool, tx: KernelTx
) -> FieldLineage:
    return record_field_lineage(tx, task_id, path, sources, unknown=unknown)


@pytest.mark.parametrize(
    "case",
    [
        "prior-known-denied-distinct",
        "prior-known-denied-same",
        "prior-unknown-distinct-preserves-s1a-sibling",
        "prior-unknown-same",
        "codex-root-repro-denied-and-unknown-distinct",
        "prior-empty-items",
    ],
)
def test_preexisting_field_constraints_flow_to_task_and_distinct_or_same_path_fields(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, case: str
) -> None:
    repo_allow = _register(
        kernel,
        clock,
        dan,
        alias="r5a",
        checkout=trusted_tmp / "r5a",
        remote="https://h.example/o/r5a.git",
        egress=True,
    )
    src_allow = _artifact(repo_allow, "art-r5-allow")
    repo_deny: WorkspaceBinding | None = None
    src_deny: LineageRef | None = None
    if case not in ("prior-unknown-distinct-preserves-s1a-sibling", "prior-unknown-same"):
        repo_deny = _register(
            kernel,
            clock,
            dan,
            alias="r5d",
            checkout=trusted_tmp / "r5d",
            remote="https://h.example/o/r5d.git",
            egress=False,
        )
        src_deny = _artifact(repo_deny, "art-r5-deny")

    if case == "codex-root-repro-denied-and-unknown-distinct":
        assert repo_deny is not None
        _prepare(kernel, dan.principal, "r5d", "r5-seed-deny-binding")
        _prepare(kernel, dan.principal, "r5a", "r5-seed-allow-binding")
        restrictions = StoreSourceRestrictions(kernel.store, kernel.policy)
        assert restrictions.is_restricted(binding_lineage_ref(repo_deny)) is False
        assert restrictions.is_restricted(binding_lineage_ref(repo_allow)) is False
    elif src_deny is not None:
        restrictions = StoreSourceRestrictions(
            kernel.store, kernel.policy, resolvers={"artifact": {src_allow, src_deny}.__contains__}
        )
        assert restrictions.is_restricted(src_allow) is False
        assert restrictions.is_restricted(src_deny) is False
    else:
        restrictions = StoreSourceRestrictions(kernel.store, kernel.policy, resolvers={"artifact": src_allow.__eq__})
        assert restrictions.is_restricted(src_allow) is False

    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    prior_digest = field_path_digest(("prior",))
    new_digest = field_path_digest(("new",))
    same_digest = field_path_digest(("same",))
    allow_binding_ref = binding_lineage_ref(repo_allow)

    for obs_label, observer in (("unavailable", None), ("available", _Observer(_desc(TREE_1)))):
        task_id = f"r5-{case}-{obs_label}"
        if case == "prior-known-denied-distinct":
            assert src_deny is not None
            kstore.transact(partial(_seed_prior_field, task_id, ("prior",), frozenset({src_deny}), False))
            items: tuple[DeliveryItem, ...] = (DeliveryItem(("new",), frozenset({src_allow}), unknown_source=False),)
        elif case == "prior-known-denied-same":
            assert src_deny is not None
            kstore.transact(partial(_seed_prior_field, task_id, ("same",), frozenset({src_deny}), False))
            items = (DeliveryItem(("same",), frozenset({src_allow}), unknown_source=False),)
        elif case == "prior-unknown-distinct-preserves-s1a-sibling":
            kstore.transact(partial(_seed_prior_field, task_id, ("prior",), frozenset({src_allow}), True))
            items = (DeliveryItem(("new",), frozenset({src_allow}), unknown_source=False),)
        elif case == "prior-unknown-same":
            kstore.transact(partial(_seed_prior_field, task_id, ("same",), frozenset({src_allow}), True))
            items = (DeliveryItem(("same",), frozenset({src_allow}), unknown_source=False),)
        elif case == "codex-root-repro-denied-and-unknown-distinct":
            assert repo_deny is not None
            deny_binding_ref = binding_lineage_ref(repo_deny)
            kstore.transact(partial(_seed_prior_field, task_id, ("prior",), frozenset({deny_binding_ref}), True))
            items = (DeliveryItem(("new",), frozenset({allow_binding_ref}), unknown_source=False),)
        else:
            assert case == "prior-empty-items"
            assert src_deny is not None
            kstore.transact(partial(_seed_prior_field, task_id, ("prior",), frozenset({src_deny}), True))
            items = ()

        initial, view = _prepare_and_check_boundaries(
            kernel,
            dan.principal,
            "r5a",
            task_id,
            items=items,
            restrictions=restrictions,
            observer=observer,
        )
        if observer is None:
            assert initial.binding.snapshot_status is SnapshotStatus.UNAVAILABLE
            assert initial.binding.source_snapshot_id is None
        else:
            assert initial.binding.snapshot_status is SnapshotStatus.AVAILABLE
            assert initial.binding.source_snapshot_id is not None
        assert initial.omitted_items == ()
        by_digest = {f.field_path_digest: f for f in view.items}

        if case == "prior-known-denied-distinct":
            assert src_deny is not None
            assert len(view.items) == 2
            assert set(by_digest) == {prior_digest, new_digest}
            assert {allow_binding_ref, src_allow, src_deny} <= view.task_lineage
            assert view.task_unknown is False
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[prior_digest].sources
            assert by_digest[prior_digest].unknown_source is False
            assert src_deny in by_digest[new_digest].sources
            assert view.task_lineage <= by_digest[new_digest].sources
            assert by_digest[new_digest].unknown_source is False
            assert dict(view.field_eligibility) == {prior_digest: False, new_digest: False}
        elif case == "prior-known-denied-same":
            assert src_deny is not None
            assert len(view.items) == 1
            assert set(by_digest) == {same_digest}
            assert {allow_binding_ref, src_allow, src_deny} <= view.task_lineage
            assert view.task_unknown is False
            assert view.task_eligible is False
            assert src_deny in by_digest[same_digest].sources
            assert view.task_lineage <= by_digest[same_digest].sources
            assert by_digest[same_digest].unknown_source is False
            assert view.field_eligibility == ((same_digest, False),)
        elif case == "prior-unknown-distinct-preserves-s1a-sibling":
            assert len(view.items) == 2
            assert set(by_digest) == {prior_digest, new_digest}
            assert {allow_binding_ref, src_allow} <= view.task_lineage
            assert view.task_unknown is True
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[prior_digest].sources
            assert by_digest[prior_digest].unknown_source is True
            assert view.task_lineage <= by_digest[new_digest].sources
            assert by_digest[new_digest].unknown_source is False
            assert dict(view.field_eligibility) == {prior_digest: False, new_digest: True}
        elif case == "prior-unknown-same":
            assert len(view.items) == 1
            assert set(by_digest) == {same_digest}
            assert {allow_binding_ref, src_allow} <= view.task_lineage
            assert view.task_unknown is True
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[same_digest].sources
            assert by_digest[same_digest].unknown_source is True
            assert view.field_eligibility == ((same_digest, False),)
        elif case == "codex-root-repro-denied-and-unknown-distinct":
            assert repo_deny is not None
            deny_binding_ref = binding_lineage_ref(repo_deny)
            assert len(view.items) == 2
            assert set(by_digest) == {prior_digest, new_digest}
            assert deny_binding_ref in view.task_lineage
            assert allow_binding_ref in view.task_lineage
            assert view.task_unknown is True
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[prior_digest].sources
            assert by_digest[prior_digest].unknown_source is True
            assert deny_binding_ref in by_digest[new_digest].sources
            assert view.task_lineage <= by_digest[new_digest].sources
            assert by_digest[new_digest].unknown_source is False
            assert dict(view.field_eligibility) == {prior_digest: False, new_digest: False}
        else:
            assert case == "prior-empty-items"
            assert src_deny is not None
            assert len(view.items) == 1
            assert set(by_digest) == {prior_digest}
            assert {allow_binding_ref, src_deny} <= view.task_lineage
            assert view.task_unknown is True
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[prior_digest].sources
            assert by_digest[prior_digest].unknown_source is True
            assert view.field_eligibility == ((prior_digest, False),)


@pytest.mark.parametrize(
    "case",
    [
        "prior-clean-in-disabled-workspace",
        "prior-clean-with-denied-served-source",
        "prior-field-with-snapshot-dependent-restriction-on-same-path",
    ],
)
def test_preexisting_clean_field_inherits_disabled_workspace_or_served_lineage_and_same_path_snapshot_restriction(
    kernel: Runtime, dan: SeededCredential, clock: FakeClock, trusted_tmp: Path, case: str
) -> None:
    repo_allow = _register(
        kernel,
        clock,
        dan,
        alias="r5ba",
        checkout=trusted_tmp / "r5ba",
        remote="https://h.example/o/r5ba.git",
        egress=True,
    )
    repo_deny = _register(
        kernel,
        clock,
        dan,
        alias="r5bd",
        checkout=trusted_tmp / "r5bd",
        remote="https://h.example/o/r5bd.git",
        egress=False,
    )
    src_allow = _artifact(repo_allow, "art-r5b-allow")
    src_deny = _artifact(repo_deny, "art-r5b-deny")
    restrictions = StoreSourceRestrictions(
        kernel.store, kernel.policy, resolvers={"artifact": {src_allow, src_deny}.__contains__}
    )
    assert restrictions.is_restricted(src_allow) is False
    assert restrictions.is_restricted(src_deny) is False
    kstore = KernelWorkspaceStore(kernel.store, kernel.policy)
    prior_digest = field_path_digest(("prior",))
    snap_digest = field_path_digest(("snap_same",))
    snap_new_digest = field_path_digest(("snap_new",))

    if case in ("prior-clean-in-disabled-workspace", "prior-clean-with-denied-served-source"):
        for obs_label, observer in (("unavailable", None), ("available", _Observer(_desc(TREE_1)))):
            task_id = f"r5b-{case}-{obs_label}"
            kstore.transact(partial(_seed_prior_field, task_id, ("prior",), frozenset({src_allow}), False))
            alias = "r5bd" if case == "prior-clean-in-disabled-workspace" else "r5ba"
            served = () if case == "prior-clean-in-disabled-workspace" else (src_deny,)
            initial, view = _prepare_and_check_boundaries(
                kernel,
                dan.principal,
                alias,
                task_id,
                items=(),
                served=served,
                restrictions=restrictions,
                observer=observer,
            )
            assert initial.omitted_items == ()
            assert len(view.items) == 1
            by_digest = {f.field_path_digest: f for f in view.items}
            assert set(by_digest) == {prior_digest}
            if case == "prior-clean-in-disabled-workspace":
                assert binding_lineage_ref(repo_deny) in by_digest[prior_digest].sources
                assert {binding_lineage_ref(repo_deny), src_allow} <= view.task_lineage
            else:
                assert src_deny in by_digest[prior_digest].sources
                assert binding_lineage_ref(repo_allow) in by_digest[prior_digest].sources
                assert {binding_lineage_ref(repo_allow), src_allow, src_deny} <= view.task_lineage
            assert src_allow in by_digest[prior_digest].sources
            assert view.task_lineage <= by_digest[prior_digest].sources
            assert by_digest[prior_digest].unknown_source is False
            assert view.task_unknown is False
            assert view.field_eligibility == ((prior_digest, False),)
            assert view.task_eligible is False
    else:
        assert case == "prior-field-with-snapshot-dependent-restriction-on-same-path"
        for unk_label, item_unknown in (("denied-and-unknown", True), ("denied-known-only", False)):
            task_id = f"r5b-snap-same-{unk_label}"
            kstore.transact(partial(_seed_prior_field, task_id, ("snap_same",), frozenset({src_allow}), False))
            initial, view = _prepare_and_check_boundaries(
                kernel,
                dan.principal,
                "r5ba",
                task_id,
                items=(
                    DeliveryItem(
                        ("snap_same",),
                        frozenset({src_deny}),
                        unknown_source=item_unknown,
                        snapshot_dependent=True,
                    ),
                ),
                restrictions=restrictions,
                observer=None,
            )
            assert initial.binding.snapshot_status is SnapshotStatus.UNAVAILABLE
            assert initial.omitted_items == ()
            assert len(view.items) == 1
            by_digest = {f.field_path_digest: f for f in view.items}
            assert set(by_digest) == {snap_digest}
            assert src_deny in by_digest[snap_digest].sources
            assert src_deny in view.task_lineage
            assert {binding_lineage_ref(repo_allow), src_allow, src_deny} <= view.task_lineage
            assert view.task_unknown is item_unknown
            assert view.task_eligible is False
            assert view.task_lineage <= by_digest[snap_digest].sources
            assert by_digest[snap_digest].unknown_source is item_unknown
            assert view.field_eligibility == ((snap_digest, False),)

        # A distinct new snapshot_dependent path is still omitted while the already-persisted path stays in items.
        sibling_task = "r5b-snap-same-plus-omitted-new"
        kstore.transact(partial(_seed_prior_field, sibling_task, ("snap_same",), frozenset({src_allow}), False))
        sib_init, sib_view = _prepare_and_check_boundaries(
            kernel,
            dan.principal,
            "r5ba",
            sibling_task,
            items=(
                DeliveryItem(
                    ("snap_same",),
                    frozenset({src_deny}),
                    unknown_source=True,
                    snapshot_dependent=True,
                ),
                DeliveryItem(
                    ("snap_new",),
                    frozenset({src_allow}),
                    unknown_source=False,
                    snapshot_dependent=True,
                ),
            ),
            restrictions=restrictions,
            observer=None,
        )
        assert sib_init.omitted_items == (snap_new_digest,)
        sib_by_digest = {f.field_path_digest: f for f in sib_view.items}
        assert set(sib_by_digest) == {snap_digest}
        assert src_deny in sib_view.task_lineage
        assert sib_view.task_unknown is True
        assert sib_view.task_eligible is False
        assert src_deny in sib_by_digest[snap_digest].sources
        assert sib_by_digest[snap_digest].unknown_source is True
        assert sib_view.field_eligibility == ((snap_digest, False),)
