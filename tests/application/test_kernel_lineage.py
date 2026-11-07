"""Task 3 lineage model tests (D6, spec 9/14.2, owner ruling S1=A): monotonic, server-built, egress-checked."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping

import pytest

from superbrain.application.lineage import (
    admit_client_sources,
    evaluate_egress_eligibility,
    lineage_field,
    local_deadline_ns,
    redact_lineaged_field,
    union_lineage,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    COMMIT_RESERVE_NS,
    LOCAL_PHASE_BUDGET_NS,
    AuthSnapshot,
    BootstrapAuthorization,
    FieldLineage,
    LabeledDelivery,
    LineagedField,
    LineageRef,
    ObjectRef,
    Principal,
    RepoPolicy,
    Scope,
    SelectorPath,
    SelectorReason,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    TaskBinding,
    WorkspaceBinding,
    WorkspaceRegistration,
    field_path_digest,
)
from superbrain.ports.policy import Intent

MS = 1_000_000


def _ref(owner: str, repo: str, kind: str, ident: str, revision: int = 1) -> LineageRef:
    return LineageRef(
        owner_id=owner,
        repo_id=repo,
        source=ObjectRef(
            kind=kind, id=ident, revision=revision, digest=digest_bytes(f"{kind}:{ident}:{revision}".encode())
        ),
    )


A1 = _ref("dan", "repo-a", "artifact", "art-1")
A2 = _ref("dan", "repo-a", "lesson", "les-7", 3)
B1 = _ref("dan", "repo-b", "artifact", "art-9")
C1 = _ref("dan", "repo-c", "artifact", "art-3")


class _Policy:
    """``KernelPolicyPort`` double: only ``snapshot()`` is meaningful for eligibility."""

    def __init__(self, egress: Mapping[str, bool], owner: str = "dan") -> None:
        self.calls = 0
        self._snapshot = AuthSnapshot(
            store_id="store-1",
            trust_generation=1,
            repo_policies={
                repo: RepoPolicy(repo_id=repo, owner_id=owner, provider_egress_enabled=enabled)
                for repo, enabled in egress.items()
            },
        )

    def snapshot(self) -> AuthSnapshot:
        self.calls += 1
        return self._snapshot

    def resolve_credential(self, token: str) -> Principal:
        raise AssertionError("eligibility must not authenticate")

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        raise AssertionError("eligibility reads current repo policy only")

    def record_authorized_revocation(self, credential_id: str, authorization: BootstrapAuthorization) -> Intent:
        raise AssertionError("eligibility never writes policy")

    def register_authorized_workspace(
        self, registration: WorkspaceRegistration, authorization: BootstrapAuthorization
    ) -> WorkspaceBinding:
        raise AssertionError("eligibility never writes policy")

    def request_digest_key(self) -> tuple[str, bytes]:
        raise AssertionError("eligibility never reads request keys")


class _Restrictions:
    def __init__(self, restricted: set[LineageRef]) -> None:
        self.restricted = restricted

    def is_restricted(self, ref: LineageRef) -> bool:
        return ref in self.restricted


NONE_RESTRICTED = _Restrictions(set())


def test_union_lineage_is_monotonic_and_deduplicated() -> None:
    current = frozenset({A1})
    grown = union_lineage(current, [A2, A1, B1])
    assert grown == frozenset({A1, A2, B1})
    assert current <= grown
    assert union_lineage(grown, []) == grown
    with pytest.raises(BrainError) as exc:
        union_lineage(current, [object()])  # type: ignore[list-item]
    assert exc.value.code is ErrorCode.INVALID_INPUT


def test_client_removal_attempt_cannot_shrink_lineage() -> None:
    server_set = frozenset({A1, A2, B1})
    client_claims_subset = [A1]
    after = union_lineage(server_set, client_claims_subset)
    assert after == server_set
    merged, unknown = admit_client_sources(server_set, [], lambda ref: None)
    assert merged == server_set
    assert unknown is False


def test_client_claims_only_add_resolved_sources_else_mark_unknown() -> None:
    resolvable = {B1.source: B1}
    merged, unknown = admit_client_sources(frozenset({A1}), [B1.source, C1.source], resolvable.get)
    assert merged == frozenset({A1, B1})
    assert unknown is True


def test_handoff_t1_served_source_a_is_inherited_by_t2_field() -> None:
    # T1 runs in repo B and is served source A (from repo A); the client never mentions A.
    t1_binding = _ref("dan", "repo-b", "workspace_binding", "chk-b")
    t1_lineage = union_lineage(frozenset({t1_binding}), [A1])
    handoff = lineage_field({"handoff": "summary"}, t1_lineage)
    # T2 consumes T1's handoff ref; its field inherits A even though T2's own binding is repo C.
    t2_binding = _ref("dan", "repo-c", "workspace_binding", "chk-c")
    t2_lineage = union_lineage(frozenset({t2_binding}), handoff.sources)
    t2_field = lineage_field("derived from handoff", t2_lineage)
    assert A1 in t2_field.sources
    assert {ref.repo_id for ref in t2_field.sources} == {"repo-a", "repo-b", "repo-c"}
    assert t2_field.unknown_source is False


def test_explicit_unknown_source_is_preserved() -> None:
    field = lineage_field("value", frozenset({A1}), unknown_source=True)
    assert field.unknown_source is True
    widened = lineage_field(field.value, union_lineage(field.sources, [B1]), unknown_source=field.unknown_source)
    assert widened.unknown_source is True
    redacted = redact_lineaged_field(widened)
    assert redacted.unknown_source is True
    with pytest.raises(BrainError):
        LineagedField(value="x", sources=frozenset({"not-a-ref"}))  # type: ignore[arg-type]


def test_quarantined_content_redacts_value_but_keeps_lineage_restriction() -> None:
    field = lineage_field({"text": "served content"}, frozenset({A1, B1}))
    redacted = redact_lineaged_field(field)
    assert redacted.value == {"status": "redacted"}
    assert redacted.sources == field.sources
    policy = _Policy({"repo-a": True, "repo-b": True})
    assert evaluate_egress_eligibility(field, policy, restrictions=NONE_RESTRICTED) is True
    quarantined_a = _Restrictions({A1})
    assert evaluate_egress_eligibility(field, policy, restrictions=quarantined_a) is False
    assert evaluate_egress_eligibility(redacted, policy, restrictions=quarantined_a) is False


def test_restrictions_port_is_required_without_default() -> None:
    params = inspect.signature(evaluate_egress_eligibility).parameters
    assert params["restrictions"].default is inspect.Parameter.empty
    assert params["restrictions"].kind is inspect.Parameter.KEYWORD_ONLY
    with pytest.raises(TypeError):
        evaluate_egress_eligibility(lineage_field("x", frozenset({A1})), _Policy({"repo-a": True}))  # type: ignore[call-arg]
    with pytest.raises(BrainError):
        evaluate_egress_eligibility(
            lineage_field("x", frozenset({A1})),
            _Policy({"repo-a": True}),
            restrictions=None,  # type: ignore[arg-type]
        )


def test_s1a_snapshot_status_alone_does_not_block_egress() -> None:
    assert not any("snapshot" in name for name in inspect.signature(evaluate_egress_eligibility).parameters)
    binding_ref = _ref("dan", "repo-a", "workspace_binding", "chk-a")
    task_lineage = union_lineage(frozenset({binding_ref}), [A2])
    known_field = lineage_field("known item", task_lineage)
    policy = _Policy({"repo-a": True})
    assert evaluate_egress_eligibility(known_field, policy, restrictions=NONE_RESTRICTED) is True
    assert evaluate_egress_eligibility(task_lineage, policy, restrictions=NONE_RESTRICTED) is True
    # Only the genuinely unknown item is blocked, never the known ones beside it.
    unknown_item = lineage_field("unproven item", task_lineage, unknown_source=True)
    assert evaluate_egress_eligibility(unknown_item, policy, restrictions=NONE_RESTRICTED) is False
    assert evaluate_egress_eligibility(known_field, policy, restrictions=NONE_RESTRICTED) is True


def test_egress_denied_for_unknown_disabled_missing_or_foreign_sources() -> None:
    policy = _Policy({"repo-a": True, "repo-b": False})
    ok = NONE_RESTRICTED
    assert evaluate_egress_eligibility(lineage_field("x", frozenset({A1})), policy, restrictions=ok) is True
    assert evaluate_egress_eligibility(lineage_field("x", frozenset({A1, B1})), policy, restrictions=ok) is False
    assert evaluate_egress_eligibility(lineage_field("x", frozenset({A1, C1})), policy, restrictions=ok) is False
    assert evaluate_egress_eligibility(lineage_field("x", frozenset()), policy, restrictions=ok) is False
    foreign = _ref("eve", "repo-a", "artifact", "art-1")
    assert evaluate_egress_eligibility(lineage_field("x", frozenset({foreign})), policy, restrictions=ok) is False
    assert evaluate_egress_eligibility(frozenset({A1}), policy, restrictions=_Restrictions({A1})) is False


def test_local_deadline_uses_min_of_local_phase_and_commit_reserve() -> None:
    assert LOCAL_PHASE_BUDGET_NS == 100 * MS
    assert COMMIT_RESERVE_NS == 200 * MS
    start = 5_000 * MS
    assert local_deadline_ns(start, start + 1_500 * MS) == start + 100 * MS
    assert local_deadline_ns(start, start + 250 * MS) == start + 50 * MS
    assert local_deadline_ns(start, start + 150 * MS) == start - 50 * MS


def test_snapshot_descriptor_one_of_and_dirty_digest_changes_digest() -> None:
    tree = "sha256:" + "a" * 64
    clean = SnapshotDescriptor("git", tree, False, None, "2026-11-06T01:02:03.000000Z")
    dirty1 = SnapshotDescriptor("git", tree, True, "sha256:" + "b" * 64, "2026-11-06T01:02:03.000000Z")
    dirty2 = SnapshotDescriptor("git", tree, True, "sha256:" + "c" * 64, "2026-11-06T01:02:03.000000Z")
    later_clean = SnapshotDescriptor("git", tree, False, None, "2026-11-06T09:09:09.000000Z")
    assert len({clean.descriptor_digest, dirty1.descriptor_digest, dirty2.descriptor_digest}) == 3
    assert later_clean.descriptor_digest == clean.descriptor_digest
    bad_builders: tuple[Callable[[], object], ...] = (
        lambda: SnapshotDescriptor("git", tree, True, None, "2026-11-06T01:02:03.000000Z"),
        lambda: SnapshotDescriptor("git", tree, False, "sha256:" + "b" * 64, "2026-11-06T01:02:03.000000Z"),
        lambda: SnapshotDescriptor("svn", tree, False, None, "2026-11-06T01:02:03.000000Z"),  # type: ignore[arg-type]
        lambda: SnapshotDescriptor("git", "not-a-digest", False, None, "2026-11-06T01:02:03.000000Z"),
        lambda: SnapshotDescriptor("git", tree, 1, None, "2026-11-06T01:02:03.000000Z"),  # type: ignore[arg-type]
        lambda: SnapshotDescriptor("git", tree, False, None, "yesterday"),
    )
    for bad in bad_builders:
        with pytest.raises(BrainError) as exc:
            bad()
        assert exc.value.code is ErrorCode.INVALID_INPUT


def test_snapshot_observation_available_iff_descriptor() -> None:
    desc = SnapshotDescriptor("directory", "sha256:" + "d" * 64, False, None, "2026-11-06T01:02:03.000000Z")
    assert SnapshotObservation(SnapshotStatus.AVAILABLE, desc).descriptor == desc
    for status, descriptor in (
        (SnapshotStatus.AVAILABLE, None),
        (SnapshotStatus.UNAVAILABLE, desc),
        (SnapshotStatus.DEADLINE, desc),
        ("available", desc),
    ):
        with pytest.raises(BrainError):
            SnapshotObservation(status, descriptor)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "case",
    ["duplicate-items", "duplicate-omitted", "item-and-omitted-overlap"],
)
def test_labeled_delivery_requires_unique_and_disjoint_field_digests(case: str) -> None:
    binding = TaskBinding(
        task_id="task-ld-1",
        owner_id="dan",
        repo_id="repo-a",
        checkout_id="chk-a",
        delivery_id=new_id(),
        assignment_id=None,
        source_snapshot_id=None,
        snapshot_status=SnapshotStatus.UNAVAILABLE,
        selector_path=SelectorPath.RULES,
        selector_reason=SelectorReason.PROVIDER_UNAVAILABLE,
    )
    d_a = field_path_digest(("a",))
    d_b = field_path_digest(("b",))
    d_c = field_path_digest(("c",))
    d_d = field_path_digest(("d",))
    valid = LabeledDelivery(
        binding=binding,
        task_lineage=frozenset({A1}),
        task_unknown=False,
        items=(FieldLineage(d_a, frozenset({A1})), FieldLineage(d_b, frozenset({A1, A2}))),
        omitted_items=(d_c, d_d),
    )
    assert [f.field_path_digest for f in valid.items] == [d_a, d_b]
    assert valid.omitted_items == (d_c, d_d)

    if case == "duplicate-items":
        items: tuple[FieldLineage, ...] = (
            FieldLineage(d_a, frozenset({A1}), unknown_source=False),
            FieldLineage(d_a, frozenset({A1}), unknown_source=True),
        )
        omitted: tuple[str, ...] = (d_c,)
    elif case == "duplicate-omitted":
        items = (FieldLineage(d_a, frozenset({A1})),)
        omitted = (d_c, d_c)
    else:
        assert case == "item-and-omitted-overlap"
        items = (FieldLineage(d_a, frozenset({A1})),)
        omitted = (d_c, d_a)

    with pytest.raises(BrainError) as exc:
        LabeledDelivery(
            binding=binding,
            task_lineage=frozenset({A1}),
            task_unknown=True,
            items=items,
            omitted_items=omitted,
        )
    assert exc.value.code is ErrorCode.INVALID_INPUT
