"""Handoff mutation commits, work-task creation and artifact-get records for ``handoffs.HandoffStore``."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from superbrain.core._kernel_base import (
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffFence,
    HandoffPatch,
    HandoffRevisionHeader,
)
from superbrain.ports.handoff import (
    CreateWorkTaskResult,
    HandoffHeaderState,
    HandoffMutationOutcome,
)
from superbrain.ports.kernel import KernelTx
from superbrain.storage import handoffs as _m
from superbrain.storage._handoff_rows import _check_blob_status as _check_blob_status
from superbrain.storage._handoff_rows import _has_open_handoffs_in_db as _has_open_handoffs_in_db
from superbrain.storage._handoff_rows import _insert_episode_evidence as _insert_episode_evidence
from superbrain.storage._handoff_rows import _req_int as _req_int
from superbrain.storage._handoff_rows import _require_v8_ready as _require_v8_ready
from superbrain.storage._handoff_rows import _row_to_header as _row_to_header
from superbrain.storage._handoff_rows import _row_to_rev_header as _row_to_rev_header
from superbrain.storage._handoff_rows import _txn_of as _txn_of
from superbrain.storage._handoff_rows import _unique_codes as _unique_codes
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.ledger import utc_timestamp


def tx_commit_handoff_mutation(
    self: _m.HandoffStore,
    tx: KernelTx,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    harness_id: str,
    session_ref: str,
    episode_id: str,
    base_revision: int | None,
    expected_fence: HandoffFence | None,
    takeover: bool,
    takeover_acknowledge_active: bool,
    has_patch: bool,
    new_agent_bytes: bytes | None,
    next_task_state: str | None,
    evidence_items: Sequence[tuple[str, bytes]],
    manual_submission_enabled: bool,
    now: datetime,
) -> HandoffMutationOutcome:
    live_epoch = _require_v8_ready(self._store, self._policy)
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)
    txn = _txn_of(tx)
    db = txn.db

    row = db.execute(_m._HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
    if row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    cur = _row_to_header(row, live_restore_epoch=live_epoch)
    if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    ev_held: list[tuple[str, str, str]] = []
    for ev_id, ev_bytes in evidence_items:
        ev_hid = new_id()
        ev_dig = tx.hold_blob(ev_bytes, holder_id=ev_hid)
        ev_held.append((ev_id, ev_dig, ev_hid))

    if not has_patch and not takeover:
        ev_ids = tuple(e[0] for e in ev_held)
        db.execute(
            "INSERT INTO episodes ("
            "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
            "committed_revision, committed_restore_epoch, committed_writer_generation, "
            "evidence_ids_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)",
            (
                episode_id,
                task_id,
                owner_id,
                repo_id,
                checkout_id,
                principal_id,
                session_ref,
                canonical_json(list(ev_ids)).decode("utf-8"),
                stamp,
            ),
        )
        _insert_episode_evidence(
            db, episode_id=episode_id, task_id=task_id, evidence_held=ev_held, stamp=stamp
        )
        return HandoffMutationOutcome(
            episode_id=episode_id,
            evidence_ids=ev_ids,
            handoff_status="plain",
            handoff_revision=None,
            revision=None,
            revision_epoch=None,
            fence=cur.live_fence,
            holder_principal=cur.holder_principal,
            holder_session_ref=cur.holder_session_ref,
        )

    new_agent_ref: str | None = None
    new_agent_hid: str | None = None
    if manual_submission_enabled and has_patch:
        if new_agent_bytes is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "new_agent_bytes required for patch")
        new_agent_hid = new_id()
        new_agent_ref = tx.hold_blob(new_agent_bytes, holder_id=new_agent_hid)

    return self._apply_handoff_mutation_in_tx(
        db,
        live_epoch=live_epoch,
        task_id=task_id,
        owner_id=owner_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        principal_id=principal_id,
        harness_id=harness_id,
        session_ref=session_ref,
        episode_id=episode_id,
        base_revision=base_revision,
        expected_fence=expected_fence,
        takeover=takeover,
        takeover_acknowledge_active=takeover_acknowledge_active,
        has_patch=has_patch,
        new_agent_ref=new_agent_ref,
        new_agent_holder_id=new_agent_hid,
        next_task_state=next_task_state,
        evidence_held=ev_held,
        manual_submission_enabled=manual_submission_enabled,
        now=now_utc,
    )


def commit_handoff_mutation(
    self: _m.HandoffStore,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    harness_id: str,
    session_ref: str,
    episode_id: str,
    base_revision: int | None,
    expected_fence: HandoffFence | None,
    takeover: bool,
    takeover_acknowledge_active: bool,
    patch: HandoffPatch | None,
    raw_patch: JsonValue | None = None,
    evidence_digests: Sequence[tuple[str, bytes]],
    manual_submission_enabled: bool,
    now: datetime,
    apply_patch: Callable[[HandoffAgentState | None, HandoffPatch], HandoffAgentState] | None = None,
    validate_limits: (
        Callable[[HandoffAgentState | None, HandoffAgentState, Mapping[str, JsonValue]], None] | None
    ) = None,
) -> HandoffMutationOutcome:
    live_epoch = _require_v8_ready(self._store, self._policy)
    now_utc, _ = require_aware_utc(now)
    # Pre-compute agent_bytes outside tx when patching, then re-verify inside tx if concurrent check fails.
    staged_agent: tuple[bytes, str] | None = None
    if manual_submission_enabled and patch is not None:
        if apply_patch is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "apply_patch callback required for handoff patch")
        cur = self.read_header(task_id, principal_id=principal_id, scope=Scope(repo_id, checkout_id))
        if cur is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task not found")
        prev_state = self._load_agent_state_checked(cur, now=now_utc)
        next_state = apply_patch(prev_state, patch)
        if validate_limits is not None and isinstance(raw_patch, Mapping):
            validate_limits(prev_state, next_state, raw_patch)
        agent_bytes = canonical_json(next_state.to_dict())
        self._store.cas.put(agent_bytes)
        staged_agent = (agent_bytes, digest_bytes(agent_bytes))
    ev_tuples: list[tuple[str, str, bytes]] = []
    for ev_id, ev_bytes in evidence_digests:
        self._store.cas.put(ev_bytes)
        ev_tuples.append((ev_id, digest_bytes(ev_bytes), ev_bytes))
    with self._store.transaction() as txn:
        holder_id = new_id()
        if staged_agent is not None:
            txn.hold(staged_agent[1], "event", holder_id, RetentionClass.DURABLE, None)
        ev_held: list[tuple[str, str, str]] = []
        for ev_id, ev_dig, _ev_bytes in ev_tuples:
            ev_hid = new_id()
            txn.hold(ev_dig, "event", ev_hid, RetentionClass.DURABLE, None)
            ev_held.append((ev_id, ev_dig, ev_hid))
        return self._apply_handoff_mutation_in_tx(
            txn.db,
            live_epoch=live_epoch,
            task_id=task_id,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            principal_id=principal_id,
            harness_id=harness_id,
            session_ref=session_ref,
            episode_id=episode_id,
            base_revision=base_revision,
            expected_fence=expected_fence,
            takeover=takeover,
            takeover_acknowledge_active=takeover_acknowledge_active,
            has_patch=(patch is not None),
            new_agent_ref=None if staged_agent is None else staged_agent[1],
            new_agent_holder_id=None if staged_agent is None else holder_id,
            next_task_state=None if patch is None else next_state.task_state,
            evidence_held=ev_held,
            manual_submission_enabled=manual_submission_enabled,
            now=now_utc,
        )


def create_work_task(
    self: _m.HandoffStore,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    session_ref: str | None,
    description: str,
    delivery_id: str,
    now: datetime,
) -> CreateWorkTaskResult:
    live_epoch = _require_v8_ready(self._store, self._policy)
    goal_bytes = description.encode("utf-8")
    self._store.cas.put(goal_bytes)
    goal_holder_id = new_id()
    with self._store.transaction() as txn:
        goal_digest = digest_bytes(goal_bytes)
        txn.hold(goal_digest, "event", goal_holder_id, RetentionClass.DURABLE, None)
        return self._apply_create_work_task_in_tx(
            txn.db,
            live_epoch=live_epoch,
            task_id=task_id,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            principal_id=principal_id,
            session_ref=session_ref,
            goal_digest=goal_digest,
            goal_holder_id=goal_holder_id,
            delivery_id=delivery_id,
            now=now,
        )


def tx_create_work_task(
    self: _m.HandoffStore,
    tx: KernelTx,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    session_ref: str | None,
    goal_bytes: bytes | None,
    delivery_id: str,
    now: datetime,
) -> CreateWorkTaskResult:
    live_epoch = _require_v8_ready(self._store, self._policy)
    goal_holder_id: str | None = None
    goal_digest: str | None = None
    if goal_bytes is not None:
        goal_holder_id = new_id()
        goal_digest = tx.hold_blob(goal_bytes, holder_id=goal_holder_id)
    return self._apply_create_work_task_in_tx(
        _txn_of(tx).db,
        live_epoch=live_epoch,
        task_id=task_id,
        owner_id=owner_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        principal_id=principal_id,
        session_ref=session_ref,
        goal_digest=goal_digest,
        goal_holder_id=goal_holder_id,
        delivery_id=delivery_id,
        now=now,
    )


def tx_record_artifact_get(
    self: _m.HandoffStore,
    tx: KernelTx,
    *,
    result_id: str,
    task_id: str,
    artifact_id: str,
    revision_epoch: int,
    revision: int,
    level: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    now: datetime,
) -> None:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(result_id, label="result_id")
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(artifact_id, label="artifact_id")
    require_non_negative_int(revision_epoch)
    require_positive_int(revision)
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)
    db = _txn_of(tx).db
    row = db.execute(
        "SELECT r.task_id, t.owner_id, t.repo_id, t.checkout_id "
        "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
        "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
        (artifact_id, revision_epoch, revision),
    ).fetchone()
    if (
        row is None
        or str(row[0]) != task_id
        or str(row[1]) != owner_id
        or str(row[2]) != repo_id
        or str(row[3]) != checkout_id
    ):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    db.execute(
        "INSERT INTO artifact_get_results ("
        "result_id, task_id, artifact_id, revision_epoch, revision, level, "
        "owner_id, repo_id, checkout_id, principal_id, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            result_id,
            task_id,
            artifact_id,
            revision_epoch,
            revision,
            level,
            owner_id,
            repo_id,
            checkout_id,
            principal_id,
            stamp,
        ),
    )


def try_read_task_header_scoped(
    self: _m.HandoffStore,
    task_id: str,
    *,
    owner_id: str,
    selected_scope: Scope | None,
) -> HandoffHeaderState | None:
    live_epoch = _require_v8_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(owner_id, label="owner_id")
    row = self._store._db.execute(
        "SELECT h.task_id, h.artifact_id, h.repo_id, h.checkout_id, h.current_revision, "
        "h.current_revision_epoch, h.handoff_revision, h.writer_generation, h.holder_principal, "
        "h.holder_session_ref, h.holder_restore_epoch, h.task_state, h.task_state_source, "
        "COALESCE(h.goal_ref, t.goal_ref), h.agent_ref, h.observed_ref, h.l0_summary_ref, "
        "h.agent_updated_at, h.observed_through, t.owner_id "
        "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id WHERE h.task_id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        return None
    row_owner = str(row[19])
    hdr = _row_to_header(row[:19], live_restore_epoch=live_epoch)
    if row_owner != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if selected_scope is not None:
        if hdr.repo_id != selected_scope.repo_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope.checkout_id is not None and hdr.checkout_id != selected_scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return hdr


def read_revision_header(
    self: _m.HandoffStore,
    *,
    artifact_id: str,
    revision_epoch: int,
    revision: int,
    principal_id: str,
    scope: Scope,
) -> HandoffRevisionHeader | None:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(artifact_id, label="artifact_id")
    require_non_negative_int(revision_epoch)
    require_positive_int(revision)
    require_opaque_id(principal_id, label="principal_id")
    if scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    row = self._store._db.execute(
        _m._REV_HDR_SELECT + "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
        (artifact_id, revision_epoch, revision),
    ).fetchone()
    if row is None or str(row[17]) != scope.repo_id or str(row[18]) != scope.checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return _row_to_rev_header(row)


def read_header_by_artifact(
    self: _m.HandoffStore,
    artifact_id: str,
    *,
    task_id: str,
    scope: Scope,
) -> HandoffHeaderState:
    live_epoch = _require_v8_ready(self._store, self._policy)
    require_opaque_id(artifact_id, label="artifact_id")
    require_opaque_id(task_id, label="task_id")
    if scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    row = self._store._db.execute(
        _m._HEADER_SQL + "WHERE h.artifact_id = ? AND h.task_id = ?",
        (artifact_id, task_id),
    ).fetchone()
    if row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    hdr = _row_to_header(row, live_restore_epoch=live_epoch)
    if hdr.repo_id != scope.repo_id or hdr.checkout_id != scope.checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return hdr
