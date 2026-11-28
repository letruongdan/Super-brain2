"""Work delivery records, L0 rendering and delivery/episode outcomes for ``handoffs.HandoffStore``."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import datetime

from superbrain.core._kernel_base import (
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffAgentState,
)
from superbrain.ports.continuity import SessionState, decide_session_liveness
from superbrain.ports.handoff import (
    CreateWorkTaskResult,
    DeliveryOutcomeRecord,
    DiscoverEntry,
    EpisodeOutcomeRecord,
    ResumeRefSpec,
    SeenHandoffSpec,
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
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.sessions import SessionStore


def tx_record_work_delivery(
    self: _m.HandoffStore,
    tx: KernelTx,
    *,
    delivery_id: str,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    session_ref: str | None,
    description_bytes: bytes | None,
    create_task: bool,
    source_snapshot_id: str | None,
    snapshot_status: str,
    assignment_id: str | None,
    resume_ref: ResumeRefSpec | None,
    seen_handoff_refs: Sequence[SeenHandoffSpec],
    exposure_evidence: str,
    degraded_codes: Sequence[str],
    now: datetime,
    task_id_provided: bool | None = None,
) -> CreateWorkTaskResult:
    live_epoch = _require_v8_ready(self._store, self._policy)
    require_opaque_id(delivery_id, label="delivery_id")
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    require_opaque_id(principal_id, label="principal_id")
    if session_ref is not None:
        require_sha256_digest(session_ref)
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)
    cutoff = utc_timestamp(now_utc - _m._DISCOVER_WINDOW)
    txn = _txn_of(tx)
    db = txn.db

    self._validate_seen_refs_in_tx(
        db, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id, seen_refs=seen_handoff_refs
    )
    has_open_other = _has_open_handoffs_in_db(
        db,
        owner_id=owner_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        cutoff=cutoff,
        exclude_task_id=task_id,
    )

    res_art_id: str | None = None
    res_epoch: int | None = None
    res_rev: int | None = None
    res_receipt_id: str | None = None
    resume_exposure: str | None = None
    observed_newer = False

    if create_task:
        if resume_ref is not None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        work_res = self.tx_create_work_task(
            tx,
            task_id=task_id,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            principal_id=principal_id,
            session_ref=session_ref,
            goal_bytes=description_bytes,
            delivery_id=delivery_id,
            now=now_utc,
        )
        eff_live = work_res.handoff_live
        goal_digest = work_res.goal_digest
        artifact_id = work_res.artifact_id
    else:
        row = db.execute(_m._HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        cur = _row_to_header(row, live_restore_epoch=live_epoch)
        if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        towner_row = db.execute("SELECT owner_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if towner_row is None or str(towner_row[0]) != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if resume_ref is not None:
            res_art_id, res_epoch, res_rev, res_receipt_id, resume_exposure, observed_newer = (
                self._validate_resume_in_tx(
                    db,
                    task_id=task_id,
                    owner_id=owner_id,
                    repo_id=repo_id,
                    checkout_id=checkout_id,
                    principal_id=principal_id,
                    cur=cur,
                    resume_ref=resume_ref,
                )
            )
        eff_live = cur.handoff_live
        goal_digest = cur.goal_ref or digest_bytes(b"")
        artifact_id = cur.artifact_id
        work_res = CreateWorkTaskResult(
            task_id=task_id,
            artifact_id=artifact_id,
            delivery_id=delivery_id,
            goal_digest=goal_digest,
            handoff_live=eff_live,
        )

    if resume_exposure is not None:
        eff_exposure = resume_exposure
    elif seen_handoff_refs:
        eff_exposure = "seen_l0"
    elif has_open_other:
        eff_exposure = "unreviewed_open_handoffs"
    else:
        eff_exposure = exposure_evidence or "none"

    explicit_task_id = (not create_task) if task_id_provided is None else task_id_provided
    eff_degraded_codes = _unique_codes(degraded_codes)
    if not explicit_task_id and has_open_other and _m._OPEN_HANDOFFS_PRESENT_CODE not in eff_degraded_codes:
        eff_degraded_codes.append(_m._OPEN_HANDOFFS_PRESENT_CODE)
    if observed_newer and _m._OBSERVED_NEWER_CODE not in eff_degraded_codes:
        eff_degraded_codes.append(_m._OBSERVED_NEWER_CODE)

    served_ep = eff_live.revision_epoch
    served_rev = eff_live.revision
    served_dig: str | None = None
    if served_rev is not None and served_ep is not None and not create_task:
        hrow_dig = db.execute(
            "SELECT COALESCE(r.agent_ref, t.goal_ref) "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.task_id = ? AND r.revision_epoch = ? AND r.revision = ?",
            (task_id, served_ep, served_rev),
        ).fetchone()
        if hrow_dig is not None and hrow_dig[0] is not None:
            served_dig = str(hrow_dig[0])

    db.execute(
        "INSERT INTO deliveries ("
        "delivery_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
        "mode, source_snapshot_id, snapshot_status, assignment_id, "
        "resume_artifact_id, resume_revision_epoch, resume_revision, resume_receipt_id, "
        "exposure_evidence, degraded_codes_json, handoff_served_epoch, handoff_served_rev, "
        "handoff_served_digest, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 'work', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            delivery_id,
            task_id,
            owner_id,
            repo_id,
            checkout_id,
            principal_id,
            session_ref,
            source_snapshot_id,
            snapshot_status,
            assignment_id,
            res_art_id,
            res_epoch,
            res_rev,
            res_receipt_id,
            eff_exposure,
            canonical_json(eff_degraded_codes).decode("utf-8"),
            served_ep,
            served_rev,
            served_dig,
            stamp,
        ),
    )
    for idx, ref in enumerate(seen_handoff_refs):
        db.execute(
            "INSERT INTO delivery_seen_handoffs "
            "(delivery_id, idx, artifact_id, revision_epoch, revision, digest) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (delivery_id, idx, ref.artifact_id, ref.revision_epoch, ref.revision, ref.digest),
        )
    return work_res


def render_delivery_handoff_l0(
    self: _m.HandoffStore,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    revision_epoch: int,
    revision: int,
    served_digest: str | None,
    now: datetime,
    render_l0: Callable[..., str] | None = None,
) -> DiscoverEntry:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    require_non_negative_int(revision_epoch)
    require_positive_int(revision)
    now_utc, _ = require_aware_utc(now)

    row = self._store._db.execute(
        "SELECT r.task_id, r.artifact_id, r.revision_epoch, r.revision, r.handoff_revision, "
        "t.goal_ref, t.goal_holder_id, r.agent_ref, r.agent_holder_id, "
        "r.holder_session_ref, r.agent_updated_at, r.observed_through "
        "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
        "WHERE r.task_id = ? AND r.revision_epoch = ? AND r.revision = ? "
        "AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ?",
        (task_id, revision_epoch, revision, owner_id, repo_id, checkout_id),
    ).fetchone()
    if row is None:
        return DiscoverEntry(
            task_id=task_id,
            artifact_id=task_id,
            revision_epoch=revision_epoch,
            revision=revision,
            digest=served_digest or "",
            summary="",
            status="redacted",
            reason="not_found",
        )
    return self._render_l0_row(
        tid=str(row[0]),
        art_id=str(row[1]),
        rev_epoch=int(row[2]),
        rev=int(row[3]),
        hrev=int(row[4]),
        goal_ref=None if row[5] is None else str(row[5]),
        goal_hid=None if row[6] is None else str(row[6]),
        agent_ref=None if row[7] is None else str(row[7]),
        agent_hid=None if row[8] is None else str(row[8]),
        holder_sref=None if row[9] is None else str(row[9]),
        agent_at=None if row[10] is None else str(row[10]),
        obs_through=None if row[11] is None else str(row[11]),
        repo_id=repo_id,
        checkout_id=checkout_id,
        now_utc=now_utc,
        render_l0=render_l0,
    )


def read_delivery_outcome(
    self: _m.HandoffStore,
    delivery_id: str,
    *,
    owner_id: str,
    principal_id: str,
    selected_scope: Scope | None,
) -> DeliveryOutcomeRecord:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(delivery_id, label="delivery_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(principal_id, label="principal_id")
    row = self._store._db.execute(
        "SELECT delivery_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
        "source_snapshot_id, snapshot_status, assignment_id, exposure_evidence, degraded_codes_json, "
        "resume_artifact_id, resume_revision_epoch, resume_revision, resume_receipt_id, "
        "handoff_served_epoch, handoff_served_rev, handoff_served_digest "
        "FROM deliveries WHERE delivery_id = ?",
        (delivery_id,),
    ).fetchone()
    if row is None or str(row[2]) != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if selected_scope is not None:
        if str(row[3]) != selected_scope.repo_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope.checkout_id is not None and str(row[4]) != selected_scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    raw_codes = json.loads(str(row[11]))
    codes = tuple(str(c) for c in raw_codes) if isinstance(raw_codes, list) else ()
    seen_rows = self._store._db.execute(
        "SELECT artifact_id, revision_epoch, revision, digest "
        "FROM delivery_seen_handoffs WHERE delivery_id = ? ORDER BY idx ASC",
        (delivery_id,),
    ).fetchall()
    seen_refs = tuple((str(r[0]), int(r[1]), int(r[2]), str(r[3])) for r in seen_rows)
    return DeliveryOutcomeRecord(
        delivery_id=str(row[0]),
        task_id=str(row[1]),
        owner_id=str(row[2]),
        repo_id=str(row[3]),
        checkout_id=str(row[4]),
        principal_id=str(row[5]),
        session_ref=None if row[6] is None else str(row[6]),
        source_snapshot_id=None if row[7] is None else str(row[7]),
        snapshot_status=str(row[8]),
        assignment_id=None if row[9] is None else str(row[9]),
        exposure_evidence=str(row[10]),
        degraded_codes=codes,
        resume_artifact_id=None if row[12] is None else str(row[12]),
        resume_revision_epoch=None if row[13] is None else int(row[13]),
        resume_revision=None if row[14] is None else int(row[14]),
        resume_receipt_id=None if row[15] is None else str(row[15]),
        seen_refs=seen_refs,
        handoff_served_epoch=None if row[16] is None else int(row[16]),
        handoff_served_rev=None if row[17] is None else int(row[17]),
        handoff_served_digest=None if row[18] is None else str(row[18]),
    )


def _render_l0_row(
    self: _m.HandoffStore,
    *,
    tid: str,
    art_id: str,
    rev_epoch: int,
    rev: int,
    hrev: int,
    goal_ref: str | None,
    goal_hid: str | None,
    agent_ref: str | None,
    agent_hid: str | None,
    holder_sref: str | None,
    agent_at: str | None,
    obs_through: str | None,
    repo_id: str,
    checkout_id: str,
    now_utc: datetime,
    render_l0: Callable[..., str] | None,
) -> DiscoverEntry:
    task_goal = ""
    if goal_ref is not None:
        gbytes, gstatus = _check_blob_status(
            self._store._db,
            self._store,
            self._policy,
            goal_ref,
            holder_id=goal_hid,
            now=now_utc,
        )
        if gstatus != "ok" or gbytes is None:
            return DiscoverEntry(
                task_id=tid,
                artifact_id=art_id,
                revision_epoch=rev_epoch,
                revision=rev,
                digest=agent_ref or goal_ref,
                summary="",
                status="redacted",
                reason=gstatus,
            )
        task_goal = gbytes.decode("utf-8", errors="replace")

    agent_state: HandoffAgentState | None = None
    if agent_ref is not None:
        abytes, astatus = _check_blob_status(
            self._store._db,
            self._store,
            self._policy,
            agent_ref,
            holder_id=agent_hid,
            now=now_utc,
        )
        if astatus != "ok" or abytes is None:
            return DiscoverEntry(
                task_id=tid,
                artifact_id=art_id,
                revision_epoch=rev_epoch,
                revision=rev,
                digest=agent_ref,
                summary="",
                status="redacted",
                reason=astatus,
            )
        agent_state = HandoffAgentState.from_dict(json.loads(abytes.decode("utf-8")))

    sess_state: str | None = None
    other_active = False
    if holder_sref is not None:
        srow = self._store._db.execute(
            "SELECT state, last_event_at FROM sessions WHERE session_ref = ?",
            (holder_sref,),
        ).fetchone()
        if srow is not None:
            sess_state = decide_session_liveness(
                recorded_state=SessionState(str(srow[0])),
                last_event_at=parse_iso_utc(str(srow[1])),
                now=now_utc,
            ).state.value
        other_row = self._store._db.execute(
            "SELECT 1 FROM sessions WHERE repo_id = ? AND checkout_id = ? AND state = 'active' "
            "AND session_ref != ? LIMIT 1",
            (repo_id, checkout_id, holder_sref),
        ).fetchone()
        other_active = other_row is not None

    if render_l0 is not None:
        summary = render_l0(
            task_goal=task_goal,
            state=agent_state,
            handoff_revision=hrev,
            session_state=sess_state,
            agent_updated_at=agent_at,
            observed_through=obs_through,
            other_active_warning=other_active,
        )
    else:
        summary = (task_goal or "")[:200]
    return DiscoverEntry(
        task_id=tid,
        artifact_id=art_id,
        revision_epoch=rev_epoch,
        revision=rev,
        digest=agent_ref or goal_ref or digest_bytes(summary.encode("utf-8")),
        summary=summary,
        status="ok",
    )


def read_episode_outcome(
    self: _m.HandoffStore,
    episode_id: str,
    *,
    owner_id: str,
    principal_id: str,
    selected_scope: Scope | None,
) -> EpisodeOutcomeRecord:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(episode_id, label="episode_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(principal_id, label="principal_id")
    row = self._store._db.execute(
        "SELECT episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
        "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
        "committed_revision, committed_restore_epoch, committed_writer_generation, evidence_ids_json "
        "FROM episodes WHERE episode_id = ?",
        (episode_id,),
    ).fetchone()
    if row is None or str(row[2]) != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if selected_scope is not None:
        if str(row[3]) != selected_scope.repo_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope.checkout_id is not None and str(row[4]) != selected_scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    raw_ev = json.loads(str(row[14]))
    ev_ids = tuple(str(x) for x in raw_ev) if isinstance(raw_ev, list) else ()
    return EpisodeOutcomeRecord(
        episode_id=str(row[0]),
        task_id=str(row[1]),
        owner_id=str(row[2]),
        repo_id=str(row[3]),
        checkout_id=str(row[4]),
        principal_id=str(row[5]),
        session_ref=str(row[6]),
        has_handoff_op=bool(int(row[7])),
        handoff_status=None if row[8] is None else str(row[8]),
        handoff_artifact_id=None if row[9] is None else str(row[9]),
        committed_handoff_revision=None if row[10] is None else int(row[10]),
        committed_revision=None if row[11] is None else int(row[11]),
        committed_restore_epoch=None if row[12] is None else int(row[12]),
        committed_writer_generation=None if row[13] is None else int(row[13]),
        evidence_ids=ev_ids,
    )


def bind_session_for_episode(
    self: _m.HandoffStore,
    *,
    principal_id: str,
    repo_id: str,
    checkout_id: str,
    harness_id: str,
    raw_session_id: str,
    now: datetime,
) -> str:
    _require_v8_ready(self._store, self._policy)
    ss = SessionStore(self._store, self._policy)
    rec = ss.bind_session(
        principal_id=principal_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        harness_id=harness_id,
        raw_session_id=raw_session_id,
        now=now,
    )
    return rec.session_ref
