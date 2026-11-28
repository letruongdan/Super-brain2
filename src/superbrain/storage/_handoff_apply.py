"""Mutation application and resume/seen-ref validation inside a handoff transaction."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime

from superbrain.core._kernel_base import (
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import SendAttemptState, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffFence,
)
from superbrain.ports.handoff import (
    CreateWorkTaskResult,
    HandoffHeaderState,
    HandoffMutationOutcome,
    ResumeRefSpec,
    SeenHandoffSpec,
)
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
from superbrain.storage._handoff_schema import max_task_event_order_in_tx, read_revision_events_since_agent_in_tx
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.send_attempts import read_read_ack_by_receipt_row, read_send_attempt_row


def _apply_handoff_mutation_in_tx(
    self: _m.HandoffStore,
    db: sqlite3.Connection,
    *,
    live_epoch: int,
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
    new_agent_ref: str | None,
    new_agent_holder_id: str | None,
    next_task_state: str | None,
    evidence_held: Sequence[tuple[str, str, str]],
    manual_submission_enabled: bool,
    now: datetime,
) -> HandoffMutationOutcome:
    stamp = utc_timestamp(now)
    row = db.execute(_m._HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
    if row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    cur = _row_to_header(row, live_restore_epoch=live_epoch)
    if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    ev_ids = tuple(e[0] for e in evidence_held)

    if not manual_submission_enabled:
        db.execute(
            "INSERT INTO episodes ("
            "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
            "committed_revision, committed_restore_epoch, committed_writer_generation, "
            "evidence_ids_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'not_stored_policy', ?, NULL, NULL, ?, ?, ?, ?)",
            (
                episode_id,
                task_id,
                owner_id,
                repo_id,
                checkout_id,
                principal_id,
                session_ref,
                1 if (has_patch or takeover) else 0,
                cur.artifact_id,
                cur.live_fence.restore_epoch,
                cur.writer_generation,
                canonical_json(list(ev_ids)).decode("utf-8"),
                stamp,
            ),
        )
        _insert_episode_evidence(
            db, episode_id=episode_id, task_id=task_id, evidence_held=evidence_held, stamp=stamp
        )
        return HandoffMutationOutcome(
            episode_id=episode_id,
            evidence_ids=ev_ids,
            handoff_status="not_stored_policy",
            handoff_revision=None,
            revision=None,
            revision_epoch=None,
            fence=cur.live_fence,
            holder_principal=cur.holder_principal,
            holder_session_ref=cur.holder_session_ref,
        )

    if expected_fence is None or base_revision is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "base_revision and fence required")
    if expected_fence != cur.live_fence or base_revision != cur.handoff_revision:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "handoff revision or fence conflict")

    initial_claim = (
        cur.holder_principal is None
        and cur.holder_session_ref is None
        and cur.writer_generation == 0
        and cur.holder_restore_epoch == live_epoch
    )
    if not takeover and not initial_claim:
        if (
            cur.holder_principal != principal_id
            or cur.holder_session_ref != session_ref
            or cur.holder_restore_epoch != live_epoch
        ):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "caller is not current handoff holder")
    elif takeover:
        if (
            cur.holder_session_ref is not None
            and cur.holder_session_ref != session_ref
            and self._is_session_active(db, cur.holder_session_ref, now=now)
            and not takeover_acknowledge_active
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "takeover requires acknowledge_active=true")

    next_rev = cur.revision + 1
    next_epoch = live_epoch
    next_hrev = (cur.handoff_revision + 1) if has_patch else cur.handoff_revision
    next_wgen = (cur.writer_generation + 1) if (takeover or initial_claim) else cur.writer_generation
    eff_agent_ref = new_agent_ref if has_patch else cur.agent_ref
    eff_task_state = (
        next_task_state if (has_patch and next_task_state is not None) else cur.task_state
    )
    eff_source = "agent" if (has_patch or cur.agent_ref is not None) else cur.task_state_source
    eff_agent_at = stamp if has_patch else cur.agent_updated_at
    take_from_p = cur.holder_principal if takeover else None
    take_from_s = cur.holder_session_ref if takeover else None
    if has_patch:
        next_events_since_agent = 0
        next_agent_event_order: int | None = max_task_event_order_in_tx(db, task_id)
    else:
        next_events_since_agent = read_revision_events_since_agent_in_tx(
            db,
            artifact_id=cur.artifact_id,
            revision_epoch=cur.revision_epoch,
            revision=cur.revision,
        )
        next_agent_event_order = None

    if has_patch and new_agent_holder_id is not None:
        db.execute(
            "UPDATE task_handoffs SET agent_holder_id = ? WHERE task_id = ?",
            (new_agent_holder_id, task_id),
        )
        hdr_holder_id: str | None = new_agent_holder_id
    else:
        r_ah = db.execute("SELECT agent_holder_id FROM task_handoffs WHERE task_id = ?", (task_id,)).fetchone()
        hdr_holder_id = None if r_ah is None or r_ah[0] is None else str(r_ah[0])

    db.execute(
        "UPDATE task_handoffs SET current_revision = ?, current_revision_epoch = ?, handoff_revision = ?, "
        "writer_generation = ?, agent_ref = ?, task_state = ?, task_state_source = ?, holder_principal = ?, "
        "holder_session_ref = ?, holder_restore_epoch = ?, agent_updated_at = ?, "
        "agent_event_order = COALESCE(?, agent_event_order), "
        "takeover_from_principal = COALESCE(?, takeover_from_principal), "
        "takeover_from_session_ref = COALESCE(?, takeover_from_session_ref), updated_at = ? WHERE task_id = ?",
        (
            next_rev,
            next_epoch,
            next_hrev,
            next_wgen,
            eff_agent_ref,
            eff_task_state,
            eff_source,
            principal_id,
            session_ref,
            next_epoch,
            eff_agent_at,
            next_agent_event_order,
            take_from_p,
            take_from_s,
            stamp,
            task_id,
        ),
    )
    db.execute(
        "UPDATE tasks SET current_revision = ?, current_revision_epoch = ?, task_state = ?, "
        "task_state_source = ?, holder_principal = ?, holder_session_ref = ?, updated_at = ? WHERE task_id = ?",
        (next_rev, next_epoch, eff_task_state, eff_source, principal_id, session_ref, stamp, task_id),
    )
    db.execute(
        "INSERT INTO handoff_revisions "
        "(task_id, handoff_revision, source_kind, agent_ref, observed_ref, recorded_at) "
        "VALUES (?, ?, 'agent', ?, ?, ?)",
        (task_id, next_hrev, eff_agent_ref, cur.observed_ref, stamp),
    )
    sess_state_str = "active" if self._is_session_active(db, session_ref, now=now) else "in_progress_unknown"
    db.execute(
        "INSERT INTO handoff_revision_headers ("
        "artifact_id, revision_epoch, revision, handoff_revision, task_id, task_state, task_state_source, "
        "holder_restore_epoch, writer_generation, holder_harness_id, holder_principal, holder_session_ref, "
        "session_state, agent_ref, agent_holder_id, observed_ref, agent_updated_at, observed_through, "
        "events_since_agent, recorded_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cur.artifact_id,
            next_epoch,
            next_rev,
            next_hrev,
            task_id,
            eff_task_state,
            eff_source,
            next_epoch,
            next_wgen,
            harness_id,
            principal_id,
            session_ref,
            sess_state_str,
            eff_agent_ref,
            hdr_holder_id,
            cur.observed_ref,
            eff_agent_at,
            cur.observed_through,
            next_events_since_agent,
            stamp,
        ),
    )
    db.execute(
        "INSERT INTO episodes ("
        "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
        "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
        "committed_revision, committed_restore_epoch, committed_writer_generation, evidence_ids_json, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'stored', ?, ?, ?, ?, ?, ?, ?)",
        (
            episode_id,
            task_id,
            owner_id,
            repo_id,
            checkout_id,
            principal_id,
            session_ref,
            cur.artifact_id,
            next_hrev,
            next_rev,
            next_epoch,
            next_wgen,
            canonical_json(list(ev_ids)).decode("utf-8"),
            stamp,
        ),
    )
    _insert_episode_evidence(
        db, episode_id=episode_id, task_id=task_id, evidence_held=evidence_held, stamp=stamp
    )
    return HandoffMutationOutcome(
        episode_id=episode_id,
        evidence_ids=ev_ids,
        handoff_status="stored",
        handoff_revision=next_hrev,
        revision=next_rev,
        revision_epoch=next_epoch,
        fence=HandoffFence(restore_epoch=next_epoch, writer_generation=next_wgen),
        holder_principal=principal_id,
        holder_session_ref=session_ref,
    )


def _apply_create_work_task_in_tx(
    self: _m.HandoffStore,
    db: sqlite3.Connection,
    *,
    live_epoch: int,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    session_ref: str | None,
    goal_digest: str | None,
    goal_holder_id: str | None,
    delivery_id: str,
    now: datetime,
) -> CreateWorkTaskResult:
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    require_opaque_id(principal_id, label="principal_id")
    if session_ref is not None:
        require_sha256_digest(session_ref)
    if goal_digest is not None:
        require_sha256_digest(goal_digest)
    require_opaque_id(delivery_id, label="delivery_id")
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)
    artifact_id = task_id

    db.execute(
        "INSERT INTO tasks ("
        "task_id, owner_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
        "task_state, task_state_source, holder_principal, holder_session_ref, created_at, updated_at, "
        "goal_ref, goal_holder_id"
        ") VALUES (?, ?, ?, ?, 0, ?, 'open', 'agent', NULL, NULL, ?, ?, ?, ?)",
        (task_id, owner_id, repo_id, checkout_id, live_epoch, stamp, stamp, goal_digest, goal_holder_id),
    )
    db.execute(
        "INSERT INTO task_handoffs ("
        "task_id, artifact_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
        "handoff_revision, writer_generation, agent_ref, observed_ref, task_state, task_state_source, "
        "holder_principal, holder_session_ref, agent_updated_at, observed_through, "
        "holder_restore_epoch, goal_ref, goal_holder_id, agent_holder_id, l0_summary_ref, updated_at"
        ") VALUES (?, ?, ?, ?, 0, ?, 0, 0, NULL, NULL, 'open', 'agent', NULL, NULL, NULL, NULL, "
        "?, ?, ?, NULL, NULL, ?)",
        (task_id, artifact_id, repo_id, checkout_id, live_epoch, live_epoch, goal_digest, goal_holder_id, stamp),
    )
    return CreateWorkTaskResult(
        task_id=task_id,
        artifact_id=artifact_id,
        delivery_id=delivery_id,
        goal_digest=goal_digest or digest_bytes(b""),
        handoff_live=HandoffHeaderState(
            task_id=task_id,
            artifact_id=artifact_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            revision=0,
            revision_epoch=live_epoch,
            handoff_revision=0,
            writer_generation=0,
            holder_principal=None,
            holder_session_ref=None,
            holder_restore_epoch=live_epoch,
            live_restore_epoch=live_epoch,
            task_state="open",
            task_state_source="agent",
            goal_ref=goal_digest,
            agent_ref=None,
            observed_ref=None,
            l0_summary_ref=None,
            agent_updated_at=None,
            observed_through=None,
        ).handoff_live,
    )


def _validate_seen_refs_in_tx(
    self: _m.HandoffStore,
    db: sqlite3.Connection,
    *,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    seen_refs: Sequence[SeenHandoffSpec],
) -> None:
    for ref in seen_refs:
        row = db.execute(
            "SELECT r.agent_ref, COALESCE(h.goal_ref, t.goal_ref) "
            "FROM handoff_revision_headers AS r "
            "JOIN tasks AS t ON t.task_id = r.task_id "
            "JOIN task_handoffs AS h ON h.task_id = r.task_id "
            "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ? "
            "AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ?",
            (ref.artifact_id, ref.revision_epoch, ref.revision, owner_id, repo_id, checkout_id),
        ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        agent_ref = None if row[0] is None else str(row[0])
        goal_ref = None if row[1] is None else str(row[1])
        allowed = {d for d in (agent_ref, goal_ref) if d is not None}
        if allowed and ref.digest not in allowed:
            raise BrainError(ErrorCode.INVALID_INPUT, "seen_handoff_refs digest mismatch")


def _validate_resume_in_tx(
    self: _m.HandoffStore,
    db: sqlite3.Connection,
    *,
    task_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    principal_id: str,
    cur: HandoffHeaderState,
    resume_ref: ResumeRefSpec,
) -> tuple[str, int, int, str | None, str, bool]:
    art_row = db.execute(
        "SELECT t.task_id, t.owner_id, t.repo_id, t.checkout_id "
        "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
        "WHERE h.artifact_id = ?",
        (resume_ref.artifact_id,),
    ).fetchone()
    if (
        art_row is None
        or str(art_row[1]) != owner_id
        or str(art_row[2]) != repo_id
        or str(art_row[3]) != checkout_id
        or str(art_row[0]) != task_id
    ):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    if resume_ref.served_receipt_id is not None:
        attempt = read_send_attempt_row(db, resume_ref.served_receipt_id)
        if (
            attempt is None
            or attempt.principal_id != principal_id
            or attempt.task_id != task_id
            or attempt.artifact_id != resume_ref.artifact_id
            or attempt.revision != resume_ref.revision
            or attempt.level != "L1"
            or attempt.state is SendAttemptState.UNKNOWN
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if attempt.state is SendAttemptState.PENDING:
            raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
        if attempt.state is not SendAttemptState.SERVED_ONLY or not attempt.resource_digests:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        res_epoch = attempt.revision_epoch
        ack = read_read_ack_by_receipt_row(db, resume_ref.served_receipt_id)
        has_matching_ack = (
            ack is not None
            and ack.served_receipt_id == attempt.send_attempt_id
            and ack.principal_id == principal_id
            and ack.task_id == task_id
            and ack.artifact_id == attempt.artifact_id
            and ack.revision_epoch == attempt.revision_epoch
            and ack.revision == attempt.revision
            and ack.resource_digests == attempt.resource_digests
        )
        resume_exposure = "read_ack" if has_matching_ack else "served_only"
    else:
        resume_exposure = "unknown"
        cand_epoch = db.execute(
            "SELECT 1 FROM handoff_revision_headers "
            "WHERE artifact_id = ? AND revision_epoch = ? AND revision = ?",
            (resume_ref.artifact_id, resume_ref.fence.restore_epoch, resume_ref.revision),
        ).fetchone()
        if cand_epoch is None:
            any_rev = db.execute(
                "SELECT 1 FROM handoff_revision_headers WHERE artifact_id = ? AND revision = ?",
                (resume_ref.artifact_id, resume_ref.revision),
            ).fetchone()
            if any_rev is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            raise BrainError(ErrorCode.REVISION_CONFLICT, "resume_ref does not match revision header")
        res_epoch = resume_ref.fence.restore_epoch

    hrow = db.execute(
        "SELECT handoff_revision, holder_restore_epoch, writer_generation "
        "FROM handoff_revision_headers WHERE artifact_id = ? AND revision_epoch = ? AND revision = ?",
        (resume_ref.artifact_id, res_epoch, resume_ref.revision),
    ).fetchone()
    if hrow is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    hdr_hrev = int(hrow[0])
    hdr_fence = HandoffFence(restore_epoch=int(hrow[1]), writer_generation=int(hrow[2]))
    if resume_ref.handoff_revision != hdr_hrev or resume_ref.fence != hdr_fence:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "resume_ref does not match revision header")
    if cur.handoff_revision != hdr_hrev or cur.committed_fence != hdr_fence:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "handoff changed since read revision")
    observed_newer = (cur.revision_epoch, cur.revision) != (res_epoch, resume_ref.revision)
    return (
        resume_ref.artifact_id,
        res_epoch,
        resume_ref.revision,
        resume_ref.served_receipt_id,
        resume_exposure,
        observed_newer,
    )
