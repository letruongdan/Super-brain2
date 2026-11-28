"""Read, discover and source-resolution paths of ``handoffs.HandoffStore``."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from superbrain.core._kernel_base import (
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffRevisionHeader,
    ResolvedSourceContent,
)
from superbrain.ports.continuity import SessionState, decide_session_liveness
from superbrain.ports.handoff import (
    ArtifactGetRecord,
    DiscoverEntry,
    HandoffContentBundle,
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
from superbrain.storage._sessions_sources import live_event_record
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.kinds import is_uuid
from superbrain.storage.ledger import utc_timestamp


def resolve_observed_sources(
    self: _m.HandoffStore,
    *,
    task_id: str,
    observed_ref: str | None,
    now: datetime,
) -> tuple[list[ResolvedSourceContent], list[ResolvedSourceContent]]:
    _require_v8_ready(self._store, self._policy)
    now_utc, _ = require_aware_utc(now)
    if observed_ref is None:
        return [], []

    raw_obs, obs_status = _check_blob_status(
        self._store._db,
        self._store,
        self._policy,
        observed_ref,
        holder_id=None,
        now=now_utc,
    )
    if obs_status != "ok" or raw_obs is None:
        redacted_status = "redacted" if obs_status in {"quarantined", "tombstoned"} else "expired"
        return (
            [
                ResolvedSourceContent(
                    source_event_id=observed_ref,
                    source_digest=observed_ref,
                    kind="observed_summary",
                    status=redacted_status,
                    reason=obs_status,
                )
            ],
            [],
        )

    try:
        decoded = json.loads(raw_obs.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [], []
    if not isinstance(decoded, Mapping):
        return [], []
    raw_sources = decoded.get("source_events")
    if not isinstance(raw_sources, list):
        return [], []

    kind_by_eid: dict[str, str] = {}
    raw_items = decoded.get("items")
    if isinstance(raw_items, list):
        for it in raw_items:
            if (
                isinstance(it, Sequence)
                and not isinstance(it, (str, bytes))
                and len(it) >= 2
                and isinstance(it[0], str)
                and isinstance(it[1], str)
            ):
                kind_by_eid.setdefault(it[1], it[0])

    pinned_refs: list[tuple[str, int, str, str]] = []
    seen_keys: set[tuple[str, int, str, str]] = set()
    for entry in raw_sources:
        if (
            not isinstance(entry, Sequence)
            or isinstance(entry, (str, bytes))
            or len(entry) < 4
            or not isinstance(entry[0], str)
            or type(entry[1]) is not int
            or not isinstance(entry[2], str)
            or not isinstance(entry[3], str)
        ):
            continue
        ref_key = (entry[0], entry[1], entry[2], entry[3])
        if ref_key not in seen_keys:
            seen_keys.add(ref_key)
            pinned_refs.append(ref_key)

    obs_items: list[ResolvedSourceContent] = []
    conv_items: list[ResolvedSourceContent] = []

    for stream, seq, eid, dig in reversed(pinned_refs):
        meta_row = self._store._db.execute(
            "SELECT l.kind, l.recorded_at, e.cas_holder_id "
            "FROM session_task_events AS l "
            "LEFT JOIN capture_events AS e "
            "ON e.producer_stream = l.producer_stream AND e.sequence = l.sequence "
            "AND e.event_id = l.event_id AND e.payload_digest = l.payload_digest "
            "WHERE l.task_id = ? AND l.producer_stream = ? AND l.sequence = ? "
            "AND l.event_id = ? AND l.payload_digest = ?",
            (task_id, stream, seq, eid, dig),
        ).fetchone()
        meta_kind = (
            str(meta_row[0])
            if meta_row is not None and isinstance(meta_row[0], str)
            else kind_by_eid.get(eid, "event")
        )
        meta_rec_at = str(meta_row[1]) if meta_row is not None and isinstance(meta_row[1], str) else None
        cas_hid = str(meta_row[2]) if meta_row is not None and isinstance(meta_row[2], str) else None

        rec = live_event_record(
            self._store,
            self._policy,
            task_id=task_id,
            producer_stream=stream,
            sequence=seq,
            event_id=eid,
            payload_digest=dig,
            now=now_utc,
        )
        if rec is None:
            is_redacted = self._policy.is_quarantined(dig) or (
                cas_hid is not None and is_uuid(cas_hid) and self._policy.is_tombstoned("event", cas_hid)
            )
            status = "redacted" if is_redacted else "expired"
            content = ResolvedSourceContent(
                source_event_id=eid,
                source_digest=dig,
                kind=meta_kind,
                status=status,
                reason=status,
                recorded_at=meta_rec_at,
            )
            eff_kind = meta_kind
        else:
            content = ResolvedSourceContent(
                source_event_id=rec.event_id,
                source_digest=dig,
                kind=rec.kind,
                status="ok",
                payload=rec.payload,
                recorded_at=rec.recorded_at,
            )
            eff_kind = rec.kind

        if eff_kind in {"user_message", "user_prompt"}:
            conv_items.append(content)
        obs_items.append(content)

    return obs_items, conv_items


def read_handoff_content_bundle(
    self: _m.HandoffStore,
    *,
    artifact_id: str,
    revision_epoch: int,
    revision: int,
    task_id: str,
    principal_id: str,
    scope: Scope,
    now: datetime,
    include_history: bool = False,
) -> HandoffContentBundle:
    _require_v8_ready(self._store, self._policy)
    now_utc, _ = require_aware_utc(now)
    hdr = self.read_revision_header(
        artifact_id=artifact_id,
        revision_epoch=revision_epoch,
        revision=revision,
        principal_id=principal_id,
        scope=scope,
    )
    if hdr is None or hdr.task_id != task_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    live = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
    extra_row = self._store._db.execute(
        "SELECT r.agent_holder_id, t.goal_ref, t.goal_holder_id "
        "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
        "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
        (artifact_id, revision_epoch, revision),
    ).fetchone()
    if extra_row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    agent_hid = None if extra_row[0] is None else str(extra_row[0])
    goal_ref = None if extra_row[1] is None else str(extra_row[1])
    goal_hid = None if extra_row[2] is None else str(extra_row[2])

    task_goal: str | None = ""
    goal_status = "ok"
    if goal_ref is not None:
        gbytes, gstatus = _check_blob_status(
            self._store._db,
            self._store,
            self._policy,
            goal_ref,
            holder_id=goal_hid,
            now=now_utc,
        )
        goal_status = gstatus
        if gstatus == "ok" and gbytes is not None:
            task_goal = gbytes.decode("utf-8", errors="replace")
        else:
            task_goal = None

    agent_state: HandoffAgentState | None = None
    agent_status = "ok"
    if hdr.agent_ref is not None:
        abytes, astatus = _check_blob_status(
            self._store._db,
            self._store,
            self._policy,
            hdr.agent_ref,
            holder_id=agent_hid,
            now=now_utc,
        )
        agent_status = astatus
        if astatus == "ok" and abytes is not None:
            agent_state = HandoffAgentState.from_dict(json.loads(abytes.decode("utf-8")))

    obs_items, conv_items = self.resolve_observed_sources(
        task_id=task_id,
        observed_ref=hdr.observed_ref,
        now=now_utc,
    )

    sess_state = hdr.session_state
    holder_harness_id = hdr.holder_harness_id
    other_active = False
    if hdr.holder_session_ref is not None:
        srow = self._store._db.execute(
            "SELECT state, last_event_at, harness_id FROM sessions WHERE session_ref = ?",
            (hdr.holder_session_ref,),
        ).fetchone()
        if srow is not None:
            sess_state = decide_session_liveness(
                recorded_state=SessionState(str(srow[0])),
                last_event_at=parse_iso_utc(str(srow[1])),
                now=now_utc,
            ).state.value
            if holder_harness_id is None:
                holder_harness_id = str(srow[2])
        if scope.checkout_id is not None:
            orow = self._store._db.execute(
                "SELECT 1 FROM sessions WHERE repo_id = ? AND checkout_id = ? AND state = 'active' "
                "AND session_ref != ? LIMIT 1",
                (scope.repo_id, scope.checkout_id, hdr.holder_session_ref),
            ).fetchone()
            other_active = orow is not None

    revision_history: tuple[HandoffRevisionHeader, ...] = (
        self.list_revision_history(
            artifact_id=artifact_id,
            task_id=task_id,
            revision_epoch=revision_epoch,
            revision=revision,
            principal_id=principal_id,
            scope=scope,
        )
        if include_history
        else ()
    )

    return HandoffContentBundle(
        header=hdr,
        live=live,
        task_goal=task_goal,
        goal_status=goal_status,
        agent_state=agent_state,
        agent_status=agent_status,
        observed_sources=tuple(obs_items),
        conversation_sources=tuple(conv_items),
        holder_harness_id=holder_harness_id,
        session_state=sess_state,
        other_active_warning=other_active,
        revision_history=revision_history,
        events_since_agent=hdr.events_since_agent,
    )


def list_discover(
    self: _m.HandoffStore,
    *,
    principal_id: str,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    task_id: str | None = None,
    now: datetime,
    render_l0: Callable[..., str] | None = None,
) -> tuple[DiscoverEntry, ...]:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(principal_id, label="principal_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    now_utc, _ = require_aware_utc(now)
    cutoff = utc_timestamp(now_utc - _m._DISCOVER_WINDOW)

    if task_id is not None:
        require_opaque_id(task_id, label="task_id")
        rows = self._store._db.execute(
            "SELECT h.task_id, h.artifact_id, h.current_revision_epoch, h.current_revision, "
            "h.handoff_revision, COALESCE(h.goal_ref, t.goal_ref), t.goal_holder_id, h.agent_ref, "
            "h.agent_holder_id, h.holder_session_ref, h.agent_updated_at, h.observed_through "
            "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
            "WHERE t.task_id = ? AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
            "AND h.current_revision >= 1",
            (task_id, owner_id, repo_id, checkout_id),
        ).fetchall()
    else:
        rows = self._store._db.execute(
            "SELECT h.task_id, h.artifact_id, h.current_revision_epoch, h.current_revision, "
            "h.handoff_revision, COALESCE(h.goal_ref, t.goal_ref), t.goal_holder_id, h.agent_ref, "
            "h.agent_holder_id, h.holder_session_ref, h.agent_updated_at, h.observed_through "
            "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
            "WHERE t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
            "AND h.task_state IN ('open', 'in_progress') "
            "AND COALESCE(NULLIF(h.updated_at, ''), t.updated_at) >= ? AND h.current_revision >= 1 "
            "ORDER BY COALESCE(NULLIF(h.updated_at, ''), t.updated_at) DESC, t.task_id ASC LIMIT 3",
            (owner_id, repo_id, checkout_id, cutoff),
        ).fetchall()

    return tuple(
        self._render_l0_row(
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
        for row in rows
    )


def list_revision_history(
    self: _m.HandoffStore,
    *,
    artifact_id: str,
    task_id: str,
    revision_epoch: int,
    revision: int,
    principal_id: str,
    scope: Scope,
    limit: int = 1024,
) -> tuple[HandoffRevisionHeader, ...]:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(artifact_id, label="artifact_id")
    require_opaque_id(task_id, label="task_id")
    require_non_negative_int(revision_epoch)
    require_positive_int(revision)
    require_opaque_id(principal_id, label="principal_id")
    require_positive_int(limit)
    if scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    rows = self._store._db.execute(
        _m._REV_HDR_SELECT
        + "WHERE r.artifact_id = ? AND r.task_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
        "AND r.revision_epoch <= ? AND r.revision <= ? "
        "ORDER BY r.revision DESC, r.revision_epoch DESC",
        (artifact_id, task_id, scope.repo_id, scope.checkout_id, revision_epoch, revision),
    ).fetchall()
    results: list[HandoffRevisionHeader] = []
    target_found = False
    cur_max_epoch = revision_epoch
    last_rev = revision + 1
    for row in rows:
        hdr = _row_to_rev_header(row)
        if not target_found:
            if hdr.revision == revision and hdr.revision_epoch == revision_epoch:
                target_found = True
                results.append(hdr)
                cur_max_epoch = hdr.revision_epoch
                last_rev = hdr.revision
                if len(results) >= limit:
                    break
            continue
        if hdr.revision == last_rev:
            continue
        if hdr.revision > last_rev or hdr.revision_epoch > cur_max_epoch:
            continue
        results.append(hdr)
        cur_max_epoch = hdr.revision_epoch
        last_rev = hdr.revision
        if len(results) >= limit:
            break
    if not target_found:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return tuple(results)


def resolve_artifact_revision_epoch(
    self: _m.HandoffStore,
    *,
    task_id: str,
    artifact_id: str,
    revision: int,
    revision_epoch: int | None,
    principal_id: str,
    scope: Scope,
) -> int:
    live_epoch = _require_v8_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(artifact_id, label="artifact_id")
    require_positive_int(revision)
    require_opaque_id(principal_id, label="principal_id")
    if scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if revision_epoch is not None:
        require_non_negative_int(revision_epoch)
        hdr = self.read_revision_header(
            artifact_id=artifact_id,
            revision_epoch=revision_epoch,
            revision=revision,
            principal_id=principal_id,
            scope=scope,
        )
        if hdr is None or hdr.task_id != task_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return revision_epoch

    rows = self._store._db.execute(
        "SELECT r.revision_epoch, r.task_id, t.repo_id, t.checkout_id "
        "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
        "WHERE r.artifact_id = ? AND r.revision = ?",
        (artifact_id, revision),
    ).fetchall()
    scoped_epochs = [
        int(r[0])
        for r in rows
        if str(r[1]) == task_id and str(r[2]) == scope.repo_id and str(r[3]) == scope.checkout_id
    ]
    if not scoped_epochs:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if live_epoch in scoped_epochs:
        return live_epoch
    if len(scoped_epochs) == 1:
        return scoped_epochs[0]
    raise BrainError(ErrorCode.INVALID_INPUT, "revision_epoch required after restore")


def read_artifact_get(
    self: _m.HandoffStore,
    result_id: str,
    *,
    owner_id: str,
    principal_id: str,
    selected_scope: Scope | None,
) -> ArtifactGetRecord:
    _require_v8_ready(self._store, self._policy)
    require_opaque_id(result_id, label="result_id")
    require_opaque_id(owner_id, label="owner_id")
    require_opaque_id(principal_id, label="principal_id")
    row = self._store._db.execute(
        "SELECT result_id, task_id, artifact_id, revision_epoch, revision, level, "
        "owner_id, repo_id, checkout_id, principal_id "
        "FROM artifact_get_results WHERE result_id = ?",
        (result_id,),
    ).fetchone()
    if row is None or str(row[6]) != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if selected_scope is not None:
        if str(row[7]) != selected_scope.repo_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope.checkout_id is not None and str(row[8]) != selected_scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return ArtifactGetRecord(
        result_id=str(row[0]),
        task_id=str(row[1]),
        artifact_id=str(row[2]),
        revision_epoch=int(row[3]),
        revision=int(row[4]),
        level=str(row[5]),
        owner_id=str(row[6]),
        repo_id=str(row[7]),
        checkout_id=str(row[8]),
        principal_id=str(row[9]),
    )
