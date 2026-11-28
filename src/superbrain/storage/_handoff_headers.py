"""Header, holder-status and agent-state reads of ``handoffs.HandoffStore``."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from superbrain.core._kernel_base import (
    require_opaque_id,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffFence,
)
from superbrain.ports.continuity import SessionState, decide_session_liveness
from superbrain.ports.handoff import (
    HandoffHeaderState,
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
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.ledger import utc_timestamp


def read_live_holder_status(
    self: _m.HandoffStore,
    task_id: str,
    *,
    principal_id: str,
    session_ref: str,
    scope: Scope,
) -> tuple[bool, HandoffFence]:
    hdr = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
    is_holder = (
        hdr.holder_principal == principal_id
        and hdr.holder_session_ref == session_ref
        and hdr.holder_restore_epoch == hdr.live_restore_epoch
    )
    return is_holder, hdr.live_fence


def has_open_handoffs(
    self: _m.HandoffStore, *, owner_id: str, repo_id: str, checkout_id: str, now: datetime | None = None
) -> bool:
    _require_v8_ready(self._store, self._policy)
    cutoff: str | None = None
    if now is not None:
        cutoff = utc_timestamp(require_aware_utc(now)[0] - _m._DISCOVER_WINDOW)
    return _has_open_handoffs_in_db(
        self._store._db,
        owner_id=owner_id,
        repo_id=repo_id,
        checkout_id=checkout_id,
        cutoff=cutoff,
    )


def read_header(self: _m.HandoffStore, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState | None:
    live_epoch = _require_v8_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(principal_id, label="principal_id")
    if scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    row = self._store._db.execute(_m._HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
    if row is None:
        return None
    hdr = _row_to_header(row, live_restore_epoch=live_epoch)
    if hdr.repo_id != scope.repo_id or hdr.checkout_id != scope.checkout_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return hdr


def _load_agent_state_checked(
    self: _m.HandoffStore, hdr: HandoffHeaderState, *, now: datetime
) -> HandoffAgentState | None:
    if hdr.agent_ref is None:
        return None
    row = self._store._db.execute(
        "SELECT agent_holder_id FROM task_handoffs WHERE task_id = ?", (hdr.task_id,)
    ).fetchone()
    hid = None if row is None or row[0] is None else str(row[0])
    data, status = _check_blob_status(
        self._store._db, self._store, self._policy, hdr.agent_ref, holder_id=hid, now=now
    )
    if status != "ok" or data is None:
        raise BrainError(ErrorCode.NOT_FOUND, "handoff content unavailable")
    return HandoffAgentState.from_dict(json.loads(data.decode("utf-8")))


def load_agent_state_scoped(
    self: _m.HandoffStore,
    *,
    task_id: str,
    principal_id: str,
    scope: Scope,
    now: datetime,
) -> HandoffAgentState | None:
    _require_v8_ready(self._store, self._policy)
    now_utc, _ = require_aware_utc(now)
    cur = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
    return self._load_agent_state_checked(cur, now=now_utc)


def read_task_header_scoped(
    self: _m.HandoffStore,
    task_id: str,
    *,
    owner_id: str,
    selected_scope: Scope | None,
) -> HandoffHeaderState:
    hdr = self.try_read_task_header_scoped(task_id, owner_id=owner_id, selected_scope=selected_scope)
    if hdr is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return hdr


def _is_session_active(self: _m.HandoffStore, db: sqlite3.Connection, session_ref: str, *, now: datetime) -> bool:
    row = db.execute("SELECT state, last_event_at FROM sessions WHERE session_ref = ?", (session_ref,)).fetchone()
    if row is None:
        return False
    dec = decide_session_liveness(
        recorded_state=SessionState(str(row[0])),
        last_event_at=parse_iso_utc(str(row[1])),
        now=now,
    )
    return dec.state is SessionState.ACTIVE
