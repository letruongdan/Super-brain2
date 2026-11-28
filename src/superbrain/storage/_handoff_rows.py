"""Row decoding, readiness checks and evidence helpers shared by the handoff store modules."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime

from superbrain.core._kernel_base import (
    require_non_negative_int,
    require_positive_int,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports._handoff_types import (
    HandoffFence,
    HandoffRevisionHeader,
)
from superbrain.ports.handoff import (
    HandoffHeaderState,
)
from superbrain.storage._restore_epoch import read_restore_epoch
from superbrain.storage.cas import HOLDERS_TABLE, read_held_blob_or_none
from superbrain.storage.kinds import RetentionClass, is_uuid
from superbrain.storage.ledger import Txn, utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


def _unique_codes(codes: Sequence[str]) -> list[str]:
    """Deduplicate degraded codes while preserving insertion order."""
    out: list[str] = []
    seen: set[str] = set()
    for code in codes:
        if code not in seen:
            seen.add(code)
            out.append(code)
    return out


def _has_open_handoffs_in_db(
    db: sqlite3.Connection,
    *,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    cutoff: str | None = None,
    exclude_task_id: str | None = None,
) -> bool:
    clauses = [
        "t.owner_id = ?",
        "t.repo_id = ?",
        "t.checkout_id = ?",
        "h.task_state IN ('open', 'in_progress')",
        "h.current_revision >= 1",
    ]
    params: list[object] = [owner_id, repo_id, checkout_id]
    if exclude_task_id is not None:
        clauses.append("h.task_id != ?")
        params.append(exclude_task_id)
    if cutoff is not None:
        clauses.append("COALESCE(NULLIF(h.updated_at, ''), t.updated_at) >= ?")
        params.append(cutoff)
    sql = (
        "SELECT 1 FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
        f"WHERE {' AND '.join(clauses)} LIMIT 1"
    )
    return db.execute(sql, tuple(params)).fetchone() is not None


def _txn_of(tx: object) -> Txn:
    txn = getattr(tx, "_txn", None)
    if not isinstance(txn, Txn):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected StoreKernelTx transaction")
    return txn


def _insert_episode_evidence(
    db: sqlite3.Connection,
    *,
    episode_id: str,
    task_id: str,
    evidence_held: Sequence[tuple[str, str, str]],
    stamp: str,
) -> None:
    """Insert ``episode_evidence`` child rows after the parent ``episodes`` row exists."""
    for idx, (ev_id, ev_dig, ev_hid) in enumerate(evidence_held):
        db.execute(
            "INSERT INTO episode_evidence "
            "(evidence_id, episode_id, task_id, idx, digest, cas_holder_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ev_id, episode_id, task_id, idx, ev_dig, ev_hid, stamp),
        )


def _require_v8_ready(store: Store, policy: PolicyStore) -> int:
    store._check()
    policy._check()
    if store.schema_version < 8 or policy.schema_version < 5:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    return read_restore_epoch(store.root, schema_version=store.schema_version, os_=store._os)


def _check_blob_status(
    db: sqlite3.Connection,
    store: Store,
    policy: PolicyStore,
    digest: str,
    *,
    holder_id: str | None,
    now: datetime,
) -> tuple[bytes | None, str]:
    """Return ``(bytes, 'ok')`` or ``(None, 'quarantined'|'tombstoned'|'expired')`` fail-closed."""
    if policy.is_quarantined(digest):
        return None, "quarantined"
    if holder_id is not None and is_uuid(holder_id):
        if policy.is_tombstoned("event", holder_id):
            return None, "tombstoned"
        data = read_held_blob_or_none(
            db,
            store.cas,
            policy,
            digest,
            holder_kind="event",
            holder_id=holder_id,
            now=now,
        )
        if data is None:
            return None, "expired"
        return data, "ok"

    cutoff = utc_timestamp(now)
    rows = db.execute(
        f"SELECT holder_id, retention_class, expires_at FROM {HOLDERS_TABLE} "
        "WHERE holder_kind = 'event' AND digest = ?",
        (digest,),
    ).fetchall()
    has_live_hold = False
    saw_tombstoned = False
    for hid_raw, ret_raw, exp_raw in rows:
        hid = str(hid_raw)
        if policy.is_tombstoned("event", hid):
            saw_tombstoned = True
            continue
        if str(ret_raw) == RetentionClass.DURABLE.value or exp_raw is None or str(exp_raw) > cutoff:
            has_live_hold = True
            break
    if not has_live_hold:
        return None, "tombstoned" if saw_tombstoned else "expired"
    if not store.cas.blob_intact(digest):
        return None, "expired"
    return store.cas.read(digest), "ok"


def _req_int(val: object) -> int:
    if type(val) is not int:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected integer column value")
    return val


def _row_to_header(row: Sequence[object], *, live_restore_epoch: int) -> HandoffHeaderState:
    return HandoffHeaderState(
        task_id=str(row[0]),
        artifact_id=str(row[1]),
        repo_id=str(row[2]),
        checkout_id=str(row[3]),
        revision=_req_int(row[4]),
        revision_epoch=_req_int(row[5]),
        handoff_revision=_req_int(row[6]),
        writer_generation=_req_int(row[7]),
        holder_principal=None if row[8] is None else str(row[8]),
        holder_session_ref=None if row[9] is None else str(row[9]),
        holder_restore_epoch=_req_int(row[10]),
        live_restore_epoch=live_restore_epoch,
        task_state=str(row[11]),
        task_state_source=str(row[12]),
        goal_ref=None if row[13] is None else str(row[13]),
        agent_ref=None if row[14] is None else str(row[14]),
        observed_ref=None if row[15] is None else str(row[15]),
        l0_summary_ref=None if row[16] is None else str(row[16]),
        agent_updated_at=None if row[17] is None else str(row[17]),
        observed_through=None if row[18] is None else str(row[18]),
    )


def _row_to_rev_header(row: Sequence[object]) -> HandoffRevisionHeader:
    return HandoffRevisionHeader(
        artifact_id=str(row[0]),
        revision_epoch=require_non_negative_int(row[1]),
        revision=require_positive_int(row[2]),
        handoff_revision=require_non_negative_int(row[3]),
        task_id=str(row[4]),
        task_state=str(row[5]),
        task_state_source=str(row[6]),
        fence=HandoffFence(
            restore_epoch=require_non_negative_int(row[7]),
            writer_generation=require_non_negative_int(row[8]),
        ),
        holder_harness_id=None if row[9] is None else str(row[9]),
        holder_principal=None if row[10] is None else str(row[10]),
        holder_session_ref=None if row[11] is None else str(row[11]),
        session_state=None if row[12] is None else str(row[12]),
        agent_ref=None if row[13] is None else str(row[13]),
        observed_ref=None if row[14] is None else str(row[14]),
        agent_updated_at=None if row[15] is None else str(row[15]),
        observed_through=None if row[16] is None else str(row[16]),
        events_since_agent=require_non_negative_int(row[19]),
    )
