"""Self-contained ``policy.db`` accounting authority and legacy ``(4,3) -> (5,4)`` migration (I3-4)."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    classify_policy_change_risk,
    policy_change_subject_id,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core._kernel_jobs import require_decimal
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import InvocationState, is_strict_int, require_aware_utc, require_opaque_id
from superbrain.storage import _policy_approvals as approvals
from superbrain.storage.cas import blob_path
from superbrain.storage.kinds import is_uuid
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.sqlite import open_readonly

__all__ = [
    "AccountingInvocationRecord",
    "AccountingLockRecord",
    "PolicyAccountingMixin",
    "ensure_accounting_schema",
    "sync_legacy_accounting_from_store",
]

_CAP_META_PREFIX = "accounting_cap:"
_ACCT_REV_META_KEY = "accounting_revision"
_INV_COLS = (
    "invocation_id, job_id, owner_id, writer_epoch, period_key, "
    "reserved_amount, settled_amount, state, recorded_at, updated_at"
)
_LOCK_COLS = (
    "lock_key, owner_id, period_key, backup_created_at, locked_at, state, reconciled_at, reconciled_approval_id"
)


@dataclass(frozen=True)
class AccountingInvocationRecord:
    invocation_id: str
    job_id: str
    owner_id: str
    writer_epoch: int
    period_key: str
    reserved_amount: str
    settled_amount: str | None
    state: InvocationState
    recorded_at: str
    updated_at: str


@dataclass(frozen=True)
class AccountingLockRecord:
    lock_key: str
    owner_id: str
    period_key: str
    backup_created_at: str
    locked_at: str
    state: str
    reconciled_at: str | None
    reconciled_approval_id: str | None


def canonical_decimal(value: Decimal) -> str:
    """Format a non-negative ``Decimal`` as the canonical string expected by ``require_decimal``."""
    norm = value.normalize()
    if norm == 0:
        return "0"
    rendered = format(norm, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def ensure_accounting_schema(db: sqlite3.Connection) -> None:
    """Ensure ``accounting_invocations`` and ``accounting_locks`` carry full I3-4 columns."""
    inv_cols = {str(r[1]) for r in db.execute("PRAGMA table_info(accounting_invocations)").fetchall()}
    if "owner_id" not in inv_cols:
        db.execute("DROP TABLE IF EXISTS accounting_invocations")
        db.execute(
            "CREATE TABLE accounting_invocations ("
            "invocation_id TEXT PRIMARY KEY, "
            "job_id TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "writer_epoch INTEGER NOT NULL, "
            "period_key TEXT NOT NULL, "
            "reserved_amount TEXT NOT NULL, "
            "settled_amount TEXT, "
            "state TEXT NOT NULL CHECK (state IN ('reserved', 'outcome_unknown', 'settled')), "
            "recorded_at TEXT NOT NULL, "
            "updated_at TEXT NOT NULL)"
        )
    lock_cols = {str(r[1]) for r in db.execute("PRAGMA table_info(accounting_locks)").fetchall()}
    if "period_key" not in lock_cols:
        db.execute("DROP TABLE IF EXISTS accounting_locks")
        db.execute(
            "CREATE TABLE accounting_locks ("
            "lock_key TEXT PRIMARY KEY, "
            "owner_id TEXT NOT NULL, "
            "period_key TEXT NOT NULL, "
            "backup_created_at TEXT NOT NULL, "
            "locked_at TEXT NOT NULL, "
            "state TEXT NOT NULL CHECK (state IN ('locked', 'reconciled')), "
            "reconciled_at TEXT, "
            "reconciled_approval_id TEXT)"
        )


def _decode_inv(row: tuple[object, ...]) -> AccountingInvocationRecord:
    inv_id, job_id, owner_id, epoch, period, reserved, settled, state, rec_at, upd_at = row
    if not isinstance(epoch, int):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "invalid writer_epoch in accounting_invocations")
    return AccountingInvocationRecord(
        invocation_id=str(inv_id),
        job_id=str(job_id),
        owner_id=str(owner_id),
        writer_epoch=epoch,
        period_key=str(period),
        reserved_amount=str(reserved),
        settled_amount=None if settled is None else str(settled),
        state=InvocationState(str(state)),
        recorded_at=str(rec_at),
        updated_at=str(upd_at),
    )


def _decode_lock(row: tuple[object, ...]) -> AccountingLockRecord:
    key, owner_id, period, bak_at, locked_at, state, rec_at, app_id = row
    return AccountingLockRecord(
        lock_key=str(key),
        owner_id=str(owner_id),
        period_key=str(period),
        backup_created_at=str(bak_at),
        locked_at=str(locked_at),
        state=str(state),
        reconciled_at=None if rec_at is None else str(rec_at),
        reconciled_approval_id=None if app_id is None else str(app_id),
    )


def _period_key(now: datetime) -> str:
    utc_dt, _ = require_aware_utc(now)
    return utc_dt.astimezone(UTC).strftime("%Y-%m-%d")


def _committed_sum(db: sqlite3.Connection, owner_id: str, period_key: str) -> Decimal:
    rows = db.execute(
        "SELECT state, reserved_amount, settled_amount FROM accounting_invocations "
        "WHERE owner_id = ? AND period_key = ?",
        (owner_id, period_key),
    ).fetchall()
    total = Decimal("0")
    for state, reserved, settled in rows:
        st = str(state)
        if st in ("reserved", "outcome_unknown"):
            total += Decimal(str(reserved))
        elif st == "settled":
            total += Decimal(str(settled if settled is not None else reserved))
    return total


def _read_descriptor_decimal(cas_dir: Path, digest: str, field: str) -> str:
    try:
        path = blob_path(cas_dir, digest)
    except BrainError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid CAS descriptor digest {digest!r}") from exc
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"missing CAS descriptor {digest}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid CAS descriptor file {digest}")
    try:
        raw_bytes = path.read_bytes()
        if digest_bytes(raw_bytes) != digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"corrupt CAS descriptor {digest}")
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"unreadable CAS descriptor {digest}") from exc
    if not isinstance(raw, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"malformed CAS descriptor {digest}")
    val = raw.get(field)
    if not isinstance(val, str):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"missing decimal {field!r} in CAS descriptor {digest}")
    try:
        require_decimal(val)
    except BrainError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid decimal {field!r} in CAS descriptor {digest}") from exc
    return val


def sync_legacy_accounting_from_store(policy_db_path: Path, root: DataRoot, *, now: datetime) -> None:
    """Copy existing ``p_provider_invocations_state`` rows from ``store/brain.db`` into upgraded ``policy.db``."""
    if not os.path.lexists(root.store_db):
        return
    store_db = open_readonly(root.store_db)
    try:
        tables = {str(r[0]) for r in store_db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not {"p_provider_invocations_state", "p_jobs_state"} <= tables:
            return
        rows = store_db.execute(
            "SELECT i.invocation_id, i.job_id, j.owner_id, i.writer_epoch, i.reservation_digest, "
            "i.state, i.usage_digest FROM p_provider_invocations_state i "
            "JOIN p_jobs_state j ON i.job_id = j.job_id"
        ).fetchall()
    finally:
        store_db.close()
    if not rows:
        return
    stamp = utc_timestamp(now)
    period = _period_key(now)
    pdb = sqlite3.connect(policy_db_path, isolation_level=None)
    try:
        pdb.execute("BEGIN IMMEDIATE")
        try:
            ensure_accounting_schema(pdb)
            for inv_id, job_id, owner_id, epoch, res_dig, state, usage_dig in rows:
                if not isinstance(res_dig, str):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "missing reservation_digest on legacy invocation")
                reserved = _read_descriptor_decimal(root.cas_dir, res_dig, "max_amount")
                settled: str | None = None
                if str(state) == InvocationState.SETTLED.value:
                    if not isinstance(usage_dig, str):
                        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "missing usage_digest on settled invocation")
                    settled = _read_descriptor_decimal(root.cas_dir, usage_dig, "amount")
                pdb.execute(
                    "INSERT OR IGNORE INTO accounting_invocations "
                    f"({_INV_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(inv_id),
                        str(job_id),
                        str(owner_id),
                        int(epoch),
                        period,
                        reserved,
                        settled,
                        str(state),
                        stamp,
                        stamp,
                    ),
                )
            pdb.execute("COMMIT")
        except BaseException:
            if pdb.in_transaction:
                pdb.execute("ROLLBACK")
            raise
    finally:
        pdb.close()


class PolicyAccountingMixin:
    """Self-contained accounting & lock reconciliation methods on ``PolicyStore`` (`policy v4+`)."""

    _store_id: str

    def _authority_tx(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def _read(self) -> sqlite3.Connection:
        raise NotImplementedError

    def _now(self) -> datetime:
        raise NotImplementedError

    def trust_generation(self) -> int:
        raise NotImplementedError

    def set_period_cap(self, owner_id: str, max_amount: str | None) -> None:
        require_opaque_id(owner_id, label="owner_id")
        if max_amount is not None:
            require_decimal(max_amount)
        key = f"{_CAP_META_PREFIX}{owner_id}"
        with self._authority_tx() as db:
            ensure_accounting_schema(db)
            if max_amount is None:
                db.execute("DELETE FROM meta WHERE key = ?", (key,))
            else:
                db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, max_amount))

    def period_cap(self, owner_id: str) -> str | None:
        require_opaque_id(owner_id, label="owner_id")
        row = (
            self._read()
            .execute("SELECT value FROM meta WHERE key = ?", (f"{_CAP_META_PREFIX}{owner_id}",))
            .fetchone()
        )
        return None if row is None else str(row[0])

    def reserve_accounting_invocation(
        self,
        *,
        invocation_id: str,
        job_id: str,
        owner_id: str,
        writer_epoch: int,
        max_amount: str,
        now: datetime,
    ) -> AccountingInvocationRecord:
        if not is_uuid(invocation_id) or not is_uuid(job_id) or not is_strict_int(writer_epoch) or writer_epoch < 1:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(owner_id, label="owner_id")
        require_decimal(max_amount)
        period = _period_key(now)
        stamp = utc_timestamp(now)
        with self._authority_tx() as db:
            ensure_accounting_schema(db)
            locked = db.execute(
                "SELECT 1 FROM accounting_locks WHERE state = 'locked' AND owner_id IN (?, '*') AND period_key = ? "
                "LIMIT 1",
                (owner_id, period),
            ).fetchone()
            if locked is not None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "accounting locked pending reconciliation")
            existing = db.execute(
                f"SELECT {_INV_COLS} FROM accounting_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            if existing is not None:
                rec = _decode_inv(tuple(existing))
                if (rec.job_id, rec.owner_id, rec.writer_epoch, rec.period_key, rec.reserved_amount) == (
                    job_id,
                    owner_id,
                    writer_epoch,
                    period,
                    max_amount,
                ):
                    return rec
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            cap_row = db.execute(
                "SELECT value FROM meta WHERE key = ?", (f"{_CAP_META_PREFIX}{owner_id}",)
            ).fetchone()
            if cap_row is not None and _committed_sum(db, owner_id, period) + Decimal(max_amount) > Decimal(
                str(cap_row[0])
            ):
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "period accounting cap exceeded")
            db.execute(
                f"INSERT INTO accounting_invocations ({_INV_COLS}) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                (
                    invocation_id,
                    job_id,
                    owner_id,
                    writer_epoch,
                    period,
                    max_amount,
                    InvocationState.RESERVED.value,
                    stamp,
                    stamp,
                ),
            )
            created = db.execute(
                f"SELECT {_INV_COLS} FROM accounting_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            assert created is not None
            return _decode_inv(tuple(created))

    def settle_accounting_invocation(
        self,
        *,
        invocation_id: str,
        amount: str | None,
        complete: bool,
        now: datetime,
    ) -> AccountingInvocationRecord:
        if not is_uuid(invocation_id) or type(complete) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if complete:
            require_decimal(amount)
        elif amount is not None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        stamp = utc_timestamp(now)
        with self._authority_tx() as db:
            ensure_accounting_schema(db)
            row = db.execute(
                f"SELECT {_INV_COLS} FROM accounting_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            if row is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            rec = _decode_inv(tuple(row))
            if rec.state is InvocationState.SETTLED:
                if complete and rec.settled_amount == amount:
                    return rec
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if not complete:
                if rec.state is InvocationState.OUTCOME_UNKNOWN:
                    return rec
                db.execute(
                    "UPDATE accounting_invocations SET state = ?, updated_at = ? WHERE invocation_id = ?",
                    (InvocationState.OUTCOME_UNKNOWN.value, stamp, invocation_id),
                )
            else:
                db.execute(
                    "UPDATE accounting_invocations SET state = ?, settled_amount = ?, updated_at = ? "
                    "WHERE invocation_id = ?",
                    (InvocationState.SETTLED.value, amount, stamp, invocation_id),
                )
            updated = db.execute(
                f"SELECT {_INV_COLS} FROM accounting_invocations WHERE invocation_id = ?",
                (invocation_id,),
            ).fetchone()
            assert updated is not None
            return _decode_inv(tuple(updated))

    def recover_accounting_epochs(self, *, current_epoch: int, now: datetime) -> int:
        if not is_strict_int(current_epoch) or current_epoch < 1:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        stamp = utc_timestamp(now)
        with self._authority_tx() as db:
            ensure_accounting_schema(db)
            cur = db.execute(
                "UPDATE accounting_invocations SET state = ?, updated_at = ? WHERE state = ? AND writer_epoch < ?",
                (InvocationState.OUTCOME_UNKNOWN.value, stamp, InvocationState.RESERVED.value, current_epoch),
            )
            return cur.rowcount

    def accounting_invocation(self, invocation_id: str) -> AccountingInvocationRecord | None:
        if not is_uuid(invocation_id):
            return None
        db = self._read()
        row = db.execute(
            f"SELECT {_INV_COLS} FROM accounting_invocations WHERE invocation_id = ?", (invocation_id,)
        ).fetchone()
        return None if row is None else _decode_inv(tuple(row))

    def list_accounting_invocations(
        self, *, owner_id: str | None = None, period_key: str | None = None
    ) -> tuple[AccountingInvocationRecord, ...]:
        db = self._read()
        clauses, params = [], []
        if owner_id is not None:
            clauses.append("owner_id = ?")
            params.append(owner_id)
        if period_key is not None:
            clauses.append("period_key = ?")
            params.append(period_key)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = db.execute(
            f"SELECT {_INV_COLS} FROM accounting_invocations {where} ORDER BY rowid", tuple(params)
        ).fetchall()
        return tuple(_decode_inv(tuple(r)) for r in rows)

    def list_accounting_locks(self, *, state: str | None = "locked") -> tuple[AccountingLockRecord, ...]:
        db = self._read()
        if state is None:
            rows = db.execute(f"SELECT {_LOCK_COLS} FROM accounting_locks ORDER BY period_key, lock_key").fetchall()
        else:
            rows = db.execute(
                f"SELECT {_LOCK_COLS} FROM accounting_locks WHERE state = ? ORDER BY period_key, lock_key", (state,)
            ).fetchall()
        return tuple(_decode_lock(tuple(r)) for r in rows)

    def period_committed_total(self, owner_id: str, period_key: str) -> str:
        require_opaque_id(owner_id, label="owner_id")
        db = self._read()
        return canonical_decimal(_committed_sum(db, owner_id, period_key))

    def policy_revision(self) -> int:
        db = self._read()
        c_intents = int(db.execute("SELECT COUNT(*) FROM intents").fetchone()[0])
        c_signers = int(db.execute("SELECT COUNT(*) FROM signer").fetchone()[0])
        c_locks = int(db.execute("SELECT COUNT(*) FROM accounting_locks").fetchone()[0])
        rev_row = db.execute("SELECT value FROM meta WHERE key = ?", (_ACCT_REV_META_KEY,)).fetchone()
        c_acct_rev = int(rev_row[0]) if rev_row is not None else 0
        return c_intents + c_signers + c_locks + c_acct_rev

    def reconcile_accounting_locks(
        self,
        *,
        repo_id_or_global: str = "global",
        base_policy_revision: int,
        base_restore_epoch: int,
        policy_diff_digest: str,
        approval: ApprovalMessage,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
        expected_restore_epoch: int | None = None,
    ) -> tuple[AccountingLockRecord, ...]:
        if expected_restore_epoch is not None and base_restore_epoch != expected_restore_epoch:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "stale restore_epoch")
        if base_policy_revision != self.policy_revision():
            raise BrainError(ErrorCode.REVISION_CONFLICT, "stale policy_revision")
        risk = classify_policy_change_risk(
            widens_capture_or_egress=False, sets_review_harness_or_command=False, reconcile_accounting=True
        )
        expected_subject = policy_change_subject_id(
            repo_id_or_global=repo_id_or_global,
            base_policy_revision=base_policy_revision,
            base_trust_generation=self.trust_generation(),
            base_restore_epoch=base_restore_epoch,
            policy_diff_digest=policy_diff_digest,
        )
        if (
            not isinstance(approval, ApprovalMessage)
            or approval.action is not ApprovalAction.POLICY_CHANGE
            or approval.risk_level is not risk
            or approval.risk_policy_version != RISK_POLICY_VERSION
            or tuple(approval.resource_digests) != (ResourceDigest("policy_diff", policy_diff_digest),)
            or approval.subject_id != expected_subject
        ):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "approval does not match policy_change subject")
        with self._authority_tx() as db:
            ensure_accounting_schema(db)
            receipt = approvals.consume_approval(
                db,
                approval,
                store_id=self._store_id,
                trust_generation=self.trust_generation(),
                signer_id=signer_id,
                channel=channel,
                now=self._now(),
                new_sign_count=new_sign_count,
                terminal_eligible=False,
            )
            stamp = utc_timestamp(self._now())
            locked_keys = [
                str(r[0])
                for r in db.execute(
                    "SELECT lock_key FROM accounting_locks WHERE state = 'locked' ORDER BY period_key, lock_key"
                ).fetchall()
            ]
            db.execute(
                "UPDATE accounting_locks SET state = 'reconciled', reconciled_at = ?, reconciled_approval_id = ? "
                "WHERE state = 'locked'",
                (stamp, receipt.approval_id),
            )
            rev_row = db.execute("SELECT value FROM meta WHERE key = ?", (_ACCT_REV_META_KEY,)).fetchone()
            next_rev = (int(rev_row[0]) if rev_row is not None else 0) + 1
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (_ACCT_REV_META_KEY, str(next_rev)))
            if not locked_keys:
                return ()
            placeholders = ",".join("?" for _ in locked_keys)
            rows = db.execute(
                f"SELECT {_LOCK_COLS} FROM accounting_locks WHERE lock_key IN ({placeholders}) ORDER BY period_key",
                tuple(locked_keys),
            ).fetchall()
            return tuple(_decode_lock(tuple(r)) for r in rows)
