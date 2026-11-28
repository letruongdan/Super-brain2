"""Policy v5 session HMAC key, append-only ``session_ref_bindings``, and restore stage hook (SP2-3)."""

from __future__ import annotations

import os
import sqlite3
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path

from superbrain.core._kernel_base import require_opaque_id, require_sha256_digest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import require_aware_utc
from superbrain.ports.continuity import SESSION_HMAC_KEY_BYTES, SessionBindingRecord
from superbrain.storage.backup import BackupManifest
from superbrain.storage.errors import sqlite_error
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.sqlite import open_readonly


def apply_policy_v5(db: sqlite3.Connection) -> None:
    """Policy store v5 DDL: per-store 32-byte ``session_hmac_key`` and append-only ``session_ref_bindings``."""
    db.execute(
        "CREATE TABLE session_hmac_key ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), "
        "key_id TEXT NOT NULL, "
        "secret BLOB NOT NULL CHECK (length(secret) = 32), "
        "created_at TEXT NOT NULL)"
    )
    db.execute(
        "INSERT INTO session_hmac_key (id, key_id, secret, created_at) VALUES (1, ?, ?, ?)",
        (new_id(), os.urandom(32), "1970-01-01T00:00:00.000000Z"),
    )
    db.execute(
        "CREATE TABLE session_ref_bindings ("
        "session_ref TEXT PRIMARY KEY, "
        "principal_id TEXT NOT NULL, "
        "repo_id TEXT, "
        "checkout_id TEXT, "
        "harness_id TEXT, "
        "bound_at TEXT NOT NULL)"
    )
    db.execute("CREATE INDEX idx_session_ref_bindings_principal ON session_ref_bindings (principal_id)")


def _decode_binding(row: tuple[object, ...]) -> SessionBindingRecord:
    return SessionBindingRecord(
        session_ref=str(row[0]),
        principal_id=str(row[1]),
        repo_id=None if row[2] is None else str(row[2]),
        checkout_id=None if row[3] is None else str(row[3]),
        harness_id=None if row[4] is None else str(row[4]),
        bound_at=str(row[5]),
    )


class PolicySessionMixin:
    """``PolicyStore`` methods for policy v5 HMAC session keys and append-only session bindings."""

    _db: sqlite3.Connection
    _schema_version: int

    def _check(self) -> None:
        raise NotImplementedError

    def _immediate(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def _require_v5_session_tables(self) -> None:
        self._check()
        if self._schema_version < 5:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def session_hmac_key(self) -> bytes:
        """Return the 32-byte per-store secret HMAC key used to derive opaque ``session_ref`` digests."""
        self._require_v5_session_tables()
        try:
            row = self._db.execute("SELECT secret FROM session_hmac_key WHERE id = 1").fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read session_hmac_key", exc) from exc
        if row is None or not isinstance(row[0], (bytes, bytearray)) or len(row[0]) != SESSION_HMAC_KEY_BYTES:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "invalid session_hmac_key in policy store")
        return bytes(row[0])

    def lookup_session_binding(self, session_ref: str) -> SessionBindingRecord | None:
        """Read-only lookup of a ``session_ref`` binding in ``policy.db``."""
        self._require_v5_session_tables()
        require_sha256_digest(session_ref)
        try:
            row = self._db.execute(
                "SELECT session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at "
                "FROM session_ref_bindings WHERE session_ref = ?",
                (session_ref,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot query session_ref_bindings", exc) from exc
        return None if row is None else _decode_binding(tuple(row))

    def list_session_bindings(self) -> tuple[SessionBindingRecord, ...]:
        """Return every persisted session binding ordered deterministically by ``bound_at, session_ref``."""
        self._require_v5_session_tables()
        try:
            rows = self._db.execute(
                "SELECT session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at "
                "FROM session_ref_bindings ORDER BY bound_at, session_ref"
            ).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot list session_ref_bindings", exc) from exc
        return tuple(_decode_binding(tuple(r)) for r in rows)

    def repo_policy_flags(self, repo_id: str) -> tuple[str | None, bool, bool]:
        """Return ``(owner_id, automatic_capture_enabled, manual_submission_enabled)`` fail-closed."""
        self._check()
        require_opaque_id(repo_id, label="repo_id")
        if self._schema_version < 2:
            return None, False, False
        try:
            row = self._db.execute(
                "SELECT owner_id, automatic_capture_enabled, manual_submission_enabled "
                "FROM repo_policy WHERE repo_id = ?",
                (repo_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot query repo_policy flags", exc) from exc
        if row is None:
            return None, False, False
        return str(row[0]), int(row[1]) == 1, int(row[2]) == 1

    def bind_or_verify_session_ref(
        self,
        session_ref: str,
        *,
        principal_id: str,
        repo_id: str | None = None,
        checkout_id: str | None = None,
        harness_id: str | None = None,
        now: datetime,
    ) -> SessionBindingRecord:
        """Bind ``session_ref -> principal_id`` append-only or reject hijacking with ``IDENTITY_MISMATCH``."""
        self._require_v5_session_tables()
        require_sha256_digest(session_ref)
        require_opaque_id(principal_id, label="principal_id")
        if repo_id is not None:
            require_opaque_id(repo_id, label="repo_id")
        if checkout_id is not None:
            require_opaque_id(checkout_id, label="checkout_id")
        if harness_id is not None:
            require_opaque_id(harness_id, label="harness_id")
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)

        with self._immediate() as db:
            row = db.execute(
                "SELECT session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at "
                "FROM session_ref_bindings WHERE session_ref = ?",
                (session_ref,),
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO session_ref_bindings "
                    "(session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (session_ref, principal_id, repo_id, checkout_id, harness_id, stamp),
                )
                return SessionBindingRecord(
                    session_ref=session_ref,
                    principal_id=principal_id,
                    repo_id=repo_id,
                    checkout_id=checkout_id,
                    harness_id=harness_id,
                    bound_at=stamp,
                )

            existing = _decode_binding(tuple(row))
            if existing.principal_id != principal_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session_ref bound to different principal")
            if existing.repo_id is not None and repo_id is not None and existing.repo_id != repo_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session_ref bound to different repo_id")
            if existing.checkout_id is not None and checkout_id is not None and existing.checkout_id != checkout_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session_ref bound to different checkout_id")

            next_repo = existing.repo_id if existing.repo_id is not None else repo_id
            next_chk = existing.checkout_id if existing.checkout_id is not None else checkout_id
            next_harness = existing.harness_id if existing.harness_id is not None else harness_id
            if (next_repo, next_chk, next_harness) != (existing.repo_id, existing.checkout_id, existing.harness_id):
                db.execute(
                    "UPDATE session_ref_bindings SET repo_id = ?, checkout_id = ?, harness_id = ? "
                    "WHERE session_ref = ?",
                    (next_repo, next_chk, next_harness, session_ref),
                )
            return SessionBindingRecord(
                session_ref=existing.session_ref,
                principal_id=existing.principal_id,
                repo_id=next_repo,
                checkout_id=next_chk,
                harness_id=next_harness,
                bound_at=existing.bound_at,
            )


class SessionPolicyRestoreStageHook:
    """Carry forward ``session_hmac_key`` and ``session_ref_bindings`` from live ``policy.db`` during restore."""

    def on_stage_policy(
        self,
        live_policy_db: Path | None,
        staged_policy_db: sqlite3.Connection,
        *,
        manifest: BackupManifest,
        now: datetime,
        trust_generation: int,
    ) -> None:
        _ = manifest, now, trust_generation
        if live_policy_db is None or not os.path.lexists(live_policy_db):
            return
        staged_tables = {
            str(r[0]) for r in staged_policy_db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if not {"session_hmac_key", "session_ref_bindings"} <= staged_tables:
            return
        try:
            live_db = open_readonly(live_policy_db)
        except (BrainError, sqlite3.Error):
            return
        try:
            live_tables = {
                str(r[0]) for r in live_db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            if "session_hmac_key" in live_tables:
                key_row = live_db.execute(
                    "SELECT key_id, secret, created_at FROM session_hmac_key WHERE id = 1"
                ).fetchone()
                if key_row is not None:
                    staged_policy_db.execute(
                        "INSERT INTO session_hmac_key (id, key_id, secret, created_at) VALUES (1, ?, ?, ?) "
                        "ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id, secret = excluded.secret, "
                        "created_at = excluded.created_at",
                        (str(key_row[0]), bytes(key_row[1]), str(key_row[2])),
                    )
            if "session_ref_bindings" in live_tables:
                rows = live_db.execute(
                    "SELECT session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at "
                    "FROM session_ref_bindings"
                ).fetchall()
                for row in rows:
                    sref = str(row[0])
                    prin = str(row[1])
                    existing = staged_policy_db.execute(
                        "SELECT principal_id FROM session_ref_bindings WHERE session_ref = ?",
                        (sref,),
                    ).fetchone()
                    if existing is None:
                        staged_policy_db.execute(
                            "INSERT INTO session_ref_bindings "
                            "(session_ref, principal_id, repo_id, checkout_id, harness_id, bound_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (sref, prin, row[2], row[3], row[4], str(row[5])),
                        )
                    elif str(existing[0]) != prin:
                        raise BrainError(
                            ErrorCode.IDENTITY_MISMATCH,
                            "session_ref binding conflict between live policy and backup",
                        )
        finally:
            live_db.close()


__all__ = [
    "PolicySessionMixin",
    "SessionPolicyRestoreStageHook",
    "apply_policy_v5",
]
