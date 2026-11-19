"""Task 4c storage adapter and SQLite helpers for ``artifact_send_attempt`` and ``artifact_read_ack`` (C5)."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    ArtifactReadAck,
    ArtifactSendAttempt,
    ArtifactSendSpec,
    Identity,
    SendAttemptCompletion,
    SendAttemptState,
    canonicalize_resource_digests,
    decode_resource_digests_json,
    is_strict_int,
    require_opaque_id,
)
from superbrain.ports.kernel import KernelSendAttemptPort
from superbrain.storage._pair_admission import verify_admitted_store_pair, verify_live_store_handle
from superbrain.storage.errors import sqlite_error
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


def read_send_attempt_row(db: sqlite3.Connection, send_attempt_id: str) -> ArtifactSendAttempt | None:
    """Read and decode ``artifact_send_attempt`` by primary key ``send_attempt_id``."""
    require_opaque_id(send_attempt_id, label="send_attempt_id")
    try:
        row = db.execute(
            "SELECT id, logical_result_id, principal_id, task_id, artifact_id, revision, digests_json, state "
            "FROM artifact_send_attempt WHERE id = ?",
            (send_attempt_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read artifact_send_attempt row", exc) from exc
    if row is None:
        return None
    raw_id, raw_res_id, raw_principal, raw_task, raw_artifact, raw_rev, raw_digests_json, raw_state = row
    if (
        not isinstance(raw_id, str)
        or not isinstance(raw_res_id, str)
        or not isinstance(raw_principal, str)
        or not isinstance(raw_task, str)
        or not isinstance(raw_artifact, str)
        or not is_strict_int(raw_rev)
        or not isinstance(raw_digests_json, str)
        or not isinstance(raw_state, str)
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    digests = decode_resource_digests_json(raw_digests_json)
    try:
        state = SendAttemptState(raw_state)
        return ArtifactSendAttempt(
            send_attempt_id=raw_id,
            logical_result_id=raw_res_id,
            principal_id=raw_principal,
            task_id=raw_task,
            artifact_id=raw_artifact,
            revision=raw_rev,
            resource_digests=digests,
            state=state,
        )
    except (ValueError, BrainError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err


def insert_send_attempt_row(db: sqlite3.Connection, attempt: ArtifactSendAttempt) -> None:
    """Insert ``attempt`` into ``artifact_send_attempt``."""
    if not isinstance(attempt, ArtifactSendAttempt):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _, digests_json = canonicalize_resource_digests(attempt.resource_digests)
    try:
        db.execute(
            "INSERT INTO artifact_send_attempt "
            "(id, logical_result_id, principal_id, task_id, artifact_id, revision, digests_json, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attempt.send_attempt_id,
                attempt.logical_result_id,
                attempt.principal_id,
                attempt.task_id,
                attempt.artifact_id,
                attempt.revision,
                digests_json,
                attempt.state.value,
            ),
        )
    except sqlite3.Error as exc:
        raise sqlite_error("cannot insert artifact_send_attempt row", exc) from exc


def read_read_ack_by_receipt_row(db: sqlite3.Connection, served_receipt_id: str) -> ArtifactReadAck | None:
    """Read and decode ``artifact_read_ack`` by unique ``served_receipt_id``."""
    require_opaque_id(served_receipt_id, label="served_receipt_id")
    try:
        row = db.execute(
            "SELECT a.id, a.served_receipt_id, a.principal_id, a.task_id, s.artifact_id, a.revision, a.digests_json "
            "FROM artifact_read_ack AS a "
            "LEFT JOIN artifact_send_attempt AS s ON s.id = a.served_receipt_id "
            "WHERE a.served_receipt_id = ?",
            (served_receipt_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read artifact_read_ack row", exc) from exc
    if row is None:
        return None
    raw_id, raw_receipt, raw_principal, raw_task, raw_artifact, raw_rev, raw_digests_json = row
    if (
        not isinstance(raw_id, str)
        or not isinstance(raw_receipt, str)
        or not isinstance(raw_principal, str)
        or not isinstance(raw_task, str)
        or not isinstance(raw_artifact, str)
        or not is_strict_int(raw_rev)
        or not isinstance(raw_digests_json, str)
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    digests = decode_resource_digests_json(raw_digests_json)
    try:
        return ArtifactReadAck(
            ack_id=raw_id,
            served_receipt_id=raw_receipt,
            principal_id=raw_principal,
            task_id=raw_task,
            artifact_id=raw_artifact,
            revision_epoch=0,
            revision=raw_rev,
            resource_digests=digests,
        )
    except BrainError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err


def insert_read_ack_row(db: sqlite3.Connection, ack: ArtifactReadAck) -> None:
    """Insert ``ack`` into ``artifact_read_ack``."""
    if not isinstance(ack, ArtifactReadAck):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _, digests_json = canonicalize_resource_digests(ack.resource_digests)
    try:
        db.execute(
            "INSERT INTO artifact_read_ack "
            "(id, served_receipt_id, principal_id, task_id, revision, digests_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                ack.ack_id,
                ack.served_receipt_id,
                ack.principal_id,
                ack.task_id,
                ack.revision,
                digests_json,
            ),
        )
    except sqlite3.Error as exc:
        raise sqlite_error("cannot insert artifact_read_ack row", exc) from exc


class KernelSendAttemptStore(KernelSendAttemptPort):
    """Owner-thread operational ``artifact_send_attempt`` store over ``store4`` (C5)."""

    def __init__(
        self,
        store: Store,
        policy_store: PolicyStore | None = None,
        *,
        writer_epoch: int | None = None,
    ) -> None:
        self._store = store
        self._policy_store = policy_store
        self._writer_epoch = writer_epoch
        self._check_live()

    def _check_live(self) -> None:
        if self._policy_store is not None:
            verify_admitted_store_pair(self._store, self._policy_store, writer_epoch=self._writer_epoch)
        else:
            verify_live_store_handle(self._store, writer_epoch=self._writer_epoch)

    def record_pending_attempt(self, spec: ArtifactSendSpec) -> ArtifactSendAttempt:
        self._check_live()
        if not isinstance(spec, ArtifactSendSpec):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        attempt = ArtifactSendAttempt(
            send_attempt_id=new_id(),
            logical_result_id=spec.logical_result_id,
            principal_id=spec.principal_id,
            task_id=spec.task_id,
            artifact_id=spec.artifact_id,
            revision=spec.revision,
            resource_digests=spec.resource_digests,
            state=SendAttemptState.PENDING,
        )
        with self._store.transaction() as txn:
            insert_send_attempt_row(txn.db, attempt)
        return attempt

    def read_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt | None:
        self._check_live()
        with self._store.transaction() as txn:
            return read_send_attempt_row(txn.db, send_attempt_id)

    def finalize_attempt(
        self,
        completion: SendAttemptCompletion,
        *,
        expected_identity: Identity,
    ) -> ArtifactSendAttempt:
        self._check_live()
        if not isinstance(completion, SendAttemptCompletion) or not isinstance(expected_identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if (
            completion.identity.store_id != expected_identity.store_id
            or completion.identity.store_id != self._store.store_id
        ):
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
        if (
            completion.identity.writer_epoch != expected_identity.writer_epoch
            or completion.identity.instance_id != expected_identity.instance_id
        ):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

        with self._store.transaction() as txn:
            existing = read_send_attempt_row(txn.db, completion.send_attempt_id)
            if existing is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if (
                existing.logical_result_id,
                existing.principal_id,
                existing.task_id,
                existing.artifact_id,
                existing.level,
                existing.revision_epoch,
                existing.revision,
                existing.resource_digests,
            ) != (
                completion.logical_result_id,
                completion.principal_id,
                completion.task_id,
                completion.artifact_id,
                completion.level,
                completion.revision_epoch,
                completion.revision,
                completion.resource_digests,
            ):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

            if existing.state is SendAttemptState.SERVED_ONLY:
                return existing
            if existing.state is SendAttemptState.UNKNOWN:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

            try:
                cur = txn.db.execute(
                    "UPDATE artifact_send_attempt SET state = ? WHERE id = ? AND state = ?",
                    (
                        SendAttemptState.SERVED_ONLY.value,
                        existing.send_attempt_id,
                        SendAttemptState.PENDING.value,
                    ),
                )
            except sqlite3.Error as exc:
                raise sqlite_error("cannot finalize artifact_send_attempt row", exc) from exc
            if cur.rowcount != 1:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            return replace(existing, state=SendAttemptState.SERVED_ONLY)

    def interrupt_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt:
        self._check_live()
        with self._store.transaction() as txn:
            existing = read_send_attempt_row(txn.db, send_attempt_id)
            if existing is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if existing.state is SendAttemptState.UNKNOWN:
                return existing
            if existing.state is SendAttemptState.SERVED_ONLY:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            try:
                cur = txn.db.execute(
                    "UPDATE artifact_send_attempt SET state = ? WHERE id = ? AND state = ?",
                    (
                        SendAttemptState.UNKNOWN.value,
                        existing.send_attempt_id,
                        SendAttemptState.PENDING.value,
                    ),
                )
            except sqlite3.Error as exc:
                raise sqlite_error("cannot interrupt artifact_send_attempt row", exc) from exc
            if cur.rowcount != 1:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            return replace(existing, state=SendAttemptState.UNKNOWN)

    def recover_pending_attempts(self) -> int:
        self._check_live()
        with self._store.transaction() as txn:
            try:
                cur = txn.db.execute(
                    "UPDATE artifact_send_attempt SET state = ? WHERE state = ?",
                    (SendAttemptState.UNKNOWN.value, SendAttemptState.PENDING.value),
                )
                return int(cur.rowcount)
            except sqlite3.Error as exc:
                raise sqlite_error("cannot recover pending artifact_send_attempt rows", exc) from exc
