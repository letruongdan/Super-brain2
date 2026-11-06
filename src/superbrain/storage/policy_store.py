"""The policy store (spec 5.3, 5.4, 5.7): security intents and the trust generation, in ``policy/policy.db``.

Security state goes first. ``record_intent`` commits a tombstone or quarantine intent together with its effect row
in one transaction, and the content is blocked from that commit on (``is_tombstoned``/``is_quarantined``). The main
store applies the intent's ledger effects later, in ``Store.reconcile_policy``, and is the only place that records
an intent as applied: nothing here knows or stores whether an intent has been applied.

``trust_generation`` never goes back: ``writer.lock`` keeps its high-water mark and every open re-aligns the two.
Like ``Store``, a ``PolicyStore`` belongs to the thread that created or opened it and refuses work once its lease
was released.
"""

import json
import os
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    AuthSnapshot,
    BootstrapAuthorization,
    Principal,
    Scope,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage import backup
from superbrain.storage._policy_authority import (
    build_policy_snapshot,
    policy_allows,
    read_policy_request_digest_key,
    resolve_policy_credential,
)
from superbrain.storage._policy_mutations import (
    record_policy_authorized_revocation,
    register_policy_authorized_workspace,
)
from superbrain.storage.errors import sqlite_error
from superbrain.storage.identity import validate_policy_intent_payload
from superbrain.storage.kinds import CORE_KINDS, KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.schema import (
    POLICY_MIGRATIONS,
    Migration,
    ensure_writable,
    initialize,
    read_schema_info,
    readmit_writable,
)
from superbrain.storage.sqlite import CREATING, connect, db_files, remove_unfinished_creates
from superbrain.storage.writer import WriterLease

_HANDLE = "policy"
STORE_PUBLISHED = "store_published"
"""``meta`` key set to ``'1'`` once the main store bound to this policy store was published (C02 lifecycle marker)."""
# The payload of each intent kind, and the reserved ledger kind whose schema (plus ``intent_id``) validates it.
_PAYLOAD_FIELDS: dict[IntentKind, tuple[str, ...]] = {
    IntentKind.TOMBSTONE: ("holder_kind", "holder_id"),
    IntentKind.QUARANTINE: ("digest",),
}
_EFFECT_KIND: dict[IntentKind, str] = {
    IntentKind.TOMBSTONE: "policy.tombstone",
    IntentKind.QUARANTINE: "policy.quarantine",
}
_CORE = KindRegistry(CORE_KINDS)


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("the policy store needs a held writer lease for this data root")


def _validated_payload(kind: object, payload: object, intent_id: str) -> dict[str, JsonValue]:
    """The payload of an intent of ``kind``, checked against its effect's ledger schema; else ``INVALID_INPUT``.

    TOMBSTONE takes exactly ``holder_kind`` (a ``cas.hold`` holder kind) and ``holder_id`` (a UUID); QUARANTINE
    takes exactly ``digest``. Authorized kernel intents (``CREDENTIAL_REVOKE``, ``WORKSPACE_REGISTER``) cannot be
    submitted through generic ``record_intent``.
    """
    if not isinstance(kind, IntentKind) or kind not in _PAYLOAD_FIELDS:
        raise BrainError(ErrorCode.INVALID_INPUT, f"{kind!r} is not an allowed generic IntentKind")
    if not isinstance(payload, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, f"a {kind} payload must be an object")
    fields = _PAYLOAD_FIELDS[kind]
    if set(payload) != set(fields):
        raise BrainError(ErrorCode.INVALID_INPUT, f"a {kind} payload takes exactly {list(fields)}")
    checked: dict[str, JsonValue] = {name: payload[name] for name in fields}
    _CORE.validate(_EFFECT_KIND[kind], {**checked, "intent_id": intent_id})
    return checked


def _decode_intent(row: Sequence[object]) -> Intent:
    intent_id, kind, payload, created_at = row
    try:
        if not isinstance(intent_id, str) or not isinstance(created_at, str) or not isinstance(payload, bytes):
            raise BrainError(ErrorCode.INVALID_INPUT, "a column has the wrong type")
        decoded = json.loads(payload)
        intent_kind = IntentKind(str(kind))
        checked = validate_policy_intent_payload(intent_kind, decoded, intent_id)
    except (BrainError, ValueError) as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"policy intent {intent_id!r} is malformed: {exc}") from exc
    return Intent(intent_id=intent_id, kind=intent_kind, payload=checked, created_at=created_at)


class PolicyStore:
    """Implements ``PolicySource``. Obtain it with ``create`` or ``open``; ``close`` it when done."""

    def __init__(
        self, *, root: DataRoot, lease: WriterLease, os_: OsAdapters, db: sqlite3.Connection, store_id: str
    ) -> None:
        self._owner = threading.get_ident()
        self._root = root
        self._lease = lease
        self._os = os_
        self._db = db
        self._store_id = store_id
        self._closed = False

    # --- lifecycle ---------------------------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        *,
        store_id: str,
        migrations: Sequence[Migration] = POLICY_MIGRATIONS,
    ) -> "PolicyStore":
        """Create a new policy store bound to the main store ``store_id``, then open it.

        As in ``Store.create``, the database (with its trust row, ``generation = hwm + 1``, or 1 on a fresh lock, so
        strictly above every generation already issued) is built at
        ``policy.db.creating-<id>``, closed and only then published as ``policy.db``; leftover ``creating-*``
        files are removed first. An existing ``policy.db`` (or ``-wal``/``-shm``) is ``INVALID_INPUT``.
        """
        _check_lease(root, lease)
        if type(store_id) is not str or not store_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "store_id must be a non-empty string")
        path = root.policy_db
        if any(os.path.lexists(p) for p in db_files(path)):
            raise BrainError(ErrorCode.INVALID_INPUT, f"a policy store already exists at {path}")
        lease.register_handle(_HANDLE)
        try:
            remove_unfinished_creates(path)
            staging = path.with_name(f"{path.name}{CREATING}{new_id()}")
            db = connect(staging)
            try:
                initialize(db, migrations, store_id=store_id)
                hwm = lease.state().trust_generation_hwm
                generation = hwm + 1 if hwm >= 1 else 1
                try:
                    db.execute("INSERT INTO trust (id, generation) VALUES (1, ?)", (generation,))
                except sqlite3.Error as exc:
                    raise sqlite_error("cannot write the trust generation", exc) from exc
            finally:
                db.close()
            if any(os.path.lexists(p) for p in db_files(staging)[1:]):
                raise BrainError(ErrorCode.IO_ERROR, f"{staging}: the WAL was not checkpointed away on close")
            os_.permissions.secure_file(staging)
            os_.publisher.publish(staging, path)
            return cls._open_registered(root, lease, os_, migrations)
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise

    @classmethod
    def open(
        cls,
        root: DataRoot,
        lease: WriterLease,
        os_: OsAdapters,
        *,
        migrations: Sequence[Migration] = POLICY_MIGRATIONS,
    ) -> "PolicyStore":
        """Open the existing policy store for writing (its schema must equal the code's): ``NOT_FOUND`` if missing.

        The trust generation is re-aligned with the lock's high-water mark: one below it becomes ``hwm + 1``
        (persisted here first, then in the lock); one above it raises the lock's mark to it.
        """
        _check_lease(root, lease)
        lease.register_handle(_HANDLE)
        try:
            return cls._open_registered(root, lease, os_, migrations)
        except BaseException:
            lease.unregister_handle(_HANDLE)
            raise

    @classmethod
    def _open_registered(
        cls, root: DataRoot, lease: WriterLease, os_: OsAdapters, migrations: Sequence[Migration]
    ) -> "PolicyStore":
        """``open`` once the ``policy`` handle is registered; the caller unregisters it on failure."""
        path = root.policy_db
        info = read_schema_info(path)
        if info is None:
            raise BrainError(ErrorCode.NOT_FOUND, f"no policy store at {path}")
        ensure_writable(info, migrations)
        db = connect(path)
        try:
            readmit_writable(db, path, info, migrations)
            policy = cls(root=root, lease=lease, os_=os_, db=db, store_id=info.store_id)
            for file in db_files(path):
                if file.exists():
                    os_.permissions.secure_file(file)
            policy._align_trust_generation()
        except BaseException:
            db.close()
            raise
        return policy

    def _align_trust_generation(self) -> None:
        hwm = self._lease.state().trust_generation_hwm
        generation = self.trust_generation()
        if generation < hwm:
            self._write_generation(hwm + 1)
            self._lease.raise_trust_hwm(hwm + 1)
        elif generation > hwm:
            self._lease.raise_trust_hwm(generation)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._check()
        self._closed = True
        try:
            self._db.close()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot close the policy store", exc) from exc
        finally:
            self._lease.unregister_handle(_HANDLE)

    @property
    def root(self) -> DataRoot:
        self._check()
        return self._root

    def snapshot_db(self, dest: Path) -> None:
        """Copy the live database, as of now, into the new self-contained file ``dest`` (``backup._snapshot_db``)."""
        self._check()
        backup._snapshot_db(self._db, dest, self._os)

    # --- PolicySource --------------------------------------------------------------------------------------------

    @property
    def store_id(self) -> str:
        """The id of the main store this policy store belongs to."""
        self._check()
        return self._store_id

    def is_quarantined(self, digest: str) -> bool:
        self._check()
        return self._exists("SELECT 1 FROM quarantine WHERE digest = ?", (digest,))

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        self._check()
        return self._exists(
            "SELECT 1 FROM tombstones WHERE holder_kind = ? AND holder_id = ?", (holder_kind, holder_id)
        )

    def intents(self) -> Sequence[Intent]:
        """Every recorded intent, in the order it was recorded (not by ``created_at``: the clock may go back)."""
        self._check()
        rows = self._query("SELECT intent_id, kind, payload, created_at FROM intents ORDER BY rowid", ())
        return [_decode_intent(row) for row in rows]

    def tombstones(self) -> list[tuple[str, str]]:
        """Every tombstoned ``(holder_kind, holder_id)``, sorted."""
        self._check()
        rows = self._query("SELECT holder_kind, holder_id FROM tombstones ORDER BY holder_kind, holder_id", ())
        return [(str(kind), str(holder)) for kind, holder in rows]

    # --- intents and trust -----------------------------------------------------------------------------------

    def record_intent(self, kind: IntentKind, payload: Mapping[str, JsonValue]) -> Intent:
        """Record a TOMBSTONE or QUARANTINE intent and its effect row in one transaction; the content is blocked
        from the commit on. The payload is validated before anything is written (``INVALID_INPUT``).

        An already tombstoned holder or quarantined digest keeps its effect row; the new intent is still recorded.
        The main store's ledger effects follow in ``Store.reconcile_policy``, which this does not call.
        """
        self._check()
        intent_id = new_id()
        checked = _validated_payload(kind, payload, intent_id)
        intent = Intent(
            intent_id=intent_id,
            kind=kind,
            payload=checked,
            created_at=utc_timestamp(self._os.clock.now()),
        )
        with self._immediate() as db:
            db.execute(
                "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (intent_id, kind.value, canonical_json(checked), intent.created_at),
            )
            if kind is IntentKind.TOMBSTONE:
                db.execute(
                    "INSERT OR IGNORE INTO tombstones (holder_kind, holder_id, intent_id) VALUES (?, ?, ?)",
                    (checked["holder_kind"], checked["holder_id"], intent_id),
                )
            else:
                db.execute(
                    "INSERT OR IGNORE INTO quarantine (digest, intent_id) VALUES (?, ?)",
                    (checked["digest"], intent_id),
                )
        crashpoint("policy.after_intent_commit")
        return intent

    def mark_store_published(self) -> None:
        """Record durably that the main store bound to this policy store was published (``meta.store_published``).

        Idempotent: once set it is never written again or cleared. ``open_runtime`` calls it after every successful
        ``Store.create``/``Store.open``, and refuses to re-create a missing ``brain.db`` once it is set (C02).
        The commit is durable (``synchronous=FULL``); the one-time write is then checkpointed so the WAL is empty
        again, as after ``create``, and later reads leave the database files as they are.
        """
        self._check()
        if self.store_published():
            return
        with self._immediate() as db:
            db.execute("INSERT INTO meta (key, value) VALUES (?, '1')", (STORE_PUBLISHED,))
        try:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot checkpoint the policy store", exc) from exc

    def store_published(self) -> bool:
        self._check()
        return self._exists("SELECT 1 FROM meta WHERE key = ? AND value = '1'", (STORE_PUBLISHED,))

    def trust_generation(self) -> int:
        self._check()
        rows = self._query("SELECT generation FROM trust WHERE id = 1", ())
        if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the policy store has no valid trust generation")
        return rows[0][0]

    # --- KernelPolicyPort --------------------------------------------------------------------------------------

    def resolve_credential(self, token: str) -> Principal:
        self._check_kernel_available()
        return resolve_policy_credential(self._db, token)

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        self._check_kernel_available()
        return policy_allows(self._db, principal, scope, action=action)

    def snapshot(self) -> AuthSnapshot:
        self._check_kernel_available()
        gen = self._kernel_trust_generation()
        return build_policy_snapshot(self._db, store_id=self._store_id, trust_generation=gen)

    def record_authorized_revocation(
        self, credential_id: str, authorization: BootstrapAuthorization
    ) -> Intent:
        self._check_kernel_available()
        return record_policy_authorized_revocation(
            self._db,
            self._immediate,
            _decode_intent,
            credential_id=credential_id,
            authorization=authorization,
            store_id=self._store_id,
            trust_generation=self._kernel_trust_generation(),
            now=self._os.clock.now(),
        )

    def register_authorized_workspace(
        self, registration: WorkspaceRegistration, authorization: BootstrapAuthorization
    ) -> WorkspaceBinding:
        self._check_kernel_available()
        return register_policy_authorized_workspace(
            self._db,
            self._immediate,
            _decode_intent,
            registration=registration,
            authorization=authorization,
            store_id=self._store_id,
            trust_generation=self._kernel_trust_generation(),
            now=self._os.clock.now(),
        )

    def request_digest_key(self) -> tuple[str, bytes]:
        self._check_kernel_available()
        return read_policy_request_digest_key(self._db)

    # --- internals ---------------------------------------------------------------------------------------------

    def _kernel_trust_generation(self) -> int:
        try:
            return self.trust_generation()
        except BrainError as exc:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable") from exc

    def _check_kernel_available(self) -> None:
        if threading.get_ident() != self._owner:
            raise AssertionError("policy store used off its owner thread")
        if self._closed or not self._lease.held:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

    def _check(self) -> None:
        if self._closed:
            raise AssertionError("policy store closed")
        if not self._lease.held:
            raise AssertionError("policy store used after its writer lease was released")
        if threading.get_ident() != self._owner:
            raise AssertionError("policy store used off its owner thread")

    def _write_generation(self, value: int) -> None:
        with self._immediate() as db:
            cursor = db.execute("UPDATE trust SET generation = ? WHERE id = 1", (value,))
            if cursor.rowcount != 1:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the policy store has no trust row")

    def _exists(self, sql: str, params: tuple[str, ...]) -> bool:
        return bool(self._query(sql, params))

    def _query(self, sql: str, params: tuple[str, ...]) -> list[tuple[object, ...]]:
        try:
            return self._db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the policy store", exc) from exc

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        """``BEGIN IMMEDIATE`` ... ``COMMIT``: SQLite errors are mapped by ``sqlite_error`` (a busy ``BEGIN`` is
        ``STORE_BUSY``); any exception rolls back."""
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise sqlite_error("cannot begin a policy transaction", exc, busy=True) from exc
        try:
            try:
                yield self._db
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                raise sqlite_error("cannot write the policy store", exc) from exc
        except BaseException:
            if self._db.in_transaction:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise sqlite_error("cannot roll back the policy transaction", exc) from exc
            raise
