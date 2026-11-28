# SP2-4 Review Fix Note (`cbd9bf7` → Remediation Round 1)

Response to independent review [`2026-11-26-sp2-4-review-cbd9bf7.md`](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-26-sp2-4-review-cbd9bf7.md) on branch `sp2-4-handoff`.

---

## Finding 1 (P1) — Replay ACK `writer_status` vs. Live Fence Equality

### 1. Invariant
An operation acknowledgment reports write-holder authority (`writer_status = holder`) if and only if the caller still matches the active holder identity and session for the current restore epoch AND the fence recorded by that operation equals the task's current live fence (`restore_epoch`, `writer_generation`).

### 2. Sibling Sweep
- **Fresh commit ACK (`submit_episode` normal patch, initial claim, and takeover-only):** `HandoffStore._apply_handoff_mutation_in_tx` sets `committed_restore_epoch = next_epoch` and `committed_writer_generation = next_wgen` equal to the new live fence (`cur.live_fence` updated in the same transaction) and `_render_episode` evaluates `is_holder and ep.principal_id == principal.principal_id and ep_fence == live_fence` -> `holder`. Verified clean.
- **Replay ACK after holder round-trip (`A -> B -> A`, case 74) and takeover-only replay:** Previously `_render_episode` computed `ep_fence` from `ep.committed_restore_epoch` / `ep.committed_writer_generation` while computing `writer_status` solely from `is_holder` (which checked only principal, session, and `holder_restore_epoch == live_restore_epoch`). Fixed in [`handoff_service.py::_render_episode`](../../src/superbrain/application/handoff_service.py#L753-L772) so `writer_is_live_holder` requires `is_holder and ep.principal_id == principal.principal_id and ep_fence == live_fence` (and fails closed `False` if committed fence columns are null).
- **Restore rewind (`restore_epoch` bumped):** `ep_fence.restore_epoch != live_fence.restore_epoch` AND `read_live_holder_status` fails `holder_restore_epoch == live_restore_epoch` -> `not_holder` both before and after any post-restore takeover. Verified tested.
- **`not_stored_policy` branch (`manual_submission_enabled=False`):** Sibling defect found during sweep: [`handoffs.py::_apply_handoff_mutation_in_tx`](../../src/superbrain/storage/handoffs.py#L736-L742) stored `cur.holder_restore_epoch` into `episodes.committed_restore_epoch` while returning `fence=cur.live_fence` (`live_restore_epoch`). After a restore, that stored stale epoch diverged from `live_fence`. Fixed to persist `cur.live_fence.restore_epoch`; if the caller is currently the live holder with `manual_submission=False`, fresh & immediate replay report `"holder"` until another writer advances `writer_generation` or a restore increments `restore_epoch`, after which replay flips to `"not_holder"`.
- **`prepare_task` (`discover` / `work` / `resume`) & `get_artifact`:** Neither returns `writer_status`; `get_artifact` and `prepare_task` return current `handoff_live` from `task_handoffs`. Checked clean.
- **Documentation (§7.4 & §20 case 74 / 68):** Spec explicitly requires replay ACK `writer_status=holder` iff `fence` committed in ACK equals live fence and caller is current holder; code now agrees 100%.

### 3. Lens Table (Audited on Both Repaired and New Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | `_apply_handoff_mutation_in_tx` updates `task_handoffs`, `tasks`, `handoff_revision_headers`, `episodes`, and `idempotency` atomically inside one SQLite `KernelTx` transaction. |
| 2. Restore, rollback & migration rewind | fixed here | `ep_fence == live_fence` compares full `(restore_epoch, writer_generation)` tuple; fixed `not_stored_policy` row persistence to record `cur.live_fence.restore_epoch` so restore epochs stay consistent. |
| 3. Old binaries, old data, version fences | holds | Requires store v8 (`_require_v8_ready`), which fails closed if `restore_epoch.json` is missing/corrupt; `committed_restore_epoch`/`committed_writer_generation` missing fails closed to `not_holder`. |
| 4. Every path to the same invariant | fixed here | Covered fresh patch, initial claim, takeover, takeover-only, `A->B` replay, `A->B->A` same-session replay, restore replay, and `not_stored_policy` fresh + replay. |
| 5. Concurrency, shutdown & cutoffs | holds | All reads/writes occur on the serialized owner-loop SQLite connection / bridge transaction without unlocked shared mutation. |
| 6. Authority, identity & scope | fixed here | `_render_episode` checks `ep.principal_id == principal.principal_id`, `read_live_holder_status` scope/owner/session binding, and full `ep_fence == live_fence`. |
| 7. Fail closed at limits & on `unknown` | holds | Missing `committed_restore_epoch` or `committed_writer_generation` evaluates `writer_is_live_holder = False` (`not_holder`) rather than trusting `live_fence`. |
| 8. What actually left & to whom | holds | Replay returns only committed `episode_id`, `evidence_ids`, committed `handoff_revision`, `handoff_status`, `fence`, and computed `writer_status`. |
| 9. World outside the daemon | not applicable | Authority and fence state reside solely in the daemon's SQLite store and `restore_epoch.json`. |
| 10. Evidence & oracles | fixed here | Added requirement-derived integration test `test_replay_ack_writer_status_requires_live_fence_match_across_siblings`, confirmed RED on `cbd9bf7`, GREEN on Py3.14 & Py3.11, and killed behavioral mutant `M7`. |
| 11. Document agrees with itself | holds | Matches §7.4 ACK table, `not_stored_policy` branch, and §20 cases 67, 68, 73, 74. |

---

## Finding 2 (P1) — `prepare_task` Privacy Filtering on `description` Before Goal Blob Staging

### 1. Invariant
Every durable ingress path carrying client text must run the repo's ingress privacy policy (redaction, fail-closed rejection, and `manual_submission` suppression) before any CAS blob is held or any database row is written.

### 2. Sibling Sweep
- **`prepare_task` (`mode=work`, new task & existing `task_id`):** Previously [`handoff_service.py::_prepare_work_task`](../../src/superbrain/application/handoff_service.py#L262-L273) encoded raw `description.encode("utf-8")` when `create_task=True` and skipped privacy validation when `create_task=False`. Fixed to read `flags = self._repo_flags(binding.repo_id)`, construct `fpolicy = filter_policy_for(flags)`, and run `self._privacy.apply({"description": description}, fpolicy)` unconditionally before preparing any CAS blob or `PreparedEffect`:
  - `manual_submission=True` + valid input: stages filtered `description` bytes when creating the task.
  - `manual_submission=False` + valid input: `project_manual_submission` drops `"description"` -> `goal_bytes=None` -> `tx_create_work_task` skips `tx.hold_blob` and stores `NULL` for `goal_ref`/`goal_holder_id` across `tasks` and `task_handoffs` (zero CAS blobs held, §14.2 metadata-only contract).
  - Privacy filter rejection (e.g. unclosed `<private>`, blocked shape) under EITHER `manual_submission=True` OR `False`, new OR existing task: raises `ErrorCode.INVALID_INPUT` (`"privacy filter rejected payload"`) without input echo and commits zero CAS blobs or rows.
- **`submit_episode` (`evidence`, `handoff`):** Already invokes `self._privacy.apply(..., fpolicy)` gated by `flags.manual_submission` at lines 426–430 and 459–463. Verified clean.
- **`get_artifact` (`L0`/`L1`/`L2`) & `prepare_task(mode=discover)`:** Read-only/rendering paths reading CAS blobs after checking quarantine, tombstone, and expiry (`_check_blob_status`), truncating `task_goal` safely at UTF-8 boundaries without exposing withheld blobs. Verified clean.
- **Lineage `prepare_task` (`application/lineage.py:429`) & `capture/privacy_gate.py`:** Both invoke `PrivacyFilter.apply(...)` before persistence; note `tx_record_work_delivery` with existing `task_id` (`create_task=False`) leaves the original task's immutable filtered `goal_ref` untouched (`goal_bytes=None`), and validates the incoming `description` against the repo filter policy first.

### 3. Lens Table (Audited on Both Repaired and New Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | Filtering occurs inside `prepare_mutation` before `hold_blob` or `_apply`; crash leaves zero unheld or raw blobs. |
| 2. Restore, rollback & migration rewind | holds | `goal_ref` / `goal_holder_id` live on `tasks` and `task_handoffs` identically in backup/restore/migration; nullable `goal_ref` works uniformly across L0/L1/L2 rendering and `read_task_scope`. |
| 3. Old binaries, old data, version fences | holds | `goal_ref` and `goal_holder_id` columns on `tasks` and `task_handoffs` are nullable `TEXT`; pre-existing v7 tasks and `manual_submission=False` v8 tasks share the exact `NULL` representation. |
| 4. Every path to the same invariant | fixed here | Covers `manual_submission=True` (clean & redaction), `manual_submission=False` (metadata-only `goal_ref=NULL`), replay with same idempotency key (0 extra blobs), existing `task_id`, and malformed filter rejections. |
| 5. Concurrency, shutdown & cutoffs | holds | `PrivacyFilter` runs synchronously on normalized input under the shared request budget before entering SQLite commit. |
| 6. Authority, identity & scope | holds | `_repo_flags(binding.repo_id)` runs after `resolve_binding` verifies scope and policy admission. |
| 7. Fail closed at limits & on `unknown` | fixed here | Rejects unclosed `<private>` / oversized / ambiguous inputs with static `INVALID_INPUT` reason regardless of `manual_submission` or `create_task`; returns empty bytes digest fallback only for `StoredResult.refs` metadata when `goal_ref` is absent. |
| 8. What actually left & to whom | fixed here | Raw sensitive input neither enters CAS, SQLite (`tasks`, `task_handoffs`, `deliveries`), error messages, nor L0/L1/L2 rendered outputs. |
| 9. World outside the daemon | not applicable | Filtering happens inside the trusted daemon boundary before CAS or SQLite I/O. |
| 10. Evidence & oracles | fixed here | Added `test_prepare_task_description_privacy_filter_manual_submission_and_rejection` with direct CAS byte checks, SQLite `NULL` metadata-only checks, full store dir canary scan, and positive twin; RED on `cbd9bf7`, GREEN on Py3.14/Py3.11, and killed mutant `M8`. |
| 11. Document agrees with itself | holds | Matches §14.2 ("Privacy filter áp dụng ở mọi đường vào bền vững" and "`manual_submission` tắt: chỉ lưu ID và trạng thái"). |

---

## Finding 3 (P2) — Strict DDL Contract Verification in Store v8 Migration (`_handoff_schema.py`)

### 1. Invariant
Every schema migration must verify the exact normalized DDL contract (`sqlite_master` tables, columns, types, constraints, primary keys, and indexes) for both pre-existing altered tables and newly introduced tables inside the staged migration transaction before publishing the bumped version.

### 2. Sibling Sweep
- **`_continuity_schema.py` (v7):** Already uses normalized `sqlite_master` `sql` comparison against `:memory:` canonical reference DDLs (`_definitions` / `_known_definitions`). Verified clean.
- **`_handoff_schema.py` (v8):** Previously checked only column-name subsets on 4 base tables (`artifact_send_attempt`, `artifact_read_ack`, `tasks`, `task_handoffs`) and used `CREATE TABLE IF NOT EXISTS` on the 6 new v8 tables (`handoff_revision_headers`, `deliveries`, `delivery_seen_handoffs`, `episodes`, `episode_evidence`, `artifact_get_results`), plus `CREATE INDEX IF NOT EXISTS`. Replaced in [`_handoff_schema.py`](../../src/superbrain/storage/_handoff_schema.py#L140-L310) with:
  - Single-query `_definitions_by_table(db, _ALL_V8_TABLES)` collecting normalized `type:name -> sql` for all objects on the 10 v8-touched tables (including `idx_artifact_send_attempt_state`, `idx_handoff_rev_headers_task`, and any rogue view/trigger/index colliding by name).
  - `@lru_cache(maxsize=1) def _reference_ddls()` building exact canonical `v7` and `v8` reference maps in `:memory:`.
  - Pre-check rejecting any non-v7/non-v8 DDL drift (missing columns, wrong column types, missing `NOT NULL`/`DEFAULT`/`CHECK`/`PRIMARY KEY`/`REFERENCES`, or preseeded partial new tables such as 3-col `handoff_revision_headers`) with `ErrorCode.INTEGRITY_FAILURE`.
  - Removal of `IF NOT EXISTS` on all 6 v8 `CREATE TABLE` statements and `CREATE INDEX`.
  - Post-migration check confirming `_definitions_by_table(db, _ALL_V8_TABLES) == v8_ddls` before committing v8.
- **Sibling C5 column upgrades (`artifact_send_attempt` & `artifact_read_ack`):** Covered identically by `_reference_ddls()` exact `sql` equality check, catching wrong defaults (`DEFAULT 'L1'`), nullable vs `NOT NULL`, wrong column types (`TEXT` vs `INTEGER`), and partial upgrades.
- **Live v8 backup restore & existing stores:** Verified `restore_store` rejects a v7 backup injected with a malformed 3-col `handoff_revision_headers` during staged migration (`INTEGRITY_FAILURE`) while leaving the live v8 store, `restore_epoch`, and committed task data untouched; verified existing `test_kernel_migration.py` and `test_kernel_send_attempts.py` remain green.

### 3. Lens Table (Audited on Both Repaired and New Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | `apply_handoff_store_v8` runs inside `migrate_database` / `restore_store` staging; failure raises `INTEGRITY_FAILURE` before directory swap, leaving live store untouched. |
| 2. Restore, rollback & migration rewind | fixed here | Tested both direct `migrate_database` and `restore_store` over a tampered v7 backup; live v8 store, `restore_epoch`, and data survive unchanged. |
| 3. Old binaries, old data, version fences | fixed here | Reuses v7 exact-DDL pattern; `min_reader_version=8` blocks pre-v8 readers while strict v7-to-v8 DDL checks reject partial/corrupt shapes and `record_v8_revision_header_in_tx` helper stays unchanged. |
| 4. Every path to the same invariant | fixed here | Enforces exact DDL contract across ALL 4 altered tables (`artifact_send_attempt`, `artifact_read_ack`, `tasks`, `task_handoffs`) AND ALL 6 new tables + index on both `initialize`, `migrate_database`, and `restore_store`. |
| 5. Concurrency, shutdown & cutoffs | holds | Maintenance lease / staging isolation prevents concurrent readers or writers during migration. |
| 6. Authority, identity & scope | not applicable | Schema migration validates physical catalog contracts under maintenance lease; no caller-level ACL dispatch occurs here. |
| 7. Fail closed at limits & on `unknown` | fixed here | Any unknown/extra/missing table, column, index, type, default, `CHECK`, `NOT NULL`, or FK mismatch raises `INTEGRITY_FAILURE` both before and after executing v8 DDL steps. |
| 8. What actually left & to whom | holds | Error code is `INTEGRITY_FAILURE` with table name/phase only; zero raw data exposed. |
| 9. World outside the daemon | fixed here | Covers tampered backup `brain.db` or pre-seeded tables left by external tools before upgrade/restore. |
| 10. Evidence & oracles | fixed here | Added `test_handoff_store_v8_migration_and_restore_reject_malformed_ddl_shapes` covering all 6 new tables, 3 C5 column drift shapes, and tampered v7 backup restore with live v8 control; RED on `cbd9bf7`, GREEN on Py3.14/Py3.11, and killed mutant `M9`. |
| 11. Document agrees with itself | holds | Matches §5.6/§5.7 fail-closed staged migration and restore guarantees and v7 pattern in `_continuity_schema.py`. |
