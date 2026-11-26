# SP2-4 Pre-Review Note (11-Lens Self-Audit)

- **Branch / Worktree:** `sp2-4-handoff` (`C:\Users\letru\.gemini\antigravity\worktrees\Super-brain2\thuc_hien_ke_hoach_sp2`, forked from sealed SP2-3 commit `049ed572f1f2fe5db6fdb0e3fef5044f9197d37e`)
- **Scope:** SP2-4 continuity ledger & budgets, Store v8 migration (`apply_handoff_store_v8`), `HandoffStore`, `HandoffKernelDomain`, loopback daemon wiring, SP2-4 crash points (`handoff.after_commit_before_ack`, `artifact_send.after_pending_before_flush`), C5 `ServedReceipt`/`ReadAck` across `get_artifact`/`submit_episode`/`prepare_task(resume_ref)`, and legacy/v7 pin updates.
- **Unmodified Protected Files:** `.verification/task9-seal.json` and `schemas/mcp-tools-v2.json` remain byte-identical to `049ed57` (awaiting independent review & reseal).

## Defect Classes Caught & Fixed During Integration and Audit

### Finding A — Task Scope Resolution on C5 ReadAck (`record_projected_read_acks`)
- **Invariant:** Every receipt-backed `ReadAck` verifies owner/repo/checkout ownership of `attempt.task_id` consistently whether the task was bound through the SP1 `task_lineage` projection or created directly in SP2-4 `tasks`.
- **Sibling sweep:** Checked `src/superbrain/application/send_attempts.py::record_projected_read_acks` & `record_read_acks` (fixed via `_TaskScopeReader`), `src/superbrain/storage/workspaces.py::StoreKernelTx.read_task_scope` (added with mismatch cross-check raising `ErrorCode.INTEGRITY_FAILURE`), `src/superbrain/application/lineage.py` (SP1 lineage still uses `read_task_binding` only; holds), `tests/cli_api/test_schema_digest_handshake.py` (`FakeTx` without `read_task_scope` falls back to `tx.read_task_binding`; holds), and `src/superbrain/storage/handoffs.py::tx_commit_handoff_mutation` / `read_task_header_scoped` (already scope-checked `tasks` + `task_handoffs`; holds).

### Finding B — Architecture Layer Boundaries (`ports` / `storage` vs `domain`)
- **Invariant:** `ports` may depend only on `core`, and `storage` may depend only on `ports` and `core`, with zero package cycles across `superbrain.*`.
- **Sibling sweep:** Audited all imports across `src/superbrain/` via `tests/architecture/test_imports.py` (function-level & cycle AST scanner) and `importlinter.cli`:
  - Extracted pure handoff DTOs (`HandoffFence`, `HandoffLive`, `HandoffHeaderState`, `HandoffRevisionHeader`, `HandoffAgentState`, `HandoffPatch`, `ResolvedSourceContent`, parsers) into `src/superbrain/ports/_handoff_types.py` (importing only `core`); re-exported unchanged from `domain/continuity/handoff_model.py` and `rendering.py`.
  - Decoupled `src/superbrain/ports/handoff.py` and `src/superbrain/storage/handoffs.py` from `domain.continuity.*` (replaced `compute_patched_agent_bytes` with `load_agent_state_scoped`, added `render_l0` / `apply_patch` / `validate_limits` injection, and ran domain patching/budget/rendering in `application/handoff_service.py`).
  - Checked `storage/sessions.py`, `storage/_sessions_worker.py`, `storage/_handoff_schema.py`, and `ports/_continuity_checkpoint.py` (all clean).

### Finding C — Fail-Closed Store v8 Upgrade Guard (`apply_handoff_store_v8`)
- **Invariant:** A schema migration modifies existing tables only after verifying expected base columns and rejecting partial/half-migrated intermediate states before swapping.
- **Sibling sweep:** Checked `src/superbrain/storage/_handoff_schema.py::apply_handoff_store_v8` (now verifies required base columns on `artifact_send_attempt`, `artifact_read_ack`, `tasks`, `task_handoffs` and raises `INTEGRITY_FAILURE` on half-migrated `1/2` extended C5 column pairs), `src/superbrain/storage/_continuity_schema.py::apply_continuity_store_v7` (already strict DDL-matched; holds), and added `test_handoff_store_v8_migration_rejects_half_migrated_and_malformed_shapes`.

## 11-Lens Table (Whole SP2-4 Change)

| Lens | Status | Notes / Verification |
| --- | --- | --- |
| 1. Crash between two durable steps | holds | Added crash points `handoff.after_commit_before_ack` and `artifact_send.after_pending_before_flush`; verified deterministic replay/recovery in `tests/storage/test_crash_matrix.py` and `tests/integration/test_capture_ack_and_crash_matrix.py` (`46` registered fault points). |
| 2. Restore, rollback & migration rewind | holds | `revision` + `revision_epoch` composite key prevents post-restore aliasing; `live_fence` (`restore_epoch`, `writer_generation`) blocks stale-epoch commits; `restore_epoch.json` corruption fails closed (`INTEGRITY_FAILURE`); verified across backup/restore + migrate in `test_handoff_restore_and_epochs.py`. |
| 3. Old binaries, old data, version fences | fixed here | Store bumped `7 -> 8` (`min_reader_version=8`) so v7 binaries fail closed (`UNSUPPORTED_VERSION`); `apply_handoff_store_v8` verifies base v7 columns & rejects half-migrated C5 columns before swap; `record_v8_revision_header_in_tx` no-ops on `< v8`. |
| 4. Every path to the same invariant | fixed here | C5 `ReadAck` scope verification unified across SP1 `p_task_lineage_bindings` and SP2-4 `tasks` (`read_task_scope`), replay on `get_artifact` mints fresh `served_receipt_id` (case 72), and production loopback daemon defaults to `HandoffKernelDomain` across live/restore paths. |
| 5. Concurrency, shutdown and cutoffs | holds | `submit_episode` pre-stages CAS blobs before SQLite tx and re-verifies fence/base_revision inside `tx_commit_handoff_mutation` (`REVISION_CONFLICT`); `FakeClock` used throughout (`0` fixed `sleep`). |
| 6. Authority, identity and scope | holds | Identity and `session_ref` HMAC derive server-side from auth/session channel (never trusted from payload); every direct ref (`task_id`, `artifact_id`, `resume_ref`, `seen_handoff_refs`, `read_acks`) enforces `owner_id`/`repo_id`/`checkout_id` and `principal_id` checks. |
| 7. Fail closed at limits and on unknown | holds | `validate_handoff_write_limits` enforces UTF-8 item (2 KB), patch (16 KB), constraints (16 KB), pending changes (4 KB), and total (32 KB) caps; unknown/invalid fence, patch fields, or `unterminated <private>` fail closed with `INVALID_INPUT` and zero side effects. |
| 8. What actually left, and to whom | holds | Raw `session_id` never stored or leaked into blobs/SQLite (`RAW_*` scans verified); `get_artifact` quarantined items return `Redacted` without `served_receipt_id`; `deliveries` records distinct `resumed` / `seen_l0` / `unreviewed_open_handoffs` / `none` exposure evidence. |
| 9. The world outside the daemon | holds | No new filesystem/process shortcuts; CAS/SQLite operations use existing `Store`/`os_adapters` paths; `record_projected_read_acks` / loopback server preserve existing framing and TLS guards. |
| 10. Evidence and oracles | fixed here | `ruff check`, `mypy src` (203 files, 0 issues), `importlinter`, `tests/architecture/test_imports.py` (9 passed), focused SP2-4 + architecture + send_attempts suites `74 passed` on Python 3.14 (`green_py314.log`) and Python 3.11 (`green_py311.log`), plus `6/6` KILLED isolated behavioral mutations (`mutants_sp2_4.log` with SHA-256 restore proof). Note: tests were authored alongside implementation (not independent test author); awaiting independent Codex oracle review & reseal. |
| 11. The document agrees with itself | holds | `docs/design/sp1-crash-table.md` updated to `46` crash cases matching `core/faults.py` and `tests/core/test_faults.py`; legacy/v7 version pins updated across integration/storage tests without changing `schemas/mcp-tools-v2.json` or `.verification/task9-seal.json`. |

## Evidence Receipts (Outside Repo Tree)
- `C:\Users\letru\sb2-trusted-local\evidence\sp2-4-bugproof\red_sp2_4.log`
- `C:\Users\letru\sb2-trusted-local\evidence\sp2-4-bugproof\green_py314.log`
- `C:\Users\letru\sb2-trusted-local\evidence\sp2-4-bugproof\green_py311.log`
- `C:\Users\letru\sb2-trusted-local\evidence\sp2-4-bugproof\mutants_sp2_4.log`

## Request for Independent Reviewer
When auditing this SP2-4 delta for independent review and `.verification/task9-seal.json` reseal approval, please include for any finding: the violated invariant, the review lens it belongs to, and any adjacent variants to check next round.
