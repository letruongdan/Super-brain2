# SP2-4 Review Fix Note (`bb223a6` → Remediation Round 2)

Response to independent re-review [`2026-11-26-sp2-4-review-bb223a6.md`](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-26-sp2-4-review-bb223a6.md) on branch `sp2-4-handoff`.

---

## Finding 1 (P2) — Replay Delivery Pinned to Committed Serving Ref Under Live Policy

### 1. Invariant
An idempotent delivery replay reconstructs its rendered items solely from the immutable revision reference originally served by that delivery, evaluated against current policy/quarantine/expiry state, while computing live concurrency metadata separately from the task's current header.

### 2. Sibling Sweep
- **Delivery replay (`prepare_task` idempotency hit -> `_render_delivery`):** Previously [`HandoffKernelDomain._render_delivery`](../../src/superbrain/application/handoff_service.py#L568-L583) called `list_discover(..., task_id=rec.task_id)`, which read the mutable `task_handoffs` head row instead of the revision originally served to that delivery. Fixed [`HandoffStore.read_delivery_outcome`](../../src/superbrain/storage/handoffs.py#L1405-L1458) to load `handoff_served_epoch`, `handoff_served_rev`, and `handoff_served_digest` into [`DeliveryOutcomeRecord`](../../src/superbrain/ports/handoff.py#L41-L61), added `HandoffStore.render_delivery_handoff_l0` keyed by `(task_id, handoff_served_epoch, handoff_served_rev)`, and extracted shared helper `HandoffStore._render_l0_row` so `list_discover` and `render_delivery_handoff_l0` share the exact same live quarantine/tombstone/expiry and L0 rendering logic without drift. Initial create deliveries (`handoff_served_rev IS NULL`) render `continuity = []` on both fresh delivery and replay, while `handoff_live` continues to reflect current live header/epoch via `resolve_task_scope`.
- **`tx_record_work_delivery` `handoff_served_digest` capture:** Sibling fix in [`handoffs.py::tx_record_work_delivery`](../../src/superbrain/storage/handoffs.py#L1352-L1403) now fetches `COALESCE(r.agent_ref, t.goal_ref)` directly from `handoff_revision_headers` matching `(task_id, served_ep, served_rev)` rather than relying only on `task_handoffs` head columns.
- **`get_artifact` replay (`_render_artifact`) & `submit_episode` replay (`_render_episode`):** `_render_artifact` already looks up `(artifact_id, revision_epoch, revision)` in `artifact_get_results` and reads immutable `handoff_revision_headers` while returning separate `handoff_live`; `_render_episode` reads immutable `episodes` row columns plus live `read_live_holder_status` (remediated in round 1). Both verified clean.
- **`prepare_task(mode=discover)`:** Intentionally queries live `task_handoffs` head (discovery endpoint has no delivery record or idempotency key per §7.4). Verified clean.
- **Restore + revision-number reuse across epochs:** Since `handoff_revision_headers` is keyed by `(artifact_id, revision_epoch, revision)` and `deliveries` stores both `handoff_served_epoch` and `handoff_served_rev`, a pre-restore delivery pinned to `(0, 1)` stays on `(0, 1)` after restore (`restore_epoch` -> `1`) and post-restore writes on `(1, 2)` never alias `(0, 2)` (`render_delivery_handoff_l0` returns `status="redacted", reason="not_found"` if missing).

### 3. Lens Table (Audited on Both Repaired and New Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | `deliveries` (`handoff_served_*`), `tasks`, `task_handoffs`, and `idempotency` commit atomically inside one SQLite `KernelTx`. |
| 2. Restore, rollback & migration rewind | fixed here | `deliveries` carries both `handoff_served_epoch` and `handoff_served_rev`; `render_delivery_handoff_l0` keys on `(task_id, revision_epoch, revision)` so reused post-restore revision numbers never alias pre-restore deliveries. |
| 3. Old binaries, old data, version fences | holds | Columns `handoff_served_epoch`, `handoff_served_rev`, `handoff_served_digest` already belong to canonical v8 `deliveries` schema; nullable semantics handle rev-0 initial deliveries cleanly. |
| 4. Every path to the same invariant | fixed here | Tested rev-0 create delivery replay (`[]`), rev-1 replay after observed-only update (rev 2), replay after agent patch (rev 3), live quarantine of both rev 3 and rev 1, and post-restore epoch-reuse non-aliasing. |
| 5. Concurrency, shutdown & cutoffs | holds | `read_delivery_outcome` and `render_delivery_handoff_l0` read on the serialized owner/bridge transaction path. |
| 6. Authority, identity & scope | holds | `_render_delivery` verifies `principal.owner_id`, `selected_scope`, and `self._policy.allows(principal, scope, action="prepare_task")` before `render_delivery_handoff_l0` filters `t.owner_id`, `t.repo_id`, and `t.checkout_id`. |
| 7. Fail closed at limits & on `unknown` | fixed here | Missing/unmatched `(task_id, revision_epoch, revision)` row returns `DiscoverEntry(status="redacted", reason="not_found")` rather than falling back to head. |
| 8. What actually left & to whom | fixed here | Replay re-checks `_check_blob_status` (quarantine, tombstone, expiry) against live policy at render time so revoked items become `status="redacted"`. |
| 9. World outside the daemon | not applicable | Rendering reads daemon-controlled SQLite headers and local CAS under owner-only permissions. |
| 10. Evidence & oracles | fixed here | Added `test_delivery_replay_pins_committed_revision_and_rechecks_live_policy_and_restore`, verified RED on `bb223a6`, GREEN on Py3.14 & Py3.11, and killed mutant `M10`. |
| 11. Document agrees with itself | holds | Matches §6.3 (idempotency reconstructs from committed refs + live policy) and §7.4 (`continuity` vs live `handoff_live`). |

---

## Finding 2 (P2) — Resume `exposure_evidence` Stratification (`read_ack` / `served_only` / `unknown`) and Receipt Binding

### 1. Invariant
When resuming a task, recorded exposure provenance must report strictly `{read_ack, served_only, unknown}` derived from server-verified L1 `ServedReceipt` and digest-matched `ArtifactReadAck` records bound to the caller, task, artifact, epoch, and revision, rejecting invalid/wrong-level/pending receipts and conflicting committed revisions fail-closed.

### 2. Sibling Sweep
- **Resolution & validation of `resume_ref` (`HandoffStore._validate_resume_in_tx`):** Previously [`_validate_resume_in_tx`](../../src/superbrain/storage/handoffs.py#L1182-L1240) allowed L0 or stale `resume_ref` shortcuts (`live_fence`, ambiguous non-receipt lookups) and `tx_record_work_delivery` collapsed every resume into `exposure_evidence="resumed"`. Fixed to:
  - Require `resume_ref.served_receipt_id` when supplied to match `attempt` (`principal_id`, `task_id`, `artifact_id == resume_ref.artifact_id`, `revision == resume_ref.revision`, `level == "L1"`, and `state != UNKNOWN`), raising `IN_PROGRESS` for `PENDING` and `NOT_FOUND` for wrong level/task/principal/missing receipt; check `read_read_ack_by_receipt_row(db, receipt_id)` against exact tuple `(served_receipt_id, principal_id, task_id, artifact_id, revision_epoch, revision, resource_digests)` -> `read_ack` iff matched else `served_only`.
  - When `served_receipt_id` is omitted, record `exposure_evidence = "unknown"` and look up `(resume_ref.artifact_id, resume_ref.fence.restore_epoch, resume_ref.revision)` directly (so live post-restore fence cannot substitute for the committed `revision_epoch` of the read header, raising `REVISION_CONFLICT` if the revision exists only at another epoch or `NOT_FOUND` if nonexistent).
  - Verify `resume_ref.handoff_revision == hdr_hrev` and `resume_ref.fence == hdr_fence`, AND verify latest header `cur.handoff_revision == hdr_hrev` and `cur.committed_fence == hdr_fence` (`REVISION_CONFLICT` on mismatch; preserves resume across store restore when only `live_fence` changed while `committed_fence` stayed unchanged!).
  - Propagate `observed_newer` when `(cur.revision_epoch, cur.revision) != (res_epoch, resume_ref.revision)` (agent state unchanged, observed refresh newer) into `deliveries.degraded_codes_json`.
  - Write `"read_ack" | "served_only" | "unknown"` (never `"resumed"`) into `deliveries.exposure_evidence`.
- **Test oracle alignment:** Updated `test_production_loopback_daemon_l0_l1_l2_served_receipt_read_ack_and_resume` (which previously pinned the buggy `"resumed"` string right after submitting a valid `ReadAck` on `receipt_1`) to assert `"read_ack"`, and added comprehensive `test_resume_exposure_evidence_distinguishes_unknown_served_only_read_ack_and_receipt_guards`.
- **`seen_handoff_refs` sibling & capture exposure (`exposure.py`):** Non-resume `seen_handoff_refs` continues recording `"seen_l0"` per §7.4 (`_validate_seen_refs_in_tx` verifies owner/scope/epoch/revision/digest); capture segment `exposure.py` validates model-call egress `ExposureEvidence` enum independently. Checked clean.

### 3. Lens Table (Audited on Both Repaired and New Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | Resume validation reads committed `artifact_send_attempt`, `artifact_read_ack`, and `handoff_revision_headers`, writing `deliveries` atomically inside one `KernelTx`. |
| 2. Restore, rollback & migration rewind | fixed here | Checks committed fence (`hdr_fence` and `cur.committed_fence`) rather than `live_fence` during header comparison, matching §7.4 ("restore chỉ đổi fence sống, không đổi header, nên không chặn resume"). |
| 3. Old binaries, old data, version fences | holds | `_require_v8_ready` requires store v8/policy v5 (`level` & `revision_epoch` columns guaranteed present by strict v8 schema contract). |
| 4. Every path to the same invariant | fixed here | Covers omitted receipt (`unknown`), finalized unacked L1 receipt (`served_only`), acked L1 receipt (`read_ack`), L0 receipt (`NOT_FOUND`), `PENDING` (`IN_PROGRESS`), wrong principal/task/missing (`NOT_FOUND`), stale `handoff_revision` (`REVISION_CONFLICT`), `observed_newer` continuation, and post-agent-patch staleness. |
| 5. Concurrency, shutdown & cutoffs | holds | `PENDING` L1 receipt raises `IN_PROGRESS` until loopback server / owner loop finalizes `served_only`. |
| 6. Authority, identity & scope | fixed here | Receipt ownership checked against channel `principal_id`, `task_id`, `artifact_id`, `revision`, and `level == "L1"`; ACK checked against exact digest tuple matching `attempt.resource_digests`. |
| 7. Fail closed at limits & on `unknown` | fixed here | Missing/UNKNOWN receipt fails closed (`NOT_FOUND`), empty `resource_digests` fails closed (`NOT_FOUND`), and missing `served_receipt_id` records `unknown` rather than claiming delivery proof. |
| 8. What actually left & to whom | fixed here | Preserves SP1 Obligation C strict distinction between server-sent (`served_only`), client-acknowledged exact digests (`read_ack`), and unproven (`unknown`). |
| 9. World outside the daemon | not applicable | Evidence classification reads only daemon-persisted SQLite C5 tables inside the transaction. |
| 10. Evidence & oracles | fixed here | Fixed loopback test pin (`read_ack`), added full stratification/negative-guard integration test, observed RED on `bb223a6`, GREEN on Py3.14 & Py3.11, and killed behavioral mutants `M11` & `M12`. |
| 11. Document agrees with itself | fixed here | Directly satisfies §7.4 lines 635–640, §12.2 (`exposure_evidence`), Obligation C, and §20 cases 36, 63, and 69. |
