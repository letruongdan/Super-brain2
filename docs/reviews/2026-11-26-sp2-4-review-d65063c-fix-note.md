# SP2-4 Review Fix Note (`d65063c` -> Remediation Round 4)

Response to independent re-review [`2026-11-26-sp2-4-review-d65063c.md`](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-26-sp2-4-review-d65063c.md) on branch `sp2-4-handoff`.

---

## Finding 1 (P2) — Header L1/L2 Must Carry Committed `agent_ref` and `observed_ref`

### 1. Invariant
Every rendered `handoff_header` resource at detail levels L1 and L2 must reproduce all committed identity, ref-digest (`agent_ref`, `observed_ref`), state-source, and fence fields from the immutable header of the pinned revision so served content and its `ServedReceipt` digest match the durable header record.

### 2. Sibling Sweep
- **Artifact rendering ([`handoff_service.py::_render_artifact`](../../src/superbrain/application/handoff_service.py#L644-L725)):** Previously L1 and L2 called `render_handoff_l1` in two duplicated blocks, neither forwarding `agent_ref`, `observed_ref`, `task_state_source`, `task_state`, nor `restore_epoch_for_header` from `bundle.header`. Merged both L1 and L2 into one shared `render_handoff_l1(...)` call passing `agent_ref=bundle.header.agent_ref`, `observed_ref=bundle.header.observed_ref`, `task_state=bundle.header.task_state`, `task_state_source=bundle.header.task_state_source`, and `restore_epoch_for_header=bundle.header.fence.restore_epoch`, eliminating L1/L2 header drift and preserving `ServedReceipt` (`artifact_send_attempt.digests_json["handoff_header"]`) parity.
- **L1 domain renderer ([`rendering.py::render_handoff_l1`](../../src/superbrain/domain/continuity/rendering.py#L170-L222)):** Added optional `task_state: str | None = None` (defaulting cleanly for direct unit-test callers) and preserved explicit `task_state_source` when provided, while keeping `agent_ref`/`observed_ref` exact from the caller.
- **Historical & post-restore replay (`_render_artifact` + `read_handoff_content_bundle`):** Replaying a pre-restore `get_artifact` idempotency key or issuing a fresh read on an archived `(revision_epoch, revision)` reads that exact immutable row in `handoff_revision_headers` and keeps committed `fence.restore_epoch`, `agent_ref`, and `observed_ref` distinct from live `handoff_live`.
- **Restore-epoch parity for continuity worker & session manual patches ([`_handoff_schema.py::record_v8_revision_header_in_tx`](../../src/superbrain/storage/_handoff_schema.py#L312-L370), [`_sessions_worker.py`](../../src/superbrain/storage/_sessions_worker.py#L554-L569), [`sessions.py`](../../src/superbrain/storage/sessions.py#L512-L527)):** Sibling check found `record_v8_revision_header_in_tx` used stale `task_handoffs.current_revision_epoch` instead of reading `read_restore_epoch(store.root, ...)` on v8+ stores. Passed `store=self._store` from both `_sessions_worker.py` (at 600 lines) and `sessions.py`, updating `current_revision_epoch` and `handoff_revision_headers.revision_epoch` to live `restore_epoch` without altering `holder_restore_epoch` or `HandoffStore.commit_handoff_mutation` (already checked clean).
- **`prepare_task` (`mode=discover` / `mode=work`):** L0 discovery (`render_handoff_l0`) renders the <=600 B summary without `handoff_header`; `_prepare_work_task` `ObjectRef` digest and `deliveries.handoff_served_digest` were checked unaffected.

### 3. Lens Table (Audited on Both Repaired and Newly Added Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | `get_artifact` commits `artifact_get_results` and `artifact_send_attempt` atomically inside `KernelTx`; `_render_artifact` is pure read-only from immutable headers. |
| 2. Restore, rollback & migration rewind | fixed here | L1/L2 headers pin committed `fence.restore_epoch`, `agent_ref`, and `observed_ref` for archived epochs while `handoff_live` surfaces post-restore epoch; worker/session header helper now reads live `restore_epoch`. |
| 3. Old binaries, old data, version fences | holds | `_require_v8_ready` requires store v8/policy v5; optional `task_state=None` in `render_handoff_l1` and `store=None` in `record_v8_revision_header_in_tx` keep existing callers compatible. |
| 4. Every path to the same invariant | fixed here | Tested agent-only (`observed_ref=None`), observed-only (`agent_ref=None`), combined agent+observed, multi-revision distinct `agent_ref`, `ServedReceipt` digest match, and pre/post-restore replay in both L1 and L2. |
| 5. Concurrency, shutdown & cutoffs | holds | Header lookup reads immutable keyed row `(artifact_id, revision_epoch, revision)` on the serialized owner path. |
| 6. Authority, identity & scope | holds | `read_artifact_get` and `read_handoff_content_bundle` check `owner_id`, `repo_id`, `checkout_id`, and `policy.allows(..., action="get_artifact")` before rendering headers; cross-scope reads return `NOT_FOUND`. |
| 7. Fail closed at limits & on `unknown` | holds | Quarantined/expired/missing `goal_ref` or `agent_ref` redacts cleanly (`status="redacted"`, `resources=[]`) without releasing blocked content. |
| 8. What actually left & to whom | fixed here | Single `render_handoff_l1` path ensures `handoff_header` bytes hashed into `ServedReceipt` (`digests_json["handoff_header"]`) equal the served resource in both L1 and L2. |
| 9. World outside the daemon | not applicable | Header fields derive solely from SQLite `handoff_revision_headers` and CAS under owner-only permissions. |
| 10. Evidence & oracles | fixed here | Verified RED on `d65063c`, GREEN in domain & integration tests on Py3.14 & Py3.11, and killed isolated behavioral mutants `M16` & `M17`. |
| 11. Document agrees with itself | fixed here | Directly matches §7.4 ("Header. L1 và L2 luôn có resource `handoff_header`: `artifact_id`, `revision`, digest của hai ref... Fence trong header là fence đã commit"). |

---

## Finding 2 (P2) — L2 `revision_history` Must Include Causal Prior Revisions Within 256 KB Budget Across Restores

### 1. Invariant
Detail-level L2 rendering must walk and serialize causal ancestor revisions for the pinned `(artifact_id, revision_epoch, revision)` in newest-first order within scope and without cross-branch revision mixing, keeping every emitted JSON resource within per-resource and total UTF-8 byte budgets.

### 2. Sibling Sweep
- **Storage revision history query ([`handoffs.py::list_revision_history`](../../src/superbrain/storage/handoffs.py#L315-L370), [`handoffs.py::_row_to_rev_header`](../../src/superbrain/storage/handoffs.py#L234-L253), [`handoffs.py::read_handoff_content_bundle`](../../src/superbrain/storage/handoffs.py#L1748-L1856)):** Extracted `_row_to_rev_header` shared with `read_revision_header`. Implemented `list_revision_history` scoped strictly by `(artifact_id, task_id, repo_id, checkout_id)` and anchored at `(revision_epoch, revision)`, walking `ORDER BY r.revision DESC, r.revision_epoch DESC` while skipping duplicate revision numbers from older/abandoned restore branches (`hdr.revision == last_rev`) and any row from a higher epoch than the causal branch (`hdr.revision_epoch > cur_max_epoch`), up to `limit=1024`. Added `revision_history` to `HandoffContentBundle` (`ports/handoff.py`) populated when `include_history=(rec.level == "L2")`.
- **Application L2 serialization ([`handoff_service.py::_render_artifact`](../../src/superbrain/application/handoff_service.py#L698-L725)):** Replaced the single-element `[bundle.header]` placeholder with the ordered `bundle.revision_history` sequence including `artifact_id`, `revision_epoch`, `revision`, `handoff_revision`, `task_state`, `task_state_source`, `fence`, `agent_ref`, `observed_ref`, `agent_updated_at`, and `observed_through`.
- **Domain L2 chunking & 256 KB budget ([`rendering.py::render_handoff_l2`](../../src/superbrain/domain/continuity/rendering.py#L343-L392), `_pack_goal_chunks`, `_pack_list_section`):** Fixed a sibling defect exposed during RED testing: previously when the single `l2_history_0` resource exceeded `HANDOFF_L1_RESOURCE_MAX_BYTES` (8 KB), `_chunk_json_entries` string-clipped `[history_payload]` into invalid truncated JSON (`JSONDecodeError`) instead of triggering piecewise chunking. Fixed `render_handoff_l2` to emit `l2_history_0` ONLY when valid JSON fits both `<= 8192 B` and remaining `max_total_bytes` (`262144 B`), and otherwise pack valid `<= 8192 B` JSON chunks (`l2_goal_*`, `l2_closed_*`, `l2_decisions_*`, `l2_rejected_*`, `l2_revisions_*`, `l2_conversation_*`) keeping whole items newest-first and stopping cleanly before exceeding `256 KB`.
- **Sibling query `resolve_artifact_revision_epoch` (`storage/handoffs.py`):** Verified clean — resolves single revision epoch for `get_artifact` `revision_epoch` omission and prefers live epoch if unambiguous; checked L2 history does not alter resolution rules.

### 3. Lens Table (Audited on Both Repaired and Newly Added Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | Reads committed rows in `handoff_revision_headers` joined to `tasks`; no mutation during L2 rendering. |
| 2. Restore, rollback & migration rewind | fixed here | Ancestor walk uses `(revision_epoch, revision)` with monotonic non-increasing epoch and strictly decreasing revision, so Branch Y `(post_ep, 3)->(0, 2)->(0, 1)` never mixes retained Branch X `(0, 3)` and archived `(0, 3)` never includes epoch `post_ep`. |
| 3. Old binaries, old data, version fences | holds | Relies strictly on existing v8 `handoff_revision_headers` table and composite primary key/index; no schema/wire changes needed. |
| 4. Every path to the same invariant | fixed here | Tested multi-revision L2 `(0, 3)`, historical pin `(0, 2)`, post-restore `(post_ep, 4)` with overlapping `(0, 3)`, archived branch `(0, 3)`, replay `(0, 2)`, cross-scope `NOT_FOUND`, medium (>8 KB), and >256 KB truncation. |
| 5. Concurrency, shutdown & cutoffs | holds | History scan is bounded by `limit=1024` and SQL filter `r.revision_epoch <= ? AND r.revision <= ?`. |
| 6. Authority, identity & scope | fixed here | `list_revision_history` enforces `scope.checkout_id is not None` and SQL `r.artifact_id = ? AND r.task_id = ? AND t.repo_id = ? AND t.checkout_id = ?`; tested cross-scope `NOT_FOUND`. |
| 7. Fail closed at limits & on `unknown` | fixed here | Missing target header raises `NOT_FOUND`; oversized >256 KB history drops oldest entries whole without splitting JSON objects or overflowing 8 KB / 256 KB caps. |
| 8. What actually left & to whom | holds | History records carry only header metadata + ref digests (never unredacted CAS secrets or raw `session_id`); conversation excerpts continue filtering via live policy. |
| 9. World outside the daemon | not applicable | Pure SQLite + deterministic domain serialization without external file/socket access. |
| 10. Evidence & oracles | fixed here | Added unit budget test (`test_render_handoff_l2_chunks_revision_history_newest_first_within_256kb_budget`) & end-to-end restore branch test; observed RED on `d65063c`, GREEN on Py3.14 & Py3.11 (`28 passed`), killed mutants `M18`, `M19`, `M20`. |
| 11. Document agrees with itself | fixed here | Matches §7.4 ("L2: Lịch sử quyết định, đề xuất đã đóng, các revision trước, đoạn hội thoại gần nhất... Tối đa 256 KB mới nhất; cũ hơn thì đọc theo `revision` đã ghim"). |
