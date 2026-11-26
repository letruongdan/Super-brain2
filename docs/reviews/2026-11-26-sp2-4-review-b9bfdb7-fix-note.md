# SP2-4 Review Fix Note (`b9bfdb7` -> Remediation Round 5)

Response to independent re-review [`2026-11-26-sp2-4-review-b9bfdb7.md`](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-26-sp2-4-review-b9bfdb7.md) on branch `sp2-4-handoff`.

---

## Finding 1 (P2) — L1/L2 Observed Section and Conversation Excerpts Must Resolve Strictly From Pinned `observed_ref`

### 1. Invariant
Rendering the observed section and conversation excerpts of any pinned revision must resolve exclusively the source event references committed in that revision's immutable summary ref under current authorization, quarantine, and expiry state, computing `events_since_agent` from the committed revision timeline rather than scanning uncommitted events.

### 2. Sibling Sweep
- **Observed source resolution ([`handoffs.py::resolve_observed_sources`](../../src/superbrain/storage/handoffs.py#L1108-L1247)):** Previously ignored `observed_ref` (`_ = observed_ref`) and scanned the newest 64 rows in `session_task_events WHERE task_id = ?`, leaking uncommitted events added after a worker commit (and even into `observed_ref=None` agent-only revisions) across L1, L2, conversation excerpts, and replays. Fixed to:
  - Return `([], [], 0)` immediately when `observed_ref is None`.
  - Verify `observed_ref` itself via `_check_blob_status(..., holder_id=None, now=now_utc)` before parsing; if quarantined, tombstoned, or expired, fail closed by returning a single `[ResolvedSourceContent(..., kind="observed_summary", status="redacted"|"expired", reason=obs_status)]`, `[]`, `0` instead of scanning events or leaking unheld CAS bytes.
  - Extract deduplicated `(producer_stream, sequence, event_id, payload_digest)` tuples from the parsed `ObservedSummary` JSON (`source_events`, falling back to `items` for metadata `kind` when source rows expire) and walk newest-first.
  - Resolve each pinned tuple through `live_event_record(...)` (checking exact `(task_id, producer_stream, sequence, event_id, payload_digest)`, session binding authority, and live payload holder / quarantine / tombstone / expiry). When blocked or expired (`rec is None`), emit `status="redacted"` (for quarantine or tombstone of the source `cas_holder_id`) or `status="expired"` with metadata `kind` and `recorded_at`, hiding blocked content in both L1/L2 `observed_*` items and L2 `conversation_excerpts`.
- **`events_since_agent` calculation ([`handoffs.py::read_handoff_content_bundle`](../../src/superbrain/storage/handoffs.py#L1835-L1895), [`ports/handoff.py`](../../src/superbrain/ports/handoff.py#L108-L112), [`handoff_service.py::_render_artifact`](../../src/superbrain/application/handoff_service.py#L700-L710)):** Previously `handoff_service.py` never passed `events_since_agent`, so `render_handoff_l1` always emitted `events_since_agent=0`. Added `events_since_agent: int = 0` on `HandoffContentBundle` and forwarded it into the shared `render_handoff_l1` call (used for both L1 and L2). `read_handoff_content_bundle` walks the already-fetched causal `list_revision_history` (reused when `include_history=True`) to find the ancestor committing the current `handoff_revision` and sets `observed_after_agent` from `(agent_commit_hdr.observed_ref != hdr.observed_ref) or (hdr.observed_through > hdr.agent_updated_at)`: initial/worker-only revisions (`handoff_revision == 0` or `agent_updated_at is None`) count all pinned sources (`events_since_agent == len(pinned_refs)`), worker refreshes after an agent patch count pinned sources with `recorded_at >= agent_updated_at`, and subsequent agent patches reset `events_since_agent == 0` on the new revision while archived worker revisions retain their historical count.
- **Sibling L0 / Replay / Continuity Worker paths checked clean:**
  - `prepare_task` (`mode=discover` & `mode=work` + delivery replay via `list_discover` / `render_delivery_handoff_l0`) renders only L0 (`task_goal` + `agent_state` + `observed_through` timestamp) and does not call `resolve_observed_sources`; tested unaffected.
  - `HandoffKernelDomain._render_artifact` shares one `render_handoff_l1` path across L1 & L2 and `ServedReceipt` hashes the rendered `observed_*` / `handoff_header` resources verbatim; tested aligned.
  - `ContinuityWorkerCoordinator` (`resolve_refresh_sources`, `apply_worker_commit_in_tx`) uses `live_event_record` independently when building worker outputs; tested unaffected.

### 3. Lens Table (Audited on Both Repaired and Newly Added Surface)

| Lens | Status | Notes |
|---|---|---|
| 1. Crash between two durable steps | holds | Read path queries immutable `handoff_revision_headers.observed_ref` and held CAS summary committed atomically inside worker transactions. |
| 2. Restore, rollback & migration rewind | fixed here | Tested `restore_store` advancing `restore_epoch`: archived `(0, 2)` stays anchored on Event 1 (redacted by policy), post-restore `(post_ep, 3)` anchors on Event 3 only (never leaking Event 1's policy status nor uncommitted Event 4), and expires source events independently of the summary blob. |
| 3. Old binaries, old data, version fences | holds | `_require_v8_ready` enforces store v8 / policy v5; `HandoffContentBundle.events_since_agent` defaults cleanly to `0`, and `resolve_observed_sources` keeps backwards-compatible keyword defaults (`agent_updated_at=None`, `observed_after_agent=True`). |
| 4. Every path to the same invariant | fixed here | Covers L1, L2, L2 `conversation_excerpts`, cached `get_artifact` idempotent replay, fresh read of historical revision, `observed_ref=None`, agent patch resetting counter on rev 3 while preserving rev 2's count, source quarantine, source-only expiry, and summary blob expiry. |
| 5. Concurrency, shutdown & cutoffs | holds | Reuses single `list_revision_history` call inside `read_handoff_content_bundle` and walks bounded pinned `source_events` on the owner read path without concurrent mutation. |
| 6. Authority, identity & scope | fixed here | Each pinned tuple in `source_events` is resolved through `live_event_record(task_id=task_id, ...)` verifying task/session/principal binding in `policy.db`; summary blob itself passes `_check_blob_status`. |
| 7. Fail closed at limits & on `unknown` | fixed here | Missing, expired, quarantined, or undecodable `observed_ref` fails closed (`observed_summary` redacted/expired or `[], [], 0`) without scanning `session_task_events`; blocked source events never emit plaintext payloads. |
| 8. What actually left & to whom | fixed here | Neither L1 `observed_*` resources nor L2 `conversation_excerpts` can emit events committed after the pinned revision or withheld by quarantine/tombstone/expiry; `events_since_agent` accurately reports count since last agent patch. |
| 9. World outside the daemon | not applicable | Pure SQLite + CAS read path with injected `now` clock; no external files or sockets touched. |
| 10. Evidence & oracles | fixed here | Added `test_get_artifact_l1_l2_pins_observed_ref_sources_and_events_since_agent_across_restore`; observed genuine RED on `b9bfdb7`, GREEN on Py3.14 & Py3.11 (`29 passed`), and killed isolated behavioral mutants `M21`–`M24` (`4/4`) with SHA-256 restore proof. |
| 11. Document agrees with itself | fixed here | Directly satisfies §7.4 ("Sổ có hai ref bất biến: `agent_ref` và `observed_ref`", "Nội dung của từng mục quan sát được dựng từ Event nguồn lúc phục vụ", "Phần quan sát... kèm `observed_through` và số event kể từ lần agent ghi cuối"). |
