# SP1 increment 2 re-review validation

Reviewed by the Codex reviewer agent `/root/sp1_i2_plan_review` in parent chat `01a18c0b-c124-7e32-9c9e-7b8f63565aff`. This agent performed the scoped review and authored this report. The parent coordinates the plan and owns its edits. The review authority here is a documented independent agent assessment.

Review scope covers Antigravity findings N1-N7, the proposed corrections, and their consistency with the existing I1 source. It includes the selected checkout boundary, observer deadlines, policy rollback and re-adoption, event-sourced snapshot and lineage records, HTTP prefetch limits, and TLS health. Read-only source inspection was performed. This report is the only file written by the reviewer. Product code, tests and native probes were not executed.

The verdict applies to the exact byte pins below. T0 remains unrun and blocks Task 1 until owner authorization, successful selected-host probes and confirmation of D2. Runtime acceptance and the later native and CI gates require their own evidence.

| Subject | Exact identity |
|---|---|
| Product source HEAD | `77f2a12c99798c81032c5e99b2e99f9371eed8a9` |
| Rev 4 specification Git blob | `88f450e2fa72146c42804dceb1864735fafd9a85` |
| Reviewed plan | `docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md` |
| Plan SHA-256 | `c46558798148ae2b3a154a29d2e8c393066361e4c56fa20d2d9cfd7abb6868d5` |
| Reviewed decisions | `docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md` |
| Decisions SHA-256 | `4ce857d9b00cc4ba8af9739c115a67ec8c7568d1fc733172aeab8edcc5a76a57` |
| External re-review | `C:/Users/letru/.gemini/antigravity/brain/02c79a65-8291-42ab-9e7e-96d270340269/sp1-increment2-plan-rereview.md` |
| External re-review SHA-256 | `790af1ef14725da3d8282f0cb906907cfb31d85cf627a008697e2874a5e48302` |

| Finding | Disposition for these pins | Basis |
|---|---|---|
| N1 | Resolved in the plan | One checkout per owner-provisioned profile, verified launch CWD, explicit profile workspace fields and refusal of other selectors. Client arguments permit zero or one selector, daemon arguments require exactly one after shim injection. The private `KernelHttpCall` carries `selected_scope` into `Call` and `CallContext`. Every workspace subject is checked against it using current policy. HMAC covers tool, scope and normalized arguments, while the idempotency key scope stays principal/tool/key. Same-repo cross-checkout outcome/artifact and profile-switch conflict tests are required. See plan lines 70-74 and 214-220, decisions D3. |
| N2 | Resolved as a plan contract, with observer activation pending | Admission, filtering and observer work share the original 100 ms local budget inside the 1,500 ms total. There is no additional 300 ms observer phase. The deadline is set once and passed through. Missing or late observation refuses a fresh commit. Cached mtime/size is not content proof. I2 uses a fixture observer. A secure bounded observer and malicious Git configuration tests remain prerequisites for SP2/SP5 activation. Prepare does not call a Git subprocess. See plan Task 3 and decisions D3/D5. |
| N3 | Resolved with an explicit I3 handoff | Current policy remains the authority after policy restore. Main mirror and ledger can supply candidates for an owner-reviewed proposal. I3 high-risk `workspace_link` must preview and re-adopt the exact verified old IDs with owner, generation, locator and evidence binding. It cannot silently allocate replacement IDs for that old binding. Behavioral and architecture checks keep authorization independent of the mirror. See plan Task 3 and final I3 handoff, decisions D3. |
| N4 | Resolved in the storage design | Snapshot and task/field lineage are typed business ledger events with safe CAS descriptors and holders. Their tables are reducer projections rebuilt into shadow tables and swapped through existing I1 logic. Rebuild must preserve unknown-source constraints and perform no observation, ID creation or external work. T2 adds policy2 and the store2 reader fence before new kernel kinds. T4 appends store3 for operational records. Previously committed migrations stay immutable. See plan Tasks 2-3 and decisions D3. |
| N5 | Resolved as a required T0 and transport oracle | T0 must test request/header caps before stdlib parsing and prefetched identity/tool/third-request bytes. Buffered data obeys the same state, deadlines and bounds. A blocking peek is excluded. T6b repeats these named tests. T0 has not run, so transport feasibility remains a release gate. See plan T0 and Task 6b. |
| N6 | Resolved in the health contract | Shallow health derives `tls_expiring` at the 30-day boundary from loaded certificate metadata and the current clock. The named oracle requires no DB writes or network probe. Expired certificates still fail startup validation. Owner-approved rotation belongs to I3. See plan Task 6a and decisions D5. |
| N7 | Recorded in this report | Canonical reviewer agent, parent chat, source identity, exact input hashes, review method, finding dispositions and conditional verdict are retained here. The parent coordinates this review and owns plan edits. |

During this review, the initial N1 correction still left later calls without a daemon-visible selected checkout. A `record_outcome` request for another checkout of the same repo could otherwise retain identical public arguments and HMAC. The reviewer raised that P2 against plan `f4448cc3c84be8024567acf18100bfc4ed1d474eaf2858944103289c90b1784c` and decisions `075c891c4867a722cdb11511d9026c742654a6d30b0980691f3606a1c02ed57f`. The parent added private selected scope, subject checks, scope-bound HMAC and the regression oracles. The final pins above contain that correction.

Source checks confirmed the mechanisms the plan extends. `storage/store.py` creates missing projection tables and replays their history at lines 308-320. Its `rebuild_projections` builds shadow tables and swaps them within one transaction at lines 434-450. `storage/schema.py` treats projection DDL separately from the base schema at lines 36-40 and refuses newer or older writable schema versions at lines 139-144. `storage/restore.py` restores the policy snapshot and raises trust generation at lines 187-204. It does not merge the live registry into that snapshot.

Verdict for the scoped review is **acceptable as a plan for owner approval**. No remaining P1 or P2 was found in N1-N7 or the selected-scope correction.

Implementation release still requires confirmation of rev 4 and D1-D8, approval of the concrete T0 scope, successful probes for every host the owner selects for implementation, confirmation of D2 and committed document/source pins. A selected host with an unrun or failed probe keeps Task 1 blocked. T0 does not replace the final installed-shim native gate. The later CI, native, bootstrap and real-observer requirements retain their stated scope.

Review date is 2026-11-05 UTC. No product code, tests, native probes, merge or configuration actions were performed by this reviewer.

