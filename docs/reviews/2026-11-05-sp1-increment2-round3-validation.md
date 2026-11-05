# SP1 increment 2 round 3 validation

Review date is 2026-11-05 UTC. The reviewer is Codex agent `/root/sp1_i2_plan_review` in parent chat `01a18c0b-c124-7e32-9c9e-7b8f63565aff`. The parent coordinates the task and owns the plan changes. This review uses a separate reviewer agent within the same parent conversation and shared workspace. Its independence is limited by that shared context and coordination. It is not an external-harness assessment.

This report covers Antigravity round 3 findings R1-R3 and the corresponding revisions. The review is based on document inspection and the previously inspected I1 mechanisms. Only this report is written in this review turn. No product code, tests, native probes, host configuration or merge operations were executed.

| Input | Exact identity |
|---|---|
| Product source HEAD | `77f2a12c99798c81032c5e99b2e99f9371eed8a9` |
| Rev 4 specification Git blob | `88f450e2fa72146c42804dceb1864735fafd9a85` |
| Plan | `docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md` |
| Plan SHA-256 | `2a9ad5d6df4069e996d9995999fa07723b62e96d7993b69ffb23ecdbaf24a1a3` |
| Decisions | `docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md` |
| Decisions SHA-256 | `46a79f3ab7543d8e0d0dd5d241a9380f3984386db821ce5bb46e8d05aa6cb251` |
| External round 3 review | `C:/Users/letru/.gemini/antigravity/brain/02c79a65-8291-42ab-9e7e-96d270340269/sp1-increment2-plan-review-round3.md` |
| External review SHA-256 | `27b37a458842dfa1f854ed188a098875658f906b9b37b75390750e96a66fe5bb` |

| Finding | Disposition | Review basis and remaining gate |
|---|---|---|
| R1 | Addressed in the proposed T0 gate | Plan line 47 requires observed launch CWD, a sanitized environment allowlist, configuration scope, root capabilities, same-repo and cross-repo workspace transitions, multiple windows, and actual shim PID/profile reuse or relaunch. Tool calls and selected scope must be correlated with host operations. Decisions D3 requires an immutable process scope or verified relaunch before accepting launch-only binding. A reused process serving another workspace is a counterexample that blocks Task 1 for that selected host pending a reviewed per-call design or an explicit unsupported-host decision. Roots are observations and do not grant authority. T0 remains unapproved and unrun. |
| R2 | Addressed according to owner choice A | The parent review assignment records the owner's explicit choice A. Plan types, wire output and tests consistently permit a labeled local Delivery when observation is unavailable or reaches its local deadline. `SnapshotObservation` is available with a real descriptor, or unavailable/deadline with no descriptor. Result schema requires a real snapshot ID exactly when status is available, otherwise null and the matching degraded code. Local eligibility, filtering and safe rules fallback precede optional observation within the shared 100 ms phase and the original 1,500 ms total. See plan lines 67, 75-79, 97, 129-139 and 238, decisions D3. |
| R3 | Provenance and limits recorded | This report states the reviewer agent, parent chat, shared-context independence, exact pins, method and conditional verdict. Plan Task 9 requires reviewer provenance and independence level, preserves earlier review artifacts, and allows a separately identified outside reviewer when selected by the owner. Reviewed documents and chosen review artifacts must be committed and pinned before implementation release. This report does not claim that commit has occurred. See plan line 255 and the release conditions. |

The R2 safety boundary is explicit in the reviewed text. Fallback selects only locally permitted skills and lessons and omits items requiring verified source state. Current credentials, scope, policy and quarantine still apply. Unknown source is set by the server and blocks unproved provider egress and technical-proof promotion. Client-supplied invalid or quarantined snapshot IDs, authorization and binding failures, validation/privacy failures and an exhausted total deadline retain typed errors. Production I2 `prepare_task` remains `capability_unavailable` until its domain exists. The I2 fixture exercises the selected fallback contract.

The Delivery status, nullable snapshot binding and monotone unknown lineage commit with the logical result through typed events and the existing transaction boundary. No synthetic `snapshot.observed` event is written for missing observation. A late observer result cannot change the committed result. Same-key replay retains the original Delivery, status and assignment without re-observation or upgrade. A new request may use a new key, while an existing task's unknown-source constraint remains monotone. HMAC continues to bind the normalized external call and selected scope, excluding a newly observed snapshot.

The earlier strict-snapshot draft and its review remain historical evidence for their own pins. The expected handling of a missing or slow observer changes under owner choice A. The total deadline, authorization, privacy, immutable replay and proof requirements retain their explicit acceptance conditions. Planned fixture, real-shim and rebuild tests cover the revised contract, but those tests have not run in this review.

The scoped verdict is **acceptable as a plan for owner approval**. No remaining P1 or P2 was found in R1-R3 or the snapshot fallback changes.

Choice A does not authorize T0. T0 remains unapproved and unrun, and Task 1 remains blocked until the owner authorizes the concrete probe scope, every selected host passes the lifecycle and connectivity gates, D2 and the resolution contract are confirmed, and the chosen documents/reviews are committed with exact pins. Later native, CI, production-domain and secure-observer activation gates require their own evidence.

