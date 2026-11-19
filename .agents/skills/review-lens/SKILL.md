---
name: review-lens
description: Use before submitting any design, plan, code change or fix for independent review in this repository, and when answering review findings. Lists what this project's reviewer checks, so a fix closes the whole class of defect instead of the one counterexample that was reported.
---

# Review lens

Distilled from 62 review files in `docs/reviews/` (2026-10-30 to 2026-11-10, about 130 findings). Most re-review rounds were caused by one thing: the fix closed the counterexample the reviewer wrote down, and the next round found the same broken invariant on an adjacent path.

A reported counterexample is one witness of a broken invariant. Fix the invariant.

## Before submitting a fix

For every finding, write a fix note with these three parts and submit it with the change:

1. **Invariant.** One sentence stating the rule that was violated, without naming the reported scenario. If the sentence only makes sense for that scenario, it is not the invariant yet.
2. **Sibling sweep.** Every other place that relies on the same invariant: other entry points, other stores, other states, other clauses of the document. List what was checked, including places that turned out fine.
3. **Lens table.** One row per lens below: `holds`, `fixed here`, or `not applicable` with the reason. A lens that is skipped without a reason counts as not checked.

The fix itself is new, unreviewed surface. Run the lenses on what you added, not only on what you repaired.

## The lenses

Each lens is a question the reviewer has asked repeatedly. The line in italics is how it showed up here.

### 1. Crash between two durable steps

For every pair of steps that must both happen, what does restart see if the process dies between them? Is the state it sees distinguishable from every other state that looks the same on disk?

- Write the intent before the action, and put in the intent what you need to recognize your own work afterwards.
- Recognize ownership by something pinned in advance (an identity, an ID), never by content equality. A user can produce the same bytes.
- Cover both directions. Rollback has its own intermediate states, and "rollback not started" must differ from "apply not started".
- Cover the empty case: the target did not exist before.

*Seen as: an apply journal with no state for "original moved, target empty"; then no proof that the file at the target was the one the daemon published; then a rollback that could be read as a finished apply.*

### 2. Restore, rollback and migration rewind state

For every piece of state the change touches: which store holds it, and what happens when that store is restored to an older snapshot? Check main store only, policy store only, both, both orders, and the same restore twice.

- Anything that grants authority, counts spending, records what left the machine, or marks something revoked must not rewind with the data store.
- A number that is reused after restore (revision, generation, counter) is not an identifier. Add the epoch.
- State computed for a snapshot that is still being staged must not affect the live store until that snapshot is published.
- Markers that must survive until the user handles them must survive a second restore.
- Migration must carry the same state forward that restore protects.

*Seen as: restore reviving an ended recovery grant; expiry tombstones lost when both stores were restored; a staged snapshot's tombstones blocking live data; a revision number serving different content after restore; a pin-loss marker lost on the second restore; migrate dropping the restore epoch.*

### 3. Old binaries, old data, version fences

Does a store written by the previous binary still open with this one? Does the previous binary refuse a store written by this one **before** it mutates anything? Is that true for every entry point of the old binary, including maintenance commands, not only normal startup?

- Changing a durable payload format needs a version bump and an upgrade path for retained records.
- A fence must sit in the store that the old binary cannot replace. A fence that a restore of the other store can remove is not a fence.
- Never edit a migration that has shipped; append.

*Seen as one finding that took four rounds: new required field broke old retained intents; then the old binary wrote authority before the fence fired; then the old binary's restore command removed the fence; closed only when the fence was added to the second store.*

### 4. Every path to the same invariant

List every way to reach the behavior, then check each: first call, retry with the same key, cached replay, late response, direct read by reference, search, the listing path, the maintenance API, the CLI, the background job.

- A check added on the fresh path is usually missing on the replay or cached path.
- A check on one input spelling is usually missing on its variants (case, separators, length at the limit).
- A rule enforced when recommending is not automatically enforced when reading by reference. Decide which reads enforce it and say so.

*Seen as: a deadline enforced for new requests and skipped on cached replay; a privacy projection bypassed by one field; a lowercase scheme and a long username slipping past credential detection; a pin enforced in one read path and contradicted in another.*

### 5. Concurrency, shutdown and cutoffs

For every lock: what code runs while it is held, and can any of it block or call user code? For every wait: is it bounded by the shared deadline? For every thread start: what if it fails?

- User callbacks never run on the caller's thread past a cutoff, and never under an internal lock.
- A late hand-off must not reach a component that has already closed.
- Two settlements of the same future must not race; callbacks on one future keep their order.
- After fixing one race, rerun every earlier probe. Half of the findings in the longest chain were introduced by the previous fix.
- Three rounds in the same area means the design is too intricate. Simplify it instead of adding a guard.

*Seen as nine rounds on one shutdown path: cancel racing completion, callbacks holding stop past its grace, an unbounded join, a failed thread start losing notifications, a hand-off after close, overlapping callbacks.*

### 6. Authority, identity and scope

Who is allowed, according to which record, read at which moment? Is the subject compared against the immutable original or against a registry that may have changed since?

- Identity and source labels are assigned by the server from the channel, never taken from the payload.
- Every direct reference is checked for owner, scope and revision, even when the caller knows the ID.
- What is signed or approved must be the full identifier of what will be acted on. If the tuple in the approval is shorter than the reference used elsewhere, that is a finding.
- Authority is re-read from the current policy before each write. A journal or cached result records progress; it does not grant permission.
- Losing the authority record means refuse, not default-allow.

*Seen as: an intent compared against the live registry; a bridge accepting another root's policy with the same store ID; a batch approval signed without the epoch; a recovery proceeding on a journal alone.*

### 7. Fail closed at limits and on the unknown

What happens at limit + 1, on a malformed value, on a version newer than this build, on a state called `unknown`?

- A cap must refuse or keep counting. It must not silently stop looking.
- `unknown` is never treated as the favorable case. An unverified profile does not run; an unknown cost is not zero.
- Parsing limits are part of the security check, so the over-limit branch needs the same outcome as the match branch.

*Seen as: accounting that ignored records after the 1,024th; a length limit that made a credential check fail open; a job allowed to start while its read-only profile was unverified.*

### 8. What actually left, and to whom

For every byte sent out or written to a log: was this exact item already disclosed to this exact recipient, with evidence? Same session and same provider is not evidence.

- Derived artifacts carry the data: descriptors, field paths, error text, exception messages, receipts, traces.
- Log a static phase and code. Never `str(exc)` built from input.
- Items captured locally or written to the store were not necessarily sent to the model provider.
- Check the current policy of every source immediately before each send, including retries and background jobs.
- Internal references and lineage stay out of the outbound payload.

*Seen as: a filtered key persisted through a field-path descriptor; exception text in a log; a review job that could send another session's events; items never sent to the provider treated as a resend.*

### 9. The world outside the daemon

What can change without the daemon knowing? The user edits a file between check and write. A parent directory becomes a junction. Another process binds the port. A harness loads files on its own, even when the daemon is down.

- Pin the physical target, not the path, and recheck at the moment of writing.
- Never destroy bytes that are not already in a backup.
- If another program enforces nothing, a rule the daemon enforces only at its own boundary does not hold there. Either prove the other program enforces it or do not use that channel.

*Seen as: a CAS shard that followed a junction out of the data root; an approval that pinned a path but not its physical target; a native skill install the harness could load past pin and quarantine. The last one was closed by removing the feature.*

### 10. Evidence and oracles

Does the test fail for the right reason, and would it pass on an empty or trivial result?

- Every negative case needs a positive twin. A test that only checks forbidden items are absent passes on an empty payload.
- Sent is not received, received is not applied, applied is not observed. Name which one the evidence proves.
- A receipt that lacks an outcome is not accepted. An unexpected pass is not a pass.
- A mutation that survives means the oracle is weak. Add the mutation for each guard you add.
- Claims stop at what ran: the OS, the interpreter, the host that produced the receipt.
- Keep the gate's time budget in view; a fix that passes but pushes the suite over its limit reopens the task.

*Seen as: non-strict XPASS counted as passed; a receipt missing one outcome still accepted; a milestone that counted "served" as "loaded"; a scenario satisfiable by sending nothing.*

### 11. The document agrees with itself

After changing one clause, search for every other mention of the concept: decision tables, the contract section, the threat table, deadlines per sub-project, acceptance scenarios, the mapping table.

- Two clauses that give different answers for the same case are a finding even if each is reasonable alone.
- An acceptance scenario must be satisfiable under the rules as written, and must not contradict another scenario.
- When a feature is removed, remove its residue everywhere, and restate scenarios that referred to it.

*Seen as: a pending revision that had to return its reference and also must not appear in any result; a scenario that forbade a read another scenario required; a removed channel still listed in the channel table.*

## When a class keeps coming back

- Count rounds per area. On the third round with a finding of the same lens, stop patching and propose a simpler design or removing the feature. Removal has closed more blocking findings here than any guard.
- Prefer one mechanism that covers the class (a write-ahead intent, an epoch in every reference, one admission slot) over a guard per counterexample.

## For the reviewer

Ask the reviewer to include, for each finding: the invariant, the lens it belongs to, and the adjacent variants it would check next round. That moves next round's findings into this round.

## Keeping this skill current

After each review round, for every finding that was only partly fixed, ask which lens would have caught it. If none, add a lens or a bullet. Keep entries as rules, not as incident history; one italic line of provenance per lens is enough.
