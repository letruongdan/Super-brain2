<!-- review-lens:rules:start -->
## Review lens (pre-review check & finding remediation)

Before submitting any design, plan, code change, or fix for independent review in
this repository, and whenever answering or remediating review findings, read the
complete skill at `skills/review-lens/SKILL.md` (mirrored for native harness
discovery at `.agents/skills/review-lens/SKILL.md` and
`.claude/skills/review-lens/SKILL.md`) and check all 11 lenses so the change
closes the whole class of defect rather than a single counterexample.

When answering or remediating review findings, submit a fix note for **every
finding** alongside the change with all three required parts:
1. **Invariant** — one sentence stating the rule that was violated, without naming the reported scenario.
2. **Sibling sweep** — every other entry point, store, state, or document clause relying on the same invariant, including places checked that turned out fine.
3. **Lens table** — one row per lens (`holds`, `fixed here`, or `not applicable` with the reason; skipping a lens without a reason counts as not checked).

The fix itself is new, unreviewed surface: run the lenses on what you added, not
only on what you repaired. When requesting an independent review, ask the
reviewer to include for each finding: the invariant, the lens it belongs to, and
the adjacent variants it would check next round.

When updating `skills/review-lens/SKILL.md`, keep
`.agents/skills/review-lens/SKILL.md` and `.claude/skills/review-lens/SKILL.md`
byte-identical with `skills/review-lens/SKILL.md`. Installed guidance is not
proof of native loading or application.
<!-- review-lens:rules:end -->

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
