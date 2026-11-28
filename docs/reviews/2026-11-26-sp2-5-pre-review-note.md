# SP2-5 Pre-Review Note (11-Lens Self-Audit on `sp2-5-adapters-m1`)

**Branch:** `sp2-5-adapters-m1` (forked from sealed SP2-4 baseline `c294ee1c7d38a3083f355cb652e184f3804bd20e`)  
**Scope covered:** SP2-5 Step 1 + Step 2 (Claude Code & Codex capture adapters, `NativeHostReceipt` verification & automatic invalidation, read-only SP2 `doctor` probes, `build_capture_hook_command`, and M1 fixture rehearsal driver). Step 3 native host M1 rehearsal on real Claude Code / Codex processes remains **`not_run`** pending owner approval and Codex SP2-5 review + reseal.  
**Sealed files invariant:** `.verification/task9-seal.json`, `schemas/mcp-tools-v2.json`, and `scripts/gate.py` budgets (`TEST_JOB_BUDGET_S == 300.0`, `_WHEEL_SETUP_COST_MS == 3_000`) remain byte-identical to `c294ee1`.

---

## Implemented Modules (All New/Changed `src/` Files `<= 600` Lines)

| File | Role | Lines |
|---|---|---:|
| [`src/superbrain/adapters/harness/__init__.py`](../../src/superbrain/adapters/harness/__init__.py) | Public adapter & Layer-2 receipt exports | 39 |
| [`src/superbrain/adapters/harness/_common.py`](../../src/superbrain/adapters/harness/_common.py) | Link-safe bounded reader, checkout containment, fail-closed `RecipientProfile`, scoped JSONL transcript helper | 585 |
| [`src/superbrain/adapters/harness/claude_code.py`](../../src/superbrain/adapters/harness/claude_code.py) | `ClaudeCodeCaptureAdapter` (`bare_mode`, `.mcp.json`, `CLAUDE.md`, `.claude/settings*.json`, scoped transcripts) | 107 |
| [`src/superbrain/adapters/harness/codex.py`](../../src/superbrain/adapters/harness/codex.py) | `CodexCaptureAdapter` (`hooks.json`, `config.toml`, `AGENTS.md`, `hooks_enabled`, scoped transcripts) | 102 |
| [`src/superbrain/adapters/harness/layer2_probe.py`](../../src/superbrain/adapters/harness/layer2_probe.py) | `NativeHostReceipt`, `AuthorityCommandProbeResult`, `compute_harness_config_digest`, `verify_native_host_receipt` | 245 |
| [`src/superbrain/adapters/harness_config/bootstrap_templates.py`](../../src/superbrain/adapters/harness_config/bootstrap_templates.py) | Adds `build_capture_hook_command` aligned with `python -I -m superbrain.composition.hook_entry` | 451 |
| [`src/superbrain/storage/_policy_layer2.py`](../../src/superbrain/storage/_policy_layer2.py) | Adds `reconcile_layer2_binding` atomic drift downgrade to `Layer2State.UNKNOWN` | 387 |
| [`src/superbrain/storage/_policy_authority_api.py`](../../src/superbrain/storage/_policy_authority_api.py) | Exposes `PolicyStore.reconcile_layer2_binding` | 341 |
| [`src/superbrain/composition/doctor_probes_sp2.py`](../../src/superbrain/composition/doctor_probes_sp2.py) | Zero-mutation `probe_outbox_readonly`, `probe_sp2_store_readonly`, `probe_sp2_layer2_readonly`, `run_sp2_doctor_probes`, `reconcile_harness_layer2_in_policy` | 468 |
| [`scripts/rehearse_m1.py`](../../scripts/rehearse_m1.py) | M1 draft checkout A/B fixture rehearsal & `--owner-approved` gate on `--mode native` | 491 |

---

## 11-Lens Self-Audit

| Lens | Status | Analysis |
|---|---|---|
| 1. Crash between two durable steps | holds | `PolicyStore.reconcile_layer2_binding` and `set_layer2_state` append `harness_layer2_state` and `LAYER2_STATE_SET` inside one SQLite authority transaction; `probe_outbox_readonly` never locks, creates, or sweeps `.part` files during crash recovery. |
| 2. Restore, rollback & migration rewind | tested here | No schema version bump required (`harness_layer2_state` already in policy v4/v5). Tested `restore_policy` rewinding to a prior `VERIFIED` backup (`c_dig1`) after checkout config drifted (`c_dig2`): both read-only `run_sp2_doctor_probes` and `reconcile_harness_layer2_in_policy` detect `config_digest_changed` and immediately downgrade to `UNKNOWN`. |
| 3. Old binaries, old data, version fences | holds | Existing `NativeHostReceipt` checks `schema_version == "sp2-layer2-native-host-receipt-v1"`, strict digest parity, and exact 11-command coverage (`AUTHORITY_ASK_COMMANDS`); unknown schema versions fail closed to `Layer2State.UNKNOWN`. |
| 4. Every path to the same invariant | tested here | Both `ClaudeCodeCaptureAdapter` and `CodexCaptureAdapter` route through one shared `adapt_harness_event`, `verify_checkout_containment`, and `read_scoped_transcript_file`; both `doctor` read-only drift detection and online `reconcile_harness_layer2_in_policy` use the exact same `compute_harness_config_digest`, immediately blocking `terminal` approvals (`CAPABILITY_UNAVAILABLE`) and downgrading `KernelBridge.ingest_capture_batch` to `("unknown", "unverified")`. |
| 5. Concurrency, shutdown & cutoffs | holds | All file reads enforce `O_NOFOLLOW`, `samestat` race checks, bounded buffers (`1 MiB` configs, `8 MiB` transcripts), zero `sleep()`, and temp-dir `open_readonly` without contending on `writer.lock` or WAL files. |
| 6. Authority, identity & scope | tested here | `adapt_harness_event` strips any client-forged `source`, `source_verification`, `exposure_evidence`, `session_id`, `raw_session_id`, hashes raw account/endpoint/model strings into `sha256:...` digests on `RecipientProfile`, rejects cross-checkout `cwd` or symlinks/junctions with `WORKSPACE_MISMATCH`, and isolates transcripts to `allowed_roots` + matching `(checkout_root, session_ref)`. |
| 7. Fail closed at limits & on `unknown` | tested here | Missing `cwd` -> `UNKNOWN`; missing/unsupported event, `bare_mode=True`, `hooks_enabled=False`, outside `allowed_roots`, missing/linked transcript -> `UNAVAILABLE`; incomplete `RecipientProfile` or failed `model_call` -> `"unknown"` fields and `ExposureEvidence.UNKNOWN`; missing `AUTHORITY_ASK_COMMANDS` or tampered receipt -> `Layer2State.UNKNOWN`; unblocked ask command -> `Layer2State.UNSUPPORTED`. |
| 8. What actually left & to whom | tested here | `classify_exposure_evidence` stays strictly `LOCAL_ONLY` for local hooks, `UNKNOWN` on incomplete `model_io` or client claims, and `SENT_TO_RECIPIENT` only with a verified completed `ModelExchangeProof` matching `RecipientProfile` digests (zero raw emails/session IDs/secrets emitted). |
| 9. World outside the daemon | tested (fixture); `not_run` (native) | Tests never inspect live `~/.claude` or `~/.codex` and never spawn real host binaries; `scripts/rehearse_m1.py --mode native` refuses (`exit 2`) without `--owner-approved`. Native M1 Step 3 awaits owner approval after SP2-5 review. |
| 10. Evidence & oracles | verified (self-authored) | Genuine RED on `c294ee1` (`red_sp2_5.log`); GREEN across Python 3.14 (`68 passed in 31.32s`) and Python 3.11 (`68 passed in 35.79s`) with `ruff`, `mypy --strict` (452 files), `importlinter`, and `tests/architecture/test_imports.py` clean; `M30`–`M35` killed `6/6` with SHA-256 restore proof (`mutants_sp2_5.log`). Oracles await independent Codex review & reseal. |
| 11. Document agrees with itself | holds | Matches `docs/design/sp2-host-capture-matrix.md` §1–§3 (all 11 `AUTHORITY_ASK_COMMANDS`, `(harness_id, host_version, config_digest)` invalidation, `RecipientProfile` / `ExposureEvidence` defaults, `--bare` & `hooks_enabled` fallback) and `docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md` SP2-5 Step 1 + Step 2 file map (without altering sealed test inputs). |
