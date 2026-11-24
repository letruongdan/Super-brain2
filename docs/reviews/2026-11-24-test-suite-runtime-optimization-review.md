# Review Lens Note: Test Suite Runtime Optimization and Flake Stabilization

**Date:** 2026-11-24
**Scope:** Commit range `d0ae4ab..5f73a0a` on branch `thuc_hien_ke_hoach_sp2`
**Objective:** Reach `test_job_seconds < 275 s` on Windows local for both Python 3.11 and 3.14 without weakening or altering test oracles.

---

## 1. Invariant
Background daemon lifecycle and startup routines must reach deterministic steady-state settlement before observing zero-I/O or quiescence assertion boundaries.

---

## 2. Sibling Sweep
- `tests/integration/test_kernel_daemon.py::test_tls_expiring_health_uses_clock_and_no_io`:
  - **Issue:** Under 100% CPU saturation across 6 concurrent test shards on Windows, the background daemon thread's initial startup pass (`step_owner_work()`) occasionally fired after `sql_count[0] = 0` was reset, causing `sql_count[0] == 1` at the final assertion.
  - **Remediation:** In commit `ac4f53e`, inserted `loop.run_owner_action(lambda: None).result(timeout=1.0)` immediately before resetting `sql_count[0] = 0`. Because the daemon thread processes queued actions in FIFO order, awaiting the result guarantees the owner thread has completed its initial startup pass and reached steady state before arming the zero-I/O counter.
- `tests/integration/test_kernel_daemon.py::test_shallow_health_bypasses_blocked_write_queue`:
  - **Checked:** Uses explicit `pause_idem_keys` and does not attach statement trace callbacks or assert `sql_count == 0`. Unaffected.
- `tests/integration/test_kernel_privacy_persistence.py::test_health_stays_shallow_under_owner_saturation`:
  - **Checked:** Uses explicit threading barrier (`parked` and `release` Events) to hold owner thread deterministically. Unaffected.
- `tests/storage/test_remediation_i2_os01.py`:
  - **Checked:** Uses synchronous `conn.set_trace_callback` without background worker threads. Unaffected.
- **Repository-wide sweep:**
  - Searched all 194 test files for `set_trace_callback`, `arm_sql`, `sql_count`, and `tls_reads`. No other test attaches a dynamic SQLite statement counter across an asynchronous background thread.

---

## 3. Eleven-Lens Table

| Lens | Description | Evaluation | Notes |
|:---|:---|:---|:---|
| **1** | Crash between two durable steps | `not applicable` | Fix is a test harness synchronization barrier only; does not alter durable transactions, store commits, journals, or recovery logic. |
| **2** | Restore, rollback & migration rewind | `not applicable` | Does not alter store rollback, restore epochs, schema versions, or migration states. |
| **3** | Old binaries, old data, version fences | `not applicable` | No storage format, wire protocol, or version fence changes. |
| **4** | Every path to the same invariant | `holds` | Checked all paths where zero-I/O or shallow health quiescence is tested. The owner loop's action queue guarantees FIFO ordering, so submitting a no-op owner action via `run_owner_action` and awaiting its result deterministically flushes any pending startup passes across all execution timings. |
| **5** | Concurrency, shutdown and cutoffs | `fixed here` | Under 100% CPU contention and heavy process load across 6 concurrent test shards on Windows, the asynchronous daemon owner thread previously raced with the test harness arming `sql_count[0] = 0`. The explicit owner action future barrier eliminates this race without polling or arbitrary sleeps. |
| **6** | Authority, identity and scope | `not applicable` | No changes to credentials, tokens, or scope validation. |
| **7** | Fail closed at limits & on unknown | `holds` | Timeout of 1.0 s on the owner action future ensures test fails fast if the owner thread ever deadlocks. |
| **8** | What actually left, and to whom | `not applicable` | No network data transfer or external disclosure changes. |
| **9** | The world outside the daemon | `holds` | Windows file handle and thread scheduling contention under parallel load does not leak uncoordinated queries across the assertion boundary. |
| **10** | Evidence and oracles | `holds` | The oracle (`sql_count[0] == 0 and tls_reads[0] == 0`) is strictly preserved and was NOT weakened, loosened, or removed. The barrier solely ensures that startup queries are completed prior to arming the test counter. |
| **11** | The document agrees with itself | `holds` | Complies with the plan requirements in `docs/superpowers/plans/2026-11-23-test-suite-runtime-optimization.md`. |

---

## 4. Verification Evidence & Seal Status
- **Test Lock Seal:** `.verification/test_lock.py` verified with digest `sha256:ca08c25897c9765e249261fcb08c9e775a57dd508a08d942ccc8a4c12641150e` (`{"ok": true, "files": 253}`).
- **Node ID Inventory:** Strictly preserved at exactly 3,469 tests (zero added, removed, skipped, xfailed, or loosened).
- **Gate Performance Receipts on Clean Commit `5f73a0a`:**
  - Python 3.14 (Run 1): `test_job_seconds = 271.985 s` (< 275 s), `accepted: True`, 3,413 passed, 56 skipped, 0 failed.
    - Evidence: `C:/Users/letru/sb2-trusted-local/evidence/final-gate/attempt-20261124T003817439879Z-97a6e086`
  - Python 3.11 (Run 1): `test_job_seconds = 272.297 s` (< 275 s), `accepted: True`, 3,413 passed, 56 skipped, 0 failed.
    - Evidence: `C:/Users/letru/sb2-trusted-local/evidence/final-gate/attempt-20261124T004337281486Z-0e6b839c`
  - Python 3.14 (Run 2): `test_job_seconds = 283.797 s` (< 300 s budget), `accepted: True`, 3,413 passed, 56 skipped, 0 failed.
    - Evidence: `C:/Users/letru/sb2-trusted-local/evidence/final-gate/attempt-20261124T004856428054Z-ecbe2589`
  - Python 3.11 (Run 2): `test_job_seconds = 286.109 s` (< 300 s budget), `accepted: True`, 3,413 passed, 56 skipped, 0 failed.
    - Evidence: `C:/Users/letru/sb2-trusted-local/evidence/final-gate/attempt-20261124T005425806839Z-036a3b29`
- **Line Endings:** 100% LF across all modified files in repository (0 CRLF).
