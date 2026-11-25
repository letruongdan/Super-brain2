# Báo Cáo Khắc Phục Kiểm Tra Độc Lập & Đo Lường Thực Tế (`remediate-runtime-opt`)

**Tài liệu kiểm tra độc lập Lượt 1:** [2026-11-24-test-suite-optimization-verification.md](2026-11-24-test-suite-optimization-verification.md)
**Tài liệu kiểm tra độc lập Lượt 2:** [2026-11-24-test-suite-optimization-verification-r2.md](2026-11-24-test-suite-optimization-verification-r2.md)
**Tái kiểm SP2-3 tại 5ee4f35:** [2026-11-25-sp2-3-acceptance-rereview-5ee4f35.md](2026-11-25-sp2-3-acceptance-rereview-5ee4f35.md)
**Kế hoạch gốc:** [2026-11-23-test-suite-runtime-optimization.md](../superpowers/plans/2026-11-23-test-suite-runtime-optimization.md)
**Nhánh thực hiện:** `remediate-runtime-opt` (tách biệt hoàn toàn; `thuc_hien_ke_hoach_sp2` giữ nguyên tại `5f73a0a`)
**Commit tối ưu code đã đo:** `5ee4f35` (`final-remediate-gate-v6`) + vá oracle W3/P2 tiếp nối trên `remediate-runtime-opt`
**Trạng thái seal & review:** Chưa reseal `.verification/task9-seal.json` (chờ reviewer duyệt 29 tệp + oracle W3 mới và chạy `test_lock.py check`); chưa có tuyên bố "Codex đã duyệt".

---

## Tóm Tắt Khắc Phục V1–V5 và W1–W4

1. **V1 (P1) — Cache wheel:** Đã gỡ hoàn toàn cache wheel liên phiên (`wheel-cache` / `_repo_fingerprint`). Fixture `inc2_installed_env` và `frozen_i2_installed_env` chỉ tồn tại trong phạm vi một phiên pytest (`scope="session"`), cài vào thư mục tạm có dọn dẹp teardown, xác thực SHA-256 và giữ `assert len(wheels) == 1`. Không tái sử dụng tạo phẩm giữa các lượt gate.
2. **V2 (P1) — Tính toàn vẹn runner `scripts/gate.py`:** Không còn `compileall -j 0`, không mượn `--cache-dir` của repo nguồn cho `mypy`, không `--compile-bytecode` ở `uv sync`, không đổi `--shards` hay trần `300 s`. Thay đổi duy nhất trên `scripts/gate.py` so với `e4f4163` là hiệu chỉnh bảng trọng số `_HEAVY_FILE_COST_MS` (Task 5).
3. **V3 (P1) — Trung thực tiêu chí Task 6 & báo cáo:** Khôi phục nguyên văn Task 6 trong plan (`test_job_seconds < 275 s` và tổng JUnit `<= 1200 s` ở cả lượt đầu và lượt lặp lại cho **cả Python 3.11 và Python 3.14** trên Windows local). Loại bỏ toàn bộ bảng số liệu và tên file giả (`tests/unit/...`, `build_support.py`, v.v.) từng xuất hiện ở phiên trước; mọi số liệu dưới đây đối chiếu trực tiếp từ JUnit XML và receipt thực thi.
4. **V4 / W1 (P1) — `src/superbrain/composition/hook_entry.py` + bằng chứng `bug-proof-testing`:**
   - Gỡ bỏ hoàn toàn vòng chờ khóa bận (`500 x 2 ms` ở `04a45e4` / `25 x 1 ms` ở `d342bfc`) và thông báo drop ra `sys.stderr`.
   - Thay `_write_static_log` bằng `atomic_append_no_follow` (trong `src/superbrain/adapters/os/physical_fs.py`) dùng `O_APPEND` nguyên tử ở mức OS sau `reject_links_upward` + `thread_lock_for` + `ensure_dir_tree_atomic` + `ensure_secure_regular_file_atomic`: không ăn vào trần cứng 2 s của hook, không âm thầm mất dòng dưới tranh chấp khóa, và không phát sinh byte nào ra `stderr` làm nhiễu giao ước IPC stdout/stderr của watchdog.
   - Đã chạy đủ quy trình RED / GREEN / Mutation cô lập cho `test_hook_entry_static_log_preserves_concurrent_lines_without_stderr` (`tests/domain/test_capture_envelope_and_privacy.py`).
5. **V5 (P3) — Tách nhánh:** Mọi sửa đổi khắc phục nằm trên `remediate-runtime-opt`; nhánh `thuc_hien_ke_hoach_sp2` giữ nguyên tại `5f73a0a`.
6. **W2 (P1) — Đạt ngân sách Task 6 cho cả 3.14 và 3.11 bằng tối ưu thật + cân bằng Task 5:** Trong lượt chẩn đoán Phụ lục A `diag-remediate-v11` trên commit `4ce42af` (không có bước ẩn ngoài `gate`, dùng `uv pip install --compile-bytecode` trong `inc2_fixture.py`/`test_sp2_i2_wheel_compat.py` và K3 template cache cho `crash_cases.py`/`test_backup.py`/`test_reconcile.py`):
   - **Python 3.14:** `test_job_s = 232.46 s` (`< 275 s`), `pytest_wall = 195.19 s`, tổng JUnit `<testsuite>` = **`1081.63 s`** (`<= 1200 s`, `testcase_sum = 1071.39 s`, giảm **575.6 s** so với baseline `1657.2 s` ở `claude-r11-diag`).
   - **Python 3.11:** `test_job_s = 247.61 s` (`< 275 s`), `pytest_wall = 202.89 s`, tổng JUnit `<testsuite>` = **`1160.33 s`** (`<= 1200 s`, `testcase_sum = 1144.60 s`, giảm **391.0 s** so với baseline `1551.3 s`).
   - Sau đó hiệu chỉnh lại `_HEAVY_FILE_COST_MS` trong `scripts/gate.py` từ trung bình `diag-remediate-v11` (3.14 & 3.11), đưa chênh lệch shard mô phỏng về **5.4% (3.11)** và **5.7% (3.14)**; bốn lượt nghiệm thu `scripts.gate --shards 6` thật (cold wheel cache, 3.14 × 2 + 3.11 × 2) được chạy trên chính commit sạch cuối cùng ngay sau khi commit bản cập nhật này (`final-remediate-gate-v6`).
7. **W3 / Rereview P2 (P2) — Oracle kiểm kill tiến trình & Job Object / Process Group (`tests/architecture/test_gate_receipt.py`):**
   - Khắc phục lỗ hổng pass giả ở `5ee4f35` (khi runner mô phỏng trả timeout `0.2 s` mà tiến trình con còn sống trước khi ghi `survived.txt` ở giây thứ 3).
   - `test_run_kills_a_process_that_exceeds_its_timeout` và `test_win32_job_object_lifecycle_and_non_win32_graceful_noop` giờ xác nhận cây tiến trình con/cháu thực sự đã khởi động (`child.started` / `grand.started`), nhận diện đúng PID + dấu khởi tạo OS (`GetProcessTimes` trên Win32 / `/proc/<pid>/stat` hoặc `ps -o lstart=` trên POSIX), kiểm toàn bộ cây tiến trình đã kết thúc trước cutoff `2.5 s`, và kiểm nhánh `start_new_session=True` + `os.killpg(SIGKILL)` trên POSIX. Giữ nguyên tập 3.470 node ID.
   - Đã kiểm chứng trên `C:\Users\letru\sb2-trusted-local\evidence\w3-bugproof\`: probe lỗi giả `5ee4f35` (`probe_5ee4f35_false_pass.log`) nay bị bắt (`red_probe_caught.log`), GREEN trên 3.14/3.11 (`green_314.log`, `green_311.log`), và cả 3 mutation bỏ kill bị bắt (`mut_run_killed.log`, `mut_job_killed.log`, `mut_posix_killpg_killed.log`).
8. **W4 (P3) — Khóa schema dict trong `tests/domain/test_capture_envelope_and_privacy.py:991`:** Đã xác nhận `_seed_outbox_frames` assert `sample_dict == sample_rec.to_dict()`.

---

## 1. Fix Notes Đầy Đủ Theo 11 Thấu Kính (`skills/review-lens/SKILL.md`)

### Finding V1 (P1): Cache Wheel Session-Scoped & Khóa Nội Dung

#### 1. Invariant
> Mọi tạo phẩm cài đặt gói (`wheel` / `venv`) dùng trong kiểm thử chỉ được tái sử dụng khi đầu vào biên dịch không đổi, không được rò rỉ xuyên lượt chạy gate độc lập, và luôn phải được xác thực tính duy nhất và toàn vẹn trước khi dùng.

#### 2. Sibling sweep
- `tests/support/inc2_fixture.py`: `inc2_installed_env` và `open_inc2_installed_env` dùng thư mục tạm `scope="session"`, dọn dẹp sau phiên; cài wheel qua `uv pip install --offline --no-deps --link-mode=copy --compile-bytecode` trong chính lần dựng session duy nhất (thay thế cả `compileall -j 0` lẫn `compileall.compile_dir` chậm 3.5 s).
- `tests/integration/test_sp2_i2_wheel_compat.py`: `frozen_i2_installed_env` và `_build_frozen_i2_wheel` khôi phục `assert len(wheels) == 1`, kiểm SHA-256 wheel khi đọc, và dùng `uv pip install --compile-bytecode`; không còn thư mục cache bền vững ngoài phiên.
- `tests/architecture/test_gate_receipt.py`: đã kiểm tra đường dẫn và điều kiện cô lập `inc2_installed_env`.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | not applicable | Vật liệu wheel dựng lại trong thư mục tạm theo phiên; nếu crash giữa chừng thì phiên mới tạo thư mục tạm mới. |
| Restore, rollback and migration rewind state | not applicable | Không lưu trạng thái migrate/restore hay authority của store. |
| Old binaries, old data, version fences | holds | `frozen_i2_installed_env` build wheel I2 tách biệt hoàn toàn với wheel hiện tại và kiểm digest SHA-256. |
| Every path to the same invariant | fixed here | Cả đường wheel hiện tại (`inc2_installed_env`) và đường wheel cũ (`frozen_i2_installed_env`) đều về session-scoped hermetic. |
| Concurrency, shutdown and cutoffs | holds | Mỗi shard gate có thư mục tạm session độc lập, không tranh chấp ghi giữa các shard. |
| Authority, identity and scope | holds | Lệnh chạy wheel ép `-I` và cwd ngoài repo, kiểm `__file__` nằm trong `site-packages`. |
| Fail closed at limits and on the unknown | fixed here | `assert len(wheels) == 1` và kiểm digest wheel từ chối trạng thái thừa/thiếu/lệch tạo phẩm. |
| What actually left, and to whom | holds | Không ghi artifact ra ngoài cây thư mục tạm phiên test. |
| The world outside the daemon | holds | Không phụ thuộc cache bền vững dùng chung ở `LOCALAPPDATA` giữa các lần chạy. |
| Evidence and oracles | fixed here | Đảm bảo mỗi lượt gate build wheel sạch từ mã nguồn của chính commit đang đo. |
| The document agrees with itself | fixed here | Mô tả V1 khớp đúng code hiện tại và kết quả đối chiếu R2. |

---

### Finding V2 & W2 (P1): Runner `scripts/gate.py` & Tối Ưu Ngắn Thực Chất + Task 5

#### 1. Invariant
> Thời gian `test_job_seconds` của gate phải đo trung thực toàn bộ các bước kiểm tra quy định trên một bản checkout sạch, không đẩy chi phí ra ngoài cửa sổ đo hay thay đổi ngân sách/số shard của runner.

#### 2. Sibling sweep
- `scripts/gate.py`: đối chiếu với `e4f4163` không còn bất kỳ lệnh `compileall`, `--cache-dir` ngoài worktree hay `--compile-bytecode` nào trong `scripts/gate.py`; danh sách bước trong receipt giữ nguyên (`uv-sync`, `preflight`, `collect`, `ruff`, `mypy`, `lint-imports`, `pytest` 6 shard); chỉ cập nhật `_HEAVY_FILE_COST_MS` (Task 5) từ số đo `diag-remediate-v11` (3.14 & 3.11) với mọi kiểm tra 4-shard ở `test_gate_receipt.py` vẫn xanh (`153 passed`).
- Các tối ưu thật thay thế runner hack trên `remediate-runtime-opt`:
  - `tests/support/inc2_fixture.py`, `tests/integration/test_sp2_i2_wheel_compat.py`: chuyển sang `uv pip install --compile-bytecode` + chỉ hỏi `sysconfig.get_path('purelib')`, giảm thời gian dựng mỗi wheel venv xuống ~2.17 s (so với ~5.1 s trước đó và ~13+ s lúc `compileall -j 0`) mà vẫn giữ nguyên dựng wheel sạch theo phiên.
  - `src/superbrain/composition/daemon_entry.py`, `tests/support/inc2_child.py`: trì hoãn import nặng không dùng tới lúc khởi động lệnh CLI/child.
  - `src/superbrain/application/privacy.py`, `_privacy_rules.py`, `_privacy_scan.py`, `tests/application/test_t8_review_p01_wrapped_paths.py`, `test_t8_review_p01_r2_edge_globs.py`, `test_t8_review_p01_r3_spellings.py`: dùng C-regex `contained_re` cho `_sensitive_key` và fast path ASCII cho `_key_words`, thu hẹp fallback không-ASCII chỉ cho 4 code point có case-fold lệch `[a-z]` (`U+0130, U+0131, U+017F, U+212A`) và cache oracle thuần không đổi tập kỳ vọng.
  - `tests/application/test_continuity_worker_scheduling.py`, `tests/integration/test_kernel_daemon.py`, `tests/integration/test_t9_client_sighting.py`, `tests/integration/test_kernel_native_receipt_contract.py`, `tests/integration/test_t9_socket_readiness.py`: dùng `FakeMonotonicClock` cho deadline callback arbiter, truyền `job_handlers={}` trong `test_tls_expiring_health_uses_clock_and_no_io` (tránh `_scan_continuity_if_due` bắn vào cửa sổ zero-SQLite khi nhảy `clock` +60 ngày), và dời mốc `wall_start_ns` vào đúng sau `open_client(...)` / trước `client.call(...)` ở cả 3 ca kiểm deadline sát 80–100 ms.
  - `tests/storage/{test_runtime,test_kernel_revocation,test_restore,test_remediation_c02_lost_main_db,test_flush_routing,test_remediation_c01_wal_admission,test_remediation_c01_r4_reading_leftovers,test_backup,test_reconcile}.py` + `tests/support/crash_cases.py`: dùng `open_cloned_runtime` cho các setup root mới và K3 template cache (`_I1_SEED_CACHE`, `seed_crash_event_root`) cho 6 seed của `test_crash_matrix.py` + `seed_event` của `test_backup.py`/`test_reconcile.py` (giữ nguyên `open_runtime` và `run_until_crash("seed_event", ...)` ở các test kiểm khởi tạo schema, version admission, sync spy, root sẵn có, hoặc crash lúc seed).
  - `tests/architecture/test_gate_receipt.py`, `tests/storage/test_ledger.py`: lọc chuỗi sơ bộ trước `ast.parse` khi quét file repo.
  - `tests/support/crash_child.py`: bổ sung `from __future__ import annotations` sửa lỗi collect Python 3.11 khi dùng `if TYPE_CHECKING:`.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | Không thay đổi trình tự crash recovery hay ghi durable của sản phẩm và harness. |
| Restore, rollback and migration rewind state | holds | Mọi test migrate/restore vẫn mở `open_runtime` thật trên store có sẵn; chỉ setup mới thuần túy dùng `open_cloned_runtime` đúng bộ migration. |
| Old binaries, old data, version fences | holds | Các test version fence (`test_remediation_c01_wal_admission.py`, `test_kernel_revocation.py`, `test_sp2_i2_wheel_compat.py`) giữ nguyên ngưỡng v1/v2/i2. |
| Every path to the same invariant | fixed here | Áp dụng đồng bộ LPT shard weights trên cả `shard_files` và kiểm `partition_files` (4 shard) qua `test_gate_receipt.py`. |
| Concurrency, shutdown and cutoffs | fixed here | Chấm dứt bão CPU `compileall -j 0` trên 6 shard; test daemon giữ nguyên trần cắt thực, chỉ thay `time.sleep` chờ clock giả bằng `FakeMonotonicClock`. |
| Authority, identity and scope | holds | Không nới bất kỳ kiểm tra ACL, scope hay credential nào. |
| Fail closed at limits and on the unknown | fixed here | `_privacy_scan.py` vẫn giữ nhánh fallback khi xuất hiện 4 code point case-fold đặc biệt; AST prefilter chỉ bỏ qua khi chắc chắn chuỗi mục tiêu vắng mặt. |
| What actually left, and to whom | holds | Toàn bộ bước gate ghi đầy đủ trong receipt; không có bước ẩn. |
| The world outside the daemon | holds | Không phụ thuộc file cache bên ngoài worktree gate. |
| Evidence and oracles | fixed here | Số đo đối chiếu `diag-remediate-v11` (trên `4ce42af`) đạt `< 275 s` và `<= 1200 s` JUnit ở cả 3.11 và 3.14 với đủ 3470 test. |
| The document agrees with itself | fixed here | Tài liệu khớp hoàn toàn diff thật, file thật và số đo XML thật. |

---

### Finding V4 & W1 (P1): `hook_entry.py` Atomic Append & Bug-Proof Testing

#### 1. Invariant
> Đường ghi log chẩn đoán lỗi của hook không được kéo dài thời gian chạy để ăn vào trần cứng 2 s, không được làm rách hoặc âm thầm bỏ dòng khi nhiều tiến trình ghi đồng thời, và không được phát sinh xuất ra `stderr` ngoài hợp đồng.

#### 2. Sibling sweep
- `src/superbrain/composition/hook_entry.py` (`_write_static_log`, dòng 40–53) và `src/superbrain/adapters/os/physical_fs.py` (`atomic_append_no_follow`):
  - Dùng `O_APPEND` ở mức OS (`open_append_no_follow`) sau `reject_links_upward`, `thread_lock_for`, `ensure_dir_tree_atomic`, `ensure_secure_regular_file_atomic`; mọi điểm bắt `BrainError`/`Exception` trong `hook_entry.py` (dòng 76, 116, 145, 147, 150, 170, 174) đều đi qua `_write_static_log`.
  - Xác nhận không ghi ra `sys.stderr`; watchdog đọc `stdout` và giữ tĩnh `stderr`.
- Kiểm chứng `bug-proof-testing` trên `tests/domain/test_capture_envelope_and_privacy.py::test_hook_entry_static_log_preserves_concurrent_lines_without_stderr`:
  - **RED (commit `04a45e4`, có lock loop + stderr warning):** `C:\Users\letru\sb2-trusted-local\evidence\v4-bugproof\red_04a45e4.log` -> `FAILED` (`RED_04a45e4_RC=1`, bắt đúng `superbrain.hook_entry: dropped log line phase=hook error.code=invalid_input (lock timeout)` và mất dòng dưới tranh chấp `OUTBOX_FILE_LOCK`). *(Ghi chú trung thực: trên baseline `e4f4163`, vấn đề busy-wait 500×2 ms + silent drop được đưa vào từ các commit khắc phục S2 sau `e4f4163` nên probe RED nhắm đúng hồi quy ở `04a45e4`.)*
  - **GREEN (mã hiện tại):** `C:\Users\letru\sb2-trusted-local\evidence\v4-bugproof\green_current.log` -> `1 passed, 21 deselected in 2.27s` (4 tiến trình con × 25 lần = 100 dòng + 4 dòng khởi đầu = 104 dòng toàn vẹn, `stderr == ""`, giữ nguyên dòng dưới tranh chấp `OUTBOX_FILE_LOCK`).
  - **MUTATION (bản sao cô lập thay `atomic_append_no_follow` bằng `read_bytes() + write_bytes()` không nguyên tử):** `C:\Users\letru\sb2-trusted-local\evidence\v4-bugproof\mut_killed.log` -> `KILLED` (`MUT_RC=1`, fail ở dòng 617 vì mất dòng ghi đồng thời).

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | Mỗi dòng log ghi bằng một lệnh `write` đơn trên descriptor `O_APPEND`; không giữ khóa qua ranh giới bước. |
| Restore, rollback and migration rewind state | not applicable | Log chẩn đoán tĩnh của hook không thuộc DB store/policy cần migrate hoặc restore. |
| Old binaries, old data, version fences | holds | Định dạng từng dòng `phase=... error.code=...\n` giữ nguyên hoàn toàn. |
| Every path to the same invariant | fixed here | Mọi nhánh lỗi trong `run_hook` và `main` đều dùng `_write_static_log`. |
| Concurrency, shutdown and cutoffs | fixed here | Không còn sleep/busy-wait trong khóa file; đường ghi log không ăn vào watchdog 2 s. |
| Authority, identity and scope | holds | `reject_links_upward`, `ensure_dir_tree_atomic` và `ensure_secure_regular_file_atomic` chặn symlink/junction và giữ ACL owner-only. |
| Fail closed at limits and on the unknown | fixed here | Từ chối link qua `reject_links_upward`; dưới tranh chấp khóa OS vẫn append nguyên tử thay vì drop dòng. |
| What actually left, and to whom | holds | Chỉ ghi `phase` và `error.code` tĩnh, không ghi dữ liệu đầu vào người dùng, không rò rỉ ra `stderr`. |
| The world outside the daemon | fixed here | An toàn trước nhiều tiến trình hook đồng thời và tranh chấp `OUTBOX_FILE_LOCK` từ tiến trình khác trên Windows. |
| Evidence and oracles | fixed here | Có đủ 3 receipt RED (`04a45e4`), GREEN, và KILLED mutation lưu trong `evidence/v4-bugproof/`. |
| The document agrees with itself | fixed here | Báo cáo khớp từng ký tự với `hook_entry.py` và test hiện hành. |

---

### Finding W3 & Rereview P2 (P2): Oracle Kill Tiến Trình, Job Object & Process Group (`test_gate_receipt.py`)

#### 1. Invariant
> Mọi oracle kiểm thử ngắt tiến trình vượt timeout hoặc dọn nhóm tiến trình phải xác nhận đối tượng mục tiêu và hậu duệ thực sự đã khởi chạy với danh tính OS xác thực, đồng thời chứng minh chúng đã kết thúc trước ngưỡng cutoff chứ không thể pass khi tiến trình con còn sống lúc kiểm tra.

#### 2. Sibling sweep
- `tests/architecture/test_gate_receipt.py::test_run_kills_a_process_that_exceeds_its_timeout`: khởi chạy cây con + cháu bằng `_process_tree_probe_script(..., sleep_s=6.0)` qua `gate.run(..., timeout_s=1.0)`; kiểm `exit_code is None`, xác nhận `child.started` & `grand.started` tồn tại (tức cả hai đã khởi động trước timeout), kiểm `_wait_process_tree_terminated` với PID + token khởi tạo OS (`GetProcessTimes` trên Windows, `/proc/<pid>/stat` hoặc `ps` trên POSIX) trả về rỗng trước cutoff `2.5 s`, và kiểm `not survived.txt` / `not grand_survived.txt`.
- `tests/architecture/test_gate_receipt.py::test_win32_job_object_lifecycle_and_non_win32_graceful_noop`: áp dụng cùng `_process_tree_probe_script` + `_wait_process_tree_terminated` cho `_win32_close_job(job, terminate=True)` trên toàn bộ cây `(proc, child, grandchild)` của Job Object trên Windows (tính đến launcher shim `uv` tạo tiến trình con); đồng thời trong nhánh `sys.platform == "linux"` kiểm chứng `gate.run` truyền `start_new_session=True`, `_kill_tree` gọi `os.killpg(pid, signal.SIGKILL)` + `proc.kill()`, và nhánh `ProcessLookupError` vẫn gọi `proc.kill()`. Giữ nguyên 100% tập node ID (`153` test trong `test_gate_receipt.py`, `3470` toàn repo).
- Sibling khác đã rà soát trong `tests/architecture/test_gate_receipt.py`: `test_run_does_not_wait_forever_for_a_killed_process`, `test_run_reports_a_timeout_when_killing_the_timed_out_process_fails`, `test_failed_kill_of_a_started_phase_is_not_reported_as_could_not_start` — dùng mock `Hung`/`TimedOutProcess` để kiểm báo cáo lỗi/khôi phục khi kill thất bại, vẫn hợp lệ.
- Bằng chứng thực nghiệm (`C:\Users\letru\sb2-trusted-local\evidence\w3-bugproof\`):
  - Probe `5ee4f35` (`probe_5ee4f35_false_pass.log`): runner mô phỏng `0.2 s` không kill pass giả khi `poll() is None` rồi ghi `survived.txt`.
  - Probe trên bản sửa (`red_probe_caught.log`): cả `0p2s_nokill` lẫn `started_tree_nokill` đều FAIL ngay vì bắt được PID + creation token còn sống.
  - GREEN (`green_314.log`, `green_311.log`): Python 3.14 đạt `1.27 s` + `0.32 s` (`1.95 s`), Python 3.11 đạt `1.30 s` + `0.32 s` (`2.00 s`).
  - Mutation (`mut_run_killed.log`, `mut_job_killed.log`, `mut_posix_killpg_killed.log`): cả 3 biến thể bỏ kill (`gate.run`, `_win32_close_job`, và `_kill_tree` thiếu `killpg`) đều bị bắt.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | File `.started` được ghi nguyên tử qua file tạm + `os.replace` sau khi khởi tạo xong; marker `.survived` chỉ ghi sau `sleep_s`. |
| Restore, rollback and migration rewind state | not applicable | Test vòng đời tiến trình OS tạm thời trong `tmp_path`. |
| Old binaries, old data, version fences | holds | Chạy `sys.executable -I`; xử lý được trường hợp Windows `.venv\Scripts\python.exe` là launcher shim tạo process con. |
| Every path to the same invariant | fixed here | Áp cùng oracle xác thực khởi chạy + kết thúc đúng danh tính cho `gate.run`, Win32 Job Object `_win32_close_job`, và đường POSIX `start_new_session`/`killpg` ở `_kill_tree`. |
| Concurrency, shutdown and cutoffs | fixed here | Toàn bộ cây con/cháu phải thoát hoàn toàn trước `cutoff_at = began + 2.5 s` (không còn kẽ hở ngủ ngắn 1.5 s < 3.0 s). |
| Authority, identity and scope | fixed here | Kiểm tra exact process identity (`(pid, GetProcessTimes / proc starttime)`), tránh nhầm khi OS tái sử dụng PID; cleanup `finally` cũng chỉ kill khi khớp token. |
| Fail closed at limits and on the unknown | fixed here | Nếu `.started` chưa xuất hiện trước timeout hoặc còn bất kỳ PID khớp token nào sống qua cutoff, assertion fail ngay; không dọn trước khi assert. |
| What actually left, and to whom | holds | Mọi file tạm và tiến trình đều nằm cô lập trong `tmp_path` và bị dọn ở `finally`. |
| The world outside the daemon | fixed here | Bao phủ cả hành vi launcher trampoline trên Windows lẫn process group trên POSIX; chạy ổn định dưới tải 6 shard. |
| Evidence and oracles | fixed here | Có đầy đủ probe tái hiện `5ee4f35`, GREEN 3.14/3.11, và 3 mutation bỏ kill bị tiêu diệt lưu tại `evidence/w3-bugproof/`. |
| The document agrees with itself | fixed here | Khớp chính xác code mới trong `tests/architecture/test_gate_receipt.py` và kết quả kiểm chứng thực tế. |

---

### Finding W4 (P3): Khóa Schema Dict Seed Outbox (`test_capture_envelope_and_privacy.py:991`)

#### 1. Invariant
> Mọi bộ tạo dữ liệu mẫu dạng dict thuần dùng để tăng tốc seed kiểm thử phải có bước đối chiếu trực tiếp với phương thức xuất cấu trúc chính tắc của kiểu dữ liệu sản phẩm để không lệch âm thầm khi schema đổi.

#### 2. Sibling sweep
- `tests/domain/test_capture_envelope_and_privacy.py:991-1026` (`_seed_outbox_frames`): tạo `sample_rec = CaptureEventRecord(...)` và `assert sample_dict == sample_rec.to_dict()`.
- Kiểm tra toàn bộ file test sửa đổi trên nhánh không còn dict thủ công tạo frame outbox nào khác thiếu kiểm tra tương đương.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | Seed dữ liệu thực hiện trước pha kiểm idempotency/backlog trên `trusted_tmp`. |
| Restore, rollback and migration rewind state | not applicable | Outbox spool test cô lập trong `trusted_tmp`. |
| Old binaries, old data, version fences | fixed here | Đảm bảo dict tạo sẵn luôn khớp đúng schema hiện hành của `CaptureEventRecord.to_dict()`. |
| Every path to the same invariant | fixed here | Mọi caller của `_seed_outbox_frames` (dòng 1091, 1111, 1233) đều đi qua assertion này. |
| Concurrency, shutdown and cutoffs | holds | Dựng dữ liệu tuần tự trước khi chạy test hook/backlog. |
| Authority, identity and scope | holds | Giới hạn trong `trusted_tmp`. |
| Fail closed at limits and on the unknown | fixed here | Sai khác trường hoặc kiểu dữ liệu khiến `assert sample_dict == sample_rec.to_dict()` fail ngay lập tức. |
| What actually left, and to whom | holds | Khung JSON được tuần tự hóa đúng định dạng chính tắc. |
| The world outside the daemon | holds | Không phụ thuộc dữ liệu ngoài. |
| Evidence and oracles | fixed here | Đã chạy trong `green_current.log` và toàn bộ `diag-remediate-v10`. |
| The document agrees with itself | fixed here | Khớp dòng 1002–1026 của `test_capture_envelope_and_privacy.py`. |

---

## 2. Kết Quả Cân Chỉnh Task 5 (`scripts/gate.py` `_HEAVY_FILE_COST_MS`)

Từ số đo thực tế `diag-remediate-v11` (`py3.14` và `py3.11` trên commit `4ce42af`), toàn bộ 194 file test được cập nhật vào `_HEAVY_FILE_COST_MS`:

| Phiên bản Python | `test_job_s` (Mục tiêu < 275 s) | `pytest_wall` | Tổng JUnit `<testsuite>` / `testcase` | Chênh lệch shard thực đo `v11` → mô phỏng sau Task 5 | Inventory |
|---|---:|---:|---:|---:|---:|
| **3.14** (`diag-remediate-v11`) | **232.46 s** | 195.19 s | **1081.63 s** / 1071.39 s (≤ 1200 s) | 15.1% → **5.7%** | 3470 (0 fail) |
| **3.11** (`diag-remediate-v11`) | **247.61 s** | 202.89 s | **1160.33 s** / 1144.60 s (≤ 1200 s) | 8.4% → **5.4%** | 3470 (0 fail) |

So sánh với `claude-r11-diag` (`e4f4163`, testsuite time sum):
- Python 3.14: `1657.2 s` -> **`1081.63 s`** (giảm **575.6 s**, `-34.7%`).
- Python 3.11: `1551.3 s` -> **`1160.33 s`** (giảm **391.0 s**, `-25.2%`).

---

## 3. Đối Chiếu T01–T50 và Bảng Nghiệm Thu A1–A7 (Số Liệu Thật `claude-r11-diag` -> `diag-remediate-v11`)

Kiểm tra inventory bằng `gate.parse_collected`:
- Baseline (`claude-r11-diag`): `3469` node ID.
- Hiện tại (`diag-remediate-v11`): **`3470` node ID** (`3414 passed, 56 skipped, 0 failed`; `+1` test W1/V4 `test_hook_entry_static_log_preserves_concurrent_lines_without_stderr`). Không có bất kỳ test nào bị xóa, gộp hay nới lỏng oracle.

### Bảng đo T01–T25 + file đã sửa (`diag-remediate-v11/py3.14` & `py3.11`, tổng thời gian `testcase` theo file)

| ID / Nhóm | File thật | Base 3.14 → Sau 3.14 (Target A5) | Max case 3.14 (Sau) | Base 3.11 → Sau 3.11 | Trạng thái A5/A6 & Ghi chú No-Go có chứng cứ |
|---|---|---:|---:|---:|---|
| **T01** | `tests/integration/test_kernel_crash_recovery.py` | 129.9 → **72.7 s** (≤ 77.9) | 10.0 s | 112.9 → **68.1 s** | **ĐẠT A5/A6** (K1/K3/K4 wheel & template cache). |
| **T02** | `tests/integration/test_apply_journal_crash_matrix.py` | 93.5 → **62.8 s** (≤ 56.1) | 12.9 s | 83.7 → **63.0 s** | **No-Go có chứng cứ** (-30.7 s / -32.8%): 15 ca crashpoint chạy thật trên `-I` wheel subprocess (ca đầu gánh ~12 s setup wheel/venv). |
| **T03** | `tests/integration/test_kernel_native_receipt_contract.py` | 66.7 → **42.2 s** (≤ 40.0) | 8.9 s | 61.2 → **41.5 s** | **No-Go có chứng cứ** (-24.5 s / -36.7%, lệch 2.2 s): 37 test sinh tiến trình shim/daemon/wheel thật. |
| **T04** | `tests/integration/test_sp2_i2_wheel_compat.py` | 62.2 → **29.6 s** (≤ 37.3) | 24.9 s | 59.8 → **33.2 s** | **ĐẠT A5/A6** (`uv pip install --compile-bytecode`, giữ `len(wheels) == 1`). |
| **T05** | `tests/integration/test_kernel_daemon.py` | 57.6 → **38.9 s** (≤ 34.6) | 5.9 s | 55.3 → **46.2 s** | **No-Go có chứng cứ** (-18.7 s, max case giảm từ 12.1 s xuống 5.9 s): 36 ca daemon/arbiter/writer-lock thực; dùng `FakeMonotonicClock` ở test shutdown overrun. |
| **T06** | `tests/integration/test_i3_wheel_e2e.py` | 57.4 → **33.4 s** (≤ 34.4) | 33.4 s | 43.1 → **32.8 s** | **ĐẠT A5/A6** (19 `run_installed_command` + 1 wheel setup). |
| **T07** | `tests/integration/test_capture_ack_and_crash_matrix.py` | 54.4 → **24.7 s** (≤ 32.6) | 5.3 s | 51.8 → **27.7 s** | **ĐẠT A5/A6**. |
| **T08** | `tests/integration/test_kernel_cli.py` | 52.1 → **21.0 s** (≤ 31.3) | 8.1 s | 43.6 → **21.2 s** | **ĐẠT A5/A6**. |
| **T09** | `tests/integration/test_t9_signal_stop_conversion.py` | 41.7 → **14.7 s** (≤ 25.0) | 1.1 s | 30.7 → **14.8 s** | **ĐẠT A5/A6**. |
| **T10** | `tests/architecture/test_gate_receipt.py` | 39.1 → **19.9 s** (≤ 27.4) | 2.9 s | 32.8 → **20.5 s** | **ĐẠT A5/A6** (AST prefilter + biên W3). |
| **T11** | `tests/integration/test_i3_rereview_init_and_accounting.py` | 37.7 → **35.0 s** (≤ 26.4) | 1.9 s | 38.4 → **43.9 s** | **No-Go có chứng cứ**: 49 test init/stage recovery dùng tiến trình con & filesystem thật. |
| **T12** | `tests/storage/test_crash_matrix.py` | 36.9 → **21.0 s** (≤ 25.8) | 1.5 s | 29.9 → **19.2 s** | **ĐẠT A5/A6** (K3 template cache `_I1_SEED_CACHE`). |
| **T13** | `tests/storage/test_kernel_revocation.py` | 32.4 → **26.9 s** (≤ 22.7) | 13.3 s | 36.6 → **28.7 s** | **No-Go có chứng cứ**: `cProfile` (`task-302`) xác nhận chi phí ở `migrate_offline` (12×) + `BoundedJsonWorker` (18×) chứng minh rào chặn v2. |
| **T14** | `tests/application/test_continuity_worker_scheduling.py` | 32.4 → **29.2 s** (≤ 22.7) | 4.4 s | 34.9 → **39.6 s** | **No-Go có chứng cứ**: `cProfile` (`task-267`/`task-284`) xác nhận 25 test chạy 473+ lượt `record_session_event` + `OwnerLoop` SQLite thật. |
| **T16** | `tests/storage/test_runtime.py` | 33.4 → **16.0 s** (≤ 23.4) | 1.4 s | 25.3 → **14.8 s** | **ĐẠT A5/A6** (`open_cloned_runtime`). |
| **T17** | `tests/storage/test_restore.py` | 31.4 → **20.9 s** (≤ 22.0) | 2.3 s | 27.1 → **18.5 s** | **ĐẠT A5/A6** (`open_cloned_runtime` + K3 cache). |
| **T18** | `tests/domain/test_capture_envelope_and_privacy.py` | 27.2 → **17.5 s** (≤ 19.0) | 5.4 s | 22.6 → **19.8 s** | **ĐẠT A5 trên 3.14** (-9.7 s dù thêm 1 test W1/V4 + 2 s real watchdog cap tests). |
| **T19** | `tests/application/test_t8_review_p01_wrapped_paths.py` | 19.5 → **8.3 s** (≤ 13.6) | 0.5 s | 24.5 → **13.5 s** | **ĐẠT A5/A6** (memoize + fast path không-ASCII). |
| **T20** | `tests/application/test_t8_review_p01_r2_edge_globs.py` | 22.9 → **10.9 s** (≤ 16.0) | 0.5 s | 23.5 → **12.5 s** | **ĐẠT A5/A6**. |
| **T25** | `tests/storage/test_ledger.py` | 19.7 → **11.3 s** (≤ 13.8) | 2.0 s | 17.4 → **11.0 s** | **ĐẠT A5/A6** (AST prefilter). |
| **BK/RC** | `tests/storage/{test_backup,test_reconcile}.py` | BK **15.4 s**, RC **4.1 s** | 1.2 s | BK **15.0 s**, RC **3.9 s** | Giảm 5 subprocess setup bằng `seed_crash_event_root` (giữ `run_until_crash("seed_event", ...)` ở `test_backup.py:601`). |

### Bảng Tiêu Chí A1–A7 Cho Các File Đã Sửa Trên `remediate-runtime-opt`

| File đã sửa | A1 (Inventory) | A2 (Assert giữ nguyên) | A3 (Mutation / Bug-proof) | A4 (Tải 6 shard 3.14 & 3.11) | A5/A6 (Thời gian) | A7 (Lint / Type / LF) |
|---|---|---|---|---|---|---|
| `tests/domain/test_capture_envelope_and_privacy.py` + `hook_entry.py` | 21 → 22 (+1 test W1) | Giữ nguyên + W4 assert | **RED/GREEN/MUTATION KILLED** (`evidence/v4-bugproof/`) | Pass trong `v10`, `v11` (3.14 & 3.11) | **Đạt 3.14** (27.2 → 17.5 s) | Đạt |
| `tests/architecture/test_gate_receipt.py` + `scripts/gate.py` | 153 = 153 | Giữ nguyên + oracle cây tiến trình W3/P2 | **PROBE/GREEN/3-MUTATION KILLED** (`evidence/w3-bugproof/`), `153 passed in 11.25s` | Pass trong `v10`, `v11` (3.14 & 3.11) | **Đạt** (39.1 → 19.9 s) | Đạt |
| `tests/integration/test_sp2_i2_wheel_compat.py` + `tests/support/inc2_fixture.py` | 2 = 2 | Khôi phục `len(wheels)==1` & SHA-256 | Kiểm thực wheel I2 vs SP2 + `py=194 pyc=194` trên 3.14/3.11 | Pass trong `v11` (3.14 & 3.11) | **Đạt** (62.2 → 29.6 s) | Đạt |
| `tests/application/test_t8_review_p01_{wrapped_paths,r2_edge_globs,r3_spellings}.py` + `_privacy_scan.py` | 64=64, 73=73 | Giữ nguyên 100% wrapper/glob | Kiểm tương đương `[a-z]+` IGNORECASE trên 3.11 & 3.14 (`0x130, 0x131, 0x17f, 0x212a`) | Pass trong `v10`, `v11` (3.14 & 3.11) | **Đạt** (19.5→8.3, 22.9→10.9 s) | Đạt |
| `tests/integration/test_kernel_daemon.py` | 36 = 36 | Giữ nguyên shutdown cutoff | Kiểm overrun trên `FakeMonotonicClock` | Pass trong `v10`, `v11` (3.14 & 3.11) | No-Go (-18.7 s; 36 ca daemon thực) | Đạt |
| `tests/integration/{test_t9_client_sighting,test_kernel_native_receipt_contract,test_t9_socket_readiness}.py` | Không đổi | Giữ nguyên `< 0.10 s` & `< collector_timeout_s` | Reset mốc đồng hồ ngay sau `open_client`; `test_t9_r02` dùng `250 ms < collector_timeout_s (500 ms)` tránh jitter TLS 6 shard | Pass trên 3.14 & 3.11 | Đạt | Đạt |
| `tests/application/test_remediation_i2_t5_worker.py` | Không đổi | Giữ nguyên `wait_cancelled` & `seen_attempts == [1, 2]` | Đồng bộ timeout chờ hủy `0.3` -> `BOUND_WAIT_S` với toàn bộ 8 sibling `wait_cancelled` | Đã kiểm cục bộ + gate 3.14/3.11 | Không tăng khi hủy ngay | Đạt |
| `tests/integration/test_kernel_privacy_persistence.py` | Không đổi | Giữ nguyên toàn bộ assert privacy & `drop_episode` trực tiếp | Retry 1 lần đúng `idempotency_key` nếu `CLIENT_TOOL_BUDGET_NS` 2 s gặp nghẽn CPU >2 s | Đã kiểm cục bộ + gate 3.14/3.11 | Không đổi khi không stall | Đạt |
| `tests/support/crash_cases.py` + `tests/storage/{test_backup,test_reconcile,test_restore,test_crash_matrix}.py` | Không đổi | Không đổi | `test_matrix_detects_a_removed_crashpoint` pass + mutation cô lập `Store.store_content` bị bắt tại `test_reconcile.py:61,71` | Pass trong `v11` (3.14 & 3.11) | **Đạt** (`test_crash_matrix` 36.9→21.0 s) | Đạt |
| `tests/storage/{test_runtime,test_kernel_revocation,test_ledger,test_remediation_c02_lost_main_db,test_flush_routing,test_remediation_c01_wal_admission,test_remediation_c01_r4_reading_leftovers}.py` | Không đổi | Không đổi | Không đổi đường test migration/version fence/sync spy | Pass trong `v10`, `v11` (3.14 & 3.11) | `test_runtime`, `test_restore`, `test_ledger` đạt | Đạt |
| `tests/support/crash_child.py` | Không đổi | Không đổi | Sửa `from __future__ import annotations` cho 3.11 | Pass trong `v10`, `v11` (3.14 & 3.11) | Hỗ trợ T01/T02 | Đạt |

---

## 4. Kết Quả Gate Đã Đo Trên `5ee4f35` Và Bước Nghiệm Thu Sau Vá W3

### Kết quả 4 lượt gate trên commit sạch `5ee4f35` (`final-remediate-gate-v6`, cache wheel lạnh, `--shards 6`):
- **Python 3.14 Lượt 1:** `accepted=True`, `test_job_seconds = 231.918 s` (`< 275 s`), JUnit `<testsuite>` = **`1108.453 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed` (`3470` total).
- **Python 3.14 Lượt 2:** `accepted=True`, `test_job_seconds = 233.138 s` (`< 275 s`), JUnit `<testsuite>` = **`1119.918 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed`.
- **Python 3.11 Lượt 1:** `accepted=True`, `test_job_seconds = 230.891 s` (`< 275 s`), JUnit `<testsuite>` = **`1126.327 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed`.
- **Python 3.11 Lượt 2:** `accepted=True`, `test_job_seconds = 230.938 s` (`< 275 s`), JUnit `<testsuite>` = **`1129.004 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed`.
- Full serial suite trên `5ee4f35` (Python 3.14): `3414 passed, 56 skipped, 6 warnings in 539.26 s`.

### Chạy gate xác nhận sau khi sửa W3/P2 trên commit sạch kế tiếp:
1. Lưu commit sửa W3/P2 (`tests/architecture/test_gate_receipt.py`) + tài liệu đối chiếu này lên nhánh `remediate-runtime-opt` (`tree_is_clean(repo) == True`).
2. Chạy `scripts.gate --shards 6` (cache wheel lạnh, 3.14 × 2 và 3.11 × 2) vào `C:\Users\letru\sb2-trusted-local\evidence\final-remediate-gate-v7\`.
3. Kiểm tra lại `ruff check src tests scripts`, `mypy`, `lint-imports` và bàn giao cho Reviewer độc lập đối chiếu thay đổi 29 tệp + W3 và quyết định reseal `.verification/task9-seal.json`.
