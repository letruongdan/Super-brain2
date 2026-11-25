# Báo Cáo Khắc Phục Kiểm Tra Độc Lập & Đo Lường Thực Tế (`remediate-runtime-opt`)

**Tài liệu kiểm tra độc lập Lượt 1:** [2026-11-24-test-suite-optimization-verification.md](2026-11-24-test-suite-optimization-verification.md)
**Tài liệu kiểm tra độc lập Lượt 2:** [2026-11-24-test-suite-optimization-verification-r2.md](2026-11-24-test-suite-optimization-verification-r2.md)
**Tái kiểm SP2-3 tại 5ee4f35:** [2026-11-25-sp2-3-acceptance-rereview-5ee4f35.md](2026-11-25-sp2-3-acceptance-rereview-5ee4f35.md)
**Tái kiểm SP2-3 tại 4f5138c:** [2026-11-25-sp2-3-acceptance-rereview-4f5138c.md](2026-11-25-sp2-3-acceptance-rereview-4f5138c.md)
**Tái kiểm SP2-3 tại b289f87:** [2026-11-25-sp2-3-acceptance-rereview-b289f87.md](2026-11-25-sp2-3-acceptance-rereview-b289f87.md)
**Review oracle trước reseal tại b289f87:** [2026-11-25-sp2-3-reseal-review-b289f87.md](2026-11-25-sp2-3-reseal-review-b289f87.md)
**Kế hoạch gốc:** [2026-11-23-test-suite-runtime-optimization.md](../superpowers/plans/2026-11-23-test-suite-runtime-optimization.md)
**Nhánh thực hiện:** `remediate-runtime-opt` (tách biệt hoàn toàn; `thuc_hien_ke_hoach_sp2` giữ nguyên tại `5f73a0a`)
**Commit tối ưu code đã đo:** `b289f87` (`final-remediate-gate-v8`, 4/4 lượt đạt `< 275 s` và `≤ 1200 s`) + vá oracle shutdown Reseal-P2 trên `remediate-runtime-opt`
**Trạng thái seal & review:** Chưa reseal `.verification/task9-seal.json` (chờ reviewer duyệt 29 tệp sau khi vá oracle shutdown Reseal-P2 và chạy `test_lock.py check`); chưa có tuyên bố "Codex đã duyệt".

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
- `tests/architecture/test_gate_receipt.py::test_run_kills_a_process_that_exceeds_its_timeout`: khởi chạy cây con + cháu bằng `_process_tree_probe_script(..., sleep_s=6.0)` qua `gate.run(..., timeout_s=1.0)`; kiểm `exit_code is None`, xác nhận `child.started` & `grand.started` tồn tại (tức cả hai đã khởi động trước timeout), kiểm `_wait_process_tree_terminated` với PID + token khởi tạo OS (`GetProcessTimes` trên Windows, `/proc/<pid>/stat` hoặc `ps` trên POSIX) trả về rỗng trước cutoff `2.5 s`, và kiểm `not survived.txt` / `not grand_survived.txt`. Trong `finally`, `_collect_started_identities(child_started, grand_started)` thu hồi mọi PID đã công bố kể cả khi cây chỉ khởi động một phần (ví dụ `grand.started` đã ghi nhưng `child.started` chưa ghi).
- `tests/architecture/test_gate_receipt.py::test_win32_job_object_lifecycle_and_non_win32_graceful_noop`: nạp `(proc.pid, proc_ticks)` ngay sau `Popen` trước vòng đợi `.started`, áp cùng `_process_tree_probe_script` + `_wait_process_tree_terminated` cho `_win32_close_job(job, terminate=True)` trên toàn bộ cây `(proc, child, grandchild)`, và trong `finally` thu hồi cả `_collect_started_identities(child_started, grand_started)` phòng trường hợp partial-start; đồng thời trong nhánh `sys.platform == "linux"` kiểm chứng `gate.run` truyền `start_new_session=True`, `_kill_tree` gọi `os.killpg(pid, signal.SIGKILL)` + `proc.kill()`, và nhánh `ProcessLookupError` vẫn gọi `proc.kill()`. Giữ nguyên 100% tập node ID (`153` test trong `test_gate_receipt.py`, `3470` toàn repo).
- Sibling khác đã rà soát trong `tests/architecture/test_gate_receipt.py`: `test_run_does_not_wait_forever_for_a_killed_process`, `test_run_reports_a_timeout_when_killing_the_timed_out_process_fails`, `test_failed_kill_of_a_started_phase_is_not_reported_as_could_not_start` — dùng mock `Hung`/`TimedOutProcess` để kiểm báo cáo lỗi/khôi phục khi kill thất bại, vẫn hợp lệ.
- Bằng chứng thực nghiệm (`C:\Users\letru\sb2-trusted-local\evidence\w3-bugproof\`):
  - Probe `5ee4f35` (`probe_5ee4f35_false_pass.log`): runner mô phỏng `0.2 s` không kill pass giả khi `poll() is None` rồi ghi `survived.txt`.
  - Probe trên bản sửa (`red_probe_caught.log`): cả `0p2s_nokill` lẫn `started_tree_nokill` đều FAIL ngay vì bắt được PID + creation token còn sống.
  - Probe partial-start (`partial_start_cleanup.log`): giữ tiến trình cha trước `child.started`, để tiến trình cháu ghi `grand.started` và trả timeout không kill -> assertion khởi động bắt lỗi (`child process tree never started before timeout`), `finally` dọn sạch cháu (`Grandchild alive after finally cleanup: False`).
  - GREEN (`green_314.log`, `green_311.log` và full suite `153 passed in 11.30s`): toàn bộ đạt.
  - Mutation (`mut_run_killed.log`, `mut_job_killed.log`, `mut_posix_killpg_killed.log`): cả 3 biến thể bỏ kill (`gate.run`, `_win32_close_job`, và `_kill_tree` thiếu `killpg`) đều bị bắt.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | fixed here | Mỗi `.started` ghi nguyên tử qua `os.replace`; kể cả lỗi ở bước kiểm tra một phần, `finally` thu hồi độc lập từng file `.started` đã tồn tại. |
| Restore, rollback and migration rewind state | not applicable | Test vòng đời tiến trình OS tạm thời trong `tmp_path`. |
| Old binaries, old data, version fences | holds | Chạy `sys.executable -I`; xử lý được trường hợp Windows `.venv\Scripts\python.exe` là launcher shim tạo process con. |
| Every path to the same invariant | fixed here | Áp cùng oracle khởi chạy + cleanup partial-start + kết thúc đúng danh tính cho cả `gate.run` (`test_run_kills_...`), Win32 Job Object (`test_win32_job_object_...`), và đường POSIX `killpg`. |
| Concurrency, shutdown and cutoffs | fixed here | Toàn bộ cây con/cháu phải thoát hoàn toàn trước `cutoff_at = began + 2.5 s` (không còn kẽ hở ngủ ngắn 1.5 s < 3.0 s) và không rò rỉ hậu duệ nếu timeout xảy ra giữa lúc khởi động. |
| Authority, identity and scope | fixed here | Kiểm tra exact process identity (`(pid, GetProcessTimes / proc starttime)`), tránh nhầm khi OS tái sử dụng PID; cleanup `finally` cũng chỉ kill khi khớp token. |
| Fail closed at limits and on the unknown | fixed here | Nếu `.started` chưa xuất hiện trước timeout hoặc còn bất kỳ PID khớp token nào sống qua cutoff, assertion fail ngay; cleanup chỉ chạy sau assertion ở `finally`. |
| What actually left, and to whom | holds | Mọi file tạm và tiến trình đều nằm cô lập trong `tmp_path` và bị dọn ở `finally`. |
| The world outside the daemon | fixed here | Bao phủ cả launcher trampoline trên Windows, partial-start giữa cha/cháu, lẫn process group trên POSIX; chạy ổn định dưới tải 6 shard. |
| Evidence and oracles | fixed here | Có đầy đủ probe `5ee4f35`, probe partial-start (`partial_start_cleanup.log`), GREEN 3.14/3.11, và 3 mutation bỏ kill bị tiêu diệt lưu tại `evidence/w3-bugproof/`. |
| The document agrees with itself | fixed here | Khớp chính xác code mới trong `tests/architecture/test_gate_receipt.py` và kết quả kiểm chứng thực tế. |

---

### Finding Reseal-P2 (P2): Oracle Cutoff Chung Cho Shutdown Daemon (`test_kernel_daemon.py:5223`)

#### 1. Invariant
> Ca kiểm cutoff chung lúc shutdown phải phát hiện được khi một lần gọi tiếp nối tự mở deadline mới hoặc tổng thời gian chờ của các pha `stop()` cộng dồn vượt quá phần ngân sách còn lại kể từ lần khởi tạo đầu tiên.

#### 2. Sibling sweep
- `tests/integration/test_kernel_daemon.py::test_stop_applies_shared_cutoff_to_arbiter_join_and_reports_overrun_when_arbiter_callback_blocks` (Part A):
  - Thu hẹp biên dư so với `grace_s`: chuyển từ `grace_s=0.35`, `pre_release_deadline = stop_started + 0.85` (biên dư `0.50 s > 0.35 s`) sang **`grace_s=0.55`**, **`pre_release_deadline = stop_started + 0.85`** (biên dư `0.30 s < grace_s = 0.55 s` và nhỏ hơn probe `+0.40 s`), giữ nguyên `third_stop_fut` (`grace_s=0.5`, `timeout=0.30`).
  - Dùng `monkeypatch.context()` cục bộ trên instance `loop_a._closed_done.wait`, `owner_thread_a.join`, `arbiter_thread_a.join` ngay trước `loop_a.stop(grace_s=0.55)` để xác minh ở biên tham số:
    1. `observed_deadlines == [first_cutoff, first_cutoff]` (`loop_a._stop_wall_deadline` không thay đổi khi caller thứ hai `grace_s=3.0` và thứ ba `grace_s=0.5` đi vào).
    2. Mọi lệnh `loop_a._closed_done.wait(timeout)` đều có `0 <= timeout <= max(0, first_cutoff - called_at) + 0.02` và `<= 0.55`; riêng caller thứ ba sau khi `first_cutoff` đã qua chỉ nhận `timeout <= 0.05` (không nhận `0.5 s`).
    3. Mọi lệnh `owner_thread_a.join(timeout)` / `arbiter_thread_a.join(timeout)` đều có `timeout <= max(0.01, first_cutoff - called_at) + 0.02` và `<= 0.55 + 0.02`.
- Sibling đã kiểm:
  - Part B (`loop_b`, dòng 5350–5375): kiểm trường hợp callback được giải phóng trước deadline (`1.43 s < grace_s = 1.50 s`) -> giữ nguyên oracle.
  - Part C (`serve`, dòng 5382–5475): kiểm foreground `serve()` chờ cả hai thread kết thúc khi `OVERRUN` và trả về `rc = 1` -> giữ nguyên oracle.
  - `tests/integration/test_t9_r21_shutdown_wait.py` và W3 (`tests/architecture/test_gate_receipt.py`): giữ nguyên, cùng mô hình quan sát biên `join` / cutoff.
- Bằng chứng thực nghiệm (`C:\Users\letru\sb2-trusted-local\evidence\daemon-cutoff-bugproof\`):
  - **Probe +0.40 s (`red_extra_wait_0p40s.log`):** chèn `time.sleep(0.40)` ngay trước khi `OwnerLoop.stop` trả về -> **FAIL** ngay tại `assert first_returned_before_cb_release is True` (`PROBE_0P40S_RC=1`, 1 failed in 1.82s).
  - **Mutation mở lại deadline (`mut_reopen_deadline_killed.log`):** caller thứ hai ghi đè `_stop_wall_deadline` bằng `now + 3.0` -> **FAIL** (`MUT_REOPEN_RC=1`, 1 failed in 1.66s).
  - **GREEN:** `green_314.log` (`2.51 s` call / `3.69 s` total), `green_311.log` (`2.65 s` call / `3.54 s` total), và toàn file `test_kernel_daemon.py` đạt **36 passed in 21.79s** cùng `ruff`, `mypy` (431 files), `lint-imports` (2 contracts kept).

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | Part A vẫn tạo/đóng store thật, kiểm endpoint bị xóa và mở lại thành công ở epoch `epoch_a + 1`. |
| Restore, rollback and migration rewind state | not applicable | Kiểm tra điều phối cutoff bộ nhớ RAM và join thread trong `OwnerLoop.stop`. |
| Old binaries, old data, version fences | holds | Khởi tạo daemon runtime chuẩn với store v7, giữ nguyên phiên bản schema. |
| Every path to the same invariant | fixed here | Kiểm cả caller 1 (`0.55`), caller 2 (`3.0`), caller 3 (`0.5`) trên `_stop_wall_deadline`, `_closed_done.wait`, `owner_thread.join` và `arbiter_thread.join`. |
| Concurrency, shutdown and cutoffs | fixed here | Thu hẹp slack về `0.30 s < grace_s (0.55 s)` kết hợp spy tham số wait/join; chặn hoàn toàn lượt chờ lặp pha hay `+0.40 s`. |
| Authority, identity and scope | holds | Giữ nguyên token/scope của `_daemon_template`. |
| Fail closed at limits and on the unknown | fixed here | Timeout join/wait bằng `None` hoặc vượt quá `first_cutoff - now` đều khiến assertion fail; quá `pre_release_deadline` cũng fail. |
| What actually left, and to whom | holds | Callback vẫn bị chặn bởi event thật và chỉ nhả sau khi các `stop()` trả `OVERRUN`. |
| The world outside the daemon | holds | Chừa biên `0.30 s` đủ cho jitter Windows 6 shard (`~0.01–0.05 s`) như baseline `0.35 s` trước đây. |
| Evidence and oracles | fixed here | Đủ bằng chứng GREEN 3.14/3.11 (36/36 pass), probe `+0.40 s` FAIL (`rc=1`) và mutation mở deadline FAIL (`rc=1`). |
| The document agrees with itself | fixed here | Khớp dòng 5223–5330 của `test_kernel_daemon.py`, `owner_loop.py` và bảng A1–A7 dưới đây. |

---

### Finding Reseal2-P2a (P2): Vòng Đời Kết Nối Trong Ca Đối Chứng Lookup PID (`test_kernel_native_receipt_contract.py`)

#### 1. Invariant
> Mọi ca đối chứng khẳng định định danh tiến trình client từ bộ quan sát socket bất đồng bộ phải giữ kết nối TCP còn sống tới khi pha lookup nhìn thấy 4-tuple và chốt timestamp trước lúc đóng socket, không phụ thuộc vào tốc độ chạy đua giữa luồng HTTP trả nhanh và thread pool quan sát.

#### 2. Sibling sweep
- `tests/integration/test_kernel_native_receipt_contract.py`:
  - Thêm context helper `_hold_lookup_before_reply(monkeypatch, native_owner)` dùng cục bộ trong `with` cho từng ca đối chứng: theo dõi `_lookup_loopback_client_pid` theo từng `(client_port, listen_port)` để ghi `(pid, saw_ns)` và mở khóa `_release_owner_reply` / `_write_200_best_effort` ngay trước khi server flush response & đóng socket.
  - `test_t9_r02_handshake_independent_of_collector_latency`:
    - **Part 1 (`corr-r02-pos`):** chạy trong `_hold_lookup_before_reply`, kiểm đủ `owner_call` và `socket_observation` (`observation_status == "ok"`, `client_pid == os.getpid()`, `client_started_at == daemon_started_at`, `started_at <= observed_at <= ended_at`, `so["ended_at"] >= ev1[0]["ended_at"]`, và `saw_ns <= flush_ns` trên tuple nhìn thấy). Context thoát hoàn toàn trước Part 2 & Part 3.
    - **Part 2 (`corr-r02-held`):** giữ nguyên không prewait (`worker_entered_event` trong 5 ms, trả lời `< 0.25 s`, suy biến `observation_incomplete`).
    - **Part 3 (`corr-r02-deadline`):** giữ đồng hồ thực kiểm cutoff 250 ms < 500 ms mà không chặn reply; khẳng định `res_deadline["ok"] is True` và `t_deadline_elapsed < 0.25`, đồng thời fail closed khi kiểm receipt (`"ok"` khớp PID/start_time hoặc `"observation_incomplete"` với `client_pid is None` dưới nghẽn 6 shard).
  - **Sibling sửa cùng lỗi:** `test_owner_driver_non_release_error_quiesced_and_timeout_logging` Part 1 (`corr-submit-boom`, dòng 2961) và Part 2 (`corr-quiesced`, dòng 3000) cùng dùng `_write_200_best_effort` trả nhanh `get_health` bị lỗi tương tự Part 1 -> bọc hai lượt này bằng `_hold_lookup_before_reply` (nhả trước Call 3 `corr-timeout-none` và Call 4 `_boom_pid`).
  - Các sibling khác đã kiểm (đã đồng bộ sẵn hoặc kiểm kịch bản đóng/lỗi): `test_t9_r02_socket_observation_lifetime_and_post_close_lookup_rejection` (`_wait_live_lookup_before_reply`), `test_t9_r02_tls_close_before_worker_return_and_ready_port_mismatch` (`_wait_live_before_reply`), `tests/support/inc2_native_owner.py` (giữ nguyên collector không prewait).
- Bằng chứng thực nghiệm (`C:\Users\letru\sb2-trusted-local\evidence\v9-p2-bugproof\`):
  - **RED (`red_p2a_siblings.log`):** chèn trễ 50 ms mô phỏng nghẽn CPU vào `_lookup_loopback_client_pid` trước khi sửa -> cả dòng 2961 (`corr-submit-boom`) và dòng 5517 (`corr-r02-pos`) FAIL (`assert None == os.getpid()`, `RED_P2A_RC=1`).
  - **GREEN (`green_p2a_50ms_delay_314.log`, `green_p2a_5x_50ms_311.log`):** với cùng trễ 50 ms, 3.14 pass (`2 passed in 2.17s`), 3.11 pass liên tiếp 5/5 lượt.
  - **Mutation (`mut_p2a_null_pid.log`):** ép lookup trả `None` -> FAIL ngay tại dòng `assert ev1[0]["client_pid"] == os.getpid()` (`MUT_P2A_NULL_PID_RC=1`).

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | not applicable | Kiểm telemetry TCP/TLS bộ nhớ RAM của `LoopbackServer` và collector. |
| Restore, rollback and migration rewind state | not applicable | Không thao tác store/migration. |
| Old binaries, old data, version fences | holds | Chạy trên template transport chuẩn của T7/T9. |
| Every path to the same invariant | fixed here | Vá đồng bộ Part 1 (`_release_owner_reply`), Part 3 (`corr-r02-deadline`) và hai sibling `_write_200_best_effort` (`corr-submit-boom`, `corr-quiesced`). |
| Concurrency, shutdown and cutoffs | fixed here | Chờ lookup xong chỉ trong phạm vi context ca đối chứng theo đúng cặp port `(client_port, listen_port)`; Part 2/Part 3 vẫn chạy hoàn toàn không prewait. |
| Authority, identity and scope | holds | Vẫn kiểm khớp `client_pid == os.getpid()` và `client_started_at == daemon_started_at`. |
| Fail closed at limits and on the unknown | fixed here | Part 3 không chấp nhận trộn `"ok"` với `pid=None` hay `"observation_incomplete"` với PID khác `None`; Part 2 giữ `observation_incomplete`. |
| What actually left, and to whom | holds | Đối chiếu `owner_call` và `socket_observation` khớp `connection_id` và `response_flushed_ok=True`. |
| The world outside the daemon | fixed here | Giữ kết nối TCP sống tới lúc `GetExtendedTcpTable` sighting xong để phản ánh đúng ca đối chứng trên Windows dưới tải 6 shard. |
| Evidence and oracles | fixed here | Đủ RED (`red_p2a_siblings.log`), GREEN dưới trễ 50 ms (3.14 & 3.11 × 5) và mutation `None` PID FAIL (`MUT_P2A_NULL_PID_RC=1`). |
| The document agrees with itself | fixed here | Docstring/comment trong `test_kernel_native_receipt_contract.py` và bảng A1–A7 khớp hành vi mới. |

---

### Finding Reseal2-P2b (P2): Tách Hai Nhánh Envelope Uncertain Theo Đặc Tả §6.5 (`crash_cases.py`, `sp1-crash-table.md`)

#### 1. Invariant
> Khi một request đang trong pha `COMMITTING` bị gián đoạn trước lúc nhận success, client shim phải nhận đúng một trong hai envelope uncertain tách biệt — mất kết nối sau POST (`daemon_unavailable` kèm `_meta.superbrain/request_may_have_run=true`) hoặc vượt cutoff `1.475 ms` trong pha commit theo mục 6.5 (`commit_outcome_unknown` không kèm `_meta` vận chuyển) — và mọi khẳng định crashpoint/bền/replay phía sau vẫn giữ nguyên.

#### 2. Sibling sweep
- `tests/support/crash_cases.py` (`assert_uncertain`, dùng cho cả `expect_crash_before_commit` dòng 1514 và `expect_crash_after_commit` dòng 1587):
  - Tách thành hai helper xác minh chặt chẽ theo từng nhánh: `_assert_transport_uncertain` (yêu cầu `error.code == "daemon_unavailable"`, `message == "daemon unavailable"`, `_meta == {"superbrain/request_may_have_run": True}`) và `_assert_in_commit_cutoff_unknown` (yêu cầu `error.code == "commit_outcome_unknown"`, `message == "commit outcome unknown"`, `"_meta" not in result` — đúng chuẩn shim `stdio.py` & `tests/mcp/test_stdio.py:1001`). Mọi mã khác (kể cả `deadline_exceeded` / `store_busy` trước commit) đều fail; đồng thời `run_kernel_case` vẫn đòi `assert_request_crashed` (`CRASHPOINT_HIT <tên>` + exit 86), 0 commit (`before_commit`) / 1 commit (`after_commit_before_response`), và retry đúng `idempotency_key` replay chuẩn theo policy hiện tại.
- `tests/integration/test_kernel_privacy_persistence.py` (`_call_idempotent_with_uncertain_retry`, dòng 190): cập nhật sibling helper thử lại 1 lần khi nghẽn host > 1.5–2 s để nhận diện cả hai envelope uncertain hợp lệ (giữ nguyên ca `drop_episode` dòng 375 kiểm trực tiếp `_meta` cho `BrokenPipeError`).
- `docs/design/sp1-crash-table.md` (dòng 115–118): đồng bộ mô tả hai envelope tách biệt (mất kết nối sau POST vs cutoff `1.475 ms` trong pha `COMMITTING` theo mục 6.5), giữ nguyên đòi hỏi `CRASHPOINT_HIT`, exit 86, 1 commit và replay.
- Sibling đã kiểm không cần đổi: `src/superbrain/mcp/stdio.py`, `tests/mcp/test_stdio.py:986-1009`, `tests/integration/test_kernel_shim.py:1751, 1978` (đều phân biệt đúng `commit_outcome_unknown` không `_meta` với `ToolCallUncertain` có `_meta`).
- Bằng chứng thực nghiệm (`C:\Users\letru\sb2-trusted-local\evidence\v9-p2-bugproof\`):
  - **RED (`red_p2b.log`):** `assert_uncertain` cũ gặp `commit_outcome_unknown` (không `_meta`) bị `AssertionError` ở dòng 1428 (`EXIT=1`).
  - **4 Mutants + Oracle (`green_and_mutants_p2b.log`):** reject cả `daemon_unavailable` thiếu `_meta`, `commit_outcome_unknown` mang `_meta` giả, `deadline_exceeded` trước commit, và `_meta.request_may_have_run=False`.
  - **E2E Real-Shim Pausepoint (`green_p2b_real_shim_commit_unknown.log`):** bật `SUPERBRAIN_CRASHPOINT=kernel.after_commit_before_response` + `SUPERBRAIN_PAUSEPOINT=kernel.after_commit_before_response` thả sau `1.65 s` -> `brain-mcp` thật nhận `{'code': 'commit_outcome_unknown', 'message': 'commit outcome unknown'}` (`HAS_META= False`), tiến trình con vẫn thoát 86 với `CRASHPOINT_HIT kernel.after_commit_before_response`, kiểm 1 delivery/idempotency/event bền và replay `brain-mcp`/`brain mcp` **PASS** (`1 passed in 16.12s`).

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | fixed here | `before_commit` vẫn buộc 0 commit, `after_commit_before_response` buộc đúng 1 commit + replay duy nhất dưới mọi nhánh uncertain. |
| Restore, rollback and migration rewind state | holds | Vẫn qua kiểm tra `tighten_policy_offline` (quarantine + revoke) trước khi replay. |
| Old binaries, old data, version fences | holds | Chạy driver wheel thực `-I` qua `brain-mcp` và `brain mcp`. |
| Every path to the same invariant | fixed here | Đồng bộ `crash_cases.py` (`before_commit` & `after_commit_before_response`), `test_kernel_privacy_persistence.py` (`_call_idempotent_with_uncertain_retry`), `sp1-crash-table.md`. |
| Concurrency, shutdown and cutoffs | fixed here | Phản ánh chính xác nhánh arbiter `1.475 ms` ở pha `COMMITTING` (§6.5) song hành đường crash socket drop trước cutoff. |
| Authority, identity and scope | holds | Replay vẫn bị từ chối `UNAUTHENTICATED` trên credential đã thu hồi của cùng principal. |
| Fail closed at limits and on the unknown | fixed here | Không nới lỏng `_pre_commit_refusal`; cấm `daemon_unavailable` thiếu `_meta` và cấm `commit_outcome_unknown` mang `_meta` sai hợp đồng. |
| What actually left, and to whom | holds | Redacted artifact digest vẫn không rò rỉ trong payload replay. |
| The world outside the daemon | holds | Xử lý trung thực biến động trễ ổ đĩa/CPU 6 shard trên Windows mà không hạ ngưỡng cutoff sản phẩm. |
| Evidence and oracles | fixed here | Đủ RED, 4 mutants FAIL, và E2E real-shim pausepoint 1.65 s với `commit_outcome_unknown` -> PASS toàn bộ kiểm tra bền & replay. |
| The document agrees with itself | fixed here | Cập nhật `sp1-crash-table.md` dòng 115–118 khớp §6.5, `stdio.py` T7a và `tests/mcp/test_stdio.py:1001`. |

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
| `tests/integration/test_kernel_daemon.py` | 36 = 36 | Giữ nguyên + spy cutoff & wait/join Reseal-P2 (`grace_s=0.55 < 0.85`) | **+0.40s PROBE & REOPEN-DEADLINE MUTATION KILLED** (`evidence/daemon-cutoff-bugproof/`), `36 passed in 21.79s` | Pass trong `v6`–`v8` + kiểm sau vá Reseal-P2 | No-Go (-18.7 s; 36 ca daemon thực) | Đạt |
| `tests/integration/{test_t9_client_sighting,test_kernel_native_receipt_contract,test_t9_socket_readiness}.py` | Không đổi | Giữ nguyên `< 0.10 s`, `< collector_timeout_s`, `client_pid == os.getpid()`, `observation_status == "ok"` | Reseal2-P2a: `_hold_lookup_before_reply` + sibling `2961/3000` + `corr-r02-deadline`; RED/GREEN 50ms/NULL-PID MUTANT (`evidence/v9-p2-bugproof/`) | Pass 3.14 & 3.11 × 5 (trễ 50 ms) | Đạt | Đạt |
| `tests/application/test_remediation_i2_t5_worker.py` | Không đổi | Giữ nguyên `wait_cancelled` & `seen_attempts == [1, 2]` | Đồng bộ timeout chờ hủy `0.3` -> `BOUND_WAIT_S` với toàn bộ 8 sibling `wait_cancelled` | Đã kiểm cục bộ + gate 3.14/3.11 | Không tăng khi hủy ngay | Đạt |
| `tests/integration/test_kernel_privacy_persistence.py` | Không đổi | Giữ nguyên toàn bộ assert privacy & `drop_episode` trực tiếp | Retry 1 lần đúng `idempotency_key` cho cả post-POST `daemon_unavailable` (`_meta`) lẫn §6.5 `commit_outcome_unknown` | Pass full file trong `green_suites_314.log` (`63 passed`) | Không đổi khi không stall | Đạt |
| `tests/support/crash_cases.py` + `docs/design/sp1-crash-table.md` + `tests/storage/{test_backup,test_reconcile,test_restore,test_crash_matrix}.py` | Không đổi | Tách 2 nhánh uncertain trong `assert_uncertain` | Reseal2-P2b: RED/4-mutant/E2E pausepoint `commit_outcome_unknown` (`evidence/v9-p2-bugproof/`) + `test_matrix_detects_a_removed_crashpoint` | Pass 3.14 & 3.11 (`green_suites_314.log`, `green_focused_311.log`) | **Đạt** (`test_crash_matrix` 36.9→21.0 s) | Đạt |
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

### Kết quả 4 lượt gate trên commit sạch `4f5138c` (`final-remediate-gate-v7`, cache wheel lạnh, `--shards 6`):
- **Python 3.14 Lượt 1:** `accepted=True`, `test_job_seconds = 212.606 s` (`< 275 s`), JUnit `<testsuite>` = **`992.595 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed` (`3470` total).
- **Python 3.14 Lượt 2:** `accepted=True`, `test_job_seconds = 242.177 s` (`< 275 s`), JUnit `<testsuite>` = **`1137.544 s`** (`<= 1200 s`), `3414 passed, 56 skipped, 0 failed`.
- **Python 3.11 Lượt 1:** `accepted=True`, `test_job_seconds = 278.078 s` (`< 300 s`, `shard-2 = 224.12 s` lệch tải), JUnit `<testsuite>` = `1226.702 s`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.11 Lượt 2:** `accepted=True`, `test_job_seconds = 271.532 s` (`< 275 s`), JUnit `<testsuite>` = `1272.188 s`, `3414 passed, 56 skipped, 0 failed`.

### Kết quả 4 lượt gate trên commit sạch `b289f87` (`final-remediate-gate-v8`, cache wheel lạnh, `--shards 6`):
- **Python 3.11 Lượt 1:** `accepted=True`, `test_job_seconds = 204.110 s` (`< 275 s`), JUnit `<testsuite>` = **`963.175 s`** (`<= 1200 s`), độ lệch shard `7.2%`, `3414 passed, 56 skipped, 0 failed` (`3470` total).
- **Python 3.11 Lượt 2:** `accepted=True`, `test_job_seconds = 224.547 s` (`< 275 s`), JUnit `<testsuite>` = **`1070.423 s`** (`<= 1200 s`), độ lệch shard `6.4%`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.14 Lượt 1:** `accepted=True`, `test_job_seconds = 235.173 s` (`< 275 s`), JUnit `<testsuite>` = **`1118.863 s`** (`<= 1200 s`), độ lệch shard `8.7%`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.14 Lượt 2:** `accepted=True`, `test_job_seconds = 236.985 s` (`< 275 s`), JUnit `<testsuite>` = **`1110.450 s`** (`<= 1200 s`), độ lệch shard `9.2%`, `3414 passed, 56 skipped, 0 failed`.

### Kết quả gate `final-remediate-gate-v9` trên `e9bb521ef` (`--shards 6`, cache wheel lạnh):
- **Python 3.11 Lượt 1:** `accepted=True`, `test_job_seconds = 240.515 s`, JUnit `<testsuite>` = `1153.353 s`, spread `6.9%`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.11 Lượt 2 (giữ nguyên làm hồ sơ):** `accepted=False`, `test_job_seconds = 244.172 s`, `3413 passed, 1 failed` (`test_t9_r02_handshake_independent_of_collector_latency` — đã vá ở **Reseal2-P2a**).
- **Python 3.11 Lượt chạy lại sạch:** `accepted=True`, `test_job_seconds = 246.531 s`, JUnit `<testsuite>` = `1197.435 s`, spread `6.8%`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.14 Lượt 1:** `accepted=True`, `test_job_seconds = 248.071 s`, JUnit `<testsuite>` = `1161.379 s`, spread `10.6%`, `3414 passed, 56 skipped, 0 failed`.
- **Python 3.14 Lượt 2 (giữ nguyên làm hồ sơ):** `accepted=False`, `test_job_seconds = 245.166 s`, `3413 passed, 1 failed` (`test_replay_after_response_loss_through_real_shim[serve-fixture@kernel.after_commit_before_response]` — đã vá ở **Reseal2-P2b**).
- **Python 3.14 Lượt chạy lại sạch:** `accepted=True`, `test_job_seconds = 251.562 s`, JUnit `<testsuite>` = `1189.461 s`, spread `10.4%`, `3414 passed, 56 skipped, 0 failed`.

### Bước tiếp theo ngay sau commit vá Reseal2-P2a & Reseal2-P2b:
1. Kiểm `ruff`, `mypy`, `lint-imports`, `green_suites_314.log` (`63 passed`), `green_focused_311.log` (`4 passed`), và toàn bộ bằng chứng `evidence/v9-p2-bugproof/` trên commit sạch của `remediate-runtime-opt` (`tree_is_clean == True`).
2. Bàn giao cho Reviewer độc lập (Codex) thẩm định delta + phê duyệt reseal `.verification/task9-seal.json` (giữ digest cũ).
3. Chạy xác nhận gate cuối trên chính commit sạch đã được reseal (`test_lock.py check` exit 0 + `scripts.gate --shards 6` cho 3.11 × 2 và 3.14 × 2).
