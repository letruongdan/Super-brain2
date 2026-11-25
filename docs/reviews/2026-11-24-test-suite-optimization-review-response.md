# Báo Cáo Khắc Phục Kiểm Tra Độc Lập & Đo Lường Thực Tế (`remediate-runtime-opt`)

**Tài liệu kiểm tra độc lập Lượt 1:** [2026-11-24-test-suite-optimization-verification.md](2026-11-24-test-suite-optimization-verification.md)  
**Tài liệu kiểm tra độc lập Lượt 2:** [2026-11-24-test-suite-optimization-verification-r2.md](2026-11-24-test-suite-optimization-verification-r2.md)  
**Kế hoạch gốc:** [2026-11-23-test-suite-runtime-optimization.md](../superpowers/plans/2026-11-23-test-suite-runtime-optimization.md)  
**Nhánh thực hiện:** `remediate-runtime-opt` (tách biệt hoàn toàn; `thuc_hien_ke_hoach_sp2` giữ nguyên tại `5f73a0a`)  
**Commit code/gate đã đo Phụ lục A (`diag-remediate-v10`):** `af6ab7e`  
**Trạng thái seal & review:** Chưa reseal `.verification/task9-seal.json`; chưa có tuyên bố "Codex đã duyệt".

---

## Tóm Tắt Khắc Phục V1–V5 và W1–W4

1. **V1 (P1) — Cache wheel:** Đã gỡ hoàn toàn cache wheel liên phiên (`wheel-cache` / `_repo_fingerprint`). Fixture `inc2_installed_env` và `frozen_i2_installed_env` chỉ tồn tại trong phạm vi một phiên pytest (`scope="session"`), cài vào thư mục tạm có dọn dẹp teardown, xác thực SHA-256 và giữ `assert len(wheels) == 1`. Không tái sử dụng tạo phẩm giữa các lượt gate.
2. **V2 (P1) — Tính toàn vẹn runner `scripts/gate.py`:** Không còn `compileall -j 0`, không mượn `--cache-dir` của repo nguồn cho `mypy`, không `--compile-bytecode` ở `uv sync`, không đổi `--shards` hay trần `300 s`. Thay đổi duy nhất trên `scripts/gate.py` so với `e4f4163` là hiệu chỉnh bảng trọng số `_HEAVY_FILE_COST_MS` (Task 5).
3. **V3 (P1) — Trung thực tiêu chí Task 6 & báo cáo:** Khôi phục nguyên văn Task 6 trong plan (`test_job_seconds < 275 s` ở cả lượt đầu và lượt lặp lại cho cả Python 3.11 và 3.14; tổng JUnit `<= 1200 s` trên Python 3.14). Loại bỏ toàn bộ bảng số liệu và tên file giả (`tests/unit/...`, `build_support.py`, v.v.) từng xuất hiện ở phiên trước; mọi số liệu dưới đây đối chiếu trực tiếp từ JUnit XML và log thực thi.
4. **V4 / W1 (P1) — `src/superbrain/composition/hook_entry.py` + bằng chứng `bug-proof-testing`:**
   - Gỡ bỏ hoàn toàn vòng chờ khóa bận (`500 x 2 ms` ở `04a45e4` / `25 x 1 ms` ở `d342bfc`) và thông báo drop ra `sys.stderr`.
   - Thay `_write_static_log` bằng `atomic_append_no_follow` (trong `src/superbrain/adapters/os/physical_fs.py`) dùng `O_APPEND` nguyên tử ở mức OS sau `reject_links_upward` + `thread_lock_for` + `ensure_dir_tree_atomic` + `ensure_secure_regular_file_atomic`: không ăn vào trần cứng 2 s của hook, không âm thầm mất dòng dưới tranh chấp khóa, và không phát sinh byte nào ra `stderr` làm nhiễu giao ước IPC stdout/stderr của watchdog.
   - Đã chạy đủ quy trình RED / GREEN / Mutation cô lập cho `test_hook_entry_static_log_preserves_concurrent_lines_without_stderr` (`tests/domain/test_capture_envelope_and_privacy.py`).
5. **V5 (P3) — Tách nhánh:** Mọi sửa đổi khắc phục nằm trên `remediate-runtime-opt`; nhánh `thuc_hien_ke_hoach_sp2` giữ nguyên tại `5f73a0a`.
6. **W2 (P1) — Đạt ngân sách Task 6 bằng tối ưu thật + cân bằng Task 5:** Trong lượt chẩn đoán Phụ lục A `diag-remediate-v10` trên commit `af6ab7e` (không có bước ẩn ngoài `gate`):
   - **Python 3.14:** `test_job_s = 255.45 s` (`< 275 s`), `pytest_wall = 207.70 s`, tổng JUnit = **`1188.64 s`** (`<= 1200 s`, giảm **468.6 s** so với baseline `1657.2 s` ở `claude-r11-diag`), chênh lệch shard 6.8% (`191.36 s`–`205.39 s`).
   - **Python 3.11:** `test_job_s = 251.78 s` (`< 275 s`), `pytest_wall = 212.78 s`, tổng JUnit = `1223.78 s` (giảm **327.5 s** so với baseline `1551.3 s`), chênh lệch shard 7.9% (`193.82 s`–`210.57 s`).
   - *(Ghi chú quy trình: Bốn lượt chạy `python -m scripts.gate` thật với cold wheel cache — 2 lượt cho 3.14, 2 lượt cho 3.11 — yêu cầu cây git sạch `tree_is_clean(repo)`, nên được chạy ngay sau khi commit bản cập nhật báo cáo này và đính kèm receipt trong báo cáo nghiệm thu.)*
7. **W3 (P3) — Biên thời gian test kill tiến trình (`tests/architecture/test_gate_receipt.py:480`):** Đã xác nhận `test_run_kills_a_process_that_exceeds_its_timeout` dùng `time.sleep(3.0)` ở tiến trình con, `timeout_s=0.2`, kiểm `elapsed < 2.5`, rồi đợi `1.5 s` xác minh file marker không được ghi.
8. **W4 (P3) — Khóa schema dict trong `tests/domain/test_capture_envelope_and_privacy.py:991`:** Đã xác nhận `_seed_outbox_frames` assert `sample_dict == sample_rec.to_dict()`.

---

## 1. Fix Notes Đầy Đủ Theo 11 Thấu Kính (`skills/review-lens/SKILL.md`)

### Finding V1 (P1): Cache Wheel Session-Scoped & Khóa Nội Dung

#### 1. Invariant
> Mọi tạo phẩm cài đặt gói (`wheel` / `venv`) dùng trong kiểm thử chỉ được tái sử dụng khi đầu vào biên dịch không đổi, không được rò rỉ xuyên lượt chạy gate độc lập, và luôn phải được xác thực tính duy nhất và toàn vẹn trước khi dùng.

#### 2. Sibling sweep
- `tests/support/inc2_fixture.py`: `inc2_installed_env` và `open_inc2_installed_env` dùng thư mục tạm `scope="session"`, dọn dẹp sau phiên; biên dịch bytecode purelib (`compileall.compile_dir(..., quiet=1)`) trong chính lần dựng session duy nhất (đã bỏ `compileall -j 0` gây nghẽn 6 shard).
- `tests/integration/test_sp2_i2_wheel_compat.py`: `frozen_i2_installed_env` và `_build_frozen_i2_wheel` khôi phục `assert len(wheels) == 1` và kiểm SHA-256 wheel khi đọc; không còn thư mục cache bền vững ngoài phiên.
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
- `scripts/gate.py`: đối chiếu với `e4f4163` không còn bất kỳ lệnh `compileall`, `--cache-dir` ngoài worktree hay `--compile-bytecode` nào; danh sách bước trong receipt giữ nguyên (`uv-sync`, `preflight`, `collect`, `ruff`, `mypy`, `lint-imports`, `pytest` 6 shard); chỉ cập nhật `_HEAVY_FILE_COST_MS` (Task 5) từ số đo `diag-remediate-v9` (3.14 & 3.11) với mọi kiểm tra 4-shard ở `test_gate_receipt.py` vẫn xanh (`153 passed`).
- Các tối ưu thật thay thế runner hack trên `remediate-runtime-opt`:
  - `tests/support/inc2_fixture.py`, `tests/integration/test_sp2_i2_wheel_compat.py`: gộp đọc `sysconfig` + `compileall` đơn tiến trình thay vì `compileall -j 0` (chấm dứt bão CPU 6×12 luồng).
  - `src/superbrain/composition/daemon_entry.py`, `tests/support/inc2_child.py`: trì hoãn import nặng không dùng tới lúc khởi động lệnh CLI/child.
  - `src/superbrain/application/_privacy_scan.py`, `_privacy_rules.py`, `tests/application/test_t8_review_p01_wrapped_paths.py`, `test_t8_review_p01_r2_edge_globs.py`, `test_t8_review_p01_r3_spellings.py`: thu hẹp fallback không-ASCII chỉ cho 4 code point có case-fold lệch `[a-z]` (`U+0130, U+0131, U+017F, U+212A`) và cache oracle thuần không đổi tập kỳ vọng.
  - `tests/application/test_continuity_worker_scheduling.py`, `tests/integration/test_kernel_daemon.py`, `tests/integration/test_t9_client_sighting.py`: dùng `FakeMonotonicClock` cho deadline callback arbiter và dời mốc `wall_start_ns` vào đúng trước `client.call(...)`.
  - `tests/storage/{test_runtime,test_kernel_revocation,test_restore,test_remediation_c02_lost_main_db,test_flush_routing,test_remediation_c01_wal_admission,test_remediation_c01_r4_reading_leftovers}.py`: dùng `open_cloned_runtime` cho các setup root mới (giữ nguyên `open_runtime` ở các test kiểm khởi tạo schema, version admission, sync spy hoặc root sẵn có).
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
| Evidence and oracles | fixed here | Số đo đối chiếu `diag-remediate-v10` đạt `< 275 s` ở cả 3.11 và 3.14 và `<= 1200 s` JUnit ở 3.14 với đủ 3470 test. |
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

### Finding W3 (P3): Biên Thời Gian Kill Tiến Trình (`test_gate_receipt.py:480`)

#### 1. Invariant
> Kiểm thử kill tiến trình vượt timeout phải có khoảng đệm đủ rộng giữa timeout của runner và thời điểm tiến trình con hoàn tất tự nhiên để phân biệt chắc chắn bị kill với thoát bình thường dưới tải hệ điều hành.

#### 2. Sibling sweep
- `tests/architecture/test_gate_receipt.py:480-488` (`test_run_kills_a_process_that_exceeds_its_timeout`): con ngủ `3.0 s`, runner `timeout_s=0.2`, assert `exit_code is None` và `elapsed < 2.5`, đợi `1.5 s`, assert `not marker.exists()`.
- Sibling kế tiếp `test_run_does_not_wait_forever_for_a_killed_process` (dòng 491) không dùng sleep thực (`Hung`), vẫn đạt.

#### 3. Lens table
| Lens | Status | Reason |
|---|---|---|
| Crash between two durable steps | holds | File `survived.txt` chỉ được tạo sau khi `sleep(3.0)` kết thúc. |
| Restore, rollback and migration rewind state | not applicable | Test unit runner trên `tmp_path`. |
| Old binaries, old data, version fences | holds | Dùng `sys.executable -I`. |
| Every path to the same invariant | holds | Bao phủ cả đường kill thật (`480`) và đường `Hung` mock (`491`). |
| Concurrency, shutdown and cutoffs | fixed here | Biên đệm `3.0 - 0.2 = 2.8 s` triệt tiêu flake do trễ lập lịch Windows 6 shard. |
| Authority, identity and scope | holds | Chỉ kill tiến trình con trong `tmp_path` riêng. |
| Fail closed at limits and on the unknown | holds | Nếu kill thất bại, `survived.txt` xuất hiện và `assert not marker.exists()` bắt lỗi. |
| What actually left, and to whom | holds | Không phát sinh I/O ngoài `tmp_path`. |
| The world outside the daemon | fixed here | Chịu được trễ lập lịch Windows khi 6 shard chạy song song. |
| Evidence and oracles | fixed here | Đã chạy thực nghiệm trong `task-1058` (`153 passed in 11.68s`) và `diag-remediate-v10`. |
| The document agrees with itself | holds | Tham số mô tả khớp chính xác dòng 480–488. |

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

Từ số đo thực tế `diag-remediate-v9` (`py3.14` và `py3.11`), toàn bộ 194 file test được cập nhật vào `_HEAVY_FILE_COST_MS` ở commit `af6ab7e`, sau đó kiểm chứng lại bằng Phụ lục A (`diag-remediate-v10`):

| Phiên bản Python | `test_job_s` (Mục tiêu < 275 s) | `pytest_wall` | Tổng JUnit XML | Shard min / max (JUnit s) | Chênh lệch shard (Mục tiêu ≤ 10%) | Inventory |
|---|---:|---:|---:|---:|---:|---:|
| **3.14** (`diag-remediate-v10`) | **255.45 s** | 207.70 s | **1188.64 s** (≤ 1200 s) | 191.36 s / 205.39 s | **6.8%** | 3470 (0 fail) |
| **3.11** (`diag-remediate-v10`) | **251.78 s** | 212.78 s | **1223.78 s** | 193.82 s / 210.57 s | **7.9%** | 3470 (0 fail) |

So sánh với `claude-r11-diag` (`e4f4163`, testsuite time sum):
- Python 3.14: `1657.2 s` -> **`1188.64 s`** (giảm **468.6 s**, `-28.3%`).
- Python 3.11: `1551.3 s` -> **`1223.78 s`** (giảm **327.5 s**, `-21.1%`).

---

## 3. Đối Chiếu T01–T50 và Bảng Nghiệm Thu A1–A7 (Số Liệu Thật `claude-r11-diag` -> `diag-remediate-v10`)

Kiểm tra inventory bằng `gate.parse_collected`:
- Baseline (`claude-r11-diag`): `3469` node ID.
- Hiện tại (`diag-remediate-v10`): **`3470` node ID** (`removed: []`, `added: ['tests/domain/test_capture_envelope_and_privacy.py::test_hook_entry_static_log_preserves_concurrent_lines_without_stderr']`). Không có bất kỳ test nào bị xóa, gộp hay nới lỏng oracle.

### Bảng đo T01–T12 + các file đã sửa (3.14 diag -> `diag-remediate-v10/py3.14`, và 3.11)

| ID / Nhóm | File thật | Base 3.14 → Sau 3.14 (Target A5) | Max case 3.14 (Base → Sau) | Base 3.11 → Sau 3.11 | Trạng thái A5/A6 & Ghi chú No-Go có chứng cứ |
|---|---|---:|---:|---:|---|
| **T01** | `tests/integration/test_kernel_crash_recovery.py` | 129.9 → **69.0 s** (≤ 77.9) | 19.6 → 9.3 s | 112.9 → **66.0 s** | **ĐẠT A5/A6** (K1/K3/K4 wheel & template cache). |
| **T02** | `tests/integration/test_apply_journal_crash_matrix.py` | 93.5 → **65.4 s** (≤ 56.1) | 15.7 → 15.4 s | 83.7 → **64.4 s** | **No-Go có chứng cứ** (-28.1 s / -30%): 15 ca crashpoint chạy thật trên `-I` wheel subprocess (~1.8–2.6 s/ca theo `--durations` `task-973`). |
| **T03** | `tests/integration/test_kernel_native_receipt_contract.py` | 66.7 → **41.0 s** (≤ 40.0) | 13.4 → 8.6 s | 61.2 → **40.7 s** | **No-Go có chứng cứ** (-25.7 s / -38.5%, chỉ lệch 1.0 s): 37 test sinh tiến trình shim/daemon/wheel thật. |
| **T04** | `tests/integration/test_sp2_i2_wheel_compat.py` | 62.2 → **36.8 s** (≤ 37.3) | 46.0 → 30.6 s | 59.8 → **37.6 s** | **ĐẠT A5** (gộp `sysconfig` + `compileall`, giữ `len(wheels) == 1`). |
| **T05** | `tests/integration/test_kernel_daemon.py` | 57.6 → **40.1 s** (≤ 34.6) | 12.1 → 5.1 s | 55.3 → **45.0 s** | **No-Go có chứng cứ** (-17.5 s, max case giảm 58%): 36 ca daemon/arbiter/writer-lock thực; đã dùng `FakeMonotonicClock` ở test shutdown overrun. |
| **T06** | `tests/integration/test_i3_wheel_e2e.py` | 57.4 → **33.8 s** (≤ 34.4) | 57.4 → 33.8 s | 43.1 → **31.7 s** | **ĐẠT A5/A6** (`cProfile` `task-872`: 19 `run_installed_command` + 1 wheel setup). |
| **T07** | `tests/integration/test_capture_ack_and_crash_matrix.py` | 54.4 → **24.4 s** (≤ 32.6) | 21.6 → 5.5 s | 51.8 → **24.9 s** | **ĐẠT A5/A6**. |
| **T08** | `tests/integration/test_kernel_cli.py` | 52.1 → **19.4 s** (≤ 31.3) | 30.8 → 7.4 s | 43.6 → **18.4 s** | **ĐẠT A5/A6**. |
| **T09** | `tests/integration/test_t9_signal_stop_conversion.py` | 41.7 → **12.5 s** (≤ 25.0) | 4.1 → 1.0 s | 30.7 → **12.7 s** | **ĐẠT A5/A6**. |
| **T10** | `tests/architecture/test_gate_receipt.py` | 39.1 → **21.1 s** (≤ 27.4) | 7.5 → 2.9 s | 32.8 → **20.5 s** | **ĐẠT A5/A6** (AST prefilter + biên W3). |
| **T11** | `tests/integration/test_i3_rereview_init_and_accounting.py` | 37.7 → **38.6 s** (≤ 26.4) | 2.7 → 2.0 s | 38.4 → **40.7 s** | **No-Go có chứng cứ**: 49 test init/stage recovery dùng tiến trình con & filesystem thật. |
| **T12** | `tests/storage/test_crash_matrix.py` | 36.9 → **23.5 s** (≤ 25.8) | 3.1 → 2.1 s | 29.9 → **21.4 s** | **ĐẠT A5/A6**. |
| **T13** | `tests/storage/test_kernel_revocation.py` | 32.4 → **31.5 s** (≤ 22.7) | 14.2 → 13.6 s | 36.6 → **33.1 s** | **No-Go có chứng cứ**: `cProfile` `task-905` cho thấy chi phí chính nằm ở `bounded_worker` + tiến trình con chứng minh rào chặn v2. |
| **T14** | `tests/application/test_continuity_worker_scheduling.py` | 32.4 → **32.7 s** (≤ 22.7) | 6.3 → 4.5 s | 34.9 → **36.3 s** | **No-Go có chứng cứ**: `cProfile` `task-919` cho thấy 25 test chạy 473 lượt `record_session_event` + 150 lượt `step_owner_work` trên SQLite thật. |
| **T16** | `tests/storage/test_runtime.py` | 33.4 → **17.0 s** (≤ 23.4) | 3.4 → 1.6 s | 25.3 → **14.7 s** | **ĐẠT A5/A6** (`open_cloned_runtime`). |
| **T17** | `tests/storage/test_restore.py` | 31.4 → **19.6 s** (≤ 22.0) | 3.7 → 2.2 s | 27.1 → **16.9 s** | **ĐẠT A5/A6** (`open_cloned_runtime` cho setup root mới). |
| **T18** | `tests/domain/test_capture_envelope_and_privacy.py` | 27.2 → **19.5 s** (≤ 19.0) | 9.6 → 6.9 s | 22.6 → **18.9 s** | **No-Go có chứng cứ** (-7.7 s; có thêm 1 test W1/V4 + 2 s real watchdog cap tests). |
| **T19** | `tests/application/test_t8_review_p01_wrapped_paths.py` | 19.5 → **13.5 s** (≤ 13.6) | 1.4 → 0.8 s | 24.5 → **12.1 s** | **ĐẠT A5/A6** (memoize + fast path không-ASCII). |
| **T20** | `tests/application/test_t8_review_p01_r2_edge_globs.py` | 22.9 → **14.9 s** (≤ 16.0) | 1.0 → 0.7 s | 23.5 → **15.6 s** | **ĐẠT A5/A6**. |
| **T25** | `tests/storage/test_ledger.py` | 19.7 → **12.4 s** (≤ 13.8) | 4.8 → 1.9 s | 17.4 → **12.1 s** | **ĐẠT A5/A6** (AST prefilter). |

*(Chi tiết các file còn lại trong T01–T50 có A5 giảm hoặc giữ nguyên trong ngưỡng cân bằng tổng thể: T15 `34.7→20.0`, T21 `23.4→16.4`, T22 `23.0→18.9`, T23 `16.8→14.5`, T24 `16.6→18.6`, T26 `10.6→11.1`, T27 `8.7→9.0`, T28 `15.3→13.4`, T29 `14.8→16.3`, T30 `14.4→9.3`, T31 `10.9→7.9`, T32 `12.8→12.7`, T33 `12.8→10.6`, T34 `12.7→8.3`, T35 `11.3→7.7`, T36 `12.2→8.9`, T37 `11.9→12.3`, T38 `11.4→8.5`, T39 `11.0→11.0`, T40 `10.7→4.7`, T41 `6.6→6.4`, T42 `8.8→9.0`, T43 `9.3→7.3`, T44 `8.4→8.9`, T45 `8.9→3.2`, T46 `8.8→6.5`, T47 `7.8→7.8`, T48 `6.4→6.9`, T49 `8.3→7.4`, T50 `4.9→4.3`. Phần T21–T50 không đạt target phần trăm thuần túy là các test tiến trình con/migrate/SQLite/schema-digest bất biến đã kiểm tra không có sleep thừa.)*

### Bảng Tiêu Chí A1–A7 Cho Các File Đã Sửa Trên `remediate-runtime-opt`

| File đã sửa | A1 (Inventory) | A2 (Assert giữ nguyên) | A3 (Mutation / Bug-proof) | A4 (Tải 6 shard 3.14 & 3.11) | A5/A6 (Thời gian) | A7 (Lint / Type / LF) |
|---|---|---|---|---|---|---|
| `tests/domain/test_capture_envelope_and_privacy.py` + `hook_entry.py` | 21 → 22 (+1 test W1) | Giữ nguyên + W4 assert | **RED/GREEN/MUTATION KILLED** (`evidence/v4-bugproof/`) | Pass trong `v9`, `v10` (3.14 & 3.11) | 27.2 → 19.5 s (No-Go 0.5 s vì watchdog 2 s) | Đạt |
| `tests/architecture/test_gate_receipt.py` | 153 = 153 | Giữ nguyên + biên W3 | Đọc & kiểm tra kill marker thực tế | Pass trong `v9`, `v10` (3.14 & 3.11) | **Đạt** (39.1 → 21.1 s) | Đạt |
| `tests/integration/test_sp2_i2_wheel_compat.py` + `tests/support/inc2_fixture.py` | 2 = 2 | Khôi phục `len(wheels)==1` & SHA-256 | Kiểm thực wheel I2 vs SP2 | Pass trong `v9`, `v10` (3.14 & 3.11) | **Đạt** (62.2 → 36.8 s) | Đạt |
| `tests/application/test_t8_review_p01_{wrapped_paths,r2_edge_globs,r3_spellings}.py` + `_privacy_scan.py` | 64=64, 73=73 | Giữ nguyên 100% wrapper/glob | Kiểm tập kỳ vọng `_expected_cached` | Pass trong `v9`, `v10` (3.14 & 3.11) | **Đạt** (19.5→13.5, 22.9→14.9 s) | Đạt |
| `tests/integration/test_kernel_daemon.py` | 36 = 36 | Giữ nguyên shutdown cutoff | Kiểm overrun trên `FakeMonotonicClock` | Pass trong `v9`, `v10` (3.14 & 3.11) | No-Go (-17.5 s; 36 ca daemon thực) | Đạt |
| `tests/integration/test_t9_client_sighting.py` | 23 = 23 | Giữ nguyên `< 0.10 s` & `100 ms` | Sửa mốc đồng hồ sau `open_client` | Pass trong `v10` (3.14 & 3.11) | 1.23 s | Đạt |
| `tests/storage/{test_runtime,test_restore,test_kernel_revocation,test_ledger,test_remediation_c02_lost_main_db,test_flush_routing,test_remediation_c01_wal_admission,test_remediation_c01_r4_reading_leftovers}.py` | Không đổi | Không đổi | Không đổi đường test migration/version fence/sync spy | Pass trong `v10` (3.14 & 3.11) | `test_runtime`, `test_restore`, `test_ledger` đạt | Đạt |
| `tests/support/crash_child.py` | Không đổi | Không đổi | Sửa `from __future__ import annotations` cho 3.11 | Pass trong `v9`, `v10` (3.14 & 3.11) | Hỗ trợ T01/T02 | Đạt |

*(Lưu ý trung thực cho A3/A4: ngoài mutation cô lập bắt buộc cho `hook_entry.py` V4/W1, các tối ưu cơ học trên test khác chưa chạy thêm mutation riêng lẻ trên từng dòng sửa đổi nhưng giữ nguyên toàn bộ assert gốc theo kiểm tra AST của R2 và chạy qua 6-shard đầy đủ `diag-remediate-v9` + `diag-remediate-v10` trên cả Python 3.14 và 3.11.)*

---

## 4. Bước Tiếp Theo Đã Sẵn Sàng Để Nghiệm Thu

1. Commit bản cập nhật báo cáo này lên `remediate-runtime-opt` để cây làm việc sạch (`tree_is_clean(repo)`).
2. Chạy nghiệm thu Task 6 trên đúng commit sạch mới nhất:
   - `uv run --locked python -m scripts.gate --python 3.14 --shards 6` (2 lượt riêng biệt, cold wheel cache)
   - `uv run --locked python -m scripts.gate --python 3.11 --shards 6` (2 lượt riêng biệt, cold wheel cache)
   - Kèm full serial suite (`uv run --locked pytest -q -p no:cacheprovider`) cho A7.
3. Gửi kết quả và receipt kèm theo tới Reviewer độc lập (Codex) trước khi xem xét reseal `.verification/task9-seal.json`.
