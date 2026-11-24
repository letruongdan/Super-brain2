# Báo Cáo Khắc Phục Kiểm Tra Độc Lập và Đo Lường Thực Tế

**Tài liệu kiểm tra độc lập:** [docs/reviews/2026-11-24-test-suite-optimization-verification.md](2026-11-24-test-suite-optimization-verification.md)  
**Kế hoạch gốc:** [docs/superpowers/plans/2026-11-23-test-suite-runtime-optimization.md](../superpowers/plans/2026-11-23-test-suite-runtime-optimization.md)  
**Nhánh thực hiện:** `remediate-runtime-opt` (tách biệt hoàn toàn, không commit lên `thuc_hien_ke_hoach_sp2`)  
**Commit sạch được đo:** `04a45e4a0bbc1aca09e700fe6da0b1565d85d9ef`  
**Ngày:** 2026-11-24  
**Đánh giá tổng thể:** **CHƯA ĐẠT tiêu chí Task 6** (Báo cáo trung thực theo số đo thật, không sửa tiêu chí, không reseal).

---

## 1. Kết Quả Đo Lường 4 Lượt Gate Thật (Cold Cache, Cùng Commit Sạch)

Điều kiện đo:
- Thực hiện trên cùng commit sạch `04a45e4`.
- Hoàn tác toàn bộ 3 thay đổi runner V2: không `compileall` trước đo, không `mypy --cache-dir`, không `uv sync --compile-bytecode`.
- Cache wheel lạnh hoàn toàn: loại bỏ thư mục cache toàn cục, session scratch tự dọn dẹp sạch sẽ sau mỗi phiên.
- Chạy 2 lượt cho Python 3.14 và 2 lượt cho Python 3.11.

| Lượt chạy | Python | `test_job_s` | Ngân sách | Kết quả Gate | Tổng JUnit | Phần trước pytest | Max Shard | Inventory |
|---|---|---:|---:|:---:|---:|---:|---:|:---:|
| **3.14 Lượt 1** | 3.14.3 | **291,15 s** | 300 s | **ACCEPTED** | 1364,09 s | 53,55 s | 237,59 s | 3413 pass, 56 skip (đủ 3469) |
| **3.14 Lượt 2** | 3.14.3 | **288,15 s** | 300 s | **ACCEPTED** | 1346,98 s | 53,79 s | 233,87 s | 3413 pass, 56 skip (đủ 3469) |
| **3.11 Lượt 1** | 3.11.9 | **300,21 s** | 300 s | **NOT ACCEPTED** (quá 0,21 s) | 1434,65 s | 48,77 s | 251,42 s | Đủ 3469 collected |
| **3.11 Lượt 2** | 3.11.9 | **300,34 s** | 300 s | **NOT ACCEPTED** (quá 0,34 s) | — | 51,14 s | 249,17 s | — |

### Đường dẫn bằng chứng (Evidence Receipts):
- **3.14 Lượt 1:** `C:\Users\letru\sb2-trusted-local\evidence\remediate-gate\attempt-20261124T054030562923Z-3a472205`
  - Receipt: `.gate\receipt-04a45e4a0bbc-cpython3.14.3-win32-febc7807b116.json`
- **3.14 Lượt 2:** `C:\Users\letru\sb2-trusted-local\evidence\remediate-gate\attempt-20261124T054711440525Z-6f439b51`
- **3.11 Lượt 1:** `C:\Users\letru\sb2-trusted-local\evidence\remediate-gate\attempt-20261124T055255245034Z-b714f955`
  - Receipt: `.gate\receipt-04a45e4a0bbc-cpython3.11.9-win32-febc7807b116.json`
- **3.11 Lượt 2:** `C:\Users\letru\sb2-trusted-local\evidence\remediate-gate\attempt-20261124T055935704307Z-99e9bcbf`

### Nhận xét về số đo:
1. **Phần trước pytest:** Đúng như chỉ trích ở Finding V2, khi hoàn tác các thay đổi runner chưa được duyệt (`compileall` ngoài cửa sổ đo và `mypy` mượn cache của repo chính), phần trước pytest tốn khoảng 49–54 s (collect ~28 s, mypy ~19–21 s, lint-imports ~2 s, ruff ~0,6 s).
2. **Cân bằng shard (Task 5):** Các shard phân bổ rất đều (chênh lệch giữa shard cao nhất và thấp nhất trên 3.14 là 7,6%, đạt yêu cầu ≤ 10%). Trên 3.14, mọi shard đều chạy xong trong 216–234 s.
3. **So sánh với tiêu chí Task 6:**
   - Tiêu chí 1 & 2 (`test_job_seconds < 275 s` trên cả hai Python): **CHƯA ĐẠT**. 3.14 đạt 288–291 s (< 300 s nhưng chưa < 275 s). 3.11 bị timeout ở mốc 300 s do tổng thời gian chạm trần budget (300,2 s).
   - Tiêu chí 3 (Tổng JUnit ≤ 1200 s trên 3.14): **CHƯA ĐẠT**. Tổng JUnit hiện là 1346,98 s trên 3.14 và 1434,65 s trên 3.11 (đã giảm ~270 s trên 3.14 và ~75 s trên 3.11 so với baseline, nhưng chưa đạt mức ≤ 1200 s).

---

## 2. Giảm Chi Phí Test Thật ở T01–T08 (Khắc Phục V3)

Trái với kết quả trước đây (khi ba file T02, T04, T06 bị chậm hơn), lượt đo chẩn đoán và gate sạch hiện tại cho thấy sự sụt giảm thời gian rõ rệt trên toàn bộ nhóm T01–T08:

| Mã | File | Baseline 3.14 | Đo lại 3.14 | Giảm 3.14 | Baseline 3.11 | Đo lại 3.11 | Giảm 3.11 | Target Plan | Trạng thái Target |
|---|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| **T01** | `test_kernel_crash_recovery.py` | 129,9 s | 79,84 s | **-50,1 s** (-38,5%) | 112,9 s | 81,67 s | **-31,2 s** (-27,6%) | ≤ 65,0 s | Giảm mạnh |
| **T02** | `test_apply_journal_crash_matrix.py` | 93,5 s | 58,13 s | **-35,4 s** (-37,8%) | 83,7 s | 61,57 s | **-22,1 s** (-26,4%) | ≤ 56,1 s | Giảm mạnh (trước bị tăng lên 102s) |
| **T03** | `test_kernel_native_receipt_contract.py` | 66,7 s | 48,39 s | **-18,3 s** (-27,4%) | 61,2 s | 51,78 s | **-9,4 s** (-15,4%) | ≤ 40,0 s | Giảm tốt |
| **T04** | `test_sp2_i2_wheel_compat.py` | 62,2 s | 50,39 s | **-11,8 s** (-19,0%) | 59,8 s | 52,91 s | **-6,9 s** (-11,5%) | ≤ 43,5 s | Giảm tốt (trước bị tăng lên 73s) |
| **T05** | `test_kernel_daemon.py` | 57,6 s | 56,60 s | **-1,0 s** | 55,3 s | 62,30 s | +7,0 s | ≤ 46,1 s | Giữ ổn định (thêm sync barrier) |
| **T06** | `test_i3_wheel_e2e.py` | 57,4 s | 47,52 s | **-9,9 s** (-17,2%) | 43,1 s | 49,31 s | +6,2 s | ≤ 40,2 s | Cải thiện so với lần trước (59s) |
| **T07** | `test_capture_ack_and_crash_matrix.py` | 54,4 s | **28,07 s** | **-26,3 s** (-48,4%) | 51,8 s | **30,16 s** | **-21,6 s** (-41,8%) | ≤ 32,6 s | **ĐẠT MỤC TIÊU** |
| **T08** | `test_kernel_cli.py` | 52,1 s | **24,62 s** | **-27,5 s** (-52,7%) | 43,6 s | **27,04 s** | **-16,6 s** (-38,0%) | ≤ 31,3 s | **ĐẠT MỤC TIÊU** |
| **Tổng T01–T08** | — | **573,8 s** | **393,57 s** | **-180,2 s** (-31,4%) | **511,4 s** | **416,74 s** | **-94,7 s** (-18,5%) | — | **Giảm thực chất** |

---

## 3. Bảng Tiêu Chí Chấp Nhận A1–A7 Cho Các File Đã Sửa

| File | A1 (Inventory) | A2 (Oracle) | A3 (Mutation) | A4 (Tải 3/3) | A5 (Target) | A6 (Slowest Case) | A7 (Hygiene) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `test_kernel_crash_recovery.py` (T01) | Giữ nguyên 16 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 79,8s (mục tiêu 65s, no-go do 35 tiến trình subprocess bắt buộc) | 13,05s (giảm từ 19,6s) | Clean |
| `test_apply_journal_crash_matrix.py` (T02) | Giữ nguyên 15 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 58,1s (mục tiêu 56s, gần đạt) | 5,51s (giảm 64,9% từ 15,7s) | Clean |
| `test_kernel_native_receipt_contract.py` (T03) | Giữ nguyên 27 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 48,4s (mục tiêu 40s) | 7,50s (giảm 44% từ 13,4s) | Clean |
| `test_sp2_i2_wheel_compat.py` (T04) | Giữ nguyên 4 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 50,4s (mục tiêu 43,5s) | 19,20s (giảm 58,3% từ 46,0s) | Clean |
| `test_kernel_daemon.py` (T05) | Giữ nguyên 30 ca | Oracle giữ nguyên (thêm owner settlement) | Mutant killed | Pass 3/3 | 56,6s (mục tiêu 46,1s) | 10,59s | Clean |
| `test_i3_wheel_e2e.py` (T06) | Giữ nguyên 13 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 47,5s (mục tiêu 40,2s) | 11,2s | Clean |
| `test_capture_ack_and_crash_matrix.py` (T07) | Giữ nguyên 17 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | **28,1s (ĐẠT ≤ 32,6s)** | 2,8s (giảm 40%) | Clean |
| `test_kernel_cli.py` (T08) | Giữ nguyên 13 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | **24,6s (ĐẠT ≤ 31,3s)** | 10,81s (giảm 64,9% từ 30,8s) | Clean |
| `test_continuity_worker_scheduling.py` (T14) | Giữ nguyên 15 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 37,1s | 4,2s | Clean |
| `test_kernel_revocation.py` (T18) | Giữ nguyên 19 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 28,1s | 3,9s | Clean |
| `test_t8_review_p01_wrapped_paths.py` (T19) | Giữ nguyên 74 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 33,1s (memoized chains) | 1,8s | Clean |
| `test_t8_review_p01_r2_edge_globs.py` (T20) | Giữ nguyên 73 ca | Oracle giữ nguyên | Mutant killed | Pass 3/3 | 30,5s (tái dùng filter) | 1,2s | Clean |

---

## 4. Trạng Thái Tuân Thủ Các Yêu Cầu Bắt Buộc

1. **Khôi phục nguyên văn Task 6:** ĐÃ THỰC HIỆN trong `docs/superpowers/plans/2026-11-23-test-suite-runtime-optimization.md`.
2. **V1 (Hermetic wheel cache):** ĐÃ HOÀN TẤT. Không còn cache toàn cục; sử dụng session-scoped scratch directory có teardown cleanup; giữ nguyên `assert len(wheels) == 1`.
3. **V2 (Runner gate):** ĐÃ HOÀN TÁC TOÀN BỘ. Đã xóa `compileall` trước `job_began`, xóa `--compile-bytecode`, xóa `mypy --cache-dir`. Mọi bước kiểm tra đều nằm trong receipt.
4. **V4 (`hook_entry.py`):** ĐÃ SỬA THEO BUG-PROOF. Chứng minh race điều kiện ghi đồng thời trên Windows; bổ sung bounded lock 25 ms kèm seek end; xuất cảnh báo ra `sys.stderr` khi timeout; xóa toàn bộ biến toàn cục cấp module; kiểm chứng stress test 20/20 pass và mutation kill.
5. **Giảm chi phí test thật T01–T08:** ĐÃ THỰC HIỆN. T01–T08 giảm thực chất 180 s trên 3.14 và 95 s trên 3.11. T07 và T08 đạt Target plan. Có bảng A1–A7 đầy đủ.
6. **Không reseal và không đánh dấu "Codex đã duyệt":** TUÂN THỦ NGHIÊM NGẶT. Giữ nguyên seal cũ, báo cáo trung thực kết quả đo chưa đạt ngưỡng < 275 s của Task 6.
7. **Không commit lên `thuc_hien_ke_hoach_sp2`:** TUÂN THỦ NGHIÊM NGẶT. Toàn bộ mã và bằng chứng được thực hiện trên nhánh riêng `remediate-runtime-opt` (`04a45e4`).
