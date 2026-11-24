# Báo Cáo Khắc Phục Kiểm Tra Độc Lập (Finding Remediation Note)

**Tài liệu kiểm tra độc lập:** [docs/reviews/2026-11-24-test-suite-optimization-verification.md](2026-11-24-test-suite-optimization-verification.md)  
**Kế hoạch:** [docs/superpowers/plans/2026-11-23-test-suite-runtime-optimization.md](../superpowers/plans/2026-11-23-test-suite-runtime-optimization.md)  
**Nhánh thực hiện:** `remediate-runtime-opt` (tách biệt hoàn toàn khỏi `thuc_hien_ke_hoach_sp2`)  
**Ngày:** 2026-11-24  

---

## 1. Khắc Phục Các Findings (Review Lens Fix Notes)

### Finding V1 (P1): Cache wheel lâu dài với khóa không phản ánh nội dung nguồn

1. **Invariant:** Mọi tạo phẩm build và môi trường venv kiểm thử phải được cô lập theo từng session kiểm thử hoặc băm theo nội dung đầy đủ của mọi đầu vào, tuyệt đối không tái sử dụng tạo phẩm không xác thực xuyên suốt giữa các lần chạy gate.
2. **Sibling sweep:**
   - `tests/support/inc2_fixture.py`: Đã loại bỏ hoàn toàn bộ nhớ cache toàn cục trong `LOCALAPPDATA/superbrain-tests/wheel-cache`, bỏ khóa liên tiến trình và hàm băm `_repo_fingerprint()`. Đã khôi phục cơ chế tạo thư mục scratch tạm thời theo phiên (`_make_trusted_session_dir("inc2-wheel", tmp_path_factory)`) và dọn dẹp thư mục sau khi session kết thúc qua `_cleanup_dir(scratch)`. Giữ nguyên kiểm tra nghiêm ngặt `assert len(wheels) == 1`.
   - `tests/integration/test_sp2_i2_wheel_compat.py`: Đã loại bỏ hoàn toàn bộ nhớ cache toàn cục `LOCALAPPDATA/superbrain-tests/wheel-cache` cho wheel I2. Khôi phục fixture phiên độc lập tạo thư mục qua `_make_trusted_session_dir("i2-wheel-", tmp_path_factory)` và dọn dẹp sạch sẽ trong khối `finally:`. Giữ nguyên `assert len(wheels) == 1`.
   - `tests/storage/test_kernel_revocation.py`: Đã loại bỏ bộ nhớ cache zip/archive chia sẻ trong `LOCALAPPDATA`. Khôi phục việc trích xuất trong thư mục tạm biệt lập và đăng ký dọn dẹp qua `atexit`.
   - Quét toàn bộ repository: Không còn bất kỳ file test nào lưu trữ tạo phẩm build ngoài phạm vi session/temporary scratch.
3. **Bảng 11 Lens:**
   - **Lens 1 (Crash):** `not applicable` (Không thay đổi luồng ghi dữ liệu bền vững).
   - **Lens 2 (Restore/Rollback):** `not applicable` (Không đổi lược đồ lưu trữ).
   - **Lens 3 (Version fences):** `fixed here` (Tạo phẩm kiểm thử được build từ đúng mã nguồn của phiên hiện tại, triệt tiêu nguy cơ chạy trên wheel cũ).
   - **Lens 4 (Every path):** `holds` (Tất cả 3 điểm dùng wheel/archive fixture đã được đồng bộ hóa về cơ chế session scratch).
   - **Lens 5 (Concurrency):** `holds` (Mỗi tiến trình pytest session sở hữu thư mục tạm riêng biệt, không xung đột I/O).
   - **Lens 6 (Authority):** `holds` (Thư mục tạm được bảo vệ quyền truy cập qua `_make_trusted_session_dir`).
   - **Lens 7 (Fail closed):** `holds` (Bảo lưu `assert len(wheels) == 1`, fail ngay nếu có lỗi đóng gói wheel).
   - **Lens 8 (Data export):** `not applicable`.
   - **Lens 9 (Outside world):** `holds` (Gate hoàn toàn hermetic, không phụ thuộc trạng thái tồn đọng trong `LOCALAPPDATA`).
   - **Lens 10 (Evidence & oracles):** `holds` (Khôi phục độ tin cậy tuyệt đối cho các bài kiểm tra mutation và kiểm thử tích hợp).
   - **Lens 11 (Agreement):** `holds` (Đúng theo yêu cầu hermetic gate của Spec 17).

---

### Finding V2 (P1): Đổi runner gate trái quy tắc 2, chưa có reviewer duyệt

1. **Invariant:** Bộ runner kiểm tra gate phải đo đạc trung thực toàn bộ các bước kiểm tra trên bản checkout sạch và ghi nhận minh bạch mọi thao tác vào receipt mà không đẩy chi phí ra ngoài cửa sổ đo hoặc mượn cache từ repository nguồn.
2. **Sibling sweep:**
   - `scripts/gate.py`:
     - Hoàn tác toàn bộ lệnh `compileall` trước `job_began`.
     - Hoàn tác tùy chọn `--compile-bytecode` trong lệnh `uv sync`.
     - Hoàn tác tùy chọn `--cache-dir` của `mypy` trỏ về `.mypy_cache` của repo nguồn; mypy hiện chạy độc lập trong worktree gate.
     - Xóa bỏ import `contextlib` không dùng đến.
   - `tests/architecture/test_gate_receipt.py`: 153/153 tests pass xanh nguyên vẹn, receipt khớp hoàn toàn định dạng hợp đồng.
3. **Bảng 11 Lens:**
   - **Lens 1 to 3:** `not applicable`.
   - **Lens 4 (Every path):** `holds` (Tất cả các bước kiểm tra gate chạy đồng nhất và được ghi nhận trong receipt).
   - **Lens 5 (Concurrency & deadlines):** `holds` (Thời gian `test_job_seconds` phản ánh trung thực toàn bộ công việc kiểm thử).
   - **Lens 6:** `not applicable`.
   - **Lens 7 (Fail closed):** `holds` (Mọi lỗi trong quá trình chạy collect, ruff, mypy, lint-imports hay pytest đều được ghi nhận vào receipt).
   - **Lens 8:** `not applicable`.
   - **Lens 9 (Outside world):** `holds` (Không làm biến đổi thư mục cache `.mypy_cache` của repo chính).
   - **Lens 10 (Evidence):** `holds` (Số đo receipt phản ánh đúng hiệu năng thực tế).
   - **Lens 11 (Agreement):** `holds` (Tuân thủ triệt để Spec 17 và Rule 2).

---

### Finding V3 (P1): Tiêu chí nghiệm thu bị sửa sau khi chạy

1. **Invariant:** Tiêu chí nghiệm thu của kế hoạch tối ưu hóa phải được bảo toàn nguyên văn, không được hạ thấp hoặc thay đổi mục tiêu khi kết quả chưa đạt.
2. **Sibling sweep:**
   - `docs/superpowers/plans/2026-11-23-test-suite-runtime-optimization.md`: Khôi phục nguyên văn Task 6 dòng 203–211:
     1. Hai gate thật trên cùng commit sạch đều `accepted=true` với `test_job_seconds < 275 s` và JUnit đủ toàn bộ inventory.
     2. Chạy lại cả hai gate lần thứ hai: vẫn `accepted=true` và `< 275 s`.
     3. Tổng JUnit của lượt chẩn đoán cuối cùng ≤ 1200 s trên 3.14.
     4. Mọi dòng T01–T50 có bảng A1–A7 hoặc ghi chú no-go đã được reviewer chấp nhận; mọi dòng S1–S5 đã đóng.
     5. Seal mới được Codex duyệt; ledger có đường dẫn receipt gate, JUnit, mutation và seal.
3. **Bảng 11 Lens:**
   - **Lens 1 to 9:** `not applicable`.
   - **Lens 10 (Evidence & oracles):** `fixed here` (Khôi phục tiêu chí gốc và báo cáo kết quả đo thực tế).
   - **Lens 11 (Agreement):** `holds` (Văn bản kế hoạch thống nhất với mục tiêu ban đầu).

---

### Finding V4 (P2): Đổi mã sản phẩm `hook_entry.py` không có bằng chứng bug-proof

1. **Invariant:** Hook ghi sự kiện phải đảm bảo tính nguyên tử khi ghi nối (append) file qua các tiến trình đồng thời, tuân thủ nghiêm ngặt trần thời gian 2,0 s, và ghi nhận rõ ràng ra `sys.stderr` khi buộc phải hủy bỏ dòng log do hết hạn khóa thay vì âm thầm bỏ qua.
2. **Sibling sweep:**
   - `src/superbrain/composition/hook_entry.py`:
     - Nguyên nhân gốc được chẩn đoán theo `bug-proof-testing`: Trên Windows, cờ `os.O_APPEND` không đảm bảo kernel atomic append giữa các tiến trình con mở file cùng lúc khi file vừa tạo lạnh (cả hai tiến trình cùng đọc offset 0 và ghi đè nội dung của nhau).
     - Khắc phục theo bug-proof: Thêm cơ chế khóa file có giới hạn tối đa 25 lần × 1 ms (tổng cộng ≤ 25 ms, rất nhỏ so với dự trữ 150 ms của trần 2,0 s). Nếu không lấy được khóa sau 25 ms, ghi thông báo rõ ràng ra `sys.stderr`: `superbrain.hook_entry: dropped log line phase=... (lock timeout)` và flush ngay, không âm thầm nuốt lỗi. Dưới khóa, thực hiện `os.lseek(fd, 0, os.SEEK_END)` trước khi ghi nội dung.
     - Loại bỏ toàn bộ các biến cache toàn cục cấp module (`_PERMISSIONS`, `_DEFAULT_GATE`).
   - `tests/storage/test_outbox_durability_and_limits.py`: Kiểm thử stress test đồng thời chạy qua 20/20 lần không có bất kỳ lỗi nào. Đã kiểm chứng mutation kill.
   - `src/superbrain/storage/outbox.py`: Đã kiểm tra các vị trí thao tác spool outbox khác, đều sử dụng `OUTBOX_FILE_LOCK`.
3. **Bảng 11 Lens:**
   - **Lens 1 (Crash):** `holds` (Ghi log atomic và an toàn).
   - **Lens 2 to 3:** `not applicable`.
   - **Lens 4 (Every path):** `holds` (Mọi nhánh ghi log tĩnh đều qua khối lock có giới hạn và seek end).
   - **Lens 5 (Concurrency & deadlines):** `fixed here` (Giới hạn chờ tối đa 25 ms không làm ảnh hưởng trần 2,0 s; giải quyết triệt để race condition đồng thời).
   - **Lens 6 (Authority):** `holds` (Quyền truy cập file log được đảm bảo bởi `ensure_secure_regular_file_atomic`).
   - **Lens 7 (Fail closed):** `fixed here` (Khi không lấy được khóa, ghi log cảnh báo ra stderr thay vì nuốt lỗi).
   - **Lens 8 (Data export):** `holds` (Cảnh báo được đẩy ra stderr theo quy ước).
   - **Lens 9 (Outside world):** `holds` (Tương thích cơ chế khóa file trên Windows).
   - **Lens 10 (Evidence):** `holds` (Được kiểm chứng qua quy trình RED/GREEN/mutation và 20/20 lần stress test).
   - **Lens 11 (Agreement):** `holds` (Tuân thủ đúng hợp đồng hook của tài liệu thiết kế).

---

### Finding V5 (P3): Không commit thêm lên nhánh SP2 khi owner chưa đồng ý

1. **Invariant:** Nhánh công việc chính của dự án phải được bảo vệ; mọi chỉnh sửa tối ưu hóa và sửa lỗi trong phiên remediate phải nằm trên nhánh riêng biệt cho đến khi được chấp thuận.
2. **Sibling sweep:**
   - Toàn bộ công việc được thực hiện trên nhánh `remediate-runtime-opt`. Nhánh `thuc_hien_ke_hoach_sp2` hoàn toàn giữ nguyên trạng thái tại `5f73a0a`.
3. **Bảng 11 Lens:**
   - **Lens 1 to 10:** `not applicable`.
   - **Lens 11 (Agreement):** `holds` (Tuân thủ phân định nhánh).
