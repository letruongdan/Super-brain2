# Review lượt 2 · Plan SP1 đợt 2 sau phản hồi review ngoài

Ngày 2026-11-05. Reviewer: Antigravity. Chỉ đọc tài liệu, source và receipt; không sửa repo, không chạy test hay spike.

| Đối tượng | SHA-256 kiểm được |
|---|---|
| [Plan](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md) | `fef7e26c…5bce7`, khớp hash trong phản hồi |
| [Quyết định D1–D8](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md) | `0d0fc79a…3716c`, khớp |
| [Phản hồi review ngoài](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-05-sp1-increment2-external-review-response.md) | Đối chiếu từng mục F1–F13 |

## Kết luận

Phản hồi xử lý đủ F1–F13 và có căn cứ. Hai chỗ phản hồi chỉnh lại nhận định của tôi là đúng:

- **F1:** receipt `final-r13-windows` (cả 3.11.9 lẫn 3.14.3) ghi `app_container: false`, `integrity_level: medium`. Nhận định "có thể là AppContainer" của tôi chưa có bằng chứng. Phần còn đúng là rủi ro thứ tự, và phần này đã được xử lý bằng T0.
- **F4:** pytest mất 188,6 / 193,8 giây là số của một lượt matrix cụ thể. Cách đặt checkpoint 240/260/280 giây hợp lý hơn đề xuất của tôi.

Tôi chấp nhận hai điểm phản hồi không theo đề xuất của tôi:

- **F9:** migration chỉ thêm (append-only) đúng hơn đề xuất "sửa DDL tới lúc handoff". Cách của tôi làm hỏng nhận diện dữ liệu fixture của các commit trung gian.
- **F7:** tái dùng parser của stdlib kèm adapter đọc có deadline là khả thi, với điều kiện T0 kiểm các điểm ở N5 bên dưới.

Còn **2 finding P2 mới**, phát sinh từ chính bản sửa. Cả hai chạm schema được pin ở T1, nên cần sửa tài liệu trước khi owner duyệt. Các finding P3 có thể ghi vào handoff.

**Verdict:** sẵn sàng để owner duyệt sau khi sửa N1–N2. T0 vẫn là gate trước Task 1.

## Finding mới

| ID | Mức | Phát hiện | Bằng chứng | Đề xuất |
|---|---|---|---|---|
| N1 | P2 | **Chưa rõ ai cung cấp `workspace_hint`, và profile không có chỗ chứa mapping.** D3 viết "shim đã cài gửi hint lấy từ mapping owner-approved", nhưng wire lại đặt `workspace_hint` trong arguments của tool, tức là agent tự viết. `ClientProfile` ở T7 không có trường nào chứa mapping thư mục→alias. Nếu agent tự chọn alias, nó cần một cách để biết danh sách alias, và chọn nhầm sẽ nhận continuity của checkout khác. Nếu shim tự chèn alias, cần nói rõ shim xác định workspace hiện tại bằng cách nào, xử lý ra sao khi có nhiều root hoặc không có root, và hint được chèn có tham gia digest không. | D3 dòng 33. Plan wire dòng 72. `ClientProfile` dòng 208. | Chọn rõ một hướng. Gợi ý: shim lấy root qua capability `roots/list` của MCP 2025-06-18 (khi host hỗ trợ) hoặc từ cwd lúc launch, rồi tra mapping cục bộ trong profile. Không gửi path cho daemon. Hint đã chèn được tính vào digest. Agent chỉ được truyền alias tường minh khi shim không phân giải được. Thêm trường mapping vào `ClientProfile`, kèm test cho các ca nhiều root, không có root và alias không khớp. |
| N2 | P2 | **`SnapshotObserver` chưa có chỗ trong ngân sách deadline.** Khi thiếu `source_snapshot_id`, observer chạy đồng bộ trên đường đi của `prepare_task`. Đi qua hint thì gần như luôn thiếu snapshot, nên observer chạy ở hầu hết các lần gọi. §6.5 chỉ chia ngân sách cho lọc ≤100 ms, Jev và commit ≤200 ms; tính dirty digest trên repo lớn có thể vượt. Ngoài ra, observer thật ở SP2 nếu gọi `git` sẽ đọc config cục bộ của repo, mà `core.fsmonitor` có thể chạy một chương trình tùy ý. Điều này trái nguyên tắc "không chạy code của dự án". | D3 dòng 35. Plan T3 dòng 125. Spec §6.5. | Thêm phase observer vào bảng ngân sách, ví dụ ≤300 ms có cache theo mtime và size. Quá hạn thì trả mã đã định nghĩa, không tính lại trong transaction. Ghi ràng buộc cho handoff SP2: observer chỉ đọc object/index, hoặc gọi git với config bị khóa (tắt fsmonitor và hook, không dùng config cục bộ của repo); có test bằng repo chứa config độc hại. |
| N3 | P3 | **Store mirror sau khi rollback policy.** `restore_policy` I1 không mang intent của bản live sang ([restore.py](file:///d:/ensemble-agents/Super-brain2/src/superbrain/storage/restore.py#L190-L199)). Vì vậy sau rollback, ledger và `p_workspace_registry_*` của main vẫn còn binding mà policy không còn. Plan cấm phục sinh tự động, nhưng chưa định nghĩa đường để owner nhận lại ID cũ. Thiếu đường đó, lần đăng ký lại sẽ sinh `repo_id` mới, vi phạm §5.2. | D3 dòng 31. T3 dòng 129. | Thêm test AST/kiến trúc: không đường authorization nào đọc mirror. Ghi vào handoff I3 một hành động "re-adopt ID từ mirror" cần approval, kèm preview. |
| N4 | P3 | **`source_snapshots`, `task_lineage`, `field_lineage` là bảng nền của store, nằm ngoài ledger.** `rebuild_projections` và audit không phủ các bảng này. Với idempotency thì spec cho phép là bảng vận hành; với lineage và snapshot thì chưa rõ chúng là bản ghi nghiệp vụ (theo §5.4 phải là ledger + projection) hay chỉ là dữ liệu vận hành. | Plan T3 dòng 123. Spec §5.3–5.4. | Ghi rõ loại của từng bảng. Nếu là nghiệp vụ, append entry ledger có kiểu và dùng bảng làm projection. |
| N5 | P3 | **Điểm cần T0 kiểm để chốt F7.** `BaseHTTPRequestHandler` dùng `rfile` có buffer, nên byte của request pipeline có thể nằm sẵn trong buffer; muốn từ chối pipeline thì phải kiểm buffer sau body. Ngoài ra, `http.client.parse_headers` chỉ chặn ở 100 header và dòng 65.536 byte, nên các cap 8 KiB / 16 KiB / 32 header phải do wrapper thực thi trước bước parse. | Plan dòng 202. | Đưa hai điểm này vào checklist spike transport của T0. |
| N6 | P3 | **Leaf TLS hết hạn sau 365 ngày thì `serve` từ chối.** Công cụ xoay chứng chỉ chỉ có ở I3, còn `doctor` ở I4. | D2 dòng 17. T2 dòng 109. | Thêm `degraded_codes` kiểu `tls_expiring` (≤30 ngày) vào shallow health của I2. Chi phí thấp, không cần ghi DB. |
| N7 | P3 | **Nguồn gốc của "reviewer độc lập".** Phản hồi ghi verdict của reviewer độc lập nhưng không nêu danh tính, hội thoại hay artifact nào làm bằng chứng. | Phản hồi dòng 39. | Ghi đường dẫn hoặc ID hội thoại của reviewer, giống cách I1 lưu `codex-scoped-review-*.md`. |

## Ghi chú

- Cổng T0 nêu "host đang dùng (Claude Code/Codex)". Phiên review này chạy trong Antigravity, nên cần liệt kê tên host cụ thể trong gate để tránh hiểu khác nhau.
- Điều kiện release ở dòng 255 đã đủ: rev 4, D1–D8, T0, commit tài liệu, nhánh tách từ `77f2a12`. Ba tài liệu vẫn chưa được commit.
