# Review lượt 3 · Plan SP1 đợt 2 sau phản hồi N1–N7

Ngày 2026-11-05. Reviewer: Antigravity. Lượt này chỉ đọc tài liệu và source, không sửa repo, không chạy test hay spike.

| Đối tượng | SHA-256 | Khớp |
|---|---|---|
| [Plan](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md) | `c4655879…6868d5` | ✓ với validation |
| [Quyết định D1–D8](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md) | `4ce857d9…a76a57` | ✓ |
| Re-review lượt 2 của tôi | `790af1ef…e48302` | ✓ với hash được trích dẫn |
| [Response](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-05-sp1-increment2-rereview-response.md), [validation](file:///d:/ensemble-agents/Super-brain2/docs/reviews/2026-11-05-sp1-increment2-rereview-validation.md) | – | Đã đọc toàn bộ |

## Kết luận

Tôi đồng ý rằng N1–N7 đã được giải quyết. Hai điểm làm tốt nhất:

- **N1:** `selected_scope` đi trong private envelope và được tính vào HMAC. Reviewer Codex tự phát hiện lỗ hổng `record_outcome` khi một repo có hai checkout, và đã có test cho trường hợp đó.
- **N4:** snapshot và lineage chuyển sang dạng event-sourced. T2 dùng store2 làm mốc chặn binary I1 bằng `min_reader_version` trước khi xuất hiện các kind mới. Cách này khớp với cơ chế của [schema.py](file:///d:/ensemble-agents/Super-brain2/src/superbrain/storage/schema.py#L139-L168).

Còn **2 điểm P2 mới**. Một là lỗ hổng trong checklist T0. Hai là một quyết định cho owner về hành vi khi không quan sát được snapshot. Cả hai đều chạm vào schema mà Task 1 sẽ freeze (`x-resolution`, mã lỗi của `prepare_task`).

**Verdict:** có thể giao owner duyệt sau khi sửa R1 (một bullet trong T0) và owner chốt R2.

## Finding mới

| ID | Mức | Phát hiện | Bằng chứng | Đề xuất |
|---|---|---|---|---|
| R1 | P2 | **T0 chưa kiểm CWD lúc host khởi chạy shim, dù T7 nói là có.** Thiết kế mỗi shim một checkout (`x-resolution=single-checkout-owner-profile-v1`) dựa trên ba giả định về từng host, chưa có giả định nào được kiểm: (a) host chạy stdio MCP server với CWD nằm trong checkout; (b) có thể cấu hình MCP theo từng dự án; (c) host không dùng lại cùng một process shim khi người dùng chuyển workspace. Nếu (a) hoặc (b) sai, ví dụ ở host chỉ có cấu hình MCP toàn cục, mọi workspace tool sẽ bị từ chối. Nếu (c) sai, phép kiểm CWD chỉ chạy lúc khởi động sẽ không còn đúng, và continuity của checkout cũ bị giao nhầm mà không có lỗi nào. | Plan T7 [dòng 216](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md#L216) ghi "T0 kiểm host launch CWD/profile", nhưng các bullet T0 ở [dòng 45–48](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md#L45-L48) chỉ kiểm việc đọc file, loopback và transport. D3 dòng 33. | Thêm một bullet vào T0. Trên mỗi host được chọn, ghi lại: CWD và env của stdio MCP server; host có hỗ trợ cấu hình MCP theo dự án hay không; host có dùng lại process khi đổi workspace hay mở nhiều cửa sổ hay không; host có hỗ trợ `roots` hay không. Chỉ freeze `x-resolution` sau khi có kết quả. Nếu (c) sai, cần thêm cơ chế kiểm theo từng lần gọi (ví dụ dùng `roots` làm phép kiểm khi host hỗ trợ, không dùng làm selector) hoặc chặn hẳn host đó. |
| R2 | P2 · owner quyết | **Fail closed khi thiếu snapshot chặt hơn spec, và sẽ chặn delivery ở SP2.** Với observer thật, xác định nội dung working tree trong ≤100 ms mà không có watcher tin cậy là không khả thi với repo lớn, và plan cũng cấm dùng mtime/size làm bằng chứng. Khi đó `prepare_task` trả `deadline_exceeded` và harness không nhận được skill hay bài học nào. Spec §6.1 không yêu cầu snapshot cho `prepare_task`. §10 ưu tiên "hạ cấp có nhãn". §4.1 yêu cầu không làm treo hay chặn harness, và rules luôn có sẵn làm dự phòng. | D3 [dòng 41](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md#L41). Plan wire dòng 74. | Owner chọn một trong hai: (a) cho phép Delivery với `source_snapshot_id=null` và `snapshot_status ∈ {unavailable, deadline}` có nhãn, lineage `unknown_source`, chỉ fail closed ở bước egress; hoặc (b) giữ mức chặt, nhưng ghi vào handoff SP2/SP5 rằng một observer nền dựa trên watcher, với freshness contract đã review, là **điều kiện tiên quyết** trước khi bật `prepare_task` production. Tôi nghiêng về (a). Dù chọn hướng nào, cần chốt trước T1 vì mã lỗi và trường kết quả nằm trong schema. |
| R3 | P3 | **Mức độc lập của reviewer.** Reviewer `/root/sp1_i2_plan_review` là agent con trong cùng parent chat với bên sở hữu bản sửa. Cách này có provenance tốt nhưng độc lập hạn chế. Ngoài ra, file validation vẫn chưa được commit (`docs/reviews/` untracked). | Validation dòng 3. `git status`. | Commit các review cùng plan khi owner chọn bản duyệt. Với review toàn nhánh ở T9, cân nhắc dùng reviewer ngoài phiên tác giả (khác harness hoặc khác lineage hội thoại). |

## Đối chiếu nhanh N1–N7

| ID | Xác nhận |
|---|---|
| N1 | `ClientProfile.workspace` là một object duy nhất. `Call`/`CallContext.selected_scope` có, HMAC tính trên `{tool,selected_scope,arguments}`, khóa idempotency giữ `(principal,tool,key)`. Có test cho hai checkout cùng repo và cho việc đổi profile (plan dòng 70–74, 214–220). Phần còn hở nằm ở R1. |
| N2 | Observer dùng chung ngân sách ≤100 ms, không có Git subprocess trên đường đi của `prepare_task`, và có ràng buộc config độc hại cho SP2. Phần còn hở nằm ở R2. |
| N3 | Có test `test_workspace_authorization_ignores_main_mirror`. I3 có `workspace_link` để tái nhận ID cũ, kèm preview. |
| N4 | Có event `snapshot.observed`/lineage, projection `p_*`, rebuild không gọi observer. |
| N5 | Có đủ ca prefetch qua `rfile`, cap áp trước parser, không dùng blocking peek (T0 dòng 47, T6b). |
| N6 | Có `tls_expiring` và `tls_expired`, không ghi DB. |
| N7 | Có danh tính agent, parent chat và các hash input. Xem thêm R3. |
