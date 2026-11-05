# Review vòng 5 (đóng) · Plan SP1 đợt 2

Ngày 2026-11-05. Reviewer: Antigravity. Lượt này chỉ đọc tài liệu và artifact; không sửa repo, không chạy gì.

| Đối tượng | SHA-256 | Khớp |
|---|---|---|
| [Plan](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md) | `002af95a…8d3fe8` | ✓ với validation vòng 4 |
| [Quyết định D1–D8](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md) | `c544947e…40f3b0` | ✓ |
| Bản ghi quyết định owner (`.superpowers/sdd/…/owner-snapshot-decisions-20261105.json`) | `89aa1d23…fc6634` | ✓ với D3 |
| Review vòng 4 của tôi | `a58b3fe6…13ee9c` | ✓ |

## Kết luận

- **S1 đã giải quyết.** D3 dòng 43–49 tách lineage khỏi snapshot đúng theo §14.2: repo lấy từ binding đã xác minh và các nguồn đã phục vụ luôn được giữ; `unknown_source` chỉ áp cho nguồn thực sự không xác định; `snapshot_status` tự nó không bật hay tắt Jev, và không có mã lý do giả kiểu `missing_snapshot`. Các test ở plan dòng 139 và 238 đã được viết lại tương ứng. SP6 phải báo cáo phân tầng theo `snapshot_status` và đường selector.
- **S2 đã giải quyết.** Bản ghi JSON giữ nguyên văn hai câu hỏi, các lựa chọn, câu trả lời, tool call ID và quan hệ supersede R2→S1. `occurred_at` để `null` thay vì đoán thời điểm.
- Tôi quét lại plan và D3, không còn câu chữ cũ kiểu "toàn task unknown", "always-local" hay `providercalls0`.

## Finding còn lại

| ID | Mức | Phát hiện | Đề xuất |
|---|---|---|---|
| T1 | P3 | **Bản ghi quyết định owner nằm trong `.superpowers/`, thư mục bị gitignore** (bàn giao I1, dòng 69). D3 trích hash của nó, nhưng khi commit tài liệu thì file này không đi kèm, nên người đọc từ Git không kiểm lại được. | Khi commit bản duyệt, chép bản ghi sang `docs/reviews/` (hoặc commit riêng có chủ đích), hoặc ghi rõ trong D3 rằng nó được bảo quản ngoài Git giống các ledger I1. |

## Tổng kết các vòng

Các vòng F1–F13, N1–N7, R1–R3 và S1–S2 **không còn finding P1 hoặc P2 nào**. Từ góc độ review tài liệu, plan đã sẵn sàng để owner duyệt.

Các điều kiện còn lại không thuộc phạm vi review tài liệu, và đã được plan ghi đúng ở dòng 255 trở đi:

1. Owner xác nhận spec rev 4, duyệt D1–D8 và scope cụ thể của T0.
2. Chạy T0 trên các host được chọn, đạt cả gate kết nối lẫn gate vòng đời workspace; sau đó chốt D2 và `x-resolution`.
3. Commit plan, quyết định và các review đã chọn bằng đường dẫn chính xác, pin hash, rồi tách nhánh I2 từ `77f2a12`.
