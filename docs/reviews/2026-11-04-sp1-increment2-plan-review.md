# Review trước triển khai · SP1 đợt 2

> Cập nhật 2026-11-05. Các verdict dưới đây gắn hash lịch sử ngày 04/11. Review Antigravity bổ sung F1–F13 và bản plan sửa hiện tại được đối chiếu ở [báo cáo ngày 05/11](2026-11-05-sp1-increment2-external-review-response.md). Release hiện chờ owner duyệt và T0, không dùng verdict cũ để bắt đầu Task 1.

Ngày 2026-11-04. Đối chiếu [spec rev 4](../superpowers/specs/2026-10-30-super-brain2-system-design.md), [bàn giao đợt 1](../design/sp1-increment1-handover.md) và code tại `77f2a12c99798c81032c5e99b2e99f9371eed8a9`. Phạm vi là review tài liệu và interface hiện có. Gate sản phẩm và probe native sẽ chạy trong plan đã duyệt.

- [Plan daemon/MCP/kernel](../superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md)
- [Các quyết định D1–D8](../superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md)

## Lượt 1

Builder check và reviewer đọc độc lập. Draft plan SHA-256 `7548c305a8666c4119493c0c733bb75250511a7aae7e9d09f2bc0da475ff9557`; draft quyết định `9584aa7b30102fedbeee3b35a74dee3b05bb68eefa66e80b68a409e55143083c5`. Kết luận ban đầu **cần sửa trước khi triển khai**.

| ID | Mức | Phát hiện | Sửa trong plan |
|---|---|---|---|
| I2-P01 | P1 | `open_runtime()` I1 có thể tạo DB, ghi epoch và mở policy trước khi kiểm store. Migration từng DB có thể để cặp lệch phiên bản. | D1/T2/T6 chốt `expected_store_id`, raw OS lock trước preflight không ghi epoch, read-only recovery view, kiểm cả live và stage có thể publish. Một lease xuyên policy→store; mixed schema dừng serve và explicit migrate tiếp. |
| I2-P02 | P1 | SQLite owner có thể bị chặn đúng lúc cần trả `in_progress`/`commit_outcome_unknown`. Giới hạn socket không tự chứng minh deadline. | D4/D5/T4/T6/T8 đặt reservation và arbiter ngoài owner, chốt t0/cutoff, test thật giữ commit qua cutoff rồi retry đúng ID/assignment. EOF được ghi là transport uncertainty. |
| I2-P03 | P1 | Kiểm store identity sau bearer có thể gửi secret sang endpoint stale hoặc sai kho. | D2/T6/T7 chỉ CA riêng + leaf pin, rồi tuple không bearer và đúng một tool call trên cùng socket; test wrong-store cùng cert, port reuse, cert hết hạn và không reconnect ngầm. |
| I2-P04 | P1 | Giữ idempotency vô hạn trái §5.6. Bằng chứng cho mỗi lần gửi artifact bị trộn với kết quả business idempotent. | D4/T4/T8 giữ 30 ngày kể từ commit gốc, expiry/replace cùng transaction, prune bounded, result IDs ổn định. Mỗi send attempt riêng, pending/unknown khi gián đoạn; `ReadAck` bind đủ digest. |
| I2-P05 | P1 | Cần chống cấp authority qua generic intent và chống direct ref vượt repo/checkout/snapshot. | D3/T2/T3 tách revoke authorized intent với stable ID và trust generation; compare owner/action/subject; validate object gốc và scope. Fixture có principal riêng, production enrollment thuộc I3. |
| I2-P06 | P1 | Job schema lẫn với projection, callback/recovery có thể sửa state hoặc account hai lần. | D5/T5/T8 chốt reducer ownership, transition matrix, fences, invocation reserve/settle, terminal job pending usage, kill sau cancel/settle và hai lần restart. |
| I2-P07 | P2 | Gate I1 chưa khóa inner uv, xóa JUnit, chưa kiểm tổng thời gian; native receipt thiếu principal/epoch. | T1/T8/T9 chốt dev inputs/lock và installed wheel, additive evidence export, aggregate budget, sáu cell, host thật phải đọc profile/endpoint/credential, observer bind source/build/principal/epoch. |
| I2-P08 | P2 | Các task chưa thống nhất producer của types, config, DDL, fixture và exact lineage refs. | Bản đồ file/T2–T5 chốt ownership và dependency, types trong core/ports, full identity+revision+digest và monotone lineage khi bị redacted. |

## Đối chiếu phạm vi

- Kế hoạch có chín task. Mỗi tình huống §20 từ 1 đến 36 xuất hiện một lần trong bảng ánh xạ, với test hoặc đợt/domain chịu trách nhiệm. Các ngưỡng còn lại được ghi trong global constraints và gate T8/T9.
- T2 giữ các invariants đã nghiệm thu trong I1. T8 yêu cầu suite cũ cùng crash parity; các receipt `77f2a12` chỉ là baseline. Windows configured root và lỗi ACL của profile mặc định giữ riêng; macOS, remote CI và power loss chỉ nhận claim theo bằng chứng thực tế.
- Mọi capability thuộc I3/I4/SP2+ có handoff. Cấp credential thật, chỉnh config harness và loopback exemptions thuộc scope riêng. D1 chọn owner foreground; D2 đề xuất TLS pin để tránh phát bearer cho listener sai. Cả hai vẫn là lựa chọn để chủ dự án duyệt.

## Lượt 2 và kết luận

Reviewer độc lập đối chiếu lại SHA-256 plan `59e624f5b94e952d9f6c2c260f884153b36616e83a334cf816db8407137ff58c` và quyết định `9e494ff6462e376c92e5c54399f207e611e914bc293a7d327237eaa29b5bbf7d`. Verdict: các blocker ban đầu đã xử lý. Task 1 có thể bắt đầu sau khi chủ dự án duyệt plan.

Reviewer đề nghị một chỉnh sửa câu chữ cho I2-P04. T8 và D4 hiện nói rõ daemon quan sát HTTP flush tới shim. Lỗi stdout không tự tạo ReadAck. Acknowledgment tường minh khớp digest là khai báo của client, không dùng để chứng minh daemon quan sát stdout thành công.

Phiên bản giao duyệt sau chỉnh sửa trên:

| Tài liệu | SHA-256 |
|---|---|
| Plan | `f33c9985acfe38d0b6dc2577f1167373159249c7b7ee28d17f198468cc02f776` |
| Quyết định D1–D8 | `7d49ea5b9869e803dfa34340e09a308e9bfc5829c10b9a1248474b7847ab65b8` |

**Kết luận review:** sẵn sàng giao chủ dự án duyệt. Khi duyệt, xác nhận phương án daemon chạy foreground từ phiên owner, vận hành một kho, và TLS pin với chứng chỉ riêng từng kho. Native probe dùng installed shim và cấu hình cô lập được duyệt riêng. CI đủ sáu cell và native từng host là kết quả cần thu trong lúc triển khai, không phải bằng chứng có sẵn từ review tài liệu.
