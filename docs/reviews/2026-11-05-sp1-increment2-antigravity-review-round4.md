# Review vòng 4 · Plan SP1 đợt 2 sau phản hồi R1–R3

Ngày 2026-11-05. Reviewer: Antigravity. Lượt này chỉ đọc tài liệu và spec; không sửa repo, không chạy gì.

| Đối tượng | SHA-256 | Khớp |
|---|---|---|
| [Plan](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md) | `2a9ad5d6…24a1a3` | ✓ với validation |
| [Quyết định D1–D8](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md) | `46a79f3a…6cb251` | ✓ |
| Review vòng 3 của tôi | `27b37a45…6fe5bb` | ✓ |

## Kết luận

- **R1 đã giải quyết.** T0 có "workspace lifecycle gate" ([plan dòng 47](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md#L47)) ghi lại PID, CWD, config theo dự án hay toàn cục, roots, chuyển checkout A→B và mở hai cửa sổ. Nếu host dùng lại cùng process cho checkout khác thì T0 tính là fail. Có thêm điều kiện freeze `x-resolution`.
- **R3 đã giải quyết.** Mức độc lập của reviewer được công bố đúng mức; T9 yêu cầu ghi provenance.
- **R2: đồng ý hướng A.** Cách viết trong tài liệu hiện có **một chỗ trái spec §14.2**, xem S1. Chỗ này chưa ảnh hưởng tới I2, vì I2 không có Jev, nhưng sẽ được đóng băng vào contract mà SP4 và SP6 phải kế thừa.

**Verdict:** sẵn sàng giao owner duyệt sau khi sửa câu chữ S1.

## Finding

| ID | Mức | Phát hiện | Bằng chứng | Đề xuất |
|---|---|---|---|---|
| S1 | P2 | **Thiếu snapshot làm task mất lineage, trái spec.** Bản sửa ghi: thiếu snapshot thì "toàn bộ trường task-derived giữ unknown lineage và không gọi Jev/egress". Spec §14.2 lại định nghĩa lineage của task gồm **repo của task** cộng các mục đã được phục vụ; snapshot (commit + dirty digest) chỉ cho biết phiên bản nội dung, không phải nguồn lineage. Trong khi đó repo đã được xác minh qua `selected_scope`. Hệ quả: (1) Jev bị tắt mỗi khi thiếu snapshot, trái Q1 (Jev là bộ chọn chính) và làm yếu M2; (2) SP6 bị lệch số đo, vì nhóm thiếu snapshot luôn đi qua rules, nên so sánh Jev với rules và holdout bị nhiễu. | Spec [§14.2 dòng 870–884](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-10-30-super-brain2-system-design.md#L870-L884). D3 [dòng 43, 47](file:///d:/ensemble-agents/Super-brain2/docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md#L43-L47). Plan test dòng 238 (`providercalls0`, unknown lineage). | Sửa D3, T3 và T8 như sau. (a) Thiếu snapshot: lineage của task vẫn gồm repo lấy từ binding đã xác minh, cộng các mục đã phục vụ; chỉ bỏ các mục **phụ thuộc snapshot** (context hoặc finishing gate cần source digest) và đặt `unknown_source` cho đúng những mục đó. (b) Egress tuân `provider_egress` hiện hành của repo như §9/§14.2; `snapshot_status` không tự chặn Jev. Nếu owner muốn chặt hơn spec, ghi rõ đó là `policy_change` hoặc quyết định riêng, không suy từ lineage. (c) Đổi test dòng 238 sang kiểm lineage gồm repo và kiểm không có mục phụ thuộc snapshot. Bỏ assert `providercalls0`, vì I2 production vốn không có provider. (d) Handoff SP6: báo cáo phân tầng theo `snapshot_status` và đường selector. |
| S2 | P3 | **Nguồn của quyết định owner.** D3 ghi "Owner chọn A ngày 2026-11-05", qua câu hỏi async trong chat Codex. Repo chưa có artifact nào giữ câu hỏi và câu trả lời. | Response dòng 19. D3 dòng 43. | Lưu nguyên văn câu hỏi, các lựa chọn, câu trả lời và thời điểm vào ledger `.superpowers/sdd/…`, rồi trích hash vào D3. Làm tương tự cho các quyết định owner về sau (D1–D8, T0 scope). |

## Ghi chú

Không còn finding P1. Các gate còn lại đã được tài liệu ghi đúng: T0 chưa được phép chạy, owner duyệt D1–D8, commit tài liệu và review rồi pin hash.
