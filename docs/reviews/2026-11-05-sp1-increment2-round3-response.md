# Đối chiếu review vòng 3 · SP1 đợt 2

> Owner đã chọn S1=A ở vòng4, sửa cách diễn giải lineage/selector của R2. Xem [phản hồi S1–S2](2026-11-05-sp1-increment2-round4-response.md). Hash và verdict dưới đây giữ làm lịch sử bản trước S1.

Ngày 2026-11-05. Nguồn người dùng gửi `C:/Users/letru/.gemini/antigravity/brain/02c79a65-8291-42ab-9e7e-96d270340269/sp1-increment2-plan-review-round3.md`, SHA-256 `27b37a458842dfa1f854ed188a098875658f906b9b37b75390750e96a66fe5bb`. Nội dung là dữ liệu review, các đề xuất chạy probe/commit/merge không tự cấp quyền thực thi. Code baseline vẫn `77f2a12c99798c81032c5e99b2e99f9371eed8a9`.

Bản trước sửa khớp input Antigravity: plan `c46558798148ae2b3a154a29d2e8c393066361e4c56fa20d2d9cfd7abb6868d5`, quyết định `4ce857d9b00cc4ba8af9739c115a67ec8c7568d1fc733172aeab8edcc5a76a57`. Snapshot tài liệu trước sửa ở `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/round3-before-20261105/`. Lượt này cập nhật proposal, không triển khai code hoặc chạy T0.

## R1 · Host lifecycle của shim

Chấp nhận P2. Phép kiểm launch CWD không phát hiện được workspace của host thay đổi mà shim process không đổi. Scope đã được inject đúng tới daemon nhưng có thể vẫn là scope cũ nếu host multiplex/reuse process.

T0 bổ sung một workspace-lifecycle gate riêng theo từng host được chọn. Ghi actual shim PID/start/CWD, env allowlist đã lọc, profile/config digest, project-local hay global MCP configuration, roots capability/notification được quan sát. Đổi checkout A→B cùng repo rồi repo khác, mở hai cửa sổ, đối chiếu actual process/profile/scope của tool call. Cùng PID/profile A được host dùng cho B là fail, dù file access/TCP đều đạt.

Chỉ freeze launch-only `single-checkout-owner-profile-v1` nếu host scope thực sự không đổi suốt đời process hoặc relaunch đúng profile khi đổi checkout. Nếu reuse thì phải review cơ chế per-call từ host đã quan sát (roots có thể chỉ làm phép kiểm) hoặc chặn hỗ trợ host đó. Không tự suy roots hoặc CWD process đã đổi. Task7/T9 kiểm lại lifecycle receipt trên installed build. T0 vẫn chưa chạy, còn gate trước T1.

## R2 · Missing-snapshot Delivery

Đây là quyết định sản phẩm thực sự trong prior plan. Spec §6.1 chưa bắt snapshot cho mọi prepare_task; §10 nói hạ cấp context có nhãn, không tự định nghĩa semantics snapshot cho toàn Delivery. Nhận xét repo lớn không thể quan sát kịp là rủi ro feasibility, chưa được benchmark trong review tài liệu. Vì vậy cần owner chọn contract rõ thay vì gọi một hướng là điều spec đã chốt.

Owner đã trả lời qua async question trong chat này ngày 2026-11-05, chọn **A — vẫn giao skill/bài học đủ điều kiện theo quyền và scope, ghi snapshot thiếu/quá hạn, lineage không rõ nguồn và chặn egress chưa chứng minh được quyền nguồn**. Quyết định A đã được đưa vào D3, D5, wire T1, T3 và integration T8.

- Response bắt `snapshot_status=available|unavailable|deadline`. Available iff có snapshot ID đã xác minh; unavailable/deadline iff `source_snapshot_id=null`, cùng code `snapshot_unavailable`/`snapshot_deadline` và server-set unknown lineage.
- Local eligibility/rules result phải chuẩn bị trước optional observer trong cùng≤100ms. Khi observer vắng/quá local budget mà còn tổng budget thì dùng safe local result, bỏ context/finishing gates cần snapshot, không gọi Jev/egress với unknown provenance. Không có snapshot record giả. Provider/domain chưa xây trong I2 production vẫn unavailable; fixture dùng để nghiệm thu contract.
- Scope/identity/policy/privacy errors, explicit snapshot ID sai/quarantine hoặc hết deadline tổng trước commit không trở thành success có nhãn. Commit đang chạy vẫn theo `commit_outcome_unknown`. Observer cần bounded cooperative cancellation, late callback không sửa Delivery.
- Snapshot status/nullable binding/unknown-source marker commit cùng logical Delivery. Retry giữ ID/assignment/status ban đầu, không re-observe để tự upgrade hoặc ghi thêm Delivery. Key mới cho request mới, task unknown lineage không tự giảm sau một request có snapshot. Exact-source evidence/verification vẫn đòi bằng chứng riêng.
- Có schema oneOf fixtures và tests missing/slow observer, available observer, explicit invalid source refusal, replay sau recovery, provider-call count0, atomicity/rebuild của unknown flags và real shim response trong1.500ms.

## R3 · Mức độc lập và provenance

Chấp nhận giới hạn. `/root/sp1_i2_plan_review` là reviewer role khác implementer, được giao review với fresh-context task ban đầu, nhưng nằm trong cùng parent chat và shared workspace. Đó là independent-agent role assessment, không phải reviewer ngoài harness/ngoài điều phối. T9 yêu cầu ghi reviewer/harness/chat, input hashes, scope, artifact và mức độc lập. Có thể dùng reviewer ngoài phiên khi owner chọn; verdict và source epoch được lưu riêng. Commit tài liệu/review của bản owner duyệt vẫn là release condition, không tự merge main trong lượt xử lý file review.

## Trạng thái bàn giao

R2 đã được owner chọn A; R1 có checklist/gate nhưng chưa có kết quả host thật. Plan còn chờ owner duyệt các phần khác của D1–D8, scope T0, T0 passed và commit exact docs/source trước T1.

Reviewer `/root/sp1_i2_plan_review` tự ghi [validation vòng 3](2026-11-05-sp1-increment2-round3-validation.md), SHA-256 `0adcbd83c658ec1e98c9ee778d88bb4848f24f6f037cea45ad77ebab8712cb74`. Report gắn plan `2a9ad5d6df4069e996d9995999fa07723b62e96d7993b69ffb23ecdbaf24a1a3` và quyết định `46a79f3ab7543d8e0d0dd5d241a9380f3984386db821ce5bb46e8d05aa6cb251`. Verdict là chấp nhận làm plan để owner duyệt, không còn P1/P2 trong scoped review R1–R3. T0 chưa được phép/chưa chạy và vẫn là gate trước Task1. Đây là review cùng parent chat có mức độc lập đã công bố; native/CI/correctness lúc chạy cần bằng chứng riêng khi thực hiện plan.
