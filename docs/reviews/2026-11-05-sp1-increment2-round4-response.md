# Đối chiếu vòng 4 S1–S2

> Vòng5 xác nhận S1/S2 đã xử lý và đóng review tài liệu. Bản owner decision được chép nguyên bytes sang docs để commit cùng plan. Xem [phản hồi vòng5](2026-11-05-sp1-increment2-round5-response.md). Hash trong báo cáo vòng4 giữ làm lịch sử bản trước thay đường dẫn provenance.

Nguồn người dùng gửi `C:/Users/letru/.gemini/antigravity/brain/02c79a65-8291-42ab-9e7e-96d270340269/sp1-increment2-plan-review-round4.md`, SHA-256 `a58b3fe613b8366f9fe5fac15bebd8b4f93d3d0d73ad8750cf0728fc6913ee9c`. Review đọc đúng bản plan `2a9ad5d6df4069e996d9995999fa07723b62e96d7993b69ffb23ecdbaf24a1a3` và quyết định `46a79f3ab7543d8e0d0dd5d241a9380f3984386db821ce5bb46e8d05aa6cb251`. Baseline code vẫn `77f2a12c99798c81032c5e99b2e99f9371eed8a9`.

## S1 và quyết định owner

Chấp nhận việc phải tách source lineage khỏi content version. Spec §14.2 giữ repo binding và mọi served source trong lineage đơn điệu; thiếu snapshot không xóa các nguồn đó. Prior draft đã conflated snapshot unavailable với automatic unknown trên mọi task field. Tuy nhiên nó xuất phát từ câu hỏi R2 và reply A thực của owner, nên không được tự thay chỉ theo review đính kèm.

Root đã hỏi lại S1, owner chọn **A — theo spec, thiếu snapshot vẫn giữ repo/lineage đã biết, chỉ đánh unknown cho nguồn thực sự không xác định; Jev tuân policy hiện hành và không bị tắt chỉ vì thiếu snapshot**. Quyết định này supersede phần always-local/automatic-unknown của R2. Labeled snapshot/null/status, replay IDs, deadline và quyền vẫn giữ.

Plan và D3/T3/T8 hiện yêu cầu giữ binding repo + served sources, bỏ context/gates đòi exact source snapshot; eligibility của Jev phụ thuộc allowlist/current policy và unknown thực sự, không snapshot_status. I2 vẫn không có provider execution vì domain chưa triển khai. Tests dùng fake eligibility port để so available/unavailable/deadline dưới cùng nguồn/quyền và kiểm unknown/disabled repo thật vẫn bị chặn. SP6 phân tầng theo snapshot_status và actual selector path/reason để tránh suy missing snapshot thành rules assignment.

## S2 và provenance

Lưu nguyên văn hai câu hỏi, cả hai lựa chọn và hai câu trả lời R2→S1 ở `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/owner-snapshot-decisions-20261105.json`, SHA-256 `89aa1d23186e7dfe94979e5f5b0cbc874d980f3104cda44a5adbe76d5dfc6634`, được D3 và plan trích dẫn. Artifact ghi parent chat, tool call IDs và recorded_at UTC. `occurred_at=null` vì không có exact original timestamps trong context, chỉ biết ngày 2026-11-05 theo giờ người dùng. Đây là manual transcription từ reply thật, không phải signed approval hoặc receipt do verifier cấp. Không ghi thời điểm suy đoán thành thời điểm owner trả lời.

T0 vẫn chưa được phép/chưa chạy. Owner chọn S1 không cấp quyền chạy host-native, code hay merge. Các bản review trước gắn hashes cũ và được giữ làm lịch sử. Bản sửa chờ scoped validation theo final hash và owner duyệt phần plan còn lại.

## Phiên bản cuối vòng 4

Plan SHA-256 `002af95a2cd3474366d179f02a7a576b9559b33643eae34dfde24a4a7a8d3fe8`, quyết định `c544947e7e4e24a12583a4bcdcf66604d15e6080c2ba228961d814111440f3b0`. Đã đổi tên test thành `test_missing_or_slow_observer_produces_labeled_delivery_with_known_lineage` để không ngụ ý missing snapshot luôn local-only. Tự kiểm xác nhận T0 + Task1–9, đủ36 tình huống §20, local Markdown links, whitespace và hash owner decision. Tracked source vẫn ở baseline nghiệm thu I1.

Reviewer `/root/sp1_i2_plan_review` tự ghi [validation vòng 4](2026-11-05-sp1-increment2-round4-validation.md), SHA-256 `649813b3532ce6fec6c42a47a4d7d2dba305ad78ce28cf2130110b506acfc189`, đối chiếu đúng hai hash cuối và artifact owner decision. Verdict chấp nhận làm plan để owner duyệt; không còn P1/P2 trong scoped review S1–S2. Reviewer cùng parent chat và shared workspace, provenance/mức độc lập ghi trong artifact. T0 vẫn chưa được phép/chưa chạy và các điều kiện release khác giữ như plan.
