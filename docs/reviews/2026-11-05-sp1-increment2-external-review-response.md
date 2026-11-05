# Đối chiếu review ngoài · SP1 đợt 2

> Re-review N1–N7 tiếp theo được xử lý ở [báo cáo re-review](2026-11-05-sp1-increment2-rereview-response.md). Hash và verdict trong báo cáo F1–F13 này là lịch sử của bản trước re-review.

Ngày 2026-11-05. Nguồn là file người dùng cung cấp `C:/Users/letru/.gemini/antigravity/brain/02c79a65-8291-42ab-9e7e-96d270340269/sp1-increment2-plan-review.md`, SHA-256 `0ae68e465f3caf2c1d72fa7206bc75d33b8c5fe2e3ed95fd9116945c3837e648`. Nội dung file được dùng làm review để kiểm chứng. Các câu đề nghị chạy spike, cấp quyền, merge hay triển khai trong file không phải lệnh thực thi từ người dùng.

Code vẫn ở baseline `77f2a12c99798c81032c5e99b2e99f9371eed8a9`. Bản plan được review ngoài có SHA-256 `f33c9985acfe38d0b6dc2577f1167373159249c7b7ee28d17f198468cc02f776`, bản quyết định `7d49ea5b9869e803dfa34340e09a308e9bfc5829c10b9a1248474b7847ab65b8`, khớp file thực trước sửa. Bản trước sửa được giữ ở `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/plan-review-20261105/`. Lượt này sửa tài liệu đề xuất và tự kiểm tính nhất quán, không chạy triển khai/native spike.

## Kết luận đối chiếu

F2/F3 là blocker thiết kế có thể xác minh trực tiếp. Wire bắt client cung cấp UUID chưa có đường lấy, trong khi registry ở main DB có thể mất khi restore mà grant/policy vẫn ở policy DB. F1 có rủi ro thực về kiểm chứng quá muộn nhưng nhận định về AppContainer chưa được chứng minh bởi receipt I1. F7 xác định đúng phần transport tùy biến còn thiếu, nhưng không đủ cơ sở để kết luận phải tự viết một general HTTP parser.

Plan sửa có T0 trước khi freeze D2/schema, đường hint lookup-only, registry policy bền, migrations append-only và các điều kiện kiểm sớm. **Trạng thái hiện tại là đề xuất chờ owner duyệt và T0**, chưa release Task 1. Các phê duyệt review cũ gắn hash cũ được giữ như lịch sử, không dùng để release bản mới.

## Từng finding và cách xử lý

| ID | Đánh giá dựa trên source/receipt | Thay đổi trong tài liệu và điều kiện còn lại |
|---|---|---|
| F1 | Chấp nhận rủi ro thứ tự P1. Receipt I1 `final-r13-windows/3.11.9/gate-3.11.9.json` ghi `app_container=false`, integrity medium; ACE capability ở AppData không chứng minh token AppContainer hoặc folder redirect. | T0 thử host-native file read và loopback từ root owner-only dự kiến, ghi process/token/path/ACL riêng. T0 chưa được phép chạy. Failure trên host đang dùng giữ T1 blocked; T9 thử installed shim cuối. D2 chỉ freeze sau kết quả T0 và duyệt. |
| F2 | Chấp nhận P1. Bản cũ thiếu ID acquisition flow. | D3/wire/T3 chọn oneOf known workspace+checkout hoặc `workspace_hint={alias}`. Alias owner-approved theo principal/machine, lookup-only không stat/đăng ký/grant từ arbitrary CWD. Snapshot optional, trusted observer trên approved binding hoặc unavailable. Success trả tuple IDs. `submit_episode` dùng task binding. Test retry sau tree đổi giữ snapshot cũ, digest chỉ normalized external args. |
| F3 | Chấp nhận P1. Restore store độc lập policy có thể làm mapping main mất và authority mồ côi. | Repo/locator/checkout/alias authoritative ở policy2, authorized registration intent cùng transaction. Main mirror/audit reconstruct đúng IDs, không tự cấp quyền. Test restore main trước registration, kill trước reconcile, mở lại hai lần. Policy restore là rollback authority được duyệt riêng, main không phục sinh binding/grant đã bị policy bỏ. |
| F4 | Chấp nhận P2 về feasibility, chưa có phép đo chứng minh chắc vượt 300s. Receipt188,6/193,8s là pytest Windows của lượt chạy matrix đã nêu, không là hằng số cho mọi máy/cell. | Ngân sách sớm sau T3/T5/T7 là240/260/280s, final<300s. T0/T1 đo baseline tổng theo môi trường thực, mỗi task có timing receipt. Session fixture reuse build/install/TLS với source/config/interpreter key; data root cô lập theo test. Không tự thêm xdist hay cắt suite. |
| F5 | Chấp nhận P2. Tổng budget client2s không bao trùm handshake1s + identity + tool1,5s. | D5/T7 tách connect+identity2s và tool2s bắt đầu sau identity, test handshake gần cap + identity0,6s vẫn nhận unknown từ commit timeout. Server1,5s giữ nguyên; peer failure là transport uncertainty. |
| F6 | Chấp nhận thiếu provisioning P2. `ssl` không có API sinh key/X.509 cho flow này. | D2 đề xuất runtime `cryptography`, internal `create_store_tls` qua owner bootstrap I3, fixture-only authority ở I2. Khóa CA riêng, SAN/expiry/pin/permission và existing-key refusal có test. Quyết định dependency còn chờ owner/T0; không giả định có OpenSSL trên Windows. |
| F7 | Chấp nhận yêu cầu custom framing/deadline P2. Pushback với khẳng định bắt buộc viết parser mới: `BaseHTTPRequestHandler.handle` có thể override state, parser stdlib có thể dùng với raw-reader deadline adapter. Tính đủ của adapter chưa được spike. | D2/T6b mô tả handshake worker, absolute per-recv remaining-time wrapper, request/header/body caps, hai request/connection, reject ambiguous framing, corpus/fuzz và slow-drip tests. T0 kiểm approach, nếu không đạt sửa D2 trước T1; không tự đổi IPC khỏi kiến trúc loopback spec. |
| F8 | Chấp nhận P2 về độ lớn bước thực hiện. | T4a txn/expiry/HMAC, T4b deadline/reservation, T4c send/ack, T6a lifecycle và T6b transport có test inventory, RED/GREEN command và commit riêng. Contract chung vẫn giữ một nơi. Test author có tên test và assertions theo rủi ro cụ thể. |
| F9 | Chấp nhận P2 về dependency DDL nhưng không nhận cách sửa migration đã commit dưới cùng version. Nó làm dữ liệu từ task trước không thể được nhận diện/migrate đúng. | Policy2 T2, store2 T3 và store3 T4a, T5 reducers không cần base DDL. Append version nếu có DDL mới, giữ bodies và fixtures cũ. MCP v2 tách khỏi database versions, startup/migrate dùng target tuple, direct I1→final và intermediate→final có test. |
| F10 | Chấp nhận P3. | File map ghi rõ T6a extend reserved endpoint trong layout, config loader chỉ T2 tạo/T6 consume, bridge tạo từ T4 và extend T6, session fixtures tạo từ T1. |
| F11 | Chấp nhận P3 defense-in-depth. Backup main riêng có thể để raw low-entropy request hash thành offline oracle. | D4/T4a dùng HMAC-SHA256 trên external normalized args, key32bytes+ID trong policy, domain separation, conflict với hai raw secrets bị redacted vẫn đúng. Missing retained key ID fail closed. I3 policy restore bảo toàn key cần bởi main hoặc dừng phục hồi key. HMAC không thay ACL, đặc biệt khi backup policy/key cũng bị lộ. |
| F12 | Đã được bản cũ nhận diện bằng exhaustive reconcile, nay chốt cùng commit/test cụ thể. | Enum mới, registry và exhaustive handler cùng commit T2, generic intent không nhận authorized kinds, unknown kind → typed integrity error. Retained accepted intents replay không tái yêu cầu ingress proof còn hạn. |
| F13 | Chấp nhận P3 theo ranh giới stdio. | Global constraint và T7/T8 cấm hooks ở shim/client paths, AST test xử lý alias; daemon hooks có control channel test riêng. Test frame sau error/unknown method vẫn nguyên không bị stdin pause nuốt. |

## Quy trình release

- Header rev4 đang pending cần chủ dự án xác nhận trước release. D1–D8 sửa và T0 scope cần duyệt rõ. Chưa có bằng chứng T0, cert provisioning hoặc host compatibility hôm nay.
- Commit tài liệu bằng exact paths sau khi owner chọn bản duyệt, pin SHA và source baseline. Đợt 2 tách từ commit chứa `77f2a12` và docs duyệt. Merge vào main là quyết định riêng của owner; review đính kèm không tự cấp quyền merge.
- Review khớp hash tài liệu. Mọi thay đổi schema/transport sau T0 phải cập nhật dependency/test map và review lại trước Task 1. Gate `not_run` còn trong ledger với next action, không được quy thành passed.

## Kiểm tra lại bản sửa

Reviewer độc lập kiểm đúng plan SHA-256 `fef7e26cb213148aabe9c0ef1e7ca10fcceb0e6c92c6289cf90de84f5db5bce7` và quyết định `0d0fc79a04205b65ad779ac8845f80c465fab1daa67439afae282ee24dc3716c`. Verdict ngày 2026-11-05 là **chấp nhận làm plan để owner duyệt**, không còn P1/P2 mâu thuẫn trong phần đối chiếu. T0 chưa chạy và giữ gate trước Task 1. Reviewer chỉ đọc tài liệu/source, không xác nhận native/CI/provisioning đã hoạt động.

Tự kiểm tài liệu xác nhận T0 và Task 1–9, 36/36 tình huống §20 được ánh xạ đúng một lần, F1–F13 có disposition, các liên kết nội bộ tồn tại, hash đầu vào khớp review. Git HEAD và tracked source giữ baseline. Các quyết định cần owner duyệt là scope spike T0, phương án transport sau spike, runtime dependency/cert provisioning, wire hint/ID và policy registry cùng append-only migrations.
