# Super-brain2: thiết kế hệ thống tổng thể

- **Ngày:** 2026-10-30
- **Phiên bản:** rev 22. Rev 16 tới rev 21 chỉ tồn tại trong working tree, SHA-256 lần lượt `331bf0d9…ad91`, `e3802cbc…799a`, `86f85b64…7ccc`, `95c755d0…a405`, `797903dd…5b5f` và `57a3c323…905d`.
- **Trạng thái:** rev 22 đã được chủ dự án duyệt làm baseline ngày 2026-11-19 trên commit `035a4cd` kèm làm rõ §7.4 / §20 ca 62 ([biên bản quyết định](../../reviews/2026-11-19-sp2-baseline-and-ca62-decisions.json)). Rev 10 đã được duyệt ngày 2026-11-09. Hướng của rev 17 đã được chủ dự án duyệt ngày 2026-11-10. Rev 22 gồm cả các thay đổi tích lũy của rev 16 tới rev 21.
- **Quy trình:** superpowers:brainstorming, nhánh kiến trúc.
  - Các phần thiết kế 1–12 đã được duyệt lần lượt trong hội thoại ngày 2026-10-29/30.
  - Rev 2 xử lý review `docs/reviews/2026-10-30-system-design-review.md` (SB2-S01…S18) và thêm Q17–Q19.
  - Rev 3 xử lý review `docs/reviews/2026-10-30-system-design-rev2-review.md` (SB2-R2-01…R2-15), chốt lại Q18 và thêm Q20.
  - Rev 4 xử lý review `docs/reviews/2026-10-30-system-design-rev3-review.md`: hai yêu cầu SB2-R3-01, R3-02, và các nghĩa vụ A–C cùng checklist cho plan SP1.
  - Rev 5 thêm sổ bàn giao giữa các harness (Q21, mục 7.4) theo thiết kế chủ dự án duyệt trong hội thoại ngày 2026-11-09. Rev 5 chỉ đổi tài liệu: `schemas/mcp-tools-v2.json` và code được cập nhật ở task đầu của SP2.
  - Rev 6 xử lý review `docs/reviews/2026-11-09-system-design-rev5-review.md` (SB2-R5-01…R5-09). Rev 6 cũng chỉ đổi tài liệu.
  - Rev 7 xử lý review `docs/reviews/2026-11-09-system-design-rev6-review.md`. Rev 7 bỏ cơ chế xác nhận bằng khớp câu chữ theo quyết định của chủ dự án ngày 2026-11-09, và cũng chỉ đổi tài liệu.
  - Rev 8 xử lý review `docs/reviews/2026-11-09-system-design-rev7-review.md`, và cũng chỉ đổi tài liệu.
  - Rev 9 xử lý review `docs/reviews/2026-11-09-system-design-rev8-review.md`, và cũng chỉ đổi tài liệu.
  - Rev 10 xử lý review `docs/reviews/2026-11-09-system-design-rev9-review.md`, và cũng chỉ đổi tài liệu.
  - Rev 16 bổ sung ref bất biến qua restore cho sổ bàn giao, theo phát hiện trong các vòng review SP8 đã hủy, và cũng chỉ đổi tài liệu.
  - Rev 17 đưa vòng skill vào làm trung tâm cùng sổ bàn giao (Q22–Q24, mục 8.6–8.11), theo đề xuất `2026-11-10-skill-loop-direction-design.md` mà chủ dự án duyệt hướng ngày 2026-11-10. Rev 17 chỉ đổi tài liệu và không đổi nội dung SP1; thay đổi contract áp dụng ở task đầu của SP3.
  - Rev 18 xử lý review `docs/reviews/2026-11-10-system-design-rev17-review.md` (SB2-R17-01…R17-13), và cũng chỉ đổi tài liệu. Khác với rev 17, rev 18 thêm yêu cầu cho **SP1 đợt 3** (R17-01, R17-02, R17-07, R17-11). SP1 đợt 2 không đổi.
  - Rev 19 xử lý review `docs/reviews/2026-11-10-system-design-rev18-review.md` (SB2-R18-01…R18-08), và cũng chỉ đổi tài liệu. Review đó xác nhận R17-01, 05, 08, 11 và 12 đã đóng ở mức đặc tả; tám mục còn lại được sửa tiếp ở rev 19.
  - Rev 20 bỏ đường cài skill gốc theo quyết định của chủ dự án ngày 2026-11-10 (Q25): skill chỉ được phân phối qua MCP. Rev 20 chỉ đổi tài liệu, và chỉ gỡ bớt nội dung so với rev 19.
  - Rev 21 xử lý review `docs/reviews/2026-11-10-system-design-rev20-review.md` (SB2-R20-01…R20-07), và cũng chỉ đổi tài liệu. Review đó xác nhận R18-03 đã đóng theo Q25 và R18-04 đã đóng.
  - Rev 22 xử lý bốn mục trong `docs/reviews/2026-11-10-system-design-rev21-review.md` (SB2-R21-01…R21-04) ở mức đặc tả.
  - Mục 21 ánh xạ các phát hiện từ review và từng thay đổi của rev 5, rev 16 và rev 17 tới chỗ đã sửa.
- **Thay thế:** mọi tài liệu thiết kế của repo cũ `D:\ensemble-agents\Super-brain`. Tài liệu cũ chỉ còn là tham chiếu (xem mục 16).

---

## 1. Mục tiêu

Super-brain2 là một "bộ não" chạy cục bộ, kết nối nhiều coding harness vào **một kho tri thức chung** qua MCP. Hai sản phẩm chính dùng chung một nền: **vòng skill** (Q22) và **sổ bàn giao** (Q21).

1. **Tự rút skill từ công việc thật và dùng lại.** Sau task, agent rút ra skill, tức quy trình làm một loại việc. Harness khác và dự án khác dùng lại, vá và cải tiến skill đó (mục 8.6–8.11). Bài học có bằng chứng được gắn vào skill hoặc đứng riêng (mục 8.1–8.5). Nhờ vậy các harness làm tốt hơn qua từng phiên.
2. **Có sẵn tri thức từ ngày đầu.** Danh mục agency-agents cộng các skill cấp user đang có trên máy chủ dự án được nhập vào cùng kho skill. Đây là nguồn nhập, không phải trọng tâm.
3. **Chọn nhanh và đúng.** Brain lọc tại máy và trả một danh sách ngắn; model của harness quyết định nạp mục nào. Jev (mô hình System One của TypeSafe) là bộ chọn tùy chọn (Q1, mục 9).
4. **Đo được bằng chứng.** "Thông minh hơn" phải được đo bằng tín hiệu thụ động và holdout ngẫu nhiên, không tự tuyên bố.
5. **Chạy trên Windows, macOS và Linux** (Q19). Về sau có thể chia sẻ cho nhiều người dùng.
6. **Bàn giao không đổi hướng** (Q21). Một harness dừng giữa chừng, kể cả đột ngột vì hết quota, thì harness khác làm tiếp được mà giữ nguyên mục tiêu, kế hoạch và các quyết định đã có.

### Ngoài phạm vi

- Không thay thế agent runtime: brain không sinh code, không chạy vòng lặp agent, không tự sửa file dự án.
- Không chạy Probe kiểu harness2: brain không chạy lại task và không để agent nền sửa file dự án. Ngoại lệ duy nhất là lượt rà soát chỉ-đọc sau phiên (Q23, mục 8.10).
- Chưa đồng bộ nhiều máy, chưa có nhiều người dùng.
  - Danh tính (`owner_id`, principal, người ký) và versioning của schema được chừa chỗ mở rộng để **giảm** thay đổi phá vỡ khi thêm hai việc này. Spec không hứa sẽ không cần migration.
- Không nhập dữ liệu `brain.db` của repo cũ. Migration schema của chính Super-brain2 vẫn nằm trong phạm vi (mục 5.8).
- Chưa đóng gói phát hành (PyPI, Docker, Smithery). Việc public mã nguồn và gói skill lên GitHub được chuẩn bị theo Q24.

## 2. Các quyết định đã chốt

| # | Chủ đề | Quyết định |
|---|---|---|
| Q1 | Bộ chọn | Mặc định: brain lọc tại máy, model của harness quyết định nạp. Jev là bộ chọn tùy chọn, mặc định tắt, chỉ bật khi phép so sánh offline cho thấy nó hơn bộ lọc tại máy (mục 9). Luôn chạy được khi offline |
| Q2 | Ngân sách Jev | Người dùng tự đặt; **mặc định không có trần**. Chi phí luôn được ghi lại |
| Q3 | Tài liệu | Viết tổng hợp lại từ các nguồn và mục tiêu; tài liệu cũ chỉ để tham chiếu |
| Q4 | Harness | 5 harness: Codex (app desktop), Claude Code, Antigravity, OpenCode, Cursor (hoãn tới khi được cài) |
| Q5 | Jev-Mem | Bỏ hẳn |
| Q6 | Tri thức có sẵn | agency-agents cộng khoảng 70 skill cấp user trên máy. Gộp bản trùng, ghi nguồn gốc và license. Không lấy skill trong plugin cache |
| Q7 | Đo "thông minh hơn" | Chỉ số dùng lại skill và tín hiệu thụ động trước (mục 12.1). Holdout ngẫu nhiên giữ schema ghi nhận; báo cáo nhân quả hoãn tới khi có nhiều người dùng (mục 12.2) |
| Q8 | Triển khai | Một người, một máy, một kho. Nhiều máy và nhóm sẽ làm sau (Q19) |
| Q9 | Tự cải tiến | Phân tầng: skill thuần văn bản do agent viết có hiệu lực ngay trong repo gốc qua `prepare_task`, có nhãn (Q22); bài học đứng riêng đã kiểm chứng tự kích hoạt sau Conflict Review; thăng hạng skill ra ngoài repo gốc và mọi thay đổi file cấu hình harness phải chờ duyệt (Q18); có phiên bản và rollback |
| Q10 | Capture | Sự kiện có cấu trúc cộng nội dung hội thoại đã lọc. **Kho chính nằm trên máy; dữ liệu đi ra ngoài (tới Jev khi bật, và tới harness trong lượt rà soát sau phiên) được kiểm soát theo allowlist.** Lọc trước khi ghi đĩa, có thời hạn lưu. Năm cờ policy theo repo (mục 14.2) |
| Q11 | harness2 | Chỉ lấy ý tưởng; không chạy probe. Lượt rà soát sau phiên (Q23) chỉ đọc và không phải probe |
| Q12 | Phạm vi bài học và skill | Bài học, và skill đã thăng hạng lên phạm vi `owner` (mục 8.7), được chia sẻ giữa mọi repo của cùng một `owner_id`. Lọc ứng viên tại máy. Chỉ nội dung bài học và skill được chia sẻ; evidence thô, continuity và context nguồn không đi theo sang repo khác |
| Q13 | Cách xây | Hướng B: viết theo spec. Tầng thấp trích xuất từ repo cũ kèm test; tầng domain/application viết mới bằng TDD |
| Q14 | Ai viết câu chữ skill, bài học và sổ bàn giao | Agent đang làm việc viết qua `submit_episode`; brain chỉ xác minh. Skill và bản vá skill viết ở ba thời điểm (mục 8.9); lượt rà soát sau phiên soạn thay khi agent chưa viết (mục 8.10). Bài học viết khi đã đủ chất liệu, chậm nhất ở cuối phiên. Sổ bàn giao viết **liên tục trong phiên** (mục 7.4), vì phiên có thể dừng mà không kịp viết gì thêm. Phiên nào agent không gửi thì dùng mẫu trích xuất |
| Q15 | Thời hạn lưu sự kiện thô | Mặc định 90 ngày, chỉnh được |
| Q16 | Tự chẩn đoán | Lệnh `brain doctor` cộng `get_health(deep=true)`; daemon tự chạy khi khởi động và mỗi ngày |
| Q17 | Contract | Phát hành `mcp-tools-v2`: giữ 8 tên tool; schema canonical pin trong repo kèm fixtures request/response/error. Không làm adapter v1 |
| Q18 | Cổng duyệt | Ba lớp (mục 11.3): rule văn bản trong harness; quyền `ask` của harness; brain tự xác minh. Rủi ro thấp: terminal (chỉ khi lớp 2 đã được xác minh). Rủi ro cao: passkey có user verification, **hoặc chữ ký SSH bằng bất kỳ khóa nào**. Mỗi approval ghi mức bảo đảm; khóa SSH thường được ghi là `key_authorization`. Bản review/apply tối thiểu nằm trong SP1 |
| Q19 | Hệ điều hành | Đa OS ngay từ SP1 (Windows, macOS, Linux, chạy trong CI). Nhiều người dùng làm sau |
| Q20 | Thử trước khi đề xuất | Skill thuần văn bản được dùng ở kênh động trong repo gốc trước khi thăng hạng (Q22). Skill có script không thuộc kênh tĩnh: nó chỉ đổi trạng thái trong kho qua `skill_activate` ở mức rủi ro cao, rồi được cấp qua MCP (Q25, mục 8.6). Các thay đổi kênh tĩnh (c1, c2, c5, c7, c8) không có bước thử và đi thẳng tới cổng duyệt |
| Q21 | Bàn giao giữa harness | Agent ghi sổ bàn giao liên tục, worker ghép phần quan sát được (mục 7.4). Harness nhận việc được đổi quyết định cũ khi có bằng chứng mới, phải ghi quyết định thay thế kèm lý do và báo người dùng. Ràng buộc do người dùng đặt thì harness phải hỏi trực tiếp. Phiên nghe trực tiếp được làm theo trong phiên đó; sổ chỉ ghi đề xuất, ràng buộc cũ không đổi, và phiên khác muốn dựa vào đề xuất thì phải hỏi lại. Chỉ giữ được những gì đã viết ra; suy luận nội bộ của model không chuyển được |
| Q22 | Vòng skill | Skill là đơn vị tri thức thủ tục. Agent viết và vá skill. Ba phạm vi `project`, `owner`, `public`: ghi tự do ở `project`, duyệt khi thăng hạng. Không ghi đè mà thêm phiên bản hoặc biến thể; mỗi repo ghim bản của mình (mục 8.6–8.9, 8.11) |
| Q23 | Rà soát sau phiên | Khi agent chưa ghi skill, daemon chạy chính harness đó ở chế độ không giao diện để soạn. Chỉ đọc, có trần, có cờ policy theo repo (mục 8.10) |
| Q24 | Chuẩn bị public | Hiện một người, một máy Windows. Dự án sẽ public lên GitHub cho nhiều người dùng và đóng góp, nên giữ thiết kế nhiều người dùng và đa OS (Q8, Q19 không đổi). Gói skill công khai xuất từ phạm vi `owner`. Phần nào của SP1 được hoãn nghiệm thu là việc còn mở O12, chưa quyết ở rev 17 |
| Q25 | Phân phối skill | Skill chỉ được phân phối qua MCP. Brain không ghi skill vào thư mục skill của harness. Đường cài gốc của rev 17 đến rev 19 bị bỏ: nó đòi harness có cổng nạp kiểm pin và quarantine trước mỗi lần nạp, mà chưa harness nào được biết là có (mục 8.11). Q25 nói về đường cấp skill cho harness đang làm việc; xuất gói công khai có cổng riêng (mục 8.7). Chủ dự án quyết ngày 2026-11-10 |

## 3. Các nguồn và phần lấy từ mỗi nguồn

Revision dưới đây là HEAD tại thời điểm khảo sát (2026-10-29). Đây là mốc nghiên cứu, không tự động cập nhật theo upstream.

| Nguồn | Revision | Giấy phép | Lấy gì | Không lấy |
|---|---|---|---|---|
| shared-agent-brain (local, thuộc chủ dự án) | `6d2d364` (working tree có 20 file thay đổi chưa commit; chỉ dùng nội dung đã commit) | Của chủ dự án | Tên 8 tool và ý tưởng contract, danh tính và namespace, ledger/CAS, tách evidence khỏi tự báo cáo, các bước lựa chọn → delivery → áp dụng → kết quả | Học có ngân sách provider, owned fixture campaign, chuẩn hóa Hermes |
| [OpenViking](https://github.com/volcengine/OpenViking) | `ba344c5` | AGPL-3.0 | Ý tưởng phân tầng L0/L1/L2 và hạ cấp theo ngân sách | **Không copy code** (vì AGPL), không dùng runtime |
| [Hindsight](https://github.com/vectorize-io/hindsight) | `82109477` | MIT | Retain/recall/reflect, bộ ba world/experience/belief, nguồn gốc, lặp lại không phải bằng chứng | PostgreSQL, pgvector, ML nặng |
| [agency-agents](https://github.com/msitarzewski/agency-agents) | `b37b5bb` | MIT | Danh mục persona/skill (nhập làm tri thức có sẵn), checklist chuyển thành finishing gates | Nạp hàng trăm persona vào mọi prompt |
| [claude-mem](https://github.com/thedotmack/claude-mem) | `d7c2da3` | Apache-2.0 (có NOTICE) | Hook → chuẩn hóa → lọc privacy → hàng đợi bền → tóm tắt và nạp lại phiên | Bun, Chroma, ingest mặc định toàn bộ transcript |
| [harness2](https://github.com/google-research/harness2) | `1cfe254` | Apache-2.0 | Mô hình 8 thành phần, thư viện kinh nghiệm, rút kinh nghiệm sau task, đánh giá so sánh không cần đáp án, nguyên tắc "được chọn không chứng minh có ích" | Vòng Propose–Probe–Compose chạy agent (mỗi task tốn 4k rollout và 3k phiên cải tiến); giám khảo LLM tự quyết định áp dụng |
| [Jev / TypeSafe](https://docs.typesafe.ai) | model `jev-1.14.0` | Dịch vụ thương mại | API System One (Choice/Score/Noul), mẫu "skill suggestion", confidence gating | – |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | Tài liệu chính thức đọc ngày 2026-11-10; chưa ghim commit | MIT | Vòng tạo skill sau task, ba thời điểm ghi, cấu trúc `SKILL.md` bốn phần, vá skill khi dùng, rà soát sau phiên, nạp theo cấp | Runtime agent; ghi skill không qua lọc và không có nhãn nguồn; **không copy code** |

**Ghi chú về Jev:**
- Jev là dịch vụ hosted, không có bản chạy local.
- Giá $0,042 cho mỗi triệu token input; token output miễn phí.
- Context 64k token mỗi request, 32k mỗi câu hỏi.
- Lỗi 429/529 cần retry với backoff.
- Trong cookbook skill suggestion, TypeSafe tự báo tỷ lệ chọn sai giảm từ 16,8% xuống 7,3%. Đây là số liệu của nhà cung cấp, **không phải cam kết cho dự án này**.

**Ghi chú về harness2 và cổng duyệt:** harness2 không có người duyệt. Giám khảo LLM chọn giữa các bản harness đã chạy thử thật (Probe), và mọi thay đổi chỉ nằm trong thư mục thí nghiệm. Super-brain2 không có Probe (Q11) và ghi vào cấu hình thật của harness, nên thay bằng cổng duyệt của người dùng (Q9, Q18).

## 4. Kiến trúc tổng thể

```
 Claude Code   Codex   Antigravity   OpenCode   (Cursor)
      │          │          │            │
      ├─ MCP stdio shim (mỗi harness một credential) ┐
      └─ hook / đọc transcript (có outbox cục bộ) ───┤        brain CLI
                                                     ▼            │
                              loopback HTTP + credential ◄────────┘
 ┌──────────────────── Brain daemon (1 tiến trình / data root) ─────────┐
 │ interfaces: mcp/ · cli_api/ · review_web/ · workers/                  │
 │ application/  use case của 8 tool, review/apply, doctor, maintenance  │
 │ domain/       capture · continuity · skills · lessons · catalog ·     │
 │               selection · context · improvement · measurement         │
 │ ports/        Protocol cho storage, policy store, Jev, filesystem,    │
 │               durable_publish, clock, OS                              │
 │ storage/      SQLite WAL · CAS sha256 · ledger · policy store         │
 │ adapters/     jev · harness config · os (khóa, đường dẫn, quyền, fsync)│
 │ core/         types, ID, validation, config, lỗi có mã                │
 │ composition   nơi duy nhất ráp storage/adapters vào application       │
 └───────────────────────────────────────────────────────────────────────┘
        ▲ lời gọi ra ngoài: Jev API khi bật (qua adapter, theo allowlist);
          lượt rà soát sau phiên gọi harness (mục 8.10)
```

### 4.1 Nguyên tắc

1. **Mỗi data root có đúng một daemon giữ quyền ghi** (mục 5.5).
   - Mỗi harness chạy một shim stdio. Shim mang credential của harness đó và chuyển tiếp request tới daemon qua loopback HTTP.
   - CLI cũng đi qua daemon, không ghi thẳng vào DB.
2. **Capture không làm harness bị treo.** Hook có ngân sách thời gian; lỗi không bao giờ làm harness dừng (mục 7.1).
3. **Việc nặng chạy trong worker nền**, để tool MCP trả lời trong deadline.
4. **Không giữ write transaction khi đang gọi mạng.**
5. **Thiếu bằng chứng thì từ chối (fail closed),** không âm thầm hạ cấp: phiên bản lạ, lớp 2 chưa xác minh, policy không đọc được.

### 4.2 Ma trận phụ thuộc

Một package chỉ được import các package ghi trong cột "được import". Luật được kiểm tra bằng import-linter **và** test AST quét cả import nằm trong hàm.

| Package | Được import |
|---|---|
| `core` | (thư viện chuẩn và thư viện bên thứ ba đã duyệt) |
| `ports` | `core` |
| `storage` | `ports`, `core` |
| `adapters.*` | `ports`, `core` |
| `domain.*` | `ports`, `core`, và các `domain.*` khác theo danh sách cho phép |
| `application` | `domain.*`, `ports`, `core` |
| `mcp`, `cli_api`, `review_web`, `workers` | `application`, `core` |
| `cli` (tiến trình riêng) | `core` và client HTTP; không import `storage`/`domain` |
| `composition` | tất cả; không package nào import ngược lại nó |

Mỗi package được phân công cho một dự án con (mục 15). Một dự án con có thể sở hữu nhiều package.

### 4.3 Đa hệ điều hành (Q19)

- Python ≥ 3.11. CI chạy ma trận {Windows, macOS, Linux} × {3.11, bản ổn định mới nhất}.
- Mọi chỗ phụ thuộc OS đi qua `adapters.os`:
  - **Thư mục dữ liệu:** Windows `%LOCALAPPDATA%\ensemble-brain`, macOS `~/Library/Application Support/ensemble-brain`, Linux `$XDG_DATA_HOME/ensemble-brain`. Ghi đè được bằng biến môi trường.
  - **Khóa độc quyền:** `LockFileEx` trên Windows, `fcntl.flock` trên Unix.
  - **Quyền truy cập file:** mục 5.9.
  - **Làm bền dữ liệu:** mục 5.4.
  - **Tự khởi động daemon:** tự khởi động lúc đăng nhập là tùy chọn, chốt trong plan SP1 (O7). Cơ chế "shim khởi động daemon khi cần" **chưa đủ** để bảo đảm daemon chạy ngoài sandbox của harness (xem chính sách bên dưới).
- **Chính sách daemon, data root và sandbox của harness** (chủ dự án xác nhận ngày 2026-10-31):
  - Daemon chạy bằng tài khoản user thông thường, dùng **một data root chung đã xác minh**.
  - Daemon tự quyết định data root dựa trên cấu hình đã được xác nhận. Không có harness nào chọn data root theo môi trường riêng của nó.
  - Mọi shim kết nối tới đúng daemon và đúng `store_id`. Không kết nối được thì shim báo lỗi rõ ràng, **không tự tạo kho riêng** theo môi trường của harness.
  - Giữ nguyên nhóm SID tin cậy ở mục 5.9. Chưa có allowlist bổ sung.
  - Môi trường nghiệm thu phải được kiểm tra trên thực tế: token của tiến trình, đường dẫn vật lý và ACL thật của data root cùng các thư mục cha. Việc chạy trong một terminal user thông thường không tự chứng minh môi trường đạt yêu cầu.
  - Đợt 2 của SP1 phải giải quyết cơ chế khởi động daemon bên ngoài sandbox. Đợt này cũng phải thử kết nối shim → daemon trên từng harness thật, rồi mới xác định cấu hình cần thiết (ví dụ loopback exemption). Không mặc định một cấu hình nào là bắt buộc trước khi thử.
- Đường dẫn trong dữ liệu lưu dạng chuẩn hóa: dấu `/`, phân biệt hoa thường theo filesystem thực tế.
- **CI đa OS chỉ chứng minh code chạy đúng trên ba OS.** Nó không chứng minh khả năng native của từng harness trên từng OS, cũng không chứng minh độ bền khi mất điện trên mọi filesystem. Các claim này có gate riêng (mục 17).

## 5. Danh tính, bản ghi và lưu trữ

### 5.1 Principal và quyền

- **Principal** là danh tính truy cập, gắn với một credential. Mỗi credential cấp cho một cặp (harness, máy) của một owner.
- Daemon **suy** `owner_id`, `harness_id`, `machine_id` từ credential. Payload khai owner/harness khác với principal thì bị từ chối (`identity_mismatch`), kể cả khi truy cập trực tiếp bằng ref của artifact, job hay context.
- Tác nhân hệ thống có danh tính riêng: `system:doctor`, `system:worker:<tên>`, `system:catalog-import`, `user:cli`. Bản ghi của tác nhân hệ thống không bịa `session_ref`; trường này để trống.
- Thu hồi credential: `brain credential revoke`, là hành động cần duyệt (mục 11.3). Request dùng credential đã thu hồi bị từ chối ngay.

### 5.2 Repo, checkout và snapshot

Ba khái niệm tách biệt:

| Khái niệm | Ý nghĩa |
|---|---|
| `repo_id` | Repo logic. UUIDv7 cấp khi đăng ký lần đầu. Remote git đã chuẩn hóa và đường dẫn chỉ là **locator** trỏ tới repo, không phải ID |
| `checkout_id` | Một thư mục làm việc cụ thể trên một máy (một worktree là một checkout). Hai worktree cùng remote là hai checkout của cùng một repo |
| `source_snapshot` | Trạng thái nội dung: commit git cộng digest các thay đổi chưa commit, hoặc digest nội dung nếu không có git |

Quy tắc:
- Remote khớp locator của repo đã có → dùng `repo_id` đó, thêm checkout mới.
- Repo không có remote bị chuyển thư mục → tạo checkout mới. Hai checkout được nối lại khi người dùng chạy `brain workspace link`. Không bao giờ âm thầm đổi `repo_id`.
- Thêm hoặc đổi remote → thêm locator; repo cũ giữ nguyên.
- Continuity gắn với **checkout** (công việc dở dang nằm trên một thư mục cụ thể). Bài học, skill phạm vi `project` và thống kê gắn với **repo**.
- Trong tài liệu, "workspace" nghĩa là repo; `workspace_id` trong contract v2 chính là `repo_id`.

### 5.3 Các loại bản ghi

Mọi bản ghi mang `owner_id`, `actor` (principal hoặc tác nhân hệ thống) và nếu có thì `repo_id`, `checkout_id`, `harness_id`, `session_ref` (định danh đã chuẩn hóa, không phải `session_id` gốc của harness, mục 7.4), `machine_id`. ID dùng UUIDv7.

| Bản ghi | Nội dung chính | Tạo bởi |
|---|---|---|
| Event | Sự kiện hook/transcript đã lọc; `producer_stream` + `sequence`; payload (mọi kích thước) nằm trong CAS | capture |
| CaptureGap | Khoảng sự kiện bị mất: lý do, khoảng thời gian, số lượng ước tính; không chứa nội dung | capture, outbox |
| Evidence | Bằng chứng có kiểu (lần chạy lệnh, exit code, digest output, diff); `source` do server gán theo kênh nhận (mục 8.2) | capture, `submit_episode`, CLI |
| Episode | Một task (hoặc một phần task) kèm các evidence; trạng thái `open`, `checkpointed`, `closed` | `submit_episode`, capture |
| Handoff | Sổ bàn giao của một task trên một checkout, có revision; gồm hai ref bất biến tới phần agent khai và phần quan sát (mục 7.4). Phần agent khai nằm trong CAS; phần quan sát chỉ chứa ref tới Event nguồn | `submit_episode`, worker capture |
| Lesson | Bài học có phiên bản: nội dung, `kind ∈ {world, experience, belief}`, `claim_type ∈ {technical, preference}`, điều kiện áp dụng, nguồn gốc (lineage), trạng thái (mục 8.3), proof lineage | reflection |
| Artifact | Skill, persona, rule… gắn `component ∈ {c1..c8}`. Có revision; nội dung và **toàn bộ resource đi kèm** nằm trong CAS; ghi nguồn gốc và license | catalog, improvement |
| Skill | Một Artifact `component=c6` có thêm: phạm vi (`project`, `owner`, `public`), nhóm skill và biến thể, nhãn nguồn, lineage, trạng thái (mục 8.6–8.8). Mỗi phiên bản có ref bất biến `(skill_id, revision_epoch, revision, digest)` (mục 8.8) | `submit_episode`, rà soát sau phiên, catalog |
| SkillPin | Phiên bản và biến thể mà một repo đang ghim cho một nhóm skill (mục 8.8) | `submit_episode`, review |
| SkillUsage | Hồ sơ dùng của một phiên bản skill: Delivery, ServedReceipt/ReadAck, Outcome, harness, OS, repo (mục 8.8) | `prepare_task`, `get_artifact`, measurement |
| ChangeProposal | Diff, lý do, evidence, mức rủi ro do server xếp, các file đích kèm digest bản gốc, trạng thái duyệt, con trỏ rollback | improvement, bootstrap |
| ApplyJournal | Trạng thái apply của một proposal và của từng file đích (mục 11.2) | apply |
| ApprovalReceipt | Approval message chuẩn (mục 11.3), người ký, kênh, mức bảo đảm | cổng duyệt |
| Delivery | Những gì đã chọn và trả cho một lần `prepare_task`, kèm holdout assignment | `prepare_task` |
| ServedReceipt | Server đã gửi artifact nào, revision nào, digest từng resource, cho principal/task nào | `get_artifact` |
| ReadAck | Client xác nhận đã nhận đủ bytes của một ServedReceipt, khớp digest | `record_outcome`, `submit_episode` |
| SelectionTrace | Ứng viên (chỉ ID cho mục local-only), câu trả lời/xác suất của Jev, lý do chuyển sang rules, độ trễ, chi phí, phiên bản policy | selection |
| Outcome | Kết quả, nguồn (`declared`, `observed`, `inferred`), độ đầy đủ quan sát, cửa sổ quan sát | `record_outcome`, measurement |
| Job | Việc nền: trạng thái, lease, số lần thử, kết quả, trạng thái accounting (mục 6.4) | `request_improvement`, hệ thống |
| ProviderInvocation | Một lời gọi ra ngoài (Jev, hoặc harness trong lượt rà soát sau phiên, mục 8.10): invocation ID, phần giữ chỗ, usage thực, chi phí (hoặc `unknown`), kết quả (`ok`, `failed`, `outcome_unknown`) | adapter Jev |
| NativeHostReceipt | Bằng chứng một host thật đã gọi shim (mục 17.3) | shim, adapter |
| DoctorRun | Kết quả từng mục kiểm tra của `doctor` | doctor |

**Policy store** (mục 5.7) giữ riêng các bản ghi bảo mật: credential và trạng thái thu hồi, người ký, danh sách quarantine, tombstone, policy theo repo, nonce của approval, `trust_generation`, trạng thái lớp 2, recovery grant và trạng thái của nó (mục 11.2), tầng accounting của lời gọi ra ngoài (mục 5.7), và hồ sơ xuất gói công khai (mục 8.7).

**Ledger không chứa nội dung có thời hạn lưu.** Ledger bất biến chỉ giữ metadata, ID và ref. Mọi payload thuộc lớp có thời hạn lưu (Event, Evidence, nội dung `manual_submission`) đều nằm trong CAS, bất kể kích thước, để hết hạn và quarantine có hiệu lực mà không phải sửa ledger.

### 5.4 Commit, ACK, độ bền và replay

- **Một transaction SQLite** gồm: ledger append, cập nhật projection (bảng trạng thái hiện tại), bản ghi idempotency và kết quả trả về. Hoặc tất cả cùng commit, hoặc không gì cả.
- **Trạng thái bảo mật đi trước.** Hành động thay đổi trạng thái bảo mật (thu hồi, quarantine, tombstone, đổi policy) ghi vào policy store **trước**, dưới dạng một intent có ID, rồi mới áp vào kho dữ liệu.
  - Việc áp vào kho được khóa theo intent ID, nên chạy lại bao nhiêu lần cũng chỉ có một hiệu lực.
  - Crash ở giữa thì nội dung đã bị chặn, và việc áp vào kho chạy lại khi khởi động.
  - Phục hồi chỉ hoàn tất đúng intent đã được cho phép, không tạo thêm authority hay mutation nào khác.
  - Trạng thái hiệu lực, hướng thao tác và kết thúc của recovery grant (mục 11.2) cũng là trạng thái bảo mật: ghi vào policy store trước, rồi mới chiếu sang kho chính.
  - **Ngoại lệ có chủ ý:** danh sách hết hạn, dấu mất pin và dấu rà soát mà restore chuẩn bị được ghi bền cùng snapshot **đang dựng**. Chúng chỉ có hiệu lực khi snapshot được công bố (mục 5.7).
- **SQLite:** WAL với `synchronous=FULL`; trên macOS bật thêm `PRAGMA fullfsync=ON` và `checkpoint_fullfsync=ON`.
- **Đưa blob vào CAS** qua port `durable_publish`:

  | Bước | Việc |
  |---|---|
  | 1 | Ghi vào thư mục staging |
  | 2 | Làm bền nội dung file: `fsync` trên Linux, `F_FULLFSYNC` trên macOS, `FlushFileBuffers` trên Windows |
  | 3 | Kiểm tra sha256 |
  | 4 | Đổi tên nguyên tử vào `cas/`. Trên Windows dùng `MoveFileEx` với `MOVEFILE_WRITE_THROUGH` |
  | 5 | Làm bền thư mục đích: `fsync` thư mục trên Linux, `F_FULLFSYNC` trên macOS |
  | 6 | Transaction DB ghi ref |

  Ref chỉ được trả về sau bước 6. Blob mồ côi (có trong CAS nhưng không có ref) bị dọn sau một thời gian chờ, bằng job bảo trì.
- **Mức độ bền được công bố**, do `adapters.os` xác định và `doctor` báo cáo:
  - `power_loss_durable`: OS và filesystem hỗ trợ đủ các bước trên. Dữ liệu đã ACK không mất khi tiến trình chết hoặc mất điện, miễn là ổ đĩa tôn trọng lệnh flush (RPO = 0).
  - `process_crash_durable`: ví dụ filesystem mạng, hoặc thiếu một bước. Dữ liệu đã ACK chỉ được bảo đảm khi tiến trình chết. `doctor` báo WARN.
- **Ledger:** mỗi dòng có `sequence` tăng dần, `schema_version`, `handler_version`, `writer_epoch`.
- **Replay:**
  - Dựng projection vào bảng mới, kiểm tra, rồi mới hoán đổi.
  - Replay không gọi Jev, không tạo job hay chi phí mới: side effect chỉ phát sinh từ bản ghi Job và ProviderInvocation, vốn đã nằm trong ledger.
  - Replay tôn trọng tombstone và quarantine trong policy store (mục 5.6).
  - Gặp `handler_version` không biết thì dừng replay và báo lỗi, không đoán (mục 5.8).
- **Bảng điểm crash** là deliverable của plan SP1.
  - Bảng phủ: DB chính, policy store, khoảng giữa commit policy store và commit kho, CAS publish, lease chặn GC của backup, hoán đổi `store/`, ApplyJournal.
  - Bảng nêu trạng thái trước/sau từng bước, ACK và retry, **tách riêng tiến trình chết và mất điện**.
  - Fault-injection test (kill tiến trình) chứng minh trường hợp tiến trình chết.
  - Trường hợp mất điện dựa trên ngữ nghĩa đã công bố của OS. Test kill tiến trình không được coi là bằng chứng cho mất điện.

### 5.5 Một chủ ghi

**Bố cục data root:**

```
<data root>/
  writer.lock        khóa ghi; không bao giờ bị hoán đổi
  policy/            policy store (SQLite riêng); không bị restore kho dữ liệu thay thế
  store/             DB chính + CAS; là đơn vị hoán đổi khi restore/migrate
  outbox/, logs/, backups/
```

- **Quyền ghi** = giữ khóa độc quyền của OS trên `writer.lock` suốt đời tiến trình.
  - OS tự nhả khóa khi tiến trình chết. Vì vậy không dùng PID hay timeout để đoán tiến trình đã chết.
  - Mỗi lần lấy được khóa, `writer_epoch` tăng 1 và được ghi vào ledger.
- **Hai shim cùng khởi động daemon:** tiến trình nào lấy được khóa thì làm daemon; tiến trình còn lại thoát và kết nối tới daemon đó.
- **Thao tác bảo trì** (migrate, rebuild, restore, `--fix` có ghi):
  - Chạy trong chế độ bảo trì của daemon, hoặc bằng lệnh offline giữ cùng khóa đó.
  - Giữ khóa **liên tục** qua mọi bước: đóng DB, hoán đổi `store/`, mở lại DB/CAS/endpoint.
  - Tăng `writer_epoch` sau khi xong.
  - Không bao giờ chạy song song với writer đang hoạt động.
- **Tắt daemon:** ngừng nhận việc mới, hoàn tất hoặc hủy việc đang chạy theo chính sách của từng loại, để hàng đợi bền lại cho lần chạy sau.

### 5.6 Thời hạn lưu, tham chiếu CAS, tombstone và quarantine

**Tham chiếu CAS.** Mỗi blob có danh sách holder: (loại bản ghi, ID, lớp thời hạn lưu). Một blob có thể được nhiều holder dùng chung, vì cùng nội dung thì cùng digest.

| Dữ liệu | Thời hạn mặc định | Khi hết hạn |
|---|---|---|
| Payload của Event | 90 ngày (Q15) | Bỏ holder của Event, ghi tombstone; giữ metadata (loại, thời gian, ID) |
| Evidence | Còn được bài học, outcome hoặc proposal dẫn tới thì giữ; không thì theo Event | Như Event |
| Sổ bàn giao, phần agent khai và `task_goal` | Holder theo từng revision. Revision còn được bài học, outcome hoặc proposal dẫn tới thì giữ; không thì 90 ngày từ lần agent ghi cuối (Q15). Worker làm mới không gia hạn | Như Event |
| Sổ bàn giao, phần quan sát | Chỉ là ref, không giữ holder trên payload Event nên không gia hạn nguồn. Nội dung theo thời hạn của Event nguồn | Mục đó trả `expired`; giữ ID và digest |
| Bản ghi idempotency | 30 ngày | Xóa; chỉ chứa ID/ref, không chứa nội dung (mục 6.3) |
| Outbox đã ACK | Xóa ngay sau ACK | – |
| Log, trace | 30 ngày | Xoay vòng; log không bao giờ chứa payload thô (mục 14.2) |
| Dead-letter | 30 ngày, chỉ chứa metadata và lý do | – |
| Backup | Giữ N bản gần nhất (mặc định 7) | Xóa bản cũ nhất |
| Bài học, artifact, proposal, receipt | Giữ | – |

- **Hạn gốc theo holder.** Mỗi holder lưu `expires_at` gốc, hoặc điều kiện giữ của nó, ngay trong kho chính. Mọi đường đọc, replay, rebuild và restore đều kiểm hạn này. Holder đã quá hạn không được phục vụ, kể cả khi không có tombstone. Tombstone ghi lại việc đã xử lý; nó không phải nguồn duy nhất cho biết một holder đã hết hạn.
- **Blob dùng chung:** hạn áp theo từng holder. Holder đã hết hạn không đọc được; holder còn hiệu lực vẫn đọc được cùng blob đó.
- **Xóa vật lý** một blob chỉ khi không còn holder nào trong kho đang chạy. Backup tự chứa bản sao blob của nó (mục 5.7), nên GC của kho không ảnh hưởng backup.
- **Tombstone:** replay và rebuild không bao giờ phục sinh holder đã hết hạn.
- **Quarantine theo digest:** chặn **mọi** holder của blob đó. Nội dung bị loại khỏi delivery, index, search, egress và mọi lần retry (mục 6.3). Chỉ xem được bằng `brain quarantine show`. Không xóa âm thầm.

### 5.7 Backup, restore và policy store

- **`brain backup`** tạo thư mục backup **tự chứa**:
  - snapshot DB (SQLite backup API);
  - bản sao của mọi blob mà snapshot tham chiếu;
  - manifest: schema version, ledger high-water mark, danh sách digest.

  Trong lúc chép, backup giữ một lease chặn GC xóa các blob đó.
- **Policy store** được backup riêng. Restore kho dữ liệu **không** thay policy store.
- **`brain restore`** (hành động cần duyệt, rủi ro cao):
  1. khôi phục vào thư mục mới;
  2. kiểm tra snapshot khớp với manifest (DB, mọi blob, digest);
  3. áp lại trạng thái hiện hành của policy store lên bản khôi phục: thu hồi, quarantine, tombstone, policy;
  4. tính hạn gốc của từng holder (mục 5.6) trên bản đang dựng: holder đã quá hạn tại thời điểm restore bị bỏ **trong bản đang dựng**, và danh sách hết hạn được ghi bền **cùng bản đó**. Bước này không ghi gì vào policy store sống;
  5. dựng tập dấu mất pin của bản đang dựng (mục 8.8) và, từ SP4, xử lý các dấu rà soát theo mục 8.10. Các dấu được ghi bền cùng bản đang dựng;
  6. hoán đổi `store/` trong chế độ bảo trì, giữ khóa liên tục (mục 5.5). Đây là điểm công bố snapshot;
  7. sau khi công bố, dưới cùng writer lease và **trước khi phục vụ đọc hoặc nhận Job**: hoàn tất các intent hết hạn của đúng snapshot vào policy store và áp các dấu mất pin, dấu rà soát. Job rà soát bị chặn bởi dấu phải được xử lý theo mục 8.10 trước khi mở lại hàng đợi.

  Không ghi đè bản backup nguồn. Snapshot thiếu blob hoặc sai subject bị từ chối trước khi đụng vào dữ liệu đang dùng.
  - **Crash trước bước 6:** kho cũ mở lại nguyên vẹn. Danh sách hết hạn, dấu mất pin và dấu rà soát của bản chưa công bố bị bỏ cùng bản đó, nên holder còn hiệu lực ở kho sống vẫn đọc được.
  - **Crash sau bước 6, trước khi xong bước 7:** khi khởi động, phục hồi xác định đúng snapshot đã được công bố, hoàn tất bước 7 rồi mới mở lại. Holder quá hạn đã bị bỏ trong bản đó và mọi đường đọc đều kiểm hạn gốc. Dấu rà soát đã đi cùng snapshot, nên Job bị chặn vẫn chưa được phép gọi harness.
  - Nhờ vậy hết hạn đúng với mọi tổ hợp và mọi thứ tự restore (chỉ kho, chỉ policy store, cả hai), kể cả ở lần đọc đầu tiên trước khi job dọn dữ liệu chạy. Với restore chỉ policy store, việc kiểm hạn gốc lúc đọc là cơ chế bảo đảm.
  - ApplyJournal nằm trong bản kho được khôi phục chỉ cung cấp tiến độ và digest để đối chiếu. Quyền tiếp tục hay rollback đọc từ policy store hiện hành (mục 11.2).
- **Accounting không quay lui theo kho dữ liệu.** Reservation, số lượt đã gửi và chi phí đã ghi của mọi lời gọi ra ngoài (Jev, lượt rà soát) nằm ở tầng accounting trong policy store, và được ghi bền **trước** khi gửi. Restore kho chính không đổi chúng.
  - Một lời gọi `outcome_unknown` giữ nguyên reservation của nó cho tới khi đối soát.
  - Restore policy store làm mất bằng chứng về số đã dùng. Khi đó brain chặn lời gọi mới trong phạm vi bị ảnh hưởng (kỳ ngân sách hiện tại, trần ngày hiện tại) cho tới khi chủ dự án đối soát bằng `policy_change`, hoặc tới khi kỳ đó kết thúc. Khóa này là một phần của chính lần restore: nó đã có hiệu lực ở lời gọi đầu tiên sau khi hoán đổi.
- **Restore policy store** là một hành động riêng, rủi ro cao. Trước khi duyệt, brain hiện chính xác trạng thái nào bị quay lui: credential nào sống lại, người ký nào, quarantine nào bị gỡ.
  - Mỗi lần restore policy store, `trust_generation` **tăng lên** so với giá trị lớn nhất từng có. Giá trị này được ghi cả trong `writer.lock`, vốn không bao giờ bị hoán đổi.
  - Approval message mang `trust_generation`. Approval và nonce của thế hệ cũ đều mất hiệu lực, nên chữ ký cũ không thể dùng lại sau restore dù nonce trong snapshot đang ở trạng thái chưa dùng.
  - Mỗi lần restore kho chính, `restore_epoch` được đặt bằng `writer_epoch` của lease đang giữ và ghi vào một file metadata bên trong `store/` đang dựng, **trước** khi hoán đổi, không đụng bytes của `brain.db`. Nó đổi cùng lúc với bản kho trong cùng một lần hoán đổi. `writer_epoch` tăng sau mỗi lần hoán đổi, nên mỗi lần restore có một giá trị riêng.
  - Kho có schema từ SP2 trở lên **luôn có** file này; tạo kho mới hoặc nâng kho cũ lên schema SP2 thì ghi giá trị 0. Thiếu hoặc hỏng ở kho SP2, khi mở kho hay khi phục hồi swap, đều trả `INTEGRITY_FAILURE`. Chỉ kho có schema trước SP2 mới được đọc thiếu thành 0.
  - Backup không chép file này; restore luôn cấp giá trị mới. `writer.lock` không đổi định dạng.
  - Người giữ sổ bàn giao có `restore_epoch` khác giá trị hiện hành không còn hiệu lực (mục 7.4).
  - Bảo đảm này áp dụng cho mọi tổ hợp restore: chỉ kho, chỉ policy store, hay cả hai.

### 5.8 Phiên bản và migration

- Migrate kho mang nguyên `restore_epoch` đã xác minh sang stage và làm bền trước khi đánh dấu stage là sẵn sàng hoán đổi (`READY`, mục 5.7).
- Kho ghi `schema_version` và `min_reader_version`.
  - Binary gặp kho có schema mới hơn mức nó hỗ trợ thì từ chối **trước mọi thao tác ghi**.
  - Chỉ cho chạy `doctor` ở chế độ đọc.
- Handler gặp `handler_version` không biết thì báo lỗi, không đoán.
- **Migration:**
  - giữ khóa độc quyền;
  - bắt buộc tạo backup trước;
  - chạy trên bản sao rồi mới hoán đổi, nên lỗi giữa chừng không làm hỏng kho đang dùng.
- Không hỗ trợ hạ phiên bản; muốn quay lại thì restore backup tạo trước migration.

### 5.9 Bảo vệ dữ liệu trên đĩa

- **Toàn bộ data root** (policy store, DB, WAL/SHM, CAS, staging, outbox, log, backup) chỉ tài khoản owner truy cập được:
  - **Windows:** ACL chỉ cho user hiện tại (cộng SYSTEM khi OS bắt buộc).
  - **Unix:** thư mục `0700`, file `0600`; daemon đặt `umask 077`.
- Khi data root bị ghi đè đường dẫn, hoặc khi xuất backup ra chỗ khác, brain kiểm tra cả thư mục cha. Thư mục cha cho người khác ghi thì từ chối.
  - Mối đe dọa cần chặn là tài khoản OS khác **đổi tên hoặc thay** cây thư mục của brain.
  - **POSIX:** thư mục cha cho người khác ghi nhưng có sticky bit (ví dụ `/tmp`) được chấp nhận, vì sticky bit ngăn người khác đổi tên hay xóa entry không thuộc họ. Chủ dự án xác nhận ngày 2026-10-30.
  - **Windows:** tương đương là không có SID ngoài nhóm tin cậy (user, SYSTEM, Administrators, TrustedInstaller) được cấp `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER` trên thư mục cha, và owner của thư mục cha phải thuộc nhóm tin cậy.
- `doctor` kiểm tra quyền của kho tách riêng với quyền của credential.
- **Phạm vi bảo vệ:** ngăn tài khoản OS khác vô tình đọc được. Không chống tiến trình chạy cùng tài khoản (giới hạn đã công bố ở mục 11.3).

## 6. Contract `mcp-tools-v2` (Q17)

Schema JSON canonical nằm trong repo (`schemas/mcp-tools-v2.json`), kèm fixtures request/response/error. Fixtures chạy round-trip qua shim và daemon trong integration test. Schema này **không** tương thích ngược với `mcp-tools-v1` của shared-agent-brain.

### 6.1 Tám tool

| Tool | Loại | Hành vi |
|---|---|---|
| `prepare_task` | `mode=work` (mặc định): ghi, có idempotency. `mode=discover`: chỉ đọc | `work`: lọc tại máy → Jev chọn nếu bật → áp holdout nếu có → ghi Delivery. Trả về: L0 của 0–N skill kèm phạm vi và nhãn nguồn, 0–K bài học, sổ bàn giao của task khi có `task_id`, ref context, finishing gates, `delivery_id`. `discover`: tìm sổ bàn giao, không tạo task, Delivery hay Job (mục 7.4) |
| `search_knowledge` | Chỉ đọc | FTS5 kết hợp độ mới. Không gọi Jev. Tìm cả skill trong phạm vi được phép; agent gọi trước khi tạo skill mới (mục 8.9) |
| `get_artifact` | Đọc, có ghi audit (ServedReceipt) | Trả nội dung ở cấp L0/L1/L2 kèm revision và digest từng resource, gồm cả sổ bàn giao và skill. Đọc skill luôn chỉ định ref đầy đủ. Gửi thêm `delivery_id` để nạp mục đã đề cử theo pin (mục 8.11) |
| `submit_episode` | Ghi (có idempotency) | Lưu Episode và evidence (`source=agent_reported`); nhận bài học đề xuất do agent viết (Q14); nhận `read_acks`; nhận `handoff` kèm `base_revision` và `takeover` (mục 7.4); nhận `skill_draft`, `skill_patch` hoặc `skill_pin` (mục 8.8, 8.9) |
| `record_outcome` | Ghi (có idempotency) | Kết quả theo `delivery_id`, kèm ref đã áp dụng và `read_acks` |
| `request_improvement` | Ghi (có idempotency), bất đồng bộ | Tạo hoặc trả lại Job theo điều kiện admission. Với rà soát skill, mục 8.10 quy định kết quả khi task đã rà hoặc lịch sử rà không xác minh được |
| `get_job` | Chỉ đọc | Trạng thái và kết quả job |
| `get_health` | Chỉ đọc khi `deep=false`; có thể tạo Job khi `deep=true` | Trạng thái nhanh. `deep=true` trả DoctorRun gần nhất kèm tuổi; quá cũ thì tạo job doctor (mục 13) |

### 6.2 Quy tắc chung

- **Lỗi có kiểu và mã**, ví dụ:
  - `identity_mismatch`, `not_found`, `quarantined`, `revision_conflict`;
  - `idempotency_conflict`, `in_progress`, `commit_outcome_unknown`;
  - `store_busy`, `deadline_exceeded`;
  - `capability_unavailable`, `unsupported_version`.
- Domain chưa được xây trả `capability_unavailable`, không trả success rỗng.
  - Ngoại lệ duy nhất: tool có domain một phần (`prepare_task` ở SP2 chỉ có continuity) được trả success khi phần đang có là thật, và phải liệt kê phần chưa có trong `degraded_codes` (`skills_unavailable`, `lessons_unavailable`, `context_unavailable`, `finishing_gates_unavailable`). Mảng rỗng đi kèm các mã này nghĩa là "chưa có khả năng", không phải "không có gì phù hợp".
  - `prepare_task` thêm mã `skill_review_pending` khi task trước trên checkout có chất liệu mà chưa được rà skill (mục 8.10).
- **Không tool MCP nào tạo được ApprovalReceipt** (mục 11.3).
- Mỗi tool ghi rõ trong schema: đồng bộ hay bất đồng bộ, và side effect gì.
- **Ngân sách context** tính bằng token, ước lượng bằng một tokenizer cố định có ghi tên trong schema. Mặc định 4.000.
  - `utf8-byte-v1`: số token ước lượng = `ceil(số byte UTF-8 của nội dung trả về / 4)`. Đây là phép ước lượng xác định, không phụ thuộc model, và không phải số token thật của nhà cung cấp.
  - Phép tính này chỉ dùng cho ngân sách context cục bộ và các giới hạn context ở mục 10. Nó không phải cận trên của token tính phí; giữ chỗ chi phí và usage theo mục 9.
  - Đếm trên tổng byte của `summary` hoặc nội dung được chọn; `ceil` áp dụng một lần trên tổng; không tính envelope JSON.

### 6.3 Idempotency

- Phạm vi khóa: (principal, tool, `idempotency_key`).
- Mỗi khóa gắn với digest của request đã chuẩn hóa (canonical JSON):
  - Cùng khóa, cùng digest → trả lại **cùng object ID, cùng assignment** (kể cả holdout).
  - Cùng khóa, khác digest → `idempotency_conflict`.
  - Cùng khóa đang xử lý → `in_progress`.
- Bản ghi idempotency commit cùng transaction với side effect (mục 5.4).
- Bản ghi idempotency **chỉ lưu ID và ref, không lưu nội dung.** Mỗi lần phục vụ lại, nội dung được dựng lại từ ref và kiểm tra quyền, policy, revoke, quarantine **hiện hành**.
  - Mục đã bị cấm được thay bằng `{status: "redacted", reason}`, vẫn giữ ID.
  - "Lịch sử đã xảy ra" (Delivery có ID đó) khác với "được phép giao nội dung lúc này".

### 6.4 Job

- **Trạng thái:** `queued → leased → running → succeeded | failed | cancelled | dead_letter`.
- **Lease** gắn `writer_epoch`. Mỗi lần thử ghi `attempt`. Mặc định thử tối đa 3 lần với backoff, sau đó vào `dead_letter`.
- **Phục hồi sau crash:** khi daemon khởi động với epoch mới, job ở `leased`/`running` của epoch cũ:
  - quay về `queued` với `attempt + 1`, nếu còn lượt;
  - hết lượt thì vào `dead_letter`.
- **Lời gọi Jev dở dang:** ProviderInvocation chưa có kết quả được ghi `outcome_unknown`. Chi phí giữ ở mức giữ chỗ tối đa cho tới khi đối soát được (mục 9). Chạy lại job có thể tạo một lời gọi trùng; lời gọi đó cũng được ghi chi phí.
- **Hủy job** (`brain job cancel`) có hiệu lực tại điểm có thể hủy. Usage đến muộn của job đã hủy vẫn được ghi.
- **Lời gọi ra ngoài của mọi job** (Jev, harness rà soát) ghi reservation ở tầng accounting trước khi gửi (mục 5.7).
- **Job có điều kiện nguồn** (ví dụ rà soát skill, mục 8.10) dùng một reservation bền theo khóa admission, và kiểm lại điều kiện nguồn trong chính transaction commit kết quả.

### 6.5 Deadline

- Deadline của `prepare_task` là **1,5 giây tính từ lúc daemon nhận request tới lúc trả response**.
- Ngân sách từng phase:

  | Phase | Ngân sách |
  |---|---|
  | Lọc | ≤ 100 ms |
  | Jev | phần còn lại trừ 200 ms |
  | Commit | ≤ 200 ms |

- Jev quá hạn → dùng kết quả rules.
- **`store_busy`** chỉ trả khi request bị từ chối **trước khi bắt đầu** (hàng đợi ghi đầy). Khi đó chắc chắn không có Delivery.
- **Hết deadline khi commit đang chạy:** trả `commit_outcome_unknown`. Transaction vẫn tiếp tục. Retry cùng `idempotency_key` nhận kết quả thật, hoặc `in_progress`. Deadline là điều kiện để trả response, không phải bằng chứng rollback.
- Đã commit mà client mất response → retry cùng khóa nhận lại đúng kết quả (mục 6.3).

## 7. Capture, phiên và liên tục phiên

### 7.1 Đường đi của một sự kiện

```
hook/transcript → adapter dịch sang envelope v2 → privacy filter → outbox cục bộ (fsync)
 → daemon nhận (bỏ trùng theo producer_stream + sequence) → Event
 → worker: gom episode, nhận diện tín hiệu, tạo observation ứng viên
```

- Chỉ chạy khi cờ `automatic_capture` của repo bật (mục 14.2).
- **Hook:**
  - Mục tiêu dưới 100 ms. Trần cứng 2 giây; quá trần thì thoát với mã thành công cho harness và ghi CaptureGap.
  - Lỗi không bao giờ làm harness dừng. Lỗi ghi vào log cục bộ (không chứa payload) và hiện trong `get_health`.
  - **Cấu hình hook do bootstrap ghi** theo đúng schema của từng host: `hooks.<Event>` là mảng nhóm matcher, mỗi nhóm có `hooks` gồm handler `type: "command"` và `timeout` (giây). Bootstrap quản lý một nhóm `matcher: "*"` cho `PreToolUse` và `PostToolUse`; Claude Code dùng dạng exec (`command` là trình thông dịch, `args` là phần còn lại, không qua shell), Codex dùng chuỗi lệnh `command` và `commandWindows`. Slice quản lý `hooks#super-brain` là các nhóm có handler chạy `superbrain.composition.hook_entry`; merge, cập nhật và rollback chỉ chạm các nhóm này, hook khác của người dùng trong cùng event được giữ nguyên. Hook project của Codex chỉ chạy sau khi người dùng tin cậy (`/hooks`).
- **Outbox:**
  - Có giới hạn, mặc định 100 MB mỗi harness. Đầy hoặc đĩa đầy thì ghi CaptureGap; không âm thầm bỏ sự kiện.
  - Chỉ xóa sự kiện khỏi outbox sau khi daemon ACK theo mục 5.4.
  - **Mức độ bền của outbox trên Windows là `process_crash_durable`.** Outbox công bố frame, cursor, ACK page, bucket binding và `streams/.v4_fence` bằng `os.replace` (`MoveFileExW` với `MOVEFILE_REPLACE_EXISTING`, không có `MOVEFILE_WRITE_THROUGH`), và Windows không fsync được thư mục. Vì vậy chỉ bảo đảm khi tiến trình chết: một bước công bố đã trả về thì còn nguyên sau khi tiến trình chết. Không bảo đảm thứ tự hay sự tồn tại của directory entry khi mất điện; khi đó recovery có thể thấy một cursor trỏ tới ACK page bị mất và trả `INTEGRITY_FAILURE` (fail closed), không âm thầm mất sự kiện. Trên Linux/macOS, outbox fsync thư mục sau mỗi bước công bố và dừng trước bước kế tiếp nếu gặp lỗi I/O thật. Filesystem báo không hỗ trợ fsync thư mục cũng chỉ đạt `process_crash_durable`.
  - **Quyền sở hữu slot.** Mỗi slot `(producer_stream, sequence)` thuộc về đúng một notification. Notification có định danh ổn định (dedup key) giữ slot bằng binding bền; khi hook phải ghi `CaptureGap` thay cho sự kiện, binding được đóng dấu gap `(gap_id, reason, recorded_at, duration_ms)` và ghi bền trước khi công bố gap. Retry, sự kiện đến muộn và timeout lặp lại sau khi gap đã được ACK đều dùng đúng slot và đúng định danh gap đó (`gap_id` suy ra từ slot). Mọi đường ghi (hook, gap fallback, ghi `Event` trực tiếp) đều kiểm chủ slot: một `Event` khác nhận `IDEMPOTENCY_CONFLICT`, chủ slot vẫn hoàn tất được. Binding có dấu gap là định dạng v4 nên chỉ được ghi sau `streams/.v4_fence`. Khi cửa sổ binding đã đầy, gap vẫn được ghi (không mất âm thầm) nhưng không giữ slot. Notification không có định danh ổn định (không dedup key, không sequence) không giữ được slot qua retry: gap của nó lấy slot trống kế tiếp.
- **Privacy filter** áp dụng ở mọi đường vào bền vững (mục 14.2), không chỉ ở capture.
- **Sự kiện harness không cung cấp được** thì ghi là `unavailable`, không đoán.
- **Các tín hiệu worker nhận diện:**
  - lần chạy test và exit code;
  - chữ ký lỗi, và lỗi lặp lại;
  - file bị sửa;
  - **lời người dùng sửa agent**: dùng mẫu rules trước; ca chưa rõ thì gom lô hỏi Jev bằng câu Noul, nếu Jev đang bật và cờ `provider_egress` cho phép.

### 7.2 Task, phiên và episode

- **Session** là một phiên của một harness.
  - Adapter capture ghi **hồ sơ người nhận** theo từng **đoạn phiên**: harness, hồ sơ provider (endpoint và cấu hình model dưới dạng digest) và account khi xác minh được. Phần không xác minh được ghi `unknown`. Phiên đổi hồ sơ giữa chừng thì mở đoạn mới; một `session_ref` có thể có nhiều đoạn.
  - Mỗi Event mang **bằng chứng tiếp xúc** do adapter gán theo kênh thu, không do client khai:
    - `sent_to_recipient`: harness ghi nhận chính mục này đã nằm trong một lời gọi model **đã hoàn tất và xác minh được**, gửi đi hoặc nhận về. Bằng chứng gắn với ref và digest của mục, đoạn phiên, và lời gọi đó. Lần gửi lỗi hoặc chưa rõ kết quả không đủ; mục đó là `unknown`;
    - `local_only`: mục chỉ được hook thu tại máy hoặc chỉ được ghi vào brain, chưa có bằng chứng đã tới provider;
    - `unknown`: không xác định được.
  - Lượt rà soát dùng hai thông tin này để biết **đúng mục nào đã tới đúng ai** (mục 8.10, 14.2). Cùng phiên và cùng provider là chưa đủ.
- **Task** là một mục tiêu công việc; một task có thể trải qua nhiều phiên và nhiều harness.
- **Episode** là phần việc của một task trong một phiên.
- Phân tích đo lường đếm theo task, không đếm mỗi phiên là một lần thử độc lập.

### 7.3 Liên tục phiên

- **Khi nào tạo:**
  - Phiên kết thúc: tạo bản tóm tắt cuối.
  - Không hoạt động quá 30 phút: tạo **checkpoint** có nhãn `in_progress_unknown`, **không** phải kết thúc thành công hay thất bại.
  - Trong suốt phiên: sổ bàn giao được cập nhật liên tục (mục 7.4). Hai mốc trên không còn là nguồn duy nhất.
- **Checkpoint của việc chạy dài** ghi:
  - lệnh, thư mục làm việc, source revision;
  - PID/handle kèm thời điểm khởi động, nếu có;
  - đường dẫn log hoặc receipt;
  - việc tiếp theo.

  Phiên sau đọc receipt trước. Nếu chưa có receipt kết thúc, chỉ kiểm tra tiến trình gốc một lần; không khởi động lại chỉ vì quá timeout.
- **Sự kiện đến muộn** tạo một revision mới của continuity và giữ lịch sử revision cũ; không ghi đè mà không để lại dấu vết.
- **Nội dung:** sổ bàn giao, theo cấu trúc và giới hạn ở mục 7.4.
  - Phần agent khai đến từ `submit_episode`.
  - Agent không gửi thì chỉ còn phần quan sát được, trích xuất theo luật, và L0 ghi rõ là không có phần agent khai.
- **Phạm vi:** gắn với **checkout** (mục 5.2). Được đưa vào `prepare_task` của phiên kế tiếp trên checkout đó, với bất kỳ harness nào. Chuyển việc sang checkout khác, kể cả worktree khác của cùng repo, chưa được hỗ trợ.
- **Lineage:** continuity, checkpoint và bản bàn giao mang lineage của task tạo ra chúng (mục 14.2). Khi được đưa vào task mới, task mới kế thừa lineage đó.

### 7.4 Sổ bàn giao (Q21)

Mục đích: khi một harness dừng, harness khác làm tiếp mà không đổi hướng. **Thiết kế không dựa vào việc biết trước phiên sắp dừng**, nên không cần hook báo hết quota. Sổ luôn phải đủ mới từ trước đó.

Sổ luôn mang nhãn `agent_reported` ở phần agent khai, không bao giờ được tính là bằng chứng cho bài học (mục 8.2), và là **dữ liệu, không phải lệnh**: không cấp thêm quyền, không thay cổng duyệt (mục 11.3). Lượt rà soát skill sau phiên (mục 8.10) chỉ dùng các mục quan sát của sổ có Event nguồn thuộc đúng phiên được rà và có bằng chứng đã tới đúng người nhận (mục 7.2). Phần agent khai, kể cả patch do chính phiên đó ghi, và trạng thái gộp của sổ không được gửi đi: chúng chỉ có bằng chứng đã ghi vào brain. Skill soạn từ đó vẫn mang nhãn `agent_reported`.

**Binding.** Mỗi sổ gắn với đúng một task, và task có binding đã xác minh `(owner_id, repo_id, checkout_id, task_id)`. Tìm sổ, đọc theo ref, resume, ghi và replay đều kiểm binding này, quyền hiện hành của principal và `selected_scope` **trước** khi trả L0 hoặc đọc CAS. Sai scope trả `not_found`, kể cả khi caller biết ID và revision. Với `kind=handoff`, `id` của item vừa là `task_id` vừa là `artifact_id`.

**Phần agent khai:**

| Mục | Nội dung | Cách cập nhật |
|---|---|---|
| `working_goal` | Cách hiểu hiện tại về mục tiêu | Thay thế |
| `plan` | Các bước và bước đang làm; mỗi bước có tùy chọn `depends_on_change` | Thay thế |
| `decisions` | `id` (agent đặt, duy nhất trong sổ), quyết định, lý do, `evidence_refs`, tùy chọn `supersedes` hoặc `reopens` | Chỉ thêm |
| `rejected` | `id`, phương án đã loại, lý do, tùy chọn `merges` để gộp các mục cũ | Chỉ thêm |
| `user_constraints` | `id`, ràng buộc do người dùng đặt | Chỉ thêm |
| `constraint_changes` | Đề xuất đổi ràng buộc; `closed_changes` để đóng đề xuất (xem bên dưới) | Chỉ thêm |
| `tooling` | Lệnh và công cụ cấp dự án, ghi theo mục đích; không ghi tên tool riêng của harness | Thay thế |
| `hypotheses` | Giả thuyết đang kiểm tra | Thay thế |
| `next_action` | Việc làm ngay tiếp theo; tùy chọn `depends_on_change` | Thay thế |
| `long_running` | Việc chạy dài: các trường ở mục 7.3 | Thay thế |
| `task_state` | `open`, `done` hoặc `abandoned` | Thay thế |

`task_goal` là `description` ở lần tạo task, do server lưu thành một blob riêng, ghim và không sửa được. L0 hiện tối đa 200 byte, cắt đúng ranh giới ký tự UTF-8 và có dấu đã cắt. L1 hiện tối đa 2 KB; bản đầy đủ ở L2. L0 và L1 hiện cả `working_goal` khi nó khác `task_goal`.

**Phần quan sát** (worker ghi, agent không sửa được). Đây là danh sách mục, mỗi mục chỉ gồm `kind`, `source_event_id` và `source_digest`: file đã đổi, lệnh và exit code, lỗi gần nhất, lời người dùng gần đây, câu trả lời gắn với đề xuất đổi ràng buộc. Kèm `observed_through` và số event kể từ lần agent ghi cuối. Harness không có hook hay transcript thì phần này là `unavailable`.

**Trích đoạn giữ hiệu lực của nguồn.** Nội dung của từng mục quan sát được dựng từ Event nguồn **lúc phục vụ**, không sao vào sổ.
- Mỗi lần phục vụ L1, L2, report, retry hoặc sau restore đều kiểm tra lại quyền, tombstone và quarantine theo digest nguồn.
- Nguồn bị chặn thì mục đó trả `redacted`; nguồn hết hạn thì trả `expired`. ID và digest vẫn giữ, bytes không còn được phục vụ.
- Digest của lần đã phục vụ nằm trong ServedReceipt. Bản phục vụ lại có digest theo nội dung thực tế.
- L0 không chứa trích đoạn. L0 dựng sẵn mang digest của `agent_ref` và `task_goal`, và được kiểm tra tombstone, quarantine trước khi trả, kể cả khi tìm đúng theo `task_id`. Một trong hai bị chặn hoặc hết hạn thì trả RedactedItem kèm `reason`.
- Phần agent khai và `task_goal` bị quarantine theo digest của chính chúng, ở từng revision.

**Revision và merge.**
- Sổ có hai ref bất biến: `agent_ref` và `observed_ref`. Owner thread commit `revision` của artifact bằng ref mới của phần vừa đổi và ref hiện hành của phần kia, đọc trong cùng transaction. Worker chụp dữ liệu cũ cũng không làm mất patch của agent.
- `handoff_revision` chỉ tăng khi agent ghi patch; `base_revision` so với bộ đếm này. `revision` của artifact tăng khi một trong hai phần **hoặc người giữ** đổi; ServedReceipt gắn với bộ đếm này. Tiếp quản không kèm patch tăng `revision` và `writer_generation`, không tăng `handoff_revision`. Worker không bao giờ đổi tập đang hiệu lực, nên không cần tăng `handoff_revision`.
- Mỗi `revision` của artifact giữ một bản ghi header bất biến gồm `handoff_revision` và fence của chính revision đó.
- **Ref bất biến qua restore** là `(artifact_id, revision_epoch, revision)`, với `revision_epoch` là `restore_epoch` lúc commit revision đó. Sau restore, số `revision` có thể lặp lại với nội dung khác, nên đọc, ServedReceipt, ReadAck và lineage đều dùng đủ ba giá trị.
- Worker có thể tạo sổ khi có task hợp lệ: `revision` dương, `handoff_revision=0` nghĩa là chưa có bản khai, `task_state=open` kèm `task_state_source=inferred`. L0 ghi rõ chưa có phần agent khai. Agent đầu tiên cập nhật bằng `base_revision=0`.
- Độ cũ tính riêng: `agent_updated_at` cho phần khai, `observed_through` cho phần quan sát. Worker cập nhật liên tục không làm sổ khai đã cũ trông như mới.

**Header.** L1 và L2 luôn có resource `handoff_header`: `artifact_id`, `revision`, digest của hai ref, `handoff_revision`, `task_id`, `task_state`, `task_state_source`, fence (`restore_epoch`, `writer_generation`), harness đang giữ sổ, trạng thái phiên, `agent_updated_at`, `observed_through`. Fence trong header là fence đã commit của đúng revision đó, nên có thể cũ sau restore; fence sống nằm trong `handoff_live`.

**Cấp đọc và giới hạn** (đếm byte UTF-8 của bản đã render):

| Cấp | Nội dung | Lấy bằng | Giới hạn mặc định |
|---|---|---|---|
| L0 | `task_goal` đã cắt, bước đang làm, việc tiếp theo, số quyết định, độ cũ, trạng thái phiên, cảnh báo có phiên khác đang chạy, số đề xuất đổi ràng buộc đang chờ | `prepare_task` | ≤600 byte |
| L1 | Header; **toàn bộ** phần bắt buộc; phần quan sát | `get_artifact` | Mỗi resource ≤8 KB |
| L2 | Lịch sử quyết định, đề xuất đã đóng, các revision trước, đoạn hội thoại gần nhất đã lọc (dựng từ ref như phần quan sát) | `get_artifact` | Tối đa 256 KB mới nhất; cũ hơn thì đọc theo `revision` đã ghim |

- **Phần bắt buộc** gồm: ràng buộc đang hiệu lực, đề xuất đổi ràng buộc đang chờ, quyết định đang hiệu lực, phương án đã loại còn hiệu lực, `plan`, `next_action`, `tooling`, `long_running`. L1 không bao giờ cắt phần này: nội dung dài được chia thành nhiều resource trong cùng một response.
- **Giới hạn ghi:** một mục ≤2 KB, một patch ≤16 KB, tổng phần bắt buộc ≤32 KB, trong đó ràng buộc đang hiệu lực ≤16 KB. Đề xuất đang chờ nằm trong vùng riêng ≤4 KB, không tính vào 32 KB.
- Vượt giới hạn thì trả `invalid_input` và giữ nguyên sổ. **Patch không làm tăng tổng phần bắt buộc được miễn xét giới hạn tổng 32 KB**, kể cả khi sổ đang ở trần, nên agent luôn rút gọn được bằng `supersedes` hoặc `merges`. Miễn trừ này chỉ áp dụng cho giới hạn tổng; giới hạn một mục, một patch, vùng đề xuất đang chờ và quyền ghi vẫn áp dụng. Ràng buộc đang hiệu lực không rút gọn được; chạm trần 16 KB thì agent phải báo người dùng.
- Các mục không bắt buộc thiếu chỗ thì L1 trả `incomplete_optional=true`.

**Đường ghi của agent.** `submit_episode` với `handoff` chứa các mục đã đổi, kèm `base_revision` và `fence`. Mục không gửi thì giữ nguyên. `evidence` có thể rỗng. Mỗi lần ghi là một transaction cùng Episode và bản ghi idempotency (mục 6.3).
- Agent cập nhật ở 6 thời điểm, không phải mỗi lượt: lập hoặc đổi kế hoạch; chốt quyết định hoặc loại phương án; người dùng đặt thêm ràng buộc; xong một bước; ngay trước lệnh chạy lâu; khi task kết thúc (đặt `task_state`).
- Quy tắc này được cài vào file hướng dẫn của harness qua bootstrap, nên **model tự giác, server không ép được**. Harness có hook phù hợp thì hook có thể nhắc khi sổ đã cũ; hook chỉ nhắc, không bao giờ chặn.

**Người giữ sổ và tiếp quản.** Không dùng khóa có hạn, vì harness hết quota không thể tự nhả khóa.
- Mỗi sổ có `writer_generation` (ban đầu 0) và người giữ `(principal, session_ref, restore_epoch)`. **Fence** là cặp `(restore_epoch, writer_generation)`; header, `handoff_live` và mọi ACK ghi sổ đều mang fence.
- `session_ref` là HMAC của `session_id` bằng khóa trong policy store. Mọi bản ghi và ledger chỉ dùng `session_ref` (mục 5.3); `session_id` gốc không xuất hiện trong L0, L1, L2, log hay ledger. `session_ref` được gắn với principal ở lần dùng đầu; principal khác khai cùng `session_id` thì trả `identity_mismatch`.
- **Mọi lần ghi sổ** phải gửi `fence` hiện hành và phải đến từ đúng người giữ. Sai một trong hai thì trả `revision_conflict`, kể cả khi `base_revision` đúng. Nhờ `restore_epoch` nằm trong fence, request từ trước restore bị từ chối kể cả khi sau đó `writer_generation` và `handoff_revision` trùng lại.
- Muốn giữ sổ phải tiếp quản rõ ràng: `submit_episode` kèm `takeover`, `base_revision` và `fence` hiện hành, có thể kèm hoặc không kèm `handoff`. Server so khớp trên trạng thái hiện hành, **luôn tăng** `writer_generation` và ghi `takeover_from`. Vì thế patch đến muộn của A sau chuỗi A → B → A vẫn bị từ chối. Hai bên cùng tiếp quản thì chỉ một bên thắng; bên thua nhận `revision_conflict`.
- Lần ghi đầu của mọi phiên đều là tiếp quản, kể cả trên sổ mới (`writer_generation=0`).
- Phiên giữ sổ còn `active` thì tiếp quản phải có `takeover.acknowledge_active=true`, và agent phải báo người dùng trước khi làm tiếp. Thiếu thì trả `invalid_input`.
- Agent chỉ được đổi file trong checkout **sau khi nhận ACK của lần tiếp quản có `handoff_status=stored` và `writer_status=holder`**. ACK có `not_holder` nghĩa là quyền của lần tiếp quản đó không còn: không được đổi file, phải đọc lại. Nhận `commit_outcome_unknown` thì retry cùng khóa để biết kết quả trước.
- **Restore:** `restore_epoch` đổi cùng lúc với bản kho (mục 5.7). Người giữ có `restore_epoch` khác giá trị hiện hành không còn hiệu lực, nên mọi phiên phải tiếp quản lại.
- **Fence sống.** `handoff_live` gồm `revision`, `revision_epoch`, `handoff_revision` và fence `(restore_epoch hiện hành, writer_generation của bản mới nhất)`. Trường này được tính lúc trả sau khi kiểm binding, không nằm trong resource, không tính vào digest và không lưu trong bản ghi idempotency. `get_artifact` với sổ bàn giao và `prepare_task` với `mode=work` đều trả trường này. Task mới chưa có sổ nhận `revision=null`, `handoff_revision=0` và fence `(restore_epoch hiện hành, 0)`. `mode=discover` không phát fence.
- Hàng rào này chỉ kiểm soát việc ghi sổ. File trên đĩa vẫn dùng chung, nên agent phải đối chiếu trạng thái checkout và báo người dùng theo Q21.

**Đổi quyết định.**
- `decisions` và `rejected` không xóa được. `supersedes` phải trỏ tới một quyết định **đang hiệu lực**, kèm lý do. Trỏ sai loại, trỏ mục đã bị thay hoặc thiếu lý do thì trả `invalid_input`. Nhờ `base_revision`, hai đề xuất cùng trỏ một mục chỉ có một bên được ghi; bên còn lại đọc lại và thấy mục đã bị thay.
- Mở lại phương án đã loại bằng một quyết định có `reopens` trỏ mục trong `rejected`, kèm lý do nêu bằng chứng mới và `evidence_refs` nếu có.
- `merges` trên một mục `rejected` mới chỉ được trỏ tới các mục loại **còn hiệu lực**. Sau khi gộp, các mục nguồn rời tập đang hiệu lực và vẫn đọc được ở L2. Trỏ mục không còn hiệu lực thì trả `invalid_input`.
- `evidence_refs` phải thuộc cùng binding, sai thì trả `not_found`. Tập đang hiệu lực được dựng lại một cách xác định từ chuỗi revision, nên replay cho đúng kết quả đó.

**Đổi ràng buộc của người dùng.** Harness hỏi trực tiếp, người dùng trả lời tự nhiên. Không có mã xác nhận và SP2 không có trạng thái xác nhận chính thức.
- Brain không hiểu nghĩa câu trả lời, nên sổ **không bao giờ tự đổi ràng buộc**. Ràng buộc cũ giữ nguyên trong tập đang hiệu lực.
- Agent ghi một mục `constraint_changes` gồm `id`, ràng buộc đích, nội dung đề xuất và lý do, ở trạng thái `proposed`, rồi hỏi người dùng.
- Worker tự gắn ref tới tin nhắn kế tiếp của người dùng sau khi đề xuất được commit, do adapter đã đăng ký ghi lại, trên đúng binding. Ref này nằm trong phần quan sát và chỉ để tham khảo: một câu từ chối hoặc câu không liên quan cũng được gắn như vậy và **không có hiệu lực gì**. L0 chỉ hiện số đề xuất đang chờ; L1 và `brain report` dựng trích đoạn ≤512 byte từ ref.
- **Phiên đã trực tiếp hỏi và nhận câu trả lời được làm theo trong phiên đó.** Phiên khác muốn dựa vào đề xuất để hành động thì phải hỏi lại người dùng. Harness không capture được thì đề xuất không có ref, và quy tắc này vẫn áp dụng.
- Bước trong `plan` hoặc `next_action` phụ thuộc vào ngoại lệ chỉ có hiệu lực trong phiên đó thì ghi `depends_on_change` trỏ tới đề xuất, để phiên sau biết phải hỏi lại trước khi làm. Trỏ đề xuất không tồn tại thì trả `invalid_input`.
- Người giữ sổ đóng đề xuất bằng `closed_changes`: `rejected` khi người dùng từ chối, `withdrawn` khi agent rút lại. Đề xuất đã đóng rời khỏi vùng đang chờ và chỉ còn ở L2.
- Ràng buộc mới do agent khai không được nới lỏng ràng buộc đang có. Server không phát hiện được mâu thuẫn về ngữ nghĩa; khi hai mục mâu thuẫn, agent áp dụng mục có trước và hỏi người dùng.

| Nguồn của câu trả lời bị ảnh hưởng | Kết quả |
|---|---|
| Hết hạn | Trích đoạn trả `expired`, trạng thái đề xuất không đổi |
| Quarantine, tombstone | Trích đoạn trả `redacted`, trạng thái đề xuất không đổi |
| Restore | Theo mục 5.6, không phục sinh nội dung đã hết hạn |

Vì SP2 không có trạng thái xác nhận, không policy nào làm mất hiệu lực một thay đổi ràng buộc: thay đổi đó chưa từng có hiệu lực trên sổ.

**Đường ghi của worker.** Theo đường capture ở mục 7.1, chỉ dùng luật, không gọi LLM.
- Worker nhận dạng theo task, session, `producer_stream` và watermark. Watermark tính riêng cho từng `producer_stream` và chỉ tăng; sự kiện đến muộn được gộp vào và tạo `revision` mới.
- Làm mới được **lên lịch** sau 20 event hoặc 60 giây kể từ event đầu tiên chưa được làm mới, tùy điều kiện nào đến trước. Phiên im lặng khi mới có dưới 20 event vẫn được lên lịch nhờ mốc 60 giây.
- Mỗi task có tối đa một job chờ. Job đang chạy mà có event mới thì đánh dấu, và chạy đúng một job tiếp theo.
- 60 giây là mốc lên lịch, không phải cam kết phục vụ: thời điểm thực tế còn phụ thuộc hàng đợi job và retry. `observed_through` luôn cho biết dữ liệu mới tới đâu. Event chưa ACK không được bảo đảm, và được báo bằng `CaptureGap` theo mục 7.1.
- `prepare_task` chỉ đọc bản đã dựng sẵn, không tính lại từ event, để giữ ngân sách xử lý tại máy ≤100 ms (mục 6.5).

| `automatic_capture` | `manual_submission` | Worker quan sát | Phần agent khai |
|---|---|---|---|
| bật | bật | Chạy | Được lưu |
| bật | tắt | Chạy (sổ chỉ có phần quan sát) | Không lưu, `not_stored_policy` |
| tắt | bật | Không thêm mục mới | Được lưu |
| tắt | tắt | Không thêm mục mới | Không lưu, `not_stored_policy` |

Job kiểm tra cờ hiện hành khi bắt đầu và khi commit. Dữ liệu cũ sau khi tắt cờ vẫn được phục vụ tới khi hết hạn, trừ khi bị quarantine hoặc tombstone.

**Trạng thái phiên.** Brain không đoán phiên đã kết thúc:

| Trạng thái | Nghĩa |
|---|---|
| `active` | Có event trong 5 phút gần đây |
| `in_progress_unknown` | Im lặng, không rõ đã dừng hay chưa |
| `ended` | Harness báo phiên đã kết thúc. Event đến sau mốc này được gộp vào phần quan sát nhưng không đổi trạng thái; chỉ sự kiện `session_resumed` của adapter mới đổi |

**Đường đọc:**
1. **Tìm sổ.** Đầu phiên agent gọi `prepare_task` với `mode=discover`. Lần gọi này chỉ đọc, không có `idempotency_key`, không tạo task, Delivery hay Job, không gọi Jev, không có holdout, không thuộc mẫu số đo lường. Kết quả là L0 của tối đa 3 sổ còn mở trên checkout, mới nhất trước. Mỗi item mang ref bất biến đủ `id`, `revision_epoch`, `revision`, với `revision_epoch` đã commit, có thể khác `restore_epoch` hiện hành sau restore.
   - Sổ còn mở là sổ có `task_state=open` và có cập nhật trong 14 ngày.
   - Truyền `task_id` thì nhận đúng bản mới nhất của sổ đó dù nằm ngoài top 3 hoặc đã đóng, sau khi kiểm tra binding. Đây cũng là đường lấy bản mới nhất sau `revision_conflict`.
2. **Đọc.** Agent chọn sổ và gọi `get_artifact` L1 với `task_id` bằng `id` của item. ServedReceipt gắn với principal và task đó.
3. **Resume.** Agent gọi `prepare_task` với `mode=work`, `task_id` và `resume_ref` gồm `artifact_id`, `revision`, `handoff_revision`, `fence` **đã commit** của revision đã đọc (`restore_epoch` trong đó chính là `revision_epoch`, không phải fence sống) và `served_receipt_id` nếu có. Delivery mới gắn với task cũ, dùng lại scope đã ghim, sau khi kiểm tra lại quyền và policy hiện hành. Snapshot thiếu xử lý theo S1 như mọi Delivery.
   - Server so `handoff_revision` và `fence` trong `resume_ref` với header bất biến của chính `revision` đó, kể cả khi không có receipt. Không khớp thì trả `revision_conflict`.
   - `served_receipt_id` phải là lần phục vụ **L1** của đúng principal, task, artifact và revision, và có tập digest của các resource bắt buộc, kể cả mục đã `redacted`. Sai thì trả `not_found`; receipt còn `pending` thì trả `in_progress`.
   - Bằng chứng ghi vào `exposure_evidence`: có ReadAck khớp digest thực tế là `read_ack`; có receipt hợp lệ là `served_only`; không có receipt là `unknown`.
   - Sau đó so với **header đã commit của bản mới nhất**: `handoff_revision` hoặc fence đã đổi kể từ `revision` đã đọc thì trả `revision_conflict`, phải đọc lại. Restore chỉ đổi fence sống, không đổi header, nên không chặn resume; agent vẫn phải tiếp quản bằng fence sống.
   - Chỉ `revision` tăng (phần quan sát mới hơn) thì vẫn đi tiếp, và `degraded_codes` có `observed_newer`.
4. **Kiểm tra trước khi làm.** Agent so sổ với trạng thái thật của code, nói lại ngắn gọn cho người dùng: mục tiêu, bước đang làm, các quyết định sẽ giữ.
5. **Tiếp quản** bằng lần ghi đầu, dùng fence từ `handoff_live`, theo quy tắc ở trên.

Sau restore hoặc `revision_conflict`, thứ tự phục hồi là: tìm sổ bằng `task_id`, đọc L1, lấy `handoff_live`, resume, rồi tiếp quản.

Không có sổ phù hợp thì agent gọi `mode=work` như thường. `mode=work` không kèm `task_id` không trả nội dung sổ nào; nếu checkout có sổ còn mở thì `degraded_codes` có `open_handoffs_present`, để agent bỏ qua bước tìm sổ vẫn được nhắc. Agent dùng thông tin từ L0 đã xem cho một task mới thì khai `seen_handoff_refs`; server kiểm binding rồi thêm vào lineage. Không khai thì đó là nội dung agent tự chép, thuộc giới hạn ở mục 14.2.

**Ngân sách.** L0 không bị cắt đôi. Brain lấy nhiều sổ nhất vừa `context_budget_tokens`, mới nhất trước, tính theo mục 6.2. Không đủ thì bỏ các sổ còn lại và trả `continuity_truncated`. Sổ bị bỏ vẫn tìm được bằng `task_id`.

**Tranh chấp:**

| Tình huống | Cách xử lý |
|---|---|
| Người giữ ghi trên bản cũ | `revision_conflict`, không tạo revision. Đọc lại rồi gộp; server không tự gộp |
| Phiên không giữ sổ ghi, kể cả đúng revision | `revision_conflict` |
| Tiếp quản khi phiên cũ vẫn `active` | Phải có `acknowledge_active`; L0 cảnh báo và agent phải báo người dùng |
| Hai harness làm hai task khác nhau trên cùng checkout | Mỗi task một sổ, worker gán event theo phiên. L0 cảnh báo vì file trên đĩa dùng chung |

**Retry.** Tra idempotency **trước** khi so `base_revision` và `fence`, nên retry hợp lệ nhận đúng kết quả đã commit thay vì `revision_conflict`. Kết quả phục vụ lại theo mục 6.3: giữ ID và revision đã commit, kiểm tra lại quyền hiện hành. Replay chỉ trả lại kết quả cũ, không trả lại quyền ghi. Mọi ACK ghi sổ mang `writer_status` tính **lúc trả**, kể cả khi replay: `holder` chỉ khi **fence đã commit trong ACK bằng fence sống** và người giữ hiện hành đúng là caller, còn lại là `not_holder`. Các trường khác giữ nguyên như đã commit. Hết deadline lúc commit trả `commit_outcome_unknown` và retry cùng khóa để biết kết quả thật.

**Lỗi:**

| Tình huống | Cách xử lý |
|---|---|
| Harness dừng giữa lời gọi ghi sổ | Giữ nguyên revision đã commit gần nhất |
| Daemon tắt | Shim báo lỗi rõ ràng, không lưu sổ ở nơi khác. Agent gửi lại ở mốc sau. Phần quan sát được vẫn nằm trong outbox |
| Privacy filter từ chối | Không lưu gì của lần ghi đó, trả lỗi có mã |
| Nhánh `not_stored_policy` | Không có hiệu lực patch, không đổi người giữ, không tăng revision hay `writer_generation`, kể cả với request chỉ xin tiếp quản. Kết quả vẫn có `episode_id`, `evidence_ids`, kèm `handoff_status=not_stored_policy`, `handoff_revision=null` và `writer_status` hiện hành. Retry cùng khóa trả đúng kết quả đó |

**Thay đổi contract** (áp dụng ở task đầu của SP2):
- `PrepareTaskClientArgs`, `PrepareTaskDaemonArgs` tách theo `mode`:
  - `discover`: bắt buộc `schema_version`, `mode`, selector workspace theo cùng quy tắc hiện có; tùy chọn `task_id`, `context_budget_tokens`; cấm `idempotency_key`, `description`, `resume_ref`, `seen_handoff_refs`.
  - `work`: như hiện tại, thêm tùy chọn `resume_ref` (bắt buộc đi cùng `task_id`) và `seen_handoff_refs`.
  - Hai nhánh được pin ở schema, normalizer, phân loại side effect, kiểm tra result và admission. `discover` có result riêng gồm `workspace_id`, `checkout_id`, `continuity`, `degraded_codes`.
- `SubmitEpisodeClientArgs`, `SubmitEpisodeDaemonArgs`: thêm `handoff`, `base_revision`, `fence`, `takeover`; `base_revision` và `fence` bắt buộc khi có `handoff` hoặc `takeover`. `constraint_changes` và `closed_changes` nằm trong `handoff`.
- `SubmitEpisodeResult`: thêm `handoff_revision`, `handoff_status` (`stored` hoặc `not_stored_policy`), `fence`, `writer_status`. Chỉ phát các trường này khi request có `handoff` hoặc `takeover`. Request chỉ xin tiếp quản là một nhánh có fixture riêng.
- `ArtifactSendAttempt`: thêm `level` để kiểm receipt L1, và `revision_epoch`.
- `GetArtifactClientArgs`, `GetArtifactDaemonArgs`: thêm `revision_epoch`, bắt buộc với sổ bàn giao.
- `GetArtifactOkResult` (với sổ bàn giao) và `PrepareTaskResult` (`mode=work`): thêm `handoff_live`.
- `writer.lock` **không đổi định dạng**: `restore_epoch` nằm trong file metadata bên trong `store/` (mục 5.7).
- Item trong `continuity` có `kind=handoff`, dùng `summary` cho L0, và thêm `revision_epoch`. Thêm các `degraded_codes` `open_handoffs_present`, `continuity_truncated`, `observed_newer`.
- **Nhận diện schema.** `GET /v2/identity` trả thêm `schema_digest`; shim so với digest catalog của mình trên socket đã pin trước khi gửi tool call. Shim cũng gửi `schema_digest` trong private envelope để daemon kiểm tra chiều ngược lại. Thiếu hoặc khác ở bất kỳ chiều nào đều trả `unsupported_version` và không chạy tool. Không có chế độ tương thích; nâng cấp bằng cách dừng daemon, cài bản mới, khởi động daemon, rồi khởi động lại các shim. Yêu cầu trả `unsupported_version` áp cho mọi thành phần từ SP2 trở đi ở cả hai chiều (shim SP2 gặp daemon I2 thiếu `schema_digest`, shim SP2 gặp `schema_digest` lệch, daemon SP2 gặp private envelope thiếu/lệch `schema_digest`); ca đối chiếu với wheel lịch sử I2 nguyên bản (`5d00a88`/`972ae5a`/`035a4cd`) giữ nguyên kết quả quan sát `(code="identity_mismatch", bearer_sent=0, dispatches=0)` do decoder I2 chỉ nhận đúng 4 khóa danh tính.
- Đổi `x-implemented-in` và `x-side-effects` của `prepare_task`, `get_artifact`, cùng fixture request, response, error, mismatch và replay, phải sửa các file đang nằm trong seal, nên cần reviewer độc lập duyệt reseal.

**Giới hạn được công bố:**
- Chỉ giữ được những gì đã viết ra. Sổ chỉ mới tới lần agent cập nhật cuối; phần sau đó chỉ còn dữ liệu quan sát được.
- Harness nhận là model khác nên vẫn có thể suy luận khác. Mục `tooling` giữ được ý định, không bảo đảm dùng đúng cùng một tool.
- Brain không chặn được lệnh của harness. Việc tuân theo sổ và ràng buộc là do model tự giác; sổ chỉ bảo đảm thông tin được giữ và được trao đúng.
- Khi chuyển harness giữa chừng, người dùng có thể bị hỏi lại một lần về một thay đổi ràng buộc đã trả lời.
- Agent quên ghi thì sổ cũ; L0 báo độ cũ, không che giấu.
- Hai tiến trình cùng principal dùng chung một `session_id` thì brain không phân biệt được.
- Brain không phát hiện được về mặt ngữ nghĩa nội dung độc hại mà agent đã chép vào sổ, hay mâu thuẫn giữa các ràng buộc.

## 8. Skill, bài học và thư viện kinh nghiệm

Mục 8.1–8.5 nói về bài học. Mục 8.6–8.11 nói về vòng skill (Q22, Q23), thêm ở rev 17. Số mục cũ được giữ nguyên để các tham chiếu không đổi; về vai trò, skill là đơn vị tri thức chính và bài học bổ trợ cho nó.

### 8.1 Nguồn tạo bài học

1. Cặp lỗi → cách sửa: lệnh kiểm tra đỏ → xanh trong cùng task.
2. Lời người dùng sửa agent.
3. Chiến lược thành công lặp lại.

Câu chữ do agent viết (Q14) hoặc lấy theo mẫu. Mọi bài học bắt đầu ở `candidate` và mang lineage do server lập (mục 14.2). Bài học kỹ thuật có skill liên quan được ghi vào phần cạm bẫy của skill đó (mục 8.6); các bài học còn lại đứng riêng theo mục 8.2–8.5.

### 8.2 Nguồn evidence và điều kiện xác minh

`source` của evidence do **server gán theo kênh nhận**; client không tự khai được.

| Kênh nhận | `source` |
|---|---|
| Adapter capture đã đăng ký (có NativeHostReceipt), quan sát trực tiếp lệnh và kết quả | `tool_observed` |
| `submit_episode` | `agent_reported`, luôn luôn |
| Xác nhận của người dùng qua cổng ở mục 11.3 (`brain lesson confirm`) | `user_confirmed` |

**Lên `verified`** cần **một** trong hai điều kiện:
1. **Proof `tool_observed` gắn đúng subject.** Với loại sửa lỗi, proof gồm:
   - claim/tiêu chí;
   - task và source snapshot;
   - lần chạy thất bại và lần chạy thành công của **cùng** lệnh kiểm tra, có thay đổi nằm giữa;
   - trạng thái kết thúc, digest output;
   - phạm vi kết luận.

   Phân loại proof cho các loại bài học khác (world, chiến lược thành công) chốt trước SP5.
2. **ApprovalReceipt `user_confirmed`** cho đúng revision bài học.
   - Dùng cho `claim_type=preference`.
   - Với `claim_type=technical` thì chỉ xác nhận người dùng đồng ý, không ghi là "đã đo hiệu quả".

Thêm vào đó:
- **Lặp lại** ở các episode độc lập (khác task, khác phiên, mỗi episode đều có proof loại 1) chỉ **tăng độ tin cậy**, không tự đủ để xác minh.
- `agent_reported` không bao giờ đủ, dù lặp lại bao nhiêu lần.
- Độc lập xét theo task, phiên và nguồn, không theo số ID. Cùng một proof không được đếm hai lần, kể cả sau khi gộp bài học.

### 8.3 Trạng thái

```
candidate → verified → pending_conflict_check → active
                               │                  │
                               └→ conflicted ─────┤→ suspended → active
                                  (chờ duyệt)     ├→ superseded
                                                  ├→ revoked
                                                  └→ dormant → (evidence mới) → pending_conflict_check
```

- Chỉ `active` mới được đưa ra. **Lần đưa đầu tiên luôn sau Conflict Review.** Quy tắc này áp dụng cho bài học đứng riêng; skill theo mục 8.7, và hai skill mâu thuẫn được xử lý như biến thể (mục 8.8).
- **Conflict Review:**
  - Xét các bài học có điều kiện áp dụng chồng nhau.
  - Hỏi Jev câu Noul "A có mâu thuẫn với B **trong điều kiện C** không?", nếu Jev đang bật (mục 9) và `provider_egress` của lineage cả hai bài học cho phép.
  - Không gọi được Jev, hoặc policy cấm → dùng rules: không có bài học nào chồng điều kiện thì qua; có thì giữ ở `pending_conflict_check`. Không bao giờ coi như đã qua.
  - Phát hiện mâu thuẫn: **chỉ bài học mới** sang `conflicted` chờ duyệt. Bài học cũ đang `active` giữ nguyên, trừ khi người dùng quyết định khác.
- Mỗi chuyển trạng thái ghi actor, lý do và evidence vào ledger.
- Bảng chuyển trạng thái đầy đủ (suspend, supersede, revoke, reactivate, merge) chốt trước SP5 (mục 19).

### 8.4 Hạ hạng

- Holdout cho thấy bài học có hại (theo quy tắc chốt trước SP6) thì hạ xuống `dormant`.
- Muốn kích hoạt lại phải có evidence mới, rồi qua lại Conflict Review.

### 8.5 Gộp trùng và thư viện kinh nghiệm

- Bài học gần giống được gộp lại, giữ đủ nguồn gốc, lineage và proof lineage của từng bản.
- **Thư viện kinh nghiệm** (từ harness2): mỗi bài học và mỗi phiên bản skill giữ hồ sơ Delivery → lý do chọn → ServedReceipt/ReadAck → Outcome. Bộ chọn và reflection dùng hồ sơ này.

### 8.6 Skill (Q22)

Skill là quy trình làm một loại việc, do agent rút ra từ công việc thật. Ý tưởng lấy từ Hermes Agent (mục 3).

- **Định dạng:** thư mục có `SKILL.md` theo chuẩn mở mà các harness đang dùng. Bốn phần bắt buộc: khi nào dùng, quy trình, cạm bẫy, kiểm chứng.
  - L0 của skill là tên và phần "khi nào dùng"; L1 là toàn bộ `SKILL.md`; L2 là các resource đi kèm.
- **Trung lập với harness:** ghi theo mục đích, không ghi tên tool riêng của harness, cùng quy tắc với mục `tooling` của sổ bàn giao (mục 7.4). Ghi chú riêng cho từng harness nằm ở một phần tách biệt, tùy chọn.
- **Ghi bài học, không ghi nhật ký:** không tên dự án, đường dẫn tuyệt đối, số PR, ngày tháng hay tường thuật sự cố.
- **Chỉ skill thuần văn bản được ghi tự do.** Skill có script, file thực thi, hoặc file được tham chiếu như một lệnh là rủi ro cao (mục 11.3) và luôn chờ duyệt trước khi có hiệu lực ở bất kỳ phạm vi nào. Brain không bao giờ chạy script trong skill (mục 11.4).
  - Draft hoặc bản vá loại này tạo một **revision chờ duyệt riêng**, ở trạng thái `pending_approval`, kèm một ChangeProposal ghim đúng ref đầy đủ của revision đó, toàn bộ resource đi kèm và phạm vi sẽ kích hoạt. `submit_episode` trả `skill_status=pending_approval` và ref của proposal.
  - **Revision chờ duyệt không phải head phục vụ.** Nó không làm tiến head của bất kỳ phạm vi nào và không đổi pin. Revision đang được phục vụ trước đó tiếp tục được phục vụ nguyên như cũ cho tới khi revision mới được kích hoạt.
  - Revision chờ duyệt bị chặn ở mọi đường thường: `prepare_task`, `search_knowledge`, đọc trực tiếp theo ref bằng `get_artifact` (trả `not_found`), và `adopt`. Yêu cầu `adopt` gửi kèm một draft chờ duyệt không có hiệu lực, và kết quả ghi rõ pin không đổi. Chỉ luồng review đọc được proposal, theo đúng ref.
  - **Kích hoạt** cần approval rủi ro cao với action `skill_activate`, ký đúng phạm vi, ref đầy đủ và closure. Khi áp dụng, trong một transaction, server kiểm quyền và trạng thái hiện hành (chưa bị thu hồi hay quarantine, base của revision vẫn là head phục vụ) rồi mới cập nhật head. Base đã đổi thì trả `revision_conflict` và cần đề xuất lại. Resource đổi sau khi duyệt thì approval không còn dùng được.
  - **Từ chối** đưa revision về `rejected`; head và pin không đổi.
  - File được tham chiếu gián tiếp như một lệnh (một file văn bản gọi tới file khác) được xếp như script trực tiếp.
- **Skill là dữ liệu, không phải lệnh.** Gói context đánh dấu rõ điều này. Skill không cấp thêm quyền cho harness và không thay cổng duyệt.
- **Nhãn nguồn:** mỗi phiên bản skill mang `source` do server gán theo kênh nhận, như mục 8.2. Skill do agent viết luôn là `agent_reported`.
- **Quan hệ với bài học:**
  - Bài học kỹ thuật (lỗi → cách sửa) có skill liên quan được ghi thành một mục trong phần cạm bẫy của skill đó. Mục này mang nhãn nguồn riêng; có proof `tool_observed` theo mục 8.2 thì ghi nhãn đó.
  - Bài học sở thích và quy ước (`claim_type=preference`), và bài học kỹ thuật không gắn được skill nào, vẫn là bài học đứng riêng theo mục 8.1–8.5.
- Giới hạn kích thước của `SKILL.md` và resource chốt trước SP3 (mục 19).

### 8.7 Ba phạm vi và thăng hạng

| Phạm vi | Ai được phục vụ | Cách vào | Điều kiện |
|---|---|---|---|
| `project` | Mọi harness có quyền trên đúng repo sinh ra skill | Agent ghi qua `submit_episode`, hoặc lượt rà soát (mục 8.10) | Qua privacy filter. Hiệu lực ngay chỉ áp dụng cho revision thuần văn bản; revision có script chờ duyệt theo mục 8.6. Mang nhãn `agent_reported` và "chưa thăng hạng". Kiểm tra nội dung riêng của dự án chỉ cảnh báo |
| `owner` | Mọi repo của cùng `owner_id` | Thăng hạng từ `project`, hoặc nhập danh mục | Approval `skill_promote` (mục 11.3). Kiểm tra nội dung riêng của dự án là bắt buộc |
| `public` | Người ngoài, qua gói công khai | Xuất từ `owner` | Approval `skill_publish` ở mức rủi ro cao; lọc lại; có giấy phép (O1) |

- **Có hiệu lực ngay ở `project`.** Revision thuần văn bản vừa ghi được đưa cho mọi harness trên repo đó từ lần `prepare_task` kế tiếp, không chờ duyệt và không qua ChangeProposal.
- **Ra ngoài repo gốc phải qua duyệt.** Principal ở repo khác không thấy skill `project` qua `prepare_task`, `search_knowledge` hay đọc theo ref. Sai phạm vi trả `not_found`, kể cả khi caller biết ID và revision.
- **Duyệt gộp.** Một approval có subject là một lô gồm ref đầy đủ `(skill_id, revision_epoch, revision, digest)` của từng mục (mục 8.8). Đổi bất kỳ mục nào trong lô thì approval đó không còn dùng được. Một revision xuất hiện sau restore với cùng số và cùng digest nhưng khác `revision_epoch` là một mục khác, nên approval cũ không áp dụng cho nó. Hàng đợi duyệt xếp trước các skill đã được dùng lại thành công trong repo gốc.
- **Kiểm tra nội dung riêng của dự án** tìm đường dẫn tuyệt đối, tên repo, tên máy và định danh nội bộ. Đây là luật theo mẫu, không hiểu ngữ nghĩa.
- **Lineage:** skill mang lineage của task sinh ra nó (mục 14.2). Thăng hạng chia sẻ nội dung skill, không chia sẻ evidence nguồn (Q12).
- **Skill từ ngoài vào** (gói công khai, danh mục nhập) là skill bên thứ ba và theo quy tắc nhập ở mục 14.1.
- **Thu hồi và quarantine** theo digest có hiệu lực ở mọi phạm vi và với mọi bản đã ghim. Gói đã phát hành xử lý theo phần dưới đây.

**Xuất gói công khai** (phạm vi `public`):
- Gói công khai là một đích ra ngoài riêng (mục 14.2).
- Approval `skill_publish` ghim: đúng bytes đã lọc của từng resource, manifest của gói, digest từng resource, và đối tượng nhận (kho công khai nào).
- Trước khi xuất, brain kiểm cho từng resource: lineage, trạng thái thu hồi và quarantine hiện hành, và quyền phân phối (nguồn gốc và giấy phép). Resource có nguồn hoặc quyền phân phối chưa xác minh được thì bị chặn; gói không được xuất thiếu kiểm tra này.
- Gói không chứa ref tới evidence, task, checkout hay định danh nội bộ nào.
- **Định danh công khai.** Mỗi skill trong manifest mang một định danh công khai ổn định, gắn với đúng phiên bản bytes đã xuất: tên công khai và digest của bytes đã lọc. Định danh này không chứa `skill_id` hay `revision_epoch`.
- **Hồ sơ xuất** nằm trong policy store, nên sống qua restore kho chính. Nó được ghi bền **trước khi gói có thể được nhận**, dưới dạng một intent xuất gồm: manifest đã duyệt, đích nhận, định danh công khai của từng skill, và ánh xạ từ ref đầy đủ cùng **digest của từng resource nguồn** sang định danh công khai và digest bytes đã xuất. Ánh xạ theo từng resource là cần thiết vì quarantine áp theo digest của từng blob.
- Crash sau khi ghi intent mà chưa rõ gói đã ra ngoài hay chưa: các định danh công khai trong intent được giữ ở trạng thái **có thể đã xuất**, và được xử lý như đã xuất trong mọi việc thu hồi.
- **Ngay trước khi publish**, brain kiểm cả closure của gói mới lẫn danh sách thu hồi hiện hành. Danh sách thu hồi đã đổi so với manifest đã ký thì manifest phải được dựng và duyệt lại; gói không được xuất với manifest thiếu mục thu hồi.
- Resource bị thay sau khi duyệt thì approval không còn dùng được.
- **Phạm vi thu hồi:** brain không lấy lại được bytes đã phát hành. Thu hồi hoặc quarantine một skill, hoặc một resource thành phần của nó, chặn mọi lần xuất sau, và đưa định danh công khai của mọi bản đã xuất của skill đó vào danh sách thu hồi trong manifest của lần xuất kế tiếp. Việc tra dùng hồ sơ xuất chứ không dùng kho chính, nên vẫn đúng khi kho chính đã bị restore về trước lần xuất.
- Restore policy store có thể làm mất hồ sơ xuất. Khi đó brain chặn lần xuất kế tiếp cho tới khi chủ dự án đối soát với gói đã phát hành.

### 8.8 Nhóm skill, phiên bản, biến thể và ghim

Mục này quy định việc xử lý khi một harness khác, ở dự án khác, có cách giải tốt hơn cho cùng loại vấn đề.

- **Không ghi đè.** Mỗi thay đổi tạo phiên bản mới; phiên bản cũ vẫn đọc được theo ref.
- **Ref bất biến qua restore.** Ref của một phiên bản skill là `(skill_id, revision_epoch, revision, digest)`. `revision_epoch` là `restore_epoch` lúc commit phiên bản đó (mục 5.7); `digest` phủ toàn bộ resource. Đây là cùng quy tắc với sổ bàn giao (mục 7.4).
  - Ref này đi qua Delivery, `search_knowledge`, `get_artifact`, SkillPin, `skill_patch`, approval, ServedReceipt, ReadAck, SkillUsage và lineage. Không chỗ nào dùng riêng số `revision`.
  - Sau restore, số `revision` có thể lặp lại với nội dung khác. Ref của phiên bản không còn trong kho trả `not_found`; nó không bao giờ được phục vụ bằng nội dung của phiên bản mới trùng số. Receipt, usage, pin và lineage của phiên bản cũ không bị gán sang phiên bản mới.
  - **Mất pin sau restore.** Trước khi hoán đổi, restore dựng tập dấu mất pin cho bản đang dựng, khóa theo (repo, nhóm skill, ref bị mất), từ hai nguồn: các dấu chưa xử lý đang có ở kho sống, và dấu mới cho từng pin hiện hành của kho sống mà ref không có trong bản đang dựng. Tập này thay cho mọi dấu nằm sẵn trong snapshot. Trạng thái xử lý hiện hành của kho sống là căn cứ: dấu đã được xử lý không bị dựng lại từ snapshot cũ, và dấu chưa xử lý không mất qua các lần restore lặp. Tập dấu được ghi cùng bản đang dựng và có hiệu lực khi bản đó được công bố (mục 5.7). Nhờ vậy vẫn có dấu cả khi snapshot không chứa pin lẫn revision.
  - Repo có dấu mất pin chọn theo cách của repo chưa ghim cho nhóm đó, và `prepare_task` báo `skill_pin_lost` trong `degraded_codes` cho tới khi repo ghim lại hoặc xác nhận bỏ pin bằng `skill_pin`.
  - Khi restore mà không còn kho sống để so, không có gì để dựng dấu; repo khi đó ở trạng thái chưa ghim.
  - Skill chỉ có từ SP3, nên không có dữ liệu skill legacy thiếu `revision_epoch`. Artifact nhập từ danh mục dùng cùng ref này.
- **Head theo phạm vi.** Head của một skill được xác định theo (nhóm, biến thể, phạm vi, repo). Phạm vi `owner` có một head; mỗi repo có head `project` riêng. Head ở đây là head phục vụ: revision chờ duyệt không bao giờ là head (mục 8.6).
- **Bản vá.** Agent đã nạp skill rồi làm khác đi thì gửi `skill_patch` kèm `base_ref`, là ref đầy đủ đã đọc. Server so `base_ref` với head hợp lệ **trong phạm vi mà repo đó được đọc**. Không khớp thì trả `revision_conflict` và không tạo phiên bản. Agent đọc lại rồi gộp; server không tự gộp.
- **Vá skill phạm vi `owner` từ một repo** là một lần fork. Lần vá đầu so `base_ref` với head `owner` rồi tạo phiên bản đầu ở phạm vi `project` của repo đó. Các lần vá kế tiếp của repo đó so với head `project` của chính nó.
  - Hai repo fork cùng một base không xung đột nhau. Không repo nào bị từ chối vì một phiên bản mà nó không có quyền đọc.
  - Phiên bản `project` mới đọc được ngay tại repo đó và là ứng viên thăng hạng.
  - Head `owner` và hành vi ở các repo khác không đổi cho tới khi được duyệt.
- **Lineage của phiên bản mới** kế thừa lineage của mọi parent được dùng để dựng nội dung: base của bản vá và các biến thể được gộp. Điều này đúng cả khi task tạo bản vá chưa có ServedReceipt của parent (mục 14.2).
- **Nhóm skill và biến thể.** Cách làm khác hẳn cho cùng loại vấn đề được ghi thành biến thể trong cùng một nhóm skill: agent khai `variant_of`, hoặc bước gộp trùng đề xuất xếp chung nhóm và đưa vào hàng đợi duyệt. Các biến thể cùng tồn tại. Server không tự gộp hai skill.
- **Ghim theo repo (SkillPin).** Pin là điều kiện chọn, không phải điểm cộng. Pin áp dụng ở hai chỗ: khi đề cử trong `prepare_task`, và khi nạp theo Delivery (mục 8.11). Đọc tường minh theo ref không chịu pin.
  - Với nhóm skill mà repo đã ghim, bộ lọc chỉ đưa đúng ref đã ghim và loại mọi ứng viên khác của nhóm đó trước khi xếp hạng (mục 9).
  - Pin chỉ đổi khi repo nhận bản khác một cách tường minh qua `submit_episode`: `skill_patch` hoặc `skill_draft` kèm `adopt`, hoặc `skill_pin` đứng riêng. Bản vá không kèm `adopt` tạo phiên bản mới mà không đổi pin.
  - Repo chưa ghim dùng head `project` của chính nó nếu có; không có thì dùng bản mặc định `owner` của nhóm.
- **Hồ sơ sử dụng (SkillUsage).** Mỗi phiên bản và biến thể ghi số lần được đưa, được nạp (ServedReceipt, ReadAck), kết quả task và số lần người dùng sửa, tách theo harness, OS và repo. Các mức đã chọn, đã gửi, client xác nhận nhận đủ, agent khai đã áp dụng và quan sát được không bao giờ gộp làm một.
- **Bản mặc định của nhóm.** Khi dữ liệu còn ít, hệ thống không tự đổi bản mặc định. Lượt rà soát (mục 8.10) có thể soạn bản gộp của hai biến thể và đưa vào hàng đợi duyệt, kèm diff hai bên. Đổi bản mặc định ở phạm vi `owner` luôn qua duyệt. Ngưỡng đủ dữ liệu để đề xuất đổi chốt trước SP4.
- **Nghỉ.** Biến thể lâu không được dùng chuyển sang `dormant` và không còn được đưa ra; không bị xóa. Ngưỡng chốt trước SP4.
- Bảng trạng thái đầy đủ của skill chốt trước SP3 (mục 19).

### 8.9 Đường tạo skill

- **Ba thời điểm**, cài vào file hướng dẫn của harness qua bootstrap:
  1. agent tìm ra một quy trình nhiều bước chạy được;
  2. agent gặp lỗi rồi tìm được đường đúng;
  3. người dùng sửa cách làm của agent.
- **Tìm trước khi tạo.** Agent gọi `search_knowledge`. Có skill phù hợp thì vá; không có thì tạo mới.
- **Đường ghi.** `submit_episode` với `skill_draft` (skill mới, tùy chọn `variant_of`) hoặc `skill_patch` (kèm `base_ref`, mục 8.8). Mỗi lần ghi là một transaction cùng Episode và bản ghi idempotency (mục 6.3). Nguồn luôn là `agent_reported`.
- **Lọc phạm vi trước.** Gộp trùng, resolve `variant_of`, kiểm `base_ref` và dựng danh sách skill gần giống chỉ xét các skill mà principal và repo đó được đọc. Kết quả không bao giờ chứa ref của skill `project` thuộc repo khác.
- **Privacy filter** chạy trước khi ghi bền vững. Filter từ chối thì không lưu gì của lần ghi đó và trả lỗi có mã.
- **`manual_submission` tắt:** không lưu, trả `skill_status=not_stored_policy`, không tạo phiên bản. Retry cùng khóa trả đúng kết quả đó.
- **Kết quả** trả ref đầy đủ của phiên bản vừa ghi, `skill_status`, phạm vi, trạng thái pin của repo, và ref của các skill gần giống mà bước gộp trùng tìm thấy.
  - `skill_status` là `stored`, `pending_approval` (draft có script, mục 8.6; kèm ref của proposal) hoặc `not_stored_policy`.
- Việc ghi ở ba thời điểm là do **model tự giác**; server không ép được. Hook, khi harness có, chỉ nhắc và không bao giờ chặn.

### 8.10 Rà soát sau phiên (Q23)

Mục đích: soạn skill khi agent quên ghi, hoặc khi phiên dừng đột ngột.

- **Khi nào.** Phiên ở trạng thái `ended` hoặc `in_progress_unknown` (mục 7.4), task chưa có skill do agent ghi và chưa có dấu rà thành công, và phần quan sát cho thấy có chất liệu: lỗi đã được sửa, hoặc lời người dùng sửa agent. Agent cũng có thể yêu cầu bằng `request_improvement`.
- **Cách chạy.** Daemon tạo một Job (mục 6.4). Job gọi harness ở chế độ không giao diện với một prompt cố định có phiên bản.
  - **Đầu vào.** Có hai nhánh gửi. Cả hai dùng chung các điều kiện cho từng mục:
    - có nguồn thuộc đúng `task_id` và `session_ref` của phiên được rà;
    - provenance xác minh được: ref và digest của mục, đoạn phiên, và lời gọi model đã xác minh mà mục đó nằm trong;
    - có bằng chứng tiếp xúc `sent_to_recipient` (mục 7.2);
    - thuộc loại nội dung được phép: lượt hội thoại đã lọc, và mục quan sát của sổ bàn giao dựng từ những Event như vậy.
    - hồ sơ người nhận của đoạn phiên nguồn và của lượt rà đều xác minh được đầy đủ, gồm harness, hồ sơ provider và account. Hồ sơ nguồn có trường `unknown` làm mục đó bị loại. Hồ sơ đích có trường `unknown` chặn lượt gọi và chuyển sang nhánh dự phòng.

    **Luôn bị loại, ở cả hai nhánh:** mục `local_only` hoặc `unknown`, ví dụ Event mà hook thu sau lời gọi model cuối, hoặc mục mà lần gửi lỗi hay chưa rõ kết quả; phần agent khai của sổ, kể cả patch do chính phiên đó ghi; trạng thái gộp của sổ; mục có nguồn từ phiên khác, kể cả Event đến muộn của harness trước trên cùng task; mục thiếu provenance. Gửi các loại này sẽ là một lần tiết lộ mới và cần quyết định policy riêng; rev này không cho phép.
  - **Nhánh gửi lại** (mặc định). Hồ sơ nguồn khớp đầy đủ hồ sơ đích. Bằng chứng tiếp xúc xác nhận đúng mục đã tới người nhận đó.
  - **Nhánh người nhận mới đã duyệt.** Hồ sơ nguồn và đích có thể khác nhau. Cần approval hoặc policy hiện hành cho **đúng đích đó** trên repo (mục 14.2), và `provider_egress` hiện hành của mọi nguồn trong lineage của từng mục. Chỉ các mục đạt đủ điều kiện mới được gửi.

    Ref nguồn và lineage của từng mục được giữ trong metadata nội bộ của Job và ProviderInvocation; chúng không nằm trong payload gửi đi. Ngay trước mỗi lần gửi, brain kiểm quyền đọc, tombstone, quarantine và policy hiện hành của **từng** nguồn.
  - **Đầu ra:** văn bản theo định dạng cố định, do Job nhận. Job đưa nó qua privacy filter và đường ghi ở mục 8.9, với actor `system:worker:skill-review`, nhãn `agent_reported` và đánh dấu là kết quả rà soát.
- **Ràng buộc:**
  - **Chỉ đọc là điều kiện khởi chạy.** Daemon chỉ spawn harness qua một adapter có cơ chế giới hạn quyền ghi và công cụ, và chỉ khi trạng thái là `verified` cho đúng bộ (OS, phiên bản harness, lệnh, digest cấu hình của hồ sơ chạy). Trạng thái `unknown` hoặc `unsupported`, hoặc bất kỳ thành phần nào của bộ đó đã đổi: **không spawn process nào**, và đi nhánh dự phòng kèm lý do. Cờ `post_session_review` bật là chưa đủ để chạy.
    - Hồ sơ chạy giới hạn quyền ghi vào một vùng tạm dành riêng cho job, không phải checkout, và tắt các công cụ không cần cho việc soạn văn bản. Hồ sơ chạy cũng chỉ cho đọc đầu vào đã được cấp.
    - Process của harness không thừa hưởng môi trường của daemon: không có credential của brain, không có đường dẫn data root. Nó chỉ có đúng quyền và credential mà lời gọi của harness cần.
    - `verified` cần NativeHostReceipt ghi rõ hồ sơ chạy và các phép kiểm đã quan sát, gồm ca transcript dụ harness ghi ra ngoài vùng tạm bằng đường dẫn tuyệt đối, và ca dụ harness đọc một file ngoài đầu vào bằng đường dẫn tuyệt đối (mục 17.3).
    - Lượt rà soát không chạy lại task và không sửa file dự án, nên không phải Probe (Q11).
  - **Lệnh cố định.** Lệnh gọi harness nằm trong cấu hình được duyệt ở mức rủi ro cao qua bootstrap (mục 11.2). Daemon không chạy lệnh nào khác.
  - **Người nhận.** Lượt rà soát chỉ gửi theo một trong hai nhánh nêu ở phần đầu vào. Không mục nào có người nhận hợp lệ thì đi nhánh dự phòng.
  - **Có trần.** Số lượt mỗi ngày có trần, chốt trước SP4. Mỗi lời gọi ghi một ProviderInvocation; harness không báo chi phí thì ghi `unknown`. Reservation và số lượt nằm ở tầng accounting sống qua restore (mục 5.7).
  - **Theo cờ.** Cờ `post_session_review` hoặc `manual_submission` của repo tắt thì không chạy, vì kết quả sẽ không được lưu.
- **Admission và commit:**
  - Trigger tự động và `request_improvement` dùng chung một admission.
  - **Một slot theo task.** Mỗi task có tối đa một Job rà soát đang chờ hoặc đang chạy. Yêu cầu mới cho task đang có Job nhận lại đúng Job đó, kể cả khi cửa sổ nguồn của yêu cầu mới khác.
  - **Khóa cửa sổ.** Mỗi Job ghim digest của toàn bộ cửa sổ nguồn, tức danh sách ref của các Event đủ điều kiện làm đầu vào. Một watermark đơn lẻ là chưa đủ, vì Event đến muộn có thể chen vào giữa. Retry cùng cửa sổ nhận lại Job và reservation đã ghi khi chúng còn trong kho, theo quy tắc về dấu rà soát sau restore bên dưới.
  - **Mỗi task có tối đa một kết quả rà thành công.** Lần commit thành công ghi dấu theo `task_id` và binding đã xác minh, kèm ID Job, digest cửa sổ và ref kết quả. Dấu chỉ chứa metadata. Nó chặn mọi cửa sổ tiếp theo ở admission, trước khi gọi và khi commit, kể cả Event đến muộn. Kiểm dấu trong chính transaction commit ngăn hai Job cùng ghi kết quả.
  - **Trước khi gọi harness**, Job kiểm lại: phiên vẫn ở trạng thái đủ điều kiện, còn chất liệu, task chưa có skill do agent ghi và chưa có dấu thành công, hai cờ còn bật, và trạng thái `verified` còn đúng.
  - **Khi commit**, trong cùng transaction với Episode, skill, dấu thành công và kết quả Job, server so lại binding và điều kiện ghi: phiên không hoạt động lại kể từ cửa sổ đã ghim, agent chưa tự ghi skill cho task kể từ đó, task chưa có dấu thành công, và hai cờ còn bật.
  - **Không đạt điều kiện:** không ghi skill và không ghi dấu thành công. Job vào trạng thái cuối `cancelled` với lý do `discarded` kèm mã cụ thể, và trả slot. Accounting thực tế của lượt đã gọi được giữ nguyên, như mọi job đã hủy (mục 6.4).
  - **Cửa sổ mới** chỉ được xét khi task chưa có dấu thành công: Job trước đã `cancelled`, slot trống, phiên vẫn đủ điều kiện, và cửa sổ có chất liệu mới so với cửa sổ của Job trước. Retry cùng cửa sổ có thể trả cả Job đã kết thúc.
  - Crash sau commit không tạo skill thứ hai: phục hồi và retry tìm thấy kết quả theo khóa cửa sổ và dấu thành công.
- **Dấu rà soát qua restore.** Ở bước 5 mục 5.7, bản đang dựng lấy hợp các dấu thành công và dấu lịch sử không xác minh được từ snapshot và kho sống. Dấu thành công được ưu tiên nếu một task có cả hai. Giữ dấu theo đúng task và binding, kể cả khi task tạm vắng trong snapshot, để lần restore sau vẫn nhận ra task đó. Migrate và rebuild giữ các dấu này.
  - Sau khi kiểm binding và quyền, xét dấu rà soát trước khi dùng slot hoặc khóa cửa sổ. Khi có dấu thành công, yêu cầu rà mới trả Job cũ nếu Job đó còn ở `succeeded`, khớp ref kết quả ghi trong dấu và ref vẫn còn trong kho. Nếu snapshot thiếu Job thành công hoặc kết quả tương ứng, trả `skill_review_result_lost` kèm `job_id` trong dấu. Cả hai trường hợp đều chặn tạo Job mới. Replay còn bản ghi idempotency giữ `job_id` đã commit theo mục 6.3 và áp các kiểm tra trạng thái, quyền và policy hiện hành khi dựng kết quả.
  - Với task trong bản đang dựng chưa có dấu thành công, nếu không xác minh được đúng task và binding trong kho sống thì ghi dấu `skill_review_history_unknown` cùng snapshot. Quy tắc này áp dụng cả khi mất kho sống và khi restore lần sau đưa trở lại task vắng trong kho sống. Dấu chặn trigger tự động và `request_improvement`. Yêu cầu qua tool trả mã đó. Task tạo mới sau restore theo admission thông thường.
  - Trước khi mở hàng đợi sau restore, đưa Job rà soát đang chờ hoặc đang chạy trong snapshot về `cancelled` nếu task đã có dấu thành công hoặc dấu lịch sử không xác minh được. Accounting đã ghi vẫn giữ nguyên. Hai dấu được kiểm ở admission, trước khi gọi và khi commit. `prepare_task` báo `skill_review_result_lost` hoặc `skill_review_history_unknown` trong `degraded_codes` khi đang làm đúng task có trạng thái đó.
- **Dự phòng.** Khi không chạy được (cờ tắt, trạng thái chưa `verified`, không có người nhận hợp lệ, hết quota, vượt trần, bị chặn chờ đối soát accounting), `prepare_task` của phiên kế tiếp trên checkout trả mã `skill_review_pending` kèm đối tượng `skill_review`: `task_id`, `session_ref`, digest cửa sổ nguồn, `reason`, và `material_refs` của đúng binding. Agent của phiên đó tự ghi skill theo mục 8.9.
  - Khi `manual_submission` tắt, agent dự phòng cũng không ghi được. Khi đó `skill_review` chỉ mang `reason=blocked_by_policy`, không có `material_refs`, và không yêu cầu agent ghi.
- **Trạng thái theo harness:** `unknown`, `unsupported` hoặc `verified`, tính cho đúng bộ nêu ở ràng buộc chỉ-đọc. Khảo sát và xác minh từng harness thuộc SP4 (O9).
- **Giới hạn được công bố:**
  - Chất lượng skill do lượt rà soát soạn chưa được kiểm chứng. Skill đó mang cùng nhãn và cùng điều kiện thăng hạng như skill agent viết.
  - `verified` chỉ chứng minh cho đúng bộ đã kiểm. Harness đổi phiên bản hay cấu hình thì trạng thái về `unknown` và lượt rà soát dừng cho tới khi kiểm lại, nên với harness tự cập nhật thường xuyên, nhánh dự phòng có thể là nhánh chạy chủ yếu.
  - Lượt rà soát dùng quota của người dùng.

### 8.11 Phân phối skill

Skill chỉ được phân phối qua MCP (Q25).

- `prepare_task` trả L0 của các skill phù hợp, kèm phạm vi và nhãn nguồn. Agent tự quyết nạp skill nào bằng `get_artifact`. Mỗi lần nạp có ServedReceipt, và ReadAck khi client xác nhận.
- Đường này không ghi vào cấu hình hay thư mục nào của harness, nên skill `project` không cần cổng duyệt của kênh tĩnh, và pin, thu hồi, quarantine có hiệu lực ngay ở lần cấp kế tiếp.
- **Hai cách đọc skill qua `get_artifact`:**
  - **Nạp theo Delivery.** Request mang `delivery_id` và `skill_ref` đầy đủ của đúng mục muốn nạp. Trước khi đọc CAS, kể cả khi replay, server kiểm Delivery của đúng task, principal và scope, rồi kiểm ref có trong danh sách đã đề cử. Sai binding hoặc ref ngoài danh sách trả `not_found`. Ref trong danh sách vẫn phải đủ điều kiện hiện hành của repo, gồm pin, thu hồi và quarantine. ServedReceipt ghim đúng Delivery và ref đã cấp. Chỉ nhánh này được tính là nạp skill cho SkillUsage và M2.
  - **Đọc tường minh.** Request mang `skill_ref` đầy đủ và bỏ `delivery_id`. Server kiểm ACL theo phạm vi, trạng thái và quarantine của đúng ref. Nhánh này dùng để xem lại hoặc vá revision. Pin chỉ áp dụng ở nhánh nạp theo Delivery. ServedReceipt ghi rõ đây là lượt đọc tường minh.
- **Delivery cũ sau khi pin đổi.** Delivery là lịch sử: ID và danh sách ref đã đề cử giữ nguyên. Khi pin hiện hành đã đổi, lần nạp theo Delivery cũ, kể cả retry cùng khóa, trả `{status: "no_longer_eligible"}` cho ref không còn là ref ghim, vẫn giữ ID. Nó không cấp nội dung đó như bản đang ghim. Agent gọi `prepare_task` mới để nhận ref hiện hành.
- **Kích hoạt và proposal.** `skill_activate` chỉ đổi trạng thái trong kho; nó không tạo file nào trong thư mục của harness. Một ChangeProposal có file đích nằm trong thư mục skill của harness bị từ chối trước khi tới cổng duyệt.
- Q25 nói về đường cấp skill cho harness đang làm việc. Xuất gói công khai có cổng riêng (mục 8.7).
- **Brain không ghi skill vào thư mục skill của harness** ở bất kỳ luồng nào. Đường cài gốc có trong rev 17 đến rev 19 đã bị bỏ theo quyết định của chủ dự án ngày 2026-11-10: harness tự nạp file trong thư mục skill mà không hỏi brain, nên muốn giữ đúng pin và quarantine thì harness phải có một cổng nạp mà chưa harness nào được biết là có (SB2-R17-06, SB2-R18-03).
- Hệ quả được công bố: skill của brain không dùng được khi daemon không chạy, và không đi qua cơ chế tự chọn skill sẵn có của harness.
- Skill mà người dùng tự đặt trong thư mục skill của harness nằm ngoài brain. Brain không quản lý, không ghim và không thu hồi được chúng.

**Thay đổi contract** (áp dụng ở task đầu của SP3; tên định nghĩa trong schema chốt trong plan SP3):
- **Ref skill** ở mọi chỗ trong contract là ref đầy đủ `(skill_id, revision_epoch, revision, digest)` (mục 8.8). `get_artifact` với skill bắt buộc có `revision_epoch`.
- Input của `submit_episode`: thêm `skill_draft`, `skill_patch` và `skill_pin`. `skill_patch` bắt buộc có `base_ref`. `skill_draft` và `skill_patch` có tùy chọn `adopt`.
- Result của `submit_episode` có ba nhánh, chỉ phát khi request có `skill_draft`, `skill_patch` hoặc `skill_pin`:
  - **Có revision mới** (`skill_status` là `stored` hoặc `pending_approval`): ref đầy đủ của revision vừa ghi, `skill_scope`, trạng thái pin, và `similar_skill_refs` đã lọc theo phạm vi. Với `pending_approval` thêm `proposal_ref`. Đây là metadata của lần ghi, trả cho chính người ghi; nó không phải nội dung của revision.
  - **Chỉ đổi pin** (`skill_pin` đứng riêng): trạng thái pin trước và sau; không có ref của revision mới.
  - **`not_stored_policy`:** chỉ có `skill_status`; không có ref và không đổi pin.
- Result của `prepare_task` (`mode=work`) và của `search_knowledge`: item skill mang ref đầy đủ, `scope`, `source` và cờ đã thăng hạng hay chưa. `degraded_codes` thêm `skill_review_pending` và `skill_pin_lost`.
- Input của `get_artifact` với skill: `skill_ref` đầy đủ là bắt buộc. Có `delivery_id` thì nạp mục đó từ Delivery, vắng `delivery_id` thì đọc tường minh. Result thêm `no_longer_eligible` cho mục đã đề cử nhưng không còn là ref ghim. ServedReceipt ghi cách đọc.
- Input của `request_improvement`: thêm loại Job rà soát skill, dùng chung admission với trigger tự động. Các mã `skill_review_result_lost` và `skill_review_history_unknown` áp dụng từ SP4 theo mục 8.10.
- Result của `prepare_task` (`mode=work`): khi có mã `skill_review_pending`, thêm đối tượng `skill_review` gồm `task_id`, `session_ref`, digest cửa sổ nguồn, `reason` và `material_refs`. Với `reason=blocked_by_policy` thì không có `material_refs`.
- Nội dung của revision `pending_approval` không được phục vụ qua `prepare_task`, `search_knowledge` hay `get_artifact` (trả `not_found`). ACK của chính lần ghi vẫn trả metadata nêu ở trên. `adopt` kèm draft chờ duyệt không đổi pin; result ghi rõ điều đó.
- Đổi `x-implemented-in`, `x-side-effects` và fixture của các tool trên phải sửa các file đang nằm trong seal, nên cần reviewer độc lập duyệt reseal.

## 9. Bộ chọn: lọc tại máy → model của harness; Jev tùy chọn

**Đối tượng được chọn:** skill, bài học, hướng dẫn tool (c4), persona/finishing gates. File context (mục 10) đang hoãn.

**Mặc định (Q1):** brain chạy bước 1, 2, 6 và 7 dưới đây, rồi trả L0 của danh sách đã lọc. Model của harness quyết định nạp mục nào bằng `get_artifact`. Khi Jev tắt, danh sách trả về mặc định tối đa 10 skill và 10 bài học trong ngân sách context; hai con số này đo lại ở SP3 (O5).

**Jev là tùy chọn, mặc định tắt.** Bước 3, 4 và 5 chỉ chạy khi Jev được bật cho kho. Bật Jev là `policy_change`, chỉ sau khi phép so sánh offline (mục 12.2) cho thấy Jev chọn tốt hơn bộ lọc tại máy trên dữ liệu của chính kho này.

1. **State:** mô tả task, hồ sơ repo, harness, OS, khả năng của harness.
2. **Lọc tại máy, mục tiêu dưới 50 ms:**
   - Loại cứng: không tương thích khả năng, không `active`, đang quarantine, ngoài phạm vi mà repo được đọc. Với nhóm skill mà repo đã ghim, chỉ giữ đúng ref đã ghim (mục 8.8).
   - Chấm điểm: BM25 trên L0, khớp nhãn, lợi ích đã đo, độ mới, hồ sơ sử dụng.
   - Mặc định tối đa 40 skill, 40 bài học, 20 file. Phần file đang hoãn (mục 10).
   - **Tách hai tập:**
     - *được đưa tại máy*: mọi ứng viên còn lại;
     - *được gửi cho Jev*: tập con mà policy `provider_egress` hiện hành của toàn bộ lineage cho phép (mục 14.2).
3. **Gọi Jev** (chỉ khi Jev bật; chỉ với tập được gửi, chỉ với trường trong allowlist):
   - **Request 1:** Choice trên các skill ứng viên; Noul cổng ("cần skill không?", "cần quy trình không?", "chỉ cần trả lời bằng chữ?"); mỗi bài học và mỗi file ứng viên một câu Noul "có liên quan không?" (phần file đang hoãn, mục 10).
   - **Request 2:** sắp xếp lại top 3 skill bằng mô tả đầy đủ, kèm Noul "có đúng việc này không?".
   - Request 1 thành công nhưng request 2 quá hạn → dùng kết quả request 1, ghi trace.
   - Ngưỡng confidence mặc định 0,30 (theo cookbook), chỉnh lại sau khi đo. Được phép chọn **không skill nào**.
4. **Ứng viên chỉ-tại-máy** (không được gửi cho Jev) được rules chấm bằng điểm lọc ở bước 2 với ngưỡng cố định, rồi gộp với kết quả Jev trong cùng giới hạn số lượng. Payload Jev và trace không chứa nội dung của chúng, chỉ ID trong trace.
5. **Chuyển toàn bộ sang rules** khi Jev lỗi, quá deadline, chạm trần (nếu người dùng đặt), policy cấm, hoặc trả lời không hợp lệ.
   - Câu trả lời được kiểm tra chặt: đủ câu hỏi, đúng kiểu, đúng khoảng giá trị.
6. **Kiểm tra lại** eligibility, trạng thái duyệt và thu hồi ngay trước khi ghi Delivery.
7. **Áp holdout** (mục 12).

**Vận hành Jev:**
- Chốt model `jev-1.14.0`; nâng phiên bản là thay đổi có chủ đích.
- **Cache:**
  - Key gồm model, phiên bản selector, phiên bản prompt/schema, `policy_epoch`, digest state, digest ứng viên.
  - `policy_epoch` tăng khi có revoke, đổi trạng thái bài học, hoặc đổi policy, nên kết quả cache cũ tự mất hiệu lực.
- **Retry:** 429/529 retry với backoff, nằm trong deadline.
- **Lời gọi đến muộn:**
  - Không bao giờ thay đổi Delivery đã chốt.
  - Chi phí vẫn được ghi vào ProviderInvocation.
  - Thiếu usage → chi phí `unknown`, không ghi 0.
- **Ngân sách theo Q2.**
  - Mặc định không trần nhưng luôn có giới hạn số lời gọi đồng thời và hàng đợi.
  - **Giữ chỗ** mỗi lời gọi bằng **chi phí tối đa** của một request = trần kích thước request (mặc định 64k token) × giá input đã ghim (token output miễn phí). Với giá hiện tại, con số này khoảng $0,0027.
  - Usage `unknown` giữ nguyên mức giữ chỗ tối đa cho tới khi đối soát được.
  - Phần giữ chỗ, số lời gọi đã gửi và chi phí theo kỳ nằm ở tầng accounting trong policy store, ghi trước khi gửi, nên restore kho chính không làm chúng quay lui (mục 5.7).
  - Khi người dùng đặt trần:
    - kỳ ngân sách là tháng dương lịch (UTC);
    - từ 80% thì tắt câu hỏi nền; đến 100% thì chuyển toàn bộ sang rules.

    Trần bị vượt tối đa bằng (số lời gọi đang chạy × chi phí tối đa mỗi request). Bảo đảm này chỉ đúng khi giá và cách tính tiền của nhà cung cấp khớp với giá đã ghim. `doctor` và `brain report` cảnh báo khi usage thực lệch khỏi giá đã ghim.
- Tắt `provider_egress` cho repo, hoặc thu hồi bài học, có hiệu lực với cả job đang chờ và lời gọi chưa gửi.
- **Thứ tự làm:** pipeline chạy bằng bộ lọc tại máy trước (SP3). Jev thuộc SP5 và chỉ bật theo điều kiện ở đầu mục này.

## 10. Context L0/L1/L2

**Phạm vi ở rev 17.** Cấu trúc ba cấp L0/L1/L2 áp dụng cho skill (mục 8.6), bài học và sổ bàn giao (mục 7.4). Phần index file của checkout dưới đây (index, hai loại địa chỉ, bảng cấp cho file, khung AST, độ mới, ranh giới filesystem) **hoãn vô thời hạn** và không thuộc dự án con nào ở mục 15. Nội dung được giữ làm thiết kế tham chiếu. Harness tự tìm và đọc code của dự án. Cờ `indexing` (mục 14.2) không có tác dụng cho tới khi phần này được làm.

- **Index:** các checkout đã đăng ký, khi cờ `indexing` của repo bật. Tôn trọng `.gitignore` và danh sách đường dẫn cấm. `.gitignore` không thay thế privacy policy: nội dung L0/L1 cũng đi qua privacy filter. Skill và artifact cũng có L0/L1.
- **Hai loại digest:**
  - `source_digest`: digest của bytes nguồn.
  - `repr_digest`: digest của bản L0/L1 đã lọc hoặc parse, kèm `builder_version`.

  Mọi biểu diễn L0/L1/L2 đều gắn với `source_digest` mà nó được dựng từ đó.
- **Hai loại địa chỉ:**
  - **Live:** `brain://context/{repo_id}/{checkout_id}/{path}#l0|l1|l2`. Phân giải tới nội dung hiện tại.
  - **Immutable:** `brain://context/{repo_id}/{checkout_id}/{path}@sha256:{source_digest}#l0|l1|l2`. Trỏ đúng bytes nguồn đã dùng; dùng trong Delivery và receipt.

| Cấp | Nội dung | Giới hạn |
|---|---|---|
| L0 | Đường dẫn, ngôn ngữ, mục đích (docstring/header), kích thước | ≤50 token |
| L1 | Khung AST qua tree-sitter (Python, TypeScript, Go, Rust) | ≤300 token |
| L2 | Nội dung đầy đủ | File ≤1 MB; lớn hơn trả `capability_unavailable` |

- Thiết kế này là của dự án, *lấy cảm hứng* từ OpenViking. OpenViking thật sự làm khác: L0/L1 ở cấp thư mục, dựa trên ngữ nghĩa.
- **Độ mới:**
  - mtime và kích thước chỉ là đường tắt để chọn file cần index lại.
  - **Bước lọc** (mục 9) dùng L0 đã cache, ghi kèm `source_digest` và thời điểm index. Đây là dữ liệu có thể cũ, được ghi nhãn như vậy.
  - **Khi đưa vào gói context hoặc phục vụ** L0/L1/L2, brain đọc bytes, tính `source_digest` và chỉ trả biểu diễn được dựng từ đúng digest đó. Không khớp thì dựng lại, hoặc hạ cấp có nhãn.
  - File đổi trong lúc đọc → `revision_conflict`. Thuật toán phát hiện và giới hạn của nó chốt khi phần này được làm (mục 19). Test kill tiến trình không chứng minh mọi race đọc đều bị phát hiện.
  - Ngôn ngữ chưa hỗ trợ, file nhị phân hoặc quá lớn: trả cấp thấp hơn có nhãn, không bịa AST.
- **Ranh giới filesystem:**
  - Đường dẫn thực (sau khi theo symlink, junction, reparse point) phải nằm trong thư mục của checkout.
  - Từ chối UNC/device path và alternate data stream trên Windows.
  - Kiểm tra lại danh tính file sau khi mở. Thuật toán cụ thể chốt khi phần này được làm (mục 19).
- **Ghép context:** ngân sách mặc định 4.000 token, chỉnh được. Phân bổ theo chiều rộng trước; khi hết ngân sách thì hạ L1 → L0 → chỉ URI, không cắt đôi nội dung. L0 của sổ bàn giao được ghép trước và không bị cắt đôi; không đủ ngân sách thì bỏ nguyên sổ theo quy tắc ở mục 7.4.
- **Không tuyên bố tiết kiệm token** khi chưa đo (mục 12).

## 11. Tự cải tiến và cổng duyệt

### 11.1 Mô hình 8 thành phần (từ harness2)

| | c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8 |
|---|---|---|---|---|---|---|---|---|
| Thành phần | rule / system prompt | guardrail | memory / bài học | hướng dẫn tool | subagent | skill | script | plugin / hook / MCP config |

| Kênh | Thành phần | Cách đưa | Cổng duyệt |
|---|---|---|---|
| Động | c3, c4, skill (c6): skill `project` trong repo gốc và skill `owner` đã thăng hạng; skill có script sau khi được kích hoạt | Gói context của `prepare_task`, rồi `get_artifact` | Bài học `active` (mục 8.3); skill theo phạm vi (mục 8.7); skill có script cần `skill_activate` (mục 8.6) |
| Tĩnh | c1, c2, c5, c7, c8. Skill (c6) không thuộc kênh này (Q25) | Ghi vào file cấu hình của harness | **Luôn chờ duyệt** (Q20) |

**Nguồn đề xuất:**
- Lời sửa lặp lại → rule.
- Skill được đưa ra mà vẫn thất bại lặp lại → sửa skill.
- Chiến lược thành công → skill mới theo mục 8.9. Revision thuần văn bản ở phạm vi `project` không qua ChangeProposal. Revision có script và thăng hạng thì có (mục 8.6, 8.7).

Câu chữ do agent viết, brain gom evidence. Mức rủi ro do server xếp (mục 11.3).

### 11.2 Review và apply

- **Lệnh CLI:**
  - `brain review list|show|approve|reject`
  - `brain apply`
  - `brain rollback <change>`
- **Trang review local** (`review_web`): xem diff và duyệt bằng passkey. Nội dung proposal (diff, lý do, resource) là **input không đáng tin**, nằm cùng trang có quyền tạo approval. Vì vậy:
  - **Hiển thị như dữ liệu trơ.** Không render HTML hay Markdown chủ động từ proposal; mọi nội dung được escape. Không tự tải URL hay ảnh từ nội dung. Content-Security-Policy chặt: chỉ script của chính trang, không inline script, không nguồn bên ngoài.
  - **Subject hiển thị khóa với approval message.** Trang dựng phần tóm tắt (action, proposal, revision, file đích, digest, mức rủi ro) **từ chính approval message** được dùng làm challenge. Subject đổi thì challenge đổi, và trang hiện subject mới.
  - **API của trang có xác thực.** Phiên duyệt mở bằng URL chứa token một lần do `brain review` cấp. Daemon kiểm tra header `Origin` và `Host` (chống DNS rebinding) và CSRF token trên mọi request. Chỉ nghe trên loopback là chưa đủ.
- Approval khóa chặt subject theo mục 11.3. File đích đổi sau khi duyệt → từ chối apply, phải duyệt lại.
- **Đích vật lý của mỗi file đích.** Đường dẫn và digest khớp là chưa đủ: thư mục cha có thể đã bị đổi thành junction hoặc symlink trỏ sang nơi khác có file cùng bytes.
  - Subject ghi file gồm: root được phép, đường dẫn tương đối đã chuẩn hóa, định danh vật lý của thư mục cha và của file đích, và digest bản gốc. Với file chưa tồn tại, subject ghim thư mục cha, tên file dự kiến và điều kiện "chưa tồn tại".
  - Đường dẫn thực, sau khi theo symlink, junction và reparse point, phải nằm trong root được phép. Từ chối UNC, device path và alternate data stream trên Windows.
  - Mọi thao tác đi từ root đã xác minh. Định danh vật lý của chuỗi thư mục cha và của đích được kiểm lại ngay tại điểm publish, khi tiếp tục và khi rollback.
  - Đích hoặc chuỗi thư mục cha đã đổi thì từ chối ghi, journal về `recovery_required`, và cần duyệt lại. Brain không ghi vào đích thay thế, dù bytes gốc ở đó trùng.
  - **Không hủy bytes chưa có trong backup.** Bản gốc được dời sang backup bằng đổi tên nguyên tử, rồi brain kiểm digest của chính file đã dời. Digest khác bản gốc đã duyệt nghĩa là người dùng vừa sửa file: brain dời trả lại và dừng ở `recovery_required`. Nếu trong lúc đó đã có file mới ở đích thì brain giữ cả hai và không ghi đè.
  - Ranh giới này thuộc review/apply và SP1 đợt 3. Nó độc lập với ranh giới đọc của phần index đang hoãn ở mục 10. Thuật toán định danh vật lý theo từng OS chốt trong plan SP1 đợt 3 (mục 19).
- **Quyền sở hữu nội dung trong file dùng chung, theo định dạng:**
  - **Markdown:** khối có đánh dấu `<!-- ensemble-brain:begin … end -->`.
  - **JSON:** chỉ các khóa do brain quản lý (ví dụ `mcpServers.ensemble-brain`).
  - **TOML:** chỉ các bảng do brain quản lý.
  - Mỗi phần được quản lý có digest trong manifest. Phần đó bị người dùng tự sửa thì **từ chối ghi** và hiện diff.
- **ApplyJournal cho proposal nhiều file.** Trước khi ghi file đầu tiên, journal được ghi bền với từng file đích: digest bản gốc, digest dự kiến, ref backup. Trạng thái:

  ```
  apply     approved → applying → applied
                       applying → partially_applied
  rollback  applied | partially_applied | recovery_required
            → partially_applied [direction=rollback] → rolled_back
  lỗi       lượt dở dang → recovery_required
  ```

  - **Nguyên tắc cho mỗi file.** Mọi thao tác làm một file xuất hiện hoặc biến mất ở đích đều có một **ý định ghi bền trước**, và ý định đó ghim sẵn định danh vật lý của file sẽ được đưa vào hoặc lấy ra. Đổi tên trong cùng volume giữ nguyên định danh, nên sau crash brain nhận ra file của chính nó bằng định danh đã ghim, không bằng digest. Một file có cùng bytes nhưng khác định danh là file của người dùng.
  - Nơi dựng bản thay thế và backup phải nằm cùng volume với đích. Vị trí cụ thể chốt trong plan SP1 đợt 3 (mục 19).
  - **Hướng của cả lượt thao tác.** Trước lần ghi file đầu tiên của một lượt apply hoặc rollback đã được cấp quyền, daemon ghi bền intent ghim ApplyJournal, `direction` (`apply` hoặc `rollback`) và grant của lượt đó trong policy store, rồi chiếu vào kho chính (mục 5.4). Phục hồi hoàn tất chiếu intent hiện hành trước khi phân loại journal, kể cả khi kho chính vẫn ghi trạng thái cuối của lượt trước. Mỗi ý định theo file gắn với đúng lượt.
  - **Journal ghi cho mỗi file:**
    - `original`: `present`, kèm định danh và digest gốc đã duyệt; hoặc `absent`, khi file được tạo mới;
    - pha hiện tại: `original_in_place`, `original_moved` hoặc `replacement_published`. Với `original=absent`, pha đầu là `target_absent` và không có backup;
    - đường dẫn backup dành riêng, định danh và digest của bản thay thế, và nơi giữ bản thay thế khi rollback.
  - **Trình tự apply một file:**
    1. kiểm đích vật lý;
    2. dựng bản thay thế ở nơi dựng, làm bền, rồi **ghim định danh và digest của nó vào journal**;
    3. ghi bền ý định dời; dời bản gốc sang backup; kiểm định danh và digest của chính file đã dời; ghi pha `original_moved`. Với `original=absent` thì bỏ bước này;
    4. ghi bền ý định publish, gồm định danh bản thay thế, đích đã duyệt, backup và hướng; đổi tên bản thay thế vào đích **với điều kiện đích vắng**; làm bền; ghi pha `replacement_published`.
  - Có file khác xuất hiện ở đích lúc publish thì brain giữ file đó, backup và bản thay thế, rồi đưa journal về `recovery_required`.
  - **Rollback đi ngược đúng các pha đó**, sau khi intent cho lượt `direction=rollback` đã được ghi và chiếu vào journal. Với `original=present` còn cần khôi phục, kiểm định danh và digest của backup trước khi xếp lượt rollback là có thể tiếp tục. Kiểm lại backup tương ứng trước khi dời bản thay thế khỏi đích. Thiếu backup hoặc không khớp thì giữ nguyên đích và đưa journal về `recovery_required`.
    - Brain ghi ý định, dời bản thay thế đúng định danh đã ghim từ đích ra nơi giữ, kiểm định danh và digest của file vừa dời, rồi đưa bản gốc từ backup về đích với điều kiện đích vắng. File vừa dời không khớp bản thay thế đã ghim thì brain dời trả lại và dừng ở `recovery_required`. Bản thay thế đã dời ra được giữ cho tới khi journal vào trạng thái cuối.
    - File ở `original_moved` chưa publish được đưa bản gốc về thẳng từ backup đã xác minh, với điều kiện đích vắng.
    - **Với `original=absent`**, rollback chỉ dời đúng bản thay thế do journal sở hữu ra khỏi đích, để đích về lại trạng thái vắng. Không có bản gốc nào được đưa về.
  - **Sau crash**, khởi động lại thì xét từng file theo `direction`, pha đã ghi, các ý định đã ghi và trạng thái thực trên đĩa. Mọi nhận định về file ở đích dựa trên định danh đã ghim:
    - *Ý định dời đã ghi, chưa rõ đã đổi tên chưa.* Đích còn bản gốc đúng định danh và digest, backup chưa có: `original_in_place`. Backup đúng định danh và digest, chuỗi thư mục cha còn hợp lệ, đích vắng: `original_moved`.
    - *Ý định publish đã ghi, chưa rõ đã publish chưa.* Đích vắng và bản thay thế còn ở nơi dựng: vẫn ở pha trước publish. Đích chứa file có **đúng định danh và digest của bản thay thế đã ghim**: `replacement_published`. Đích chứa file khác, kể cả file cùng bytes nhưng khác định danh: giữ nguyên file đó, backup và bản thay thế, rồi vào `recovery_required`.
    - *Hướng rollback, đích chưa từng bị đổi.* Pha và các ý định xác nhận apply chưa đổi đích, và kiểm tra trên đĩa xác nhận đúng trạng thái gốc. File đó đã ở trạng thái gốc, kể cả `original=absent` và bản thay thế còn ở nơi dựng.
    - *Hướng rollback, ý định đưa bản gốc về đã ghi.* Đích chứa file đúng định danh và digest của bản gốc: file đó đã rollback xong.
    - *Hướng rollback với `original=absent` sau publish.* Đích vắng và bản thay thế đúng định danh và digest nằm ở nơi giữ: file đó đã rollback xong.
    - *Hướng rollback đang dở.* Đích còn bản thay thế đúng định danh và digest: file đó chưa được rollback. Với `original=present`, nhánh này cũng đòi backup đúng định danh và digest. Đích vắng và bản gốc còn ở backup đã xác minh: đưa bản gốc về khi pha đã xác nhận chưa publish hoặc bản thay thế khớp định danh và digest ở nơi giữ.
    - Mọi tổ hợp khác: giữ nguyên mọi file và vào `recovery_required`.
  - **Trạng thái của cả journal sau khi xét từng file.** File nào không xác minh được thì journal về `recovery_required`. Các trường hợp còn lại xét theo hướng đã ghi của lượt:
    - `apply`: mọi file ở `replacement_published` và đúng digest dự kiến thì chạy kiểm tra bắt buộc, rồi `applied`. Mọi file còn ở pha đầu và đúng trạng thái gốc thì quay về `approved`. Các trường hợp khác là `partially_applied`.
    - `rollback`: mọi file đã ở trạng thái gốc đã xác minh thì `rolled_back`. Còn file cần xử lý thì `partially_applied` với hướng rollback, kể cả khi tất cả file vẫn đang ở `replacement_published`. Grant rollback còn hiệu lực cho phép tiếp tục đúng hướng đã ghi.
  - **Approval và recovery grant là hai thứ khác nhau.**
    - Thời hạn (`expires_at`) và nonce chỉ được kiểm tra **một lần**, lúc daemon nhận approval đã ký.
    - Khi được chấp nhận, ApprovalReceipt trở thành một **recovery grant** gắn với ApplyJournal của đúng proposal đó. Grant còn hiệu lực tới khi journal vào trạng thái cuối (`applied` hoặc `rolled_back`), và mất hiệu lực khi `trust_generation` đổi.
    - Dùng grant không phải nộp lại nonce, nên hết 10 phút trong lúc crash không chặn việc phục hồi.
    - **Grant sống trong policy store.** Bản ghi grant gồm ApplyJournal, subject, action, `trust_generation` và trạng thái `active` hoặc `ended`. Khi lượt thao tác đạt trạng thái cuối của đúng hướng đã ghi, daemon ghi `ended` cho grant của lượt đó và trạng thái cuối vào intent trong policy store **trước**, rồi mới chiếu sang kho chính. Crash ở giữa thì reconcile theo intent (mục 5.4).
    - Trước mỗi lần ghi file khi tiếp tục hoặc rollback, daemon kiểm tra grant còn `active` trong policy store hiện hành. Grant đã `ended`, hoặc không có bản ghi grant, đưa journal về `recovery_required`, kể cả khi digest các file khớp đúng trạng thái dở dang.
    - Journal trong một bản kho vừa được restore chỉ cung cấp tiến độ và digest để đối chiếu, không cung cấp quyền. Restore riêng kho chính vì vậy không làm sống lại grant đã kết thúc.
  - Từ `partially_applied`, kiểm grant và hướng của lượt hiện hành:
    - Hướng `apply` tiếp tục nếu mỗi file chưa publish còn đúng trạng thái gốc ở đích hoặc đang ở pha trước publish với backup đúng định danh và digest. Publish dùng điều kiện đích vắng. Có thể mở lượt rollback nếu phạm vi grant cho phép.
    - Hướng `rollback` tiếp tục hoàn tất các pha rollback nêu trên. Kiểm đúng định danh và digest trước khi dời file đã publish hoặc đưa bản gốc về từ backup. Đưa bản gốc về dùng điều kiện đích vắng.
  - File nào bị người dùng sửa giữa chừng → `recovery_required`. Cần approval mới; không tự ghi đè.
  - **Rollback thông thường** (`brain rollback` sau khi đã `applied`) là một action riêng, cần approval mới.
  - Chỉ báo "đã cài xong / sẵn sàng" khi mọi file đích đúng digest đã duyệt **và** kiểm tra bắt buộc đã qua (ví dụ `doctor` nhóm Harness).
- **Bootstrap:** lần cài đặt đầu tiên cho mỗi harness (MCP config, hook, rule lớp 1–2) là một ChangeProposal rủi ro cao. Bản review/apply tối thiểu thuộc **SP1**. SP6 bổ sung tự sinh proposal và đo lường.

### 11.3 Cổng duyệt ba lớp (Q18)

**Ba lớp:**

| Lớp | Cơ chế | Ai thực thi |
|---|---|---|
| 1. Rule văn bản | Brain cài câu "Không tự duyệt hay xác nhận thay cho người dùng; khi cần duyệt, báo người dùng" vào file hướng dẫn của harness (CLAUDE.md, AGENTS.md…) | Model tự giác |
| 2. Quyền harness | Bootstrap cài rule `ask` vào cơ chế quyền của từng harness cho **mọi lệnh cấp authority**: `brain review approve/reject`, `brain apply`, `brain rollback`, `brain lesson confirm`, `brain signer *`, `brain policy *`, `brain credential *`, `brain restore`, `brain workspace link` | Harness |
| 3. Brain tự xác minh | Endpoint duyệt của daemon chỉ nhận ApprovalReceipt hợp lệ theo kênh và mức rủi ro dưới đây | Daemon |

**Trạng thái lớp 2** theo từng (harness, phiên bản host, digest cấu hình):
- `unknown`: mặc định.
- `unsupported`: harness không có cơ chế này.
- `verified`: có NativeHostReceipt chứng minh harness thực sự chặn và hỏi lệnh đã cấu hình. Khảo sát và xác minh từng harness thuộc SP2/SP7.

`doctor` báo khi rule bị sửa hay xóa, hoặc khi phiên bản host hay cấu hình đổi (trạng thái trở về `unknown`).

**Xếp mức rủi ro.** Server tự xếp, không dựa vào nhãn client gửi lên. Xếp trên **toàn bộ resource đi kèm** của proposal và lấy mức cao nhất. Mức là **cao** khi có bất kỳ điều nào sau:
- chạm c2, c5, c7 hoặc c8;
- có file thực thi được, hoặc được tham chiếu như một lệnh;
- ghi vào file cấu hình harness ngoài các khối hướng dẫn;
- policy mở rộng capture hoặc egress, thêm người ký, thu hồi credential, restore;
- kích hoạt một revision skill có script (`skill_activate`, mục 8.6);
- xuất skill ra gói công khai (`skill_publish`); chỉ định harness dự phòng cho lượt rà soát; cấu hình lệnh gọi harness của lượt rà soát (mục 8.10).

Còn lại là **thấp**: khối hướng dẫn c1/c4 không kéo theo script, `brain lesson confirm`, thăng hạng skill thuần văn bản lên phạm vi `owner` (`skill_promote`). Quy tắc xếp hạng có `risk_policy_version`.

**Kênh xác nhận và mức bảo đảm:**

| Kênh | Mức bảo đảm | Dùng được cho |
|---|---|---|
| `passkey_uv`: WebAuthn qua trang review local, bắt buộc cờ user verification | `human_verified` | Thấp và cao |
| `ssh_sk_verified`: khóa SSH FIDO (`sk-*`) với tùy chọn `verify-required` | `human_verified` | Thấp và cao |
| `ssh_sk`: khóa SSH FIDO, chỉ cần chạm | `human_present` | Thấp và cao |
| `ssh_key`: khóa SSH thường, có hay không có passphrase | `key_authorization`. Được công bố rõ: agent có thể ký qua ssh-agent nếu khóa đang mở | Thấp và cao (Q18) |
| `terminal`: gõ lại mã hiện trên màn hình | `confirm_only` | Chỉ thấp, và chỉ khi lớp 2 của **mọi** harness có shell đang kết nối ở trạng thái `verified`. Không đạt thì đòi kênh mạnh hơn; không âm thầm hạ cấp |

**Approval message chuẩn.** Đây là thứ được ký hoặc dùng làm challenge của WebAuthn:
- `store_id`, `owner_id`, `trust_generation`;
- `action ∈ {approve, reject, apply, rollback, lesson_confirm, signer_enroll, signer_revoke, policy_change, credential_revoke, restore, workspace_link, skill_promote, skill_activate, skill_publish}`;
- `subject_id`, `subject_revision`, digest nội dung của toàn bộ resource đi kèm. Với mọi action về skill, subject dùng ref đầy đủ `(skill_id, revision_epoch, revision, digest)`; với duyệt gộp (mục 8.7), subject là lô gồm ref đầy đủ của từng mục. `skill_activate` ký thêm phạm vi sẽ kích hoạt;
- danh sách file đích, mỗi file gồm root được phép, đường dẫn tương đối đã chuẩn hóa, định danh vật lý của thư mục cha và của đích, và digest bản gốc (mục 11.2);
- `risk_level`, `risk_policy_version`;
- phạm vi phục hồi được phép (tiếp tục / rollback, mục 11.2);
- với `skill_publish`: bytes đã lọc và digest của từng resource, manifest của gói, và đối tượng nhận (mục 8.7);
- `nonce` do daemon cấp, dùng một lần; `expires_at` (mặc định 10 phút).

Một approval không dùng được cho action, subject hay kho khác.

**Xác minh:**
- **WebAuthn:** kiểm tra challenge khớp approval message, origin, RP ID, cờ UV, bộ đếm chữ ký. Dùng thư viện đã được duy trì, không tự viết mã kiểm tra mật mã.
- **SSH:** `ssh-keygen -Y verify` với file `allowed_signers` do brain quản lý, namespace riêng `ensemble-brain-approval`.

**Đăng ký người ký:**
- Người ký đầu tiên đăng ký lúc `brain init`, trước khi bootstrap bất kỳ harness nào. Đây là **tin ở lần đầu** (trust on first use) và được ghi rõ là giới hạn.
- Người ký sau, và việc thu hồi người ký, cần approval của một người ký hiện có ở mức rủi ro cao.
- **Mất hết người ký:** `brain init --reset-signers` chỉ chạy offline, giữ khóa ghi. Lệnh này:
  - làm mọi approval đang chờ mất hiệu lực;
  - ghi sự kiện nổi bật mà `doctor` luôn hiện;
  - lại là tin ở lần đầu.
- `doctor` liệt kê người ký, kênh và lần dùng gần nhất.

**Giới hạn được công bố:**
- Một tiến trình chạy cùng tài khoản OS có toàn quyền vẫn có thể vượt lớp 1–2. Với `ssh_key`, nó có thể ký qua ssh-agent. Với `brain init` lần đầu hoặc reset, nó có thể đăng ký khóa của chính nó.
- Kênh `terminal` chỉ chống nhầm lẫn.
- `brain report` hiện mức bảo đảm của từng approval.
- Spec không tuyên bố cô lập mạnh hơn ranh giới mà OS và phần cứng xác thực cung cấp.

**Khi có nhóm:** thêm nhiều người ký, luật N/M, và kênh `pr_merge` cho repo cấu hình chung.

### 11.4 Đánh giá sau khi áp dụng

- Kênh động đo bằng chỉ số dùng lại và tín hiệu thụ động; holdout khi đủ điều kiện (mục 12).
- Kênh tĩnh chỉ so sánh trước/sau và **ghi rõ là bằng chứng yếu**.
- Brain **không bao giờ chạy** script trong skill. Nội dung skill không tự cấp thêm quyền cho harness.

## 12. Đo lường

### 12.1 Tín hiệu thụ động

Chạy khi cờ `automatic_capture` của repo bật. Repo tắt cờ này thì không có tín hiệu thụ động, chỉ còn dữ liệu agent tự gửi (nếu `manual_submission` bật).

Tính theo task, harness, loại task và repo:
- tỷ lệ người dùng sửa lời agent;
- lỗi lặp lại sau khi đã có bài học;
- tỷ lệ tool lỗi;
- số lượt, token, thời gian mỗi phiên (`unavailable` nếu harness không cung cấp);
- thời gian tới khi test xanh;
- số lần cập nhật sổ bàn giao mỗi task, độ cũ của sổ lúc tiếp quản, số đề xuất đổi ràng buộc của người dùng;
- **chỉ số của vòng skill (chỉ số chính ở giai đoạn một người dùng, Q7):**
  - số lần một skill được nạp ở repo khác và ở harness khác với nơi sinh ra nó;
  - tỷ lệ skill phải vá sau khi dùng;
  - tỷ lệ lặp lại của cùng một chữ ký lỗi trước và sau khi có skill liên quan;
  - tỷ lệ task có chất liệu mà agent tự ghi skill, so với phần do lượt rà soát soạn;
  - kết quả các lần diễn tập bàn giao (mục 15).

Các chỉ số của vòng skill luôn mang nhãn "tương quan" (mục 12.3).

Mỗi số liệu kèm **độ phủ quan sát**: tầng capture, CaptureGap, mẫu số. Hai harness có mức capture khác nhau không được so như nhau. **Thiếu dữ liệu là `unknown`, không bao giờ được tính là "không có lỗi".**

### 12.2 Holdout ngẫu nhiên

**Ở rev 17 (Q7).** Với một người dùng, holdout theo từng bài học khó đạt đủ mẫu. Vì vậy:
- Schema ghi nhận dưới đây giữ nguyên, để dữ liệu phân tích lại được sau.
- Báo cáo nhân quả hoãn tới khi có nhiều người dùng. Trước đó `brain report` chỉ dùng nhãn "tương quan".
- Holdout vẫn chỉ áp dụng cho bài học đứng riêng. Skill không bị giữ lại ở rev 17; quy tắc holdout cho skill, nếu có, chốt trước SP6.
- **So sánh offline Jev với bộ lọc tại máy** (điều kiện bật Jev ở mục 9):
  - Tập task và tập ứng viên được ghim trước khi chạy.
  - Nhãn "skill đúng" cho từng task do một phép đánh giá độc lập với exposure cũ gán. Skill từng được dùng **không** là mốc so, vì nó phụ thuộc danh sách mà bộ chọn cũ đã phục vụ; lịch sử dùng chỉ là tín hiệu bổ sung. Tập task phải có ca mà skill đúng chưa từng được bộ chọn cũ phục vụ.
  - Hai bộ chọn được so trong cùng giới hạn số mục và cùng ngân sách context.
  - Metric và ngưỡng "tốt hơn" chốt trước khi chạy (mục 19).
  - Phép so này cần `provider_egress` cho phép và tốn tiền, nên chỉ chạy khi chủ dự án cho phép.

**Đã chốt:**
- Gán nhóm trước khi biết kết quả. Retry với cùng `idempotency_key` giữ nguyên nhóm (mục 6.3).
- **Không bao giờ giữ lại:** bài học gắn nhãn an toàn, bảo mật, mất dữ liệu, quy ước/sở thích người dùng đã xác nhận, và sổ bàn giao. Holdout chỉ áp dụng cho bài học. Lần gọi `prepare_task` với `mode=discover` không qua Jev, không có holdout và không thuộc mẫu số đo lường.
- Mỗi Delivery lưu đủ dữ liệu để phân tích lại:
  - tập bài học đủ điều kiện;
  - xác suất được chọn và xác suất được gán nhóm;
  - seed, phiên bản policy;
  - revision chính xác của bài học;
  - assignment;
  - exposure, kèm loại bằng chứng tường minh `exposure_evidence ∈ {read_ack, served_only, unknown}`. `served_only` chỉ là proxy: nó chứng minh server đã gửi, không chứng minh client nhận đủ. Không gộp các loại này thành một cờ "đã nhận". Phân tích theo exposure dùng proxy phải ghi rõ giả định và độ phủ;
  - độ đầy đủ quan sát.
- Báo cáo chính theo nhóm được gán (intent-to-treat). Phân tích theo exposure là phần bổ sung, ghi rõ giả định.
- Chỉ ghi nhãn "nhân quả" khi thiết kế và các cổng chất lượng dữ liệu đạt. Không chỉ vì bản ghi có tên holdout.
- ≥30 mỗi nhóm là sàn để bắt đầu báo cáo, không phải bảo đảm đủ lực thống kê.

**Chốt trước SP6** (mục 19). Rev 1 có hai quy tắc mâu thuẫn: *p* = 10% cho mỗi cặp (Delivery, bài học), nhưng tối đa 1 bài bị giữ mỗi phiên. Hai hướng sửa:
- **(i)** Mỗi task chọn tối đa một bài học trọng tâm theo policy đã ghi, rồi random hiện/giữ cho bài đó.
- **(ii)** Random độc lập từng bài học và bỏ giới hạn.

Ngoài ra cần chốt:
- assignment nhất quán khi một task có nhiều Delivery;
- cửa sổ outcome;
- carryover (bài học đã thấy ở phiên trước);
- xử lý dữ liệu thiếu;
- metric chính;
- xem kết quả nhiều lần và so sánh nhiều bài học;
- quy tắc hạ `dormant`.

**Tùy chọn, mặc định tắt:** nhánh chỉ dùng rules, để đo xem Jev hơn rules bao nhiêu.

### 12.3 Báo cáo

`brain report` gồm:
- xu hướng;
- số liệu dùng lại của từng skill và từng biến thể, tách theo repo và harness (mục 8.8, 12.1);
- lợi ích từng bài học kèm khoảng tin cậy;
- chi phí Jev (gồm phần `unknown` và cảnh báo lệch giá);
- mức bảo đảm của các approval;
- mức độ bền đang áp dụng.

Mọi con số được ghi nhãn "nhân quả" (holdout đạt điều kiện) hoặc "tương quan" (trước/sau, thụ động). "Pipeline có dữ liệu đúng assignment" và "đủ dữ liệu kết luận lợi ích" là hai trạng thái khác nhau.

## 13. Tự chẩn đoán: `brain doctor`

- **`brain doctor [--fix] [--json]`:** chạy toàn bộ kiểm tra qua daemon. Daemon không chạy thì chỉ chạy các kiểm tra offline ở chế độ đọc.
- **`get_health()`:** nhanh, chỉ đọc, không gọi mạng, không ghi gì.
- **`get_health(deep=true)`:**
  - Trả DoctorRun gần nhất kèm tuổi.
  - DoctorRun cũ hơn 24 giờ thì tạo job doctor (không gọi Jev) và trả `job_id`.
  - Side effect duy nhất được công bố: ghi Job và DoctorRun.
- **Kiểm tra Jev chủ động** (gửi request thật, tốn tiền) chỉ chạy khi gọi `brain doctor --jev`.
- Daemon tự chạy doctor (không gọi Jev) khi khởi động và mỗi 24 giờ, lưu DoctorRun.

| Nhóm | Kiểm tra |
|---|---|
| Daemon | Đang giữ `writer.lock`, `writer_epoch`, phiên bản schema và `min_reader_version` |
| Danh tính | Credential tồn tại, credential đã thu hồi không còn dùng, mỗi harness đã đăng ký có credential; danh sách người ký, kênh, lần dùng gần nhất; sự kiện reset người ký |
| Storage | `PRAGMA integrity_check`, kích thước WAL, lấy mẫu kiểm tra digest trong CAS, blob mồ côi, ledger khớp với projection, policy store được áp đủ vào kho, dung lượng đĩa, backup gần nhất, **mức độ bền** (`power_loss_durable` / `process_crash_durable`) |
| Quyền file | Quyền owner-only trên toàn bộ data root, thư mục cha, nơi xuất backup (mục 5.9) |
| Capture | Mỗi harness: lần nhận sự kiện gần nhất, tầng capture đang hoạt động, độ dồn của outbox, CaptureGap, dead-letter |
| Privacy | Canary secret giả phải bị chặn ở mọi đường vào (hook, tool trực tiếp, object lồng nhau, log lỗi, trace, outbox, nội dung dẫn xuất); quét lại kho bằng bộ mẫu mới |
| Harness | Cấu hình MCP trỏ đúng shim; phần do brain quản lý bị sửa tay (drift); hook đã cài; rule lớp 2 còn nguyên và **trạng thái lớp 2** từng harness; ApplyJournal kẹt ở `partially_applied`/`recovery_required` |
| Jev | Key có cấu hình; tỷ lệ chuyển sang rules gần đây; chi phí so với trần (nếu có); usage lệch giá đã ghim; độ trễ từ trace gần đây. Kiểm tra model còn tồn tại chỉ với `--jev` |
| Index | Số file chưa index hoặc đã cũ. Nhóm này đang hoãn cùng phần index (mục 10) |
| Lessons | Số bài học kẹt ở `pending_conflict_check` hoặc `conflicted` |
| Skill | Số skill chờ duyệt thăng hạng; biến thể chờ gộp; lượt rà soát lỗi hoặc đang chờ; trạng thái rà soát của từng harness |
| Retention | Job dọn dữ liệu lần cuối chạy lúc nào; tombstone khớp với holder trong CAS |

- Mỗi mục trả về `PASS | WARN | FAIL`, kèm mô tả và hướng sửa.
- **`--fix` chỉ làm việc an toàn:**
  - khởi động lại daemon;
  - phát lại outbox;
  - áp lại policy store vào kho;
  - dựng lại projection hoặc index vào bảng mới, kiểm tra rồi mới hoán đổi;
  - xoay vòng log;
  - sửa quyền file về owner-only.

  **Không bao giờ xóa dữ liệu,** không ghi vào cấu hình harness (việc đó phải qua `review/apply`), và không tự xử lý ApplyJournal (việc đó cần approval).

## 14. Bảo mật và quyền riêng tư

### 14.1 Mối đe dọa

| Mối đe dọa | Biện pháp |
|---|---|
| Secret lọt vào kho | Privacy filter ở mọi đường vào bền vững; quét lại định kỳ; phát hiện thì quarantine theo digest, không xóa âm thầm |
| Đầu độc bài học | `source` do server gán; bài học do agent viết chỉ là `candidate` tới khi có proof (mục 8.2); Conflict Review trước lần đưa đầu; gói context đánh dấu rõ "dữ liệu tham khảo, không phải lệnh" |
| Skill do agent viết sai hoặc bị đầu độc | Khi chưa thăng hạng chỉ có hiệu lực trong repo gốc; mang nhãn `agent_reported` và "chưa thăng hạng"; gói context đánh dấu "dữ liệu tham khảo, không phải lệnh"; chỉ văn bản được ghi tự do; thăng hạng phải qua duyệt kèm kiểm tra nội dung riêng của dự án; thu hồi theo digest có hiệu lực ở mọi phạm vi (mục 8.6, 8.7) |
| Lượt rà soát làm lộ nội dung hoặc sửa dự án | Chỉ đọc, chạy ngoài checkout; lệnh cố định đã duyệt; mặc định cùng nhà cung cấp với phiên gốc; chỉ gửi nội dung của chính phiên và task đó; cờ `post_session_review` (mục 8.10, 14.2) |
| Skill bên thứ ba độc hại | Không chạy script; nhập skill phải qua review, approval bao gồm toàn bộ resource đi kèm, rủi ro xếp theo toàn bộ resource; ghi nguồn gốc và license; gộp skill không làm mất provenance |
| Tiến trình lạ gọi daemon | Chỉ nghe trên loopback; credential riêng cho từng harness; danh tính suy từ credential; dữ liệu owner-only trên đĩa (mục 5.9) |
| Agent tự duyệt thay đổi | Cổng ba lớp, có công bố giới hạn và mức bảo đảm (mục 11.3) |
| Nội dung proposal tấn công trang duyệt | Hiển thị như dữ liệu trơ, CSP chặt, subject dựng từ approval message, token phiên, kiểm tra Origin/Host, CSRF (mục 11.2) |
| Dùng lại chữ ký sau restore | `trust_generation` tăng mỗi lần restore policy store (mục 5.7) |
| Retry làm lộ nội dung đã bị chặn | Idempotency chỉ lưu ref; mỗi lần phục vụ lại đều kiểm tra policy hiện hành (mục 6.3) |
| Restore làm sống lại quyền đã thu hồi | Policy store tách khỏi restore kho dữ liệu (mục 5.7) |
| Path traversal và đổi đích ghi sau khi duyệt | Đích vật lý của file đích được ghim trong approval và kiểm lại khi ghi (mục 11.2). Ranh giới đọc của index ở mục 10 đang hoãn |
| Restore làm sống lại quyền ghi file đã kết thúc | Recovery grant và trạng thái của nó nằm trong policy store (mục 11.2) |
| Restore làm lùi số lượt gọi và chi phí | Tầng accounting nằm trong policy store, ghi trước khi gửi (mục 5.7) |
| Harness tự nạp skill ngoài tầm kiểm soát của brain | Brain không ghi skill vào thư mục skill của harness; skill chỉ được phân phối qua MCP, nơi pin và quarantine có hiệu lực ở mỗi lần cấp (Q25, mục 8.11) |
| Lượt rà soát tiết lộ mục chưa từng tới người nhận | Kiểm bằng chứng tiếp xúc và hồ sơ nguồn của từng mục. Gửi lại cần khớp hồ sơ đích. Gửi tới đích mới cần duyệt đúng đích và kiểm lineage (mục 7.2, 8.10) |
| Dữ liệu gửi cho Jev | Allowlist theo loại request, policy theo lineage (mục 14.2) |

### 14.2 Privacy contract

**Năm cờ policy theo repo** (mặc định đều bật):

| Cờ | Tắt thì |
|---|---|
| `automatic_capture` | Không thu sự kiện từ hook/transcript; không có tín hiệu thụ động |
| `manual_submission` | `submit_episode` và nội dung của `record_outcome` từ repo này không được lưu (chỉ lưu ID và trạng thái) |
| `indexing` | Không index context của repo |
| `provider_egress` | Không nội dung nào có nguồn từ repo này được gửi cho Jev |
| `post_session_review` | Không chạy lượt rà soát sau phiên cho repo này (mục 8.10); chỉ còn lời nhắc `skill_review_pending` |

Đổi cờ là `policy_change`. Mở rộng capture hoặc egress là rủi ro cao (mục 11.3). Chỉ định một harness dự phòng cho lượt rà soát là mở rộng egress.

**Đường vào.** Privacy filter chạy trước khi ghi bền vững ở **mọi** đường vào:
- hook/transcript;
- `submit_episode` (gồm evidence, diff, bài học đề xuất, sổ bàn giao, skill và bản vá skill);
- đầu ra của lượt rà soát sau phiên;
- `record_outcome`;
- nhập artifact;
- index context.

Filter xử lý:
- secret và token theo mẫu, chuỗi có entropy cao;
- nội dung trong `<private>…</private>`;
- danh sách đường dẫn cấm.

**Mẫu đường dẫn trong SP1.** Mẫu được so với từng thành phần đường dẫn bằng glob `*`, `?` và lớp ký tự dạng `[ab]`, `[0-9]`, `[!x]`, sau khi chuyển chữ thường. Hai dấu `/` và `\` đều phân tách thành phần. Bỏ thành phần rỗng và `.`, giữ `..`. Mẫu một thành phần khớp ở bất kỳ vị trí nào. Mẫu nhiều thành phần khớp một chuỗi thành phần liên tiếp, và dấu phân tách cuối mẫu áp dụng cùng quy tắc.

Khi dựng policy, mẫu không còn thành phần hoặc chứa ký tự mà bộ quét tách thành ranh giới phải bị từ chối với `invalid_input`. Các ký tự ranh giới gồm khoảng trắng, dấu nháy, `< > | ( ) { } , ;` và dấu ngoặc vuông dùng như ký tự literal. Lớp glob hợp lệ phải đóng, không rỗng và không chứa lớp lồng hoặc ký tự ranh giới. Khi xử lý dấu câu bao quanh token, vẫn phải kiểm cách viết gốc nếu phần đã cắt dấu câu không khớp, để các mẫu như `..`, `vault.` hoặc `vault?` được thực thi.

Filter duyệt cả object và list lồng nhau. **Filter lỗi thì không lưu payload gốc**, kể cả trong log lỗi, trace hay dead-letter.

**Lưu trữ.** Log, trace và dead-letter không chứa payload thô; chỉ ID, loại và digest.

**Lineage do server lập.**
- **Mỗi task có lineage**, gồm:
  - repo của task;
  - mọi bài học, artifact, context, continuity/checkpoint/bản bàn giao đã được phục vụ trong task đó (theo Delivery và ServedReceipt).

  Lineage của task chỉ tăng thêm, không bao giờ bớt.
- **Mọi nội dung do brain quản lý hoặc chuẩn bị gửi đi mang lineage**, gồm:
  - Episode, Evidence, bài học;
  - trạng thái task, continuity, checkpoint, bản bàn giao;
  - cửa sổ hội thoại dùng để phân loại lời sửa;
  - **từng trường** của payload gửi cho Jev.

  Nội dung tạo trong task kế thừa lineage của task tại thời điểm tạo. Một trường gửi đi (ví dụ mô tả task trong `prepare_task` thứ hai của cùng task) mang lineage hiện tại của task, không chỉ repo.
- **Phục vụ sang task mới chuyển cả lineage.** Continuity rút từ task T1 được đưa vào T2 thì T2 kế thừa lineage của T1.
- **Phiên bản skill mới kế thừa lineage của mọi parent** được dùng để dựng nội dung (base của bản vá, các biến thể được gộp), kể cả khi task tạo bản vá chưa có ServedReceipt của parent (mục 8.8).
- Client có thể khai thêm nguồn, **không thể bỏ** nguồn do server đã ghi.
- **Trường không xác định được nguồn thì không được gửi ra ngoài.** Nội dung không rõ nguồn được xử lý bảo thủ (coi như `provider_egress` tắt), trừ khi owner gỡ hạn chế bằng `policy_change`.
- **Giới hạn được công bố:** brain chỉ theo dõi được nguồn gốc của những gì đi qua nó. Brain không chứng minh được nguồn ngữ nghĩa của nội dung mà agent đã chép từ ngoài vào, và không hứa theo dõi lây lan toàn diện (universal taint tracking).

**Đi ra ngoài.** Có ba đích: Jev, khi được bật (mục 9); harness được gọi trong lượt rà soát sau phiên (mục 8.10); và gói skill công khai (mục 8.7).

**Tới harness rà soát:**
- Mọi mục gửi đi phải có nguồn thuộc đúng `task_id` và `session_ref` của phiên được rà, provenance xác minh được, bằng chứng tiếp xúc `sent_to_recipient` và thuộc loại nội dung được phép. Cả hai nhánh yêu cầu hồ sơ nguồn và đích đầy đủ. Trường `unknown` ở hồ sơ nguồn loại mục tương ứng. Trường `unknown` ở hồ sơ đích chặn lượt gọi (mục 7.2, 8.10).
- Không gửi: mục `local_only` hay `unknown`; phần agent khai của sổ bàn giao, kể cả patch của chính phiên đó; trạng thái gộp của sổ; nội dung của phiên khác (kể cả phiên khác của cùng task), task khác hay repo khác; mục thiếu provenance. Gửi các loại này sẽ là một lần tiết lộ mới và cần quyết định policy riêng; rev này không cho phép.
- **Nhánh gửi lại** (mặc định): thêm điều kiện người nhận khớp hồ sơ đã ghi của đoạn phiên chứa mục đó, gồm harness, hồ sơ provider và account (mục 7.2). Người nhận đó đã nhận **đúng các mục này** khi phiên chạy, nên việc gửi lại không phải một lần tiết lộ mới.
- **Nhánh người nhận mới đã duyệt:** không đòi khớp hồ sơ, nhưng cần approval hoặc policy hiện hành cho đúng đích đó, và `provider_egress` hiện hành của mọi nguồn trong lineage của từng mục.
- Hai hồ sơ đã xác minh khác nhau được xử lý theo nhánh người nhận mới, kể cả khi tên harness giống nhau. Chỉ định một người nhận mới cho repo là `policy_change` ở mức rủi ro cao.
- Ref nguồn và lineage chỉ nằm trong metadata nội bộ, không nằm trong payload gửi đi.
- Trước mỗi lần gửi, brain kiểm tra lại quyền đọc, tombstone, quarantine và các cờ hiện hành của từng nguồn.

**Tới gói công khai:** chỉ qua approval `skill_publish`, với các kiểm tra về lineage, thu hồi và quyền phân phối ở mục 8.7. Không có đường xuất nào khác.

**Tới Jev:**

| Loại request Jev | Trường được gửi |
|---|---|
| Chọn (request 1) | Mô tả task đã lọc; L0 của skill, bài học, file ứng viên trong tập được gửi (phần file đang hoãn, mục 10); nhãn repo |
| Xếp lại (request 2) | Mô tả task đã lọc; mô tả đầy đủ (L1) của tối đa 3 skill |
| Phân loại lời sửa | Tin nhắn người dùng đã lọc, kèm tối đa 2 lượt trước đã lọc |
| Conflict Review | L0 và điều kiện áp dụng của hai bài học |

- Không bao giờ gửi cho Jev L2, evidence thô, sổ bàn giao hay nội dung transcript ngoài các trường trên.
- Với Jev, mọi trường do brain dẫn xuất từ sổ bàn giao là chỉ-tại-máy, kể cả ở repo cho phép egress. Brain không dựng `description` hay trường Jev nào từ sổ. `description` do agent tự viết đi theo lineage của task; nội dung agent tự chép từ sổ vào đó thuộc giới hạn đã công bố ở trên.
- Ranh giới của egress là daemon. Dữ liệu daemon trả cho harness đã được cấp quyền sẽ do model của harness đó xử lý; việc này nằm ngoài kiểm soát của brain.
- **Trước mỗi lời gọi** (kể cả retry và job nền), brain kiểm tra allowlist và kiểm tra `provider_egress` **hiện hành** của mọi nguồn trong lineage của từng mục. Brain không dựa vào nhãn đã sao chép lúc tạo.
- Chia sẻ owner-wide (Q12) chỉ áp dụng cho nội dung bài học và nội dung skill đã thăng hạng. Resolve ref tới nguồn vẫn kiểm tra quyền.

### 14.3 Xử lý lỗi

- Daemon tắt: shim trả lỗi rõ ràng; outbox giữ sự kiện và gửi lại sau mà không tạo bản trùng.
- Jev lỗi: chuyển sang rules, có trace.
- Dữ liệu hỏng: quarantine; khôi phục theo mục 5.7.
- Phiên bản lạ, policy không đọc được, lớp 2 chưa xác minh: từ chối có mã lỗi, không âm thầm hạ cấp.
- Cấm nuốt lỗi; mọi chế độ dự phòng đều hiện trong `get_health`.

## 15. Các dự án con và thứ tự

Mỗi dự án con có plan riêng (superpowers:writing-plans) dựa trên spec này. Nếu một dự án con cần quyết định thiết kế mà spec chưa có, chạy một vòng brainstorming ngắn và bổ sung spec trước khi viết plan. Các quyết định có hạn chót riêng nằm ở mục 19.

| # | Dự án con | Nội dung | Package sở hữu | Nguồn code |
|---|---|---|---|---|
| SP1 | Kernel | Xem danh sách bên dưới | `core`, `ports`, `storage`, `adapters.os`, `mcp`, `cli_api`, `review_web`, `cli`, `composition`, phần nền của `application` | **Trích xuất** từ repo cũ `f83271d` kèm test; phần còn lại viết mới |
| SP2 | Capture và liên tục phiên | envelope v2, outbox, worker tín hiệu, task/session/episode, continuity, sổ bàn giao và cập nhật contract v2 (mục 7.4); bản hẹp của `prepare_task` (`discover` và `work` chỉ có sổ bàn giao, không Jev, mục 6.2, 7.4) và `get_artifact` (chỉ sổ bàn giao); khảo sát + adapter cho Claude Code và Codex app, gồm **xác minh lớp 2** của hai harness này | `domain.capture`, `domain.continuity`, `adapters.harness.*` | Queue trích xuất; phần còn lại viết mới |
| SP3 | Vòng skill | Kho skill, ba phạm vi, phiên bản và biến thể, ghim theo repo, đường ghi `skill_draft`/`skill_patch`, đường động với bộ lọc tại máy, hồ sơ sử dụng, cập nhật contract v2 (mục 8.6–8.9, 8.11, 9) | `domain.skills`, phần lọc tại máy của `domain.selection` | Viết mới (TDD) |
| SP4 | Rà soát và thăng hạng | Lượt rà soát sau phiên, hàng đợi duyệt gộp, thăng hạng lên `owner`; khảo sát chế độ không giao diện của Claude Code và Codex app (mục 8.7, 8.10) | `domain.skills`, `domain.improvement`, `adapters.harness.*` | Viết mới, có bước khảo sát trước |
| SP5 | Bài học đứng riêng, danh mục và Jev tùy chọn | Vòng đời, xác minh, Conflict Review của bài học đứng riêng (mục 8.1–8.5); nhập agency-agents và skill local; Jev, tập chỉ-tại-máy, ngân sách, allowlist egress (mục 9) | `domain.lessons`, `domain.catalog`, `domain.selection`, `adapters.jev` | Viết mới |
| SP6 | Cải tiến, đo lường và gói công khai | Tự sinh ChangeProposal cho các thành phần ngoài skill, holdout, report, lọc và xuất gói skill công khai (mục 8.7, 11, 12) | `domain.improvement`, `domain.measurement` | Viết mới |
| SP7 | Các adapter còn lại | OpenCode, Antigravity; Cursor khi được cài; xác minh lớp 2 từng harness | `adapters.harness.*` | Viết mới, mỗi harness có bước khảo sát trước |

Context L0/L1/L2 cho file (`domain.context`, SP5 ở các rev trước) đang hoãn vô thời hạn và không thuộc dự án con nào (mục 10). Rev 17 không đổi SP1 và SP2. Rev 18 thêm yêu cầu cho SP1 đợt 3 (recovery grant trong policy store, đích vật lý của file đích, hạn gốc của holder khi restore, tầng accounting) và cho SP2 (hồ sơ người nhận của phiên, provenance theo phiên); xem mục 19.

**Nội dung SP1:**
- `core`, `ports`;
- `storage` theo mục 5.4–5.9: `durable_publish`, policy store, backup/restore, migration;
- `adapters.os`;
- daemon, shim, khóa ghi;
- khung contract v2 với 8 tool (domain chưa có trả `capability_unavailable`), idempotency, job;
- privacy filter cho mọi đường vào;
- `doctor` cơ bản;
- bootstrap review/apply tối thiểu với ApplyJournal;
- cổng duyệt ba lớp: passkey, SSH, terminal, đăng ký người ký, framework trạng thái lớp 2, trang review an toàn;
- model lineage cho task và cho từng trường gửi đi (ref/record; việc lan truyền và kiểm tra egress đầy đủ thuộc SP2–SP5);
- CI đa OS và hàng rào.

**Plan SP1 chia thành các đợt, mỗi đợt có gate nội bộ:**
1. `core`, `ports`, storage, policy store, `durable_publish`, độ bền.
2. Daemon, shim, khóa ghi, contract v2, idempotency, job, phục hồi sau crash.
3. Review/apply, ApplyJournal, cổng duyệt, `review_web`. Từ rev 18, đợt này gồm cả các yêu cầu của SB2-R17-01, R17-02, R17-07 và R17-11 (mục 19).
4. `doctor` và integration trên 3 OS.

Mọi phần đã giao cho SP1 ở trên đều phải nằm trong một đợt. Không phần nào bị bỏ chỉ vì SP1 được gọi là "kernel".

### Các mốc và điều kiện nghiệm thu

- **M1 (SP1 + SP2):**
  - Claude Code và Codex app trên máy chủ dự án cùng ghi vào một kho thật.
  - Cả hai được cài qua bootstrap ChangeProposal đã duyệt ở mức rủi ro cao. ApplyJournal ở `applied`.
  - Mỗi harness có NativeHostReceipt của host thật (mục 17.3). Trạng thái lớp 2 được ghi đúng như đã xác minh, kể cả khi là `unsupported`.
  - Phiên của harness này nhận được continuity của phiên trước từ harness kia **trên cùng checkout**. Một checkout khác của cùng remote không nhận nhầm.
  - **Bài diễn tập bàn giao** trên host thật:
    - **Dựng trước:** fixture task ghim trước `next_action` đúng, một phương án sai nhưng hấp dẫn đã bị loại, một ràng buộc của người dùng và một hành động bị cấm.
    - **Kịch bản:** giết tiến trình Claude Code giữa chừng, không có sự kiện kết thúc phiên, rồi mở Codex app ngay trên cùng checkout.
    - **Bằng chứng trước khi giết:** artifact `revision`, `handoff_revision`, digest và ACK của lần ghi cuối, source snapshot, trạng thái tiến trình, `CaptureGap` nếu có.
    - **Bằng chứng phía nhận:** principal, `task_id`, Delivery, ServedReceipt, ReadAck nếu có, và chi phí thực của thao tác ghi sổ khi harness cung cấp được.
    - **Đạt khi:** (1) Codex nêu đúng mục tiêu và bước đang làm; (2) giữ các quyết định và ràng buộc đang hiệu lực; (3) **lệnh và side effect thực tế** không thử lại phương án đã loại, không làm hành động bị cấm, và làm đúng `next_action`; (4) mọi phần đã ACK vẫn đọc được, và báo riêng phần khai và phần quan sát mới tới đâu.
    - **Ca phủ định:** một checkout khác của cùng repo bị từ chối qua cả `mode=discover` lẫn đọc trực tiếp theo ref.
    - Kết quả chỉ chứng minh cho lần diễn tập đó. Chiều ngược lại chạy nếu capture của Codex cho phép; không chạy thì ghi `not_run`.
- **M2 (+ SP3, SP4):**
  - Harness A tạo một skill sau một task thật ở repo X. Skill có hiệu lực ngay ở repo X cho harness B, và không lộ sang repo Y.
  - Skill được thăng hạng lên phạm vi `owner` qua approval thật.
  - Harness B ở repo Y nạp skill đó cho một task tương tự. Kết quả ghi riêng bốn mức: đã gửi, client xác nhận nhận đủ, agent khai đã áp dụng, và hành vi quan sát được.
    - Ca nạp chỉ đạt khi có ReadAck gắn với đúng lần cấp theo Delivery qua MCP (mục 8.11), khớp task, principal, ref đầy đủ và digest của các resource bắt buộc. Quan sát trên host thật chỉ được dùng làm bằng chứng cho đúng lần cấp đó, khi khớp task, ref và digest. Chỉ có ServedReceipt thì ghi `served_only` và ca này chưa đạt.
    - Host tự nạp một file local có cùng digest mà không có lần cấp nào qua MCP: không được tính là nạp skill của brain, và kết quả M2 ghi đúng như vậy.
    - **Ca mất kết nối sau khi gửi:** kết quả là `served_only`, không được tính là đã nạp.
  - **Ca biến thể:** harness B gửi một cách làm khác cho cùng loại vấn đề. Hai biến thể cùng tồn tại, repo X vẫn dùng bản đã ghim, và hồ sơ sử dụng tách theo biến thể.
  - **Ca rà soát:** một phiên bị giết trước khi agent ghi skill. Lượt rà soát soạn skill, hoặc phiên kế tiếp nhận `skill_review_pending`; kết quả ghi đúng là nhánh nào đã chạy.
  - Hệ thống phân biệt được các mức: đã chọn, đã gửi (ServedReceipt), client xác nhận đã nhận đủ (ReadAck), agent khai đã áp dụng, quan sát được.
  - Kết quả chỉ chứng minh cho các lần chạy đó, không chứng minh skill có ích.
- **M3 (+ SP5, SP6):**
  - `brain report` có số liệu dùng lại skill thật theo mục 12.1, với nhãn "tương quan".
  - Một bài học đứng riêng được `verified` bằng proof `tool_observed`, qua Conflict Review và được đưa cho harness khác.
  - Nếu Jev được bật: có kết quả phép so sánh offline ở mục 12.2. Không bật thì ghi `not_run`.
  - Kết luận "có lợi ích" là một claim riêng, chỉ khi đủ điều kiện ở mục 12.2. Không có cam kết thời gian đạt đủ dữ liệu.

**Danh sách trích xuất cho SP1:** đồ thị import và số dòng đã đo nằm trong `docs/notes/2026-10-29-extraction-analysis-draft.md` (chỉ để tham khảo). Plan SP1 chốt manifest chính thức theo quy tắc ở mục 17.4.

## 16. Đối chiếu với tài liệu cũ

| Chủ đề | Tài liệu/code cũ | Spec này |
|---|---|---|
| Bộ chọn | Rules mặc định, Jev tùy chọn | Lọc tại máy và model của harness; Jev tùy chọn (rev 17) |
| Tự tạo skill | – | Vòng skill theo ý tưởng của Hermes Agent (Q22, Q23) |
| Phạm vi bài học | Cô lập chặt theo workspace | Chia sẻ trong cùng `owner_id`, repo chỉ là gợi ý |
| Persona/skill | 8 persona + 217 skill (docs/plan); V5 thu gọn còn 8 | Skill do agent tự tạo, cộng agency-agents và ~70 skill local được nhập vào |
| Harness | 5, sau đó tăng lên 9 | 5 (Cursor hoãn) |
| Hệ điều hành | Windows | Windows, macOS, Linux |
| Contract | `mcp-tools-v1` | `mcp-tools-v2`, không tương thích ngược |
| Tự cải tiến | `evolution` chạy probe theo harness2; `learning` campaign | Không chạy probe; agent viết, brain xác minh |
| Cổng duyệt | – | Ba lớp, ApprovalReceipt có mức bảo đảm |
| Đo lường | Owned fixture, benchmark, utility experiment | Tín hiệu thụ động + holdout |
| Cơ sở dữ liệu | `brain.db` + `cognitive.db`; V5 gộp | Một kho dữ liệu mới + policy store, không nhập dữ liệu cũ |
| Phát hành | PyPI, Docker, Smithery | Ngoài phạm vi |
| Tự chẩn đoán | `get_health` | `doctor` + `get_health(deep)` |

## 17. Kiểm thử, hàng rào và nghiệm thu

### 17.1 Kiểm thử

- TDD cho code mới.
- Jev: dùng transport giả cho contract và các ca lỗi.
- Fault injection (kill tiến trình) cho các điểm crash ở mục 5.4 và ApplyJournal.
- Test quyền file theo từng OS trong ma trận CI.

### 17.2 Các gate

| Gate | Gồm | Chạy ở đâu | Điều kiện |
|---|---|---|---|
| **Mặc định** | Unit + integration (SQLite thật, daemon thật dạng subprocess, fixtures contract v2) | CI ma trận 3 OS × 2 Python, và tại máy | Mỗi job dưới 5 phút. Kèm import-linter + test AST, không vòng phụ thuộc, `mypy --strict`, `ruff` cho `src` và `tests`, cấm nuốt lỗi, cảnh báo file vượt 600 dòng |
| **Canary Jev** | Một request thật | Tại máy, khi chủ dự án cho phép | Tốn tiền; chạy riêng |
| **Native** | Kiểm chứng với host thật, gồm lớp 2 | Tại máy, khi chủ dự án đồng ý | Tạo NativeHostReceipt |
| **Xác thực phần cứng** | Passkey thật, khóa SSH FIDO thật | Tại máy, khi chủ dự án thao tác | Gate thủ công; CI dùng authenticator giả và ghi rõ là giả |

- Gate chưa chạy thì trạng thái là **chưa nghiệm thu**, không phải "được miễn".
- Không xóa, skip hay giảm assertion để đạt thời gian.
- Chuyển một test sang nhóm khác cần review có requirement đi kèm.
- **Receipt của gate** gắn: commit SHA (working tree sạch), digest lockfile và config, danh sách test, kết quả cuối. Source đổi giữa lần chạy thì receipt không nghiệm thu cho snapshot cuối.

### 17.3 NativeHostReceipt

- Gắn: tên và phiên bản host, phiên bản/digest build của shim, digest cấu hình, task, và lời gọi quan sát được.
- Receipt tạo từ fixture có loại `fixture` và không bao giờ được tính là host thật.
- Tên host hay digest trong receipt không tự tạo authority. Receipt chỉ có giá trị khi được tạo qua kênh quan sát đã đăng ký.
- Receipt dùng cho lượt rà soát sau phiên (mục 8.10) ghi thêm: OS, lệnh, digest cấu hình của hồ sơ chạy, và từng phép kiểm chỉ-đọc đã quan sát kèm kết quả. Receipt này chỉ có giá trị cho đúng bộ đó.

### 17.4 Quy tắc trích xuất (cho plan SP1)

- Mỗi phần trích xuất có commit/blob nguồn, test đi kèm và requirement của spec mà nó phục vụ.
- Test mang sang chạy trước khi sửa.
  - Test fail sẵn ở nguồn được giữ và phân loại, không sửa assertion để có baseline xanh.
  - Khi spec mới chủ ý đổi hành vi, test đổi theo requirement đã review và ghi lý do.
- Không kéo theo code chỉ vì nằm trong import closure.

### 17.5 Quy tắc tuyên bố

- Không ghi "xong" hay "verified" khi chưa có receipt của gate mặc định.
- Không ghi "hỗ trợ harness X" khi chưa có NativeHostReceipt của host thật.
- Không ghi "bền khi mất điện" ngoài mức độ bền mà `doctor` báo cho máy đó.
- Khung tool trả `capability_unavailable` không được gọi là "đã có tính năng".

## 18. Việc còn mở (không chặn việc viết plan cho SP1)

| # | Việc | Khi nào xử lý |
|---|---|---|
| O1 | Giấy phép của dự án và của gói skill công khai | Trước lần public đầu tiên lên GitHub (Q24) |
| O2 | Codex app desktop: hook, vị trí transcript, cơ chế quyền cho lớp 2 | Bước khảo sát trong SP2 |
| O3 | Antigravity `agy` 1.4.8 và OpenCode 2.2.0: hook/plugin, định dạng transcript, cơ chế quyền | Bước khảo sát trong SP7 |
| O4 | Độ trễ Jev thực tế trên mạng của chủ dự án; ngưỡng confidence | Canary trong SP5, nếu bật Jev |
| O5 | Số lượng ứng viên lọc (40/40/20), số mục trả về khi Jev tắt (10/10) và ngân sách 4.000 token | Đo trong SP3 và SP5 |
| O6 | License của từng skill trong ~70 skill local | Bước nhập trong SP5 |
| O7 | Tự khởi động daemon lúc đăng nhập trên từng OS (mặc định: chạy khi cần) | Plan của SP1 |
| O8 | Hình thức chia sẻ nhiều người dùng: máy chủ chung, đồng bộ, hay chỉ chia sẻ gói skill/bài học. Rev 17 mới chốt một hình thức: gói skill công khai (mục 8.7) | Khi bắt đầu giai đoạn nhiều người dùng |
| O9 | Với từng harness: có chế độ không giao diện không; có cơ chế giới hạn quyền ghi, quyền đọc và công cụ không; tách được môi trường khỏi daemon không; adapter capture có xác định được hồ sơ người nhận theo đoạn phiên và bằng chứng tiếp xúc của từng mục không (mục 7.2, 8.10). Harness chưa đạt thì lượt rà soát không chạy | Phần capture khảo sát trong SP2; phần còn lại trong SP4, có NativeHostReceipt |
| O10 | **Đã đóng ở rev 20.** Đường cài gốc bị bỏ (Q25), nên không còn cần khảo sát thư mục skill và cổng nạp của từng harness | Đã xong |
| O11 | Ba thí nghiệm kiểm chứng rẻ: agent có ghi skill đều ở ba thời điểm không; skill tự viết có dùng lại được ở repo và harness khác không; mỗi tuần có bao nhiêu chất liệu | Trước plan SP3 |
| O12 | Phần nào của SP1 đợt 3 và đợt 4 được hoãn nghiệm thu theo Q24 (macOS/Linux, các kênh duyệt ngoài kênh ký chính). Rev 17 **chưa đổi** gì ở SP1 | Khi viết plan đợt 3 của SP1 |
| O13 | **Đã chốt.** Chủ dự án xác nhận ngày 2026-11-10 cả ba điểm: gói công khai gồm cả bộ skill đã lọc của chủ dự án; cờ `post_session_review` mặc định bật; harness dự phòng mặc định không được rà soát thay (mục 8.7, 8.10, 14.2) | Đã xong |

## 19. Hạn chót của các quyết định theo dự án con

| Trước | Cần chốt |
|---|---|
| Plan SP1 | Bảng điểm crash (tiến trình chết / mất điện) cho từng OS, syscall của `durable_publish` theo OS, bố cục data root và policy store, thứ tự ghi file và thuật toán ApplyJournal, thư viện WebAuthn, UI trang review, manifest trích xuất, tên package, O7 |
| SP2 | Hồ sơ người nhận theo đoạn phiên, bằng chứng tiếp xúc của từng Event và `session_ref` nguồn của từng mục quan sát, chốt trước khi pin schema capture (R17-04, R18-02); điều kiện gắn `sent_to_recipient` theo lời gọi model đã xác minh và nhận diện hồ sơ nguồn chưa xác minh (R20-02, R21-02); contract hook có giới hạn và trường hợp chưa bền vững, xử lý sự kiện muộn, ánh xạ task/session/episode của từng harness, checkpoint việc chạy dài, độ phủ capture theo harness, cách xác minh lớp 2 của Claude Code và Codex, schema chi tiết của `handoff`, đo lại nhịp worker (20 event, 60 giây), ngưỡng `active` (5 phút), mốc 14 ngày và các giới hạn của sổ (200 byte, 512 byte, 600 byte, 2 KB, 4 KB, 8 KB, 16 KB, 32 KB, 256 KB), đo chi phí quota mỗi lần ghi sổ, cách hook nhắc cập nhật theo từng harness |
| Plan SP1 đợt 3 | Bản ghi recovery grant trong policy store và thứ tự ghi `ended` (R17-01); thuật toán định danh vật lý của đích ghi theo từng OS và trình tự dời bản gốc sang backup (R17-02); ba pha của journal, ý định dời, publish với điều kiện đích vắng, định danh của bản thay thế và các pha của rollback (R18-01); ý định publish ghim sẵn định danh bản thay thế, `direction`, nhánh `original=absent` và vị trí nơi dựng cùng volume (R20-01); intent hướng của cả lượt, kiểm backup và tổng hợp theo hướng khi phục hồi (R21-01); danh sách hết hạn và dấu mất pin ghi cùng bản đang dựng, điểm công bố snapshot và thứ tự hoàn tất intent sau đó (R18-04); điểm ghép dấu rà soát ở SP4 (R21-04); áp lại hạn gốc của holder khi restore, theo mọi thứ tự restore (R17-07); tầng accounting trong policy store và quy trình đối soát sau restore policy (R17-11); các điểm crash mới trong bảng crash |
| SP3 | Ref đầy đủ của skill trong mọi schema và fixture, kể cả subject của approval theo lô (R17-03, R18-05); cách chọn khi mất pin và thời hạn của dấu mất pin (R18-05); revision chờ duyệt tách khỏi head phục vụ và action `skill_activate` (R18-06); hai cách đọc skill qua `get_artifact`, cặp `delivery_id` và `skill_ref` khi nạp, trạng thái `no_longer_eligible` và ba nhánh result của `submit_episode` (R20-03, R20-04, R21-03); tập dấu mất pin qua các lần restore lặp (R20-05); head theo phạm vi, quy tắc `adopt` và `skill_pin`, lọc phạm vi trước gộp trùng (R17-08); trạng thái `pending_approval` và proposal của draft có script (R17-09); kết quả ba thí nghiệm ở O11; giới hạn kích thước của skill; bảng trạng thái đầy đủ của skill; quy tắc gộp trùng và nhận nhóm; quy tắc ghim và nhận bản mới; schema chi tiết của `skill_draft` và `skill_patch`; luật kiểm tra nội dung riêng của dự án; số mục trả về khi Jev tắt |
| SP4 | Khảo sát O9; admission, reservation và điều kiện commit của job rà soát (R17-10); slot theo task, digest cửa sổ nguồn, dấu thành công và các trường `skill_review` trên wire (R18-07); một kết quả rà thành công cho mỗi task, giữ dấu qua restore và xử lý Job được restore (R20-06, R21-04); hai nhánh gửi, cách ghim approval cho đúng đích và xử lý hồ sơ `unknown` (R20-02, R21-02); cách dựng đầu vào theo đúng phiên và cách so hồ sơ người nhận (R17-04); hồ sơ chạy chỉ-đọc và các phép kiểm của nó (R17-05); prompt và định dạng đầu ra của lượt rà soát; trần số lượt mỗi ngày; ngưỡng đủ dữ liệu để đề xuất đổi bản mặc định; ngưỡng `dormant` của biến thể; thủ tục duyệt gộp |
| SP5 | Bảng chuyển trạng thái đầy đủ của bài học (actor, evidence), taxonomy proof cho từng loại bài học, chi tiết proof độc lập, so điều kiện áp dụng, gộp/merge giữ lineage, lan truyền lineage khi gộp; review artifact kèm resource closure; nếu bật Jev: payload Jev chính xác theo allowlist, cách gộp tập chỉ-tại-máy với kết quả Jev, cache/policy, accounting lời gọi đang chạy, canary đo độ trễ; tập task, cách gán nhãn độc lập, metric và ngưỡng của phép so sánh offline (R17-12) |
| SP6 | Thuật toán holdout (mục 12.2), estimand, missing/carryover, quy tắc CI và `dormant`, quy trình tự sinh proposal; manifest của gói công khai, kiểm tra quyền phân phối từng resource, danh sách thu hồi trong gói và thủ tục lọc (R17-13); dạng của định danh công khai, hồ sơ xuất và thủ tục đối soát sau restore (R18-08); intent xuất ghi trước khi trả gói, trạng thái có thể đã xuất, ánh xạ theo từng resource và kiểm danh sách thu hồi trước publish (R20-07); giấy phép (O1) |
| Hoãn (mục 10) | Thuật toán ranh giới filesystem trên từng OS, phát hiện file đổi trong lúc đọc, parser, chi tiết index |
| SP7 | Khảo sát native từng adapter và receipt cho các khả năng thực sự được tuyên bố, gồm lớp 2 |

## 20. Tình huống nghiệm thu bắt buộc cho SP1

Plan SP1 phải biến mỗi tình huống dưới đây thành test, hoặc ghi rõ thuộc SP nào nếu chỉ kiểm tra được khi domain đó có.

**Từ review rev 1:**
1. Payload khai owner khác principal không đọc/ghi được; truy cập trực tiếp bằng ref artifact/job cũng bị kiểm tra như vậy.
2. Hai checkout cùng remote, cùng đường dẫn tương đối nhưng nội dung khác nhau không dùng nhầm continuity/context.
3. Request trùng đồng thời và retry sau khi mất response trả cùng object/kết quả; cùng khóa khác payload trả `idempotency_conflict`.
4. Mất response của `prepare_task` không tạo Delivery hay holdout assignment mới khi retry.
5. Kill tiến trình tại mọi điểm crash không làm ref đã ACK trỏ tới dữ liệu không khôi phục được.
6. Replay cùng ledger không tạo thêm job/lesson/chi phí; payload đã hết hạn hoặc quarantine không bị rebuild phục sinh.
7. Snapshot DB–CAS đúng thì khôi phục được; snapshot thiếu hoặc sai subject bị từ chối trước khi thay dữ liệu đang dùng.
8. Hai daemon khởi động đồng thời, hoặc bảo trì chạy cạnh writer, không bao giờ có hai chủ ghi hợp lệ.
9. Secret qua tool trực tiếp, object/list lồng nhau, log lỗi, trace, outbox hay nội dung dẫn xuất không vượt privacy invariant.
10. Repo tắt `provider_egress` không bị gọi Jev qua retry, job nền, hay bài học dẫn xuất từ nguồn bị cấm (kiểm tra đầy đủ ở SP5).
11. Agent không tự nâng self-report thành `tool_observed`/`user_confirmed`; hai episode tự báo cáo không đủ xác minh (kiểm tra đầy đủ ở SP5).
12. Bootstrap hiện diff cụ thể; chỉ apply đúng approval và bản gốc; file đích bị sửa sau duyệt thì từ chối; thay đổi rủi ro cao không duyệt được bằng terminal.
13. `get_health()` không gọi mạng, không ghi; `deep=true` chỉ ghi Job/DoctorRun và không chặn `prepare_task`.
14. NativeHostReceipt loại fixture không được nhận là host thật; ServedReceipt/ReadAck gắn đúng task và revision artifact.
15. Receipt của gate có source/config/test inventory và kết quả cuối; giới hạn thời gian không đạt được bằng cách giảm coverage âm thầm.

**Từ review rev 2:**

16. Approval cho proposal A không dùng được cho proposal B, cho action khác, cho kho khác, hoặc sau khi hết hạn; nonce không dùng lại được.
17. Approval qua `ssh_key` được ghi mức `key_authorization`. Approval qua WebAuthn thiếu cờ UV, sai origin hoặc sai RP ID bị từ chối.
18. Thêm người ký thứ hai mà không có approval của người ký hiện có thì bị từ chối.
19. Proposal có skill c6 kéo theo script bị xếp rủi ro cao dù client gửi nhãn thấp.
20. Lớp 2 ở `unknown` thì kênh terminal bị từ chối với mã lỗi rõ ràng.
21. Restore không thay `writer.lock`; trong suốt quá trình restore không có writer thứ hai. Credential đã thu hồi sau thời điểm backup vẫn bị thu hồi sau restore.
22. Retry cùng `idempotency_key` sau khi nội dung bị quarantine/revoke trả cùng ID với mục `redacted`, không trả lại bytes.
23. Hết deadline đúng lúc commit trả `commit_outcome_unknown`; retry tìm ra kết quả thật, không tạo Delivery thứ hai.
24. Job đang `running` khi daemon chết được đưa lại hàng đợi ở epoch mới, với `attempt + 1`; ProviderInvocation dở dang ở `outcome_unknown`.
25. Một blob dùng chung bởi Event đã hết hạn và Evidence còn giữ vẫn resolve được qua Evidence; backup cũ vẫn restore được sau khi GC chạy trên kho.
26. Binary gặp kho có `schema_version` mới hơn thì từ chối trước mọi thao tác ghi.
27. Apply bị kill giữa hai file: khởi động lại ở `partially_applied`; tiếp tục hoặc rollback đều cho ra trạng thái nhất quán; file bị người dùng sửa giữa chừng dẫn tới `recovery_required`.
28. File trong data root có quyền rộng hơn owner-only bị `doctor` báo FAIL, và `--fix` sửa lại được.
29. Bài học sinh ra trong task đã được phục vụ bài học local-only mang lineage tới bài đó, kể cả khi client không khai; đổi `provider_egress` của nguồn có hiệu lực ngay với lần egress kế tiếp (kiểm tra đầy đủ ở SP5).

**Từ review rev 3:**

30. Bài học local-only từ repo A → task T1 ở repo B → continuity → task T2 ở repo B → mọi payload Jev của T2 bị chặn với nội dung có nguồn A. Request mới trong task đã nhận A cũng giữ hạn chế đó (model và ref trong SP1, kiểm tra đầy đủ ở SP2–SP5).
31. Proposal chứa HTML, script, event handler hoặc URL chỉ hiện như văn bản trên trang review. Request khác origin, sai `Host`, thiếu CSRF token hoặc thiếu token phiên không tạo được approval. Subject đổi thì challenge đổi và trang hiện subject mới.
32. Backup policy store → dùng approval → restore policy store → nộp lại chữ ký cũ bị từ chối. Điều này đúng với mọi tổ hợp restore (chỉ kho, chỉ policy, cả hai).
33. Approval được nhận trước khi hết hạn, crash giữa apply, khởi động lại sau khi đã hết hạn: tiếp tục hoặc rollback trong phạm vi recovery grant vẫn chạy được. Action ngoài phạm vi đó cần approval mới; file bị người dùng sửa không bị ghi đè.
34. Crash giữa commit policy store và commit kho: khởi động lại hoàn tất đúng intent một lần, không tạo mutation trùng.
35. Event và Evidence có payload nhỏ vẫn hết hạn đúng hạn; ledger không chứa nội dung của chúng.
36. Delivery chỉ có ServedReceipt được ghi `exposure_evidence=served_only`, không bao giờ là `read_ack`.

**Từ rev 5 (sổ bàn giao, thuộc SP2):**

37. Cập nhật một phần giữ nguyên các mục không gửi; mục chỉ-thêm không xóa được; `supersedes` thiếu lý do hoặc trỏ sai trả `invalid_input`.
38. `base_revision` cũ trả `revision_conflict` và không tạo revision; gọi lại cùng `idempotency_key` nhận đúng kết quả cũ.
39. Worker làm mới phần quan sát được không đổi `handoff_revision` và không gây `revision_conflict` cho agent.
40. Giết tiến trình harness, không có sự kiện kết thúc phiên: principal khác trên cùng checkout nhận revision đã commit gần nhất; trạng thái không phải `ended`.
41. Secret mồi trong sổ không xuất hiện trên đĩa, log hay trace; checkout khác không nhận được sổ.
42. Sổ không xuất hiện trong payload Jev và không giúp bài học đạt `verified`.
43. `prepare_task` của SP2 liệt kê các phần chưa có trong `degraded_codes`, không trả mảng rỗng mà thiếu mã.
44. Sổ có `task_state` khác `open`, hoặc quá 14 ngày không cập nhật, không xuất hiện trong danh sách của `mode=discover` nhưng vẫn tìm được khi truyền đúng `task_id`.

**Từ review rev 5 (thuộc SP2):**

45. A ghi, B tiếp quản, A đọc revision mới rồi ghi đúng `base_revision` mà không tiếp quản: bị từ chối.
46. Principal khác khai `session_id` của B: `identity_mismatch`. `session_id` không xuất hiện trong L0, L1, L2, log hay ledger.
47. Hai bên cùng tiếp quản từ một `writer_generation`: chỉ một bên thắng. Tiếp quản khi phiên giữ sổ còn `active` mà thiếu `acknowledge_active` bị từ chối.
48. Principal cùng repo nhưng khác checkout bị từ chối ở `discover`, đọc theo ref, resume, ghi và replay, kể cả khi biết ID và revision.
49. Đề xuất đổi ràng buộc, kèm câu trả lời đồng ý, câu phủ định chứa đoạn trùng, câu đồng ý về việc khác hoặc không có câu trả lời: ràng buộc cũ vẫn là hiện hành ở L1 và sau replay, L0 hiện đúng trạng thái và số đề xuất đang chờ, và đề xuất ở nguyên `proposed` cho tới khi người giữ sổ đóng nó.
50. `supersedes` trỏ sai loại hoặc trỏ mục đã bị thay trả `invalid_input`. Mở lại phương án đã loại theo `reopens`. Replay dựng đúng tập đang hiệu lực.
51. Event nguồn bị revoke hoặc quarantine sau khi đã vào sổ: L1, L2, retry, revision cũ và `description` do brain dựng đều không có bytes bị cấm; ref và trạng thái `redacted` đúng hợp đồng; digest đã phục vụ vẫn còn trong ServedReceipt.
52. Event nguồn hết hạn: mục trả `expired`. Worker làm mới không gia hạn, restore không phục sinh.
53. Worker chụp ref cũ, agent commit, worker xong sau: patch của agent vẫn còn. Sổ chỉ có worker được agent đầu tiên cập nhật bằng `base_revision=0`.
54. Phiên chết khi mới có dưới 20 event: event đã ACK được lên lịch làm mới và `observed_through` phản ánh đúng. Event đến muộn không làm lùi watermark của `producer_stream` đó; event đến sau `ended` không đổi trạng thái, chỉ `session_resumed` mới đổi.
55. `mode=discover` không tạo task, Delivery, Job, không gọi Jev và không vào mẫu số. Delivery resume gắn đúng task cũ và ref đã đọc.
56. Crash trước commit, sau commit trước ACK, retry sau tiếp quản và retry sau revoke: cùng khóa nhận đúng kết quả đã commit trong phạm vi còn quyền, không tạo revision mới, không trả lại quyền ghi.
57. Mục thứ 31 đang hiệu lực vẫn có trong L1. Nội dung đa byte tính đúng theo UTF-8. Một mục vượt 2 KB, một patch vượt 16 KB, phần bắt buộc vượt 32 KB hoặc ràng buộc vượt 16 KB trả `invalid_input` và giữ nguyên sổ. `task_goal` dài được cắt đúng ranh giới ký tự ở L0 và L1.
58. `context_budget_tokens` thấp hơn L0: không cắt đôi, bỏ nguyên sổ, trả `continuity_truncated` và vẫn tìm được bằng `task_id`.
59. Đủ bốn tổ hợp của `automatic_capture` và `manual_submission` theo bảng ở mục 7.4, gồm đường capture-only. Đổi cờ khi job worker đang chờ: job theo cờ hiện hành lúc bắt đầu và lúc commit. Dữ liệu cũ phục vụ đến hết hạn và nhánh `not_stored_policy` trả đúng kết quả, kể cả khi retry.

**Từ review rev 6 (thuộc SP2):**

60. Chuỗi A → B → A bằng tiếp quản: patch đến muộn của A mang fence cũ bị từ chối dù đúng người giữ và đúng `base_revision`. Tiếp quản thiếu `base_revision` hoặc `fence` trả `invalid_input`.
61. Restore kho về snapshot cũ: người giữ cũ mất hiệu lực và patch cũ bị từ chối; phiên phải tiếp quản lại. Sau khi đã tiếp quản lại và `writer_generation`, `handoff_revision` trùng với request từ trước restore, request cũ đó vẫn bị từ chối.
62. `schema_digest` thiếu hoặc khác ở từng chiều trên socket đã pin: trả `unsupported_version` và không chạy tool (đối chiếu với wheel I2 lịch sử giữ kết quả quan sát `identity_mismatch` với `bearer_sent=0`, `dispatches=0` theo §7.4).
63. Resume: receipt sai principal hoặc task trả `not_found`; không có receipt ghi `exposure_evidence=unknown`; ReadAck khớp digest thực tế của bản đã render; đổi người giữ hoặc `handoff_revision` giữa lúc đọc và resume trả `revision_conflict`; chỉ phần quan sát mới hơn thì đi tiếp với `observed_newer`.
64. Sổ đầy: patch không làm tăng dung lượng vẫn được nhận; đề xuất đổi ràng buộc vào được vùng riêng; đề xuất bị từ chối rời vùng đang chờ; ràng buộc cũ vẫn còn.
65. Câu trả lời gắn với đề xuất bị quarantine hoặc hết hạn: L0 không có trích đoạn; L1, report, replay và restore trả `redacted` hoặc `expired`; trạng thái đề xuất không đổi. `task_goal` hết hạn thì tìm đúng theo `task_id` trả RedactedItem.
66. Agent thêm ràng buộc mâu thuẫn với mục đang có: mục cũ vẫn đang hiệu lực và không bị thay.

**Từ review rev 7 (thuộc SP2):**

67. A commit tiếp quản nhưng mất ACK, B tiếp quản, A retry cùng khóa: nhận kết quả đã commit với `writer_status=not_holder`, và patch tiếp theo của A bị từ chối.
68. Request chỉ xin tiếp quản: thành công trả fence mới và `writer_status=holder`, tăng `revision`, không tăng `handoff_revision`; retry sau khi mất ACK nhận đúng kết quả; `manual_submission` tắt trả `not_stored_policy`, giữ nguyên người giữ, fence và revision.
69. Receipt L0 của cùng artifact và revision trả `not_found`. Receipt cũ của `revision` 12 kèm counter mới của `revision` 13 trả `revision_conflict`. Không có receipt thì vẫn kiểm counter theo header của `revision` đó và ghi `unknown`.
70. Crash trước khi hoán đổi kho: kho cũ vẫn nguyên và người giữ cũ vẫn hợp lệ. Crash giữa hai bước đổi tên được phục hồi với `restore_epoch` đi cùng đúng bản kho. `writer.lock` giữ nguyên định dạng hiện có.
71. `merges` trên mục loại còn hiệu lực: mục nguồn rời tập đang hiệu lực và còn ở L2; trỏ mục không còn hiệu lực trả `invalid_input`. Miễn trừ giới hạn tổng không miễn giới hạn một mục, một patch, vùng đề xuất đang chờ hay quyền ghi.
72. `depends_on_change` trỏ đề xuất không tồn tại trả `invalid_input`; phiên sau thấy đúng phụ thuộc ở L1.

**Từ review rev 8 (thuộc SP2):**

73. Sau restore: `discover` trả `revision_epoch` đã commit dù fence sống ở epoch mới; client mới đọc L1 và resume bằng epoch đã commit, lấy `handoff_live`, và tiếp quản bằng fence sống thành công; request từ trước restore vẫn bị từ chối; task mới tạo được sổ đầu tiên với fence `(restore_epoch hiện hành, 0)`.
74. A → B → A: replay ACK tiếp quản cũ có fence `(5,9)` khi fence sống là `(5,11)` trả `not_holder`, dù người giữ hiện hành vẫn là A.
75. Hai lần restore liên tiếp cho hai `restore_epoch` khác nhau. File metadata hỏng trả `INTEGRITY_FAILURE` trước khi phục vụ.

**Từ review rev 9 (thuộc SP2):**

76. Restore, rồi migrate trước bất kỳ lần tiếp quản nào: `restore_epoch` giữ nguyên sau migrate, và thử lại patch mang epoch cũ vẫn bị từ chối.
77. Kho SP2 mất file metadata: từ chối phục vụ bằng `INTEGRITY_FAILURE`, cả khi mở kho và khi phục hồi swap. Kho schema trước SP2 đọc thiếu thành 0, và nâng lên SP2 ghi giá trị 0.

**Từ rev 16 (thuộc SP2):**

78. Phục vụ sổ X ở `revision` 5, restore về 4, rồi ghi Y ở `revision` 5: ref cũ không trỏ sang Y, cả khi đọc lẫn trong ServedReceipt, ReadAck và lineage.

**Từ rev 17 (vòng skill, thuộc SP3 và SP4):**

79. Skill `project` do agent viết ở repo X: harness khác trên repo X nhận L0 kèm nhãn `agent_reported` và "chưa thăng hạng" từ lần `prepare_task` kế tiếp. Principal ở repo Y không thấy skill đó qua `prepare_task`, `search_knowledge` hay đọc theo ref, kể cả khi biết ID và revision.
80. Secret mồi trong `skill_draft` không xuất hiện trên đĩa, log hay trace. Privacy filter lỗi thì không lưu gì của lần ghi đó.
81. `skill_draft` có file thực thi, hoặc file được tham chiếu như một lệnh (trực tiếp hoặc gián tiếp), không có hiệu lực tự do: bị xếp rủi ro cao dù client gửi nhãn thấp, trả `skill_status=pending_approval` kèm ref proposal, và không xuất hiện trong tập phục vụ hay pin. Repo đang phục vụ R1 nhận một bản vá R2 có script: R1 tiếp tục được phục vụ; R2 không đọc được qua `prepare_task`, `search_knowledge` hay đọc theo ref; `adopt` gửi kèm không đổi pin. Từ chối R2: head và pin không đổi. Duyệt bằng `skill_activate`: head chuyển sang R2 trong một transaction; base đã đổi thì trả `revision_conflict`; resource đổi sau khi duyệt thì approval bị từ chối. ACK của chính lần ghi revision chờ duyệt trả metadata của ref, `proposal_ref` và trạng thái pin, nhưng nội dung của revision đó không đọc được qua tool nào. Kích hoạt hợp lệ không tạo file nào trong thư mục skill của harness.
82. `skill_patch` với `base_ref` không khớp head trong phạm vi của repo trả `revision_conflict` và không tạo phiên bản. Gọi lại cùng `idempotency_key` nhận đúng kết quả cũ.
83. Repo X và repo Y cùng fork skill `owner` S@1: hai bản vá cùng tồn tại, không bên nào nhận `revision_conflict` vì bản của bên kia. Mỗi repo thấy bản vá của mình ngay. Head `owner` không đổi cho tới khi được duyệt. ACK gộp trùng của X không chứa ref riêng của Y.
84. Hai biến thể trong một nhóm cùng tồn tại, không biến thể nào bị ghi đè. Hồ sơ sử dụng tách theo biến thể. Repo đã ghim S@1 mà vá không kèm `adopt`: đọc được bản vá mới, nhưng `prepare_task` vẫn chỉ đưa S@1; kèm `adopt` thì pin đổi đúng sang bản mới. Không ứng viên nào của nhóm vượt bản đã ghim.
85. Approval cho một lô thăng hạng không dùng được khi một skill trong lô đổi revision. Skill chưa qua kiểm tra nội dung riêng của dự án bị từ chối thăng hạng.
86. Skill bị thu hồi hoặc quarantine: mọi phạm vi, mọi bản đã ghim và mọi lần retry trả `redacted`, không trả lại bytes.
87. `manual_submission` tắt: `skill_draft` trả `not_stored_policy` và không tạo phiên bản, kể cả khi retry.
88. Lượt rà soát chỉ chạy đúng lệnh đã duyệt, trên hồ sơ đã `verified`. Transcript dụ harness ghi file bằng đường dẫn tuyệt đối vào checkout hoặc một thư mục ngoài vùng tạm: các file mồi giữ nguyên. Trạng thái `unknown`, `unsupported`, hoặc digest cấu hình đã đổi: không process nào được spawn, và phiên kế tiếp nhận `skill_review_pending` đúng lý do. Cờ `post_session_review` hoặc `manual_submission` tắt thì không chạy.
89. Task T chuyển từ harness A sang B. Một Event của phiên A đến muộn trước lượt rà phiên B: payload phiên B không chứa byte nào của phiên A. Trong một phiên khác, đổi hồ sơ A → B trên cùng `session_ref` và rà với B. Khi B chưa được duyệt, mục đã gửi cho A không được chuyển sang B. Lặp trên fixture độc lập với cùng dữ liệu và approval cho đúng hồ sơ B: nhánh đích mới gửi mục đủ quyền, loại mục có nguồn tắt `provider_egress` và loại mục có lần gửi chưa rõ kết quả. Lặp ca B đã duyệt với hồ sơ nguồn thiếu provider hoặc account: loại đúng mục đó và giữ mục đủ quyền. Hồ sơ đích thiếu provider hoặc account: không gọi harness. Với cùng hồ sơ đã xác minh, Event tạo sau lời gọi model cuối và patch chỉ có trong brain đều bị loại. Payload không chứa ref nguồn hay lineage.
90. Đầu ra của lượt rà soát đi qua privacy filter, mang nhãn `agent_reported`, và không giúp bài học đạt `verified`.
91. Jev tắt: `prepare_task` không tạo ProviderInvocation nào tới Jev, và skill vẫn được trả theo bộ lọc tại máy.
92. Brain không tạo, sửa hay xóa file nào trong thư mục skill của harness ở bất kỳ luồng nào: ghi skill, ghim, thăng hạng, thu hồi hay quarantine (Q25). Một ChangeProposal có file đích nằm trong thư mục skill của harness bị từ chối trước khi tới cổng duyệt.

**Từ review rev 17:**

93. (SP1 đợt 3) Backup khi ApplyJournal đang dở, file A đã ghi và B còn nguyên → apply xong → người dùng đưa B về bytes gốc → restore riêng kho chính: lần resume giữ nguyên B và yêu cầu quyền mới. Fault injection sau khi policy store ghi grant `ended` và trước khi kho chính ghi trạng thái cuối: khởi động lại reconcile đúng một lần. Crash thông thường giữa hai file vẫn tiếp tục được bằng grant còn `active` của đúng subject.
94. (SP1 đợt 3) Sau approval, thay thư mục cha bằng junction hoặc symlink trỏ sang đích khác có cùng bytes gốc; lặp lại với file vốn chưa tồn tại: apply, resume và rollback đều từ chối và không ghi vào đích thay thế.
95. (SP1 đợt 3) Người dùng sửa file đích giữa bước kiểm và bước publish: bản sửa còn nguyên, journal dừng ở `recovery_required`, không byte nào của người dùng bị mất.
96. (SP3) Phục vụ skill X ở `revision` 5, restore về 4, rồi ghi Y ở `revision` 5: ref của X trả `not_found` và không được phục vụ thành Y; bản vá dựa trên X không tạo phiên bản; receipt, usage, pin và lineage của X không bị gán sang Y; repo ghim X nhận `skill_pin_lost`, kể cả khi snapshot không chứa cả pin lẫn revision X. Một approval lô cũ gặp revision mới có cùng số và cùng digest nhưng khác `revision_epoch`: bị từ chối. Đọc một revision cũ còn trong snapshot vẫn thành công. Restore cùng một backup hai lần liên tiếp trước khi người dùng xử lý: dấu mất pin vẫn còn sau lần thứ hai. Restore tiếp sau khi người dùng đã xác nhận: dấu đã xử lý không bị dựng lại.
97. (SP3) Bản vá từ một parent có nguồn tắt `provider_egress` kế thừa ràng buộc đó, kể cả khi task tạo bản vá chưa đọc parent qua MCP.
98. (SP4) Auto trigger và `request_improvement` cùng lúc cho một cửa sổ: chỉ một Job. Phiên hoạt động lại giữa job, người dùng tắt cờ giữa job, hoặc agent tự ghi skill trước commit: không skill nào được ghi thêm, Job vào `cancelled` với lý do `discarded`, và accounting thực tế còn nguyên. Crash sau commit không tạo skill thứ hai. Phiên đã `ended` nhận một Event muộn, auto giữ cửa sổ W1 và manual yêu cầu với cửa sổ W2: chỉ một Job chạy và chỉ một kết quả được ghi cho task. `manual_submission` tắt: phiên kế tiếp nhận `skill_review` với `reason=blocked_by_policy` và không có `material_refs`. W1 đã thành công rồi mới có Event đến muộn: W2 không được nhận. W1 bị `discarded` rồi có W2 với chất liệu mới: W2 được nhận và chạy. Retry cùng W1 sau khi nó kết thúc nhận lại đúng Job cũ.
99. (SP3) Repo ghim R1, vá thành R2 mà không `adopt`: đọc tường minh R2 theo ref đầy đủ thành công và được ghi là lượt đọc tường minh, trong khi Delivery vẫn chỉ đề cử R1 và nạp theo Delivery chỉ cấp R1. Sau khi đổi pin sang R2, retry Delivery cũ không cấp R1 như bản đang ghim: mục đó trả `no_longer_eligible` và giữ nguyên ID. Hai repo ghim hai ref khác nhau của một nhóm trên cùng harness: mỗi repo chỉ được đề cử và nạp theo Delivery đúng ref của mình. Host tự nạp một file local cùng digest mà không có lần cấp qua MCP: không được tính là nạp, và M2 ghi đúng như vậy. Delivery D đề cử hai skill A và B. `get_artifact` gửi `delivery_id=D` cùng full `skill_ref` của B và chỉ cấp resource của B theo cấp yêu cầu. ServedReceipt gắn đúng D và B. Thiếu `skill_ref` là `invalid_input`. Ref ngoài D, hoặc Delivery của task, principal hay scope khác, trả `not_found` trước khi đọc CAS.
100. (SP3) Quarantine R2: mọi lần cấp mới qua MCP bị chặn, ở mọi repo và với mọi bản ghim, kể cả retry cùng khóa. (Phần về bản cài gốc của ca này ở rev 18 và rev 19 không còn, vì đường cài gốc đã bị bỏ.)
101. (SP1 đợt 3) Backup cả hai kho trước khi Event hết hạn, đợi job dọn ghi tombstone, rồi restore cả hai bản cũ, theo cả hai thứ tự: lần đọc đầu tiên, trước khi job dọn chạy lại, không trả bytes đã hết hạn. Một blob vừa có Event hết hạn vừa có Evidence còn giữ: vẫn đọc được qua Evidence, không đọc được qua Event. Evidence E còn được một Lesson giữ ở kho sống nhưng đã quá hạn trong snapshot cũ: kill sau khi dựng danh sách hết hạn và trước khi hoán đổi thì kho cũ mở lại vẫn đọc được E; kill sau khi hoán đổi và trước khi hoàn tất intent thì kho mới vẫn chặn E ngay ở lần đọc đầu tiên.
102. (SP1 đợt 3, kiểm đầy đủ ở SP4 và SP5) Dùng hết trần trong kỳ với số lời gọi đang chạy bằng 0, rồi restore kho chính về trước các lời gọi đó: trần vẫn được tính là đã chạm. Restore khi còn khoản giữ chỗ `outcome_unknown`: khoản đó còn nguyên. Restore policy store: lời gọi mới trong kỳ bị chặn cho tới khi đối soát, và khóa đã có hiệu lực ở lời gọi đầu tiên sau khi hoán đổi.
103. (SP5) Phép so sánh offline: tập task có ca mà skill đúng chưa từng được bộ chọn cũ phục vụ; nhãn không lấy từ lịch sử dùng; hai bộ chọn chạy cùng giới hạn; metric và ngưỡng có trước khi chạy.
104. (SP6) Xuất gói công khai: resource bị thay sau khi duyệt, nguồn bị quarantine, hoặc resource thiếu quyền phân phối đều làm lần xuất bị từ chối. Gói không chứa ref tới evidence, task hay checkout. Skill bị thu hồi sau khi phát hành xuất hiện trong danh sách thu hồi của lần xuất kế tiếp, dưới định danh công khai, không có `skill_id` hay `revision_epoch`. Backup kho chính, xuất R, quarantine R, rồi restore backup đó: manifest kế tiếp vẫn liệt kê đúng định danh công khai đã xuất của R. Restore policy store làm mất hồ sơ xuất: lần xuất kế tiếp bị chặn cho tới khi đối soát. Crash giữa lúc trả gói và lúc ghi kết quả: các định danh công khai trong intent ở trạng thái có thể đã xuất, và vẫn được đưa vào danh sách thu hồi khi cần. Quarantine một resource thành phần rồi restore kho chính: ánh xạ theo resource vẫn tìm ra đúng gói đã xuất. Thu hồi một bản đã phát hành sau khi manifest kế tiếp đã được ký: lần publish bị chặn cho tới khi manifest được dựng và duyệt lại.

**Từ review rev 18:**

105. (SP1 đợt 3) Kill ngay sau khi đổi tên bản gốc và trước khi ghi pha `original_moved`; lặp lại ở ngay trước và ngay sau khi publish bản thay thế. Ở mỗi điểm, cả tiếp tục lẫn đưa bản gốc về lại đều cho trạng thái nhất quán. Người dùng tạo một file mới ở đích giữa hai bước: file đó và backup đều được giữ, journal về `recovery_required`. Rollback sau khi một file đã publish thành công xác minh đúng bản thay thế theo định danh đã ghim, dù định danh đó khác bản gốc.

**Từ review rev 20:**

106. (SP1 đợt 3) Kill sau khi publish và trước khi ghi pha, với file ở đích đúng là bản do daemon publish: phục hồi nhận đúng `replacement_published`. Lặp lại với một file cùng bytes nhưng khác định danh do người dùng tạo: file đó, backup và bản thay thế đều được giữ, và journal về `recovery_required`. Kill ngay sau lần đưa bản gốc cuối cùng về lại trong hướng rollback: journal kết thúc ở `rolled_back`, không bị coi là apply chưa bắt đầu. Rollback một file tạo mới (`original=absent`): chỉ bản thay thế do journal sở hữu bị dời đi, và đích về trạng thái vắng.

**Từ review rev 21:**

107. (SP1 đợt 3) Duyệt rollback một proposal đã `applied`. Kill sau khi ghi intent hướng rollback vào policy store và trước khi chiếu sang journal. Lặp lại sau khi chiếu hướng và ghi ý định dời file đầu tiên, trước lần rename đầu tiên. Tại cả hai điểm, tất cả file vẫn ở `replacement_published`. Khởi động lại giữ đúng hướng rollback, trạng thái `partially_applied` và grant còn `active`. Tiếp tục đưa các đích về trạng thái gốc, rồi ghi `rolled_back` và kết thúc đúng grant. Thử thêm proposal đang apply dở có file `original=absent` chưa từng publish: rollback ghi nhận file đó đã ở trạng thái gốc và không đòi backup cho nó. Lặp với `original=present`, bản thay thế ở đích vẫn đúng nhưng backup cần cho rollback bị mất hoặc sai định danh hay digest: trước lần dời bản thay thế, journal vào `recovery_required` và đích giữ nguyên.
108. (SP4) Backup khi task T đã có chất liệu, rồi rà thành công T và restore backup. Thử trigger tự động và `request_improvement` bằng khóa mới ở cả cửa sổ cũ và cửa sổ mới. Dấu thành công còn, kết quả bị mất báo `skill_review_result_lost` kèm `job_id` trong dấu. Không phát sinh invocation thứ hai, accounting trước restore còn nguyên. Lặp với backup chứa Job đang chờ, kill sau công bố snapshot và trước mở hàng đợi. Job đó bị hủy trước khi có thể gọi harness, và yêu cầu mới ở cả hai cửa sổ vẫn báo `skill_review_result_lost`. Replay còn bản ghi idempotency giữ đúng ID đã commit. Restore qua một snapshot tạm không có T rồi qua snapshot có T vẫn giữ dấu. Nếu kho sống bị mất, task trong backup thiếu dấu thành công nhận `skill_review_history_unknown` và không chạy lượt rà. Lặp đường mất kho sống → restore A thiếu T → restore B có T nhưng thiếu dấu thành công: T vẫn nhận `skill_review_history_unknown` và không gọi harness. Task mới sau restore vẫn được xét bình thường.

## 21. Ánh xạ review → spec

**Review rev 1** (`2026-10-30-system-design-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-S01 contract v1 | Q17, mục 6 |
| SB2-S02 danh tính | Mục 5.1, 5.2, 10 (ranh giới filesystem) |
| SB2-S03 nguồn evidence | Mục 8.2 |
| SB2-S04 privacy/egress | Q10, mục 14.2 |
| SB2-S05 cổng duyệt, bootstrap | Q18, mục 11.2, 11.3, SP1 |
| SB2-S06 commit/ACK/replay | Mục 5.4 |
| SB2-S07 idempotency, outbox, job | Mục 6.3, 6.4, 7.1 |
| SB2-S08 retention, quarantine, backup | Mục 5.6, 5.7 |
| SB2-S09 một chủ ghi | Mục 5.5 |
| SB2-S10 deadline, deep doctor | Mục 6.1, 6.5, 13 |
| SB2-S11 delivery/read/applied/native | Mục 5.3, 17.3, M2 |
| SB2-S12 Conflict Review | Mục 8.3; chi tiết trước SP5 (SP3 ở các rev trước rev 17) |
| SB2-S13 holdout | Mục 12.2; thuật toán trước SP6 |
| SB2-S14 phiên im lặng, capture thiếu | Mục 7.2, 7.3, 12.1 |
| SB2-S15 cache, budget | Mục 9 |
| SB2-S16 context ref | Mục 10 |
| SB2-S17 phân tầng, trích xuất | Mục 4.2, 17.4 |
| SB2-S18 gate, catalog | Mục 17.2, 17.5, 14.1, M1–M3 |

**Review rev 2** (`2026-10-30-system-design-rev2-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R2-01 chữ ký và xác nhận người dùng | Q18, mục 11.3 (approval message, kênh và mức bảo đảm, đăng ký người ký) |
| SB2-R2-02 xếp rủi ro, lớp 2 | Mục 11.3 (xếp rủi ro theo resource đi kèm, trạng thái lớp 2, danh sách lệnh), SP2/SP7 |
| SB2-R2-03 CAS bền khi mất điện | Mục 5.4 (`durable_publish`, mức độ bền) |
| SB2-R2-04 restore, khóa, trạng thái bảo mật | Mục 5.5 (bố cục data root), 5.7 (policy store) |
| SB2-R2-05 retry vượt revoke/quarantine | Mục 6.3 |
| SB2-R2-06 commit chưa xác định, lease sau crash | Mục 6.4, 6.5 |
| SB2-R2-07 ReadReceipt | Mục 5.3 (ServedReceipt, ReadAck), 6.1, 12.2 |
| SB2-R2-08 cờ opt-out, lineage | Mục 14.2 (bốn cờ, năm cờ từ rev 17; lineage do server lập, kiểm tra theo policy hiện hành) |
| SB2-R2-09 cấm egress khác cấm delivery | Mục 9 (hai tập ứng viên) |
| SB2-R2-10 bound vượt ngân sách | Mục 9 (giữ chỗ bằng chi phí tối đa) |
| SB2-R2-11 độ mới của L0 | Mục 10 (`source_digest`, `repr_digest`) |
| SB2-R2-12 blob CAS dùng chung, backup | Mục 5.6, 5.7 |
| SB2-R2-13 phiên bản, migration | Mục 1 (hạ lời hứa), 5.8 |
| SB2-R2-14 quyền file toàn kho | Mục 5.9, 13 |
| SB2-R2-15 apply nhiều file | Mục 11.2 (ApplyJournal) |

**Review rev 3** (`2026-10-30-system-design-rev3-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R3-01 lineage qua continuity và trường gửi đi | Mục 7.3, 14.2; SP1 (model), tình huống 30 |
| SB2-R3-02 an toàn trang review | Mục 11.2, 14.1; tình huống 31 |
| Nghĩa vụ A: nonce sống qua restore policy, crash giữa hai kho | Mục 5.4 (intent), 5.7 (`trust_generation`); tình huống 32, 34 |
| Nghĩa vụ B: approval khác recovery grant | Mục 11.2; tình huống 33 |
| Nghĩa vụ C: ServedReceipt chỉ là proxy | Mục 12.2 (`exposure_evidence`); tình huống 36 |
| Checklist 3: phạm vi bảng crash | Mục 5.4 |
| Checklist 4: payload có thời hạn nằm ngoài ledger | Mục 5.3; tình huống 35 |
| Checklist 6: chia SP1 thành đợt | Mục 15 |

**Rev 5** (thiết kế do chủ dự án duyệt ngày 2026-11-09, không đến từ review):

| Thay đổi | Ở đâu |
|---|---|
| Mục tiêu bàn giao không đổi hướng | Mục 1, Q21 |
| Sổ bàn giao viết liên tục trong phiên | Q14, mục 5.3, 5.6, 7.3, 7.4 |
| Đơn vị của `utf8-byte-v1` | Mục 6.2 |
| Tool có domain một phần báo bằng `degraded_codes` | Mục 6.2 |
| Sổ bàn giao trong context, đo lường, holdout, privacy | Mục 10, 12.1, 12.2, 14.2 |
| SP2 làm bản hẹp của `prepare_task`, `get_artifact`; bài diễn tập ở M1 | Mục 15, 19 |
| Tình huống nghiệm thu 37–44 | Mục 20 |

**Review rev 5** (`2026-11-09-system-design-rev5-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R5-01 quyền đọc cùng checkout, tiếp quản | Mục 7.4 (Binding, Người giữ sổ và tiếp quản); tình huống 45–48 |
| SB2-R5-02 ràng buộc còn hiệu lực sau `supersedes`, `goal` | Q21, mục 7.4 (Đổi quyết định, Đổi ràng buộc của người dùng); tình huống 49, 50 |
| SB2-R5-03 trích đoạn giữ quyền và thời hạn của nguồn | Mục 5.3, 5.6, 7.4 (Trích đoạn), 14.2; tình huống 51, 52, 59 |
| SB2-R5-04 hai revision, tìm head đã cấp quyền, wire | Mục 7.4 (Header, Đường đọc, Thay đổi contract) |
| SB2-R5-05 quy tắc merge, sổ chỉ có worker | Mục 7.4 (Revision và merge, Đường ghi của worker); tình huống 53, 54 |
| SB2-R5-06 tách discover và resume, retry | Mục 6.1, 7.4 (Đường đọc, Retry), 12.2; tình huống 55, 56 |
| SB2-R5-07 giới hạn làm mất nội dung bắt buộc | Mục 7.4 (Cấp đọc và giới hạn); tình huống 57 |
| SB2-R5-08 budget thấp, token nội bộ và tính phí | Mục 6.2, 7.4, 10; tình huống 58 |
| SB2-R5-09 oracle của diễn tập M1 | Mục 15 (M1) |

**Review rev 6** (`2026-11-09-system-design-rev6-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R5-02 khớp câu chữ không chứng minh đồng ý | Q21, mục 7.4 (Đổi ràng buộc của người dùng): bỏ cơ chế xác nhận; tình huống 49, 66 |
| SB2-R5-03 câu xác nhận theo ranh giới của nguồn | Mục 7.4 (Trích đoạn, Đổi ràng buộc); tình huống 65 |
| SB2-R5-01 fence qua nhiều lần tiếp quản, restore | Mục 5.3, 5.7, 7.4 (Người giữ sổ và tiếp quản); tình huống 60, 61 |
| SB2-R5-04 trao đổi `schema_digest`, nhánh theo mode | Mục 7.4 (Thay đổi contract); tình huống 62 |
| SB2-R5-05 revision, watermark, policy của worker | Mục 7.4 (Revision và merge, Đường ghi của worker, Trạng thái phiên); tình huống 54, 59 |
| SB2-R5-06 `resume_ref` đã được phục vụ | Mục 7.4 (Đường đọc); tình huống 63 |
| SB2-R5-07 sổ hết chỗ, `task_goal` | Mục 7.4 (Cấp đọc và giới hạn, Đổi ràng buộc); tình huống 57, 64 |

**Review rev 7** (`2026-11-09-system-design-rev7-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R5-01 fence qua restore, ACK lịch sử | Mục 5.7, 7.4 (Người giữ sổ và tiếp quản, Retry, Thay đổi contract); tình huống 61, 67, 70 |
| SB2-R5-04 ACK của request chỉ xin tiếp quản | Mục 7.4 (Revision và merge, Lỗi, Thay đổi contract); tình huống 68 |
| SB2-R5-06 receipt L1 và counter của đúng revision | Mục 7.4 (Revision và merge, Đường đọc, Thay đổi contract); tình huống 69 |
| Chi tiết `merges`, miễn trừ giới hạn | Mục 7.4 (Cấp đọc và giới hạn, Đổi quyết định); tình huống 71 |
| Chi tiết phụ thuộc ngoại lệ theo phiên, ca 49 | Mục 7.4 (Đổi ràng buộc của người dùng); tình huống 49, 72 |

**Review rev 8** (`2026-11-09-system-design-rev8-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R8-01 slot mới bị writer cũ ghi đè | Mục 5.7, 7.4 (Thay đổi contract): không đổi định dạng `writer.lock`; tình huống 70, 75 |
| SB2-R5-01 fence sống, `writer_status` của ACK cũ | Mục 7.4 (Header, Người giữ sổ và tiếp quản, Đường đọc, Retry); tình huống 73, 74 |
| Nhãn phiên bản | Đầu tài liệu |

**Review rev 9** (`2026-11-09-system-design-rev9-review.md`):

| Review | Đã xử lý ở |
|---|---|
| SB2-R9-01 migrate làm mất `restore_epoch` | Mục 5.7, 5.8; tình huống 75–77 |

**Rev 16:**

| Thay đổi | Ở đâu |
|---|---|
| Ref bất biến qua restore, `discover` trả epoch đã commit | Mục 7.4 (Binding, Revision và merge, Người giữ sổ và tiếp quản, Đường đọc, Thay đổi contract); tình huống 73, 78 |

**Rev 17** (hướng do chủ dự án duyệt ngày 2026-11-10 theo đề xuất `2026-11-10-skill-loop-direction-design.md`, không đến từ review):

| Thay đổi | Đề xuất | Ở đâu |
|---|---|---|
| Hai sản phẩm: vòng skill và sổ bàn giao | P1 | Mục 1, Q22 |
| Skill là đơn vị tri thức thủ tục; quan hệ với bài học | P2 | Mục 3 (Hermes Agent), 5.3, 8 (mở đầu), 8.1, 8.6 |
| Ba phạm vi, thăng hạng, duyệt gộp | P3 | Q9, Q12, Q20, mục 8.7, 11.3 (`skill_promote`, `skill_publish`), 14.1 |
| Phiên bản, biến thể, ghim theo repo, hồ sơ sử dụng | P4 | Mục 5.3, 8.3, 8.5, 8.8 |
| Ba thời điểm và đường ghi skill | P5 | Q14, mục 6.1, 8.9, 8.11 (Thay đổi contract) |
| Rà soát sau phiên bằng harness | P6 | Mục 1 (ngoài phạm vi), Q11, Q23, mục 4, 5.3, 6.1, 6.2, 7.4, 8.10, 14.1, 14.2 (cờ thứ năm, đích ra ngoài thứ hai) |
| Hai đường phân phối; Jev tùy chọn | P7 | Q1, mục 6.1, 8.11, 9, 11.1 |
| Sổ bàn giao là đầu vào của lượt rà soát | P8 | Mục 7.4 |
| Chỉ số dùng lại trước, holdout hoãn báo cáo | P9 | Q7, mục 11.4, 12.1, 12.2, 12.3 |
| Chuẩn bị public; hoãn index file | P10 | Mục 1, Q24, mục 10, O1, O8, O12 |
| Thứ tự dự án con và mốc M2, M3 | — | Mục 15, 16, 19 |
| `doctor` nhóm Skill | — | Mục 13 |
| Việc còn mở O9–O13 | — | Mục 18 |
| Tình huống nghiệm thu 79–92 | — | Mục 20 |

**Review rev 17** (`2026-11-10-system-design-rev17-review.md`), xử lý ở rev 18:

| Review | Đã xử lý ở | Tình huống |
|---|---|---|
| SB2-R17-01 recovery grant qua restore | Mục 5.3 (policy store), 5.4, 5.7, 11.2 (Grant sống trong policy store), 14.1 | 93 |
| SB2-R17-02 đích vật lý của approval | Mục 11.2 (Đích vật lý của mỗi file đích), 11.3 (approval message), 14.1 | 94, 95 |
| SB2-R17-03 ref bất biến cho skill | Mục 5.3, 8.8 (Ref bất biến qua restore), 8.9, 8.11 (Thay đổi contract) | 96 |
| SB2-R17-04 ranh giới đầu vào của job rà soát | Mục 7.2 (hồ sơ người nhận), 7.4, 8.10 (Đầu vào, Cùng người nhận), 14.2, 19 | 89 |
| SB2-R17-05 chỉ đọc là điều kiện khởi chạy | Mục 8.10 (Chỉ đọc là điều kiện khởi chạy, Trạng thái theo harness), 17.3, O9 | 88 |
| SB2-R17-06 pin và quarantine trên kênh cài gốc | Rev 18 thêm điều kiện cho đường cài gốc. Rev 20 bỏ hẳn đường này (Q25, mục 8.11), nên phản ví dụ không còn đường xảy ra: brain không ghi skill vào thư mục skill của harness | 92, 99, 100 |
| SB2-R17-07 hết hạn sau khi restore cả hai kho | Mục 5.6 (Hạn gốc theo holder), 5.7 (bước 4) | 101 |
| SB2-R17-08 head, pin và lineage của bản vá | Mục 8.8 (Head theo phạm vi, Vá từ một repo, Lineage, Ghim), 8.9 (Lọc phạm vi trước), 9, 14.2 | 82, 83, 84, 97 |
| SB2-R17-09 draft có script và cổng duyệt | Mục 8.6, 8.9, 8.11 | 81 |
| SB2-R17-10 admission và commit của job rà soát | Mục 6.4, 8.10 (Admission và commit, Theo cờ, Dự phòng) | 98 |
| SB2-R17-11 accounting không quay lui | Mục 5.3, 5.7 (Accounting không quay lui), 6.4, 8.10, 9, 14.1 | 102 |
| SB2-R17-12 bằng chứng nạp skill và so sánh Jev | Mục 12.2 (So sánh offline), 15 (M2), 19 | 103 |
| SB2-R17-13 contract của gói công khai | Mục 8.7 (Xuất gói công khai), 11.3, 14.2, 19 | 104 |
| Phần file còn sót trong mục 9, 13, 14.2 | Ghi rõ là đang hoãn theo mục 10 | – |

**Review rev 18** (`2026-11-10-system-design-rev18-review.md`), xử lý ở rev 19. Review này xác nhận R17-01, R17-05, R17-08, R17-11 và R17-12 đã đóng ở mức đặc tả.

| Review | Mục rev 17 liên quan | Đã xử lý ở | Tình huống |
|---|---|---|---|
| SB2-R18-01 journal thiếu trạng thái sau khi dời bản gốc | R17-02 | Mục 11.2 (Ba pha của mỗi file, Ý định dời, Publish với điều kiện đích vắng, Định danh của bản thay thế, Rollback đi ngược các pha, Sau crash) | 105; giữ 94, 95 |
| SB2-R18-02 cùng phiên và cùng provider chưa đủ | R17-04 | Mục 7.2 (đoạn phiên, bằng chứng tiếp xúc), 7.4, 8.10 (Đầu vào, Cùng người nhận, quyền đọc của hồ sơ chạy), 14.1, 14.2, O9 | 89 |
| SB2-R18-03 bản cài gốc lệch pin khi apply, restore, disable | R17-06 | Rev 19 thêm cổng nạp làm điều kiện. Rev 20 bỏ hẳn đường cài gốc (Q25, mục 8.11, 14.1); O10 đóng | 92, 99, 100 |
| SB2-R18-04 tombstone của snapshot đang dựng | R17-07 | Mục 5.4 (Ngoại lệ có chủ ý), 5.7 (bước 4–7, hai ca crash) | 101 |
| SB2-R18-05 ref ký trong lô, dữ liệu để báo mất pin | R17-03 | Mục 5.7 (bước 5), 8.7 (Duyệt gộp), 8.8 (Mất pin sau restore), 11.3 | 96 |
| SB2-R18-06 revision chờ duyệt tách khỏi head phục vụ | R17-09 | Mục 8.6, 8.7, 8.8 (Head theo phạm vi), 8.11, 11.1, 11.3 (`skill_activate`) | 81 |
| SB2-R18-07 chống trùng lượt rà qua hai cửa sổ | R17-10 | Mục 8.10 (Một slot theo task, Khóa cửa sổ, Dấu hoàn tất, Không đạt điều kiện, Cửa sổ mới, Dự phòng), 8.11 | 98 |
| SB2-R18-08 định danh công khai sống qua restore | R17-13 | Mục 5.3, 8.7 (Định danh công khai, Hồ sơ xuất, Phạm vi thu hồi) | 104 |
| Khóa accounting có hiệu lực ngay sau restore policy | R17-11 | Mục 5.7 | 102 |

**Review rev 20** (`2026-11-10-system-design-rev20-review.md`), xử lý ở rev 21. Review này xác nhận R18-03 đã đóng theo Q25 và R18-04 đã đóng.

| Review | Mục rev 18 liên quan | Đã xử lý ở | Tình huống |
|---|---|---|---|
| SB2-R20-01 phục hồi sau publish thiếu bằng chứng sở hữu | R18-01 | Mục 11.2 (Nguyên tắc cho mỗi file, Journal ghi cho mỗi file, Trình tự apply, Rollback, nhánh `original=absent`, Sau crash, Trạng thái của cả journal) | 106; giữ 105 |
| SB2-R20-02 tách gửi lại và gửi tới người nhận mới | R18-02 | Mục 7.2 (`sent_to_recipient`), 8.10 (Đầu vào, hai nhánh, Người nhận), 14.2 | 89 |
| SB2-R20-03 ca 99 mâu thuẫn với đọc ref tường minh | R18-03, Q25 | Mục 6.1, 8.8 (Ghim), 8.11 (Hai cách đọc, Delivery cũ sau khi pin đổi), 15 (M2) | 99; giữ 84 |
| SB2-R20-04 ACK pending và kênh của skill có script | R18-06 | Q20, Q25, mục 8.11 (ba nhánh result, Kích hoạt và proposal), 11.1 | 81, 92 |
| SB2-R20-05 dấu mất pin qua restore lặp | R18-05 | Mục 5.7 (bước 5), 8.8 (Mất pin sau restore) | 96 |
| SB2-R20-06 cửa sổ mới sau khi task đã rà thành công | R18-07 | Mục 8.10 (Mỗi task có tối đa một kết quả rà thành công, Cửa sổ mới) | 98 |
| SB2-R20-07 hồ sơ xuất và danh sách thu hồi | R18-08 | Mục 8.7 (Hồ sơ xuất, trạng thái có thể đã xuất, kiểm trước publish, Phạm vi thu hồi) | 104 |

**Rev 20** (quyết định của chủ dự án ngày 2026-11-10, không đến từ review):

| Thay đổi | Ở đâu |
|---|---|
| Bỏ đường cài skill gốc; skill chỉ phân phối qua MCP | Q25, mục 8.11 |
| Gỡ các điều khoản chỉ phục vụ đường cài gốc: hồ sơ bản cài, phạm vi gỡ trong approval, đơn vị publish là thư mục skill, mã `installed_skill_blocked`, quy tắc pin đi cùng bản cài | Mục 5.3, 8.7, 8.8, 8.11, 11.1, 11.2, 11.3, 13 |
| Mối đe dọa "harness tự nạp skill ngoài tầm kiểm soát" | Mục 14.1 |
| SP4 không còn phân phối gốc; O10 đóng | Mục 15, 18, 19 |
| Tình huống 92, 99 và 100 viết lại cho đường MCP | Mục 20 |

Đề xuất P7 có hai đường phân phối; từ rev 20 chỉ còn đường động.

**Review rev 21** (`2026-11-10-system-design-rev21-review.md`), xử lý ở rev 22.

| Review | Đã xử lý ở | Tình huống |
|---|---|---|
| SB2-R21-01 phục hồi rollback trước rename đầu tiên | Mục 5.4, 11.2 (Hướng của cả lượt, Sau crash, Trạng thái của cả journal) | 107, giữ 106 |
| SB2-R21-02 điều kiện gửi tới B và hồ sơ `unknown` | Mục 8.10 (Đầu vào và hai nhánh gửi), 14.2 | 89 |
| SB2-R21-03 chỉ định một skill trong Delivery | Mục 6.1, 8.11 (Hai cách đọc, Thay đổi contract) | 99 |
| SB2-R21-04 dấu rà thành công qua restore | Mục 5.7 (bước 5–7), 8.10 (Dấu rà soát qua restore) | 108 |

**Điểm rev 17 khác với đề xuất:**
- Đề xuất P10 ghi hoãn nghiệm thu macOS/Linux và các kênh duyệt phụ. Việc này sẽ đổi nội dung SP1, trái với cam kết không đổi SP1 của chính đề xuất. Rev 17 giữ nguyên Q8, Q19 và SP1, và chuyển việc này thành O12.
- Đề xuất chưa xếp chỗ cho bài học đứng riêng. Rev 17 đặt nó vào SP5 cùng danh mục và Jev.
