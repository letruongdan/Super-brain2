# Super-brain2: thiết kế hệ thống tổng thể

- **Ngày:** 2026-10-30
- **Trạng thái:** chờ chủ dự án duyệt bản viết
- **Quy trình:** superpowers:brainstorming, nhánh kiến trúc. Các phần thiết kế 1–12 đã được duyệt lần lượt trong hội thoại ngày 2026-10-29/30.
- **Thay thế:** mọi tài liệu thiết kế của repo cũ `D:\ensemble-agents\Super-brain`. Tài liệu cũ chỉ còn là tham chiếu (xem mục 16).

---

## 1. Mục tiêu

Super-brain2 là một "bộ não" chạy cục bộ, kết nối nhiều coding harness vào **một kho tri thức chung** qua MCP.

1. **Học từ công việc thật.** Thu thập dữ liệu từ các phiên làm việc, rút ra bài học có bằng chứng, rồi đưa bài học đúng lúc cho bất kỳ harness nào. Nhờ vậy các harness làm tốt hơn qua từng phiên.
2. **Có sẵn tri thức từ ngày đầu.** Danh mục agency-agents cộng các skill cấp user đang có trên máy chủ dự án.
3. **Chọn nhanh và chính xác.** Jev (mô hình System One của TypeSafe) chọn skill, bài học, hướng dẫn tool và context. Khi Jev không dùng được thì rules thay thế.
4. **Đo được bằng chứng.** "Thông minh hơn" phải được đo bằng tín hiệu thụ động và holdout ngẫu nhiên, không tự tuyên bố.

### Ngoài phạm vi

- Không thay thế agent runtime: brain không sinh code, không chạy vòng lặp agent, không tự sửa file dự án.
- Không chạy agent nền (không có bước Probe kiểu harness2).
- Chưa đồng bộ nhiều máy, chưa có nhiều người dùng. Thiết kế chỉ chừa đường cho hai việc này (mục 3).
- Không nhập dữ liệu `brain.db` của repo cũ.
- Chưa phát hành công khai (PyPI, Docker, Smithery).

## 2. Các quyết định đã chốt

| # | Chủ đề | Quyết định |
|---|---|---|
| Q1 | Bộ chọn | Jev là bộ chọn chính, rules làm dự phòng; vẫn chạy được khi offline |
| Q2 | Ngân sách Jev | Người dùng tự đặt; **mặc định không có trần**. Chi phí luôn được ghi lại |
| Q3 | Tài liệu | Viết tổng hợp lại từ các nguồn và mục tiêu; tài liệu cũ chỉ để tham chiếu |
| Q4 | Harness | 5 harness: Codex (app desktop), Claude Code, Antigravity, OpenCode, Cursor (hoãn tới khi được cài) |
| Q5 | Jev-Mem | Bỏ hẳn |
| Q6 | Tri thức có sẵn | agency-agents cộng khoảng 70 skill cấp user trên máy. Gộp bản trùng, ghi nguồn gốc và license. Không lấy skill trong plugin cache |
| Q7 | Đo "thông minh hơn" | Tín hiệu thụ động cộng holdout ngẫu nhiên khi dùng thật |
| Q8 | Triển khai | Một người, một máy Windows; chừa đường cho nhiều máy và cho nhóm |
| Q9 | Tự cải tiến | Phân tầng: bài học đã kiểm chứng tự kích hoạt qua `prepare_task`; mọi thay đổi file cấu hình harness phải chờ duyệt; có phiên bản và rollback |
| Q10 | Capture | Sự kiện có cấu trúc cộng nội dung hội thoại đã lọc. Lọc trước khi ghi đĩa, dữ liệu chỉ nằm trên máy, có thời hạn lưu, tắt được theo workspace |
| Q11 | harness2 | Chỉ lấy ý tưởng; không chạy probe |
| Q12 | Phạm vi bài học | Chia sẻ giữa mọi repo của cùng một `owner_id`. Lọc ứng viên tại máy, Jev chọn |
| Q13 | Cách xây | Hướng B: viết theo spec. Tầng thấp trích xuất từ repo cũ kèm test; tầng domain/application viết mới bằng TDD |
| Q14 | Ai viết câu chữ bài học | Agent đang làm việc viết ở cuối phiên qua `submit_episode`; brain chỉ xác minh. Phiên nào agent không gửi thì dùng mẫu trích xuất |
| Q15 | Thời hạn lưu sự kiện thô | Mặc định 90 ngày, chỉnh được |
| Q16 | Tự chẩn đoán | Lệnh `brain doctor` cộng `get_health(deep=true)`; daemon tự chạy khi khởi động và mỗi ngày |

## 3. Các nguồn và phần lấy từ mỗi nguồn

Revision dưới đây là HEAD tại thời điểm khảo sát (2026-10-29). Đây là mốc nghiên cứu, không tự động cập nhật theo upstream.

| Nguồn | Revision | Giấy phép | Lấy gì | Không lấy |
|---|---|---|---|---|
| shared-agent-brain (local, thuộc chủ dự án) | `6d2d364` (working tree có 20 file thay đổi chưa commit) | Của chủ dự án | Contract 8 tool, danh tính và namespace, ledger/CAS, tách evidence khỏi tự báo cáo, các bước lựa chọn → delivery → áp dụng → kết quả | Học có ngân sách provider, owned fixture campaign, chuẩn hóa Hermes |
| [OpenViking](https://github.com/volcengine/OpenViking) | `ba344c5` | AGPL-3.0 | Ý tưởng phân tầng L0/L1/L2 và hạ cấp theo ngân sách | **Không copy code** (vì AGPL), không dùng runtime |
| [Hindsight](https://github.com/vectorize-io/hindsight) | `82109477` | MIT | Retain/recall/reflect, bộ ba world/experience/belief, nguồn gốc, lặp lại không phải bằng chứng | PostgreSQL, pgvector, ML nặng |
| [agency-agents](https://github.com/msitarzewski/agency-agents) | `b37b5bb` | MIT | Danh mục persona/skill (nhập làm tri thức có sẵn), checklist chuyển thành finishing gates | Nạp hàng trăm persona vào mọi prompt |
| [claude-mem](https://github.com/thedotmack/claude-mem) | `d7c2da3` | Apache-2.0 (có NOTICE) | Hook → chuẩn hóa → lọc privacy → hàng đợi bền → tóm tắt và nạp lại phiên | Bun, Chroma, ingest mặc định toàn bộ transcript |
| [harness2](https://github.com/google-research/harness2) | `1cfe254` | Apache-2.0 | Mô hình 8 thành phần, thư viện kinh nghiệm, rút kinh nghiệm sau task, đánh giá so sánh không cần đáp án | Vòng Propose–Probe–Compose chạy agent (mỗi task tốn 4k rollout và 3k phiên cải tiến) |
| [Jev / TypeSafe](https://docs.typesafe.ai) | model `jev-1.14.0` | Dịch vụ thương mại | API System One (Choice/Score/Noul), mẫu "skill suggestion", confidence gating | – |

**Ghi chú về Jev:**
- Jev là dịch vụ hosted, không có bản chạy local.
- Giá $0,042 cho mỗi triệu token input; token output miễn phí.
- Context 64k token mỗi request, 32k mỗi câu hỏi.
- Lỗi 429/529 cần retry với backoff.
- Trong cookbook skill suggestion, TypeSafe tự báo tỷ lệ chọn sai giảm từ 16,8% xuống 7,3%. Đây là số liệu của nhà cung cấp, **không phải cam kết cho dự án này**.

## 4. Kiến trúc tổng thể

```
 Claude Code   Codex   Antigravity   OpenCode   (Cursor)
      │          │          │            │
      ├─ MCP stdio shim (mỗi harness một danh tính) ─┐
      └─ hook / đọc transcript (có outbox cục bộ) ───┤
                                                     ▼  loopback HTTP + credential
 ┌──────────────────── Brain daemon (1 tiến trình) ───────────────────┐
 │ mcp/         transport, xác thực, schema 8 tool                     │
 │ application/ use case của 8 tool, review/apply, doctor              │
 │ domain/      capture · continuity · lessons · catalog · selection · │
 │              context · improvement · measurement                    │
 │ workers/     xử lý observation, reflection, index, câu hỏi Jev nền  │
 │ storage/     SQLite WAL (1 writer) · CAS sha256 · ledger append-only │
 │ core/        types, danh tính, validation, config, clock            │
 └─────────────────────────────────────────────────────────────────────┘
        ▲ lời gọi ra ngoài duy nhất: Jev API (qua adapter)
```

1. **Chỉ một daemon giữ quyền ghi SQLite.**
   - Mỗi harness chạy một shim stdio. Shim mang danh tính cố định của harness đó và chuyển tiếp request tới daemon qua loopback HTTP có credential.
2. **Capture không bao giờ làm harness bị treo.**
   - Sự kiện được ghi vào outbox cục bộ trước, rồi mới gửi tới daemon. Daemon tắt thì sự kiện được giữ lại và gửi sau.
3. **Phân tầng một chiều:** `mcp → application → domain → storage → core`.
   - Các package trong `domain` chỉ import nhau theo danh sách cho phép, khai báo trong cấu hình import-linter.
   - Mọi lời gọi ra ngoài (Jev, filesystem của harness) đi qua interface.
4. **Việc nặng chạy trong worker nền**, để tool MCP trả lời nhanh.
5. **Mỗi package trong `domain` ứng với một dự án con** (mục 15).

**Ngôn ngữ:** Python ≥ 3.11. CI chạy trên 3.11 và phiên bản đang cài trên máy (3.14).

## 5. Mô hình dữ liệu và danh tính

### 5.1 Danh tính

Mọi bản ghi mang các trường `owner_id`, `workspace_id`, `harness_id`, `session_id`, `machine_id`.

| Trường | Ý nghĩa |
|---|---|
| `owner_id` | Ranh giới cô lập cứng |
| `workspace_id` | Lấy từ remote git đã chuẩn hóa. Repo không có remote thì băm đường dẫn tuyệt đối |
| `harness_id` | Cố định theo credential của từng shim; harness không tự khai được |
| `machine_id` | Ghi lại để chuẩn bị cho nhiều máy, chưa dùng để lọc |

ID dùng UUIDv7.

### 5.2 Các loại bản ghi

| Bản ghi | Nội dung chính | Tạo bởi |
|---|---|---|
| Event | Sự kiện hook/transcript đã lọc; payload lớn nằm trong CAS | capture |
| Evidence | Bằng chứng có kiểu (exit code của test, digest output, diff) với `source ∈ {tool_observed, agent_reported, user_confirmed}` | capture, `submit_episode` |
| Episode | Một task hoàn chỉnh kèm các evidence | `submit_episode`, capture |
| Lesson | Bài học có phiên bản: nội dung, `kind ∈ {world, experience, belief}`, nhãn áp dụng (ngôn ngữ, tool, OS, lĩnh vực), nguồn gốc, trạng thái, `proof_count` (chỉ tính evidence độc lập), thống kê lợi ích | reflection |
| Artifact | Skill, persona, rule… gắn `component ∈ {c1..c8}` (mục 11). Có phiên bản, nội dung trong CAS, ghi nguồn gốc và license | catalog, improvement |
| ChangeProposal | Diff, lý do, evidence, mức rủi ro, các harness bị ảnh hưởng, trạng thái duyệt, con trỏ rollback | improvement |
| Delivery | Những gì đã đưa cho phiên nào, kèm nhóm holdout | `prepare_task` |
| SelectionTrace | Ứng viên, câu trả lời/xác suất của Jev, lý do chuyển sang rules, độ trễ, chi phí | selection |
| Outcome | `declared` (qua tool) hoặc `inferred` (từ tín hiệu thụ động) | `record_outcome`, measurement |
| BudgetEntry | Token và chi phí thực tế của Jev, lấy từ `usage` | adapter Jev |
| DoctorRun | Kết quả từng mục kiểm tra của `doctor` | doctor |

### 5.3 Lưu trữ

- Một file SQLite (WAL, `synchronous=NORMAL`, FTS5) cộng thư mục CAS theo sha256.
- **Ledger chỉ ghi thêm.** Các bảng trạng thái hiện tại dựng lại được từ ledger.
- `workspace_id` của bài học chỉ là thông tin nguồn gốc và gợi ý cho bộ chọn, **không dùng để lọc** (Q12).
- Thời hạn lưu chỉ áp dụng cho Event (mặc định 90 ngày). Evidence mà bài học đang dẫn tới, bản thân bài học và artifact được giữ lại.

## 6. Tám tool MCP

Tên và cấu trúc giữ theo contract `mcp-tools-v1` của shared-agent-brain.

| Tool | Hành vi |
|---|---|
| `prepare_task` | Lọc tại máy → Jev chọn → áp holdout → ghi Delivery. **Deadline mặc định 1,5 giây**; quá hạn thì chuyển sang rules. Trả về: 0–N skill, 0–K bài học, tóm tắt phiên trước trong repo, ref L0/L1, finishing gates, `delivery_id` |
| `search_knowledge` | FTS5 kết hợp độ mới. Không gọi Jev |
| `get_artifact` | Nội dung đầy đủ ở cấp L0/L1/L2 kèm digest; ghi lại việc đã đọc |
| `submit_episode` | Lưu Episode và evidence; nhận bài học đề xuất do agent viết (Q14) |
| `record_outcome` | Kết quả theo `delivery_id`, kèm các ref đã áp dụng |
| `request_improvement` | Đưa job reflection vào hàng đợi nền; tạo bài học hoặc ChangeProposal |
| `get_job` | Trạng thái và kết quả job |
| `get_health` | Trạng thái nhanh. Khi `deep=true` thì chạy bộ kiểm tra `doctor` ở chế độ chỉ đọc (mục 13) |

**Quy tắc chung:**
- Tool ghi bắt buộc có `idempotency_key`.
- Lỗi trả về có kiểu và có mã.
- Không tool MCP nào duyệt được ChangeProposal; việc duyệt chỉ làm được qua CLI.
- Harness không gọi `record_outcome` thì Outcome được suy ra và đánh dấu `inferred`.

## 7. Capture và liên tục phiên

### 7.1 Đường đi của một sự kiện

```
hook/transcript → adapter dịch sang envelope v1 → privacy filter → outbox cục bộ (đã fsync)
 → daemon nhận (bỏ trùng theo event_id, chấp nhận lệch thứ tự) → Event
 → worker: chia episode, nhận diện tín hiệu, tạo observation ứng viên
```

- **Hook:** mục tiêu dưới 100ms rồi thoát; không bao giờ trả lỗi làm harness dừng. Lỗi ghi vào log cục bộ và hiện trong `get_health`.
- **Privacy filter** chạy **trước** khi ghi đĩa. Nó xử lý:
  - secret và token theo mẫu, chuỗi có entropy cao;
  - nội dung trong `<private>…</private>`;
  - danh sách đường dẫn cấm;
  - workspace bị tắt capture.
- **Sự kiện harness không cung cấp được** thì ghi là `unavailable`, không đoán.
- **Các tín hiệu worker nhận diện:**
  - lần chạy test và exit code;
  - chữ ký lỗi, và lỗi lặp lại;
  - file bị sửa;
  - **lời người dùng sửa agent**: dùng mẫu rules trước, ca chưa rõ thì gom lô hỏi Jev bằng câu Noul.

### 7.2 Liên tục phiên

- **Khi nào:** lúc phiên kết thúc, hoặc khi phát hiện phiên bị bỏ dở (quá thời gian không hoạt động, mặc định 30 phút).
- **Nội dung:** L0 (≤50 từ) và L1 dạng dòng thời gian (≤300 từ): mục tiêu, file đã động tới, lệnh, lỗi, việc còn dở.
  - Ưu tiên bản bàn giao do agent gửi qua `submit_episode`.
  - Nếu không có thì trích xuất theo luật.
- **Phạm vi:** gắn với **repo**. Được đưa vào `prepare_task` của phiên kế tiếp trong repo đó, với bất kỳ harness nào.

## 8. Vòng đời bài học và thư viện kinh nghiệm

```
candidate ──(evidence)──> verified ──(tự động)──> active ──> superseded | revoked | dormant
```

**Nguồn tạo bài học:**
1. Cặp lỗi → cách sửa: test đỏ → xanh trong cùng phiên.
2. Lời người dùng sửa agent.
3. Chiến lược thành công lặp lại.

Câu chữ do agent viết (Q14) hoặc lấy theo mẫu.

**Lên `verified`** cần ít nhất một trong ba điều kiện:
- evidence `tool_observed` gắn đúng với cặp lỗi/cách sửa;
- `user_confirmed`;
- bài học lặp lại ở ít nhất **2 episode độc lập**.

`agent_reported` không bao giờ đủ. Nhắc lại cùng một câu không làm tăng `proof_count`.

**`verified` → `active`** tự động (Q9). Bài học chỉ được đưa ra qua kênh động (`prepare_task`).

**Conflict Review Gate:**
- Ở nền, hỏi Jev câu Noul "A có mâu thuẫn với B không?" cho các cặp bài học có nhãn chồng nhau.
- Nếu mâu thuẫn, cả hai bị treo chờ duyệt qua CLI.

**Hạ hạng tự động:**
- Holdout cho thấy bài học có hại thì hạ xuống `dormant`, vì đây là chiều an toàn.
- Muốn kích hoạt lại phải có evidence mới.

**Gộp trùng:** bài học gần giống được gộp lại, giữ đủ nguồn gốc của từng bản.

**Thư viện kinh nghiệm** (lấy từ harness2): mỗi bài học giữ hồ sơ áp dụng (Delivery → lý do chọn → Outcome). Bộ chọn và reflection dùng hồ sơ này.

## 9. Bộ chọn: lọc tại máy → Jev → rules

**Đối tượng được chọn:** skill, bài học, hướng dẫn tool (c4), persona/finishing gates, và file context (mục 10).

1. **State:** mô tả task, hồ sơ repo, harness, OS, khả năng của harness.
2. **Lọc tại máy, mục tiêu dưới 50ms:**
   - Loại cứng: không tương thích khả năng, không `active`, đang `dormant`.
   - Chấm điểm: BM25 trên L0, khớp nhãn, lợi ích đã đo, độ mới.
   - Mặc định tối đa 40 skill, 40 bài học, 20 file.
3. **Gọi Jev:**
   - **Request 1:** Choice trên các skill ứng viên; Noul cổng ("cần skill không?", "cần quy trình không?", "chỉ cần trả lời bằng chữ?"); mỗi bài học và mỗi file ứng viên một câu Noul "có liên quan không?".
   - **Request 2:** sắp xếp lại top 3 skill bằng mô tả đầy đủ, kèm Noul "có đúng việc này không?".
   - Ngưỡng confidence mặc định 0,30 (theo cookbook), chỉnh lại sau khi đo. Được phép chọn **không skill nào**.
4. **Chuyển sang rules** khi Jev lỗi, quá deadline, chạm trần (nếu người dùng đặt), hoặc trả lời không hợp lệ.
   - Câu trả lời được kiểm tra chặt: đủ câu hỏi, đúng kiểu, đúng khoảng giá trị.
   - Rules dùng điểm lọc ở bước 2 với ngưỡng cố định.
5. **Áp holdout** (mục 12).

**Vận hành Jev:**
- Chốt model `jev-1.14.0`; nâng phiên bản là thay đổi có chủ đích.
- Cache theo cặp (digest state, digest ứng viên).
- Retry 429/529 với backoff, nằm trong deadline.
- Ngân sách theo Q2. Khi có trần, `prepare_task` ưu tiên trước câu hỏi nền: từ 80% thì tắt câu hỏi nền, đến 100% thì toàn bộ chuyển sang rules.
- **Thứ tự làm:** pipeline chạy được bằng rules trước, sau đó bật Jev.

## 10. Context L0/L1/L2

- **Index:** các repo đã đăng ký (lần `prepare_task` hoặc phiên đầu tiên), tôn trọng `.gitignore` và danh sách đường dẫn cấm. Skill và artifact cũng có L0/L1.
- **Địa chỉ:** `brain://context/{workspace_id}/{path}#l0|l1|l2`.

| Cấp | Nội dung | Giới hạn |
|---|---|---|
| L0 | Đường dẫn, ngôn ngữ, mục đích (docstring/header), kích thước | ≤50 token |
| L1 | Khung AST qua tree-sitter (Python, TypeScript, Go, Rust) | ≤300 token |
| L2 | Nội dung đầy đủ, đọc khi được yêu cầu và kiểm tra digest | – |

- Thiết kế này là của dự án, *lấy cảm hứng* từ OpenViking. OpenViking thật sự làm khác: L0/L1 ở cấp thư mục, dựa trên ngữ nghĩa.
- **Cập nhật tăng dần:** theo mtime/kích thước rồi digest. Khi có yêu cầu thì kiểm tra lại mtime, nên không bao giờ trả L1 cũ của file đã đổi.
- **Ghép context:** ngân sách mặc định 4.000 token cho gói context, chỉnh được. Phân bổ theo chiều rộng trước; khi hết ngân sách thì hạ L1 → L0 → chỉ URI, không cắt đôi nội dung.
- **Không tuyên bố tiết kiệm token** khi chưa đo (mục 12).

## 11. Tự cải tiến và cổng duyệt

**Mô hình 8 thành phần** (từ harness2):

| | c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8 |
|---|---|---|---|---|---|---|---|---|
| Thành phần | rule / system prompt | guardrail | memory / bài học | hướng dẫn tool | subagent | skill | script | plugin / hook / MCP config |

| Kênh | Thành phần | Cách đưa | Cổng duyệt |
|---|---|---|---|
| Động | c3, c4, chọn skill đã duyệt (c6) | Gói context của `prepare_task` | Bài học `verified` thì tự động |
| Tĩnh | c1, c2, c5, nội dung c6, c7, c8 | Ghi vào file cấu hình của harness | **Luôn chờ duyệt** |

**Nguồn đề xuất:**
- Lời sửa lặp lại → rule.
- Skill được đưa ra mà vẫn thất bại lặp lại → sửa skill.
- Chiến lược thành công lặp lại → bản nháp skill mới.

Câu chữ do agent viết, brain gom evidence và gắn mức rủi ro.

**CLI:** `brain review list|show|approve|reject`, `brain apply`, `brain rollback <change>`.
- Ghi file theo kiểu nguyên tử, sao lưu bản gốc.
- Trong file dùng chung, chỉ sửa khối có đánh dấu `<!-- ensemble-brain:begin … end -->`.
- Khối đó đã bị người dùng tự sửa thì **từ chối ghi** và hiện diff.
- Lần cài đặt đầu tiên cho mỗi harness cũng là một ChangeProposal.

**Đánh giá sau khi áp dụng:** kênh động đo bằng holdout. Kênh tĩnh chỉ so sánh trước/sau và **ghi rõ là bằng chứng yếu**.

Brain **không bao giờ chạy** script trong skill.

## 12. Đo lường

### 12.1 Tín hiệu thụ động (luôn bật)

Tính theo phiên, harness, loại task và repo:
- tỷ lệ người dùng sửa lời agent;
- lỗi lặp lại sau khi đã có bài học;
- tỷ lệ tool lỗi;
- số lượt, token, thời gian mỗi phiên (`unavailable` nếu harness không cung cấp);
- thời gian tới khi test xanh.

### 12.2 Holdout ngẫu nhiên

- **Đơn vị:** cặp (Delivery, bài học).
- **Xác suất giữ lại:** *p* = 10% mặc định; tối đa 1 bài học bị giữ lại mỗi phiên.
- **Gán nhóm trước khi biết kết quả**, seed theo `delivery_id`.
- **Không bao giờ giữ lại:** bài học gắn nhãn an toàn, bảo mật, mất dữ liệu, và quy ước/sở thích người dùng đã xác nhận.
- **Outcome:** `declared` nếu có; nếu không thì `inferred`. Tín hiệu chính là lỗi mà bài học nhắm tới có xuất hiện trong phiên hay không.
- **Phân tích:**
  - Chỉ so sánh giữa nhóm được đưa và nhóm bị giữ lại trong số các lần bài học *đã được chọn*.
  - Mỗi nhóm cần ít nhất 30 lần; chưa đủ thì báo "chưa đủ dữ liệu".
  - Chỉ báo "có cải thiện" khi khoảng tin cậy 95% không chứa 0.
- **Tùy chọn, mặc định tắt:** nhánh chỉ dùng rules, để đo xem Jev hơn rules bao nhiêu.

### 12.3 Báo cáo

`brain report` gồm xu hướng, lợi ích từng bài học kèm khoảng tin cậy, và chi phí Jev. Mọi con số được ghi nhãn "nhân quả" (holdout) hoặc "tương quan" (trước/sau, thụ động).

## 13. Tự chẩn đoán: `brain doctor`

`brain doctor [--fix] [--json]`. Qua MCP: `get_health(deep=true)` chạy cùng bộ kiểm tra ở chế độ chỉ đọc. Daemon tự chạy khi khởi động và mỗi 24 giờ, lưu DoctorRun.

| Nhóm | Kiểm tra |
|---|---|
| Daemon | Đang chạy, lease ghi còn hợp lệ, phiên bản schema |
| Danh tính | File credential tồn tại, ACL đúng, mỗi harness đã đăng ký có credential |
| Storage | `PRAGMA integrity_check`, kích thước WAL, lấy mẫu kiểm tra digest trong CAS, ledger khớp với các bảng trạng thái, dung lượng đĩa |
| Capture | Mỗi harness: lần nhận sự kiện gần nhất, tầng capture đang hoạt động, độ dồn của outbox, dead-letter |
| Privacy | Tự kiểm tra bằng secret giả (canary) phải bị chặn; quét lại kho bằng bộ mẫu mới |
| Harness | Cấu hình MCP trỏ đúng shim; khối có đánh dấu bị sửa tay (drift); hook đã cài |
| Jev | Key hợp lệ, model đã chốt còn tồn tại, độ trễ, tỷ lệ chuyển sang rules gần đây, chi phí so với trần (nếu có) |
| Index | Số file chưa index hoặc đã cũ |
| Lessons | Số bài học kẹt ở trạng thái chờ duyệt; số mâu thuẫn chưa xử lý |
| Retention | Job dọn dữ liệu lần cuối chạy lúc nào |

- Mỗi mục trả về `PASS | WARN | FAIL`, kèm mô tả và hướng sửa.
- **`--fix` chỉ làm việc an toàn:** khởi động lại daemon, phát lại outbox, dựng lại bảng trạng thái hoặc index, quay vòng log. **Không bao giờ xóa dữ liệu** và không ghi vào cấu hình harness (việc đó phải qua `review/apply`).

## 14. Xử lý lỗi, bảo mật, quyền riêng tư

| Mối đe dọa | Biện pháp |
|---|---|
| Secret lọt vào kho | Lọc trước khi ghi đĩa; quét lại định kỳ; phát hiện thì quarantine, không xóa âm thầm |
| Đầu độc bài học | Bài học do agent viết chỉ là `candidate` tới khi có evidence; gói context đánh dấu rõ "dữ liệu tham khảo, không phải lệnh"; mâu thuẫn thì chờ duyệt |
| Skill bên thứ ba độc hại | Không chạy script; nhập skill phải qua review, ghi nguồn gốc và license |
| Tiến trình lạ gọi daemon | Chỉ nghe trên loopback; credential riêng cho từng harness; ACL trên file credential; duyệt chỉ qua CLI |
| Path traversal | Chuẩn hóa đường dẫn; chặn `..` và symlink ra ngoài workspace |
| Dữ liệu gửi cho Jev | Chỉ gửi mô tả task, L0 và tin nhắn cần phân loại, sau khi đã lọc; không gửi L2; tắt được Jev theo workspace |

**Xử lý lỗi:**
- Daemon tắt: shim trả lỗi rõ ràng; outbox giữ sự kiện và gửi lại sau mà không tạo bản trùng.
- Jev lỗi: chuyển sang rules, có trace.
- Dữ liệu hỏng: quarantine; có backup định kỳ và lệnh khôi phục.
- Cấm nuốt lỗi; mọi chế độ dự phòng đều hiện trong `get_health`.

## 15. Các dự án con và thứ tự

Mỗi dự án con có plan riêng (superpowers:writing-plans) dựa trên spec này. Nếu một dự án con cần quyết định thiết kế mà spec chưa có, chạy một vòng brainstorming ngắn và bổ sung spec trước khi viết plan.

| # | Dự án con | Nội dung | Nguồn code |
|---|---|---|---|
| SP1 | Kernel | `core`, `storage`, daemon + shim, khung 8 tool, `doctor` cơ bản, hàng rào CI | **Trích xuất** từ repo cũ `f83271d` kèm test |
| SP2 | Capture và liên tục phiên | envelope v1, privacy, outbox, worker tín hiệu, continuity; khảo sát + adapter cho Claude Code và Codex app | Privacy/queue trích xuất; phần còn lại viết mới |
| SP3 | Bài học | Vòng đời, xác minh, Conflict Review Gate, thư viện kinh nghiệm | Viết mới (TDD) |
| SP4 | Catalog và bộ chọn | Nhập agency-agents và skill local; lọc → Jev → rules; ngân sách | Viết mới |
| SP5 | Context L0/L1/L2 | Index, tree-sitter, ghép context | Viết mới, tham khảo code cũ |
| SP6 | Cải tiến và đo lường | ChangeProposal, review/apply/rollback, holdout, report | Viết mới |
| SP7 | Các adapter còn lại | OpenCode, Antigravity; Cursor khi được cài | Viết mới, mỗi harness có bước khảo sát trước |

**Các mốc:**
- **M1** (SP1 + SP2): Claude Code và Codex app cùng ghi vào một kho thật, có NativeHostReceipt. Phiên của harness này nhận được tóm tắt phiên trước của harness kia.
- **M2** (+ SP3, SP4): một bài học `verified` từ harness A được Jev chọn và đưa cho harness B.
- **M3** (+ SP5, SP6): `brain report` có số liệu holdout thật.

**Danh sách trích xuất cho SP1:** đồ thị import và số dòng đã đo nằm trong `docs/notes/2026-10-29-extraction-analysis-draft.md` (chỉ để tham khảo). Danh sách chính thức sẽ được chốt trong plan của SP1.

## 16. Đối chiếu với tài liệu cũ

| Chủ đề | Tài liệu/code cũ | Spec này |
|---|---|---|
| Bộ chọn | Rules mặc định, Jev tùy chọn | Jev chính, rules dự phòng |
| Phạm vi bài học | Cô lập chặt theo workspace | Chia sẻ trong cùng `owner_id`, workspace chỉ là gợi ý |
| Persona/skill | 8 persona + 217 skill (docs/plan); V5 thu gọn còn 8 | agency-agents cộng ~70 skill local, chọn bằng Jev |
| Harness | 5, sau đó tăng lên 9 | 5 (Cursor hoãn) |
| Tự cải tiến | `evolution` chạy probe theo harness2; `learning` campaign | Không chạy probe; agent viết, brain xác minh |
| Đo lường | Owned fixture, benchmark, utility experiment | Tín hiệu thụ động + holdout |
| Cơ sở dữ liệu | `brain.db` + `cognitive.db`; V5 gộp | Một DB mới, không nhập dữ liệu cũ |
| Phát hành | PyPI, Docker, Smithery | Ngoài phạm vi |
| Tự chẩn đoán | `get_health` | `doctor` + `get_health(deep)` |

## 17. Kiểm thử và hàng rào

**Kiểm thử:**
- TDD cho code mới. Code trích xuất phải mang test theo và chạy xanh trước khi sửa.
- Ba tầng: unit; integration với SQLite và daemon thật; kiểm chứng native thủ công khi chủ dự án đồng ý.
- Jev: dùng transport giả cho contract và các ca lỗi; một bài canary gọi Jev thật, chạy riêng.

**Hàng rào chạy trong CI và tại máy:**
- import-linter kèm test AST quét cả import nằm trong hàm;
- không có vòng phụ thuộc giữa package;
- `mypy --strict`;
- `ruff` cho `src` và `tests`;
- cấm nuốt lỗi;
- cảnh báo khi file vượt 600 dòng;
- full suite chạy xong dưới 5 phút.

**Quy tắc tuyên bố:**
- Không ghi "xong" hay "verified" khi chưa có kết quả full suite.
- Không ghi "hỗ trợ harness X" khi chưa có NativeHostReceipt.

## 18. Việc còn mở (không chặn việc viết plan cho SP1)

| # | Việc | Khi nào xử lý |
|---|---|---|
| O1 | Giấy phép của dự án (nếu công khai) | Trước khi phát hành, ngoài phạm vi hiện tại |
| O2 | Codex app desktop: hook và vị trí transcript | Bước khảo sát trong SP2 |
| O3 | Antigravity `agy` 1.4.8 và OpenCode 2.2.0: hook/plugin, định dạng transcript | Bước khảo sát trong SP7 |
| O4 | Độ trễ Jev thực tế trên mạng của chủ dự án; ngưỡng confidence | Bài canary trong SP4 |
| O5 | Số lượng ứng viên lọc (40/40/20) và ngân sách 4.000 token | Đo trong SP4/SP5 |
| O6 | License của từng skill trong ~70 skill local | Bước nhập trong SP4 |
| O7 | Daemon chạy thế nào trên Windows (tự khởi động khi đăng nhập hay chạy khi cần) | Plan của SP1 |
