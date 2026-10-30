# Super-brain2: thiết kế hệ thống tổng thể

- **Ngày:** 2026-10-30
- **Phiên bản:** rev 2. Rev 1 là commit `7a1825e`.
- **Trạng thái:** chờ chủ dự án duyệt rev 2.
- **Quy trình:** superpowers:brainstorming, nhánh kiến trúc.
  - Các phần thiết kế 1–12 đã được duyệt lần lượt trong hội thoại ngày 2026-10-29/30.
  - Rev 2 bổ sung contract nền theo bản review `docs/reviews/2026-10-30-system-design-review.md` (SB2-S01…S18) và ba quyết định mới Q17–Q19.
  - Mục 21 ánh xạ từng phát hiện của review tới chỗ đã sửa.
- **Thay thế:** mọi tài liệu thiết kế của repo cũ `D:\ensemble-agents\Super-brain`. Tài liệu cũ chỉ còn là tham chiếu (xem mục 16).

---

## 1. Mục tiêu

Super-brain2 là một "bộ não" chạy cục bộ, kết nối nhiều coding harness vào **một kho tri thức chung** qua MCP.

1. **Học từ công việc thật.** Thu thập dữ liệu từ các phiên làm việc, rút ra bài học có bằng chứng, rồi đưa bài học đúng lúc cho bất kỳ harness nào. Nhờ vậy các harness làm tốt hơn qua từng phiên.
2. **Có sẵn tri thức từ ngày đầu.** Danh mục agency-agents cộng các skill cấp user đang có trên máy chủ dự án.
3. **Chọn nhanh và chính xác.** Jev (mô hình System One của TypeSafe) chọn skill, bài học, hướng dẫn tool và context. Khi Jev không dùng được thì rules thay thế.
4. **Đo được bằng chứng.** "Thông minh hơn" phải được đo bằng tín hiệu thụ động và holdout ngẫu nhiên, không tự tuyên bố.
5. **Chạy trên Windows, macOS và Linux** (Q19). Về sau có thể chia sẻ cho nhiều người dùng.

### Ngoài phạm vi

- Không thay thế agent runtime: brain không sinh code, không chạy vòng lặp agent, không tự sửa file dự án.
- Không chạy agent nền (không có bước Probe kiểu harness2).
- Chưa đồng bộ nhiều máy, chưa có nhiều người dùng.
  - Danh tính, định dạng dữ liệu và approval được thiết kế để thêm hai việc này mà không đổi schema (mục 5, 11).
- Không nhập dữ liệu `brain.db` của repo cũ. Migration schema của chính Super-brain2 vẫn nằm trong phạm vi.
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
| Q8 | Triển khai | Một người, một máy, một kho. Nhiều máy và nhóm sẽ làm sau; thiết kế chừa đường (Q19) |
| Q9 | Tự cải tiến | Phân tầng: bài học đã kiểm chứng tự kích hoạt qua `prepare_task` sau Conflict Review; mọi thay đổi file cấu hình harness phải chờ duyệt (Q18); có phiên bản và rollback |
| Q10 | Capture | Sự kiện có cấu trúc cộng nội dung hội thoại đã lọc. **Kho chính nằm trên máy; dữ liệu đi ra ngoài (chỉ tới Jev) được kiểm soát theo allowlist** (mục 14.2). Lọc trước khi ghi đĩa, có thời hạn lưu, tắt được theo workspace |
| Q11 | harness2 | Chỉ lấy ý tưởng; không chạy probe |
| Q12 | Phạm vi bài học | Chia sẻ giữa mọi repo của cùng một `owner_id`. Lọc ứng viên tại máy, Jev chọn. Chỉ nội dung bài học được chia sẻ; evidence thô, continuity và context nguồn không đi theo sang repo khác |
| Q13 | Cách xây | Hướng B: viết theo spec. Tầng thấp trích xuất từ repo cũ kèm test; tầng domain/application viết mới bằng TDD |
| Q14 | Ai viết câu chữ bài học | Agent đang làm việc viết ở cuối phiên qua `submit_episode`; brain chỉ xác minh. Phiên nào agent không gửi thì dùng mẫu trích xuất |
| Q15 | Thời hạn lưu sự kiện thô | Mặc định 90 ngày, chỉnh được |
| Q16 | Tự chẩn đoán | Lệnh `brain doctor` cộng `get_health(deep=true)`; daemon tự chạy khi khởi động và mỗi ngày |
| Q17 | Contract | Phát hành `mcp-tools-v2`: giữ 8 tên tool; schema canonical pin trong repo kèm fixtures request/response/error. Không làm adapter v1 |
| Q18 | Cổng duyệt | Ba lớp (mục 11.3): rule văn bản trong harness; quyền `ask` cài vào harness, có `doctor` kiểm tra; brain tự xác minh bằng terminal (rủi ro thấp) hoặc passkey/chữ ký SSH (rủi ro cao). Bản review/apply tối thiểu nằm trong SP1 |
| Q19 | Hệ điều hành | Đa OS ngay từ SP1 (Windows, macOS, Linux, chạy trong CI). Nhiều người dùng làm sau |

## 3. Các nguồn và phần lấy từ mỗi nguồn

Revision dưới đây là HEAD tại thời điểm khảo sát (2026-10-29). Đây là mốc nghiên cứu, không tự động cập nhật theo upstream.

| Nguồn | Revision | Giấy phép | Lấy gì | Không lấy |
|---|---|---|---|---|
| shared-agent-brain (local, thuộc chủ dự án) | `6d2d364` (working tree có 20 file thay đổi chưa commit; chỉ dùng nội dung đã commit) | Của chủ dự án | Tên 8 tool và ý tưởng contract, danh tính và namespace, ledger/CAS, tách evidence khỏi tự báo cáo, các bước lựa chọn → delivery → áp dụng → kết quả | Học có ngân sách provider, owned fixture campaign, chuẩn hóa Hermes |
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
      ├─ MCP stdio shim (mỗi harness một credential) ┐
      └─ hook / đọc transcript (có outbox cục bộ) ───┤        brain CLI
                                                     ▼            │
                              loopback HTTP + credential ◄────────┘
 ┌──────────────────── Brain daemon (1 tiến trình / data root) ─────────┐
 │ interfaces: mcp/ · cli_api/ · workers/                                │
 │ application/  use case của 8 tool, review/apply, doctor, maintenance  │
 │ domain/       capture · continuity · lessons · catalog · selection ·  │
 │               context · improvement · measurement                     │
 │ ports/        Protocol cho storage, Jev, filesystem, clock, OS        │
 │ storage/      SQLite WAL · CAS sha256 · ledger      (cài đặt port)    │
 │ adapters/     jev · harness config · os (khóa, đường dẫn, ACL)        │
 │ core/         types, ID, validation, config, lỗi có mã                │
 │ composition   nơi duy nhất ráp storage/adapters vào application       │
 └───────────────────────────────────────────────────────────────────────┘
        ▲ lời gọi ra ngoài duy nhất: Jev API (qua adapter, theo allowlist)
```

### 4.1 Nguyên tắc

1. **Mỗi data root có đúng một daemon giữ quyền ghi** (mục 5.5).
   - Mỗi harness chạy một shim stdio. Shim mang credential của harness đó và chuyển tiếp request tới daemon qua loopback HTTP.
   - CLI cũng đi qua daemon, không ghi thẳng vào DB.
2. **Capture không làm harness bị treo.** Hook có ngân sách thời gian, lỗi không bao giờ làm harness dừng (mục 7.1).
3. **Việc nặng chạy trong worker nền**, để tool MCP trả lời trong deadline.
4. **Không giữ write transaction khi đang gọi mạng.**

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
| `mcp`, `cli_api`, `workers` | `application`, `core` |
| `cli` (tiến trình riêng) | `core` và client HTTP; không import `storage`/`domain` |
| `composition` | tất cả; không package nào import ngược lại nó |

Mỗi package được phân công cho một dự án con (mục 15). Một dự án con có thể sở hữu nhiều package.

### 4.3 Đa hệ điều hành (Q19)

- Python ≥ 3.11. CI chạy ma trận {Windows, macOS, Linux} × {3.11, bản ổn định mới nhất}.
- Mọi chỗ phụ thuộc OS đi qua `adapters.os`:
  - **Thư mục dữ liệu:** Windows `%LOCALAPPDATA%\ensemble-brain`, macOS `~/Library/Application Support/ensemble-brain`, Linux `$XDG_DATA_HOME/ensemble-brain`. Ghi đè được bằng biến môi trường.
  - **Khóa độc quyền:** `msvcrt`/`LockFileEx` trên Windows, `fcntl.flock` trên Unix.
  - **Bảo vệ file credential:** ACL chỉ cho user hiện tại trên Windows, `0600` trên Unix. `doctor` kiểm tra cả hai.
  - **Tự khởi động daemon:** chạy khi cần (shim khởi động nếu chưa có) là mặc định trên mọi OS. Tự khởi động lúc đăng nhập là tùy chọn, chốt trong plan SP1 (O7).
- Đường dẫn trong dữ liệu lưu dạng chuẩn hóa (dấu `/`, không phân biệt hoa thường trên Windows/macOS theo filesystem thực tế).

## 5. Danh tính, bản ghi và lưu trữ

### 5.1 Principal và quyền

- **Principal** là danh tính truy cập, gắn với một credential. Mỗi credential cấp cho một cặp (harness, máy) của một owner.
- Daemon **suy** `owner_id`, `harness_id`, `machine_id` từ credential. Payload khai owner/harness khác với principal thì bị từ chối (`identity_mismatch`), kể cả khi truy cập trực tiếp bằng ref của artifact, job hay context.
- Tác nhân hệ thống có danh tính riêng: `system:doctor`, `system:worker:<tên>`, `system:catalog-import`, `user:cli`. Bản ghi của tác nhân hệ thống không bịa `session_id`; trường này để trống.
- Thu hồi credential: `brain credential revoke`. Request dùng credential đã thu hồi bị từ chối ngay.

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
- Continuity gắn với **checkout** (công việc dở dang nằm trên một thư mục cụ thể). Bài học và thống kê gắn với **repo**.
- Trong tài liệu, "workspace" nghĩa là repo; `workspace_id` trong contract v2 chính là `repo_id`.

### 5.3 Các loại bản ghi

Mọi bản ghi mang `owner_id`, `actor` (principal hoặc tác nhân hệ thống) và nếu có thì `repo_id`, `checkout_id`, `harness_id`, `session_id`, `machine_id`. ID dùng UUIDv7.

| Bản ghi | Nội dung chính | Tạo bởi |
|---|---|---|
| Event | Sự kiện hook/transcript đã lọc; `producer_stream` + `sequence`; payload lớn nằm trong CAS | capture |
| CaptureGap | Khoảng sự kiện bị mất: lý do, khoảng thời gian, số lượng ước tính; không chứa nội dung | capture, outbox |
| Evidence | Bằng chứng có kiểu (lần chạy lệnh, exit code, digest output, diff); `source` do server gán theo kênh nhận (mục 8.2) | capture, `submit_episode`, CLI |
| Episode | Một task (hoặc một phần task) kèm các evidence; trạng thái `open`, `checkpointed`, `closed` | `submit_episode`, capture |
| Lesson | Bài học có phiên bản: nội dung, `kind ∈ {world, experience, belief}`, `claim_type ∈ {technical, preference}`, điều kiện áp dụng, nguồn gốc, trạng thái (mục 8.3), proof lineage, chính sách egress kế thừa | reflection |
| Artifact | Skill, persona, rule… gắn `component ∈ {c1..c8}`. Có revision; nội dung và **toàn bộ resource đi kèm** nằm trong CAS; ghi nguồn gốc và license | catalog, improvement |
| ChangeProposal | Diff, lý do, evidence, mức rủi ro, các file đích kèm digest bản gốc, trạng thái duyệt, con trỏ rollback | improvement, bootstrap |
| ApprovalReceipt | Proposal revision, digest nội dung, file đích, digest bản gốc, người duyệt, kênh (`terminal`, `passkey`, `ssh_sig`, `pr_merge`), độ mạnh của kênh | cổng duyệt |
| Delivery | Những gì đã chọn và trả cho một lần `prepare_task`, kèm holdout assignment | `prepare_task` |
| ReadReceipt | Client đã đọc đủ artifact nào, revision nào, digest từng resource | `get_artifact` |
| SelectionTrace | Ứng viên, câu trả lời/xác suất của Jev, lý do chuyển sang rules, độ trễ, chi phí, phiên bản policy | selection |
| Outcome | Kết quả, nguồn (`declared`, `observed`, `inferred`), độ đầy đủ quan sát, cửa sổ quan sát | `record_outcome`, measurement |
| Job | Việc nền: trạng thái, lease, số lần thử, kết quả, trạng thái accounting (mục 6.4) | `request_improvement`, hệ thống |
| ProviderInvocation | Một lời gọi Jev: invocation ID, ước lượng giữ chỗ, usage thực, chi phí (hoặc `unknown`) | adapter Jev |
| NativeHostReceipt | Bằng chứng một host thật đã gọi shim (mục 17.3) | shim, adapter |
| DoctorRun | Kết quả từng mục kiểm tra của `doctor` | doctor |

### 5.4 Commit, ACK và replay

- **Một transaction SQLite** gồm: ledger append, cập nhật projection (bảng trạng thái hiện tại), bản ghi idempotency và kết quả trả về. Hoặc tất cả cùng commit, hoặc không gì cả.
- **Độ bền:** dùng WAL với `synchronous=FULL`. Một request đã nhận ACK thì không mất khi tiến trình chết hoặc mất điện, miễn là OS và ổ đĩa tôn trọng fsync. Nói cách khác, RPO bằng 0 cho dữ liệu đã ACK.
- **Đưa blob vào CAS:**
  1. ghi vào thư mục staging;
  2. fsync;
  3. kiểm tra sha256;
  4. đổi tên nguyên tử vào `cas/`;
  5. mới đến transaction DB ghi ref.

  Ref chỉ được trả về sau bước 5. Blob mồ côi (có trong CAS nhưng không có ref) bị dọn sau một thời gian chờ, bằng job bảo trì.
- **Ledger** mỗi dòng có `sequence` tăng dần, `schema_version`, `handler_version`, `writer_epoch`.
- **Replay:**
  - Dựng projection vào bảng mới, kiểm tra, rồi mới hoán đổi.
  - Replay không gọi Jev, không tạo job hay chi phí mới: side effect chỉ phát sinh từ bản ghi Job và ProviderInvocation, vốn đã nằm trong ledger.
  - Replay tôn trọng tombstone (mục 5.6).
- **Bảng điểm crash** (trạng thái trước/sau từng bước, ACK, retry) là deliverable của plan SP1 và có fault-injection test.

### 5.5 Một chủ ghi

- **Quyền ghi** = giữ khóa độc quyền của OS trên file `<data root>/writer.lock` suốt đời tiến trình.
  - OS tự nhả khóa khi tiến trình chết. Vì vậy không dùng PID hay timeout để đoán tiến trình đã chết.
  - Mỗi lần lấy được khóa, `writer_epoch` tăng 1 và được ghi vào ledger.
- **Hai shim cùng khởi động daemon:** tiến trình nào lấy được khóa thì làm daemon; tiến trình còn lại thoát và kết nối tới daemon đó.
- **Thao tác bảo trì** (migrate, rebuild, restore, `--fix` có ghi): chạy trong chế độ bảo trì của daemon, hoặc bằng lệnh offline giữ cùng khóa đó. Không bao giờ chạy song song với writer đang hoạt động.
- **Tắt daemon:** ngừng nhận việc mới, hoàn tất hoặc hủy việc đang chạy theo chính sách của từng loại, để hàng đợi bền lại cho lần chạy sau.

### 5.6 Thời hạn lưu, tombstone và quarantine

| Dữ liệu | Thời hạn mặc định | Khi hết hạn |
|---|---|---|
| Payload của Event | 90 ngày (Q15) | Xóa payload trong CAS, ghi tombstone vào ledger; giữ metadata (loại, thời gian, ID) |
| Evidence | Còn được bài học, outcome hoặc proposal dẫn tới thì giữ; không thì theo Event | Như Event |
| Outbox đã ACK | Xóa ngay sau ACK | – |
| Log, trace | 30 ngày | Xoay vòng; log không bao giờ chứa payload thô (mục 14.2) |
| Dead-letter | 30 ngày, chỉ chứa metadata và lý do | – |
| Backup | Giữ N bản gần nhất (mặc định 7) | Xóa bản cũ nhất |
| Bài học, artifact, proposal, receipt | Giữ | – |

- **Tombstone:** replay và rebuild không bao giờ phục sinh payload đã hết hạn hoặc bị quarantine.
- **GC của CAS:** dựa trên danh sách root đang được tham chiếu, không dựa vào tuổi file.
- **Quarantine:** nội dung bị loại khỏi delivery, index, search và egress. Chỉ xem được bằng `brain quarantine show`. Không xóa âm thầm.

### 5.7 Backup và restore

- `brain backup` tạo manifest gồm: snapshot DB (SQLite backup API), schema version, ledger high-water mark, danh sách digest CAS được tham chiếu.
- `brain restore`:
  1. khôi phục vào thư mục mới;
  2. kiểm tra snapshot khớp với manifest (DB, CAS, digest);
  3. mới hoán đổi, trong chế độ bảo trì.

  Không ghi đè bản backup nguồn. Snapshot thiếu blob hoặc sai subject bị từ chối trước khi đụng vào dữ liệu đang dùng.

## 6. Contract `mcp-tools-v2` (Q17)

Schema JSON canonical nằm trong repo (`schemas/mcp-tools-v2.json`), kèm fixtures request/response/error. Fixtures chạy round-trip qua shim và daemon trong integration test. Schema này **không** tương thích ngược với `mcp-tools-v1` của shared-agent-brain.

### 6.1 Tám tool

| Tool | Loại | Hành vi |
|---|---|---|
| `prepare_task` | Ghi (có idempotency) | Lọc tại máy → Jev chọn → áp holdout → ghi Delivery. Trả về: 0–N skill, 0–K bài học, continuity của checkout, ref context, finishing gates, `delivery_id` |
| `search_knowledge` | Chỉ đọc | FTS5 kết hợp độ mới. Không gọi Jev |
| `get_artifact` | Đọc, có ghi audit | Trả nội dung ở cấp L0/L1/L2 kèm revision và digest từng resource. Đọc đủ mọi resource thì tạo ReadReceipt |
| `submit_episode` | Ghi (có idempotency) | Lưu Episode và evidence (`source=agent_reported`); nhận bài học đề xuất do agent viết (Q14) |
| `record_outcome` | Ghi (có idempotency) | Kết quả theo `delivery_id`, kèm ref đã áp dụng và các ReadReceipt |
| `request_improvement` | Ghi (có idempotency), bất đồng bộ | Tạo Job reflection; trả `job_id` |
| `get_job` | Chỉ đọc | Trạng thái và kết quả job |
| `get_health` | Chỉ đọc | Trạng thái nhanh. `deep=true` trả DoctorRun gần nhất kèm tuổi; quá cũ thì tạo job doctor (mục 13) |

### 6.2 Quy tắc chung

- **Lỗi có kiểu và mã.**
  - Ví dụ: `identity_mismatch`, `idempotency_conflict`, `in_progress`, `store_busy`, `deadline_exceeded`, `capability_unavailable`, `revision_conflict`, `not_found`, `quarantined`.
  - Domain chưa được xây trả `capability_unavailable`, không trả success rỗng.
- **Không tool MCP nào duyệt được ChangeProposal** (mục 11.3).
- Mỗi tool ghi rõ trong schema: đồng bộ hay bất đồng bộ, và side effect gì.
- **Ngân sách context** tính bằng token (ước lượng bằng một tokenizer cố định, ghi tên trong schema). Mặc định 4.000.

### 6.3 Idempotency

- Phạm vi khóa: (principal, tool, `idempotency_key`).
- Mỗi khóa gắn với digest của request đã chuẩn hóa (canonical JSON).
  - Cùng khóa, cùng digest → trả lại đúng object và kết quả đã lưu, kể cả holdout assignment.
  - Cùng khóa, khác digest → `idempotency_conflict`.
  - Cùng khóa đang xử lý → `in_progress`.
- Bản ghi idempotency commit cùng transaction với side effect (mục 5.4). Giữ ít nhất 30 ngày.

### 6.4 Job

- Trạng thái: `queued → leased → running → succeeded | failed | cancelled | dead_letter`.
- Lease gắn `writer_epoch`. Mỗi lần thử ghi `attempt`. Mặc định thử tối đa 3 lần với backoff, sau đó vào `dead_letter`.
- Kết quả cuối và trạng thái accounting (`complete`, `unknown`) được lưu cùng job.
- Hủy (`brain job cancel`) có hiệu lực tại điểm có thể hủy; kết quả đến muộn của job đã hủy chỉ được ghi vào trace.

### 6.5 Deadline

- Deadline của `prepare_task` là **1,5 giây tính từ lúc daemon nhận request tới lúc trả response**.
- Ngân sách từng phase:

  | Phase | Ngân sách |
  |---|---|
  | Lọc | ≤ 100 ms |
  | Jev | phần còn lại trừ 200 ms |
  | Commit | ≤ 200 ms |

- Jev quá hạn → dùng kết quả rules. Chưa commit được trong hạn → `store_busy`, không có Delivery.
- Đã commit mà client mất response → retry với cùng `idempotency_key` nhận lại đúng kết quả.
- Hàng đợi ghi có giới hạn; đầy thì fail nhanh với `store_busy`.

## 7. Capture, phiên và liên tục phiên

### 7.1 Đường đi của một sự kiện

```
hook/transcript → adapter dịch sang envelope v2 → privacy filter → outbox cục bộ (fsync)
 → daemon nhận (bỏ trùng theo producer_stream + sequence) → Event
 → worker: gom episode, nhận diện tín hiệu, tạo observation ứng viên
```

- **Hook:**
  - Mục tiêu dưới 100 ms. Trần cứng 2 giây; quá trần thì thoát với mã thành công cho harness và ghi CaptureGap.
  - Lỗi không bao giờ làm harness dừng. Lỗi ghi vào log cục bộ (không chứa payload) và hiện trong `get_health`.
- **Outbox:**
  - Có giới hạn, mặc định 100 MB mỗi harness. Đầy hoặc đĩa đầy thì ghi CaptureGap; không âm thầm bỏ sự kiện.
  - Chỉ xóa sự kiện khỏi outbox sau khi daemon ACK theo mục 5.4.
- **Privacy filter** áp dụng ở mọi đường vào bền vững (mục 14.2), không chỉ ở capture.
- **Sự kiện harness không cung cấp được** thì ghi là `unavailable`, không đoán.
- **Các tín hiệu worker nhận diện:**
  - lần chạy test và exit code;
  - chữ ký lỗi, và lỗi lặp lại;
  - file bị sửa;
  - **lời người dùng sửa agent**: dùng mẫu rules trước; ca chưa rõ thì gom lô hỏi Jev bằng câu Noul, nếu policy egress của repo cho phép.

### 7.2 Task, phiên và episode

- **Session** là một phiên của một harness.
- **Task** là một mục tiêu công việc; một task có thể trải qua nhiều phiên và nhiều harness.
- **Episode** là phần việc của một task trong một phiên.
- Phân tích đo lường đếm theo task, không đếm mỗi phiên là một lần thử độc lập.

### 7.3 Liên tục phiên

- **Khi nào tạo:**
  - Phiên kết thúc: tạo bản tóm tắt cuối.
  - Không hoạt động quá 30 phút: tạo **checkpoint** có nhãn `in_progress_unknown`, **không** phải kết thúc thành công hay thất bại.
- **Checkpoint của việc chạy dài** ghi:
  - lệnh, thư mục làm việc, source revision;
  - PID/handle kèm thời điểm khởi động, nếu có;
  - đường dẫn log hoặc receipt;
  - việc tiếp theo.

  Phiên sau đọc receipt trước. Nếu chưa có receipt kết thúc, chỉ kiểm tra tiến trình gốc một lần; không khởi động lại chỉ vì quá timeout.
- **Sự kiện đến muộn** tạo một revision mới của continuity và giữ lịch sử revision cũ; không ghi đè mà không để lại dấu vết.
- **Nội dung:** L0 (≤50 từ) và L1 dạng dòng thời gian (≤300 từ): mục tiêu, file đã động tới, lệnh, lỗi, việc còn dở.
  - Ưu tiên bản bàn giao do agent gửi qua `submit_episode`.
  - Nếu không có thì trích xuất theo luật.
- **Phạm vi:** gắn với **checkout** (mục 5.2). Được đưa vào `prepare_task` của phiên kế tiếp trên checkout đó, với bất kỳ harness nào.

## 8. Bài học và thư viện kinh nghiệm

### 8.1 Nguồn tạo bài học

1. Cặp lỗi → cách sửa: lệnh kiểm tra đỏ → xanh trong cùng task.
2. Lời người dùng sửa agent.
3. Chiến lược thành công lặp lại.

Câu chữ do agent viết (Q14) hoặc lấy theo mẫu. Mọi bài học bắt đầu ở `candidate`.

### 8.2 Nguồn evidence và điều kiện xác minh

`source` của evidence do **server gán theo kênh nhận**; client không tự khai được.

| Kênh nhận | `source` |
|---|---|
| Adapter capture đã đăng ký (có NativeHostReceipt), quan sát trực tiếp lệnh và kết quả | `tool_observed` |
| `submit_episode` | `agent_reported`, luôn luôn |
| Xác nhận của người dùng qua cổng ở mục 11.3 (`brain lesson confirm`) | `user_confirmed` |

**Lên `verified`** cần **một** trong hai điều kiện:
1. **Proof `tool_observed` gắn đúng subject.** Gồm:
   - claim/tiêu chí;
   - task và source snapshot;
   - lần chạy thất bại và lần chạy thành công của **cùng** lệnh kiểm tra, có thay đổi nằm giữa;
   - trạng thái kết thúc, digest output;
   - phạm vi kết luận.
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

- Chỉ `active` mới được đưa ra (`eligible_for_delivery`). **Lần đưa đầu tiên luôn sau Conflict Review.**
- **Conflict Review:**
  - Xét các bài học có điều kiện áp dụng chồng nhau. Hỏi Jev câu Noul "A có mâu thuẫn với B **trong điều kiện C** không?", nếu policy egress của cả hai bài học cho phép.
  - Không gọi được Jev, hoặc policy cấm → dùng rules: không có bài học nào chồng điều kiện thì qua; có thì giữ ở `pending_conflict_check`. Không bao giờ coi như đã qua.
  - Phát hiện mâu thuẫn: **chỉ bài học mới** sang `conflicted` chờ duyệt. Bài học cũ đang `active` giữ nguyên, trừ khi người dùng quyết định khác.
- Mỗi chuyển trạng thái ghi actor, lý do và evidence vào ledger.
- Chi tiết bảng chuyển trạng thái đầy đủ (suspend, supersede, revoke, reactivate, merge) chốt trước SP3 (mục 19).

### 8.4 Hạ hạng

- Holdout cho thấy bài học có hại (theo quy tắc chốt trước SP6) thì hạ xuống `dormant`.
- Muốn kích hoạt lại phải có evidence mới, rồi qua lại Conflict Review.

### 8.5 Gộp trùng và thư viện kinh nghiệm

- Bài học gần giống được gộp lại, giữ đủ nguồn gốc và proof lineage của từng bản.
- **Thư viện kinh nghiệm** (từ harness2): mỗi bài học giữ hồ sơ Delivery → lý do chọn → ReadReceipt → Outcome. Bộ chọn và reflection dùng hồ sơ này.

## 9. Bộ chọn: lọc tại máy → Jev → rules

**Đối tượng được chọn:** skill, bài học, hướng dẫn tool (c4), persona/finishing gates, và file context (mục 10).

1. **State:** mô tả task, hồ sơ repo, harness, OS, khả năng của harness.
2. **Lọc tại máy, mục tiêu dưới 50 ms:**
   - Loại cứng: không tương thích khả năng, không `active`, đang quarantine, policy egress không cho gửi.
   - Chấm điểm: BM25 trên L0, khớp nhãn, lợi ích đã đo, độ mới.
   - Mặc định tối đa 40 skill, 40 bài học, 20 file.
3. **Gọi Jev** (chỉ với trường trong allowlist, mục 14.2):
   - **Request 1:** Choice trên các skill ứng viên; Noul cổng ("cần skill không?", "cần quy trình không?", "chỉ cần trả lời bằng chữ?"); mỗi bài học và mỗi file ứng viên một câu Noul "có liên quan không?".
   - **Request 2:** sắp xếp lại top 3 skill bằng mô tả đầy đủ, kèm Noul "có đúng việc này không?".
   - Request 1 thành công nhưng request 2 quá hạn → dùng kết quả request 1, ghi trace.
   - Ngưỡng confidence mặc định 0,30 (theo cookbook), chỉnh lại sau khi đo. Được phép chọn **không skill nào**.
4. **Chuyển sang rules** khi Jev lỗi, quá deadline, chạm trần (nếu người dùng đặt), policy cấm, hoặc trả lời không hợp lệ.
   - Câu trả lời được kiểm tra chặt: đủ câu hỏi, đúng kiểu, đúng khoảng giá trị.
   - Rules dùng điểm lọc ở bước 2 với ngưỡng cố định.
5. **Kiểm tra lại** eligibility, trạng thái duyệt và thu hồi ngay trước khi ghi Delivery.
6. **Áp holdout** (mục 12).

**Vận hành Jev:**
- Chốt model `jev-1.14.0`; nâng phiên bản là thay đổi có chủ đích.
- **Cache:**
  - Key gồm model, phiên bản selector, phiên bản prompt/schema, `policy_epoch`, digest state, digest ứng viên.
  - `policy_epoch` tăng khi có revoke, đổi trạng thái bài học, hoặc đổi policy egress, nên kết quả cache cũ tự mất hiệu lực.
- **Retry:** 429/529 retry với backoff, nằm trong deadline.
- **Lời gọi đến muộn:**
  - Không bao giờ thay đổi Delivery đã chốt.
  - Chi phí vẫn được ghi vào ProviderInvocation.
  - Thiếu usage → chi phí `unknown`, không ghi 0.
- **Ngân sách theo Q2.**
  - Mặc định không trần nhưng luôn có giới hạn số lời gọi đồng thời và hàng đợi.
  - Khi người dùng đặt trần:
    - kỳ ngân sách là tháng dương lịch (UTC);
    - trước mỗi lời gọi giữ chỗ chi phí ước lượng, sau đó đối soát theo usage thực;
    - từ 80% thì tắt câu hỏi nền; đến 100% thì chuyển toàn bộ sang rules.

    Trần có thể bị vượt tối đa bằng phần đang giữ chỗ cho các lời gọi đang chạy; `brain report` ghi rõ điều này.
- Tắt Jev cho repo hoặc thu hồi bài học có hiệu lực với cả job đang chờ và lời gọi chưa gửi.
- **Thứ tự làm:** pipeline chạy được bằng rules trước, sau đó bật Jev.

## 10. Context L0/L1/L2

- **Index:** các checkout đã đăng ký, tôn trọng `.gitignore` và danh sách đường dẫn cấm. `.gitignore` không thay thế privacy policy: nội dung L0/L1 cũng đi qua privacy filter. Skill và artifact cũng có L0/L1.
- **Hai loại địa chỉ:**
  - **Live:** `brain://context/{repo_id}/{checkout_id}/{path}#l0|l1|l2`. Luôn trỏ tới nội dung hiện tại.
  - **Immutable:** `brain://context/{repo_id}/{checkout_id}/{path}@sha256:{digest}#l0|l1|l2`. Trỏ đúng bytes đã phục vụ, dùng trong Delivery và receipt.

| Cấp | Nội dung | Giới hạn |
|---|---|---|
| L0 | Đường dẫn, ngôn ngữ, mục đích (docstring/header), kích thước | ≤50 token |
| L1 | Khung AST qua tree-sitter (Python, TypeScript, Go, Rust) | ≤300 token |
| L2 | Nội dung đầy đủ | File ≤1 MB; lớn hơn trả `capability_unavailable` |

- Thiết kế này là của dự án, *lấy cảm hứng* từ OpenViking. OpenViking thật sự làm khác: L0/L1 ở cấp thư mục, dựa trên ngữ nghĩa.
- **Độ mới:**
  - mtime và kích thước chỉ là đường tắt để chọn file cần index lại.
  - Khi phục vụ L1/L2, brain đọc bytes, tính digest và chỉ trả L1 nếu L1 được dựng từ đúng digest đó.
  - File đổi trong lúc đọc → `revision_conflict`.
  - Ngôn ngữ chưa hỗ trợ, file nhị phân hoặc quá lớn: trả cấp thấp hơn có nhãn, không bịa AST.
- **Ranh giới filesystem:**
  - Đường dẫn thực (sau khi theo symlink, junction, reparse point) phải nằm trong thư mục của checkout.
  - Từ chối UNC/device path và alternate data stream trên Windows.
  - Kiểm tra lại danh tính file sau khi mở. Thuật toán cụ thể chốt trước SP5.
- **Ghép context:** ngân sách mặc định 4.000 token, chỉnh được. Phân bổ theo chiều rộng trước; khi hết ngân sách thì hạ L1 → L0 → chỉ URI, không cắt đôi nội dung.
- **Không tuyên bố tiết kiệm token** khi chưa đo (mục 12).

## 11. Tự cải tiến và cổng duyệt

### 11.1 Mô hình 8 thành phần (từ harness2)

| | c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8 |
|---|---|---|---|---|---|---|---|---|
| Thành phần | rule / system prompt | guardrail | memory / bài học | hướng dẫn tool | subagent | skill | script | plugin / hook / MCP config |

| Kênh | Thành phần | Cách đưa | Cổng duyệt |
|---|---|---|---|
| Động | c3, c4, chọn skill đã duyệt (c6) | Gói context của `prepare_task` | Bài học `active` (mục 8.3) |
| Tĩnh | c1, c2, c5, nội dung c6, c7, c8 | Ghi vào file cấu hình của harness | **Luôn chờ duyệt** |

**Nguồn đề xuất:**
- Lời sửa lặp lại → rule.
- Skill được đưa ra mà vẫn thất bại lặp lại → sửa skill.
- Chiến lược thành công lặp lại → bản nháp skill mới.

Câu chữ do agent viết, brain gom evidence và gắn mức rủi ro.

### 11.2 Review và apply

- **Lệnh CLI:**
  - `brain review list|show|approve|reject`
  - `brain apply`
  - `brain rollback <change>`
- **Approval khóa chặt** proposal revision, digest nội dung (gồm toàn bộ resource đi kèm), file đích và digest bản gốc. File đích đổi sau khi duyệt → từ chối apply, phải duyệt lại.
- Ghi file theo kiểu nguyên tử, sao lưu bản gốc.
- **Quyền sở hữu nội dung trong file dùng chung, theo định dạng:**
  - **Markdown:** khối có đánh dấu `<!-- ensemble-brain:begin … end -->`.
  - **JSON:** chỉ các khóa do brain quản lý (ví dụ `mcpServers.ensemble-brain`).
  - **TOML:** chỉ các bảng do brain quản lý.
  - Mỗi phần được quản lý có digest trong manifest. Phần đó bị người dùng tự sửa thì **từ chối ghi** và hiện diff.
- **Bootstrap:** lần cài đặt đầu tiên cho mỗi harness (MCP config, hook, rule lớp 1–2) cũng là một ChangeProposal. Bản review/apply tối thiểu (preview diff, xác nhận, apply đúng bản gốc, backup, rollback) thuộc **SP1**. SP6 bổ sung tự sinh proposal và đo lường.

### 11.3 Cổng duyệt ba lớp (Q18)

| Lớp | Cơ chế | Ai thực thi | Chống được gì |
|---|---|---|---|
| 1. Rule văn bản | Brain cài câu "Không tự duyệt ChangeProposal; khi có proposal, báo người dùng" vào file hướng dẫn của harness (CLAUDE.md, AGENTS.md…) | Model tự giác | Agent hành xử đúng trong trường hợp bình thường |
| 2. Quyền harness | Bootstrap cài rule `ask` cho `brain review approve`, `brain apply`, `brain rollback` vào cơ chế quyền của từng harness. `doctor` kiểm tra rule còn nguyên | Harness | Agent chạy lệnh duyệt mà người dùng không thấy hộp xin phép |
| 3. Brain tự xác minh | **Rủi ro thấp** (khối hướng dẫn c1/c4/c6): xác nhận trong terminal, chỉ khi lớp 2 đang hoạt động. **Rủi ro cao** (c2 guardrail, c5, c7 script, c8 hook/MCP/plugin): bắt buộc passkey (WebAuthn có user verification, qua trang review local) hoặc chữ ký SSH (`ssh-keygen -Y sign`, khóa có passphrase hoặc khóa phần cứng) | Daemon | Lách mẫu lệnh, gọi thẳng HTTP tới daemon, chế độ bỏ qua quyền |

- Endpoint duyệt của daemon chỉ chấp nhận bằng chứng đúng kênh. Không đường MCP nào tạo được ApprovalReceipt.
- ApprovalReceipt ghi kênh và độ mạnh; `brain report` hiện rõ.
- **Giới hạn được công bố:**
  - Một tiến trình chạy cùng tài khoản OS có toàn quyền và điều khiển được giao diện (computer-use) vẫn có thể vượt lớp 1–2.
  - Kênh `terminal` chỉ chống nhầm lẫn.
  - Spec không tuyên bố cô lập mạnh hơn ranh giới mà OS cung cấp.
- **Khi có nhóm:** thêm danh sách người được duyệt (`allowed_signers` / passkey đã đăng ký), luật N/M, và kênh `pr_merge` cho repo cấu hình chung.

### 11.4 Đánh giá sau khi áp dụng

- Kênh động đo bằng holdout.
- Kênh tĩnh chỉ so sánh trước/sau và **ghi rõ là bằng chứng yếu**.
- Brain **không bao giờ chạy** script trong skill. Nội dung skill không tự cấp thêm quyền cho harness.

## 12. Đo lường

### 12.1 Tín hiệu thụ động

Chạy mặc định, nhưng tôn trọng opt-out của từng repo: repo tắt capture thì không có tín hiệu thụ động, chỉ còn dữ liệu agent tự gửi.

Tính theo task, harness, loại task và repo:
- tỷ lệ người dùng sửa lời agent;
- lỗi lặp lại sau khi đã có bài học;
- tỷ lệ tool lỗi;
- số lượt, token, thời gian mỗi phiên (`unavailable` nếu harness không cung cấp);
- thời gian tới khi test xanh.

Mỗi số liệu kèm **độ phủ quan sát**: tầng capture, CaptureGap, mẫu số. Hai harness có mức capture khác nhau không được so như nhau. **Thiếu dữ liệu là `unknown`, không bao giờ được tính là "không có lỗi".**

### 12.2 Holdout ngẫu nhiên

**Đã chốt:**
- Gán nhóm trước khi biết kết quả. Retry với cùng `idempotency_key` giữ nguyên nhóm (mục 6.3).
- **Không bao giờ giữ lại:** bài học gắn nhãn an toàn, bảo mật, mất dữ liệu, và quy ước/sở thích người dùng đã xác nhận.
- Mỗi Delivery lưu đủ dữ liệu để phân tích lại:
  - tập bài học đủ điều kiện;
  - xác suất được chọn và xác suất được gán nhóm;
  - seed, phiên bản policy;
  - revision chính xác của bài học;
  - assignment và exposure (ReadReceipt);
  - độ đầy đủ quan sát.
- Báo cáo chính theo nhóm được gán (intent-to-treat). Phân tích theo exposure là phần bổ sung, ghi rõ giả định.
- Chỉ ghi nhãn "nhân quả" khi thiết kế và các cổng chất lượng dữ liệu đạt. Không chỉ vì bản ghi có tên holdout.
- ≥30 mỗi nhóm là sàn để bắt đầu báo cáo, không phải bảo đảm đủ lực thống kê.

**Chốt trước SP6** (mục 19). Rev 1 có hai quy tắc mâu thuẫn: *p* = 10% cho mỗi cặp (Delivery, bài học), nhưng tối đa 1 bài bị giữ mỗi phiên. Hai hướng sửa:
- **(i)** Mỗi task chọn tối đa một bài học trọng tâm theo policy đã ghi, rồi random hiện/giữ cho bài đó.
- **(ii)** Random độc lập từng bài học và bỏ giới hạn.

Ngoài ra cần chốt:
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
- lợi ích từng bài học kèm khoảng tin cậy;
- chi phí Jev (gồm phần `unknown`);
- độ mạnh kênh duyệt.

Mọi con số được ghi nhãn "nhân quả" (holdout đạt điều kiện) hoặc "tương quan" (trước/sau, thụ động). "Pipeline có dữ liệu đúng assignment" và "đủ dữ liệu kết luận lợi ích" là hai trạng thái khác nhau.

## 13. Tự chẩn đoán: `brain doctor`

- **`brain doctor [--fix] [--json]`:** chạy toàn bộ kiểm tra qua daemon. Daemon không chạy thì chỉ chạy các kiểm tra offline.
- **`get_health()`:** nhanh, chỉ đọc, không gọi mạng, không ghi gì.
- **`get_health(deep=true)`:**
  - Trả DoctorRun gần nhất kèm tuổi.
  - DoctorRun cũ hơn 24 giờ thì tạo job doctor (không gọi Jev) và trả `job_id`.
  - Side effect duy nhất được công bố: ghi Job và DoctorRun.
- **Kiểm tra Jev chủ động** (gửi request thật, tốn tiền) chỉ chạy khi gọi `brain doctor --jev`.
- Daemon tự chạy doctor (không gọi Jev) khi khởi động và mỗi 24 giờ, lưu DoctorRun.

| Nhóm | Kiểm tra |
|---|---|
| Daemon | Đang giữ `writer.lock`, `writer_epoch`, phiên bản schema |
| Danh tính | File credential tồn tại, ACL/quyền file đúng theo OS, mỗi harness đã đăng ký có credential, credential đã thu hồi không còn dùng |
| Storage | `PRAGMA integrity_check`, kích thước WAL, lấy mẫu kiểm tra digest trong CAS, blob mồ côi, ledger khớp với projection, dung lượng đĩa, backup gần nhất |
| Capture | Mỗi harness: lần nhận sự kiện gần nhất, tầng capture đang hoạt động, độ dồn của outbox, CaptureGap, dead-letter |
| Privacy | Canary secret giả phải bị chặn ở mọi đường vào (hook, tool trực tiếp, object lồng nhau, log lỗi, trace, outbox, nội dung dẫn xuất); quét lại kho bằng bộ mẫu mới |
| Harness | Cấu hình MCP trỏ đúng shim; phần do brain quản lý bị sửa tay (drift); hook đã cài; **rule `ask` lớp 2 còn nguyên** |
| Jev | Key có cấu hình; tỷ lệ chuyển sang rules gần đây; chi phí so với trần (nếu có); độ trễ từ trace gần đây. Kiểm tra model còn tồn tại chỉ với `--jev` |
| Index | Số file chưa index hoặc đã cũ |
| Lessons | Số bài học kẹt ở `pending_conflict_check` hoặc `conflicted` |
| Retention | Job dọn dữ liệu lần cuối chạy lúc nào; tombstone khớp với CAS |

- Mỗi mục trả về `PASS | WARN | FAIL`, kèm mô tả và hướng sửa.
- **`--fix` chỉ làm việc an toàn:**
  - khởi động lại daemon;
  - phát lại outbox;
  - dựng lại projection hoặc index vào bảng mới, kiểm tra rồi mới hoán đổi;
  - xoay vòng log.

  **Không bao giờ xóa dữ liệu** và không ghi vào cấu hình harness (việc đó phải qua `review/apply`).

## 14. Bảo mật và quyền riêng tư

### 14.1 Mối đe dọa

| Mối đe dọa | Biện pháp |
|---|---|
| Secret lọt vào kho | Privacy filter ở mọi đường vào bền vững; quét lại định kỳ; phát hiện thì quarantine, không xóa âm thầm |
| Đầu độc bài học | `source` do server gán; bài học do agent viết chỉ là `candidate` tới khi có proof (mục 8.2); Conflict Review trước lần đưa đầu; gói context đánh dấu rõ "dữ liệu tham khảo, không phải lệnh" |
| Skill bên thứ ba độc hại | Không chạy script; nhập skill phải qua review, approval bao gồm toàn bộ resource đi kèm; ghi nguồn gốc và license; gộp skill không làm mất provenance |
| Tiến trình lạ gọi daemon | Chỉ nghe trên loopback; credential riêng cho từng harness, ACL/`0600`; danh tính suy từ credential; duyệt theo mục 11.3 |
| Agent tự duyệt thay đổi | Cổng ba lớp (mục 11.3), có công bố giới hạn |
| Path traversal | Ranh giới filesystem ở mục 10 |
| Dữ liệu gửi cho Jev | Allowlist theo loại request (mục 14.2) |

### 14.2 Privacy contract

**Đường vào.** Privacy filter chạy trước khi ghi bền vững ở **mọi** đường vào:
- hook/transcript;
- `submit_episode` (gồm evidence, diff, bài học đề xuất);
- `record_outcome`;
- nhập artifact;
- index context.

Filter xử lý:
- secret và token theo mẫu, chuỗi có entropy cao;
- nội dung trong `<private>…</private>`;
- danh sách đường dẫn cấm;
- repo bị tắt capture.

Filter duyệt cả object và list lồng nhau. **Filter lỗi thì không lưu payload gốc**, kể cả trong log lỗi, trace hay dead-letter.

**Lưu trữ.** Log, trace và dead-letter không chứa payload thô; chỉ ID, loại và digest.

**Đi ra ngoài.** Jev là đích ra ngoài duy nhất.

| Loại request Jev | Trường được gửi |
|---|---|
| Chọn (request 1) | Mô tả task đã lọc; L0 của skill, bài học, file ứng viên; nhãn repo |
| Xếp lại (request 2) | Mô tả task đã lọc; mô tả đầy đủ (L1) của tối đa 3 skill |
| Phân loại lời sửa | Tin nhắn người dùng đã lọc, kèm tối đa 2 lượt trước đã lọc |
| Conflict Review | L0 và điều kiện áp dụng của hai bài học |

- Không bao giờ gửi L2, evidence thô hay nội dung transcript ngoài các trường trên.
- Allowlist được kiểm tra trước mọi lời gọi, kể cả retry và job nền.

**Policy theo repo.**
- Mỗi repo có policy `capture: on|off`, `jev: on|off`.
- Nội dung dẫn xuất kế thừa policy chặt nhất của mọi nguồn: bài học rút từ repo `jev: off` mang nhãn `egress: local_only` và không bao giờ được gửi cho Jev, kể cả khi được chọn trong repo khác.
- Chia sẻ owner-wide (Q12) chỉ áp dụng cho nội dung bài học. Resolve ref tới nguồn vẫn kiểm tra quyền.

### 14.3 Xử lý lỗi

- Daemon tắt: shim trả lỗi rõ ràng; outbox giữ sự kiện và gửi lại sau mà không tạo bản trùng.
- Jev lỗi: chuyển sang rules, có trace.
- Dữ liệu hỏng: quarantine; khôi phục theo mục 5.7.
- Cấm nuốt lỗi; mọi chế độ dự phòng đều hiện trong `get_health`.

## 15. Các dự án con và thứ tự

Mỗi dự án con có plan riêng (superpowers:writing-plans) dựa trên spec này. Nếu một dự án con cần quyết định thiết kế mà spec chưa có, chạy một vòng brainstorming ngắn và bổ sung spec trước khi viết plan. Các quyết định có hạn chót riêng nằm ở mục 19.

| # | Dự án con | Nội dung | Package sở hữu | Nguồn code |
|---|---|---|---|---|
| SP1 | Kernel | `core`, `ports`, `storage` (mục 5.4–5.7), `adapters.os`, daemon + shim + khóa ghi, khung contract v2 với 8 tool (domain chưa có trả `capability_unavailable`), idempotency, job, privacy filter cho mọi đường vào, `doctor` cơ bản, **bootstrap review/apply tối thiểu + cổng duyệt ba lớp**, CI đa OS và hàng rào | `core`, `ports`, `storage`, `adapters.os`, `mcp`, `cli_api`, `cli`, `composition`, phần nền của `application` | **Trích xuất** từ repo cũ `f83271d` kèm test, phần còn lại viết mới |
| SP2 | Capture và liên tục phiên | envelope v2, outbox, worker tín hiệu, task/session/episode, continuity; khảo sát + adapter cho Claude Code và Codex app | `domain.capture`, `domain.continuity`, `adapters.harness.*` | Queue trích xuất; phần còn lại viết mới |
| SP3 | Bài học | Vòng đời, xác minh, Conflict Review, thư viện kinh nghiệm | `domain.lessons` | Viết mới (TDD) |
| SP4 | Catalog và bộ chọn | Nhập agency-agents và skill local; lọc → Jev → rules; ngân sách; allowlist egress | `domain.catalog`, `domain.selection`, `adapters.jev` | Viết mới |
| SP5 | Context L0/L1/L2 | Index, tree-sitter, ref live/immutable, ghép context | `domain.context` | Viết mới, tham khảo code cũ |
| SP6 | Cải tiến và đo lường | Tự sinh ChangeProposal, holdout, report | `domain.improvement`, `domain.measurement` | Viết mới |
| SP7 | Các adapter còn lại | OpenCode, Antigravity; Cursor khi được cài | `adapters.harness.*` | Viết mới, mỗi harness có bước khảo sát trước |

### Các mốc và điều kiện nghiệm thu

- **M1 (SP1 + SP2):**
  - Claude Code và Codex app trên máy chủ dự án cùng ghi vào một kho thật.
  - Cả hai được cài qua bootstrap ChangeProposal đã duyệt.
  - Mỗi harness có NativeHostReceipt của host thật (mục 17.3).
  - Phiên của harness này nhận được continuity của phiên trước từ harness kia **trên cùng checkout**. Một checkout khác của cùng remote không nhận nhầm.
- **M2 (+ SP3, SP4):**
  - Một bài học được `verified` bằng proof `tool_observed` từ harness A.
  - Bài học qua Conflict Review, được **Jev** chọn (không phải rules) và đưa cho harness B.
  - Hệ thống phân biệt được các mức: đã chọn, đã trả, đã đọc đủ (ReadReceipt), agent khai đã áp dụng, quan sát được.
- **M3 (+ SP5, SP6):**
  - `brain report` có dữ liệu holdout thật với assignment đúng thuật toán đã chốt.
  - Kết luận "có lợi ích" là một claim riêng, chỉ khi đủ điều kiện ở mục 12.2. Không có cam kết thời gian đạt đủ dữ liệu.

**Danh sách trích xuất cho SP1:** đồ thị import và số dòng đã đo nằm trong `docs/notes/2026-10-29-extraction-analysis-draft.md` (chỉ để tham khảo). Plan SP1 chốt manifest chính thức theo quy tắc ở mục 17.4.

## 16. Đối chiếu với tài liệu cũ

| Chủ đề | Tài liệu/code cũ | Spec này |
|---|---|---|
| Bộ chọn | Rules mặc định, Jev tùy chọn | Jev chính, rules dự phòng |
| Phạm vi bài học | Cô lập chặt theo workspace | Chia sẻ trong cùng `owner_id`, repo chỉ là gợi ý |
| Persona/skill | 8 persona + 217 skill (docs/plan); V5 thu gọn còn 8 | agency-agents cộng ~70 skill local, chọn bằng Jev |
| Harness | 5, sau đó tăng lên 9 | 5 (Cursor hoãn) |
| Hệ điều hành | Windows | Windows, macOS, Linux |
| Contract | `mcp-tools-v1` | `mcp-tools-v2`, không tương thích ngược |
| Tự cải tiến | `evolution` chạy probe theo harness2; `learning` campaign | Không chạy probe; agent viết, brain xác minh |
| Cổng duyệt | – | Ba lớp, có ApprovalReceipt |
| Đo lường | Owned fixture, benchmark, utility experiment | Tín hiệu thụ động + holdout |
| Cơ sở dữ liệu | `brain.db` + `cognitive.db`; V5 gộp | Một DB mới, không nhập dữ liệu cũ |
| Phát hành | PyPI, Docker, Smithery | Ngoài phạm vi |
| Tự chẩn đoán | `get_health` | `doctor` + `get_health(deep)` |

## 17. Kiểm thử, hàng rào và nghiệm thu

### 17.1 Kiểm thử

- TDD cho code mới.
- Jev: dùng transport giả cho contract và các ca lỗi.
- Fault injection cho các điểm crash ở mục 5.4.

### 17.2 Các gate

| Gate | Gồm | Chạy ở đâu | Điều kiện |
|---|---|---|---|
| **Mặc định** | Unit + integration (SQLite thật, daemon thật dạng subprocess, fixtures contract v2) | CI ma trận 3 OS × 2 Python, và tại máy | Mỗi job dưới 5 phút. Cùng với import-linter + test AST, không vòng phụ thuộc, `mypy --strict`, `ruff` cho `src` và `tests`, cấm nuốt lỗi, cảnh báo file vượt 600 dòng |
| **Canary Jev** | Một request thật | Tại máy, khi chủ dự án cho phép | Tốn tiền; chạy riêng |
| **Native** | Kiểm chứng với host thật | Tại máy, khi chủ dự án đồng ý | Tạo NativeHostReceipt |

- Gate chưa chạy thì trạng thái là **chưa nghiệm thu**, không phải "được miễn".
- Không xóa, skip hay giảm assertion để đạt thời gian.
- Chuyển một test sang nhóm khác cần review có requirement đi kèm.
- **Receipt của gate** gắn: commit SHA (working tree sạch), digest lockfile và config, danh sách test, kết quả cuối. Source đổi giữa lần chạy thì receipt không nghiệm thu cho snapshot cuối.

### 17.3 NativeHostReceipt

- Gắn: tên và phiên bản host, phiên bản/digest build của shim, digest cấu hình, task, và lời gọi quan sát được.
- Receipt tạo từ fixture có loại `fixture` và không bao giờ được tính là host thật.

### 17.4 Quy tắc trích xuất (cho plan SP1)

- Mỗi phần trích xuất có commit/blob nguồn, test đi kèm và requirement của spec mà nó phục vụ.
- Test mang sang chạy trước khi sửa.
  - Test fail sẵn ở nguồn được giữ và phân loại, không sửa assertion để có baseline xanh.
  - Khi spec mới chủ ý đổi hành vi, test đổi theo requirement đã review và ghi lý do.
- Không kéo theo code chỉ vì nằm trong import closure.

### 17.5 Quy tắc tuyên bố

- Không ghi "xong" hay "verified" khi chưa có receipt của gate mặc định.
- Không ghi "hỗ trợ harness X" khi chưa có NativeHostReceipt của host thật.
- Khung tool trả `capability_unavailable` không được gọi là "đã có tính năng".

## 18. Việc còn mở (không chặn việc viết plan cho SP1)

| # | Việc | Khi nào xử lý |
|---|---|---|
| O1 | Giấy phép của dự án (nếu công khai) | Trước khi phát hành, ngoài phạm vi hiện tại |
| O2 | Codex app desktop: hook, vị trí transcript, cơ chế quyền cho lớp 2 | Bước khảo sát trong SP2 |
| O3 | Antigravity `agy` 1.4.8 và OpenCode 2.2.0: hook/plugin, định dạng transcript, cơ chế quyền | Bước khảo sát trong SP7 |
| O4 | Độ trễ Jev thực tế trên mạng của chủ dự án; ngưỡng confidence | Canary trong SP4 |
| O5 | Số lượng ứng viên lọc (40/40/20) và ngân sách 4.000 token | Đo trong SP4/SP5 |
| O6 | License của từng skill trong ~70 skill local | Bước nhập trong SP4 |
| O7 | Tự khởi động daemon lúc đăng nhập trên từng OS (mặc định: chạy khi cần) | Plan của SP1 |
| O8 | Hình thức chia sẻ nhiều người dùng: máy chủ chung, đồng bộ, hay chỉ chia sẻ gói skill/bài học | Khi bắt đầu giai đoạn nhiều người dùng |

## 19. Hạn chót của các quyết định theo dự án con

| Trước | Cần chốt |
|---|---|
| Plan SP1 | Bảng điểm crash (mục 5.4), manifest trích xuất, tên package, O7 |
| SP2 | Contract hook có giới hạn và trường hợp chưa bền vững, xử lý sự kiện muộn, ánh xạ task/session/episode của từng harness, checkpoint việc chạy dài, độ phủ capture theo harness |
| SP3 | Bảng chuyển trạng thái đầy đủ (actor, evidence), chi tiết proof độc lập, so điều kiện áp dụng, gộp/merge giữ lineage |
| SP4 | Review artifact kèm resource closure, payload Jev chính xác theo allowlist, cache/policy, accounting lời gọi đang chạy, canary đo độ trễ |
| SP5 | Thuật toán ranh giới filesystem trên từng OS, parser, chi tiết index |
| SP6 | Thuật toán holdout (mục 12.2), estimand, missing/carryover, quy tắc CI và `dormant`, quy trình tự sinh proposal |
| SP7 | Khảo sát native từng adapter và receipt cho các khả năng thực sự được tuyên bố |

## 20. Tình huống nghiệm thu bắt buộc cho SP1

Plan SP1 phải biến mỗi tình huống dưới đây thành test (hoặc ghi rõ thuộc SP nào nếu chỉ kiểm tra được khi domain đó có):

1. Payload khai owner khác principal không đọc/ghi được; truy cập trực tiếp bằng ref artifact/job cũng bị kiểm tra như vậy.
2. Hai checkout cùng remote, cùng đường dẫn tương đối nhưng nội dung khác nhau không dùng nhầm continuity/context.
3. Request trùng đồng thời và retry sau khi mất response trả cùng object/kết quả; cùng khóa khác payload trả `idempotency_conflict`.
4. Mất response của `prepare_task` không tạo Delivery hay holdout assignment mới khi retry.
5. Dừng tiến trình tại mọi điểm crash không làm ref đã ACK trỏ tới dữ liệu không khôi phục được.
6. Replay cùng ledger không tạo thêm job/lesson/chi phí; payload đã hết hạn hoặc quarantine không bị rebuild phục sinh.
7. Snapshot DB–CAS đúng thì khôi phục được; snapshot thiếu hoặc sai subject bị từ chối trước khi thay dữ liệu đang dùng.
8. Hai daemon khởi động đồng thời, hoặc bảo trì chạy cạnh writer, không bao giờ có hai chủ ghi hợp lệ.
9. Secret qua tool trực tiếp, object/list lồng nhau, log lỗi, trace, outbox hay nội dung dẫn xuất không vượt privacy invariant.
10. Repo tắt Jev không bị gọi Jev qua retry, job nền, hay bài học dẫn xuất từ nguồn bị cấm (kiểm tra ở SP4).
11. Agent không tự nâng self-report thành `tool_observed`/`user_confirmed`; hai episode tự báo cáo không đủ xác minh (kiểm tra đầy đủ ở SP3).
12. Bootstrap hiện diff cụ thể; chỉ apply đúng approval và bản gốc; file đích bị sửa sau duyệt thì từ chối; thay đổi rủi ro cao không duyệt được bằng terminal.
13. `get_health()` không gọi mạng, không ghi; `deep=true` công bố side effect và không chặn `prepare_task`.
14. NativeHostReceipt loại fixture không được nhận là host thật; ReadReceipt gắn đúng task và revision artifact.
15. Receipt của gate có source/config/test inventory và kết quả cuối; giới hạn thời gian không đạt được bằng cách giảm coverage âm thầm.

## 21. Ánh xạ review → rev 2

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
| SB2-S10 deadline, deep doctor | Mục 6.5, 13 |
| SB2-S11 delivery/read/applied/native | Mục 5.3 (ReadReceipt, NativeHostReceipt), 17.3, M2 |
| SB2-S12 Conflict Review | Mục 8.3; chi tiết trước SP3 |
| SB2-S13 holdout | Mục 12.2; thuật toán trước SP6 |
| SB2-S14 phiên im lặng, capture thiếu | Mục 7.2, 7.3, 12.1 |
| SB2-S15 cache, budget | Mục 9 |
| SB2-S16 context ref | Mục 10 |
| SB2-S17 phân tầng, trích xuất | Mục 4.2, 17.4 |
| SB2-S18 gate, catalog | Mục 17.2, 17.5, 14.1, M1–M3 |
