# SP2 Host Capture Matrix, Budgets & Coordinated Schema/Crash Contract (O2/O9 Baseline)

**Tài liệu:** Baseline `SP2-0` cho Super-brain2 Capture & Session Continuity (`Claude Code` & `Codex`).  
**Ngày khóa:** `2026-11-19T03:25:21Z` (`2026-11-19T10:25:21+07:00`).  
**Baseline commit:** `035a4cdc5936155982e5172602213353d4bbb6c4`.  
**Đặc tả tham chiếu:** [Thiết kế hệ thống rev 22](../superpowers/specs/2026-10-30-super-brain2-system-design.md) (§5.2–5.9, §6.1–6.5, §7.1–7.4, §8.2, §8.10, §11.3, §14.2, §17.2–17.5, §19, §20) và [Hồ sơ quyết định A1–A3](../reviews/2026-11-19-sp2-baseline-and-ca62-decisions.json).

> **Quy tắc liêm chính O2/O9 (Owner Decision A3):** Ma trận dưới đây chỉ sử dụng:
> (a) hồ sơ đã kiểm chứng trong repo (`T0`, `R56`, `D8` trên `035a4cd`, [Checklist native I2](sp1-increment2-native-checklist.md), [Bàn giao I2](sp1-increment2-handover.md)),
> (b) tài liệu / đặc tả kiến trúc đã khóa của dự án (`rev 22`, kế hoạch I3/SP2), và
> (c) đầu ra CLI read-only `--version` / `--help` / `Get-AppxPackage` quan sát được trên máy chủ Windows.  
> **Tuyệt đối không** đọc cấu hình live `~/.claude` / `~/.codex` hoặc transcript thực của người dùng để suy đoán field. Mọi trường hook/transcript/provider-call chưa được chứng minh bằng probe được phê duyệt bắt buộc ghi là `unknown`, và mọi sự kiện host chưa chứng minh có phát hành bắt buộc ghi là `unavailable`.

---

## 1. Bảng nền host đã xác minh & Ma trận Capture O2/O9 (`Claude Code` & `Codex`)

### 1.1 Phiên bản & bằng chứng quan sát được (read-only)

| Trường | `Claude Code` | `Codex` |
| --- | --- | --- |
| **Artifact / Phiên bản quan sát hiện tại** | `claude --version`: `2.1.325 (Claude Code)` (Windows `win32`) | `Get-AppxPackage *Codex*`: `OpenAI.Codex 26.1111.2228.0` MSIX + `OpenAI.CodexPrimaryRuntime.v26-1116-1220-0`, `OpenAI.CodexPrimaryRuntime.v26-1117-835-0`; `codex` CLI không nằm trên `PATH` mặc định |
| **Phiên bản trong hồ sơ D8 / T0 (`035a4cd`)** | D8: `2.1.322 (Claude Code)` (`claude_cli_mcp_isolated`); T0: `2.1.317` (`passed`, `t0r3`) | D8: `OpenAI.Codex 26.1111.2228.0` MSIX (`codex_desktop_gui`, `ChatGPT.exe`, `passed`); phụ trợ CLI ở T0/checklist: `codex-cli 0.167.0-alpha.4.1` (diagnostic only) |
| **Cơ chế MCP đã xác minh D2/D3** | `--mcp-config <ABS_ISOLATED_CONFIG>` + `--strict-mcp-config`; cờ quan sát được từ `claude --help`: `--bare` (bỏ qua hook ở settings/plugin), `--settings <file-or-json>`, `--allowed-tools <tools...>`, `doctor`, `purge` | Desktop GUI (`ChatGPT.exe`) dùng `CODEX_HOME` cô lập; mỗi cửa sổ checkout giữ tiến trình `shim` độc lập nối socket loopback D2 về daemon |
| **Vòng đời tiến trình & ràng buộc D3** | Launch riêng cho checkout (`<checkout>/.mcp.json` hoặc `--mcp-config`), tắt/khởi tạo lại khi đổi checkout; hook đồng bộ chạy ngoài luồng giữ CWD của checkout đang mở | `codex_desktop_gui` mở window theo checkout (`A`, `B`, `C`), relaunch shim khi chuyển workspace; chế độ desktop AppContainer/sandbox phải tuân ACL `LOCALAPPDATA` / trusted root |
| **Vị trí hook & cấu hình mục tiêu (kế hoạch I3 §11.2 / D3)** | `<checkout>/.mcp.json`, `<checkout>/CLAUDE.md`, `<checkout>/.claude/settings.local.json` (hoặc `.claude/settings.json` được chọn — cấm ghi cứng `--profile <A>` ở cấu hình global làm gãy checkout `B`) | `<checkout>/AGENTS.md`, `.codex/config.toml`, `.codex/hooks.json` (hoặc `CODEX_HOME` cô lập gắn checkout; giữ nguyên comment/bảng người dùng qua `tomlkit`) |
| **Nguồn xác định checkout scope** | `ClientProfile` (`profile.json`) + `SelectedWorkspace(alias, Scope(repo_id, checkout_id))` xác minh từ physical path CWD qua `verify_launch_checkout` và mang `capture_binding(producer_stream, repo_id, checkout_id)` riêng | Tương tự: `ClientProfile` gắn đúng checkout + `CaptureProducerBinding(producer_stream, repo_id, checkout_id)` tách biệt credential `capture_producer` khỏi MCP shim và `user:cli` |
| **Cờ tắt/lọc trên host & `--bare`** | `--bare` (theo `claude --help`) bỏ qua mọi hook trong settings/plugin -> khi chạy dưới `--bare` hoặc thiếu hook, `Capture` rơi về `unavailable` an toàn | Nếu build/profile Codex không bật hook hoặc chạy thiếu runtime hook -> `Capture` rơi về `unavailable` an toàn |

### 1.2 Ma trận trường quan sát O2/O9 theo từng loại dữ liệu (`unknown` / `unavailable` fail-closed)

| Nhóm dữ liệu O2/O9 | `Claude Code` | `Codex` | Quy tắc fail-closed bắt buộc |
| --- | --- | --- | --- |
| **Schema JSON chính thức của từng hook event** | `unknown` *(chờ probe SP2-5 được chủ dự án duyệt; `--bare` & `--settings` đã xác nhận tồn tại)* | `unknown` *(chờ probe SP2-5 trên `OpenAI.Codex` runtime)* | Mọi trường chưa xác minh ở adapter ghi `unknown`; thiếu payload hook không làm hỏng harness |
| **Định dạng/vị trí transcript cục bộ & quyền đọc** | `unknown` *(không đọc `~/.claude` ngoài phạm vi được duyệt)* | `unknown` *(không đọc `~/.codex` ngoài phạm vi được duyệt)* | Chỉ đọc đường dẫn được cấu hình/xác minh physical path + owner-only ACL; nếu không đọc được thì phần quan sát = `unavailable` |
| **Hook sự kiện người dùng / shell / kết quả tool / kết thúc phiên** | `unknown` *(chỉ giữ tên khái niệm lớp event: user message, tool/command, error, session end / `session_resumed`)* | `unknown` *(tương ứng; desktop GUI event hook cần probe riêng)* | Sự kiện harness không phát hành hoặc không thu được ghi `unavailable`; không suy đoán từ timeout |
| **Cơ chế Layer 2 (`ask` rule theo lệnh)** | `unknown` *(cần `NativeHostReceipt` gắn `(harness_id="claude-code", host_version, config_digest)` ở SP1 I3-1 + SP2-5)* | `unknown` *(cần `NativeHostReceipt` gắn `(harness_id="codex", host_version, config_digest)` ở SP1 I3-1 + SP2-5)* | Khi Layer 2 là `unknown` hoặc `unsupported`: cấm `terminal` approval (§11.3) và hạ mọi capture về `source_verification="unverified"`, không cho gắn `source="tool_observed"` (§8.2) |
| **Chi phí / token / provider call metadata từng lượt** | `unknown` *(phương thức trích `provider_endpoint_digest`, `model_config_digest`, `account_digest` chờ probe SP2-5)* | `unknown` *(tương ứng)* | Trường người nhận không xác minh được ghi `"unknown"`; thiếu chứng cứ model call hoàn tất thì `exposure_evidence="unknown"` (không bao giờ nâng thành `sent_to_recipient`) |
| **Rà soát không giao diện (`§8.10`) sandbox profile** | `unknown` *(chờ `NativeHostReceipt` cho profile đọc-cục-bộ + vùng tạm riêng)* | `unknown` *(chờ `NativeHostReceipt` cho profile đọc-cục-bộ + vùng tạm riêng)* | Trạng thái `unknown`/`unsupported` -> **không spawn** process harness cho rà soát sau phiên, đi nhánh dự phòng kèm lý do |

---

## 2. Hồ sơ người nhận theo `SessionSegment` & Bằng chứng tiếp xúc `ExposureEvidence` (§7.2, §8.10)

### 2.1 Danh tính phiên gắn kép hai kho (`session_ref`)
- Định danh thô `session_id` của harness **không bao giờ** xuất hiện trong L0, L1, L2, SQLite (`brain.db`, `policy.db`), CAS blobs, outbox hay log.
- Brain ánh xạ `session_ref = HMAC-SHA256(session_hmac_key, session_id)` (bắt buộc qua `policy.db` v5 `session_hmac_key` + bảng `session_ref_bindings(session_ref, principal_id, bound_at)` trước khi chiếu sang `sessions` ở `brain.db` v6).
- Cùng `session_id` nếu được gửi bởi `principal_id` khác (qua bất kỳ đường nào: `capture`, `submit_episode`, replay) bị từ chối với `IDENTITY_MISMATCH`.

### 2.2 Hồ sơ người nhận theo đoạn phiên (`SessionSegment`)
Mỗi `SessionSegment` trực thuộc đúng một `session_ref` và ghi cố định 4 thành phần:

| Trường `SessionSegment` | Kiểu & quy tắc ghi | Mặc định fail-closed |
| --- | --- | --- |
| `harness_id` | Chuỗi định danh harness (`"claude-code"`, `"codex"`, ...) lấy từ credential/receipt đã xác minh | `"unknown"` nếu chưa xác minh |
| `provider_endpoint_digest` | `sha256:...` phủ endpoint nhà cung cấp đã xác minh cho lượt model | `"unknown"` nếu không đọc/xác minh được |
| `model_config_digest` | `sha256:...` phủ tên model + tham số cấu hình suy luận đã xác minh | `"unknown"` nếu không đọc/xác minh được |
| `account_digest` | `sha256:...` của định danh tài khoản nhà cung cấp đã xác minh (không lưu token/email thô) | `"unknown"` nếu không xác minh được |

- **Bất biến chuyển đoạn (§7.2):** Hễ bất kỳ trường nào trong `(harness_id, provider_endpoint_digest, model_config_digest, account_digest)` thay đổi giữa phiên, adapter/service mở một `SessionSegment` mới; một `session_ref` có thể chứa nhiều đoạn, và bằng chứng tiếp xúc **không bao giờ** lan truyền chéo giữa các đoạn hay các mục.

### 2.3 Phân loại `ExposureEvidence` trên từng `Event` / item (§7.2, §8.10)
`exposure_evidence` do **adapter/server** gắn theo kênh thu, tuyệt đối **không** tin trường do client tự khai:

| Giá trị | Điều kiện được phép gán | Ý nghĩa cho §8.10 (rà soát sau phiên) |
| --- | --- | --- |
| `sent_to_recipient` | **Chỉ khi** adapter có chứng cứ khớp đủ `(item_ref, item_digest, session_segment_id, completed_model_call_id)` trong một lời gọi model **đã hoàn tất và xác minh được** (gửi đi hoặc nhận về) với hồ sơ người nhận đầy đủ không chứa `"unknown"` | Đủ điều kiện gửi lại trong nhánh rà soát cùng người nhận (hoặc nhánh người nhận mới đã duyệt `policy`) |
| `local_only` | Có căn cứ chắc chắn mục chỉ thu qua hook cục bộ tại máy hoặc chỉ do agent/user ghi vào brain (chưa đi qua lời gọi model tới provider, hoặc thu sau lời gọi model cuối) | **Luôn bị loại** khỏi payload gửi ra ngoài ở §8.10 (cấm tiết lộ mới không qua duyệt) |
| `unknown` | Mặc định fail-closed cho mọi ca còn lại (lời gọi model lỗi/timeout/hủy giữa chừng, thiếu provenance, hoặc hồ sơ đoạn phiên có bất kỳ trường `"unknown"` nào) | **Luôn bị loại** khỏi payload gửi ra ngoài ở §8.10 |

---

## 3. Lớp 2 (§11.3), 11 nhóm lệnh Authority & Vô hiệu hóa `NativeHostReceipt`

### 3.1 Danh mục nhóm lệnh Authority bắt buộc cấu hình `ask` ở Lớp 2 (§11.3 & I3 plan)
Theo đặc tả §11.3 (mục "2. Quyền harness") và chi tiết hóa trong [Plan SP1 đợt 3](../superpowers/plans/2026-11-18-sp1-increment3-review-apply.md):

| STT | Nhóm lệnh CLI Authority | Tham chiếu đặc tả / Plan I3 | Rủi ro tối thiểu |
| --- | --- | --- | --- |
| 1 | `brain init*` *(khởi tạo / `--reset-signers`)* | Plan I3 (`§11.3` TOFU init & reset) | Cao (khóa signers / trust) |
| 2 | `brain review approve*` | §11.3 & Plan I3 | Theo proposal (chặn tự duyệt) |
| 3 | `brain review reject*` | §11.3 & Plan I3 | Theo proposal |
| 4 | `brain apply*` | §11.3 & Plan I3 | Cao / theo proposal |
| 5 | `brain rollback*` | §11.3 & Plan I3 | Cao / theo proposal |
| 6 | `brain lesson confirm*` | §11.3 & Plan I3 | Thấp (cần approval `user_confirmed`) |
| 7 | `brain signer*` *(enroll/revoke/...)* | §11.3 & Plan I3 | Cao |
| 8 | `brain policy*` *(set/reconcile-accounting/...)* | §11.3 & Plan I3 | Cao |
| 9 | `brain credential*` *(issue/revoke/...)* | §11.3 & Plan I3 | Cao |
| 10 | `brain restore*` | §11.3 & Plan I3 | Cao |
| 11 | `brain workspace link*` | §11.3 & Plan I3 | Cao (ràng buộc checkout/alias) |

*(Ghi chú đồng bộ I3: đặc tả §11.3 nêu 9 lệnh bắt đầu từ `brain review approve/reject` tới `brain workspace link`; Plan I3 tách `approve` / `reject` và bổ sung `brain init*`, gom thành 11 mẫu lệnh `ask` cụ thể ở bảng trên — adapter SP2-5 phải kiểm đủ cả 11 mẫu lệnh này.)*

### 3.2 Neo `NativeHostReceipt` & Quy tắc vô hiệu hóa kép
- Trạng thái lớp 2 trong `policy.db` (`harness_layer2_state`) khóa chính xác theo bộ ba:
  **`(harness_id, host_version, config_digest)`**.
- **Hai tác động bắt buộc khi thiếu hoặc lệch bất kỳ phần nào của `(harness_id, host_version, config_digest)`:**
  1. **Kênh duyệt `terminal` (§11.3):** Nếu tập harness active có bất kỳ harness nào ở `unknown` / `unsupported` (hoặc tập harness active rỗng) -> `terminal_channel_eligible == False`, từ chối mọi `terminal` approval và đòi kênh mạnh hơn.
  2. **Nhãn nguồn capture (§8.2, ca 11 & 42):** `POST /v2/capture/events` **chỉ** gắn `source="tool_observed"` và `source_verification="verified_host"` khi producer credential (`capture_producer`) khớp **đồng thời** `(principal_id, producer_stream, repo_id, checkout_id)` **và** `PolicyStore` có `NativeHostReceipt` hợp lệ khớp đúng `(harness_id, host_version, config_digest)` hiện hành. Mọi trạng thái `unknown`, `unsupported` hoặc lệch version/config tự động gắn `source_verification="unverified"`, chặn vĩnh viễn việc nâng bài học từ nguồn đó lên `verified` và buộc `doctor` báo cảnh báo lớp 2 quay về `unknown`.

---

## 4. Toàn bộ ngân sách số, công thức & oracle bất biến cho `SP2-1`..`SP2-5` (§6.2, §7.1, §7.3, §7.4, §19)

| Nhóm | Thông số / Quy tắc | Giá trị ghim cứng | Công thức & Oracle kiểm thử |
| --- | --- | --- | --- |
| **Hook đồng bộ (`hook_entry`)** | Ngân sách mục tiêu | `< 100 ms` | Đo thực thi `python -I` trên workload chuẩn (chỉ stdlib + `core` + `domain.capture`, 0 import SQLite/network/heavy libs) |
| **Hook đồng bộ (`hook_entry`)** | Trần cứng (hard cap) | `2 s` (`2,000 ms`), tính từ lúc tiến trình bắt đầu chạy code | Quá `2 s` (khi I/O chậm giả lập): thoát với mã thành công (`rc=0`) để không chặn harness; phần chính dừng ở `trần − 150 ms (watchdog) − dự trữ ≤ 300 ms` để `CaptureGap` ghi bền trước khi watchdog kết thúc tiến trình; log chỉ chứa mã lỗi + tên pha (`0` payload thô). I/O treo hẳn: chỉ còn log tĩnh |
| **Outbox cục bộ** | Dung lượng trần mặc định mỗi harness | `100 MB` (`104,857,600` bytes) | Tổng byte outbox chạm/vượt `104,857,600 B` hoặc `ENOSPC`: từ chối/ghi `CaptureGap`, không âm thầm xóa/bỏ sự kiện chưa ACK; quyền owner-only; `fsync` mỗi lô; **tách riêng ACK `Event` và ACK `CaptureGap`:** bản ghi `Event` chỉ xóa khi `sequence <= contiguous_event_acked_through` hoặc `sequence in committed_event_sequences`; bản ghi `CaptureGap` do producer tự phát chỉ xóa khi `sequence in acked_producer_gap_sequences` (mục `4.1` — cấm xóa `Event` dựa vào đóng gap hay `high_seq`) |
| **Lịch Worker làm mới sổ** | Ngưỡng đếm sự kiện | `20` events mới (chưa làm mới) | Qua `FakeClock` & owner queue: kích hoạt `continuity.refresh` ngay khi đạt event thứ `20` |
| **Lịch Worker làm mới sổ** | Ngưỡng thời gian chờ | `60 s` kể từ event đầu tiên chưa làm mới | Qua `FakeClock` (`0` fixed sleeps): dù `< 20` event (hoặc phiên im lặng), chạm `+60 s` thì xếp tối đa `1` job; event đến trong lúc job đang chạy bật `dirty_flag` và xếp đúng `1` job kế tiếp sau khi commit xong |
| **Trạng thái phiên** | Ngưỡng rời `active` (takeover) | `<= 5 min` (`300 s`) | Hàm toàn phần cho phiên chưa `ended` theo `elapsed = now - last_event_at`: `0 <= elapsed <= 300 s` -> **`active`** (cảnh báo L0 và bắt buộc `acknowledge_active=true` khi tiếp quản) |
| **Trạng thái phiên & Checkpoint** | Rời `active` sau `300 s`; checkpoint `in_progress_unknown` sau `1,800 s` | Rời `active`: `> 300 s`; checkpoint: `> 1,800 s` (hoặc crash không end event) | `elapsed > 300 s` (từ phút thứ 6 trở đi, gồm cả `(300 s, 1,800 s]` lẫn `> 1,800 s`) -> **`in_progress_unknown`** (hết cảnh báo `active`, không đòi `acknowledge_active`); **tách riêng** ngưỡng tạo bản ghi checkpoint `in_progress_unknown` tại **`elapsed > 1,800 s`** (`> 30 phút`, mục `4.2`); chỉ event kết thúc đặt `ended`; event thường sau `ended` gộp vào quan sát nhưng giữ `ended`, chỉ `session_resumed` mở lại `active` |
| **Cửa sổ `prepare_task(mode=discover)`** | Tuổi sổ mở tối đa | `14 days` (`1,209,600 s`) | Lọc `task_state == "open"` và `updated_at >= now - 14d`; giữ tối đa **`3`** sổ mới nhất trước (chỉ qua `FakeClock`, không đụng `sleep`); truyền đúng `task_id` bỏ qua lọc `<= 3`, `<= 14d` và `task_state == "open"` sau khi kiểm binding |
| **Tokenizer ngân sách context** | `utf8-byte-v1` | `ceil(total_utf8_bytes / 4)` | Đếm trên tổng byte UTF-8 của phần nội dung/L0 được chọn (không tính envelope JSON-RPC/HTTP bọc ngoài); `ceil` áp dụng **một lần trên tổng**, không làm tròn từng item; không cắt đôi L0 (chạm `context_budget_tokens`, mặc định `4,000`, thì bỏ các sổ kế tiếp và đặt `continuity_truncated=true`) |
| **Giới hạn §7.4 (byte UTF-8)** | `task_goal` ở `L0` | `<= 200 B` UTF-8 | Cắt đúng ranh giới ký tự UTF-8 (không chẻ code point đa byte) kèm dấu đã cắt |
| **Giới hạn §7.4 (byte UTF-8)** | `task_goal` ở `L1` | `<= 2 KB` (`2,048 B`) | Đầy đủ nguyên văn ở `L2` |
| **Giới hạn §7.4 (byte UTF-8)** | Trích đoạn trả lời `constraint_changes` ở `L1` / report | `<= 512 B` UTF-8 | Cắt đúng ranh giới UTF-8 khi dựng từ ref lúc phục vụ; nguồn hết hạn -> `"expired"`, nguồn quarantine/tombstone -> `"redacted"`, giữ nguyên trạng thái `proposed` |
| **Giới hạn §7.4 (byte UTF-8)** | Độ dài `L0` mỗi item sổ | `<= 600 B` UTF-8 | Kiểm theo độ dài byte UTF-8 (không chỉ số ký tự Unicode trong JSON Schema) ngay tại đầu ra bước dựng `L0` của `prepare_task` ở `SP2-4`, gồm cả chuỗi đa byte (`600 B` đạt / `601 B` bị chặn) |
| **Giới hạn §7.4 (byte UTF-8)** | Tối đa `1` mục đơn lẻ trong sổ | `<= 2 KB` (`2,048 B`) | Vượt `2,048 B` -> `INVALID_INPUT`, giữ nguyên sổ |
| **Giới hạn §7.4 (byte UTF-8)** | Vùng đề xuất đổi ràng buộc đang chờ (`proposed`) | `<= 4 KB` (`4,096 B`) | Tính **riêng** ngoài trần `32 KB` của phần bắt buộc; đóng đề xuất qua `closed_changes` đưa sang L2 và giải phóng vùng chờ `4 KB` |
| **Giới hạn §7.4 (byte UTF-8)** | Kích thước tối đa **mỗi resource** ở `L1` | `<= 8 KB` (`8,192 B`) | **Cấm cắt bỏ phần bắt buộc:** chia thành nhiều resource `<= 8,192 B` trong cùng response `get_artifact`; chỉ mục không bắt buộc thiếu chỗ mới đánh dấu `incomplete_optional=true` |
| **Giới hạn §7.4 (byte UTF-8)** | Kích thước `1` patch ghi vào `submit_episode` | `<= 16 KB` (`16,384 B`) | Vượt `16,384 B` -> `INVALID_INPUT` |
| **Giới hạn §7.4 (byte UTF-8)** | Tổng ràng buộc đang hiệu lực (`user_constraints`) | `<= 16 KB` (`16,384 B`) | Ràng buộc chỉ-thêm, không rút gọn được; vượt `16,384 B` -> `INVALID_INPUT` (agent phải báo người dùng) |
| **Giới hạn §7.4 (byte UTF-8)** | Tổng phần bắt buộc của sổ | `<= 32 KB` (`32,768 B`) | Vượt `32,768 B` -> `INVALID_INPUT`, **ngoại trừ** patch dùng `supersedes`/`merges` có tổng phần bắt buộc **nhỏ hơn hoặc bằng** bản hiện hành (không tăng byte); miễn trừ này **chỉ** áp dụng cho trần `32 KB`, vẫn kiểm `2 KB` / item, `16 KB` / patch, `4 KB` vùng chờ, quyền giữ & fence |
| **Giới hạn §7.4 (byte UTF-8)** | Tổng nội dung `L2` | `<= 256 KB` (`262,144 B`) | Mới nhất tối đa `262,144 B`; lịch sử cũ hơn đọc qua `revision` tường minh |

### 4.1 Quy tắc ACK tách riêng `Event` và `CaptureGap` khi stream outbox có lỗ sequence (`SP2-2`, §7.1 / §5.4)
- **Bất biến:** Chỉ được xóa một bản ghi `Event` còn nằm ở outbox cục bộ khi có bằng chứng daemon đã `COMMIT` bền SQLite WAL **chính `Event` đó** trên đúng stream `(producer_stream, repo_id, checkout_id)`. Việc daemon ghi nhận hoặc đóng một gap **không bao giờ** là bằng chứng cho phép xóa một `Event` còn chờ trên đĩa outbox.
- **Phân định ai được đóng gap và vòng đời gap theo 2 nguồn riêng:**
  1. **`CaptureGap` do producer tự phát (`producer_gap`):** Chỉ producer/hook mới được tự tạo bản ghi loại `CaptureGap(seq)` (khi không thể xếp hàng `Event(seq)` cục bộ vì quá trần `2 s`, outbox chạm `100 MB` hoặc `ENOSPC`; lúc đó outbox **không** có payload `Event(seq)`). Khi daemon WAL-`COMMIT` bản ghi này, `seq` đi vào **`acked_producer_gap_sequences`** (KHÔNG đi vào `committed_event_sequences` hay đẩy `contiguous_event_acked_through`).
  2. **Gap quan sát ở daemon (`pending` -> `closed_gap`):** Khi daemon nhận lệch thứ tự (vd `{1, 3}` trước `2`), daemon **chỉ** được mở gap `2` ở trạng thái tạm chờ (`pending`), **cấm** đóng vĩnh viễn ngay chỉ vì thấy `3` đến trước. Daemon chỉ được chuyển gap `2` sang đóng bền trên daemon (`closed_gap_sequences` cho sổ gap / `get_health`) khi quá ngưỡng chờ hoặc đóng/thu hồi stream — trạng thái này **chỉ có hiệu lực quan sát ở daemon**, tuyệt đối không đi vào `committed_event_sequences`, không đẩy `contiguous_event_acked_through`, và không xóa được `Event 2` nếu producer vẫn còn giữ `Event 2`.
- **Ba trường ACK tách rời trả về cho mỗi stream:**
  - `committed_event_sequences`: tập (hoặc dải rời rạc) chính các `sequence` có bản ghi **`Event` thật** đã WAL-`COMMIT` (mới commit hoặc dedup trùng `(producer_stream, sequence)` của `Event` thật). Không bao giờ chứa bất kỳ gap nào (`pending` hay `closed_gap` hay `producer_gap`).
  - `contiguous_event_acked_through`: mốc nguyên lớn nhất $N \ge 0$ sao cho **mọi** sequence nguyên $1 \le s \le N$ của stream đều đã có `Event` thật nằm trong `committed_event_sequences`. **Cấm** nhảy qua lỗ chưa commit hoặc gán `contiguous_event_acked_through = high_seq`.
  - `acked_producer_gap_sequences`: tập các `sequence` ứng với bản ghi loại `CaptureGap` do producer gửi lên đã WAL-`COMMIT` ở daemon.
- **Quy tắc xóa ở `OutboxSpool` (khớp theo loại bản ghi trên đĩa):**
  - Bản ghi loại **`Event`** tại `seq`: chỉ xóa khi **`seq <= contiguous_event_acked_through` hoặc `seq in committed_event_sequences`**. Nếu stream mới commit `Event` `{1, 3}` trong khi `Event 2` còn chờ ở outbox thì `committed_event_sequences = {1, 3}`, `contiguous_event_acked_through = 1` (KHÔNG phải `3`), và kể cả nếu daemon đóng gap `2` vào `closed_gap_sequences` trước khi nhận được `2`, `OutboxSpool` **vẫn phải giữ nguyên `Event 2`** trên đĩa và gửi lại ở lần reconnect kế tiếp; khi daemon WAL-`COMMIT` `Event 2` (theo luật `Event` đến muộn không làm lùi watermark phiên), daemon trả `2` trong `committed_event_sequences` (và nâng `contiguous_event_acked_through` lên `3`), lúc đó `OutboxSpool` mới được xóa `Event 2`.
  - Bản ghi loại **`CaptureGap`** tại `seq`: chỉ xóa khi **`seq in acked_producer_gap_sequences`**. Tín hiệu ACK của `CaptureGap` không bao giờ xóa một `Event` cùng `seq` còn trên đĩa.
- **Oracle kiểm thử bắt buộc cho `SP2-2`:** Kiểm đủ 3 kịch bản: (1) giao trễ/đảo thứ tự có lỗ (`1`, `3` commit trước `2`) kèm `restart` cả `OutboxSpool` và daemon -> `2` còn nguyên trong outbox, `3` dedup đúng, `contiguous_event_acked_through` chỉ lên `3` sau khi chính `2` commit; (2) gap bền + `Event` giao muộn + `restart` -> daemon đưa `2` vào `closed_gap_sequences` (hiện qua `get_health`) trong khi `OutboxSpool` còn `Event 2`, xác minh `2` vắng trong `committed_event_sequences` và `Event 2` vẫn tồn tại qua `restart`, rồi giao muộn `Event 2` thành công -> `2 in committed_event_sequences` mới xóa `Event 2` (không lùi watermark); (3) `CaptureGap(seq)` do producer tự phát -> xóa đúng bản ghi `CaptureGap` qua `acked_producer_gap_sequences` và không cho phép xóa `Event` cùng `seq`.

### 4.2 Tách mốc rời `active` và mốc tạo checkpoint `in_progress_unknown` (`SP2-3`/`SP2-4`, §7.3–§7.4)
- **Trạng thái phiên xác định tại mọi thời điểm (không có vùng chưa định nghĩa trên `(300 s, 1,800 s]`):**
  - Nếu phiên đã có sự kiện kết thúc hợp lệ (`ended`) và chưa có `session_resumed` sau mốc đó -> **`ended`** (`acknowledge_active` không bắt buộc). `Event` thường đến sau `ended` chỉ gộp vào phần quan sát và **không** đổi trạng thái; chỉ **`session_resumed`** chuyển lại **`active`** và cập nhật `last_event_at`.
  - Nếu phiên chưa `ended` với `elapsed = now - last_event_at`:
    - `0 <= elapsed <= 300 s` (`<= 5 phút`): **`active`** — cảnh báo `active` trên L0 và tiếp quản bắt buộc `acknowledge_active=true`.
    - **`elapsed > 300 s`** (ngay sau `300 s`, tức phút thứ 6 trở đi qua mọi mốc `<= 1,800 s` và `> 1,800 s`): **`in_progress_unknown`** — tắt cảnh báo `active` trên L0 và tiếp quản **không** đòi `acknowledge_active`.
- **Ngưỡng tạo bản ghi checkpoint `in_progress_unknown` (đồng hồ riêng ở worker §7.3):**
  - Khoảng `(300 s, 1,800 s]`: phiên đã ở trạng thái `in_progress_unknown` cho quyết định takeover, nhưng worker **chưa** tự ghi bản checkpoint `in_progress_unknown`.
  - Khi **`elapsed > 1,800 s`** (`> 30 phút`, hoặc worker phát hiện tiến trình harness crash không có end event): tạo bản **checkpoint** `in_progress_unknown` (không coi là `done`/`failed`).
- **Oracle `FakeClock` bắt buộc cho `SP2-3`/`SP2-4`:** Kiểm đủ các mốc biên: `t = 300 s` (`active`, đòi `acknowledge_active`), ngay sau `300 s` (vd `301 s`: `in_progress_unknown`, không đòi `acknowledge_active`, chưa tạo checkpoint), `t = 1,800 s` (`in_progress_unknown`, chưa tạo checkpoint), ngay sau `1,800 s` (vd `1,801 s`: tạo checkpoint `in_progress_unknown`), cùng chuyển tiếp khi nhận `Event` mới hoặc `session_resumed` sau `ended`.

---

## 5. Phối hợp Schema `(store=6, policy=5)` & Danh mục 6 Crashpoint SP2

### 5.1 Thứ tự phụ thuộc với SP1 Đợt 3 (`I3`)
- Nền hiện hành ở nhánh này (`SP2-0`, `SP2-1`) là `(store=4, policy=3)` trên transport I2 (`035a4cd`).
- **Ranh giới dừng SP2-1 (Owner Decision A2):** `SP2-1` khóa toàn bộ hợp đồng `schemas/mcp-tools-v2.json`, handshake `schema_digest` hai chiều, khung route/auth `POST /v2/capture/events`, tách nhánh `prepare_task` (`discover` vs `work`) và `(artifact_id, revision_epoch, revision)` trên `ReadAckInput` / `ArtifactSendAttempt` **mà không nâng** `store v4`/`policy v3`.
- Trước khi mở `SP2-2..SP2-4`, chờ nhánh `SP1 Đợt 3` (`thuc_hien_ke_hoach_sp1_dot3`) hợp nhất:
  - `(store=5, policy=4)` (`min_reader_version` = `5` và `4`);
  - `store/restore_epoch.json` + cơ chế tăng `restore_epoch` khi `restore_store`;
  - `PolicyRestoreStageHook` trên `restore_policy` (để `SP2-3` bảo toàn `session_hmac_key` và `session_ref_bindings` qua mọi lần restore `policy/`);
  - `storage/_policy_approvals.py` + `harness_layer2_state` (để `SP2-5` nối `NativeHostReceipt`);
  - `bootstrap_templates.py` (để cài rule Lớp 1–2 và §7.4).
- Từ nền `(5, 4)` của I3, `SP2-2..SP2-4` nâng append-only lên **`(store=6, policy=5)`** với `min_reader_version` = `6` và `5`.

### 5.2 Sáu điểm cắt crash SP2 đã khóa tên (`SP2-2..SP2-4`)

| Task triển khai | Tên crashpoint chính thức (dành cho `SP2-2..SP2-4`) | Ranh giới bền vững & bất biến phục hồi |
| --- | --- | --- |
| **SP2-2** | `capture.outbox.after_write_before_fsync` | Mục ghi dở trước `fsync` trong outbox cục bộ bị loại bỏ an toàn khi đọc lại; mục đã `fsync` trước đó vẫn nguyên vẹn |
| **SP2-2** | `capture.daemon.after_commit_before_ack` | Batch event đã commit WAL trên `brain.db` trước khi trả ACK -> retry cùng `(producer_stream, sequence)` dedup nguyên vẹn, trả ACK mới; `outbox` chỉ xóa `Event` qua `committed_event_sequences` / `contiguous_event_acked_through` và chỉ xóa `CaptureGap` của producer qua `acked_producer_gap_sequences` (cấm xóa `Event` dựa vào `closed_gap_sequences` hay lỗ sequence chưa commit) |
| **SP2-3** | `session.after_policy_bind_before_store_project` | Đã ghi bền `(session_ref, principal_id)` vào `policy.db` v5 trước khi chiếu vào `sessions` của `brain.db` v6 -> lần đọc/ghi kế tiếp đối chiếu và reconcile đúng 1 lần theo policy store |
| **SP2-3** | `continuity.worker.before_owner_commit` | Worker dừng/chết trước pha commit 3-phase trên `OwnerLoop` -> không đè `agent_ref`, không tiến watermark sai; lease cũ hết/thu hồi sang epoch mới thì job phục hồi an toàn |
| **SP2-4** | `handoff.after_commit_before_ack` | Patch/takeover handoff + idempotency đã commit bền trước khi trả HTTP response -> retry cùng `idempotency_key` đọc idempotency **trước** `base_revision`/`fence`, dựng lại đúng kết quả đã commit kèm `writer_status` tính lúc trả |
| **SP2-4** | `artifact_send.after_pending_before_flush` | `ArtifactSendAttempt(PENDING)` đã commit trước khi ghi bytes HTTP -> khởi động lại gọi `recover_pending_attempts()` chuyển `PENDING -> UNKNOWN`, không cấp nhầm `SERVED_ONLY` và chặn `resume_ref` dùng receipt chưa xác minh |

> **Cảnh báo niêm phong SP2-0 / SP2-1:** Tệp `docs/design/sp1-crash-table.md` phải giữ nguyên đúng **29 dòng I1 + I2** trong suốt `SP2-0` và `SP2-1` (kiểm tra tự động bởi `tests/storage/test_crash_matrix.py::test_every_known_crashpoint_has_a_case_and_a_doc_row`). Chỉ bổ sung 6 dòng trên vào `sp1-crash-table.md` và `KNOWN_CRASHPOINTS` cùng lúc triển khai từng task `SP2-2..SP2-4` kèm reseal độc lập.
