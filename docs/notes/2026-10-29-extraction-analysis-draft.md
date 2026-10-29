# Kế hoạch trích xuất Super-brain2

Trạng thái: **bản nháp viết sớm, KHÔNG có hiệu lực.** File này được viết trước khi có spec được duyệt,
tức là đi sai thứ tự quy trình superpowers (brainstorming → spec → writing-plans). Nó chỉ được giữ
làm số liệu tham khảo (đồ thị import, số dòng). Kế hoạch thật sẽ được viết lại bằng writing-plans sau khi spec được duyệt.

## 1. Nguồn và mục tiêu

- **Nguồn:** `D:\ensemble-agents\Super-brain`, commit `f83271d` (nhánh `master`).
  Working tree của repo cũ đang có thay đổi chưa commit. Kế hoạch này **chỉ dựa trên
  commit `f83271d`**; các thay đổi chưa commit không được tính.
- **Repo cũ** đóng băng, chỉ dùng làm tài liệu tham chiếu. Không xóa, không phát triển song song.
- **Mục tiêu:** chứng minh MVP của roadmap V5 (`docs/planning/v5-roadmap.md`) trên một
  codebase nhỏ, phân tầng đúng và test chạy xong được trên máy dev.
- **Cách làm:** trích xuất có kiểm soát. Mỗi module được chuyển sang cùng với test của nó,
  sau khi đã cắt các phụ thuộc ngược. Không copy cả mảng, không viết lại từ đầu.

## 2. Vì sao không copy nguyên được (số đo trên `f83271d`)

Đồ thị import được dựng bằng AST, **tính cả import nằm trong hàm**: 171 module, 61.377 dòng.

| Điểm bắt đầu | Chỉ import cấp module | Tính cả import trong hàm |
|---|---|---|
| `mcp.stdio_server` | 13 module, 2.425 dòng (3%) | 138 module, 49.816 dòng (**81%**) |
| `storage.ledger` | 8 module, 2.034 dòng (3%) | 137 module, 49.651 dòng (**80%**) |
| `observation.queue` | 12 module, 2.545 dòng (4%) | 137 module, 49.651 dòng (**80%**) |
| `core.types` | 4 module, 254 dòng | 4 module, 254 dòng |

Kết luận: phần lõi thực chất chỉ vài nghìn dòng. Các import nằm trong hàm, trỏ ngược lên tầng trên,
là thứ dính nó vào 80% còn lại. Danh sách cụ thể nằm ở mục 5.

## 3. Kiến trúc đích

```
cli  →  mcp (transport: stdio, http, daemon)
          ↓
     application (các use case của 8 tool)
          ↓
  domain: observation · memory · knowledge · continuity · context · routing · workforce · decisions(rules) · jobs
          ↓
     storage (ledger, CAS, evidence, ownership)
          ↓
     core (types, validation, auth, config, revisions)
```

Quy tắc: chỉ được import **xuống dưới**. Các package cùng tầng domain chỉ được import nhau
theo một danh sách cho phép, viết rõ trong cấu hình.

Hai chỗ trùng lặp mà audit V5 đã chỉ ra sẽ được gộp ngay khi chuyển sang:
- `core/service.py` và `mcp/service.py`: tách thành các use case trong `application`; `mcp` chỉ làm transport.
- `capture/` và `observation/`: chỉ giữ `observation/` (một event contract duy nhất).

## 4. Hàng rào tự động (Giai đoạn 0, làm trước khi chuyển code)

Mỗi hàng rào là một check chạy trong CI và chạy được tại máy. Không dựa vào kỷ luật.

| # | Hàng rào | Cách kiểm tra |
|---|---|---|
| G-1 | Phân tầng | `import-linter` với contract `layers` theo mục 3 |
| G-2 | Không có import ngược nằm trong hàm | Test AST quét **mọi** import (cả trong hàm, ngoài `TYPE_CHECKING`) rồi đối chiếu với G-1. Đây là chỗ `check_architecture` cũ bị lọt. |
| G-3 | Không có vòng phụ thuộc giữa package | Cũng test AST trên, đồ thị package phải là DAG |
| G-4 | Ngân sách thời gian test | Toàn bộ suite < 5 phút trên máy dev; test chậm gắn marker `slow` và chạy riêng |
| G-5 | Kiểu dữ liệu | `mypy --strict` cho toàn package ngay từ đầu (repo cũ có khoảng 6.000 lỗi) |
| G-6 | Lint | `ruff` cho cả `src` và `tests` |
| G-7 | Không nuốt lỗi | Ruff `BLE001`/`S110`, cấm `except Exception: pass` |
| G-8 | Kích thước | Cảnh báo khi một file > 600 dòng (`mcp/service.py` cũ có 1.876 dòng) |

## 5. Phạm vi và thứ tự chuyển

Số dòng là dòng vật lý trong file ở `f83271d`, **trước khi cắt**. Giai đoạn 1 và 2 cộng lại khoảng 27k dòng,
**lớn hơn nhiều so với mức 12–16k** đã ước lượng thô ở phiên trước. Vì thế phạm vi được chia thành ba giai đoạn,
và Mốc 1 chỉ cần Giai đoạn 1.

Nguyên tắc phân loại: phần nào có trong `docs/plan` đều được mang sang, chỉ khác nhau ở giai đoạn.
Phần không có trong `docs/plan` cần chủ dự án xác nhận (D-7) trước khi mang sang.

### Giai đoạn 1: lõi đủ để có bằng chứng native đầu tiên (~21k dòng trước khi cắt, chưa tính phần gate)

| Package | Module chuyển sang | Dòng | Phụ thuộc ngược phải cắt (`L` = import trong hàm) |
|---|---|---|---|
| core | `types`, `validation`, `auth`, `revisions`, `client_registration` | 567 | – |
| core | `config` | 391 | `providers.base` (L:167) |
| core | `health` | 263 | `operations.build_identity` (L:12) |
| core | `service` → gộp vào `application` | 723 | `routing.catalog`; `core.approval` (L), `core.owner_confirmation` (L), `capture.observations` (L:64), `jobs.queue` (L:703) |
| storage | `sqlite_connections`, `schema`, `ownership` | 264 | – |
| storage | `ledger` | 1.063 | `operations.release_evidence` (L:296), `learning.evaluation` (L:941) |
| storage | `artifacts` | 579 | `learning.worker` (L:161), `capture.importer` (L:266) |
| storage | `evidence` | 848 | `observation.privacy` (L:259): chuyển hàm scan privacy xuống `core` |
| storage | `outbox` | 123 | `jobs.dispatcher` (L:55) |
| storage | `schema_v3`…`schema_v6` | 840 | Phụ thuộc quyết định D-2 |
| observation | `schema`, `privacy`, `queue`, `processor` | 1.297 | `processor` → `decisions.engine`: tiêm qua interface |
| memory | `models`, `repository`, `retain`, `recall`, `reflect` | 3.155 | – |
| knowledge | `models`, `policy`, `repository`, `transitions`, `verification` | ~2.000 | `repository` → `context.retrieval` (L:337) |
| learning | chỉ `candidate_evaluator` (đường candidate → verified) | 372 | – (chuyển vào `knowledge` hoặc `memory`) |
| decisions | `primitives`, `engine` (chỉ backend rules) | 783 | Không mang Jev/`providers` |
| application | `brain`, `runtime` | 398 | `operations.diagnostics` (L:68), `mcp.service` (L:229) |
| mcp | `auth`, `gateway`, `server`, `stdio_server`, `http`, `daemon`, `daemon_entry`, `runtime`, `catalog` | ~990 | `runtime` → `cli.config`; `daemon` → `cli.config` (L:187) |
| mcp | `service`: tách theo tool, đưa logic xuống `application` | 1.876 | `learning.candidate_evaluator`, `learning.evolution_worker`, `capture.skill_session` (L), `capture.observations` (L), cùng toàn bộ phần context/jobs/workforce |
| cli | `config`, `entrypoint`, `__main__` | ~56 | – |
| capture | Đường hook thụ động: `native_session`, `native_envelopes`, `native_observation`, `sanitization`, `outbox` | ~2.000 | Cần đo lại; `skill_session`, `observations` gộp vào `observation` (một event contract) |
| operations | `native_conformance` (nơi định nghĩa `NativeHostReceipt`) | 948 | Cần đo lại; Mốc 1 phụ thuộc trực tiếp |
| core | Phần **Conflict Review Gate** trong `approval`/`owner_confirmation` | cần xác minh | Hai file này 2.545 dòng; chỉ lấy phần thực hiện gate trong thiết kế (07 §2, 17), không lấy nguyên |
| jobs | `queue` (hàng đợi nền), `dispatcher` | 2.529 | `queue` có 7 import trong hàm sang `learning`/`providers` phải cắt |

Đủ 8 tool trong Giai đoạn 1. `request_improvement` làm đúng theo thiết kế (05 §2.6): đưa việc phản tư
`memory.reflect` vào hàng đợi nền; `get_job` đọc trạng thái hàng đợi đó.

**Mốc 1 (tiêu chí hoàn thành Giai đoạn 1):** "port xong" chưa phải là xong. Mốc 1 đạt khi:
1. Claude Code và Codex kết nối MCP thật tới server trên máy này, mỗi bên có danh tính riêng.
2. Có `NativeHostReceipt` đầu tiên do host thật tạo ra (không phải `sdk_fixture`).
3. Chạy hết một vòng: harness A ghi bài học, kiểm chứng bằng test thật để thành `verified`,
   harness B nhận đúng bài học đó qua `prepare_task` trong cùng scope.
4. Toàn bộ suite chạy xong dưới 5 phút; G-1 đến G-8 đều PASS.

### Giai đoạn 2: trải nghiệm đầy đủ của MVP (~6k dòng)

| Package | Dòng | Phụ thuộc ngược phải cắt |
|---|---|---|
| continuity (5 module) | 1.221 | – |
| routing: `catalog`, `router`, `utility` | 789 | `router` → `mcp.catalog` (chuyển catalog xuống); `catalog` → `learning.draft_validation` (L:23); `utility` → `learning.evaluation` (L:180) |
| workforce: `registry`, `matcher`, `gates` + 8 persona | 904 | `gates` → `decisions.engine` |
| context (L0/L1/L2, 11 module) | 3.333 | `indexer` → `jobs.dispatcher`; `index_store` → `jobs.dispatcher` (L:123); `service` → `application.brain` |

### Giai đoạn 3: các phần còn lại trong thiết kế

| Phần | Căn cứ thiết kế | Module nguồn |
|---|---|---|
| Ba harness còn lại: Antigravity, OpenCode, Cursor | 00 §4, 08 | `cli.setup`, `cli.harness_rules`, `operations.harness_onboarding` |
| System 1 / Jev (tùy chọn, rules vẫn là mặc định) | MASTER-PLAN §2.1, 02, V5 Phase 8 | `decisions.backend`, `decisions.service`, `providers.base`/`registry` |
| Benchmark (P95 < 35ms trên 10k bản ghi, Precision@3 ≥ 90%) | 09 | `operations.performance`, `operations.retrieval_quality` |
| Đóng gói: wheel, Docker, Smithery | 10 Giai đoạn 8, 13 | `operations.release*` (chỉ phần build) |
| 217 agency skill | 00 §4, 03 §2.5 (V5 ghi là tùy chọn) | `packs/agency_skills` |
| Retention, backup | 04 | `storage.retention`, `storage.backup` |

### Không có trong `docs/plan`: cần chủ dự án xác nhận (D-7)

Các phần dưới đây không tìm thấy trong 20 tài liệu `docs/plan`. Có thể chúng đến từ chương trình nâng cấp V5
hoặc các quyết định sau này. Chưa mang sang cho tới khi chủ dự án xác nhận:

- 4 harness ứng viên: gemini, copilot, openclaw, hermes. Thiết kế chỉ nêu Codex, Claude Code, Antigravity, OpenCode, Cursor.
- `evolution` (2.365 dòng) và phần lớn `learning` (agenda, induction, practice, campaign, owned fixtures…; 5.868 dòng).
  Từ khóa "evolution" không xuất hiện trong `docs/plan`.
- `providers.accounting`, `jobs.budget`, `operations.utility_*`, `operations.test_evidence`, `operations.release_evidence`.
- `storage.legacy_cognitive_import`, `storage.migrations`, `storage.reconciliation`: chỉ dùng để chuyển dữ liệu cũ (tùy D-2).

## 6. Quy trình chuyển một module

1. Chép module và các test trực tiếp của nó từ `f83271d` (ghi rõ đường dẫn nguồn trong commit message).
2. Chạy test **trước khi sửa** để có baseline.
3. Cắt từng phụ thuộc ngược: tiêm qua interface/callback, chuyển code xuống tầng dưới, hoặc xóa nhánh thuộc phạm vi bị loại.
4. Test phải xanh trở lại mà **không** sửa assertion. Nếu buộc phải đổi assertion vì phạm vi thay đổi,
   ghi lý do từng test vào `docs/MIGRATION_LOG.md`.
5. G-1 đến G-8 PASS rồi mới commit. Mỗi commit chỉ chứa một module hoặc một nhóm nhỏ.

Test cũ được chia theo thư mục. Riêng `tests/remediation/` (263 test) phải được phân loại theo module
mà từng test nhắm tới; test chỉ nhắm vào phần bị loại thì không mang sang.

## 7. Quyết định cần chủ dự án chốt

| # | Câu hỏi | Lựa chọn | Đề xuất |
|---|---|---|---|
| D-1 | Tên package Python | (a) giữ `ensemble_brain`; (b) tên mới | (a): dễ đối chiếu với repo cũ |
| D-2 | Dữ liệu `brain.db` cũ | (a) đọc được (mang chuỗi schema v3–v6 và `migrations`); (b) schema mới gộp làm một, viết công cụ import riêng sau | (b): bỏ được 840+ dòng schema lịch sử; dữ liệu cũ vẫn nằm nguyên ở repo cũ |
| D-3 | Việc dang dở ở repo cũ (B1, A1–A4…) | (a) dừng; (b) làm tiếp song song | (a): theo nguyên tắc không phát triển hai nơi |
| D-4 | `request_improvement` làm theo thiết kế 05 §2.6 (phản tư nền) hay theo bản cũ (evolution/learning campaign) | (a) theo thiết kế; (b) theo bản cũ | (a): đúng tài liệu, nhỏ hơn nhiều |
| D-5 | Git | `git init` tại `Super-brain2`, nhánh `main`, chưa có remote | Làm khi bắt đầu Giai đoạn 0 |
| D-6 | Python | Repo cũ ghi `>=3.11`; máy hiện có Python 3.14 | Giữ `>=3.11`, CI chạy 3.11 và 3.14 |
| D-7 | Các phần không có trong `docs/plan` (mục 5) | Giữ từng phần / bỏ / để sau | Để sau, trừ khi bạn nói phần nào là ý định thiết kế |

## 8. Rủi ro

- **Tốc độ sinh code lặp lại tình trạng cũ.** Biện pháp: hàng rào ở mục 4 chặn tự động,
  và mỗi commit chỉ chứa một module.
- **Cắt phụ thuộc làm mất một bản sửa đã trả giá đắt** (lỗi riêng Windows, transaction nguyên tử,
  quarantine, cô lập tenant). Biện pháp: test đi kèm module là điều kiện để chuyển; không xóa test khi cắt.
- **Ước tính kích thước sai.** Số dòng ở mục 5 là trước khi cắt. Sau mỗi giai đoạn sẽ đo lại và cập nhật tài liệu này.
- **MCP `ensemble_super_brain` chưa kết nối được** với Claude Code (đúng cả ở phiên này).
  Mốc 1 phụ thuộc trực tiếp vào việc này.
