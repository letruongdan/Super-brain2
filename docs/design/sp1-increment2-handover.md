# Bàn giao SP1 đợt 2: kernel daemon, MCP shim và đường native

Ngày cập nhật: 2026-11-12. Tài liệu này là bản bàn giao SP1 đợt 2 trên nhánh `codex/sp1-i2-task9` (tách từ mốc Task 8 `3527a99803059cb06b5120cd18edea2e1a828857`).

Theo quy tắc tuyên bố của [spec rev22 mục 17.2–17.5](../superpowers/specs/2026-10-30-super-brain2-system-design.md#172-các-gate): chỉ được tuyên bố đóng toàn bộ SP1 đợt 2 khi **toàn bộ** điều kiện sau cùng đạt trên đúng commit `HEAD` cuối có working tree sạch:
1. Gate mặc định (`scripts/gate.py`, F4 dưới 300 s, 0 fail/error/XPASS, JUnit đầy đủ, `ruff`, strict `mypy`, `import-linter`) đạt trên đủ ma trận OS × Python áp dụng.
2. Benchmark (`tests/integration/test_kernel_performance.py`) đạt ngưỡng trên các ô đích.
3. Gate native có `NativeConnectionProbe` hợp lệ (`kind="native"`, `status="passed"`) cho từng host đã chọn trên cùng kho/epoch/instance với phê duyệt D8 của owner.
4. Review độc lập toàn nhánh xác nhận đúng commit pin, test seal, ledger và inventory cuối.

Tính đến thời điểm commit tài liệu này:
- Phần code, unit/integration/architecture/crash/wheel tests của Task 1–9 và checklist vận hành đã **triển khai trên nhánh** (`implemented` về mặt mã nguồn chưa đóng review).
- Các ô gate **Linux** và **macOS** (Python 3.11 và 3.14): **`not_run`**.
- Các phép thử host thật theo D8 (**Codex desktop app** và **Claude Code**): **`not_run`** (chờ phê duyệt D8 tách biệt sau khi pin F4/perf trên commit cuối).
- **Lớp 2** (spec §11.3): **`unknown`** (thuộc SP2 / SP7).
- **Review độc lập cuối cho Task 9**: **`closure pending`**.

---

## 1. Phạm vi SP1 đợt 2 và phần chuyển giao

### Đã hoàn thiện trong kernel SP1 đợt 2

- **Hợp đồng wire và schema:** [schemas/mcp-tools-v2.json](../../schemas/mcp-tools-v2.json) (`sha256:4cf906a67cfde9edf636bac5e2fa3667653d895fdc5c4c9b9e2648f000857dfc`), canonical JSON, ID validation và typed `BrainError`.
- **Transport D2 (TLS loopback + state machine 2 bước):** bind `127.0.0.1:<ephemeral_port>`, private CA và leaf cert theo từng kho (`cryptography`), client pin leaf + check SAN/thời hạn, `GET /v2/identity` không mang bearer trước khi gửi `POST /v2/tools/call` có bearer trên cùng socket, deadline monotonic 2 s TLS + 2 s tool (`1.5 s` daemon + phần dự phòng).
- **Vận hành daemon owner và CLI/MCP shim (D1, D3):** `brain serve --config <ABS>`, `brain migrate --offline --config <ABS>`, `brain-mcp` và `brain mcp --profile <ABS>` (stdio MCP `2025-06-18`) thực thi `single-checkout-owner-profile-v1`, xác minh raw path, physical identity và launch CWD, tiêm `workspace_hint` và `selected_scope={repo_id, checkout_id}` trước HMAC digest.
- **Policy v3 & Store v4:** principal `(owner_id, harness_id, machine_id)`, bearer `<credential_uuidv7>.<secret>` lưu hash SHA-256 + constant-time verify, `AuthGate` nguyên tử (generation + trust generation + grant stamp), registry workspace trên policy và reconcile theo intent ID vào kho, HMAC-SHA256 `idempotency` với replay/conflict/lost-response recovery, mô hình `Delivery`/`ServedReceipt`/`ReadAck`, `LineageRef`/`LineageSet`/`LineagedField`, tương thích S1=A (`snapshot_status`), và `Job`/`JobService`/`ProviderInvocation` với lease/attempt/cancel/settlement.
- **Privacy filter & ma trận crash:** 10 nhóm lọc secret/PII/entropy/`<private>`/path cấm trước canonical safe payload; 29 dòng crashpoint trong [sp1-crash-table.md](sp1-crash-table.md) (19 I1 + 10 kernel Task 8) được kiểm parity tên/doc/case bằng AST/matrix tests.
- **Contract nhận diện kết nối & quan sát owner Task 9:** `tests/support/inc2_native.py` (`sp1-i2-native-connection-v1`), `tests/support/inc2_native_owner.py` (chạy wheel dưới `python -I`, nối `read_admitted_tool_command`, `LoopbackServer._conn_worker`, `LoopbackServer._release_owner_reply`, `write_json_response`, `AuthGate.authorize_stamp` / `AuthGrantStamp` == `AuthGate.current()` và lookup PID socket loopback OS qua `GetExtendedTcpTable` trên Win32 hoặc `/proc` / `lsof` trên Linux/macOS), 14 contract/wheel tests trong `tests/integration/test_kernel_native_receipt_contract.py`, và [sp1-increment2-native-checklist.md](sp1-increment2-native-checklist.md).

### Không thuộc SP1 đợt 2 (hoãn đúng theo D1–D8 và spec §20)

- **Production tools ngoài `get_health(deep=false)` và đọc `get_job`:** `prepare_task`, `get_artifact`, `record_outcome`, `submit_episode`, `get_health(deep=true)`, `doctor`, `apply` trả `capability_unavailable` ở daemon sản phẩm cho tới các đợt/SP tương ứng; chỉ đường composition fixture (`FixtureKernelDomain`) được dùng để nghiệm thu atomic persistence trong test.
- **Bootstrap sản phẩm (`brain init`, `brain credential revoke`, signer M1, WebAuthn/SSH FIDO, UI duyệt & `ApplyJournal`):** thuộc SP1 đợt 3–4.
- **Lớp 2 (`§11.3`), hook/capture session, handoff continuity và egress Jev thật:** thuộc SP2–SP5; đánh giá hiệu quả thuộc SP6.
- **Host bổ sung (`Antigravity` R1, `OpenCode`, `Cursor`):** ngoài tập host được chọn ở T0 (thuộc SP7 / quyết định riêng của owner).

---

## 2. Cơ chế pin source, khác biệt spec và provenance artifact

1. **Nhánh và base pin:** nhánh `codex/sp1-i2-task9` tách từ commit Task 8 `3527a99803059cb06b5120cd18edea2e1a828857`. Lưu ý checkout `sp1-increment2` ở `6a3a4d2` giữ bản spec rev22 trước phần giải thích mẫu đường dẫn ở §14.2, trong khi `3527a99` (và nhánh Task 9) giữ bản có `§14.2` tại [2026-10-30-super-brain2-system-design.md](../superpowers/specs/2026-10-30-super-brain2-system-design.md) (`sha256:a468a917f775d2fb8a00b519f5e5ed31d3273ca0b63ad7f8115b6678065783b7`). Toàn bộ điều khoản native, D2–D8 và T0 giống nhau.
2. **Pin cấu hình bất biến kèm trong commit này:**
   - `pyproject.toml`: `sha256:4f54cc75470b21bb44257e9f434d4f043c8ad979c08c0a804eb956fece8a87a3`
   - `uv.lock`: `sha256:a17fae4c237aad0f0b13460a8672cf8b193fb1004316b98149c10532fdc399cb`
   - `schemas/mcp-tools-v2.json`: `sha256:4cf906a67cfde9edf636bac5e2fa3667653d895fdc5c4c9b9e2648f000857dfc`
   - `docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md`: `sha256:1fa6cb104918866ba08ef1a52153e05635214f45d90e920ddb43b6bc0477969b`
   - `docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md`: `sha256:6761e5c2a4d45964033278e4b67abf67bb02b610e8e34b8279e34ad8e0ec2623`
3. **Quy tắc pin không vòng lặp (Plan T9-P01):** tài liệu bàn giao được commit **trước** khi chạy `scripts/gate.py` và benchmark cuối. Do đó mọi receipt của Task 9 được lưu ngoài tracked Git dưới `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/` (`test-seal-final.json`, `ledger.md`, `final-<short_sha>/`), và **chỉ có hiệu lực** khi `receipt.start.commit == receipt.end.commit == git rev-parse HEAD`, `tree_clean == true`, và digest seal test khớp đúng commit đó. Bất kỳ chỉnh sửa file tracked nào đều làm các receipt cũ hết hiệu lực kiểm chứng.
4. **Provenance build wheel:**
   - Benchmark `tests/integration/test_kernel_performance.py` tự build một wheel sạch từ commit được pin vào temp riêng và ghi `wheel_digest` trong receipt `perf-*.json`.
   - Mọi phép thử native D8 về sau phải ghi rõ `shim_build_digest` của đúng file `.whl` đã cài vào môi trường host (gắn cùng `source_commit`, `uv.lock` và `schema_sha256`), không ghép chéo digest wheel của benchmark sang lượt native.

---

## 3. Baseline Task 8 (`3527a99`) và ma trận Gate / OS của Task 9

### Baseline đã quan sát tại pin Task 8 (`3527a99803059cb06b5120cd18edea2e1a828857`)

*Chỉ dùng làm mốc đối chiếu; không thay thế receipt của commit Task 9.*

| Ô môi trường | Gate F4 (`receipt.json`) | Benchmark (`perf-*.json`) | Nơi lưu trong ledger |
|---|---|---|---|
| Native Windows (`win32`, configured `C:\Users\letru\sb2-trusted-local`), Python `3.11.9` | `accepted=true`, 2.165 ID (`2.120 pass / 45 skip / 0 fail / 0 error / 0 xpass`), `188.546 s` (< 300 s) | `accepted=true`, warm `prepare` p95 `178.0051 ms`, privacy 1 MiB p95 `70.1561 ms` (ratio `0.9788`), cold `brain mcp` p95 `432.7608 ms`, `brain-mcp` p95 `383.6546 ms` | `task-8/final-3527a99/gate-3.11.9/` & `perf-3.11.9/` |
| Native Windows (`win32`, configured `C:\Users\letru\sb2-trusted-local`), Python `3.14.3` | `accepted=true`, 2.165 ID (`2.120 pass / 45 skip / 0 fail / 0 error / 0 xpass`), `189.961 s` (< 300 s) | `accepted=true`, warm `prepare` p95 `44.102 ms`, privacy 1 MiB p95 `73.0047 ms` (ratio `1.0137`), cold `brain mcp` p95 `525.9607 ms`, `brain-mcp` p95 `450.287 ms` | `task-8/final-3527a99/gate-3.14.3/` & `perf-3.14.3/` |

### Ma trận Gate & OS cho commit cuối Task 9 (`codex/sp1-i2-task9`)

Môi trường Windows sử dụng `LOCALAPPDATA=C:\Users\letru\sb2-trusted-local` và `TEMP`/`TMP=C:\Users\letru\sb2-trusted-local\gate-temp` vì `AppData\Local` mặc định của session Codex mang SID takeover rights; guard quyền sản phẩm được giữ nguyên trạng không nới lỏng.

| OS | CPython | Trạng thái F4 & Benchmark trên pin cuối T9 | Đường dẫn kiểm chứng trong ledger | Điều kiện đóng ô |
|---|---|---|---|---|
| Native Windows 11 (`win32`, configured trusted root) | `3.11.9` | **Sắp chạy tuần tự sau commit này** *(chưa đóng tới khi đọc `accepted=true` trên `HEAD`)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-<head>/gate-3.11.9/` & `perf-3.11.9/` | Chạy `scripts/gate.py --python 3.11.9` (< 300 s, 0 fail/error/XPASS, JUnit parity, seal khớp trước/sau) và `test_kernel_performance` |
| Native Windows 11 (`win32`, configured trusted root) | `3.14.3` | **Sắp chạy tuần tự sau commit này** *(chưa đóng tới khi đọc `accepted=true` trên `HEAD`)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-<head>/gate-3.14.3/` & `perf-3.14.3/` | Chạy `scripts/gate.py --python 3.14.3` (< 300 s, 0 fail/error/XPASS, JUnit parity, seal khớp trước/sau) và `test_kernel_performance` |
| Linux / ext4 | `3.11` | `not_run` | *(trống; WSL `final-r13-linux` thuộc I1 `e09d8a0`, không thay I2)* | Chạy `scripts/gate.py` và `test_kernel_performance` trên clone Linux sạch ở đúng commit pin cuối T9 |
| Linux / ext4 | `3.14` | `not_run` | *(trống)* | Như trên cho CPython 3.14 |
| macOS | `3.11` | `not_run` | *(trống; mypy platform override không thay runtime macOS)* | Chạy `scripts/gate.py` (`F_FULLFSYNC`, permissions POSIX) và `test_kernel_performance` trên macOS ở đúng commit pin cuối T9 |
| macOS | `3.14` | `not_run` | *(trống)* | Như trên cho CPython 3.14 |

---

## 4. Verdict Q4 · Kết nối native theo từng host

Quy ước theo §17.3 / §17.5: 14 bài kiểm trong `tests/integration/test_kernel_native_receipt_contract.py` là bằng chứng **contract và fixture qua wheel cài đặt thật** (`kind="fixture"`), hoàn toàn không thay thế `NativeHostReceipt` từ tiến trình host thật.

| Host (Q4) | Trạng thái T0 lịch sử | Verdict native T9 hiện tại | Ghi chú & điều kiện |
|---|---|---|---|
| **Codex desktop app** (`26.1029.7803.0` / `codex.exe 0.166.0-alpha.6`) | `passed` (`t0r1`/`t0r2`) | `not_run` | Đã có checklist cô lập & verifier; chờ phê duyệt D8 của owner và chạy trên pin cuối sau khi F4/perf Windows pass |
| **Claude Code** (`2.1.317`) | `passed` (`t0r3`) | `not_run` | Đã có checklist cô lập & verifier; chờ phê duyệt D8 + quota và chạy trên pin cuối sau khi F4/perf Windows pass |
| **Antigravity Desktop** (`1.23.2` / `agy 1.5.1`) | `failed_r1_unsupported_in_i2` | `not_run` *(ngoài tập I2)* | Đã loại khỏi tập hỗ trợ I2 theo Owner Ruling `2026-11-05T19:05:18+07:00`; giữ nguyên lịch sử failure `t0r2` cho SP7 |
| **OpenCode** (`2.2.0`) | `not_run` | `not_run` | Chưa được chọn cho I2; cần quyết định phạm vi và D8 |
| **Cursor** | `not_run` | `not_run` | Chưa cài đặt / chưa được chọn cho I2; cần quyết định phạm vi và D8 |

---

## 5. Đối chiếu §20, bảng crash và giới hạn phải giữ khi đóng

- **Bảng crash 29 dòng:** [sp1-crash-table.md](sp1-crash-table.md) (19 dòng I1 + 10 dòng kernel Task 8). Mọi crashpoint có test kill tiến trình thật và kiểm parity tên/doc/case; cột mất điện là lập luận dựa trên `FlushFileBuffers` / `F_FULLFSYNC` / `WAL synchronous=FULL` (chưa có test rút điện vật lý).
- **Ánh xạ tình huống §20 áp dụng cho I2:**
  - Tình huống 1, 2 (isolation & checkout khác nội dung): `PolicyStore` + D3 scope/CWD + `ShimTestDomain`/job scope tests.
  - Tình huống 3, 4, 22, 23 (idempotency, retry mất response, redact sau quarantine, commit outcome unknown): HMAC digest + `KernelIdempotencyStore` + deadline arbiter + `kernel.after_commit_before_response`.
  - Tình huống 5, 6, 7, 8, 25, 26, 34, 35 (crash, replay, backup/restore, writer lock, retention, version fence, policy/store intent, expiry): kế thừa toàn bộ suite I1 + các dòng mở rộng T2/T5/T6/T8.
  - Tình huống 9, 10, 11 (privacy filter, cấm egress/no-self-confirm model): T3/T8 privacy equivalence & raw leak tests (kiểm đầy đủ Jev/verify ở SP5).
  - Tình huống 13 (`get_health`): shallow ready read-only trong I2; `deep=true` vẫn trả `capability_unavailable` chờ đợt 4.
  - Tình huống 14, 36 (`fixture` vs `native`, `ServedReceipt`/`ReadAck`): T8 `Delivery`/receipt persistence + T9 `inc2_native.py` verifier (`require_native=True` từ chối fixture); tích hợp artifact/reader thật ở SP4/SP5.
  - Tình huống 15 (gate receipt & thời gian): `scripts/gate.py` giữ đủ denominator/raw JUnit và ngân sách < 300 s.
  - Tình huống 21, 24 (restore giữ `writer.lock`/revocation; requeue job & invocation `outcome_unknown`): T2/T5/T8 crash & recovery tests.
  - Tình huống 29, 30 (lineage ref/inheritance): `LineageSet` & `LineagedField` model/ref trong T3; truyền lineage đầy đủ qua continuity/Jev thuộc SP2–SP5.
- **Lớp 2 (`§11.3`):** giữ `unknown`.
- **Phê duyệt và review độc lập (`closure pending`):** mọi receipt, RED/GREEN/mutation log, seal digest (`test-seal-9.1-r3.json`, `test-seal-9.2-r2.json`, `test-seal-final.json`), provenance review và báo cáo cuối nằm trong ledger ngoài Git tại `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`. Chỉ khi hoàn tất F4/perf trên pin cuối, thu đủ host native đã duyệt và có review độc lập đồng thuận mới được đóng SP1 đợt 2.
