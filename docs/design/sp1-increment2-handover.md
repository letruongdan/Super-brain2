# Bàn giao SP1 đợt 2: kernel daemon, MCP shim và đường native

Ngày cập nhật: 2026-11-14. Tài liệu này là bản bàn giao SP1 đợt 2 trên nhánh `codex/sp1-i2-task9` (tách từ mốc Task 8 `3527a99803059cb06b5120cd18edea2e1a828857`, sau đó merge closure Task 8 `978e63ae685d76b725114102eb932c140ef79f24` bằng merge commit `8439dbae40ef2595a6f547bdbc3d4489014a3065`).

Theo quy tắc tuyên bố của [spec rev22 mục 17.2–17.5](../superpowers/specs/2026-10-30-super-brain2-system-design.md#172-các-gate): chỉ được tuyên bố đóng toàn bộ SP1 đợt 2 khi **toàn bộ** điều kiện sau cùng đạt trên đúng commit `HEAD` cuối có working tree sạch:
1. Gate mặc định (`scripts/gate.py`, F4 dưới 300 s, 0 fail/error/XPASS, JUnit đầy đủ, `ruff`, strict `mypy`, `import-linter`) đạt trên đủ ma trận OS × Python áp dụng.
2. Benchmark (`tests/integration/test_kernel_performance.py`) đạt ngưỡng trên các ô đích.
3. Gate native có `NativeConnectionProbe` hợp lệ (`kind="native"`, `status="passed"`) cho từng host đã chọn trên cùng kho/epoch/instance với phê duyệt D8 của owner.
4. Review độc lập toàn nhánh xác nhận đúng commit pin, test seal, ledger và inventory cuối.

Tính đến thời điểm commit tài liệu này (trước khi chốt/chạy nghiệm thu cuối trên `HEAD` theo quy tắc không vòng lặp T9-P01):
- Phần code, unit/integration/architecture/crash/wheel tests của Task 1–9 và checklist vận hành đã **triển khai trên nhánh** (`implemented` ở mức mã nguồn trước nghiệm thu pin cuối).
- **Ma trận gate & benchmark trên pin cuối (`pending_after_commit`)**: gồm ma trận CI 6 ô (`win32`, `linux`, `macos` × Python `3.11` và `3.14`, artifact lưu ngoài Git dưới `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/github-run-<run_id>/`) và ma trận local 4 ô (`win32`, `linux/ext4` × Python `3.11` và `3.14`, artifact lưu ngoài Git dưới `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-r28-<short_sha>/`), tổng hợp kiểm chứng tại `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`. Chỉ công nhận đạt khi `receipt.start.commit == receipt.end.commit == HEAD` cuối sạch và khớp seal test của commit đó.
- **Kết nối native D8 (`Codex desktop app` và `Claude Code`)**: D8 đã được owner duyệt cho **Codex desktop app** và **Claude Code** với root cô lập theo pin cuối tại `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\`. Các probe lịch sử ở pin trung gian trước đây không thay thế nghiệm thu trên wheel và commit pin cuối; kết quả probe thực tế trên pin cuối và biên bản đối chiếu verifier giữ tại `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md` và `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\`.
- **Lớp 2** (spec §11.3): **`unknown`** (thuộc SP2 / SP7).
- **Mục mở kế thừa từ Task 8 (`T9-OPEN-W1`)**: mẫu wire 1 MiB qua daemon thật phải đạt ngân sách trên đúng commit pin cuối (`ledger.md`, `final-r28-<short_sha>/`, `github-run-<run_id>/`).
- **Review độc lập cuối cho Task 9**: đang chờ đối chiếu trên đúng commit pin cuối (các seal/review trung gian trước đây chỉ mang tính lịch sử; nghiệm thu cuối kiểm đúng commit `HEAD`, full test seal, ledger, ma trận CI/local và D8 receipt cuối).

---

## 1. Phạm vi SP1 đợt 2 và phần chuyển giao

### Đã hoàn thiện trong kernel SP1 đợt 2

- **Hợp đồng wire và schema:** [schemas/mcp-tools-v2.json](../../schemas/mcp-tools-v2.json) (`sha256:a8d2317c2a56191a5c08510a6c3c26b7141ebfd43943385507bfc60bc8df65a1`), canonical JSON, ID validation và typed `BrainError`.
- **Transport D2 (TLS loopback + state machine 2 bước):** bind `127.0.0.1:<ephemeral_port>`, private CA và leaf cert theo từng kho (`cryptography`), client pin leaf + check SAN/thời hạn, `GET /v2/identity` không mang bearer trước khi gửi `POST /v2/tools/call` có bearer trên cùng socket, deadline monotonic 2 s TLS + 2 s tool (`1.5 s` daemon + phần dự phòng).
- **Vận hành daemon owner và CLI/MCP shim (D1, D3):** `brain serve --config <ABS>`, `brain migrate --offline --config <ABS>`, `brain-mcp` và `brain mcp --profile <ABS>` (stdio MCP `2025-06-18`) thực thi `single-checkout-owner-profile-v1`, xác minh raw path, physical identity và launch CWD, tiêm `workspace_hint` và `selected_scope={repo_id, checkout_id}` trước HMAC digest.
- **Policy v3 & Store v4:** principal `(owner_id, harness_id, machine_id)`, bearer `<credential_uuidv7>.<secret>` lưu hash SHA-256 + constant-time verify, `AuthGate` nguyên tử (generation + trust generation + grant stamp), registry workspace trên policy và reconcile theo intent ID vào kho, HMAC-SHA256 `idempotency` với replay/conflict/lost-response recovery, mô hình `Delivery`/`ServedReceipt`/`ReadAck`, `LineageRef`/`LineageSet`/`LineagedField`, tương thích S1=A (`snapshot_status`), và `Job`/`JobService`/`ProviderInvocation` với lease/attempt/cancel/settlement.
- **Privacy filter & ma trận crash:** 10 nhóm lọc secret/PII/entropy/`<private>`/path cấm trước canonical safe payload; 29 dòng crashpoint trong [sp1-crash-table.md](sp1-crash-table.md) (19 I1 + 10 kernel Task 8) được kiểm parity tên/doc/case bằng AST/matrix tests.
- **Contract nhận diện kết nối & quan sát owner Task 9:** `tests/support/inc2_native.py` (`sp1-i2-native-connection-v1`, bắt buộc `run_id`, `observer_id`, `host_mode`, `registered_host_versions` khác rỗng, manifest `evidence-index.json` + đọc kiểm tra đủ 4 kênh trên đĩa, khớp `connection_id` 1-1 không null fallback), `tests/support/inc2_native_owner.py` (chạy wheel dưới `python -I`, nối `read_admitted_tool_command`, `LoopbackServer._conn_worker`, `LoopbackServer._release_owner_reply`, `write_json_response`, `AuthGate.authorize_stamp` / `AuthGrantStamp` == `AuthGate.current()`, lookup PID socket loopback chạy bất đồng bộ ngoài thread request/deadline để không ảnh hưởng SLA daemon và gắn `observation_status="observation_incomplete"` khi quá hạn/lỗi), bộ kiểm `tests/integration/test_kernel_native_receipt_contract.py`, và [sp1-increment2-native-checklist.md](sp1-increment2-native-checklist.md).

### Không thuộc SP1 đợt 2 (hoãn đúng theo D1–D8 và spec §20)

- **Production tools ngoài `get_health(deep=false)` và đọc `get_job`:** `prepare_task`, `get_artifact`, `record_outcome`, `submit_episode`, `get_health(deep=true)`, `doctor`, `apply` trả `capability_unavailable` ở daemon sản phẩm cho tới các đợt/SP tương ứng; chỉ đường composition fixture (`FixtureKernelDomain`) được dùng để nghiệm thu atomic persistence trong test.
- **Bootstrap sản phẩm (`brain init`, `brain credential revoke`, signer M1, WebAuthn/SSH FIDO, UI duyệt & `ApplyJournal`):** thuộc SP1 đợt 3–4.
- **Lớp 2 (`§11.3`), hook/capture session, handoff continuity và egress Jev thật:** thuộc SP2–SP5; đánh giá hiệu quả thuộc SP6.
- **Host bổ sung (`Antigravity` R1, `OpenCode`, `Cursor`):** ngoài tập host được chọn ở T0 (thuộc SP7 / quyết định riêng của owner).

---

## 2. Cơ chế pin source, khác biệt spec và provenance artifact

1. **Nhánh và base pin:** nhánh `codex/sp1-i2-task9` tách từ commit Task 8 `3527a99803059cb06b5120cd18edea2e1a828857`; closure Task 8 `978e63a` (tối ưu privacy/wire, review độc lập APPROVED) được merge vào nhánh tại `8439dba`, không xung đột, phần `src` của merge bằng đúng `978e63a`. Lưu ý checkout `sp1-increment2` ở `6a3a4d2` giữ bản spec rev22 trước phần giải thích mẫu đường dẫn ở §14.2, trong khi `3527a99` (và nhánh Task 9) giữ bản có `§14.2` tại [2026-10-30-super-brain2-system-design.md](../superpowers/specs/2026-10-30-super-brain2-system-design.md) (`sha256:560eea11f23d75a677cc684ae33f85c79c3e3291ac4a1ca77a8778f0f24e8ff4`). Toàn bộ điều khoản native, D2–D8 và T0 giống nhau.
2. **Pin cấu hình bất biến kèm trong commit này:**
   - `pyproject.toml`: `sha256:4f54cc75470b21bb44257e9f434d4f043c8ad979c08c0a804eb956fece8a87a3`
   - `uv.lock`: `sha256:b0431c4a5ad311ce1d1e25edc1698d0eea6fbad9b5f1b7d2fe16e2983cc4b419`
   - `schemas/mcp-tools-v2.json`: `sha256:a8d2317c2a56191a5c08510a6c3c26b7141ebfd43943385507bfc60bc8df65a1`
   - `docs/superpowers/specs/2026-10-30-super-brain2-system-design.md`: `sha256:560eea11f23d75a677cc684ae33f85c79c3e3291ac4a1ca77a8778f0f24e8ff4`
   - `docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md`: `sha256:bb9072099f36e9142cfd1b5f72687556e8af4919769d276b4fc8d35a2ab50596`
   - `docs/superpowers/plans/2026-11-04-sp1-increment2-daemon-mcp-kernel.md`: `sha256:1e957f93bd1b4c6908d8634394eb317c3955d45dc362a75595f765f33ed9fb6a`
3. **Quy tắc pin không vòng lặp (Plan T9-P01):** tài liệu bàn giao được commit **trước** khi chạy `scripts/gate.py`, benchmark và native probe trên pin cuối. Do đó mọi receipt của Task 9 được lưu ngoài tracked Git dưới `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/` (`ledger.md`, `github-run-<run_id>/`, `final-r28-<short_sha>/`, `test-seal-final.json`) và root D8 cô lập `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\`, và **chỉ có hiệu lực** khi `receipt.start.commit == receipt.end.commit == git rev-parse HEAD`, `tree_clean == true`, và digest seal test khớp đúng commit đó. Bất kỳ chỉnh sửa file tracked nào đều làm các receipt cũ hết hiệu lực kiểm chứng.
4. **Provenance build wheel:**
   - Benchmark `tests/integration/test_kernel_performance.py` tự build một wheel sạch từ commit được pin vào temp riêng và ghi `wheel_digest` trong receipt `perf-*.json`.
   - Mọi phép thử native D8 về sau phải ghi rõ `shim_build_digest` của đúng file `.whl` đã cài vào môi trường host (gắn cùng `source_commit`, `uv.lock` và `schema_sha256`), không ghép chéo digest wheel của benchmark sang lượt native.

---

## 3. Baseline Task 8 và ma trận Gate / OS của Task 9

Receipt closure Task 8 tại `978e63a` (F4 accepted trên Windows 3.11.9 và 3.14.3; benchmark chỉ trượt ở mẫu wire 1 MiB, mục `T9-OPEN-W1`) nằm ở ledger Task 8 §13. Kết quả F4/benchmark trên pin cuối Task 9 được ghi vào ledger Task 9 ngoài Git sau khi chốt pin (quy tắc ở mục 2.3), không nhúng vào tài liệu này.

### Baseline lịch sử tại pin Task 8 (`3527a99803059cb06b5120cd18edea2e1a828857`)

*Chỉ dùng làm mốc đối chiếu; không thay thế receipt của commit Task 9.*

| Ô môi trường | Gate F4 (`receipt.json`) | Benchmark (`perf-*.json`) | Nơi lưu trong ledger |
|---|---|---|---|
| Native Windows (`win32`, configured `C:\Users\letru\sb2-trusted-local`), Python `3.11.9` | `accepted=true`, 2.165 ID (`2.120 pass / 45 skip / 0 fail / 0 error / 0 xpass`), `188.546 s` (< 300 s) | `accepted=true`, warm `prepare` p95 `178.0051 ms`, privacy 1 MiB p95 `70.1561 ms` (ratio `0.9788`), cold `brain mcp` p95 `432.7608 ms`, `brain-mcp` p95 `383.6546 ms` | `task-8/final-3527a99/gate-3.11.9/` & `perf-3.11.9/` |
| Native Windows (`win32`, configured `C:\Users\letru\sb2-trusted-local`), Python `3.14.3` | `accepted=true`, 2.165 ID (`2.120 pass / 45 skip / 0 fail / 0 error / 0 xpass`), `189.961 s` (< 300 s) | `accepted=true`, warm `prepare` p95 `44.102 ms`, privacy 1 MiB p95 `73.0047 ms` (ratio `1.0137`), cold `brain mcp` p95 `525.9607 ms`, `brain-mcp` p95 `450.287 ms` | `task-8/final-3527a99/gate-3.14.3/` & `perf-3.14.3/` |

### Ma trận Gate & OS cho commit cuối Task 9 (`codex/sp1-i2-task9`)

Môi trường Windows local sử dụng `LOCALAPPDATA=C:\Users\letru\sb2-trusted-local` và `TEMP`/`TMP=C:\Users\letru\sb2-trusted-local\gate-temp` vì `AppData\Local` mặc định của session Codex mang SID takeover rights; guard quyền sản phẩm được giữ nguyên trạng không nới lỏng. Theo quy tắc T9-P01, toàn bộ ma trận CI 6 ô và ma trận local 4 ô phải được kiểm chứng sau khi chốt commit cuối `HEAD`, đối chiếu qua `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`:

| Kênh / OS | CPython | Trạng thái trên pin cuối T9 (T9-P01) | Đường dẫn kiểm chứng trong ledger | Điều kiện đóng ô |
|---|---|---|---|---|
| Local Native Windows 11 (`win32`, configured trusted root) | `3.11.9` | `pending_after_commit` *(kiểm chứng sau commit `HEAD` cuối; các vòng trước không thay pin cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-r28-<short_sha>/` & `ledger.md` | Chạy `scripts/gate.py --python 3.11.9` (< 300 s, 0 fail/error/XPASS, JUnit parity, seal khớp trước/sau) và `test_kernel_performance` trên đúng `HEAD` |
| Local Native Windows 11 (`win32`, configured trusted root) | `3.14.3` | `pending_after_commit` *(kiểm chứng sau commit `HEAD` cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-r28-<short_sha>/` & `ledger.md` | Chạy `scripts/gate.py --python 3.14.3` (< 300 s, 0 fail/error/XPASS, JUnit parity, seal khớp trước/sau) và `test_kernel_performance` trên đúng `HEAD` |
| Local Linux / ext4 (`wsl` / ext4 clean clone) | `3.11` | `pending_after_commit` *(kiểm chứng sau commit `HEAD` cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-r28-<short_sha>/` & `ledger.md` | Chạy `scripts/gate.py` và `test_kernel_performance` trên clone Linux sạch ở đúng commit `HEAD` cuối |
| Local Linux / ext4 (`wsl` / ext4 clean clone) | `3.14` | `pending_after_commit` *(kiểm chứng sau commit `HEAD` cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/final-r28-<short_sha>/` & `ledger.md` | Như trên cho CPython 3.14 trên đúng commit `HEAD` cuối |
| CI GitHub Actions Windows | `3.11` & `3.14` | `pending_after_commit` *(2 ô CI thuộc ma trận 6 ô trên `HEAD` cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/github-run-<run_id>/` & `ledger.md` | Toàn bộ job & artifact CI khớp đúng commit `HEAD` cuối, `accepted=true` F4 + benchmark |
| CI GitHub Actions Linux | `3.11` & `3.14` | `pending_after_commit` *(2 ô CI thuộc ma trận 6 ô trên `HEAD` cuối)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/github-run-<run_id>/` & `ledger.md` | Toàn bộ job & artifact CI khớp đúng commit `HEAD` cuối, `accepted=true` F4 + benchmark |
| CI GitHub Actions macOS | `3.11` & `3.14` | `pending_after_commit` *(2 ô CI thuộc ma trận 6 ô trên `HEAD` cuối; `mypy` override không thay runtime macOS)* | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/github-run-<run_id>/` & `ledger.md` | Chạy `scripts/gate.py` (`F_FULLFSYNC`, POSIX permissions) và `test_kernel_performance` trên runner macOS ở đúng `HEAD` cuối |

---

## 4. Verdict Q4 · Kết nối native theo từng host

Quy ước theo §17.3 / §17.5: các bài kiểm trong `tests/integration/test_kernel_native_receipt_contract.py` là bằng chứng **contract và fixture qua wheel cài đặt thật** (`kind="fixture"`, `host_mode="wheel_mcp_pipe"`/`"fixture_mcp_stdio"`), hoàn toàn không thay thế `NativeHostReceipt` từ tiến trình host thật.

| Host (Q4) | Trạng thái T0 lịch sử | Verdict native T9 theo pin cuối (T9-P01) | Ghi chú & nơi đối chiếu |
|---|---|---|---|
| **Codex desktop app** (`26.1106.6628.0`, `codex_desktop_gui`; T0 `26.1029.7803.0`) | `passed` (`t0r1`/`t0r2`) | `pending_after_commit` *(D8 đã duyệt; kiểm trên wheel pin cuối)* | D8 đã duyệt. Probe thực tế chạy ở root cô lập `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\` và lưu đối chiếu wheel/verifier/source trên đúng pin cuối trong `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`. |
| **Codex CLI** (`codex-cli 0.167.0-alpha.4.1`, `codex_cli_exec`; T0 `0.166.0-alpha.6`) | *(chẩn đoán phụ T0)* | *(chẩn đoán phụ; không thay Codex desktop app)* | Chỉ làm chẩn đoán phụ theo `codex_cli_exec`; **không** thay thế verdict của **Codex desktop app**. |
| **Claude Code** (`2.1.322 (Claude Code)`, `claude_cli_mcp_isolated`; T0 `2.1.317`) | `passed` (`t0r3`) | `pending_after_commit` *(D8 đã duyệt; kiểm trên wheel pin cuối)* | D8 đã duyệt. Probe thực tế chạy ở root cô lập `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\` (chung daemon với probe Codex trên đúng pin cuối) và lưu đối chiếu trong `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`. |
| **Antigravity Desktop** (`1.23.2` / `agy 1.5.1`) | `failed_r1_unsupported_in_i2` | *(ngoài tập I2)* | Đã loại khỏi tập hỗ trợ I2 theo Owner Ruling `2026-11-05T19:05:18+07:00`; giữ nguyên lịch sử failure `t0r2` cho SP7 |
| **OpenCode** (`2.2.0`) | `not_run` | *(chưa chọn trong I2)* | Chưa được chọn cho I2; cần quyết định phạm vi và D8 |
| **Cursor** | `not_run` | *(chưa cài đặt / chưa chọn trong I2)* | Chưa cài đặt / chưa được chọn cho I2; cần quyết định phạm vi và D8 |

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
- **Phê duyệt và review độc lập (`closure pending`):** mọi receipt, RED/GREEN/mutation log, seal digest (`test-seal-final.json`, `.verification/task9-seal.json`), ma trận CI (`github-run-<run_id>/`), ma trận local (`final-r28-<short_sha>/`), kết quả native D8 (`C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\`), provenance review và báo cáo cuối nằm trong ledger ngoài Git tại `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md`. Chỉ khi hoàn tất ma trận F4/benchmark trên pin cuối, thu đủ probe native đã duyệt trên đúng wheel pin cuối và có review độc lập đồng thuận mới được đóng SP1 đợt 2.
