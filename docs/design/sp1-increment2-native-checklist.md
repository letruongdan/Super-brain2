# Checklist kiểm chứng kết nối native · SP1 đợt 2 (Task 9)

Ngày cập nhật: 2026-11-15. Tài liệu vận hành cho Task 9 (spec rev22 §2 Q4, §4.3, §5.9, §17.2–17.5; D1–D8; [biên bản freeze T0](../reviews/2026-11-06-sp1-increment2-t0-closure-and-d2-freeze.json)). Mọi receipt phát sinh từ fixture hoặc wheel test mang `kind="fixture"`, **không** bao giờ được nâng thành `native`. Chỉ cấp `native connection accepted` cho từng host sau khi có `NativeConnectionProbe` (`kind="native"`, `status="passed"`, schema `sp1-i2-native-connection-v1`) đi qua cùng verifier `tests/support/inc2_native.py::verify_native_connection` với `ObserverRegistration` do coordinator pin độc lập từ ngoài payload.

---

## 1. Quy tắc xin phép D8 trước khi chạm host thật

Không tự ý chạy host thật, không ghi/sửa `~/.codex/config.toml`, `~/.claude*`, Windows ACL mặc định, Windows Firewall hoặc loopback exemption khi chưa có phê duyệt riêng của owner theo §17.2 / D8. Hồ sơ xin phép 7 mục đã chuẩn bị sẵn tại `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/d8-approval-request.md`.

Mỗi đề xuất xin phép gửi owner trước khi chạy phải nêu đủ 7 mục:

1. **Host, mode và version mục tiêu:** tên host, mode cụ thể (`codex_desktop_gui` cho Codex desktop app, `claude_cli_mcp_isolated` cho Claude Code; `codex_cli_exec` chỉ làm chẩn đoán phụ và **không** thay thế Codex desktop app), xác nhận version cài đặt thực tế ngay trước lúc chạy.
2. **Lệnh shim đã pin:** `brain-mcp --profile <ABS_PROFILE>` hoặc `brain mcp --profile <ABS_PROFILE>` từ đúng file wheel của commit cuối được pin (kèm SHA-256 artifact wheel, `uv.lock`, `schemas/mcp-tools-v2.json`).
3. **Phạm vi cấu hình cô lập:** thư mục tạm riêng (`CODEX_HOME` tạm, `--user-data-dir` tạm, hoặc `--mcp-config` cô lập), cam kết không đọc/ghi cấu hình live của user.
4. **Data root và checkout synthetic:** kho synthetic đã migrate (`store v4`, `policy v3`), tối thiểu hai principal khác `harness_id` (`claude-code`, `codex`) cùng owner trên một `store_id`/epoch, checkout synthetic `A` và `B` trên cùng Repo 1 cùng `C` trên Repo 2, đủ grant đọc `get_job` cho từng checkout để kiểm chứng chéo D3.
5. **Phương thức quan sát đã đăng ký:** `ObserverRegistration` (`run_id`, `task_id`, `registered_observer_id`, `registered_channel`, `expected_host_mode`, danh sách `registered_host_versions` khác rỗng, digest config/profile/wheel/schema, `evidence_root`), manifest `evidence-index.json` cùng đủ 4 kênh trên đĩa (`owner-ready.json`, `owner-events.jsonl`, `host-calls.jsonl`, `socket-observations.jsonl` với `connection_id` 1-1), owner daemon `brain serve --config <ABS>` (hoặc `tests/support/inc2_native_owner.py` trên kho synthetic), và collector metadata socket loopback chạy ngoài thread request/deadline (báo `observation_status="observation_incomplete"` nếu timeout mà không ảnh hưởng deadline/tool response).
6. **Kế hoạch dừng và cleanup:** tiêu chí dừng theo `pid` + `started_at`, kiểm tra `writer.lock`/`endpoint.json`, đối chiếu hash/timestamp cấu hình user trước–sau, và dọn thư mục synthetic sau khi xác nhận physical path/ownership.
7. **Ước lượng quota / model call:** số lượt prompt/tool call dự kiến (tối thiểu để host gọi `get_health` và `get_job`), không tạo job nền hoặc canary Jev ngoài phạm vi được duyệt.

Nếu trong lúc chạy phát sinh lỗi hệ thống (sandbox chặn file, loopback bị chặn hoặc thiếu quyền ACL), **dừng và bảo toàn evidence lỗi**, rồi lập đề xuất thay đổi hẹp kèm lỗi và stage quan sát được để xin phép riêng một lượt D8 mới. Không tự sửa cấu hình máy hoặc mở rộng quyền ngoài phạm vi đã duyệt.

---

## 2. Bảng Q4 · Tách biệt kết quả lịch sử T0 và verdict Task 9

| Host | Version quan sát được | OS | Mode | T0 lịch sử (freeze 2026-11-06) | Registration ID | Digest `source / wheel / config / profile` | Task / Run ID | Verdict T9 | Stage / Reason | Artifact path (ledger ngoài Git) | Điều kiện chạy lại / tiếp tục |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Codex desktop app | `OpenAI.Codex 26.1106.6628.0 MSIX` (runtime `26.1111.570.0`; T0 `26.1029.7803.0`) | `win32` | Desktop GUI window (`codex_desktop_gui`, `ChatGPT.exe`) với `CODEX_HOME` cô lập (bắt buộc cho gate Q4 Codex; không thay bằng CLI) | `passed` (`t0r1` / `t0r2`) | Đã duyệt D8; ID đăng ký theo run pin cuối | Khớp pin cuối `HEAD` (wheel, `uv.lock`, `schema`, config, profile) | theo từng run dưới `final-<short_sha>` | `pending_after_commit` *(kiểm trên wheel pin cuối theo T9-P01)* | Chờ đối chiếu probe A/B/C và A+B đồng thời trên pin cuối | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md` & `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\` | Kiểm đủ A/B/C và hai cửa sổ đồng thời A+B trong `CODEX_HOME` cô lập trên wheel của đúng commit `HEAD` cuối; mọi probe ở pin cũ chỉ dùng đối chiếu lịch sử |
| Codex CLI *(chẩn đoán phụ, không thay Desktop app)* | `codex-cli 0.167.0-alpha.4.1` (T0 `0.166.0-alpha.6`) | `win32` | Headless `codex exec` (`codex_cli_exec`) với `--strict-config` + `CODEX_HOME` cô lập | *(ghi chú phụ trợ T0)* | `pending_d8_diag` | `null` | `null` | `diagnostic_only` *(không thay Desktop app)* | `optional_auxiliary_diag` | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/native/codex-cli/` | Chỉ dùng làm smoke/chẩn đoán CLI phụ trợ nếu owner duyệt kèm D8; `verify_native_connection` tách riêng `host_mode="codex_cli_exec"` khỏi `codex_desktop_gui` |
| Claude Code | `2.1.322 (Claude Code)` *(T0 từng ghi nhận `2.1.317`)* | `win32` | CLI/MCP session cô lập (`claude_cli_mcp_isolated`, `--strict-mcp-config --mcp-config`), chính Claude Code phát MCP call | `passed` (`t0r3`) | Đã duyệt D8; ID đăng ký theo run pin cuối | Khớp pin cuối `HEAD` (wheel, `uv.lock`, `schema`, config, profile) | theo từng run dưới `final-<short_sha>` | `pending_after_commit` *(kiểm trên wheel pin cuối theo T9-P01)* | Chờ đối chiếu probe A/B/C và A+B đồng thời trên pin cuối | `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/ledger.md` & `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\` | Đối chiếu A/B/C và A+B đồng thời chung daemon với Codex desktop app trên wheel của đúng commit `HEAD` cuối; mọi probe ở pin cũ chỉ dùng đối chiếu lịch sử |
| Antigravity Desktop | `Antigravity.exe 1.23.2` + `agy 1.5.1` *(T0)* | `win32` | Desktop GUI (`--user-data-dir`) | `failed_r1_unsupported_in_i2` *(ruling 2026-11-05: `language_server.exe` dùng chung tái sử dụng shim A giữa các checkout/cửa sổ)* | `none (excluded_i2)` | `n/a` | `n/a` | `excluded_i2` *(ngoài tập I2)* | `r1_excluded_in_i2` | `docs/reviews/2026-11-06-sp1-increment2-t0-closure-and-d2-freeze.json` | Chỉ mở lại nếu có quyết định riêng của owner cho SP7 (per-call workspace binding / O3) hoặc build mới chứng minh relaunch/tách shim từng checkout |
| OpenCode | `2.2.0` *(kiểm tra T0)* | `win32` | Chưa chọn trong I2 | `not_run` | `none (unselected_i2)` | `n/a` | `n/a` | `unselected_i2` *(ngoài tập I2)* | `unselected_in_i2_and_unapproved` | `n/a` | Owner chọn đưa vào phạm vi, kiểm mode/cài đặt thực tế và duyệt D8 |
| Cursor | `null` *(chưa ghi nhận cài đặt trong T0)* | `win32` | Chưa chọn trong I2 | `not_run` | `none (unselected_i2)` | `n/a` | `n/a` | `unselected_i2` *(chưa cài/ngoài tập I2)* | `uninstalled_unselected_unapproved` | `n/a` | Cài đặt trên máy đích, owner đưa vào phạm vi và duyệt D8 |

Ghi chú: mọi hàng `passed` trong `tests/integration/test_kernel_native_receipt_contract.py` chạy bằng `inc2_native_owner.py` qua wheel cài đặt thật đều mang `kind="fixture"` (`host_mode="wheel_mcp_pipe"` hoặc `"fixture_mcp_stdio"`) và chỉ nghiệm thu harness/contract/wiring trên Windows, không điền vào cột Verdict T9 native ở bảng trên.

---

## 3. Quy trình chuẩn bị môi trường owner và preflight trước probe

Chỉ chạy sau khi đã có phê duyệt D8 và pin commit cuối:

1. **Xác nhận artifact & provenance:**
   - Pin đúng commit `HEAD` sạch (`git status --porcelain` rỗng).
   - Build hoặc xác định đúng wheel artifact sẽ cài vào host; ghi SHA-256 wheel, `uv.lock`, `schemas/mcp-tools-v2.json` vào bảng `ObserverRegistration` trong ledger `task-9/`.
   - Kiểm tra dưới `python -I` của môi trường cài đặt rằng `superbrain.__file__` nằm bên trong venv/cài đặt mục tiêu và `load_catalog().schema_sha256` khớp commit pin.
2. **Kiểm tra token, physical root và ACL từ shell owner:**
   - Chạy dưới tài khoản user thường ngoài sandbox (nếu Windows user `AppData\Local` có SID takeover rights không an toàn như phiên Codex hiện tại, dùng root được cấu hình rõ như `C:\Users\letru\sb2-trusted-local`, **không** hạ chuẩn guard sản phẩm và **không** sửa ACL hồ sơ thật khi chưa được duyệt).
   - Xác minh kết quả `PathCheckResult`: `physical_root_ok=True`, `ancestors_ok=True`, `symlink_or_reparse_rejected=True`, token/SID owner đúng và không có app-container trừ khi đang kiểm hành vi sandbox của chính host.
   - Ghi nhận trạng thái baseline (`mtime` + SHA-256) của `~/.codex/config.toml` và file cấu hình Claude để đối chứng sau khi cleanup.
3. **Provision kho synthetic và hai profile khác principal:**
   - Khởi tạo kho synthetic (store v4, policy v3), TLS private CA + leaf pin riêng cho kho đó (`127.0.0.1:<port>`).
   - Seed ít nhất hai credential khác `harness_id` dưới cùng `owner_id`:
     - principal cho `claude-code`, kèm profile cho checkout `A`, `B`, `C`
     - principal cho `codex`, kèm profile cho checkout `A`, `B`, `C`
   - Đảm bảo principal có grant phù hợp để `get_job` trả `ok=True` đúng checkout và trả `not_found` khi đọc chéo checkout khác.
4. **Khởi động owner daemon và kiểm collector socket:**
   - Chạy daemon từ shell owner với `brain serve --config <ABS_CONFIG>` (hoặc `inc2_native_owner.run_observed_owner` đối với kho synthetic có tap auth/flush).
   - Chạy 1 lượt kiểm preflight collector kết nối loopback ngắn trước khi mở host thật để chắc chắn môi trường chạy bắt được cặp `(local_addr:port, remote_addr:port, client_pid, client_started_at)` trước khi socket đóng (`close_conn=True`).

---

## 4. Các bước chạy kiểm chứng trên từng host được duyệt (D2 + D3)

Thực hiện riêng từng host đã đăng ký trong cùng `writer_epoch` / `instance_id` của daemon (hoặc ghi nhận restart riêng nếu epoch đổi):

1. **Khởi chạy từ cấu hình cô lập:**
   - **Codex desktop app:** mở cửa sổ desktop trỏ `CODEX_HOME` cô lập tới thư mục synthetic đã chuẩn bị; xác nhận process desktop thật (`ChatGPT.exe` / `codex.exe`) qua `pid` + `started_at`.
   - **Claude Code:** mở với `--mcp-config <ABS_ISOLATED_CONFIG>` tại checkout synthetic; thu bằng chứng trực tiếp từ session rằng chính Claude Code khởi chạy shim và phát tool call.
2. **Kiểm kết nối căn bản (`get_health` + `get_job`):**
   - Trong mỗi session đang mở ở checkout `A`, gọi một lệnh shallow `get_health({"schema_version": "2.0", "deep": false})` và một lệnh `get_job({"schema_version": "2.0", "job_id": "<job_a_id>"})` (cùng một ca kiểm tra chéo `job_b_id` kỳ vọng `not_found`).
   - Xác minh đầy đủ chuỗi nối qua 4 kênh trước khi chấp nhận row:
     - Host registration (`ObserverRegistration` pre-pinned, `active=True`, khớp `host`, `host_version`, `os`, `source_commit`, `shim_build_digest`, `config_digest`, `profile_digest`, `schema_digest`, `store_id`).
     - Tiến trình shim launcher và shim worker có đủ `(pid, started_at)` và `filtered_command` (không chứa token, private key hay credential path thô).
     - Socket loopback IPv4 nối `shim_worker_process` tới cổng `listen` của `daemon_process` theo cặp `connection_id` 1-1 và cửa sổ `[so_started_at, so_ended_at]` bao `[oc_started_at, oc_ended_at]` (cấm bỏ qua khi `client_*` null).
     - Owner event (`observation_status="ok"`) xác thực `AuthGrantStamp` khớp `AuthGate.current()`, `principal_id` thuộc đúng `harness_id` của host (hoặc `<unknown>` khi auth lỗi; không tách `raw_token`), và `write_json_response` đã flush HTTP 200 với envelope thực `ok=True` (`response_digest` khớp bytes terminal host nhận được; collector socket luôn chạy ngoài thread request/deadline để không làm chậm daemon).
3. **Kiểm ma trận chuyển workspace theo D3 (`single-checkout-owner-profile-v1`):**
   - **Chuyển A → B cùng repo 1:** xác minh host relaunch shim mới (`pid` hoặc `started_at` đổi, CWD vật lý ở checkout `B`, `profile_digest` của `B`), `get_job(job_b)` thành công và `get_job(job_a)` bị từ chối `not_found`.
   - **Chuyển B → C khác repo 2:** xác minh relaunch shim mới cho `C`, đúng scope Repo 2.
   - **Hai cửa sổ song song A + B:** cả hai tiến trình shim sống đồng thời, từng tool call nối đúng socket/worker của chính cửa sổ đó, không chéo scope hay đè call ID.
   - **Thêm thư mục / roots khi đang ở session A (nếu host hỗ trợ):** ghi rõ thao tác host thực hiện; kiểm chứng scope của shim `A` vẫn giữ cố định tại `A` (nếu một thao tác chuyển đổi giữ nguyên PID/CWD của `A` mà đổi workspace cho người dùng hoặc từ chối relaunch đúng profile, kết luận `lifecycle_mismatch` / fail D3).
4. **Gate kho chung hai host:**
   - Chỉ khi **cả** Codex desktop app và Claude Code đều có `NativeConnectionProbe` `kind="native"`, `status="passed"`, `verify_native_connection(..., require_native=True) == True` trên **cùng** `(daemon_process, store_id, writer_epoch, instance_id)` với hai `principal_id` khác nhau (`verify_same_daemon == True`), mới đủ điều kiện đóng gate native kho chung của I2. Nếu daemon restart giữa chừng, giữ verdict từng lần chạy riêng và chạy lại cặp cùng epoch.

---

## 5. Phân loại lỗi, redaction và quy tắc stop/cleanup

### Mã trạng thái và stage lỗi chuẩn

- Thiếu phê duyệt D8, thiếu host cài đặt hoặc thiếu kênh đăng ký trước launch: `status="not_run"`, `reason_code` nêu rõ điều kiện thiếu (ví dụ `awaiting_d8_approval`, `host_not_installed`).
- Lỗi xảy ra từ lúc launch trở đi: `status="failed"` kèm một `reason_code` giai đoạn cụ thể (chữ thường ASCII `[a-z][a-z0-9_]{1,63}`):
  - `profile_read`: shim trong sandbox không đọc được file profile hoặc lệch path vật lý / CWD / ACL.
  - `endpoint_read`: không đọc được `endpoint.json` (quyền hoặc chưa publish).
  - `credential_read`: không đọc được file bearer credential.
  - `loopback_connect`: sandbox/firewall chặn kết nối TCP tới `127.0.0.1:<port>`.
  - `tls_identity`: lỗi handshake TLS, hết hạn chứng chỉ, lệch CA/leaf pin hoặc lệch `GET /v2/identity` `(store_id, writer_epoch, instance_id)`.
  - `daemon_auth`: bearer từ chối, credential thu hồi, grant mismatch hoặc lệch `AuthGrantStamp`.
  - `host_terminal`: daemon xử lý nhưng host không nhận hoặc không hiển thị kết quả terminal khớp (`response_digest`, `ok=True`, `ready=True`).
  - `lifecycle_mismatch`: host giữ nguyên shim A qua chuyển workspace sang B/C hoặc lệch `profile_digest` / `observed_scope`.
  - `observation_incomplete`: hai lệnh trùng không phân biệt được, retry ngầm thiếu telemetry, hoặc collector bỏ lỡ socket loopback ngắn.
- Khi stderr chỉ in lỗi chung không phân định được stage, ghi stage chưa xác định kèm đúng các fact đã quan sát (không đoán nguyên nhân).

### Kiểm soát rò rỉ dữ liệu trong evidence

Mọi receipt JSON và log giữ ở `task-9/native/` phải vượt qua parser `inc2_native.py::parse_native_probe` (cấm unknown key, duplicate key, bearer `<uuidv7>.<secret>`, PEM private key block, URI chứa `user:pass@`, hoặc raw exception string chứa đường dẫn bí mật). Giữ nguyên bytes config và credential ở ngoài receipt chia sẻ.

### Quy trình dừng và cleanup sau mỗi lần thử

1. Lưu toàn bộ `NativeConnectionProbe` JSON, observer index và socket/owner metadata đã lọc tại `C:\Users\letru\sb2-trusted-local\d8-live\final-<short_sha>\` và/hoặc `.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/` (`ledger.md`, `final-r32-<short_sha>/`, `native/<host>/<run_id>/`) **trước** khi dọn thư mục làm việc.
2. Đóng các cửa sổ/session test của host, xác nhận tất cả tiến trình `shim` (`launcher` + `worker`) đã kết thúc theo đúng `(pid, started_at)`.
3. Gửi tín hiệu dừng nhẹ (`CTRL_BREAK_EVENT` trên Windows / `SIGTERM` trên POSIX) tới daemon owner theo đúng `(pid, started_at)`; xác nhận mã thoát sạch, file `writer.lock` đã được nhả và `endpoint.json` đã bị xóa.
4. Kiểm tra physical path và owner của toàn bộ thư mục synthetic trước khi xóa; tuyệt đối không dùng xóa đệ quy qua link/junction.
5. Kiểm tra lại baseline `~/.codex/config.toml` và cấu hình Claude xác nhận hash/timestamp không đổi.
