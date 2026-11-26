# Runbook · `brain doctor`

Tài liệu vận hành cho lệnh tự chẩn đoán (SP1 đợt 4, đặc tả §13). Mọi đường dẫn trong lệnh phải là đường dẫn tuyệt đối.

## 1. Chế độ chạy

| Lệnh | Khi nào dùng | Hành vi |
|---|---|---|
| `brain doctor --config <ABS>` | Máy chủ có file config của daemon | Daemon đang phục vụ (có endpoint, giữ writer lock): gửi yêu cầu báo cáo đầy đủ qua kênh operator TLS đã pin. Không có endpoint và không ai giữ writer lock: đọc offline. |
| `brain doctor --profile <ABS>` | Máy client chỉ có profile operator | Như trên. Không dùng chung được với `--config`. |
| `brain doctor --config <ABS> --offline` | Cố ý đọc kho trực tiếp | Chỉ đọc: không lấy writer lease, không đổi byte nào. Nếu writer lock đang bị giữ thì trả `store_busy`. Vẫn chẩn đoán được khi schema mới hơn bản đang cài. |
| `brain doctor … --checkout <ABS>` | Kiểm thêm một checkout | So theo dạng chuẩn của hệ điều hành. Report của một checkout không bao giờ được trả cho lời gọi toàn kho. |
| `brain doctor … --wait-ms <0..10000>` | Chờ job doctor đang chạy | Mặc định 10000. Hết thời gian chờ thì trả `status: running` kèm `job_id`; chạy lại lệnh để đọc kết quả. |
| `brain doctor … --json` | Dùng cho script | Kết quả là `{"ok": true, "data": …}`, hoặc `{"ok": false, "error": {"code", "message"}}` khi lỗi. |
| `brain doctor --config|--profile <ABS> --fix` | Áp dụng mọi thao tác sửa an toàn (§3) qua daemon | Chỉ chạy online và cần credential operator thuộc **chủ kho đã ghim** (`store_owner`). Operator hợp lệ khác hoặc khi chưa ghim `store_owner` đều bị từ chối fail-closed với `not_found` (mã thoát `1`, không chạy thao tác nào). Dùng cùng `--offline`, hoặc khi daemon không phục vụ, thì trả `daemon_unavailable`. |

**Mã thoát:** `0` khi có báo cáo, kể cả báo cáo chứa WARN hoặc FAIL; `1` khi gặp lỗi có mã (auth, TLS, scope, daemon không sẵn sàng, identity lệch, store bận…); `2` khi cú pháp sai (`invalid_input`).

**Bảo vệ kiểu fail-closed:** khi lỗi pin, revocation, scope hay identity, lệnh trả lỗi có mã và **không** tự chuyển sang đọc offline. Nếu không có cách xác định ai đang giữ writer lock, lệnh trả `capability_unavailable`.

## 2. Đọc báo cáo

Mỗi mục check có các trường `group`, `name`, `status` (`PASS`, `WARN` hoặc `FAIL`), `reason`, `detail` và `remediation`. Khi một check thiếu bằng chứng native xác minh, phát hiện drift/lỗi quyền hay chạm giới hạn quét, nó trả `WARN` hoặc `FAIL` kèm `reason` riêng, không bao giờ làm giả `PASS`. Khi chạy bare CLI chưa nối adapter SP2, `capture.probe` trả `PASS` với `reason="sp2_not_wired"`; trên `run_m1_handover_probe` (`capture.sp2_probes`), thiếu adapter trả `WARN` với `reason="capture_probe_unattached"`; còn `--fix replay_outbox` / `restart_daemon` khi thiếu adapter trả `capability_unavailable`.

| Nhóm | Mã check |
|---|---|
| daemon | `daemon.schema_version`, `daemon.writer_lock` |
| storage | `storage.sqlite_integrity`, `storage.wal_size`, `storage.cas_sample`, `storage.orphan_blobs`, `storage.ledger_projection_match`, `storage.policy_reconcile`, `storage.disk_space`, `storage.latest_backup`, `storage.durability`, `storage.accounting_locks`, `storage.pending_restore_tombstones`, `storage.active_turn_intents`, `storage.incomplete_journals` |
| permissions | `permissions.tree` (quyền rộng, link, reparse point) |
| identity | `identity.signers`, `identity.credentials` |
| privacy | `privacy.canaries`, `privacy.rescan` |
| retention | `retention.tombstones` |
| harness | `harness.layer2`, `harness.proposals`, `harness.bootstrap_drift` |
| capture | `capture.probe` (số liệu do SP2 cấp qua adapter) |
| jev | `jev.passive` (kiểm thụ động không nối mạng: `ok` hoặc `price_drift`) |
| chưa có khả năng | `index.status`, `skill.status`, `lessons.status` (`deferred_sp_scope`, hoãn SP3–SP4) |

`get_health(deep=true)` (MCP) chỉ trả trạng thái và ref đã lọc của DoctorRun toàn kho gần nhất. Nếu run đó cũ hơn 24 giờ, nó xếp hoặc gắn vào một job và trả `job_id`. Muốn xem báo cáo đầy đủ thì cần quyền operator.

### Mẫu output đã lọc (`brain doctor --config <ABS> --json`)

Mọi chuỗi trong report (`detail`, `remediation`, `layer2_harnesses`, `permission_problems`…) đều đi qua bộ lọc privacy trước khi xuất ra CLI/operator (`DoctorReport.to_dict()`):

```json
{
  "ok": true,
  "data": {
    "overall_status": "pass",
    "store_id": "019...",
    "data_root": "<ABS_DATA_ROOT>",
    "schema": {
      "store_version": 5,
      "policy_version": 4,
      "expected_store_version": 5,
      "expected_policy_version": 4,
      "min_store_reader_version": 1,
      "min_policy_reader_version": 1
    },
    "restore_epoch": 0,
    "trust_generation": 1,
    "signer_reset_recorded": false,
    "terminal_channel_eligible": false,
    "signers": [{"signer_id": "sig_...", "channel": "ssh_key", "key_digest": "sha256:...", "tofu": true, "sign_count": 0}],
    "layer2_harnesses": [],
    "unresolved_accounting_locks": [],
    "pending_restore_tombstones": {"present": false, "restore_epoch": null, "expired_holders_count": 0, "corrupt_error": null},
    "pending_proposals": [],
    "bootstrap_drifts": [],
    "checks": [
      {"group": "daemon", "name": "daemon.writer_lock", "status": "PASS", "reason": "stopped_cleanly", "detail": "daemon stopped cleanly (epoch=1, endpoint.json absent (daemon stopped))", "remediation": null},
      {"group": "storage", "name": "storage.cas_sample", "status": "PASS", "reason": "ok", "detail": "verified 0/0 CAS blobs (0B)", "remediation": null},
      {"group": "permissions", "name": "permissions.tree", "status": "PASS", "reason": "ok", "detail": "owner-only tree and ancestors verified", "remediation": null}
    ],
    "remediations": [],
    "integrity_errors": [],
    "active_turn_intents": [],
    "incomplete_journals": [],
    "permission_problems": []
  }
}
```

## 3. Thao tác sửa an toàn

Cả CLI (`brain doctor --config|--profile <ABS> --fix`) lẫn API operator (`POST /v2/operator/doctor/fix`) đều yêu cầu credential operator của **chủ kho đã ghim** (`store_owner`). Operator thuộc principal khác (dù hợp lệ với `brain doctor` / `/v2/operator/doctor/report`) hoặc khi store chưa ghim `store_owner` đều bị từ chối fail-closed với mã `not_found` trước khi chạy bất kỳ thao tác nào. Lệnh `brain doctor … --fix` không chỉ định thao tác nên **mọi** thao tác dưới đây đều được chạy; muốn chỉ chạy một số thao tác thì gọi API operator với `{"actions": [...]}` (không được thêm khoá nào khác ngoài `actions` và `checkout_root`).

| Thao tác | Tác dụng | Ghi chú |
|---|---|---|
| `tighten_permissions` | Thu quyền của cây dữ liệu về chỉ owner | Không đi theo link; giữ nguyên byte của file |
| `reconcile_policy` | Đối soát policy intent đang chờ | Chạy lại check liên quan sau khi xong |
| `rebuild_projections` | Dựng lại projection trên vùng stage rồi swap | Crash trước khi swap thì projection cũ còn nguyên |
| `rotate_logs` | Xoay log | Giữ bản cũ; nếu filesystem bận thì báo lỗi, không mất byte |
| `replay_outbox` | Phát lại outbox capture theo hợp đồng ACK của SP2 | Không có adapter thì trả `capability_unavailable` |
| `restart_daemon` | Khởi động lại qua supervisor đã xác minh | Không có supervisor thì trả `capability_unavailable` |

Mỗi thao tác kiểm principal thuộc `store_owner` đã ghim (nếu lệch hoặc chưa ghim thì fail-closed với `not_found`), writer lease và đích vật lý ngay trước khi ghi, rồi trả kết quả riêng: `applied`, `noop`, `capability_unavailable` hoặc `failed`. Các thao tác sửa **không bao giờ** đổi config của harness, không xử lý ApplyJournal và không restore. Các việc đó đi qua entrypoint có cổng duyệt riêng.

## 4. Chạy nền

- **Lịch tự chạy:** daemon tự chạy doctor khi khởi động (trừ khi đã có run toàn kho hợp lệ trong vòng 24 giờ) và sau đó mỗi 24 giờ. Lịch chạy, deep health và lời gọi doctor online cùng chia một slot job cho mỗi scope.
- **Khi payload của job hỏng:** nếu blob payload bị mất, sai digest, sai loại, là link hoặc có quyền rộng, job doctor kết thúc ở `failed` dưới fence, người gọi nhận `integrity_failure`, và lượt hợp lệ kế tiếp vẫn chạy trong cùng epoch. Lỗi I/O tạm thì được retry có backoff, hết số lần thì vào `dead_letter`.
- **Khi lần ghi không rõ kết quả:** chỉ trạng thái bền mới quyết định. Runner giữ trách nhiệm với job cho tới khi hàng job xác nhận kết quả, và đánh thức daemon để thử lại khoảng mỗi 0,2 giây.
- **Sau restore:** báo cáo của kho hoặc epoch cũ không còn được dùng. Các job doctor cũ bị huỷ (`cancelled`).

## 5. Xử lý sự cố

| Triệu chứng | Làm gì |
|---|---|
| `daemon_unavailable` | Kiểm tra daemon bằng `brain status --profile <ABS>`. Chỉ đọc offline khi chắc chắn daemon đã dừng. |
| `store_busy` khi dùng `--offline` | Có tiến trình đang giữ writer lock. Dùng đường online, hoặc dừng daemon trước. |
| `identity_mismatch`, lỗi pin hay revoked | Không thử chạy offline thay thế; xác minh lại profile hoặc credential operator |
| `not_found` khi chạy `--fix` hoặc gọi `POST /v2/operator/doctor/fix` | Credential operator không thuộc chủ kho đã ghim (`store_owner`) hoặc kho chưa ghim `store_owner`; không có thao tác sửa nào được chạy. Đổi sang credential/profile của `store_owner` rồi thử lại. |
| `status: running` mãi không xong | Đọc lại theo `job_id`, rồi xem `get_health(deep=true)`. Job lỗi sẽ kết thúc ở `failed` hoặc `dead_letter` và không chặn lượt kế tiếp. |
| `permissions.tree` hay `storage.ledger_projection_match` FAIL | Dùng credential operator của `store_owner` đã ghim để chạy `brain doctor --config|--profile <ABS> --fix`, hoặc gọi API `POST /v2/operator/doctor/fix` với `tighten_permissions` hay `rebuild_projections` |
| Có Capture gap hoặc outbox còn tồn | Thao tác `replay_outbox` (cần adapter SP2) |

## 6. Bằng chứng nghiệm thu

Receipt gate nằm ngoài cây tracked: `.gate/receipt-<sha>-<python>-<platform>-*.json` trong checkout nghiệm thu, cùng thư mục `--evidence-dir` của mỗi lượt. Biên bản nghiệm thu I4 (fix note R1 tới R11 và A1/A2, ghi chú gói B, kế hoạch bàn giao `2026-11-25-sp1-increment4-acceptance-handoff.md`) nằm trong `docs/reviews/` và `docs/superpowers/plans/` của checkout điều phối.
