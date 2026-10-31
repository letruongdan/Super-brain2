# Bàn giao SP1 đợt 1: nền tảng storage

> **Trạng thái (2026-10-31): CHƯA ĐÓNG NGHIỆM THU.**
>
> Review triển khai `docs/reviews/2026-10-31-sp1-increment1-implementation-review.md` đã tái hiện bảy lỗi, SP1-C01 đến C07, trong đó bốn lỗi P1. Review này chạy trên Windows và trên Linux (WSL).
>
> Gate chạy lại trong môi trường Codex trên Windows **không được chấp nhận**. Gate trên Linux cũng **không được chấp nhận**, vì `mypy` fail.
>
> Các receipt `accepted: true` liệt kê bên dưới chỉ chứng minh những lần chạy trước đó, trong môi trường lúc ấy. Chúng không đóng được nghiệm thu đợt 1. Đợt 1 chỉ đóng khi việc khắc phục C01 đến C07 qua đủ RED, GREEN, mutation, review độc lập và các gate bắt buộc, với snapshot source khớp.

Tài liệu này làm theo mục "Bàn giao đợt 1" của plan
`docs/superpowers/plans/2026-10-30-sp1-increment1-storage-foundation.md`. Nó tách rõ phần **đã nghiệm thu**, có bằng
chứng đi kèm, với phần **chưa nghiệm thu**. Phần chưa nghiệm thu không được ghi là "verified" ở bất kỳ đâu.

## 1. Đã nghiệm thu

### 1.1. Receipt của gate mặc định

Gate chạy bằng `scripts/gate.py` trên Windows 11, trong một worktree niêm phong tại đúng commit, với working tree
sạch. Gate gồm bốn phase bắt buộc: `ruff`, `mypy`, `lint-imports`, `pytest`.

Hai receipt dưới đây gắn với commit **`1dfd9e5118f09d96047ba44708afc9cffc258a5e`**. Đó là commit cuối cùng có thay
đổi code hoặc test của đợt 1.

| Python | Receipt | `accepted` | `reasons` | Kết quả test |
|---|---|---|---|---|
| CPython 3.11.9 | `.gate/receipt-1dfd9e5118f0-cpython3.11.9-win32-8e5b9291a873.json` | `true` | `[]` | 778 passed, 7 skipped, 0 failed, 0 error |
| CPython 3.14.3 | `.gate/receipt-1dfd9e5118f0-cpython3.14.3-win32-8e5b9291a873.json` | `true` | `[]` | 778 passed, 7 skipped, 0 failed, 0 error |

Cả hai receipt có `tree_clean: true`, cùng `lock_digest` `sha256:8e5b9291a873…`, cùng `test_count` 785. Mọi phase
trả mã thoát 0.

**Commit chứa tài liệu này.** Commit đó là con trực tiếp của `1dfd9e5`, và chỉ thêm đúng file này. Gate được chạy lại
trên chính commit chứa tài liệu này, cho cả hai bản Python. Receipt của lần chạy đó nằm ở
`.gate/receipt-<12 ký tự đầu của commit chứa tài liệu này>-cpython3.11.9-win32-8e5b9291a873.json` và
`…-cpython3.14.3-win32-8e5b9291a873.json`. Có thể kiểm lại bằng `git diff --stat 1dfd9e5 <commit>`: lệnh này chỉ
liệt kê file này. Tài liệu không chép SHA của chính commit chứa nó, vì SHA đó phụ thuộc vào nội dung tài liệu. Báo
cáo sửa cuối (`final-fix-report.md`) ghi lại SHA và hai receipt đó.

`.gate/` nằm trong `.gitignore`, nên receipt chỉ có trên máy đã chạy gate. CI chưa chạy gate (xem mục 2).

### 1.2. Bảng điểm crash

- `docs/design/sp1-crash-table.md` có đúng một dòng cho mỗi crashpoint trong `KNOWN_CRASHPOINTS`.
- `tests/support/crash_cases.py::CRASH_CASES` có đúng một ca cho mỗi crashpoint. Ca seed trạng thái đã ACK, giết
  tiến trình con bằng mã thoát 86 đúng ở điểm đó, mở lại data root rồi assert trạng thái cụ thể.
- `tests/storage/test_crash_matrix.py::test_every_known_crashpoint_has_a_case_and_a_doc_row` kiểm sự khớp giữa ba
  nguồn trên. `test_crash_case` chạy mọi ca. `test_matrix_detects_a_removed_crashpoint` chứng minh ma trận phát hiện
  một crashpoint bị gỡ.
- Cột "Mất điện" của bảng chỉ là **lập luận**, không phải bằng chứng (xem mục 2).

### 1.3. Tình huống nghiệm thu được test phủ

Đánh số theo spec mục 20. Mọi test dưới đây xanh trong cả hai receipt ở mục 1.1.

| Tình huống | Mức phủ | Test |
|---|---|---|
| 26: binary gặp schema mới hơn thì từ chối ghi | Phủ đủ | `test_schema.py::test_newer_schema_is_never_writable_even_if_readable`, `test_runtime.py::test_runtime_forwards_store_migrations` |
| 34: crash giữa commit policy và commit kho | Phủ đủ | `test_reconcile.py::test_crash_between_policy_and_store_applies_exactly_once`; ca `policy.after_intent_commit` và `intents.after_store_apply` của ma trận crash |
| 5: kill ở mọi điểm crash | Phần storage | `test_crash_matrix.py::test_crash_case` (mọi crashpoint), `test_ledger.py::test_crash_after_commit_keeps_entry`, `test_cas.py::test_crash_after_rename_before_hold_leaves_orphan_only` |
| 6: replay không nhân đôi, không phục sinh | Phần storage | `test_ledger.py::test_rebuild_reproduces_projection_without_duplicates`, `test_retention.py::test_rebuild_does_not_resurrect_expired_holder`, `test_cas.py::test_tombstoned_holder_is_skipped_and_replay_applies_new_tombstones`, `test_cas.py::test_quarantine_is_checked_before_existence_and_hash` |
| 7: snapshot đúng thì khôi phục, sai thì từ chối trước khi thay | Phần storage | `test_backup.py::test_store_backup_round_trips_and_survives_live_gc`, `test_restore.py::test_restore_of_wrong_store_is_refused_before_touching_store_dir`, `test_restore.py::test_unverifiable_full_backup_is_not_restored`, `test_restore.py::test_backup_changed_after_verification_is_not_published` |
| 8: không bao giờ có hai chủ ghi hợp lệ | Phần storage | `test_writer.py::test_second_process_cannot_acquire_while_held`, `test_runtime.py::test_runtime_holds_the_writer_lock`, `test_runtime.py::test_maintenance_lease_opens_no_database`, `test_writer.py::test_release_with_open_handles_is_refused_and_keeps_the_lock`, `test_runtime.py::test_releasing_the_lease_under_open_stores_is_refused`, `test_runtime.py::test_stores_refuse_work_once_their_lease_was_released` |
| 21: restore không thay `writer.lock`; tombstone và quarantine mới hơn được áp lại | Phần storage (tombstone/quarantine) | `test_restore.py::test_restore_reapplies_newer_tombstone_and_quarantine`, `test_restore.py::test_restore_keeps_lock_object_identity`, `test_restore.py::test_startup_of_second_process_never_touches_an_inflight_restore` |
| 25: blob dùng chung; backup cũ restore được sau GC | Phần storage | `test_cas.py::test_shared_blob_has_independent_holders`, `test_backup.py::test_store_backup_round_trips_and_survives_live_gc` |
| 28: quyền rộng hơn owner-only bị phát hiện | Phần storage (hàm kiểm tra quyền, nhánh Windows) | `test_permissions.py::test_everyone_ace_is_reported`, `test_permissions.py::test_unsecured_nested_entry_is_found_recursively`, `test_layout.py::test_prepare_refuses_an_existing_entry_others_can_access`, `test_layout.py::test_secure_subdirectories_refuses_an_existing_loose_subdirectory` |
| 32: generation không bao giờ lùi hay bị dùng lại | Phần storage (`trust_generation`) | `test_restore.py::test_policy_restore_crash_never_lowers_generation`, `test_restore.py::test_restore_after_a_crash_before_the_hwm_update_never_reuses_a_generation`, `test_restore.py::test_successive_policy_restores_strictly_increase_generation`, `test_policy_store.py::test_create_starts_strictly_above_the_lock_hwm` |
| 35: payload nhỏ hết hạn đúng hạn, không vào ledger | Phần Event | `test_retention.py::test_small_event_payload_expires_and_never_reaches_ledger` |

Đường dẫn test tính từ `tests/storage/` hoặc `tests/adapters/`.

### 1.4. Đợt sửa cuối (review toàn nhánh)

Các mục review cuối đã sửa, mỗi mục có test đỏ trước khi sửa và xanh sau khi sửa:

- **I1, một chủ ghi xuyên module:** `WriterLease.release()` từ chối khi còn handle mở. `Store` và `PolicyStore` từ
  chối mọi thao tác khi lease đã nhả.
- **I2, một cách ánh xạ đĩa đầy:** `storage/errors.py` gom `os_error` và `sqlite_error`. `ENOSPC`, `EDQUOT`,
  `ERROR_DISK_FULL` và `SQLITE_FULL` đều thành `storage_full` ở mọi điểm review liệt kê.
- **I3, fsync không được hỗ trợ:** nếu filesystem không hỗ trợ `F_FULLFSYNC` thì lùi về `fsync`. Nếu không fsync
  được thư mục thì bỏ qua bước đó. Phép thử `durability()` báo cả hai trường hợp là `process_crash_durable`.
- **I4, `expires_at` naive từ API public:** trả `invalid_input`.
- **`flush_file`:** mọi lần làm bền file trong `backup`, `restore` và `migrate` đi qua port `DurablePublisher`.
- **M1:** policy store mới bắt đầu ở `hwm + 1`.
- **M3:** `prune_backups` cần lease.
- **M9:** mất `brain.db` khi còn lịch sử (intent, hoặc backup kho đầy đủ) thì bị từ chối.

### 1.5. Ghi chú hành vi và giới hạn sau khắc phục C01–C08

Mục này chỉ ghi hành vi và giới hạn đã biết. Nó không phải claim nghiệm thu: đợt 1 vẫn chưa đóng (xem đầu tài liệu).

- **Restore từ chối blob backup không owner-only (C04).** Mọi blob được đọc hay chép (`put`, `read`, GC, `copy_blobs`,
  kể cả khi restore từ `backup/cas`) phải là file thường, không phải link/junction/reparse point, và chỉ owner truy
  cập được (mục 5.9: toàn bộ data root, gồm `backups/`). Backup do brain tạo luôn owner-only. Backup được chép vào từ
  nơi khác với ACL/mode của người khác (ví dụ `cp -p`, `robocopy /COPYALL`) bị từ chối với `insecure_permissions`.
  Brain không tự sửa quyền: người dùng phải đặt lại quyền owner-only rồi chạy lại. `verify_backup` cũng từ chối
  backup có shard hoặc blob là link/junction/reparse point (`integrity_failure`), và không đọc gì ngoài backup.
- **Mất `brain.db` (C02).** Policy store giữ marker bền `meta.store_published`. Marker được ghi sau lần
  `Store.create` công bố thành công đầu tiên, và được ghi lại (idempotent) sau mỗi lần `Store.open` thành công.
  Khi `brain.db` mất mà marker đã có, hoặc còn intent, backup kho đầy đủ hay nội dung trong `cas/`, thì `open_runtime`
  từ chối với `integrity_failure` và không tạo DB thay thế. Crash sau khi công bố nhưng trước khi ghi marker vẫn mở
  được ở lần khởi động sau, và lần đó ghi marker.
  **Giới hạn:** nếu mất **cả** `policy.db` lẫn `brain.db` thì marker và intent mất theo. Khi đó chỉ còn nội dung trong
  `cas/` hoặc một backup kho đầy đủ (`store`/`store_full`) chặn được việc tạo DB mới. Nếu không còn tín hiệu nào trong
  số đó, data root trông như mới và trường hợp này không phát hiện được.
  `restore_policy` không mang `meta.store_published` sang policy store được khôi phục: policy store khôi phục từ một
  backup chụp trước lần công bố đầu tiên mất tín hiệu này, cho tới lần `Store.open` thành công kế tiếp. Việc này để
  lại cho đợt 2 (quyết định của controller trong ledger).
- **Bản sao đọc tạm `<db>.reading-*` (C01).** Khi có `-wal` mà thiếu `-shm`, `open_readonly` đọc qua một bản sao
  riêng cạnh DB rồi xóa nó. Nếu tiến trình chết giữa chừng, bản sao còn lại. `open_runtime` xóa các bản sao này dưới
  lease ở lần mở sau, chỉ xóa thư mục thật, không đi theo link.
- **TODO đợt 2 (C03, hiệu năng):** mỗi lần mở, `check_history` chạy `GROUP BY kind` trên toàn ledger (cột `kind`
  chưa có index). Chấp nhận được với kích thước đợt 1. Đợt 2 xem xét index `(kind, handler_version)` hoặc high-water
  theo kind giữ trong `meta`, cập nhật trong transaction append.

## 2. Chưa nghiệm thu

Các mục dưới đây **chưa nghiệm thu**. Không mục nào được coi là "verified".

- **CI trên macOS và Linux.** Repo chưa có remote, nên `.github/workflows/ci.yml` chưa từng chạy. Mọi receipt ở mục
  1.1 chỉ là của Windows.
- **Độ bền khi mất điện.** Chỉ có lập luận theo ngữ nghĩa OS, ghi ở `docs/design/sp1-crash-table.md`. Chưa có phép thử
  mất điện nào. Riêng rename trong cùng volume trên Windows dựa vào `MOVEFILE_WRITE_THROUGH` cộng với journal của NTFS.
  Đó là cơ sở lập luận, không phải bảo đảm.
- **Tình huống 21, phần credential:** thu hồi credential thuộc đợt 2–3.
- **Tình huống 32, phần nonce và chữ ký:** thuộc đợt 2–3. Đợt 1 chỉ phủ `trust_generation`.
- **Tình huống 35, phần Evidence:** chính sách tham chiếu evidence thuộc SP2/SP3. Đợt 1 chỉ phủ Event.
- **Tình huống 28, phần `doctor` và `--fix`:** thuộc đợt 4. Đợt 1 chỉ có hàm kiểm tra quyền.
- **Mọi nhánh POSIX chưa từng được chạy ở bất kỳ đâu.** Máy duy nhất đã chạy test là Windows, và chưa có CI. Code
  POSIX có trong repo, nhưng chưa có lần chạy nào chứng minh nó đúng:
  - `PosixPermissionGuard` (chmod `0700`/`0600`, kiểm tổ tiên ghi được cho người khác, ngoại lệ sticky bit);
  - khóa `flock` của `writer.lock`;
  - fsync thư mục thật trên POSIX, gồm cả cách xử lý `EINVAL`/`ENOTSUP`/`ENOSYS`/`EBADF`;
  - phép dò filesystem qua `/proc/self/mountinfo` (Linux) và `statfs` (macOS), cùng `F_FULLFSYNC` thật trên macOS;
  - 7 test bị skip trên Windows:
    `test_durable.py::test_sync_directory_io_error_is_brain_error`,
    `test_durable.py::test_sync_directory_missing_directory_is_brain_error_on_posix`,
    `test_permissions.py::test_posix_secure_modes`,
    `test_permissions.py::test_group_readable_file_is_reported`,
    `test_permissions.py::test_world_writable_ancestor_without_sticky_is_reported`,
    `test_permissions.py::test_sticky_world_writable_ancestor_is_accepted`,
    `test_layout.py::test_prepare_sets_owner_only_umask`.

  Một số test trên Windows giả lập lỗi của `fcntl`/`fsync` để kiểm logic lùi về `fsync` và bỏ qua fsync thư mục. Các
  test đó chỉ kiểm logic ánh xạ lỗi. Chúng không chứng minh hành vi của hệ điều hành POSIX thật.
