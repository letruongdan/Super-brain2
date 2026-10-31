# Bảng điểm crash của SP1 đợt 1

Tài liệu này là deliverable "bảng điểm crash" mà spec mục 5.4 yêu cầu. Mỗi crashpoint đã đăng ký trong
`superbrain.core.faults.KNOWN_CRASHPOINTS` có **đúng một dòng** ở các bảng dưới đây. Test
`tests/storage/test_crash_matrix.py::test_every_known_crashpoint_has_a_case_and_a_doc_row` đọc cột đầu tiên của mọi
bảng (tên crashpoint đặt trong backtick) và đòi tập tên đó bằng đúng `KNOWN_CRASHPOINTS`.

## Cách đọc bảng

- **Operation:** operation của `tests/support/crash_child.py` chạy trong tiến trình con và chết ở crashpoint đó.
- **Trước / sau crash:** trạng thái đĩa đã ACK trước khi operation bắt đầu, và trạng thái đĩa tiến trình chết để lại.
- **Đã ACK?:** operation đã trả kết quả thành công cho caller hay chưa. Crash luôn xảy ra trước khi operation trả về,
  nên câu trả lời là "chưa" cho toàn bộ operation; cột này nói rõ phần nào đã bền dù chưa ACK.
- **Phục hồi:** việc lần mở kế tiếp làm, theo thứ tự cố định của `open_runtime`: `prepare_data_root` →
  `acquire_writer` → `recover_interrupted_swaps` → mở policy store → mở kho (`Store.open` đối chiếu mọi intent).
- **CrashCase:** ca trong `tests/support/crash_cases.py::CRASH_CASES`, có id `operation@crashpoint` trong
  `test_crash_case`. Ca seed trạng thái đã ACK, cho tiến trình con chết với mã thoát 86 đúng ở điểm đó, mở lại
  data root rồi assert trạng thái **cụ thể**. `db_integrity() == "ok"` chỉ là kiểm tra bổ sung.
- **Tiến trình chết:** có test. Ngoài ca trong ma trận, cột này nêu test chuyên biệt có sẵn.
- **Mất điện:** **không** được chứng minh bằng test kill tiến trình. Lập luận dựa trên ngữ nghĩa OS đã chốt ở Task 5
  (port `DurablePublisher`). Mọi lần làm bền file của storage đi qua port (`write_new`, `flush_file`): `fsync`,
  hoặc `F_FULLFSYNC` trên macOS, hoặc `FlushFileBuffers` trên Windows. Trên POSIX, sau mỗi rename thư mục cha được
  sync. Filesystem không hỗ trợ `F_FULLFSYNC` thì lùi về `fsync`; filesystem không fsync được thư mục thì bước đó được
  bỏ qua. Trong cả hai trường hợp, phép thử của `durability()` báo `process_crash_durable` kèm lý do.
- **Rename trên Windows:** `MoveFileEx` với `MOVEFILE_WRITE_THROUGH`, trong cùng một volume NTFS. Cờ này cộng với
  journal metadata của NTFS là **cơ sở lập luận** rằng rename bền sau mất điện. Đó là lập luận, **không phải bảo
  đảm**: Windows không cam kết điều này thành văn, và chưa có phép thử mất điện nào kiểm chứng.
- SQLite chạy WAL với `synchronous=FULL`, trên macOS thêm `fullfsync=ON` và `checkpoint_fullfsync=ON`. Mọi lập luận
  chỉ đúng khi ổ đĩa tôn trọng lệnh flush và filesystem được báo `power_loss_durable`. Với `process_crash_durable`
  (ổ mạng, OneDrive, tmpfs…) chỉ có bảo đảm của cột "Tiến trình chết".

## Hai điều ghi rõ

- **GC và backup không để lại trạng thái pin.** GC và backup cùng chạy trên owner thread, nên tự tuần tự. Cờ
  `Store.maintenance()` không lồng được: gọi GC khi backup đang chạy trả `STORE_BUSY`. Không có bảng pin bền vững, nên
  crash giữa backup không để lại gì cần thu hồi (xem các dòng `backup.*`).
- **ApplyJournal thuộc đợt 3.** Bảng này chưa có dòng cho ApplyJournal. Đợt 3 thêm crashpoint và dòng tương ứng.

## Writer lock

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `writer.mid_slot_write` | `acquire_writer` | `writer.lock` có slot hợp lệ, epoch `e` | Slot cũ hơn bị ghi dở một nửa (CRC sai); slot kia còn nguyên | Chưa: lease chưa trả về | `acquire_writer` đọc slot hợp lệ có `seq` lớn nhất, bỏ slot rách, ghi epoch `e + 1` | Epoch không bao giờ lùi; một slot rách không làm mất trạng thái lock; cả hai slot hỏng → `integrity_failure` | `acquire_writer@writer.mid_slot_write`: epoch mở lại là `e + 1`, trust generation và HWM không đổi, ledger không đổi | Có test; thêm `test_writer.py::test_torn_slot_write_falls_back_to_other_slot` | Mỗi nửa slot được `write` rồi `full_fsync` (`F_FULLFSYNC` trên macOS). Mất điện chỉ có thể làm rách slot đang ghi; CRC32 loại nó và slot kia đã bền từ lần ghi trước |

## Ledger

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `ledger.before_commit` | `append_demo` | Kho rỗng, gắn với policy store | Transaction `BEGIN IMMEDIATE` dang dở trong WAL, chưa commit | Chưa | SQLite bỏ phần chưa commit khi mở | Một transaction: entry, projection và kết quả cùng commit hoặc không gì cả | `append_demo@ledger.before_commit`: ledger vẫn rỗng, epoch +2 | Có test; thêm `test_ledger.py::test_crash_before_commit_leaves_nothing` | WAL `synchronous=FULL`: frame chưa commit không bao giờ được coi là dữ liệu |
| `ledger.after_commit` | `append_demo` | Kho rỗng | Entry đã commit trong WAL; tiến trình chết trước khi trả về | Chưa ACK, nhưng đã bền | Mở lại thấy đúng một entry | Đã commit thì còn, không nhân đôi | `append_demo@ledger.after_commit`: đúng một entry `demo.count` với `n = 1` sau các entry cũ | Có test; thêm `test_ledger.py::test_crash_after_commit_keeps_entry` | Commit WAL với `synchronous=FULL` (cộng `fullfsync` trên macOS) đã flush trước khi `COMMIT` trả về |

## CAS

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `cas.after_staging_write` | `put_and_hold` | Kho rỗng | Một file `*.tmp` trong `store/staging/`, chưa có blob trong `cas/` | Chưa | `Store.open` xóa file dở trong `staging/` | Không có blob dở trong `cas/`, không có rác trong `staging/`, không có holder trỏ tới blob không tồn tại | `put_and_hold@cas.after_staging_write`: blob không tồn tại, `staging/` rỗng, không có orphan, ledger không đổi | Có test; thêm `test_cas.py::test_crash_after_staging_write_leaves_no_blob` | File staging chưa publish; mất điện có thể để lại file dở hoặc không có gì, và cả hai đều bị dọn khi mở |
| `cas.after_rename` | `put_and_hold` | Kho rỗng | Blob đã publish trong `cas/`, chưa có holder | Chưa: ref chỉ trả về sau transaction ghi holder | Blob là orphan; GC xóa sau thời gian chờ | Không có holder trỏ tới blob đã mất; orphan vô hại | `put_and_hold@cas.after_rename`: blob đọc được, là orphan duy nhất, không holder, ledger không đổi | Có test; thêm `test_cas.py::test_crash_after_rename_before_hold_leaves_orphan_only` | `durable_publish`: fsync nội dung, kiểm sha256, rename nguyên tử (`MOVEFILE_WRITE_THROUGH` trên Windows), sync thư mục. Mất điện trước khi sync thư mục: blob có thể chưa xuất hiện, tương đương crash trước rename; chưa có holder nên không mất gì đã ACK |

## Policy và kho

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `policy.after_intent_commit` | `tombstone_event` | Payload event được `("event", E1)` giữ | Intent TOMBSTONE đã commit trong policy store; kho chưa áp | Chưa ACK; intent đã bền | `Store.open` đối chiếu mọi intent với `applied_intents` và áp intent còn thiếu | Trạng thái bảo mật đi trước: intent đã ghi thì nội dung đã bị chặn và được áp đúng một lần; phục hồi không tạo mutation nào khác (tình huống 34) | `tombstone_event@policy.after_intent_commit`: một intent, `is_tombstoned`, holder bị gỡ, payload thành orphan, đúng một `policy.tombstone` và một `cas.release`, đối chiếu lại áp 0 | Có test; thêm `test_reconcile.py::test_crash_between_policy_and_store_applies_exactly_once` | Hai DB SQLite riêng, đều `synchronous=FULL`. Commit policy bền trước khi kho được chạm tới, nên mọi tổ hợp sau mất điện đều là "intent có, chưa áp" hoặc "đã áp" |
| `intents.after_store_apply` | `tombstone_event` | Như trên | Intent đã ghi và đã áp vào kho (cùng transaction với `applied_intents`) | Chưa ACK; cả hai phía đã bền | Đối chiếu thấy intent đã áp, không làm gì | Áp theo intent ID nên chạy lại không nhân đôi | `tombstone_event@intents.after_store_apply`: các assert giống dòng trên, cụ thể không có `policy.tombstone` hay `cas.release` thứ hai | Có test; thêm `test_reconcile.py::test_crash_after_store_apply_does_not_duplicate` | Như trên; `applied_intents` commit cùng transaction với hiệu lực của intent |

## Backup

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `backup.after_db_snapshot` | `backup_store` | Payload event được giữ | `backups/store-…/` có `brain.db`, chưa có `cas/` và `manifest.json` | Chưa | Không cần gì: kho không bị chạm, không có pin bền vững. Backup thiếu manifest không bao giờ verify; `prune_backups` đổi tên nó thành `*.incomplete` sau 24 giờ | Backup chỉ hợp lệ khi có manifest; kho nguồn không đổi | `backup_store@backup.after_db_snapshot`: event vẫn được giữ và đọc được, ledger không đổi, đúng một thư mục backup, có `brain.db`, không có `cas/` và manifest, `verify_backup` trả `integrity_failure` | Có test; thêm `test_backup.py::test_crash_mid_backup_leaves_incomplete_backup_that_never_verifies` | Manifest được publish cuối cùng qua port, nên sau mất điện backup vẫn thiếu manifest hoặc đầy đủ. Snapshot được làm bền bằng `flush_file` của port trong `_snapshot_db` |
| `backup.after_blob_copy` | `backup_store` | Như trên | Như trên, thêm `cas/` đã chép blob có holder | Chưa | Như trên | Như trên | `backup_store@backup.after_blob_copy`: như trên, nhưng `cas/` có trong backup dở | Có test; thêm test chuyên biệt như dòng trên | Blob được chép qua `write_new` của port; snapshot như dòng trên |

## Restore kho

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `restoring.store.after_stage` | `restore_from_latest` | Kho giữ `before` và `after`; backup chỉ có `before` | `store.restoring/` đầy đủ và có `READY`; `store/` nguyên vẹn | Chưa | `recover_interrupted_swaps`, dưới lease: target còn nguyên nên stage bị cất thành `store.restoring.abandoned-*` | Restore không bao giờ xóa dữ liệu; không tiến trình nào chạm `store*` trước khi có lease | `restore_from_latest@restoring.store.after_stage`: kho vẫn giữ cả `before` và `after`, có đúng một thư mục cất `store.restoring.abandoned`, mọi thư mục gốc còn dữ liệu, epoch +2 | Có test; thêm `test_restore.py::test_interrupted_restore_recovers_under_lease` | Stage dựng qua `write_new` của port; `READY` được làm bền rồi sync thư mục. Mỗi lần rename đều sync thư mục cha, nên sau mất điện đĩa ở một trong hai trạng thái mà recovery xử lý. Bản sao `brain.db` đi qua port, và snapshot nguồn đã được làm bền qua `flush_file` khi backup |
| `restoring.store.between_renames` | `restore_from_latest` | Như trên | `store/` đã đổi thành `store.replaced-*`; stage `READY` chưa được đổi thành `store/` | Chưa | Target vắng và stage `READY` nên recovery làm nốt rename thứ hai | Như trên; swap chỉ hoàn tất khi stage đã `READY` | `restore_from_latest@restoring.store.between_renames`: kho chỉ còn `before`, có đúng một thư mục `store.replaced`, dữ liệu cũ còn đó, epoch +2 | Có test; thêm test chuyên biệt như dòng trên và `test_restore.py::test_startup_of_second_process_never_touches_an_inflight_restore` | Như trên |

## Restore policy

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `restoring.policy.after_generation_persist` | `restore_policy_from_latest` | Trust generation `g = 5` bằng HWM; có policy backup ở `g` | `policy.restoring/policy.db` mang generation `g + 1`, chưa có `READY` | Chưa | Target còn nguyên nên stage bị cất thành `policy.restoring.abandoned-*` | Generation không bao giờ lùi hay bị dùng lại (I1-14, tình huống 32) | `restore_policy_from_latest@restoring.policy.after_generation_persist`: generation và HWM vẫn là `g`; stage bị cất mang `g + 1`, không được dùng; store và policy cùng `store_id`; epoch +2 | Có test; thêm `test_restore.py::test_policy_restore_crash_never_lowers_generation` | `_write_generation` làm bền `policy.db` đã stage bằng `flush_file` của port trước khi ghi `READY` |
| `restoring.policy.after_stage` | `restore_policy_from_latest` | Như trên | Stage `READY`, mang `g + 1`; `policy/` nguyên vẹn | Chưa | Như trên | Như trên | `restore_policy_from_latest@restoring.policy.after_stage`: như dòng trên | Có test; thêm test chuyên biệt như dòng trên | Như dòng trên; `READY` và các rename đi qua port |
| `restoring.policy.between_renames` | `restore_policy_from_latest` | Như trên | `policy/` đã thành `policy.replaced-*`; stage `READY` chưa công bố; HWM vẫn `g` | Chưa | Recovery công bố stage; `PolicyStore.open` thấy generation `g + 1` > HWM nên nâng HWM lên `g + 1` | Như trên; một restore tiếp theo luôn đi trên mọi generation trước đó | `restore_policy_from_latest@restoring.policy.between_renames`: generation và HWM là `g + 1`; thư mục `policy.replaced` mang `g`; epoch +2 | Có test; thêm test chuyên biệt như dòng trên và `test_restore.py::test_restore_after_a_crash_before_the_hwm_update_never_reuses_a_generation` | Như dòng trên |
| `restoring.policy.before_hwm_update` | `restore_policy_from_latest` | Như trên | Swap đã xong và epoch đã tăng; HWM trong lock vẫn `g` | Chưa | `PolicyStore.open` nâng HWM lên `g + 1` | Như trên | `restore_policy_from_latest@restoring.policy.before_hwm_update`: như dòng trên nhưng epoch +3 (swap đã tăng epoch) | Có test; thêm hai test chuyên biệt như dòng trên | Như dòng trên; HWM nằm trong slot lock được `full_fsync` |

## Migrate

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `migrating.store.after_stage` | `migrate_store_to_v2` | Kho schema v1 giữ payload event | Backup `store_full-*` đầy đủ; `store.migrating/` v2 có `READY`; `store/` v1 nguyên vẹn | Chưa | Stage bị cất thành `store.migrating.abandoned-*`; kho vẫn v1 | Migration không bao giờ tự chạy hay nửa vời; không ca nào được nới `ensure_writable` | `migrate_store_to_v2@migrating.store.after_stage`, mở bằng bộ migration v1: schema v1, event còn được giữ, ledger không đổi, backup `store_full` verify được. Sau khi đóng, mở bằng bộ có v2 trả `migration_required` | Có test; thêm `test_migrate.py::test_interrupted_migration_recovers` | Snapshot của backup bảo trì và file đã migrate trong stage đều được làm bền bằng `flush_file` của port trước khi ghi `READY` |
| `migrating.store.between_renames` | `migrate_store_to_v2` | Như trên | `store/` đã thành `store.replaced-*` (v1); stage v2 `READY` chưa công bố | Chưa | Recovery công bố stage v2 | Như trên; bản cũ được đổi tên, không xóa | `migrate_store_to_v2@migrating.store.between_renames`, mở bằng bộ có v2: schema v2, `store.replaced` là v1, event còn được giữ, ledger không đổi, backup verify được | Có test; thêm test chuyên biệt như dòng trên | Như dòng trên |
| `migrating.policy.after_stage` | `migrate_policy_to_v2` | Policy store v1, payload event bị quarantine (intent đã áp) | Backup `policy-*` đầy đủ; `policy.migrating/` v2 có `READY`; `policy/` v1 nguyên vẹn | Chưa | Stage bị cất thành `policy.migrating.abandoned-*` | Như dòng kho; quarantine không bao giờ bị mất qua migrate | `migrate_policy_to_v2@migrating.policy.after_stage`, mở bằng bộ v1: policy v1, quarantine còn hiệu lực (đọc trả `quarantined`, đối chiếu áp 0), generation và HWM không đổi, backup `policy` verify được. Sau khi đóng, mở bằng bộ có v2 trả `migration_required` | Có test (ma trận) | Như dòng kho |
| `migrating.policy.between_renames` | `migrate_policy_to_v2` | Như trên | `policy/` đã thành `policy.replaced-*` (v1); stage v2 `READY` chưa công bố | Chưa | Recovery công bố stage v2 | Như trên | `migrate_policy_to_v2@migrating.policy.between_renames`, mở bằng bộ có v2: policy v2, `policy.replaced` là v1, quarantine còn hiệu lực, generation không đổi | Có test (ma trận) | Như dòng kho |

## Bảo đảm của chính ma trận

- `test_every_known_crashpoint_has_a_case_and_a_doc_row`: mỗi crashpoint đã đăng ký có đúng một `CrashCase` và đúng một
  dòng trong tài liệu này.
- `test_crash_case`: mỗi ca phải chết với mã 86 **đúng** ở crashpoint của nó (`run_until_crash`).
- `test_matrix_detects_a_removed_crashpoint`: với `SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST=cas.after_rename`, tiến
  trình con chạy hết operation như thể lời gọi crashpoint đã bị xóa khỏi code, và ma trận fail. Biến này chỉ dùng để
  kiểm chứng harness, không có tác dụng gì khi không được đặt.
