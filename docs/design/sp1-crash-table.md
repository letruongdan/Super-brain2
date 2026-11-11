# Bảng điểm crash của SP1 (đợt 1 và kernel đợt 2)

Tài liệu này là deliverable "bảng điểm crash" mà spec mục 5.4 yêu cầu. Mỗi crashpoint đã đăng ký trong
`superbrain.core.faults.KNOWN_CRASHPOINTS` có **đúng một dòng** ở các bảng dưới đây. Test
`tests/storage/test_crash_matrix.py::test_every_known_crashpoint_has_a_case_and_a_doc_row` đọc cột đầu tiên của mọi
bảng (tên crashpoint đặt trong backtick) và đòi tập tên đó bằng đúng `KNOWN_CRASHPOINTS`, không trùng, và bằng đúng
tập tên của `CRASH_CASES` (đợt 1) cộng `KERNEL_CRASH_CASES` (đợt 2, Task 8).

## Cách đọc bảng

- **Operation:** operation của `tests/support/crash_child.py` chạy trong tiến trình con và chết ở crashpoint đó.
- **Trước / sau crash:** trạng thái đĩa đã ACK trước khi operation bắt đầu, và trạng thái đĩa tiến trình chết để lại.
- **Đã ACK?:** operation đã trả kết quả thành công cho caller hay chưa. Crash luôn xảy ra trước khi operation trả về,
  nên câu trả lời là "chưa" cho toàn bộ operation; cột này nói rõ phần nào đã bền dù chưa ACK.
- **Phục hồi:** việc lần mở kế tiếp làm, theo thứ tự cố định của `open_runtime`: `prepare_data_root` →
  `acquire_writer` → `recover_interrupted_swaps` → mở policy store → mở kho (`Store.open` đối chiếu mọi intent).
- **CrashCase:** ca trong `tests/support/crash_cases.py::CRASH_CASES`, có id `operation@crashpoint` trong
  `test_crash_case`; các dòng kernel dùng `KERNEL_CRASH_CASES` (xem mục kernel bên dưới). Ca seed trạng thái đã ACK, cho tiến trình con chết với mã thoát 86 đúng ở điểm đó, mở lại
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

## Kernel daemon và offline migrate (SP1 đợt 2, Task 8.1)

Ba dòng này là `KernelCrashCase` trong `tests/support/crash_cases.py::KERNEL_CRASH_CASES`, chạy bởi
`tests/integration/test_kernel_crash_recovery.py` với node ID `operation@crashpoint`. Operation là mode của
`tests/support/inc2_t8_child.py`, driver chạy bằng `python -I` trong venv của wheel đã cài và kiểm `superbrain.__file__`
nằm trong venv đó. Driver in `ENTERED <pid> <start>` lên stderr trước khi gọi owner operation; test đòi
`CRASHPOINT_HIT <tên>` và mã thoát 86 của chính lần gọi đó, `ENTERED` đứng trước hit, không có `READY`. Kiểm trạng thái
sau crash đọc thẳng `writer.lock`, `endpoint.json` và hai DB (qua `open_readonly`, kể cả khi hai schema lệch nhau), không
mở runtime. Restart, refuse và resume dùng `brain serve`, `brain migrate --offline` và `brain-mcp` đã cài.

| Crashpoint | Operation | Trước | Sau crash | Đã ACK? | Phục hồi | Invariant | CrashCase | Tiến trình chết | Mất điện |
|---|---|---|---|---|---|---|---|---|---|
| `daemon.after_bind_before_endpoint` | `serve` | Root (store v4, policy v3) có credential, workspace và hai job đã ACK; writer epoch `e`; `endpoint.json` của epoch `e` (instance cũ, port cũ) còn trên đĩa | Tiến trình đã lấy lease (epoch `e + 1`), mở runtime, phục hồi job, publish auth view trong RAM và bind listener loopback; chưa ghi stage hay `endpoint.json` mới, chưa ready. Lock được OS nhả khi tiến trình chết | Chưa: chưa có endpoint nên không client nào gửi được request | Không cần bước riêng: `endpoint.json` cũ chỉ là descriptor, không phải authority. Writer kế tiếp lấy epoch `e + 2`, instance mới, rồi thay descriptor | Endpoint chỉ được publish dưới lease đang giữ, mang đúng epoch của lease; tuple cũ không bao giờ được xác thực, kể cả khi port của nó được tái sử dụng | `serve@daemon.after_bind_before_endpoint`: `endpoint.json` vẫn đúng bytes của epoch `e`, không còn `endpoint.json.stage-*`, ledger và `applied_intents` không đổi, lock epoch `e + 1` và không bị giữ. Tuple cũ hỏi `get_health` trả `daemon_unavailable` hoặc `identity_mismatch`. `brain serve` restart: endpoint epoch `e + 2`, instance khác, bytes khớp; tuple cũ trỏ vào port của daemon mới trả `identity_mismatch`; `brain-mcp` trả shallow `get_health` ready với cùng `store_id`/epoch và `get_job` của job đã ACK; owner thứ hai bị fence `writer_held` và không phát hit; sau khi dừng, endpoint bị gỡ và các entry đã ACK vẫn là tiền tố của ledger | Có test (process thật từ wheel); thêm `test_kernel_daemon.py::test_epoch_and_instance_change_after_kill` cho kill sau ready | Không có ghi bền nào giữa bind và publish. Epoch `e + 1` nằm trong slot lock đã `full_fsync` trước khi lease trả về, nên sau mất điện epoch kế tiếp vẫn lớn hơn mọi epoch đã dùng. `endpoint.json` cũ còn nguyên hoặc vẫn là bản trước đó; client luôn kiểm identity sống qua TLS trước khi gửi credential |
| `daemon.after_endpoint_publish` | `serve` | Như trên, không có `endpoint.json` | `endpoint.json` mang epoch `e + 1`, instance và port của tiến trình chết đã được publish (stage, `secure_file`, `flush_file`, rename); chưa ready, worker chưa chạy | Chưa ACK request nào; descriptor đã bền | Writer kế tiếp lấy epoch `e + 2` và thay descriptor bằng bản của mình; descriptor của tiến trình chết không bao giờ được xác thực lại | Như dòng trên; descriptor còn lại sau crash chỉ là một tuple cũ | `serve@daemon.after_endpoint_publish`: descriptor đọc được, `store_id` của root, epoch `e + 1`, không còn stage, ledger không đổi. Tuple đó fail closed trước restart, và trả `identity_mismatch` khi trỏ vào port của daemon mới. Restart, shim, fence và kiểm ACK như dòng trên | Có test (process thật từ wheel) | Descriptor đi qua port `DurablePublisher` như mọi file bền khác, nên sau mất điện hoặc chưa có hoặc có đầy đủ. Cả hai trường hợp đều là tuple không có tiến trình sống; client kiểm identity trước khi gửi bearer |
| `kernel.migrate.after_policy_swap` | `migrate` | Cặp đợt 1: store v2 (hai blob bền, một intent QUARANTINE đã áp), policy v2 (principal, credential đang hoạt động, request digest key, trust generation) | `migrate_database` đã publish policy v3 (backup `policy-*` và `policy.replaced-*` v2 còn lại); store vẫn v2, chưa có `store.migrating*` hay `store.replaced*`. Không in envelope | Chưa: lệnh migrate chưa trả kết quả | `brain serve` từ chối `migration_required`, không publish endpoint, không đổi schema hay dữ liệu. `brain migrate --offline --config …` chạy lại: policy `skipped` 3→3, store `migrated` 2→4. Lần lặp lại là no-op, cả hai `skipped` | Migration không tự chạy và không nửa vời được dùng: cặp lệch schema không bao giờ được serve; resume chỉ chạy phần còn thiếu; ID, intent và authority giữ nguyên qua crash và resume; hook chỉ phát sau khi policy thực sự được migrate trong lần chạy đó | `migrate@kernel.migrate.after_policy_swap`: schema (policy, store) = (3, 2), chỉ có `policy.replaced` bị cất, ledger/`applied_intents`/intents/quarantine/trust/principal/credential/request key bằng đúng lúc seed. `brain serve` thoát 1 với `migration_required` và stdout rỗng. Resume và lần lặp chạy **vẫn đặt** `SUPERBRAIN_CRASHPOINT=kernel.migrate.after_policy_swap`, thoát 0, stderr rỗng (không hit), schema (3, 4), dữ liệu bằng lúc seed. `brain serve` sau đó ready và dừng sạch | Có test (process thật từ wheel); thêm `test_kernel_cli.py::test_installed_migrate_respects_offline_lease` cho đường không crash | Swap policy đi qua stage `READY`, rename có sync thư mục và backup đã làm bền (như các dòng `migrating.policy.*`), nên sau mất điện policy là v2 hoặc v3 đầy đủ. Store v2 chưa bị chạm. Mọi tổ hợp (v2, v2) và (v3, v2) đều bị serve từ chối và được `migrate --offline` đưa về (v3, v4) |

## Bảo đảm của chính ma trận

- `test_every_known_crashpoint_has_a_case_and_a_doc_row`: mỗi crashpoint đã đăng ký có đúng một ca (`CrashCase` hoặc
  `KernelCrashCase`) và đúng một dòng trong tài liệu này, không tên nào trùng.
- `test_registry_is_exactly_the_increment_1_names_plus_the_task_8_1_names`: registry bằng đúng 19 tên đợt 1 cộng 3 tên
  của Task 8.1; 19 ca đợt 1 giữ nguyên node ID. Phần 8.3 nâng tập này lên đủ 10 tên Task 8 (tổng 29).
- `test_crash_case`: mỗi ca phải chết với mã 86 **đúng** ở crashpoint của nó (`run_until_crash`).
- `test_matrix_detects_a_removed_crashpoint`: với `SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST=cas.after_rename`, tiến
  trình con chạy hết operation như thể lời gọi crashpoint đã bị xóa khỏi code, và ma trận fail. Biến này chỉ dùng để
  kiểm chứng harness, không có tác dụng gì khi không được đặt.
