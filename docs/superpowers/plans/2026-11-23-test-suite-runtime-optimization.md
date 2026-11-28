# Tối ưu thời gian toàn bộ bộ test để gate Windows đạt dưới 275 s — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Trước khi sửa bất kỳ test nào, đọc đủ `skills/review-lens/SKILL.md` và `C:/Users/letru/.agents/skills/bug-proof-testing/SKILL.md` (hoặc `skills/bug-proof-testing/SKILL.md`).

**Goal:** Đưa `test_job_seconds` của `scripts/gate.py` (từ preflight đến hết pytest, 6 shard) xuống **dưới 275 s trên Windows local cho cả Python 3.11 và 3.14**, kể cả ở lượt máy chậm, mà **không** xóa, skip, xfail hay làm yếu bất kỳ test nào, và **không** đổi số shard, ngân sách hay trần 300 s.

**Bối cảnh:** Gate SP2-3 r11 ở commit `e4f4163` không đạt ([báo cáo gate](../../reviews/2026-11-23-sp2-3-r11-windows-gate.md)). Owner chốt ngày 2026-11-23: giảm chi phí, giữ ngân sách. Số đo trên cùng code `e4f4163`:

| Lượt | Tổng thời gian test (JUnit) | Mỗi shard | Phần trước pytest |
|---|---:|---:|---:|
| Gate Codex 3.14 (lượt đầu) | 1317 s | 200–236 s | ~51 s |
| Chẩn đoán 3.14 (không giới hạn) | 1617 s | 271–298 s | ~36 s |
| Chẩn đoán 3.11 (không giới hạn) | 1507 s | 240–276 s | ~31 s |

Cùng code nhưng tổng dao động khoảng 23%; phần tăng nằm ở các test sinh nhiều tiến trình con (crash, wheel, CLI). 50 file nặng nhất (≥ 8 s) chiếm 1322/1617 s.

**Bài toán ngân sách:** Muốn dưới 275 s trong lượt chậm với phần trước pytest khoảng 36–51 s, shard nặng nhất phải ≤ 220 s. Với 6 shard cân bằng, tổng JUnit của lượt chậm phải ≤ khoảng 1200 s, tức giảm **≥ 420 s (≈ 26%) so với 1617 s**. Bảng mục tiêu ở Task 2 cộng lại giảm 437 s.

**Nguồn dữ liệu:**
- JUnit gate: `C:/Users/letru/sb2-trusted-local/evidence/sp2-3-r11-mwspq71y/gate-3.14/attempt-20261123T033554876756Z-e8a2edc7/`.
- JUnit chẩn đoán: `C:/Users/letru/sb2-trusted-local/evidence/claude-r11-diag/py3.14/` và `py3.11/`.
- Script chẩn đoán: Phụ lục A.

**Tech Stack:** Python 3.11/3.14, `uv`, pytest (JUnit XML), Windows 11, gate `scripts/gate.py` (6 shard, `TEST_JOB_BUDGET_S = 300`), `.verification/test_lock.py` (seal).

---

## Quy tắc bắt buộc (áp dụng cho mọi task)

1. **Không làm yếu oracle.** Không xóa, skip, xfail, đổi assert thành lỏng hơn, giảm giá trị biên (ví dụ `1024` trong `test_job_accounting_includes_invocation_after_1024`), giảm số lần lặp chứng minh một bất biến, hay thay tiến trình thật bằng mock khi chính tiến trình thật là đối tượng test (crash, signal, ACL, wheel đã cài, CLI đã cài, Windows handle).
2. **Không đổi runner để tạo pass.** Không đổi `--shards`, `TEST_JOB_BUDGET_S`, `PHASE_TIMEOUTS_S`, thứ tự phase hay cách tính `test_job_seconds` trong `scripts/gate.py`. Ngoại lệ duy nhất là Task 5 (cập nhật `_HEAVY_FILE_COST_MS`) và Task 4 (chỉ làm sau khi reviewer duyệt).
3. **Inventory giữ nguyên.** Tập node ID của `pytest --collect-only -q` trước và sau phải bằng nhau. Nếu cần tách hoặc gộp test, phải có bảng ánh xạ cũ → mới và reviewer duyệt trước; mỗi node cũ phải có node mới kiểm cùng điều kiện.
4. **Seal.** Mọi file dưới `tests/`, `scripts/`, `pyproject.toml`, `uv.lock` nằm trong seal (`.verification/test_lock.py`). Mỗi thay đổi test là thay đổi oracle; chỉ reviewer độc lập (Codex) được duyệt reseal. Gửi mỗi batch kèm fix note theo `skills/review-lens/SKILL.md`.
5. **Độc lập test.** Fixture dùng chung chỉ được chia sẻ **vật liệu bất biến** (wheel đã build, venv đã cài, cặp khóa TLS, data root mẫu đã đóng). Mỗi test nhận bản sao riêng của mọi thứ nó ghi. Không có test nào phụ thuộc thứ tự chạy.
6. **Không có commit tự ý.** Chỉ commit khi owner yêu cầu, không thêm dòng attribution.
7. **Số đo phải là cặp A/B cùng phiên** (Phụ lục B). Không so số của hai ngày khác nhau.

---

## Tiêu chí nghiệm thu chung cho mỗi file test (áp dụng cho từng dòng T01–T50)

Một file chỉ được đánh dấu xong khi có đủ **tất cả** các mục sau trong ledger:

- **A1 · Inventory:** `pytest --collect-only -q <file>` trước và sau cho cùng tập node ID (diff rỗng), hoặc có bảng ánh xạ đã được duyệt.
- **A2 · Assert không lỏng hơn:** diff của file không xóa hay nới bất kỳ `assert`, `pytest.raises`, giá trị kỳ vọng, timeout dùng làm điều kiện test (ví dụ trần `< 1.0 s` của `READY`, trần 2 s của hook), hay tham số biên. Reviewer kiểm diff từng file theo checklist này.
- **A3 · Bằng chứng còn bắt lỗi:** với mỗi test có thay đổi cơ chế setup, wait hay fixture, chạy ít nhất một mutation cô lập trên mã sản phẩm mà test đó phải bắt; ghi kết quả `KILLED` vào receipt. Ưu tiên mutant đã có trong các receipt cũ (`.superpowers/sdd/**/*mutation-receipt*.json`) nếu đúng test.
- **A4 · Ổn định:** file pass 3/3 lần liên tiếp **dưới tải đầy đủ** (chạy trong lượt chẩn đoán 6 shard ở Phụ lục A) trên cả 3.11 và 3.14, không có cảnh báo cleanup mới.
- **A5 · Thời gian:** trong cặp A/B cùng phiên (Phụ lục B), tổng thời gian JUnit của file ở lượt sau ≤ cột **Target** của bảng Task 2, quy theo tỉ lệ máy: `target_phiên = target_bảng × (tổng_baseline_phiên / 1617)` cho 3.14 và `× (tổng_baseline_phiên / 1507)` cho 3.11. Nếu không đạt, phải có ghi chú "no-go có chứng cứ": profile (`--durations`, `-X importtime`, hoặc đếm tiến trình con) cho thấy phần còn lại là chính đối tượng test.
- **A6 · Ca chậm nhất:** ca chậm nhất của file (cột "Slowest case") phải giảm ít nhất cùng tỉ lệ Cut, hoặc có ghi chú no-go như A5.
- **A7 · Toàn bộ suite:** sau mỗi batch, full suite serial vẫn xanh (`uv run --locked pytest -q -p no:cacheprovider`), `mypy --strict`, `ruff check src tests scripts`, `lint-imports` sạch, không file `.py` nào bị đổi sang CRLF.

---

## Kỹ thuật được phép (chọn theo từng file)

| Mã | Kỹ thuật | Khi nào dùng | Điều kiện an toàn |
|---|---|---|---|
| K1 | Đưa vật liệu bất biến lên fixture `scope="session"` hoặc cache theo khóa (như `open_cloned_runtime`, `inc2_installed_env`, `inc2_tls_material`) | Test tự build wheel, tạo venv, sinh khóa TLS (`create_store_tls`) hoặc dựng data root từ đầu mỗi lần | Test nhận bản sao riêng; cache có khóa theo mọi tham số ảnh hưởng nội dung; không cache thứ test sẽ ghi |
| K2 | Thay `sleep`/poll cố định bằng chờ theo sự kiện (Event, file xuất hiện, dòng log, `READY` callback) | Test có `time.sleep`, poll với chu kỳ dài, hoặc chờ đủ timeout mới kết luận "không xảy ra" | Ca kết luận "không xảy ra" vẫn phải chờ đủ cửa sổ do spec quy định; chỉ rút ngắn phần chờ "đã xảy ra" |
| K3 | Bỏ setup trùng lặp trong ma trận crash: dựng trạng thái tiền-crash một lần rồi sao chép cho từng crashpoint | Ma trận `crash@point` dựng lại cùng kho/wheel cho mỗi điểm | Mỗi crashpoint vẫn crash một tiến trình thật tại đúng điểm đó; bản sao phải là thư mục riêng |
| K4 | Biên dịch bytecode một lần cho venv test tạo ra (`python -m compileall` lúc tạo venv session) | Test chạy CLI/wheel đã cài nhiều lần | Không đổi nội dung cài; chỉ thêm `.pyc` |
| K5 | Gộp nhiều lần khởi động tiến trình con chỉ để đọc một giá trị tĩnh thành một lần | Test gọi subprocess lặp lại để lấy cùng thông tin không đổi | Không áp dụng khi mỗi lần gọi là một kịch bản khác nhau |
| K6 | Giảm kích thước dữ liệu không phải đối tượng test | Payload lớn, nhiều bản ghi đệm không liên quan đến biên đang kiểm | Giữ nguyên mọi giá trị biên và số lượng mà spec hoặc tên test nêu |
| K7 | Chạy phần logic thuần trong tiến trình test thay vì tiến trình con | Assert thuần dữ liệu đang được kiểm qua subprocess chỉ vì tiện | Không áp dụng cho test có tiến trình thật là đối tượng (crash, signal, CLI đã cài, ACL) |

Kỹ thuật **cấm**: giảm parametrize, gộp ca biên, nới timeout làm điều kiện, mock tiến trình thật là đối tượng, `pytest.mark.skipif` theo thời gian/tải, đổi thứ tự để mượn trạng thái của test khác.

---

## Task 0: Đo baseline cặp A/B và khóa môi trường đo

**Files:** không đổi file repo; script ở Phụ lục A đặt ngoài repo.

- [x] **Step 1:** Tạo worktree tách rời tại commit nền (commit SP2-3 cuối cùng được duyệt; hiện là `e4f4163`) trong `C:/Users/letru/sb2-trusted-local/gate-temp/`. Đặt `LOCALAPPDATA=C:/Users/letru/sb2-trusted-local`, `TEMP`/`TMP` vào `gate-temp`.
- [x] **Step 2:** Chạy Phụ lục A cho 3.14 rồi 3.11, ghi `timings.json` và JUnit vào `evidence/opt-baseline-<ngày>/`.
- [x] **Step 3:** Ghi vào ledger: tổng JUnit, từng shard, phần trước pytest, danh sách test fail dưới tải (nếu có).

**Nghiệm thu Task 0:** có JUnit đủ 6 shard cho cả hai Python; tổng và từng file được ghi kèm đường dẫn file bằng chứng.

## Task 1: Ổn định các test đang fail hoặc chập chờn dưới tải

Phải xong trước Task 2, vì test chập chờn làm hỏng mọi số đo.

| ID | Test | Hiện tượng đã quan sát | Nghiệm thu riêng |
|---|---|---|---|
| S1 | `tests/integration/test_kernel_transport.py::TestTransportLifecycleAndRelease::test_shutdown_drains_with_one_grace_and_closes_transport` (dòng ~1600) | `READY` mất 1,8887 s dưới tải full gate 3.14 (trần test 1,0 s); chạy riêng thì đạt | Đo riêng admission, mở store, sweep/recover, khởi động listener dưới tải 6 shard; sửa nguyên nhân trong **mã sản phẩm** nếu startup thật sự chậm. **Không nới trần 1,0 s.** Pass 3/3 dưới tải trên cả hai Python |
| S2 | `tests/storage/test_outbox_durability_and_limits.py::test_outbox_and_hook_log_handle_concurrent_cold_creation_under_loose_parent_while_refusing_preexisting_insecure` | Fail trong lượt chẩn đoán 3.14 | Tìm nguyên nhân (race thật hay giới hạn chờ của harness); nếu là race thật thì sửa mã sản phẩm theo bug-proof-testing (RED/GREEN/mutation). Pass 3/3 dưới tải |
| S3 | `tests/integration/test_kernel_native_receipt_contract.py::test_wheel_probe_builder_avoids_toctou_when_owner_jsonl_grows_mid_build` | Fail trong lượt chẩn đoán 3.14 | Như S2 |
| S4 | `tests/integration/test_sp2_continuity_authority_read_errors.py::test_owner_loop_retries_a_refresh_after_the_binding_authority_reads_again` | Owner action quá 5 s dưới tải 3.11 (`_owner` trong `test_sp2_store_v7_migration.py`) | Đã nới thời gian chờ của helper lên `_WAIT_S` (chưa commit, chưa chạy lại). Xác nhận pass 3/3 dưới tải trên cả hai Python; các test dùng `_owner`/`_wait` cũng phải pass |
| S5 | Các dấu `F` không danh tính ở shard 0 trong lượt gate chạy lại (báo cáo gate F4-2) | Không có JUnit vì timeout | Sau Task 0, đối chiếu JUnit đủ để định danh; thêm vào bảng này nếu có |

## Task 2: Tối ưu từng file theo bảng mục tiêu

Áp dụng **Tiêu chí nghiệm thu chung A1–A7** cho từng dòng. Thứ tự làm từ trên xuống: các file đầu bảng cho lợi lớn nhất. Cột "Cost signals" là số lần xuất hiện mẫu trong file (gợi ý nơi tìm chi phí, không phải kết luận):
- `proc`: `subprocess`/`Popen`/tiến trình con;
- `tls`: tạo vật liệu TLS;
- `wheel`: wheel hoặc lệnh đã cài;
- `rt`: mở hoặc dựng runtime;
- `daemon`: khởi động daemon/owner loop;
- `sleep`: chờ hoặc deadline;
- `crash`: crashpoint.

Mục tiêu Target tính trên lượt chẩn đoán 3.14 (1617 s): Cut 40% cho file ≥ 40 s, 30% cho file 15–40 s, 20% cho file 8–15 s. Tổng 50 file: 1322 s → ≤ 885 s.

| ID | File | Cases | 3.14 gate | 3.14 diag | 3.11 diag | Cut | Target (3.14 diag basis) | Slowest case in 3.14 diag (s) | Cost signals (grep counts) |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| T01 | `tests/integration/test_kernel_crash_recovery.py` | 16 | 94.5 | 129.9 | 112.9 | 40% | <= 77.9 | 19.6 `test_revoke_intent_crash_reconciles_once_and_refuses_before_replay_or_` | proc=6, tls=0, wheel=25, rt=0, daemon=0, sleep=0, crash=34 |
| T02 | `tests/integration/test_apply_journal_crash_matrix.py` | 15 | 72.1 | 93.5 | 83.7 | 40% | <= 56.1 | 15.7 `test_apply_journal_crash_matrix[apply@apply.after_policy_turn_intent]` | proc=9, tls=0, wheel=22, rt=2, daemon=0, sleep=0, crash=32 |
| T03 | `tests/integration/test_kernel_native_receipt_contract.py` | 37 | 46.5 | 66.7 | 61.2 | 40% | <= 40.0 | 13.4 `test_two_concurrent_live_shims_same_repo_checkouts_replaced_root_and_r` | proc=76, tls=0, wheel=90, rt=0, daemon=26, sleep=74, crash=3 |
| T04 | `tests/integration/test_sp2_i2_wheel_compat.py` | 2 | 53.2 | 62.2 | 59.8 | 40% | <= 37.3 | 46.0 `test_cross_wheel_compatibility_matrix_and_raw_tls_probes` | proc=13, tls=4, wheel=88, rt=2, daemon=3, sleep=2, crash=0 |
| T05 | `tests/integration/test_kernel_daemon.py` | 36 | 46.4 | 57.6 | 55.3 | 40% | <= 34.6 | 12.1 `test_maintenance_and_writer_are_exclusive` | proc=48, tls=6, wheel=4, rt=48, daemon=67, sleep=165, crash=23 |
| T06 | `tests/integration/test_i3_wheel_e2e.py` | 1 | 35.8 | 57.4 | 43.1 | 40% | <= 34.4 | 57.4 `test_i3_wheel_synthetic_lifecycle_e2e` | proc=2, tls=0, wheel=37, rt=4, daemon=8, sleep=0, crash=0 |
| T07 | `tests/integration/test_capture_ack_and_crash_matrix.py` | 12 | 44.6 | 54.4 | 51.8 | 40% | <= 32.6 | 21.6 `test_offline_store5_to_store6_migration_and_installed_hook_wheel` | proc=14, tls=0, wheel=25, rt=2, daemon=2, sleep=6, crash=10 |
| T08 | `tests/integration/test_kernel_cli.py` | 3 | 39.0 | 52.1 | 43.6 | 40% | <= 31.3 | 30.8 `test_installed_cli_uses_only_explicit_config_and_releases_lease` | proc=7, tls=0, wheel=56, rt=2, daemon=5, sleep=11, crash=0 |
| T09 | `tests/integration/test_t9_signal_stop_conversion.py` | 15 | 23.2 | 41.7 | 30.7 | 40% | <= 25.0 | 4.1 `test_stop_signal_conversion[worker_thread-SIGTERM]` | proc=3, tls=0, wheel=0, rt=0, daemon=2, sleep=1, crash=0 |
| T10 | `tests/architecture/test_gate_receipt.py` | 153 | 27.2 | 39.1 | 32.8 | 30% | <= 27.4 | 7.5 `test_parse_junit_maps_real_pytest_output_to_collected_node_ids` | proc=27, tls=0, wheel=109, rt=0, daemon=0, sleep=12, crash=6 |
| T11 | `tests/integration/test_i3_rereview_init_and_accounting.py` | 49 | 34.8 | 37.7 | 38.4 | 30% | <= 26.4 | 2.7 `test_f3_real_subprocess_death_stage_recovery_completes[cli.credential]` | proc=4, tls=0, wheel=0, rt=6, daemon=10, sleep=0, crash=2 |
| T12 | `tests/storage/test_crash_matrix.py` | 23 | 24.2 | 36.9 | 29.9 | 30% | <= 25.8 | 3.1 `test_crash_case[restore_from_latest@restoring.store.after_stage]` | proc=0, tls=0, wheel=1, rt=3, daemon=0, sleep=0, crash=43 |
| T13 | `tests/storage/test_kernel_revocation.py` | 10 | 34.4 | 32.4 | 36.6 | 30% | <= 22.7 | 14.2 `test_historical_restore_policy_cannot_strip_main_store_fence_before_au` | proc=58, tls=0, wheel=0, rt=88, daemon=0, sleep=0, crash=0 |
| T14 | `tests/application/test_continuity_worker_scheduling.py` | 25 | 31.3 | 32.4 | 34.9 | 30% | <= 22.7 | 6.3 `test_four_policy_combinations_and_claim_plus_commit_recheck_case_59` | proc=16, tls=4, wheel=0, rt=6, daemon=8, sleep=7, crash=10 |
| T15 | `tests/integration/test_restore_and_migration_i3.py` | 5 | 27.2 | 34.7 | 32.7 | 30% | <= 24.3 | 18.5 `test_offline_restore_cli_refuses_writer_held_and_recovers_missing_or_c` | proc=1, tls=0, wheel=21, rt=4, daemon=4, sleep=1, crash=10 |
| T16 | `tests/storage/test_runtime.py` | 21 | 20.7 | 33.4 | 25.3 | 30% | <= 23.4 | 3.4 `test_runtime_holds_the_writer_lock` | proc=7, tls=0, wheel=0, rt=31, daemon=0, sleep=0, crash=1 |
| T17 | `tests/storage/test_restore.py` | 24 | 22.5 | 31.4 | 27.1 | 30% | <= 22.0 | 3.7 `test_successive_policy_restores_strictly_increase_generation` | proc=6, tls=0, wheel=0, rt=30, daemon=0, sleep=0, crash=13 |
| T18 | `tests/domain/test_capture_envelope_and_privacy.py` | 21 | 20.3 | 27.2 | 22.6 | 30% | <= 19.0 | 9.6 `test_hook_entry_backlog_stays_within_budget_and_preserves_idempotency` | proc=35, tls=0, wheel=0, rt=0, daemon=0, sleep=45, crash=1 |
| T19 | `tests/application/test_t8_review_p01_wrapped_paths.py` | 64 | 20.5 | 19.5 | 24.5 | 30% | <= 13.6 | 1.4 `test_p01_edge_punctuation_pattern_is_enforced_under_every_wrapper_comb` | proc=0, tls=0, wheel=0, rt=0, daemon=0, sleep=0, crash=0 |
| T20 | `tests/application/test_t8_review_p01_r2_edge_globs.py` | 73 | 16.6 | 22.9 | 23.5 | 30% | <= 16.0 | 1.0 `test_p01_r2_glob_edge_pattern_is_enforced_under_every_wrapper_combinat` | proc=0, tls=0, wheel=0, rt=0, daemon=0, sleep=0, crash=0 |
| T21 | `tests/integration/test_kernel_shim.py` | 13 | 15.6 | 23.4 | 19.4 | 30% | <= 16.4 | 14.3 `test_installed_shim_exposes_packaged_catalog_and_calls_daemon` | proc=6, tls=0, wheel=33, rt=0, daemon=6, sleep=4, crash=0 |
| T22 | `tests/storage/test_backup.py` | 54 | 22.9 | 23.0 | 20.2 | 30% | <= 16.1 | 3.6 `test_full_backup_includes_committed_wal_of_a_crashed_writer[kept]` | proc=6, tls=0, wheel=0, rt=8, daemon=0, sleep=0, crash=9 |
| T23 | `tests/storage/test_kernel_migration.py` | 7 | 20.1 | 16.8 | 20.7 | 30% | <= 11.8 | 11.9 `test_two_target_orchestration_with_injected_sequences_and_noop` | proc=19, tls=0, wheel=0, rt=16, daemon=0, sleep=0, crash=4 |
| T24 | `tests/integration/test_i3_rereview_bootstrap_and_handoff.py` | 6 | 14.2 | 16.6 | 19.9 | 30% | <= 11.6 | 4.9 `test_f4_manifest_driven_rebootstrap_preserves_u1_and_blocks_in_slice_t` | proc=0, tls=0, wheel=0, rt=2, daemon=0, sleep=0, crash=0 |
| T25 | `tests/storage/test_ledger.py` | 62 | 18.6 | 19.7 | 17.4 | 30% | <= 13.8 | 4.8 `test_append_demo_without_crash_commits` | proc=24, tls=0, wheel=0, rt=11, daemon=0, sleep=0, crash=8 |
| T26 | `tests/integration/test_sp2_store_v7_shape_and_refs.py` | 11 | 10.7 | 10.6 | 16.9 | 30% | <= 7.4 | 1.4 `test_continuity_refs_resolve_only_the_pinned_event_of_a_verified_link[` | proc=13, tls=0, wheel=0, rt=7, daemon=0, sleep=0, crash=0 |
| T27 | `tests/storage/test_recovery_grant_and_turn_intent.py` | 5 | 16.0 | 8.7 | 10.0 | 30% | <= 6.1 | 2.7 `test_cli_review_continue_and_operator_proposal_continue` | proc=0, tls=3, wheel=0, rt=3, daemon=0, sleep=1, crash=0 |
| T28 | `tests/integration/test_kernel_receipts.py` | 12 | 11.9 | 15.3 | 14.8 | 30% | <= 10.7 | 3.7 `test_writable_shim_observes_commit_unknown_before_release` | proc=0, tls=0, wheel=4, rt=0, daemon=14, sleep=21, crash=0 |
| T29 | `tests/storage/test_remediation_i2_t5.py` | 7 | 11.1 | 14.8 | 15.1 | 30% | <= 10.4 | 9.0 `test_job_accounting_includes_invocation_after_1024` | proc=3, tls=0, wheel=0, rt=15, daemon=0, sleep=0, crash=0 |
| T30 | `tests/storage/test_cas.py` | 46 | 12.0 | 14.4 | 11.1 | 20% | <= 11.5 | 3.2 `test_put_and_hold_without_crash_holds_the_payload` | proc=7, tls=0, wheel=0, rt=2, daemon=0, sleep=0, crash=10 |
| T31 | `tests/integration/test_sp2_continuity_authority_read_errors.py` | 11 | 9.6 | 10.9 | 14.3 | 20% | <= 8.7 | 3.7 `test_owner_loop_survives_a_sqlite_failure_reading_the_task_owner_and_r` | proc=1, tls=0, wheel=0, rt=0, daemon=3, sleep=0, crash=0 |
| T32 | `tests/integration/test_kernel_transport.py` | 13 | 13.3 | 12.8 | 13.0 | 20% | <= 10.2 | 2.9 `test_identity_and_tool_share_one_socket` | proc=3, tls=0, wheel=0, rt=0, daemon=9, sleep=69, crash=6 |
| T33 | `tests/integration/test_sp2_daemon_leased_attempt_retry.py` | 6 | 10.2 | 12.8 | 11.9 | 20% | <= 10.2 | 4.1 `test_owner_retries_the_same_leased_job_after_it_could_not_finish_handl` | proc=3, tls=0, wheel=0, rt=0, daemon=4, sleep=0, crash=0 |
| T34 | `tests/integration/test_kernel_privacy_persistence.py` | 4 | 8.5 | 12.7 | 10.4 | 20% | <= 10.2 | 4.1 `test_health_stays_shallow_under_owner_saturation` | proc=2, tls=0, wheel=7, rt=0, daemon=6, sleep=5, crash=0 |
| T35 | `tests/storage/test_reconcile.py` | 10 | 12.6 | 11.3 | 9.1 | 20% | <= 9.0 | 3.6 `test_crash_between_policy_and_store_applies_exactly_once` | proc=4, tls=0, wheel=0, rt=8, daemon=0, sleep=0, crash=10 |
| T36 | `tests/application/test_bootstrap_and_doctor.py` | 4 | 7.5 | 12.2 | 9.6 | 20% | <= 9.8 | 8.4 `test_doctor_strictly_readonly_and_surfaces_handover_states_drift_and_l` | proc=0, tls=0, wheel=0, rt=3, daemon=0, sleep=0, crash=0 |
| T37 | `tests/contract/test_mcp_v2_schema.py` | 9 | 9.8 | 11.9 | 10.0 | 20% | <= 9.5 | 10.7 `test_schema_roundtrip_and_packaged_digest` | proc=2, tls=3, wheel=13, rt=0, daemon=0, sleep=8, crash=0 |
| T38 | `tests/storage/test_outbox_durability_and_limits.py` | 30 | 7.4 | 11.4 | 9.2 | 20% | <= 9.1 | 6.4 `test_outbox_and_hook_log_handle_concurrent_cold_creation_under_loose_p` | proc=24, tls=0, wheel=0, rt=0, daemon=0, sleep=8, crash=2 |
| T39 | `tests/storage/test_remediation_i2_t3_lineage.py` | 31 | 10.2 | 11.0 | 11.2 | 20% | <= 8.8 | 0.5 `test_preexisting_clean_field_inherits_disabled_workspace_or_served_lin` | proc=0, tls=0, wheel=0, rt=2, daemon=1, sleep=2, crash=0 |
| T40 | `tests/architecture/test_remediation_c06_gate_xpass.py` | 2 | 5.6 | 10.7 | 7.8 | 20% | <= 8.6 | 5.5 `test_passes_and_expected_failures_are_still_classified_as_such` | proc=4, tls=0, wheel=0, rt=0, daemon=0, sleep=0, crash=0 |
| T41 | `tests/storage/test_remediation_i2_t3_mirror_history.py` | 1 | 10.3 | 6.6 | 6.5 | 20% | <= 5.3 | 6.6 `test_exact_007_v1_register_entry_with_subject_opens_with_current_mirro` | proc=4, tls=0, wheel=0, rt=6, daemon=0, sleep=0, crash=0 |
| T42 | `tests/storage/test_kernel_idempotency.py` | 17 | 7.4 | 8.8 | 9.6 | 20% | <= 7.0 | 1.8 `test_store3_to_store4_migration_min_reader_fence_and_backup_restore` | proc=27, tls=0, wheel=0, rt=7, daemon=1, sleep=10, crash=0 |
| T43 | `tests/integration/test_cli_init_and_authority.py` | 8 | 7.7 | 9.3 | 9.0 | 20% | <= 7.4 | 3.0 `test_brain_init_routes_to_the_isolated_init_entry` | proc=7, tls=0, wheel=0, rt=7, daemon=0, sleep=0, crash=1 |
| T44 | `tests/application/test_kernel_send_attempts.py` | 21 | 8.0 | 8.4 | 9.2 | 20% | <= 6.7 | 1.8 `test_r1_oversized_wire_envelope_records_no_pending_send_attempt` | proc=30, tls=0, wheel=0, rt=2, daemon=1, sleep=15, crash=1 |
| T45 | `tests/support/test_crash_harness.py` | 9 | 5.0 | 8.9 | 7.0 | 20% | <= 7.1 | 1.5 `test_child_does_not_inherit_fault_variables` | proc=6, tls=0, wheel=0, rt=2, daemon=0, sleep=2, crash=8 |
| T46 | `tests/support/test_bounded_worker.py` | 23 | 7.7 | 8.8 | 8.0 | 20% | <= 7.0 | 0.7 `test_mcp_session_finish_fails_when_descendant_holds_stderr` | proc=11, tls=0, wheel=0, rt=0, daemon=0, sleep=24, crash=4 |
| T47 | `tests/storage/test_restore_epoch_and_expiry.py` | 13 | 8.5 | 7.8 | 7.8 | 20% | <= 6.2 | 1.3 `test_case_101_restore_orders_and_policy_only_block_expired_on_first_re` | proc=0, tls=0, wheel=0, rt=11, daemon=0, sleep=0, crash=10 |
| T48 | `tests/integration/test_t9_socket_readiness.py` | 10 | 8.4 | 6.4 | 7.6 | 20% | <= 5.1 | 0.9 `test_socket_readiness_causal_barrier_waits_for_slow_lookup_and_preserv` | proc=0, tls=0, wheel=0, rt=0, daemon=0, sleep=21, crash=0 |
| T49 | `tests/application/test_i3_5_bootstrap_doctor_regressions.py` | 3 | 7.2 | 8.3 | 8.0 | 20% | <= 6.6 | 4.7 `test_r02_doctor_rejects_store_mismatch_junction_data_dirs_tampered_cas` | proc=1, tls=0, wheel=0, rt=5, daemon=0, sleep=0, crash=0 |
| T50 | `tests/integration/test_apply_journal_e2e.py` | 3 | 7.5 | 4.9 | 8.3 | 20% | <= 3.9 | 2.0 `test_shared_file_post_applied_rollback_preserves_out_of_band_edits_and` | proc=0, tls=0, wheel=0, rt=0, daemon=0, sleep=0, crash=0 |

### Ghi chú và tiêu chí riêng theo nhóm

Các ghi chú dưới đây bổ sung cho A1–A7, không thay thế.

- **Nhóm crash thật (T01, T02, T07, T12, T15, T35, T45 và các ca `crash@` khác):**
  - Mỗi crashpoint vẫn phải làm chết một tiến trình thật tại đúng điểm có tên, và sau đó mở lại hoặc khôi phục trên kho thật.
  - Nghiệm thu thêm: số crashpoint được thực thi (đếm từ log hoặc biến môi trường crash) trước và sau bằng nhau, và mỗi crashpoint vẫn có ít nhất một assert sau khi khởi động lại.
  - Gợi ý: K3 (dựng trạng thái tiền-crash một lần rồi sao chép), K4 cho venv wheel.
- **Nhóm wheel và CLI đã cài (T03, T04, T06, T08, T10, T21, T37):**
  - Lệnh vẫn phải chạy từ wheel đã cài trong venv riêng, không chạy từ `src/`.
  - Nghiệm thu thêm: test vẫn kiểm `__file__` hoặc đường dẫn gói nằm trong venv cài wheel nếu trước đó có kiểm.
  - Nếu cần nhiều phiên bản wheel (I2, SP2), mỗi phiên bản chỉ build một lần mỗi session.
  - Gợi ý: K1 (wheel/venv session, đã có `inc2_installed_env`), K4, K5.
  - `test_gate_receipt.py` có 109 chỗ chạm wheel: kiểm xem các ca dùng pytest thật có tự dựng project/venv lặp lại không.
- **Nhóm daemon, transport và owner loop (T05, T09, T14, T28, T31–T34, T48):**
  - Gợi ý K2: thay chờ cố định bằng chờ sự kiện.
  - Các trần thời gian là điều kiện test thì giữ nguyên: `READY < 1,0 s`, trần thoát của hook 2 s, cửa sổ 60 s/20 Event là đồng hồ giả lập.
  - Nghiệm thu thêm: mọi ca "không xảy ra trong cửa sổ X" vẫn quan sát đủ X.
- **Nhóm storage/runtime (T13, T16, T17, T22, T23, T25, T29, T30, T47):**
  - Gợi ý: K1 qua `open_cloned_runtime` (đã cache template theo khóa), tránh `open_runtime` dựng schema từ đầu khi test không kiểm chính việc dựng schema.
  - Nghiệm thu thêm: test kiểm migration hay khởi tạo schema vẫn đi qua đường migration thật.
- **Nhóm ma trận thuần logic (T19, T20, T39):**
  - Không có tiến trình con. Tìm chi phí ở fixture dựng lại dữ liệu cho từng ca; gợi ý K1 với dữ liệu bất biến.
  - Không giảm số tổ hợp wrapper.
- **Nhóm test SP2-3 mới (T14, T26, T31, T33):**
  - Mỗi test daemon đang gọi `_config()` → `create_store_tls` (sinh khóa EC mới) và `migrate_offline` riêng.
  - Gợi ý: cache vật liệu TLS theo `store_id` trong session, và cache data root đã migrate làm template rồi sao chép.
  - Nghiệm thu thêm: các ca migration v7 vẫn tự chạy `migrate_offline` trên bản sao của riêng mình (ba dạng v6, ngắt quãng giữa policy và store, binary cũ bị từ chối).

## Task 3: Kiểm lại toàn bộ sau mỗi batch

- [ ] Sau mỗi batch tối đa 5 file: chạy Phụ lục A cho cả hai Python, cập nhật ledger (tổng, từng shard, file đã đạt hoặc chưa).
- [ ] Gửi Codex review batch đó cùng fix note (invariant, sibling sweep, bảng lens), bảng A1–A7 từng file và receipt mutation. Chỉ reseal khi Codex duyệt.

## Task 4: Biên dịch bytecode lúc cài môi trường gate (chỉ làm sau khi reviewer duyệt)

- Số đo: collect lạnh trong venv mới mất 21,8 s, ấm 10,9 s; xóa pycache của repo không đổi kết quả (10,4 s). Tức khoảng 11 s là biên dịch lần đầu các dependency trong venv.
- Đề xuất: thêm `--compile-bytecode` vào lệnh `uv sync` của `scripts/gate.py` (bước này nằm ngoài cửa sổ `test_job`). Đây là hành vi mặc định của `pip`, nhưng nó chuyển chi phí ra ngoài cửa sổ đo, nên **reviewer phải quyết định** việc này có hợp lệ với spec 17 hay không.
- Nghiệm thu: `test_gate_receipt.py` vẫn xanh nguyên vẹn; receipt ghi lệnh sync mới; reviewer duyệt bằng văn bản.

## Task 5: Cân lại trọng số shard (làm cuối cùng)

- [ ] Cập nhật `_HEAVY_FILE_COST_MS` trong `scripts/gate.py` bằng trung bình thời gian JUnit của 3.11 và 3.14 từ lượt chẩn đoán cuối cùng (sau mọi tối ưu), cho mọi file có sai số ước tính ≥ 3 s. Giữ comment nguồn số liệu (commit, ngày, đường dẫn evidence).
- Nghiệm thu: chênh lệch giữa shard nặng nhất và nhẹ nhất ≤ 10% trong lượt chẩn đoán kế tiếp trên cả hai Python; `test_gate_receipt.py` xanh.

## Task 6: Nghiệm thu cuối cùng

Điều kiện đóng plan, tất cả phải đạt:
1. Hai gate thật `python -m scripts.gate --python 3.14 --shards 6` và `--python 3.11 --shards 6`, chạy trên cùng commit sạch, đều `accepted=true` với `test_job_seconds < 275` và JUnit đủ toàn bộ inventory.
2. Chạy lại cả hai gate lần thứ hai (khác thời điểm): vẫn `accepted=true` và dưới 275 s.
3. Tổng JUnit của lượt chẩn đoán cuối cùng ≤ 1200 s trên 3.14 (quy về điều kiện máy của Task 0 theo tỉ lệ ở A5).
4. Mọi dòng T01–T50 có A1–A7 hoặc ghi chú no-go đã được reviewer chấp nhận; mọi dòng S1–S5 đã đóng.
5. Seal mới được Codex duyệt; ledger có đường dẫn receipt gate, JUnit, mutation và seal.

---

## Phụ lục A: Script chẩn đoán (không giới hạn thời gian, đủ JUnit)

Đặt ngoài repo (ví dụ `C:/Users/letru/sb2-trusted-local/tools/diag_gate.py`). Chạy từ worktree có `uv`:
`uv run python diag_gate.py <probe_worktree> <evidence_dir> <3.14|3.11> [--compile-bytecode]`.
Script làm đúng trình tự gate: xóa `.venv` và pycache của repo, `uv sync --locked` (ngoài cửa sổ đo), preflight, collect, ruff, mypy, lint-imports, rồi chạy 6 shard song song theo `gate.shard_files`. Không có timeout. Kết quả nằm trong `timings.json` và `junit-shard-N.xml`.

```python
import json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

probe, evidence, python = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
compile_bc = "--compile-bytecode" in sys.argv
out = evidence / f"py{python}{'-bc' if compile_bc else ''}"
out.mkdir(parents=True, exist_ok=True)
env = dict(os.environ)
for name in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "PYTHONPATH", "PYTHONHOME"):
    env.pop(name, None)
env["UV_LINK_MODE"] = "copy"

def uv(*args):
    return ["uv", "run", "--locked", "--no-sync", "--project", str(probe), "--python", python, *args]

def timed(name, cmd):
    t = time.monotonic()
    p = subprocess.run(cmd, cwd=probe, env=env, capture_output=True, text=True)
    d = time.monotonic() - t
    (out / f"{name}.log").write_text(p.stdout + p.stderr, encoding="utf-8")
    return d, p.returncode, p.stdout

timings = {}
if (probe / ".venv").exists():
    subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(probe / ".venv")], check=False)
for cache in list(probe.rglob("__pycache__")):
    if ".venv" not in cache.parts:
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(cache)], check=False)
sync = ["uv", "sync", "--locked", "--project", str(probe), "--python", python] + (["--compile-bytecode"] if compile_bc else [])
timings["sync"] = timed("sync", sync)[:2]
job0 = time.monotonic()
timings["preflight"] = timed("preflight", uv("python", "-I", "-c", "import superbrain"))[:2]
d, code, collect_out = timed("collect", uv("pytest", "--collect-only", "-q"))
timings["collect"] = (d, code)
for name, cmd in (("ruff", uv("ruff", "check", "src", "tests", "scripts")), ("mypy", uv("mypy")), ("lint-imports", uv("lint-imports"))):
    timings[name] = timed(name, cmd)[:2]
sys.path[:0] = [str(probe), str(probe / "src")]
from scripts import gate
groups = gate.shard_files(gate.parse_collected(collect_out), 6)

def shard(i):
    junit = out / f"junit-shard-{i}.xml"
    d, code, _ = timed(f"pytest-shard-{i}", uv("pytest", f"--junitxml={junit}", "-q", "-rfEX", *groups[i]))
    return i, d, code

t = time.monotonic()
with ThreadPoolExecutor(max_workers=len(groups)) as pool:
    timings["shards"] = list(pool.map(shard, range(len(groups))))
timings["pytest_wall"] = time.monotonic() - t
timings["test_job_s"] = time.monotonic() - job0
(out / "timings.json").write_text(json.dumps(timings, indent=2), encoding="utf-8")
print(json.dumps(timings, indent=2))
```

## Phụ lục B: Quy trình đo cặp A/B

1. Hai worktree tách rời: **A** = commit nền, **B** = commit hoặc bản sửa đang xét.
2. Trong cùng một phiên máy, chạy theo thứ tự A, B, B, A cho 3.14, rồi lặp lại cho 3.11. Không chạy việc nặng nào khác trong lúc đo.
3. Thời gian một file = trung bình hai lượt của mỗi bên, tính từ thuộc tính `time` của `testcase` trong JUnit.
4. Tỉ lệ máy của phiên: `tổng_A_phiên / 1617` cho 3.14 và `tổng_A_phiên / 1507` cho 3.11; dùng tỉ lệ này để quy Target như trong A5.
5. Ghi vào ledger: ngày giờ, commit A/B, đường dẫn evidence, tổng của từng lượt, kết quả từng file đã xét.
