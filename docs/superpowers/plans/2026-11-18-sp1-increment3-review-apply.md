# SP1 đợt 3 · Bootstrap, review/apply và restore — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cho phép chủ kho khởi tạo người ký, duyệt và cài đặt bootstrap rủi ro cao cho Claude Code và Codex qua `ChangeProposal` + `ApplyJournal` an toàn trước thay đổi ngoài luồng, đồng thời hoàn thiện `backup`/`restore`/`migrate`/accounting giữ đúng quyền, hạn gốc và hàng rào thế hệ cho M1.

**Architecture:** Trạng thái bảo mật (signer, nonce, trạng thái lớp 2, `recovery_grant`, hướng lượt `ApplyJournal`, accounting và cờ khóa đối soát) nằm bền trong `policy/policy.db` (`policy v4`) trước khi chiếu một lần theo `intent_id` sang `store/brain.db` (`store v5`). Các thao tác ghi file cấu hình đi qua adapter vật lý không theo symlink/reparse, dựng và backup trên cùng volume ngoài cây Git của checkout, publish bằng syscall `no-replace` và phân loại phục hồi theo định danh vật lý đã ghim. CLI giữ `superbrain.cli` thuần stdlib (`python -I`), tách `user:cli` qua `cli_api` (gồm chế độ bảo trì dưới cùng `WriterLease`) với các lệnh `--offline` phục hồi thảm họa khi kho sống không thể mở.

**Tech Stack:** Python ≥ 3.11, `uv`, SQLite WAL, `cryptography>=44,<51`, `pywin32>=311` (Windows), bổ sung có duyệt `webauthn>=2.2,<3` (`py_webauthn`) và `tomlkit>=0.13,<1`, OpenSSH `ssh-keygen -Y verify`, stdlib HTTP loopback, pytest, mypy `--strict`, ruff, import-linter.

**Spec:** [Thiết kế hệ thống rev 22 (§5.4–5.9, §6.4, §7.4, §8.11, §11.1–11.4, §14, §15, §17, §19, §20)](../specs/2026-10-30-super-brain2-system-design.md) · [Plan SP1 đợt 2](2026-11-04-sp1-increment2-daemon-mcp-kernel.md) · [Plan SP2](2026-11-18-sp2-capture-continuity.md) · [Báo cáo review kế hoạch đợt 3](../../reviews/2026-11-18-sp1-increment3-plan-review.md) · [Ghi chú xử lý review I3/SP2](../../reviews/2026-11-18-sp1-i3-sp2-plan-fix-notes.md).

---

## Điểm chốt trước triển khai

| Quyết định | Hồ sơ và điều kiện khóa baseline |
| --- | --- |
| **Baseline I2** | Task 9 đã đóng `CLOSED_TASK9` tại `5d00a88280d06d6ac5b0e8d5804285cb9c1fcf1b` ([bàn giao I2](../../../.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-9/i2-5d00a88-handover.md)). Bản vá code, 3 bộ test và seal cho `I2-CLOSE-01` (U+007F canonical JSON) đã có tại `972ae5a42ddd2f00a2116be7a3968cd031cc1e2b`. Chỉ pin SHA triển khai chung cho `I3-0` và `SP2-0` sau khi có re-review độc lập trên `972ae5a`, đủ gate/benchmark đúng pin, đối chiếu tác động lên receipt native theo `T9-P01` và chủ dự án xác nhận spec rev 22. |
| **O12 và phạm vi gate** | Chủ dự án chốt `O12` cùng rev 22: đề xuất Windows làm máy chạy lượt bootstrap/native/phần cứng đầu tiên cho M1; ghi tường minh từng ô OS/kênh ký chưa chạy là `not_run` kèm điều kiện kích hoạt, không tuyên bố vượt phạm vi đã có receipt (§17.5). Giữ nguyên ma trận CI mặc định 3 OS × 2 Python theo §17.2. |
| **Hợp đồng với SP2** | Một điều phối viên giữ `storage` migrations, wire schema, crash table và reseal. I3 nâng cặp kho lên **`(store=5, policy=4)`** (`min_reader_version` = `5` và `4`). Từ **`store v5`**, `store/restore_epoch.json` là bắt buộc (`restore_epoch=0` khi tạo kho mới hoặc nâng từ `store < 5`, cấp `lease.epoch` khi `restore_store`, giữ nguyên qua `migrate`, từ chối thiếu/hỏng ở cả mở kho lẫn phục hồi swap). Thứ tự tích hợp: **I3-0 + SP2-0 → SP2-1 trên transport I2 → I3-4/SP2-4 tích hợp fence và restore → 2 host native**. |
| **Thư viện, OS và reseal** | Duyệt đưa `webauthn>=2.2,<3` và `tomlkit>=0.13,<1` vào runtime `pyproject.toml`/`uv.lock`; kiểm `uv sync --locked --offline` và đóng gói wheel offline không kéo dev deps. SSH dùng `ssh-keygen -Y verify` với namespace `ensemble-brain-approval`. Mọi thay đổi chạm selector của `.verification/task9-seal.json` (`pyproject.toml`, `uv.lock`, `docs/design/sp1-crash-table.md`, `scripts/gate.py`, `tests/**`) phải có reviewer độc lập duyệt reseal. |
| **Phạm vi thử thật** | Phê duyệt riêng trước khi chạm cấu hình harness thật, thiết bị passkey/FIDO hoặc dữ liệu người dùng; ghi host/version/config digest và bước cleanup. Mọi lượt chạy bằng fixture hoặc authenticator giả ghi `kind="fixture"`. |

## Global Constraints

- **Kiến trúc & phân tầng (§4.2):** Python ≥ 3.11; ma trận `{Windows, macOS, Linux} × {3.11, 3.14}`. Giữ `ruff`, `mypy --strict`, `import-linter` và `tests/architecture/test_imports.py` (cấm vòng lặp package, cấm import ngược tầng, file > 600 dòng phát cảnh báo). `superbrain.cli` chỉ dùng `core` và stdlib, khởi chạy qua `python -I -m superbrain.composition.<entry>`. Cấm tuyệt đối mọi tham chiếu `superbrain.core.faults` / `SUPERBRAIN_CRASHPOINT` / `SUPERBRAIN_PAUSEPOINT` trong `mcp/`, `cli/`, `composition/shim_entry.py`, `composition/client_entry.py`.
- **Độ bền & quyền đĩa (§5.4, §5.5, §5.9):** Một chủ ghi giữ `writer.lock` xuyên suốt; SQLite WAL với `synchronous=FULL`, `secure_delete=ON` (macOS bật `fullfsync=ON`, `checkpoint_fullfsync=ON`). Quyền owner-only (`0700`/`0600`, `umask 077` trên POSIX; owner + SYSTEM trên Windows), kiểm tra không link/reparse và chuỗi tổ tiên tin cậy trước khi đọc/ghi.
- **Ranh giới kênh tĩnh & dữ liệu an toàn (§8.11, §11.2, §14.2):** Cấm mọi `ChangeProposal` có đích trong thư mục skill của harness (`.claude/skills`, `.agents/skills`, `.codex/skills` ở cả checkout lẫn thư mục user, so khớp case-fold trên FS không phân biệt hoa thường), trong `data_root`, hoặc dùng UNC/device/ADS (Q25, §20 ca 92). Không log token, khóa, query string chứa bootstrap token hay `str(exc)` lấy từ input; ledger chỉ lưu metadata có kiểu, mọi nội dung có TTL nằm trong CAS.
- **Ngân sách gate mặc định F4 (`< 300 s`, §17.2):** Cuối đợt 2, `test_job_seconds` ở `264,1 s` (Windows local) và `285,9 s` (Windows CI). Dùng chung wheel venv theo session, viết test máy trạng thái SQLite/filesystem trong tiến trình và chỉ mở subprocess từ wheel cho các điểm cắt kill tiến trình thật và smoke CLI. Cân bằng lại 4 shard pytest trong `scripts/gate.py` (có reseal), giữ mốc kiểm soát local Windows `< 275 s` và toàn bộ 10 ô local/CI `< 300 s`, giữ nguyên denominator lịch sử, 0 fail/error/XPASS, cấm skip/xóa/giảm assertion.

## Review Focus

1. **Chỉnh sửa ngoài luồng trên file cấu hình dùng chung rồi `brain rollback` sau khi đã `applied`, hoặc ghi TOML làm rơi comment của người dùng (`I3-2`, `I3-3`):** `test_shared_file_post_applied_rollback_preserves_out_of_band_edits_and_toml_comments` kiểm sự tách biệt giữa rollback phục hồi lượt dở dang và gỡ cài đặt có chữ ký mới dựng từ file sống.
2. **File mới của người dùng xuất hiện đúng giữa bước kiểm và bước publish trên POSIX/Windows, hoặc checkout nằm ở ổ đĩa khác `data_root` (`I3-2`, `I3-3`):** `test_publish_no_replace_preserves_late_user_file_on_all_platforms` và `test_cross_volume_checkout_stages_on_target_volume_outside_git_worktree`.
3. **Kênh `terminal` gặp tập kết nối rỗng (`all([]) == True`), hoặc `--reset-signers` bỏ sót `recovery_grant` đang `active` / mất dấu cảnh báo sau khi restore policy cũ (`I3-1`, `I3-3`, `I3-4`):** `test_terminal_approval_refuses_empty_or_unverified_harness_set` và `test_reset_signers_ends_active_grants_and_survives_policy_restore`.
4. **`policy-only restore` làm mất tombstone của holder đã quá hạn, hoặc restore policy hai lần liên tiếp làm rơi khóa đối soát accounting / khoản giữ chỗ `outcome_unknown` (`I3-4`):** `test_holder_original_expiry_enforced_on_first_read_after_policy_only_restore` và `test_accounting_locks_and_unknown_holds_survive_repeated_policy_restore`.
5. **Mất `brain.db` hoặc `policy.db` khiến `brain serve` từ chối mở nên không chạy được `restore`, hoặc `review_web` dùng IP `127.0.0.1` làm trình duyệt từ chối WebAuthn / lộ one-time token (`I3-4`, `I3-5`):** `test_offline_restore_recovers_missing_store_or_policy_with_verified_authority` và `test_review_web_localhost_origin_csrf_and_token_single_exchange`.

---

## Bản đồ file và hợp đồng dùng chung

### Phân công module theo task

| Task | Module sản xuất tạo mới / mở rộng (`src/superbrain/`) | Test, bảng thiết kế và cấu hình |
| --- | --- | --- |
| **I3-0** | — (chốt bảng hợp đồng, crashpoint names, reseal dependency) | `docs/design/sp1-crash-table.md` (bản thiết kế dòng mới), `pyproject.toml`, `uv.lock` |
| **I3-1** | `core/_kernel_approval.py`, `core/_kernel_auth.py`, `ports/approval.py`, `ports/kernel.py`, `storage/kernel_schema.py` (`policy v4` phần authority/signer/nonce/layer2), `storage/_policy_approvals.py`, `adapters/auth/{ssh_sig.py,webauthn_verifier.py}`, `application/approvals.py`, `cli_api/operator.py`, `cli/main.py`, `composition/{init_entry.py,operator_entry.py}` | `tests/core/test_approval_message.py`, `tests/adapters/test_approval_verifiers.py`, `tests/storage/test_signer_and_layer2_authority.py`, `tests/integration/test_cli_init_and_authority.py` |
| **I3-2** | `core/proposals.py`, `ports/os.py`, `adapters/os/{physical_fs.py,durable.py}`, `adapters/harness_config/{markdown_blocks.py,json_keys.py,toml_tables.py,bootstrap_templates.py}`, `storage/proposals.py`, `storage/kernel_schema.py` (`store v5` kinds/tables cho proposal & journal), `application/review_apply.py` | `tests/adapters/test_physical_fs_and_no_replace.py`, `tests/adapters/test_shared_config_mergers.py`, `tests/application/test_change_proposal_and_journal.py` |
| **I3-3** | `storage/_policy_grants.py`, `application/journal_recovery.py`, `core/faults.py`, `composition/daemon_entry.py` (reconcile & recovery trước khi mở phục vụ) | `docs/design/sp1-crash-table.md`, `tests/support/inc3_crash_child.py`, `tests/support/crash_cases.py`, `tests/storage/test_crash_matrix.py`, `tests/integration/test_apply_journal_crash_matrix.py` |
| **I3-4** | `storage/{layout.py,restore.py,migrate.py,runtime.py,cas.py,retention.py,jobs.py}`, `storage/_policy_accounting.py`, `application/{jobs.py,maintenance.py}`, `composition/{owner_entry.py,operator_entry.py}` | `tests/storage/test_restore_epoch_and_expiry.py`, `tests/storage/test_policy_accounting.py`, `tests/integration/test_restore_and_migration_i3.py` |
| **I3-5** | `review_web/{server.py,assets.py}`, `application/review_session.py`, `composition/review_entry.py`, `scripts/gate.py` (cân bằng shard F4 nếu cần) | `tests/review_web/test_review_web_security.py`, `tests/integration/test_bootstrap_synthetic_e2e.py` |

### Hợp đồng dùng chung xuyên suốt `I3-1`..`I3-5`

- **Cặp schema và `restore_epoch`:**
  - Đích đợt 3 là **`(store=5, policy=4)`**. `policy v4` thêm các bảng `signer`, `approval_nonce`, `approval_receipt_meta`, `harness_layer2_state`, `recovery_grant`, `apply_turn_intent`, `accounting_invocations`, `accounting_locks`. `store v5` nâng capability fence (`min_reader_version=5`) và đăng ký typed ledger kinds/reducers cho `ChangeProposal`, `ApplyJournal`, `ApprovalReceipt` cùng các intent `policy.signer_reset`, `policy.repo_policy_set`, `policy.layer2_state_set`, `policy.recovery_grant_opened`, `policy.recovery_grant_ended`.
  - File `store/restore_epoch.json` (`{"format_version": 1, "restore_epoch": <int>=0}`, canonical JSON, owner-only) nằm trong `RESERVED_ENTRIES` của `storage/layout.py` và được kiểm link/ACL/nội dung ở `_effective_target_db`, `recover_interrupted_swaps`, `admit_existing_pair` và `Store.open` cho mọi kho (kể cả stage `READY`) có `schema_version >= 5`. Kho `schema_version < 5` vắng file được đọc thành `0`; nâng cấp lên `v5` ghi `0`; `migrate` từ `v5+` chép nguyên giá trị đã xác minh sang stage trước `READY`; `restore_store` ghi `lease.epoch` mới vào `stage/restore_epoch.json` trước `READY`; `backup` không chép file này.
- **Định danh vật lý, publish `no-replace` và vị trí staging cùng volume:**
  - `OsAdapters` cung cấp `stat_physical_identity(path: Path) -> PhysicalObjectId` không bao giờ đi theo symlink/reparse (`CreateFileW` với `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` + `GetFileInformationByHandleEx(FileIdInfo)` trả `(volume_serial, file_id_128, is_link)` trên Windows NTFS/ReFS; `os.lstat` trả `(st_dev, st_ino, is_link)` trên POSIX) và `DurablePublisher.publish_no_replace(staging: Path, final: Path) -> None` (Windows: `MoveFileExW(src, dst, MOVEFILE_WRITE_THROUGH)` không có `MOVEFILE_REPLACE_EXISTING`; Linux: `renameat2(..., RENAME_NOREPLACE)` với fallback `os.link` + `os.unlink`; macOS: `renamex_np(..., RENAME_EXCL)` với fallback `os.link` + `os.unlink`; tất cả đều trả `FileExistsError` nguyên tử mà không chạm đích nếu có file xuất hiện muộn, và giữ nguyên `PhysicalObjectId`).
  - Nơi dựng và backup của mỗi file đích được chọn theo volume của đích: nếu cùng volume với `data_root` thì đặt tại `<data_root>/apply_staging/<journal_id>/`; nếu khác volume (ví dụ `data_root` ở `C:` và checkout ở `D:\repo\checkout-a`) thì đặt ở thư mục anh em owner-only **bên ngoài cây làm việc Git** trên cùng volume `<checkout_parent>/.ensemble-brain-apply-<owner_hash>/<journal_id>/` (kiểm không link, `check_ancestors` đạt, quyền `0700`/owner+SYSTEM; thất bại thì từ chối trước khi tiêu thụ approval).
- **Hai chế độ rollback trên file dùng chung:**
  - *Rollback phục hồi lượt dở dang* (`partially_applied` dưới `recovery_grant` đang sống): chỉ chạy khi file ở đích vẫn khớp đúng `PhysicalObjectId` + digest của `replacement` (hoặc đang ở `original_moved`/`target_absent`), đưa nguyên `backup` gốc về đích; nếu người dùng đã sửa đích giữa chừng thì dừng ở `recovery_required` và giữ nguyên mọi bản.
  - *`brain rollback <proposal_id>` sau khi đã `applied`* (action mới, cần `ApprovalReceipt` mới): nếu toàn bộ file của proposal vẫn khớp đúng `PhysicalObjectId` + digest lúc cài đặt xong, mở lượt `direction=rollback` trả `backup` gốc. Nếu có file dùng chung đã được người dùng chỉnh sửa ngoài phần quản lý (`U0 + Block → U1 + Block`), kiểm phần do brain quản lý vẫn khớp digest trong manifest (nếu phần quản lý bị sửa thì báo diff xung đột và từ chối), dựng bản đích mới `U1` giữ nguyên mọi chỉnh sửa/comment của người dùng, ký `original = (id(U1+Block), digest(U1+Block))` và `replacement = digest(U1)` trong approval mới, backup `U1 + Block` rồi publish `U1` theo journal.
- **Mặt lệnh CLI, danh tính `user:cli` và chế độ bảo trì:**
  - Lệnh offline dưới `WriterLease` (`--config <abs>` qua `composition.init_entry` / `owner_entry`): `brain init`, `brain init --reset-signers`, `brain migrate --offline`, `brain restore --offline` (dùng khi daemon dừng hoặc khi mất/hỏng `brain.db` hay `policy.db` khiến `brain serve` không thể mở).
  - Lệnh qua daemon (`--profile <abs>` mang credential của principal `user:cli` qua `cli_api` HTTPS): `brain status`, `brain backup [--target store|policy|both]`, `brain job cancel --job-id <id>`, `brain signer list|enroll|revoke`, `brain credential issue|revoke`, `brain policy show|set|reconcile-accounting`, `brain workspace link`, `brain review [list|show|approve|reject|web]`, `brain apply`, `brain rollback <id>`, `brain restore` (chuyển owner loop sang chế độ bảo trì dưới cùng `WriterLease`, chặn call mới bằng `STORE_BUSY`, đóng `Store`+`PolicyStore`, hoán đổi, hoàn tất bước 7, mở lại runtime và làm mới `AuthGate`). Bearer của harness (`claude-code`, `codex`…) bị từ chối với `IDENTITY_MISMATCH` trên mọi endpoint `/v2/operator/*`.
- **Bố cục file bootstrap theo ràng buộc `D3` (`single-checkout-owner-profile-v1`):**
  - Không bao giờ ghi cứng `--profile <checkout_A>` vào file cấu hình MCP toàn cục cấp user nếu làm hỏng checkout `B`. Với Claude Code: ghi MCP server vào `<checkout>/.mcp.json`, khối rule lớp 1 + §7.4 vào `<checkout>/CLAUDE.md`, và quyền lớp 2 `ask` + hook vào `<checkout>/.claude/settings.local.json` (hoặc `.claude/settings.json` được chọn). Với Codex: ghi khối rule lớp 1 + §7.4 vào `<checkout>/AGENTS.md` và cấu hình MCP/hook theo phạm vi checkout (`.codex/config.toml` / `.codex/hooks.json` hoặc `CODEX_HOME` gắn workspace khớp biên bản T0/R56). Tập lệnh lớp 2 `ask` gồm đủ 10 nhóm: `brain init*`, `brain review approve*`, `brain review reject*`, `brain apply*`, `brain rollback*`, `brain lesson confirm*`, `brain signer*`, `brain policy*`, `brain credential*`, `brain restore*`, `brain workspace link*`.

---

## I3-0 · Chốt ma trận hợp đồng, reseal dependencies và bảng điểm crash

**Files:**
- Modify: `pyproject.toml`, `uv.lock`, `docs/design/sp1-crash-table.md` (thiết kế các hàng mới trước khi gắn code ở I3-3/I3-4)
- Artifact đối chiếu: `.superpowers/sdd/2026-11-18-sp1-increment3/ledger.md`

**Interfaces:**
- Consumes: kết quả đóng `972ae5a` (`I2-CLOSE-01`), quyết định `O12` và spec rev 22 của chủ dự án.
- Produces: lockfile offline cho `webauthn` và `tomlkit`, bảng ánh xạ action/authority, bảng pha/hướng `ApplyJournal` và danh sách tên crashpoint cố định giao cho `I3-1`..`I3-5`.

- [ ] **Step 1: Xác nhận baseline sau `972ae5a` và ghi quyết định `O12`**
  Đối chiếu hồ sơ re-review độc lập, ma trận gate/benchmark trên `972ae5a` và kiểm tra tác động lên receipt native Epoch 11 theo `T9-P01`. Ghi SHA baseline, quyết định `O12` (OS/kênh ký chạy thật, ô `not_run` và điều kiện mở lại) vào ledger chung với `SP2-0`.
- [ ] **Step 2: Khóa bảng action, bảng pha `ApplyJournal` và ánh xạ đủ các ca §20**
  Lập bảng cho toàn bộ `action ∈ {approve, reject, apply, rollback, lesson_confirm, signer_enroll, signer_revoke, policy_change, credential_revoke, restore, workspace_link, skill_promote, skill_activate, skill_publish}` (chủ thể ký, risk do server xếp, kênh hợp lệ, trạng thái lớp 2, intent policy và đường phục hồi; các action thuộc SP3–SP6 khóa enum/validator ở core và trả `capability_unavailable` ở handler đợt 3). Khóa bảng ánh xạ §20: `I3-1` (`12, 16–21, 32, 34`), `I3-2` (`12, 19, 27, 92, 94–95, 105–106`), `I3-3` (`27, 32–34, 93, 105–107`), `I3-4` (`21, 25–26, 32, 35, 70, 75–77, 93, 101–102`), `I3-5` (`12, 14–15, 31`).
- [ ] **Step 3: Thêm `webauthn` và `tomlkit`, kiểm offline wheel và duyệt reseal**
  Cập nhật `pyproject.toml` và `uv.lock`, chạy kiểm tra offline build và xin reviewer độc lập duyệt reseal `.verification/task9-seal.json` trước khi viết oracle `I3-1`.
  Run: `uv sync --locked --offline && uv run --locked pytest -q tests/contract/test_mcp_v2_schema.py tests/architecture/test_imports.py`
  Expected: `PASS`, wheel cài đặt không lẫn gói dev, seal check `rc=0`.

---

## I3-1 · Signer, cổng duyệt ba lớp và khởi tạo kho (`brain init`)

**Files:**
- Create: `src/superbrain/core/_kernel_approval.py`, `src/superbrain/ports/approval.py`, `src/superbrain/storage/_policy_approvals.py`, `src/superbrain/adapters/auth/ssh_sig.py`, `src/superbrain/adapters/auth/webauthn_verifier.py`, `src/superbrain/application/approvals.py`, `src/superbrain/cli_api/operator.py`, `src/superbrain/composition/init_entry.py`, `src/superbrain/composition/operator_entry.py`
- Modify: `src/superbrain/core/_kernel_auth.py`, `src/superbrain/ports/kernel.py`, `src/superbrain/storage/kernel_schema.py`, `src/superbrain/storage/policy_store.py`, `src/superbrain/storage/identity.py`, `src/superbrain/cli/main.py`
- Test: `tests/core/test_approval_message.py`, `tests/adapters/test_approval_verifiers.py`, `tests/storage/test_signer_and_layer2_authority.py`, `tests/integration/test_cli_init_and_authority.py`

**Interfaces:**
- Consumes: `WriterLease`, `create_store_tls`, `PolicyStore`, `Store`, `LoopbackClient`.
- Produces: `ApprovalMessage`, `ApprovalChannel`, `AssuranceLevel`, `RiskLevel`, `classify_proposal_risk(...) -> RiskLevel`, `ApprovalVerifierPort`, `PolicyStore` v4 authority APIs (`enroll_signer`, `revoke_signer`, `issue_nonce`, `consume_approval`, `reset_signers_offline`, `set_layer2_state`, `terminal_channel_eligible`), CLI `brain init [--reset-signers]`, `brain signer *`, `brain credential *`, `brain policy *`, `brain workspace link`, `brain backup`, `brain job cancel`.

- [ ] **Step 1: Viết bộ test RED cho `ApprovalMessage`, xếp hạng rủi ro, verifiers và điều kiện kênh `terminal`**
  Kiểm canonical serialization của `ApprovalMessage` đủ trường §11.3 (`store_id`, `owner_id`, `trust_generation`, `action`, `subject_id`/`subject_revision`, toàn bộ resource digests, danh sách file đích kèm root/path chuẩn hóa/`PhysicalObjectId` cha và đích/digest gốc hoặc `absent`, `risk_level`, `risk_policy_version`, `recovery_scope`, `nonce`, `expires_at`). Kiểm `classify_proposal_risk` luôn trả `high` khi chạm `c2/c5/c7/c8`, có file thực thi/tham chiếu lệnh hoặc sửa ngoài khối hướng dẫn dù client gửi nhãn `low` (ca 19). Kiểm `terminal_channel_eligible` trả `False` khi tập harness principal active trên máy **rỗng** (`0` harness) hoặc có bất kỳ harness nào ở `unknown`/`unsupported`/lệch `(host_version, config_digest)` (ca 12, 20), và trả `True` khi có ≥1 harness active và tất cả đều `verified`.
  Run: `uv run --locked pytest -q tests/core/test_approval_message.py tests/adapters/test_approval_verifiers.py tests/storage/test_signer_and_layer2_authority.py`
  Expected: `FAIL` (module/API chưa tồn tại).
- [ ] **Step 2: Viết test RED cho `brain init`, `--reset-signers` và các lệnh CLI vận hành**
  Kiểm `brain init` offline dưới `WriterLease` khởi tạo `store_id`, TLS (`D2`), quyền đĩa (`D1`–`D3`), principal `user:cli` và người ký đầu tiên (ghi rõ TOFU), dùng intent policy trước rồi reconcile đúng một lần. Kiểm `brain init --reset-signers` chỉ chạy offline dưới lease: nâng `trust_generation` trên cả `policy.db` và `writer.lock` HWM (có test crash giữa hai bước), hủy mọi nonce chờ, chuyển mọi `recovery_grant` đang `active` sang `ended` (`reason="trust_reset"`), đặt cờ bền `meta.signer_reset_recorded='1'` và append intent `policy.signer_reset` để `doctor` luôn hiện. Kiểm thêm người ký thứ hai không có approval của người ký hiện hành bị từ chối (ca 18), `credential revoke`, `policy set`, `workspace link`, `brain backup` và `brain job cancel` chỉ nhận `user:cli` (từ chối bearer của harness).
- [ ] **Step 3: Niêm phong test rồi triển khai `ApprovalMessage`, verifiers SSH/WebAuthn, `policy v4` (phần authority) và CLI**
  Xác minh WebAuthn qua thư viện `webauthn` (kiểm challenge khớp bytes `ApprovalMessage`, `origin`, `rp_id`, cờ `UV=True`, `sign_count` tăng khi counter > 0) và SSH qua `ssh-keygen -Y verify` với file `allowed_signers` riêng và namespace `ensemble-brain-approval`, ghi đúng `AssuranceLevel` (`key_authorization` cho `ssh_key`, ca 17).
- [ ] **Step 4: Chạy GREEN, kiểm tra mutation hành vi và commit**
  Mutation bắt buộc: bỏ kiểm tập rỗng ở `terminal` (`all([])`), bỏ cờ `UV` của WebAuthn, cho phép dùng lại `nonce`, bỏ kiểm `trust_generation`, bỏ kết thúc `recovery_grant` khi `--reset-signers`, và cho phép bearer harness gọi `/v2/operator/*`. Tất cả mutant phải bị bắt. §20 ca 12, 16–21, 32, 34.
  Run: `uv run --locked pytest -q tests/core/test_approval_message.py tests/adapters/test_approval_verifiers.py tests/storage/test_signer_and_layer2_authority.py tests/integration/test_cli_init_and_authority.py tests/architecture/test_imports.py`
  Expected: `PASS`.

---

## I3-2 · `ChangeProposal`, hợp nhất file dùng chung và publish theo `ApplyJournal`

**Files:**
- Create: `src/superbrain/core/proposals.py`, `src/superbrain/adapters/os/physical_fs.py`, `src/superbrain/adapters/harness_config/markdown_blocks.py`, `src/superbrain/adapters/harness_config/json_keys.py`, `src/superbrain/adapters/harness_config/toml_tables.py`, `src/superbrain/adapters/harness_config/bootstrap_templates.py`, `src/superbrain/storage/proposals.py`, `src/superbrain/application/review_apply.py`
- Modify: `src/superbrain/ports/os.py`, `src/superbrain/adapters/os/durable.py`, `src/superbrain/storage/kernel_schema.py`, `src/superbrain/cli_api/operator.py`, `src/superbrain/cli/main.py`
- Test: `tests/adapters/test_physical_fs_and_no_replace.py`, `tests/adapters/test_shared_config_mergers.py`, `tests/application/test_change_proposal_and_journal.py`

**Interfaces:**
- Consumes: `ApprovalMessage`, `classify_proposal_risk`, `PolicyStore`, `Store`, `OsAdapters`.
- Produces: `PhysicalObjectId`, `OsAdapters.stat_physical_identity`, `DurablePublisher.publish_no_replace`, `ChangeProposal`, `ManagedSliceManifest`, `ApplyJournal`, `FileJournalEntry`, `BootstrapPlanner`, CLI `brain review list|show|approve|reject`, `brain apply`, `brain rollback <id>`.

- [ ] **Step 1: Viết test RED cho `stat_physical_identity`, `publish_no_replace` đa nền tảng và chọn staging cùng volume**
  Kiểm từ chối UNC/device/ADS, từ chối đích nằm trong thư mục skill của harness (`.claude/skills`, `.agents/skills`, `.codex/skills` ở checkout và `~`, ca 92) hoặc trong `data_root`, và từ chối đích/chuỗi cha bị đổi sang symlink/junction/reparse sau khi duyệt dù file ở đích mới có cùng bytes (ca 94). Kiểm `publish_no_replace` không bao giờ ghi đè file mới xuất hiện ở đích trên cả Windows, Linux và macOS, giữ nguyên `PhysicalObjectId` của file đã stage (ca 95, 105, 106). Kiểm chọn thư mục staging/backup tại `<checkout_parent>/.ensemble-brain-apply-<owner_hash>/<journal_id>/` khi đích khác volume với `data_root`, giữ `git status --porcelain` của checkout rỗng.
- [ ] **Step 2: Viết test RED cho bộ hợp nhất 3 định dạng (Markdown, JSON, TOML) và hai chế độ rollback**
  Kiểm cài mới và cập nhật cho Markdown (`<!-- ensemble-brain:begin:<id> -->`..`end`), JSON (khóa con đã khai như `mcpServers.ensemble-brain`) và TOML (bảng đã khai qua `tomlkit`, **giữ nguyên comment, khoảng trắng và các bảng khác của người dùng**). Lần cài đầu gặp khối/khóa/bảng đã tồn tại mà chưa có manifest sở hữu → xung đột; lần cập nhật hoặc gỡ mà phần quản lý lệch digest manifest → xung đột; cả hai hiện diff đúng phần xung đột và không ghi đĩa. Kiểm `brain rollback` sau khi đã `applied` trên file có chỉnh sửa ngoài luồng (`U0 + Block → U1 + Block`): tạo lượt gỡ có approval ký trên `(id(U1+Block), digest(U1+Block))` và publish `U1` giữ nguyên phần `U1` cùng comment TOML, không bao giờ chép đè bản `U0` cũ.
- [ ] **Step 3: Viết test RED cho trình tự `ApplyJournal` nhiều file (`original=present` và `original=absent`)**
  Kiểm ghi bền journal trước lần chạm đĩa đầu tiên; dựng bản thay thế cùng volume, flush và ghim `(PhysicalObjectId, digest)` vào journal; ghi intent dời trước rename sang backup, kiểm lại `(PhysicalObjectId, digest)` của chính file vừa dời (sai digest thì dời trả lại nếu đích còn trống, giữ cả hai nếu đích đã có file mới, dừng ở `recovery_required`); ghi intent publish ghim sẵn `PhysicalObjectId` bản thay thế trước `publish_no_replace`. Kiểm rollback lượt dở dang xác minh backup trước khi dời file đầu tiên và xử lý đúng `original=absent` (chỉ dời bản thay thế do journal sở hữu về vùng giữ, đích trở lại vắng, không đòi backup).
- [ ] **Step 4: Niêm phong test, triển khai adapters/journal và chạy GREEN + mutations**
  Mutation bắt buộc: thay `publish_no_replace` bằng `os.replace`, so sở hữu bằng digest thay vì `PhysicalObjectId`, bỏ kiểm chuỗi cha lúc resume/rollback, bỏ kiểm thư mục skill (ca 92), và dùng lại `backup` `U0` khi `brain rollback` file đã có chỉnh sửa ngoài luồng `U1`. §20 ca 12, 19, 27, 92, 94–95, 105–106.
  Run: `uv run --locked pytest -q tests/adapters/test_physical_fs_and_no_replace.py tests/adapters/test_shared_config_mergers.py tests/application/test_change_proposal_and_journal.py`
  Expected: `PASS`.

---

## I3-3 · Hướng phục hồi (`direction`), `recovery_grant` và ma trận điểm crash từ wheel

**Files:**
- Create: `src/superbrain/storage/_policy_grants.py`, `src/superbrain/application/journal_recovery.py`, `tests/support/inc3_crash_child.py`, `tests/integration/test_apply_journal_crash_matrix.py`
- Modify: `src/superbrain/core/faults.py`, `src/superbrain/storage/policy_store.py`, `src/superbrain/composition/daemon_entry.py`, `docs/design/sp1-crash-table.md`, `tests/support/crash_cases.py`, `tests/storage/test_crash_matrix.py`
- Test: `tests/integration/test_apply_journal_crash_matrix.py`, `tests/storage/test_crash_matrix.py`

**Interfaces:**
- Consumes: `PolicyStore` (`recovery_grant`, `apply_turn_intent`), `ApplyJournal`, `stat_physical_identity`, `publish_no_replace`, wheel venv theo session.
- Produces: `RecoveryGrant` (`active`/`ended`, gắn `turn_id`, `journal_id`, `subject_id`, `action`, `recovery_scope`, `trust_generation`), `reconcile_and_classify_journals(...)` chạy trước khi daemon nhận request, và các dòng `ApplyJournal` chính thức trong `KNOWN_CRASHPOINTS` + `docs/design/sp1-crash-table.md`.

- [ ] **Step 1: Đăng ký các điểm cắt của `ApplyJournal` và viết test RED trên process thực từ wheel**
  Bổ sung vào `KNOWN_CRASHPOINTS` và `docs/design/sp1-crash-table.md` (giữ nguyên 29 ID của đợt 1–2 và parity test `test_every_known_crashpoint_has_a_case_and_a_doc_row`):
  - `apply.after_policy_turn_intent` (đã ghi `direction` + grant vào `policy.db`, chưa chiếu sang journal ở `brain.db`);
  - `apply.before_move_original`, `apply.after_move_before_phase` (đã rename gốc sang backup, chưa ghi `original_moved`);
  - `apply.before_publish_replacement`, `apply.after_publish_before_phase` (đã `publish_no_replace`, chưa ghi `replacement_published`);
  - `rollback.after_policy_turn_intent` (đã ghi hướng `rollback` vào `policy.db` trên proposal đã `applied`, chưa chiếu sang journal — ca 107);
  - `rollback.before_first_move` (đã chiếu `direction=rollback` và ghi ý định dời file đầu tiên, tất cả file vẫn ở `replacement_published` — R21-01 / ca 107);
  - `rollback.after_move_replacement`, `rollback.after_restore_last_original` (đã đưa bản gốc cuối cùng về đích, chưa ghi `rolled_back` — ca 106);
  - `apply.after_policy_grant_ended` (đã ghi `ended` + trạng thái cuối vào intent policy, chưa chiếu sang `brain.db` — ca 93).
  Kiểm thêm: approval nhận trước khi hết hạn nhưng crash và mở lại sau 10 phút vẫn phục hồi được nhờ `recovery_grant` (ca 33); file cùng bytes khác `PhysicalObjectId` do người dùng tạo giữa hai bước làm journal dừng ở `recovery_required` và giữ đủ cả 3 bản (ca 106); backup thiếu/sai định danh hoặc digest khi mở lượt rollback dừng ở `recovery_required` trước lần dời đầu tiên (ca 107); lần phục hồi thứ hai liên tiếp là no-op; `--reset-signers` giữa chừng làm mất hiệu lực grant và chuyển journal sang `recovery_required`.
- [ ] **Step 2: Niêm phong test + crash table, triển khai máy phân loại theo `direction` và vòng đời grant**
  Thứ tự bắt buộc khi mở lại kho: hoàn tất chiếu `apply_turn_intent` và `recovery_grant_ended` từ `policy.db` sang `brain.db` **trước** khi phân loại từng file theo `(direction, recorded_phase, file_intent, PhysicalObjectId trên đĩa)`. Kiểm grant còn `active` và khớp `trust_generation` hiện hành trước **mọi** thao tác chạm file; khi đạt trạng thái cuối (`applied` sau kiểm bắt buộc, hoặc `rolled_back`), ghi bền `ended` vào `policy.db` trước rồi mới chiếu trạng thái cuối sang `brain.db`.
- [ ] **Step 3: Chạy GREEN, kiểm tra parity crash matrix, mutations và đo F4**
  Mutation bắt buộc: tổng hợp trạng thái journal trước khi xét `direction` (tái hiện lỗi R21-01 kết thúc nhầm rollback ở `applied`), cho phép tiếp tục dựa trên journal trong `brain.db` khi grant trong `policy.db` đã `ended` (ca 93), và bỏ kiểm backup trước lần dời đầu tiên khi rollback. Kiểm thời gian chạy trên Windows giữ dưới mốc kiểm soát F4 nhờ gom batch subprocess trên cùng wheel venv. §20 ca 27, 32–34, 93, 105–107.
  Run: `uv run --locked pytest -q tests/integration/test_apply_journal_crash_matrix.py tests/storage/test_crash_matrix.py`
  Expected: `PASS`, parity 1-1 giữa `KNOWN_CRASHPOINTS`, `CRASH_CASES`/`KERNEL_CRASH_CASES` và `sp1-crash-table.md`.

---

## I3-4 · Restore có duyệt, `restore_epoch`, hạn gốc lúc đọc và tầng accounting trong policy store

**Files:**
- Create: `src/superbrain/storage/_policy_accounting.py`, `src/superbrain/application/maintenance.py`, `tests/storage/test_restore_epoch_and_expiry.py`, `tests/storage/test_policy_accounting.py`, `tests/integration/test_restore_and_migration_i3.py`
- Modify: `src/superbrain/storage/layout.py`, `src/superbrain/storage/restore.py`, `src/superbrain/storage/migrate.py`, `src/superbrain/storage/runtime.py`, `src/superbrain/storage/cas.py`, `src/superbrain/storage/retention.py`, `src/superbrain/storage/jobs.py`, `src/superbrain/application/jobs.py`, `src/superbrain/composition/owner_entry.py`, `src/superbrain/composition/operator_entry.py`
- Test: `tests/storage/test_restore_epoch_and_expiry.py`, `tests/storage/test_policy_accounting.py`, `tests/integration/test_restore_and_migration_i3.py`

**Interfaces:**
- Consumes: `stage_and_swap`, `verify_backup`, `admit_existing_pair`, `PolicyStore` v4, `Store` v5, `JobService`.
- Produces: `store/restore_epoch.json` lifecycle (`read_restore_epoch`, `write_restore_epoch`), `drain_published_restore_effects`, kiểm `expires_at` trực tiếp trên `active_held_digests`/`read_held_blob`/`HolderProjection`, bảng accounting tự chứa trong `policy.db` (`reserve`, `settle`, `recover_old_epochs`, `reconcile_accounting_lock`), preview diff authority trước khi restore policy, và cả hai đường `brain restore` (daemon maintenance mode & `--offline` khi mất kho sống).

- [ ] **Step 1: Viết test RED cho `restore_epoch` (`store v5`), hạn gốc trên đường đọc và bước 4/7 khi restore kho**
  Kiểm tạo kho mới `v5` và nâng cấp kho `< 5` lên `v5` đều ghi `store/restore_epoch.json` = `0`; kho `< 5` thiếu file đọc thành `0`; kho `v5+` thiếu/hỏng file hoặc bị thay bằng symlink bị từ chối với `INTEGRITY_FAILURE` **cả khi mở kho lẫn khi phục hồi swap có stage `READY`** (ca 75, 77). Kiểm hai lần restore liên tiếp cho hai `restore_epoch` tăng ngặt, và `restore → migrate` trước tiếp quản giữ nguyên `restore_epoch` (ca 75–76). Kiểm blob dùng chung giữa Event hết hạn và Evidence còn được giữ vẫn đọc được qua Evidence nhưng bị chặn qua Event; kiểm Evidence có payload nhỏ hết hạn đúng hạn ngoài ledger (ca 25, 35). Kiểm ca 101 đầy đủ: backup cả hai kho → đợi hết hạn → restore cả hai theo cả hai thứ tự và `policy-only restore` → lần đọc đầu tiên trước khi `expire_due`/GC chạy **không trả bytes đã hết hạn**; kill sau khi dựng `pending_restore_tombstones.json` trong stage và trước swap thì kho sống mở lại vẫn đọc được Evidence `E` còn Lesson giữ; kill tại `restoring.store.after_swap_before_effect_drain` (sau swap, trước khi hoàn tất intent) thì `open_runtime` hoàn tất intent của đúng snapshot vừa công bố trước khi mở đọc/nhận Job và chặn `E` ngay lần đọc đầu. Kiểm restore kho chính chứa journal dở sau khi grant đã `ended` không hồi sinh quyền ghi file (ca 93).
- [ ] **Step 2: Viết test RED cho tầng accounting tự chứa trong `policy.db`, preview restore policy, mất kho sống và fence binary cũ**
  Kiểm `JobService.reserve_invocation`/`settle_usage`/`recover` ghi bền số tiền giữ chỗ và trạng thái (`reserved`, `outcome_unknown`, `settled`) trực tiếp trong `policy.db` (không phụ thuộc `store/cas/`) **trước** khi ghi vào `brain.db`, xử lý đúng crash giữa hai DB và migrate giữ nguyên các dòng `ProviderInvocation` sẵn có từ kho `(store=4, policy=3)`. Kiểm ca 102: chạm trần kỳ rồi restore `store/` vẫn giữ trạng thái chạm trần; `outcome_unknown` giữ nguyên mức giữ chỗ qua restore `store/`; `restore_policy` hiện chính xác thay đổi authority (credential/signer hồi sinh, quarantine gỡ) trước khi duyệt, ghi khóa chặn lời gọi mới cho mọi kỳ bị ảnh hưởng (từ `backup.created_at` tới `now`) ngay trong stage trước `READY` để có hiệu lực ở request đầu tiên sau swap, **và mang tiếp các khóa chưa đối soát / khoản `outcome_unknown` cùng cờ `signer_reset_recorded` từ `policy.db` sống sang stage để không mất qua lần restore policy thứ hai**; chỉ `policy_change` có bằng chứng đối soát mới mở khóa. Kiểm `brain restore` chạy được cả ở chế độ bảo trì của daemon đang sống lẫn `brain restore --offline` khi `store/brain.db` hoặc `policy/policy.db` bị mất/hỏng (xác minh chữ ký với `policy.db` sống, hoặc với tập signer trong bản backup policy đã `verify_backup` + HWM `writer.lock` khi mất `policy.db`). Kiểm binary I2 từ chối kho `(5, 4)` trước mọi thao tác ghi trên cả `serve`, `migrate` và `restore` (ca 21, 26, 32, 70).
- [ ] **Step 3: Niêm phong test, triển khai `restore.py`/`migrate.py`/`runtime.py`/`cas.py`/`_policy_accounting.py` và điểm mở rộng SP2/SP3/SP4**
  Gắn điểm hook rõ ràng trong pipeline dựng stage/sau swap cho cả hai kho: `PolicyRestoreStageHook` trên `restore_policy` (để SP2 `policy v5` mang tiếp `session_hmac_key` và tập `session_ref_bindings` mà không làm đứt hay chiếm đoạt `session_ref`) và `RestoreStageHook` trên `restore_store` (để SP3 gắn tập dấu mất pin `skill_pin_lost` và SP4 gắn dấu rà soát `skill_review_*` theo §5.7 bước 5 & 7) mà không phải sửa lại cấu trúc swap/drain.
- [ ] **Step 4: Chạy GREEN, kiểm tra mutations và commit**
  Mutation bắt buộc: bỏ kiểm `expires_at` trong `active_held_digests`/`read_held_blob`, ghi tombstone vào `policy.db` sống trước swap, bỏ `drain_published_restore_effects` trong `open_runtime`, bỏ carry-forward `accounting_locks`/`signer_reset_recorded` khi restore policy lần hai, và bỏ kiểm `restore_epoch.json` trên stage `READY` lúc phục hồi swap. §20 ca 21, 25–26, 32, 35, 70, 75–77, 93, 101–102.
  Run: `uv run --locked pytest -q tests/storage/test_restore_epoch_and_expiry.py tests/storage/test_policy_accounting.py tests/integration/test_restore_and_migration_i3.py tests/storage/test_restore.py tests/storage/test_migrate.py`
  Expected: `PASS`.

---

## I3-5 · Trang duyệt `review_web`, cài rule §7.4 và bàn giao sang Đợt 4 / SP2

**Files:**
- Create: `src/superbrain/review_web/server.py`, `src/superbrain/review_web/assets.py`, `src/superbrain/application/review_session.py`, `src/superbrain/composition/review_entry.py`, `tests/review_web/test_review_web_security.py`, `tests/integration/test_bootstrap_synthetic_e2e.py`
- Modify: `src/superbrain/review_web/__init__.py`, `src/superbrain/adapters/harness_config/bootstrap_templates.py`, `src/superbrain/cli/main.py`, `scripts/gate.py` (nếu cần cân bằng lại thứ tự phân mảnh 4 shard pytest)
- Test: `tests/review_web/test_review_web_security.py`, `tests/integration/test_bootstrap_synthetic_e2e.py`

**Interfaces:**
- Consumes: `ApprovalMessage`, `WebAuthnVerifier`, `ReviewApplyService`, `BootstrapPlanner`, `ClientProfile`.
- Produces: loopback HTTP UI cho `brain review web` (`http://localhost:<port>`, `rpId="localhost"`), bộ template bootstrap hoàn chỉnh cho Claude Code và Codex (MCP + hook + rule lớp 1–2 + rule §7.4), rule kiểm tra bàn giao cho `doctor` đợt 4, và full gate receipt của SP1 đợt 3.

- [ ] **Step 1: Viết test RED cho `review_web` theo threat model §11.2 và chuẩn WebAuthn trình duyệt**
  Socket chỉ bind trên `127.0.0.1:<port>`, nhưng URL phiên duyệt, kiểm tra `Host`, `Origin` và WebAuthn `rpId` khóa chặt vào `http://localhost:<port>` (`rpId="localhost"`, không dùng IP literal hay TLS tự ký khiến trình duyệt thật chặn WebAuthn). Đổi one-time token từ fragment/POST khởi tạo sang cookie phiên `HttpOnly; SameSite=Strict` đúng một lần (dùng lại token bị từ chối), kèm `Cache-Control: no-store`, `Referrer-Policy: no-referrer` và không bao giờ ghi token vào log. Kiểm CSP chặt (`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'`), escape toàn bộ diff/lý do/resource mang HTML/script/event handler/URL thành văn bản trơ, kiểm CSRF header, từ chối sai `Host` (DNS rebinding, kể cả `127.0.0.1:<port>` hoặc `evil.localhost`), sai `Origin`, request quá trần kích thước (`8 KiB` line / `16 KiB` headers / `64 KiB` body) hoặc quá deadline, và đóng sạch keep-alive khi kết thúc phiên/tắt daemon. Kiểm phần tóm tắt hiển thị trên trang được dựng trực tiếp từ chính bytes `ApprovalMessage` làm challenge; subject/revision/file đích đổi giữa lúc xem thì challenge cũ bị từ chối và trang buộc nạp challenge mới (ca 31).
- [ ] **Step 2: Viết test RED cho nội dung rule §7.4 + lớp 1–2 và luồng synthetic E2E từ wheel**
  Template bootstrap cài vào cả Claude Code và Codex:
  - **Lớp 1 & Lớp 2 (§11.3):** câu cấm tự duyệt thay người dùng trong `CLAUDE.md`/`AGENTS.md` và đủ 10 mẫu lệnh `ask` trong cấu hình quyền của harness.
  - **Rule sổ bàn giao (§7.4):** cập nhật ở 6 thời điểm (lập/đổi kế hoạch, chốt quyết định/loại phương án, người dùng thêm ràng buộc, xong một bước, ngay trước lệnh chạy lâu, kết thúc task đặt `task_state`), hook phù hợp chỉ nhắc không chặn. Khi **tiếp quản một sổ đang mở**, agent đối chiếu checkout, báo người dùng nếu phiên cũ còn `active`, và chờ ACK của lần tiếp quản có cả `handoff_status="stored"` lẫn `writer_status="holder"` trước lần sửa file đầu tiên (`not_holder` → đọc lại và tiếp quản bằng fence sống; `commit_outcome_unknown` → retry cùng khóa rồi xét ACK; `not_stored_policy` khi đang xin tiếp quản sổ đang mở → giữ nguyên checkout và báo/hỏi người dùng vì chưa nhận được quyền giữ sổ). Khi **làm việc không tiếp quản sổ mở** trên repo chủ động tắt cờ riêng tư `manual_submission=false` (§14.2, §7.4 dòng 616), `not_stored_policy` chỉ báo việc không lưu nội dung thủ công theo policy và agent vẫn thực hiện công việc bình thường.
  - **Synthetic E2E từ wheel:** chạy trọn chu trình `brain init` → tạo proposal bootstrap cho hai checkout `A` và `B` trên cả Claude Code và Codex (cô lập trong thư mục test) → xem qua `review_web` / CLI → ký bằng SSH và authenticator WebAuthn kiểm soát → `brain apply` → xác minh `ApplyJournal = applied`, `recovery_grant = ended`, đúng digest file đích, đúng TLS/profile theo `D3` kết nối được daemon thật, giữ nguyên nội dung/comment ngoài luồng → chạy tiếp `brain rollback` có duyệt và kiểm tra khôi phục sạch.
- [ ] **Step 3: Niêm phong test, triển khai `review_web`, template bootstrap và cân bằng F4**
  Đóng gói bàn giao các hàm đọc trạng thái bền cho `doctor` đợt 4 (kiểm danh sách người ký, cờ `signer_reset_recorded`, trạng thái lớp 2 theo `(harness_id, host_version, config_digest)`, drift của phần cấu hình do brain quản lý và `ApplyJournal` kẹt ở `partially_applied`/`recovery_required`). Chỉ báo bootstrap "sẵn sàng" khi mọi file đích khớp digest đã duyệt và qua hết các phép kiểm bắt buộc (ca 12, 14).
- [ ] **Step 4: Chạy full gate SP1 đợt 3, review độc lập và bàn giao cho Đợt 4 / SP2**
  Chạy `scripts/gate.py` trên working tree sạch với seal đã duyệt: 0 fail/error/XPASS, đủ inventory JUnit, parity 100% với `docs/design/sp1-crash-table.md`, toàn bộ ô ma trận OS/Python đạt **`test_job_seconds < 300 s`** (local Windows `< 275 s`), kèm review độc lập toàn nhánh theo 11 lens. Thu receipt phần cứng/native riêng khi đến lượt được chủ dự án duyệt. Chuyển giao baseline cài đặt và hồ sơ capability từng host cho `SP2` và `SP1 đợt 4`. §20 ca 12, 14–15, 31.
  Run: `uv run --locked python scripts/gate.py --python 3.11 && uv run --locked python scripts/gate.py --python 3.14`
  Expected: `accepted: true` trên cả hai interpreter, `test_job_seconds < 300.0`, 0 fail/error/XPASS.

---

## Quy trình nghiệm thu mỗi task

Mỗi task tuân thủ nghiêm ngặt: tác giả test viết oracle độc lập từ spec, lưu chứng cứ RED đúng nguyên nhân và niêm phong bằng `.verification/test_lock.py` trước khi sửa code sản xuất; implementer đạt GREEN qua CLI/daemon/SQLite/filesystem thật theo phạm vi và chứng minh mỗi guard mới bằng ít nhất một mutation hành vi bị bắt; reviewer độc lập rà lại cả 11 lens của `skills/review-lens/SKILL.md` trên phần được sửa lẫn các đường gọi lân cận. Mọi bằng chứng runtime lưu ngoài cây source đã pin; tiến trình chạy dài ghi checkpoint gồm PID, `started_at`, lệnh đã lọc bí mật, `cwd`, commit nguồn và đường dẫn log/receipt trước khi dừng chờ.
