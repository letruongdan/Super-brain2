# Bàn giao SP1 đợt 1: nền tảng storage

Ngày cập nhật: 2026-11-04. Phạm vi nghiệm thu: nền storage của SP1 đợt 1 trên native Windows với data root cấu hình rõ, và WSL Ubuntu/ext4. Điều kiện đóng là các receipt `final-*` dưới đây có `accepted=true`, khớp đúng HEAD cuối, cùng review độc lập chấp thuận. Receipt cũ hoặc focused pass không thay được điều kiện này.

## Phạm vi

Đợt 1 gồm core/ports, adapter OS, một writer lease, SQLite/ledger/projection, CAS/holder/retention/GC, policy intent, backup/restore/migration, crash matrix và gate receipt. Không có daemon/shim/MCP v2, review/apply/ApplyJournal, approval UI hoặc doctor; các phần đó thuộc SP1 đợt 2–4.

Nguồn sản phẩm cuối: `712bd329f1d42e839e24f07598d0e54849c4e973`. Claude đã commit phần sửa round 8; Codex tiếp quản cùng ledger, bổ sung RED oracle và sửa shared boundary cho C04/C08 qua `8cffa9d`, `9ebe0ff`, `712bd32`. Commit bàn giao chỉ đổi tài liệu; required receipts vẫn phải gắn đúng commit HEAD chứa tài liệu này. Lịch sử claim nghiệm thu đã rút lại giữ trong Git và bản sao ignored `handover-before-codex-20261104.md`; không đổi failed thành green.

## C01–C08 sau remediation

| ID | Hành vi cần nghiệm thu |
|---|---|
| C01 | Admission thấy committed WAL dù thiếu SHM; schema/policy readers cùng dùng committed state; cleanup bản sao reader sau crash. |
| C02 | Mất main DB khi còn CAS, marker hoặc intent thì fail closed. Policy restore bảo toàn marker và mọi live intent history, kể cả WAL-only state và khi main đã mất. |
| C03 | Từ chối handler/kind downgrade trước mutation dù live projection tồn tại. |
| C04 | CAS và backup kiểm type, link/reparse và owner-only trước đọc/copy; backup bao gồm chính directory, manifest, snapshots, cas/, shards và blobs; source backup ngoài root phải có ancestor không thể bị tài khoản khác thay thế. |
| C05 | Retry sau lỗi sync parent phải sync lại trước ACK; cache chỉ ghi sau sync thành công. |
| C06 | XPASS không strict được phân loại từ terminal evidence và làm gate không accepted. |
| C07 | Fake Windows errors có typing portable; strict mypy và mapping lỗi vẫn được kiểm. |
| C08 | Preflight dùng token thật, physical paths và ACL thật; kiểm raw configured path trước resolve, từ chối cú pháp bị cấm/link/loose root/regular file hoặc cha là file. RootFacts giữ độc lập existence và admission problems; trusted temporary parent dùng ancestor/sticky rule. |

Oracle cuối: `.superpowers/sdd/sp1-inc1-remediation/test-seal-r12.json`, **66 file**, digest `sha256:8ea5d0c73ed2482ca07f6aca9b316fa0b7da1d9e97b1973b629fe61594602d5d`, do independent test author giữ và root/reviewer đối chiếu. R8 (63 file) được giữ nguyên khi sửa lệnh chọn test mutation. Sau đó independent review tìm thêm counterexample thật, nên r9 bổ sung oracle cho ancestor backup và root vắng dưới link; r10 chỉ chuyển fake probe sang RootFacts, giữ mọi assertion. R11 bổ sung ma trận cú pháp/kiểu cha của configured path; R12 bổ sung đối chứng multiple-missing/Unicode và shared-parent linked ancestry. Mọi assertion cũ giữ nguyên; không tự reseal để chấp nhận mismatch. RED gốc, các reseal có review, failed receipts và mutation lịch sử vẫn ở cùng ledger.

Ca `C04-tree-dirs-only` cũ không phải mutant bỏ kiểm file: nó chèn `continue` trong nhánh directory. Selector cũ chỉ chạy r8 file tests nên để mutant sống. Tập oracle r6+r8 vốn đã niêm phong giết đúng mutant đó tại behavioral permission-refusal assertions trên Windows và WSL. Không đổi test chỉ để có pass; đây là sửa phạm vi lệnh mutation.

## Môi trường và receipt

Gate thật là `scripts/gate.py`, bốn phase ruff, strict mypy, import-linter, pytest trong sealed worktree. Receipt phải khớp commit HEAD cuối, start=end, collected IDs=JUnit IDs; không lấy focused pass thay required suite.

Windows nghiệm thu dùng cấu hình process riêng, native adapter và strict permission guard nguyên trạng:
- Profile fixture riêng được tạo owner-only tại `C:/Users/letru/.sb2-acceptance-20261104-f037d591e8f1`.
- `LOCALAPPDATA` của tiến trình test trỏ vào `local-app-data/` của fixture; `SUPERBRAIN_HOME` trỏ vào `data/` của fixture.
- Không sửa environment cấp user/machine, ACL profile hiện hữu, trusted SID set hoặc production guard.
- Preflight ghi actual configured/resolved paths, token và root/ancestor problems; phạm vi này là configured-root acceptance.

Môi trường Windows mặc định của phiên Codex vẫn bị từ chối vì capability SID có takeover rights trên `AppData` và `AppData/Local`. Failed receipts mặc định ở `.gate/completion-20261104/baseline-windows-default/` được giữ nguyên. Kết quả configured-root không sửa hay nghiệm thu default-profile environment đó.

WSL Ubuntu dùng clone sạch trên ext4 và gate subprocess thật cho Python 3.11.15/3.14.4. Nó là bằng chứng POSIX trên WSL, không thay macOS hoặc remote CI.

Baseline source `b9a49d5`: receipts/logs dưới `.gate/completion-20261104/baseline-*`, chỉ có giá trị baseline. Required final-source receipts:

| Môi trường | Receipt dưới `.gate/completion-20261104/` |
|---|---|
| Native Windows, Python 3.11.9 | `final-windows-configured/gate-3.11.9.json` |
| Native Windows, Python 3.14.3 | `final-windows-configured/gate-3.14.3.json` |
| WSL Ubuntu/ext4, Python 3.11.15 | `final-linux/gate-3.11.15.json` |
| WSL Ubuntu/ext4, Python 3.14.4 | `final-linux/gate-3.14.4.json` |

`closure-summary.json` gắn HEAD, seal, source hashes, kết quả từng phase, test/JUnit inventory, crash cases và trạng thái cuối. Mỗi thư mục có command logs, JUnit, worker start/end và source manifest. Root/reviewer phải đọc receipt terminal, không lấy worker exit hoặc tên file làm bằng chứng pass. Receipt filename chuẩn theo commit/interpreter/lock digest có thể được chép từ kết quả quan sát, không sửa acceptance decision.

## Bảng crash và các tình huống storage

`docs/design/sp1-crash-table.md`, `KNOWN_CRASHPOINTS`, `CRASH_CASES` và test parity được kiểm trong suite. Test giết child tại crashpoint là bằng chứng process-crash/replay; cột power-loss trong bảng là lập luận.

Plan đợt 1 phủ đủ tình huống 26 (version admission), 34 (reconcile policy/store); phủ storage của 5,6,7,8,21,25,28,32,35 qua crash/replay/backup/writer/permission/generation/Event-retention tests. Credential/nonce/signature/Evidence/doctor vẫn thuộc các đợt/domain đã nêu trong plan.

## Các giới hạn phải giữ khi đóng

- macOS và remote CI chưa chạy tại đây; repo chưa có remote được dùng cho CI. Không suy ra native macOS từ platform override của mypy.
- Chưa thử mất điện; không có claim power-loss ngoài durability tier máy thật báo.
- Windows file symlink bị skip khi tài khoản thiếu privilege; real junction và POSIX symlink là các ca riêng, không thay nhau một cách ngầm định.
- Không nghiệm thu native harness hoặc khả năng học/hiệu quả/Jev. Không gửi project sang MCP namespace chưa enroll.
- Hiệu năng quét history khi mở và các minor lịch sử không chặn invariant vẫn giữ trong ledger cho đợt 2; không deferred counterexample của C02/C04/C08 để đóng đợt 1.

## Bằng chứng và tiếp tục

Ledger chuẩn: `.superpowers/sdd/sp1-inc1-remediation/ledger.md`. Các báo cáo Codex cùng thư mục: `codex-test-author-report.md`, `codex-owner-report.md`, `codex-final-review.md` (pre-fix), `codex-scoped-review-r9.md` (pre-fix) và `codex-scoped-review-final.md` (candidate cuối); gate artifacts dưới `.gate/completion-20261104/`. Giữ chúng khi chuyển harness vì `.superpowers` và `.gate` là gitignored.
