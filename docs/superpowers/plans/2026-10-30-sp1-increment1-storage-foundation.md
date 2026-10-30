# SP1 · Đợt 1: Nền lưu trữ — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dựng nền lưu trữ của Super-brain2, có đủ hàng rào kiến trúc, chạy trên Windows, macOS và Linux. Nền gồm: data root an toàn, khóa ghi, ledger cộng projection, CAS bền vững có holder, policy store có intent, retention/tombstone/quarantine, backup/restore, migration.

**Architecture:**
- Package `superbrain` theo ma trận phụ thuộc ở spec mục 4.2.
- Đợt này tạo `core`, `ports`, `adapters.os` và `storage`. Các tầng trên chỉ là package rỗng, để hàng rào import có chỗ kiểm tra.
- Mọi thao tác phụ thuộc OS (đường dẫn, khóa, quyền file, fsync, rename) và mọi chỗ storage cần đọc policy đều đi qua `ports`.
- `storage` không bao giờ import `adapters`. Chỉ `tests` và `composition` (về sau) ráp adapter vào.

**Tech Stack:** Python ≥ 3.11 (kiểm tra trên 3.11 và 3.14), `uv`, `sqlite3` của thư viện chuẩn, `pywin32` (chỉ trên Windows), pytest, mypy, ruff, import-linter.

**Spec:** `docs/superpowers/specs/2026-10-30-super-brain2-system-design.md` (rev 4, commit `92492f5`). Đợt này triển khai mục 4.2–4.3 và 5.3–5.9, trừ các bản ghi thuộc đợt sau.

**Review đã xử lý:**
- `docs/reviews/2026-10-30-sp1-increment1-plan-review.md` (SP1-I1-01…14);
- `docs/reviews/2026-10-30-sp1-increment1-plan-review-round2.md` (SP1-I1-R2-01…09).

Bản ánh xạ nằm ở cuối plan.

**Shell:** các lệnh trong plan dùng `&&`, nên chạy trong bash hoặc PowerShell 7. `scripts/gate.py` là runner Python chạy tuần tự, không phụ thuộc shell.

## Phạm vi của đợt 1

**Có trong đợt 1:**
- Scaffold và hàng rào (spec 17.2).
- `core`: lỗi có mã, canonical JSON/digest, UUIDv7, crashpoint.
- `ports` và `adapters.os`: đường dẫn an toàn, quyền owner-only, `durable_publish` và mức độ bền, khóa độc quyền, đồng hồ.
- `storage`:
  - bố cục data root, writer lease, khởi động runtime;
  - SQLite, kiểm tra phiên bản khi đọc và khi ghi;
  - ledger với entry kind có kiểu;
  - CAS có holder và GC;
  - policy store có intent, `trust_generation`;
  - retention;
  - backup, restore, migration;
  - phục hồi sau crash.
- Bảng điểm crash.
- Gate và receipt.

**Không có trong đợt 1:**
- Đợt 2: daemon, shim, contract v2, idempotency, job, O7.
- Đợt 3: ApplyJournal, review/apply, cổng duyệt, nonce, người ký.
- Đợt 4: `doctor`.

Các bảng credential, người ký, nonce, policy theo repo và trạng thái lớp 2 sẽ được thêm vào policy store bằng migration ở đợt cần chúng.

## Quyết định chốt trong plan này

| Quyết định | Chốt |
|---|---|
| Tên | Distribution `super-brain2`, import package `superbrain`. CLI `brain` thêm ở đợt 2 |
| Bố cục data root | `writer.lock`, `policy/policy.db`, `store/brain.db`, `store/cas/<2 hex đầu>/<64 hex>`, `store/staging/`, `outbox/`, `logs/`, `backups/`. Thư mục tạm của restore và migrate: `store.restoring/`, `store.migrating/`, `policy.restoring/`, `policy.migrating/`. Bản cũ được cất ở `*.replaced-<UTC>-<id>/`, bản bỏ dở ở `*.abandoned-<UTC>-<id>/` |
| Biến môi trường ghi đè data root | `SUPERBRAIN_HOME` |
| Nội dung `writer.lock` | Byte 0 là vùng khóa. Tiếp theo là hai slot 256 byte ở offset 1 và 257. Mỗi slot chứa JSON `{seq, writer_epoch, trust_generation_hwm}` đệm khoảng trắng tới 252 byte, cộng 4 byte CRC32 big-endian. Ghi đè slot cũ hơn; đọc slot hợp lệ có `seq` lớn nhất. Cả hai slot hỏng → `integrity_failure` |
| Thứ tự khởi động (sửa I1-01) | `prepare_data_root` (chỉ kiểm tra và tạo root cùng `writer.lock`) → `acquire_writer` → `recover_interrupted_swaps(lease)` → tạo và bảo vệ các thư mục con → mở policy store → mở store. **Không thao tác nào chạm vào `store*`/`policy*` trước khi có lease** |
| Quyền mở ghi (sửa I1-02) | Mở ghi chỉ khi `schema_version` **bằng đúng** version của code. Mới hơn → `unsupported_version`; cũ hơn → `migration_required`. Mở chỉ đọc khi `min_reader_version ≤ code`. Migration không bao giờ tự chạy |
| Metadata của ledger (sửa I1-08) | Mỗi entry kind đăng ký một schema metadata có kiểu, thuộc các loại `uuid`, `digest`, `int`, `timestamp`, `enum`, `bool`. **Không có kiểu chuỗi tự do.** `actor` và `owner_id` theo mẫu định danh. Lý do (reason) là `enum` |
| Ghi nhận đã áp intent (sửa I1-03) | Chỉ kho dữ liệu (bảng `applied_intents`) ghi nhận intent nào đã áp. Policy store không có cờ "đã áp". Mỗi lần mở store, store đối chiếu **mọi** intent trong policy store với `applied_intents` của chính nó |
| Mô hình thực thi (sửa R2-09) | `Store` và `PolicyStore` thuộc về **một owner thread**, là thread đã mở chúng. Mọi method public kiểm tra `threading.get_ident()`; gọi từ thread khác → `AssertionError`. `connect` giữ `check_same_thread=True` mặc định. Daemon ở đợt 2 sẽ gửi mọi thao tác storage qua owner thread này |
| Chuyển giao `put` → `hold` (sửa R2-03) | `Txn.hold` kiểm tra blob tồn tại và đúng digest **bên trong** transaction ghi (`BEGIN IMMEDIATE`). GC xóa blob cũng **bên trong** một transaction ghi, sau khi kiểm tra lại không còn holder. SQLite xếp hai transaction này tuần tự, nên không thể có holder trỏ tới blob đã mất. `hold` thấy blob đã mất → `NOT_FOUND`. `Store.store_content(...)` gói `put` + `hold`, thử lại đúng một lần khi gặp `NOT_FOUND` |
| GC và backup (sửa I1-12) | Cùng chạy trên owner thread nên tự nhiên tuần tự. `Store.maintenance()` là cờ không lồng được: gọi GC khi backup đang chạy → `STORE_BUSY`. Không có bảng pin bền vững, nên crash không để lại gì cần thu hồi |
| Backup (sửa I1-04, I1-05, R2-01, R2-07) | Ba loại: `store` (closure, từ Store đang mở, chỉ chép blob có holder), `store_full` (bảo trì, theo đường dẫn, chép mọi blob), `policy` (từ PolicyStore đang mở, hoặc theo đường dẫn khi bảo trì). Verifier **tự rút** `store_id`, `schema_version`, high-water và tập root từ chính DB snapshot. Với `store`: tập root **bằng đúng** `blobs`. Với `store_full` đọc được bằng code hiện tại: tập root **là tập con** của `blobs`, cho phép blob mồ côi thừa. Với `store_full` có schema lạ: chỉ kiểm vật lý, manifest ghi `logical_verified=false`, restore từ chối. Verifier luôn kiểm `kind` đúng loại được yêu cầu |
| Thay policy (sửa R2-02) | Restore hay migrate **policy** yêu cầu cả handle `store` và `policy` đều đóng. Sau khi công bố, caller mở runtime mới, nên Store được gắn với policy mới và đối chiếu lại |
| Mở theo bộ migration (sửa R2-05) | `open_runtime`, `Store.open`, `PolicyStore.open` nhận tham số `store_migrations` / `policy_migrations`, mặc định là `STORE_MIGRATIONS` / `POLICY_MIGRATIONS`. Đây là đường chính thức để binary có migration mới mở kho; test dùng chính đường này, không patch phần kiểm tra version |
| Gate trên checkout niêm phong (sửa I1-10) | `scripts/gate.py` tạo `git worktree add --detach <tmp> HEAD`, chạy `uv sync` và mọi phase trong worktree đó, rồi gỡ worktree. Bytes được kiểm luôn đúng bằng commit |
| Mức độ bền (sửa I1-06) | Chỉ báo `power_loss_durable` khi filesystem nằm trong **danh sách đã biết là bền** và lần ghi thử (probe) thành công. Mọi trường hợp khác là `process_crash_durable`, kèm lý do |
| Quyền tổ tiên (sửa I1-07, R2-08) | Mối đe dọa: tài khoản OS khác **đổi tên hoặc thay** cây thư mục của brain. POSIX: tổ tiên cho người khác ghi chỉ được chấp nhận khi có sticky bit; **chủ dự án đã xác nhận ngày 2026-10-30** và spec 5.9 đã ghi lại. Windows: mọi tổ tiên phải có owner thuộc nhóm tin cậy, và không ACE nào cấp quyền đổi tên/thay cho SID ngoài nhóm đó |
| Subprocess cho crash test (sửa I1-09) | `python -I -c "import runpy,sys; runpy.run_path(sys.argv[1], run_name='__main__')" <đường dẫn tuyệt đối tới tests/support/crash_child.py> <operation> <data_root>`. Child chỉ import `superbrain`, đã được cài editable trong venv. Operation `ping` in ra `superbrain.__file__` để kiểm tra child dùng đúng source của checkout |
| Crashpoint | `SUPERBRAIN_CRASHPOINT=<tên>`: ghi `CRASHPOINT_HIT <tên>` ra stderr, flush, rồi `os._exit(86)`. `SUPERBRAIN_PAUSEPOINT=<tên>`: ghi `PAUSED <tên>` ra stderr, rồi chặn tới khi đọc được một dòng trên stdin |
| Python mới nhất | 3.14 là bản ổn định mới nhất tại thời điểm viết plan (2026-10-30), được ghim cho CI và gate. Nâng lên bản mới hơn là thay đổi có chủ đích |
| O7 | Chuyển sang plan đợt 2 |

## Manifest trích xuất

Nguồn: `D:\ensemble-agents\Super-brain`, commit `f83271d`. Chỉ dùng Git object, không dùng working tree.

| Nguồn (blob) | Đích | Test mang theo | Requirement |
|---|---|---|---|
| `src/ensemble_brain/core/revisions.py` (`d80d7f5`) | `src/superbrain/core/canonical.py`. Đổi tên: `canonical_revision` → `canonical_digest`, `resource_digest` → `digest_bytes`, `_validate_json` → `validate_json` | Từ `tests/core/test_contracts.py` (`8e6bf49`): `test_canonical_revision_rejects_non_json_and_float_quantities`, `test_canonical_revision_uses_utf8_not_ascii_escapes`, `test_canonical_revision_is_order_independent_but_content_sensitive`, `test_resource_digest_hashes_exact_delivered_bytes`, `test_resource_digest_requires_bytes`. Giữ nguyên assertion và giá trị hash | Spec 5.4, 6.3 |
| `docs/examples/skill-body.txt` (`ed19012`) | `tests/fixtures/skill-body.txt` | Fixture của test digest | – |
| `src/ensemble_brain/storage/ownership.py` (`d28475c`): phần kiểm tra symlink/reparse và khóa `msvcrt`/`fcntl` | `src/superbrain/adapters/os/paths.py`, `src/superbrain/adapters/os/locks.py` | `tests/storage/test_runtime_path_safety.py` (`7c48659`): hai test đầu, đổi `writer_ownership` thành `prepare_data_root`/`open_runtime` và đổi tên entry theo bố cục mới. `tests/storage/test_ownership.py` (`15e0852`) **không** mang sang: test đó kiểm tra lease gắn với thread trong tiến trình, khác với khóa liên tiến trình của spec 5.5 | Spec 5.5, 10 |
| `src/ensemble_brain/storage/artifacts.py` (`b0bb49c`): `_fsync_directory` | `src/superbrain/adapters/os/durable.py` | Không có test riêng ở nguồn; viết test mới ở Task 5 | Spec 5.4 |

**Không trích xuất** (thiết kế mới khác bản cũ):
- `storage/ledger.py`: bảng khóa `o2/o3/o4`, không có projection rebuild.
- `storage/artifacts.py`, phần bundle.
- `storage/backup.py`: backup không tự chứa blob.
- `storage/schema*.py`, `storage/migrations.py`: chuỗi schema lịch sử (Q13 không nhập dữ liệu cũ).
- `storage/sqlite_connections.py`: kho mới giữ một kết nối sống lâu.

**Baseline:** trước khi sửa, chạy các test được mang theo trên `f83271d` (dùng `git worktree` tạm ở scratchpad) và ghi kết quả vào commit message của task tương ứng. Test fail sẵn ở nguồn được giữ và ghi lý do (spec 17.4).

## Global Constraints

- **Python và CI:** `>=3.11`; chạy test trên 3.11 và 3.14 tại máy; CI ma trận {Windows, macOS, Linux} × {3.11, 3.14}.
- **Phân tầng** theo spec 4.2: `core` ← `ports` ← (`storage` | `adapters.*`) ← `domain.*` ← `application` ← (`mcp` | `cli_api` | `review_web` | `workers`) ← `composition`. `cli` chỉ import `core`. Kiểm tra cả import trong hàm.
- **Kiểm tra tĩnh:** `mypy --strict` cho `src` và `tests`; `ruff` cho `src` và `tests`; không có vòng phụ thuộc giữa package.
- **Cấm nuốt lỗi:** ruff `BLE001`, `S110`, `S112`. Mọi lỗi ra khỏi API là `BrainError` có `ErrorCode`.
- **Kích thước file:** cảnh báo, không fail, khi một file vượt 600 dòng.
- **Thời gian:** mỗi job test dưới 5 phút. Không xóa, skip hay giảm assertion để đạt thời gian.
- **SQLite:** WAL, `synchronous=FULL`, `secure_delete=ON`; macOS thêm `fullfsync=ON` và `checkpoint_fullfsync=ON`.
- **Ledger** chỉ chứa metadata có kiểu, ID và ref; payload có thời hạn lưu luôn nằm trong CAS.
- **Quyền:** toàn bộ data root owner-only. Windows: chỉ user hiện tại cộng SYSTEM. Unix: thư mục `0700`, file `0600`, `umask 077`.
- **Thời hạn mặc định:** payload Event 90 ngày, cấu hình được; giữ 7 bản backup mỗi loại.
- **Restore và migrate không bao giờ xóa dữ liệu:** bản cũ được đổi tên. Riêng `prune_backups` được xóa backup cũ theo spec 5.6.
- **Commit message** ghi attribution đúng người hoặc công cụ thực sự tham gia, theo hướng dẫn của harness đang chạy.

## Review Focus

1. **Data root nằm trong đường dẫn có dấu tiếng Việt hoặc khoảng trắng** (ví dụ `C:\Users\Lê Trung\…`): mọi thao tác chạy bình thường. Test ở Task 3 và Task 6.
2. **Ổ đĩa đầy khi ghi blob:** trả `storage_full`, không để lại blob dở trong `cas/`, không để file rác trong `staging/`. Test ở Task 9.
3. **Data root nằm trong OneDrive, ổ mạng hoặc tmpfs:** mức độ bền là `process_crash_durable`, có lý do. Test ở Task 5.
4. **Antivirus hoặc indexer trên Windows giữ file làm rename báo sharing violation:** thử lại có giới hạn (5 lần, chờ 50/100/200/400/800 ms), sau đó trả `filesystem_busy`. Test ở Task 5.
5. **Đồng hồ hệ thống lùi lại:** không có gì hết hạn sớm; UUIDv7 vẫn tăng dần; không crash. Test ở Task 2 và Task 12.

---

## File Structure

```
pyproject.toml, uv.lock, .gitignore
.github/workflows/ci.yml             ma trận 3 OS × 2 Python, chạy scripts/gate.py
scripts/gate.py                      gate mặc định và receipt
docs/design/sp1-crash-table.md       bảng điểm crash
src/superbrain/core/errors.py        ErrorCode, BrainError
src/superbrain/core/jsonvalue.py     JsonValue
src/superbrain/core/canonical.py     validate_json, canonical_json, digest_bytes, canonical_digest
src/superbrain/core/ids.py           IdGenerator, new_id, id_timestamp_ms
src/superbrain/core/faults.py        crashpoint, pausepoint, KNOWN_CRASHPOINTS
src/superbrain/ports/os.py           PathSafety, PermissionGuard, PermissionProblem, DurablePublisher,
                                     DurabilityTier, DurabilityReport, FsInfo, LockHandle, LockFactory, OsAdapters
src/superbrain/ports/clock.py        Clock
src/superbrain/ports/policy.py       IntentKind, Intent, PolicyView, PolicySource
src/superbrain/adapters/os/__init__.py     os_adapters()
src/superbrain/adapters/os/paths.py        OsPathSafety, default_data_root
src/superbrain/adapters/os/permissions.py  PosixPermissionGuard, WindowsPermissionGuard
src/superbrain/adapters/os/durable.py      PosixPublisher, DarwinPublisher, WindowsPublisher, detect_fs
src/superbrain/adapters/os/locks.py        OsLockFactory
src/superbrain/adapters/os/clock.py        SystemClock
src/superbrain/storage/layout.py     DataRoot, RESERVED_ENTRIES, prepare_data_root, secure_subdirectories
src/superbrain/storage/writer.py     LockState, WriterLease, acquire_writer
src/superbrain/storage/swap.py       stage_and_swap, recover_interrupted_swaps
src/superbrain/storage/sqlite.py     connect
src/superbrain/storage/schema.py     SchemaInfo, Migration, read_schema_info, ensure_writable, ensure_readable,
                                     initialize, STORE_MIGRATIONS, POLICY_MIGRATIONS
src/superbrain/storage/kinds.py      FieldType, EntryKind, KindRegistry, CORE_KINDS
src/superbrain/storage/ledger.py     LedgerEntry, ProjectionHandler, Txn
src/superbrain/storage/store.py      Store
src/superbrain/storage/cas.py        RetentionClass, ContentStore, HolderProjection, GcReport
src/superbrain/storage/policy_store.py  PolicyStore
src/superbrain/storage/runtime.py    Runtime, open_runtime
src/superbrain/storage/retention.py  RetentionPolicy, ExpiryReport, default_expiry, expire_due
src/superbrain/storage/backup.py     BackupManifest, create_store_backup, create_maintenance_backup,
                                     create_policy_backup, verify_backup, prune_backups
src/superbrain/storage/restore.py    RestoreReport, restore_store, restore_policy
src/superbrain/storage/migrate.py    MigrationReport, migrate_database
src/superbrain/{domain,application,mcp,cli_api,review_web,workers,composition,cli}/__init__.py   rỗng
tests/support/clock.py               FakeClock
tests/support/crash.py               run_child, run_until_crash, paused_child, ChildResult
tests/support/crash_child.py         operation của tiến trình con (chạy bằng runpy, không import tests.*)
tests/support/fs.py                  digest_tree, file_identity, read_all_bytes
tests/storage/conftest.py            fixture env, store, policy, os_, clock
tests/architecture/…, tests/core/…, tests/adapters/…, tests/storage/…
```

---

### Task 1: Scaffold dự án và hàng rào kiến trúc

**Files:**
- Create: `pyproject.toml`, `.gitignore` (gồm `.gate/`), `src/superbrain/__init__.py`, các `__init__.py` rỗng của mọi package
- Test: `tests/architecture/test_imports.py`

**Interfaces:**
- Produces: `LAYER_RULES: dict[str, frozenset[str]]` và `find_violations(root: Path, rules: Mapping[str, frozenset[str]]) -> list[tuple[str, str]]` trong file test. Task sau không sửa bảng này, trừ khi spec 4.2 đổi.

- [ ] **Step 1: Tạo `pyproject.toml`**

- `[build-system]`: `requires = ["hatchling>=1.26,<2"]`, `build-backend = "hatchling.build"`. `[tool.hatch.build.targets.wheel] packages = ["src/superbrain"]`. Nhờ có build system, `uv sync` cài chính project dạng editable vào `.venv` (sửa R2-06).
- `[project]`: `name = "super-brain2"`, `requires-python = ">=3.11"`, dependency `pywin32>=311; sys_platform == 'win32'`.
- `[dependency-groups] dev`: `pytest`, `mypy`, `ruff`, `import-linter`. Thêm bằng `uv add --dev`.
- `[tool.ruff]`: `target-version = "py311"`, `line-length = 120`, `lint.select = ["E","F","W","I","B","UP","BLE","S110","S112"]`.
- `[tool.mypy]`: `strict = true`, `files = ["src","tests"]`. Task 17 thêm `"scripts"` khi tạo `scripts/gate.py`.
- `[tool.pytest.ini_options]`: `testpaths = ["tests"]`, `addopts = ["--import-mode=importlib","-p","no:cacheprovider"]`.
- `[tool.importlinter]`: `root_package = "superbrain"`, kèm hai contract:
  - contract `layers`: `superbrain.composition`, `superbrain.mcp | superbrain.cli_api | superbrain.review_web | superbrain.workers`, `superbrain.application`, `superbrain.domain`, `superbrain.storage | superbrain.adapters`, `superbrain.ports`, `superbrain.core`;
  - contract `forbidden`: `superbrain.cli` không được import `superbrain.storage`, `.domain`, `.application`, `.adapters`, `.ports`.

- [ ] **Step 2: Viết test kiến trúc**

```python
LAYER_RULES = {
    "core": frozenset(), "ports": frozenset({"core"}),
    "storage": frozenset({"ports", "core"}), "adapters": frozenset({"ports", "core"}),
    "domain": frozenset({"ports", "core", "domain"}), "application": frozenset({"domain", "ports", "core"}),
    "mcp": frozenset({"application", "core"}), "cli_api": frozenset({"application", "core"}),
    "review_web": frozenset({"application", "core"}), "workers": frozenset({"application", "core"}),
    "cli": frozenset({"core"}), "composition": ALL_LAYERS - {"composition"},
}

def test_every_import_including_function_level_respects_layers():
    assert find_violations(SRC / "superbrain", LAYER_RULES) == []

def test_checker_detects_function_level_upward_import(tmp_path):
    pkg = make_package(tmp_path, {"superbrain/core/a.py": "def f():\n    import superbrain.storage.x\n",
                                  "superbrain/storage/x.py": ""})
    assert find_violations(pkg / "superbrain", LAYER_RULES) == [("superbrain.core.a", "superbrain.storage.x")]

def test_checker_detects_relative_and_type_checking_imports(tmp_path):
    pkg = make_package(tmp_path, {"superbrain/storage/a.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from ..adapters import b\n",
                                  "superbrain/adapters/b.py": ""})
    assert find_violations(pkg / "superbrain", LAYER_RULES) == [("superbrain.storage.a", "superbrain.adapters.b")]

def test_package_graph_is_acyclic():
    assert find_package_cycles(SRC / "superbrain") == []

def test_report_files_over_600_lines():
    for path, count in files_over(SRC, 600):
        warnings.warn(f"{path} has {count} lines (>600)")
```

- [ ] **Step 3: Chạy test, xác nhận fail**

Run: `uv run pytest tests/architecture -v`
Expected: FAIL, `NameError: find_violations`.

- [ ] **Step 4: Cài đặt `find_violations`, `find_package_cycles`, `files_over`, `make_package` trong file test**

`find_violations` duyệt AST mọi `.py`, lấy **mọi** `Import` và `ImportFrom` ở mọi độ sâu, resolve import tương đối theo tên module, chỉ xét tên bắt đầu bằng `superbrain.`.

- [ ] **Step 5: Cài project và kiểm tra interpreter sạch dùng đúng checkout**

Run: `uv sync && uv run python -I -c "import superbrain, pathlib; print(pathlib.Path(superbrain.__file__).resolve())"`
Expected: in ra đường dẫn nằm dưới `<repo>/src/superbrain/`. Chạy với `-I`, nên kết quả không phụ thuộc cwd hay `PYTHONPATH`.

- [ ] **Step 6: Chạy toàn bộ kiểm tra**

Run: `uv run pytest tests/architecture -v && uv run lint-imports && uv run ruff check src tests && uv run mypy`
Expected: PASS; lint-imports báo `2 kept, 0 broken`.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock .gitignore src tests
git commit -m "build: scaffold superbrain package with layer guardrails"
```

---

### Task 2: `core` — lỗi, canonical digest, UUIDv7, crashpoint

**Files:**
- Create: `src/superbrain/core/{errors,jsonvalue,canonical,ids,faults}.py`, `tests/fixtures/skill-body.txt`
- Test: `tests/core/test_canonical.py`, `tests/core/test_ids.py`, `tests/core/test_faults.py`

**Interfaces:**
- Produces:
  - `class ErrorCode(StrEnum)`: `invalid_input`, `identity_mismatch`, `not_found`, `quarantined`, `revision_conflict`, `idempotency_conflict`, `in_progress`, `commit_outcome_unknown`, `store_busy`, `deadline_exceeded`, `capability_unavailable`, `unsupported_version`, `migration_required`, `writer_held`, `unsafe_path`, `insecure_permissions`, `integrity_failure`, `storage_full`, `filesystem_busy`.
  - `class BrainError(Exception)`: `__init__(self, code: ErrorCode, message: str)`, thuộc tính `.code`, `.message`.
  - `JsonValue` (kiểu đệ quy của JSON).
  - `validate_json(value: object, *, reject_floats: bool = False) -> None`.
  - `canonical_json(value: object) -> bytes`: `sort_keys`, `separators=(",",":")`, `ensure_ascii=False`, `allow_nan=False`, UTF-8.
  - `digest_bytes(data: bytes) -> str`: trả `"sha256:<hex>"`.
  - `canonical_digest(kind: str, manifest: Mapping[str, JsonValue]) -> str`.
  - `class IdGenerator`: `__init__(self, now_ms: Callable[[], int], random_bits: Callable[[int], int])`, `next() -> str`. Sinh UUIDv7 thread-safe và tăng dần nghiêm ngặt:
    - trùng ms thì tăng bộ đếm 12 bit `rand_a`;
    - bộ đếm tràn (quá 4.095) thì mượn thêm 1 ms;
    - đồng hồ lùi thì giữ timestamp cuối cùng.
  - `new_id() -> str`: dùng generator mặc định với `time.time_ns() // 1_000_000` và `secrets.randbits`.
  - `id_timestamp_ms(value: str) -> int`.
  - `crashpoint(name: str) -> None`, `pausepoint(name: str) -> None`, `KNOWN_CRASHPOINTS: frozenset[str]`. Gọi với tên không có trong registry → `AssertionError`.

- [ ] **Step 1: Mang test từ nguồn và viết test mới**

Chép 5 test trong manifest, đổi tên hàm theo bảng manifest, **giữ nguyên** mọi giá trị hash. Mọi lỗi phải có `code == ErrorCode.INVALID_INPUT`. Thêm:

```python
def test_ids_are_v7_and_strictly_increasing_across_4096_in_one_ms():
    gen = IdGenerator(now_ms=lambda: 1_700_000_000_000, random_bits=lambda n: 0)
    ids = [gen.next() for _ in range(5000)]
    assert ids == sorted(ids) and len(set(ids)) == 5000
    assert all(uuid.UUID(i).version == 7 and uuid.UUID(i).variant == uuid.RFC_4122 for i in ids)

def test_clock_rollback_keeps_ids_increasing():                      # Review Focus 5
    times = iter([1000, 1000, 400, 400, 1001])
    gen = IdGenerator(now_ms=lambda: next(times), random_bits=lambda n: 0)
    ids = [gen.next() for _ in range(5)]
    assert ids == sorted(ids) and len(set(ids)) == 5

def test_ids_from_threads_are_unique():
    with ThreadPoolExecutor(8) as pool:
        ids = list(pool.map(lambda _: new_id(), range(8000)))
    assert len(set(ids)) == 8000

def test_crashpoint_reports_hit_and_exits_86():
    r = run_python("from superbrain.core.faults import crashpoint; crashpoint('cas.after_rename'); print('alive')",
                   env={"SUPERBRAIN_CRASHPOINT": "cas.after_rename"})
    assert r.returncode == 86 and "CRASHPOINT_HIT cas.after_rename" in r.stderr and "alive" not in r.stdout

def test_crashpoint_is_inert_for_other_names():
    r = run_python(SAME, env={"SUPERBRAIN_CRASHPOINT": "ledger.after_commit"})
    assert r.returncode == 0 and r.stdout.strip() == "alive"

def test_unregistered_crashpoint_is_a_programming_error():
    with pytest.raises(AssertionError): crashpoint("not.registered")
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/core -v`
Expected: FAIL, `ModuleNotFoundError`.

- [ ] **Step 3: Cài đặt**

`canonical.py` chép thân hàm từ `revisions.py` của nguồn, đổi `BrainError("invalid_input", …)` thành `BrainError(ErrorCode.INVALID_INPUT, …)`. `KNOWN_CRASHPOINTS` là đúng danh sách ở Task 16.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/core -v && uv run mypy`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `f83271d:src/ensemble_brain/core/revisions.py` (blob `d80d7f5`) và kết quả baseline.

---

### Task 3: Port `PathSafety` và adapter đường dẫn

**Files:**
- Create: `src/superbrain/ports/os.py` (phần `PathSafety`), `src/superbrain/adapters/os/paths.py`
- Test: `tests/adapters/test_paths.py`

**Interfaces:**
- Produces (`ports/os.py`): `class PathSafety(Protocol)`:
  - `reject_unsafe_path(raw: str) -> None`;
  - `reject_links(path: Path, *, entries: Sequence[Path] = ()) -> None`.
- Produces (adapter):
  - `OsPathSafety`:
    - `reject_unsafe_path`: trên Windows, từ chối tiền tố `\\?\`, `\\.\`, đường UNC `\\server\…`, và dấu `:` ngoài vị trí ký tự ổ đĩa;
    - `reject_links`: kiểm tra `path`, mọi tổ tiên đang tồn tại **và từng đường dẫn trong `entries`** đang tồn tại. Gặp symlink, hoặc `st_file_attributes & 0x400` (reparse point) → `BrainError(UNSAFE_PATH)`. Phần kiểm tra này trích từ `ownership.py`.
  - `default_data_root(env: Mapping[str, str], platform: str) -> Path`:
    - có `SUPERBRAIN_HOME` thì dùng;
    - `win32`: `%LOCALAPPDATA%\ensemble-brain`;
    - `darwin`: `~/Library/Application Support/ensemble-brain`;
    - còn lại: `$XDG_DATA_HOME/ensemble-brain`, mặc định `~/.local/share/ensemble-brain`.

- [ ] **Step 1: Viết test**

```python
@pytest.mark.parametrize("platform,env,expected", [
    ("win32", {"LOCALAPPDATA": r"C:\Users\Lê Trung\AppData\Local"}, PureWindowsPath(r"C:\Users\Lê Trung\AppData\Local\ensemble-brain")),
    ("darwin", {"HOME": "/Users/u"}, PurePosixPath("/Users/u/Library/Application Support/ensemble-brain")),
    ("linux", {"HOME": "/home/u"}, PurePosixPath("/home/u/.local/share/ensemble-brain")),
    ("linux", {"HOME": "/home/u", "XDG_DATA_HOME": "/data"}, PurePosixPath("/data/ensemble-brain")),
    ("linux", {"SUPERBRAIN_HOME": "/srv/brain"}, PurePosixPath("/srv/brain")),
])
def test_default_data_root(platform, env, expected): ...

def test_linked_root_is_refused(tmp_path, monkeypatch):            # port: test_runtime_refuses_linked_root_before_resolving_alias
    root = tmp_path / "runtime"; root.mkdir()
    fake_link(monkeypatch, root)
    with pytest.raises(BrainError) as e: OsPathSafety().reject_links(root)
    assert e.value.code == ErrorCode.UNSAFE_PATH

def test_linked_entry_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "runtime"; (root / "store").mkdir(parents=True)
    fake_link(monkeypatch, root / "store")
    with pytest.raises(BrainError): OsPathSafety().reject_links(root, entries=[root / "store"])

@windows_only
def test_real_junction_is_refused(tmp_path):
    target = tmp_path / "outside"; target.mkdir(); link = tmp_path / "root"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)   # junction không cần quyền admin
    with pytest.raises(BrainError): OsPathSafety().reject_links(link)

@pytest.mark.parametrize("raw", [r"\\?\C:\x", r"\\.\pipe\x", r"\\server\share\x", r"C:\x\file.db:stream"])
@windows_only
def test_reject_unsafe_windows_path(raw): ...

def test_vietnamese_and_space_path_is_accepted(tmp_path):            # Review Focus 1
    root = tmp_path / "thư mục có dấu" / "Lê Trung"; root.mkdir(parents=True)
    OsPathSafety().reject_links(root)
```

`fake_link(monkeypatch, path)` (đặt trong `tests/support/fs.py`) patch `Path.is_symlink` để trả `True` cho đúng `path`. Đây là cùng kỹ thuật với test nguồn, dùng cho các OS không tạo được symlink khi thiếu quyền. Junction thật được thử riêng trên Windows.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_paths.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_paths.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `ownership.py` (blob `d28475c`) và `test_runtime_path_safety.py` (blob `7c48659`).

---

### Task 4: Quyền owner-only và đồng hồ

**Files:**
- Create: `src/superbrain/ports/os.py` (phần quyền), `src/superbrain/ports/clock.py`, `src/superbrain/adapters/os/permissions.py`, `src/superbrain/adapters/os/clock.py`, `tests/support/clock.py`
- Test: `tests/adapters/test_permissions.py`

**Interfaces:**
- Produces (`ports/os.py`):
  - `@dataclass(frozen=True) class PermissionProblem`: `path: Path`, `reason: str`.
  - `class PermissionGuard(Protocol)`:
    - `secure_directory(path: Path) -> None`;
    - `secure_file(path: Path) -> None`;
    - `problems(root: Path) -> list[PermissionProblem]`, duyệt đệ quy;
    - `check_ancestors(path: Path) -> list[PermissionProblem]`.
- Produces (`ports/clock.py`): `class Clock(Protocol)` với `now() -> datetime`, luôn có timezone UTC.
- Produces (adapter): `PosixPermissionGuard`, `WindowsPermissionGuard`, `SystemClock`.
- Produces (test support): `FakeClock(start: datetime)` với `.now()`, `.advance(delta)`, `.set(value)`.

**Quy tắc:**

| | POSIX | Windows |
|---|---|---|
| `secure_directory` | chmod `0o700` | DACL được bảo vệ (tắt kế thừa), chỉ hai ACE `FILE_ALL_ACCESS` kèm `OBJECT_INHERIT_ACE \| CONTAINER_INHERIT_ACE` cho SID của user hiện tại và `S-1-5-18`; đặt owner là user hiện tại |
| `secure_file` | chmod `0o600` | Như trên, không có cờ kế thừa |
| `problems` | `mode & 0o077 != 0`, hoặc `st_uid != geteuid()` | Có ACE cho phép truy cập tới SID khác hai SID trên; hoặc owner SID khác user hiện tại |
| `check_ancestors` | Mọi tổ tiên tới `/`: cho group/other ghi mà không có sticky bit → báo; owner khác root và khác user → báo | Gọi nhóm tin cậy là {user, SYSTEM, Administrators `S-1-5-32-544`, TrustedInstaller `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`}. Với mọi tổ tiên tới gốc ổ đĩa: **owner SID ngoài nhóm tin cậy → báo**, vì owner luôn tự sửa được DACL (sửa R2-08); có ACE cấp `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER` hoặc `GENERIC_ALL`/`FILE_ALL_ACCESS` cho SID ngoài nhóm tin cậy → báo. `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY` không bị tính, vì chúng không cho đổi tên hay xóa entry của người khác |

Administrators, SYSTEM và TrustedInstaller được chấp nhận vì chúng đã có toàn quyền trên máy. Đây là giới hạn đã công bố ở spec 5.9 và 11.3.

- [ ] **Step 1: Viết test**

```python
def test_secured_tree_has_no_problems(tmp_path, guard):
    d = tmp_path / "root"; d.mkdir(); guard.secure_directory(d)
    f = d / "x.db"; f.write_bytes(b"x"); guard.secure_file(f)
    assert guard.problems(d) == []

@posix_only
def test_group_readable_file_is_reported(tmp_path, guard):
    f = secured_file(tmp_path, guard); os.chmod(f, 0o640)
    assert [p.path for p in guard.problems(f.parent)] == [f]

@windows_only
def test_everyone_ace_is_reported(tmp_path, guard):
    f = secured_file(tmp_path, guard); grant(f, "S-1-1-0", FILE_GENERIC_READ)
    assert [p.path for p in guard.problems(f.parent)] == [f]

@windows_only
def test_ancestor_with_delete_child_for_users_is_reported(tmp_path, guard):
    parent = tmp_path / "p"; parent.mkdir(); grant(parent, "S-1-5-32-545", FILE_DELETE_CHILD)
    assert guard.check_ancestors(parent / "root") != []

@windows_only
def test_foreign_owned_ancestor_with_safe_looking_dacl_is_reported(tmp_path, guard, monkeypatch):
    parent = tmp_path / "p"; parent.mkdir(); guard.secure_directory(parent)
    fake_owner(monkeypatch, parent, "S-1-5-21-1-2-3-1001")         # owner là tài khoản khác; DACL vẫn chỉ có user + SYSTEM
    assert [x.path for x in guard.check_ancestors(parent / "root") if x.path == parent] == [parent]

@windows_only
def test_trusted_owner_chain_is_accepted(tmp_path, guard):
    assert [x for x in guard.check_ancestors(tmp_path / "root") if x.path.is_relative_to(tmp_path)] == []

@posix_only
def test_world_writable_ancestor_without_sticky_is_reported(tmp_path, guard):
    p = tmp_path / "open"; p.mkdir(); os.chmod(p, 0o777)
    assert guard.check_ancestors(p / "root") != []

@posix_only
def test_sticky_world_writable_ancestor_is_accepted(tmp_path, guard):
    p = tmp_path / "tmpdir"; p.mkdir(); os.chmod(p, 0o1777)
    assert [x for x in guard.check_ancestors(p / "root") if x.path == p] == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_permissions.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt theo bảng quy tắc**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_permissions.py -v`
Expected: PASS. Test của OS khác được skip kèm lý do.

- [ ] **Step 5: Commit**

---

### Task 5: `durable_publish` và mức độ bền

**Files:**
- Create: `src/superbrain/ports/os.py` (phần độ bền), `src/superbrain/adapters/os/durable.py`
- Test: `tests/adapters/test_durable.py`

**Interfaces:**
- Produces (`ports/os.py`):
  - `class DurabilityTier(StrEnum)`: `POWER_LOSS = "power_loss_durable"`, `PROCESS_CRASH = "process_crash_durable"`.
  - `@dataclass(frozen=True) class DurabilityReport`: `tier: DurabilityTier`, `reasons: tuple[str, ...]`.
  - `@dataclass(frozen=True) class FsInfo`: `fs_type: str`, `remote: bool`.
  - `class DurablePublisher(Protocol)`:
    - `write_new(path: Path, data: bytes) -> None`: `O_CREAT|O_EXCL`, ghi đủ, làm bền nội dung;
    - `publish(staging: Path, final: Path) -> None`: rename nguyên tử, rồi làm bền entry của thư mục đích;
    - `rename_dir(src: Path, dst: Path) -> None`: rename thư mục; đích đã tồn tại → `FileExistsError`; rồi làm bền thư mục cha;
    - `sync_directory(directory: Path) -> None`;
    - `durability(directory: Path, env: Mapping[str, str]) -> DurabilityReport`.
- Produces (adapter): `PosixPublisher`, `DarwinPublisher`, `WindowsPublisher`, mỗi cái có `__init__(self, *, sleep: Callable[[float], None] = time.sleep, fs_info: Callable[[Path], FsInfo] = detect_fs)`; `publisher_for(platform: str) -> DurablePublisher`; `detect_fs(path: Path) -> FsInfo`.

| Thao tác | Linux | macOS | Windows |
|---|---|---|---|
| Làm bền file | `os.fsync(fd)` | `fcntl(fd, F_FULLFSYNC)` | `os.fsync(fd)` (gọi `FlushFileBuffers`) |
| Rename file | `os.replace` | `os.replace` | `MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` |
| Rename thư mục | `os.rename` sau khi kiểm tra đích chưa có | như Linux | `MoveFileExW(src, dst, MOVEFILE_WRITE_THROUGH)` |
| Làm bền thư mục | `fsync` fd thư mục (từ `_fsync_directory` của nguồn) | `F_FULLFSYNC` fd thư mục | Không có thao tác riêng; `MOVEFILE_WRITE_THROUGH` đảm nhiệm |
| Sharing violation (`winerror` 32, 5) | – | – | Thử lại 5 lần, chờ 50/100/200/400/800 ms; vẫn lỗi → `FILESYSTEM_BUSY` |
| `ENOSPC` / `winerror` 112 | `STORAGE_FULL` | `STORAGE_FULL` | `STORAGE_FULL` |

**`durability()` theo danh sách cho phép.** Hàm trả `POWER_LOSS` chỉ khi **cả ba** điều kiện đúng:
1. `fs_info(directory)` không phải remote, và `fs_type` thuộc danh sách đã biết là bền:
   - Linux `{ext4, ext3, xfs, btrfs, f2fs, zfs}`;
   - macOS `{apfs, hfs}`;
   - Windows `{NTFS, ReFS}`, với `GetDriveTypeW == DRIVE_FIXED`.
2. Thư mục không nằm dưới đường dẫn của `env["OneDrive"]`, `env["OneDriveConsumer"]` hay `env["OneDriveCommercial"]`.
3. Probe thành công: `write_new` một file tạm trong thư mục, `publish`, `sync_directory`, xóa file tạm. Trên macOS, probe gồm cả `F_FULLFSYNC`.

Trường hợp còn lại trả `PROCESS_CRASH`, kèm lý do cụ thể: `volatile filesystem tmpfs`, `unknown filesystem <tên>`, `remote filesystem`, `cloud-synced folder (OneDrive)`, `sync probe failed: <errno>`.

`detect_fs` lấy thông tin theo từng OS:
- Linux: đọc `/proc/self/mountinfo`, lấy mount point dài nhất là tiền tố của đường dẫn;
- macOS: `os.statvfs` không có tên fs, nên dùng `ctypes` gọi `statfs` để lấy `f_fstypename`;
- Windows: `GetVolumeInformationW` và `GetDriveTypeW`.

- [ ] **Step 1: Viết test**

```python
def test_publish_moves_bytes_and_leaves_no_staging(tmp_path, publisher): ...
def test_write_new_refuses_existing_file(tmp_path, publisher): ...
def test_rename_dir_refuses_existing_target(tmp_path, publisher): ...

def test_disk_full_maps_to_storage_full(tmp_path, publisher, monkeypatch):
    monkeypatch.setattr(os, "write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(BrainError) as e: publisher.write_new(tmp_path / "x", b"data")
    assert e.value.code == ErrorCode.STORAGE_FULL

@pytest.mark.parametrize("info,reason", [
    (FsInfo("tmpfs", False), "volatile filesystem tmpfs"),
    (FsInfo("ramfs", False), "volatile filesystem ramfs"),
    (FsInfo("weirdfs", False), "unknown filesystem weirdfs"),
    (FsInfo("ext4", True), "remote filesystem"),
])
def test_non_allowlisted_filesystems_are_process_crash(tmp_path, info, reason):     # Review Focus 3
    report = publisher_with(fs=info).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH and reason in report.reasons

def test_onedrive_folder_is_process_crash(tmp_path):
    report = publisher_with(fs=KNOWN_GOOD_FS).durability(tmp_path / "d", {"OneDrive": str(tmp_path)})
    assert report.tier == DurabilityTier.PROCESS_CRASH

def test_failed_probe_is_process_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fsync", raising(OSError(errno.EINVAL, "no")))
    assert publisher_with(fs=KNOWN_GOOD_FS).durability(tmp_path, {}).tier == DurabilityTier.PROCESS_CRASH

def test_known_filesystem_with_passing_probe_is_power_loss(tmp_path):
    assert publisher_with(fs=KNOWN_GOOD_FS).durability(tmp_path, {}).tier == DurabilityTier.POWER_LOSS

def test_detect_fs_reports_this_machine(tmp_path):
    info = detect_fs(tmp_path); assert info.fs_type != ""        # không assert tier, vì tier phụ thuộc môi trường

@windows_only
def test_transient_sharing_violation_is_retried(tmp_path, monkeypatch):      # Review Focus 4
    fake = FlakyMoveFileEx(failures=2, winerror=32); monkeypatch.setattr(durable, "_move_file_ex", fake)
    WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert fake.calls == 3

@windows_only
def test_persistent_sharing_violation_is_filesystem_busy(tmp_path, monkeypatch):
    monkeypatch.setattr(durable, "_move_file_ex", FlakyMoveFileEx(failures=99, winerror=32))
    with pytest.raises(BrainError) as e: WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert e.value.code == ErrorCode.FILESYSTEM_BUSY
```

`KNOWN_GOOD_FS` là `FsInfo` tương ứng nền tảng đang chạy test: `ext4`, `apfs` hoặc `NTFS`.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_durable.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt theo các bảng trên**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_durable.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `_fsync_directory` từ `artifacts.py` (blob `b0bb49c`).

---

### Task 6: Khóa ghi, bố cục data root, writer lease và harness tiến trình con

**Files:**
- Create: `src/superbrain/ports/os.py` (phần khóa và `OsAdapters`), `src/superbrain/adapters/os/locks.py`, `src/superbrain/adapters/os/__init__.py`, `src/superbrain/storage/layout.py`, `src/superbrain/storage/writer.py`, `tests/support/crash.py`, `tests/support/crash_child.py`, `tests/support/fs.py`
- Test: `tests/storage/test_writer.py`, `tests/storage/test_layout.py`, `tests/support/test_crash_harness.py`

**Interfaces:**
- Produces (`ports/os.py`):
  - `class LockHandle(Protocol)`: `read_payload() -> bytes`, `write_payload(offset: int, data: bytes) -> None`, `release() -> None`.
  - `class LockFactory(Protocol)`: `acquire(path: Path) -> LockHandle`. Khóa đang bị giữ → `BrainError(WRITER_HELD)` ngay.
  - `@dataclass(frozen=True) class OsAdapters`: `paths: PathSafety`, `permissions: PermissionGuard`, `publisher: DurablePublisher`, `locks: LockFactory`, `clock: Clock`.
- Produces (adapter):
  - `OsLockFactory`: Windows `msvcrt.locking(fd, LK_NBLCK, 1)` trên byte 0; Unix `fcntl.flock(LOCK_EX|LOCK_NB)`. Không bao giờ xóa file khóa.
  - `os_adapters(clock: Clock | None = None) -> OsAdapters`.
- Produces (`storage/layout.py`):
  - `@dataclass(frozen=True) class DataRoot`:
    - các trường `root`, `lock_path`, `policy_dir`, `store_dir`, `outbox_dir`, `logs_dir`, `backups_dir`;
    - property `policy_db`, `store_db`, `cas_dir`, `staging_dir`.
  - `RESERVED_ENTRIES: tuple[str, ...]`, đường dẫn tương đối: `writer.lock`, `policy`, `policy/policy.db`, `policy/policy.db-wal`, `policy/policy.db-shm`, `store`, `store/brain.db`, `store/brain.db-wal`, `store/brain.db-shm`, `store/cas`, `store/staging`, `outbox`, `logs`, `backups`. Cộng mọi entry đang tồn tại có tên khớp `store.*` hoặc `policy.*`.
  - `prepare_data_root(root: Path, os_: OsAdapters) -> DataRoot`. **Không** tạo hay sửa gì ngoài `root` và `writer.lock`. Thứ tự:
    1. `paths.reject_unsafe_path`;
    2. `paths.reject_links(root, entries=<mọi RESERVED_ENTRIES đang tồn tại>)`;
    3. `permissions.check_ancestors(root)`: có vấn đề → `INSECURE_PERMISSIONS`;
    4. tạo `root` nếu chưa có, rồi `secure_directory(root)`;
    5. tạo `writer.lock` nếu chưa có, rồi `secure_file`.

    Bước 2 và 3 chạy **trước** mọi chmod hay open.
  - `secure_subdirectories(root: DataRoot, lease: WriterLease, os_: OsAdapters) -> None`: kiểm tra lại `reject_links`, rồi tạo và bảo vệ `policy/`, `store/`, `store/cas/`, `store/staging/`, `outbox/`, `logs/`, `backups/`.
- Produces (`storage/writer.py`):
  - `@dataclass(frozen=True) class LockState`: `writer_epoch: int`, `trust_generation_hwm: int`.
  - `class WriterLease`, dùng được làm context manager:
    - thuộc tính `root: DataRoot`, `epoch: int`;
    - `state() -> LockState`;
    - `raise_trust_hwm(value: int) -> None`: không bao giờ giảm;
    - `bump_epoch() -> int`;
    - `release() -> None`;
    - `register_handle(name: str) -> None`, `unregister_handle(name: str) -> None`, `open_handles() -> frozenset[str]`.
  - `acquire_writer(root: DataRoot, os_: OsAdapters) -> WriterLease`: lấy khóa, đọc slot, tăng `writer_epoch` rồi ghi bền **trước khi** trả về.
- Produces (test support):
  - `run_child(operation: str, data_root: Path, *args: str) -> ChildResult`, với `ChildResult` có `returncode`, `stdout`, `stderr`, `error_code: str | None`, `hit: str | None`.
  - `run_until_crash(operation: str, crashpoint: str, data_root: Path, *args: str) -> ChildResult`: **assert** `returncode == 86` và `hit == crashpoint`.
  - `paused_child(operation: str, pausepoint: str, data_root: Path) -> AbstractContextManager[subprocess.Popen[str]]`: chờ dòng `PAUSED <tên>`, yield, rồi gửi một dòng vào stdin và chờ child kết thúc.
  - `crash_child.py`:
    - in `ERROR <code>` khi gặp `BrainError`;
    - định nghĩa bảng `OPERATIONS: dict[str, Callable[[Path, list[str]], None]]`;
    - operation đầu tiên là `ping`, in `superbrain.__file__`.
  - `tests/support/fs.py`: `digest_tree(path) -> dict[str, str]`, `file_identity(path) -> tuple[int, int]`, `read_all_bytes(paths) -> bytes`, `fake_link(monkeypatch, path)`.

- [ ] **Step 1: Viết test**

```python
def test_child_imports_this_checkout():                                  # sửa I1-09
    r = run_child("ping", Path("."))
    assert r.returncode == 0 and Path(r.stdout.strip()).is_relative_to(REPO / "src")

def test_run_until_crash_fails_when_point_is_not_hit(tmp_path):
    with pytest.raises(AssertionError): run_until_crash("ping", "ledger.after_commit", tmp_path)

def test_second_process_cannot_acquire_while_held(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    with acquire_writer(root, os_adapters()):
        assert run_child("acquire_writer", root.root).error_code == "writer_held"

def test_lock_released_when_holder_process_is_killed(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    with paused_child("acquire_writer_and_pause", "writer.held", root.root) as child:
        child.kill()
    with acquire_writer(root, os_adapters()) as lease: assert lease.epoch == 2

def test_epoch_increments_on_every_acquisition(tmp_path): ...            # [1, 2, 3]
def test_trust_hwm_never_decreases(tmp_path): ...                        # raise 5, raise 3 → 5

def test_torn_slot_write_falls_back_to_other_slot(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    with acquire_writer(root, os_adapters()): pass
    run_until_crash("acquire_writer", "writer.mid_slot_write", root.root)
    with acquire_writer(root, os_adapters()) as lease: assert lease.epoch == 2

def test_both_slots_corrupt_is_integrity_failure(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters()); corrupt_bytes(root.lock_path, offsets=[10, 266])
    with pytest.raises(BrainError) as e: acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

@pytest.mark.parametrize("entry", ["writer.lock", "store", "policy", "store/brain.db", "store/cas", "store/staging", "store.restoring"])
def test_prepare_refuses_linked_reserved_entry_before_touching_anything(tmp_path, monkeypatch, entry):
    root = tmp_path / "r"; make_entry(root, entry); fake_link(monkeypatch, root / entry)
    before = digest_tree(tmp_path); modes = modes_tree(tmp_path)
    with pytest.raises(BrainError) as e: prepare_data_root(root, os_adapters())
    assert e.value.code == ErrorCode.UNSAFE_PATH and digest_tree(tmp_path) == before and modes_tree(tmp_path) == modes

def test_prepare_touches_only_root_and_lock(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    assert sorted(p.name for p in root.root.iterdir()) == ["writer.lock"]

def test_subdirectories_are_secured_under_lease(tmp_path):
    root = prepare_data_root(tmp_path / "Lê Trung", os_adapters())     # Review Focus 1
    with acquire_writer(root, os_adapters()) as lease:
        secure_subdirectories(root, lease, os_adapters())
    assert os_adapters().permissions.problems(root.root) == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_writer.py tests/storage/test_layout.py tests/support -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

Crashpoint `writer.mid_slot_write` đặt sau khi ghi 128 byte đầu của slot. Pausepoint `writer.held` dùng cho operation `acquire_writer_and_pause`.

Mỗi task sau tự thêm vào `OPERATIONS` các operation mà test của nó dùng, ví dụ `append_demo`, `put_and_hold`, `tombstone_event`, `backup_store`, `restore_from_latest`, `restore_policy_from_latest`, `migrate_store_to_v2`, `open_runtime`. Mỗi pausepoint dùng cùng tên với crashpoint tương ứng: `pausepoint(name)` được gọi ngay trước `crashpoint(name)` tại mọi điểm.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_writer.py tests/storage/test_layout.py tests/support -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 7: SQLite và kiểm tra phiên bản khi đọc và khi ghi

**Files:**
- Create: `src/superbrain/storage/sqlite.py`, `src/superbrain/storage/schema.py`
- Test: `tests/storage/test_schema.py`

**Interfaces:**
- Produces:
  - `connect(path: Path, *, readonly: bool = False, platform: str = sys.platform) -> sqlite3.Connection`.
    - Mặc định: `isolation_level=None`, `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `secure_delete=ON`, `busy_timeout=5000`.
    - `darwin`: thêm `fullfsync=ON`, `checkpoint_fullfsync=ON`.
    - `readonly`: mở bằng URI `file:<path>?mode=ro`, và không đổi `journal_mode`.
  - `@dataclass(frozen=True) class SchemaInfo`: `schema_version: int`, `min_reader_version: int`, `store_id: str`.
  - `@dataclass(frozen=True) class Migration`: `to_version: int`, `min_reader_version: int`, `apply: Callable[[sqlite3.Connection], None]`.
  - `STORE_MIGRATIONS`, `POLICY_MIGRATIONS`: `tuple[Migration, ...]`, mỗi tuple có đúng một migration tạo v1.
  - `code_version(migrations: Sequence[Migration]) -> int`.
  - `read_schema_info(path: Path) -> SchemaInfo | None`: chỉ đọc. Không có file → `None`.
  - `ensure_writable(info: SchemaInfo, migrations: Sequence[Migration]) -> None`:
    - `info.schema_version > code` → `UNSUPPORTED_VERSION`, **bất kể** `min_reader_version`;
    - `<` → `MIGRATION_REQUIRED`.
  - `ensure_readable(info: SchemaInfo, migrations: Sequence[Migration]) -> None`: `info.min_reader_version > code` → `UNSUPPORTED_VERSION`.
  - `initialize(db: sqlite3.Connection, migrations: Sequence[Migration], *, store_id: str) -> None`: chỉ dùng cho DB mới.

- [ ] **Step 1: Viết test**

```python
def test_connection_pragmas(tmp_path):
    db = connect(tmp_path / "a.db")
    assert pragma(db, "journal_mode") == "wal" and pragma(db, "synchronous") == 2 and pragma(db, "secure_delete") == 1

def test_darwin_enables_fullfsync(tmp_path):
    assert pragma(connect(tmp_path / "a.db", platform="darwin"), "fullfsync") == 1

@pytest.mark.parametrize("schema,min_reader", [(2, 1), (99, 99)])
def test_newer_schema_is_never_writable_even_if_readable(tmp_path, schema, min_reader):   # tình huống 26
    path = make_db_with_meta(tmp_path, schema_version=schema, min_reader_version=min_reader)
    before = read_all_bytes(db_files(path))
    with pytest.raises(BrainError) as e: ensure_writable(read_schema_info(path), STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and read_all_bytes(db_files(path)) == before

def test_newer_schema_with_compatible_reader_is_readable(tmp_path):
    ensure_readable(read_schema_info(make_db_with_meta(tmp_path, schema_version=2, min_reader_version=1)), STORE_MIGRATIONS)

def test_older_schema_requires_explicit_migration(tmp_path):
    with pytest.raises(BrainError) as e:
        ensure_writable(read_schema_info(make_db_with_meta(tmp_path, schema_version=0, min_reader_version=0)), STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED

def test_read_schema_info_does_not_create_wal(tmp_path):
    path = make_db_with_meta(tmp_path, schema_version=1, min_reader_version=1); checkpoint_and_remove_wal(path)
    read_schema_info(path)
    assert not path.with_name(path.name + "-wal").exists()
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_schema.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_schema.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 8: Entry kind có kiểu, ledger, transaction, projection

**Files:**
- Create: `src/superbrain/ports/policy.py`, `src/superbrain/storage/kinds.py`, `src/superbrain/storage/ledger.py`, `src/superbrain/storage/store.py`, `tests/storage/conftest.py`
- Test: `tests/storage/test_kinds.py`, `tests/storage/test_ledger.py`

**Interfaces:**
- Produces (`ports/policy.py`):
  - `class IntentKind(StrEnum)`: `TOMBSTONE = "tombstone"`, `QUARANTINE = "quarantine"`.
  - `@dataclass(frozen=True) class Intent`: `intent_id: str`, `kind: IntentKind`, `payload: Mapping[str, JsonValue]`, `created_at: str`.
  - `class PolicyView(Protocol)`: `is_quarantined(digest: str) -> bool`, `is_tombstoned(holder_kind: str, holder_id: str) -> bool`.
  - `class PolicySource(PolicyView, Protocol)`: `intents() -> Sequence[Intent]`, `store_id: str` (property).
- Produces (`storage/kinds.py`):
  - `class FieldType(StrEnum)`: `UUID`, `DIGEST`, `INT`, `TIMESTAMP`, `BOOL`, `ENUM`.
  - `@dataclass(frozen=True) class EntryKind`: `kind: str`, `handler_version: int`, `fields: Mapping[str, FieldType]`, `enums: Mapping[str, frozenset[str]]`, `nullable: frozenset[str] = frozenset()`. Mọi trường trong `fields` là bắt buộc phải có mặt; trường thuộc `nullable` được phép mang giá trị `null`.
  - `class KindRegistry`: `__init__(self, kinds: Iterable[EntryKind])`, `get(kind: str) -> EntryKind` (không có → `INVALID_INPUT`), `validate(kind: str, meta: Mapping[str, JsonValue]) -> None`.
  - `CORE_KINDS: tuple[EntryKind, ...]`, gồm:
    - `cas.hold` với `{digest: DIGEST, holder_kind: ENUM, holder_id: UUID, retention: ENUM, expires_at: TIMESTAMP}`, trong đó `expires_at` nullable;
    - `cas.release` với `{digest: DIGEST, holder_kind: ENUM, holder_id: UUID, reason: ENUM}`;
    - `policy.quarantine` với `{digest: DIGEST, intent_id: UUID}`;
    - `policy.tombstone` với `{holder_kind: ENUM, holder_id: UUID, intent_id: UUID}`.

    Enum `holder_kind ∈ {event, evidence, artifact, lesson, proposal, receipt}`, `retention ∈ {event_payload, evidence, durable}`, `reason ∈ {expired, tombstoned, superseded, deleted_by_owner}`.
  - Quy tắc kiểm tra:
    - không cho khóa thừa;
    - không lồng nhau;
    - `UUID` phải là UUID hợp lệ;
    - `DIGEST` theo mẫu `^sha256:[0-9a-f]{64}$`;
    - `TIMESTAMP` dạng ISO-8601 UTC có `Z`;
    - `actor` theo mẫu `^(user|system|principal):[a-z0-9][a-z0-9._:-]{0,63}$`;
    - `owner_id` theo mẫu `^[a-z0-9][a-z0-9._-]{0,63}$`;
    - mỗi phần tử của `refs` theo mẫu `DIGEST`; `refs` không có phần tử trùng.
- Produces (`storage/ledger.py`):
  - `@dataclass(frozen=True) class LedgerEntry`: `sequence: int`, `entry_id: str`, `kind: str`, `schema_version: int`, `handler_version: int`, `writer_epoch: int`, `actor: str`, `owner_id: str | None`, `recorded_at: str`, `meta: Mapping[str, JsonValue]`, `refs: tuple[str, ...]`.
  - `class ProjectionHandler(Protocol)`:
    - thuộc tính `name: str`, `handler_version: int`, `kinds: frozenset[str]`;
    - `create_tables(db: sqlite3.Connection, prefix: str) -> None`;
    - `apply(db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None`.
  - `class Txn`:
    - `append(kind: str, *, actor: str, owner_id: str | None, meta: Mapping[str, JsonValue], refs: Sequence[str] = ()) -> LedgerEntry`. `handler_version` lấy từ registry, không do caller chọn. Kiểm tra (`validate`) chạy **trước khi** ghi.
    - `mark_intent_applied(intent_id: str) -> bool`: `False` nếu đã có.
    - thuộc tính `db: sqlite3.Connection`.
- Produces (`storage/store.py`): `class Store`.
  - Hàm khởi tạo và đóng:
    - `create(root: DataRoot, lease: WriterLease, os_: OsAdapters, policy: PolicySource, handlers: Sequence[ProjectionHandler], kinds: KindRegistry, *, migrations: Sequence[Migration] = STORE_MIGRATIONS) -> Store` (classmethod): tạo DB mới với `store_id = policy.store_id`;
    - `open(...)` (classmethod, cùng tham số): gọi `ensure_writable(info, migrations)`; `store_id` trong DB khác `policy.store_id` → `INTEGRITY_FAILURE`; `lease.register_handle("store")`;
    - `close() -> None`: `unregister_handle`. Sau khi đóng, mọi lời gọi → `AssertionError("store closed")`.
    - Owner thread là thread gọi `create`/`open`. Mọi method public gọi từ thread khác → `AssertionError("store used off its owner thread")` (sửa R2-09).
  - Ghi và đọc:
    - `transaction() -> AbstractContextManager[Txn]`;
    - `entries(after: int = 0) -> Iterator[LedgerEntry]`;
    - `rebuild_projections() -> int`;
    - `db_integrity() -> str`;
    - `store_id: str` (property).
  - Bảo trì: `maintenance() -> AbstractContextManager[None]`, cờ không lồng được. Gọi `maintenance()` khi cờ đang bật → `BrainError(STORE_BUSY)`.
  - Phụ trợ tạm thời: `reconcile_policy() -> int` ở task này chỉ là chỗ móc rỗng trả 0; Task 11 cài đặt thật. Thuộc tính `cas` được Task 9 thêm vào.

Thứ tự transaction:
1. `BEGIN IMMEDIATE`;
2. `append`: `validate` → `INSERT` ledger → `handler.apply(db, "p_<name>_", entry, policy)` cho handler có `kind` tương ứng;
3. `crashpoint("ledger.before_commit")`;
4. `COMMIT`;
5. `crashpoint("ledger.after_commit")`.

Có exception thì `ROLLBACK`.

`rebuild_projections`:
1. tạo bảng `r_`;
2. replay toàn bộ entry; entry có `handler_version` lớn hơn của handler → `UNSUPPORTED_VERSION` và xóa bảng `r_`;
3. trong một transaction: `DROP` các bảng `p_`, rồi `RENAME` bảng `r_` thành `p_`.

DDL v1: bảng `ledger` (cột như `LedgerEntry`; `meta` và `refs` dạng canonical JSON), `applied_intents(intent_id TEXT PRIMARY KEY, applied_sequence INTEGER NOT NULL)`, `meta`.

Fixture trong `tests/storage/conftest.py` (task này tạo):
- `os_`: adapters thật cộng `FakeClock`;
- `StaticPolicy`: test double cài `PolicySource`, có `store_id` cố định và danh sách quarantine/tombstone/intents;
- `CounterProjection`: handler đếm entry `demo.count`;
- `DEMO_KINDS`: `CORE_KINDS` cộng `demo.count {n: INT}`;
- `store_factory(handlers=..., policy=...)`: tạo data root mới, lấy lease, `Store.create`.

- [ ] **Step 1: Viết test**

```python
@pytest.mark.parametrize("meta", [
    {"n": 1, "extra": 2}, {"n": "1"}, {"n": {"nested": 1}}, {},
])
def test_meta_outside_schema_is_rejected_before_write(store_factory, meta):          # sửa I1-08
    store = store_factory(handlers=[CounterProjection()])
    with pytest.raises(BrainError) as e:
        with store.transaction() as t: t.append("demo.count", actor="user:cli", owner_id="dan", meta=meta)
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []

@pytest.mark.parametrize("refs", [["tiny-secret-7f3a"], [D, D], ["sha256:XYZ"]])
def test_refs_must_be_unique_digests(store_factory, refs):
    with pytest.raises(BrainError):
        with store_factory().transaction() as t: t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1}, refs=refs)

def test_nullable_field_accepts_null_but_must_be_present(store_factory):
    hold = {"digest": D, "holder_kind": "lesson", "holder_id": U, "retention": "durable"}
    with store_factory().transaction() as t: t.append("cas.hold", actor="system:worker:x", owner_id="dan", meta={**hold, "expires_at": None})
    with pytest.raises(BrainError):
        with store_factory().transaction() as t: t.append("cas.hold", actor="system:worker:x", owner_id="dan", meta=hold)

def test_free_text_payload_cannot_enter_ledger(store_factory):
    with pytest.raises(BrainError):
        with store_factory().transaction() as t:
            t.append("cas.release", actor="user:cli", owner_id="dan",
                     meta={"digest": D, "holder_kind": "event", "holder_id": U, "reason": "tiny-secret-7f3a"})

def test_unknown_kind_creates_nothing(store_factory):                                 # sửa I1-02
    store = store_factory(handlers=[CounterProjection()])
    with pytest.raises(BrainError):
        with store.transaction() as t: t.append("demo.unknown", actor="user:cli", owner_id="dan", meta={})
    assert list(store.entries()) == [] and counter(store) == 0

def test_append_and_projection_commit_together(store_factory): ...
def test_exception_rolls_back_ledger_and_projection(store_factory): ...
def test_entries_record_epoch_and_registry_version(store_factory): ...    # writer_epoch == 1, handler_version == 1

def test_rebuild_reproduces_projection_without_duplicates(store_factory):             # tình huống 6 (phần projection)
    store = store_factory(handlers=[CounterProjection()]); append_n(store, 5)
    assert store.rebuild_projections() == 5 and counter(store) == 5
    assert store.rebuild_projections() == 5 and counter(store) == 5

def test_foreign_history_with_newer_handler_stops_rebuild(store_factory):
    store = store_factory(handlers=[CounterProjection()]); append_n(store, 1)
    insert_raw_ledger_row(store, kind="demo.count", handler_version=9)       # mô phỏng lịch sử từ binary khác
    with pytest.raises(BrainError) as e: store.rebuild_projections()
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and counter(store) == 1

def test_store_id_mismatch_with_policy_is_refused(tmp_path): ...

def test_closed_store_cannot_be_used(store_factory):
    store = store_factory(); store.close()
    with pytest.raises(AssertionError): store.transaction()

def test_store_refuses_use_from_another_thread(store_factory):
    store = store_factory(); errors: list[BaseException] = []
    t = threading.Thread(target=lambda: capture(errors, lambda: list(store.entries()))); t.start(); t.join()
    assert len(errors) == 1 and isinstance(errors[0], AssertionError)

def test_maintenance_cannot_nest(store_factory):
    store = store_factory()
    with store.maintenance():
        with pytest.raises(BrainError) as e:
            with store.maintenance(): pass
    assert e.value.code == ErrorCode.STORE_BUSY

def test_crash_after_commit_keeps_entry(tmp_path):                                     # tình huống 5 (phần ledger)
    seed_store(tmp_path); run_until_crash("append_demo", "ledger.after_commit", tmp_path)
    assert [e.meta["n"] for e in reopen(tmp_path).entries()] == [1]

def test_crash_before_commit_leaves_nothing(tmp_path):
    seed_store(tmp_path); run_until_crash("append_demo", "ledger.before_commit", tmp_path)
    assert list(reopen(tmp_path).entries()) == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_kinds.py tests/storage/test_ledger.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

Sau khi tạo DB, gọi `secure_file` cho `brain.db`, `brain.db-wal`, `brain.db-shm`.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage -v && uv run mypy && uv run lint-imports`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 9: CAS có holder

**Files:**
- Create: `src/superbrain/storage/cas.py`
- Modify: `src/superbrain/storage/store.py` (property `cas`; đăng ký `HolderProjection` và `CORE_KINDS` mặc định), `src/superbrain/storage/ledger.py` (`Txn.hold`, `Txn.release`)
- Test: `tests/storage/test_cas.py`

**Interfaces:**
- Consumes: `DurablePublisher` (Task 5), `Txn`, `Store`, `PolicyView` (Task 8).
- Produces:
  - `class RetentionClass(StrEnum)`: `EVENT_PAYLOAD = "event_payload"`, `EVIDENCE = "evidence"`, `DURABLE = "durable"`.
  - `class ContentStore`:
    - `put(data: bytes) -> str`: bytes đã có thì kiểm tra rồi trả digest;
    - `read(digest: str) -> bytes`. Thứ tự kiểm tra: `policy.is_quarantined` → `QUARANTINED`; không có → `NOT_FOUND`; sai digest → `INTEGRITY_FAILURE`;
    - `exists(digest: str) -> bool`;
    - `holders(digest: str) -> list[tuple[str, str, RetentionClass]]`;
    - `orphans() -> list[str]`.
  - Trên `Txn`:
    - `hold(digest: str, holder_kind: str, holder_id: str, retention: RetentionClass, expires_at: datetime | None) -> None`. **Bên trong** transaction ghi, hàm kiểm tra file blob tồn tại và sha256 đúng; không đạt → `BrainError(NOT_FOUND)` và không ghi gì. Đạt thì ghi `cas.hold`;
    - `release(digest: str, holder_kind: str, holder_id: str, reason: str) -> None`, ghi `cas.release`.
  - `Store.store_content(data: bytes, holder_kind: str, holder_id: str, retention: RetentionClass, expires_at: datetime | None) -> str`: `put`, rồi `hold` trong một transaction. Gặp `NOT_FOUND` (GC vừa xóa blob) thì `put` lại và thử đúng một lần nữa; lần hai vẫn lỗi thì raise lỗi đó.
  - `HolderProjection` (name `cas_holders`): bảng `p_cas_holders_(digest, holder_kind, holder_id, retention_class, expires_at, PRIMARY KEY(holder_kind, holder_id, digest))`. Entry `cas.hold` có `(holder_kind, holder_id)` đang `is_tombstoned` thì bị bỏ qua.

Trình tự `put`:
1. kiểm tra digest đã có;
2. `write_new(staging/<new_id>.tmp)`;
3. `crashpoint("cas.after_staging_write")`;
4. `publish(staging, cas/<aa>/<hex>)`;
5. `crashpoint("cas.after_rename")`.

Gặp lỗi bất kỳ thì xóa file staging rồi raise lại lỗi đó. Holder chỉ được thêm bằng `txn.hold` sau khi `put` trả về.

- [ ] **Step 1: Viết test**

```python
def test_put_read_roundtrip_and_dedup(store): ...
def test_read_detects_corruption(store): ...                              # INTEGRITY_FAILURE

def test_disk_full_leaves_no_blob_or_staging(store, monkeypatch):         # Review Focus 2
    monkeypatch.setattr(os, "write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(BrainError) as e: store.cas.put(b"x" * 1000)
    assert e.value.code == ErrorCode.STORAGE_FULL
    assert list(staging_dir(store).iterdir()) == [] and not store.cas.exists(digest_bytes(b"x" * 1000))

def test_shared_blob_has_independent_holders(store):                      # tình huống 25 (phần holder)
    d = store.cas.put(b"shared")
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, expires_at=T0 + timedelta(days=90))
        t.hold(d, "evidence", V1, RetentionClass.EVIDENCE, expires_at=None)
    with store.transaction() as t: t.release(d, "event", E1, reason="expired")
    assert [h[0] for h in store.cas.holders(d)] == ["evidence"] and store.cas.read(d) == b"shared"

def test_crash_after_rename_before_hold_leaves_orphan_only(tmp_path):      # tình huống 5 (phần CAS)
    seed_store(tmp_path); run_until_crash("put_and_hold", "cas.after_rename", tmp_path)
    store = reopen(tmp_path)
    assert store.cas.orphans() == [digest_bytes(b"payload")] and store.cas.holders(digest_bytes(b"payload")) == []

def test_hold_of_missing_blob_is_refused(store):
    with pytest.raises(BrainError) as e:
        with store.transaction() as t: t.hold(digest_bytes(b"never-put"), "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert e.value.code == ErrorCode.NOT_FOUND and list(store.entries()) == []

def test_crash_after_staging_write_leaves_no_blob(tmp_path):
    seed_store(tmp_path); run_until_crash("put_and_hold", "cas.after_staging_write", tmp_path)
    assert not reopen(tmp_path).cas.exists(digest_bytes(b"payload"))
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_cas.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

Khi mở Store, xóa các file `.tmp` trong `staging/`. Đây là file của các lần `put` chưa xong, nên chưa có ref nào trỏ tới chúng.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 10: GC của CAS

**Files:**
- Modify: `src/superbrain/storage/cas.py`
- Test: `tests/storage/test_cas_gc.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class GcReport`: `deleted: tuple[str, ...]`, `kept_young: tuple[str, ...]`.
  - `ContentStore.collect_garbage(*, now: datetime, grace: timedelta = timedelta(hours=24)) -> GcReport`:
    - chạy **trong** `store.maintenance()`; gọi khi cờ đang bật (ví dụ đang backup) → `STORE_BUSY`;
    - với mỗi blob ứng viên (không holder, mtime cũ hơn `grace`): mở một transaction ghi (`BEGIN IMMEDIATE`), kiểm tra lại không có holder, xóa file, làm bền thư mục, rồi commit. Kiểm tra và xóa nằm trong cùng transaction ghi với `Txn.hold`, nên hai bên được SQLite xếp tuần tự (sửa R2-03);
    - không bao giờ xóa blob còn holder;
    - không xóa thư mục con.

- [ ] **Step 1: Viết test**

```python
def test_gc_deletes_old_orphan_only(store, clock): ...
def test_gc_keeps_young_orphan(store, clock): ...

def test_gc_is_refused_while_maintenance_is_active(store, clock):
    orphan = store.cas.put(b"orphan")
    with store.maintenance():
        with pytest.raises(BrainError) as e: store.cas.collect_garbage(now=clock.now() + timedelta(days=2))
    assert e.value.code == ErrorCode.STORE_BUSY and store.cas.exists(orphan)

def test_gc_between_put_of_aged_existing_blob_and_hold_never_leaves_dangling_ref(store, clock):   # sửa R2-03
    aged = store.cas.put(b"dedup-me"); set_mtime(blob_path(store, aged), clock.now() - timedelta(days=3))
    d = store.cas.put(b"dedup-me")                         # bytes đã có: put trả digest ngay, không ghi lại file
    store.cas.collect_garbage(now=clock.now())             # GC xóa blob mồ côi đã cũ
    with pytest.raises(BrainError) as e:
        with store.transaction() as t: t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert e.value.code == ErrorCode.NOT_FOUND and store.cas.holders(d) == []

def test_store_content_republishes_after_gc_race(store, clock, monkeypatch):
    aged = store.cas.put(b"dedup-me"); set_mtime(blob_path(store, aged), clock.now() - timedelta(days=3))
    gc_once_before_first_hold(monkeypatch, store, now=clock.now())          # chèn GC đúng một lần giữa put và hold
    d = store.store_content(b"dedup-me", "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert store.cas.read(d) == b"dedup-me" and [h[1] for h in store.cas.holders(d)] == [E1]
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_cas_gc.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_cas_gc.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 11: Policy store, đối chiếu intent, `trust_generation` và khởi động runtime

**Files:**
- Create: `src/superbrain/storage/policy_store.py`, `src/superbrain/storage/runtime.py`
- Modify:
  - `src/superbrain/storage/store.py`: cài đặt thật `reconcile_policy` và gọi nó trong `open`.
  - `tests/storage/conftest.py`: thêm fixture `env` dùng `open_runtime`, và helper `maintenance_lease(path) -> AbstractContextManager[tuple[DataRoot, WriterLease]]`. Helper này làm đủ chuỗi `prepare_data_root` → `acquire_writer` → `recover_interrupted_swaps` (từ Task 14; trước đó bỏ qua) → `secure_subdirectories`, và không mở Store hay PolicyStore. Lệnh `brain migrate` ở đợt 2 sẽ dùng cùng trình tự.
- Test: `tests/storage/test_policy_store.py`, `tests/storage/test_reconcile.py`, `tests/storage/test_runtime.py`

**Interfaces:**
- Consumes: `IntentKind`, `Intent`, `PolicySource` (Task 8), `WriterLease` (Task 6), `connect`/`schema` (Task 7).
- Produces (`policy_store.py`): `class PolicyStore`, cài `PolicySource`.
  - Khởi tạo và đóng:
    - `create(root: DataRoot, lease: WriterLease, os_: OsAdapters, *, store_id: str, migrations: Sequence[Migration] = POLICY_MIGRATIONS) -> PolicyStore` (classmethod);
    - `open(root: DataRoot, lease: WriterLease, os_: OsAdapters, *, migrations: Sequence[Migration] = POLICY_MIGRATIONS) -> PolicyStore` (classmethod): gọi `ensure_writable`; `lease.register_handle("policy")`;
    - `close() -> None`;
    - quy tắc owner thread như `Store`.
  - Intent:
    - `record_intent(kind: IntentKind, payload: Mapping[str, JsonValue]) -> Intent`;
    - `intents() -> Sequence[Intent]`;
    - `tombstones() -> list[tuple[str, str]]`.
  - `trust_generation() -> int`.
  - `set_trust_generation(value: int) -> None`: chỉ dùng trong restore, trên bản đang dựng.
- Produces (`store.py`): `Store.reconcile_policy() -> int`. Với **mỗi** intent trong `policy.intents()` mà `applied_intents` chưa có, hàm mở một `store.transaction()`, gọi `txn.mark_intent_applied(id)`, rồi áp tác dụng:
  - tombstone: `txn.append("policy.tombstone", …)`, rồi `txn.release(...)` cho mọi holder khớp `(holder_kind, holder_id)` còn trong projection;
  - quarantine: `txn.append("policy.quarantine", …)`.

  Sau commit: `crashpoint("intents.after_store_apply")`. Hàm trả số intent đã áp. **Không có thao tác nào ghi ngược vào policy store** (I1-03).
- Produces (`runtime.py`):
  - `@dataclass class Runtime`: `root: DataRoot`, `lease: WriterLease`, `policy: PolicyStore`, `store: Store`, `os_: OsAdapters`, `close() -> None`.
  - `open_runtime(path: Path, os_: OsAdapters, *, handlers: Sequence[ProjectionHandler] = (), kinds: KindRegistry | None = None, store_migrations: Sequence[Migration] = STORE_MIGRATIONS, policy_migrations: Sequence[Migration] = POLICY_MIGRATIONS) -> Runtime`. Hai tham số migration được truyền thẳng xuống `PolicyStore` và `Store` (sửa R2-05). Thứ tự:
    1. `prepare_data_root`;
    2. `acquire_writer`;
    3. `recover_interrupted_swaps(root, lease, os_)`. Task 14 thêm bước này; trước đó không có gì;
    4. `secure_subdirectories`;
    5. policy store chưa có → `PolicyStore.create(store_id=new_id())`, có rồi → `open`;
    6. store chưa có → `Store.create`, có rồi → `Store.open`. `Store.open` đã gọi `reconcile_policy`.

    Lỗi ở bất kỳ bước nào thì đóng những gì đã mở và nhả lease.

Ngữ nghĩa:
- `record_intent` chạy trong **một** transaction của `policy.db`: ghi intent cùng bảng tác dụng, `tombstones(holder_kind, holder_id, intent_id)` hoặc `quarantine(digest, intent_id)`. Sau `COMMIT` mới `crashpoint("policy.after_intent_commit")`. Nội dung bị chặn ngay khi commit.
- `trust_generation`:
  - bảng `trust(id=1, generation)`; khi tạo mới, `generation = max(1, hwm)`;
  - khi mở, nếu `generation < hwm`: đặt `hwm + 1` và `lease.raise_trust_hwm(hwm + 1)`;
  - nếu `generation > hwm`: `lease.raise_trust_hwm(generation)`.

- [ ] **Step 1: Viết test**

```python
def test_quarantine_blocks_every_holder_immediately(env):
    d = put_and_hold(env.store, b"secret", holders=[("event", E1), ("evidence", V1)])
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": d})
    with pytest.raises(BrainError) as e: env.store.cas.read(d)
    assert e.value.code == ErrorCode.QUARANTINED

def test_crash_between_policy_and_store_applies_exactly_once(tmp_path):              # tình huống 34
    seed_event(tmp_path); run_until_crash("tombstone_event", "policy.after_intent_commit", tmp_path)
    rt = open_runtime(tmp_path, os_adapters())
    assert rt.store.cas.holders(D) == [] and count_entries(rt.store, "policy.tombstone") == 1; rt.close()
    rt = open_runtime(tmp_path, os_adapters())
    assert count_entries(rt.store, "policy.tombstone") == 1

def test_crash_after_store_apply_does_not_duplicate(tmp_path):
    seed_event(tmp_path); run_until_crash("tombstone_event", "intents.after_store_apply", tmp_path)
    rt = open_runtime(tmp_path, os_adapters())
    assert count_entries(rt.store, "policy.tombstone") == 1 and count_entries(rt.store, "cas.release") == 1

def test_reconcile_does_not_write_to_policy(env):
    before = digest_files(env.root.policy_dir); env.store.reconcile_policy()
    assert digest_files(env.root.policy_dir) == before

def test_policy_generation_below_lock_hwm_is_raised_above_it(tmp_path):
    rt = open_runtime(tmp_path, os_adapters()); assert rt.policy.trust_generation() == 1
    rt.lease.raise_trust_hwm(10); rt.close()
    rt = open_runtime(tmp_path, os_adapters())
    assert rt.policy.trust_generation() == 11 and rt.lease.state().trust_generation_hwm == 11

def test_open_runtime_on_fresh_root_binds_store_to_policy(tmp_path):
    rt = open_runtime(tmp_path / "r", os_adapters())
    assert rt.store.store_id == rt.policy.store_id

def test_failed_open_releases_lease(tmp_path, monkeypatch):
    monkeypatch.setattr(Store, "open", raising(BrainError(ErrorCode.INTEGRITY_FAILURE, "x")))
    open_runtime(tmp_path, os_adapters()).close()                           # tạo lần đầu dùng create
    with pytest.raises(BrainError): open_runtime(tmp_path, os_adapters())
    assert run_child("acquire_writer", tmp_path).error_code is None
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_policy_store.py tests/storage/test_reconcile.py tests/storage/test_runtime.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy toàn bộ test storage, xác nhận pass**

Run: `uv run pytest tests/storage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 12: Retention và tombstone

**Files:**
- Create: `src/superbrain/storage/retention.py`
- Test: `tests/storage/test_retention.py`

**Interfaces:**
- Consumes: `Store`, `PolicyStore.record_intent`, `Store.reconcile_policy`.
- Produces:
  - `@dataclass(frozen=True) class RetentionPolicy`: `event_payload_days: int = 90`. Giá trị ngoài khoảng `1..3650` → `INVALID_INPUT`.
  - `@dataclass(frozen=True) class ExpiryReport`: `expired: tuple[tuple[str, str], ...]`.
  - `default_expiry(retention: RetentionClass, now: datetime, policy: RetentionPolicy) -> datetime | None`:
    - `EVENT_PAYLOAD` → `now + timedelta(days=policy.event_payload_days)`;
    - `EVIDENCE` và `DURABLE` → `None`.
  - `expire_due(store: Store, policy: PolicyStore, now: datetime) -> ExpiryReport`. Với mỗi holder có `expires_at <= now` và lớp lưu khác `DURABLE`: ghi intent tombstone, rồi `store.reconcile_policy()`.

- [ ] **Step 1: Viết test**

```python
def test_configured_retention_is_used(clock):                                         # sửa I1-13
    assert default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), RetentionPolicy(event_payload_days=7)) == clock.now() + timedelta(days=7)

@pytest.mark.parametrize("days", [0, 3651, -1])
def test_out_of_range_retention_is_rejected(days):
    with pytest.raises(BrainError): RetentionPolicy(event_payload_days=days)

def test_small_event_payload_expires_and_never_reaches_ledger(env, clock):            # tình huống 35 (phần Event)
    marker = b"tiny-secret-7f3a"; d = env.store.cas.put(marker)
    with env.store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), RetentionPolicy()))
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert not env.store.cas.exists(d)
    assert marker not in read_all_bytes(db_files(env.root.store_db) + db_files(env.root.policy_db))

def test_rebuild_does_not_resurrect_expired_holder(env, clock):                       # tình huống 6
    d = hold_event(env.store, clock); expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.rebuild_projections()
    assert env.store.cas.holders(d) == []

def test_clock_going_backwards_expires_nothing(env, clock):                           # Review Focus 5
    hold_event(env.store, clock)
    assert expire_due(env.store, env.policy, clock.now() - timedelta(days=365)).expired == ()
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=91)).expired == (("event", E1),)

def test_durable_holders_never_expire(env, clock):
    d = put_and_hold(env.store, b"lesson", retention=RetentionClass.DURABLE, expires_at=None)
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=10_000)).expired == () and env.store.cas.holders(d) != []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_retention.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_retention.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 13: Backup và verifier tự rút thông tin từ DB

**Files:**
- Create: `src/superbrain/storage/backup.py`
- Test: `tests/storage/test_backup.py`

**Interfaces:**
- Consumes: `Store`, `Store.maintenance`, `PolicyStore`, `DurablePublisher`, `PermissionGuard`, `read_schema_info`.
- Produces:
  - `@dataclass(frozen=True) class BackupManifest`:
    - `format_version: int` (= 1);
    - `kind: Literal["store", "store_full", "policy"]`;
    - `store_id: str`, `schema_version: int`;
    - `ledger_high_water: int` (bằng 0 với `policy`);
    - `trust_generation: int | None`;
    - `created_at: str`, `db_digest: str`;
    - `blobs: tuple[str, ...]`, đã sắp xếp.
  - `create_store_backup(store: Store, os_: OsAdapters, now: datetime) -> Path`: loại `closure`. Toàn bộ chạy **trong** `store.maintenance()`:
    1. snapshot DB bằng `Connection.backup` vào `brain.db`;
    2. `crashpoint("backup.after_db_snapshot")`;
    3. đọc tập root từ **chính snapshot**: mọi `digest` trong `p_cas_holders_`;
    4. chép từng blob vào `cas/`, làm bền;
    5. `crashpoint("backup.after_blob_copy")`;
    6. ghi `manifest.json` sau cùng.

    Đích: `backups/store-<UTC>-<id>/`.
  - `create_policy_backup(policy: PolicyStore, os_: OsAdapters, now: datetime) -> Path`: loại `policy`, từ PolicyStore đang mở.
  - `create_maintenance_backup(root: DataRoot, lease: WriterLease, os_: OsAdapters, *, target: Literal["store", "policy"], now: datetime) -> Path` (sửa R2-07). Dùng cho migration và cho bảo trì. Điều kiện trước: `target not in lease.open_handles()`, nếu có → `STORE_BUSY`. Hàm mở DB **chỉ đọc theo đường dẫn**, không qua `Store.open`/`PolicyStore.open`, nên không cần đúng version.
    - `target="store"` tạo loại `store_full`: snapshot DB và **mọi** blob trong `cas/`.
    - `target="policy"` tạo loại `policy`: snapshot `policy.db`.

    `schema_version` và `store_id` lấy từ `read_schema_info`; `trust_generation` đọc từ bảng `trust` nếu bảng đó có.
  - `verify_backup(path: Path, *, expected_kind: Literal["store", "store_full", "policy"] | frozenset[str], expected_store_id: str, migrations: Sequence[Migration]) -> BackupManifest`. `migrations` cho biết code hiện tại đọc được schema nào. Với mọi loại, `INTEGRITY_FAILURE` khi bất kỳ điều sau xảy ra:
    - thiếu manifest;
    - `kind` của manifest không thuộc `expected_kind`;
    - digest file DB khác `db_digest`;
    - `PRAGMA integrity_check` khác `ok`;
    - giá trị **rút từ DB snapshot** (`store_id`, `schema_version`, `max(sequence)`, và `trust_generation` với loại policy) khác manifest;
    - `store_id` khác `expected_store_id`;
    - có file blob mà sha256 khác tên, hoặc có file lạ trong `cas/` mà không có trong `blobs`.

    Quy tắc riêng theo loại:
    - `store`: tập root rút từ `p_cas_holders_` của snapshot **bằng đúng** `blobs`;
    - `store_full` có schema đọc được (`ensure_readable` qua): tập root **là tập con** của `blobs`, cho phép blob mồ côi thừa (sửa R2-01). Manifest trả về có `logical_verified=True`;
    - `store_full` có schema code hiện tại không đọc được: chỉ kiểm vật lý, trả `logical_verified=False`.

    Holder đã bị tombstone thì không còn trong projection của snapshot, nên không phải root.
  - Thêm vào `BackupManifest` trường `logical_verified: bool`. Trường này do verifier điền, không đọc từ file.
  - `prune_backups(backups_dir: Path, *, keep: int = 7, now: datetime) -> list[Path]`. Mỗi loại giữ `keep` bản hoàn tất mới nhất và xóa phần còn lại. Bản thiếu manifest cũ hơn 24 giờ được đổi tên thành `*.incomplete`, không xóa.

- [ ] **Step 1: Viết test**

```python
# Trong các test dưới đây (và ở Task 14), `verify_backup(path, expected_store_id=X)` là viết tắt của helper test
# `verify_store(path, X) = verify_backup(path, expected_kind="store", expected_store_id=X, migrations=STORE_MIGRATIONS)`.
# Production API không có giá trị mặc định cho expected_kind/migrations.
def test_store_backup_round_trips_and_survives_live_gc(env, clock):            # tình huống 7, 25
    d = hold_event(env.store, clock); path = create_store_backup(env.store, env.os_, clock.now())
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert verify_backup(path, expected_store_id=env.store.store_id).blobs == (d,)

@pytest.mark.parametrize("damage", [
    "drop_manifest", "flip_db_byte", "drop_blob", "flip_blob_byte", "add_stray_blob",
    "omit_root_from_manifest_and_delete_blob", "manifest_store_id_only", "manifest_schema_only", "manifest_high_water_only",
])
def test_damaged_or_inconsistent_backup_is_rejected(env, clock, damage):            # sửa I1-04
    put_and_hold(env.store, b"kept"); path = create_store_backup(env.store, env.os_, clock.now()); DAMAGE[damage](path)
    with pytest.raises(BrainError) as e: verify_backup(path, expected_store_id=env.store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

def test_backup_of_other_store_is_rejected(env, other_env, clock): ...

def test_policy_backup_round_trip_and_corruption(env, clock):
    path = create_policy_backup(env.policy, env.os_, clock.now())
    assert verify_backup(path, expected_store_id=env.policy.store_id).trust_generation == env.policy.trust_generation()
    flip_byte(path / "policy.db")
    with pytest.raises(BrainError): verify_backup(path, expected_store_id=env.policy.store_id)

def test_maintenance_backup_requires_target_closed(env, clock):
    with pytest.raises(BrainError) as e:
        create_maintenance_backup(env.root, env.lease, env.os_, target="store", now=clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY

def test_full_backup_missing_held_root_is_rejected(tmp_path, clock):                  # sửa R2-01
    d = seed_held_blob(tmp_path)
    with maintenance_lease(tmp_path) as (root, lease):
        path = create_maintenance_backup(root, lease, os_adapters(), target="store", now=clock.now())
    delete_blob_and_manifest_entry(path, d)
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind="store_full", expected_store_id=store_id_of(tmp_path), migrations=STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

def test_full_backup_with_extra_orphan_blob_is_accepted(tmp_path, clock):
    seed_held_blob(tmp_path); seed_orphan_blob(tmp_path)
    with maintenance_lease(tmp_path) as (root, lease):
        path = create_maintenance_backup(root, lease, os_adapters(), target="store", now=clock.now())
    m = verify_backup(path, expected_kind="store_full", expected_store_id=store_id_of(tmp_path), migrations=STORE_MIGRATIONS)
    assert m.logical_verified is True

def test_kind_mismatch_is_rejected(env, clock):
    path = create_policy_backup(env.policy, env.os_, clock.now())
    with pytest.raises(BrainError):
        verify_backup(path, expected_kind="store", expected_store_id=env.policy.store_id, migrations=STORE_MIGRATIONS)

def test_policy_backup_by_path_round_trips(tmp_path, clock):                          # sửa R2-07
    open_runtime(tmp_path, os_adapters()).close()
    with maintenance_lease(tmp_path) as (root, lease):
        path = create_maintenance_backup(root, lease, os_adapters(), target="policy", now=clock.now())
    assert verify_backup(path, expected_kind="policy", expected_store_id=store_id_of(tmp_path), migrations=POLICY_MIGRATIONS).trust_generation == 1

def test_crash_mid_backup_leaves_incomplete_backup_that_never_verifies(tmp_path):
    seed_event(tmp_path); run_until_crash("backup_store", "backup.after_blob_copy", tmp_path)
    rt = open_runtime(tmp_path, os_adapters()); partial = only_backup_dir(rt.root)
    with pytest.raises(BrainError): verify_backup(partial, expected_store_id=rt.store.store_id)

def test_prune_keeps_seven_complete_per_kind(tmp_path, clock): ...       # 9 store → 7; 2 policy → 2; incomplete cũ → *.incomplete
def test_backup_directory_is_owner_only(env, clock): ...
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_backup.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_backup.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 14: Hoán đổi, phục hồi dưới lease, restore kho và restore policy

**Files:**
- Create: `src/superbrain/storage/swap.py`, `src/superbrain/storage/restore.py`
- Modify: `src/superbrain/storage/runtime.py` (gọi `recover_interrupted_swaps` ngay sau `acquire_writer`)
- Test: `tests/storage/test_swap.py`, `tests/storage/test_restore.py`

**Interfaces:**
- Consumes: `verify_backup` (Task 13), `WriterLease.bump_epoch`, `raise_trust_hwm`, `open_handles` (Task 6), `rename_dir` (Task 5).
- Produces (`swap.py`):
  - `stage_and_swap(root: DataRoot, lease: WriterLease, os_: OsAdapters, *, target: Literal["store", "policy"], purpose: Literal["restoring", "migrating"], build: Callable[[Path], None], now: datetime) -> Path`. Điều kiện trước: `target not in lease.open_handles()`, nếu có → `STORE_BUSY`. Các bước:
    1. `build(<target>.<purpose>/)`: dựng nội dung mới;
    2. ghi marker `READY` và làm bền;
    3. `crashpoint(f"{purpose}.{target}.after_stage")`;
    4. `rename_dir(<target>, <target>.replaced-<UTC>-<id>)`;
    5. `crashpoint(f"{purpose}.{target}.between_renames")`;
    6. `rename_dir(<target>.<purpose>, <target>)`;
    7. `lease.bump_epoch()`.

    Hàm trả về thư mục `replaced`.
  - `recover_interrupted_swaps(root: DataRoot, lease: WriterLease, os_: OsAdapters) -> list[str]`. **Yêu cầu** `lease.root == root`. Với mỗi `target` và `purpose`:
    - `<target>/` không tồn tại, có `<target>.<purpose>/READY` → hoàn tất rename;
    - `<target>/` còn nguyên, có `<target>.<purpose>/` (dù có marker hay không) → đổi tên thành `.abandoned-<UTC>-<id>`.

    Hàm không bao giờ xóa gì.
- Produces (`restore.py`):
  - `@dataclass(frozen=True) class RestoreReport`: `restored_from: Path`, `replaced_dir: Path`, `new_epoch: int`, `trust_generation: int | None`.
  - `restore_store(root: DataRoot, lease: WriterLease, os_: OsAdapters, backup: Path, policy: PolicyStore, now: datetime, *, migrations: Sequence[Migration] = STORE_MIGRATIONS) -> RestoreReport`:
    - `verify_backup(expected_kind=frozenset({"store", "store_full"}), expected_store_id=policy.store_id, migrations=migrations)`, chạy trước mọi thao tác. Kết quả có `logical_verified=False` → từ chối với `UNSUPPORTED_VERSION` trước khi dựng stage (sửa R2-01);
    - `stage_and_swap(target="store", purpose="restoring", build=...)`, trong đó `build` chép DB và blob vào stage rồi làm bền.

    `build` **không** mở Store và **không** đối chiếu policy. Việc đối chiếu chạy khi Store được mở lại trên bản đã công bố, qua `reconcile_policy`; đối chiếu dựa trên `applied_intents` của chính snapshot (I1-03).
  - `restore_policy(root: DataRoot, lease: WriterLease, os_: OsAdapters, backup: Path, *, store_id: str, now: datetime, migrations: Sequence[Migration] = POLICY_MIGRATIONS) -> RestoreReport`:
    - **Điều kiện trước:** `lease.open_handles()` không chứa `"store"` lẫn `"policy"`, nếu có → `STORE_BUSY` trước khi dựng stage (sửa R2-02). Sau khi công bố, caller mở runtime mới để Store gắn với policy mới;
    - `verify_backup(expected_kind="policy", expected_store_id=store_id, migrations=migrations)`;
    - `build` chép `policy.db` vào stage, tính `new_gen = max(lease.state().trust_generation_hwm, manifest.trust_generation) + 1`, ghi `new_gen` vào DB đã dựng, làm bền, rồi `crashpoint("restoring.policy.after_generation_persist")`;
    - swap;
    - `crashpoint("restoring.policy.before_hwm_update")`;
    - `lease.raise_trust_hwm(new_gen)`.

    Crash trước khi cập nhật hwm vẫn được hòa giải: lần mở policy sau thấy `generation > hwm` và nâng hwm (Task 11).

- [ ] **Step 1: Viết test**

```python
@pytest.mark.parametrize("point", ["restoring.store.after_stage", "restoring.store.between_renames"])
def test_startup_of_second_process_never_touches_an_inflight_restore(tmp_path, point):   # sửa I1-01
    seed_before_backup_after(tmp_path)
    with paused_child("restore_from_latest", point, tmp_path):
        before = digest_tree(tmp_path)
        assert run_child("open_runtime", tmp_path).error_code == "writer_held"
        assert digest_tree(tmp_path) == before

@pytest.mark.parametrize("point,expected", [
    ("restoring.store.after_stage", ["before", "after"]),
    ("restoring.store.between_renames", ["before"]),
])
def test_interrupted_restore_recovers_under_lease(tmp_path, point, expected):
    seed_before_backup_after(tmp_path); run_until_crash("restore_from_latest", point, tmp_path)
    rt = open_runtime(tmp_path, os_adapters())
    assert markers(rt.store) == expected and every_original_dir_still_exists(tmp_path)

def test_recover_requires_matching_lease(tmp_path, other_root):
    with pytest.raises(AssertionError): recover_interrupted_swaps(layout(tmp_path), lease_for(other_root), os_adapters())

def test_restore_reapplies_newer_tombstone_and_quarantine(tmp_path, clock):              # tình huống 21 (phần policy)
    d = seed_event_and_backup(tmp_path, clock)
    rt = open_runtime(tmp_path, os_adapters())
    rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": d})
    expire_due(rt.store, rt.policy, clock.now() + timedelta(days=91)); restore_latest(rt)
    rt = open_runtime(tmp_path, os_adapters())
    assert rt.store.cas.holders(d) == []
    with pytest.raises(BrainError) as e: rt.store.cas.read(d)
    assert e.value.code == ErrorCode.QUARANTINED

def test_pending_intent_survives_abandoned_restore_stage(tmp_path):                      # sửa I1-03
    seed_event_and_backup(tmp_path); record_tombstone_without_reconcile(tmp_path)
    run_until_crash("restore_from_latest", "restoring.store.after_stage", tmp_path)
    rt = open_runtime(tmp_path, os_adapters())          # stage bị bỏ, kho gốc được đối chiếu
    assert rt.store.cas.holders(D) == [] and count_entries(rt.store, "policy.tombstone") == 1

def test_restore_keeps_lock_object_identity(tmp_path):
    before = file_identity(layout(tmp_path).lock_path); restore_once(tmp_path)
    assert file_identity(layout(tmp_path).lock_path) == before

def test_restore_with_store_open_is_refused(env, clock):
    with pytest.raises(BrainError) as e: restore_store(env.root, env.lease, env.os_, latest_backup(env), env.policy, clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY

def test_policy_restore_with_store_still_open_is_refused(env, clock):                  # sửa R2-02
    path = create_policy_backup(env.policy, env.os_, clock.now()); env.policy.close()     # store vẫn mở
    before = digest_tree(env.root.policy_dir)
    with pytest.raises(BrainError) as e:
        restore_policy(env.root, env.lease, env.os_, path, store_id=env.store.store_id, now=clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY and digest_tree(env.root.policy_dir) == before

def test_after_policy_restore_new_runtime_binds_new_policy(tmp_path, clock):
    g0 = generation_of(tmp_path); path = policy_backup_of(tmp_path)
    with maintenance_lease(tmp_path) as (root, lease):
        restore_policy(root, lease, os_adapters(), path, store_id=store_id_of(tmp_path), now=clock.now())
    rt = open_runtime(tmp_path, os_adapters())
    assert rt.policy.trust_generation() > g0 and rt.store.reconcile_policy() == 0

def test_unverifiable_full_backup_is_not_restored(tmp_path, clock):
    path = full_backup_with_schema(tmp_path, schema_version=99)
    with maintenance_lease(tmp_path) as (root, lease), pytest.raises(BrainError) as e:
        rt_policy = open_policy_only(root, lease)
        restore_store(root, lease, os_adapters(), path, rt_policy, clock.now())
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION

def test_restore_of_wrong_store_is_refused_before_touching_store_dir(tmp_path, other_backup): ...

@pytest.mark.parametrize("point", ["restoring.policy.after_generation_persist", "restoring.policy.after_stage",
                                   "restoring.policy.between_renames", "restoring.policy.before_hwm_update"])
def test_policy_restore_crash_never_lowers_generation(tmp_path, point):                 # sửa I1-14, tình huống 32 (phần generation)
    g0 = seed_policy_backup(tmp_path); run_until_crash("restore_policy_from_latest", point, tmp_path)
    rt = open_runtime(tmp_path, os_adapters()); g1 = rt.policy.trust_generation()
    published = point in ("restoring.policy.between_renames", "restoring.policy.before_hwm_update")
    assert (g1 > g0) == published and g1 >= g0 and rt.lease.state().trust_generation_hwm == g1

def test_successive_policy_restores_strictly_increase_generation(tmp_path): ...       # g0 < g1 < g2
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_swap.py tests/storage/test_restore.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 15: Migration của kho và policy store

**Files:**
- Create: `src/superbrain/storage/migrate.py`
- Test: `tests/storage/test_migrate.py`

**Interfaces:**
- Consumes: `stage_and_swap` (Task 14), `create_maintenance_backup`, `verify_backup` (Task 13), `Migration`, `read_schema_info`, `code_version` (Task 7), `maintenance_lease` (Task 11).
- Produces:
  - `@dataclass(frozen=True) class MigrationReport`: `target: str`, `from_version: int`, `to_version: int`, `backup: Path`, `replaced_dir: Path`.
  - `migrate_database(root: DataRoot, lease: WriterLease, os_: OsAdapters, *, target: Literal["store", "policy"], migrations: Sequence[Migration], now: datetime) -> MigrationReport`. Điều kiện trước: `lease.open_handles()` không chứa `"store"` lẫn `"policy"`, nếu có → `STORE_BUSY`. Cả hai phải đóng, vì Store giữ tham chiếu tới policy (sửa R2-02). Các bước:
    1. `create_maintenance_backup(target=target)`, rồi `verify_backup` với `migrations` **của schema cũ** (tức `migrations` cắt tới `schema_version` hiện tại). Lỗi thì dừng, không chạm vào bản gốc;
    2. `stage_and_swap(purpose="migrating", build=...)`. `build` chép DB (và `cas/` nếu target là store) vào stage, áp mọi migration có `to_version > schema_version` theo thứ tự, mỗi migration một transaction, cập nhật `meta`, kiểm tra `integrity_check == ok`.

    `build` raise lỗi thì stage bị đổi tên thành `.abandoned-…`, kho gốc giữ nguyên, lỗi được raise lại.
  - Mặc định `migrations=STORE_MIGRATIONS` hoặc `POLICY_MIGRATIONS`. Test truyền thêm một v2 qua cùng tham số, vì hiện chưa có v2 thật. Khi có v2 thật, chỉ cần thêm vào tuple.

- [ ] **Step 1: Viết test**

```python
V2 = Migration(to_version=2, min_reader_version=1, apply=lambda db: db.execute("CREATE TABLE added_in_v2(a)"))

def test_new_binary_meets_old_store_then_migrates(tmp_path):                         # sửa I1-05
    open_runtime(tmp_path, os_adapters()).close()                                    # kho tạo bởi code v1
    with pytest.raises(BrainError) as e: open_runtime(tmp_path, os_adapters(), store_migrations=(*STORE_MIGRATIONS, V2))
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED
    with maintenance_lease(tmp_path) as (root, lease):                                # không có Store nào đang mở
        report = migrate_database(root, lease, os_adapters(), target="store", migrations=(*STORE_MIGRATIONS, V2), now=NOW)
    verify_backup(report.backup, expected_kind="store_full", expected_store_id=store_id_of(tmp_path), migrations=STORE_MIGRATIONS)
    rt = open_runtime(tmp_path, os_adapters(), store_migrations=(*STORE_MIGRATIONS, V2))
    assert read_schema_info(rt.root.store_db).schema_version == 2

def test_new_binary_meets_old_policy_then_migrates(tmp_path):                         # sửa R2-07
    P2 = Migration(to_version=2, min_reader_version=1, apply=lambda db: db.execute("CREATE TABLE added_in_v2(a)"))
    open_runtime(tmp_path, os_adapters()).close()
    with pytest.raises(BrainError) as e: open_runtime(tmp_path, os_adapters(), policy_migrations=(*POLICY_MIGRATIONS, P2))
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED
    with maintenance_lease(tmp_path) as (root, lease):
        report = migrate_database(root, lease, os_adapters(), target="policy", migrations=(*POLICY_MIGRATIONS, P2), now=NOW)
    verify_backup(report.backup, expected_kind="policy", expected_store_id=store_id_of(tmp_path), migrations=POLICY_MIGRATIONS)
    rt = open_runtime(tmp_path, os_adapters(), policy_migrations=(*POLICY_MIGRATIONS, P2))
    assert read_schema_info(rt.root.policy_db).schema_version == 2

def test_failed_policy_backup_leaves_policy_untouched(tmp_path, monkeypatch):
    open_runtime(tmp_path, os_adapters()).close(); before = digest_tree(layout(tmp_path).policy_dir)
    monkeypatch.setattr(sqlite3.Connection, "backup", raising(OSError(errno.ENOSPC, "full")))
    with maintenance_lease(tmp_path) as (root, lease), pytest.raises(BrainError):
        migrate_database(root, lease, os_adapters(), target="policy", migrations=(*POLICY_MIGRATIONS, P2_ANY), now=NOW)
    assert digest_tree(layout(tmp_path).policy_dir) == before

def test_migration_with_open_store_is_refused(env):
    with pytest.raises(BrainError) as e:
        migrate_database(env.root, env.lease, env.os_, target="store", migrations=(*STORE_MIGRATIONS, V2), now=NOW)
    assert e.value.code == ErrorCode.STORE_BUSY

def test_failed_migration_leaves_store_untouched(tmp_path):
    bad = Migration(to_version=2, min_reader_version=1, apply=raise_runtime_error)
    open_runtime(tmp_path, os_adapters()).close(); before = digest_tree(layout(tmp_path).store_dir)
    with maintenance_lease(tmp_path) as (root, lease), pytest.raises(RuntimeError):
        migrate_database(root, lease, os_adapters(), target="store", migrations=(*STORE_MIGRATIONS, bad), now=NOW)
    assert digest_tree(layout(tmp_path).store_dir) == before

@pytest.mark.parametrize("point,expected_version", [("migrating.store.after_stage", 1), ("migrating.store.between_renames", 2)])
def test_interrupted_migration_recovers(tmp_path, point, expected_version):
    open_runtime(tmp_path, os_adapters()).close(); run_until_crash("migrate_store_to_v2", point, tmp_path)
    with maintenance_lease(tmp_path) as (root, lease):                                # recover chạy trong maintenance_lease
        assert read_schema_info(root.store_db).schema_version == expected_version
```

`maintenance_lease` được định nghĩa ở Task 11. `P2_ANY` là một migration v2 bất kỳ của policy, vì test này dừng trước khi migration được áp.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_migrate.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 16: Bảng điểm crash

**Files:**
- Create: `docs/design/sp1-crash-table.md`, `tests/support/crash_cases.py`
- Test: `tests/storage/test_crash_matrix.py`

**Interfaces:**
- Consumes: `KNOWN_CRASHPOINTS` (Task 2), `run_until_crash` (Task 6), các operation trong `crash_child.py`.
- Produces: `@dataclass(frozen=True) class CrashCase` với các trường:
  - `operation: str`, `crashpoint: str`;
  - `seed: Callable[[Path], SeedState]`: dựng trạng thái đã ACK trước crash và trả lại những gì cần kiểm;
  - `expect: Callable[[Runtime, SeedState], None]`: assert trạng thái **cụ thể** sau phục hồi, gồm entry ledger, holder, tác dụng của policy, generation và thư mục snapshot;
  - `store_migrations: Sequence[Migration] = STORE_MIGRATIONS`, `policy_migrations: Sequence[Migration] = POLICY_MIGRATIONS`: bộ migration mà matrix truyền vào `open_runtime` sau phục hồi (sửa R2-05). Ca `migrating.*.between_renames` đã công bố v2, nên khai bộ có v2. Ca `migrating.*.after_stage` chưa công bố, nên khai bộ v1. Ca `after_stage` cũng được kiểm thêm: mở bằng bộ có v2 phải trả `MIGRATION_REQUIRED`. Không ca nào được nới `ensure_writable`.

  `CRASH_CASES: tuple[CrashCase, ...]` nằm trong `tests/support/crash_cases.py`.

`KNOWN_CRASHPOINTS` của đợt 1:
- `writer.mid_slot_write`
- `ledger.before_commit`, `ledger.after_commit`
- `cas.after_staging_write`, `cas.after_rename`
- `policy.after_intent_commit`, `intents.after_store_apply`
- `backup.after_db_snapshot`, `backup.after_blob_copy`
- `restoring.store.after_stage`, `restoring.store.between_renames`
- `restoring.policy.after_generation_persist`, `restoring.policy.after_stage`, `restoring.policy.between_renames`, `restoring.policy.before_hwm_update`
- `migrating.store.after_stage`, `migrating.store.between_renames`
- `migrating.policy.after_stage`, `migrating.policy.between_renames`

Mỗi dòng của `sp1-crash-table.md` gồm:
- crashpoint;
- operation;
- trạng thái đĩa trước/sau;
- đã ACK chưa;
- phục hồi khi khởi động lại;
- invariant được giữ;
- `CrashCase` chứng minh;
- **Tiến trình chết:** có test;
- **Mất điện:** dựa trên ngữ nghĩa OS ở Task 5, **không** được chứng minh bằng test kill tiến trình.

Bảng ghi rõ thêm hai điều:
- GC và backup cùng chạy trên owner thread và không lồng được nhau qua cờ `maintenance()`, nên không có trạng thái pin bền vững nào cần phục hồi;
- ApplyJournal thuộc đợt 3.

- [ ] **Step 1: Viết test**

```python
def test_every_known_crashpoint_has_a_case_and_a_doc_row():
    assert {c.crashpoint for c in CRASH_CASES} == KNOWN_CRASHPOINTS
    assert set(parse_crash_table(DOCS / "design" / "sp1-crash-table.md")) == KNOWN_CRASHPOINTS

@pytest.mark.parametrize("case", CRASH_CASES, ids=lambda c: f"{c.operation}@{c.crashpoint}")
def test_crash_case(tmp_path, case):
    seeded = case.seed(tmp_path)
    result = run_until_crash(case.operation, case.crashpoint, tmp_path)   # assert exit 86 và đúng điểm
    rt = open_runtime(tmp_path, os_adapters(), store_migrations=case.store_migrations, policy_migrations=case.policy_migrations)
    case.expect(rt, seeded)
    assert rt.store.db_integrity() == "ok"                               # kiểm tra bổ sung, không phải oracle chính

def test_matrix_detects_a_removed_crashpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST", "cas.after_rename")   # child bỏ qua đúng điểm này
    with pytest.raises(AssertionError): run_until_crash("put_and_hold", "cas.after_rename", tmp_path)
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_crash_matrix.py -v`
Expected: FAIL.

- [ ] **Step 3: Viết `CRASH_CASES` và `sp1-crash-table.md`**

`faults.crashpoint` đọc thêm `SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST`, danh sách tên cách nhau bởi dấu phẩy, chỉ dùng trong test. Biến này giúp kiểm chứng rằng ma trận thực sự fail khi một điểm bị bỏ.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_crash_matrix.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 17: Gate và receipt

**Files:**
- Create: `scripts/gate.py`
- Create: `.github/workflows/ci.yml` (ma trận 3 OS × {3.11, 3.14}; mỗi job chạy `uv run python scripts/gate.py --python <version>`)
- Modify: `pyproject.toml` (`[tool.mypy] files` thêm `"scripts"`)
- Test: `tests/architecture/test_gate_receipt.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class SourceIdentity`: `commit: str`, `tree_clean: bool`, `tracked_digest: str`, `lock_digest: str`, `config_digest: str`.
    - `tracked_digest` là digest của `git ls-files -s`;
    - `config_digest` là digest của `pyproject.toml`.
  - `REQUIRED_PHASES = ("ruff", "mypy", "lint-imports", "pytest")`.
  - `@dataclass(frozen=True) class PhaseResult`: `name: str`, `exit_code: int | None` (`None` khi timeout), `duration_s: float`.
  - `build_receipt(*, start: SourceIdentity, end: SourceIdentity, phases: Sequence[PhaseResult], collected_ids: Sequence[str], junit_ids: Sequence[str], junit_outcomes: Mapping[str, str], python: str, implementation: str, platform: str, time_budget_s: float = 300.0) -> dict[str, JsonValue]`.
  - `TERMINAL_OUTCOMES = {"passed", "failed", "error", "skipped", "xfailed", "xpassed"}`; `NON_FAILING = {"passed", "skipped", "xfailed"}`.
  - `parse_junit(path: Path) -> tuple[list[str], dict[str, str]]`. Gặp testcase trùng ID thì raise `ValueError`, không ghi đè.
  - `accepted` chỉ `True` khi **đủ tất cả**:
    - `start == end`;
    - `start.tree_clean`;
    - tập tên phase bằng đúng `REQUIRED_PHASES`, mỗi phase một lần;
    - mọi `exit_code == 0`;
    - phase pytest có `duration_s <= time_budget_s`;
    - `collected_ids` không trùng;
    - `sorted(collected_ids) == sorted(junit_ids)`;
    - **tập khóa của `junit_outcomes` bằng đúng tập `collected_ids`** (sửa R2-04);
    - mọi giá trị thuộc `TERMINAL_OUTCOMES` và thuộc `NON_FAILING`;
    - tổng các count bằng `len(collected_ids)`.

    Skip được đếm và báo, không bị ẩn.
  - Receipt gồm: `start`, `end`, `test_inventory_digest = digest_bytes(canonical_json(sorted(collected_ids)))`, số lượng theo outcome, các phase, `python`, `implementation`, `platform`, `accepted`, và `reasons` (lý do không được chấp nhận).
  - `scripts/gate.py --python <version>`:
    1. từ chối nếu working tree hiện tại không sạch;
    2. `git worktree add --detach <scratch>/gate-<id> HEAD`, tạo checkout niêm phong;
    3. trong checkout đó: lấy `SourceIdentity`, `uv sync --python <version>`, chạy từng phase với timeout (pytest 300 s) — `pytest --collect-only -q` lấy inventory, rồi pytest với `--junitxml`;
    4. lấy lại `SourceIdentity` của checkout niêm phong;
    5. ghi receipt vào `.gate/receipt-<commit[:12]>-<implementation><python>-<platform>-<lock_digest[7:19]>.json` của repo chính;
    6. gỡ worktree (`git worktree remove --force`);
    7. thoát với mã 0 chỉ khi `accepted`.

    `.gate/` nằm trong `.gitignore`. CI và máy local dùng chung script này.

- [ ] **Step 1: Viết test**

```python
def test_clean_complete_run_is_accepted(): assert build_receipt(**ok())["accepted"] is True
def test_dirty_tree_is_not_accepted(): assert build_receipt(**ok(start=dirty))["accepted"] is False
def test_source_change_during_run_is_not_accepted(): assert build_receipt(**ok(end=changed))["accepted"] is False
def test_missing_phase_is_not_accepted(): assert build_receipt(**ok(phases=without("mypy")))["accepted"] is False
def test_duplicate_phase_is_not_accepted(): ...
def test_timeout_is_not_accepted(): assert build_receipt(**ok(phases=with_pytest(exit_code=None)))["accepted"] is False
def test_over_budget_is_not_accepted(): assert build_receipt(**ok(phases=with_pytest(duration_s=301)))["accepted"] is False
def test_junit_not_matching_inventory_is_not_accepted(): assert build_receipt(**ok(junit_ids=["a"]))["accepted"] is False
def test_duplicate_test_ids_are_not_accepted(): assert build_receipt(**ok(collected_ids=["a", "a"], junit_ids=["a", "a"]))["accepted"] is False
def test_failure_is_not_accepted(): assert build_receipt(**ok(junit_outcomes={"a": "failed"}))["accepted"] is False
def test_missing_outcome_is_not_accepted(): assert build_receipt(**ok(collected_ids=["a", "b"], junit_ids=["a", "b"], junit_outcomes={"a": "passed"}))["accepted"] is False
def test_empty_outcomes_are_not_accepted(): assert build_receipt(**ok(collected_ids=["a"], junit_ids=["a"], junit_outcomes={}))["accepted"] is False
def test_extra_outcome_id_is_not_accepted(): assert build_receipt(**ok(collected_ids=["a"], junit_ids=["a"], junit_outcomes={"a": "passed", "z": "passed"}))["accepted"] is False
def test_unknown_outcome_value_is_not_accepted(): assert build_receipt(**ok(junit_outcomes={"a": "maybe"}))["accepted"] is False
def test_parse_junit_rejects_duplicate_testcase(tmp_path):
    with pytest.raises(ValueError): parse_junit(write_junit(tmp_path, [("t::a", "passed"), ("t::a", "failed")]))
def test_skips_are_reported(): assert build_receipt(**ok(junit_outcomes={"a": "passed", "b": "skipped"}))["counts"]["skipped"] == 1
def test_inventory_digest_is_order_independent(): ...
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/architecture/test_gate_receipt.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt `scripts/gate.py` và `ci.yml`**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/architecture/test_gate_receipt.py -v`
Expected: PASS.

- [ ] **Step 5: Commit gate và CI** (bắt buộc commit **trước** khi chạy gate thật)

```bash
git add scripts/gate.py .github/workflows/ci.yml pyproject.toml tests/architecture/test_gate_receipt.py
git commit -m "build: add gate runner with source-bound receipts"
```

- [ ] **Step 6: Chạy gate thật trên working tree sạch, cả hai Python**

Run: `git status --porcelain` (phải rỗng), rồi `uv run python scripts/gate.py --python 3.11`, rồi `uv run python scripts/gate.py --python 3.14`.
Expected: hai receipt có `"accepted": true` và cùng `start.commit` bằng HEAD. Receipt **không** được commit.

---

## Bàn giao đợt 1

Đợt 1 chỉ được báo "xong" khi đủ:
- receipt `accepted: true` của gate mặc định trên Windows, với Python 3.11 và 3.14, cho đúng HEAD;
- `docs/design/sp1-crash-table.md` và `CRASH_CASES` phủ mọi crashpoint;
- test xanh cho các tình huống nghiệm thu đợt 1 phủ:
  - **phủ đủ:** 26, 34;
  - **phủ phần storage:** 5, 6, 7, 8, 21 (tombstone/quarantine), 25, 28 (hàm kiểm tra quyền), 32 (`trust_generation`), 35 (Event).

Ghi rõ những gì **chưa nghiệm thu**:
- CI trên macOS và Linux, cho tới khi có remote;
- độ bền khi mất điện (chỉ có lập luận theo ngữ nghĩa OS);
- tình huống 21 phần credential, và 32 phần nonce/chữ ký: đợt 2–3;
- tình huống 35 phần Evidence: chính sách tham chiếu evidence thuộc SP2/SP3;
- tình huống 28 phần `doctor` và `--fix`: đợt 4.

Không ghi "verified" cho các phần này.

## Ánh xạ review plan → bản sửa

| Review | Đã sửa ở |
|---|---|
| SP1-I1-01 phục hồi trước khi có lease | Quyết định "Thứ tự khởi động"; Task 6 (`prepare_data_root` chỉ đụng root và lock), Task 11 (`open_runtime`), Task 14 (`recover_interrupted_swaps` cần lease; test tiến trình thứ hai không đụng restore đang chạy) |
| SP1-I1-02 quyền đọc bị dùng làm quyền ghi; handler lạ được append | Task 7 (`ensure_writable` / `ensure_readable`), Task 8 (registry kind; `handler_version` do registry quyết định; lịch sử ngoại lai được seed bằng SQL thô) |
| SP1-I1-03 stage xác nhận intent của policy đang dùng | Quyết định "Ghi nhận đã áp intent"; Task 11 (`reconcile_policy` không ghi vào policy), Task 14 (`build` không mở Store; test stage bị bỏ) |
| SP1-I1-04 verifier tin manifest | Task 13 (rút thông tin từ snapshot; so khớp chính xác tập root; 9 kiểu hỏng) |
| SP1-I1-05 migration không mở được nguồn cũ; handle còn sống | Task 13 (`create_maintenance_backup` theo đường dẫn), Task 6 (`open_handles`), Task 14 và 15 (`STORE_BUSY`), Task 15 (đường đi thật: binary mới gặp kho cũ; migrate cả policy) |
| SP1-I1-06 blacklist suy ra bền khi mất điện | Task 5 (danh sách cho phép cộng probe; tmpfs, fs lạ, remote) |
| SP1-I1-07 path safety và quyền tổ tiên | Task 3 (`entries`, junction thật), Task 4 (owner SID, chuỗi tổ tiên, `FILE_DELETE_CHILD`), Task 6 (kiểm tra trước mọi chmod; test đích ngoài root không đổi). Ngoại lệ sticky bit được ghi trong Quyết định, chờ chủ dự án xác nhận |
| SP1-I1-08 metadata tự do | Task 8 (schema có kiểu, không có chuỗi tự do; test free text bị từ chối) |
| SP1-I1-09 crash test không chạy được hoặc oracle yếu | Quyết định "Subprocess"; Task 6 (`ping`, `run_until_crash` assert exit 86 và đúng điểm), Task 16 (`CrashCase` có seed/expect cụ thể; test bỏ crashpoint thì fail) |
| SP1-I1-10 gate chạy trước commit; receipt yếu | Task 17 (commit trước rồi mới chạy; danh tính đầu–cuối; phase bắt buộc; khớp inventory; timeout và budget) |
| SP1-I1-11 interface có trước khi được dùng; storage không import adapter | Port nằm ở task tiêu thụ đầu tiên (Task 3, 4, 5, 6, 8); `PathSafety` thuộc `OsAdapters`; `PolicySource` trong `ports`; `cas` thêm ở Task 9; `open_runtime` chốt cách gắn `store_id` |
| SP1-I1-12 pin GC sau crash | Quyết định "GC và backup": owner thread cộng cờ `maintenance()`, không có pin bền vững |
| SP1-I1-13 expiry bỏ qua cấu hình | Task 12 (dùng `event_payload_days`, kiểm tra khoảng, test 7 ngày); Bàn giao ghi tình huống 35 chỉ phủ Event |
| SP1-I1-14 crash case riêng cho restore policy | Task 14 (4 crashpoint riêng của policy), Task 16 (`CrashCase` theo cặp operation và crashpoint) |
| Mục 4: attribution | Global Constraints: attribution theo người hoặc công cụ thực sự tham gia |
| Mục 4: UUIDv7 | Task 2 (`IdGenerator`: tràn bộ đếm, đồng hồ lùi, đa luồng) |
| Mục 4: "bản mới nhất" của Python | Quyết định "Python mới nhất" |
| Mục 4: `&&` | Ghi chú Shell ở đầu plan; gate là runner Python |
| Mục 4: backup policy, migration policy | Task 13 (round-trip và hỏng), Task 15 (`target="policy"`) |

### Review vòng 2

| Review | Đã sửa ở |
|---|---|
| SP1-I1-R2-01 `store_full` thiếu blob đang có holder | Quyết định "Backup"; Task 13 (tập root là tập con của `blobs`, `logical_verified`, kiểm `kind`; test bỏ root, test blob mồ côi thừa, test sai loại), Task 14 (restore từ chối backup không kiểm được logic) |
| SP1-I1-R2-02 Store giữ policy cũ khi thay policy | Quyết định "Thay policy"; Task 14 (`restore_policy` yêu cầu cả store và policy đóng; runtime mới gắn policy mới), Task 15 (`migrate_database` cũng vậy) |
| SP1-I1-R2-03 GC chen giữa `put` và `hold` | Quyết định "Chuyển giao `put` → `hold`"; Task 9 (`hold` kiểm blob trong transaction ghi, `store_content` thử lại), Task 10 (GC xóa trong transaction ghi; test blob trùng đã cũ) |
| SP1-I1-R2-04 receipt thiếu outcome vẫn được chấp nhận | Task 17 (khóa outcome bằng đúng inventory, giá trị thuộc tập terminal, tổng count bằng mẫu số, parser từ chối testcase trùng) |
| SP1-I1-R2-05 matrix mở schema v2 bằng runtime v1 | Quyết định "Mở theo bộ migration"; Task 11 (`open_runtime` nhận bộ migration), Task 16 (`CrashCase` khai bộ migration) |
| SP1-I1-R2-06 package chưa được cài; mypy thiếu input | Task 1 (`[build-system]` hatchling, `uv sync`, kiểm tra `-I` dùng đúng checkout; mypy chỉ `src`/`tests`), Task 17 (thêm `scripts`) |
| SP1-I1-R2-07 không có API backup policy theo đường dẫn | Task 13 (`create_maintenance_backup(target="policy")`), Task 15 (test binary mới gặp policy cũ; backup lỗi không chạm bản gốc) |
| SP1-I1-R2-08 owner của tổ tiên trên Windows | Quyết định "Quyền tổ tiên"; Task 4 (owner SID ngoài nhóm tin cậy bị báo; test DACL nhìn an toàn nhưng owner lạ); spec 5.9 |
| SP1-I1-R2-09 thread của connection | Quyết định "Mô hình thực thi"; Task 8 (owner thread; test gọi từ thread khác; test `maintenance()` lồng nhau), Task 10 (bỏ test GC đa luồng) |
| Mục 4: refs và `expires_at` nullable | Task 8 (`refs` là digest không trùng; `nullable`) |
| Mục 4: source ổn định trong lúc chạy gate | Quyết định "Gate trên checkout niêm phong"; Task 17 |
| Mục 4: sticky bit | Chủ dự án đã xác nhận (a); spec 5.9 và Quyết định "Quyền tổ tiên" |
