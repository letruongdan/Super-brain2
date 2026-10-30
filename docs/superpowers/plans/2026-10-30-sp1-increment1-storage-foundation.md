# SP1 · Đợt 1: Nền lưu trữ — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dựng nền lưu trữ của Super-brain2 với đủ hàng rào kiến trúc. Nền gồm: data root an toàn, khóa ghi, ledger cộng projection, CAS bền vững có holder, policy store có intent, retention/tombstone/quarantine, backup/restore, migration. Chạy được trên Windows, macOS, Linux.

**Architecture:** Package `superbrain` theo ma trận phụ thuộc ở spec mục 4.2. Đợt này tạo `core`, `ports`, `adapters.os` và `storage`; các tầng trên chỉ là package rỗng để hàng rào import có chỗ kiểm tra. Mọi thao tác phụ thuộc OS (khóa, quyền file, fsync, rename) đi qua `ports`, được `adapters.os` cài đặt.

**Tech Stack:** Python ≥ 3.11 (kiểm tra trên 3.11 và 3.14), `uv`, SQLite (thư viện chuẩn `sqlite3`), `pywin32` (chỉ trên Windows), pytest, mypy, ruff, import-linter.

**Spec:** `docs/superpowers/specs/2026-10-30-super-brain2-system-design.md` (rev 4, commit `92492f5`). Đợt này triển khai mục 4.2–4.3 và 5.3–5.9, trừ các bản ghi thuộc đợt sau.

## Phạm vi của đợt 1

**Có trong đợt 1:**
- Scaffold, hàng rào (spec 17.2): import-linter, test AST, mypy strict, ruff, cấm nuốt lỗi, cảnh báo file vượt 600 dòng, CI ma trận, receipt của gate.
- `core`: lỗi có mã, canonical JSON/digest, UUIDv7, crashpoint.
- `ports` và `adapters.os`: data root, đường dẫn an toàn, quyền owner-only, `durable_publish` và mức độ bền, khóa độc quyền.
- `storage`: bố cục data root, writer lease (epoch, `trust_generation_hwm`), kết nối SQLite, schema version, ledger cộng projection, CAS có holder và GC, policy store có intent, retention, backup, restore, migration.
- Bảng điểm crash cho các vùng trên.

**Không có trong đợt 1** (thuộc các đợt sau của SP1):
- Đợt 2: daemon, shim, contract v2, idempotency, job.
- Đợt 3: ApplyJournal, review/apply, cổng duyệt, nonce, người ký.
- Đợt 4: `doctor`.

Các bảng credential, người ký, nonce, policy theo repo và trạng thái lớp 2 trong policy store sẽ được thêm bằng migration ở đợt cần chúng.

## Quyết định chốt trong plan này

Spec mục 19 giao các quyết định sau cho plan SP1:

| Quyết định | Chốt |
|---|---|
| Tên package | Distribution `super-brain2`, import package `superbrain`. CLI `brain` thêm ở đợt 2 |
| Bố cục data root | `writer.lock`, `policy/policy.db`, `store/brain.db`, `store/cas/<2 ký tự hex đầu>/<64 hex>`, `store/staging/`, `outbox/`, `logs/`, `backups/` |
| Nội dung `writer.lock` | Byte 0 là vùng khóa. Sau đó là hai slot 256 byte (offset 1 và 257), mỗi slot chứa `{seq, writer_epoch, trust_generation_hwm}` dạng JSON cộng CRC32. Ghi đè slot cũ hơn; đọc slot hợp lệ có `seq` lớn nhất. Cả hai slot hỏng → `integrity_failure` |
| Biến môi trường ghi đè data root | `SUPERBRAIN_HOME` |
| Syscall của `durable_publish` | Như bảng ở Task 5 |
| Quyền trên Windows | `pywin32` (`win32security`): DACL được bảo vệ (tắt kế thừa), chỉ có user hiện tại và SYSTEM với quyền đầy đủ |
| Holder của CAS | Là projection dựng từ ledger entry `cas.hold` / `cas.release`. Vì vậy replay tự áp tombstone |
| Quarantine | Chặn ngay tại `ContentStore.read`, qua policy store. Mọi holder đều bị chặn |
| Migration | Không bao giờ tự chạy khi mở kho. Kho cũ hơn code thì báo `migration_required`; kho mới hơn mức code đọc được thì báo `unsupported_version` |
| Crash injection | Biến môi trường `SUPERBRAIN_CRASHPOINT=<tên>` làm tiến trình con gọi `os._exit(86)` đúng tại điểm đó. Cùng kỹ thuật với `tests/conftest.py::crash_case` của repo cũ |
| O7 (tự khởi động daemon) | Chuyển sang plan đợt 2, nơi có daemon |

## Manifest trích xuất

Nguồn: `D:\ensemble-agents\Super-brain`, commit `f83271d`. Chỉ dùng Git object, không dùng working tree.

| Nguồn (blob) | Đích | Test mang theo | Requirement |
|---|---|---|---|
| `src/ensemble_brain/core/revisions.py` (`d80d7f5`) | `src/superbrain/core/canonical.py`, đổi tên `canonical_revision` → `canonical_digest`, `resource_digest` → `digest_bytes`, `_validate_json` → `validate_json` | Từ `tests/core/test_contracts.py` (`8e6bf49`): `test_canonical_revision_rejects_non_json_and_float_quantities`, `test_canonical_revision_uses_utf8_not_ascii_escapes`, `test_canonical_revision_is_order_independent_but_content_sensitive`, `test_resource_digest_hashes_exact_delivered_bytes`, `test_resource_digest_requires_bytes`. Giữ nguyên assertion và giá trị hash | Spec 5.4 (digest), 6.3 (canonical JSON) |
| `docs/examples/skill-body.txt` (`ed19012`) | `tests/fixtures/skill-body.txt` | Fixture của test digest ở trên | – |
| `src/ensemble_brain/storage/ownership.py` (`d28475c`): phần kiểm tra symlink/reparse và khóa `msvcrt`/`fcntl` | `src/superbrain/adapters/os/paths.py` (`reject_links`) và `src/superbrain/adapters/os/locks.py` | `tests/storage/test_runtime_path_safety.py` (`7c48659`): hai test đầu, đổi `writer_ownership` thành `prepare_data_root` và tên file theo bố cục mới. `tests/storage/test_ownership.py` (`15e0852`) **không** mang sang: test đó kiểm tra lease gắn với thread trong cùng tiến trình, khác với khóa liên tiến trình của spec 5.5 | Spec 5.5, 10 (ranh giới filesystem) |
| `src/ensemble_brain/storage/artifacts.py` (`b0bb49c`): `_fsync_directory`, `_content_identity` | `src/superbrain/adapters/os/durable.py` | Không có test riêng ở nguồn; viết test mới trong Task 5 | Spec 5.4 |

**Không trích xuất,** vì thiết kế mới khác bản cũ:
- `storage/ledger.py`: bảng khóa `o2/o3/o4`, không có projection rebuild.
- `storage/artifacts.py` (phần bundle).
- `storage/backup.py`: backup không tự chứa blob.
- `storage/schema*.py` và `storage/migrations.py`: chuỗi schema lịch sử, không nhập dữ liệu cũ (Q13).
- `storage/sqlite_connections.py`: kho mới giữ một kết nối sống lâu, không cần `ClosingConnection`.

**Baseline:** trước khi sửa, chạy các test được mang theo trên code nguồn ở `f83271d` và ghi kết quả vào commit message của task tương ứng. Test fail sẵn ở nguồn được giữ và ghi lý do (spec 17.4).

## Global Constraints

- Python `>=3.11`; mọi test chạy trên 3.11 và 3.14 tại máy; CI ma trận {Windows, macOS, Linux} × {3.11, 3.14}.
- Phân tầng theo spec 4.2: `core` ← `ports` ← (`storage` | `adapters.*`) ← `domain.*` ← `application` ← (`mcp` | `cli_api` | `review_web` | `workers`) ← `composition`. `cli` chỉ import `core`. Kiểm tra cả import trong hàm.
- `mypy --strict` cho `src` và `tests`; `ruff` cho `src` và `tests`; không vòng phụ thuộc giữa package.
- Cấm nuốt lỗi: ruff `BLE001`, `S110`, `S112`. Mọi lỗi ra ngoài API là `BrainError` có `ErrorCode`.
- Cảnh báo (không fail) khi file vượt 600 dòng.
- Mỗi job test dưới 5 phút. Không xóa, skip hay giảm assertion để đạt thời gian (spec 17.2).
- SQLite: WAL, `synchronous=FULL`; macOS thêm `PRAGMA fullfsync=ON` và `PRAGMA checkpoint_fullfsync=ON` (spec 5.4).
- Ledger chỉ chứa metadata, ID và ref; payload có thời hạn lưu luôn nằm trong CAS (spec 5.3).
- Toàn bộ data root owner-only: Windows chỉ user hiện tại cộng SYSTEM; Unix thư mục `0700`, file `0600`, `umask 077` (spec 5.9).
- Thời hạn mặc định: payload Event 90 ngày; giữ 7 bản backup (spec 5.6).
- Không bao giờ xóa dữ liệu khi restore hoặc migrate: bản cũ được đổi tên, không xóa.
- Commit message kết thúc bằng `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Data root nằm trong đường dẫn có dấu tiếng Việt hoặc khoảng trắng** (ví dụ thư mục profile `C:\Users\Lê Trung\…`): mọi thao tác chạy bình thường. Test ở Task 3.
2. **Ổ đĩa đầy khi ghi blob:** trả `storage_full`, không để lại blob dở trong `cas/` hay file rác trong `staging/`. Test ở Task 10.
3. **Data root nằm trong thư mục OneDrive hoặc ổ mạng:** mức độ bền là `process_crash_durable`, có lý do. Không được báo `power_loss_durable`. Test ở Task 5.
4. **Antivirus hoặc indexer trên Windows giữ file trong chốc lát làm rename báo lỗi sharing violation:** thử lại có giới hạn (5 lần, chờ tăng dần từ 50 ms), sau đó trả `filesystem_busy`. Test ở Task 5.
5. **Đồng hồ hệ thống lùi lại** (đổi múi giờ, sửa giờ tay): không có gì hết hạn sớm, không crash. Đồng hồ tiến lại thì hết hạn đúng hạn. Test ở Task 12.

---

## File Structure

```
pyproject.toml                       cấu hình uv, ruff, mypy, pytest, import-linter
.github/workflows/ci.yml             ma trận 3 OS × 2 Python
scripts/gate.py                      chạy gate mặc định và ghi receipt
docs/design/sp1-crash-table.md       bảng điểm crash (deliverable spec 5.4)
src/superbrain/__init__.py
src/superbrain/core/errors.py        ErrorCode, BrainError
src/superbrain/core/canonical.py     validate_json, canonical_json, digest_bytes, canonical_digest
src/superbrain/core/ids.py           new_id (UUIDv7), id_timestamp_ms
src/superbrain/core/faults.py        crashpoint, KNOWN_CRASHPOINTS
src/superbrain/core/jsonvalue.py     kiểu JsonValue
src/superbrain/ports/clock.py        Clock
src/superbrain/ports/os.py           DurabilityTier, DurabilityReport, DurablePublisher, PermissionGuard,
                                     PermissionProblem, LockHandle, LockFactory, OsAdapters
src/superbrain/adapters/os/__init__.py   os_adapters()
src/superbrain/adapters/os/paths.py      default_data_root, reject_links, reject_unsafe_windows_path
src/superbrain/adapters/os/permissions.py  PosixPermissionGuard, WindowsPermissionGuard
src/superbrain/adapters/os/durable.py      PosixPublisher, DarwinPublisher, WindowsPublisher
src/superbrain/adapters/os/locks.py        OsLockFactory
src/superbrain/adapters/os/clock.py        SystemClock
src/superbrain/storage/layout.py     DataRoot, prepare_data_root, finish_interrupted_swap
src/superbrain/storage/writer.py     LockState, WriterLease, acquire_writer
src/superbrain/storage/sqlite.py     connect
src/superbrain/storage/schema.py     SchemaInfo, Migration, read_schema_info, ensure_openable, STORE_MIGRATIONS, POLICY_MIGRATIONS
src/superbrain/storage/ledger.py     LedgerEntry, ProjectionHandler, Txn
src/superbrain/storage/store.py      Store
src/superbrain/storage/cas.py        RetentionClass, ContentStore, HolderProjection, GcReport
src/superbrain/storage/policy_store.py  IntentKind, Intent, PolicyView, PolicyStore
src/superbrain/storage/intents.py    apply_pending_intents, reapply_policy
src/superbrain/storage/retention.py  RetentionPolicy, ExpiryReport, expire_due
src/superbrain/storage/backup.py     BackupManifest, create_store_backup, create_policy_backup,
                                     verify_store_backup, verify_policy_backup, prune_backups
src/superbrain/storage/restore.py    RestoreReport, restore_store, restore_policy
src/superbrain/storage/migrate.py    MigrationReport, migrate_store
src/superbrain/{domain,application,mcp,cli_api,review_web,workers,composition,cli}/__init__.py  rỗng
tests/support/clock.py               FakeClock
tests/support/crash.py               run_until_crash
tests/support/crash_scripts.py       các thao tác chạy trong tiến trình con
tests/architecture/test_imports.py
tests/core/…, tests/adapters/…, tests/storage/…
```

---

### Task 1: Scaffold dự án và hàng rào kiến trúc

**Files:**
- Create: `pyproject.toml`, `.github/workflows/ci.yml`, `.gitignore`, `src/superbrain/__init__.py`, các `__init__.py` rỗng của mọi package trong File Structure
- Test: `tests/architecture/test_imports.py`

**Interfaces:**
- Produces: `tests/architecture/test_imports.py::LAYER_RULES: dict[str, frozenset[str]]`, khóa là tên package cấp một dưới `superbrain`, giá trị là các package được phép import. Các task sau không sửa bảng này, trừ khi spec 4.2 đổi.

- [ ] **Step 1: Tạo `pyproject.toml`**

Các mục cần có:
- `[project]`: `name = "super-brain2"`, `requires-python = ">=3.11"`, dependency `pywin32>=311; sys_platform == 'win32'`.
- `[dependency-groups] dev`: `pytest`, `mypy`, `ruff`, `import-linter`. Thêm bằng `uv add --dev`.
- `[tool.ruff]`: `target-version = "py311"`, `line-length = 120`, `lint.select = ["E","F","W","I","B","UP","BLE","S110","S112"]`.
- `[tool.mypy]`: `strict = true`, `files = ["src","tests"]`.
- `[tool.pytest.ini_options]`: `testpaths = ["tests"]`, `addopts = ["--import-mode=importlib", "-p", "no:cacheprovider"]`.
- `[tool.importlinter]`: `root_package = "superbrain"`, kèm hai contract:
  - contract `layers`: `superbrain.composition`, `superbrain.mcp | superbrain.cli_api | superbrain.review_web | superbrain.workers`, `superbrain.application`, `superbrain.domain`, `superbrain.storage | superbrain.adapters`, `superbrain.ports`, `superbrain.core`;
  - contract `forbidden`: `superbrain.cli` không được import `superbrain.storage`, `superbrain.domain`, `superbrain.application`, `superbrain.adapters`, `superbrain.ports`.

- [ ] **Step 2: Viết test kiến trúc (fail trước khi có checker)**

```python
# tests/architecture/test_imports.py
LAYER_RULES = {
    "core": frozenset(),
    "ports": frozenset({"core"}),
    "storage": frozenset({"ports", "core"}),
    "adapters": frozenset({"ports", "core"}),
    "domain": frozenset({"ports", "core", "domain"}),
    "application": frozenset({"domain", "ports", "core"}),
    "mcp": frozenset({"application", "core"}),
    "cli_api": frozenset({"application", "core"}),
    "review_web": frozenset({"application", "core"}),
    "workers": frozenset({"application", "core"}),
    "cli": frozenset({"core"}),
    "composition": frozenset(LAYER_NAMES_ALL),  # mọi package, trừ chính nó
}

def test_every_import_including_function_level_respects_layers():
    violations = find_violations(SRC_ROOT / "superbrain", LAYER_RULES)
    assert violations == []

def test_checker_detects_function_level_upward_import(tmp_path):
    pkg = make_package(tmp_path, {"superbrain/core/a.py": "def f():\n    import superbrain.storage.x\n",
                                  "superbrain/storage/x.py": ""})
    assert find_violations(pkg / "superbrain", LAYER_RULES) == [("superbrain.core.a", "superbrain.storage.x")]

def test_checker_detects_type_checking_import(tmp_path): ...   # import trong `if TYPE_CHECKING:` cũng bị tính

def test_package_graph_is_acyclic():
    assert find_package_cycles(SRC_ROOT / "superbrain") == []

def test_report_files_over_600_lines():
    for path, count in files_over(SRC_ROOT, 600):
        warnings.warn(f"{path} has {count} lines (>600)")
```

`find_violations(root: Path, rules: Mapping[str, frozenset[str]]) -> list[tuple[str, str]]` duyệt AST mọi `.py` dưới `root`, lấy **mọi** `Import`/`ImportFrom` ở bất kỳ độ sâu nào, kể cả import tương đối đã được resolve. Hàm chỉ xét import bắt đầu bằng `superbrain.`. `find_package_cycles` và `files_over` nằm cùng file test.

- [ ] **Step 3: Chạy test, xác nhận fail**

Run: `uv run pytest tests/architecture -v`
Expected: FAIL vì `find_violations` chưa được định nghĩa.

- [ ] **Step 4: Cài `find_violations`, `find_package_cycles`, `files_over` trong file test, rồi chạy lại**

Run: `uv run pytest tests/architecture -v && uv run lint-imports && uv run ruff check src tests && uv run mypy`
Expected: PASS. lint-imports báo 2 contract kept.

- [ ] **Step 5: Tạo `.github/workflows/ci.yml`**

- Ma trận `os: [windows-latest, macos-latest, ubuntu-latest]` × `python: ["3.11", "3.14"]`.
- Các bước: `uv sync`, `uv run ruff check src tests`, `uv run mypy`, `uv run lint-imports`, `uv run pytest`.
- Bước pytest có `timeout-minutes: 5`.

Repo chưa có remote. Vì vậy gate trên macOS và Linux ở trạng thái **chưa nghiệm thu**, cho tới khi chủ dự án tạo remote. Gate tại máy chạy trên Windows với 3.11 và 3.14.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock .gitignore .github src tests
git commit -m "build: scaffold superbrain package with layer guardrails"
```

---

### Task 2: `core` — lỗi có mã, canonical digest, UUIDv7, crashpoint

**Files:**
- Create: `src/superbrain/core/errors.py`, `src/superbrain/core/jsonvalue.py`, `src/superbrain/core/canonical.py`, `src/superbrain/core/ids.py`, `src/superbrain/core/faults.py`, `tests/fixtures/skill-body.txt`
- Test: `tests/core/test_canonical.py`, `tests/core/test_ids.py`, `tests/core/test_faults.py`

**Interfaces:**
- Produces:
  - `class ErrorCode(StrEnum)` với các giá trị: `invalid_input`, `identity_mismatch`, `not_found`, `quarantined`, `revision_conflict`, `idempotency_conflict`, `in_progress`, `commit_outcome_unknown`, `store_busy`, `deadline_exceeded`, `capability_unavailable`, `unsupported_version`, `migration_required`, `writer_held`, `unsafe_path`, `insecure_permissions`, `integrity_failure`, `storage_full`, `filesystem_busy`.
  - `class BrainError(Exception)`: `__init__(self, code: ErrorCode, message: str)`, thuộc tính `.code`, `.message`.
  - `JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]`.
  - `validate_json(value: object, *, reject_floats: bool = False) -> None`.
  - `canonical_json(value: object) -> bytes`: `sort_keys`, `separators=(",",":")`, `ensure_ascii=False`, `allow_nan=False`, UTF-8; gọi `validate_json` trước.
  - `digest_bytes(data: bytes) -> str`: trả `"sha256:" + hex`.
  - `canonical_digest(kind: str, manifest: Mapping[str, JsonValue]) -> str`: bằng `digest_bytes(canonical_json({"kind": kind, "manifest": manifest}))`, với `reject_floats=True`.
  - `new_id() -> str` (UUIDv7 dạng chữ thường, tăng dần trong cùng tiến trình), `id_timestamp_ms(value: str) -> int`.
  - `crashpoint(name: str) -> None`, `KNOWN_CRASHPOINTS: frozenset[str]`.

- [ ] **Step 1: Mang test từ nguồn và viết test mới**

Chép 5 test liệt kê trong manifest, đổi tên hàm theo bảng manifest, **giữ nguyên** các giá trị hash. Ví dụ `sha256:eddaa692de85aab3ff2517bb0a4b619ce469ec3064ba3496e0d3662fc69e1f47` cho `{"title": "é"}`, và `sha256:ba7816bf…15ad` cho `b"abc"`. Mọi lỗi phải có `failure.value.code == ErrorCode.INVALID_INPUT`. Thêm các test mới:

```python
def test_new_id_is_uuid_v7_and_monotonic():
    ids = [new_id() for _ in range(2000)]
    assert ids == sorted(ids)
    assert all(uuid.UUID(i).version == 7 and uuid.UUID(i).variant == uuid.RFC_4122 for i in ids)

def test_id_timestamp_roundtrip():
    before = int(time.time() * 1000); value = new_id(); after = int(time.time() * 1000)
    assert before <= id_timestamp_ms(value) <= after

def test_crashpoint_exits_only_when_named(tmp_path):
    code = run_python("from superbrain.core.faults import crashpoint; crashpoint('cas.after_rename'); print('alive')",
                      env={"SUPERBRAIN_CRASHPOINT": "cas.after_rename"})
    assert code.returncode == 86 and "alive" not in code.stdout
    assert run_python(same_script, env={"SUPERBRAIN_CRASHPOINT": "other"}).stdout.strip() == "alive"

def test_unknown_crashpoint_name_is_a_programming_error():
    with pytest.raises(AssertionError):
        crashpoint("not.registered")
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/core -v`
Expected: FAIL với `ModuleNotFoundError: superbrain.core.canonical`.

- [ ] **Step 3: Cài đặt**

- `canonical.py`: chép thân hàm từ `revisions.py` của nguồn, đổi tên theo manifest, thay `BrainError("invalid_input", …)` bằng `BrainError(ErrorCode.INVALID_INPUT, …)`.
- `ids.py`: sinh UUIDv7 theo RFC 9562. Phần thời gian 48 bit tính bằng ms. Dùng 12 bit `rand_a` làm bộ đếm khi trùng ms, để ID tăng dần. Phần còn lại lấy từ `secrets`.
- `faults.py`: `KNOWN_CRASHPOINTS` liệt kê đúng các tên ở Task 16.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/core -v && uv run mypy`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `f83271d:src/ensemble_brain/core/revisions.py`, blob `d80d7f5`, và kết quả baseline của các test mang theo.

---

### Task 3: `adapters.os.paths` — vị trí data root và đường dẫn an toàn

**Files:**
- Create: `src/superbrain/adapters/os/paths.py`
- Test: `tests/adapters/test_paths.py`

**Interfaces:**
- Produces:
  - `default_data_root(env: Mapping[str, str], platform: str) -> Path`.
    - `SUPERBRAIN_HOME` có giá trị thì dùng giá trị đó.
    - `win32`: `%LOCALAPPDATA%\ensemble-brain`.
    - `darwin`: `~/Library/Application Support/ensemble-brain`.
    - còn lại: `$XDG_DATA_HOME/ensemble-brain`, mặc định `~/.local/share/ensemble-brain`.
  - `reject_links(path: Path) -> None`: duyệt `path` và mọi thư mục cha đang tồn tại. Gặp `is_symlink()` hoặc `st_file_attributes & 0x400` (reparse point) thì raise `BrainError(UNSAFE_PATH)`. Phần kiểm tra này trích từ `ownership.py`.
  - `reject_unsafe_windows_path(path: str) -> None`: từ chối tiền tố `\\?\`, `\\.\`, đường UNC `\\server\…`, và dấu `:` ngoài vị trí ký tự ổ đĩa (alternate data stream). Trên OS khác, hàm không làm gì.

- [ ] **Step 1: Viết test**

```python
@pytest.mark.parametrize("platform,env,expected", [
    ("win32", {"LOCALAPPDATA": r"C:\Users\Lê Trung\AppData\Local"}, Path(r"C:\Users\Lê Trung\AppData\Local\ensemble-brain")),
    ("darwin", {"HOME": "/Users/u"}, Path("/Users/u/Library/Application Support/ensemble-brain")),
    ("linux", {"HOME": "/home/u"}, Path("/home/u/.local/share/ensemble-brain")),
    ("linux", {"HOME": "/home/u", "XDG_DATA_HOME": "/data"}, Path("/data/ensemble-brain")),
    ("linux", {"SUPERBRAIN_HOME": "/srv/brain"}, Path("/srv/brain")),
])
def test_default_data_root(platform, env, expected): ...

def test_reject_links_refuses_symlinked_component(tmp_path, monkeypatch): ...   # port: test_runtime_refuses_linked_root_before_resolving_alias

@pytest.mark.parametrize("raw", [r"\\?\C:\x", r"\\.\pipe\x", r"\\server\share\x", r"C:\x\file.db:stream"])
def test_reject_unsafe_windows_path(raw): ...   # chỉ trên win32; OS khác thì skip, kèm lý do "Windows-only path forms"

def test_vietnamese_and_space_path_is_accepted(tmp_path):     # Review Focus 1
    root = tmp_path / "thư mục có dấu" / "Lê Trung"
    root.mkdir(parents=True)
    reject_links(root)   # không raise
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_paths.py -v`
Expected: FAIL (module chưa có).

- [ ] **Step 3: Cài đặt `paths.py`**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_paths.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `ownership.py` blob `d28475c` và `test_runtime_path_safety.py` blob `7c48659`.

---

### Task 4: `ports.os` và quyền owner-only

**Files:**
- Create: `src/superbrain/ports/os.py`, `src/superbrain/ports/clock.py`, `src/superbrain/adapters/os/permissions.py`, `src/superbrain/adapters/os/clock.py`, `tests/support/clock.py`
- Test: `tests/adapters/test_permissions.py`

**Interfaces:**
- Produces (trong `ports/os.py`):
  - `class DurabilityTier(StrEnum)`: `POWER_LOSS = "power_loss_durable"`, `PROCESS_CRASH = "process_crash_durable"`.
  - `@dataclass(frozen=True) class DurabilityReport`: `tier: DurabilityTier`, `reasons: tuple[str, ...]`.
  - `@dataclass(frozen=True) class PermissionProblem`: `path: Path`, `reason: str`.
  - `class PermissionGuard(Protocol)`:
    - `secure_directory(path: Path) -> None`;
    - `secure_file(path: Path) -> None`;
    - `problems(root: Path) -> list[PermissionProblem]`, duyệt đệ quy;
    - `check_parents(path: Path) -> list[PermissionProblem]`.
  - `class DurablePublisher(Protocol)`, `class LockHandle(Protocol)`, `class LockFactory(Protocol)`: chữ ký ở Task 5 và Task 6.
  - `@dataclass(frozen=True) class OsAdapters`: `publisher: DurablePublisher`, `permissions: PermissionGuard`, `locks: LockFactory`, `clock: Clock`.
- Produces (trong `ports/clock.py`): `class Clock(Protocol)` với `now() -> datetime`, luôn có timezone UTC.
- Produces (adapter): `PosixPermissionGuard`, `WindowsPermissionGuard`, `SystemClock`.
- Produces (test support): `tests/support/clock.py::FakeClock(start: datetime)` với `.now()`, `.advance(delta)`, `.set(value)`.

- [ ] **Step 1: Viết test**

```python
def test_secured_tree_has_no_problems(tmp_path, guard):
    d = tmp_path / "root"; d.mkdir(); guard.secure_directory(d)
    f = d / "x.db"; f.write_bytes(b"x"); guard.secure_file(f)
    assert guard.problems(d) == []

@posix_only
def test_group_readable_file_is_reported(tmp_path, guard):
    f = secured_file(tmp_path); os.chmod(f, 0o640)
    assert [p.path for p in guard.problems(f.parent)] == [f]

@windows_only
def test_everyone_ace_is_reported(tmp_path, guard):
    f = secured_file(tmp_path); grant_everyone_read(f)   # helper dùng win32security
    assert [p.path for p in guard.problems(f.parent)] == [f]

@posix_only
def test_world_writable_parent_without_sticky_is_refused(tmp_path, guard):
    parent = tmp_path / "open"; parent.mkdir(); os.chmod(parent, 0o777)
    assert guard.check_parents(parent / "root") != []

@posix_only
def test_sticky_world_writable_parent_is_accepted(tmp_path, guard):
    parent = tmp_path / "tmpdir"; parent.mkdir(); os.chmod(parent, 0o1777)
    assert guard.check_parents(parent / "root") == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_permissions.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- **POSIX:**
  - `secure_directory` chmod `0o700`, `secure_file` chmod `0o600`.
  - `problems` báo file/thư mục có `mode & 0o077 != 0` hoặc `st_uid != os.geteuid()`.
  - `check_parents` kiểm tra mọi thư mục cha tới `/`: cha nào cho group/other ghi mà không có sticky bit thì báo, trừ khi cha đó thuộc root hoặc user hiện tại và có sticky bit.
- **Windows:**
  - `win32security`: đặt DACL được bảo vệ (`PROTECTED_DACL_SECURITY_INFORMATION`), chỉ hai ACE `FILE_ALL_ACCESS` (kèm `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` cho thư mục) cho SID của user hiện tại và `S-1-5-18`.
  - `problems` báo ACE cho phép truy cập tới SID khác hai SID trên.
  - `check_parents` chỉ xét thư mục cha trực tiếp: ACE cho SID khác user/SYSTEM/Administrators (`S-1-5-32-544`) mà có quyền ghi hoặc `FILE_DELETE_CHILD` thì báo.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_permissions.py -v` (trên Windows: các test `posix_only` skip kèm lý do, và ngược lại).
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 5: `durable_publish` và mức độ bền

**Files:**
- Create: `src/superbrain/adapters/os/durable.py`
- Test: `tests/adapters/test_durable.py`

**Interfaces:**
- Produces: `class DurablePublisher(Protocol)` trong `ports/os.py`:
  - `write_new(path: Path, data: bytes) -> None`: tạo file mới (`O_CREAT|O_EXCL`), ghi đủ bytes, làm bền nội dung.
  - `publish(staging: Path, final: Path) -> None`: rename nguyên tử staging → final, rồi làm bền entry của thư mục đích.
  - `sync_directory(directory: Path) -> None`.
  - `durability(directory: Path, env: Mapping[str, str]) -> DurabilityReport`.
- Produces: `PosixPublisher`, `DarwinPublisher`, `WindowsPublisher`, `publisher_for(platform: str) -> DurablePublisher`.

| Thao tác | Linux | macOS | Windows |
|---|---|---|---|
| Làm bền nội dung file | `os.fsync(fd)` | `fcntl(fd, F_FULLFSYNC)` | `os.fsync(fd)` (gọi `FlushFileBuffers`) |
| Rename | `os.replace` | `os.replace` | `MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` qua `ctypes` |
| Làm bền thư mục | `fsync` fd của thư mục (từ `_fsync_directory` của nguồn) | `F_FULLFSYNC` trên fd của thư mục | Không có thao tác riêng; `MOVEFILE_WRITE_THROUGH` đảm nhiệm |
| Lỗi sharing violation (`winerror` 32 hoặc 5) khi rename | – | – | Thử lại tối đa 5 lần, chờ 50/100/200/400/800 ms; vẫn lỗi thì `BrainError(FILESYSTEM_BUSY)` |
| `ENOSPC` / `winerror` 112 | `BrainError(STORAGE_FULL)` | như Linux | như Linux |

`durability()` trả `PROCESS_CRASH` kèm lý do khi:
- thư mục nằm trên filesystem mạng:
  - Linux: loại trong `/proc/self/mountinfo` thuộc `{nfs, nfs4, cifs, smb3, 9p}` hoặc bắt đầu bằng `fuse.`;
  - macOS: `f_fstypename` thuộc `{nfs, smbfs, afpfs, webdav}`;
  - Windows: `GetDriveTypeW == DRIVE_REMOTE`;
- thư mục nằm dưới đường dẫn của `env["OneDrive"]`, `env["OneDriveConsumer"]` hoặc `env["OneDriveCommercial"]`;
- trên macOS, `F_FULLFSYNC` trả `ENOTSUP` khi thử trên một file tạm.

Các trường hợp còn lại trả `POWER_LOSS`.

- [ ] **Step 1: Viết test**

```python
def test_publish_moves_bytes_and_leaves_no_staging(tmp_path, publisher):
    staging = tmp_path / "s.tmp"; publisher.write_new(staging, b"data")
    publisher.publish(staging, tmp_path / "final")
    assert (tmp_path / "final").read_bytes() == b"data" and not staging.exists()

def test_write_new_refuses_existing_file(tmp_path, publisher):
    (tmp_path / "x").write_bytes(b"a")
    with pytest.raises(FileExistsError):
        publisher.write_new(tmp_path / "x", b"b")

def test_disk_full_maps_to_storage_full(tmp_path, publisher, monkeypatch):
    monkeypatch.setattr(os, "write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(BrainError) as e:
        publisher.write_new(tmp_path / "x", b"data")
    assert e.value.code == ErrorCode.STORAGE_FULL

def test_onedrive_folder_is_process_crash_tier(tmp_path, publisher):          # Review Focus 3
    report = publisher.durability(tmp_path / "d", {"OneDrive": str(tmp_path)})
    assert report.tier == DurabilityTier.PROCESS_CRASH and any("OneDrive" in r for r in report.reasons)

def test_local_folder_is_power_loss_tier(tmp_path, publisher):
    assert publisher.durability(tmp_path, {}).tier == DurabilityTier.POWER_LOSS

@windows_only
def test_transient_sharing_violation_is_retried(tmp_path, monkeypatch):      # Review Focus 4
    fake = FlakyMoveFileEx(failures=2, winerror=32); monkeypatch.setattr(durable, "_move_file_ex", fake)
    WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert fake.calls == 3

@windows_only
def test_persistent_sharing_violation_is_filesystem_busy(tmp_path, monkeypatch):
    monkeypatch.setattr(durable, "_move_file_ex", FlakyMoveFileEx(failures=99, winerror=32))
    with pytest.raises(BrainError) as e:
        WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert e.value.code == ErrorCode.FILESYSTEM_BUSY
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/adapters/test_durable.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt theo bảng trên**

`WindowsPublisher.__init__(self, sleep: Callable[[float], None] = time.sleep)` cho phép tiêm hàm chờ trong test. `_move_file_ex` là hàm cấp module bọc `ctypes.windll.kernel32.MoveFileExW`.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/adapters/test_durable.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message ghi nguồn `_fsync_directory` từ `artifacts.py` blob `b0bb49c`.

---

### Task 6: Khóa ghi và writer lease

**Files:**
- Create: `src/superbrain/adapters/os/locks.py`, `src/superbrain/adapters/os/__init__.py` (`os_adapters()`), `src/superbrain/storage/layout.py`, `src/superbrain/storage/writer.py`
- Test: `tests/storage/test_writer.py`, `tests/storage/test_layout.py`

**Interfaces:**
- Produces (`ports/os.py`):
  - `class LockHandle(Protocol)`: `read_payload() -> bytes` (đọc từ offset 1), `write_payload(offset: int, data: bytes) -> None` (ghi rồi làm bền nội dung), `release() -> None`.
  - `class LockFactory(Protocol)`: `acquire(path: Path) -> LockHandle`. Khóa đang bị giữ thì raise `BrainError(WRITER_HELD)` ngay, không chờ.
- Produces (`adapters/os`):
  - `OsLockFactory`: Windows dùng `msvcrt.locking(fd, LK_NBLCK, 1)` trên byte 0; Unix dùng `fcntl.flock(LOCK_EX|LOCK_NB)`. Không bao giờ xóa file khóa (theo ghi chú trong `ownership.py` nguồn).
  - `os_adapters() -> OsAdapters` cho nền tảng hiện tại.
- Produces (`storage/layout.py`):
  - `@dataclass(frozen=True) class DataRoot`:
    - các trường `root`, `lock_path`, `policy_dir`, `store_dir`, `outbox_dir`, `logs_dir`, `backups_dir`;
    - property `policy_db`, `store_db`, `cas_dir`, `staging_dir`.
  - `prepare_data_root(root: Path, os_: OsAdapters) -> DataRoot`. Thứ tự:
    1. `reject_unsafe_windows_path`;
    2. `reject_links`;
    3. `check_parents`: có vấn đề thì `BrainError(INSECURE_PERMISSIONS)`;
    4. tạo thư mục và `secure_directory` cho từng thư mục, `umask 077` trên Unix;
    5. tạo `writer.lock` nếu chưa có;
    6. `finish_interrupted_swap` (Task 14).
- Produces (`storage/writer.py`):
  - `@dataclass(frozen=True) class LockState`: `writer_epoch: int`, `trust_generation_hwm: int`.
  - `class WriterLease`: `root: DataRoot`, `epoch: int`, `state() -> LockState`, `raise_trust_hwm(value: int) -> None`, `bump_epoch() -> int`, `release() -> None`, kèm `__enter__`/`__exit__`.
  - `acquire_writer(root: DataRoot, os_: OsAdapters) -> WriterLease`: lấy khóa, đọc slot, tăng `writer_epoch` thêm 1 và ghi bền **trước khi** trả về.

- [ ] **Step 1: Viết test**

```python
def test_second_process_cannot_acquire_while_held(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    with acquire_writer(root, os_adapters()):
        result = run_child("acquire_writer", root.root)      # tests/support/crash.py
        assert result.error_code == "writer_held"

def test_lock_released_when_holder_process_is_killed(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    child = start_child_holding_writer(root.root); child.kill(); child.wait()
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 2

def test_epoch_increments_on_every_acquisition(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    epochs = []
    for _ in range(3):
        with acquire_writer(root, os_adapters()) as lease: epochs.append(lease.epoch)
    assert epochs == [1, 2, 3]

def test_trust_hwm_never_decreases(tmp_path):
    with writer(tmp_path) as lease:
        lease.raise_trust_hwm(5); lease.raise_trust_hwm(3)
        assert lease.state().trust_generation_hwm == 5

def test_torn_slot_write_falls_back_to_other_slot(tmp_path):
    root = prepared(tmp_path)
    with acquire_writer(root, os_adapters()): pass                      # epoch 1 ở một slot
    result = run_until_crash("acquire_writer", "writer.mid_slot_write", root.root)
    assert result.returncode == 86
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 2          # slot dở bị bỏ qua, đọc slot hợp lệ có epoch 1, rồi +1

def test_both_slots_corrupt_is_integrity_failure(tmp_path):
    root = prepared(tmp_path); corrupt_bytes(root.lock_path, offsets=[10, 266])
    with pytest.raises(BrainError) as e: acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

@pytest.mark.parametrize("component", ["writer.lock", "store", "policy"])
def test_prepare_refuses_linked_state(tmp_path, monkeypatch, component): ...   # port từ test_runtime_path_safety

def test_prepare_secures_every_directory(tmp_path):
    root = prepare_data_root(tmp_path / "r", os_adapters())
    assert os_adapters().permissions.problems(root.root) == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_writer.py tests/storage/test_layout.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- Mỗi slot là JSON `{"seq":n,"writer_epoch":e,"trust_generation_hwm":t}`, đệm khoảng trắng tới 252 byte, cộng 4 byte CRC32 big-endian.
- Ghi vào slot có `seq` nhỏ hơn, với `seq = max + 1`.
- Crashpoint `writer.mid_slot_write` nằm sau khi ghi 128 byte đầu của slot.
- `tests/support/crash.py`:
  - `run_until_crash(operation: str, crashpoint: str, data_root: Path) -> subprocess.CompletedProcess[str]`;
  - `run_child(operation: str, data_root: Path) -> ChildResult`;
  - `start_child_holding_writer(data_root: Path) -> subprocess.Popen[str]`.

  Các hàm này chạy `python -I -m tests.support.crash_scripts <operation> <data_root>` với `SUPERBRAIN_CRASHPOINT` đã đặt. `ChildResult` có `error_code: str | None`.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_writer.py tests/storage/test_layout.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 7: Kết nối SQLite và kiểm tra phiên bản schema

**Files:**
- Create: `src/superbrain/storage/sqlite.py`, `src/superbrain/storage/schema.py`
- Test: `tests/storage/test_schema.py`

**Interfaces:**
- Produces:
  - `connect(path: Path, *, readonly: bool = False, platform: str = sys.platform) -> sqlite3.Connection`.
    - Mặc định: `isolation_level=None` (tự quản transaction), `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`.
    - `darwin`: thêm `fullfsync=ON`, `checkpoint_fullfsync=ON`.
    - `readonly`: mở bằng URI `file:<path>?mode=ro`.
  - `@dataclass(frozen=True) class SchemaInfo`: `schema_version: int`, `min_reader_version: int`.
  - `@dataclass(frozen=True) class Migration`: `to_version: int`, `min_reader_version: int`, `apply: Callable[[sqlite3.Connection], None]`.
  - `STORE_MIGRATIONS: tuple[Migration, ...]` và `POLICY_MIGRATIONS: tuple[Migration, ...]`. Ở đợt này, mỗi tuple có đúng một migration tạo schema version 1.
  - `read_schema_info(path: Path) -> SchemaInfo | None`: mở readonly, đọc bảng `meta(key TEXT PRIMARY KEY, value TEXT)`.
  - `ensure_openable(path: Path, migrations: Sequence[Migration]) -> None`. Gọi **trước khi** mở ghi:
    - `info.min_reader_version > code_version` → `UNSUPPORTED_VERSION`;
    - `info.schema_version < code_version` → `MIGRATION_REQUIRED`.
  - `initialize(db: sqlite3.Connection, migrations: Sequence[Migration], *, store_id: str) -> None`: chỉ chạy với DB mới tạo. Hàm áp mọi migration rồi ghi `meta` (`schema_version`, `min_reader_version`, `store_id`).

- [ ] **Step 1: Viết test**

```python
def test_connection_pragmas(tmp_path):
    db = connect(tmp_path / "a.db")
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.execute("PRAGMA synchronous").fetchone()[0] == 2        # FULL

def test_darwin_enables_fullfsync(tmp_path):
    db = connect(tmp_path / "a.db", platform="darwin")
    assert db.execute("PRAGMA fullfsync").fetchone()[0] == 1

def test_newer_store_is_refused_before_any_write(tmp_path):          # tình huống 26
    path = make_store_with_meta(tmp_path, schema_version=99, min_reader_version=99)
    before = path.read_bytes()
    with pytest.raises(BrainError) as e:
        ensure_openable(path, STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and path.read_bytes() == before

def test_newer_store_readable_by_old_code_is_migration_free(tmp_path):
    path = make_store_with_meta(tmp_path, schema_version=2, min_reader_version=1)
    ensure_openable(path, STORE_MIGRATIONS)   # không raise: kho mới hơn nhưng vẫn cho phép code cũ đọc

def test_older_store_requires_explicit_migration(tmp_path):
    path = make_store_with_meta(tmp_path, schema_version=0, min_reader_version=0)
    with pytest.raises(BrainError) as e:
        ensure_openable(path, STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED
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

### Task 8: Ledger, transaction và projection

**Files:**
- Create: `src/superbrain/storage/ledger.py`, `src/superbrain/storage/store.py`
- Test: `tests/storage/test_ledger.py`

**Interfaces:**
- Consumes:
  - `connect`, `ensure_openable`, `initialize`, `STORE_MIGRATIONS` (Task 7);
  - `DataRoot`, `WriterLease` (Task 6);
  - `new_id`, `canonical_json`, `crashpoint` (Task 2);
  - `Clock` (Task 4).
- Produces (`ledger.py`):
  - `@dataclass(frozen=True) class LedgerEntry`: `sequence: int`, `entry_id: str`, `kind: str`, `schema_version: int`, `handler_version: int`, `writer_epoch: int`, `actor: str`, `owner_id: str | None`, `recorded_at: str`, `meta: Mapping[str, JsonValue]`, `refs: tuple[str, ...]`.
  - `class ProjectionHandler(Protocol)`:
    - thuộc tính `name: str`, `handler_version: int`, `kinds: frozenset[str]`;
    - `create_tables(db: sqlite3.Connection, prefix: str) -> None`;
    - `apply(db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None`.
  - `class Txn`:
    - `append(kind: str, *, actor: str, owner_id: str | None, meta: Mapping[str, JsonValue], refs: Sequence[str] = (), handler_version: int = 1) -> LedgerEntry`;
    - `mark_intent_applied(intent_id: str) -> bool`;
    - thuộc tính `db: sqlite3.Connection`.
  - Hằng số `MAX_META_BYTES = 4096`. `meta` dạng canonical vượt mức này thì `BrainError(INVALID_INPUT)`.
- Produces (`store.py`):
  - `class Store`:
    - `open(root: DataRoot, lease: WriterLease, os_: OsAdapters, policy: PolicyStore, handlers: Sequence[ProjectionHandler]) -> Store` (classmethod);
    - `transaction() -> AbstractContextManager[Txn]`;
    - `entries(after: int = 0) -> Iterator[LedgerEntry]`;
    - `rebuild_projections() -> int`, trả số entry đã replay;
    - property `cas: ContentStore`, `store_id: str`;
    - `close() -> None`.
  - Tiền tố bảng: projection đang chạy `p_<name>_`, bản dựng lại `r_<name>_`.

Thứ tự transaction:
1. `BEGIN IMMEDIATE`;
2. các `append`, mỗi lần gọi `handler.apply(db, "p_…", entry, policy)` cho mọi handler có `kind` tương ứng, ngay trong transaction;
3. `crashpoint("ledger.before_commit")`;
4. `COMMIT`;
5. `crashpoint("ledger.after_commit")`.

Có exception thì `ROLLBACK`. `rebuild_projections` gồm các bước:
1. tạo bảng `r_`;
2. replay toàn bộ entry;
3. entry có `handler_version` lớn hơn của handler → `UNSUPPORTED_VERSION` và xóa bảng `r_`;
4. trong một transaction: `DROP` các bảng `p_`, rồi `ALTER TABLE … RENAME` các bảng `r_` thành `p_`.

- [ ] **Step 1: Viết test**

```python
def test_append_and_projection_commit_together(store_factory):
    store = store_factory(handlers=[CounterProjection()])
    with store.transaction() as txn:
        txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert counter(store) == 1 and [e.kind for e in store.entries()] == ["demo.count"]

def test_exception_rolls_back_ledger_and_projection(store_factory):
    store = store_factory(handlers=[CounterProjection()])
    with pytest.raises(RuntimeError):
        with store.transaction() as txn:
            txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1}); raise RuntimeError
    assert counter(store) == 0 and list(store.entries()) == []

def test_entries_record_epoch_and_versions(store_factory):
    entry = append_one(store_factory())
    assert entry.writer_epoch == 1 and entry.schema_version == 1 and entry.handler_version == 1

def test_meta_over_limit_is_rejected(store_factory):
    with pytest.raises(BrainError) as e:
        append_one(store_factory(), meta={"x": "a" * 5000})
    assert e.value.code == ErrorCode.INVALID_INPUT

def test_rebuild_reproduces_projection_without_duplicates(store_factory):   # tình huống 6 (phần projection)
    store = store_factory(handlers=[CounterProjection()]); append_n(store, 5)
    assert store.rebuild_projections() == 5 and counter(store) == 5
    assert store.rebuild_projections() == 5 and counter(store) == 5

def test_unknown_handler_version_stops_rebuild_and_keeps_live_tables(store_factory):
    store = store_factory(handlers=[CounterProjection()]); append_one(store, handler_version=9)
    with pytest.raises(BrainError) as e: store.rebuild_projections()
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and counter(store) == 1

def test_crash_after_commit_keeps_entry(tmp_path):                          # tình huống 5 (phần ledger)
    assert run_until_crash("append_demo", "ledger.after_commit", tmp_path).returncode == 86
    assert len(list(reopen(tmp_path).entries())) == 1

def test_crash_before_commit_leaves_nothing(tmp_path):
    run_until_crash("append_demo", "ledger.before_commit", tmp_path)
    assert list(reopen(tmp_path).entries()) == []
```

`CounterProjection` và `store_factory` là fixture trong `tests/storage/conftest.py`. `store_factory` mở `Store` trên một data root mới, với `PolicyStore` thật (Task 11). Trong lúc Task 11 chưa xong, dùng `NullPolicyView`: `is_quarantined` và `is_tombstoned` luôn trả `False`. Task 11 thay `NullPolicyView` bằng `PolicyStore` thật trong fixture.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_ledger.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt `ledger.py` và `store.py`**

DDL schema v1 của kho:
- `ledger(sequence INTEGER PRIMARY KEY AUTOINCREMENT, entry_id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, schema_version INTEGER NOT NULL, handler_version INTEGER NOT NULL, writer_epoch INTEGER NOT NULL, actor TEXT NOT NULL, owner_id TEXT, recorded_at TEXT NOT NULL, meta BLOB NOT NULL, refs BLOB NOT NULL)`;
- `applied_intents(intent_id TEXT PRIMARY KEY, applied_sequence INTEGER NOT NULL)`;
- `meta`.

Sau khi tạo DB, gọi `secure_file` cho `brain.db`, `brain.db-wal`, `brain.db-shm`.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_ledger.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 9: CAS có holder

**Files:**
- Create: `src/superbrain/storage/cas.py`
- Modify: `src/superbrain/storage/store.py` (đăng ký `HolderProjection` mặc định; property `cas`)
- Test: `tests/storage/test_cas.py`

**Interfaces:**
- Consumes: `DurablePublisher` (Task 5), `Txn`, `Store` (Task 8), `PolicyView` (Task 11; trong lúc chờ, dùng `NullPolicyView` của Task 8).
- Produces:
  - `class RetentionClass(StrEnum)`: `EVENT_PAYLOAD = "event_payload"`, `EVIDENCE = "evidence"`, `DURABLE = "durable"`.
  - `class ContentStore`:
    - `put(data: bytes) -> str`: trả digest; bytes đã có thì kiểm tra rồi trả luôn;
    - `read(digest: str) -> bytes`: kiểm tra digest khi đọc; `QUARANTINED` nếu policy chặn; `NOT_FOUND`; sai digest → `INTEGRITY_FAILURE`;
    - `exists(digest: str) -> bool`;
    - `holders(digest: str) -> list[tuple[str, str, RetentionClass]]`.
  - Trên `Txn`:
    - `hold(digest: str, holder_kind: str, holder_id: str, retention: RetentionClass, expires_at: datetime | None) -> None`: ghi ledger entry `cas.hold`;
    - `release(digest: str, holder_kind: str, holder_id: str, reason: str) -> None`: ghi ledger entry `cas.release`.
  - `HolderProjection` (name `cas_holders`): bảng `p_cas_holders_(digest, holder_kind, holder_id, retention_class, expires_at, PRIMARY KEY(holder_kind, holder_id, digest))`. Khi `apply` một entry `cas.hold` có `(holder_kind, holder_id)` đang bị `policy.is_tombstoned`, handler bỏ qua entry đó.

Trình tự `put`:
1. kiểm tra digest đã có;
2. `write_new(staging/<new_id>.tmp)`;
3. `crashpoint("cas.after_staging_write")`;
4. `publish(staging, cas/<aa>/<hex>)`;
5. `crashpoint("cas.after_rename")`.

Gặp lỗi bất kỳ thì xóa file staging rồi raise lại lỗi đó. Holder chỉ được thêm bằng `txn.hold` **sau khi** `put` trả về (spec 5.4, bước 6).

- [ ] **Step 1: Viết test**

```python
def test_put_read_roundtrip_and_dedup(store):
    a = store.cas.put(b"hello"); b = store.cas.put(b"hello")
    assert a == b == digest_bytes(b"hello") and store.cas.read(a) == b"hello"

def test_read_detects_corruption(store):
    d = store.cas.put(b"hello"); blob_path(store, d).write_bytes(b"jello")
    with pytest.raises(BrainError) as e: store.cas.read(d)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

def test_disk_full_leaves_no_blob_or_staging(store, monkeypatch):            # Review Focus 2
    monkeypatch.setattr(os, "write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(BrainError) as e: store.cas.put(b"x" * 1000)
    assert e.value.code == ErrorCode.STORAGE_FULL
    assert list(store_dir(store).joinpath("staging").iterdir()) == [] and not store.cas.exists(digest_bytes(b"x" * 1000))

def test_shared_blob_has_independent_holders(store):                        # tình huống 25 (phần holder)
    d = store.cas.put(b"shared")
    with store.transaction() as t:
        t.hold(d, "event", "e1", RetentionClass.EVENT_PAYLOAD, expires_at=T0 + timedelta(days=90))
        t.hold(d, "evidence", "v1", RetentionClass.EVIDENCE, expires_at=None)
    with store.transaction() as t: t.release(d, "event", "e1", reason="expired")
    assert [h[0] for h in store.cas.holders(d)] == ["evidence"] and store.cas.read(d) == b"shared"

def test_crash_after_rename_before_hold_leaves_orphan_only(tmp_path):         # tình huống 5 (phần CAS)
    run_until_crash("put_and_hold", "cas.after_rename", tmp_path)
    store = reopen(tmp_path)
    assert orphan_digests(store) == [digest_bytes(b"payload")] and holders_table(store) == []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_cas.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_cas.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 10: GC của CAS và lease chặn GC

**Files:**
- Modify: `src/superbrain/storage/cas.py`
- Test: `tests/storage/test_cas_gc.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class GcReport`: `deleted: tuple[str, ...]`, `kept_pinned: tuple[str, ...]`, `kept_young: tuple[str, ...]`.
  - `ContentStore.collect_garbage(*, now: datetime, grace: timedelta = timedelta(hours=24)) -> GcReport`: xóa blob **không có holder nào**, không bị pin và có mtime cũ hơn `grace`. Không bao giờ xóa blob còn holder.
  - `ContentStore.pin(digests: Iterable[str]) -> AbstractContextManager[str]`: ghi bảng `gc_pins(lease_id, digest)` trong một transaction riêng, trả `lease_id`, rồi xóa pin khi thoát.
  - `ContentStore.orphans() -> list[str]`.
  - Không xóa thư mục `cas/<aa>/` kể cả khi rỗng.

- [ ] **Step 1: Viết test**

```python
def test_gc_deletes_old_orphan_only(store, clock):
    held = put_and_hold(store, b"held"); orphan = store.cas.put(b"orphan")
    report = store.cas.collect_garbage(now=clock.now() + timedelta(days=2))
    assert report.deleted == (orphan,) and store.cas.exists(held)

def test_gc_keeps_young_orphan(store, clock):
    orphan = store.cas.put(b"orphan")
    assert store.cas.collect_garbage(now=clock.now()).kept_young == (orphan,)

def test_gc_respects_pin(store, clock):
    orphan = store.cas.put(b"orphan")
    with store.cas.pin([orphan]):
        assert store.cas.collect_garbage(now=clock.now() + timedelta(days=2)).kept_pinned == (orphan,)
    assert store.cas.collect_garbage(now=clock.now() + timedelta(days=2)).deleted == (orphan,)
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

### Task 11: Policy store, intent và `trust_generation`

**Files:**
- Create: `src/superbrain/storage/policy_store.py`, `src/superbrain/storage/intents.py`
- Modify:
  - `src/superbrain/storage/store.py`: `Store.open` gọi `apply_pending_intents`.
  - `src/superbrain/storage/cas.py`: `read` kiểm tra `policy.is_quarantined`.
  - `tests/storage/conftest.py`: thay `NullPolicyView` bằng `PolicyStore` thật.
- Test: `tests/storage/test_policy_store.py`, `tests/storage/test_intents.py`

**Interfaces:**
- Produces (`policy_store.py`):
  - `class IntentKind(StrEnum)`: `TOMBSTONE = "tombstone"`, `QUARANTINE = "quarantine"`.
  - `@dataclass(frozen=True) class Intent`: `intent_id: str`, `kind: IntentKind`, `payload: Mapping[str, JsonValue]`, `created_at: str`.
  - `class PolicyView(Protocol)`: `is_quarantined(digest: str) -> bool`, `is_tombstoned(holder_kind: str, holder_id: str) -> bool`.
  - `class PolicyStore(PolicyView)`:
    - `open(root: DataRoot, lease: WriterLease, os_: OsAdapters, clock: Clock, *, store_id: str | None) -> PolicyStore` (classmethod);
    - `record_intent(kind: IntentKind, payload: Mapping[str, JsonValue]) -> Intent`;
    - `pending_intents() -> list[Intent]`;
    - `mark_applied(intent_id: str) -> None`;
    - `tombstones() -> list[tuple[str, str, str]]`, gồm `(holder_kind, holder_id, digest)`;
    - `trust_generation() -> int`;
    - property `store_id: str`;
    - `close() -> None`.
- Produces (`intents.py`):
  - `apply_pending_intents(store: Store, policy: PolicyStore) -> int`;
  - `reapply_policy(store: Store, policy: PolicyStore) -> int`: áp **mọi** tombstone, không chỉ intent đang chờ. Hàm này dùng sau restore.

Ngữ nghĩa:
- `record_intent` **trong cùng một transaction** của `policy.db`:
  - ghi intent;
  - ghi bảng tác dụng: `tombstones(holder_kind, holder_id, digest, intent_id)` hoặc `quarantine(digest, reason, intent_id)`.

  Commit xong mới `crashpoint("policy.after_intent_commit")`. Nhờ vậy nội dung bị chặn ngay khi commit.
- `apply_pending_intents` xử lý từng intent trong một `store.transaction()`. Nếu `txn.mark_intent_applied(id)` trả `True`:
  - với tombstone: `txn.release(...)` cho holder tương ứng, nếu holder đó còn;
  - với quarantine: `txn.append("policy.quarantine", meta={"digest": …, "intent_id": …})`.

  Sau commit gọi `crashpoint("intents.after_store_apply")`, rồi `policy.mark_applied(id)`.
- **`trust_generation`:**
  - Bảng `trust(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL)`. Lần đầu tạo, `generation = max(1, hwm)`.
  - Khi mở, nếu `generation < lease.state().trust_generation_hwm`: đặt `generation = hwm + 1` và `lease.raise_trust_hwm(hwm + 1)`. Trường hợp này xảy ra khi có người chép đè file policy cũ ngoài công cụ.
  - Khi mở, nếu `generation > hwm`: `lease.raise_trust_hwm(generation)`.
- `store_id` được ghi vào `meta` của policy lúc tạo kho. `PolicyStore.open(..., store_id=None)` với policy chưa có `store_id` là lỗi lập trình (`AssertionError`).

- [ ] **Step 1: Viết test**

```python
def test_quarantine_blocks_every_holder_immediately(store, policy):
    d = put_and_hold(store, b"secret", holders=[("event","e1"), ("evidence","v1")])
    policy.record_intent(IntentKind.QUARANTINE, {"digest": d, "reason": "secret"})
    with pytest.raises(BrainError) as e: store.cas.read(d)
    assert e.value.code == ErrorCode.QUARANTINED

def test_crash_between_policy_and_store_applies_exactly_once(tmp_path):      # tình huống 34
    run_until_crash("tombstone_event", "policy.after_intent_commit", tmp_path)
    store, policy = reopen_all(tmp_path)
    assert holder_rows(store, "event", "e1") == [] and count_entries(store, "cas.release") == 1
    store.close(); store, policy = reopen_all(tmp_path)
    assert count_entries(store, "cas.release") == 1

def test_crash_after_store_apply_before_mark_does_not_duplicate(tmp_path):
    run_until_crash("tombstone_event", "intents.after_store_apply", tmp_path)
    store, policy = reopen_all(tmp_path)
    assert count_entries(store, "cas.release") == 1 and policy.pending_intents() == []

def test_policy_generation_below_lock_hwm_is_raised_above_it(tmp_path):
    # mô phỏng việc chép đè policy.db bằng một bản cũ: hwm trong writer.lock lớn hơn generation trong file
    root = prepared(tmp_path)
    with writer(root) as lease:
        assert open_policy(root, lease).trust_generation() == 1
        lease.raise_trust_hwm(10)
    with writer(root) as lease:
        assert open_policy(root, lease).trust_generation() == 11 and lease.state().trust_generation_hwm == 11
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_policy_store.py tests/storage/test_intents.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy toàn bộ test storage, xác nhận pass** (vì fixture đã đổi sang policy thật)

Run: `uv run pytest tests/storage -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 12: Retention và tombstone

**Files:**
- Create: `src/superbrain/storage/retention.py`
- Test: `tests/storage/test_retention.py`

**Interfaces:**
- Consumes: `Store`, `PolicyStore`, `IntentKind.TOMBSTONE`, `apply_pending_intents`, `Clock`.
- Produces:
  - `@dataclass(frozen=True) class RetentionPolicy`: `event_payload_days: int = 90`.
  - `@dataclass(frozen=True) class ExpiryReport`: `expired: tuple[tuple[str, str], ...]`.
  - `expire_due(store: Store, policy: PolicyStore, now: datetime) -> ExpiryReport`. Holder có `expires_at <= now` và lớp lưu khác `DURABLE` được xử lý như sau: ghi intent tombstone cho holder đó, sau đó gọi `apply_pending_intents`.
  - `default_expiry(retention: RetentionClass, now: datetime, policy: RetentionPolicy) -> datetime | None`:
    - `EVENT_PAYLOAD` → `now + 90 ngày`;
    - `EVIDENCE` và `DURABLE` → `None`. Evidence không có hạn cố định; việc evidence theo Event được quyết định ở SP2/SP3.

- [ ] **Step 1: Viết test**

```python
def test_small_event_payload_expires_and_is_absent_from_ledger(store, policy, clock):   # tình huống 35
    marker = b"tiny-secret-7f3a"
    d = store.cas.put(marker)
    with store.transaction() as t:
        t.append("event.recorded", actor="system:worker:capture", owner_id="dan", meta={"event_id": "e1"}, refs=[d])
        t.hold(d, "event", "e1", RetentionClass.EVENT_PAYLOAD, default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), RetentionPolicy()))
    expire_due(store, policy, clock.now() + timedelta(days=91)); store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert not store.cas.exists(d)
    assert marker not in read_all_bytes(store_db_files(store))      # brain.db + -wal + -shm

def test_rebuild_does_not_resurrect_expired_holder(store, policy, clock):             # tình huống 6
    d = hold_event(store, clock); expire_due(store, policy, clock.now() + timedelta(days=91))
    store.rebuild_projections()
    assert store.cas.holders(d) == []

def test_clock_going_backwards_expires_nothing(store, policy, clock):                 # Review Focus 5
    d = hold_event(store, clock)
    assert expire_due(store, policy, clock.now() - timedelta(days=365)).expired == ()
    assert expire_due(store, policy, clock.now() + timedelta(days=91)).expired == (("event", "e1"),)

def test_durable_holders_never_expire(store, policy, clock):
    d = put_and_hold(store, b"lesson", retention=RetentionClass.DURABLE, expires_at=None)
    assert expire_due(store, policy, clock.now() + timedelta(days=10_000)).expired == () and store.cas.holders(d) != []
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_retention.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

Muốn `marker` không còn trong file DB, có hai việc phải đúng:
- ledger không bao giờ chứa payload (đã đảm bảo ở Task 8, vì `meta` chỉ chứa ID);
- DB đặt `PRAGMA secure_delete=ON` để trang bị xóa được ghi đè bằng 0.

Thêm `secure_delete=ON` vào `connect` (Task 7) và bổ sung assertion tương ứng vào `test_connection_pragmas`.

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_retention.py tests/storage/test_schema.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 13: Backup tự chứa

**Files:**
- Create: `src/superbrain/storage/backup.py`
- Test: `tests/storage/test_backup.py`

**Interfaces:**
- Consumes: `Store`, `PolicyStore`, `ContentStore.pin`, `DurablePublisher`, `PermissionGuard`.
- Produces:
  - `@dataclass(frozen=True) class BackupManifest`: `format_version: int` (= 1), `kind: Literal["store", "policy"]`, `store_id: str`, `schema_version: int`, `ledger_high_water: int` (0 với policy), `trust_generation: int | None`, `created_at: str`, `db_digest: str`, `blobs: tuple[str, ...]`.
  - `create_store_backup(store: Store, os_: OsAdapters, now: datetime) -> Path`. Backup được tạo trong `backups/store-<UTC yyyymmddThhmmssZ>-<new_id>/`, gồm:
    - snapshot DB bằng `sqlite3.Connection.backup` vào `brain.db`;
    - trong `cas.pin(blobs)`, chép mọi blob có holder trong snapshot vào `cas/`, làm bền từng file;
    - ghi `manifest.json` **sau cùng**.

    Crashpoint: `backup.after_db_snapshot`, `backup.after_blob_copy`. Thư mục backup thiếu `manifest.json` bị coi là chưa hoàn tất.
  - `create_policy_backup(policy: PolicyStore, os_: OsAdapters, now: datetime) -> Path`, tạo trong `backups/policy-…`.
  - `verify_store_backup(path: Path, *, expected_store_id: str) -> BackupManifest`. `INTEGRITY_FAILURE` khi:
    - thiếu manifest;
    - sai `db_digest`;
    - thiếu hoặc sai blob;
    - `store_id` khác `expected_store_id`;
    - `integrity_check` của DB snapshot khác `ok`.
  - `verify_policy_backup(path: Path, *, expected_store_id: str) -> BackupManifest`.
  - `prune_backups(backups_dir: Path, *, keep: int = 7) -> list[Path]`. Mỗi loại (`store`, `policy`) giữ `keep` bản hoàn tất mới nhất. Bản chưa hoàn tất cũ hơn 24 giờ được đổi tên thành `*.incomplete`, không xóa.

- [ ] **Step 1: Viết test**

```python
def test_backup_contains_every_held_blob(store, os_, clock):
    d = put_and_hold(store, b"kept"); path = create_store_backup(store, os_, clock.now())
    m = verify_store_backup(path, expected_store_id=store.store_id)
    assert d in m.blobs and (path / "cas" / d[7:9] / d[7:]).read_bytes() == b"kept"

def test_gc_on_live_store_does_not_affect_backup(store, policy, os_, clock):        # tình huống 25 (phần backup)
    d = hold_event(store, clock); path = create_store_backup(store, os_, clock.now())
    expire_due(store, policy, clock.now() + timedelta(days=91)); store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert verify_store_backup(path, expected_store_id=store.store_id).blobs == (d,)

@pytest.mark.parametrize("damage", ["drop_manifest", "flip_db_byte", "drop_blob", "flip_blob_byte"])
def test_damaged_backup_is_rejected(store, os_, clock, damage):                     # tình huống 7
    put_and_hold(store, b"kept"); path = create_store_backup(store, os_, clock.now()); DAMAGE[damage](path)
    with pytest.raises(BrainError) as e: verify_store_backup(path, expected_store_id=store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

def test_backup_for_other_store_is_rejected(store, os_, clock):
    path = create_store_backup(store, os_, clock.now())
    with pytest.raises(BrainError) as e: verify_store_backup(path, expected_store_id="other")
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE

def test_prune_keeps_seven_complete_per_kind(tmp_path):
    make_backups(tmp_path, kind="store", complete=9); make_backups(tmp_path, kind="policy", complete=2)
    make_backups(tmp_path, kind="store", incomplete=1, age=timedelta(hours=25))
    prune_backups(tmp_path, keep=7)
    assert count(tmp_path, "store-*", complete=True) == 7 and count(tmp_path, "policy-*", complete=True) == 2
    assert count(tmp_path, "*.incomplete") == 1     # đổi tên, không xóa
def test_backup_directory_is_owner_only(store, os_, clock):
    assert os_.permissions.problems(create_store_backup(store, os_, clock.now())) == []
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

### Task 14: Restore kho và restore policy store

**Files:**
- Create: `src/superbrain/storage/restore.py`
- Modify: `src/superbrain/storage/layout.py` (`finish_interrupted_swap`)
- Test: `tests/storage/test_restore.py`

**Interfaces:**
- Consumes:
  - `verify_store_backup`, `verify_policy_backup` (Task 13);
  - `reapply_policy` (Task 11);
  - `WriterLease.bump_epoch`, `raise_trust_hwm` (Task 6).
- Produces:
  - `@dataclass(frozen=True) class RestoreReport`: `restored_from: Path`, `replaced_dir: Path`, `reapplied_tombstones: int`, `new_epoch: int`.
  - `restore_store(root: DataRoot, lease: WriterLease, os_: OsAdapters, backup: Path, policy: PolicyStore, handlers: Sequence[ProjectionHandler], now: datetime) -> RestoreReport`. Điều kiện trước: caller đã `close()` Store đang mở; `lease` giữ khóa suốt quá trình. Các bước:
    1. `verify_store_backup(expected_store_id=policy.store_id)`;
    2. chép vào `store.restoring/` và làm bền;
    3. mở Store trên `store.restoring`, chạy `reapply_policy`, rồi đóng;
    4. ghi marker `store.restoring/RESTORE_READY`;
    5. `crashpoint("restore.after_stage")`;
    6. rename `store/` → `store.replaced-<UTC>-<id>/`;
    7. `crashpoint("restore.between_renames")`;
    8. rename `store.restoring/` → `store/`;
    9. `sync_directory(root)`, `lease.bump_epoch()`.
  - `restore_policy(root: DataRoot, lease: WriterLease, os_: OsAdapters, backup: Path, *, store_id: str) -> int`. Hàm dùng chung trình tự hoán đổi với `restore_store` (thư mục `policy.restoring/`, `policy.replaced-…`), rồi đặt `generation = max(hwm, snapshot.trust_generation) + 1`. Giá trị mới được ghi vào DB đã khôi phục **trước khi** hoán đổi, rồi ghi lên `writer.lock` bằng `lease.raise_trust_hwm`. Hàm trả về `generation` mới.
  - `finish_interrupted_swap(root: DataRoot, os_: OsAdapters) -> list[str]`, gọi từ `prepare_data_root`. Hàm xét `store` rồi `policy`:
    - `X/` không tồn tại, có `X.restoring/RESTORE_READY` → hoàn tất rename. Đây là crash giữa hai rename: restore đã được yêu cầu và bản gốc đã được cất ở `X.replaced-…`.
    - `X/` còn nguyên, có `X.restoring/` (dù có marker hay không) → đổi tên `X.restoring/` thành `X.restoring.abandoned-<id>`. Restore coi như chưa xảy ra; người dùng chạy lại lệnh.

    Hàm không bao giờ xóa gì và trả về danh sách hành động đã làm.

- [ ] **Step 1: Viết test**

```python
def test_restore_brings_back_backed_up_state(env):
    append_marker(env.store, "before"); path = backup(env); append_marker(env.store, "after")
    report = restore(env, path)
    assert markers(reopen_store(env)) == ["before"] and report.replaced_dir.exists()

def test_restore_reapplies_newer_tombstones_and_quarantine(env, clock):              # tình huống 21 (phần policy)
    d = hold_event(env.store, clock); path = backup(env)
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": d, "reason": "secret"})
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    restore(env, path)
    store = reopen_store(env)
    assert store.cas.holders(d) == []
    with pytest.raises(BrainError) as e: store.cas.read(d)
    assert e.value.code == ErrorCode.QUARANTINED

def test_restore_keeps_writer_lock_and_blocks_second_writer(env):
    path = backup(env); lock_identity = file_identity(env.root.lock_path)
    with child_trying_to_acquire_during(lambda: restore(env, path)) as attempts:
        pass
    assert all(a.error_code == "writer_held" for a in attempts) and file_identity(env.root.lock_path) == lock_identity

@pytest.mark.parametrize("point,expected", [
    ("restore.after_stage", ["before", "after"]),      # chưa hoán đổi → bỏ bản đang dựng dở
    ("restore.between_renames", ["before"]),           # đã cất bản gốc → hoàn tất restore
])
def test_interrupted_restore_recovers_deterministically(tmp_path, point, expected):
    seed_before_backup_after(tmp_path)                 # marker "before", backup, marker "after"
    run_until_crash("restore_from_latest", point, tmp_path)
    finish_interrupted_swap(layout(tmp_path), os_adapters())
    assert markers(reopen_store_at(tmp_path)) == expected
    assert every_original_store_dir_still_exists(tmp_path)   # store.replaced-* hoặc *.abandoned-* còn nguyên

def test_policy_restore_raises_generation_above_every_previous_value(env):            # tình huống 32 (phần generation)
    g0 = env.policy.trust_generation(); path = policy_backup(env)
    g1 = restore_policy_now(env, path); g2 = restore_policy_now(env, path)
    assert g0 < g1 < g2 and env.lease.state().trust_generation_hwm == g2

def test_restore_of_wrong_store_is_refused_before_touching_store_dir(env, other_env):
    foreign = backup(other_env); before = digest_tree(env.root.store_dir)
    with pytest.raises(BrainError) as e: restore(env, foreign)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and digest_tree(env.root.store_dir) == before
```

`env` là fixture trong `tests/storage/conftest.py`, gồm `root`, `lease`, `store`, `policy`, `os_`. Các helper `restore()`, `restore_policy_now()` tự đóng rồi mở lại `Store`/`PolicyStore`.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_restore.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_restore.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 15: Migration

**Files:**
- Create: `src/superbrain/storage/migrate.py`
- Test: `tests/storage/test_migrate.py`

**Interfaces:**
- Consumes: `Migration`, `read_schema_info` (Task 7), `create_store_backup` (Task 13), trình tự hoán đổi và `finish_interrupted_swap` (Task 14).
- Produces:
  - `@dataclass(frozen=True) class MigrationReport`: `from_version: int`, `to_version: int`, `backup: Path`, `replaced_dir: Path`.
  - `migrate_store(root: DataRoot, lease: WriterLease, os_: OsAdapters, policy: PolicyStore, migrations: Sequence[Migration], now: datetime) -> MigrationReport`. Các bước:
    1. tạo backup; backup lỗi thì dừng;
    2. chép `store/` → `store.migrating/`;
    3. áp các migration có `to_version > schema_version` theo thứ tự, mỗi migration một transaction, cập nhật `meta`;
    4. kiểm tra `PRAGMA integrity_check == ok`;
    5. ghi marker `MIGRATE_READY`;
    6. `crashpoint("migrate.after_stage")`;
    7. hoán đổi như restore, với crashpoint `migrate.between_renames`;
    8. `lease.bump_epoch()`.

    Migration nào raise lỗi thì giữ nguyên `store/`, đổi tên `store.migrating/` thành `.abandoned-<id>`, và raise lại lỗi đó.
  - `finish_interrupted_swap` (Task 14) xử lý `store.migrating/` theo cùng quy tắc với `store.restoring/`, dùng marker `MIGRATE_READY`.

- [ ] **Step 1: Viết test**

```python
def test_migration_applies_and_bumps_version(env):
    v2 = Migration(to_version=2, min_reader_version=1, apply=lambda db: db.execute("CREATE TABLE x(a)"))
    report = migrate_store(..., migrations=(*STORE_MIGRATIONS, v2), now=...)
    assert read_schema_info(env.root.store_db) == SchemaInfo(2, 1) and report.backup.exists()

def test_failed_migration_leaves_store_untouched(env):
    bad = Migration(to_version=2, min_reader_version=1, apply=raise_runtime_error)
    before = digest_tree(env.root.store_dir)
    with pytest.raises(RuntimeError): migrate_store(..., migrations=(*STORE_MIGRATIONS, bad), now=...)
    assert digest_tree(env.root.store_dir) == before

@pytest.mark.parametrize("point,expected_version", [("migrate.after_stage", 1), ("migrate.between_renames", 2)])
def test_interrupted_migration_recovers(tmp_path, point, expected_version):
    run_until_crash("migrate_to_v2", point, tmp_path)
    finish_interrupted_swap(layout(tmp_path), os_adapters())
    assert read_schema_info(layout(tmp_path).store_db).schema_version == expected_version
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_migrate.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_migrate.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 16: Bảng điểm crash

**Files:**
- Create: `docs/design/sp1-crash-table.md`
- Test: `tests/storage/test_crash_matrix.py`

**Interfaces:**
- Consumes: `KNOWN_CRASHPOINTS` (Task 2), `run_until_crash` (Task 6), và mọi crashpoint từ Task 6 tới Task 15.

`KNOWN_CRASHPOINTS` của đợt 1:
- `writer.mid_slot_write`
- `ledger.before_commit`, `ledger.after_commit`
- `cas.after_staging_write`, `cas.after_rename`
- `policy.after_intent_commit`, `intents.after_store_apply`
- `backup.after_db_snapshot`, `backup.after_blob_copy`
- `restore.after_stage`, `restore.between_renames`
- `migrate.after_stage`, `migrate.between_renames`

Mỗi dòng của `sp1-crash-table.md` gồm các cột:
- crashpoint;
- thao tác;
- trạng thái đĩa trước/sau;
- đã ACK chưa;
- phục hồi khi khởi động lại;
- invariant được giữ;
- test chứng minh;
- **Tiến trình chết:** có test;
- **Mất điện:** dựa trên ngữ nghĩa OS ở Task 5, không có test. Ghi rõ "không được chứng minh bằng test kill tiến trình" (spec 5.4).

Đầu file ghi rõ ApplyJournal thuộc đợt 3 và sẽ được thêm vào bảng ở đợt đó.

- [ ] **Step 1: Viết test**

```python
def test_every_crashpoint_is_documented():
    rows = parse_crash_table(DOCS / "design" / "sp1-crash-table.md")
    assert set(rows) == KNOWN_CRASHPOINTS

@pytest.mark.parametrize("point", sorted(KNOWN_CRASHPOINTS))
def test_every_crashpoint_has_a_recovery_test(point):
    assert crashpoint_is_exercised(point, TESTS_ROOT)   # tên crashpoint xuất hiện trong lời gọi run_until_crash ở ít nhất một test

@pytest.mark.parametrize("point", sorted(KNOWN_CRASHPOINTS))
def test_store_opens_and_passes_integrity_after_crash(tmp_path, point):
    run_until_crash(OPERATION_FOR[point], point, tmp_path)
    store, policy = reopen_all(tmp_path)
    assert store.db_integrity() == "ok" and all(store.cas.read(d) for d in held_digests(store))
```

`OPERATION_FOR: dict[str, str]` ánh xạ mỗi crashpoint tới một thao tác trong `tests/support/crash_scripts.py`. `Store.db_integrity() -> str` chạy `PRAGMA integrity_check`; thêm hàm này vào `Store` ở task này.

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/storage/test_crash_matrix.py -v`
Expected: FAIL (chưa có tài liệu).

- [ ] **Step 3: Viết `sp1-crash-table.md` và thêm `Store.db_integrity`**

- [ ] **Step 4: Chạy test, xác nhận pass**

Run: `uv run pytest tests/storage/test_crash_matrix.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 17: Gate và receipt của đợt 1

**Files:**
- Create: `scripts/gate.py`
- Test: `tests/architecture/test_gate_receipt.py`

**Interfaces:**
- Produces:
  - `build_receipt(*, commit: str, tree_clean: bool, lock_digest: str, config_digest: str, test_ids: Sequence[str], results: Mapping[str, int], python: str, platform: str, exit_codes: Mapping[str, int]) -> dict[str, JsonValue]`.
  - Receipt có `test_inventory_digest = digest_bytes(canonical_json(sorted(test_ids)))` và `accepted: bool`. `accepted` chỉ `True` khi đủ các điều kiện:
    - `tree_clean`;
    - mọi exit code bằng 0;
    - `results["failed"] == 0`, `results["error"] == 0`.

  `scripts/gate.py` chạy lần lượt `ruff check src tests`, `mypy`, `lint-imports`, `pytest --junitxml`, rồi ghi `.gate/receipt-<commit>-<python>-<platform>.json`. `.gate/` nằm trong `.gitignore`.

- [ ] **Step 1: Viết test**

```python
def test_dirty_tree_is_never_accepted():
    assert build_receipt(**base(tree_clean=False))["accepted"] is False

def test_any_failure_blocks_acceptance():
    assert build_receipt(**base(results={"passed": 10, "failed": 1, "error": 0, "skipped": 0}))["accepted"] is False

def test_inventory_digest_is_order_independent():
    assert build_receipt(**base(test_ids=["b", "a"]))["test_inventory_digest"] == build_receipt(**base(test_ids=["a", "b"]))["test_inventory_digest"]

def test_skipped_count_is_reported_not_hidden():
    assert build_receipt(**base(results={"passed": 9, "failed": 0, "error": 0, "skipped": 3}))["results"]["skipped"] == 3
```

- [ ] **Step 2: Chạy test, xác nhận fail**

Run: `uv run pytest tests/architecture/test_gate_receipt.py -v`
Expected: FAIL.

- [ ] **Step 3: Cài đặt `scripts/gate.py`**

- [ ] **Step 4: Chạy gate thật trên cả hai Python tại máy**

Run: `uv run --python 3.11 python scripts/gate.py && uv run --python 3.14 python scripts/gate.py`
Expected: hai receipt có `"accepted": true`. Pytest của mỗi lần chạy xong dưới 5 phút.

- [ ] **Step 5: Commit**

Receipt **không** được commit. Báo kết quả trong mô tả bàn giao, kèm đường dẫn file receipt và commit SHA.

---

## Bàn giao đợt 1

Đợt 1 chỉ được báo "xong" khi đủ các điều kiện sau:
- Có receipt `accepted: true` của gate mặc định trên Windows với Python 3.11 và 3.14, cho đúng commit cuối.
- `docs/design/sp1-crash-table.md` có đủ mọi crashpoint.
- Các tình huống nghiệm thu của spec mục 20 mà đợt 1 phủ đã có test xanh:
  - phủ đủ: 26, 34, 35;
  - phủ phần storage: 5, 6, 7, 8, 21, 25, 28, 32.
- Ghi rõ những gì **chưa nghiệm thu**:
  - CI trên macOS và Linux, cho tới khi có remote;
  - độ bền khi mất điện (chỉ có lập luận theo ngữ nghĩa OS);
  - phần còn lại của tình huống 21 (credential) và 32 (nonce), thuộc đợt 2–3.

Không ghi "verified" cho các phần này.
