"""Independent regression for Task 3 review finding I2-T3-R03: the registry mirror reads real historical ledgers.

Oracle sources (requirements, not current output):

- D3: ``repo_id``/``checkout_id`` live in the policy registry; the store keeps only a mirror rebuilt from policy
  intents, the authority is policy, and the mirror never grants (``test_workspace_authorization_ignores_main_mirror``
  covers the authorization side).
- Task 2 plan ("Giữ migration đã commit bất biến ... không sửa migration cũ hoặc xóa fixtures") and the I1 ledger
  rule that history is append-only: a reader may not rewrite or reject valid committed history.
- Task 3 plan: the main ``p_workspace_registry_*`` table is a mirror reducer over typed ledger entries.

Therefore a root whose ledger holds the ``policy.workspace_register`` entry exactly as accepted source ``007b40f``
wrote it (handler_version 1 *with* a ``subject_id`` digest), migrated by accepted source ``ff46f42``, must open with
the current kernel extensions; the mirror shows that registration as a candidate with its subject digest, the policy
registry keeps the same IDs, and the committed ledger history is unchanged.

The root is built through the exact revisions (``git archive`` of ``src`` and ``tests`` at each commit, run in a child
interpreter whose ``superbrain``/``tests`` imports are asserted to come from that archive). No SQL is hand-forged.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from superbrain.adapters.os import os_adapters
from superbrain.application.lineage import resolve_binding
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DaemonConfig, Principal, WorkspaceSelector
from superbrain.ports.os import OsAdapters
from superbrain.storage.ledger import LedgerEntry
from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
from superbrain.storage.workspaces import StoreWorkspaceMirror
from tests.support.clock import FakeClock

REPO_ROOT = Path(__file__).resolve().parents[2]
WRITER_007 = "007b40fd6317ef786db451d8c3b1e915836f2483"  # accepted Task 1/2 remediation: writes v1 + subject digest
MIGRATOR_FF4 = "ff46f4289c67a0d32d8f7d616b0d11dd7baa22c2"  # accepted Task 1/2 baseline: migrates to (3, 3)

_DRIVER = r"""
import datetime as dt
import json
import sys
from pathlib import Path

req = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
hist = Path(req["hist"]).resolve()
repo_root = Path(req["repo_root"]).resolve()
blocked = {repo_root, (repo_root / "src").resolve()}
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() not in blocked]
sys.path[:0] = [str(hist / "src"), str(hist)]

import superbrain
import tests.support.kernel_auth as kernel_auth
from superbrain.adapters.os import os_adapters
from superbrain.storage.schema import read_schema_info
from tests.support.clock import FakeClock

assert Path(superbrain.__file__).resolve().is_relative_to(hist / "src"), superbrain.__file__
assert Path(kernel_auth.__file__).resolve().is_relative_to(hist / "tests"), kernel_auth.__file__

base = Path(req["base"])
root = base / "data"


def dump(entries):
    return [
        {
            "sequence": e.sequence,
            "entry_id": e.entry_id,
            "kind": e.kind,
            "schema_version": e.schema_version,
            "handler_version": e.handler_version,
            "writer_epoch": e.writer_epoch,
            "actor": e.actor,
            "owner_id": e.owner_id,
            "recorded_at": e.recorded_at,
            "meta": dict(e.meta),
            "refs": list(e.refs),
        }
        for e in entries
    ]


def schema():
    return [
        read_schema_info(root / "store" / "brain.db").schema_version,
        read_schema_info(root / "policy" / "policy.db").schema_version,
    ]


if req["mode"] == "write_007":
    from superbrain.core.kernel import WorkspaceRegistration
    from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
    from superbrain.storage.runtime import open_runtime

    clock = FakeClock(dt.datetime(2026, 11, 6, 8, 0, tzinfo=dt.UTC))
    rt = open_runtime(
        root,
        os_adapters(clock=clock),
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        cred = kernel_auth.seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-hist-1"
        )
        checkout = base / "checkout"
        checkout.mkdir()
        reg = WorkspaceRegistration(
            owner_id="dan",
            principal_id=cred.principal.principal_id,
            machine_id=cred.principal.machine_id,
            alias="legacy",
            checkout_path=str(checkout),
            path_identity="fixture-physical-checkout",
        )
        binding = rt.policy.register_authorized_workspace(
            reg,
            kernel_auth.make_bootstrap_auth(
                store_id=rt.policy.store_id,
                owner_id="dan",
                action="workspace_register",
                subject_id=reg.subject_id,
                trust_generation=rt.policy.trust_generation(),
                expires_at=clock.now() + dt.timedelta(hours=1),
            ),
        )
        rt.store.reconcile_policy()
        out = {
            "store_id": rt.store.store_id,
            "repo_id": binding.repo_id,
            "checkout_id": binding.checkout_id,
            "principal": [
                cred.principal.principal_id,
                cred.principal.owner_id,
                cred.principal.harness_id,
                cred.principal.machine_id,
            ],
            "subject_id": reg.subject_id,
            "entries": dump(rt.store.entries()),
        }
    finally:
        rt.close()
    out["schema"] = schema()
    print(json.dumps(out))
elif req["mode"] == "migrate_ff4":
    from superbrain.composition.migrate_entry import migrate_offline
    from superbrain.core.kernel import DaemonConfig
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease

    clock = FakeClock(dt.datetime(2026, 11, 6, 9, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    sid = req["store_id"]
    migrate_offline(DaemonConfig(1, root, sid, base / "unused.pem", base / "unused.key"), adapters)
    rt = open_runtime_under_lease(admit_existing_pair(root, sid, adapters, purpose="serve"))
    try:
        snap = rt.policy.snapshot()
        out = {
            "entries": dump(rt.store.entries()),
            "checkouts": sorted([c.checkout_id, c.repo_id, c.alias] for c in snap.checkouts.values()),
        }
    finally:
        rt.close()
    out["schema"] = schema()
    print(json.dumps(out))
else:
    raise AssertionError(req["mode"])
"""


def _extract_revision(rev: str, dest: Path, os_: OsAdapters) -> Path:
    archive = dest.with_suffix(".zip")
    proc = subprocess.run(
        ["git", "archive", "--format=zip", f"--output={archive}", rev, "src", "tests"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    dest.mkdir()
    os_.permissions.secure_directory(dest)
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            parts = Path(member.filename).parts
            assert parts and parts[0] in ("src", "tests") and ".." not in parts, member.filename
            assert not Path(member.filename).is_absolute() and not Path(member.filename).drive, member.filename
        zf.extractall(dest)
    assert (dest / "src" / "superbrain" / "__init__.py").is_file()
    return dest


def _run_stage(hist: Path, base: Path, os_: OsAdapters, payload: dict[str, object]) -> dict[str, Any]:
    driver = base.parent / "mirror_history_driver.py"
    if not driver.exists():
        driver.write_text(_DRIVER, encoding="utf-8")
        os_.permissions.secure_file(driver)
    request = base.parent / f"request-{payload['mode']}.json"
    request.write_text(
        json.dumps({"hist": str(hist), "repo_root": str(REPO_ROOT), "base": str(base), **payload}), encoding="utf-8"
    )
    os_.permissions.secure_file(request)
    proc = subprocess.run(
        [sys.executable, str(driver), str(request)], cwd=hist, text=True, capture_output=True, check=False
    )
    assert proc.returncode == 0, f"historical stage {payload['mode']} failed:\n{proc.stdout}\n{proc.stderr}"
    parsed = json.loads(proc.stdout)
    assert isinstance(parsed, dict)
    return parsed


def _current_entries(entries: Iterable[LedgerEntry]) -> list[dict[str, object]]:
    return [
        {
            "sequence": e.sequence,
            "entry_id": e.entry_id,
            "kind": e.kind,
            "schema_version": e.schema_version,
            "handler_version": e.handler_version,
            "writer_epoch": e.writer_epoch,
            "actor": e.actor,
            "owner_id": e.owner_id,
            "recorded_at": e.recorded_at,
            "meta": json.loads(json.dumps(dict(e.meta))),
            "refs": list(e.refs),
        }
        for e in entries
    ]


def test_exact_007_v1_register_entry_with_subject_opens_with_current_mirror(trusted_tmp: Path, os_: OsAdapters) -> None:
    for rev in (WRITER_007, MIGRATOR_FF4):
        present = subprocess.run(
            ["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=REPO_ROOT, capture_output=True, check=False
        )
        assert present.returncode == 0, f"exact source revision {rev} must be available in this repository"
    hist_007 = _extract_revision(WRITER_007, trusted_tmp / "hist-007b40f", os_)
    hist_ff4 = _extract_revision(MIGRATOR_FF4, trusted_tmp / "hist-ff46f42", os_)
    base = trusted_tmp / "chain"
    base.mkdir()
    os_.permissions.secure_directory(base)

    written = _run_stage(hist_007, base, os_, {"mode": "write_007"})
    assert written["schema"] == [2, 2]
    registers = [e for e in written["entries"] if e["kind"] == "policy.workspace_register"]
    assert len(registers) == 1
    legacy = registers[0]
    assert legacy["handler_version"] == 1
    assert legacy["meta"]["subject_id"] == written["subject_id"]
    assert str(written["subject_id"]).startswith("sha256:")  # the real historical shape the finding is about

    migrated = _run_stage(hist_ff4, base, os_, {"mode": "migrate_ff4", "store_id": written["store_id"]})
    assert migrated["schema"] == [3, 3]
    assert [e for e in migrated["entries"] if e["kind"] == "policy.workspace_register"] == registers
    history = migrated["entries"]
    assert isinstance(history, list)

    root = base / "data"
    store_id = str(written["store_id"])
    repo_id, checkout_id = str(written["repo_id"]), str(written["checkout_id"])
    principal = Principal(*(str(v) for v in written["principal"]))
    clock = FakeClock(dt.datetime(2026, 11, 6, 10, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)

    # Current kernel targets (store=5, policy=4): serve refuses (3, 3) until migrate_offline upgrades (3,3)->(5,4).
    try:
        unexpected_admit = admit_existing_pair(root, store_id, adapters, purpose="serve")
        unexpected_admit.release()
        raise AssertionError("expected MIGRATION_REQUIRED before offline migration")
    except BrainError as pre_mig_err:
        assert pre_mig_err.code is ErrorCode.MIGRATION_REQUIRED

    mig_cur = migrate_offline(DaemonConfig(1, root, store_id, base / "unused.pem", base / "unused.key"), adapters)
    assert mig_cur.policy_report.status == "migrated"
    assert mig_cur.policy_report.from_version == 3 and mig_cur.policy_report.to_version == 5
    assert mig_cur.store_report.status == "migrated"
    assert mig_cur.store_report.from_version == 3 and mig_cur.store_report.to_version == 6

    for attempt in ("first open", "reopen after rebuild"):
        handlers, kinds = kernel_store_extensions()
        try:
            rt = open_runtime_under_lease(
                admit_existing_pair(root, store_id, adapters, purpose="serve"), handlers=handlers, kinds=kinds
            )
        except BrainError as err:
            raise AssertionError(
                f"{attempt}: current kernel refused valid exact-source history: {err.code.value}: {err.message}"
            ) from None
        try:
            current = _current_entries(rt.store.entries())
            assert current[: len(history)] == history, attempt  # committed history is never rewritten
            assert not [e for e in current[len(history) :] if e["kind"] == "policy.workspace_register"], attempt
            candidates = StoreWorkspaceMirror(rt.store).mirror_candidates(checkout_id=checkout_id)
            assert len(candidates) == 1, attempt
            cand = candidates[0]
            assert (cand.repo_id, cand.alias, cand.subject_id, cand.handler_version) == (
                repo_id,
                "legacy",
                written["subject_id"],
                1,
            ), attempt
            assert cand.intent_id == legacy["meta"]["intent_id"], attempt
            snap = rt.policy.snapshot()
            assert (
                sorted([c.checkout_id, c.repo_id, c.alias] for c in snap.checkouts.values()) == migrated["checkouts"]
            ), attempt  # authority stays in policy: no ID minted or dropped by the mirror
            bound = resolve_binding(principal, WorkspaceSelector(workspace_hint="legacy"), rt.policy)
            assert (bound.repo_id, bound.checkout_id) == (repo_id, checkout_id), attempt
            rt.store.rebuild_projections()
        finally:
            rt.close()
