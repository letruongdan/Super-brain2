"""Strictly read-only deep diagnostic probes for ``storage._doctor_reader`` (I4-1)."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from pathlib import Path

from superbrain.core._fs_walk import (
    MAX_TRANSIENT_WALK_ATTEMPTS,
    classify_below_root_failure,
    stat_reparse_or_link,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, describe_exception
from superbrain.ports.doctor import (
    MAX_LIST_FINDINGS_PER_GROUP,
    CaptureDoctorProbePort,
    CaptureDoctorProbeResult,
    DoctorDaemonStats,
    DoctorIdentityStats,
    DoctorJevStats,
    DoctorScanLimits,
    PrivacyRescanSummary,
    PrivacyScanFinding,
    PrivacyScannerPort,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_storage_probes import (
    is_link_entry,
    probe_storage_and_retention,
    table_exists,
)
from superbrain.storage.layout import DataRoot
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.writer import SLOT_SIZE, _read_slots

__all__ = [
    "check_permissions_strict",
    "probe_daemon_state",
    "probe_identity_and_jev",
    "probe_storage_and_retention",
    "run_capture_probe_bounded",
    "run_privacy_rescan",
]


def check_permissions_strict(
    root: DataRoot,
    os_: OsAdapters,
    errors: list[str],
    perm_problems: list[str],
    ancestor_problems: list[str],
    backup_problems: list[str],
) -> None:
    """Inspect ``data_root``, ancestors, tree entries, and ``backups/`` without descending into symlinks/junctions."""
    try:
        for p in os_.permissions.check_ancestors(root.root):
            ancestor_problems.append(str(p))
            perm_problems.append(str(p))
    except (BrainError, OSError) as exc:
        errors.append(f"ancestor permission check error: {describe_exception(exc)}")

    # Detect any link/reparse points under data_root without ever descending into their targets.
    if os.path.lexists(root.root) and not is_link_entry(root.root):
        stack: list[Path] = [root.root]
        while stack:
            cur = stack.pop()
            entries: list[os.DirEntry[str]] | None = None
            for attempt in range(MAX_TRANSIENT_WALK_ATTEMPTS):
                try:
                    with os.scandir(cur) as it:
                        entries = sorted(it, key=lambda e: e.name)
                    break
                except OSError as exc:
                    state = classify_below_root_failure(cur, root.root, exc)
                    if state == "vanished":
                        break
                    if state == "recreated_link":
                        rel = cur.relative_to(root.root).as_posix()
                        msg = f"forbidden symlink/reparse point at {rel}"
                        perm_problems.append(msg)
                        errors.append(msg)
                        break
                    if state == "recreated" and attempt + 1 < MAX_TRANSIENT_WALK_ATTEMPTS:
                        continue
                    errors.append(f"directory scan error at {cur.name}: {describe_exception(exc)}")
                    break
            if entries is None:
                continue
            for entry in entries:
                epath = Path(entry.path)
                if entry.is_symlink() or is_link_entry(epath):
                    rel = epath.relative_to(root.root).as_posix()
                    msg = f"forbidden symlink/reparse point at {rel}"
                    perm_problems.append(msg)
                    errors.append(msg)
                    continue
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    state = classify_below_root_failure(epath, root.root, exc)
                    if state == "vanished":
                        continue
                    if state == "recreated_link":
                        rel = epath.relative_to(root.root).as_posix()
                        msg = f"forbidden symlink/reparse point at {rel}"
                        perm_problems.append(msg)
                        errors.append(msg)
                        continue
                    if state == "recreated":
                        try:
                            est = os.lstat(epath)
                        except FileNotFoundError:
                            continue
                        except OSError as lstat_exc:
                            errors.append(f"stat error at {epath.name}: {describe_exception(lstat_exc)}")
                            continue
                    else:
                        errors.append(f"stat error at {epath.name}: {describe_exception(exc)}")
                        continue
                if stat_reparse_or_link(est) or entry.is_symlink():
                    rel = epath.relative_to(root.root).as_posix()
                    msg = f"forbidden symlink/reparse point at {rel}"
                    perm_problems.append(msg)
                    errors.append(msg)
                    continue
                if stat.S_ISDIR(est.st_mode):
                    stack.append(epath)

    if os.path.lexists(root.root):
        try:
            for p in os_.permissions.problems(root.root):
                text = str(p)
                if len(perm_problems) < MAX_LIST_FINDINGS_PER_GROUP * 2:
                    perm_problems.append(text)
                if root.backups_dir == p.path or root.backups_dir in p.path.parents:
                    backup_problems.append(text)
        except (BrainError, OSError) as exc:
            errors.append(f"permission check error: {describe_exception(exc)}")

    if os.path.lexists(root.backups_dir) and not is_link_entry(root.backups_dir):
        try:
            for p in os_.permissions.object_problems(root.backups_dir):
                s = str(p)
                if s not in backup_problems:
                    backup_problems.append(s)
                if s not in perm_problems:
                    perm_problems.append(s)
        except (BrainError, OSError) as exc:
            msg = f"backup permission error: {describe_exception(exc)}"
            backup_problems.append(msg)
            errors.append(msg)


def probe_daemon_state(root: DataRoot, os_: OsAdapters, errors: list[str]) -> DoctorDaemonStats:
    """Inspect ``writer.lock`` non-exclusively, decode epoch slots read-only, and check ``endpoint.json``."""
    lock_present = os.path.lexists(root.lock_path)
    lock_held = False
    writer_epoch: int | None = None
    lock_error: str | None = None

    if not lock_present:
        lock_error = "writer.lock is missing"
        errors.append(lock_error)
    elif is_link_entry(root.lock_path):
        lock_error = "writer.lock is an unsafe link/reparse point"
        errors.append(lock_error)
    else:
        probe_fn = getattr(os_.locks, "probe_held", None)
        if not callable(probe_fn):
            lock_error = "writer.lock probe unavailable"
            errors.append(lock_error)
        else:
            try:
                lock_held = bool(probe_fn(root.lock_path))
            except BrainError as exc:
                lock_error = f"writer.lock probe failed: {describe_exception(exc)}"
                errors.append(lock_error)
        try:
            with open(root.lock_path, "rb") as fh:
                fh.seek(1)
                raw = fh.read(2 * SLOT_SIZE)
            slot, _ = _read_slots(raw)
            writer_epoch = slot.writer_epoch
        except (BrainError, OSError) as exc:
            lock_error = f"writer.lock payload invalid: {describe_exception(exc)}"
            errors.append(lock_error)

    ep_present = os.path.lexists(root.endpoint_path)
    ep_valid: bool | None = None
    ep_detail = "endpoint.json absent (daemon stopped)" if not ep_present else "endpoint.json present"
    if ep_present:
        if is_link_entry(root.endpoint_path):
            ep_valid = False
            ep_detail = "endpoint.json is a symlink/reparse point"
            errors.append(ep_detail)
        else:
            ep_valid = True
    elif lock_held:
        ep_detail = "writer.lock held without endpoint.json"

    return DoctorDaemonStats(
        writer_lock_present=lock_present,
        writer_lock_held=lock_held,
        writer_epoch=writer_epoch,
        lock_error=lock_error,
        endpoint_present=ep_present,
        endpoint_valid=ep_valid,
        endpoint_detail=ep_detail,
    )


def probe_identity_and_jev(
    policy_db_path: Path,
    store_db_path: Path,
    scratch: Path,
    *,
    policy_readable: bool,
    store_readable: bool,
    errors: list[str],
    policy_conn: sqlite3.Connection | None = None,
    store_conn: sqlite3.Connection | None = None,
) -> tuple[DoctorIdentityStats, DoctorJevStats]:
    """Read identity credential coverage and passive Jev metrics with zero writes."""
    if not policy_readable or not os.path.exists(policy_db_path):
        ident = DoctorIdentityStats(error="policy store unreadable or absent")
        return ident, DoctorJevStats()

    opened_pdb: sqlite3.Connection | None = None
    try:
        db = policy_conn if policy_conn is not None else open_readonly(policy_db_path, scratch_dir=scratch)
        opened_pdb = None if policy_conn is not None else db
        active_creds = 0
        revoked_creds = 0
        active_harnesses: set[str] = set()
        if table_exists(db, "credential") and table_exists(db, "principal"):
            rows = db.execute(
                "SELECT p.harness_id, c.revoked_intent_id FROM credential c "
                "JOIN principal p ON c.principal_id = p.id"
            ).fetchall()
            for harness_id, rev in rows:
                if rev is None:
                    active_creds += 1
                    active_harnesses.add(str(harness_id))
                else:
                    revoked_creds += 1
        reg_harnesses: list[str] = []
        if table_exists(db, "harness_layer2_state"):
            sql = "SELECT DISTINCT harness_id FROM harness_layer2_state ORDER BY harness_id"
            for (hid,) in db.execute(sql).fetchall():
                reg_harnesses.append(str(hid))
        missing = tuple(sorted(h for h in reg_harnesses if h not in active_harnesses))
        ident = DoctorIdentityStats(
            active_credentials=active_creds,
            revoked_credentials=revoked_creds,
            active_harness_ids=tuple(sorted(active_harnesses)),
            registered_harness_ids=tuple(reg_harnesses),
            missing_harness_credentials=missing,
        )
    except (BrainError, sqlite3.Error, OSError) as exc:
        errors.append(f"identity stats error: {describe_exception(exc)}")
        ident = DoctorIdentityStats(error=describe_exception(exc))
    finally:
        if opened_pdb is not None:
            opened_pdb.close()

    inv_count = 0
    if store_readable and os.path.exists(store_db_path):
        opened_sdb: sqlite3.Connection | None = None
        try:
            sdb = store_conn if store_conn is not None else open_readonly(store_db_path, scratch_dir=scratch)
            opened_sdb = None if store_conn is not None else sdb
            if table_exists(sdb, "p_provider_invocations_state"):
                row = sdb.execute("SELECT COUNT(*) FROM p_provider_invocations_state").fetchone()
                inv_count = int(row[0]) if row is not None else 0
        except (BrainError, sqlite3.Error, OSError) as exc:
            errors.append(f"jev passive inspection error: {describe_exception(exc)}")
        finally:
            if opened_sdb is not None:
                opened_sdb.close()

    return ident, DoctorJevStats(key_configured=False, provider_invocations=inv_count)


def run_privacy_rescan(
    root: DataRoot,
    cas_items: list[tuple[str, Path, int]],
    limits: DoctorScanLimits,
    scanner: PrivacyScannerPort | None,
) -> PrivacyRescanSummary:
    """Bounded read-only privacy rescan across CAS blobs and ``logs/*.log`` returning rule IDs & digests only."""
    if scanner is None:
        return PrivacyRescanSummary(error="probe_unavailable: privacy scanner not wired")

    scanned_items = 0
    scanned_bytes = 0
    truncated = False
    findings: list[PrivacyScanFinding] = []

    for dig, bpath, bsize in cas_items:
        if scanned_items >= limits.max_privacy_rescan_items or (
            scanned_bytes + min(bsize, limits.max_privacy_item_bytes) > limits.max_privacy_rescan_bytes
            and scanned_items > 0
        ):
            truncated = True
            break
        try:
            with open(bpath, "rb") as fh:
                chunk = fh.read(limits.max_privacy_item_bytes)
        except OSError:
            continue
        if bsize > limits.max_privacy_item_bytes:
            truncated = True
        rules = scanner.scan_bytes(chunk)
        for rule_id in rules[:4]:
            if len(findings) < MAX_LIST_FINDINGS_PER_GROUP:
                findings.append(PrivacyScanFinding(holder_kind="cas", holder_id=dig[:19], digest=dig, rule_id=rule_id))
        scanned_items += 1
        scanned_bytes += len(chunk)

    if not truncated and os.path.lexists(root.logs_dir) and not is_link_entry(root.logs_dir):
        try:
            log_entries = sorted(os.scandir(root.logs_dir), key=lambda e: e.name)
        except OSError:
            log_entries = []
        log_files_seen = 0
        for ent in log_entries:
            lpath = Path(ent.path)
            if ent.is_symlink() or is_link_entry(lpath) or not ent.name.endswith(".log"):
                continue
            try:
                lst = ent.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat_reparse_or_link(lst) or not stat.S_ISREG(lst.st_mode):
                continue
            if log_files_seen >= limits.max_log_files or scanned_items >= limits.max_privacy_rescan_items:
                truncated = True
                break
            read_len = min(int(lst.st_size), limits.max_privacy_item_bytes, limits.max_log_bytes)
            try:
                with open(lpath, "rb") as fh:
                    chunk = fh.read(read_len)
            except OSError:
                continue
            log_dig = digest_bytes(chunk)
            if int(lst.st_size) > read_len:
                truncated = True
            rules = scanner.scan_bytes(chunk)
            for rule_id in rules[:4]:
                if len(findings) < MAX_LIST_FINDINGS_PER_GROUP:
                    findings.append(
                        PrivacyScanFinding(holder_kind="log", holder_id=ent.name, digest=log_dig, rule_id=rule_id)
                    )
            log_files_seen += 1
            scanned_items += 1
            scanned_bytes += len(chunk)

    return PrivacyRescanSummary(
        scanned_items=scanned_items,
        scanned_bytes=scanned_bytes,
        truncated=truncated,
        findings=tuple(findings),
    )


def run_capture_probe_bounded(
    data_root: Path,
    probe: CaptureDoctorProbePort | None,
    os_: OsAdapters,
    limits: DoctorScanLimits,
) -> CaptureDoctorProbeResult | None:
    """Run ``CaptureDoctorProbePort.probe_capture`` bounded strictly by ``limits.probe_timeout_s``."""
    if probe is None:
        return None
    timeout_s = max(0.001, float(limits.probe_timeout_s))
    timeout_ns = int(timeout_s * 1_000_000_000)
    box: list[CaptureDoctorProbeResult] = []
    err_box: list[Exception] = []
    done = threading.Event()

    def _run() -> None:
        try:
            box.append(probe.probe_capture(data_root))
        except (BrainError, OSError, RuntimeError, ValueError, TypeError, LookupError) as exc:
            err_box.append(exc)
        finally:
            done.set()

    start_ns = os_.monotonic.monotonic_ns()
    worker = threading.Thread(target=_run, name="superbrain-doctor-capture-probe", daemon=True)
    worker.start()
    finished = done.wait(timeout=timeout_s)
    elapsed_ns = os_.monotonic.monotonic_ns() - start_ns
    if not finished or elapsed_ns > timeout_ns:
        return CaptureDoctorProbeResult(
            available=False,
            detail=f"capture probe exceeded {limits.probe_timeout_s:.3f}s timeout",
            status="WARN",
            reason="timeout_exceeded",
            remediation="Inspect capture subsystem latency and retry diagnostics.",
            timed_out=True,
        )
    if err_box:
        return CaptureDoctorProbeResult(
            available=False,
            detail=f"capture probe error: {err_box[0]}",
            status="WARN",
            reason="probe_unavailable",
            remediation="Inspect capture adapter health.",
        )
    return box[0] if box else CaptureDoctorProbeResult(available=False, status="WARN", reason="probe_unavailable")
