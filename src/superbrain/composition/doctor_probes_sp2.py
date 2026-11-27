"""Strictly read-only SP2 diagnostic probes (outbox, gaps, sessions, Layer-2) & policy reconciliation (SP2-5)."""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from superbrain.adapters.harness.host_version import probe_installed_host_version
from superbrain.adapters.harness.layer2_probe import (
    NativeHostReceipt,
    compute_harness_config_digest,
    verify_native_host_receipt,
)
from superbrain.core._kernel_approval import CLI_HARNESS_ID, Layer2State
from superbrain.core._kernel_base import OPAQUE_ID_RE
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import OUTBOX_RECORD_EVENT, OUTBOX_RECORD_GAP
from superbrain.ports.continuity import SessionState, decide_session_liveness
from superbrain.ports.os import OsAdapters
from superbrain.storage import _policy_layer2 as policy_layer2
from superbrain.storage._outbox_io import (
    _PART_SUFFIX,
    _REPARSE_POINT,
    _STREAMS_DIR,
    entry_is_link,
    is_link_path,
    parse_frame_filename_identity,
    reject_links_upward,
)
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.sqlite import open_readonly


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
    return row is not None


@dataclass(frozen=True)
class Sp2OutboxStatus:
    present: bool
    pending_event_count: int
    pending_gap_count: int
    incomplete_part_count: int
    total_bytes: int
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "present": self.present,
            "pending_event_count": self.pending_event_count,
            "pending_gap_count": self.pending_gap_count,
            "incomplete_part_count": self.incomplete_part_count,
            "total_bytes": self.total_bytes,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class Sp2GapStatus:
    open_daemon_gaps: int
    closed_daemon_gaps: int
    producer_gaps: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "open_daemon_gaps": self.open_daemon_gaps,
            "closed_daemon_gaps": self.closed_daemon_gaps,
            "producer_gaps": self.producer_gaps,
        }


@dataclass(frozen=True)
class Sp2SessionStatus:
    total_sessions: int
    active_sessions: int
    in_progress_unknown_sessions: int
    ended_sessions: int
    pending_refresh_events: int
    dirty_tasks: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "total_sessions": self.total_sessions,
            "active_sessions": self.active_sessions,
            "in_progress_unknown_sessions": self.in_progress_unknown_sessions,
            "ended_sessions": self.ended_sessions,
            "pending_refresh_events": self.pending_refresh_events,
            "dirty_tasks": self.dirty_tasks,
        }


@dataclass(frozen=True)
class Sp2Layer2HarnessProbe:
    harness_id: str
    recorded_state: Layer2State
    effective_state: Layer2State
    recorded_host_version: str | None
    recorded_config_digest: str | None
    observed_host_version: str | None
    observed_config_digest: str | None
    invalidated_reason: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "harness_id": self.harness_id,
            "recorded_state": self.recorded_state.value,
            "effective_state": self.effective_state.value,
            "recorded_host_version": self.recorded_host_version,
            "recorded_config_digest": self.recorded_config_digest,
            "observed_host_version": self.observed_host_version,
            "observed_config_digest": self.observed_config_digest,
            "invalidated_reason": self.invalidated_reason,
        }


@dataclass(frozen=True)
class Sp2DoctorReport:
    outbox: Sp2OutboxStatus
    gaps: Sp2GapStatus
    sessions: Sp2SessionStatus
    layer2_harnesses: tuple[Sp2Layer2HarnessProbe, ...]
    terminal_channel_eligible_effective: bool
    integrity_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "outbox": self.outbox.to_dict(),
            "gaps": self.gaps.to_dict(),
            "sessions": self.sessions.to_dict(),
            "layer2_harnesses": [h.to_dict() for h in self.layer2_harnesses],
            "terminal_channel_eligible_effective": self.terminal_channel_eligible_effective,
            "integrity_errors": list(self.integrity_errors),
        }


def probe_outbox_readonly(outbox_dir: Path) -> Sp2OutboxStatus:
    """Inspect ``outbox_dir`` via ``scandir`` with zero file creation, locking, or ``.part`` sweeping."""
    if not os.path.lexists(outbox_dir):
        return Sp2OutboxStatus(False, 0, 0, 0, 0)
    errors: list[str] = []
    try:
        reject_links_upward(outbox_dir)
        st_root = os.lstat(outbox_dir)
        if not stat.S_ISDIR(st_root.st_mode) or (getattr(st_root, "st_file_attributes", 0) & _REPARSE_POINT) != 0:
            return Sp2OutboxStatus(True, 0, 0, 0, 0, errors=("outbox root is not a regular directory",))
    except (BrainError, OSError) as exc:
        return Sp2OutboxStatus(True, 0, 0, 0, 0, errors=(f"outbox path error: {exc}",))

    ev_cnt = 0
    gap_cnt = 0
    part_cnt = 0
    total_bytes = 0
    streams_dir: Path | None = None
    try:
        with os.scandir(outbox_dir) as root_it:
            for entry in root_it:
                if entry_is_link(entry):
                    errors.append(f"unsafe link in outbox: {entry.name}")
                    continue
                if entry.name.endswith(_PART_SUFFIX):
                    part_cnt += 1
                    total_bytes += entry.stat(follow_symlinks=False).st_size
                elif entry.name == _STREAMS_DIR:
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        streams_dir = Path(entry.path)
        if streams_dir is not None:
            with os.scandir(streams_dir) as s_it:
                for sd in s_it:
                    if entry_is_link(sd):
                        errors.append(f"unsafe link in streams: {sd.name}")
                        continue
                    if not stat.S_ISDIR(sd.stat(follow_symlinks=False).st_mode):
                        continue
                    with os.scandir(sd.path) as f_it:
                        for fe in f_it:
                            if entry_is_link(fe):
                                errors.append(f"unsafe link frame: {fe.name}")
                                continue
                            if fe.name.endswith(_PART_SUFFIX):
                                part_cnt += 1
                                total_bytes += fe.stat(follow_symlinks=False).st_size
                                continue
                            ident = parse_frame_filename_identity(fe.name)
                            if ident is None:
                                continue
                            st_f = fe.stat(follow_symlinks=False)
                            if not stat.S_ISREG(st_f.st_mode):
                                continue
                            total_bytes += st_f.st_size
                            if ident[0] == OUTBOX_RECORD_EVENT:
                                ev_cnt += 1
                            elif ident[0] == OUTBOX_RECORD_GAP:
                                gap_cnt += 1
    except (BrainError, OSError) as exc:
        errors.append(f"outbox scan error: {exc}")
    return Sp2OutboxStatus(True, ev_cnt, gap_cnt, part_cnt, total_bytes, errors=tuple(errors))


def probe_sp2_store_readonly(
    store_db: Path,
    scratch: Path,
    *,
    now: datetime,
    errors: list[str],
) -> tuple[Sp2GapStatus, Sp2SessionStatus]:
    """Read gap, session liveness, and continuity worker counts from ``brain.db`` read-only."""
    if not os.path.exists(store_db):
        return Sp2GapStatus(0, 0, 0), Sp2SessionStatus(0, 0, 0, 0, 0, 0)
    db: sqlite3.Connection | None = None
    open_g = closed_g = prod_g = 0
    total_s = active_s = unk_s = ended_s = 0
    pending_ev = dirty_tasks = 0
    try:
        db = open_readonly(store_db, scratch_dir=scratch)
        if _table_exists(db, "capture_gaps"):
            for status, cnt in db.execute(
                "SELECT status, COUNT(*) FROM capture_gaps GROUP BY status"
            ).fetchall():
                st_str = str(status)
                if st_str == "open":
                    open_g += int(cnt)
                elif st_str == "closed":
                    closed_g += int(cnt)
                elif st_str == "producer":
                    prod_g += int(cnt)
        if _table_exists(db, "sessions"):
            for rec_state, last_at in db.execute("SELECT state, last_event_at FROM sessions").fetchall():
                total_s += 1
                dec = decide_session_liveness(
                    recorded_state=SessionState(str(rec_state)),
                    last_event_at=parse_iso_utc(str(last_at)),
                    now=now,
                )
                if dec.state is SessionState.ACTIVE:
                    active_s += 1
                elif dec.state is SessionState.IN_PROGRESS_UNKNOWN:
                    unk_s += 1
                elif dec.state is SessionState.ENDED:
                    ended_s += 1
        if _table_exists(db, "continuity_refresh_state"):
            row = db.execute(
                "SELECT COALESCE(SUM(pending_event_count), 0), COALESCE(SUM(dirty_flag), 0) "
                "FROM continuity_refresh_state"
            ).fetchone()
            if row is not None:
                pending_ev = int(row[0])
                dirty_tasks = int(row[1])
    except (BrainError, sqlite3.Error, ValueError) as exc:
        errors.append(f"store sp2 read error: {exc}")
    finally:
        if db is not None:
            db.close()
    return (
        Sp2GapStatus(open_g, closed_g, prod_g),
        Sp2SessionStatus(total_s, active_s, unk_s, ended_s, pending_ev, dirty_tasks),
    )


def _candidate_checkouts(db: sqlite3.Connection, checkout_root: Path | None) -> tuple[Path, ...]:
    seen: dict[str, Path] = {}
    if _table_exists(db, "workspace_checkout"):
        rows = db.execute("SELECT checkout_path FROM workspace_checkout ORDER BY created_at ASC").fetchall()
        for (raw_path,) in rows:
            if isinstance(raw_path, str) and raw_path:
                norm = os.path.normcase(os.path.abspath(raw_path))
                seen.setdefault(norm, Path(raw_path))
    if checkout_root is not None:
        norm = os.path.normcase(os.path.abspath(str(checkout_root)))
        seen.setdefault(norm, checkout_root)
    return tuple(seen.values())


def _probe_has_presence(chk_path: Path, harness_id: str) -> bool:
    if harness_id == "claude-code":
        return os.path.lexists(chk_path / ".claude") or os.path.lexists(chk_path / "CLAUDE.md")
    if harness_id == "codex":
        return os.path.lexists(chk_path / ".codex") or os.path.lexists(chk_path / "AGENTS.md")
    return False


def probe_sp2_layer2_readonly(
    policy_db: Path,
    scratch: Path,
    *,
    checkout_root: Path | None,
    observed_host_versions: Mapping[str, str] | None,
    host_version_resolver: Callable[[str], str | None] | None = None,
    os_: OsAdapters,
    errors: list[str],
) -> tuple[tuple[Sp2Layer2HarnessProbe, ...], bool]:
    """Read Layer-2 bindings read-only and detect effective version/config drift without mutating."""
    if not os.path.exists(policy_db):
        return (), False
    db: sqlite3.Connection | None = None
    probes: list[Sp2Layer2HarnessProbe] = []
    active_non_cli: set[str] = set()
    seen: set[str] = set()
    try:
        db = open_readonly(policy_db, scratch_dir=scratch)
        if _table_exists(db, "principal") and _table_exists(db, "credential"):
            for (hid,) in db.execute(
                "SELECT DISTINCT p.harness_id FROM principal AS p "
                "WHERE p.harness_id != ? AND EXISTS ("
                "SELECT 1 FROM credential AS c WHERE c.principal_id = p.id AND c.revoked_intent_id IS NULL)",
                (CLI_HARNESS_ID,),
            ).fetchall():
                active_non_cli.add(str(hid))
                seen.add(str(hid))
        candidate_checkouts = _candidate_checkouts(db, checkout_root)
        configured_map = policy_layer2.configured_layer2_checkouts(db)
        if _table_exists(db, "harness_layer2_state"):
            stale_seq = policy_layer2.layer2_stale_through_seq(db)
            for (hid,) in db.execute("SELECT DISTINCT harness_id FROM harness_layer2_state").fetchall():
                seen.add(str(hid))
            for hid in sorted(seen):
                row = db.execute(
                    "SELECT seq, host_version, config_digest, state FROM harness_layer2_state "
                    "WHERE harness_id = ? ORDER BY seq DESC LIMIT 1",
                    (hid,),
                ).fetchone()
                row_seq = 0 if row is None else int(row[0])
                rec_ver = None if row is None else str(row[1])
                rec_dig = None if row is None else str(row[2])
                rec_state = Layer2State.UNKNOWN if row is None else Layer2State(str(row[3]))
                eff_resolver = (
                    host_version_resolver if host_version_resolver is not None else probe_installed_host_version
                )
                if observed_host_versions is not None:
                    raw_obs_ver: object = observed_host_versions.get(hid)
                else:
                    try:
                        raw_obs_ver = eff_resolver(hid)
                    except Exception:  # noqa: BLE001
                        raw_obs_ver = None
                obs_ver = (
                    raw_obs_ver
                    if isinstance(raw_obs_ver, str) and OPAQUE_ID_RE.fullmatch(raw_obs_ver)
                    else None
                )
                configured_paths = set(configured_map.get(hid, ()))

                obs_dig: str | None = None
                drifted_chk_dig: str | None = None
                cfg_changed = False
                for chk_p in candidate_checkouts:
                    norm_chk = os.path.normcase(os.path.abspath(str(chk_p)))
                    d = compute_harness_config_digest(hid, chk_p, os_)
                    applies = (
                        d is not None
                        or _probe_has_presence(chk_p, hid)
                        or norm_chk in configured_paths
                    )
                    if d is not None and obs_dig is None:
                        obs_dig = d
                    if applies and d != rec_dig:
                        cfg_changed = True
                        drifted_chk_dig = d
                        break

                if cfg_changed and drifted_chk_dig is not None:
                    obs_dig = drifted_chk_dig
                elif cfg_changed:
                    obs_dig = None

                eff_state = rec_state
                inv_reason: str | None = None
                if rec_state is Layer2State.VERIFIED:
                    if obs_ver is None:
                        eff_state = Layer2State.UNKNOWN
                        inv_reason = (
                            "host_version_unverified" if raw_obs_ver is None else "host_version_changed"
                        )
                    elif obs_ver != rec_ver:
                        eff_state = Layer2State.UNKNOWN
                        inv_reason = "host_version_changed"
                    elif cfg_changed:
                        eff_state = Layer2State.UNKNOWN
                        inv_reason = "config_digest_changed"
                    elif row_seq <= stale_seq:
                        eff_state = Layer2State.UNKNOWN
                        inv_reason = "policy_restored"
                probes.append(
                    Sp2Layer2HarnessProbe(
                        harness_id=hid,
                        recorded_state=rec_state,
                        effective_state=eff_state,
                        recorded_host_version=rec_ver,
                        recorded_config_digest=rec_dig,
                        observed_host_version=obs_ver,
                        observed_config_digest=obs_dig,
                        invalidated_reason=inv_reason,
                    )
                )
    except (BrainError, sqlite3.Error, ValueError) as exc:
        errors.append(f"policy layer2 read error: {exc}")
        return (), False
    finally:
        if db is not None:
            db.close()

    by_id = {p.harness_id: p for p in probes}
    eligible = bool(active_non_cli) and all(
        hid in by_id and by_id[hid].effective_state is Layer2State.VERIFIED for hid in active_non_cli
    )
    return tuple(probes), eligible


def run_sp2_doctor_probes(
    data_root: Path,
    *,
    outbox_dir: Path | None = None,
    checkout_root: Path | None = None,
    observed_host_versions: Mapping[str, str] | None = None,
    host_version_resolver: Callable[[str], str | None] | None = None,
    os_: OsAdapters,
    now: datetime | None = None,
) -> Sp2DoctorReport:
    """Run all SP2 read-only diagnostic probes across outbox, ``brain.db``, ``policy.db`` & checkout."""
    root = DataRoot.at(data_root)
    eff_now = now if now is not None else os_.clock.now()
    errors: list[str] = []
    outbox = (
        probe_outbox_readonly(outbox_dir)
        if outbox_dir is not None
        else Sp2OutboxStatus(False, 0, 0, 0, 0)
    )
    raw_tmp = os_.traits.resolved_temp_dir()
    temp_base = str(raw_tmp) if raw_tmp is not None else None
    scratch = Path(tempfile.mkdtemp(prefix="sb-sp2doc-", dir=temp_base))
    try:
        try:
            os_.paths.reject_links(data_root)
            if is_link_path(data_root):
                errors.append("data_root is an unsafe link")
                return Sp2DoctorReport(
                    outbox, Sp2GapStatus(0, 0, 0), Sp2SessionStatus(0, 0, 0, 0, 0, 0), (), False, tuple(errors)
                )
        except BrainError as exc:
            errors.append(f"data_root unsafe: {exc}")
            return Sp2DoctorReport(
                outbox, Sp2GapStatus(0, 0, 0), Sp2SessionStatus(0, 0, 0, 0, 0, 0), (), False, tuple(errors)
            )
        gaps, sessions = probe_sp2_store_readonly(root.store_db, scratch, now=eff_now, errors=errors)
        l2_probes, term_eff = probe_sp2_layer2_readonly(
            root.policy_db,
            scratch,
            checkout_root=checkout_root,
            observed_host_versions=observed_host_versions,
            host_version_resolver=host_version_resolver,
            os_=os_,
            errors=errors,
        )
        return Sp2DoctorReport(
            outbox=outbox,
            gaps=gaps,
            sessions=sessions,
            layer2_harnesses=l2_probes,
            terminal_channel_eligible_effective=term_eff,
            integrity_errors=tuple(errors),
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def reconcile_harness_layer2_in_policy(
    policy: PolicyStore,
    *,
    harness_id: str,
    checkout_root: Path,
    observed_host_version: str | None,
    os_: OsAdapters,
    receipt: NativeHostReceipt | None = None,
) -> tuple[Layer2State, str]:
    """Record a verified ``NativeHostReceipt`` or automatically downgrade drifted Layer-2 state in ``policy.db``."""
    cfg_dig = compute_harness_config_digest(harness_id, checkout_root, os_)
    if receipt is not None:
        verdict = verify_native_host_receipt(
            receipt,
            current_host_version=observed_host_version,
            current_config_digest=cfg_dig,
            expected_harness_id=harness_id,
        )
        eff_ver = (
            observed_host_version
            if isinstance(observed_host_version, str) and OPAQUE_ID_RE.fullmatch(observed_host_version)
            else receipt.host_version
        )
        eff_dig = cfg_dig if cfg_dig is not None else receipt.config_digest
        policy.set_layer2_state(
            harness_id=harness_id,
            host_version=eff_ver,
            config_digest=eff_dig,
            state=verdict.state,
        )
        if verdict.state is Layer2State.VERIFIED and cfg_dig is not None:
            policy.record_configured_layer2_checkout(
                harness_id=harness_id,
                checkout_path=str(checkout_root),
            )
        return verdict.state, verdict.reason

    latest = policy.layer2_state(harness_id)
    if latest is None:
        return Layer2State.UNKNOWN, "receipt_missing"
    _, rec_ver, rec_dig, rec_state = latest
    reason = rec_state.value
    if rec_state is Layer2State.VERIFIED:
        if rec_ver != observed_host_version:
            reason = "host_version_changed"
        elif rec_dig != cfg_dig:
            reason = "config_digest_changed"
        else:
            reason = "verified"
    next_state, _ = policy.reconcile_layer2_binding(
        harness_id=harness_id,
        current_host_version=observed_host_version,
        current_config_digest=cfg_dig,
    )
    return next_state, reason


__all__ = [
    "Sp2DoctorReport",
    "Sp2GapStatus",
    "Sp2Layer2HarnessProbe",
    "Sp2OutboxStatus",
    "Sp2SessionStatus",
    "probe_outbox_readonly",
    "probe_sp2_layer2_readonly",
    "probe_sp2_store_readonly",
    "reconcile_harness_layer2_in_policy",
    "run_sp2_doctor_probes",
]
