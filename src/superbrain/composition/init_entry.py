"""Isolated offline ``brain init`` / ``brain init --reset-signers`` entry point (spec 11.3, plan I3-1).

Both run under the writer lock with no daemon: ``init`` creates the store pair, per-store TLS, the daemon config, the
``user:cli`` credential and the trust-on-first-use signer; ``--reset-signers`` replaces every signer after a loss.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config, read_owner_json_object
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core._kernel_approval import CLI_HARNESS_ID, ApprovalChannel, SignerEnrollment, SignerRecord
from superbrain.core._kernel_base import require_opaque_id
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import BootstrapAuthorization, DaemonConfig
from superbrain.ports.os import OsAdapters
from superbrain.storage._policy_approvals import store_owner
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot, verify_existing_data_root
from superbrain.storage.runtime import (
    _preadmission_scratch,
    admit_existing_pair,
    open_runtime,
    open_runtime_under_lease,
)
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.writer import acquire_writer_unbumped

__all__ = ["InitReport", "InitRequest", "ResetReport", "init_store", "main", "reset_signers"]

ensure_maintenance_backend()

DAEMON_CONFIG_NAME = "daemon.json"
CLI_CREDENTIAL_NAME = "cli.credential"
TLS_DIR_NAME = "tls"
_BOOTSTRAP_ISSUER = "owner:local-bootstrap"
_BOOTSTRAP_TTL = timedelta(minutes=10)
_INIT_FIELDS = frozenset({"version", "data_root", "config_dir", "owner_id", "machine_id", "signer"})
_SIGNER_FIELDS = frozenset({"channel", "public_key", "credential_id"})


@dataclass(frozen=True)
class InitRequest:
    data_root: Path
    config_dir: Path
    owner_id: str
    machine_id: str
    signer: SignerEnrollment


@dataclass(frozen=True)
class InitReport:
    store_id: str
    daemon_config_path: Path
    cli_credential_path: Path
    signer: SignerRecord


@dataclass(frozen=True)
class ResetReport:
    store_id: str
    trust_generation: int
    signer: SignerRecord


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _preflight_init_paths(request: InitRequest, os_: OsAdapters) -> None:
    data_root, config_dir = request.data_root, request.config_dir
    if not data_root.is_absolute() or not isinstance(config_dir, Path) or not config_dir.is_absolute():
        raise _invalid()
    for target in (data_root, config_dir):
        os_.paths.reject_unsafe_path(str(target))
        os_.paths.reject_links(target)
        if os_.permissions.check_ancestors(target):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    root = DataRoot.at(data_root)
    existing_data = (
        root.lock_path,
        root.policy_db,
        root.store_db,
        root.policy_dir,
        root.store_dir,
        root.cas_dir,
        root.backups_dir,
    )
    if any(os.path.lexists(path) for path in existing_data):
        raise _invalid()
    if os.path.lexists(data_root):
        if not data_root.is_dir():
            raise _invalid()
        if os_.permissions.object_problems(data_root):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        if any(entry.name.startswith(("policy.", "store.")) for entry in data_root.iterdir()):
            raise _invalid()

    existing_cfg = (config_dir / DAEMON_CONFIG_NAME, config_dir / CLI_CREDENTIAL_NAME, config_dir / TLS_DIR_NAME)
    if any(os.path.lexists(path) for path in existing_cfg):
        raise _invalid()
    if os.path.lexists(config_dir):
        if not config_dir.is_dir():
            raise _invalid()
        if os_.permissions.object_problems(config_dir):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


def _require_config_dir(config_dir: Path, os_: OsAdapters) -> None:
    if not isinstance(config_dir, Path) or not config_dir.is_absolute():
        raise _invalid()
    os_.paths.reject_unsafe_path(str(config_dir))
    if os_.permissions.check_ancestors(config_dir):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if not os.path.lexists(config_dir):
        config_dir.mkdir(mode=0o700)
        os_.permissions.secure_directory(config_dir)
        os_.publisher.sync_directory(config_dir.parent)
    os_.paths.reject_links(config_dir)
    if not config_dir.is_dir():
        raise _invalid()
    if os_.permissions.object_problems(config_dir):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


def _write_owner_file(path: Path, data: bytes, os_: OsAdapters) -> None:
    try:
        os_.publisher.write_new(path, data)
    except FileExistsError as err:
        raise _invalid() from err
    os_.permissions.secure_file(path)


def init_store(request: InitRequest, os_: OsAdapters) -> InitReport:
    """Create a brand-new store pair and everything a daemon and the CLI need; an existing store is ``INVALID_INPUT``.

    Nothing is written when the target already holds a store, a daemon config, a CLI credential or TLS material.
    """
    if not isinstance(request, InitRequest) or not isinstance(request.data_root, Path):
        raise _invalid()
    require_opaque_id(request.owner_id, label="owner_id")
    require_opaque_id(request.machine_id, label="machine_id")
    if request.signer.owner_id != request.owner_id:
        raise _invalid()
    _preflight_init_paths(request, os_)

    config_dir = request.config_dir
    daemon_config = config_dir / DAEMON_CONFIG_NAME
    cli_credential = config_dir / CLI_CREDENTIAL_NAME
    tls_dir = config_dir / TLS_DIR_NAME
    _require_config_dir(config_dir, os_)

    handlers, kinds = kernel_store_extensions()
    rt = open_runtime(
        request.data_root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        store_id = rt.store.store_id
        signer = rt.policy.enroll_first_signer(request.signer)
        _principal, token = rt.policy.provision_credential(
            owner_id=request.owner_id, harness_id=CLI_HARNESS_ID, machine_id=request.machine_id
        )
        rt.store.reconcile_policy()
        generation = rt.policy.trust_generation()
    finally:
        rt.close()

    authorization = BootstrapAuthorization(
        intent_id=new_id(),
        store_id=store_id,
        owner_id=request.owner_id,
        action="provision_tls",
        subject_id=store_id,
        trust_generation=generation,
        expires_at=os_.clock.now() + _BOOTSTRAP_TTL,
        issuer_id=_BOOTSTRAP_ISSUER,
        destination=tls_dir,
    )
    tls = create_store_tls(store_id, tls_dir, authorization, os_.clock, os_)
    _write_owner_file(
        daemon_config,
        canonical_json(
            {
                "version": 1,
                "data_root": str(request.data_root),
                "expected_store_id": store_id,
                "cert_path": str(tls.cert_path),
                "key_path": str(tls.key_path),
            }
        ),
        os_,
    )
    _write_owner_file(cli_credential, f"{token}\n".encode("ascii"), os_)
    return InitReport(
        store_id=store_id, daemon_config_path=daemon_config, cli_credential_path=cli_credential, signer=signer
    )


def _preflight_reset_owner(config: DaemonConfig, enrollment: SignerEnrollment, os_: OsAdapters) -> None:
    verified_root = verify_existing_data_root(config.data_root, os_)
    with acquire_writer_unbumped(verified_root, os_):
        if not os.path.lexists(verified_root.policy_db):
            return
        with _preadmission_scratch(verified_root.root, os_, None) as scratch_dir:
            ro_db = open_readonly(verified_root.policy_db, scratch_dir=scratch_dir)
            try:
                try:
                    existing_owner = store_owner(ro_db)
                except sqlite3.Error:
                    return
            finally:
                ro_db.close()
        if existing_owner is not None and existing_owner != enrollment.owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")


def reset_signers(daemon_config_path: Path, enrollment: SignerEnrollment, os_: OsAdapters) -> ResetReport:
    """Offline ``--reset-signers``: under the writer lock, replace every signer by ``enrollment`` (TOFU again).

    A held writer lock is ``WRITER_HELD`` before any byte changes; an owner mismatch is ``IDENTITY_MISMATCH`` before
    any write; see ``PolicyStore.reset_signers_offline``.
    """
    if not isinstance(enrollment, SignerEnrollment):
        raise _invalid()
    config = read_daemon_config(daemon_config_path, os_)
    _preflight_reset_owner(config, enrollment, os_)
    admitted = admit_existing_pair(config.data_root, config.expected_store_id, os_, purpose="serve")
    handlers, kinds = kernel_store_extensions()
    rt = open_runtime_under_lease(admitted, handlers=handlers, kinds=kinds)
    try:
        existing_owner = rt.policy.store_owner()
        if existing_owner is not None and existing_owner != enrollment.owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        generation = rt.policy.reset_signers_offline()
        signer = rt.policy.enroll_first_signer(enrollment)
        rt.store.reconcile_policy()
        store_id = rt.store.store_id
    finally:
        rt.close()
    return ResetReport(store_id=store_id, trust_generation=generation, signer=signer)


def _write_stderr(code: str) -> None:
    try:
        sys.stderr.write(f"{code}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _parse_args(args: list[str]) -> tuple[bool, Path] | None:
    if len(args) == 3 and args[0] == "init" and args[1] == "--config":
        reset, raw = False, args[2]
    elif len(args) == 4 and args[0] == "init" and args[1] == "--reset-signers" and args[2] == "--config":
        reset, raw = True, args[3]
    elif len(args) == 4 and args[0] == "init" and args[1] == "--config" and args[3] == "--reset-signers":
        reset, raw = True, args[2]
    else:
        return None
    if not raw or "\x00" in raw or not Path(raw).is_absolute():
        return None
    return reset, Path(raw)


def _enrollment(raw: object, owner_id: str) -> SignerEnrollment:
    if not isinstance(raw, dict) or not set(raw) <= _SIGNER_FIELDS or not {"channel", "public_key"} <= set(raw):
        raise _invalid()
    channel, public_key, credential_id = raw["channel"], raw["public_key"], raw.get("credential_id")
    if not isinstance(channel, str) or not isinstance(public_key, str):
        raise _invalid()
    if credential_id is not None and not isinstance(credential_id, str):
        raise _invalid()
    try:
        parsed_channel = ApprovalChannel(channel)
    except ValueError as err:
        raise _invalid() from err
    return SignerEnrollment(
        owner_id=owner_id, channel=parsed_channel, public_key=public_key, credential_id=credential_id
    )


def _read_request(path: Path, os_: OsAdapters) -> InitRequest:
    raw: dict[str, Any] = read_owner_json_object(path, os_)
    if set(raw) != _INIT_FIELDS or raw["version"] != 1 or type(raw["version"]) is not int:
        raise _invalid()
    texts = [raw[name] for name in ("data_root", "config_dir", "owner_id", "machine_id")]
    if not all(isinstance(text, str) and text for text in texts):
        raise _invalid()
    data_root, config_dir, owner_id, machine_id = texts
    return InitRequest(
        data_root=Path(data_root),
        config_dir=Path(config_dir),
        owner_id=require_opaque_id(owner_id, label="owner_id"),
        machine_id=require_opaque_id(machine_id, label="machine_id"),
        signer=_enrollment(raw["signer"], owner_id),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """``init --config <abs>`` or ``init --reset-signers --config <abs>`` (the config is the owner-only init JSON)."""
    parsed = _parse_args(list(sys.argv[1:] if argv is None else argv))
    if parsed is None:
        _write_stderr(ErrorCode.INVALID_INPUT.value)
        return 2
    reset, config_path = parsed
    try:
        os_ = os_adapters()
        request = _read_request(config_path, os_)
        if reset:
            result = reset_signers(request.config_dir / DAEMON_CONFIG_NAME, request.signer, os_)
            data: dict[str, Any] = {"store_id": result.store_id, "trust_generation": result.trust_generation}
        else:
            report = init_store(request, os_)
            data = {"store_id": report.store_id, "daemon_config": str(report.daemon_config_path)}
        sys.stdout.buffer.write(canonical_json({"ok": True, "data": data}) + b"\n")
        sys.stdout.buffer.flush()
    except BrainError as err:
        _write_stderr(err.code.value)
        return 1
    except OSError:
        _write_stderr(ErrorCode.IO_ERROR.value)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
