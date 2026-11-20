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
from superbrain.adapters.os.daemon_config import (
    read_client_credential,
    read_daemon_config,
    read_owner_json_object,
)
from superbrain.composition._init_recovery import (
    compute_init_request_digest,
    has_existing_data_artifacts,
    prepare_init_recovery,
    recover_or_provision_tls,
    write_init_bootstrap_state,
)
from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core._kernel_approval import CLI_HARNESS_ID, ApprovalChannel, SignerEnrollment, SignerRecord
from superbrain.core._kernel_base import require_opaque_id
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import BootstrapAuthorization, DaemonConfig, parse_bearer_token
from superbrain.ports.os import OsAdapters
from superbrain.storage._policy_approvals import store_owner
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import verify_existing_data_root
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


def _preflight_base_paths(request: InitRequest, os_: OsAdapters) -> None:
    data_root, config_dir = request.data_root, request.config_dir
    if not data_root.is_absolute() or not isinstance(config_dir, Path) or not config_dir.is_absolute():
        raise _invalid()
    for target in (data_root, config_dir):
        os_.paths.reject_unsafe_path(str(target))
        os_.paths.reject_links(target)
        if os_.permissions.check_ancestors(target):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if os.path.lexists(data_root):
        if not data_root.is_dir():
            raise _invalid()
        if os_.permissions.object_problems(data_root):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if os.path.lexists(config_dir):
        if not config_dir.is_dir():
            raise _invalid()
        if os_.permissions.object_problems(config_dir):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")


def _preflight_fresh_config(config_dir: Path, os_: OsAdapters) -> None:
    existing_cfg = (config_dir / DAEMON_CONFIG_NAME, config_dir / CLI_CREDENTIAL_NAME, config_dir / TLS_DIR_NAME)
    if any(os.path.lexists(path) for path in existing_cfg):
        raise _invalid()
    tls_dir = config_dir / TLS_DIR_NAME
    if os.path.lexists(tls_dir):
        raise _invalid()


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


def _write_daemon_config_if_missing(
    daemon_config: Path,
    *,
    data_root: Path,
    store_id: str,
    cert_path: Path,
    key_path: Path,
    os_: OsAdapters,
) -> None:
    if os.path.lexists(daemon_config):
        return
    _write_owner_file(
        daemon_config,
        canonical_json(
            {
                "version": 1,
                "data_root": str(data_root),
                "expected_store_id": store_id,
                "cert_path": str(cert_path),
                "key_path": str(key_path),
            }
        ),
        os_,
    )
    os_.publisher.sync_directory(daemon_config.parent)


def _init_fresh_store(request: InitRequest, req_digest: str, os_: OsAdapters) -> InitReport:
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
        cred_id, _ = parse_bearer_token(token)
        rt.store.reconcile_policy()
        generation = rt.policy.trust_generation()
        write_init_bootstrap_state(
            rt,
            status="in_progress",
            request_digest=req_digest,
            config_dir=config_dir,
            cli_credential_id=cred_id,
        )
        cert_path, key_path = recover_or_provision_tls(
            store_id=store_id,
            owner_id=request.owner_id,
            generation=generation,
            data_root=request.data_root,
            tls_dir=tls_dir,
            os_=os_,
        )
        _write_daemon_config_if_missing(
            daemon_config,
            data_root=request.data_root,
            store_id=store_id,
            cert_path=cert_path,
            key_path=key_path,
            os_=os_,
        )
        _write_owner_file(cli_credential, f"{token}\n".encode("ascii"), os_)
        os_.publisher.sync_directory(config_dir)
        write_init_bootstrap_state(
            rt,
            status="completed",
            request_digest=req_digest,
            config_dir=config_dir,
            cli_credential_id=cred_id,
        )
    finally:
        rt.close()
    return InitReport(
        store_id=store_id, daemon_config_path=daemon_config, cli_credential_path=cli_credential, signer=signer
    )


def _recover_interrupted_init(
    request: InitRequest,
    req_digest: str,
    store_id: str,
    prev_cred_id: str,
    os_: OsAdapters,
) -> InitReport:
    config_dir = request.config_dir
    daemon_config = config_dir / DAEMON_CONFIG_NAME
    cli_credential = config_dir / CLI_CREDENTIAL_NAME
    tls_dir = config_dir / TLS_DIR_NAME
    _require_config_dir(config_dir, os_)

    admitted = admit_existing_pair(request.data_root, store_id, os_, purpose="serve")
    handlers, kinds = kernel_store_extensions()
    rt = open_runtime_under_lease(admitted, handlers=handlers, kinds=kinds)
    try:
        signers = rt.policy.active_signers()
        if len(signers) != 1 or signers[0].key_digest != request.signer.key_digest:
            raise _invalid()
        signer = signers[0]
        generation = rt.policy.trust_generation()
        cert_path, key_path = recover_or_provision_tls(
            store_id=store_id,
            owner_id=request.owner_id,
            generation=generation,
            data_root=request.data_root,
            tls_dir=tls_dir,
            os_=os_,
        )
        _write_daemon_config_if_missing(
            daemon_config,
            data_root=request.data_root,
            store_id=store_id,
            cert_path=cert_path,
            key_path=key_path,
            os_=os_,
        )
        active_cred_id = prev_cred_id
        if os.path.lexists(cli_credential):
            token = read_client_credential(cli_credential, os_)
            rt.policy.resolve_credential(token)
        else:
            snap = rt.policy.snapshot()
            if prev_cred_id in snap.credentials and not snap.credentials[prev_cred_id].revoked:
                rt.policy.record_authorized_revocation(
                    prev_cred_id,
                    BootstrapAuthorization(
                        intent_id=new_id(),
                        store_id=store_id,
                        owner_id=request.owner_id,
                        action="credential_revoke",
                        subject_id=prev_cred_id,
                        trust_generation=generation,
                        expires_at=os_.clock.now() + _BOOTSTRAP_TTL,
                        issuer_id=_BOOTSTRAP_ISSUER,
                    ),
                )
            _principal, token = rt.policy.provision_credential(
                owner_id=request.owner_id, harness_id=CLI_HARNESS_ID, machine_id=request.machine_id
            )
            active_cred_id, _ = parse_bearer_token(token)
            rt.store.reconcile_policy()
            write_init_bootstrap_state(
                rt,
                status="in_progress",
                request_digest=req_digest,
                config_dir=config_dir,
                cli_credential_id=active_cred_id,
            )
            _write_owner_file(cli_credential, f"{token}\n".encode("ascii"), os_)
            os_.publisher.sync_directory(config_dir)
        write_init_bootstrap_state(
            rt,
            status="completed",
            request_digest=req_digest,
            config_dir=config_dir,
            cli_credential_id=active_cred_id,
        )
    finally:
        rt.close()
    return InitReport(
        store_id=store_id, daemon_config_path=daemon_config, cli_credential_path=cli_credential, signer=signer
    )


def init_store(request: InitRequest, os_: OsAdapters) -> InitReport:
    """Create a new store pair and config/TLS/CLI artifacts, or durably resume an interrupted identical init."""
    if not isinstance(request, InitRequest) or not isinstance(request.data_root, Path):
        raise _invalid()
    require_opaque_id(request.owner_id, label="owner_id")
    require_opaque_id(request.machine_id, label="machine_id")
    if request.signer.owner_id != request.owner_id:
        raise _invalid()
    _preflight_base_paths(request, os_)
    req_digest = compute_init_request_digest(
        owner_id=request.owner_id,
        machine_id=request.machine_id,
        signer=request.signer,
        config_dir=request.config_dir,
    )
    if has_existing_data_artifacts(request.data_root):
        store_id, state = prepare_init_recovery(
            data_root=request.data_root,
            config_dir=request.config_dir,
            owner_id=request.owner_id,
            request_digest=req_digest,
            os_=os_,
        )
        return _recover_interrupted_init(request, req_digest, store_id, state.cli_credential_id, os_)
    _preflight_fresh_config(request.config_dir, os_)
    return _init_fresh_store(request, req_digest, os_)


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
