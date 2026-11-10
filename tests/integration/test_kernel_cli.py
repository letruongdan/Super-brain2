"""Integration tests for the installed ``brain`` owner CLI (`T7b.2`).

Verifies that ``brain`` and ``brain-mcp`` installed into a clean wheel virtual environment:
- Load ``superbrain`` and packaged schema strictly from the installed wheel with ``PYTHONPATH``
  stripped and ``cwd`` outside the repository checkout.
- Enforce explicit ``--config <abs>`` / ``--profile <abs>`` arguments, ignoring environment
  home variables (``SUPERBRAIN_HOME``, ``LOCALAPPDATA``) and refusing missing/mismatched roots
  without creating missing directories.
- Run foreground ``brain serve`` via an isolated ``-I`` child interpreter, respond to ``brain status``,
  block ``brain migrate --offline`` with ``writer_held``, and cleanly drain/remove ``endpoint.json``
  and release ``writer.lock`` on foreground termination signal.
- Upgrade legacy ``(store=2, policy=2)`` roots to ``(store=4, policy=3)`` under one lease via
  ``brain migrate --offline --config <abs>``, preserving ``store_id`` and reporting a no-op on repeat.
"""

from __future__ import annotations

import datetime as dt
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition.client_entry import (
    build_tool_caller,
    read_status,
)
from superbrain.composition.client_entry import (
    main as client_main,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.ids import new_id
from superbrain.core.wire import parse_json
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kernel_schema import (
    KERNEL_POLICY_MIGRATIONS,
    KERNEL_STORE_MIGRATIONS,
)
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import read_schema_info
from tests.support.clock import FakeClock
from tests.support.inc2_cli import (
    installed_script_path,
    is_writer_lock_held,
    run_installed_command,
    spawn_installed_brain_serve,
    verify_installed_wheel_isolation,
    write_client_profile_file,
    write_credential_file,
    write_daemon_config_file,
)
from tests.support.inc2_fixture import InstalledEnv, open_kernel_job_runtime
from tests.support.inc2_transport import (
    TransportTemplate,
    clone_owner_only_tree,
    create_transport_template,
    make_trusted_test_dir,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential


@pytest.fixture(scope="module")
def cli_scratch_root() -> Iterator[Path]:
    """Module-scoped trusted test root cleaned up on teardown."""
    root = make_trusted_test_dir("inc2-t7-cli")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="module")
def cli_transport_template() -> Iterator[TransportTemplate]:
    """Module-scoped admitted (store=4, policy=3) template root."""
    template = create_transport_template("inc2-t7-cli-tpl")
    try:
        yield template
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


def _assert_static_stderr_line(stderr_bytes: bytes, *, forbidden_substrings: tuple[str, ...] = ()) -> str:
    text = stderr_bytes.decode("utf-8", errors="replace").strip()
    assert text, "Expected non-empty static error message on stderr"
    assert "\n" not in text, f"Expected single-line static stderr, got: {text!r}"
    for forbidden in forbidden_substrings:
        if forbidden:
            assert forbidden not in text, f"Stderr leaked untrusted substring {forbidden!r}: {text!r}"
    return text


def test_installed_cli_uses_only_explicit_config_and_releases_lease(
    inc2_installed_env: InstalledEnv,
    cli_transport_template: TransportTemplate,
    cli_scratch_root: Path,
) -> None:
    """Installed ``brain`` CLI uses only explicit config/profile, ignores env poisoning, and releases lease."""
    from superbrain.cli.main import main as cli_main
    from superbrain.composition.owner_entry import main as owner_main
    from superbrain.composition.shim_entry import main as shim_main

    assert callable(build_tool_caller)
    assert callable(read_status)
    assert callable(client_main)
    assert callable(cli_main)
    assert callable(owner_main)
    assert callable(shim_main)

    case_dir = cli_scratch_root / "explicit-cli"
    outside_cwd = case_dir / "outside-cwd"
    poison_home = case_dir / "poison-superbrain-home"
    poison_local = case_dir / "poison-localappdata"
    outside_cwd.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(outside_cwd)

    # 1. Verify wheel console scripts exist and load strictly from the wheel venv's site-packages.
    brain_bin = installed_script_path(inc2_installed_env, "brain")
    brain_mcp_bin = installed_script_path(inc2_installed_env, "brain-mcp")
    assert brain_bin.is_file(), f"Missing installed brain script: {brain_bin}"
    assert brain_mcp_bin.is_file(), f"Missing installed brain-mcp script: {brain_mcp_bin}"

    wheel_info = verify_installed_wheel_isolation(inc2_installed_env, cwd=outside_cwd)
    venv_resolved = str(inc2_installed_env.venv_dir.resolve()).lower()
    assert str(wheel_info["module_file"]).lower().startswith(venv_resolved)
    assert str(wheel_info["schema_file"]).lower().startswith(venv_resolved)
    assert wheel_info["schema_sha256"] == inc2_installed_env.source_schema_sha256

    # 2. Clone admitted current-schema root (store=4, policy=3) from template.
    data_root = case_dir / "live-data"
    clone_owner_only_tree(cli_transport_template.root, data_root)
    os_adapters().permissions.secure_directory(data_root)
    config_path = write_daemon_config_file(
        case_dir / "daemon-config.json",
        data_root=data_root,
        expected_store_id=cli_transport_template.store_id,
        cert_path=cli_transport_template.tls.cert_path,
        key_path=cli_transport_template.tls.key_path,
    )
    endpoint_path = data_root / "endpoint.json"
    ca_file = cli_transport_template.tls.ca_cert_path
    cred_file = write_credential_file(case_dir / "client" / "credential.txt", cli_transport_template.cred.token)
    profile_path, _ = write_client_profile_file(
        case_dir / "client" / "profile.json",
        endpoint_path=endpoint_path,
        expected_store_id=cli_transport_template.store_id,
        ca_file=ca_file,
        leaf_cert_sha256=cli_transport_template.tls.leaf_cert_sha256,
        credential_file=cred_file,
    )

    # 3. Verify CLI syntax errors exit with code 2, empty stdout, and static stderr without leaking paths/args.
    canary = "relative-canary-secret-path.json"
    invalid_brain_argvs: tuple[tuple[str, ...], ...] = (
        (),
        ("unknown-cmd",),
        ("serve",),
        ("serve", "--config"),
        ("serve", "--config", canary),
        ("serve", "--config", str(config_path), "--extra"),
        ("migrate", "--config", str(config_path)),
        ("migrate", "--offline"),
        ("migrate", "--offline", "--config", canary),
        ("status",),
        ("status", "--profile"),
        ("status", "--profile", canary),
        ("status", "--profile", str(profile_path), "--extra"),
        ("mcp",),
        ("mcp", "--profile", canary),
    )
    for bad_args in invalid_brain_argvs:
        res_bad = run_installed_command(inc2_installed_env, "brain", bad_args, cwd=outside_cwd)
        assert res_bad.returncode == 2, f"Expected exit 2 for brain {bad_args}, got {res_bad.returncode}"
        assert res_bad.stdout == b""
        _assert_static_stderr_line(res_bad.stderr, forbidden_substrings=(canary, str(config_path), str(profile_path)))

    for bad_mcp_args in (
        (),
        ("--unknown",),
        ("--profile",),
        ("--profile", canary),
        ("--profile", str(profile_path), "x"),
    ):
        res_bad_mcp = run_installed_command(inc2_installed_env, "brain-mcp", bad_mcp_args, cwd=outside_cwd)
        assert res_bad_mcp.returncode == 2, (
            f"Expected exit 2 for brain-mcp {bad_mcp_args}, got {res_bad_mcp.returncode}"
        )
        assert res_bad_mcp.stdout == b""
        _assert_static_stderr_line(res_bad_mcp.stderr, forbidden_substrings=(canary, str(profile_path)))

    # 4. Verify config pointing to missing root or wrong expected_store_id is refused and missing root stays absent.
    missing_root = case_dir / "absent-data-root"
    missing_cfg = write_daemon_config_file(
        case_dir / "missing-root-config.json",
        data_root=missing_root,
        expected_store_id=cli_transport_template.store_id,
        cert_path=cli_transport_template.tls.cert_path,
        key_path=cli_transport_template.tls.key_path,
    )
    wrong_store_cfg = write_daemon_config_file(
        case_dir / "wrong-store-config.json",
        data_root=data_root,
        expected_store_id="store-wrong-id",
        cert_path=cli_transport_template.tls.cert_path,
        key_path=cli_transport_template.tls.key_path,
    )
    for bad_cfg in (missing_cfg, wrong_store_cfg):
        res_serve_bad = run_installed_command(
            inc2_installed_env,
            "brain",
            ("serve", "--config", str(bad_cfg)),
            cwd=outside_cwd,
        )
        assert res_serve_bad.returncode == 1
        assert res_serve_bad.stdout == b""
        _assert_static_stderr_line(
            res_serve_bad.stderr,
            forbidden_substrings=(str(missing_root), str(data_root), "store-wrong-id"),
        )
    assert not missing_root.exists(), "Failed serve must never create a missing data_root"

    # 5. Environment poisoning variables (SUPERBRAIN_HOME, LOCALAPPDATA) are ignored when explicit paths are given.
    poison_env: dict[str, str] = {
        "SUPERBRAIN_HOME": str(poison_home),
        "LOCALAPPDATA": str(poison_local),
    }

    # 6. Before serve: `brain status --profile <abs>` returns exit 1 and canonical daemon_unavailable JSON on stdout.
    res_offline = run_installed_command(
        inc2_installed_env,
        "brain",
        ("status", "--profile", str(profile_path)),
        cwd=outside_cwd,
        extra_env=poison_env,
    )
    assert res_offline.returncode == 1
    assert res_offline.stderr == b""
    offline_env = parse_json(res_offline.stdout.strip())
    assert offline_env == {
        "ok": False,
        "error": {
            "code": "daemon_unavailable",
            "message": "daemon unavailable",
        },
    }
    assert res_offline.stdout == canonical_json(offline_env) + b"\n"
    assert not poison_home.exists()
    assert not poison_local.exists()

    # 7. Start foreground `brain serve --config <abs>` and verify ready status, held lease, and migrate refusal.
    with spawn_installed_brain_serve(
        inc2_installed_env,
        config_path,
        data_root=data_root,
        cwd=outside_cwd,
        extra_env=poison_env,
    ) as serve_proc:
        ep = serve_proc.wait_ready()
        assert ep.store_id == cli_transport_template.store_id
        assert serve_proc.poll() is None, "Foreground `brain serve` wrapper must wait for worker process"
        assert is_writer_lock_held(data_root) is True

        # Status from arbitrary outside CWD succeeds with exit 0 and ready=True for the exact store.
        res_online = run_installed_command(
            inc2_installed_env,
            "brain",
            ("status", "--profile", str(profile_path)),
            cwd=outside_cwd,
            extra_env=poison_env,
        )
        assert res_online.returncode == 0
        assert res_online.stderr == b""
        online_env = parse_json(res_online.stdout.strip())
        assert isinstance(online_env, dict)
        assert online_env.get("ok") is True
        data_obj = online_env.get("data")
        assert isinstance(data_obj, dict)
        assert data_obj.get("ready") is True
        assert data_obj.get("store_id") == cli_transport_template.store_id
        assert data_obj.get("writer_epoch") == ep.writer_epoch
        assert res_online.stdout == canonical_json(online_env) + b"\n"

        # In-process `read_status` matches the CLI status output.
        inproc_status = read_status(profile_path, os_adapters())
        assert inproc_status.get("ok") is True
        inproc_data = inproc_status.get("data")
        assert isinstance(inproc_data, dict)
        assert inproc_data.get("store_id") == cli_transport_template.store_id

        # While daemon holds writer.lock, `brain migrate --offline --config <abs>` fails with writer_held.
        res_mig_held = run_installed_command(
            inc2_installed_env,
            "brain",
            ("migrate", "--offline", "--config", str(config_path)),
            cwd=outside_cwd,
            extra_env=poison_env,
        )
        assert res_mig_held.returncode == 1
        assert res_mig_held.stdout == b""
        err_line = _assert_static_stderr_line(res_mig_held.stderr, forbidden_substrings=(str(data_root),))
        assert err_line == "writer_held"

        # 8. Signal foreground `brain serve` and verify worker exit, endpoint.json removal, and lease release.
        rc, out_text, err_text, tracked_children = serve_proc.signal_and_wait_exit()
        assert rc == 0, f"Expected exit 0 from foreground `brain serve`, got {rc} (stderr={err_text!r})"
        assert out_text == ""
        assert err_text == ""
        if tracked_children:
            assert len(tracked_children) >= 1

    assert not endpoint_path.exists(), "endpoint.json must be removed on graceful daemon shutdown"
    assert is_writer_lock_held(data_root) is False, "writer.lock must be released after foreground serve exits"
    assert not poison_home.exists()
    assert not poison_local.exists()

    # After shutdown, status reports daemon_unavailable again.
    res_after = run_installed_command(
        inc2_installed_env,
        "brain",
        ("status", "--profile", str(profile_path)),
        cwd=outside_cwd,
    )
    assert res_after.returncode == 1
    after_env = parse_json(res_after.stdout.strip())
    assert isinstance(after_env, dict)
    assert after_env.get("ok") is False
    after_err = after_env.get("error")
    assert isinstance(after_err, dict)
    assert after_err.get("code") == "daemon_unavailable"


def test_installed_migrate_respects_offline_lease(
    inc2_installed_env: InstalledEnv,
    cli_scratch_root: Path,
) -> None:
    """Installed ``brain migrate --offline`` upgrades legacy root, preserves IDs, is idempotent, and obeys lease."""
    base_time = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=5)
    clock = FakeClock(base_time)
    adapters = os_adapters(clock=clock)

    case_dir = cli_scratch_root / "offline-migrate"
    outside_cwd = case_dir / "outside-cwd"
    outside_cwd.mkdir(parents=True, exist_ok=True)
    adapters.permissions.secure_directory(outside_cwd)

    # 1. Create a legacy Increment 1 data root at (store=2, policy=2) with durable CAS content.
    legacy_root = case_dir / "legacy-root"
    rt = open_runtime(
        legacy_root,
        adapters,
        store_migrations=KERNEL_STORE_MIGRATIONS[:2],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:2],
    )
    store_id = rt.store.store_id
    blob_payload = b"legacy-increment-1-cas-payload"
    blob_digest = rt.store.store_content(blob_payload, "evidence", new_id(), RetentionClass.DURABLE, None)
    rt.close()

    layout = DataRoot.at(legacy_root)
    p_before = read_schema_info(layout.policy_db)
    s_before = read_schema_info(layout.store_db)
    assert p_before is not None and p_before.schema_version == 2 and p_before.store_id == store_id
    assert s_before is not None and s_before.schema_version == 2 and s_before.store_id == store_id

    tls_auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=2),
        destination=case_dir / "tls",
    )
    tls = create_store_tls(store_id, case_dir / "tls", tls_auth, clock, adapters)
    legacy_cfg = write_daemon_config_file(
        case_dir / "legacy-config.json",
        data_root=legacy_root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
    )

    # 2. `brain serve` refuses unmigrated (store=2, policy=2) root with migration_required and leaves versions at 2.
    res_serve_legacy = run_installed_command(
        inc2_installed_env,
        "brain",
        ("serve", "--config", str(legacy_cfg)),
        cwd=outside_cwd,
    )
    assert res_serve_legacy.returncode == 1
    assert res_serve_legacy.stdout == b""
    assert _assert_static_stderr_line(res_serve_legacy.stderr, forbidden_substrings=(str(legacy_root),)) == (
        "migration_required"
    )
    p_still_v2 = read_schema_info(layout.policy_db)
    s_still_v2 = read_schema_info(layout.store_db)
    assert p_still_v2 is not None and p_still_v2.schema_version == 2
    assert s_still_v2 is not None and s_still_v2.schema_version == 2

    # 3. First `brain migrate --offline --config <abs>` upgrades policy 2->3 and store 2->4 under one lease.
    res_mig1 = run_installed_command(
        inc2_installed_env,
        "brain",
        ("migrate", "--offline", "--config", str(legacy_cfg)),
        cwd=outside_cwd,
    )
    assert res_mig1.returncode == 0, f"Migrate failed: stderr={res_mig1.stderr.decode('utf-8', errors='replace')!r}"
    assert res_mig1.stderr == b""
    stdout_text1 = res_mig1.stdout.decode("utf-8")
    assert str(legacy_root) not in stdout_text1, "Offline migrate stdout must never leak local backup/root paths"
    assert "backups" not in stdout_text1

    mig1_env = parse_json(res_mig1.stdout.strip())
    assert isinstance(mig1_env, dict)
    assert mig1_env.get("ok") is True
    data1 = mig1_env.get("data")
    assert isinstance(data1, dict)
    assert data1.get("store_id") == store_id
    assert data1.get("migrated") is True
    assert data1.get("noop") is False
    assert data1.get("policy_schema_version") == 3
    assert data1.get("store_schema_version") == 4
    assert data1.get("policy") == {"status": "migrated", "from_version": 2, "to_version": 3}
    assert data1.get("store") == {"status": "migrated", "from_version": 2, "to_version": 4}
    epoch1 = data1.get("writer_epoch")
    assert type(epoch1) is int and epoch1 >= 2
    assert res_mig1.stdout == canonical_json(mig1_env) + b"\n"
    assert is_writer_lock_held(legacy_root) is False

    p_after = read_schema_info(layout.policy_db)
    s_after = read_schema_info(layout.store_db)
    assert p_after is not None and p_after.store_id == store_id and p_after.schema_version == 3
    assert s_after is not None and s_after.store_id == store_id and s_after.schema_version == 4

    # 4. Repeat `brain migrate --config <abs> --offline` (alternate flag order) is a clean no-op.
    res_mig2 = run_installed_command(
        inc2_installed_env,
        "brain",
        ("migrate", "--config", str(legacy_cfg), "--offline"),
        cwd=outside_cwd,
    )
    assert res_mig2.returncode == 0
    assert res_mig2.stderr == b""
    mig2_env = parse_json(res_mig2.stdout.strip())
    assert isinstance(mig2_env, dict)
    assert mig2_env.get("ok") is True
    data2 = mig2_env.get("data")
    assert isinstance(data2, dict)
    assert data2.get("store_id") == store_id
    assert data2.get("migrated") is False
    assert data2.get("noop") is True
    assert data2.get("policy_schema_version") == 3
    assert data2.get("store_schema_version") == 4
    assert data2.get("policy") == {"status": "skipped", "from_version": 3, "to_version": 3}
    assert data2.get("store") == {"status": "skipped", "from_version": 4, "to_version": 4}
    assert data2.get("writer_epoch") == epoch1 + 1
    assert is_writer_lock_held(legacy_root) is False

    # 5. Seed an active credential on the migrated root, serve it, and verify migrate is refused with writer_held.
    rt_v2 = open_kernel_job_runtime(legacy_root, adapters)
    try:
        seed_principal_and_credential(rt_v2.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1")
    finally:
        rt_v2.close()

    with spawn_installed_brain_serve(
        inc2_installed_env,
        legacy_cfg,
        data_root=legacy_root,
        cwd=outside_cwd,
    ) as serve_proc:
        ep = serve_proc.wait_ready()
        assert ep.store_id == store_id

        # While daemon is serving the migrated root, offline migrate is refused with writer_held.
        res_held = run_installed_command(
            inc2_installed_env,
            "brain",
            ("migrate", "--offline", "--config", str(legacy_cfg)),
            cwd=outside_cwd,
        )
        assert res_held.returncode == 1
        assert res_held.stdout == b""
        assert _assert_static_stderr_line(res_held.stderr) == "writer_held"

        rc, _, _, _ = serve_proc.signal_and_wait_exit()
        assert rc == 0

    # Verify original CAS blob is still intact after migration and serve.
    hex_ = blob_digest.removeprefix("sha256:")
    assert (layout.cas_dir / hex_[:2] / hex_).read_bytes() == blob_payload

    # 6. Config pointing to missing root or wrong store_id is refused by `brain migrate --offline`.
    missing_mig_root = case_dir / "missing-migrate-root"
    missing_mig_cfg = write_daemon_config_file(
        case_dir / "missing-migrate-config.json",
        data_root=missing_mig_root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
    )
    res_mig_missing = run_installed_command(
        inc2_installed_env,
        "brain",
        ("migrate", "--offline", "--config", str(missing_mig_cfg)),
        cwd=outside_cwd,
    )
    assert res_mig_missing.returncode == 1
    assert res_mig_missing.stdout == b""
    _assert_static_stderr_line(res_mig_missing.stderr, forbidden_substrings=(str(missing_mig_root),))
    assert not missing_mig_root.exists()
