"""Cross-wheel compatibility matrix for SP2-1 vs frozen I2 baseline (035a4cd)."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.kernel import Endpoint
from superbrain.core.wire import load_catalog, parse_json
from tests.support.clock import FakeClock
from tests.support.inc2_cli import (
    InstalledServeProcess,
    decode_stdio_frames,
    encode_stdio_frames,
    get_shared_t7_transport_template,
    mcp_call_frame,
    mcp_init_frames,
    run_installed_command,
    spawn_installed_brain_serve,
    verify_installed_wheel_isolation,
    write_ca_file,
    write_client_profile_file,
    write_credential_file,
    write_daemon_config_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import (
    REPO_ROOT,
    SOURCE_SCHEMA_PATH,
    InstalledEnv,
    _clean_subprocess_env,
    _cleanup_dir,
    _make_trusted_session_dir,
    open_kernel_job_runtime,
)
from tests.support.inc2_transport import clone_owner_only_tree, read_raw_http_response
from tests.support.kernel_auth import (
    generate_bearer_token,
    make_bootstrap_auth,
    seed_principal_and_credential,
)

FROZEN_I2_COMMIT = "035a4cdc5936155982e5172602213353d4bbb6c4"


def _run_offline(cmd: list[str], *, cwd: Path, extra_env: Mapping[str, str] | None = None) -> str:
    env = _clean_subprocess_env()
    if extra_env is not None:
        env.update(extra_env)
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180.0,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


@pytest.fixture(scope="session")
def frozen_i2_installed_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[InstalledEnv]:
    """Build an offline wheel + venv from frozen baseline commit 035a4cdc5936155982e5172602213353d4bbb6c4."""
    scratch = _make_trusted_session_dir("i2-wheel-", tmp_path_factory)
    try:
        tar_path = scratch / "frozen-i2.tar"
        src_dir = scratch / "src-i2"
        src_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "archive",
                "--format=tar",
                "--output",
                str(tar_path),
                FROZEN_I2_COMMIT,
            ],
            check=True,
            capture_output=True,
            timeout=60.0,
        )
        with tarfile.open(tar_path, "r:") as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(src_dir, filter="data")
            else:
                tf.extractall(src_dir)
        tar_path.unlink(missing_ok=True)

        frozen_schema_path = src_dir / "schemas" / "mcp-tools-v2.json"
        assert frozen_schema_path.is_file()
        frozen_schema_sha256 = hashlib.sha256(frozen_schema_path.read_bytes()).hexdigest()

        dist_dir = scratch / "dist"
        dist_dir.mkdir()
        venv_dir = scratch / "venv"

        _run_offline(
            [
                "uv",
                "build",
                "--wheel",
                "--no-build-isolation",
                "--offline",
                "--python",
                sys.executable,
                "--out-dir",
                str(dist_dir),
                str(src_dir),
            ],
            cwd=src_dir,
        )
        wheels = sorted(dist_dir.glob("super_brain2-*.whl"))
        assert len(wheels) == 1, f"expected 1 wheel, found {wheels}"
        wheel_path = wheels[0]

        _run_offline(
            [
                "uv",
                "sync",
                "--project",
                str(src_dir),
                "--locked",
                "--offline",
                "--no-dev",
                "--no-install-project",
                "--python",
                sys.executable,
            ],
            cwd=src_dir,
            extra_env={"UV_PROJECT_ENVIRONMENT": str(venv_dir)},
        )
        venv_python = (
            venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"
        )
        _run_offline(
            [
                "uv",
                "pip",
                "install",
                "--offline",
                "--no-deps",
                "--link-mode=copy",
                "--python",
                str(venv_python),
                str(wheel_path),
            ],
            cwd=scratch,
        )

        purelib_dir = Path(
            subprocess.check_output(
                [str(venv_python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                text=True,
                encoding="utf-8",
                timeout=30.0,
            ).strip()
        )
        hook_src = (REPO_ROOT / "tests" / "support" / "_socket_readiness_hook.py").read_bytes()
        (purelib_dir / "_superbrain_test_readiness.py").write_bytes(hook_src)
        (purelib_dir / "_superbrain_test_readiness.pth").write_text(
            'import os; os.environ.get("SUPERBRAIN_TEST_SOCKET_READINESS") '
            'and __import__("_superbrain_test_readiness").install()\n',
            encoding="utf-8",
        )

        yield InstalledEnv(
            venv_dir=venv_dir,
            venv_python=venv_python,
            wheel_path=wheel_path,
            source_schema_path=frozen_schema_path,
            source_schema_sha256=frozen_schema_sha256,
        )
    finally:
        _cleanup_dir(scratch)


@dataclasses.dataclass(frozen=True)
class _LiveWheelDaemon:
    data_root: Path
    endpoint: Endpoint
    store_id: str
    ca_path: Path
    leaf_sha256: str
    token: str
    profile_path: Path
    client_cwd: Path
    identity_bytes: bytes


@dataclasses.dataclass(frozen=True)
class _DualDaemonBundle:
    scratch: Path
    sp2_daemon: _LiveWheelDaemon
    i2_daemon: _LiveWheelDaemon
    sp2_profile_against_i2: Path
    i2_profile_against_sp2: Path
    tls_cert_path: Path
    tls_key_path: Path


def _seed_daemon_root(scratch: Path, label: str, schema_src_root: Path) -> _LiveWheelDaemon:
    base = scratch / label
    data_root = base / "daemon-data"
    client_cwd = base / "client-cwd"
    client_cwd.mkdir(parents=True)
    clock = FakeClock(dt.datetime(2026, 11, 19, 4, 0, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)

    rt = open_kernel_job_runtime(data_root, adapters)
    try:
        store_id = rt.store.store_id
        cred = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="devbox-1"
        )
    finally:
        rt.close()

    tls_auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=2),
        destination=base / "tls",
    )
    tls = create_store_tls(store_id, base / "tls", tls_auth, clock, adapters)
    cfg_path = write_daemon_config_file(
        base / "daemon-config.json",
        data_root=data_root,
        expected_store_id=store_id,
        cert_path=tls.cert_path,
        key_path=tls.key_path,
    )
    del schema_src_root
    return _LiveWheelDaemon(
        data_root=data_root,
        endpoint=Endpoint(
            version=1,
            host="127.0.0.1",
            port=1,
            store_id=store_id,
            writer_epoch=1,
            instance_id="pending",
            contract="mcp-tools-v2",
        ),
        store_id=store_id,
        ca_path=tls.ca_cert_path,
        leaf_sha256=tls.leaf_cert_sha256,
        token=cred.token,
        profile_path=cfg_path,
        client_cwd=client_cwd,
        identity_bytes=b"",
    )


def _fetch_identity_raw(endpoint: Endpoint, ca_path: Path) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_path))
    ctx.check_hostname = True
    with socket.create_connection((endpoint.host, endpoint.port), timeout=2.0) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls_sock:
            tls_sock.sendall(
                f"GET /v2/identity HTTP/1.1\r\nHost: {endpoint.host}:{endpoint.port}\r\n\r\n".encode("ascii")
            )
            resp = read_raw_http_response(tls_sock)
    assert b"200 OK" in resp
    return resp.split(b"\r\n\r\n", 1)[1]


def _read_ledger_seq(data_root: Path) -> int:
    db_path = data_root / "store" / "brain.db"
    with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        row = conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM ledger").fetchone()
        return int(row[0]) if row is not None else 0


@pytest.fixture(scope="module")
def compat_daemons(
    inc2_installed_env: InstalledEnv,
    frozen_i2_installed_env: InstalledEnv,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[_DualDaemonBundle]:
    """Start 1 real SP2 daemon and 1 real frozen I2 daemon once for the whole compatibility matrix."""
    assert frozen_i2_installed_env.source_schema_sha256 != hashlib.sha256(
        SOURCE_SCHEMA_PATH.read_bytes()
    ).hexdigest()
    verify_installed_wheel_isolation(inc2_installed_env, cwd=inc2_installed_env.venv_dir)
    verify_installed_wheel_isolation(frozen_i2_installed_env, cwd=frozen_i2_installed_env.venv_dir)

    scratch = _make_trusted_session_dir("i2-compat-run-", tmp_path_factory)
    sp2_seed = _seed_daemon_root(scratch, "sp2", SOURCE_SCHEMA_PATH.parent)
    i2_seed = _seed_daemon_root(scratch, "i2", frozen_i2_installed_env.source_schema_path.parent)

    sp2_proc: InstalledServeProcess | None = None
    i2_proc: InstalledServeProcess | None = None
    try:
        sp2_proc = spawn_installed_brain_serve(
            inc2_installed_env,
            sp2_seed.profile_path,
            data_root=sp2_seed.data_root,
            cwd=scratch / "sp2",
        )
        i2_proc = spawn_installed_brain_serve(
            frozen_i2_installed_env,
            i2_seed.profile_path,
            data_root=i2_seed.data_root,
            cwd=scratch / "i2",
        )
        sp2_ep = sp2_proc.wait_ready(timeout=15.0)
        i2_ep = i2_proc.wait_ready(timeout=15.0)

        sp2_ident_raw = _fetch_identity_raw(sp2_ep, sp2_seed.ca_path)
        i2_ident_raw = _fetch_identity_raw(i2_ep, i2_seed.ca_path)

        sp2_ep_file = sp2_seed.data_root / "endpoint.json"
        i2_ep_file = i2_seed.data_root / "endpoint.json"
        sp2_ca = write_ca_file(scratch / "sp2-ca.pem", sp2_seed.ca_path.read_bytes())
        i2_ca = write_ca_file(scratch / "i2-ca.pem", i2_seed.ca_path.read_bytes())
        sp2_tok = write_credential_file(scratch / "sp2-tok.txt", sp2_seed.token)
        i2_tok = write_credential_file(scratch / "i2-tok.txt", i2_seed.token)

        prof_sp2_sp2, _ = write_client_profile_file(
            scratch / "prof-sp2-sp2.json",
            endpoint_path=sp2_ep_file,
            expected_store_id=sp2_seed.store_id,
            ca_file=sp2_ca,
            leaf_cert_sha256=sp2_seed.leaf_sha256,
            credential_file=sp2_tok,
            workspace=None,
        )
        prof_i2_i2, _ = write_client_profile_file(
            scratch / "prof-i2-i2.json",
            endpoint_path=i2_ep_file,
            expected_store_id=i2_seed.store_id,
            ca_file=i2_ca,
            leaf_cert_sha256=i2_seed.leaf_sha256,
            credential_file=i2_tok,
            workspace=None,
        )
        prof_sp2_i2, _ = write_client_profile_file(
            scratch / "prof-sp2-i2.json",
            endpoint_path=i2_ep_file,
            expected_store_id=i2_seed.store_id,
            ca_file=i2_ca,
            leaf_cert_sha256=i2_seed.leaf_sha256,
            credential_file=i2_tok,
            workspace=None,
        )
        prof_i2_sp2, _ = write_client_profile_file(
            scratch / "prof-i2-sp2.json",
            endpoint_path=sp2_ep_file,
            expected_store_id=sp2_seed.store_id,
            ca_file=sp2_ca,
            leaf_cert_sha256=sp2_seed.leaf_sha256,
            credential_file=sp2_tok,
            workspace=None,
        )

        yield _DualDaemonBundle(
            scratch=scratch,
            sp2_daemon=dataclasses.replace(
                sp2_seed, endpoint=sp2_ep, profile_path=prof_sp2_sp2, identity_bytes=sp2_ident_raw
            ),
            i2_daemon=dataclasses.replace(
                i2_seed, endpoint=i2_ep, profile_path=prof_i2_i2, identity_bytes=i2_ident_raw
            ),
            sp2_profile_against_i2=prof_sp2_i2,
            i2_profile_against_sp2=prof_i2_sp2,
            tls_cert_path=scratch / "sp2" / "tls" / "leaf.pem",
            tls_key_path=scratch / "sp2" / "tls" / "leaf.key",
        )
    finally:
        if sp2_proc is not None:
            sp2_proc.close()
        if i2_proc is not None:
            i2_proc.close()
        _cleanup_dir(scratch)


def _call_installed_mcp(
    env: InstalledEnv,
    *,
    script_name: str,
    prefix_args: list[str],
    profile_path: Path,
    cwd: Path,
    tool: str = "get_health",
    arguments: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    tool_args = dict(arguments) if arguments is not None else {"schema_version": "2.0"}
    stdin_bytes = encode_stdio_frames([*mcp_init_frames(1), mcp_call_frame(2, tool, tool_args)])
    proc = run_installed_command(
        env,
        script_name,
        [*prefix_args, "--profile", str(profile_path)],
        cwd=cwd,
        stdin_bytes=stdin_bytes,
    )
    assert proc.returncode == 0, f"{script_name} failed: stderr={proc.stderr!r}"
    frames = decode_stdio_frames(proc.stdout)
    assert len(frames) == 2
    res = frames[1]["result"]
    assert isinstance(res, dict)
    sc = res["structuredContent"]
    assert isinstance(sc, dict)
    return dict(sc)


def _call_installed_status(
    env: InstalledEnv,
    *,
    profile_path: Path,
    cwd: Path,
    expect_ok: bool,
) -> dict[str, Any]:
    proc = run_installed_command(env, "brain", ["status", "--profile", str(profile_path)], cwd=cwd)
    assert proc.returncode == (0 if expect_ok else 1), f"status rc={proc.returncode}, stderr={proc.stderr!r}"
    parsed = parse_json(proc.stdout.strip())
    assert isinstance(parsed, dict)
    return dict(parsed)


def _run_wire_spy_against_identity_bytes(
    *,
    scratch: Path,
    label: str,
    identity_bytes: bytes,
    base_endpoint: Endpoint,
    client_env: InstalledEnv,
    expected_code: str,
) -> None:
    """Serve exact captured daemon /v2/identity bytes and assert 0 POSTs + 0 bearer secret bytes."""
    clock = FakeClock(dt.datetime(2026, 11, 19, 5, 0, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    spy_dir = scratch / f"spy-{label}"
    spy_dir.mkdir(parents=True, exist_ok=True)
    tls_auth = make_bootstrap_auth(
        store_id=base_endpoint.store_id,
        owner_id="dan",
        action="provision_tls",
        subject_id=base_endpoint.store_id,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=1),
        destination=spy_dir / "tls",
    )
    tls = create_store_tls(base_endpoint.store_id, spy_dir / "tls", tls_auth, clock, adapters)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(tls.cert_path), keyfile=str(tls.key_path))

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(8)
    srv_sock.settimeout(0.2)
    port = int(srv_sock.getsockname()[1])
    stop_ev = threading.Event()
    spy_lock = threading.Lock()
    received_chunks: list[bytes] = []
    post_count = 0
    identity_probe_count = 0

    def _serve() -> None:
        nonlocal post_count, identity_probe_count
        while not stop_ev.is_set():
            try:
                raw_conn, _ = srv_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with ssl_ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
                    tls_conn.settimeout(2.0)
                    buf = bytearray()
                    while b"\r\n\r\n" not in buf:
                        c = tls_conn.recv(4096)
                        if not c:
                            break
                        buf.extend(c)
                    if buf:
                        first_chunk = bytes(buf)
                        with spy_lock:
                            received_chunks.append(first_chunk)
                            if first_chunk.startswith(b"GET /v2/identity "):
                                identity_probe_count += 1
                            if first_chunk.startswith(b"POST "):
                                post_count += 1
                        cl_hdr = str(len(identity_bytes)).encode("ascii")
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Content-Length: " + cl_hdr + b"\r\n\r\n" + identity_bytes
                        )
                        tls_conn.sendall(resp)
                        with contextlib.suppress(TimeoutError, OSError):
                            extra = tls_conn.recv(4096)
                            if extra:
                                with spy_lock:
                                    received_chunks.append(extra)
                                    if b"POST " in extra:
                                        post_count += 1
            except (TimeoutError, ssl.SSLError, OSError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    raw_conn.close()

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    try:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=port,
            store_id=base_endpoint.store_id,
            writer_epoch=base_endpoint.writer_epoch,
            instance_id=base_endpoint.instance_id,
            contract="mcp-tools-v2",
        )
        _, token, _, secret_canary = generate_bearer_token()
        ep_path = write_owner_only_bytes(spy_dir / "ep.json", ep.encode_canonical())
        ca_path = write_ca_file(spy_dir / "ca.pem", tls.ca_cert_path.read_bytes())
        cred_path = write_credential_file(spy_dir / "cred.txt", token)
        prof_path, _ = write_client_profile_file(
            spy_dir / "profile.json",
            endpoint_path=ep_path,
            expected_store_id=ep.store_id,
            ca_file=ca_path,
            leaf_cert_sha256=tls.leaf_cert_sha256,
            credential_file=cred_path,
            workspace=None,
        )

        for script_name, prefix_args in (("brain-mcp", []), ("brain", ["mcp"])):
            res_mcp = _call_installed_mcp(
                client_env,
                script_name=script_name,
                prefix_args=prefix_args,
                profile_path=prof_path,
                cwd=spy_dir,
            )
            assert res_mcp["ok"] is False
            assert res_mcp["error"]["code"] == expected_code

        res_status = _call_installed_status(client_env, profile_path=prof_path, cwd=spy_dir, expect_ok=False)
        assert res_status["ok"] is False
        assert res_status["error"]["code"] == expected_code

        stop_ev.set()
        with contextlib.suppress(OSError):
            srv_sock.close()
        th.join(timeout=3.0)

        joined = b"".join(received_chunks)
        assert identity_probe_count == 3
        assert b"GET /v2/identity " in joined
        assert post_count == 0
        assert secret_canary.encode("ascii") not in joined
        assert b"Authorization" not in joined
    finally:
        stop_ev.set()
        with contextlib.suppress(OSError):
            srv_sock.close()
        th.join(timeout=3.0)


def test_cross_wheel_compatibility_matrix_and_raw_tls_probes(
    inc2_installed_env: InstalledEnv,
    frozen_i2_installed_env: InstalledEnv,
    compat_daemons: _DualDaemonBundle,
) -> None:
    """Verify all 4 ca-62 cross-wheel compatibility rows plus raw TLS HTTP 426 enforcement."""
    sp2_catalog = load_catalog()
    expected_digest = sp2_catalog.schema_digest
    assert hashlib.sha256(SOURCE_SCHEMA_PATH.read_bytes()).hexdigest() == expected_digest.removeprefix("sha256:")
    assert inc2_installed_env.source_schema_sha256 != frozen_i2_installed_env.source_schema_sha256

    sp2_ident_obj = json.loads(compat_daemons.sp2_daemon.identity_bytes.decode("utf-8"))
    i2_ident_obj = json.loads(compat_daemons.i2_daemon.identity_bytes.decode("utf-8"))
    assert set(sp2_ident_obj) == {"store_id", "writer_epoch", "instance_id", "contract", "schema_digest"}
    assert sp2_ident_obj["schema_digest"] == expected_digest
    assert set(i2_ident_obj) == {"store_id", "writer_epoch", "instance_id", "contract"}

    # Row 1: SP2 shim (brain-mcp, brain mcp, brain status) <-> SP2 daemon -> succeeds
    for script, prefix in (("brain-mcp", []), ("brain", ["mcp"])):
        res = _call_installed_mcp(
            inc2_installed_env,
            script_name=script,
            prefix_args=prefix,
            profile_path=compat_daemons.sp2_daemon.profile_path,
            cwd=compat_daemons.sp2_daemon.client_cwd,
        )
        assert res["ok"] is True
        assert cast(dict[str, Any], res["data"])["ready"] is True
    st_sp2 = _call_installed_status(
        inc2_installed_env,
        profile_path=compat_daemons.sp2_daemon.profile_path,
        cwd=compat_daemons.sp2_daemon.client_cwd,
        expect_ok=True,
    )
    assert st_sp2["ok"] is True and cast(dict[str, Any], st_sp2["data"])["ready"] is True

    # Row 2: SP2 shim <-> real frozen I2 daemon -> unsupported_version across all 3 entrypoints + 0 bearer bytes
    i2_seq_before = _read_ledger_seq(compat_daemons.i2_daemon.data_root)
    for script, prefix in (("brain-mcp", []), ("brain", ["mcp"])):
        res = _call_installed_mcp(
            inc2_installed_env,
            script_name=script,
            prefix_args=prefix,
            profile_path=compat_daemons.sp2_profile_against_i2,
            cwd=compat_daemons.sp2_daemon.client_cwd,
        )
        assert res["ok"] is False
        assert cast(dict[str, Any], res["error"])["code"] == ErrorCode.UNSUPPORTED_VERSION.value
    st_sp2_i2 = _call_installed_status(
        inc2_installed_env,
        profile_path=compat_daemons.sp2_profile_against_i2,
        cwd=compat_daemons.sp2_daemon.client_cwd,
        expect_ok=False,
    )
    assert st_sp2_i2["ok"] is False
    assert cast(dict[str, Any], st_sp2_i2["error"])["code"] == ErrorCode.UNSUPPORTED_VERSION.value
    assert _read_ledger_seq(compat_daemons.i2_daemon.data_root) == i2_seq_before

    _run_wire_spy_against_identity_bytes(
        scratch=compat_daemons.scratch,
        label="sp2-vs-i2",
        identity_bytes=compat_daemons.i2_daemon.identity_bytes,
        base_endpoint=compat_daemons.i2_daemon.endpoint,
        client_env=inc2_installed_env,
        expected_code=ErrorCode.UNSUPPORTED_VERSION.value,
    )

    # Row 3: Frozen I2 shim <-> real SP2 daemon -> identity_mismatch + 0 bearer bytes;
    # plus positive control: frozen I2 shim <-> frozen I2 daemon succeeds!
    sp2_seq_before = _read_ledger_seq(compat_daemons.sp2_daemon.data_root)
    for script, prefix in (("brain-mcp", []), ("brain", ["mcp"])):
        res_i2_sp2 = _call_installed_mcp(
            frozen_i2_installed_env,
            script_name=script,
            prefix_args=prefix,
            profile_path=compat_daemons.i2_profile_against_sp2,
            cwd=compat_daemons.i2_daemon.client_cwd,
        )
        assert res_i2_sp2["ok"] is False
        assert cast(dict[str, Any], res_i2_sp2["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value
    st_i2_sp2 = _call_installed_status(
        frozen_i2_installed_env,
        profile_path=compat_daemons.i2_profile_against_sp2,
        cwd=compat_daemons.i2_daemon.client_cwd,
        expect_ok=False,
    )
    assert st_i2_sp2["ok"] is False
    assert cast(dict[str, Any], st_i2_sp2["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value
    assert _read_ledger_seq(compat_daemons.sp2_daemon.data_root) == sp2_seq_before

    _run_wire_spy_against_identity_bytes(
        scratch=compat_daemons.scratch,
        label="i2-vs-sp2",
        identity_bytes=compat_daemons.sp2_daemon.identity_bytes,
        base_endpoint=compat_daemons.sp2_daemon.endpoint,
        client_env=frozen_i2_installed_env,
        expected_code=ErrorCode.IDENTITY_MISMATCH.value,
    )

    # Positive twin for Row 3: frozen I2 shim <-> frozen I2 daemon succeeds
    for script, prefix in (("brain-mcp", []), ("brain", ["mcp"])):
        res_i2_ok = _call_installed_mcp(
            frozen_i2_installed_env,
            script_name=script,
            prefix_args=prefix,
            profile_path=compat_daemons.i2_daemon.profile_path,
            cwd=compat_daemons.i2_daemon.client_cwd,
        )
        assert res_i2_ok["ok"] is True
        assert cast(dict[str, Any], res_i2_ok["data"])["ready"] is True
    st_i2_ok = _call_installed_status(
        frozen_i2_installed_env,
        profile_path=compat_daemons.i2_daemon.profile_path,
        cwd=compat_daemons.i2_daemon.client_cwd,
        expect_ok=True,
    )
    assert st_i2_ok["ok"] is True

    # Row 4: Authenticated raw TLS probe to live SP2 daemon with missing/mismatched schema_digest
    # on BOTH POST /v2/tools/call AND POST /v2/capture/events -> HTTP 426 unsupported_version, 0 ledger advance
    sp2_d = compat_daemons.sp2_daemon
    ep = sp2_d.endpoint
    ca_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca_ctx.load_verify_locations(cafile=str(sp2_d.ca_path))
    ca_ctx.check_hostname = True

    base_tool = {
        "tool": "get_health",
        "arguments": {"schema_version": "2.0"},
        "correlation_id": None,
        "selected_scope": None,
    }
    base_capture = {
        "producer_stream": "claude-hook-v1",
        "repo_id": "repo-raw-probe",
        "checkout_id": "chk-raw-probe",
        "events": [{"event_id": "ev-1", "kind": "stop"}],
        "correlation_id": None,
    }
    for path, base_body in (("/v2/tools/call", base_tool), ("/v2/capture/events", base_capture)):
        for dig_patch in ({}, {"schema_digest": "sha256:" + ("0" * 64)}):
            payload_bytes = canonical_json({**base_body, **dig_patch})
            with socket.create_connection((ep.host, ep.port), timeout=2.0) as raw:
                with ca_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls_sock:
                    tls_sock.sendall(
                        f"GET /v2/identity HTTP/1.1\r\nHost: {ep.host}:{ep.port}\r\n\r\n".encode("ascii")
                    )
                    id_raw = read_raw_http_response(tls_sock)
                    assert b"200 OK" in id_raw
                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {ep.host}:{ep.port}\r\n"
                        f"Authorization: Bearer {sp2_d.token}\r\n"
                        f"X-Store-Id: {ep.store_id}\r\n"
                        f"X-Writer-Epoch: {ep.writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {ep.instance_id}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(payload_bytes)}\r\n\r\n"
                    ).encode("ascii") + payload_bytes
                    tls_sock.sendall(req)
                    resp_raw = read_raw_http_response(tls_sock)
            head_line = resp_raw.split(b"\r\n", 1)[0].decode("iso-8859-1")
            assert head_line.startswith("HTTP/1.1 426 "), f"expected 426 for {path} {dig_patch}: {resp_raw!r}"
            body_json = json.loads(resp_raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
            assert body_json == {
                "ok": False,
                "error": {"code": "unsupported_version", "message": "unsupported version"},
            }
    assert _read_ledger_seq(sp2_d.data_root) == sp2_seq_before


_UPGRADE_DOMAIN_SCRIPT = '''
from __future__ import annotations

import dataclasses
import json
import sys
import threading
from pathlib import Path
from typing import Any

from superbrain.application.send_attempts import extract_projected_read_acks, record_projected_read_acks
from superbrain.application.dispatch import PreparedEffect
from superbrain.composition.daemon_entry import serve_config_path
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
    KernelRecord,
    ObjectRef,
    Principal,
    ResourceDigest,
    Scope,
    StoredResult,
    require_opaque_id,
)
from superbrain.ports.kernel import KernelTx


class _AllowPolicy:
    def allows(self, _p: object, _s: object, *, action: str) -> bool:
        del action
        return True


class _PersistentUpgradeDomain:
    def __init__(self, state_path: Path, prep_log_path: Path) -> None:
        self._state_path = state_path
        self._prep_log_path = prep_log_path
        self._lock = threading.Lock()
        if state_path.is_file():
            raw = json.loads(state_path.read_text(encoding="utf-8"))
            self._task_scopes: dict[str, list[str]] = dict(raw["task_scopes"])
            self._deliveries: dict[str, list[str]] = dict(raw["deliveries"])
            self._stored_meta: dict[str, dict[str, Any]] = dict(raw["stored_meta"])
        else:
            self._task_scopes = {}
            self._deliveries = {}
            self._stored_meta = {}

    def _persist_locked(self) -> None:
        snap = {
            "task_scopes": self._task_scopes,
            "deliveries": self._deliveries,
            "stored_meta": self._stored_meta,
        }
        self._state_path.write_text(json.dumps(snap, sort_keys=True), encoding="utf-8")

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return False if deep else tool in {"prepare_task", "get_artifact", "record_outcome", "submit_episode"}

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, Any]:
        del call, ctx
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: Any) -> PreparedEffect:
        del now
        with self._lock:
            entry = json.dumps({"tool": call.tool, "idem": call.arguments.get("idempotency_key")}) + "\\n"
            with self._prep_log_path.open("a", encoding="utf-8") as fh:
                fh.write(entry)
        scope = call.selected_scope
        if scope is None or scope.checkout_id is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        if call.tool == "prepare_task":
            task_id = new_id()
            delivery_id = new_id()
            assignment_id = new_id()
            res_id = new_id()
            meta = {
                "kind": "delivery_result",
                "result_id": res_id,
                "task_id": task_id,
                "delivery_id": delivery_id,
                "assignment_id": assignment_id,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
            }
            blob = canonical_json(meta)
            ref = ObjectRef(kind="delivery_result", id=res_id, revision=1, digest=digest_bytes(blob))

            def _apply_prep(tx: KernelTx) -> StoredResult:
                tx.hold_blob(blob, holder_id=res_id)
                tx.append_record(
                    KernelRecord(
                        "lineage.task_bound",
                        {
                            "task_id": task_id,
                            "owner_id": ctx.principal.owner_id,
                            "repo_id": scope.repo_id,
                            "checkout_id": scope.checkout_id,
                            "delivery_id": delivery_id,
                            "assignment_id": assignment_id,
                            "source_snapshot_id": None,
                            "snapshot_status": "unavailable",
                            "selector_path": "rules",
                            "selector_reason": "provider_unavailable",
                        },
                    )
                )
                with self._lock:
                    self._task_scopes[task_id] = [ctx.principal.owner_id, scope.repo_id, scope.checkout_id]
                    self._deliveries[delivery_id] = [
                        ctx.principal.owner_id,
                        scope.repo_id,
                        scope.checkout_id,
                        assignment_id,
                        task_id,
                    ]
                    self._stored_meta[res_id] = meta
                    self._persist_locked()
                return StoredResult(result_id=res_id, assignment_id=assignment_id, refs=(ref,))

            return PreparedEffect(blobs=(blob,), apply=_apply_prep)

        if call.tool == "get_artifact":
            task_id = require_opaque_id(call.arguments["task_id"], label="task_id")
            artifact_id = require_opaque_id(call.arguments["artifact_id"], label="artifact_id")
            revision = int(call.arguments["revision"])
            level = str(call.arguments["level"])
            res_id = new_id()
            meta = {
                "kind": "artifact_result",
                "result_id": res_id,
                "task_id": task_id,
                "artifact_id": artifact_id,
                "revision": revision,
                "level": level,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
            }
            blob = canonical_json(meta)
            ref = ObjectRef(kind="artifact_result", id=res_id, revision=1, digest=digest_bytes(blob))

            def _apply_art(tx: KernelTx) -> StoredResult:
                tx.hold_blob(blob, holder_id=res_id)
                with self._lock:
                    self._stored_meta[res_id] = meta
                    self._persist_locked()
                return StoredResult(result_id=res_id, assignment_id=None, refs=(ref,))

            return PreparedEffect(blobs=(blob,), apply=_apply_art)

        if call.tool == "record_outcome":
            delivery_id = require_opaque_id(call.arguments["delivery_id"], label="delivery_id")
            with self._lock:
                deliv = self._deliveries.get(delivery_id)
            if deliv is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            assignment_id, task_id = deliv[3], deliv[4]
            projected_acks = extract_projected_read_acks(dict(call.arguments))
            outcome_id = new_id()
            meta = {
                "kind": "outcome_result",
                "result_id": outcome_id,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
            }
            blob = canonical_json(meta)
            ref = ObjectRef(kind="outcome_result", id=outcome_id, revision=1, digest=digest_bytes(blob))

            def _apply_out(tx: KernelTx) -> StoredResult:
                if projected_acks:
                    record_projected_read_acks(
                        tx,
                        policy=_AllowPolicy(),
                        principal=ctx.principal,
                        effective_scope=scope,
                        expected_task_id=task_id,
                        acks=projected_acks,
                        action="record_outcome",
                    )
                tx.hold_blob(blob, holder_id=outcome_id)
                with self._lock:
                    self._stored_meta[outcome_id] = meta
                    self._persist_locked()
                return StoredResult(result_id=outcome_id, assignment_id=assignment_id, refs=(ref,))

            return PreparedEffect(blobs=(blob,), apply=_apply_out)

        if call.tool == "submit_episode":
            task_id = require_opaque_id(call.arguments["task_id"], label="task_id")
            projected_acks = extract_projected_read_acks(dict(call.arguments))
            episode_id = new_id()
            meta = {
                "kind": "episode_result",
                "result_id": episode_id,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
            }
            blob = canonical_json(meta)
            ref = ObjectRef(kind="episode_result", id=episode_id, revision=1, digest=digest_bytes(blob))

            def _apply_ep(tx: KernelTx) -> StoredResult:
                if projected_acks:
                    record_projected_read_acks(
                        tx,
                        policy=_AllowPolicy(),
                        principal=ctx.principal,
                        effective_scope=scope,
                        expected_task_id=task_id,
                        acks=projected_acks,
                        action="submit_episode",
                    )
                tx.hold_blob(blob, holder_id=episode_id)
                with self._lock:
                    self._stored_meta[episode_id] = meta
                    self._persist_locked()
                return StoredResult(result_id=episode_id, assignment_id=None, refs=(ref,))

            return PreparedEffect(blobs=(blob,), apply=_apply_ep)

        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def render_stored(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, Any]:
        with self._lock:
            meta = self._stored_meta.get(result.result_id)
        if meta is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        expected_scope = Scope(repo_id=str(meta["repo_id"]), checkout_id=str(meta["checkout_id"]))
        if principal.owner_id != str(meta["owner_id"]) or selected_scope != expected_scope:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        kind = str(meta["kind"])
        if kind == "delivery_result":
            return {
                "workspace_id": str(meta["repo_id"]),
                "checkout_id": str(meta["checkout_id"]),
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": str(meta["task_id"]),
                "delivery_id": str(meta["delivery_id"]),
                "assignment_id": str(meta["assignment_id"]),
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": {"summary_md": "upgrade-domain", "sources": [], "unknown_source": False},
                "finishing_gates": [],
            }
        if kind == "artifact_result":
            art_id = str(meta["artifact_id"])
            rev = int(meta["revision"])
            lvl = str(meta["level"])
            content = f"# Upgrade {art_id}@{rev} ({lvl})\\n"
            return {
                "artifact_id": art_id,
                "revision": rev,
                "level": lvl,
                "status": "ok",
                "resources": [
                    {
                        "name": f"{lvl}.md",
                        "digest": digest_bytes(content.encode("utf-8")),
                        "encoding": "utf-8",
                        "content": content,
                    }
                ],
            }
        if kind == "outcome_result":
            return {"outcome_id": str(meta["result_id"]), "status": "declared"}
        if kind == "episode_result":
            return {"episode_id": str(meta["result_id"]), "evidence_ids": [], "candidate_lesson_id": None}
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, Any],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        del rendered, selected_scope
        if not result.refs or result.refs[0].kind != "artifact_result":
            return None
        with self._lock:
            meta = self._stored_meta.get(result.result_id)
        if meta is None:
            return None
        art_id = str(meta["artifact_id"])
        rev = int(meta["revision"])
        lvl = str(meta["level"])
        content = f"# Upgrade {art_id}@{rev} ({lvl})\\n"
        spec_kwargs: dict[str, Any] = {
            "logical_result_id": result.result_id,
            "principal_id": principal.principal_id,
            "task_id": str(meta["task_id"]),
            "artifact_id": art_id,
            "revision": rev,
            "resource_digests": (ResourceDigest(name=f"{lvl}.md", digest=digest_bytes(content.encode("utf-8"))),),
        }
        if "level" in {f.name for f in dataclasses.fields(ArtifactSendSpec)}:
            spec_kwargs["level"] = lvl
        return ArtifactSendSpec(**spec_kwargs)


if __name__ == "__main__":
    cfg_p, state_p, log_p = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    raise SystemExit(serve_config_path(cfg_p, domain=_PersistentUpgradeDomain(state_p, log_p)))
'''


def _wait_send_attempt_served(db_path: Path, receipt_id: str, *, timeout_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            row = conn.execute("SELECT state FROM artifact_send_attempt WHERE id = ?", (receipt_id,)).fetchone()
        if row is not None and row[0] == "served_only":
            return
        threading.Event().wait(0.01)
    raise AssertionError(f"send_attempt {receipt_id} did not settle to served_only within {timeout_s}s")


def test_i2_to_sp2_daemon_upgrade_replays_read_acks_and_marks_store4_attempts_unknown(
    frozen_i2_installed_env: InstalledEnv,
    inc2_installed_env: InstalledEnv,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """R1+R2 live two-daemon upgrade: I2 wheel commits -> SP2 wheel replays 6-key ReadAcks & decodes unknown level."""
    from superbrain.core.kernel import ARTIFACT_LEVEL_UNKNOWN, is_verified_l1_send
    from superbrain.storage.send_attempts import read_send_attempt_row

    tpl = get_shared_t7_transport_template()
    assert tpl.ws_a is not None
    ws_a = tpl.ws_a
    upg_dir = _make_trusted_session_dir("i2-sp2-upgrade-", tmp_path_factory)
    try:
        data_root = upg_dir / "data"
        clone_owner_only_tree(tpl.root, data_root)
        os_adapters().permissions.secure_directory(data_root)

        cfg_path = write_daemon_config_file(
            upg_dir / "daemon-config.json",
            data_root=data_root,
            expected_store_id=tpl.store_id,
            cert_path=tpl.tls.cert_path,
            key_path=tpl.tls.key_path,
        )
        ca_path = write_ca_file(upg_dir / "ca.pem", tpl.tls.ca_cert_path.read_bytes())
        cred_path = write_credential_file(upg_dir / "cred.txt", tpl.cred.token)
        profile_path, _ = write_client_profile_file(
            upg_dir / "profile.json",
            endpoint_path=data_root / "endpoint.json",
            expected_store_id=tpl.store_id,
            ca_file=ca_path,
            leaf_cert_sha256=tpl.tls.leaf_cert_sha256,
            credential_file=cred_path,
            workspace={
                "alias": ws_a.alias,
                "checkout_path": str(ws_a.checkout_path),
                "expected_workspace_id": ws_a.repo_id,
                "expected_checkout_id": ws_a.checkout_id,
            },
        )
        runner_script = upg_dir / "upgrade_domain_runner.py"
        runner_script.write_text(_UPGRADE_DOMAIN_SCRIPT.lstrip(), encoding="utf-8")
        state_path = upg_dir / "domain-state.json"
        i2_prep_log = upg_dir / "i2-prep.jsonl"
        sp2_prep_log = upg_dir / "sp2-prep.jsonl"
        client_cwd = Path(ws_a.checkout_path)
        db_path = data_root / "store" / "brain.db"

        # Phase 1: Real frozen I2 (035a4cd) daemon commits L0/L1/L2 get_artifact + I2 4-key ReadAck episode & outcome.
        i2_proc = InstalledServeProcess(
            [str(frozen_i2_installed_env.venv_python), "-I", str(runner_script),
             str(cfg_path), str(state_path), str(i2_prep_log)],
            data_root=data_root,
            cwd=upg_dir,
        )
        try:
            i2_proc.wait_ready(timeout=15.0)
            prep_res = _call_installed_mcp(
                frozen_i2_installed_env,
                script_name="brain-mcp",
                prefix_args=[],
                profile_path=profile_path,
                cwd=client_cwd,
                tool="prepare_task",
                arguments={
                    "schema_version": "2.0",
                    "workspace_hint": ws_a.alias,
                    "description": "I2 pre-upgrade commit",
                    "idempotency_key": "idem-upg-prep-0001",
                },
            )
            assert prep_res["ok"] is True
            prep_data = cast(dict[str, Any], prep_res["data"])
            task_id = str(prep_data["task_id"])
            delivery_id = str(prep_data["delivery_id"])

            receipts: list[tuple[str, str, str, str]] = []
            for idx, (art_id, lvl) in enumerate(
                (("art-upg-l1-ep", "L1"), ("art-upg-l1-out", "L1"), ("art-upg-l0", "L0"), ("art-upg-l2", "L2")),
                start=1,
            ):
                art_res = _call_installed_mcp(
                    frozen_i2_installed_env,
                    script_name="brain-mcp",
                    prefix_args=[],
                    profile_path=profile_path,
                    cwd=client_cwd,
                    tool="get_artifact",
                    arguments={
                        "schema_version": "2.0",
                        "workspace_id": ws_a.repo_id,
                        "task_id": task_id,
                        "artifact_id": art_id,
                        "revision": 1,
                        "level": lvl,
                        "idempotency_key": f"idem-upg-art-{idx:04d}",
                    },
                )
                assert art_res["ok"] is True
                art_data = cast(dict[str, Any], art_res["data"])
                rcpt = str(art_data["served_receipt_id"])
                dig = str(cast(list[dict[str, Any]], art_data["resources"])[0]["digest"])
                _wait_send_attempt_served(db_path, rcpt)
                receipts.append((art_id, lvl, rcpt, dig))

            receipt_ep, digest_ep = receipts[0][2], receipts[0][3]
            receipt_out, digest_out = receipts[1][2], receipts[1][3]

            legacy_ack_ep: dict[str, Any] = {
                "served_receipt_id": receipt_ep,
                "task_id": task_id,
                "revision": 1,
                "resource_digests": [{"name": "L1.md", "digest": digest_ep}],
            }
            ep_args_i2: dict[str, Any] = {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": task_id,
                "session_id": "sess-upg-0001",
                "evidence": [{"kind": "context", "data": {"step": "i2-commit"}}],
                "read_acks": [legacy_ack_ep],
                "idempotency_key": "idem-upg-ep-00001",
            }
            ep_res_i2 = _call_installed_mcp(
                frozen_i2_installed_env,
                script_name="brain-mcp",
                prefix_args=[],
                profile_path=profile_path,
                cwd=client_cwd,
                tool="submit_episode",
                arguments=ep_args_i2,
            )
            assert ep_res_i2["ok"] is True
            i2_ep_data = cast(dict[str, Any], ep_res_i2["data"])

            legacy_ack_out: dict[str, Any] = {
                "served_receipt_id": receipt_out,
                "task_id": task_id,
                "revision": 1,
                "resource_digests": [{"name": "L1.md", "digest": digest_out}],
            }
            out_args_i2: dict[str, Any] = {
                "schema_version": "2.0",
                "workspace_id": ws_a.repo_id,
                "delivery_id": delivery_id,
                "outcome": "success",
                "applied_refs": [{"kind": "skill", "id": "art-upg-l1-out", "revision": 1, "digest": digest_out}],
                "read_acks": [legacy_ack_out],
                "idempotency_key": "idem-upg-out-0001",
            }
            out_res_i2 = _call_installed_mcp(
                frozen_i2_installed_env,
                script_name="brain-mcp",
                prefix_args=[],
                profile_path=profile_path,
                cwd=client_cwd,
                tool="record_outcome",
                arguments=out_args_i2,
            )
            assert out_res_i2["ok"] is True
            i2_out_data = cast(dict[str, Any], out_res_i2["data"])
        finally:
            i2_proc.close()

        # Verify pre-upgrade I2 store4 send attempts all read on SP2 as level='unknown' (NOT 'L1') & ineligible.
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            for _art_id, _lvl, rcpt, _dig in receipts:
                att = read_send_attempt_row(conn, rcpt)
                assert att is not None
                assert att.level == ARTIFACT_LEVEL_UNKNOWN
                assert is_verified_l1_send(att) is False
            counts_before = {
                tbl: int(conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0])
                for tbl in ("idempotency", "ledger", "artifact_read_ack")
            }
        assert counts_before["artifact_read_ack"] == 2

        # Phase 2: Boot SP2 wheel daemon on SAME data_root; lost-ACK SP2 6-key replays succeed with 0 mutations.
        sp2_proc = InstalledServeProcess(
            [str(inc2_installed_env.venv_python), "-I", str(runner_script),
             str(cfg_path), str(state_path), str(sp2_prep_log)],
            data_root=data_root,
            cwd=upg_dir,
        )
        try:
            sp2_proc.wait_ready(timeout=15.0)
            sp2_ack_ep = {**legacy_ack_ep, "artifact_id": "art-upg-l1-ep", "revision_epoch": 0}
            sp2_ep_args = {**ep_args_i2, "read_acks": [sp2_ack_ep]}
            ep_replay = _call_installed_mcp(
                inc2_installed_env,
                script_name="brain-mcp",
                prefix_args=[],
                profile_path=profile_path,
                cwd=client_cwd,
                tool="submit_episode",
                arguments=sp2_ep_args,
            )
            assert ep_replay["ok"] is True
            assert ep_replay["data"] == i2_ep_data

            sp2_ack_out = {**legacy_ack_out, "artifact_id": "art-upg-l1-out", "revision_epoch": 0}
            sp2_out_args = {**out_args_i2, "read_acks": [sp2_ack_out]}
            out_replay = _call_installed_mcp(
                inc2_installed_env,
                script_name="brain-mcp",
                prefix_args=[],
                profile_path=profile_path,
                cwd=client_cwd,
                tool="record_outcome",
                arguments=sp2_out_args,
            )
            assert out_replay["ok"] is True
            assert out_replay["data"] == i2_out_data

            tamper_dig = digest_bytes(b"tampered upgrade payload\n")
            ep_tampers = (
                {**ep_args_i2, "read_acks": [{**sp2_ack_ep, "artifact_id": "art-wrong"}]},
                {**ep_args_i2, "read_acks": [{**sp2_ack_ep, "revision_epoch": 1}]},
                {
                    **ep_args_i2,
                    "read_acks": [{**sp2_ack_ep, "resource_digests": [{"name": "L1.md", "digest": tamper_dig}]}],
                },
                {**sp2_ep_args, "evidence": [{"kind": "context", "data": {"step": "tampered"}}]},
            )
            for bad_ep in ep_tampers:
                err_ep = _call_installed_mcp(
                    inc2_installed_env,
                    script_name="brain-mcp",
                    prefix_args=[],
                    profile_path=profile_path,
                    cwd=client_cwd,
                    tool="submit_episode",
                    arguments=bad_ep,
                )
                assert err_ep["ok"] is False
                assert cast(dict[str, Any], err_ep["error"])["code"] == ErrorCode.IDEMPOTENCY_CONFLICT.value

            out_tampers = (
                {**out_args_i2, "read_acks": [{**sp2_ack_out, "artifact_id": "art-wrong"}]},
                {**out_args_i2, "read_acks": [{**sp2_ack_out, "revision_epoch": 1}]},
                {
                    **out_args_i2,
                    "read_acks": [{**sp2_ack_out, "resource_digests": [{"name": "L1.md", "digest": tamper_dig}]}],
                },
                {**sp2_out_args, "outcome": "failure"},
            )
            for bad_out in out_tampers:
                err_out = _call_installed_mcp(
                    inc2_installed_env,
                    script_name="brain-mcp",
                    prefix_args=[],
                    profile_path=profile_path,
                    cwd=client_cwd,
                    tool="record_outcome",
                    arguments=bad_out,
                )
                assert err_out["ok"] is False
                assert cast(dict[str, Any], err_out["error"])["code"] == ErrorCode.IDEMPOTENCY_CONFLICT.value
        finally:
            sp2_proc.close()

        assert not sp2_prep_log.exists() or sp2_prep_log.read_text(encoding="utf-8").strip() == ""
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            counts_after = {
                tbl: int(conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0])
                for tbl in ("idempotency", "ledger", "artifact_read_ack")
            }
        assert counts_after == counts_before
    finally:
        _cleanup_dir(upg_dir)
    assert not upg_dir.exists()
