"""Session-scoped test fixtures for SP1 Increment 2 (wheel install & sample TLS material).

Per Preflight Ruling 5 and the F4 early timing budget, building/installing the wheel into an
isolated virtual environment and generating a sample loopback CA + leaf certificate happen at
most once per pytest session rather than per test. No fixture flags exist in ``src/superbrain``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import shutil
import subprocess
import sys
import uuid
import warnings
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from superbrain.application.jobs import JobService
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import digest_bytes
from superbrain.core.kernel import JobRef, JobSpec, ObjectRef, UsageRecord
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.runtime import Runtime, admit_existing_pair, open_runtime, open_runtime_under_lease
from superbrain.workers.executor import JobContext, JobHandler

if TYPE_CHECKING:
    from tests.support.inc2_kernel_domain import (
        FIXTURE_DOMAIN_KINDS as FIXTURE_DOMAIN_KINDS,
    )
    from tests.support.inc2_kernel_domain import (
        FixtureDeliveryRefSpec as FixtureDeliveryRefSpec,
    )
    from tests.support.inc2_kernel_domain import (
        FixtureDomainProjection as FixtureDomainProjection,
    )
    from tests.support.inc2_kernel_domain import (
        FixtureKernelDomain as FixtureKernelDomain,
    )
    from tests.support.inc2_kernel_domain import (
        FixtureResourceSpec as FixtureResourceSpec,
    )
    from tests.support.inc2_kernel_domain import (
        fixture_store_extensions as fixture_store_extensions,
    )
    from tests.support.inc2_kernel_domain import (
        validate_response_envelope as validate_response_envelope,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_SCHEMA_PATH = REPO_ROOT / "schemas" / "mcp-tools-v2.json"


@dataclass(frozen=True)
class InstalledEnv:
    """Isolated virtual environment containing the built ``super-brain2`` wheel."""

    venv_dir: Path
    venv_python: Path
    wheel_path: Path
    source_schema_path: Path
    source_schema_sha256: str


@dataclass(frozen=True)
class SampleTlsMaterial:
    """Reusable session-scoped loopback CA and leaf certificate for ``127.0.0.1``."""

    directory: Path
    ca_cert_path: Path
    ca_key_path: Path
    leaf_cert_path: Path
    leaf_key_path: Path
    leaf_cert_sha256: str


def _make_trusted_session_dir(prefix: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard

        root = Path(os.environ["LOCALAPPDATA"]) / "superbrain-tests" / f"{prefix}-{uuid.uuid4()}"
        root.mkdir(parents=True)
        WindowsPermissionGuard().secure_directory(root)
        return root
    root = tmp_path_factory.mktemp(prefix)
    root.chmod(0o700)
    return root


def _cleanup_dir(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except OSError as err:
        warnings.warn(f"could not remove session directory {path}: {err}", stacklevel=1)


def _clean_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    return env


def _run_checked(
    cmd: list[str],
    *,
    cwd: Path,
    extra_env: Mapping[str, str] | None = None,
) -> str:
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


@contextmanager
def open_inc2_installed_env(scratch: Path) -> Iterator[InstalledEnv]:
    """Build and install a wheel in caller-owned scratch, reusable by the explicit benchmark."""
    assert SOURCE_SCHEMA_PATH.is_file(), f"missing canonical schema file: {SOURCE_SCHEMA_PATH}"
    source_schema_sha256 = hashlib.sha256(SOURCE_SCHEMA_PATH.read_bytes()).hexdigest()

    dist_dir = scratch / "dist"
    dist_dir.mkdir()
    venv_dir = scratch / "venv"

    _run_checked(
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
            str(REPO_ROOT),
        ],
        cwd=REPO_ROOT,
    )
    wheels = sorted(dist_dir.glob("super_brain2-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly 1 built super_brain2 wheel, found {wheels}")
    wheel_path = wheels[0]

    _run_checked(
        [
            "uv",
            "sync",
            "--project",
            str(REPO_ROOT),
            "--locked",
            "--offline",
            "--no-dev",
            "--no-install-project",
            "--link-mode=copy",
            "--python",
            sys.executable,
        ],
        cwd=REPO_ROOT,
        extra_env={"UV_PROJECT_ENVIRONMENT": str(venv_dir)},
    )
    venv_python = venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"

    _run_checked(
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

    yield InstalledEnv(
        venv_dir=venv_dir,
        venv_python=venv_python,
        wheel_path=wheel_path,
        source_schema_path=SOURCE_SCHEMA_PATH,
        source_schema_sha256=source_schema_sha256,
    )


@pytest.fixture(scope="session")
def inc2_installed_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[InstalledEnv]:
    """Build the project wheel once per session and clean its isolated scratch afterwards."""
    scratch = _make_trusted_session_dir("inc2-wheel", tmp_path_factory)
    try:
        with open_inc2_installed_env(scratch) as installed:
            yield installed
    finally:
        _cleanup_dir(scratch)


@pytest.fixture(scope="session")
def inc2_tls_material(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SampleTlsMaterial]:
    """Generate a reusable session-scoped CA + ``127.0.0.1`` leaf certificate using ``cryptography``."""
    directory = _make_trusted_session_dir("inc2-tls", tmp_path_factory)
    try:
        now = dt.datetime.now(dt.UTC)

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "superbrain-inc2-test-ca")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        ca_cert_path = directory / "ca.pem"
        ca_key_path = directory / "ca-key.pem"
        leaf_cert_path = directory / "leaf.pem"
        leaf_key_path = directory / "leaf-key.pem"

        ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        ca_key_path.write_bytes(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        leaf_cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        leaf_key_path.write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        if sys.platform != "win32":
            for key_file in (ca_key_path, leaf_key_path):
                key_file.chmod(0o600)

        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        leaf_sha256 = hashlib.sha256(leaf_der).hexdigest()

        yield SampleTlsMaterial(
            directory=directory,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            leaf_cert_path=leaf_cert_path,
            leaf_key_path=leaf_key_path,
            leaf_cert_sha256=leaf_sha256,
        )
    finally:
        _cleanup_dir(directory)


# --- Task 5 fixture job handler and job-runtime helpers (registered only from tests) ---------------------------

FIXTURE_JOB_KIND = "fixture.echo"
"""Job kind of the test-only fixture handler; the production worker registry never contains it."""
FIXTURE_USAGE = UsageRecord(amount="0.25", complete=True)


def fixture_job_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
    """Settle every reserved invocation with ``FIXTURE_USAGE`` and return one safe ref to the payload digest."""
    for invocation_id in ctx.invocation_ids:
        ctx.report_usage(invocation_id, FIXTURE_USAGE)
    return (ObjectRef(kind="fixture_result", id=ctx.lease.job_id, revision=1, digest=digest_bytes(spec.payload)),)


def fixture_job_registry() -> Mapping[str, JobHandler]:
    """The capability registry a test runner injects to execute the fixture job (never production)."""
    return {FIXTURE_JOB_KIND: fixture_job_handler}


def open_kernel_job_runtime(root: Path, os_: OsAdapters) -> Runtime:
    """A fresh kernel store opened with the composition projections (workspace + Task 5 job reducers)."""
    handlers, kinds = kernel_store_extensions()
    return open_runtime(
        root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )


def reopen_kernel_job_runtime(root: Path, store_id: str, os_: OsAdapters) -> Runtime:
    """Reopen an existing kernel store under a new writer lease: a new ``writer_epoch`` (a killed daemon restart)."""
    handlers, kinds = kernel_store_extensions()
    return open_runtime_under_lease(
        admit_existing_pair(root, store_id, os_, purpose="serve"), handlers=handlers, kinds=kinds
    )


def kernel_job_service(
    rt: Runtime, clock: Clock, *, cancel_signal: Callable[[str], None] | None = None
) -> tuple[JobService, StagedKernelStore]:
    """A ``JobService`` over the admitted ``(store, policy)`` pair of ``rt`` at its current writer epoch."""
    store = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
    service = JobService(store, store, rt.policy, clock, writer_epoch=rt.lease.epoch, cancel_signal=cancel_signal)
    return service, store


def enqueue_job(
    service: JobService,
    store: StagedKernelStore,
    *,
    owner_id: str,
    payload: bytes = b"fixture payload",
    kind: str = FIXTURE_JOB_KIND,
    repo_id: str | None = None,
    checkout_id: str | None = None,
) -> JobRef:
    """Stage ``payload`` outside the transaction, then enqueue it in its own caller transaction."""
    spec = JobSpec(kind=kind, owner_id=owner_id, payload=payload, repo_id=repo_id, checkout_id=checkout_id)
    store.stage_blob(payload)
    return store.transact(lambda tx: service.enqueue(tx, spec))


_KERNEL_DOMAIN_EXPORTS = frozenset(
    {
        "FIXTURE_DOMAIN_KINDS",
        "FixtureDeliveryRefSpec",
        "FixtureDomainProjection",
        "FixtureKernelDomain",
        "FixtureResourceSpec",
        "fixture_store_extensions",
        "validate_response_envelope",
    }
)


def __getattr__(name: str) -> object:
    if name in _KERNEL_DOMAIN_EXPORTS:
        from tests.support import inc2_kernel_domain

        return getattr(inc2_kernel_domain, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
