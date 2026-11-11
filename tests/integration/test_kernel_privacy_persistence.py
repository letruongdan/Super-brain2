"""T8.4 privacy boundaries with the installed shim, real daemon and live SQLite/CAS."""

from __future__ import annotations

import base64
import logging
import mmap
import re
import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.cli_api import _loopback_server
from superbrain.cli_api._server_http import read_admitted_tool_command
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DAEMON_QUEUE_DEPTH,
    TOTAL_REQUEST_BUDGET_NS,
    JobErrorCode,
    JobSpec,
    JobState,
    ObjectRef,
    RepoFlags,
    Scope,
    ToolCommand,
    WorkerFailed,
    WorkspaceBinding,
)
from superbrain.storage.backup import create_store_backup
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobContext, JobExecutor, JobHandlerError, WorkItem
from tests.integration.test_kernel_receipts import intercept_sends
from tests.support import inc2_t8_harness
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    get_shared_t7_transport_template,
    mcp_call_frame,
    mcp_init_frames,
)
from tests.support.inc2_fixture import InstalledEnv, enqueue_job, kernel_job_service
from tests.support.inc2_t8_domain import ART_ALLOWED, L1_CONTENT
from tests.support.inc2_t8_harness import SendAttemptTracker, clone_template_root, count, shim_profile, store_rows
from tests.support.inc2_t8_privacy import EPISODE_KIND, EPISODE_TABLE, PrivacyDomainProxy, episode_args
from tests.support.inc2_t8_privacy import privacy_store_extensions as store_extensions
from tests.support.inc2_transport import TransportHarness, TransportTemplate
from tests.support.kernel_auth import make_bootstrap_auth

WAIT_S = 5.0
SAFE = "oak ribbon evidence t8"
MANUAL_SAFE = "maple notebook manual control"
CANARIES = {
    "subtree": "t8-hidden-subtree-wal",
    "key": "t8PrivateKeyCanary",
    "fixed": "t8FixedValueCanary",
    "entropy": "Q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5",
    "private": "t8-privé-café-wal",
    "path": "t8-blocked-path-canary",
    "url": "t8-url-canary",
    "rejected": "t8-rejected-wire-canary",
    "handler": "t8-handler-error-canary",
}
DATABASES = ("store/brain.db", "policy/policy.db")


class CapturedMcpSession(InstalledMcpPipeSession):
    def __init__(self, env: InstalledEnv, profile: Path, *, cwd: Path) -> None:
        self.stdout_bytes = bytearray()
        super().__init__(env, "brain-mcp", ("--profile", str(profile)), cwd=cwd)

    def _read_stdout_lines(self) -> None:
        try:
            while line := self._stdout.readline():
                self.stdout_bytes.extend(line)
                self._lines.put(line)
        finally:
            self._lines.put(b"")


class Shim:
    def __init__(self, pipe: CapturedMcpSession) -> None:
        self._pipe = pipe
        init, self._initialized = mcp_init_frames(1)
        assert pipe.send_frames_and_expect_response([init], timeout=WAIT_S)["id"] == 1
        self._id = 1

    def call(self, tool: str, args: dict[str, JsonValue]) -> dict[str, Any]:
        self._id += 1
        frames = [mcp_call_frame(self._id, tool, args)]
        if self._id == 2:
            frames.insert(0, self._initialized)
        reply = self._pipe.send_frames_and_expect_response(frames, timeout=WAIT_S)
        assert reply["id"] == self._id
        return cast(dict[str, Any], reply["result"])


@contextmanager
def _shim(
    h: TransportHarness, env: InstalledEnv, binding: WorkspaceBinding, name: str, token: str,
    observed: dict[str, bytes],
) -> Iterator[Shim]:
    profile = shim_profile(h, binding, name, token)
    pipe = CapturedMcpSession(env, profile, cwd=Path(binding.checkout_path))
    with pipe:
        yield Shim(pipe)
        rc, stderr = pipe.finish()
        assert rc == 0
        observed[f"{name} stdout"] = bytes(pipe.stdout_bytes)
        observed[f"{name} stderr"] = stderr


def _success(reply: dict[str, Any]) -> dict[str, Any]:
    assert reply["isError"] is False, reply
    structured = cast(dict[str, Any], reply["structuredContent"])
    assert structured["ok"] is True
    return cast(dict[str, Any], structured["data"])


def _error(reply: dict[str, Any], expected: ErrorCode) -> None:
    assert reply["isError"] is True, reply
    assert reply["structuredContent"]["error"]["code"] == expected.value, reply
    assert "data" not in reply["structuredContent"], reply


@pytest.fixture
def template() -> TransportTemplate:
    return get_shared_t7_transport_template()


def _binding(template: TransportTemplate) -> WorkspaceBinding:
    assert template.ws_a is not None
    return template.ws_a


@contextmanager
def _privacy_daemon(
    monkeypatch: pytest.MonkeyPatch, template: TransportTemplate, root: Path, *, manual_submission: bool = True
) -> Iterator[tuple[TransportHarness, Runtime, PrivacyDomainProxy, SendAttemptTracker]]:
    proxy = PrivacyDomainProxy()
    captured: list[Runtime] = []

    def ready_runtime(rt: Runtime) -> None:
        captured.append(rt)
        proxy.inner.repo_flags_overrides[_binding(template).repo_id] = RepoFlags(manual_submission=manual_submission)

    with monkeypatch.context() as mp:
        mp.setattr(inc2_t8_harness, "FixtureDomainProxy", lambda: proxy)
        mp.setattr(inc2_t8_harness, "fixture_store_extensions", store_extensions)
        hooks = DaemonTestHooks(before_job_recover=ready_runtime)
        with inc2_t8_harness.fixture_daemon(mp, template, root, hooks=hooks) as (h, _, tracker):
            (rt,) = captured
            yield h, rt, proxy, tracker


def _external_connections(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempted: list[str] = []
    original = socket.socket.connect
    resolve = socket.getaddrinfo

    def guard(host: object) -> None:
        if host not in ("127.0.0.1", "::1", "localhost", None):
            attempted.append("external")
            raise AssertionError("fixture attempted non-loopback networking")

    def connect(sock: socket.socket, address: Any) -> None:
        if isinstance(address, tuple):
            guard(address[0])
        original(sock, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        guard(host)
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return attempted


def _prepare(shim: Shim, key: str) -> tuple[str, str]:
    result = _success(shim.call("prepare_task", _prepare_args(key)))
    return str(result["task_id"]), str(result["delivery_id"])


def _prepare_args(key: str) -> dict[str, JsonValue]:
    return {"schema_version": "2.0", "description": "fixture privacy task", "idempotency_key": key}


def _artifact(shim: Shim, binding: WorkspaceBinding, task_id: str) -> dict[str, Any]:
    return _success(shim.call("get_artifact", {
        "schema_version": "2.0",
        "workspace_id": binding.repo_id,
        "task_id": task_id,
        "artifact_id": ART_ALLOWED,
        "revision": 1,
        "level": "L1",
        "idempotency_key": "privacy-artifact-control-0001",
    }))


def _evidence(data: dict[str, JsonValue]) -> list[JsonValue]:
    return [{"kind": "fixture_evidence", "data": data}]


def _canary_evidence() -> list[JsonValue]:
    return _evidence({
        "nest": {
            "api_key": {"label": CANARIES["subtree"]},
            f"load ghp_{CANARIES['key']}abcdefghijklmnopqrstuv": "private nested record",
            "control": SAFE,
        },
        "notes": [
            f"ghp_{CANARIES['fixed']}qrsabcdefghijklmnopqr",
            CANARIES["entropy"],
            f"keep <private>{CANARIES['private']}</private> public",
            f"/home/fixture/.ssh/{CANARIES['path']}",
        ],
        "remote": f"https://user:{CANARIES['url']}@example.invalid/project",
    })


def _scan(surfaces: dict[str, bytes]) -> None:
    def unescape(match: re.Match[bytes]) -> bytes:
        return chr(int(match.group(1), 16)).encode("utf-8", errors="surrogatepass")

    for name, raw in surfaces.items():
        unescaped = re.sub(rb"\\u([a-fA-F0-9]{4})", unescape, raw)
        for label, marker in CANARIES.items():
            utf8 = marker.encode()
            patterns = (utf8, marker.encode("utf-16le"), marker.encode("utf-16be"), utf8.hex().encode())
            assert not any(pattern in raw for pattern in patterns), f"{label} canary leaked to {name}"
            assert base64.b64encode(utf8) not in raw, f"base64 {label} canary leaked to {name}"
            assert utf8 not in unescaped, f"escaped {label} canary leaked to {name}"


def _root_files(root: Path) -> dict[str, bytes]:
    paths = [root / name for name in DATABASES]
    for directory in ("store/cas", "store/staging", "backups"):
        paths.extend(path for path in (root / directory).rglob("*") if path.is_file())
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in paths}


class SyntheticJobError(JobHandlerError):
    def __str__(self) -> str:
        return CANARIES["handler"]


def _dead_letter(h: TransportHarness, rt: Runtime, template: TransportTemplate, binding: WorkspaceBinding) -> None:
    """Run three real worker attempts and let the owner apply their typed failures to the same ledger."""
    principal = template.cred.principal
    service, store = h.loop.run_owner_action(lambda: kernel_job_service(rt, h.clock)).result(timeout=WAIT_S)
    kind = "fixture.privacy_job"

    def stage() -> str:
        assert template.global_job_id is not None and template.scoped_job_id is not None
        service.cancel(template.global_job_id, principal, selected_scope=None)
        service.cancel(template.scoped_job_id, principal, selected_scope=Scope(binding.repo_id, binding.checkout_id))
        return enqueue_job(service, store, owner_id=principal.owner_id, kind=kind).job_id

    def fail(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        raise SyntheticJobError(JobErrorCode.HANDLER_FAILED, retryable=True) from RuntimeError(CANARIES["handler"])

    job_id = h.loop.run_owner_action(stage).result(timeout=WAIT_S)

    def next_item() -> WorkItem:
        lease = service.lease_next(rt.lease.epoch, h.clock.now())
        assert lease is not None and lease.job_id == job_id
        service.start(lease)
        return WorkItem(lease, service.job_spec(lease), (), h.mono_clock.now + TOTAL_REQUEST_BUDGET_NS)

    worker = JobExecutor({kind: fail}, h.mono_clock.monotonic_ns)
    worker.start()
    try:
        for attempt in (1, 2, 3):
            item = h.loop.run_owner_action(next_item).result(timeout=WAIT_S)
            assert item.lease.attempt == attempt
            worker.submit(item)
            failure = worker.next_command(WAIT_S)
            assert failure == WorkerFailed(item.lease, True, JobErrorCode.HANDLER_FAILED)
            assert isinstance(failure, WorkerFailed)
            h.loop.run_owner_action(partial(service.apply_command, failure)).result(timeout=WAIT_S)
            h.clock.advance(timedelta(seconds=2))
    finally:
        assert worker.close(timeout_s=WAIT_S)
    row = store_rows(h.data_root, "SELECT state, attempt, reason FROM p_jobs_state WHERE job_id = ?", (job_id,))
    assert row == [(JobState.DEAD_LETTER.value, 3, JobErrorCode.HANDLER_FAILED.value)]


def _live_files(rt: Runtime, root: Path) -> dict[str, bytes]:
    # This action runs on the only writer, before it closes or any checkpoint on reopen.
    with rt.store.transaction():
        snapshot: dict[str, bytes] = {}
        for name in DATABASES:
            for suffix in ("", "-wal", "-shm"):
                path = name + suffix
                try:
                    if suffix == "-shm":
                        # SQLite holds byte-range locks on Windows. Reading the mapped shared memory observes
                        # its bytes without issuing a ReadFile across that locked range.
                        with (root / path).open("rb") as source:
                            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as view:
                                snapshot[path] = view[:]
                    else:
                        snapshot[path] = (root / path).read_bytes()
                except OSError as error:
                    snapshot[f"snapshot error {path}"] = repr(error).encode()
        return snapshot


def test_privacy_canary_absent_from_durable_and_observed_outputs(
    monkeypatch: pytest.MonkeyPatch, trusted_tmp: Path, inc2_installed_env: InstalledEnv,
    template: TransportTemplate, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
) -> None:
    root = clone_template_root(template, trusted_tmp / "privacy-data")
    binding = _binding(template)
    observed: dict[str, bytes] = {}
    external = _external_connections(monkeypatch)
    caplog.set_level(logging.WARNING)
    with _privacy_daemon(monkeypatch, template, root) as (h, rt, proxy, _):
        with _shim(h, inc2_installed_env, binding, "privacy", template.cred.token, observed) as shim:
            task_id, _ = _prepare(shim, "privacy-prepare-0001")
            fresh = _success(shim.call(
                "submit_episode", episode_args(task_id, "privacy-fresh-0001", _canary_evidence())
            ))
            episode_id = str(fresh["episode_id"])
            assert len(fresh["evidence_ids"]) == 1
            art = _artifact(shim, binding, task_id)
            for resource in art["resources"]:
                data = resource["content"].encode()
                observed[f"decoded artifact {resource['name']}"] = (
                    base64.b64decode(data, validate=True) if resource["encoding"] == "base64" else data
                )
            assert any(L1_CONTENT in data for data in observed.values()), "no safe content reached the shim"

            lost = [False]

            def drop_episode(raw: bytes, real_send: Callable[[bytes], int]) -> int | None:
                if not lost[0] and b'"episode_id"' in raw:
                    lost[0] = True
                    raise BrokenPipeError("fixture lost the committed response")
                return None

            sends = intercept_sends(h, drop_episode)
            retry_args = episode_args(task_id, "privacy-response-loss-0001", _canary_evidence())
            missing = shim.call("submit_episode", retry_args)
            assert lost[0] and missing["isError"] is True
            assert missing["_meta"]["superbrain/request_may_have_run"] is True
            committed = store_rows(root, f"SELECT episode_id FROM {EPISODE_TABLE} WHERE episode_id <> ?", (episode_id,))
            ((lost_episode_id,),) = committed
            retried = _success(shim.call("submit_episode", retry_args))
            assert retried["episode_id"] == lost_episode_id and count(root, EPISODE_TABLE) == 2
            assert proxy.filtered_calls == 2, "replay should render the committed sanitized result"

            bad = _evidence({"note": "<private>" + CANARIES["rejected"]})
            _error(
                shim.call("submit_episode", episode_args(task_id, "privacy-rejected-0001", bad)),
                ErrorCode.INVALID_INPUT,
            )
            assert proxy.filtered_calls == 3 and count(root, EPISODE_TABLE) == 2
            assert len(proxy.outbox) == 2
            observed["daemon HTTP sends"] = b"".join(sends)
        _dead_letter(h, rt, template, binding)
        live = h.loop.run_owner_action(lambda: _live_files(rt, root)).result(timeout=WAIT_S)
        errors = {name: data for name, data in live.items() if name.startswith("snapshot error")}
        assert not errors, errors
        assert episode_id.encode() in live["store/brain.db-wal"], "live WAL snapshot missed the committed episode"
        assert all(live[name + "-shm"] for name in DATABASES), "live DB snapshot missed SHM"
        observed.update({f"live {path}": data for path, data in live.items()})
        payload = proxy.outbox[episode_id]
        assert SAFE.encode() in payload
        content_digest = digest_bytes(payload)
        assert store_rows(
            root, f"SELECT evidence_id, content_digest FROM {EPISODE_TABLE} WHERE episode_id = ?", (episode_id,)
        ) == [(fresh["evidence_ids"][0], content_digest)]
        ((meta,),) = store_rows(root, "SELECT meta FROM ledger WHERE kind = ? AND meta LIKE ?",
                               (EPISODE_KIND, f"%{episode_id}%"))
        assert content_digest.encode() in meta
        observed["fixture outbox"] = b"".join(proxy.outbox.values())
        backup = h.loop.run_owner_action(
            lambda: create_store_backup(rt.store, rt.os_, h.clock.now())
        ).result(timeout=WAIT_S)
        assert any(path.read_bytes() == payload for path in (root / "store" / "cas").rglob("*") if path.is_file())
        assert episode_id.encode() in (backup / "brain.db").read_bytes()
        assert any(path.read_bytes() == payload for path in backup.rglob("*") if path.is_file())
    _scan(_root_files(root))
    with _privacy_daemon(monkeypatch, template, root) as (h, rt, _, _tracker):
        h.loop.run_owner_action(rt.store.rebuild_projections).result(timeout=WAIT_S)
        assert store_rows(root, f"SELECT content_digest FROM {EPISODE_TABLE} WHERE episode_id = ?", (episode_id,)) == [
            (content_digest,)
        ]
        assert h.loop.run_owner_action(lambda: rt.store.cas.read(content_digest)).result(timeout=WAIT_S) == payload
    captured = capsys.readouterr()
    observed.update({"daemon logs": caplog.text.encode(), "test process stdout": captured.out.encode(),
                     "test process stderr": captured.err.encode()})
    assert episode_id.encode() in observed["privacy stdout"], "no raw installed-shim success frame was captured"
    _scan(observed)
    _scan(_root_files(root))
    assert external == []


@pytest.mark.parametrize("manual_submission", [False, True], ids=["metadata-only", "with-content"])
def test_manual_submission_disabled_persists_metadata_only_through_shim(
    monkeypatch: pytest.MonkeyPatch, trusted_tmp: Path, inc2_installed_env: InstalledEnv,
    template: TransportTemplate, manual_submission: bool,
) -> None:
    root = clone_template_root(template, trusted_tmp / "manual-data")
    binding = _binding(template)
    with _privacy_daemon(monkeypatch, template, root, manual_submission=manual_submission) as (h, rt, proxy, tracker):
        with _shim(h, inc2_installed_env, binding, "manual", template.cred.token, {}) as shim:
            task_id, delivery_id = _prepare(shim, "privacy-manual-prepare-0001")
            artifact = _artifact(shim, binding, task_id)
            receipt_id = str(artifact["served_receipt_id"])
            tracker.wait_settled(receipt_id, timeout=WAIT_S)
            resources = artifact["resources"]
            ref = proxy.inner.store  # store stays on the owner, only its returned reference crosses the boundary

            def artifact_digest() -> str:
                with ref.transaction() as txn:
                    (digest,) = txn.db.execute(
                        "SELECT artifact_digest FROM p_fixture_domain_artifacts WHERE artifact_id = ?", (ART_ALLOWED,)
                    ).fetchone()
                return str(digest)

            digest = h.loop.run_owner_action(artifact_digest).result(timeout=WAIT_S)
            outcome_args: dict[str, JsonValue] = {
                "schema_version": "2.0",
                "workspace_id": binding.repo_id,
                "delivery_id": delivery_id,
                "outcome": "success",
                "idempotency_key": "privacy-manual-outcome-0001",
                "applied_refs": [{"kind": "skill", "id": ART_ALLOWED, "revision": 1, "digest": digest}],
                "read_acks": [{
                    "served_receipt_id": receipt_id,
                    "task_id": task_id,
                    "revision": 1,
                    "resource_digests": [{"name": r["name"], "digest": r["digest"]} for r in resources],
                }],
            }
            episode = episode_args(task_id, "privacy-manual-episode-0001", _evidence({"note": MANUAL_SAFE}))
            first_outcome = _success(shim.call("record_outcome", outcome_args))
            assert _success(shim.call("record_outcome", outcome_args)) == first_outcome
            first_episode = _success(shim.call("submit_episode", episode))
            assert _success(shim.call("submit_episode", episode)) == first_episode
        assert first_outcome["status"] == "declared"
        assert store_rows(root, "SELECT outcome_id, applied_ref_count FROM p_fixture_domain_outcomes") == [
            (first_outcome["outcome_id"], int(manual_submission))
        ]
        assert count(root, "artifact_read_ack") == int(manual_submission)
        assert count(root, EPISODE_TABLE) == 1 and proxy.filtered_calls == 1
        if manual_submission:
            assert store_rows(root, "SELECT served_receipt_id, task_id FROM artifact_read_ack") == [
                (receipt_id, task_id)
            ]
            assert len(first_episode["evidence_ids"]) == 1
            ((held,),) = store_rows(root, f"SELECT content_digest FROM {EPISODE_TABLE}")
            payload = h.loop.run_owner_action(lambda: rt.store.cas.read(str(held))).result(timeout=WAIT_S)
            assert MANUAL_SAFE.encode() in payload and proxy.outbox == {str(first_episode["episode_id"]): payload}
        else:
            assert first_episode["evidence_ids"] == [] and proxy.outbox == {}
            assert store_rows(root, f"SELECT evidence_id, content_digest FROM {EPISODE_TABLE}") == [(None, None)]
    assert any(MANUAL_SAFE.encode() in raw for raw in _root_files(root).values()) is manual_submission


def test_health_stays_shallow_under_owner_saturation(
    monkeypatch: pytest.MonkeyPatch, trusted_tmp: Path, inc2_installed_env: InstalledEnv, template: TransportTemplate,
) -> None:
    root = clone_template_root(template, trusted_tmp / "shallow-data")
    binding = _binding(template)
    scope = Scope(binding.repo_id, binding.checkout_id)
    external = _external_connections(monkeypatch)
    with _privacy_daemon(monkeypatch, template, root) as (h, rt, proxy, _tracker):
        with _shim(h, inc2_installed_env, binding, "saturated-health", template.cred.token, {}) as shim:
            task_id, _ = _prepare(shim, "privacy-health-prepare-0001")
            parked, release = threading.Event(), threading.Event()

            def hold(_tx: object) -> None:
                parked.set()
                assert release.wait(timeout=WAIT_S), "owner barrier never released"

            proxy.inner.before_apply_hook = hold
            deadline = h.mono_clock.now + TOTAL_REQUEST_BUDGET_NS
            blocker = h.loop.submit(ToolCommand(
                "prepare_task", _prepare_args("privacy-health-commit-0001") | {
                    "workspace_id": binding.repo_id, "checkout_id": binding.checkout_id,
                }, token=template.cred.token, selected_scope=scope,
            ), deadline)

            def submit_slot(index: int) -> Any:
                args = episode_args(task_id, f"privacy-health-slot-{index:04d}", [])
                return h.loop.submit(ToolCommand(
                    "submit_episode", args, token=template.cred.token, selected_scope=scope,
                ), deadline)

            try:
                assert parked.wait(timeout=WAIT_S), "owner never entered the committing write"
                waiting = [submit_slot(index) for index in range(DAEMON_QUEUE_DEPTH)]
                assert all(not future.done() for future in waiting)
                overflow = submit_slot(DAEMON_QUEUE_DEPTH).result(timeout=WAIT_S)
                assert overflow["error"]["code"] == ErrorCode.STORE_BUSY.value

                read_ns: list[int] = []
                write_ns: list[int] = []
                db_opens: list[str] = []
                read_tool = read_admitted_tool_command
                connect = cast(Callable[..., sqlite3.Connection], sqlite3.connect)

                def read(*args: Any, **kwargs: Any) -> Any:
                    read_ns.append(time.perf_counter_ns())
                    return read_tool(*args, **kwargs)

                def sent(raw: bytes, send: Callable[[bytes], int]) -> int:
                    count = send(raw)
                    write_ns.append(time.perf_counter_ns())
                    return count

                def open_db(*args: Any, **kwargs: Any) -> sqlite3.Connection:
                    db_opens.append("opened")
                    return connect(*args, **kwargs)

                intercept_sends(h, sent)
                with monkeypatch.context() as monitor:
                    monitor.setattr(sqlite3, "connect", open_db)
                    monitor.setattr(_loopback_server, "read_admitted_tool_command", read)
                    health = _success(shim.call("get_health", {"schema_version": "2.0", "deep": False}))
                assert len(read_ns) == 1 and 0 < write_ns[-1] - read_ns[0] <= TOTAL_REQUEST_BUDGET_NS
                assert db_opens == [] and not release.is_set() and not blocker.done()
                assert all(not future.done() for future in waiting), "shallow health drained the owner queue"
                assert health["ready"] is True
                assert (health["store_id"], health["writer_epoch"]) == (
                    template.store_id, h.ready.endpoint.writer_epoch
                )
                assert (health["schema_version"], health["policy_schema_version"]) == (4, 3)
            finally:
                release.set()
            assert blocker.result(timeout=WAIT_S)["ok"] is True
            assert all(future.result(timeout=WAIT_S)["ok"] is True for future in waiting)

            def totals() -> tuple[int, ...]:
                return tuple(count(root, table) for table in (
                    "ledger", "p_fixture_domain_deliveries", EPISODE_TABLE, "p_jobs_state", "idempotency",
                ))

            before = totals()
            _error(shim.call("get_health", {
                "schema_version": "2.0", "deep": True, "idempotency_key": "privacy-deep-health-0001",
            }), ErrorCode.CAPABILITY_UNAVAILABLE)
            assert totals() == before

        cred_b = template.cred_b
        assert cred_b is not None
        generation = h.loop.run_owner_action(rt.policy.trust_generation).result(timeout=WAIT_S)
        authorization = make_bootstrap_auth(
            store_id=template.store_id, action="credential_revoke", subject_id=cred_b.credential_id,
            trust_generation=generation, expires_at=h.clock.now() + timedelta(hours=1),
        )
        h.loop.revoke_credential(cred_b.credential_id, authorization).result(timeout=WAIT_S)
        with _shim(h, inc2_installed_env, binding, "revoked-health", cred_b.token, {}) as revoked:
            _error(revoked.call("get_health", {"schema_version": "2.0"}), ErrorCode.UNAUTHENTICATED)
    assert external == []
