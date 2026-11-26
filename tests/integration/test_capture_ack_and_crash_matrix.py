"""SP2-2 wheel E2E integration: auth/digest/privacy/CAS/policy/source/ACK/gaps/migration/crash."""

from __future__ import annotations

import contextlib
import json
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.composition.daemon_entry import (
    BoundLoopbackListener,
    DaemonTestHooks,
    create_daemon_owner_loop,
)
from superbrain.core._kernel_approval import Layer2State
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CAPABILITY_OPERATOR_CLI,
    Call,
    CallContext,
    CaptureBatchCommand,
    CaptureProducerBinding,
    DaemonConfig,
    PrivateRequestAuth,
    ToolCommand,
    parse_canonical_utc,
)
from superbrain.core.wire import load_catalog
from superbrain.storage.cas import RetentionClass, active_held_digests, held_digests
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import is_uuid
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import read_restore_epoch
from superbrain.storage.runtime import admit_existing_pair
from superbrain.storage.schema import SchemaInfo, code_version, read_schema_info
from superbrain.storage.sqlite import open_readonly
from tests.support.clock import FakeClock
from tests.support.crash_cases import KernelCrashContext
from tests.support.inc2_cli import (
    clean_installed_subprocess_env,
    get_shared_t7_transport_template,
    run_installed_command,
    write_daemon_config_file,
)
from tests.support.inc2_fixture import InstalledEnv, open_cloned_runtime
from tests.support.inc2_transport import (
    FakeMonotonicClock,
    TransportHarness,
    TransportTestDomain,
    clone_owner_only_tree,
    open_test_loopback_transport,
    read_raw_http_response,
)
from tests.support.kernel_auth import seed_principal_and_credential, seed_repo_grant
from tests.support.sp2_crash_cases import (
    SP2_2_CRASH_CASES,
    SP2_3_CRASH_CASES,
    SP2_4_CRASH_CASES,
    SP22CrashCase,
    run_sp2_2_crash_case,
    run_sp2_2_omission_checks,
    run_sp2_3_crash_case,
    run_sp2_4_crash_case,
)

_WAIT_S = 20.0


def _publish_auth_overlay(session: Any, snap: Any, updates: dict[str, Any]) -> None:
    current = session.auth_gate.current()
    merged = dict(snap.credentials)
    if current is not None:
        for cid, prev in current.auth.credentials.items():
            if cid in merged:
                merged[cid] = replace(
                    merged[cid],
                    capabilities=prev.capabilities,
                    capture_binding=prev.capture_binding,
                )
    merged.update(updates)
    session.auth_gate.publish(replace(snap, credentials=merged))


def _setup_capture_producer(h: Any, *, harness_id: str, stream: str, repo_id: str, checkout_id: str) -> Any:
    session: Any = h.loop._session
    assert session is not None
    rt = session._rt
    seeded = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id=harness_id, machine_id="m-1")
    seed_repo_grant(rt.policy, principal_id=seeded.principal.principal_id, repo_id=repo_id, owner_id="dan")
    snap = rt.policy.snapshot()
    rec = replace(
        snap.credentials[seeded.credential_id],
        capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
        capture_binding=CaptureProducerBinding(producer_stream=stream, repo_id=repo_id, checkout_id=checkout_id),
    )
    _publish_auth_overlay(session, snap, {seeded.credential_id: rec})
    return seeded


def _setup_capture_and_cli(h: Any, ws_a: Any, *, stream: str) -> tuple[Any, Any]:
    out: list[tuple[Any, Any]] = []

    def _act() -> None:
        cap = _setup_capture_producer(
            h, harness_id="claude-code", stream=stream, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id
        )
        session: Any = h.loop._session
        assert session is not None
        rt = session._rt
        cli = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="operator-cli", machine_id="m-1")
        seed_repo_grant(rt.policy, principal_id=cli.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        snap = rt.policy.snapshot()
        cli_rec = replace(snap.credentials[cli.credential_id], capabilities=frozenset({CAPABILITY_OPERATOR_CLI}))
        _publish_auth_overlay(session, snap, {cli.credential_id: cli_rec})
        out.append((cap, cli))

    h.loop.run_owner_action(_act).result(timeout=_WAIT_S)
    return out[0]


def _get_health(h: Any, token: str, *, deep: bool = False) -> dict[str, Any]:
    client = h.open_client()
    args: dict[str, Any] = {"schema_version": "2.0", "deep": deep}
    if deep:
        args["idempotency_key"] = f"sp22-health-{new_id()}"
    res = client.call(
        h.make_target(),
        ToolCommand(
            tool="get_health",
            arguments=args,
            token=token,
            selected_scope=None,
        ),
    )
    assert res["ok"] is True, res
    data = res["data"]
    assert isinstance(data, dict)
    return data


def _raw_post_capture(h: Any, token: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    ep = h.ready.endpoint
    ca_pem = h.tls.ca_cert_path.read_text(encoding="utf-8")
    raw_bytes = canonical_json(body)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with socket.create_connection((ep.host, ep.port), timeout=2.0) as raw, ctx.wrap_socket(
        raw, server_hostname="127.0.0.1"
    ) as tls_sock:
        tls_sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {ep.host}:{ep.port}\r\n\r\n".encode("ascii"))
        assert b"200 OK" in read_raw_http_response(tls_sock)
        req = (
            f"POST /v2/capture/events HTTP/1.1\r\n"
            f"Host: {ep.host}:{ep.port}\r\nAuthorization: Bearer {token}\r\n"
            f"X-Store-Id: {ep.store_id}\r\nX-Writer-Epoch: {ep.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {ep.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(raw_bytes)}\r\n\r\n"
        ).encode("ascii") + raw_bytes
        tls_sock.sendall(req)
        resp = read_raw_http_response(tls_sock)
    head, _, data = resp.partition(b"\r\n\r\n")
    status = int(head.decode("iso-8859-1").split("\r\n")[0].split(" ")[1])
    return status, json.loads(data.decode())


def _ev_dict(seq: int, stream: str, payload: dict[str, Any], **extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "event_id": f"ev-{stream}-{seq}",
        "producer_stream": stream,
        "sequence": seq,
        "harness_id": "claude-code",
        "kind": "tool_post",
        "recorded_at": f"2026-11-21T12:00:{seq:02d}Z",
        "payload": payload,
    }
    data.update(extra)
    return data


def test_capture_auth_scope_privacy_cas_policy_and_source_attribution() -> None:
    from superbrain.cli_api.capture_client import CaptureClient

    tpl = get_shared_t7_transport_template()
    dan, ws_a, ws_b = tpl.dan, tpl.ws_a, tpl.ws_b
    assert dan is not None and ws_a is not None and ws_b is not None
    domain = TransportTestDomain(ws_a=ws_a)
    stream = "claude-stream-a"

    with open_test_loopback_transport(tpl, name="sp22-ingest", domain=domain) as h:
        cap_cred, _cli_cred = _setup_capture_and_cli(h, ws_a, stream=stream)
        cap_client = CaptureClient(h.open_client())
        target = h.make_target()
        base_dig = load_catalog().schema_digest

        # 1. Auth/scope/digest isolation
        ok_ev = _ev_dict(1, stream, {"public": "benign-summary"})
        st_mcp, b_mcp = _raw_post_capture(
            h,
            tpl.cred.token,
            {
                "producer_stream": stream,
                "repo_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "events": [ok_ev],
                "correlation_id": None,
                "schema_digest": base_dig,
            },
        )
        assert st_mcp == 409 and b_mcp["error"]["code"] == "identity_mismatch"

        with pytest.raises(BrainError) as exc_chk:
            cap_client.post_batch(
                target,
                CaptureBatchCommand(stream, ws_a.repo_id, ws_b.checkout_id, (ok_ev,), cap_cred.token),
            )
        assert exc_chk.value.code is ErrorCode.IDENTITY_MISMATCH

        st_dig, b_dig = _raw_post_capture(
            h,
            cap_cred.token,
            {
                "producer_stream": stream,
                "repo_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "events": [ok_ev],
                "correlation_id": None,
                "schema_digest": "sha256:" + ("0" * 64),
            },
        )
        assert st_dig == 426 and b_dig["error"]["code"] == "unsupported_version"

        # 2. Daemon privacy refusal fails closed BEFORE CAS/SQLite mutation without echoing raw secret
        unclosed_bait = "DAEMON_UNCLOSED_SECRET_BAIT"
        with pytest.raises(BrainError) as exc_priv:
            cap_client.post_batch(
                target,
                CaptureBatchCommand(
                    stream,
                    ws_a.repo_id,
                    ws_a.checkout_id,
                    (_ev_dict(1, stream, {"bad": f"<private>{unclosed_bait}"}),),
                    cap_cred.token,
                ),
            )
        assert exc_priv.value.code is ErrorCode.INVALID_INPUT
        assert unclosed_bait not in str(exc_priv.value)

        # 3. Daemon sanitizes <private> bait + C2 CAS blob (90d RetentionClass.EVENT_PAYLOAD) + unverified source
        secret_bait = "PRIV_TAG_SECRET_9876"
        raw_ev1 = _ev_dict(
            1,
            stream,
            {"msg": f"before <private>{secret_bait}</private> after", "safe": "visible"},
            source_metadata={"host_version": "2.1.325", "config_digest": "sha256:" + ("c" * 64)},
        )
        ack1 = cap_client.post_batch(
            target,
            CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, (raw_ev1,), cap_cred.token),
        )
        assert ack1.accepted_count == 1 and ack1.committed_event_sequences == (1,)
        assert ack1.contiguous_event_acked_through == 1

        def _inspect_after_ev1() -> tuple[dict[str, Any], bytes]:
            session: Any = h.loop._session
            assert session is not None
            rt = session._rt
            row = rt.store._db.execute(
                "SELECT source, source_verification, payload_digest FROM capture_events "
                "WHERE producer_stream = ? AND sequence = 1",
                (stream,),
            ).fetchone()
            assert row is not None
            src, sver, pdig = str(row[0]), str(row[1]), str(row[2])
            exp_row = rt.store._db.execute(
                "SELECT retention_class, holder_kind, holder_id, expires_at FROM p_cas_holders_ WHERE digest = ?",
                (pdig,),
            ).fetchone()
            assert exp_row is not None
            ret_class, holder_kind, holder_id, expires_at_raw = (
                str(exp_row[0]),
                str(exp_row[1]),
                str(exp_row[2]),
                str(exp_row[3]),
            )
            assert ret_class == RetentionClass.EVENT_PAYLOAD.value
            assert holder_kind == "event"
            assert is_uuid(holder_id)
            assert pdig in held_digests(rt.store._db, "event", holder_id)
            assert pdig in active_held_digests(rt.store._db, "event", holder_id, now=h.clock.now())
            hold_entries = rt.store._db.execute(
                "SELECT recorded_at, meta FROM ledger WHERE kind = 'cas.hold' ORDER BY sequence DESC"
            ).fetchall()
            matching_hold = [
                str(rec_at)
                for rec_at, raw_meta in hold_entries
                if (meta_obj := json.loads(bytes(raw_meta))).get("digest") == pdig
                and meta_obj.get("holder_kind") == "event"
                and meta_obj.get("holder_id") == holder_id
            ]
            assert len(matching_hold) == 1
            blob_bytes = rt.store.cas.read(pdig)
            return {
                "source": src,
                "verification": sver,
                "committed_at": matching_hold[0],
                "expires_at": expires_at_raw,
            }, blob_bytes

        meta1, blob1 = h.loop.run_owner_action(_inspect_after_ev1).result(timeout=_WAIT_S)
        assert (meta1["source"], meta1["verification"]) == ("unknown", "unverified")
        assert secret_bait.encode() not in blob1 and b"visible" in blob1
        committed_at = parse_canonical_utc(meta1["committed_at"])
        expires_at = parse_canonical_utc(meta1["expires_at"])
        assert expires_at - committed_at == timedelta(days=90)

        ro_dir = h.base_dir / "ro-inspect"
        ro_dir.mkdir(exist_ok=True)
        with contextlib.closing(open_readonly(h.data_root / "store" / "brain.db", scratch_dir=ro_dir)) as ro_conn:
            ledger_rows = ro_conn.execute("SELECT meta, refs FROM ledger").fetchall()
            assert all(
                secret_bait.encode() not in bytes(r[0]) + bytes(r[1])
                and b"visible" not in bytes(r[0]) + bytes(r[1])
                for r in ledger_rows
            )

        # 4. Verified NativeHostReceipt matching (harness_id, host_version, config_digest)
        #    -> tool_observed + verified_host
        cfg_dig = "sha256:" + ("c" * 64)

        def _set_layer2(state: Layer2State, *, host_version: str = "2.1.325", config_digest: str = cfg_dig) -> None:
            def _act() -> None:
                session: Any = h.loop._session
                assert session is not None
                session._rt.policy.set_layer2_state(
                    harness_id="claude-code",
                    host_version=host_version,
                    config_digest=config_digest,
                    state=state,
                )

            h.loop.run_owner_action(_act).result(timeout=_WAIT_S)

        def _event_source(seq: int) -> tuple[str, str]:
            def _read() -> tuple[str, str]:
                session: Any = h.loop._session
                assert session is not None
                row = session._rt.store._db.execute(
                    "SELECT source, source_verification FROM capture_events WHERE producer_stream = ? AND sequence = ?",
                    (stream, seq),
                ).fetchone()
                assert row is not None
                return str(row[0]), str(row[1])

            return h.loop.run_owner_action(_read).result(timeout=_WAIT_S)

        def _post_event(seq: int, payload: dict[str, Any], source_metadata: dict[str, Any] | None = None) -> Any:
            ev = _ev_dict(
                seq,
                stream,
                payload,
                **({"source_metadata": source_metadata} if source_metadata is not None else {}),
            )
            return cap_client.post_batch(
                target,
                CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, (ev,), cap_cred.token),
            )

        _set_layer2(Layer2State.VERIFIED)
        ack2 = _post_event(2, {"safe": "obs"}, source_metadata={"host_version": "2.1.325", "config_digest": cfg_dig})
        assert ack2.accepted_count == 1
        assert _event_source(2) == ("tool_observed", "verified_host")

        # Mismatched host_version, config_digest, or omitted source_metadata drops to unknown/unverified.
        assert (
            _post_event(
                3, {"safe": "bad-ver"}, source_metadata={"host_version": "9.9.9", "config_digest": cfg_dig}
            ).accepted_count
            == 1
        )
        assert _event_source(3) == ("unknown", "unverified")

        assert (
            _post_event(
                4,
                {"safe": "bad-dig"},
                source_metadata={"host_version": "2.1.325", "config_digest": "sha256:" + ("d" * 64)},
            ).accepted_count
            == 1
        )
        assert _event_source(4) == ("unknown", "unverified")

        assert _post_event(5, {"safe": "no-meta"}).accepted_count == 1
        assert _event_source(5) == ("unknown", "unverified")

        # UNSUPPORTED and UNKNOWN Layer2State drop subsequent matching events back to unknown/unverified.
        _set_layer2(Layer2State.UNSUPPORTED)
        assert (
            _post_event(
                6, {"safe": "unsup"}, source_metadata={"host_version": "2.1.325", "config_digest": cfg_dig}
            ).accepted_count
            == 1
        )
        assert _event_source(6) == ("unknown", "unverified")

        _set_layer2(Layer2State.UNKNOWN)
        assert (
            _post_event(
                7, {"safe": "unk"}, source_metadata={"host_version": "2.1.325", "config_digest": cfg_dig}
            ).accepted_count
            == 1
        )
        assert _event_source(7) == ("unknown", "unverified")

        # 5. Conflicting payload on already-committed sequence -> IDEMPOTENCY_CONFLICT; identical retry -> dedup
        dedup_ack = _post_event(
            2, {"safe": "obs"}, source_metadata={"host_version": "2.1.325", "config_digest": cfg_dig}
        )
        assert (dedup_ack.accepted_count, dedup_ack.deduped_count) == (0, 1)
        assert _event_source(2) == ("tool_observed", "verified_host")

        with pytest.raises(BrainError) as exc_conf:
            _post_event(2, {"safe": "DIFFERENT"})
        assert exc_conf.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

        # 6. automatic_capture=false live toggle -> accepted_count=0, 0 writes, re-enable works
        def _set_auto_capture(enabled: bool) -> None:
            def _act() -> None:
                session: Any = h.loop._session
                assert session is not None
                session._rt.policy.set_repo_policy(ws_a.repo_id, automatic_capture_enabled=enabled)

            h.loop.run_owner_action(_act).result(timeout=_WAIT_S)

        def _seq_exists(seq: int) -> bool:
            def _check() -> bool:
                session: Any = h.loop._session
                assert session is not None
                row = session._rt.store._db.execute(
                    "SELECT 1 FROM capture_events WHERE producer_stream = ? AND sequence = ?",
                    (stream, seq),
                ).fetchone()
                return row is not None

            return bool(h.loop.run_owner_action(_check).result(timeout=_WAIT_S))

        _set_auto_capture(False)
        ack_off = _post_event(8, {"safe": "ignored"})
        assert ack_off.policy_disabled is True and ack_off.accepted_count == 0
        assert 8 not in ack_off.committed_event_sequences
        assert _seq_exists(8) is False

        _set_auto_capture(True)
        ack_on = _post_event(8, {"safe": "re-enabled"})
        assert ack_on.policy_disabled is False and ack_on.accepted_count == 1
        assert ack_on.committed_event_sequences == (8,)
        assert _seq_exists(8) is True

        # Revoked capture credential -> UNAUTHENTICATED
        def _revoke_cap() -> None:
            session: Any = h.loop._session
            assert session is not None
            snap = session._rt.policy.snapshot()
            current = session.auth_gate.current()
            base_cap = (
                current.auth.credentials.get(cap_cred.credential_id, snap.credentials[cap_cred.credential_id])
                if current is not None
                else snap.credentials[cap_cred.credential_id]
            )
            revoked = replace(base_cap, revoked=True)
            _publish_auth_overlay(session, snap, {cap_cred.credential_id: revoked})

        h.loop.run_owner_action(_revoke_cap).result(timeout=_WAIT_S)
        with pytest.raises(BrainError) as exc_rev:
            _post_event(9, {"k": "v"})
        assert exc_rev.value.code is ErrorCode.UNAUTHENTICATED


@contextlib.contextmanager
def _open_persisted_loopback_transport(
    tpl: Any,
    *,
    data_root: Path,
    base_dir: Path,
    domain: Any,
) -> Iterator[TransportHarness]:
    base_dir.mkdir(parents=True, exist_ok=True)
    cfg = DaemonConfig(
        version=1,
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=tpl.tls.cert_path,
        key_path=tpl.tls.key_path,
    )
    clock = FakeClock(tpl.base_time)
    adapters = os_adapters(clock=clock)
    mono_clock = FakeMonotonicClock(1_000_000_000)
    bound_listeners: list[BoundLoopbackListener] = []
    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        monotonic_clock=mono_clock,
        domain=domain,
        job_handlers=None,
        hooks=DaemonTestHooks(),
        on_listener_bound=bound_listeners.append,
    )
    loop_started = False
    server_started = False
    stop_event = threading.Event()
    server: LoopbackServer | None = None
    try:
        ready = loop.start(cfg)
        loop_started = True
        assert len(bound_listeners) == 1
        bound = bound_listeners[0]
        server = LoopbackServer(
            listener=bound.sock,
            ssl_context=bound.ssl_context,
            ready=ready,
            owner=loop,
            monotonic_ns=mono_clock.monotonic_ns,
            stop_event=stop_event,
        )
        harness = TransportHarness(
            base_dir=base_dir,
            data_root=data_root,
            store_id=tpl.store_id,
            cred=tpl.cred,
            tls=tpl.tls,
            config=cfg,
            loop=loop,
            ready=ready,
            server=server,
            bound=bound,
            stop_event=stop_event,
            mono_clock=mono_clock,
            clock=clock,
            domain=domain,
        )
        server.start()
        server_started = True
        yield harness
    finally:
        if server is not None and server_started:
            server.quiesce(time.perf_counter() + 2.0)
        if loop_started:
            loop.stop(grace_s=2.0)
        if server is not None and server_started:
            server.finish(time.perf_counter() + 2.0)


def test_separated_ack_closed_gap_restart_health_and_producer_gap(trusted_tmp: Path) -> None:
    from superbrain.cli_api.capture_client import CaptureClient
    from superbrain.composition.capture_drain_entry import drain_outbox
    from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap
    from superbrain.storage.capture_events import KernelCaptureStore
    from superbrain.storage.outbox import OutboxSpool

    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    stream = "gap-stream-1"
    outbox_dir = trusted_tmp / "outbox-gap"
    spool = OutboxSpool(outbox_dir)
    for seq in (1, 2, 3):
        spool.enqueue_event(
            CaptureEventRecord(
                event_id=f"ev-g-{seq}",
                producer_stream=stream,
                sequence=seq,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at=f"2026-11-21T12:10:{seq:02d}Z",
                payload={"n": seq},
            )
        )

    # First daemon session: send {1, 3} omitting 2 -> daemon opens gap 2; mark gap 2 closed persistently.
    persisted_root = trusted_tmp / "persisted-gap-data"
    clone_owner_only_tree(tpl.root, persisted_root)
    domain = TransportTestDomain(ws_a=ws_a)
    with _open_persisted_loopback_transport(
        tpl, data_root=persisted_root, base_dir=trusted_tmp / "gap-h1", domain=domain
    ) as h1:
        cap_cred, cli_cred = _setup_capture_and_cli(h1, ws_a, stream=stream)
        assert "capture_gap_present" not in _get_health(h1, tpl.cred.token, deep=False)["degraded_codes"]
        client = CaptureClient(h1.open_client())
        target = h1.make_target()
        entries_1_3 = [e for e in spool.read_pending(limit=10) if e.sequence in (1, 3)]
        ack_hole = client.post_batch(
            target,
            CaptureBatchCommand(
                stream,
                ws_a.repo_id,
                ws_a.checkout_id,
                tuple(json.loads(e.payload_json) for e in entries_1_3),
                cap_cred.token,
            ),
        )
        assert set(ack_hole.committed_event_sequences) == {1, 3}
        assert ack_hole.contiguous_event_acked_through == 1
        assert spool.apply_ack(ack_hole) == 2

        # Open gap already makes shallow get_health report capture_gap_present.
        assert "capture_gap_present" in _get_health(h1, tpl.cred.token, deep=False)["degraded_codes"]
        assert [e.sequence for e in OutboxSpool(outbox_dir).read_pending(limit=10)] == [2]

        def _close_gap() -> tuple[int, int, int, bool, list[Any]]:
            session: Any = h1.loop._session
            assert session is not None
            cstore = KernelCaptureStore(session._rt.store)
            cstore.mark_daemon_gap_closed(producer_stream=stream, sequence=2, now=h1.clock.now())
            snap = cstore.read_capture_health()
            disp_res = session._bridge._dispatcher.dispatch(
                Call(
                    tool="get_health",
                    arguments={"schema_version": "2.0", "deep": False},
                    correlation_id=None,
                    selected_scope=None,
                ),
                CallContext(
                    principal=cli_cred.principal,
                    identity=h1.ready.identity,
                    deadline_ns=h1.mono_clock.monotonic_ns() + 1_000_000_000,
                    selected_scope=None,
                ),
                auth=PrivateRequestAuth(
                    credential_id=cli_cred.credential_id,
                    principal=cli_cred.principal,
                    token=cli_cred.token,
                ),
            )
            assert disp_res["ok"] is True and isinstance(disp_res["data"], dict)
            return (
                snap.open_gaps,
                snap.closed_gaps,
                snap.producer_gaps,
                bool(snap.has_gaps),
                list(disp_res["data"]["degraded_codes"]),
            )

        open_g, closed_g, prod_g, has_gaps, disp_degraded = h1.loop.run_owner_action(_close_gap).result(timeout=_WAIT_S)
        assert (open_g, closed_g, prod_g, has_gaps) == (0, 1, 0, True)
        assert "capture_gap_present" in disp_degraded
        assert "capture_gap_present" in _get_health(h1, tpl.cred.token, deep=False)["degraded_codes"]

    # Reopen outbox & deliver late Event 2 via drain_outbox + ProducerCaptureGap(4) (simulating ENOSPC skip).
    spool2 = OutboxSpool(outbox_dir)
    assert [e.sequence for e in spool2.read_pending(limit=10)] == [2]
    spool2.enqueue_gap(
        ProducerCaptureGap(
            gap_id="pgap-4",
            producer_stream=stream,
            sequence=4,
            reason="hook_timeout",
            recorded_at="2026-11-21T12:11:00Z",
        )
    )
    with _open_persisted_loopback_transport(
        tpl, data_root=persisted_root, base_dir=trusted_tmp / "gap-h2", domain=domain
    ) as h2:
        # Persisted closed gap is still surfaced across restart BEFORE any new batch is sent.
        assert "capture_gap_present" in _get_health(h2, tpl.cred.token, deep=False)["degraded_codes"]
        cap_cred2, _ = _setup_capture_and_cli(h2, ws_a, stream=stream)
        client2 = CaptureClient(h2.open_client())
        ack_late = drain_outbox(
            spool2,
            client=client2,
            target=h2.make_target(),
            producer_stream=stream,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_cred2.token,
        )
        assert ack_late is not None
        assert 2 in ack_late.committed_event_sequences
        assert ack_late.contiguous_event_acked_through == 3
        assert 4 in ack_late.acked_producer_gap_sequences
        assert OutboxSpool(outbox_dir).read_pending(limit=10) == []
        assert "capture_gap_present" in _get_health(h2, tpl.cred.token, deep=False)["degraded_codes"]


def test_offline_store5_to_store6_migration_and_installed_hook_wheel(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    root_path = trusted_tmp / "mig56-root"
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))
    adapters = os_adapters(clock=clock)
    rt5 = open_cloned_runtime(
        root_path,
        adapters,
        role="sp22-mig5",
        store_migrations=KERNEL_STORE_MIGRATIONS[:5],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt5.store.store_id
    rt5.close()
    assert read_schema_info(DataRoot.at(root_path).store_db) == SchemaInfo(5, 5, store_id)
    assert read_restore_epoch(DataRoot.at(root_path), schema_version=5, os_=adapters) == 0

    with pytest.raises(BrainError) as exc_mig:
        bad_adm = admit_existing_pair(root_path, store_id, adapters, purpose="serve")
        bad_adm.release()
    assert exc_mig.value.code is ErrorCode.MIGRATION_REQUIRED

    cfg_dir = trusted_tmp / "cfg"
    cfg_dir.mkdir()
    adapters.permissions.secure_directory(cfg_dir)
    (cfg_dir / "c.pem").write_bytes(b"c")
    (cfg_dir / "c.key").write_bytes(b"k")
    cfg_path = write_daemon_config_file(
        cfg_dir / "daemon.json",
        data_root=root_path,
        expected_store_id=store_id,
        cert_path=cfg_dir / "c.pem",
        key_path=cfg_dir / "c.key",
    )
    mig = run_installed_command(
        inc2_installed_env, "brain", ["migrate", "--offline", "--config", str(cfg_path)], cwd=cfg_dir
    )
    assert mig.returncode == 0, mig.stderr.decode(errors="replace")
    assert read_schema_info(DataRoot.at(root_path).store_db) == SchemaInfo(8, 8, store_id)
    assert read_schema_info(DataRoot.at(root_path).policy_db) == SchemaInfo(5, 5, store_id)
    assert read_restore_epoch(DataRoot.at(root_path), schema_version=8, os_=adapters) == 0
    assert code_version(KERNEL_STORE_MIGRATIONS) == 8

    with contextlib.closing(open_readonly(DataRoot.at(root_path).store_db, scratch_dir=cfg_dir)) as conn:
        tables = {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"capture_events", "producer_watermarks", "capture_gaps"} <= tables

    with pytest.raises(BrainError) as exc_old:
        old_adm = admit_existing_pair(
            root_path,
            store_id,
            adapters,
            purpose="serve",
            store_migrations=KERNEL_STORE_MIGRATIONS[:5],
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        old_adm.release()
    assert exc_old.value.code is ErrorCode.UNSUPPORTED_VERSION

    # Also verify hook_entry executes cleanly inside installed wheel venv (python -I).
    wheel_outbox = trusted_tmp / "wheel-hook-outbox"
    ev_json = json.dumps(_ev_dict(1, "wheel-stream", {"wheel": "ok"})).encode()
    hook_res = subprocess.run(
        [
            str(inc2_installed_env.venv_python),
            "-I",
            "-m",
            "superbrain.composition.hook_entry",
            "--outbox",
            str(wheel_outbox),
        ],
        input=ev_json,
        env=clean_installed_subprocess_env(),
        capture_output=True,
        check=False,
        timeout=15.0,
    )
    assert hook_res.returncode == 0, hook_res.stderr.decode(errors="replace")


@pytest.mark.parametrize("case", SP2_2_CRASH_CASES, ids=lambda c: c.node_id)
def test_sp2_2_wheel_crash_matrix(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: SP22CrashCase
) -> None:
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    ctx = KernelCrashContext(
        env=inc2_installed_env,
        template=get_shared_t7_transport_template(),
        case_dir=trusted_tmp / "case",
        cwd=cwd,
    )
    ctx.case_dir.mkdir()
    run_sp2_2_crash_case(ctx, case)


def test_sp2_2_wheel_crash_omission_detection(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    ctx = KernelCrashContext(
        env=inc2_installed_env,
        template=get_shared_t7_transport_template(),
        case_dir=trusted_tmp / "omit",
        cwd=cwd,
    )
    ctx.case_dir.mkdir()
    run_sp2_2_omission_checks(ctx, monkeypatch)


@pytest.mark.parametrize("case", SP2_3_CRASH_CASES, ids=lambda c: c.node_id)
def test_sp2_3_wheel_crash_matrix(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: SP22CrashCase
) -> None:
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    ctx = KernelCrashContext(
        env=inc2_installed_env,
        template=get_shared_t7_transport_template(),
        case_dir=trusted_tmp / "case-sp23",
        cwd=cwd,
    )
    ctx.case_dir.mkdir()
    run_sp2_3_crash_case(ctx, case)


@pytest.mark.parametrize("case", SP2_4_CRASH_CASES, ids=lambda c: c.node_id)
def test_sp2_4_wheel_crash_matrix(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: SP22CrashCase
) -> None:
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    ctx = KernelCrashContext(
        env=inc2_installed_env,
        template=get_shared_t7_transport_template(),
        case_dir=trusted_tmp / "case-sp24",
        cwd=cwd,
    )
    ctx.case_dir.mkdir()
    run_sp2_4_crash_case(ctx, case)


def test_capture_only_policy_keeps_payload_and_source_when_manual_submission_disabled() -> None:
    from superbrain.cli_api.capture_client import CaptureClient

    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    stream = "caponly-f1-stream"
    cfg_dig = "sha256:" + ("c" * 64)

    with open_test_loopback_transport(tpl, name="sp22-f1-caponly", domain=TransportTestDomain(ws_a=ws_a)) as h:
        cap_cred, _cli_cred = _setup_capture_and_cli(h, ws_a, stream=stream)
        cap_client = CaptureClient(h.open_client())
        target = h.make_target()

        def _configure_cap_only(*, automatic_capture: bool) -> None:
            def _act() -> None:
                session: Any = h.loop._session
                assert session is not None
                session._rt.policy.set_repo_policy(
                    ws_a.repo_id,
                    manual_submission_enabled=False,
                    automatic_capture_enabled=automatic_capture,
                )
                session._rt.policy.set_layer2_state(
                    harness_id="claude-code",
                    host_version="2.1.325",
                    config_digest=cfg_dig,
                    state=Layer2State.VERIFIED,
                )

            h.loop.run_owner_action(_act).result(timeout=_WAIT_S)

        _configure_cap_only(automatic_capture=True)
        secret_pat = "github_pat_" + ("F1AbCdEf" * 4)
        ev1 = _ev_dict(
            1,
            stream,
            {
                "tool": "Read",
                "summary": "inspect <private>F1_TAG_SECRET_99</private> notes",
                "path": "README.md",
                "token": secret_pat,
            },
            source_metadata={"host_version": "2.1.325", "config_digest": cfg_dig},
        )
        ack1 = cap_client.post_batch(
            target,
            CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, (ev1,), cap_cred.token),
        )
        assert ack1.accepted_count == 1
        assert ack1.policy_disabled is False
        assert ack1.committed_event_sequences == (1,)

        def _inspect_committed() -> tuple[str, str, dict[str, Any], dict[str, Any]]:
            session: Any = h.loop._session
            assert session is not None
            rt = session._rt
            row = rt.store._db.execute(
                "SELECT source, source_verification, payload_digest, source_metadata_json "
                "FROM capture_events WHERE producer_stream = ? AND sequence = 1",
                (stream,),
            ).fetchone()
            assert row is not None
            meta_obj = json.loads(bytes(row[3]))
            payload_obj = json.loads(rt.store.cas.read(str(row[2])))
            return str(row[0]), str(row[1]), meta_obj, payload_obj

        src, sver, stored_meta, stored_payload = h.loop.run_owner_action(_inspect_committed).result(timeout=_WAIT_S)
        assert (src, sver) == ("tool_observed", "verified_host")
        assert stored_meta == {"host_version": "2.1.325", "config_digest": cfg_dig}
        assert stored_payload["tool"] == "Read"
        assert stored_payload["path"] == "README.md"
        assert "inspect" in str(stored_payload["summary"])
        dumped_payload = json.dumps(stored_payload, sort_keys=True)
        assert "F1_TAG_SECRET_99" not in dumped_payload
        assert secret_pat not in dumped_payload

        # Negative checks remain enforced under manual_submission_enabled=False.
        unclosed = _ev_dict(2, stream, {"note": "<private>F1_UNCLOSED_99"})
        with pytest.raises(BrainError) as exc_unclosed:
            cap_client.post_batch(
                target,
                CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, (unclosed,), cap_cred.token),
            )
        assert exc_unclosed.value.code is ErrorCode.INVALID_INPUT
        assert "F1_UNCLOSED_99" not in str(exc_unclosed.value)

        forged = _ev_dict(2, stream, {"raw_session_id": "raw-123"})
        with pytest.raises(BrainError) as exc_forged:
            cap_client.post_batch(
                target,
                CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, (forged,), cap_cred.token),
            )
        assert exc_forged.value.code is ErrorCode.INVALID_INPUT

        _configure_cap_only(automatic_capture=False)
        ack_off = cap_client.post_batch(
            target,
            CaptureBatchCommand(
                stream,
                ws_a.repo_id,
                ws_a.checkout_id,
                (_ev_dict(2, stream, {"tool": "Read", "summary": "ignored when disabled"}),),
                cap_cred.token,
            ),
        )
        assert ack_off.policy_disabled is True
        assert ack_off.accepted_count == 0


def test_capture_sparse_high_sequence_gap_intervals_closure_validation_and_clock_now() -> None:
    from superbrain.cli_api.capture_client import CaptureClient
    from superbrain.core.canonical import digest_bytes
    from superbrain.ports.capture import CaptureEventRecord, StagedCaptureEvent
    from superbrain.storage.capture_events import KernelCaptureStore

    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    stream = "sparse-gap-f6"

    with open_test_loopback_transport(tpl, name="sp22-f6-gaps", domain=TransportTestDomain(ws_a=ws_a)) as h:
        cap_cred, _cli_cred = _setup_capture_and_cli(h, ws_a, stream=stream)
        cap_client = CaptureClient(h.open_client())
        target = h.make_target()

        def _daemon_gaps_for(target_stream: str) -> list[tuple[int, str, int]]:
            def _read() -> list[tuple[int, str, int]]:
                session: Any = h.loop._session
                assert session is not None
                rows = session._rt.store._db.execute(
                    "SELECT sequence, status, estimated_count FROM capture_gaps "
                    "WHERE producer_stream = ? AND gap_origin = 'daemon' ORDER BY sequence ASC",
                    (target_stream,),
                ).fetchall()
                return [(int(r[0]), str(r[1]), int(r[2])) for r in rows]

            return h.loop.run_owner_action(_read).result(timeout=_WAIT_S)

        # Sparse sequence=5_000_000 inserts 1 interval row [1..4_999_999], O(1), health degraded.
        ack_high = cap_client.post_batch(
            target,
            CaptureBatchCommand(
                stream,
                ws_a.repo_id,
                ws_a.checkout_id,
                (_ev_dict(5_000_000, stream, {"sparse": "high"}, recorded_at="2026-11-21T12:00:01Z"),),
                cap_cred.token,
            ),
        )
        assert ack_high.accepted_count == 1
        assert ack_high.contiguous_event_acked_through == 0
        assert ack_high.committed_event_sequences == (5_000_000,)
        gaps_after_high = _daemon_gaps_for(stream)
        open_after_high = [g for g in gaps_after_high if g[1] == "open"]
        assert open_after_high == [(1, "open", 4_999_999)]
        assert "capture_gap_present" in _get_health(h, tpl.cred.token, deep=False)["degraded_codes"]

        # Late sequence=2_000_000 splits open interval into [1..1_999_999] and [2_000_001..4_999_999].
        ack_mid = cap_client.post_batch(
            target,
            CaptureBatchCommand(
                stream,
                ws_a.repo_id,
                ws_a.checkout_id,
                (_ev_dict(2_000_000, stream, {"sparse": "mid"}, recorded_at="2026-11-21T12:00:02Z"),),
                cap_cred.token,
            ),
        )
        assert ack_mid.accepted_count == 1
        assert ack_mid.contiguous_event_acked_through == 0
        gaps_after_mid = _daemon_gaps_for(stream)
        open_after_mid = [g for g in gaps_after_mid if g[1] == "open"]
        assert open_after_mid == [(1, "open", 1_999_999), (2_000_001, "open", 2_999_999)]

        # Closing sequence=2 produces closed_gaps == 1 while leaving remaining open intervals open.
        def _close_seq2() -> tuple[int, int, bool]:
            session: Any = h.loop._session
            assert session is not None
            cstore = KernelCaptureStore(session._rt.store)
            cstore.mark_daemon_gap_closed(producer_stream=stream, sequence=2, now=h.clock.now())
            snap = cstore.read_capture_health()
            return snap.open_gaps, snap.closed_gaps, snap.has_gaps

        open_cnt, closed_cnt, has_gaps = h.loop.run_owner_action(_close_seq2).result(timeout=_WAIT_S)
        assert closed_cnt == 1
        assert open_cnt >= 1
        assert has_gaps is True
        gaps_after_close = _daemon_gaps_for(stream)
        assert [(s, c) for s, st, c in gaps_after_close if st == "closed"] == [(2, 1)]
        remaining_open = [(s, c) for s, st, c in gaps_after_close if st == "open"]
        assert sum(c for _s, c in remaining_open) == 4_999_997
        assert all(not (s <= 2 < s + c) for s, c in remaining_open)

        # Oversized sequence=10**20 rejected with INVALID_INPUT.
        with pytest.raises(BrainError) as exc_huge:
            cap_client.post_batch(
                target,
                CaptureBatchCommand(
                    stream,
                    ws_a.repo_id,
                    ws_a.checkout_id,
                    (_ev_dict(10**20, stream, {"bad": "huge"}, recorded_at="2026-11-21T12:00:03Z"),),
                    cap_cred.token,
                ),
            )
        assert exc_huge.value.code is ErrorCode.INVALID_INPUT

        # Explicit now passed to KernelCaptureStore.commit_staged_batch is persisted rather than overwritten.
        custom_now = datetime(2029, 3, 15, 10, 45, 0, tzinfo=UTC)
        clock_stream = "clock-now-f6"

        def _commit_with_custom_now() -> tuple[str, str, str]:
            session: Any = h.loop._session
            assert session is not None
            rt = session._rt
            cstore = KernelCaptureStore(rt.store)
            rec = CaptureEventRecord(
                event_id="ev-clock-f6-1",
                producer_stream=clock_stream,
                sequence=1,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at="2026-11-21T12:00:04Z",
                payload={"clock": "explicit"},
            )
            p_bytes = canonical_json(rec.payload)
            staged = StagedCaptureEvent(
                record=rec,
                payload_bytes=p_bytes,
                payload_digest=digest_bytes(p_bytes),
                source="unknown",
                source_verification="unverified",
            )
            cstore.commit_staged_batch(
                producer_stream=clock_stream,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                principal_id=cap_cred.principal.principal_id,
                events=(staged,),
                gaps=(),
                now=custom_now,
            )
            ev_row = rt.store._db.execute(
                "SELECT committed_at, cas_holder_id FROM capture_events WHERE producer_stream = ? AND sequence = 1",
                (clock_stream,),
            ).fetchone()
            assert ev_row is not None
            wm_row = rt.store._db.execute(
                "SELECT updated_at FROM producer_watermarks WHERE producer_stream = ?",
                (clock_stream,),
            ).fetchone()
            assert wm_row is not None
            hold_row = rt.store._db.execute(
                "SELECT expires_at FROM p_cas_holders_ WHERE holder_kind = 'event' AND holder_id = ?",
                (str(ev_row[1]),),
            ).fetchone()
            assert hold_row is not None
            return str(ev_row[0]), str(wm_row[0]), str(hold_row[0])

        committed_at_s, updated_at_s, expires_at_s = h.loop.run_owner_action(_commit_with_custom_now).result(
            timeout=_WAIT_S
        )
        assert committed_at_s == "2029-03-15T10:45:00.000000Z"
        assert updated_at_s == "2029-03-15T10:45:00.000000Z"
        assert expires_at_s == "2029-06-13T10:45:00.000000Z"


def _sized_capture_dict(seq: int, stream: str, target_bytes: int) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    i = 0
    while True:
        sample = _ev_dict(
            seq,
            stream,
            payload,
            event_id=f"ev-f7-{seq}",
            recorded_at="2026-11-21T12:20:00Z",
        )
        cur = len(canonical_json(sample))
        rem = target_bytes - cur
        if rem <= 12:
            break
        take = min(50_000, max(1, rem - 10))
        payload[f"k{i:03d}"] = "x" * take
        i += 1
    return _ev_dict(
        seq,
        stream,
        payload,
        event_id=f"ev-f7-{seq}",
        recorded_at="2026-11-21T12:20:00Z",
    )


def test_drain_outbox_chunks_large_backlog_and_stops_on_mid_drain_policy_disable(trusted_tmp: Path) -> None:
    from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK
    from superbrain.cli_api.capture_client import CaptureClient
    from superbrain.cli_api.loopback import LoopbackTarget
    from superbrain.composition.capture_drain_entry import drain_outbox
    from superbrain.domain.capture.outbox_rules import partition_pending_for_batch
    from superbrain.ports.capture import CaptureBatchAck, CaptureEventRecord
    from superbrain.storage.outbox import OutboxSpool

    os_ = os_adapters()
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    stream1 = "f7-drain-full"
    stream2 = "f7-drain-mid"

    with open_test_loopback_transport(tpl, name="sp22-f7-drain", domain=TransportTestDomain(ws_a=ws_a)) as h:
        cap1, _ = _setup_capture_and_cli(h, ws_a, stream=stream1)
        cap2_holder: list[Any] = []

        def _setup_stream2() -> None:
            cap2_holder.append(
                _setup_capture_producer(
                    h, harness_id="claude-code", stream=stream2, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id
                )
            )

        h.loop.run_owner_action(_setup_stream2).result(timeout=_WAIT_S)
        cap2 = cap2_holder[0]
        cap_client = CaptureClient(h.open_client())
        target = h.make_target()

        # Part A: 7 x 200 KB + ~950 KB record drains cleanly across multiple batches to 0 bytes.
        outbox1 = trusted_tmp / "outbox-f7-full"
        spool1 = OutboxSpool(outbox1, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
        for seq in range(1, 8):
            spool1.enqueue_event(CaptureEventRecord.from_dict(_sized_capture_dict(seq, stream1, 200_000)))
        spool1.enqueue_event(CaptureEventRecord.from_dict(_sized_capture_dict(8, stream1, 950_000)))
        assert spool1.total_bytes() > 2_000_000

        ack_full = drain_outbox(
            spool1,
            client=cap_client,
            target=target,
            producer_stream=stream1,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap1.token,
        )
        assert ack_full is not None
        assert ack_full.accepted_count == 8
        assert ack_full.committed_event_sequences == (1, 2, 3, 4, 5, 6, 7, 8)
        assert ack_full.contiguous_event_acked_through == 8
        assert ack_full.policy_disabled is False
        assert spool1.total_bytes() == 0
        assert spool1.read_pending(limit=20, producer_stream=stream1) == []

        # Part B: Mid-drain automatic_capture_enabled=False after batch 1 preserves batch 2 in outbox.
        outbox2 = trusted_tmp / "outbox-f7-mid"
        spool2 = OutboxSpool(outbox2, permissions=os_.permissions, file_lock=OUTBOX_FILE_LOCK)
        for seq in range(1, 8):
            spool2.enqueue_event(CaptureEventRecord.from_dict(_sized_capture_dict(seq, stream2, 200_000)))
        planned = partition_pending_for_batch(spool2.read_pending(limit=20, producer_stream=stream2))
        assert len(planned) >= 2
        batch1_len = len(planned[0])
        assert 1 <= batch1_len < 7

        def _set_auto_capture(enabled: bool) -> None:
            def _act() -> None:
                session: Any = h.loop._session
                assert session is not None
                session._rt.policy.set_repo_policy(ws_a.repo_id, automatic_capture_enabled=enabled)

            h.loop.run_owner_action(_act).result(timeout=_WAIT_S)

        class _ToggleAfterFirstBatchClient(CaptureClient):
            def __init__(self, inner_loopback: Any) -> None:
                super().__init__(inner_loopback)
                self.calls = 0

            def post_batch(
                self,
                t: LoopbackTarget,
                command: CaptureBatchCommand,
                *,
                deadline_ns: int | None = None,
            ) -> CaptureBatchAck:
                self.calls += 1
                ack = super().post_batch(t, command, deadline_ns=deadline_ns)
                if self.calls == 1:
                    _set_auto_capture(False)
                return ack

        toggle_client = _ToggleAfterFirstBatchClient(h.open_client())
        ack_mid = drain_outbox(
            spool2,
            client=toggle_client,
            target=target,
            producer_stream=stream2,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap2.token,
        )
        assert ack_mid is not None
        assert ack_mid.policy_disabled is True
        assert ack_mid.accepted_count == batch1_len
        assert ack_mid.committed_event_sequences == tuple(range(1, batch1_len + 1))

        remaining = spool2.read_pending(limit=20, producer_stream=stream2)
        assert [e.sequence for e in remaining] == list(range(batch1_len + 1, 8))

        # Re-enable automatic capture and complete draining remaining entries.
        _set_auto_capture(True)
        ack_rest = drain_outbox(
            spool2,
            client=cap_client,
            target=target,
            producer_stream=stream2,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap2.token,
        )
        assert ack_rest is not None
        assert ack_rest.policy_disabled is False
        assert ack_rest.accepted_count == 7 - batch1_len
        assert spool2.total_bytes() == 0
        assert spool2.read_pending(limit=20, producer_stream=stream2) == []


def _iso(dt_value: datetime) -> str:
    return dt_value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _owner(h: Any, fn: Any) -> Any:
    def _act() -> Any:
        session: Any = h.loop._session
        assert session is not None
        return fn(session)

    return h.loop.run_owner_action(_act).result(timeout=_WAIT_S)


def _wait_owner(h: Any, fn: Any, *, timeout_s: float = 20.0) -> Any:
    deadline = time.monotonic() + timeout_s
    pause = threading.Event()
    while time.monotonic() < deadline:
        value = _owner(h, fn)
        if value:
            return value
        pause.wait(0.05)
    raise AssertionError("condition not reached through the daemon's own loop")


def test_acked_capture_schedules_continuity_refresh_through_the_daemon_and_after_restart(trusted_tmp: Path) -> None:
    """Spec 7.4 / case 54 through the product path: committed capture events of a task's session schedule a
    refresh at 20 events, a quiet session (< 20) is refreshed once 60 s pass, also across a daemon restart.
    No test code calls the scheduler or the worker."""
    from superbrain.cli_api.capture_client import CaptureClient
    from superbrain.storage.sessions import SessionStore

    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    stream = "sched-stream-1"
    persisted_root = trusted_tmp / "persisted-sched-data"
    clone_owner_only_tree(tpl.root, persisted_root)
    domain = TransportTestDomain(ws_a=ws_a)
    task_id = f"task-{new_id()}"
    quiet_task_id = f"task-{new_id()}"

    def _post(h: Any, cap_cred: Any, events: list[dict[str, Any]]) -> Any:
        client = CaptureClient(h.open_client())
        return client.post_batch(
            h.make_target(),
            CaptureBatchCommand(stream, ws_a.repo_id, ws_a.checkout_id, tuple(events), cap_cred.token),
        )

    def _events(h: Any, start: int, count: int, session_ref: str) -> list[dict[str, Any]]:
        now = h.clock.now()
        return [
            _ev_dict(
                seq,
                stream,
                {"tool": "Bash", "command": "pytest -q", "exit_code": seq % 2},
                session_ref=session_ref,
                recorded_at=_iso(now),
            )
            for seq in range(start, start + count)
        ]

    with _open_persisted_loopback_transport(
        tpl, data_root=persisted_root, base_dir=trusted_tmp / "sched-h1", domain=domain
    ) as h1:
        cap_cred, _cli = _setup_capture_and_cli(h1, ws_a, stream=stream)

        def _bind(session: Any) -> tuple[str, str, str]:
            ss = SessionStore(session._rt.store, session._rt.policy)
            refs = []
            for raw in ("RAW_SCHED_TASK_SESSION", "RAW_SCHED_QUIET_SESSION", "RAW_SCHED_NO_TASK_SESSION"):
                rec = ss.bind_session(
                    principal_id=cap_cred.principal.principal_id,
                    repo_id=ws_a.repo_id,
                    checkout_id=ws_a.checkout_id,
                    harness_id="claude-code",
                    raw_session_id=raw,
                    now=h1.clock.now(),
                )
                refs.append(rec.session_ref)
            for tid, sref in ((task_id, refs[0]), (quiet_task_id, refs[1])):
                ss.ensure_task_handoff(
                    task_id=tid, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id,
                    session_ref=sref, now=h1.clock.now(),
                )
            return refs[0], refs[1], refs[2]

        sref_task, sref_quiet, sref_no_task = _owner(h1, _bind)

        # Negative twin: a session with no task gets its events stored but schedules nothing.
        ack0 = _post(h1, cap_cred, _events(h1, 1, 25, sref_no_task))
        assert ack0.accepted_count == 25

        # 20 committed events of the task's session -> the daemon schedules and commits a refresh by itself.
        ack1 = _post(h1, cap_cred, _events(h1, 26, 20, sref_task))
        assert ack1.accepted_count == 20

        def _refreshed(session: Any) -> Any:
            ss = SessionStore(session._rt.store, session._rt.policy)
            handoff = ss.read_task_handoff(task_id)
            state = ss.get_continuity_worker_state(task_id)
            if handoff is None or handoff.observed_ref is None or state is None:
                return None
            if state.active_job_id is not None or state.pending_job_id is not None:
                return None
            return handoff, state

        handoff1, state1 = _wait_owner(h1, _refreshed)
        assert handoff1.current_revision >= 1 and handoff1.observed_ref.startswith("sha256:")
        assert state1.pending_event_count == 0

        def _continuity_jobs(session: Any) -> list[tuple[str, str]]:
            rows = session._rt.store._db.execute(
                "SELECT job_id, state FROM p_jobs_state WHERE kind = 'continuity.refresh'"
            ).fetchall()
            return [(str(r[0]), str(r[1])) for r in rows]

        jobs_after_20 = _owner(h1, _continuity_jobs)
        assert len(jobs_after_20) == 1 and jobs_after_20[0][1] == "succeeded"

        # Quiet session: 3 events stay pending (< 20, < 60 s); nothing is scheduled before the restart.
        ack2 = _post(h1, cap_cred, _events(h1, 46, 3, sref_quiet))
        assert ack2.accepted_count == 3
        quiet_state = _owner(
            h1, lambda s: SessionStore(s._rt.store, s._rt.policy).get_continuity_worker_state(quiet_task_id)
        )
        assert quiet_state is not None and quiet_state.pending_event_count == 3
        assert quiet_state.pending_job_id is None and quiet_state.active_job_id is None
        assert len(_owner(h1, _continuity_jobs)) == 1

    # Restart on the same root; 61 s later the durable wake refreshes the quiet task with no new event.
    with _open_persisted_loopback_transport(
        tpl, data_root=persisted_root, base_dir=trusted_tmp / "sched-h2", domain=domain
    ) as h2:
        h2.clock.advance(timedelta(seconds=61))

        def _quiet_refreshed(session: Any) -> Any:
            ss = SessionStore(session._rt.store, session._rt.policy)
            handoff = ss.read_task_handoff(quiet_task_id)
            state = ss.get_continuity_worker_state(quiet_task_id)
            if handoff is None or handoff.observed_ref is None or state is None or state.pending_event_count:
                return None
            return handoff

        quiet_handoff = _wait_owner(h2, _quiet_refreshed)
        assert quiet_handoff.current_revision >= 1
        jobs_final = _owner(h2, _continuity_jobs)
        assert len(jobs_final) == 2 and all(state == "succeeded" for _jid, state in jobs_final)
