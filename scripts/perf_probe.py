"""Actual wheel/daemon/shim measurements for the explicit Task 8 benchmark."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Isolated wheel-side entry: verify the imported package before exposing test support.
if __name__ == "__main__":
    import superbrain

    if (
        superbrain.__file__ is None or sys.prefix == sys.base_prefix
        or not Path(superbrain.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    ):
        raise SystemExit("benchmark child needs the isolated installed wheel")
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts import perf_gate as perf
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue


def _positive(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return value.get("positive_control") == perf.POSITIVE_CONTROL or any(_positive(v) for v in value.values())
    return isinstance(value, list) and any(_positive(v) for v in value)


def child(config: Path) -> int:
    """Run the real daemon composition with fixture business data and in-memory timing taps."""
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.cli_api import _loopback_server as transport
    from superbrain.composition import daemon_entry
    from superbrain.composition.daemon_entry import serve_config_path
    from superbrain.composition.owner_entry import _explicit_owner_adapters
    from superbrain.core.kernel import (
        TOTAL_REQUEST_BUDGET_NS,
        Call,
        CallContext,
        SnapshotObservation,
        StoredResult,
        WorkspaceBinding,
    )
    from superbrain.storage.idempotency import KernelIdempotencyStore
    from tests.support.inc2_t8_domain import GatedObserver, fixture_hooks
    from tests.support.inc2_t8_privacy import PrivacyDomainProxy, privacy_store_extensions

    stop = threading.Event()

    def wait_for_stop() -> None:
        sys.stdin.readline()
        stop.set()

    threading.Thread(target=wait_for_stop, daemon=True).start()
    _, adapters, scratch = _explicit_owner_adapters(config)
    proxy = PrivacyDomainProxy()
    local = threading.local()
    owner_sample: dict[str, JsonValue] | None = None
    inflight: dict[int, dict[str, JsonValue]] = {}
    inflight_lock = threading.Lock()
    transport_api: Any = transport
    composition_api: Any = daemon_entry
    original_read = transport_api.read_admitted_tool_command
    original_write = transport_api.write_json_response
    original_filter = PrivacyFilter.apply
    original_prepare = proxy.prepare_mutation
    original_commit = KernelIdempotencyStore.commit_prepared_effect

    def read(*args: Any, **kwargs: Any) -> Any:
        result = original_read(*args, **kwargs)
        if result is not None:
            assert isinstance(result.arguments, dict)
            key = str(result.arguments["idempotency_key"])
            sample: dict[str, JsonValue] = {
                "idempotency_key": key, "t0_read_ns": kwargs["deadline_ns"] - TOTAL_REQUEST_BUDGET_NS,
            }
            with inflight_lock:
                inflight[id(sample)] = sample
                if len(inflight) > 1:
                    for other in inflight.values():
                        other["overlapped"] = True
                local.sample = sample
        return result

    def prepare(call: Call, ctx: CallContext, *, now: Any) -> Any:
        nonlocal owner_sample
        admitted_ns = time.perf_counter_ns()
        with inflight_lock:
            owner_sample = None
            if len(inflight) == 1:
                (candidate,) = inflight.values()
                if (
                    candidate.get("overlapped") is not True
                    and candidate["idempotency_key"] == call.arguments["idempotency_key"]
                    and (
                        ctx is None
                        or ctx.deadline_ns == int(str(candidate["t0_read_ns"])) + TOTAL_REQUEST_BUDGET_NS
                    )
                ):
                    candidate["admission_done_ns"] = admitted_ns
                    owner_sample = candidate
        return original_prepare(call, ctx, now=now)

    def filtered(self: PrivacyFilter, value: Any, policy: Any, **kwargs: Any) -> Any:
        sample = owner_sample
        if sample is None:
            return original_filter(self, value, policy, **kwargs)
        sample["filter_ran"] = True
        sample["filter_start_ns"] = time.perf_counter_ns()
        try:
            result = original_filter(self, value, policy, **kwargs)
            sample["filter_end_ns"] = time.perf_counter_ns()
            sample["filter_bytes"] = len(canonical_json(value))
            sample.update(
                redacted_count=result.redacted_count, stripped_keys_count=result.stripped_keys_count,
                positive_control_preserved=_positive(result.value),
            )
            return result
        finally:
            sample.setdefault("filter_end_ns", time.perf_counter_ns())
            if "filter_bytes" not in sample:
                sample["filter_bytes"] = len(canonical_json(value))

    def commit(self: KernelIdempotencyStore, **kwargs: Any) -> tuple[StoredResult, bool]:
        sample = owner_sample
        if sample is None:
            return original_commit(self, **kwargs)
        sample["commit_start_ns"] = time.perf_counter_ns()
        try:
            return original_commit(self, **kwargs)
        finally:
            sample["commit_end_ns"] = time.perf_counter_ns()

    def write(*args: Any, **kwargs: Any) -> Any:
        sample: dict[str, JsonValue] | None = getattr(local, "sample", None)
        if sample is None:
            return original_write(*args, **kwargs)
        write_start_ns = time.perf_counter_ns()
        try:
            result = original_write(*args, **kwargs)
            flushed_ns = time.perf_counter_ns()
        finally:
            with inflight_lock:
                inflight.pop(id(sample), None)
                captured = dict(sample)
            local.sample = None
        captured["response_write_start_ns"] = write_start_ns
        captured["response_flushed_ns"] = flushed_ns
        captured["elapsed_ns"] = flushed_ns - int(str(captured["t0_read_ns"]))
        envelope = json.loads(kwargs["body"])
        if captured.get("overlapped") is True:
            captured["status"] = "instrumentation_overlap"
        elif envelope.get("ok") is not True:
            captured["status"] = str(envelope.get("error", {}).get("code"))
        elif "admission_done_ns" not in captured:
            # A cached replay can succeed without producing fresh owner spans.
            captured["status"] = "instrumentation_missing_owner"
        else:
            captured["status"] = "ok"
        print(json.dumps({"event": "sample", **captured}), flush=True)
        return result

    class Observer(GatedObserver):
        def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
            sample = owner_sample
            if sample is None:
                return super().observe(binding, deadline_ns)
            sample["observer_start_ns"] = time.perf_counter_ns()
            try:
                return super().observe(binding, deadline_ns)
            finally:
                sample["observer_end_ns"] = time.perf_counter_ns()

    # Test-process taps wrap the real call, never the value being measured.
    transport_api.read_admitted_tool_command = read
    transport_api.write_json_response = write
    PrivacyFilter.apply = filtered  # type: ignore[method-assign]
    KernelIdempotencyStore.commit_prepared_effect = commit  # type: ignore[method-assign]
    proxy.prepare_mutation = prepare  # type: ignore[method-assign]
    composition_api.kernel_store_extensions = privacy_store_extensions
    try:
        return serve_config_path(
            config, os_=adapters, domain=proxy, hooks=fixture_hooks(
                proxy, monotonic_ns=time.perf_counter_ns, observer=Observer(),
            ), stop_event=stop,
            on_ready=lambda ready, loop: print(json.dumps({
                "event": "ready", "pid": os.getpid(), "started_ns": time.perf_counter_ns(),
                "module": str(sys.modules["superbrain"].__file__),
            }), flush=True),
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


@contextlib.contextmanager
def _daemon(
    env: Any, config: Path, repo: Path, attempt: Path
) -> Iterator[tuple[subprocess.Popen[str], queue.Queue[Any]]]:
    records: queue.Queue[Any] = queue.Queue()
    with (attempt / "daemon.stderr").open("w", encoding="utf-8") as err, (
        attempt / "daemon.jsonl"
    ).open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [str(env.venv_python), "-I", str(Path(__file__).resolve()), "--child", str(config)],
            cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
            text=True, encoding="utf-8",
        )
        assert proc.stdout is not None and proc.stdin is not None

        def pump() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line)
                log.flush()
                records.put(json.loads(line))
            records.put(None)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        try:
            ready = records.get(timeout=15)
            if not isinstance(ready, dict) or ready.get("event") != "ready":
                raise RuntimeError("benchmark daemon did not become ready")
            yield proc, records
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            reader.join(timeout=2)
            proc.stdout.close()


def _response(frame: dict[str, JsonValue]) -> dict[str, Any]:
    result = frame.get("result")
    if not isinstance(result, dict):
        return {}
    structured = result.get("structuredContent")
    return structured if isinstance(structured, dict) else {}


def _local_privacy(
    buckets: dict[int, list[dict[str, JsonValue]]], checkpoint: Callable[[], perf.ProbeMeasurements],
    tails: dict[str, list[JsonValue]],
) -> None:
    from superbrain.application.privacy import PrivacyFilter
    from superbrain.core.errors import BrainError
    from superbrain.core.kernel import FilterPolicy

    for size in perf.PRIVACY_SIZES_KIB:
        rows: list[dict[str, JsonValue]] = []
        buckets[size] = rows
        tails[str(size)] = []
        for index in range(perf.PRIVACY_SAMPLES_PER_SIZE):
            payload, length = perf.build_privacy_corpus_sample(size, index)
            sample: dict[str, JsonValue] = {
                "filter_bytes": length, "filter_ran": True, "rejected_before_filter": False,
            }
            start = time.perf_counter_ns()
            try:
                safe = PrivacyFilter(time.perf_counter_ns).apply(payload, FilterPolicy())
                sample.update(
                    status="ok", redacted_count=safe.redacted_count, stripped_keys_count=safe.stripped_keys_count,
                    positive_control_preserved=_positive(safe.value),
                )
            except BrainError as error:
                sample["status"] = error.code.value
            sample["elapsed_ns"] = time.perf_counter_ns() - start
            rows.append(sample)
            checkpoint()
            malformed, length = perf.build_unclosed_private_tail_sample(size)
            tail: dict[str, JsonValue] = {
                "filter_bytes": length, "filter_ran": True, "rejected_before_filter": False,
                "expected_status": "invalid_input",
            }
            start = time.perf_counter_ns()
            try:
                PrivacyFilter(time.perf_counter_ns).apply(malformed, FilterPolicy())
                tail["status"] = "unexpected_success"
            except BrainError as error:
                tail["status"] = error.code.value
            tail["elapsed_ns"] = time.perf_counter_ns() - start
            tails[str(size)].append(tail)
            checkpoint()


def measure(repo: Path, attempt: Path) -> perf.ProbeMeasurements:
    from superbrain.adapters.os import os_adapters
    from tests.support.inc2_cli import (
        InstalledMcpPipeSession,
        get_shared_t7_transport_template,
        mcp_call_frame,
        mcp_init_frames,
        verify_installed_wheel_isolation,
        write_client_profile_file,
        write_credential_file,
        write_daemon_config_file,
    )
    from tests.support.inc2_fixture import open_inc2_installed_env
    from tests.support.inc2_t8_harness import clone_template_root, store_rows

    template = get_shared_t7_transport_template()
    assert template.ws_a is not None
    binding = template.ws_a
    with tempfile.TemporaryDirectory(prefix="sb2-perf-") as tmp:
        scratch = Path(tmp)
        os_adapters().permissions.secure_directory(scratch)
        with open_inc2_installed_env(scratch) as env:
            wheel_identity = verify_installed_wheel_isolation(env, cwd=scratch)
            if (
                wheel_identity.get("schema_sha256") != env.source_schema_sha256
                or not Path(str(wheel_identity.get("module_file"))).resolve().is_relative_to(env.venv_dir.resolve())
            ):
                raise RuntimeError("installed package or schema differs from the benchmark source")
            provenance = subprocess.run(
                [str(env.venv_python), "-I", "-c",
                 "import json,platform,sys;print(json.dumps(dict(version=platform.python_version(),"
                 "implementation=platform.python_implementation().lower(),executable=sys.executable)))"],
                capture_output=True, text=True, check=True, timeout=15,
            )
            runtime = json.loads(provenance.stdout)
            data_root = clone_template_root(template, scratch / "data")
            config = write_daemon_config_file(
                scratch / "daemon.json", data_root=data_root, expected_store_id=template.store_id,
                cert_path=template.tls.cert_path, key_path=template.tls.key_path,
            )
            credential = write_credential_file(scratch / "credential.txt", template.cred.token)
            profile, _ = write_client_profile_file(
                scratch / "profile.json", endpoint_path=data_root / "endpoint.json",
                expected_store_id=template.store_id, ca_file=template.tls.ca_cert_path,
                leaf_cert_sha256=template.tls.leaf_cert_sha256, credential_file=credential,
                workspace={
                    "alias": binding.alias, "checkout_path": str(binding.checkout_path),
                    "expected_workspace_id": binding.repo_id, "expected_checkout_id": binding.checkout_id,
                },
            )
            warmup: list[dict[str, JsonValue]] = []
            warm: list[dict[str, JsonValue]] = []
            wire: list[dict[str, JsonValue]] = []
            cold: dict[str, list[dict[str, JsonValue]]] = {}
            buckets: dict[int, list[dict[str, JsonValue]]] = {}
            tails: dict[str, list[JsonValue]] = {}
            deliveries: dict[str, str] = {}

            def checkpoint() -> perf.ProbeMeasurements:
                privacy = perf.evaluate_privacy_probe(buckets, wire)
                privacy["malformed_tail_samples"] = {name: list(rows) for name, rows in tails.items()}
                tail_bad = any(
                    isinstance(row, dict) and (
                        row.get("status") != "invalid_input" or type(row.get("elapsed_ns")) is not int
                    ) for rows in tails.values() for row in rows
                )
                for rows in tails.values():
                    elapsed = [
                        float(str(row["elapsed_ns"])) / 1_000_000 for row in rows
                        if isinstance(row, dict) and type(row.get("elapsed_ns")) is int
                    ]
                    tail_bad = tail_bad or bool(elapsed and perf.nearest_rank_percentile(elapsed, 95) > 100)
                if tail_bad:
                    privacy["accepted"] = False
                    tail_reasons = privacy["reasons"]
                    assert isinstance(tail_reasons, list)
                    tail_reasons.append("malformed private tail exceeded its filter budget or failed its oracle")
                observed = perf.ProbeMeasurements(
                    digest_bytes(env.wheel_path.read_bytes()), "sha256:" + str(wheel_identity["schema_sha256"]),
                    {"version": runtime["version"], "implementation": runtime["implementation"],
                     "executable": runtime["executable"]},
                    perf.evaluate_warm_prepare_probe(warmup, warm),
                    privacy,
                    perf.evaluate_cold_client_probe(cold),
                )
                tmp = attempt / f".progress.{os.getpid()}.{time.monotonic_ns()}.tmp"
                try:
                    tmp.write_bytes(canonical_json(asdict(observed)))
                    for attempt_idx in range(5):
                        try:
                            os.replace(tmp, attempt / "measurements-progress.json")
                            break
                        except PermissionError:
                            if attempt_idx == 4:
                                raise
                            time.sleep(0.02)
                finally:
                    if tmp.exists():
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
                return observed

            checkpoint()
            with _daemon(env, config, repo, attempt) as (_, records), InstalledMcpPipeSession(
                env, "brain-mcp", ["--profile", str(profile)], cwd=Path(binding.checkout_path),
            ) as shim:
                shim.send_frames_and_expect_response(mcp_init_frames())
                for index in range(perf.WARMUP_CALLS + perf.WARM_PREPARE_SAMPLES):
                    key = f"perf-prepare-{index:04d}"
                    args: dict[str, JsonValue] = {
                        "schema_version": "2.0", "description": "synthetic benchmark",
                        "workspace_hint": binding.alias, "idempotency_key": key,
                    }
                    destination = warmup if index < perf.WARMUP_CALLS else warm
                    try:
                        envelope = _response(shim.send_frames_and_expect_response([mcp_call_frame(
                            f"prepare-{index}", "prepare_task", args,
                        )], timeout=3))
                        sample = records.get(timeout=3)
                    except (AssertionError, OSError, queue.Empty):
                        destination.append({"idempotency_key": key, "status": "transport_error"})
                        checkpoint()
                        raise
                    if not isinstance(sample, dict) or sample.get("idempotency_key") != key:
                        raise RuntimeError("daemon measurement does not match the request")
                    data = envelope.get("data", {})
                    sample["delivery_verified"] = False
                    if envelope.get("ok") is True and isinstance(data.get("delivery_id"), str):
                        deliveries[key] = data["delivery_id"]
                    destination.append(sample)
                    checkpoint()
                wire_args, _, _ = perf.build_wire_privacy_sample()
                # Use the actual task from the corresponding durable Delivery.
                rows = store_rows(data_root, "SELECT task_id FROM p_fixture_domain_deliveries WHERE delivery_id = ?",
                                  (deliveries[str(warm[-1]["idempotency_key"])],))
                wire_args["task_id"] = str(rows[0][0])
                frame = mcp_call_frame("perf-wire", "submit_episode", wire_args)
                try:
                    shim.send_frames_and_expect_response([frame], timeout=3)
                    observed = records.get(timeout=3)
                    if not isinstance(observed, dict):
                        raise RuntimeError("wire filter did not produce a measurement")
                    observed.update(
                        rejected_before_filter=False, elapsed_ns=int(str(observed["filter_end_ns"]))
                        - int(str(observed["filter_start_ns"])), wire_bytes=len(canonical_json(frame)),
                    )
                    wire.append(observed)
                except Exception:
                    wire.append({
                        "idempotency_key": wire_args["idempotency_key"],
                        "status": "transport_error",
                        "wire_bytes": len(canonical_json(frame)),
                        "filter_ran": False,
                        "rejected_before_filter": False,
                    })
                    checkpoint()
                    raise
                checkpoint()
            actual_ids = {
                str(row[0]) for row in store_rows(data_root, "SELECT delivery_id FROM p_fixture_domain_deliveries")
            }
            for row in (*warmup, *warm):
                key = str(row["idempotency_key"])
                row["delivery_verified"] = deliveries.get(key) in actual_ids
            checkpoint()
            for entrypoint in ("brain-mcp", "brain mcp"):
                cold[entrypoint] = []
                script, prefix = ("brain-mcp", []) if entrypoint == "brain-mcp" else ("brain", ["mcp"])
                for _ in range(perf.COLD_CLIENT_SPAWNS):
                    started = time.perf_counter_ns()
                    sample = {"status": "transport_error", "started_ns": started}
                    try:
                        with InstalledMcpPipeSession(
                            env, script, [*prefix, "--profile", str(profile)], cwd=Path(binding.checkout_path),
                        ) as shim:
                            sample["pid"] = shim._proc.pid
                            first = shim.send_frames_and_expect_response(mcp_init_frames(), timeout=5)
                            received = time.perf_counter_ns()
                            sample.update({
                                "status": "ok", "first_frame_ns": received, "elapsed_ns": received - started,
                                "first_frame": first, "valid_initialize_frame": perf.valid_initialize_frame(first),
                            })
                    except (AssertionError, OSError):
                        cold[entrypoint].append(sample)
                        checkpoint()
                        raise
                    cold[entrypoint].append(sample)
                    checkpoint()
            _local_privacy(buckets, checkpoint=checkpoint, tails=tails)
            return checkpoint()


if __name__ == "__main__":
    raise SystemExit(child(Path(sys.argv[2])))
