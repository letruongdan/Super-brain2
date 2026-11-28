"""``get_health(deep=true)`` has one renderer and one code vocabulary, and re-evaluates its live conditions on every
read path: a replay of an SP2-5-era result, a stale DoctorRun code that has cleared, and a Layer-2 config change made
after the latest DoctorRun."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition._daemon_deep_health import historical_codes
from superbrain.composition._daemon_session import _DaemonCompositeDomain
from superbrain.core.ids import new_id
from superbrain.core.kernel import ObjectRef, StoredResult, ToolCommand
from superbrain.core.wire import SCHEMA_VERSION
from tests.integration.test_layer2_runtime_intents_applied import _verified_store
from tests.integration.test_sp2_5_production_wiring import _MACHINE, _OWNER, _serve_daemon
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.kernel_auth import seed_principal_and_credential


class _RecordingDoctor:
    def __init__(self) -> None:
        self.rendered: list[StoredResult] = []

    def render_deep_health(self, result: StoredResult, principal: Any, *, selected_scope: Any) -> dict[str, Any]:
        self.rendered.append(result)
        return {"rendered_by": "doctor"}


def test_a_replayed_sp2_era_health_result_is_rendered_by_the_doctor_renderer() -> None:
    domain = _DaemonCompositeDomain(cast(Any, object()), None, fallback=cast(Any, object()))
    doctor = _RecordingDoctor()
    domain.bind_doctor_runner(cast(Any, doctor))
    rid = new_id()
    stored = StoredResult(result_id=rid, assignment_id=None,
                          refs=(ObjectRef(kind="health_result", id=rid, revision=1, digest="sha256:" + "0" * 64),))
    assert domain.render_stored(stored, cast(Any, object()), selected_scope=None) == {"rendered_by": "doctor"}
    assert doctor.rendered == [stored]


def test_live_codes_are_dropped_from_a_doctor_runs_history() -> None:
    run_doc: dict[str, Any] = {
        "degraded_codes": ["storage.policy_reconcile", "sp2.capture_gaps", "capture_gap_present", "harness.layer2",
                           "sp2.layer2_drift", "retention.tombstones"],
    }
    assert historical_codes(run_doc) == ("storage.policy_reconcile", "retention.tombstones")


def test_a_layer2_config_change_after_the_latest_doctor_run_shows_in_deep_health(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _verified_store(trusted_tmp, monkeypatch)
    rt = reopen_kernel_job_runtime(env["data_root"], env["rep"].store_id, env["os_"])
    try:
        mcp = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
    finally:
        rt.close()
    with _serve_daemon(env["cfg"], env["os_"], env["clock"], env["mono"]) as (ready, _loop):
        target = LoopbackTarget(endpoint=ready.endpoint, expected_store_id=env["rep"].store_id, ca_pem=env["ca_pem"],
                                leaf_cert_sha256=ready.leaf_cert_sha256)
        client = LoopbackClient(monotonic_ns=env["mono"].monotonic_ns)

        def _deep() -> list[str]:
            res = client.call(target, ToolCommand(
                "get_health", {"schema_version": SCHEMA_VERSION, "deep": True, "idempotency_key": f"idem-{new_id()}"},
                token=mcp.token,
            ))
            assert res.get("ok") is True, res
            return [str(c) for c in cast(dict[str, Any], res["data"])["degraded_codes"]]

        assert "harness.layer2" not in _deep()  # verified and unchanged
        settings = env["chk"] / ".claude" / "settings.local.json"
        settings.write_bytes(settings.read_bytes().replace(b'"hooks"', b'"theme":"dark","hooks"', 1))
        assert "harness.layer2" in _deep()  # same DoctorRun, but the checkout config no longer matches
