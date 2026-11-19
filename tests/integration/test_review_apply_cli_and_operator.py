"""I3-2 oracle: CLI dispatch for ``brain review|apply|rollback`` and ``/v2/operator/proposal/*`` admission.

Requirement sources: spec rev 22 §11.3 (``user:cli`` only), §14.2 CLI, §20 cases 12, 13; plan "Mặt lệnh CLI".
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.cli.main import main as brain_main
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition import review_cli_entry
from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core.errors import SAFE_WIRE_MESSAGES, ErrorCode
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import (
    TransportHarness,
    TransportTemplate,
    create_transport_template,
    open_test_loopback_transport,
)
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential

OWNER = "dan"
PROPOSAL_OPERATOR_PATHS = (
    "/v2/operator/proposal/list",
    "/v2/operator/proposal/show",
    "/v2/operator/proposal/approve",
    "/v2/operator/proposal/reject",
    "/v2/operator/proposal/apply",
    "/v2/operator/proposal/rollback",
)


@pytest.fixture(scope="module")
def proposal_operator_template() -> Iterator[tuple[TransportTemplate, SeededCredential]]:
    template = create_transport_template("i3-2-operator-tpl")
    try:
        adapters = os_adapters(clock=FakeClock(template.base_time))
        rt = reopen_kernel_job_runtime(template.root, template.store_id, adapters)
        try:
            cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="m-2")
        finally:
            rt.close()
        yield template, cli
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


def _op_post(h: TransportHarness, path: str, token: str, body: bytes = b"{}") -> dict[str, object]:
    identity = h.ready.identity
    host = f"127.0.0.1:{h.ready.endpoint.port}"
    with h.open_raw_tls_socket() as sock:
        h.send_raw_http(sock, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"X-Store-Id: {identity.store_id}\r\nX-Writer-Epoch: {identity.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {identity.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1") + body
        raw = h.send_raw_http(sock, req)
    _, _, payload = raw.partition(b"\r\n\r\n")
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    return parsed


def _err_code(envelope: dict[str, object]) -> str | None:
    if envelope.get("ok") is True:
        return None
    err = envelope.get("error")
    assert isinstance(err, dict)
    msg = err.get("message")
    assert isinstance(msg, str) and msg in SAFE_WIRE_MESSAGES, err
    code = err.get("code")
    assert isinstance(code, str)
    return code


def test_cli_review_apply_rollback_dispatch_and_operator_proposal_gate(
    trusted_tmp: Path,
    capfd: pytest.CaptureFixture[str],
    proposal_operator_template: tuple[TransportTemplate, SeededCredential],
) -> None:
    assert hasattr(review_cli_entry, "main")
    assert set(PROPOSAL_OPERATOR_PATHS) <= OPERATOR_PATHS

    for bad_argv in (
        ["review", "list", "--profile", "relative/profile.json"],
        ["review", "show", "p1", "--profile", "relative/profile.json"],
        ["review", "approve", "p1", "--profile", "relative/profile.json"],
        ["review", "reject", "p1", "--profile", "relative/profile.json"],
        ["apply", "p1", "--profile", "relative/profile.json"],
        ["rollback", "p1", "--profile", "relative/profile.json"],
    ):
        capfd.readouterr()
        assert brain_main(bad_argv) == 2, bad_argv
        assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value

    missing_profile = trusted_tmp / "missing-profile.json"
    for missing_argv in (
        ["review", "list", "--profile", str(missing_profile)],
        ["review", "show", "p1", "--profile", str(missing_profile)],
        ["apply", "p1", "--profile", str(missing_profile)],
        ["rollback", "p1", "--profile", str(missing_profile)],
    ):
        capfd.readouterr()
        assert brain_main(missing_argv) == 1, missing_argv
        assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value

    template, cli = proposal_operator_template
    with open_test_loopback_transport(template, name="i3-2-operator") as h:
        before = h.ledger_sequence()
        for path in PROPOSAL_OPERATOR_PATHS:
            assert _err_code(_op_post(h, path, template.cred.token)) == ErrorCode.IDENTITY_MISMATCH.value, path
        assert h.ledger_sequence() == before, "harness bearer MUST NOT trigger any write on /v2/operator/proposal/*"

        bogus = "0192f3a4-5b6c-7d8e-9f01-00000000dead." + "A" * 43
        assert _err_code(_op_post(h, PROPOSAL_OPERATOR_PATHS[0], bogus)) == ErrorCode.UNAUTHENTICATED.value
        for path in PROPOSAL_OPERATOR_PATHS:
            code = _err_code(_op_post(h, path, cli.token))
            assert code not in {ErrorCode.IDENTITY_MISMATCH.value, ErrorCode.UNAUTHENTICATED.value}, (path, code)
