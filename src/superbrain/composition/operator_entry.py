"""Composition of the ``/v2/operator/*`` surface: verifiers, ``OperatorService`` and the owner-thread executor."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from superbrain.adapters.auth.ssh_sig import SshSigVerifier
from superbrain.adapters.os import find_ssh_keygen, os_adapters
from superbrain.application.approvals import (
    BootstrapProposalHandler,
    OperatorHandle,
    OperatorService,
    PreparedOperatorCall,
    RestoreHandler,
)
from superbrain.application.owner_loop import OwnerLoop
from superbrain.application.review_apply import ReviewApplyService
from superbrain.cli_api.operator import OperatorExecutor, OperatorRequest
from superbrain.composition._bootstrap_wiring import make_default_bootstrap_handler
from superbrain.core._kernel_approval import ApprovalMessage, strict_b64url_decode
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CallResult
from superbrain.core.wire import make_error_envelope, make_success_envelope
from superbrain.ports.approval import ApprovalPolicyPort, SshApprovalVerifierPort, WebAuthnApprovalVerifierPort
from superbrain.ports.os import OsAdapters

if TYPE_CHECKING:
    from superbrain.adapters.auth.webauthn_verifier import WebAuthnResult

__all__ = ["build_operator_service", "make_default_bootstrap_handler", "make_operator_executor"]

_T = TypeVar("_T")
_SLICE_S = 0.005


def _verified_ssh_scratch_dir(adapters: OsAdapters) -> Path:
    base = adapters.traits.resolved_default_scratch_base()
    if base is None:
        raw_tmp = adapters.traits.resolved_temp_dir()
        if raw_tmp is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        resolved_tmp = raw_tmp.resolve() if adapters.traits.resolve_temp_links else Path(os.path.abspath(raw_tmp))
        base = resolved_tmp / "superbrain-scratch"
    else:
        adapters.paths.reject_unsafe_path(str(base))
        base = Path(os.path.abspath(base))
    scratch = base / "ssh-verify"
    adapters.paths.reject_unsafe_path(str(scratch))
    adapters.paths.reject_links(scratch)
    if adapters.permissions.check_ancestors(scratch):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    missing: list[Path] = []
    for candidate in (scratch, *scratch.parents):
        if os.path.lexists(candidate):
            break
        missing.append(candidate)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        adapters.paths.reject_links(directory)
        if not directory.is_dir():
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        adapters.permissions.secure_directory(directory)
        if adapters.permissions.object_problems(directory):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

    adapters.paths.reject_links(scratch)
    if adapters.permissions.check_ancestors(scratch):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    if not scratch.is_dir():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if adapters.permissions.object_problems(scratch):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    return scratch


def make_lazy_ssh_verifier(os_: OsAdapters | None = None) -> Callable[[], SshApprovalVerifierPort | None]:
    """Return a lazy ``ssh-keygen`` approval verifier factory with verified scratch dir."""

    def _lazy_ssh_verifier() -> SshApprovalVerifierPort | None:
        keygen = find_ssh_keygen()
        if keygen is None:
            return None
        adapters = os_ if os_ is not None else os_adapters()
        scratch = _verified_ssh_scratch_dir(adapters)
        return SshSigVerifier(ssh_keygen=keygen, scratch_dir=scratch, os_=adapters)

    return _lazy_ssh_verifier


_LOCALHOST_ORIGIN_RE = re.compile(r"\Ahttp://localhost:([1-9][0-9]{0,4})\Z")


class _LocalhostWebAuthnVerifier(WebAuthnApprovalVerifierPort):
    """WebAuthn verifier enforcing RP ID ``localhost`` and a valid ``http://localhost:<port>`` origin."""

    def verify(
        self,
        message: ApprovalMessage,
        *,
        response_json: str,
        credential_id: bytes,
        credential_public_key: bytes,
        stored_sign_count: int,
    ) -> WebAuthnResult:
        if not isinstance(response_json, str) or len(response_json) > 64 * 1024:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        try:
            payload = json.loads(response_json)
            if not isinstance(payload, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            resp = payload.get("response")
            if not isinstance(resp, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            raw_cdj = resp.get("clientDataJSON")
            if not isinstance(raw_cdj, str):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            cdj = json.loads(strict_b64url_decode(raw_cdj).decode("utf-8"))
            if not isinstance(cdj, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            origin = cdj.get("origin")
        except BrainError:
            raise
        except Exception as err:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated") from err
        if not isinstance(origin, str):
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        match = _LOCALHOST_ORIGIN_RE.match(origin)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        from superbrain.adapters.auth.webauthn_verifier import WebAuthnApprovalVerifier

        return WebAuthnApprovalVerifier(rp_id="localhost", origin=origin).verify(
            message,
            response_json=response_json,
            credential_id=credential_id,
            credential_public_key=credential_public_key,
            stored_sign_count=stored_sign_count,
        )


def build_operator_service(
    policy: ApprovalPolicyPort,
    *,
    os_: OsAdapters | None = None,
    webauthn_verifier: WebAuthnApprovalVerifierPort | None = None,
    review_apply: ReviewApplyService | None = None,
    restore_handler: RestoreHandler | None = None,
    bootstrap_handler: BootstrapProposalHandler | None = None,
    expected_endpoint_path: Path | None = None,
    expected_leaf_cert_sha256: str | None = None,
    server_cert_path: Path | None = None,
) -> OperatorService:
    """The operator service over ``policy`` with real SSH, localhost WebAuthn, and bootstrap wiring."""
    return OperatorService(
        policy,
        ssh_verifier=make_lazy_ssh_verifier(os_),
        webauthn_verifier=webauthn_verifier if webauthn_verifier is not None else _LocalhostWebAuthnVerifier(),
        review_apply=review_apply,
        restore_handler=restore_handler,
        bootstrap_handler=(
            bootstrap_handler
            if bootstrap_handler is not None
            else make_default_bootstrap_handler(
                policy,
                os_,
                expected_endpoint_path=expected_endpoint_path,
                expected_leaf_cert_sha256=expected_leaf_cert_sha256,
                server_cert_path=server_cert_path,
            )
        ),
    )


def _check_live_budget(owner: OwnerLoop, monotonic_ns: Callable[[], int], deadline_ns: int) -> None:
    if owner.is_stopping or owner.ready is None:
        raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
    if int(monotonic_ns()) >= deadline_ns:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")


def _await_owner_future(
    fut: Future[_T], owner: OwnerLoop, monotonic_ns: Callable[[], int], deadline_ns: int
) -> _T:
    while True:
        _check_live_budget(owner, monotonic_ns, deadline_ns)
        rem_ns = deadline_ns - int(monotonic_ns())
        wait_s = min(_SLICE_S, max(0.001, rem_ns / 1_000_000_000.0))
        try:
            return fut.result(timeout=wait_s)
        except FuturesTimeoutError:
            continue


def make_operator_executor(
    owner: OwnerLoop, handle: OperatorHandle, monotonic_ns: Callable[[], int]
) -> OperatorExecutor:
    """Execute admitted operator requests in 3 phases so crypto verification never blocks ``OwnerLoop``."""

    def execute(request: OperatorRequest, deadline_ns: int) -> CallResult:
        try:
            _check_live_budget(owner, monotonic_ns, deadline_ns)

            def _phase1() -> PreparedOperatorCall:
                _check_live_budget(owner, monotonic_ns, deadline_ns)
                service = handle.service()
                if service is None:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                return service.prepare_call(request.path, request.principal, request.body, token=request.token)

            prepared = _await_owner_future(owner.run_owner_action(_phase1), owner, monotonic_ns, deadline_ns)
            if prepared.immediate is not None:
                return make_success_envelope(prepared.immediate)

            pending = prepared.pending
            assert pending is not None
            _check_live_budget(owner, monotonic_ns, deadline_ns)
            service = handle.service()
            if service is None:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            rem_s = (deadline_ns - int(monotonic_ns())) / 1_000_000_000.0
            new_sign_count = service.verify_pending(pending, timeout_s=rem_s)

            _check_live_budget(owner, monotonic_ns, deadline_ns)

            def _phase3() -> dict[str, JsonValue]:
                _check_live_budget(owner, monotonic_ns, deadline_ns)
                svc = handle.service()
                if svc is None:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                return svc.commit_call(pending, new_sign_count=new_sign_count)

            committed = _await_owner_future(owner.run_owner_action(_phase3), owner, monotonic_ns, deadline_ns)
            return make_success_envelope(committed)
        except BrainError as err:
            return make_error_envelope(err)

    return execute
