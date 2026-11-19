"""Composition of the ``/v2/operator/*`` surface: verifiers, ``OperatorService`` and the owner-thread executor."""

from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import TypeVar

from superbrain.adapters.auth.ssh_sig import SshSigVerifier
from superbrain.adapters.os import find_ssh_keygen, os_adapters
from superbrain.application.approvals import OperatorHandle, OperatorService, PreparedOperatorCall
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api.operator import OperatorExecutor, OperatorRequest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CallResult
from superbrain.core.wire import make_error_envelope, make_success_envelope
from superbrain.ports.approval import ApprovalPolicyPort, SshApprovalVerifierPort
from superbrain.ports.os import OsAdapters

__all__ = ["build_operator_service", "make_operator_executor"]

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


def build_operator_service(policy: ApprovalPolicyPort, *, os_: OsAdapters | None = None) -> OperatorService:
    """The operator service over ``policy`` with the real ``ssh-keygen`` verifier and verified scratch dir."""

    def _lazy_ssh_verifier() -> SshApprovalVerifierPort | None:
        keygen = find_ssh_keygen()
        if keygen is None:
            return None
        adapters = os_ if os_ is not None else os_adapters()
        scratch = _verified_ssh_scratch_dir(adapters)
        return SshSigVerifier(ssh_keygen=keygen, scratch_dir=scratch, os_=adapters)

    return OperatorService(policy, ssh_verifier=_lazy_ssh_verifier)


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
