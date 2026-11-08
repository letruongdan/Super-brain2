"""Task 6a owner loop, startup/shutdown lifecycle coordinator, and RAM ``AuthGate``."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import TypeVar

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    DEFAULT_SHUTDOWN_GRACE_S,
    ArtifactSendAttempt,
    AuthGrantStamp,
    AuthSnapshot,
    BootstrapAuthorization,
    CallResult,
    DaemonConfig,
    Identity,
    InvocationRecord,
    JobRecord,
    OwnerReply,
    Ready,
    RequestAuthView,
    SendAttemptCompletion,
    ShallowHealthMeta,
    ShutdownReport,
    ToolCommand,
    WorkerCommand,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.core.wire import make_error_envelope
from superbrain.ports.kernel import RequestAuthStatePort
from superbrain.ports.policy import Intent

_T = TypeVar("_T")

__all__ = ["AuthGate", "OwnerLoop"]


def _unavailable_error() -> BrainError:
    return BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")


def _failed_future(error: BrainError) -> Future[_T]:
    fut: Future[_T] = Future()
    fut.set_exception(error)
    return fut


class AuthGate(RequestAuthStatePort):
    """Single short-mutex RAM gate for ``RequestAuthView``, shallow health metadata, and release grants."""

    def __init__(self, store_id: str, writer_epoch: int, instance_id: str) -> None:
        self._identity = Identity(
            store_id=store_id,
            writer_epoch=writer_epoch,
            instance_id=instance_id,
        )
        self._lock = threading.Lock()
        self._closed = False
        self._issued_version = 0

    @property
    def identity(self) -> Identity:
        return self._identity

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def current(self) -> RequestAuthView | None:
        return None

    def current_with_health(self) -> tuple[RequestAuthView | None, ShallowHealthMeta | None, bool]:
        return (None, None, False)

    def next_version(self) -> int:
        with self._lock:
            self._issued_version += 1
            return self._issued_version

    def invalidate(self) -> None:
        return None

    def publish(
        self,
        snapshot: AuthSnapshot,
        *,
        active_request_key_id: str | None = None,
        active_request_key_bytes: bytes | None = None,
        health_meta: ShallowHealthMeta | None = None,
        version: int | None = None,
    ) -> RequestAuthView | None:
        del snapshot, active_request_key_id, active_request_key_bytes, health_meta, version
        raise _unavailable_error()

    def publish_view(
        self,
        view: RequestAuthView,
        *,
        health_meta: ShallowHealthMeta | None = None,
    ) -> RequestAuthView | None:
        del view, health_meta
        raise _unavailable_error()

    def install_view(
        self,
        view: RequestAuthView,
        *,
        health_meta: ShallowHealthMeta | None = None,
    ) -> RequestAuthView | None:
        return self.publish_view(view, health_meta=health_meta)

    def update_clock_untrusted(self, untrusted: bool) -> None:
        if not isinstance(untrusted, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    def authorize_release(self, credential_id: str, generation: int) -> bool:
        del credential_id, generation
        return False

    def authorize_stamp(self, stamp: AuthGrantStamp) -> bool:
        del stamp
        return False

    def close(self) -> None:
        with self._lock:
            self._closed = True


class OwnerLoop:
    """Single-owner daemon lifecycle and request/worker/send-attempt coordinator."""

    def __init__(self) -> None:
        self._ready: Ready | None = None

    @property
    def ready(self) -> Ready | None:
        return self._ready

    @property
    def auth_gate(self) -> AuthGate:
        raise _unavailable_error()

    def start(self, config: DaemonConfig) -> Ready:
        del config
        raise _unavailable_error()

    def submit(self, command: ToolCommand, deadline_ns: int) -> Future[CallResult]:
        del command, deadline_ns
        fut: Future[CallResult] = Future()
        fut.set_result(make_error_envelope(_unavailable_error()))
        return fut

    def submit_reply(self, command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
        del command, deadline_ns
        fut: Future[OwnerReply] = Future()
        fut.set_result(
            OwnerReply(
                envelope=make_error_envelope(_unavailable_error()),
                grant_stamp=None,
                send_completion=None,
            )
        )
        return fut

    def apply_worker_command(self, cmd: WorkerCommand) -> Future[JobRecord | InvocationRecord]:
        del cmd
        return _failed_future(_unavailable_error())

    def finalize_send_attempt(self, completion: SendAttemptCompletion) -> Future[ArtifactSendAttempt]:
        del completion
        return _failed_future(_unavailable_error())

    def interrupt_send_attempt(self, send_attempt_id: str) -> Future[ArtifactSendAttempt]:
        del send_attempt_id
        return _failed_future(_unavailable_error())

    def revoke_credential(
        self,
        credential_id: str,
        authorization: BootstrapAuthorization,
    ) -> Future[Intent]:
        del credential_id, authorization
        return _failed_future(_unavailable_error())

    def register_workspace(
        self,
        registration: WorkspaceRegistration,
        authorization: BootstrapAuthorization,
    ) -> Future[WorkspaceBinding]:
        del registration, authorization
        return _failed_future(_unavailable_error())

    def run_owner_action(self, action: Callable[[], _T]) -> Future[_T]:
        del action
        return _failed_future(_unavailable_error())

    def stop(self, grace_s: float = DEFAULT_SHUTDOWN_GRACE_S) -> ShutdownReport:
        del grace_s
        raise _unavailable_error()
