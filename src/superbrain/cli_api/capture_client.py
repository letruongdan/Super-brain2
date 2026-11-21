"""Loopback capture client wrapping ``LoopbackClient.post_capture`` into typed ``CaptureBatchAck``."""

from __future__ import annotations

from superbrain.application.capture_ingest import CaptureBatchAck, parse_capture_batch_ack
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import CaptureBatchCommand


class CaptureClient:
    """Thin loopback client adapter for ``POST /v2/capture/events``."""

    def __init__(self, client: LoopbackClient) -> None:
        if not isinstance(client, LoopbackClient):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._client = client

    def post_batch(
        self,
        target: LoopbackTarget,
        command: CaptureBatchCommand,
        *,
        deadline_ns: int | None = None,
    ) -> CaptureBatchAck:
        """Send one ``CaptureBatchCommand`` over pin-before-secret TLS and parse ``CaptureBatchAck``."""
        result = self._client.post_capture(target, command, deadline_ns=deadline_ns)
        return parse_capture_batch_ack(result)
