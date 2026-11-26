"""Codex checkout-scoped capture & transcript adapter (SP2-5)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from superbrain.adapters.harness._common import (
    AdaptedCaptureEvent,
    HarnessCaptureContext,
    HarnessConfigInspection,
    TranscriptReadResult,
    adapt_harness_event,
    compute_checkout_config_digest,
    read_scoped_transcript_file,
)
from superbrain.ports.os import OsAdapters

CODEX_EVENT_KIND_MAP: dict[str, str] = {
    "user_prompt": "user_prompt",
    "user_message": "user_message",
    "command_started": "command_started",
    "command_completed": "command_result",
    "command_result": "command_result",
    "agent_turn_end": "assistant_response",
    "assistant_response": "assistant_response",
    "session_start": "session_resumed",
    "session_end": "session_end",
    "session_ended": "session_ended",
    "session_resumed": "session_resumed",
}


class CodexCaptureAdapter:
    """Capture adapter for Codex checkout-scoped hooks, TOML config and transcripts."""

    HARNESS_ID = "codex"

    def __init__(self, os_: OsAdapters) -> None:
        self._os = os_

    def inspect_checkout_config(self, checkout_root: Path) -> HarnessConfigInspection:
        cfg_dig, files, hooks_ok, ask_covered = compute_checkout_config_digest(
            harness_id=self.HARNESS_ID,
            checkout_root=checkout_root,
            os_=self._os,
        )
        return HarnessConfigInspection(
            harness_id=self.HARNESS_ID,
            checkout_root=checkout_root,
            hooks_configured=hooks_ok,
            config_digest=cfg_dig,
            ask_commands_covered=ask_covered,
            present_files=files,
        )

    def adapt_hook_event(
        self,
        raw_event: Mapping[str, object],
        *,
        context: HarnessCaptureContext,
    ) -> AdaptedCaptureEvent:
        insp = (
            None
            if context.expected_config_digest is not None
            else self.inspect_checkout_config(context.checkout_root)
        )
        return adapt_harness_event(
            raw_event,
            harness_id=self.HARNESS_ID,
            context=context,
            event_kind_map=CODEX_EVENT_KIND_MAP,
            os_=self._os,
            inspect_fn=insp,
        )

    def read_scoped_transcript(
        self,
        transcript_path: Path,
        *,
        context: HarnessCaptureContext,
        allowed_roots: Sequence[Path],
        start_sequence: int = 1,
    ) -> TranscriptReadResult:
        insp = (
            None
            if context.expected_config_digest is not None
            else self.inspect_checkout_config(context.checkout_root)
        )
        return read_scoped_transcript_file(
            transcript_path,
            harness_id=self.HARNESS_ID,
            context=context,
            allowed_roots=allowed_roots,
            event_kind_map=CODEX_EVENT_KIND_MAP,
            os_=self._os,
            inspect_fn=insp,
            start_sequence=start_sequence,
        )


__all__ = ["CODEX_EVENT_KIND_MAP", "CodexCaptureAdapter"]
