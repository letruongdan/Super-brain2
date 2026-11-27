"""Checkout-scoped capture adapters and Layer-2 receipt probes for Claude Code and Codex (SP2-5)."""

from __future__ import annotations

from superbrain.adapters.harness._common import (
    AdaptedCaptureEvent,
    AdapterCaptureStatus,
    HarnessCaptureContext,
    HarnessConfigInspection,
    TranscriptReadResult,
)
from superbrain.adapters.harness.claude_code import CLAUDE_EVENT_KIND_MAP, ClaudeCodeCaptureAdapter
from superbrain.adapters.harness.codex import CODEX_EVENT_KIND_MAP, CodexCaptureAdapter
from superbrain.adapters.harness.host_version import (
    find_host_executable,
    probe_installed_host_version,
    probe_observed_host_versions,
)
from superbrain.adapters.harness.layer2_probe import (
    NATIVE_HOST_RECEIPT_SCHEMA_VERSION,
    AuthorityCommandProbeResult,
    Layer2ReceiptVerdict,
    NativeHostReceipt,
    compute_harness_config_digest,
    verify_native_host_receipt,
)

__all__ = [
    "CLAUDE_EVENT_KIND_MAP",
    "CODEX_EVENT_KIND_MAP",
    "NATIVE_HOST_RECEIPT_SCHEMA_VERSION",
    "AdaptedCaptureEvent",
    "AdapterCaptureStatus",
    "AuthorityCommandProbeResult",
    "ClaudeCodeCaptureAdapter",
    "CodexCaptureAdapter",
    "HarnessCaptureContext",
    "HarnessConfigInspection",
    "Layer2ReceiptVerdict",
    "NativeHostReceipt",
    "TranscriptReadResult",
    "compute_harness_config_digest",
    "find_host_executable",
    "probe_installed_host_version",
    "probe_observed_host_versions",
    "verify_native_host_receipt",
]
