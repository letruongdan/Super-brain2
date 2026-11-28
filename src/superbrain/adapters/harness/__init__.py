"""Checkout-scoped capture adapters and Layer-2 receipt probes for Claude Code and Codex (SP2-5)."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "CLAUDE_EVENT_KIND_MAP": ("superbrain.adapters.harness.claude_code", "CLAUDE_EVENT_KIND_MAP"),
    "CODEX_EVENT_KIND_MAP": ("superbrain.adapters.harness.codex", "CODEX_EVENT_KIND_MAP"),
    "NATIVE_HOST_RECEIPT_SCHEMA_VERSION": (
        "superbrain.adapters.harness.layer2_probe",
        "NATIVE_HOST_RECEIPT_SCHEMA_VERSION",
    ),
    "AdaptedCaptureEvent": ("superbrain.adapters.harness._common", "AdaptedCaptureEvent"),
    "AdapterCaptureStatus": ("superbrain.adapters.harness._common", "AdapterCaptureStatus"),
    "AuthorityCommandProbeResult": ("superbrain.adapters.harness.layer2_probe", "AuthorityCommandProbeResult"),
    "ClaudeCodeCaptureAdapter": ("superbrain.adapters.harness.claude_code", "ClaudeCodeCaptureAdapter"),
    "CodexCaptureAdapter": ("superbrain.adapters.harness.codex", "CodexCaptureAdapter"),
    "HarnessCaptureContext": ("superbrain.adapters.harness._common", "HarnessCaptureContext"),
    "HarnessConfigInspection": ("superbrain.adapters.harness._common", "HarnessConfigInspection"),
    "Layer2ReceiptVerdict": ("superbrain.adapters.harness.layer2_probe", "Layer2ReceiptVerdict"),
    "NativeHostReceipt": ("superbrain.adapters.harness.layer2_probe", "NativeHostReceipt"),
    "TranscriptReadResult": ("superbrain.adapters.harness._common", "TranscriptReadResult"),
    "compute_harness_config_digest": ("superbrain.adapters.harness.layer2_probe", "compute_harness_config_digest"),
    "find_host_executable": ("superbrain.adapters.harness.host_version", "find_host_executable"),
    "probe_installed_host_version": ("superbrain.adapters.harness.host_version", "probe_installed_host_version"),
    "probe_observed_host_versions": ("superbrain.adapters.harness.host_version", "probe_observed_host_versions"),
    "verify_native_host_receipt": ("superbrain.adapters.harness.layer2_probe", "verify_native_host_receipt"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = target
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *__all__])


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
