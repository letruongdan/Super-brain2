"""Bootstrap planner port and spec DTOs shared between adapters and application (spec 11.3, D3, I3-5)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from superbrain.core._kernel_approval import RiskResource
from superbrain.core.proposals import ManagedFormat

__all__ = [
    "BootstrapPlanSpec",
    "BootstrapPlannerPort",
    "BootstrapTargetSpec",
    "HarnessProfileValidatorPort",
]


@dataclass(frozen=True)
class BootstrapTargetSpec:
    """Single checkout-scoped bootstrap target produced by a harness planner adapter."""

    rel_path: str
    managed_format: ManagedFormat
    slice_id: str
    slice_digest: str
    preview_text: str


@dataclass(frozen=True)
class BootstrapPlanSpec:
    """Complete checkout-scoped bootstrap plan returned by a ``BootstrapPlannerPort``."""

    harness_id: str
    checkout_root: Path
    profile_path: Path
    resources: tuple[RiskResource, ...]
    targets: tuple[BootstrapTargetSpec, ...]


class HarnessProfileValidatorPort(Protocol):
    """Port validating a checkout-scoped harness profile before bootstrap planning."""

    def validate_harness_profile(
        self,
        *,
        owner_id: str,
        harness_id: str,
        checkout_root: Path,
        harness_profile_path: Path,
    ) -> None: ...


class BootstrapPlannerPort(Protocol):
    """Port implemented by harness config adapters to plan checkout-scoped bootstrap edits."""

    def plan_bootstrap(
        self,
        *,
        harness_id: str,
        checkout_root: Path,
        profile_path: Path,
        expected_slice_digests: Mapping[tuple[str, str], str] | None = None,
    ) -> BootstrapPlanSpec: ...
