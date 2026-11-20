"""Application use case for checkout-scoped harness bootstrap proposals (spec 11.3, I3-5)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ChangeProposal
from superbrain.ports.bootstrap import BootstrapPlannerPort, HarnessProfileValidatorPort
from superbrain.ports.os import OsAdapters

__all__ = ["BootstrapHarnessId", "create_bootstrap_proposal"]

BootstrapHarnessId = Literal["claude-code", "codex"]
_SUPPORTED_HARNESSES = frozenset({"claude-code", "codex"})


def _validate_abs_path(path: Path, os_: OsAdapters) -> None:
    raw = str(path)
    if not raw or "\x00" in raw or not path.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    os_.paths.reject_unsafe_path(raw)
    if os.path.lexists(path):
        os_.paths.reject_links(path)


def create_bootstrap_proposal(
    review_apply: ReviewApplyService,
    *,
    owner_id: str,
    harness_id: BootstrapHarnessId,
    checkout_root: Path,
    harness_profile_path: Path,
    planner: BootstrapPlannerPort,
    profile_validator: HarnessProfileValidatorPort,
    os_: OsAdapters,
    reason: str | None = None,
) -> ChangeProposal:
    """Validate harness profile, plan checkout-scoped edits, and store a ``HIGH``-risk ``PENDING`` proposal."""
    if harness_id not in _SUPPORTED_HARNESSES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _validate_abs_path(checkout_root, os_)
    _validate_abs_path(harness_profile_path, os_)
    if not checkout_root.is_dir():
        raise BrainError(ErrorCode.NOT_FOUND, "checkout root not found")
    if reason is not None and (not isinstance(reason, str) or not reason or "\x00" in reason):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    profile_validator.validate_harness_profile(
        owner_id=owner_id,
        harness_id=harness_id,
        checkout_root=checkout_root,
        harness_profile_path=harness_profile_path,
    )
    expected_digests = review_apply.active_slice_digests(checkout_root, owner_id=owner_id)
    plan = planner.plan_bootstrap(
        harness_id=harness_id,
        checkout_root=checkout_root,
        profile_path=harness_profile_path,
        expected_slice_digests=expected_digests,
    )
    writes = tuple(
        TargetWriteInput(
            root_path=checkout_root,
            rel_path=t.rel_path,
            replacement_bytes=t.preview_text.encode("utf-8"),
            managed_format=t.managed_format,
            slice_id=t.slice_id,
            managed_slice_digest=t.slice_digest,
        )
        for t in plan.targets
    )
    return review_apply.create_proposal(
        owner_id=owner_id,
        kind="bootstrap",
        reason=reason if reason is not None else f"bootstrap {harness_id}",
        resources=plan.resources,
        targets=writes,
    )
