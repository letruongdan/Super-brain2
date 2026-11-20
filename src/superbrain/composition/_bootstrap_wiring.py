"""Composition wiring for pre-generation harness profile validation and bootstrap proposals (F1)."""

from __future__ import annotations

import os
from pathlib import Path

from superbrain.adapters.harness_config.bootstrap_templates import AdapterBootstrapPlanner
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import (
    read_client_ca,
    read_client_credential,
    read_client_profile,
)
from superbrain.adapters.os.workspaces import physical_checkout, verify_launch_checkout
from superbrain.application._approvals_types import BootstrapProposalHandler
from superbrain.application.bootstrap import create_bootstrap_proposal
from superbrain.application.review_apply import ReviewApplyService
from superbrain.composition._tls_identity import resolve_expected_identity, verify_profile_tls_identity
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope
from superbrain.core.proposals import ChangeProposal
from superbrain.ports.approval import ApprovalPolicyPort
from superbrain.ports.bootstrap import HarnessProfileValidatorPort
from superbrain.ports.os import OsAdapters

__all__ = ["PolicyHarnessProfileValidator", "make_default_bootstrap_handler"]


class PolicyHarnessProfileValidator(HarnessProfileValidatorPort):
    """Validates a harness-specific ``ClientProfile`` against ``ApprovalPolicyPort`` and checkout identity."""

    def __init__(
        self,
        policy: ApprovalPolicyPort,
        os_: OsAdapters,
        *,
        expected_endpoint_path: Path | None = None,
        expected_leaf_cert_sha256: str | None = None,
        server_cert_path: Path | None = None,
    ) -> None:
        self._policy = policy
        self._os = os_
        self._expected_endpoint_path = expected_endpoint_path
        self._expected_leaf_cert_sha256 = expected_leaf_cert_sha256
        self._server_cert_path = server_cert_path

    def validate_harness_profile(
        self,
        *,
        owner_id: str,
        harness_id: str,
        checkout_root: Path,
        harness_profile_path: Path,
    ) -> None:
        profile = read_client_profile(harness_profile_path, self._os)
        if profile.workspace is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "harness profile must declare workspace")
        if profile.expected_store_id != self._policy.store_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        ca_pem = read_client_ca(profile.ca_file, self._os)
        ep_raw = os.fspath(profile.endpoint_path)
        self._os.paths.reject_unsafe_path(ep_raw)
        if ".." in profile.endpoint_path.parts:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        self._os.paths.reject_links(profile.endpoint_path)
        if self._os.permissions.check_ancestors(profile.endpoint_path):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")

        token = read_client_credential(profile.credential_file, self._os)
        snap = self._policy.snapshot()
        principal = snap.resolve_credential(token)
        if principal.owner_id != owner_id or principal.harness_id != harness_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        verify_launch_checkout(profile.workspace.checkout_path, checkout_root, self._os)
        phys_prof = physical_checkout(str(profile.workspace.checkout_path))
        phys_chk = physical_checkout(str(checkout_root))
        if phys_prof.checkout_path != phys_chk.checkout_path:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        binding = snap.checkouts.get(profile.workspace.expected_checkout_id)
        if (
            binding is None
            or binding.owner_id != owner_id
            or binding.repo_id != profile.workspace.expected_workspace_id
            or binding.machine_id != principal.machine_id
            or binding.alias != profile.workspace.alias
            or Path(binding.checkout_path) != Path(phys_chk.checkout_path)
            or not snap.allows(
                principal,
                Scope(repo_id=binding.repo_id, checkout_id=binding.checkout_id),
                action="prepare_task",
            )
        ):
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

        # Pinned daemon identity (F1): endpoint, leaf pin and CA must belong to this store's daemon.
        expected = resolve_expected_identity(
            self._policy,
            endpoint_path=self._expected_endpoint_path,
            leaf_cert_sha256=self._expected_leaf_cert_sha256,
            server_cert_path=self._server_cert_path,
        )
        verify_profile_tls_identity(profile, expected, ca_pem)


def make_default_bootstrap_handler(
    policy: ApprovalPolicyPort,
    os_: OsAdapters | None = None,
    *,
    expected_endpoint_path: Path | None = None,
    expected_leaf_cert_sha256: str | None = None,
    server_cert_path: Path | None = None,
) -> BootstrapProposalHandler:
    """Return a default checkout-scoped bootstrap handler wired to ``PolicyHarnessProfileValidator``."""
    adapters = os_ if os_ is not None else os_adapters()
    planner = AdapterBootstrapPlanner()

    def _handle(
        review_apply: ReviewApplyService,
        *,
        owner_id: str,
        harness_id: str,
        checkout_root: Path,
        harness_profile_path: Path,
        reason: str | None = None,
        policy: ApprovalPolicyPort = policy,
    ) -> ChangeProposal:
        validator = PolicyHarnessProfileValidator(
            policy,
            adapters,
            expected_endpoint_path=expected_endpoint_path,
            expected_leaf_cert_sha256=expected_leaf_cert_sha256,
            server_cert_path=server_cert_path,
        )
        if harness_id == "claude-code":
            return create_bootstrap_proposal(
                review_apply,
                owner_id=owner_id,
                harness_id="claude-code",
                checkout_root=checkout_root,
                harness_profile_path=harness_profile_path,
                planner=planner,
                profile_validator=validator,
                os_=adapters,
                reason=reason,
            )
        if harness_id == "codex":
            return create_bootstrap_proposal(
                review_apply,
                owner_id=owner_id,
                harness_id="codex",
                checkout_root=checkout_root,
                harness_profile_path=harness_profile_path,
                planner=planner,
                profile_validator=validator,
                os_=adapters,
                reason=reason,
            )
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    return _handle
