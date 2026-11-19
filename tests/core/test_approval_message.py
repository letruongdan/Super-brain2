"""I3-1 oracle: canonical ``ApprovalMessage``, approval vocabulary, server risk classification and channel rules.

Requirement sources: spec rev 22 §11.3 (channels, assurance, risk rules, approval message fields), §11.2 (target file
binding, recovery scope), §20 cases 12, 16, 19, 20; ledger §2.1-§2.3 (I3-0 contract, R01/R03/R06 rulings).
Expected values are written out here, never computed by the production code under test.
"""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from superbrain.core._kernel_approval import (
    ALWAYS_HIGH_ACTIONS,
    APPROVAL_NAMESPACE,
    APPROVAL_TTL,
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    SIGNER_CHANNELS,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    TargetFile,
    assurance_for,
    classify_policy_change_risk,
    classify_proposal_risk,
    policy_change_subject_id,
    required_channels,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ResourceDigest

D_A = "sha256:" + "a" * 64
D_B = "sha256:" + "b" * 64
D_C = "sha256:" + "c" * 64
D_D = "sha256:" + "d" * 64
ROOT = str(Path(os.path.abspath(os.sep)) / "checkout-a")
EXPIRES = datetime(2026, 11, 19, 6, 10, 0, tzinfo=UTC)

SPEC_ACTIONS = {
    "approve",
    "reject",
    "apply",
    "rollback",
    "lesson_confirm",
    "signer_enroll",
    "signer_revoke",
    "policy_change",
    "credential_revoke",
    "restore",
    "workspace_link",
    "skill_promote",
    "skill_activate",
    "skill_publish",
}
NON_TERMINAL = {"passkey_uv", "ssh_sk_verified", "ssh_sk", "ssh_key"}


def _present_file() -> TargetFile:
    return TargetFile(
        root_path=ROOT,
        normalized_rel_path="CLAUDE.md",
        parent_physical_id="vol-1:dir-42",
        target_physical_id="vol-1:file-7",
        original_digest=D_C,
        original_present=True,
    )


def _absent_file() -> TargetFile:
    return TargetFile(
        root_path=ROOT,
        normalized_rel_path=".mcp.json",
        parent_physical_id="vol-1:dir-42",
        target_physical_id=None,
        original_digest=None,
        original_present=False,
    )


def _fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "store_id": "store-i31-0001",
        "owner_id": "dan",
        "trust_generation": 3,
        "action": ApprovalAction.APPLY,
        "subject_id": "proposal-0001",
        "subject_revision": 2,
        "resource_digests": (ResourceDigest("CLAUDE.md", D_A), ResourceDigest(".mcp.json", D_B)),
        "target_files": (_present_file(), _absent_file()),
        "risk_level": RiskLevel.HIGH,
        "risk_policy_version": RISK_POLICY_VERSION,
        "recovery_scope": RecoveryScope.CONTINUE_OR_ROLLBACK,
        "nonce": "nonce-0001",
        "expires_at": EXPIRES,
    }
    fields.update(overrides)
    return fields


def _msg(**overrides: Any) -> ApprovalMessage:
    return ApprovalMessage(**_fields(**overrides))


def _expect_invalid(**overrides: Any) -> None:
    with pytest.raises(BrainError) as exc:
        _msg(**overrides)
    assert exc.value.code is ErrorCode.INVALID_INPUT


# --- vocabulary (ledger §2.1, R01, R06) ----------------------------------------------------------------------------


def test_channel_and_assurance_vocabulary_is_exactly_spec_11_3() -> None:
    assert {c.value for c in ApprovalChannel} == {"passkey_uv", "ssh_sk_verified", "ssh_sk", "ssh_key", "terminal"}
    assert {a.value for a in AssuranceLevel} == {"human_verified", "human_present", "key_authorization", "confirm_only"}
    expected = {
        "passkey_uv": "human_verified",
        "ssh_sk_verified": "human_verified",
        "ssh_sk": "human_present",
        "ssh_key": "key_authorization",
        "terminal": "confirm_only",
    }
    assert {c.value: assurance_for(c).value for c in ApprovalChannel} == expected
    assert {c.value for c in SIGNER_CHANNELS} == NON_TERMINAL


def test_action_scope_risk_and_layer2_domains() -> None:
    assert {a.value for a in ApprovalAction} == SPEC_ACTIONS
    assert {s.value for s in RecoveryScope} == {"none", "continue", "rollback", "continue_or_rollback"}
    assert {"low", "high"} <= {r.value for r in RiskLevel}
    assert {s.value for s in Layer2State} == {"unknown", "unsupported", "verified"}
    assert {a.value for a in ALWAYS_HIGH_ACTIONS} == {
        "signer_enroll",
        "signer_revoke",
        "credential_revoke",
        "restore",
        "skill_activate",
        "skill_publish",
    }
    assert APPROVAL_NAMESPACE == "ensemble-brain-approval"
    assert APPROVAL_TTL == timedelta(minutes=10)
    assert type(RISK_POLICY_VERSION) is int and RISK_POLICY_VERSION >= 1
    assert CLI_HARNESS_ID == "cli"


# --- canonical serialization (spec §11.3 "approval message chuẩn") -------------------------------------------------


def test_canonical_bytes_bind_every_spec_field_in_canonical_utf8_json() -> None:
    raw = _msg().canonical_bytes()
    assert isinstance(raw, bytes)
    parsed = json.loads(raw.decode("utf-8"))
    assert raw == canonical_json(parsed)
    expires_raw = parsed.pop("expires_at")
    assert isinstance(expires_raw, str) and expires_raw.endswith("Z")
    assert datetime.fromisoformat(expires_raw.replace("Z", "+00:00")) == EXPIRES
    assert parsed == {
        "store_id": "store-i31-0001",
        "owner_id": "dan",
        "trust_generation": 3,
        "action": "apply",
        "subject_id": "proposal-0001",
        "subject_revision": 2,
        "resource_digests": [{"name": ".mcp.json", "digest": D_B}, {"name": "CLAUDE.md", "digest": D_A}],
        "target_files": [
            {
                "root_path": ROOT,
                "normalized_rel_path": ".mcp.json",
                "parent_physical_id": "vol-1:dir-42",
                "target_physical_id": None,
                "original_digest": None,
                "original_present": False,
            },
            {
                "root_path": ROOT,
                "normalized_rel_path": "CLAUDE.md",
                "parent_physical_id": "vol-1:dir-42",
                "target_physical_id": "vol-1:file-7",
                "original_digest": D_C,
                "original_present": True,
            },
        ],
        "risk_level": "high",
        "risk_policy_version": RISK_POLICY_VERSION,
        "recovery_scope": "continue_or_rollback",
        "nonce": "nonce-0001",
    }


def test_canonical_bytes_are_deterministic_and_independent_of_input_order() -> None:
    first = _msg().canonical_bytes()
    reordered = _msg(
        resource_digests=(ResourceDigest(".mcp.json", D_B), ResourceDigest("CLAUDE.md", D_A)),
        target_files=(_absent_file(), _present_file()),
    ).canonical_bytes()
    assert first == _msg().canonical_bytes() == reordered


def test_canonical_bytes_keep_non_ascii_as_utf8() -> None:
    raw = _msg(subject_id="đề-xuất-01").canonical_bytes()
    assert "đề-xuất-01".encode() in raw
    assert b"\\u" not in raw


def test_every_bound_field_changes_the_signed_bytes() -> None:
    """Case 16: an approval for one store/action/subject/revision/resource/file/scope/nonce/expiry is not another's."""
    moved = dataclasses.replace(_present_file(), parent_physical_id="vol-1:dir-99")
    replaced = dataclasses.replace(_present_file(), target_physical_id="vol-1:file-8")
    edited = dataclasses.replace(_present_file(), original_digest=D_D)
    variants: dict[str, ApprovalMessage] = {
        "base": _msg(),
        "store": _msg(store_id="store-i31-0002"),
        "owner": _msg(owner_id="bob"),
        "generation": _msg(trust_generation=4),
        "action": _msg(action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.ROLLBACK),
        "subject": _msg(subject_id="proposal-0002"),
        "revision": _msg(subject_revision=3),
        "resource": _msg(resource_digests=(ResourceDigest("CLAUDE.md", D_D), ResourceDigest(".mcp.json", D_B))),
        "extra_resource": _msg(
            resource_digests=(
                ResourceDigest("CLAUDE.md", D_A),
                ResourceDigest(".mcp.json", D_B),
                ResourceDigest("hook.py", D_C),
            )
        ),
        "file_parent": _msg(target_files=(moved, _absent_file())),
        "file_target": _msg(target_files=(replaced, _absent_file())),
        "file_digest": _msg(target_files=(edited, _absent_file())),
        "file_dropped": _msg(target_files=(_present_file(),)),
        "risk": _msg(risk_level=RiskLevel.LOW),
        "risk_policy": _msg(risk_policy_version=RISK_POLICY_VERSION + 1),
        "scope": _msg(recovery_scope=RecoveryScope.CONTINUE),
        "nonce": _msg(nonce="nonce-0002"),
        "expiry": _msg(expires_at=EXPIRES + timedelta(seconds=1)),
    }
    encoded = {name: message.canonical_bytes() for name, message in variants.items()}
    assert len(set(encoded.values())) == len(encoded), "two different approvals produced the same signed bytes"


# --- validation (fail closed at construction) ----------------------------------------------------------------------


def test_message_rejects_malformed_fields() -> None:
    _expect_invalid(expires_at=datetime(2026, 11, 19, 6, 10, 0))
    _expect_invalid(trust_generation=0)
    _expect_invalid(trust_generation=True)
    _expect_invalid(nonce="")
    _expect_invalid(store_id="")
    _expect_invalid(resource_digests=(ResourceDigest("CLAUDE.md", D_A), ResourceDigest("CLAUDE.md", D_B)))
    _expect_invalid(risk_policy_version=0)


def test_target_file_presence_must_match_identity_and_digest() -> None:
    with pytest.raises(BrainError) as absent_with_digest:
        dataclasses.replace(_absent_file(), original_digest=D_A)
    assert absent_with_digest.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(BrainError) as absent_with_id:
        dataclasses.replace(_absent_file(), target_physical_id="vol-1:file-9")
    assert absent_with_id.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(BrainError) as present_without_digest:
        dataclasses.replace(_present_file(), original_digest=None)
    assert present_without_digest.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(BrainError) as bad_digest:
        dataclasses.replace(_present_file(), original_digest="md5:1234")
    assert bad_digest.value.code is ErrorCode.INVALID_INPUT


def test_recovery_scope_matches_the_action_direction() -> None:
    """Ledger §2.2/R06: only apply/rollback carry recovery directions; every other action signs ``none``."""
    continued = _msg(action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE)
    assert continued.recovery_scope is RecoveryScope.CONTINUE
    assert _msg(action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.ROLLBACK).action is ApprovalAction.ROLLBACK
    _expect_invalid(action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.NONE)
    _expect_invalid(action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.ROLLBACK)
    _expect_invalid(action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.CONTINUE)
    _expect_invalid(action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.NONE)
    for action in (ApprovalAction.SIGNER_ENROLL, ApprovalAction.APPROVE, ApprovalAction.POLICY_CHANGE):
        _expect_invalid(action=action, recovery_scope=RecoveryScope.CONTINUE, target_files=())
        assert _msg(action=action, recovery_scope=RecoveryScope.NONE, target_files=()).action is action


def test_policy_change_subject_binds_base_policy_state() -> None:
    """Ledger §2.3/R03: a diff approved over one policy state cannot be applied over a restored one."""
    base: dict[str, Any] = {
        "repo_id_or_global": "global",
        "base_policy_revision": 7,
        "base_trust_generation": 3,
        "base_restore_epoch": 0,
        "policy_diff_digest": D_A,
    }
    subject = policy_change_subject_id(**base)
    assert isinstance(subject, str) and subject
    assert subject == policy_change_subject_id(**base)
    changes: list[tuple[str, object]] = [
        ("repo_id_or_global", "repo-0001"),
        ("base_policy_revision", 8),
        ("base_trust_generation", 4),
        ("base_restore_epoch", 5),
        ("policy_diff_digest", D_B),
    ]
    seen = {subject}
    for name, value in changes:
        changed = policy_change_subject_id(**{**base, name: value})
        assert changed not in seen, f"{name} is not bound into the policy_change subject"
        seen.add(changed)
    message = _msg(
        action=ApprovalAction.POLICY_CHANGE,
        subject_id=subject,
        recovery_scope=RecoveryScope.NONE,
        target_files=(),
    )
    assert json.loads(message.canonical_bytes())["subject_id"] == subject


# --- server risk classification (spec §11.3, case 19) ---------------------------------------------------------------


def test_proposal_risk_is_high_for_spec_triggers_despite_low_client_hint() -> None:
    for component in ("c2", "c5", "c7", "c8"):
        assert classify_proposal_risk([RiskResource(component=component)], client_hint="low") is RiskLevel.HIGH
    skill_with_script = RiskResource(component="c6", executable=True)
    assert classify_proposal_risk([skill_with_script], client_hint="low") is RiskLevel.HIGH
    command_ref = RiskResource(component="c1", command_reference=True)
    assert classify_proposal_risk([command_ref], client_hint="low") is RiskLevel.HIGH
    outside_block = RiskResource(component="c4", outside_guidance_block=True)
    assert classify_proposal_risk([outside_block], client_hint="low") is RiskLevel.HIGH


def test_proposal_risk_takes_the_maximum_over_every_resource() -> None:
    guidance = RiskResource(component="c1")
    assert classify_proposal_risk([guidance, RiskResource(component="c4")]) is RiskLevel.LOW
    assert classify_proposal_risk([RiskResource(component="c6")]) is RiskLevel.LOW
    assert classify_proposal_risk([guidance, RiskResource(component="c7")], client_hint="low") is RiskLevel.HIGH
    mixed = [guidance, RiskResource(component="c4"), RiskResource(component="c6", executable=True)]
    assert classify_proposal_risk(mixed, client_hint="low") is RiskLevel.HIGH


def test_proposal_risk_rejects_unknown_component() -> None:
    with pytest.raises(BrainError) as exc:
        classify_proposal_risk([RiskResource(component="c9")])
    assert exc.value.code is ErrorCode.INVALID_INPUT


def test_policy_change_risk_is_high_when_widening_or_steering_review() -> None:
    def risk(widens: bool, harness: bool, accounting: bool) -> RiskLevel:
        return classify_policy_change_risk(
            widens_capture_or_egress=widens,
            sets_review_harness_or_command=harness,
            reconcile_accounting=accounting,
        )

    assert risk(False, False, False) is RiskLevel.LOW
    assert risk(True, False, False) is RiskLevel.HIGH
    assert risk(False, True, False) is RiskLevel.HIGH
    assert risk(False, False, True) is RiskLevel.HIGH


# --- channel requirements (spec §11.3 channel table, cases 12, 20) -------------------------------------------------


def test_high_risk_never_accepts_terminal() -> None:
    for action in ApprovalAction:
        for eligible in (True, False):
            allowed = required_channels(action, RiskLevel.HIGH, terminal_eligible=eligible)
            assert {c.value for c in allowed} == NON_TERMINAL, action


def test_terminal_only_for_low_risk_with_verified_layer2() -> None:
    low_eligible = required_channels(ApprovalAction.APPROVE, RiskLevel.LOW, terminal_eligible=True)
    assert {c.value for c in low_eligible} == NON_TERMINAL | {"terminal"}
    low_ineligible = required_channels(ApprovalAction.APPROVE, RiskLevel.LOW, terminal_eligible=False)
    assert {c.value for c in low_ineligible} == NON_TERMINAL


def test_always_high_actions_ignore_a_low_risk_claim() -> None:
    for action in ALWAYS_HIGH_ACTIONS:
        allowed = required_channels(action, RiskLevel.LOW, terminal_eligible=True)
        assert ApprovalChannel.TERMINAL not in allowed, action
        assert {c.value for c in allowed} == NON_TERMINAL


def test_reject_is_low_and_may_use_terminal_when_eligible() -> None:
    allowed = required_channels(ApprovalAction.REJECT, RiskLevel.LOW, terminal_eligible=True)
    assert ApprovalChannel.TERMINAL in allowed
