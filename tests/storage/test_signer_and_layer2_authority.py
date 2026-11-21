"""I3-1 oracle: ``policy v4`` signer authority, single-use approvals, layer-2 terminal eligibility and signer reset.

Requirement sources: spec rev 22 §5.4 (security state first, intent reconciled exactly once), §5.7 (policy restore
raises ``trust_generation``; old approvals and nonces die), §11.2 (recovery grant lifetime ends on a trust generation
change), §11.3 (signers, nonce, expiry, terminal channel, ``--reset-signers``), §20 cases 12, 16, 17, 18, 20, 32, 34;
ledger §2.2 (durable terminal rule I3-R6/R03), plan I3-1 Step 2 (``meta.signer_reset_recorded='1'``,
``reason="trust_reset"``, crash between the two generation writes).
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    IssuedNonce,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
    TargetFile,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import ResourceDigest
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kernel_schema import (
    KERNEL_POLICY_MIGRATIONS,
    KERNEL_STORE_MIGRATIONS,
    POLICY_V4_MIGRATION,
    STORE_V5_MIGRATION,
)
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy
from superbrain.storage.runtime import Runtime
from superbrain.storage.schema import SchemaInfo, code_version, read_schema_info
from superbrain.storage.writer import WriterLease
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
MACHINE = "devbox-1"
D_A = "sha256:" + "a" * 64
D_B = "sha256:" + "b" * 64
D_C = "sha256:" + "c" * 64
D_D = "sha256:" + "d" * 64
V4_TABLES = {
    "signer",
    "approval_nonce",
    "approval_receipt_meta",
    "harness_layer2_state",
    "recovery_grant",
    "apply_turn_intent",
    "accounting_invocations",
    "accounting_locks",
}
REPO_FLAGS = {
    "automatic_capture_enabled",
    "manual_submission_enabled",
    "indexing_enabled",
    "provider_egress_enabled",
    "post_session_review_enabled",
}
_REFUSED = ErrorCode.UNAUTHENTICATED
SSH = ApprovalChannel.SSH_KEY
TERMINAL = ApprovalChannel.TERMINAL


@dataclass
class Ctx:
    rt: Runtime
    root: Path
    store_id: str
    os_: OsAdapters
    clock: FakeClock


@pytest.fixture
def ctx(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> Iterator[Ctx]:
    root = trusted_tmp / "root"
    rt = open_kernel_job_runtime(root, os_, role="i3-1-authority")
    holder = Ctx(rt=rt, root=root, store_id=rt.store.store_id, os_=os_, clock=clock)
    try:
        yield holder
    finally:
        if not holder.rt.store.closed:
            holder.rt.close()


def _reopen(ctx: Ctx) -> None:
    ctx.rt.close()
    ctx.rt = reopen_kernel_job_runtime(ctx.root, ctx.store_id, ctx.os_)


def _ssh_enrollment() -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + len(raw).to_bytes(4, "big") + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _scope(action: ApprovalAction) -> RecoveryScope:
    if action is ApprovalAction.APPLY:
        return RecoveryScope.CONTINUE_OR_ROLLBACK
    if action is ApprovalAction.ROLLBACK:
        return RecoveryScope.ROLLBACK
    return RecoveryScope.NONE


def _targets(action: ApprovalAction) -> tuple[TargetFile, ...]:
    if action not in (ApprovalAction.APPLY, ApprovalAction.ROLLBACK):
        return ()
    target = TargetFile(
        root_path=str(Path(os.path.abspath(os.sep)) / "checkout-a"),
        normalized_rel_path="CLAUDE.md",
        parent_physical_id="vol-1:dir-42",
        target_physical_id="vol-1:file-7",
        original_digest=D_B,
        original_present=True,
    )
    return (target,)


def _message(ctx: Ctx, issued: IssuedNonce, **overrides: Any) -> ApprovalMessage:
    fields: dict[str, Any] = {
        "store_id": ctx.store_id,
        "owner_id": OWNER,
        "trust_generation": issued.trust_generation,
        "action": issued.action,
        "subject_id": issued.subject_id,
        "subject_revision": 1,
        "resource_digests": (ResourceDigest("CLAUDE.md", D_A),),
        "target_files": _targets(issued.action),
        "risk_level": issued.risk_level,
        "risk_policy_version": RISK_POLICY_VERSION,
        "recovery_scope": _scope(issued.action),
        "nonce": issued.nonce,
        "expires_at": issued.expires_at,
    }
    fields.update(overrides)
    return ApprovalMessage(**fields)


def _issue(ctx: Ctx, action: ApprovalAction, subject: str, risk: RiskLevel = RiskLevel.HIGH) -> IssuedNonce:
    return ctx.rt.policy.issue_nonce(action=action, subject_id=subject, risk_level=risk)


def _expect(code: ErrorCode | set[ErrorCode], exc: pytest.ExceptionInfo[BrainError]) -> None:
    codes = code if isinstance(code, set) else {code}
    assert exc.value.code in codes, exc.value


def _intent_count(ctx: Ctx, kind: IntentKind) -> int:
    return sum(1 for intent in ctx.rt.policy.intents() if intent.kind is kind)


def _layer2(policy: PolicyStore, harness: str, version: str, digest: str, state: Layer2State) -> None:
    policy.set_layer2_state(harness_id=harness, host_version=version, config_digest=digest, state=state)


# --- schema (policy v4 / store v5) ---------------------------------------------------------------------------------


def test_policy_v4_and_store_v5_schema_tables_flags_and_intent_kinds(ctx: Ctx) -> None:
    from superbrain.storage.kernel_schema import STORE_V6_MIGRATION

    assert (POLICY_V4_MIGRATION.to_version, POLICY_V4_MIGRATION.min_reader_version) == (4, 4)
    assert (STORE_V5_MIGRATION.to_version, STORE_V5_MIGRATION.min_reader_version) == (5, 5)
    assert (STORE_V6_MIGRATION.to_version, STORE_V6_MIGRATION.min_reader_version) == (6, 6)
    assert code_version(KERNEL_POLICY_MIGRATIONS) == 4
    assert code_version(KERNEL_STORE_MIGRATIONS) == 6
    assert ctx.rt.policy.schema_version == 4
    expected_kinds = {"signer_reset", "repo_policy_set", "layer2_state_set", "recovery_grant_opened"}
    assert expected_kinds | {"recovery_grant_ended"} <= {k.value for k in IntentKind}
    with ctx.rt.policy._immediate() as db:
        tables = {str(r[0]) for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        columns = {str(r[1]) for r in db.execute("PRAGMA table_info(repo_policy)")}
    assert V4_TABLES <= tables
    assert REPO_FLAGS <= columns
    ctx.rt.close()
    assert read_schema_info(ctx.root / "policy" / "policy.db") == SchemaInfo(4, 4, ctx.store_id)
    assert read_schema_info(ctx.root / "store" / "brain.db") == SchemaInfo(6, 6, ctx.store_id)


# --- signers (case 18) ---------------------------------------------------------------------------------------------


def test_first_signer_is_tofu_and_second_needs_an_existing_signers_high_approval(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    first = _ssh_enrollment()
    rec1 = policy.enroll_first_signer(first)
    assert rec1.tofu is True and rec1.revoked is False
    assert (rec1.channel, rec1.key_digest, rec1.owner_id) == (ApprovalChannel.SSH_KEY, first.key_digest, OWNER)
    assert [s.signer_id for s in policy.active_signers()] == [rec1.signer_id]

    second, third = _ssh_enrollment(), _ssh_enrollment()
    assert second.subject_id != third.subject_id
    with pytest.raises(BrainError) as tofu_again:
        policy.enroll_first_signer(second)
    _expect(_REFUSED, tofu_again)

    wrong_action = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, second.subject_id))
    other_key = _message(ctx, _issue(ctx, ApprovalAction.SIGNER_ENROLL, third.subject_id))
    for approval in (wrong_action, other_key):
        with pytest.raises(BrainError) as refused:
            policy.enroll_signer(
                second, approval=approval, approver_signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY
            )
        _expect(_REFUSED, refused)
    terminal = _message(ctx, _issue(ctx, ApprovalAction.SIGNER_ENROLL, second.subject_id))
    with pytest.raises(BrainError) as by_terminal:
        policy.enroll_signer(second, approval=terminal, approver_signer_id=rec1.signer_id, channel=TERMINAL)
    _expect({ErrorCode.CAPABILITY_UNAVAILABLE, _REFUSED}, by_terminal)
    assert len(policy.active_signers()) == 1

    issued = _issue(ctx, ApprovalAction.SIGNER_ENROLL, second.subject_id, risk=RiskLevel.LOW)
    assert issued.risk_level is RiskLevel.HIGH, "signer_enroll is always HIGH whatever the requested risk"
    approval = _message(ctx, issued)
    rec2 = policy.enroll_signer(second, approval=approval, approver_signer_id=rec1.signer_id, channel=SSH)
    assert rec2.tofu is False and rec2.key_digest == second.key_digest
    assert {s.signer_id for s in policy.active_signers()} == {rec1.signer_id, rec2.signer_id}
    with pytest.raises(BrainError) as replayed:
        policy.enroll_signer(second, approval=approval, approver_signer_id=rec1.signer_id, channel=SSH)
    _expect(_REFUSED, replayed)

    revoke = _message(ctx, _issue(ctx, ApprovalAction.SIGNER_REVOKE, rec2.signer_id))
    policy.revoke_signer(rec2.signer_id, approval=revoke, approver_signer_id=rec1.signer_id, channel=SSH)
    assert [s.signer_id for s in policy.active_signers()] == [rec1.signer_id]
    by_revoked = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, "proposal-A"))
    with pytest.raises(BrainError) as revoked_signer:
        policy.consume_approval(by_revoked, signer_id=rec2.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, revoked_signer)


def test_terminal_cannot_be_a_signer_channel() -> None:
    with pytest.raises(BrainError) as exc:
        SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.TERMINAL, public_key="confirm-code")
    _expect(ErrorCode.INVALID_INPUT, exc)


# --- single-use, bound approvals (cases 16, 17, 32) ----------------------------------------------------------------


def test_approval_nonce_is_single_use_and_bound_to_action_subject_store_owner_and_risk(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    rec1 = policy.enroll_first_signer(_ssh_enrollment())
    signer: dict[str, Any] = {"signer_id": rec1.signer_id, "channel": ApprovalChannel.SSH_KEY}
    probe = _issue(ctx, ApprovalAction.APPROVE, "proposal-A")
    assert probe.expires_at == ctx.clock.now() + timedelta(minutes=10)
    assert probe.trust_generation == policy.trust_generation()

    mismatches: dict[str, tuple[dict[str, Any], set[ErrorCode]]] = {
        "other_subject": ({"subject_id": "proposal-B"}, {_REFUSED}),
        "other_action": ({"action": ApprovalAction.REJECT}, {_REFUSED}),
        "other_store": ({"store_id": "store-foreign-0001"}, {_REFUSED, ErrorCode.IDENTITY_MISMATCH}),
        "other_owner": ({"owner_id": "bob"}, {_REFUSED, ErrorCode.IDENTITY_MISMATCH}),
        "lowered_risk": ({"risk_level": RiskLevel.LOW}, {_REFUSED}),
    }
    for name, (override, codes) in mismatches.items():
        issued = _issue(ctx, ApprovalAction.APPROVE, "proposal-A")
        with pytest.raises(BrainError) as exc:
            policy.consume_approval(_message(ctx, issued, **override), **signer)
        assert exc.value.code in codes, name

    issued = _issue(ctx, ApprovalAction.APPROVE, "proposal-A")
    message = _message(ctx, issued)
    receipt = policy.consume_approval(message, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    assert receipt.message == message and receipt.signer_id == rec1.signer_id
    assert receipt.channel is ApprovalChannel.SSH_KEY
    assert receipt.assurance is AssuranceLevel.KEY_AUTHORIZATION
    assert isinstance(receipt.approval_id, str) and receipt.approval_id
    with pytest.raises(BrainError) as replay:
        policy.consume_approval(message, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, replay)
    never_issued = _message(ctx, issued, nonce="nonce-never-issued-0001")
    with pytest.raises(BrainError) as unknown:
        policy.consume_approval(never_issued, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, unknown)


def test_approval_is_refused_after_its_ten_minute_expiry(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    rec1 = policy.enroll_first_signer(_ssh_enrollment())
    in_time = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, "proposal-A"))
    late = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, "proposal-A"))
    ctx.clock.advance(timedelta(minutes=9, seconds=59))
    policy.consume_approval(in_time, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    ctx.clock.advance(timedelta(seconds=2))
    with pytest.raises(BrainError) as exc:
        policy.consume_approval(late, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, exc)


def test_trust_generation_fence_refuses_a_message_signed_for_another_generation(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    rec1 = policy.enroll_first_signer(_ssh_enrollment())
    issued = _issue(ctx, ApprovalAction.APPROVE, "proposal-A")
    future = _message(ctx, issued, trust_generation=issued.trust_generation + 1)
    with pytest.raises(BrainError) as exc:
        policy.consume_approval(future, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, exc)
    fresh = _issue(ctx, ApprovalAction.APPROVE, "proposal-A")
    policy.consume_approval(_message(ctx, fresh), signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)


def test_old_signature_is_refused_after_policy_restore(ctx: Ctx) -> None:
    """Case 32: backup policy -> use approval -> restore policy -> resubmitting the old signature is refused."""
    rec1 = ctx.rt.policy.enroll_first_signer(_ssh_enrollment())
    old_generation = ctx.rt.policy.trust_generation()
    message = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, "proposal-A"))
    ctx.clock.advance(timedelta(seconds=5))
    backup = create_policy_backup(ctx.rt.policy, ctx.os_, ctx.clock.now())
    ctx.rt.policy.consume_approval(message, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    ctx.rt.close()
    ctx.clock.advance(timedelta(seconds=5))
    with maintenance_lease(ctx.root, ctx.os_) as (mroot, lease):
        restore_policy(
            mroot,
            lease,
            ctx.os_,
            backup,
            store_id=ctx.store_id,
            now=ctx.clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    ctx.rt = reopen_kernel_job_runtime(ctx.root, ctx.store_id, ctx.os_)
    assert ctx.rt.policy.trust_generation() > old_generation
    with pytest.raises(BrainError) as exc:
        ctx.rt.policy.consume_approval(message, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    _expect(_REFUSED, exc)


# --- layer 2 and the terminal channel (cases 12, 20) ---------------------------------------------------------------


def test_terminal_eligibility_needs_a_nonempty_all_verified_active_harness_set(ctx: Ctx) -> None:
    policy = ctx.rt.policy

    def eligible(machine: str = MACHINE) -> bool:
        return policy.terminal_channel_eligible(machine_id=machine)

    assert eligible() is False, "an empty harness set must not be eligible (all([]) is True)"
    seed_principal_and_credential(policy, owner_id=OWNER, harness_id="cli", machine_id=MACHINE)
    assert eligible() is False, "the CLI principal is not a harness"
    seed_principal_and_credential(policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
    assert eligible() is False, "layer 2 defaults to unknown"
    _layer2(policy, "claude-code", "2.1.0", D_A, Layer2State.VERIFIED)
    assert eligible() is True
    codex = seed_principal_and_credential(policy, owner_id=OWNER, harness_id="codex", machine_id=MACHINE)
    assert eligible() is False
    _layer2(policy, "codex", "0.50.0", D_B, Layer2State.UNSUPPORTED)
    assert eligible() is False
    _layer2(policy, "codex", "0.50.0", D_B, Layer2State.VERIFIED)
    assert eligible() is True
    seed_principal_and_credential(policy, owner_id=OWNER, harness_id="cursor", machine_id="devbox-2")
    assert eligible() is True and eligible("devbox-2") is False
    _layer2(policy, "claude-code", "2.2.0", D_A, Layer2State.UNKNOWN)
    assert eligible() is False, "a host upgrade drops back to unknown"
    _layer2(policy, "claude-code", "2.2.0", D_C, Layer2State.VERIFIED)
    assert eligible() is True
    _layer2(policy, "claude-code", "2.2.0", D_D, Layer2State.UNKNOWN)
    assert eligible() is False, "a config digest change drops back to unknown"
    _layer2(policy, "claude-code", "2.2.0", D_C, Layer2State.VERIFIED)
    _layer2(policy, "codex", "0.51.0", D_B, Layer2State.UNKNOWN)
    assert eligible() is False
    with policy._immediate() as db:
        db.execute("UPDATE credential SET revoked_intent_id = ? WHERE id = ?", (new_id(), codex.credential_id))
    assert eligible() is True, "a harness with no active credential leaves the active set"
    assert _intent_count(ctx, IntentKind.LAYER2_STATE_SET) == 8


def test_terminal_approval_refuses_empty_or_unverified_harness_set(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    policy.enroll_first_signer(_ssh_enrollment())

    def terminal(action: ApprovalAction, risk: RiskLevel) -> AssuranceLevel:
        message = _message(ctx, _issue(ctx, action, "proposal-T", risk=risk))
        return policy.consume_approval(message, signer_id=None, channel=ApprovalChannel.TERMINAL).assurance

    with pytest.raises(BrainError) as empty_set:
        terminal(ApprovalAction.APPROVE, RiskLevel.LOW)
    _expect(ErrorCode.CAPABILITY_UNAVAILABLE, empty_set)
    seed_principal_and_credential(policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
    with pytest.raises(BrainError) as unknown_layer2:
        terminal(ApprovalAction.APPROVE, RiskLevel.LOW)
    _expect(ErrorCode.CAPABILITY_UNAVAILABLE, unknown_layer2)
    _layer2(policy, "claude-code", "2.1.0", D_A, Layer2State.VERIFIED)
    assert terminal(ApprovalAction.APPROVE, RiskLevel.LOW) is AssuranceLevel.CONFIRM_ONLY
    assert terminal(ApprovalAction.REJECT, RiskLevel.LOW) is AssuranceLevel.CONFIRM_ONLY
    for action, risk in ((ApprovalAction.APPROVE, RiskLevel.HIGH), (ApprovalAction.SIGNER_ENROLL, RiskLevel.LOW)):
        with pytest.raises(BrainError) as high:
            terminal(action, risk)
        _expect(ErrorCode.CAPABILITY_UNAVAILABLE, high)


# --- brain init --reset-signers (plan I3-1 Step 2, case 34) --------------------------------------------------------


def _open_grant(ctx: Ctx, signer_id: str, subject: str) -> str:
    message = _message(ctx, _issue(ctx, ApprovalAction.APPLY, subject))
    receipt = ctx.rt.policy.consume_approval(message, signer_id=signer_id, channel=ApprovalChannel.SSH_KEY)
    grant = ctx.rt.policy.open_recovery_grant(approval_id=receipt.approval_id, journal_id=new_id())
    assert (grant.state, grant.end_reason, grant.subject_id) == ("active", None, subject)
    assert grant.recovery_scope is RecoveryScope.CONTINUE_OR_ROLLBACK
    assert grant.trust_generation == ctx.rt.policy.trust_generation()
    return grant.grant_id


def test_recovery_grant_opens_only_from_an_apply_or_rollback_approval(ctx: Ctx) -> None:
    rec1 = ctx.rt.policy.enroll_first_signer(_ssh_enrollment())
    _open_grant(ctx, rec1.signer_id, "proposal-G")
    approve = _message(ctx, _issue(ctx, ApprovalAction.APPROVE, "proposal-G"))
    receipt = ctx.rt.policy.consume_approval(approve, signer_id=rec1.signer_id, channel=ApprovalChannel.SSH_KEY)
    with pytest.raises(BrainError) as exc:
        ctx.rt.policy.open_recovery_grant(approval_id=receipt.approval_id, journal_id=new_id())
    _expect({ErrorCode.INVALID_INPUT, _REFUSED}, exc)
    assert _intent_count(ctx, IntentKind.RECOVERY_GRANT_OPENED) == 1


def test_reset_signers_ends_active_grants_cancels_nonces_and_records_flag(ctx: Ctx) -> None:
    policy = ctx.rt.policy
    rec1 = policy.enroll_first_signer(_ssh_enrollment())
    grants = [_open_grant(ctx, rec1.signer_id, "proposal-A"), _open_grant(ctx, rec1.signer_id, "proposal-B")]
    pending = _issue(ctx, ApprovalAction.APPROVE, "proposal-C")
    old_generation = policy.trust_generation()

    new_generation = policy.reset_signers_offline()
    assert new_generation == policy.trust_generation() > old_generation
    assert ctx.rt.lease.state().trust_generation_hwm == new_generation
    for grant_id in grants:
        record = policy.recovery_grant(grant_id)
        assert (record.state, record.end_reason) == ("ended", "trust_reset")
    assert policy.active_signers() == ()
    assert policy.signer_reset_recorded() is True
    assert _intent_count(ctx, IntentKind.SIGNER_RESET) == 1
    replacement = policy.enroll_first_signer(_ssh_enrollment())
    assert replacement.tofu is True
    for generation in (pending.trust_generation, new_generation):
        stale = _message(ctx, pending, trust_generation=generation)
        with pytest.raises(BrainError) as exc:
            policy.consume_approval(stale, signer_id=replacement.signer_id, channel=ApprovalChannel.SSH_KEY)
        _expect(_REFUSED, exc)
    with policy._immediate() as db:
        row = db.execute("SELECT value FROM meta WHERE key = 'signer_reset_recorded'").fetchone()
    assert row is not None and row[0] == "1"


def test_signer_reset_intent_is_projected_into_the_store_exactly_once(ctx: Ctx) -> None:
    """Case 34: a crash between the policy commit and the store commit completes the intent once on restart."""
    ctx.rt.policy.enroll_first_signer(_ssh_enrollment())
    ctx.rt.policy.reset_signers_offline()
    _reopen(ctx)  # the store never reconciled before the "crash"; Store.open reconciles on restart
    assert ctx.rt.store.reconcile_policy() == 0
    _reopen(ctx)
    assert ctx.rt.store.reconcile_policy() == 0
    with ctx.rt.store.transaction() as txn:
        rows = txn.db.execute("SELECT count(*) FROM ledger WHERE kind = 'policy.signer_reset'").fetchone()
    assert rows is not None and rows[0] == 1


class _KilledBetweenWrites(RuntimeError):
    pass


def test_reset_signers_crash_between_policy_and_lock_generation_is_all_or_nothing(
    ctx: Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = ctx.rt.policy
    rec1 = policy.enroll_first_signer(_ssh_enrollment())
    grant_id = _open_grant(ctx, rec1.signer_id, "proposal-A")
    old_generation = policy.trust_generation()

    def killed(self: WriterLease, value: int) -> None:
        raise _KilledBetweenWrites(f"killed before writer.lock records {value}")

    with monkeypatch.context() as patch:
        patch.setattr(WriterLease, "raise_trust_hwm", killed)
        try:
            policy.reset_signers_offline()
        except _KilledBetweenWrites:
            pass
    _reopen(ctx)
    policy = ctx.rt.policy
    generation = policy.trust_generation()
    assert ctx.rt.lease.state().trust_generation_hwm == generation
    grant = policy.recovery_grant(grant_id)
    if generation == old_generation:
        assert policy.signer_reset_recorded() is False
        assert [s.signer_id for s in policy.active_signers()] == [rec1.signer_id]
        assert grant.state == "active"
        generation = policy.reset_signers_offline()
        grant = policy.recovery_grant(grant_id)
    assert generation > old_generation
    assert ctx.rt.lease.state().trust_generation_hwm == generation == policy.trust_generation()
    assert policy.signer_reset_recorded() is True
    assert policy.active_signers() == ()
    assert (grant.state, grant.end_reason) == ("ended", "trust_reset")
    assert _intent_count(ctx, IntentKind.SIGNER_RESET) == 1
