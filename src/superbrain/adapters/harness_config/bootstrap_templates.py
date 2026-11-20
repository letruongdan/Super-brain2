"""D3 checkout-scoped bootstrap plan templates for Claude Code and Codex (spec 11.3, D3, I3-2)."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.harness_config.json_keys import merge_json_keys, merge_json_multi_keys
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.toml_tables import merge_toml_table
from superbrain.core._kernel_approval import RiskResource
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.bootstrap import BootstrapPlannerPort, BootstrapPlanSpec, BootstrapTargetSpec

__all__ = [
    "AUTHORITY_ASK_COMMANDS",
    "AdapterBootstrapPlanner",
    "BootstrapPlan",
    "BootstrapTargetPlan",
    "HANDOFF_RULE_TEXT",
    "HANDOFF_UPDATE_MOMENTS",
    "HandoffTakeoverEditDecision",
    "LAYER1_RULE_TEXT",
    "evaluate_takeover_edit_gate",
    "plan_claude_bootstrap",
    "plan_codex_bootstrap",
]

LAYER1_RULE_TEXT = (
    "Không tự duyệt, không thay người dùng chạy lệnh phê duyệt hoặc thay đổi signer/policy/restore. "
    "Mọi hành động review/apply/rollback/signer/policy/credential/restore/workspace link đều phải trình "
    "người dùng xem và xác nhận qua cổng duyệt."
)

HANDOFF_UPDATE_MOMENTS: tuple[str, ...] = (
    "plan_created_or_changed",
    "decision_or_rejection_recorded",
    "user_constraint_added",
    "step_completed",
    "before_long_running_command",
    "task_ended",
)

HANDOFF_RULE_TEXT = (
    "Session Handoff Protocol (7.4): update handoff at 6 moments "
    "(plan_created_or_changed, decision_or_rejection_recorded, user_constraint_added, "
    "step_completed, before_long_running_command, task_ended). "
    "When holding session state is active, notify the user and pass takeover.acknowledge_active=true "
    "for takeover. When taking over an open handoff, do not edit any checkout file until "
    "takeover ACK returns BOTH handoff_status=stored and writer_status=holder. "
    "If writer_status=not_holder, do not edit and re-read the latest handoff via "
    "prepare_task(mode=discover), get_artifact L1, and handoff_live. "
    "If handoff_status=not_stored_policy (manual_submission=false, disabled by policy; "
    "no holder or revision change): when taking over an open handoff, do not edit and "
    "notify the user or ask the user how to proceed; for ordinary work that is not taking over "
    "an open handoff, proceed normally under the repo policy. "
    "If commit_outcome_unknown is reported, retry submit_episode with the same idempotency_key "
    "before any edit."
)


@dataclass(frozen=True)
class HandoffTakeoverEditDecision:
    """SP2 takeover edit gate decision derived from session/ACK/commit states."""

    allow_edit: bool
    action: str
    require_acknowledge_active: bool = False
    notify_user: bool = False


def evaluate_takeover_edit_gate(
    *,
    holding_session_state: str | None,
    acknowledge_active: bool = False,
    handoff_status: str | None = None,
    writer_status: str | None = None,
    commit_outcome_unknown: bool = False,
    taking_over_open_handoff: bool = True,
) -> HandoffTakeoverEditDecision:
    """Evaluate whether checkout edits may proceed under spec §7.4 and SP2 ACK invariants.

    The stored+holder ACK gate and the ``not_stored_policy`` block apply only when taking over an
    open handoff; ordinary work proceeds under the repo policy.
    """
    if commit_outcome_unknown:
        return HandoffTakeoverEditDecision(
            allow_edit=False,
            action="retry_same_idempotency_key",
        )
    if not taking_over_open_handoff:
        if handoff_status == "not_stored_policy":
            return HandoffTakeoverEditDecision(allow_edit=True, action="proceed_without_handoff_policy")
        return HandoffTakeoverEditDecision(allow_edit=True, action="proceed_edit")
    if holding_session_state == "active" and not acknowledge_active:
        return HandoffTakeoverEditDecision(
            allow_edit=False,
            action="require_active_takeover_ack",
            require_acknowledge_active=True,
            notify_user=True,
        )
    if handoff_status == "not_stored_policy":
        return HandoffTakeoverEditDecision(
            allow_edit=False,
            action="policy_disabled",
            notify_user=True,
        )
    if handoff_status != "stored" or writer_status != "holder":
        return HandoffTakeoverEditDecision(
            allow_edit=False,
            action="reread_handoff",
        )
    return HandoffTakeoverEditDecision(
        allow_edit=True,
        action="proceed_edit",
    )

AUTHORITY_ASK_COMMANDS: tuple[str, ...] = (
    "brain init",
    "brain review approve",
    "brain review reject",
    "brain apply",
    "brain rollback",
    "brain lesson confirm",
    "brain signer",
    "brain policy",
    "brain credential",
    "brain restore",
    "brain workspace link",
)

_HIGH_RISK_RESOURCES: tuple[RiskResource, ...] = (
    RiskResource("c2", executable=True, command_reference=True),
    RiskResource("c5", outside_guidance_block=True, command_reference=True),
)


@dataclass(frozen=True)
class BootstrapTargetPlan:
    rel_path: str
    managed_format: ManagedFormat
    slice_id: str
    slice_digest: str
    preview_text: str


@dataclass(frozen=True)
class BootstrapPlan:
    harness_id: str
    checkout_root: Path
    profile_path: Path
    resources: tuple[RiskResource, ...]
    targets: tuple[BootstrapTargetPlan, ...]


def _mcp_server_entry(profile_path: Path) -> dict[str, object]:
    return {"command": "brain", "args": ["mcp", "--profile", str(profile_path)]}


_REPARSE_POINT = 0x400
_MAX_BOOTSTRAP_TARGET_BYTES = 1_048_576


def _is_link_stat(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _check_chain_no_links(checkout_root: Path, rel_parts: tuple[str, ...]) -> Path | None:
    """Walk every path segment from ``checkout_root`` down to leaf checking lstat for links/reparse points."""
    for anc in (checkout_root, *checkout_root.parents):
        if os.path.lexists(anc):
            try:
                if _is_link_stat(os.lstat(anc)):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe link in bootstrap path")
            except OSError as err:
                raise BrainError(ErrorCode.IO_ERROR, f"cannot stat bootstrap path: {err}") from err
    cur = checkout_root
    for idx, seg in enumerate(rel_parts):
        cur = cur / seg
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return None
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot stat bootstrap target: {err}") from err
        if _is_link_stat(st):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe link in bootstrap path")
        if idx < len(rel_parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap parent is not a directory")
    return cur


def _read_existing(checkout_root: Path, *rel_parts: str) -> str | None:
    leaf = _check_chain_no_links(checkout_root, rel_parts)
    if leaf is None:
        return None
    try:
        st = os.lstat(leaf)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot stat bootstrap target: {err}") from err
    if _is_link_stat(st):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe link in bootstrap target")
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap target is not a regular file")
    if st.st_size > _MAX_BOOTSTRAP_TARGET_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap target exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(leaf, flags)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot open bootstrap target: {err}") from err
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_size > _MAX_BOOTSTRAP_TARGET_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap target exceeds size limit")
        raw = os.read(fd, _MAX_BOOTSTRAP_TARGET_BYTES + 1)
        if len(raw) > _MAX_BOOTSTRAP_TARGET_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap target exceeds size limit")
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read bootstrap target: {err}") from err
    finally:
        os.close(fd)


def _guidance_body(profile_path: Path) -> str:
    return f"{LAYER1_RULE_TEXT}\n\n{HANDOFF_RULE_TEXT}\n\nProfile: {profile_path}"


def _nonblocking_hooks_payload(profile_path: Path) -> dict[str, JsonValue]:
    ask_cmds: list[JsonValue] = list(AUTHORITY_ASK_COMMANDS)
    return {
        "super_brain": {
            "mode": "remind",
            "non_blocking": True,
            "profile": str(profile_path),
            "authority_ask_commands": ask_cmds,
        }
    }


def _expected_digest(
    expected_slice_digests: Mapping[tuple[str, str], str] | None,
    rel_path: str,
    slice_id: str,
) -> str | None:
    if expected_slice_digests is None:
        return None
    return expected_slice_digests.get((rel_path, slice_id))


def plan_claude_bootstrap(
    *,
    checkout_root: Path,
    profile_path: Path,
    expected_slice_digests: Mapping[tuple[str, str], str] | None = None,
) -> BootstrapPlan:
    """Build checkout-scoped D3 bootstrap plan for Claude Code (`.mcp.json`, `CLAUDE.md`, `settings.local.json`)."""
    mcp_merge = merge_json_keys(
        _read_existing(checkout_root, ".mcp.json"),
        key_path=("mcpServers", "super-brain"),
        value=_mcp_server_entry(profile_path),
        expected_slice_digest=_expected_digest(expected_slice_digests, ".mcp.json", "mcpServers.super-brain"),
    )
    md_merge = merge_markdown_block(
        _read_existing(checkout_root, "CLAUDE.md"),
        slice_id="super-brain-layer1",
        block_body=_guidance_body(profile_path),
        expected_slice_digest=_expected_digest(expected_slice_digests, "CLAUDE.md", "super-brain-layer1"),
    )
    ask_rules = [f"Bash({cmd} *)" for cmd in AUTHORITY_ASK_COMMANDS]
    hooks_val = _nonblocking_hooks_payload(profile_path)
    settings_existing = _read_existing(checkout_root, ".claude", "settings.local.json")
    settings_merge = merge_json_multi_keys(
        settings_existing,
        entries=[(("permissions", "ask"), ask_rules), (("hooks", "PreToolUse"), hooks_val)],
        expected_slice_digest=_expected_digest(
            expected_slice_digests, ".claude/settings.local.json", "permissions.ask,hooks.PreToolUse"
        ),
    )
    return BootstrapPlan(
        harness_id="claude-code",
        checkout_root=checkout_root,
        profile_path=profile_path,
        resources=_HIGH_RISK_RESOURCES,
        targets=(
            BootstrapTargetPlan(
                rel_path=".mcp.json",
                managed_format=ManagedFormat.JSON,
                slice_id="mcpServers.super-brain",
                slice_digest=mcp_merge.slice_digest,
                preview_text=mcp_merge.updated_text,
            ),
            BootstrapTargetPlan(
                rel_path="CLAUDE.md",
                managed_format=ManagedFormat.MARKDOWN,
                slice_id="super-brain-layer1",
                slice_digest=md_merge.slice_digest,
                preview_text=md_merge.updated_text,
            ),
            BootstrapTargetPlan(
                rel_path=".claude/settings.local.json",
                managed_format=ManagedFormat.JSON,
                slice_id="permissions.ask,hooks.PreToolUse",
                slice_digest=settings_merge.slice_digest,
                preview_text=settings_merge.updated_text,
            ),
        ),
    )


def plan_codex_bootstrap(
    *,
    checkout_root: Path,
    profile_path: Path,
    expected_slice_digests: Mapping[tuple[str, str], str] | None = None,
) -> BootstrapPlan:
    """Build checkout-scoped D3 bootstrap plan for Codex (`AGENTS.md`, `.codex/config.toml`, `.codex/hooks.json`)."""
    md_merge = merge_markdown_block(
        _read_existing(checkout_root, "AGENTS.md"),
        slice_id="super-brain-layer1",
        block_body=_guidance_body(profile_path),
        expected_slice_digest=_expected_digest(expected_slice_digests, "AGENTS.md", "super-brain-layer1"),
    )
    toml_merge = merge_toml_table(
        _read_existing(checkout_root, ".codex", "config.toml"),
        table_path=("mcp_servers", "super-brain"),
        values=_mcp_server_entry(profile_path),
        expected_slice_digest=_expected_digest(
            expected_slice_digests, ".codex/config.toml", "mcp_servers.super-brain"
        ),
    )
    hooks_merge = merge_json_keys(
        _read_existing(checkout_root, ".codex", "hooks.json"),
        key_path=("hooks", "PreToolUse"),
        value=_nonblocking_hooks_payload(profile_path),
        expected_slice_digest=_expected_digest(expected_slice_digests, ".codex/hooks.json", "hooks.PreToolUse"),
    )
    return BootstrapPlan(
        harness_id="codex",
        checkout_root=checkout_root,
        profile_path=profile_path,
        resources=_HIGH_RISK_RESOURCES,
        targets=(
            BootstrapTargetPlan(
                rel_path="AGENTS.md",
                managed_format=ManagedFormat.MARKDOWN,
                slice_id="super-brain-layer1",
                slice_digest=md_merge.slice_digest,
                preview_text=md_merge.updated_text,
            ),
            BootstrapTargetPlan(
                rel_path=".codex/config.toml",
                managed_format=ManagedFormat.TOML,
                slice_id="mcp_servers.super-brain",
                slice_digest=toml_merge.slice_digest,
                preview_text=toml_merge.updated_text,
            ),
            BootstrapTargetPlan(
                rel_path=".codex/hooks.json",
                managed_format=ManagedFormat.JSON,
                slice_id="hooks.PreToolUse",
                slice_digest=hooks_merge.slice_digest,
                preview_text=hooks_merge.updated_text,
            ),
        ),
    )


class AdapterBootstrapPlanner(BootstrapPlannerPort):
    """Adapter implementing ``BootstrapPlannerPort`` for Claude Code and Codex."""

    def plan_bootstrap(
        self,
        *,
        harness_id: str,
        checkout_root: Path,
        profile_path: Path,
        expected_slice_digests: Mapping[tuple[str, str], str] | None = None,
    ) -> BootstrapPlanSpec:
        if harness_id == "claude-code":
            plan = plan_claude_bootstrap(
                checkout_root=checkout_root,
                profile_path=profile_path,
                expected_slice_digests=expected_slice_digests,
            )
        elif harness_id == "codex":
            plan = plan_codex_bootstrap(
                checkout_root=checkout_root,
                profile_path=profile_path,
                expected_slice_digests=expected_slice_digests,
            )
        else:
            raise BrainError(ErrorCode.INVALID_INPUT, "unsupported bootstrap harness")
        return BootstrapPlanSpec(
            harness_id=plan.harness_id,
            checkout_root=plan.checkout_root,
            profile_path=plan.profile_path,
            resources=plan.resources,
            targets=tuple(
                BootstrapTargetSpec(
                    rel_path=t.rel_path,
                    managed_format=t.managed_format,
                    slice_id=t.slice_id,
                    slice_digest=t.slice_digest,
                    preview_text=t.preview_text,
                )
                for t in plan.targets
            ),
        )
