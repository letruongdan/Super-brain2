"""D3 checkout-scoped bootstrap plan templates for Claude Code and Codex (spec 11.3, D3, I3-2)."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.harness_config.json_keys import merge_json_keys
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.toml_tables import merge_toml_table
from superbrain.core._kernel_approval import RiskResource
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ManagedFormat

__all__ = [
    "AUTHORITY_ASK_COMMANDS",
    "BootstrapPlan",
    "BootstrapTargetPlan",
    "LAYER1_RULE_TEXT",
    "plan_claude_bootstrap",
    "plan_codex_bootstrap",
]

LAYER1_RULE_TEXT = (
    "Không tự duyệt, không thay người dùng chạy lệnh phê duyệt hoặc thay đổi signer/policy/restore. "
    "Mọi hành động review/apply/rollback/signer/policy/credential/restore/workspace link đều phải trình "
    "người dùng xem và xác nhận qua cổng duyệt."
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


def _read_existing(path: Path) -> str | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot stat {path}: {err}") from err
    if stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe link in bootstrap target")
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INVALID_INPUT, "bootstrap target is not a regular file")
    try:
        return path.read_bytes().decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {err}") from err


def plan_claude_bootstrap(*, checkout_root: Path, profile_path: Path) -> BootstrapPlan:
    """Build checkout-scoped D3 bootstrap plan for Claude Code (`.mcp.json`, `CLAUDE.md`, `settings.local.json`)."""
    mcp_merge = merge_json_keys(
        _read_existing(checkout_root / ".mcp.json"),
        key_path=("mcpServers", "super-brain"),
        value=_mcp_server_entry(profile_path),
        expected_slice_digest=None,
    )
    md_merge = merge_markdown_block(
        _read_existing(checkout_root / "CLAUDE.md"),
        slice_id="super-brain-layer1",
        block_body=f"{LAYER1_RULE_TEXT}\nProfile: {profile_path}",
        expected_slice_digest=None,
    )
    ask_rules = [f"Bash({cmd} *)" for cmd in AUTHORITY_ASK_COMMANDS]
    settings_merge = merge_json_keys(
        _read_existing(checkout_root / ".claude" / "settings.local.json"),
        key_path=("permissions", "ask"),
        value=ask_rules,
        expected_slice_digest=None,
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
                slice_id="permissions.ask",
                slice_digest=settings_merge.slice_digest,
                preview_text=settings_merge.updated_text,
            ),
        ),
    )


def plan_codex_bootstrap(*, checkout_root: Path, profile_path: Path) -> BootstrapPlan:
    """Build checkout-scoped D3 bootstrap plan for Codex (`AGENTS.md`, `.codex/config.toml`, `.codex/hooks.json`)."""
    md_merge = merge_markdown_block(
        _read_existing(checkout_root / "AGENTS.md"),
        slice_id="super-brain-layer1",
        block_body=f"{LAYER1_RULE_TEXT}\nProfile: {profile_path}",
        expected_slice_digest=None,
    )
    toml_merge = merge_toml_table(
        _read_existing(checkout_root / ".codex" / "config.toml"),
        table_path=("mcp_servers", "super-brain"),
        values=_mcp_server_entry(profile_path),
        expected_slice_digest=None,
    )
    hooks_value = {
        "super_brain": {
            "profile": str(profile_path),
            "authority_ask_commands": list(AUTHORITY_ASK_COMMANDS),
        }
    }
    hooks_merge = merge_json_keys(
        _read_existing(checkout_root / ".codex" / "hooks.json"),
        key_path=("hooks", "PreToolUse"),
        value=hooks_value,
        expected_slice_digest=None,
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
