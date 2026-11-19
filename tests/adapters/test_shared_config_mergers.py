"""I3-2 oracle: Markdown, JSON and TOML shared config mergers plus D3 bootstrap plans.

Requirement sources: spec rev 22 §11.2 (lines 1062-1067, U0/U1 out-of-band rollback), §11.3 (three-layer gate),
plan I3-2 Step 2 & shared contracts D3 (checkout-scoped config targets, tomlkit comment preservation).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    LAYER1_RULE_TEXT,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.json_keys import merge_json_keys, remove_json_keys
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block, remove_markdown_block
from superbrain.adapters.harness_config.toml_tables import merge_toml_table, remove_toml_table
from superbrain.core._kernel_approval import RiskLevel, classify_proposal_risk
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ManagedFormat, assert_not_skill_or_internal_target

USER_HEADER = "# Project Guidelines\n\nKeep all unit tests deterministic.\n\n"
USER_FOOTER = "\n## Release Checklist\n\n- Tag release.\n"
USER_ADDED_MID = "\n## Team Notes\n\nEdited out-of-band by owner.\n"


def test_markdown_merger_install_idempotency_update_conflicts_and_u1_removal() -> None:
    slice_id = "layer1-rule"
    body_v1 = "Rule v1: always ask via brain review."
    body_v2 = "Rule v2: never self-approve proposals."

    # 1. Create when target file is absent.
    fresh = merge_markdown_block(None, slice_id=slice_id, block_body=body_v1, expected_slice_digest=None)
    assert f"<!-- ensemble-brain:begin:{slice_id} -->" in fresh.updated_text
    assert f"<!-- ensemble-brain:end:{slice_id} -->" in fresh.updated_text
    assert body_v1 in fresh.updated_text and fresh.changed is True

    # 2. Insert into existing user document preserving prose + blank lines byte-for-byte.
    u0 = USER_HEADER + USER_FOOTER.lstrip("\n")
    installed = merge_markdown_block(u0, slice_id=slice_id, block_body=body_v1, expected_slice_digest=None)
    assert USER_HEADER.strip() in installed.updated_text
    assert USER_FOOTER.strip() in installed.updated_text
    assert installed.changed is True

    # Re-merging identical content with matching manifest digest is a clean no-op.
    same = merge_markdown_block(
        installed.updated_text,
        slice_id=slice_id,
        block_body=body_v1,
        expected_slice_digest=installed.slice_digest,
    )
    assert same.updated_text == installed.updated_text
    assert same.slice_digest == installed.slice_digest
    assert same.changed is False

    # First install colliding with pre-existing unmanaged markers (no manifest) must conflict.
    with pytest.raises(BrainError) as col_exc:
        merge_markdown_block(
            installed.updated_text, slice_id=slice_id, block_body=body_v2, expected_slice_digest=None
        )
    assert col_exc.value.code is ErrorCode.REVISION_CONFLICT

    # Malformed / unclosed delimiter markers are refused.
    malformed = f"# Header\n<!-- ensemble-brain:begin:{slice_id} -->\nbroken\n"
    with pytest.raises(BrainError) as bad_exc:
        merge_markdown_block(malformed, slice_id=slice_id, block_body=body_v1, expected_slice_digest=None)
    assert bad_exc.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.INVALID_INPUT}

    # Update when user edited INSIDE the managed block refuses overwrite.
    tampered_inside = installed.updated_text.replace(body_v1, "Rule tampered by user")
    with pytest.raises(BrainError) as drift_exc:
        merge_markdown_block(
            tampered_inside, slice_id=slice_id, block_body=body_v2, expected_slice_digest=installed.slice_digest
        )
    assert drift_exc.value.code is ErrorCode.REVISION_CONFLICT
    with pytest.raises(BrainError) as rm_drift_exc:
        remove_markdown_block(tampered_inside, slice_id=slice_id, expected_slice_digest=installed.slice_digest)
    assert rm_drift_exc.value.code is ErrorCode.REVISION_CONFLICT

    # Out-of-band edit OUTSIDE managed block (U0 + Block -> U1 + Block): update and U1 removal preserve U1!
    u1_plus_block = installed.updated_text + USER_ADDED_MID
    updated_u1 = merge_markdown_block(
        u1_plus_block, slice_id=slice_id, block_body=body_v2, expected_slice_digest=installed.slice_digest
    )
    assert body_v2 in updated_u1.updated_text and USER_ADDED_MID.strip() in updated_u1.updated_text

    removed_u1 = remove_markdown_block(
        updated_u1.updated_text, slice_id=slice_id, expected_slice_digest=updated_u1.slice_digest
    )
    assert f"ensemble-brain:begin:{slice_id}" not in removed_u1.updated_text
    assert body_v2 not in removed_u1.updated_text
    assert USER_HEADER.strip() in removed_u1.updated_text
    assert USER_FOOTER.strip() in removed_u1.updated_text
    assert USER_ADDED_MID.strip() in removed_u1.updated_text


def test_json_merger_preserves_siblings_detects_conflicts_and_removes_u1() -> None:
    key_path = ("mcpServers", "super-brain")
    cfg_v1 = {"command": "brain-mcp", "args": ["--profile", "/abs/profile.json"]}
    cfg_v2 = {"command": "brain-mcp", "args": ["--profile", "/abs/profile-v2.json"]}

    # 1. Fresh JSON file creation.
    fresh = merge_json_keys(None, key_path=key_path, value=cfg_v1, expected_slice_digest=None)
    assert json.loads(fresh.updated_text) == {"mcpServers": {"super-brain": cfg_v1}}

    # 2. Existing JSON preserves unrelated top-level and sibling MCP entries.
    u0 = json.dumps({"otherTool": {"enabled": True}, "mcpServers": {"userMcp": {"command": "npx"}}}, indent=2)
    merged = merge_json_keys(u0, key_path=key_path, value=cfg_v1, expected_slice_digest=None)
    parsed = json.loads(merged.updated_text)
    assert parsed["otherTool"] == {"enabled": True}
    assert parsed["mcpServers"]["userMcp"] == {"command": "npx"}
    assert parsed["mcpServers"]["super-brain"] == cfg_v1

    # Idempotent repeat with manifest digest.
    idem = merge_json_keys(
        merged.updated_text, key_path=key_path, value=cfg_v1, expected_slice_digest=merged.slice_digest
    )
    assert idem.changed is False

    # Collision on unmanaged install + drift inside owned key.
    with pytest.raises(BrainError) as col_exc:
        merge_json_keys(merged.updated_text, key_path=key_path, value=cfg_v2, expected_slice_digest=None)
    assert col_exc.value.code is ErrorCode.REVISION_CONFLICT

    tampered = json.loads(merged.updated_text)
    tampered["mcpServers"]["super-brain"]["command"] = "rogue"
    with pytest.raises(BrainError) as drift_exc:
        merge_json_keys(
            json.dumps(tampered), key_path=key_path, value=cfg_v2, expected_slice_digest=merged.slice_digest
        )
    assert drift_exc.value.code is ErrorCode.REVISION_CONFLICT

    # Non-object / malformed JSON rejected cleanly.
    for invalid in ("[1, 2, 3]", "{broken json", '"string"'):
        with pytest.raises(BrainError) as bad_exc:
            merge_json_keys(invalid, key_path=key_path, value=cfg_v1, expected_slice_digest=None)
        assert bad_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.REVISION_CONFLICT}

    # Out-of-band edit outside Brain key (U0+Block -> U1+Block): removal keeps sibling userMcp and userU1!
    u1_obj = json.loads(merged.updated_text)
    u1_obj["userAddedKey"] = {"keep": 42}
    u1_obj["mcpServers"]["anotherUserServer"] = {"command": "uvx"}
    removed = remove_json_keys(json.dumps(u1_obj), key_path=key_path, expected_slice_digest=merged.slice_digest)
    after = json.loads(removed.updated_text)
    assert "super-brain" not in after["mcpServers"]
    assert after["mcpServers"]["userMcp"] == {"command": "npx"}
    assert after["mcpServers"]["anotherUserServer"] == {"command": "uvx"}
    assert after["userAddedKey"] == {"keep": 42}


def test_toml_merger_preserves_comments_whitespace_and_u1_edits() -> None:
    table_path = ("mcp_servers", "super-brain")
    val_v1 = {"command": "brain-mcp", "args": ["--profile", "/abs/codex.json"]}
    val_v2 = {"command": "brain-mcp", "args": ["--profile", "/abs/codex-v2.json"]}

    u0 = (
        "# User top-level comment\n"
        'model = "gpt-5-codex" # inline user comment\n\n'
        "[profiles.fast]\n"
        "# Keep this profile comment\n"
        'approval_policy = "on-request"\n'
    )
    installed = merge_toml_table(u0, table_path=table_path, values=val_v1, expected_slice_digest=None)
    assert "# User top-level comment" in installed.updated_text
    assert "# inline user comment" in installed.updated_text
    assert "# Keep this profile comment" in installed.updated_text
    parsed: dict[str, Any] = tomlkit.parse(installed.updated_text).unwrap()
    assert parsed["mcp_servers"]["super-brain"] == val_v1

    # Collision without manifest and drift inside Brain table both fail with REVISION_CONFLICT.
    with pytest.raises(BrainError) as col_exc:
        merge_toml_table(
            installed.updated_text, table_path=table_path, values=val_v2, expected_slice_digest=None
        )
    assert col_exc.value.code is ErrorCode.REVISION_CONFLICT

    tampered_doc = installed.updated_text.replace("brain-mcp", "evil-mcp")
    with pytest.raises(BrainError) as drift_exc:
        merge_toml_table(
            tampered_doc, table_path=table_path, values=val_v2, expected_slice_digest=installed.slice_digest
        )
    assert drift_exc.value.code is ErrorCode.REVISION_CONFLICT

    with pytest.raises(BrainError) as bad_toml_exc:
        merge_toml_table("[unclosed", table_path=table_path, values=val_v1, expected_slice_digest=None)
    assert bad_toml_exc.value.code is ErrorCode.INVALID_INPUT

    # Update & U1 out-of-band edit followed by rollback removal keep every user comment & new user table intact!
    u1_plus_block = (
        installed.updated_text
        + "\n# Added later by owner (U1)\n[profiles.deep]\nreason = 'preserve-me'\n"
    )
    updated = merge_toml_table(
        u1_plus_block, table_path=table_path, values=val_v2, expected_slice_digest=installed.slice_digest
    )
    assert "# Added later by owner (U1)" in updated.updated_text
    assert "# Keep this profile comment" in updated.updated_text

    removed = remove_toml_table(
        updated.updated_text, table_path=table_path, expected_slice_digest=updated.slice_digest
    )
    assert "super-brain" not in removed.updated_text
    assert "# User top-level comment" in removed.updated_text
    assert "# inline user comment" in removed.updated_text
    assert "# Keep this profile comment" in removed.updated_text
    assert "# Added later by owner (U1)" in removed.updated_text
    final_doc: dict[str, Any] = tomlkit.parse(removed.updated_text).unwrap()
    assert final_doc["profiles"]["deep"]["reason"] == "preserve-me"


def test_mergers_reject_bom_and_nul_bytes() -> None:
    with pytest.raises(BrainError) as bom_md:
        merge_markdown_block("\ufeff# BOM\n", slice_id="s1", block_body="x", expected_slice_digest=None)
    assert bom_md.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as nul_json:
        merge_json_keys('{"a": "\x00"}', key_path=("mcpServers", "x"), value={}, expected_slice_digest=None)
    assert nul_json.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as bom_toml:
        merge_toml_table(
            "\ufeffa = 1\n", table_path=("mcp_servers", "x"), values={"k": "v"}, expected_slice_digest=None
        )
    assert bom_toml.value.code is ErrorCode.INVALID_INPUT


def test_bootstrap_templates_follow_d3_checkout_scoping_and_10_authority_groups(trusted_tmp: Path) -> None:
    checkout_a = trusted_tmp / "checkout-a"
    profile_a = trusted_tmp / "profiles" / "checkout-a.json"
    checkout_a.mkdir()
    home_dir = trusted_tmp / "fake-home"

    assert "Không tự duyệt" in LAYER1_RULE_TEXT
    assert len(AUTHORITY_ASK_COMMANDS) >= 11

    claude_plan = plan_claude_bootstrap(checkout_root=checkout_a, profile_path=profile_a)
    claude_rels = {t.rel_path for t in claude_plan.targets}
    assert claude_rels == {".mcp.json", "CLAUDE.md", ".claude/settings.local.json"}
    assert classify_proposal_risk(claude_plan.resources, client_hint="low") is RiskLevel.HIGH
    assert all(t.managed_format in {ManagedFormat.JSON, ManagedFormat.MARKDOWN} for t in claude_plan.targets)
    claude_rendered = "\n".join(t.preview_text for t in claude_plan.targets)
    assert str(profile_a) in claude_rendered
    assert LAYER1_RULE_TEXT in claude_rendered
    for cmd in AUTHORITY_ASK_COMMANDS:
        assert cmd in claude_rendered, f"missing Layer-2 ask command {cmd}"
    for target in claude_plan.targets:
        assert_not_skill_or_internal_target(str(checkout_a), target.rel_path, home_dir=str(home_dir))

    codex_plan = plan_codex_bootstrap(checkout_root=checkout_a, profile_path=profile_a)
    codex_rels = {t.rel_path for t in codex_plan.targets}
    assert codex_rels == {"AGENTS.md", ".codex/config.toml", ".codex/hooks.json"}
    assert classify_proposal_risk(codex_plan.resources, client_hint="low") is RiskLevel.HIGH
    codex_rendered = "\n".join(t.preview_text for t in codex_plan.targets)
    assert str(profile_a) in codex_rendered
    assert LAYER1_RULE_TEXT in codex_rendered
    for target in codex_plan.targets:
        assert_not_skill_or_internal_target(str(checkout_a), target.rel_path, home_dir=str(home_dir))
