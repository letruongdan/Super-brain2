"""Audit 2026-11-28 group B: bootstrap writes command hooks in each host's documented schema, the command the host
would run is exactly the capture hook, and the user's own hooks survive merge, re-plan and rollback."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.harness_config.bootstrap_templates import (
    MANAGED_HOOK_EVENTS,
    _checkout_capture_paths,
    build_capture_hook_command,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.json_hook_groups import HOOK_GROUPS_SLICE, is_managed_group
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ManagedFormat

# Documented schemas (code.claude.com/docs/en/hooks, learn.chatgpt.com/docs/hooks, read 2026-11-28).
_CLAUDE_EVENTS = {"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart", "SessionEnd", "Notification"}
_CODEX_EVENTS = {"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart", "SessionEnd"}
_CLAUDE_HANDLER = {"type", "command", "args", "timeout", "statusMessage", "if", "async", "shell", "onFailure"}
_CODEX_HANDLER = {"type", "command", "commandWindows", "timeout", "statusMessage", "async"}


def _checkout(tmp: Path, name: str) -> tuple[Path, Path]:
    perms = os_adapters().permissions
    chk = tmp / name
    (chk / ".claude").mkdir(parents=True)
    (chk / ".codex").mkdir()
    prof_dir = tmp / f"{name}-profile"
    prof_dir.mkdir()
    for d in (chk, chk / ".claude", chk / ".codex", prof_dir):
        perms.secure_directory(d)
    prof = prof_dir / "harness-profile.json"
    prof.write_bytes(b"{}")
    return chk, prof


def _write(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def _preview(plan: Any, rel: str) -> dict[str, Any]:
    target = next(t for t in plan.targets if t.rel_path == rel)
    return dict(json.loads(target.preview_text))


def _validate(doc: dict[str, Any], events: set[str], handler_keys: set[str]) -> list[dict[str, Any]]:
    hooks = doc["hooks"]
    assert isinstance(hooks, dict)
    handlers: list[dict[str, Any]] = []
    for event, groups in hooks.items():
        assert event in events, event
        assert isinstance(groups, list), (event, groups)
        for group in groups:
            assert isinstance(group, dict) and set(group) <= {"matcher", "hooks"}, group
            assert isinstance(group["hooks"], list) and group["hooks"]
            for h in group["hooks"]:
                assert set(h) <= handler_keys, h
                assert h["type"] == "command" and isinstance(h["command"], str) and h["command"]
                assert type(h["timeout"]) is int and h["timeout"] > 0
                handlers.append(h)
    return handlers


def _expected_argv(harness_id: str, chk: Path, prof: Path) -> list[str]:
    outbox, log = _checkout_capture_paths(harness_id, chk, prof)
    return list(build_capture_hook_command(harness_id, outbox_dir=outbox, log_path=log,
                                           python_executable=sys.executable, checkout_root=chk, profile_path=prof))


def test_claude_settings_use_matcher_groups_with_exec_form_handlers(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-claude")
    doc = _preview(plan_claude_bootstrap(checkout_root=chk, profile_path=prof), ".claude/settings.local.json")
    handlers = _validate(doc, _CLAUDE_EVENTS, _CLAUDE_HANDLER)
    assert set(doc["hooks"]) == set(MANAGED_HOOK_EVENTS) == {"PreToolUse", "PostToolUse"}  # tool use and its result
    assert {tuple(g["matcher"] for g in doc["hooks"][e]) for e in MANAGED_HOOK_EVENTS} == {("*",)}
    # exec form: what Claude Code spawns is exactly the capture hook argv, no shell in between
    assert handlers and all([h["command"], *h["args"]] == _expected_argv("claude-code", chk, prof) for h in handlers)


def test_codex_hooks_json_uses_matcher_groups_with_command_strings(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-codex")
    doc = _preview(plan_codex_bootstrap(checkout_root=chk, profile_path=prof), ".codex/hooks.json")
    handlers = _validate(doc, _CODEX_EVENTS, _CODEX_HANDLER)
    assert set(doc["hooks"]) == set(MANAGED_HOOK_EVENTS)
    # the shell string and the Windows string both parse back to exactly the capture hook argv
    assert handlers
    for h in handlers:
        assert shlex.split(h["command"]) == _expected_argv("codex", chk, prof)
        assert h["commandWindows"] == subprocess.list2cmdline(_expected_argv("codex", chk, prof))


def test_user_hooks_survive_merge_replan_and_rollback(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-user")
    settings = chk / ".claude" / "settings.local.json"
    user_pre = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-pre", "timeout": 3}]}
    user_stop = {"hooks": [{"type": "command", "command": "echo user-stop"}]}
    _write(settings, json.dumps({"theme": "dark", "hooks": {"PreToolUse": [user_pre], "Stop": [user_stop]}}))
    plan = plan_claude_bootstrap(checkout_root=chk, profile_path=prof)
    target = next(t for t in plan.targets if t.rel_path == ".claude/settings.local.json")
    doc = json.loads(target.preview_text)
    assert doc["theme"] == "dark"
    assert doc["hooks"]["Stop"] == [user_stop]
    assert doc["hooks"]["PreToolUse"][0] == user_pre and is_managed_group(doc["hooks"]["PreToolUse"][1])
    _write(settings, target.preview_text)

    expected = {(".claude/settings.local.json", target.slice_id): target.slice_digest}
    again = plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=expected)
    assert next(t for t in again.targets if t.rel_path == ".claude/settings.local.json").preview_text == \
        target.preview_text

    # a user edit outside the managed groups is kept; an edit of a managed group is a conflict
    doc["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": "echo later"}]})
    _write(settings, json.dumps(doc))
    plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=expected)
    tampered = json.loads(json.dumps(doc))
    tampered["hooks"]["PreToolUse"][1]["hooks"][0]["timeout"] = 99
    _write(settings, json.dumps(tampered))
    with pytest.raises(BrainError) as conflict:
        plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=expected)
    assert conflict.value.code is ErrorCode.REVISION_CONFLICT

    # rollback of a modified file removes only the managed slice
    removed = SharedConfigMergerAdapter().remove_slice(
        json.dumps(doc), managed_format=ManagedFormat.JSON, slice_id=target.slice_id,
        expected_slice_digest=target.slice_digest)
    left = json.loads(removed.updated_text)
    assert left["theme"] == "dark" and "permissions" not in left
    assert left["hooks"] == {"PreToolUse": [user_pre], "Stop": doc["hooks"]["Stop"]}
    assert HOOK_GROUPS_SLICE in target.slice_id
