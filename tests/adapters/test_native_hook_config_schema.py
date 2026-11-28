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


def _legacy_object(chk: Path, prof: Path) -> dict[str, Any]:
    """What bootstrap wrote before the matcher-group schema: ``hooks.PreToolUse = {"super_brain": {...}}``."""
    return {"super_brain": {"mode": "remind", "non_blocking": True, "profile": str(prof),
                            "command": _expected_argv("claude-code", chk, prof)}}


def test_a_checkout_bootstrapped_with_the_legacy_hook_object_upgrades_to_matcher_groups(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-legacy")
    settings = chk / ".claude" / "settings.local.json"
    _write(settings, json.dumps({"theme": "dark", "hooks": {"PreToolUse": _legacy_object(chk, prof)}}))
    doc = _preview(plan_claude_bootstrap(checkout_root=chk, profile_path=prof), ".claude/settings.local.json")
    assert doc["theme"] == "dark"
    handlers = _validate(doc, _CLAUDE_EVENTS, _CLAUDE_HANDLER)  # every event is a list of matcher groups now
    assert handlers and "super_brain" not in json.dumps(doc["hooks"])


def test_a_legacy_hook_object_the_user_extended_is_a_conflict_not_a_deletion(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-legacy-user")
    legacy = _legacy_object(chk, prof) | {"my_tool": {"command": "echo mine"}}
    _write(chk / ".claude" / "settings.local.json", json.dumps({"hooks": {"PreToolUse": legacy}}))
    with pytest.raises(BrainError) as err:
        plan_claude_bootstrap(checkout_root=chk, profile_path=prof)
    assert err.value.code is ErrorCode.REVISION_CONFLICT


def test_a_user_handler_sharing_the_capture_handlers_group_survives_replan_and_rollback(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-shared-group")
    settings = chk / ".claude" / "settings.local.json"
    target = next(t for t in plan_claude_bootstrap(checkout_root=chk, profile_path=prof).targets
                  if t.rel_path == ".claude/settings.local.json")
    doc = json.loads(target.preview_text)
    user_handler = {"type": "command", "command": "echo user-also-here", "timeout": 3}
    doc["hooks"]["PreToolUse"][0]["hooks"].append(user_handler)  # the user added theirs into our group
    _write(settings, json.dumps(doc))
    expected = {(".claude/settings.local.json", target.slice_id): target.slice_digest}
    replan = plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=expected)
    replanned = json.loads(next(t for t in replan.targets if t.rel_path == ".claude/settings.local.json").preview_text)
    assert user_handler in [h for g in replanned["hooks"]["PreToolUse"] for h in g["hooks"]]
    removed = SharedConfigMergerAdapter().remove_slice(
        json.dumps(replanned), managed_format=ManagedFormat.JSON, slice_id=target.slice_id, expected_slice_digest=None)
    left = json.loads(removed.updated_text)
    assert [h for g in left["hooks"]["PreToolUse"] for h in g["hooks"]] == [user_handler]


def test_a_command_that_only_mentions_the_hook_module_is_not_managed() -> None:
    mention = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo superbrain.composition.hook_entry"}]}
    runs = {"matcher": "*", "hooks": [{"type": "command", "command": "python",
                                       "args": ["-I", "-m", "superbrain.composition.hook_entry", "--outbox", "x",
                                                "--harness", "claude-code"]}]}
    assert not is_managed_group(mention)
    assert is_managed_group(runs)


def test_a_codex_checkout_with_the_legacy_hook_object_upgrades_to_matcher_groups(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-legacy-codex")
    legacy = {"super_brain": {"mode": "remind", "command": _expected_argv("codex", chk, prof)}}
    _write(chk / ".codex" / "hooks.json", json.dumps({"hooks": {"PreToolUse": legacy}}))
    doc = _preview(plan_codex_bootstrap(checkout_root=chk, profile_path=prof), ".codex/hooks.json")
    handlers = _validate(doc, _CODEX_EVENTS, _CODEX_HANDLER)
    assert handlers and "super_brain" not in json.dumps(doc["hooks"])


def _legacy_applied_claude(chk: Path, prof: Path) -> tuple[Path, dict[tuple[str, str], str]]:
    """The settings file and the stored slice digest an earlier, fully applied Claude bootstrap left behind."""
    from superbrain.adapters.harness_config._common import digest_json_value

    ask: list[Any] = [f"Bash({cmd} *)" for cmd in ("brain review", "brain restore")]
    legacy = _legacy_object(chk, prof)
    settings = chk / ".claude" / "settings.local.json"
    _write(settings, json.dumps({"permissions": {"ask": ask}, "hooks": {"PreToolUse": legacy}}))
    digest = digest_json_value({"permissions.ask": ask, "hooks.PreToolUse": legacy})
    return settings, {(".claude/settings.local.json", "permissions.ask,hooks.PreToolUse"): digest}


def test_a_fully_applied_legacy_claude_bootstrap_upgrades_with_its_stored_digest(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-legacy-applied")
    _settings, stored = _legacy_applied_claude(chk, prof)
    doc = _preview(plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=stored),
                   ".claude/settings.local.json")
    assert _validate(doc, _CLAUDE_EVENTS, _CLAUDE_HANDLER)
    assert "super_brain" not in json.dumps(doc["hooks"])


def test_a_drifted_legacy_claude_bootstrap_is_a_conflict(trusted_tmp: Path) -> None:
    chk, prof = _checkout(trusted_tmp, "chk-legacy-drifted")
    settings, stored = _legacy_applied_claude(chk, prof)
    doc = json.loads(settings.read_text(encoding="utf-8"))
    doc["permissions"]["ask"].append("Bash(rm *)")  # edited after the legacy apply
    _write(settings, json.dumps(doc))
    with pytest.raises(BrainError) as err:
        plan_claude_bootstrap(checkout_root=chk, profile_path=prof, expected_slice_digests=stored)
    assert err.value.code is ErrorCode.REVISION_CONFLICT


def test_handlers_that_only_imitate_the_hook_or_mix_owners_are_not_managed() -> None:
    from superbrain.adapters.harness_config.json_hook_groups import is_managed_handler

    ours = ["C:/py/python.exe", "-I", "-m", "superbrain.composition.hook_entry", "--outbox", "o", "--harness", "codex"]
    assert is_managed_handler({"type": "command", "command": ours[0], "args": ours[1:]})
    echo = ["echo", *ours[1:]]
    assert not is_managed_handler({"type": "command", "command": "echo", "args": echo[1:]})
    assert not is_managed_handler({"type": "command", "command": "echo -m superbrain.composition.hook_entry"})
    mixed = {"type": "command", "command": shlex.join(ours), "commandWindows": "my-own-windows-hook.cmd"}
    assert not is_managed_handler(mixed)  # one field belongs to the user: the handler is not ours to remove
