"""Requirement-derived tests for client checkout scope selection and shim selector normalization (`T7b.1`)."""

from __future__ import annotations

import copy
import shutil
from pathlib import Path
from typing import Any

from superbrain.composition.client_entry import select_workspace
from superbrain.core.client_profile import ClientProfile, SelectedWorkspace, WorkspaceProfile

_VALID_LEAF_SHA256 = "b" * 64


def _make_secure_dir(path: Path) -> Path:
    from superbrain.adapters.os import os_adapters

    path.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(path)
    return path


def _sample_profile(base_dir: Path, workspace: WorkspaceProfile | None) -> ClientProfile:
    return ClientProfile(
        version=1,
        endpoint_path=base_dir / "endpoint.json",
        expected_store_id="store-01",
        ca_file=base_dir / "ca.pem",
        leaf_cert_sha256=_VALID_LEAF_SHA256,
        credential_file=base_dir / "credential.txt",
        workspace=workspace,
    )


def test_unknown_or_outside_launch_cwd_is_refused(monkeypatch: Any) -> None:
    import pytest

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.workspaces import verify_launch_checkout
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.kernel import Scope
    from tests.support.fs import fake_link
    from tests.support.inc2_transport import make_trusted_test_dir

    os_ = os_adapters()
    base_dir = make_trusted_test_dir("t7b1-scope-cwd")
    try:
        repo_dir = _make_secure_dir(base_dir / "repo")
        nested_dir = _make_secure_dir(_make_secure_dir(repo_dir / "subdir") / "nested")
        sibling_prefix_1 = _make_secure_dir(base_dir / "repo2")
        sibling_prefix_2 = _make_secure_dir(base_dir / "repo-other")
        unrelated_dir = _make_secure_dir(base_dir / "unrelated")
        reg_file = repo_dir / "README.md"
        reg_file.write_bytes(b"# readme\n")
        os_.permissions.secure_file(reg_file)

        ws_prof = WorkspaceProfile(
            alias="ws-a",
            checkout_path=repo_dir,
            expected_workspace_id="ws-repo-a",
            expected_checkout_id="chk-a",
        )
        prof = _sample_profile(base_dir, ws_prof)
        expected_selected = SelectedWorkspace(
            alias="ws-a",
            scope=Scope(repo_id="ws-repo-a", checkout_id="chk-a"),
        )

        # Positive: exact checkout root and nested subdirectory both succeed
        verify_launch_checkout(repo_dir, repo_dir, os_)
        verify_launch_checkout(repo_dir, nested_dir, os_)
        assert select_workspace(prof, repo_dir, os_) == expected_selected
        assert select_workspace(prof, nested_dir, os_) == expected_selected

        # Negative: launch_cwd is None when profile has a workspace -> IDENTITY_MISMATCH
        with pytest.raises(BrainError) as none_cwd_exc:
            select_workspace(prof, None, os_)
        assert none_cwd_exc.value.code == ErrorCode.IDENTITY_MISMATCH

        # Negative: missing CWD, regular file CWD, parent directory, unrelated directory,
        # and string-prefix sibling directories (`repo2`, `repo-other`) -> IDENTITY_MISMATCH
        for outside_cwd in (
            repo_dir / "missing-subdir",
            reg_file,
            base_dir,
            unrelated_dir,
            sibling_prefix_1,
            sibling_prefix_2,
        ):
            with pytest.raises(BrainError) as v_exc:
                verify_launch_checkout(repo_dir, outside_cwd, os_)
            assert v_exc.value.code == ErrorCode.IDENTITY_MISMATCH

            with pytest.raises(BrainError) as s_exc:
                select_workspace(prof, outside_cwd, os_)
            assert s_exc.value.code == ErrorCode.IDENTITY_MISMATCH

        # Link in parent of launch_cwd -> UNSAFE_PATH
        with monkeypatch.context() as mp:
            fake_link(mp, repo_dir / "subdir")
            with pytest.raises(BrainError) as link_exc:
                select_workspace(prof, nested_dir, os_)
            assert link_exc.value.code == ErrorCode.UNSAFE_PATH
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_multi_root_host_requires_selected_profile() -> None:
    import pytest

    from superbrain.adapters.os import os_adapters
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.wire import normalize_shim_args
    from tests.support.inc2_transport import make_trusted_test_dir

    os_ = os_adapters()
    base_dir = make_trusted_test_dir("t7b1-scope-none")
    try:
        prof_no_ws = _sample_profile(base_dir, None)
        assert select_workspace(prof_no_ws, None, os_) is None
        assert select_workspace(prof_no_ws, base_dir, os_) is None

        # Global / scopeless-capable tools (`get_health`, `get_job`) succeed when selected is None
        health_in: dict[str, JsonValue] = {"schema_version": "2.0", "deep": False}
        health_out = normalize_shim_args("get_health", health_in, None)
        assert health_out == {"schema_version": "2.0", "deep": False}
        assert health_out is not health_in

        job_in: dict[str, JsonValue] = {"schema_version": "2.0", "job_id": "job-01"}
        job_out = normalize_shim_args("get_job", job_in, None)
        assert job_out == {"schema_version": "2.0", "job_id": "job-01"}
        assert job_out is not job_in

        # All 6 workspace-scoped tools raise CAPABILITY_UNAVAILABLE when selected is None
        scoped_calls: list[tuple[str, dict[str, JsonValue]]] = [
            (
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "description": "prepare",
                    "idempotency_key": "idem_no_ws_prep_0001",
                },
            ),
            (
                "search_knowledge",
                {
                    "schema_version": "2.0",
                    "workspace_id": "ws-repo-a",
                    "query": "q",
                },
            ),
            (
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": "ws-repo-a",
                    "task_id": "task-01",
                    "artifact_id": "art-01",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem_no_ws_art_0001",
                },
            ),
            (
                "submit_episode",
                {
                    "schema_version": "2.0",
                    "task_id": "task-01",
                    "session_id": "sess-01",
                    "evidence": [],
                    "idempotency_key": "idem_no_ws_sub_0001",
                },
            ),
            (
                "record_outcome",
                {
                    "schema_version": "2.0",
                    "workspace_id": "ws-repo-a",
                    "delivery_id": "deliv-01",
                    "outcome": "success",
                    "idempotency_key": "idem_no_ws_out_0001",
                },
            ),
            (
                "request_improvement",
                {
                    "schema_version": "2.0",
                    "workspace_id": "ws-repo-a",
                    "task_id": "task-01",
                    "idempotency_key": "idem_no_ws_imp_0001",
                },
            ),
        ]
        for tool, sample_args in scoped_calls:
            before = copy.deepcopy(sample_args)
            with pytest.raises(BrainError) as exc_info:
                normalize_shim_args(tool, sample_args, None)
            assert exc_info.value.code == ErrorCode.CAPABILITY_UNAVAILABLE
            assert sample_args == before
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_shim_rejects_explicit_alias_or_ids_for_other_checkout() -> None:
    import pytest

    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.jsonvalue import JsonValue
    from superbrain.core.kernel import Scope
    from superbrain.core.wire import normalize_shim_args

    selected = SelectedWorkspace(
        alias="ws-a",
        scope=Scope(repo_id="ws-repo-a", checkout_id="chk-a"),
    )

    # 1. Missing selector on `prepare_task` injects `workspace_hint = selected.alias` without mutating caller's dict
    prep_no_sel: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "description": "task without explicit selector",
        "idempotency_key": "idem_prep_inject_01",
    }
    prep_no_sel_snapshot = copy.deepcopy(prep_no_sel)
    norm_injected = normalize_shim_args("prepare_task", prep_no_sel, selected)
    assert prep_no_sel == prep_no_sel_snapshot
    assert "workspace_hint" not in prep_no_sel
    assert norm_injected == {
        "schema_version": "2.0",
        "description": "task without explicit selector",
        "idempotency_key": "idem_prep_inject_01",
        "workspace_hint": "ws-a",
    }

    # 2. Matching `workspace_hint` or matching `(workspace_id, checkout_id)` succeeds
    prep_matching_hint: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_hint": "ws-a",
        "description": "matching hint",
        "idempotency_key": "idem_prep_hint_01",
    }
    assert normalize_shim_args("prepare_task", prep_matching_hint, selected) == prep_matching_hint

    prep_matching_ids: dict[str, JsonValue] = {
        "schema_version": "2.0",
        "workspace_id": "ws-repo-a",
        "checkout_id": "chk-a",
        "description": "matching ids",
        "idempotency_key": "idem_prep_ids_0001",
    }
    norm_ids = normalize_shim_args("prepare_task", prep_matching_ids, selected)
    assert norm_ids == prep_matching_ids
    assert "workspace_hint" not in norm_ids

    # 3. Client-supplied `selected_scope` in public arguments is always rejected with INVALID_INPUT
    for tool_name in ("prepare_task", "get_health", "get_job"):
        injected_scope_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "selected_scope": {"repo_id": "ws-repo-a", "checkout_id": "chk-a"},
        }
        with pytest.raises(BrainError) as scope_exc:
            normalize_shim_args(tool_name, injected_scope_args, selected)
        assert scope_exc.value.code == ErrorCode.INVALID_INPUT

    # 4. Mismatched alias or mismatched workspace_id / checkout_id -> IDENTITY_MISMATCH
    bad_identity_cases: list[dict[str, JsonValue]] = [
        {
            "schema_version": "2.0",
            "workspace_hint": "ws-b",
            "description": "wrong alias",
            "idempotency_key": "idem_wrong_alias_01",
        },
        {
            "schema_version": "2.0",
            "workspace_id": "ws-repo-b",
            "checkout_id": "chk-a",
            "description": "wrong workspace_id",
            "idempotency_key": "idem_wrong_ws_id_01",
        },
        {
            "schema_version": "2.0",
            "workspace_id": "ws-repo-a",
            "checkout_id": "chk-b",
            "description": "same repo other checkout",
            "idempotency_key": "idem_wrong_chk_id_01",
        },
        {
            "schema_version": "2.0",
            "workspace_id": "ws-repo-b",
            "checkout_id": "chk-b",
            "description": "both wrong",
            "idempotency_key": "idem_both_wrong_01",
        },
    ]
    for bad_identity_args in bad_identity_cases:
        snap = copy.deepcopy(bad_identity_args)
        with pytest.raises(BrainError) as id_exc:
            normalize_shim_args("prepare_task", bad_identity_args, selected)
        assert id_exc.value.code == ErrorCode.IDENTITY_MISMATCH
        assert bad_identity_args == snap

    # Also verify non-prepare_task tools enforce matching workspace_id / checkout_id against selected
    assert normalize_shim_args(
        "search_knowledge",
        {"schema_version": "2.0", "workspace_id": "ws-repo-a", "query": "ok"},
        selected,
    ) == {"schema_version": "2.0", "workspace_id": "ws-repo-a", "query": "ok"}

    with pytest.raises(BrainError) as sk_mismatch:
        normalize_shim_args(
            "search_knowledge",
            {"schema_version": "2.0", "workspace_id": "ws-repo-b", "query": "wrong repo"},
            selected,
        )
    assert sk_mismatch.value.code == ErrorCode.IDENTITY_MISMATCH

    with pytest.raises(BrainError) as sub_chk_mismatch:
        normalize_shim_args(
            "submit_episode",
            {
                "schema_version": "2.0",
                "task_id": "task-01",
                "session_id": "sess-01",
                "workspace_id": "ws-repo-a",
                "checkout_id": "chk-b",
                "evidence": [],
                "idempotency_key": "idem_sub_chk_mis_01",
            },
            selected,
        )
    assert sub_chk_mismatch.value.code == ErrorCode.IDENTITY_MISMATCH

    # 5. Mixed selector modes, partial ID pairs, and malformed selector values -> INVALID_INPUT
    bad_input_cases: list[dict[str, JsonValue]] = [
        # Mixed hint + workspace_id + checkout_id
        {
            "schema_version": "2.0",
            "workspace_hint": "ws-a",
            "workspace_id": "ws-repo-a",
            "checkout_id": "chk-a",
            "description": "mixed all",
            "idempotency_key": "idem_mixed_all_0001",
        },
        # Mixed hint + workspace_id
        {
            "schema_version": "2.0",
            "workspace_hint": "ws-a",
            "workspace_id": "ws-repo-a",
            "description": "mixed hint and ws",
            "idempotency_key": "idem_mixed_ws_0001",
        },
        # Mixed hint + checkout_id
        {
            "schema_version": "2.0",
            "workspace_hint": "ws-a",
            "checkout_id": "chk-a",
            "description": "mixed hint and chk",
            "idempotency_key": "idem_mixed_chk_0001",
        },
        # Partial IDs: workspace_id only
        {
            "schema_version": "2.0",
            "workspace_id": "ws-repo-a",
            "description": "missing checkout_id",
            "idempotency_key": "idem_half_ws_00001",
        },
        # Partial IDs: checkout_id only
        {
            "schema_version": "2.0",
            "checkout_id": "chk-a",
            "description": "missing workspace_id",
            "idempotency_key": "idem_half_chk_0001",
        },
        # Malformed selector values
        {
            "schema_version": "2.0",
            "workspace_hint": "../escape",
            "description": "bad hint grammar",
            "idempotency_key": "idem_bad_grammar_1",
        },
        {
            "schema_version": "2.0",
            "workspace_hint": "",
            "description": "empty hint",
            "idempotency_key": "idem_empty_hint_01",
        },
        {
            "schema_version": "2.0",
            "workspace_id": "",
            "checkout_id": "chk-a",
            "description": "empty ws id",
            "idempotency_key": "idem_empty_ws_id_1",
        },
    ]
    for bad_input_args in bad_input_cases:
        snap = copy.deepcopy(bad_input_args)
        with pytest.raises(BrainError) as inv_exc:
            normalize_shim_args("prepare_task", bad_input_args, selected)
        assert inv_exc.value.code == ErrorCode.INVALID_INPUT
        assert bad_input_args == snap
