"""C-02 closure oracle: owner-side reconstruction refuses any queued payload that is not canonical (C3:92, D3/D4).

The queued canonical bytes are the HMAC/idempotency input. A ``QueuedKernelRequest`` whose ``canonical_payload``
decodes to the right content but is not *the* canonical encoding of that content (key order, whitespace, escapes),
or whose tool/scope disagree with the payload, must be refused with ``INTEGRITY_FAILURE``.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from typing import Any

import pytest

from superbrain.application._prequeue import reconstruct_queued_call
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    Principal,
    PrivateRequestAuth,
    QueuedKernelRequest,
    RequestDeadlines,
    Scope,
)
from superbrain.core.wire import canonical_request_payload, normalize_call

PRINCIPAL = Principal(principal_id="p-closure-1", owner_id="dan", harness_id="claude-code", machine_id="devbox-1")
SCOPE = Scope(repo_id="ws-repo-a", checkout_id="chk-a")
ARGS: dict[str, JsonValue] = {
    "schema_version": "2.0",
    "workspace_id": "ws-repo-a",
    "query": "café naïve / 日本 \"quoted\" tab\there",
    "limit": 7,
}


def _canonical(content: object) -> bytes:
    """Spec canonical JSON: sorted keys, no insignificant whitespace, raw UTF-8 (no ``\\u`` escapes)."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _produced() -> QueuedKernelRequest:
    """A request whose payload comes from the real producer (``normalize_call`` + ``canonical_request_payload``)."""
    call = normalize_call("search_knowledge", dict(ARGS), PRINCIPAL, selected_scope=SCOPE, correlation_id="corr-1")
    return QueuedKernelRequest(
        store_id="store-closure",
        writer_epoch=1,
        tool=call.tool,
        correlation_id=call.correlation_id,
        selected_scope=call.selected_scope,
        deadlines=RequestDeadlines.from_receive_ns(1_000_000_000),
        auth_view_version=1,
        auth=PrivateRequestAuth(credential_id=str(uuid.uuid4()), principal=PRINCIPAL, token="cred.secret"),
        canonical_payload=canonical_request_payload(call),
    )


def _content() -> dict[str, object]:
    return {"tool": "search_knowledge", "selected_scope": SCOPE.to_dict(), "arguments": dict(ARGS)}


def test_c02_positive_control_real_producer_payload_reconstructs() -> None:
    queued = _produced()
    assert queued.canonical_payload == _canonical(_content())
    call = reconstruct_queued_call(queued)
    assert call.tool == "search_knowledge"
    assert call.arguments == ARGS
    assert call.selected_scope == SCOPE
    assert call.correlation_id == "corr-1"


def _non_canonical_variants() -> dict[str, bytes]:
    content = _content()
    canonical = _canonical(content)
    reordered = json.dumps(
        {"arguments": dict(reversed(list(ARGS.items()))), "tool": content["tool"], "selected_scope": content[
            "selected_scope"]},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    variants = {
        "reordered_keys": reordered,
        "spaces_after_separators": json.dumps(content, sort_keys=True, ensure_ascii=False).encode(),
        "pretty_printed": json.dumps(content, sort_keys=True, ensure_ascii=False, indent=2).encode(),
        "trailing_newline": canonical + b"\n",
        "leading_space": b" " + canonical,
        "escaped_unicode": json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
        "escaped_solidus": canonical.replace(b" / ", b" \\/ "),
        "escaped_plain_letter": canonical.replace(b'"query":"caf', b'"query":"\\u0063af'),
    }
    for name, raw in variants.items():
        assert raw != canonical, name
        assert json.loads(raw) == content, f"{name} must decode to the same content"
    return variants


@pytest.mark.parametrize("variant", sorted(_non_canonical_variants()))
def test_c02_non_canonical_encoding_of_same_content_is_integrity_failure(variant: str) -> None:
    queued = replace(_produced(), canonical_payload=_non_canonical_variants()[variant])
    with pytest.raises(BrainError) as exc:
        reconstruct_queued_call(queued)
    assert exc.value.code is ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize(
    "change",
    [
        {"tool": "get_job"},
        {"selected_scope": Scope(repo_id="ws-repo-b", checkout_id="chk-a")},
        {"selected_scope": Scope(repo_id="ws-repo-a", checkout_id=None)},
        {"selected_scope": None},
    ],
    ids=["tool", "scope_repo", "scope_checkout", "scope_missing"],
)
def test_c02_tool_or_scope_disagreeing_with_payload_is_integrity_failure(change: dict[str, Any]) -> None:
    queued = replace(_produced(), **change)
    with pytest.raises(BrainError) as exc:
        reconstruct_queued_call(queued)
    assert exc.value.code is ErrorCode.INTEGRITY_FAILURE
