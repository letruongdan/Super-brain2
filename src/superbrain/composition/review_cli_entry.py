"""Composition entry point for ``brain review|apply|rollback`` operator CLI commands (I3-2)."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import (
    read_client_ca,
    read_client_credential,
    read_client_endpoint,
    read_client_profile,
    read_owner_json_object,
)
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.core.client_profile import ClientProfile
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters

__all__ = ["main", "run_review_cli"]


@dataclass(frozen=True)
class _ParsedReviewCli:
    endpoint_path: str
    proposal_id: str | None
    profile_path: Path
    approval_file: Path | None
    as_json: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute()


def _parse_args(args: list[str]) -> _ParsedReviewCli | None:
    if not args:
        return None
    if args[0] == "review":
        if len(args) < 2:
            return None
        sub = args[1]
        if sub == "list":
            endpoint = "/v2/operator/proposal/list"
            rest = args[2:]
            needs_id = False
        elif sub in ("show", "approve", "reject"):
            endpoint = f"/v2/operator/proposal/{sub}"
            rest = args[2:]
            needs_id = True
        else:
            return None
    elif args[0] in ("apply", "rollback"):
        endpoint = f"/v2/operator/proposal/{args[0]}"
        rest = args[1:]
        needs_id = True
    else:
        return None

    profile_raw: str | None = None
    approval_raw: str | None = None
    as_json = False
    pos: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--json":
            if as_json:
                return None
            as_json = True
            i += 1
        elif tok == "--profile":
            if profile_raw is not None or i + 1 >= len(rest) or not _is_abs(rest[i + 1]):
                return None
            profile_raw = rest[i + 1]
            i += 2
        elif tok == "--approval-file":
            if approval_raw is not None or i + 1 >= len(rest) or not _is_abs(rest[i + 1]):
                return None
            approval_raw = rest[i + 1]
            i += 2
        elif tok.startswith("-"):
            return None
        else:
            pos.append(tok)
            i += 1

    if profile_raw is None:
        return None
    if needs_id:
        if len(pos) != 1 or not pos[0] or "\x00" in pos[0]:
            return None
        proposal_id: str | None = pos[0]
    else:
        if pos:
            return None
        proposal_id = None
    if approval_raw is not None and endpoint in ("/v2/operator/proposal/list", "/v2/operator/proposal/show"):
        return None
    return _ParsedReviewCli(
        endpoint_path=endpoint,
        proposal_id=proposal_id,
        profile_path=Path(profile_raw),
        approval_file=Path(approval_raw) if approval_raw is not None else None,
        as_json=as_json,
    )


def _write_err(code: ErrorCode) -> None:
    try:
        sys.stderr.write(f"{code.value}\n")
        sys.stderr.flush()
    except OSError:
        pass


def run_review_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    parsed = _parse_args(args)
    if parsed is None:
        _write_err(ErrorCode.INVALID_INPUT)
        return 2
    adapters = os_ if os_ is not None else os_adapters()
    if not os.path.lexists(parsed.profile_path):
        _write_err(ErrorCode.NOT_FOUND)
        return 1
    try:
        profile: ClientProfile = read_client_profile(parsed.profile_path, adapters)
        ca_pem = read_client_ca(profile.ca_file, adapters)
        token = read_client_credential(profile.credential_file, adapters)
        endpoint = read_client_endpoint(profile.endpoint_path, adapters)
        target = LoopbackTarget(
            endpoint=endpoint,
            expected_store_id=profile.expected_store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=profile.leaf_cert_sha256,
        )
        body: dict[str, object] = {}
        if parsed.proposal_id is not None:
            body["proposal_id"] = parsed.proposal_id
        if parsed.approval_file is not None:
            body["approval"] = read_owner_json_object(parsed.approval_file, adapters)
        result = LoopbackClient(monotonic_ns=adapters.monotonic.monotonic_ns).call_operator(
            target,
            parsed.endpoint_path,
            json.dumps(body).encode("utf-8"),
            token,
        )
    except BrainError as err:
        _write_err(err.code)
        return 1

    if result.get("ok") is not True:
        err_obj = result.get("error")
        code_str = err_obj.get("code") if isinstance(err_obj, dict) else ErrorCode.IO_ERROR.value
        sys.stderr.write(f"{code_str}\n")
        sys.stderr.flush()
        return 1
    if parsed.as_json:
        sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    else:
        sys.stdout.write(json.dumps(result.get("data", {}), sort_keys=True) + "\n")
    sys.stdout.flush()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_review_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
