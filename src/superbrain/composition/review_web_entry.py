"""Composition entrypoint for ``brain review --web`` (spec 11.2, 11.3, I3-5)."""

from __future__ import annotations

import json
import signal
import sys
import threading
import webbrowser
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from superbrain.application.review_session import ReviewOperatorBackendPort, ReviewSession
from superbrain.composition._operator_client import OperatorEndpointClient, write_error_code
from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    SignerRecord,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.os import OsAdapters
from superbrain.review_web.server import ReviewWebServer

__all__ = ["DaemonReviewBackend", "main", "open_review_web_server", "run_review_web_cli"]


def _unwrap_data(env: dict[str, JsonValue]) -> dict[str, JsonValue]:
    if env.get("ok") is not True:
        err_obj = env.get("error")
        if isinstance(err_obj, Mapping):
            raw_code = str(err_obj.get("code", ErrorCode.IO_ERROR.value))
            msg = str(err_obj.get("message", "operator call failed"))
            try:
                raise BrainError(ErrorCode(raw_code), msg)
            except ValueError:
                raise BrainError(ErrorCode.IO_ERROR, msg) from None
        raise BrainError(ErrorCode.IO_ERROR, "operator call failed")
    data = env.get("data")
    if not isinstance(data, dict):
        raise BrainError(ErrorCode.IO_ERROR, "malformed operator response")
    return data


class DaemonReviewBackend(ReviewOperatorBackendPort):
    """Loopback daemon adapter implementing ``ReviewOperatorBackendPort`` via ``OperatorEndpointClient``."""

    def __init__(self, client: OperatorEndpointClient) -> None:
        self._client = client

    def list_signers(self) -> tuple[SignerRecord, ...]:
        data = _unwrap_data(self._client.call("/v2/operator/signer/list", {}))
        raw_signers = data.get("signers")
        if not isinstance(raw_signers, list):
            return ()
        out: list[SignerRecord] = []
        for item in raw_signers:
            if not isinstance(item, Mapping):
                continue
            cred = item.get("credential_id")
            out.append(
                SignerRecord(
                    signer_id=str(item["signer_id"]),
                    owner_id=str(item.get("owner_id", "")),
                    channel=ApprovalChannel(str(item["channel"])),
                    key_digest=str(item["key_digest"]),
                    tofu=bool(item["tofu"]),
                    revoked=False,
                    credential_id=None if cred is None else str(cred),
                )
            )
        return tuple(out)

    def show_proposal(self, proposal_id: str) -> Mapping[str, JsonValue]:
        data = _unwrap_data(self._client.call("/v2/operator/proposal/show", {"proposal_id": proposal_id}))
        prop = data.get("proposal")
        if not isinstance(prop, Mapping):
            raise BrainError(ErrorCode.IO_ERROR, "missing proposal in show response")
        return cast(Mapping[str, JsonValue], prop)

    def request_challenge(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        recovery_scope: RecoveryScope,
    ) -> tuple[ApprovalMessage, Mapping[str, JsonValue]]:
        path = f"/v2/operator/proposal/{action.value}"
        data = _unwrap_data(
            self._client.call(
                path,
                {"proposal_id": proposal_id, "recovery_scope": recovery_scope.value},
            )
        )
        raw_ch = data.get("challenge")
        raw_prop = data.get("proposal")
        if not isinstance(raw_ch, Mapping) or not isinstance(raw_prop, Mapping):
            raise BrainError(ErrorCode.IO_ERROR, "missing challenge or proposal in operator response")
        return ApprovalMessage.from_dict(raw_ch), cast(Mapping[str, JsonValue], raw_prop)

    def submit_approval(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        raw_approval: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        path = f"/v2/operator/proposal/{action.value}"
        return _unwrap_data(
            self._client.call(
                path,
                {"proposal_id": proposal_id, "approval": dict(raw_approval)},
            )
        )


def open_review_web_server(
    profile_path: Path,
    *,
    proposal_id: str,
    action: ApprovalAction = ApprovalAction.APPROVE,
    os_: OsAdapters | None = None,
    port: int = 0,
) -> ReviewWebServer:
    """Create and bind a ``ReviewWebServer`` backed by the live daemon configured by ``profile_path``."""
    client = OperatorEndpointClient(profile_path, os_=os_)
    backend = DaemonReviewBackend(client)
    session = ReviewSession(
        backend=backend,
        proposal_id=proposal_id,
        rp_id="localhost",
        expected_origin="http://localhost:0",
        default_action=action,
    )
    server = ReviewWebServer(session, host="127.0.0.1", port=port)
    session.bind_origin(server.origin)
    return server


@dataclass(frozen=True)
class _ParsedReviewWebCli:
    proposal_id: str
    profile_path: Path
    action: ApprovalAction
    print_url_only: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute() and ".." not in Path(raw).parts


def _parse_args(args: list[str]) -> _ParsedReviewWebCli | None:
    if len(args) < 2 or args[0] != "review" or "--web" not in args:
        return None
    profile_raw: str | None = None
    action_raw = "approve"
    print_url_only = False
    pos: list[str] = []
    seen_web = False
    seen_action = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--web":
            if seen_web:
                return None
            seen_web = True
            i += 1
        elif tok == "--print-url-only":
            if print_url_only:
                return None
            print_url_only = True
            i += 1
        elif tok == "--profile":
            if profile_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            profile_raw = args[i + 1]
            i += 2
        elif tok == "--action":
            if seen_action or i + 1 >= len(args) or args[i + 1] not in ("approve", "reject", "apply", "rollback"):
                return None
            seen_action = True
            action_raw = args[i + 1]
            i += 2
        elif tok.startswith("-"):
            return None
        else:
            pos.append(tok)
            i += 1
    if not seen_web or profile_raw is None or len(pos) != 1 or not pos[0] or "\x00" in pos[0]:
        return None
    return _ParsedReviewWebCli(
        proposal_id=pos[0],
        profile_path=Path(profile_raw),
        action=ApprovalAction(action_raw),
        print_url_only=print_url_only,
    )


def run_review_web_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    parsed = _parse_args(args)
    if parsed is None:
        write_error_code(ErrorCode.INVALID_INPUT)
        return 2
    try:
        with open_review_web_server(
            parsed.profile_path,
            proposal_id=parsed.proposal_id,
            action=parsed.action,
            os_=os_,
        ) as srv:
            sys.stdout.write(json.dumps({"ok": True, "data": {"launch_url": srv.launch_url}}, sort_keys=True) + "\n")
            sys.stdout.flush()
            if parsed.print_url_only:
                return 0
            webbrowser.open(srv.launch_url)
            stop = threading.Event()
            for sig_name in ("SIGINT", "SIGTERM"):
                sig = getattr(signal, sig_name, None)
                if isinstance(sig, signal.Signals):
                    try:
                        signal.signal(sig, lambda _s, _f: stop.set())
                    except (OSError, ValueError):
                        pass
            stop.wait()
            return 0
    except BrainError as err:
        write_error_code(err.code)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_review_web_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
